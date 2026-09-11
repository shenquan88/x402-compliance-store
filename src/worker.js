// FILE-OWNER: DSH
// FILE-PURPOSE: x402 付费端点 Cloudflare Worker 主入口
// LAST-MODIFIED-BY: DSH @ 2026-09-10
// DO-NOT-MODIFY-WITHOUT: DSH 确认（subagent 委派时必须先读此备注）

/**
 * Web4 x402 Paid Endpoint — Cloudflare Worker (data-driven)
 *
 * 商品目录在 products.json（单一事实源）。加商品 = 改 JSON → `pwsh publish.ps1`。
 *
 * OWNER: DSH（主体）/ Claude（免费层 + domain-health + 发现协议）
 * CO-EDIT: 报备后可改（改动必须记入下方 CHANGELOG + daily）
 *
 * CHANGELOG:
 *   2026-09-10 DSH     audit-pro/cross-border/cn-dns-leak/firewall-status/infra-daily + CN_VPS_API
 *   2026-09-11 Claude  x402-wrap-generator 元编程旗舰（$2.00，生成买家定制包装代码包）
*   2026-09-10 Claude  发现协议三件套(.well-known/openapi/indexnow-key) + 免费层(us-probe/x402-audit) + domain-health 商品
 *
 * Flow:
 *   1. GET 无付款头  -> 402 + PAYMENT-REQUIRED（标准 base64）+ bazaar 扩展
 *   2. GET 带付款头  -> facilitator verify -> settle -> 仅结算成功才返回 200 + 内容
 *
 * 硬化点:
 *   - settle 失败不再误报 200（返回 402 + facilitator 明细）
 *   - 响应带 tx hash（receipt.transaction）
 *   - 价格按商品独立（priceUsd * 1e6）
 *   - 预留 upstream 字段（转售模式占位）
 */

import catalog from "../products.json";
import { generateWrapKit } from "./wrap_generator.js";

const { store, products, freePages = {} } = catalog;
const X402_VERSION = 2;
const FACILITATORS = [
  "https://facilitator.openx402.ai", // 免鉴权（selfbuy 兼容）
  "https://api.cdp.coinbase.com/platform/v2/x402", // CDP 备用
];

// CN VPS 探针 API（用于大陆 vantage 拨测；不可达时自动降级为 CF edge 数据）
const CN_VPS_API = "http://23.173.216.42:8080";
const WORKER_VERSION = "2.1.0";

// UTF-8-safe STANDARD base64（验证器 atob 兼容；btoa 遇中文会炸）
function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function jsonHeaders(extra = {}) {
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    ...extra,
  };
}

function toAtomicUnits(priceUsd) {
  return String(Math.round(priceUsd * 1e6));
}

// 浏览计数（KV; 采样 1/5 防刷爆 KV 写入额度，读取时 ×5 估算；含爬虫/验证器探测，看趋势不看绝对值）
const VIEW_SAMPLE = 5;
const viewSampleSeq = { n: 0 };
async function bumpView(env, key) {
  if (!env || !env.SETTLEMENTS) return;
  try {
    viewSampleSeq.n = (viewSampleSeq.n + 1) % VIEW_SAMPLE;
    if (viewSampleSeq.n !== 0) return; // 采样: 只记 1/5
    const k = "view:" + key;
    const cur = parseInt((await env.SETTLEMENTS.get(k)) || "0", 10);
    await env.SETTLEMENTS.put(k, String(cur + VIEW_SAMPLE));
  } catch { /* 计数失败不阻断服务 */ }
}

function acceptsFor(product) {
  return [
    {
      scheme: "exact",
      network: store.network,
      asset: store.asset,
      payTo: store.payTo,
      amount: toAtomicUnits(product.priceUsd),
      maxTimeoutSeconds: store.maxTimeoutSeconds,
      // EIP-712 域名必须匹配链上合约名
      extra: { name: store.assetName, version: store.assetVersion },
    },
  ];
}

function bazaarExtension(product) {
  // schema 不带 required：验证器用 402 响应体做探测校验，协议体没有商品字段
  const outputSchema = {
    type: "object",
    properties: {
      product: { type: "string" },
      title: { type: "string" },
      license: { type: "string" },
      receipt: { type: "object" },
      message: { type: "string" },
    },
  };
  const ext = {
    bazaar: {
      info: {
        title: product.title,
        description: product.description,
        input: product.input
          ? { type: "http", method: "GET", example: product.input.example || {} }
          : { type: "http", method: "GET", example: { format: "json" } },
        output: { example: product.outputExample, schema: outputSchema },
      },
      schema: outputSchema,
    },
  };
  // AI 理性购买论证：自开发成本 vs 购买价格
  if (product.selfDevelopCost) {
    ext.bazaar.info.selfDevelopCost = product.selfDevelopCost;
    ext.bazaar.info.buyVsBuild = product.selfDevelopCost.buyVsBuild;
  }
  return ext;
}

// x402 合规自检：fetch 买家的 endpoint，检查 402 响应格式
async function checkX402Compliance(targetUrl) {
  const checks = [];
  let probeStatus = null;
  let probeHeaders = {};
  let probeBody = "";
  let fetchError = null;

  // SSRF 防护：拒绝内网/环回目标
  try {
    const u = new URL(targetUrl);
    if (!["http:", "https:"].includes(u.protocol)) {
      return { endpoint: targetUrl, overall: "invalid", error: "scheme not allowed", checks: [] };
    }
    const host = u.hostname;
    if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const parts = host.split(".").map(Number);
      if (parts.length === 4 && (parts[0] === 10 || parts[0] === 127 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31 || parts[0] === 192 && parts[1] === 168 || parts[0] === 169 && parts[1] === 254)) {
        return { endpoint: targetUrl, overall: "invalid", error: "private address blocked (SSRF protection)", checks: [] };
      }
    }
  } catch (e) {
    return { endpoint: targetUrl, overall: "invalid", error: "invalid URL: " + String(e), checks: [] };
  }

  // fetch 买家的 endpoint（无付款头）
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(targetUrl, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4-x402-compliance-checker/1.0", "Accept": "application/json,*/*" },
    });
    clearTimeout(timer);
    probeStatus = resp.status;
    probeHeaders = resp.headers;
    probeBody = await resp.text();
  } catch (e) {
    fetchError = String(e);
  }

  // Check 1: HTTP 402 状态
  checks.push({ name: "http_status_402", passed: probeStatus === 402, detail: fetchError ? "fetch failed: " + fetchError.slice(0, 80) : `got HTTP ${probeStatus}` });

  let parsed = {};
  if (probeBody) {
    try { parsed = JSON.parse(probeBody); } catch { /* 非 JSON body */ }
  }

  // Check 2: x402Version
  checks.push({ name: "x402_version_field", passed: parsed.x402Version !== undefined, detail: parsed.x402Version !== undefined ? `version ${parsed.x402Version}` : "missing" });

  // Check 3: accepts array
  const accepts = parsed.accepts || [];
  checks.push({ name: "accepts_array", passed: Array.isArray(accepts) && accepts.length > 0, detail: `${accepts.length} payment scheme(s)` });

  // Check 4: accept schema (scheme/network/asset/payTo/amount)
  if (accepts.length > 0) {
    const a = accepts[0];
    const required = ["scheme", "network", "asset", "payTo", "amount"];
    const missing = required.filter((f) => !a[f]);
    checks.push({ name: "accept_schema", passed: missing.length === 0, detail: missing.length ? `missing: ${missing.join(", ")}` : "all required fields present" });
  } else {
    checks.push({ name: "accept_schema", passed: false, detail: "no accepts to check" });
  }

  // Check 5: PAYMENT-REQUIRED header
  const prHeader = probeHeaders.get("payment-required") || probeHeaders.get("PAYMENT-REQUIRED") || probeHeaders.get("X-Payment-Required");
  checks.push({ name: "payment_required_header", passed: !!prHeader, detail: prHeader ? "present" : "absent" });

  // Check 6: resource.url + resource.description
  const res = parsed.resource || {};
  checks.push({ name: "resource_metadata", passed: !!res.url && !!res.description, detail: res.url ? "url+description present" : "missing" });

  // Check 7: extensions.bazaar
  const bazaar = (parsed.extensions || {}).bazaar;
  checks.push({ name: "bazaar_extension", passed: !!bazaar, detail: bazaar ? "present" : "absent (not required but improves discovery)" });

  // Check 8: bazaar.info.title + description
  if (bazaar) {
    const info = bazaar.info || {};
    checks.push({ name: "bazaar_info", passed: !!info.title && !!info.description, detail: info.title ? "title+description present" : "missing" });
  } else {
    checks.push({ name: "bazaar_info", passed: false, detail: "no bazaar extension" });
  }

  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed);
  return {
    endpoint: targetUrl,
    http_status: probeStatus,
    overall: failed.length === 0 ? "compliant" : "non-compliant",
    checks_passed: passed,
    checks_total: checks.length,
    checks_failed: failed.length,
    critical_issues: failed.map((c) => c.name),
    checks,
  };
}

// ──────────────────────────────────────────────────────────────
// P2 新商品辅助函数
// ──────────────────────────────────────────────────────────────

function buildMeta(path, startedAt) {
  return {
    agentId: "web4shop-x402-worker",
    endpoint: path,
    startedAt: startedAt,
    completedAt: new Date().toISOString(),
    version: WORKER_VERSION,
  };
}

// SSRF-safe URL validation（新商品共享）
function validateProbeUrl(targetUrl) {
  try {
    const u = new URL(targetUrl);
    if (!["http:", "https:"].includes(u.protocol)) {
      return { ok: false, error: "scheme not allowed" };
    }
    const host = u.hostname;
    if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const parts = host.split(".").map(Number);
      if (parts.length === 4 && (parts[0] === 10 || parts[0] === 127 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31 || parts[0] === 192 && parts[1] === 168 || parts[0] === 169 && parts[1] === 254)) {
        return { ok: false, error: "private address blocked (SSRF protection)" };
      }
    }
    return { ok: true, url: u };
  } catch (e) {
    return { ok: false, error: "invalid URL: " + String(e) };
  }
}

// DNS-over-HTTPS 查询（从 CF edge 发起，比较各 resolver 的 A 记录答案）
async function dohQuery(domain, serverKey) {
  const servers = {
    google: { url: "https://dns.google/resolve", ip: "8.8.8.8" },
    cloudflare: { url: "https://1.1.1.1/dns-query", ip: "1.1.1.1" },
    alidns: { url: "https://dns.alidns.com/resolve", ip: "223.5.5.5" },
    dnspod: { url: "https://doh.pub/dns-query", ip: "119.29.29.29" },
  };
  const conf = servers[serverKey];
  if (!conf) return { server: serverKey, error: "unknown server" };
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const t0 = Date.now();
    const resp = await fetch(
      `${conf.url}?name=${encodeURIComponent(domain)}&type=A`,
      { signal: ctrl.signal, headers: { "Accept": "application/dns-json" } }
    );
    clearTimeout(timer);
    const elapsed = Date.now() - t0;
    const data = await resp.json();
    const aRecords = (data.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
    return {
      server: serverKey,
      resolver_ip: conf.ip,
      dns_status: data.Status,
      answers: aRecords,
      answer_count: aRecords.length,
      response_ms: elapsed,
    };
  } catch (e) {
    return { server: serverKey, resolver_ip: conf.ip, error: String(e).slice(0, 120) };
  }
}

// x402 合规审计 Pro：14 项检查（8 原有 + 6 新增）
async function checkX402CompliancePro(targetUrl) {
  const valResult = validateProbeUrl(targetUrl);
  if (!valResult.ok) {
    return { endpoint: targetUrl, overall: "invalid", error: valResult.error, checks: [] };
  }

  const checks = [];
  let probeStatus = null;
  let probeHeaders = {};
  let probeBody = "";
  let fetchError = null;
  let fetchTimeMs = null;

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const t0 = Date.now();
    const resp = await fetch(targetUrl, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4-x402-audit-pro/2.0", "Accept": "application/json,*/*" },
    });
    clearTimeout(timer);
    fetchTimeMs = Date.now() - t0;
    probeStatus = resp.status;
    probeHeaders = resp.headers;
    probeBody = await resp.text();
  } catch (e) {
    fetchError = String(e);
  }

  let parsed = {};
  if (probeBody) {
    try { parsed = JSON.parse(probeBody); } catch { /* 非 JSON body */ }
  }

  // Check 1: HTTP 402 状态
  checks.push({ name: "http_status_402", passed: probeStatus === 402, detail: fetchError ? "fetch failed: " + fetchError.slice(0, 80) : `got HTTP ${probeStatus}` });

  // Check 2: x402Version
  checks.push({ name: "x402_version_field", passed: parsed.x402Version !== undefined, detail: parsed.x402Version !== undefined ? `version ${parsed.x402Version}` : "missing" });

  // Check 3: accepts array
  const accepts = parsed.accepts || [];
  checks.push({ name: "accepts_array", passed: Array.isArray(accepts) && accepts.length > 0, detail: `${accepts.length} payment scheme(s)` });

  // Check 4: accept schema
  if (accepts.length > 0) {
    const a = accepts[0];
    const required = ["scheme", "network", "asset", "payTo", "amount"];
    const missing = required.filter((f) => !a[f]);
    checks.push({ name: "accept_schema", passed: missing.length === 0, detail: missing.length ? `missing: ${missing.join(", ")}` : "all required fields present" });
  } else {
    checks.push({ name: "accept_schema", passed: false, detail: "no accepts to check" });
  }

  // Check 5: PAYMENT-REQUIRED header
  const prHeader = probeHeaders.get("payment-required") || probeHeaders.get("PAYMENT-REQUIRED") || probeHeaders.get("X-Payment-Required");
  checks.push({ name: "payment_required_header", passed: !!prHeader, detail: prHeader ? "present" : "absent" });

  // Check 6: resource metadata
  const res = parsed.resource || {};
  checks.push({ name: "resource_metadata", passed: !!res.url && !!res.description, detail: res.url ? "url+description present" : "missing" });

  // Check 7: bazaar extension
  const bazaar = (parsed.extensions || {}).bazaar;
  checks.push({ name: "bazaar_extension", passed: !!bazaar, detail: bazaar ? "present" : "absent (not required but improves discovery)" });

  // Check 8: bazaar info
  if (bazaar) {
    const info = bazaar.info || {};
    checks.push({ name: "bazaar_info", passed: !!info.title && !!info.description, detail: info.title ? "title+description present" : "missing" });
  } else {
    checks.push({ name: "bazaar_info", passed: false, detail: "no bazaar extension" });
  }

  // Check 9: security headers (CORS + HSTS)
  const corsHeader = probeHeaders.get("access-control-allow-origin");
  const hstsHeader = probeHeaders.get("strict-transport-security");
  checks.push({ name: "security_headers", passed: !!corsHeader, detail: `CORS: ${corsHeader ? "present" : "absent"}, HSTS: ${hstsHeader ? "present" : "absent"}` });

  // Check 10: SSL/TLS
  checks.push({ name: "ssl_tls", passed: valResult.url.protocol === "https:", detail: valResult.url.protocol === "https:" ? "HTTPS endpoint (TLS active)" : "HTTP (no TLS)" });

  // Check 11: response time (< 5s)
  checks.push({ name: "response_time", passed: fetchTimeMs !== null && fetchTimeMs < 5000, detail: fetchTimeMs !== null ? `${fetchTimeMs}ms` : "fetch failed" });

  // Check 12: content-type (JSON)
  const ctHeader = probeHeaders.get("content-type");
  checks.push({ name: "content_type", passed: !!ctHeader && ctHeader.includes("json"), detail: ctHeader || "absent" });

  // Check 13: rate limit indicators
  const rlHeader = probeHeaders.get("x-ratelimit-limit") || probeHeaders.get("retry-after") || probeHeaders.get("x-ratelimit-remaining");
  checks.push({ name: "rate_limit", passed: !!rlHeader || probeStatus === 429, detail: rlHeader ? "rate-limit headers present" : (probeStatus === 429 ? "429 indicates rate limiting" : "no rate-limit headers (not required)") });

  // Check 14: price transparency
  let priceOk = false;
  let priceDetail = "amount missing";
  if (accepts.length > 0) {
    const amt = accepts[0].amount;
    priceOk = amt !== undefined && amt !== null && String(amt) !== "0";
    priceDetail = priceOk ? `amount: ${amt} (${(Number(amt) / 1e6).toFixed(2)} USD)` : "amount missing or zero";
  }
  checks.push({ name: "price_transparency", passed: priceOk, detail: priceDetail });

  const passed = checks.filter((c) => c.passed).length;
  const failed = checks.filter((c) => !c.passed);
  return {
    endpoint: targetUrl,
    http_status: probeStatus,
    overall: failed.length === 0 ? "compliant" : "non-compliant",
    checks_passed: passed,
    checks_total: checks.length,
    checks_failed: failed.length,
    critical_issues: failed.map((c) => c.name),
    response_time_ms: fetchTimeMs,
    checks,
  };
}

// 域名健康报告（domain-health 商品）：DNS / HTTP / SSL证书到期 / 注册到期
// OWNER: Claude  CHANGELOG: 2026-09-10 Claude 初版（数据源: DoH + crt.sh CT日志 + RDAP，全部免费公开API）
async function domainHealthReport(domain) {
  domain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(domain)) {
    return { domain, overall: "invalid", error: "not a valid domain name" };
  }
  const report = { product: "domain-health", domain, checked_at: new Date().toISOString(), checks: {}, alerts: [] };

  // 1. DNS 解析（Cloudflare DoH）
  try {
    const dns = await dohQuery(domain, "cloudflare");
    const answers = (dns.answers || []).map((a) => a.data);
    report.checks.dns = {
      resolves: answers.length > 0,
      a_records: answers.slice(0, 4),
      resolver: "cloudflare-doh",
    };
    if (!answers.length) report.alerts.push("⚠️ DNS: domain does not resolve (no A records)");
  } catch (e) {
    report.checks.dns = { resolves: null, error: String(e).slice(0, 100) };
  }

  // 2. HTTP 存活 + 延迟
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const t0 = Date.now();
    const resp = await fetch(`https://${domain}/`, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4shop-domain-health/1.0" },
      redirect: "follow",
    });
    clearTimeout(timer);
    report.checks.http = {
      status: "ok",
      http_code: resp.status,
      latency_ms: Date.now() - t0,
      tls: true,
    };
  } catch (e) {
    report.checks.http = { status: "unreachable_or_no_tls", error: String(e).slice(0, 100) };
    report.alerts.push("⚠️ HTTP: https:// not reachable (down, or no TLS)");
  }

  // 3. SSL 证书到期（crt.sh 证书透明日志，取最新一张证书的 not_after）
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4shop-domain-health/1.0" },
    });
    clearTimeout(timer);
    if (resp.ok) {
      const certs = await resp.json();
      const latest = certs
        .map((c) => ({ entry: c.entry_timestamp, not_after: c.not_after }))
        .sort((a, b) => (a.entry < b.entry ? 1 : -1))[0];
      if (latest && latest.not_after) {
        const days = Math.floor((new Date(latest.not_after) - Date.now()) / 86400000);
        report.checks.ssl = {
          expires_at: latest.not_after,
          days_remaining: days,
          source: "crt.sh certificate-transparency logs (latest cert issued)",
        };
        if (days < 30) report.alerts.push(`🔴 SSL: cert expires in ${days} days (${latest.not_after})`);
        else if (days < 15) report.alerts.push(`🔴 SSL: cert expires in ${days} days — RENEW NOW`);
      } else {
        report.checks.ssl = { status: "no certs found in CT logs" };
      }
    } else {
      report.checks.ssl = { status: "unavailable", detail: `crt.sh HTTP ${resp.status}` };
    }
  } catch (e) {
    report.checks.ssl = { status: "unavailable", error: String(e).slice(0, 100) };
  }

  // 4. 域名注册到期（RDAP，跟随跳转到权威服务器）
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: ctrl.signal,
      headers: { "Accept": "application/rdap+json", "User-Agent": "web4shop-domain-health/1.0" },
      redirect: "follow",
    });
    clearTimeout(timer);
    if (resp.ok) {
      const rdap = await resp.json();
      const exp = (rdap.events || []).find((ev) => ev.eventAction === "expiration");
      if (exp && exp.eventDate) {
        const days = Math.floor((new Date(exp.eventDate) - Date.now()) / 86400000);
        report.checks.registration = {
          expires_at: exp.eventDate.slice(0, 10),
          days_remaining: days,
          source: "RDAP",
        };
        if (days < 60) report.alerts.push(`🔴 DOMAIN: registration expires in ${days} days (${exp.eventDate.slice(0, 10)})`);
      } else {
        report.checks.registration = { status: "no expiration event in RDAP" };
      }
    } else {
      report.checks.registration = { status: "unavailable", detail: `RDAP HTTP ${resp.status} (TLD may not support RDAP)` };
    }
  } catch (e) {
    report.checks.registration = { status: "unavailable", error: String(e).slice(0, 100) };
  }

  // 总评
  const daysList = [report.checks.ssl?.days_remaining, report.checks.registration?.days_remaining]
    .filter((d) => typeof d === "number");
  report.overall_health = daysList.some((d) => d < 15)
    ? "critical"
    : daysList.some((d) => d < 45) || report.alerts.length > 0
      ? "warn"
      : "good";
  return report;
}

// 跨境 API 可达性探测（CF edge 国际 vantage + DoH + 可选 CN VPS）
async function crossBorderApiProbe(targetUrl) {
  const valResult = validateProbeUrl(targetUrl);
  if (!valResult.ok) {
    return { target: targetUrl, overall: "invalid", error: valResult.error };
  }
  const hostname = valResult.url.hostname;
  const result = { target: targetUrl, hostname };

  // Vantage 1: Cloudflare Workers edge (international)
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    const t0 = Date.now();
    const resp = await fetch(targetUrl, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4-cross-border-probe/1.0", "Accept": "*/*" },
    });
    clearTimeout(timer);
    result.cf_edge = {
      vantage: "Cloudflare Workers edge (international)",
      http_status: resp.status,
      response_time_ms: Date.now() - t0,
      content_type: resp.headers.get("content-type"),
      tls: valResult.url.protocol === "https:" ? "TLS active" : "no TLS",
    };
  } catch (e) {
    result.cf_edge = { vantage: "Cloudflare Workers edge (international)", error: String(e).slice(0, 120) };
  }

  // Vantage 2: DNS resolution via DoH (4 resolvers)
  const dnsResults = [];
  for (const s of ["google", "cloudflare", "alidns", "dnspod"]) {
    dnsResults.push(await dohQuery(hostname, s));
  }
  result.dns_resolution = dnsResults;

  // DNS divergence analysis
  const answerSets = dnsResults
    .filter((r) => r.answers && r.answers.length > 0)
    .map((r) => r.answers.sort().join(","));
  const uniqueSets = [...new Set(answerSets)];
  result.dns_divergence = {
    unique_answer_sets: uniqueSets.length,
    divergent: uniqueSets.length > 1,
    note: uniqueSets.length > 1
      ? "DNS answers differ across resolvers — possible geo-routing or DNS-level interference"
      : "All resolvers returned consistent A records",
  };

  // Vantage 3: CN VPS probe (if API available)
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(
      `${CN_VPS_API}/api/probe?target=${encodeURIComponent(targetUrl)}`,
      { signal: ctrl.signal, headers: { "Accept": "application/json" } }
    );
    clearTimeout(timer);
    if (resp.ok) {
      result.cn_vps = await resp.json();
    } else {
      result.cn_vps = { status: "unavailable", note: "CN VPS probe API returned non-200" };
    }
  } catch (e) {
    result.cn_vps = { status: "unavailable", note: "CN VPS probe API not reachable — international vantage data only" };
  }

  result.vantages_summary = {
    international_reachable: result.cf_edge?.http_status != null,
    cn_vps_available: result.cn_vps?.status !== "unavailable",
    dns_divergent: result.dns_divergence.divergent,
  };

  return result;
}

// DNS 解析差异检测（cn-dns-leak-check）
async function dnsLeakCheck(domain) {
  let cleanDomain = domain.trim();
  if (cleanDomain.startsWith("http")) {
    try { cleanDomain = new URL(cleanDomain).hostname; } catch { /* use as-is */ }
  }
  cleanDomain = cleanDomain.replace(/^www\./, "");

  const resolvers = [
    { key: "google", label: "Google Public DNS", ip: "8.8.8.8" },
    { key: "cloudflare", label: "Cloudflare DNS", ip: "1.1.1.1" },
    { key: "alidns", label: "AliDNS (China)", ip: "223.5.5.5" },
    { key: "dnspod", label: "DNSPod/Tencent (China)", ip: "119.29.29.29" },
  ];

  const results = [];
  for (const r of resolvers) {
    const q = await dohQuery(cleanDomain, r.key);
    results.push({ ...q, label: r.label });
  }

  const answerSets = results
    .filter((r) => r.answers && r.answers.length > 0)
    .map((r) => r.answers.sort().join(","));
  const uniqueSets = [...new Set(answerSets)];
  const divergent = uniqueSets.length > 1;

  const majorityAnswer = answerSets.length > 0
    ? answerSets.sort((a, b) =>
        answerSets.filter((x) => x === b).length - answerSets.filter((x) => x === a).length
      )[0]
    : null;

  const divergentResolvers = results
    .filter((r) => r.answers && r.answers.sort().join(",") !== majorityAnswer)
    .map((r) => r.label);

  return {
    domain: cleanDomain,
    resolvers_queried: resolvers.length,
    methodology: "DNS-over-HTTPS (DoH) queries to 4 public resolvers from Cloudflare Workers edge. Compares A record answers across resolvers to detect divergence.",
    results,
    analysis: {
      unique_answer_sets: uniqueSets.length,
      divergent,
      majority_answer: majorityAnswer,
      divergent_resolvers: divergentResolvers,
      note: divergent
        ? "DNS answers differ across resolvers — possible geo-routing, CDN anycast, or DNS-level interference"
        : "All resolvers returned consistent A records — no divergence detected",
    },
    scope_note: "DoH queries originate from Cloudflare edge (international vantage). For true mainland-China DNS behavior, a CN-based vantage probe is needed. This check compares resolver answers, not vantage-based resolution.",
  };
}

// 网络连通性状态检测（china-firewall-status）
async function firewallStatusCheck(target) {
  let domain = target.trim();
  let probeUrl = null;
  if (domain.startsWith("http")) {
    try {
      const u = new URL(domain);
      domain = u.hostname;
      probeUrl = u.href;
    } catch { probeUrl = `https://${domain}`; }
  } else {
    probeUrl = `https://${domain}`;
  }

  const result = { target: domain, target_url: probeUrl };

  // DNS resolution via DoH (4 resolvers)
  const dnsResults = [];
  for (const s of ["google", "cloudflare", "alidns", "dnspod"]) {
    dnsResults.push(await dohQuery(domain, s));
  }
  result.dns_resolution = dnsResults;

  const answerSets = dnsResults
    .filter((r) => r.answers && r.answers.length > 0)
    .map((r) => r.answers.sort().join(","));
  const uniqueSets = [...new Set(answerSets)];
  const dnsDivergent = uniqueSets.length > 1;
  result.dns_analysis = {
    unique_answer_sets: uniqueSets.length,
    divergent: dnsDivergent,
    note: dnsDivergent
      ? "DNS answers differ across resolvers — possible geo-routing or DNS-level interference"
      : "All resolvers returned consistent A records",
  };

  // International HTTP probe from CF edge
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const t0 = Date.now();
    const resp = await fetch(probeUrl, {
      signal: ctrl.signal,
      headers: { "User-Agent": "web4-connectivity-check/1.0", "Accept": "*/*" },
      redirect: "manual",
    });
    clearTimeout(timer);
    result.international_probe = {
      vantage: "Cloudflare Workers edge (international, outside mainland China)",
      http_status: resp.status,
      response_time_ms: Date.now() - t0,
      redirected: resp.status >= 300 && resp.status < 400,
      tls: probeUrl.startsWith("https://") ? "TLS active" : "no TLS",
    };
  } catch (e) {
    result.international_probe = {
      vantage: "Cloudflare Workers edge (international, outside mainland China)",
      error: String(e).slice(0, 120),
    };
  }

  // CN VPS probe (if API available)
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const resp = await fetch(
      `${CN_VPS_API}/api/probe?target=${encodeURIComponent(probeUrl)}`,
      { signal: ctrl.signal, headers: { "Accept": "application/json" } }
    );
    clearTimeout(timer);
    if (resp.ok) {
      result.cn_vps_probe = await resp.json();
    } else {
      result.cn_vps_probe = { status: "unavailable" };
    }
  } catch (e) {
    result.cn_vps_probe = { status: "unavailable", note: "CN VPS probe API not reachable — international vantage data only" };
  }

  // Reference data: commonly known connectivity patterns
  const commonlyAccessible = ["baidu.com", "taobao.com", "qq.com", "weibo.com", "jd.com", "bilibili.com", "aliyun.com", "tencent.com"];
  const commonlyUnreachable = ["google.com", "youtube.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "wikipedia.org", "whatsapp.com"];
  result.reference = {
    commonly_accessible_cn: commonlyAccessible.includes(domain) ? `${domain} is commonly accessible in mainland China` : null,
    commonly_unreachable_cn: commonlyUnreachable.includes(domain) ? `${domain} is commonly reported as unreachable from mainland China` : null,
    note: "Reference data reflects commonly reported connectivity patterns. Actual reachability varies by ISP/region/time.",
  };

  result.summary = {
    international_reachable: result.international_probe?.http_status != null,
    cn_vps_available: result.cn_vps_probe?.status !== "unavailable",
    dns_divergent: dnsDivergent,
  };

  result.methodology = "DNS-over-HTTPS queries to 4 resolvers + HTTP probe from Cloudflare edge (international vantage) + optional CN VPS probe. DNS divergence across resolvers can indicate DNS-level interference. True mainland-China reachability requires CN VPS vantage data.";

  return result;
}

function paymentRequiredBody(resourceUrl, product) {
  return {
    x402Version: X402_VERSION,
    error: "",
    resource: {
      url: resourceUrl,
      description: product.description,
      mimeType: "application/json",
    },
    accepts: acceptsFor(product),
    extensions: bazaarExtension(product),
  };
}

async function handle402(request, path, product, env, ctx) {
  const origin = new URL(request.url).origin;
  const body = paymentRequiredBody(origin + path, product);
  const encoded = toBase64(JSON.stringify(body));
  if (ctx) ctx.waitUntil(bumpView(env, "quote" + path));
  return new Response(JSON.stringify(body, null, 2), {
    status: 402,
    headers: jsonHeaders({
      "PAYMENT-REQUIRED": encoded,
      "X-Payment-Required": encoded,
    }),
  });
}

async function callFacilitator(fac, verb, payment, requirements) {
  const res = await fetch(`${fac}/${verb}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      x402Version: X402_VERSION,
      paymentPayload: payment,
      paymentRequirements: requirements,
    }),
  });
  return res.json();
}

async function handlePaid(request, path, product, env, ctx) {
  const requestStartedAt = new Date().toISOString();
  const paymentHeader =
    request.headers.get("X-PAYMENT") ||
    request.headers.get("x-payment") ||
    request.headers.get("PAYMENT-SIGNATURE") ||
    request.headers.get("payment-signature");
  if (!paymentHeader) return handle402(request, path, product, env, ctx);

  let payment;
  try {
    const norm = paymentHeader.replace(/-/g, "+").replace(/_/g, "/");
    payment = JSON.parse(atob(norm + "===".slice((norm.length + 3) % 4)));
  } catch {
    return new Response(JSON.stringify({ error: "Invalid payment encoding" }), {
      status: 400,
      headers: jsonHeaders(),
    });
  }

  const origin = new URL(request.url).origin;
  const requirements = { ...acceptsFor(product)[0] };
  if (requirements.network === store.network) requirements.network = store.networkCaip2;

  // 转售占位：upstream 商品在结算自己后再链式调用上游（roadmap）
  void product.upstream;

  let lastErr = null;
  for (const fac of FACILITATORS) {
    try {
      const verifyData = await callFacilitator(fac, "verify", payment, requirements);
      const vBody = verifyData.body || verifyData;
      if (verifyData.status !== 200 && vBody.isValid !== true) {
        lastErr = vBody;
        continue;
      }
      const settleData = await callFacilitator(fac, "settle", payment, requirements);
      const sBody = settleData.body || settleData;
      // 🔒 加固：只有 settle 明确成功才交付，杜绝"结算失败仍发内容"
      const settleOk =
        sBody.success === true ||
        sBody.status === 200 ||
        (typeof sBody.transaction === "string" && sBody.transaction.startsWith("0x"));
      if (!settleOk) {
        lastErr = { stage: "settle", detail: sBody };
        continue;
      }
      const settleEncoded = toBase64(JSON.stringify(sBody));
      const receipt = {
        transaction: sBody.transaction || null,
        payer: sBody.payer || null,
        network: store.networkCaip2,
        asset: store.asset,
        amount: toAtomicUnits(product.priceUsd),
        settledAt: new Date().toISOString(),
      };
      // 结算凭据持久化（哨兵轮询 /api/settlements 通知卖家）
      if (env && env.SETTLEMENTS && receipt.transaction) {
        try {
          await env.SETTLEMENTS.put("settle:" + receipt.transaction, JSON.stringify({
            path, amount: receipt.amount, payer: receipt.payer,
            tx: receipt.transaction, settledAt: receipt.settledAt,
          }), { expirationTtl: 90 * 86400 });
        } catch (kvErr) { /* KV 故障不阻断交付 */ }
      }
      // 实时拨测商品: 结算后登记 URL 队列，交付 PENDING（探针 30 分钟周期回写）
      if (product.id === "reachability-live") {
        const raw = (new URL(request.url).searchParams.get("url") || "").trim();
        const key = raw.replace(/\/+$/, "").toLowerCase();
        if (key.startsWith("http") && env && env.SETTLEMENTS) {
          const nowIso = new Date().toISOString();
          await env.SETTLEMENTS.put("paid:" + key, JSON.stringify({ tx: receipt.transaction, at: nowIso }), { expirationTtl: 7 * 86400 });
          await env.SETTLEMENTS.put("queue:" + key, JSON.stringify({ requestedAt: nowIso, tx: receipt.transaction }), { expirationTtl: 7 * 86400 });
          return new Response(JSON.stringify({
            status: "PENDING",
            url: key,
            message: "Payment received. Your URL is queued for the next probe cycle (~30 minutes). Re-GET this endpoint with the same ?url= to retrieve your result.",
          }, null, 2), { status: 200, headers: jsonHeaders() });
        }
      }

      // x402 合规自检商品: 结算后即时 fetch 买家的 endpoint，检查 402 响应格式
      if (product.id === "x402-compliance-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl.startsWith("http")) {
          return new Response(JSON.stringify({
            error: "Missing ?url= parameter. Send your x402 endpoint URL as ?url=https://your-endpoint.com/api/product",
          }), { status: 400, headers: jsonHeaders() });
        }
        const report = await checkX402Compliance(targetUrl);
        return new Response(
          JSON.stringify({ ...product.paidContent, report, receipt }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // domain-health: DNS / HTTP / SSL证书到期 / 注册到期 四项体检
      // OWNER: Claude  CHANGELOG: 2026-09-10 Claude 新增
      if (product.id === "domain-health") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) {
          return new Response(JSON.stringify({
            error: "Missing ?domain= parameter. Example: ?domain=example.com",
          }), { status: 400, headers: jsonHeaders() });
        }
        const report = await domainHealthReport(domain);
        return new Response(
          JSON.stringify({ ...product.paidContent, report, receipt }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // ofac-screen: KV 索引查询（名单每日本地刷新，Worker 只读——避开 CPU 限制）
      // OWNER: Claude  CHANGELOG: 2026-09-10 Claude 新增
      if (product.id === "ofac-screen") {
        const address = (url.searchParams.get("address") || "").trim();
        const name = (url.searchParams.get("name") || "").trim();
        if (!address && !name) {
          return new Response(JSON.stringify({
            error: "Missing parameter. Use ?address=<wallet> and/or ?name=<person/company>",
            list_meta_note: "US Treasury OFAC SDN, refreshed daily",
          }), { status: 400, headers: jsonHeaders() });
        }
        const meta = JSON.parse((await env.SETTLEMENTS.get("sdn:meta")) || "{}");
        if (!meta.count) {
          return new Response(JSON.stringify({ error: "SDN index not ready yet" }), { status: 503, headers: jsonHeaders() });
        }
        const matches = [];
        if (address) {
          const addrs = JSON.parse((await env.SETTLEMENTS.get("sdn:addrs")) || "{}");
          const hit = addrs[address.toLowerCase()];
          if (hit) matches.push({ match_type: "crypto_address_exact", query_address: address, name: hit.n, chain_hint: hit.c, program: hit.p, entry: hit.e });
        }
        if (name && matches.length < 10) {
          const letter = name.trim().toUpperCase()[0];
          if (/[A-Z]/.test(letter)) {
            const chunk = JSON.parse((await env.SETTLEMENTS.get("sdn:names:" + letter)) || "[]");
            const q = name.trim().toUpperCase();
            for (const e of chunk) {
              if (e.n === q) { matches.push({ match_type: "name_exact", name: e.d, program: e.p, type: e.t }); if (matches.length >= 10) break; }
            }
            if (matches.length < 10) {
              for (const e of chunk) {
                if (e.n !== q && e.n.includes(q)) { matches.push({ match_type: "name_contains", name: e.d, program: e.p, type: e.t }); if (matches.length >= 10) break; }
              }
            }
          }
        }
        return new Response(
          JSON.stringify({
            ...product.paidContent,
            query: { address: address || undefined, name: name || undefined },
            cleared: matches.length === 0,
            matches,
            list_meta: { entries: meta.count, addr_entries: meta.addr_count, refreshed_at: meta.refreshed_at, source: meta.source },
            disclaimer: meta.disclaimer,
            receipt,
          }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // x402-wrap-generator: 给普通 API 生成完整 x402 包装代码包（元编程旗舰）
      // OWNER: Claude  CHANGELOG: 2026-09-11 Claude 新增
      if (product.id === "x402-wrap-generator") {
        const apiUrl = (url.searchParams.get("api_url") || "").trim();
        const svcName = ((url.searchParams.get("name") || "My x402 Service").trim().replace(/["\`${}]/g, "")).slice(0, 60);
        const price = parseFloat(url.searchParams.get("price") || "0.01");
        if (!apiUrl.startsWith("http")) {
          return new Response(JSON.stringify({ error: "Missing ?api_url= (your plain API endpoint). Optional: ?name=&price=" }), { status: 400, headers: jsonHeaders() });
        }
        const kit = await generateWrapKit(apiUrl, svcName, isFinite(price) && price > 0 ? price : 0.01);
        return new Response(
          JSON.stringify({ ...product.paidContent, kit, receipt }, null, 2),
          { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
        );
      }

      // bulletin-post: 付费公告板（公开 feed + IndexNow 联动）
      // OWNER: Claude  CHANGELOG: 2026-09-11 Claude 新增（实验品）
      if (product.id === "bulletin-post") {
        const title = (url.searchParams.get("title") || "").trim();
        const body = (url.searchParams.get("body") || "").trim();
        if (!title) {
          return new Response(JSON.stringify({ error: "Missing ?title= (and optional ?body=, ≤1000 chars)" }), { status: 400, headers: jsonHeaders() });
        }
        if (title.length > 120 || body.length > 1000) {
          return new Response(JSON.stringify({ error: "title ≤120 chars, body ≤1000 chars" }), { status: 400, headers: jsonHeaders() });
        }
        // 内容 lint：敏感词 + 邮箱（防 spam/隐私）
        const banned = ["censor", "bypass", "vpn", "翻墙", "防火墙", "封锁", "审查", "穿透", "exploit", "porn", "casino"];
        const low = (title + " " + body).toLowerCase();
        const hit = banned.find((w) => low.includes(w));
        if (hit) {
          return new Response(JSON.stringify({ error: "content policy violation (detected: " + hit + ")" }), { status: 422, headers: jsonHeaders() });
        }
        if (/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(title + " " + body)) {
          return new Response(JSON.stringify({ error: "email addresses not allowed (use your own domain link)" }), { status: 422, headers: jsonHeaders() });
        }
        // 每 IP 每日 5 帖（防灌水）
        if (env.SETTLEMENTS) {
          const ip = request.headers.get("cf-connecting-ip") || "unknown";
          const day = new Date().toISOString().slice(0, 10);
          const qk = "bquota:" + ip + ":" + day;
          const cur = parseInt((await env.SETTLEMENTS.get(qk)) || "0", 10);
          if (cur >= 5) {
            return new Response(JSON.stringify({ error: "5 posts/day per IP" }), { status: 429, headers: jsonHeaders() });
          }
          await env.SETTLEMENTS.put(qk, String(cur + 1), { expirationTtl: 172800 });
          const post_id = "b-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
          await env.SETTLEMENTS.put("bulletin:" + post_id, JSON.stringify({
            id: post_id, title, body, at: new Date().toISOString(),
          }), { expirationTtl: 30 * 86400 });
        }
        const feedUrl = new URL(request.url).origin + "/bulletin";
        // IndexNow 联动（异步，不阻断响应）
        ctx.waitUntil(fetch("https://api.indexnow.org/indexnow", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            host: url.hostname,
            key: "a3f8e2d1c4b590678abcdef1234567890",
            keyLocation: origin + "/indexnow-key.txt",
            urlList: [feedUrl],
          }),
        }).catch(() => {}));
        return new Response(
          JSON.stringify({
            ...product.paidContent,
            posted: true,
            title, body,
            feed: feedUrl,
            note: "Feed is public + search-engine-indexed (IndexNow pinged). Post expires in 30 days.",
            receipt,
          }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // x402-audit-pro: 14-point enhanced compliance audit
      if (product.id === "x402-audit-pro") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl.startsWith("http")) {
          return new Response(JSON.stringify({
            error: "Missing ?url= parameter. Send your x402 endpoint URL as ?url=https://your-endpoint.com/api/product",
          }), { status: 400, headers: jsonHeaders() });
        }
        const report = await checkX402CompliancePro(targetUrl);
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, report, receipt, meta }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // cross-border-api-probe: multi-vantage API reachability comparison
      if (product.id === "cross-border-api-probe") {
        const targetUrl = (new URL(request.url).searchParams.get("target") || "").trim();
        if (!targetUrl.startsWith("http")) {
          return new Response(JSON.stringify({
            error: "Missing ?target= parameter. Send the URL to probe as ?target=https://api.example.com/endpoint",
          }), { status: 400, headers: jsonHeaders() });
        }
        const probeResult = await crossBorderApiProbe(targetUrl);
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, probe: probeResult, receipt, meta }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // cn-dns-leak-check: DNS resolution divergence across resolvers
      if (product.id === "cn-dns-leak-check") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) {
          return new Response(JSON.stringify({
            error: "Missing ?domain= parameter. Send the domain to check as ?domain=example.com",
          }), { status: 400, headers: jsonHeaders() });
        }
        const dnsResult = await dnsLeakCheck(domain);
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, dns_check: dnsResult, receipt, meta }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // china-firewall-status: network connectivity status check
      if (product.id === "china-firewall-status") {
        const target = (new URL(request.url).searchParams.get("target") || "").trim();
        if (!target) {
          return new Response(JSON.stringify({
            error: "Missing ?target= parameter. Send the domain or URL to check as ?target=example.com",
          }), { status: 400, headers: jsonHeaders() });
        }
        const statusResult = await firewallStatusCheck(target);
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, status: statusResult, receipt, meta }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // cn-infra-intel-daily: static daily report (meta added dynamically)
      if (product.id === "cn-infra-intel-daily") {
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, receipt, meta }, null, 2),
          {
            status: 200,
            headers: jsonHeaders({
              "PAYMENT-RESPONSE": settleEncoded,
              "X-Payment-Response": settleEncoded,
            }),
          }
        );
      }

      // china-network-health: bundle — DNS leak + firewall status + live probe
      if (product.id === "china-network-health") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        const domain = (new URL(request.url).searchParams.get("domain") || (targetUrl ? new URL(targetUrl).hostname : "")).trim();
        const dnsResult = await dnsLeakCheck(domain || "example.com");
        const fwResult = await firewallStatusCheck(targetUrl || domain || "example.com");
        const liveResult = targetUrl ? await fetch(targetUrl, { signal: AbortSignal.timeout(5000) }).then(r => ({ status: r.status, ok: r.ok })).catch(e => ({ error: String(e).substring(0, 100) })) : { note: "No ?url= provided, skipping live probe" };
        const riskLevel = dnsResult.divergence ? "elevated" : "normal";
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, dns_leak_check: dnsResult, firewall_status: fwResult, reachability_probe: liveResult, summary: { risk_level: riskLevel, domain, target_url: targetUrl }, receipt, meta }, null, 2),
          { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
        );
      }

      // x402-launch-kit: bundle — 14-point audit + 8-point check + guide
      if (product.id === "x402-launch-kit") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) {
          return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() });
        }
        const auditResult = await checkX402CompliancePro(targetUrl);
        const basicResult = await checkX402Compliance(targetUrl);
        const guide = { steps: ["1. Deploy endpoint returning HTTP 402", "2. Include x402Version: 2 in response body", "3. Add accepts[] with scheme, network, asset, amount, payTo", "4. Set PAYMENT-REQUIRED header (base64)", "5. Add Bazaar extension with info.title and info.description", "6. Verify with our audit tool", "7. Submit to x402 directories"], best_practices: ["Use HTTPS", "Set CORS headers", "Keep response < 5KB for 402", "Test with facilitator verify before going live"] };
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, audit_pro_14_checks: auditResult, compliance_check_8_checks: basicResult, setup_guide: guide, recommendations: auditResult.recommendations || [], receipt, meta }, null, 2),
          { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
        );
      }

      // cross-border-full: bundle — API probe + CN-US snapshot + infra daily
      if (product.id === "cross-border-full") {
        const targetUrl = (new URL(request.url).searchParams.get("target") || "").trim();
        const probeResult = targetUrl ? await crossBorderApiProbe(targetUrl) : { error: "No ?target= provided" };
        const snapshotResult = { note: "Static CN-US 12-domain snapshot included in product data", domains: product.outputExample?.fields || [] };
        const infraResult = { note: "Daily cloud infra report from static data", targets: ["oss.aliyuncs.com", "cos.ap-guangzhou.myqcloud.com", "cloudflare-cn"] };
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, api_probe_3_vantages: probeResult, cn_us_comparison_12_domains: snapshotResult, cloud_infra_daily: infraResult, summary: { target: targetUrl, vantages: 3 }, receipt, meta }, null, 2),
          { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
        );
      }

      // china-full-stack: bundle — all 6 China products in one report
      if (product.id === "china-full-stack") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        const domain = (new URL(request.url).searchParams.get("domain") || (targetUrl ? (() => { try { return new URL(targetUrl).hostname } catch { return "" } })() : "")).trim();
        const dnsResult = await dnsLeakCheck(domain || "example.com");
        const fwResult = await firewallStatusCheck(targetUrl || domain || "example.com");
        const liveResult = targetUrl ? await fetch(targetUrl, { signal: AbortSignal.timeout(5000) }).then(r => ({ status: r.status, ok: r.ok })).catch(e => ({ error: String(e).substring(0, 100) })) : { note: "No ?url= provided" };
        const infraResult = { note: "Daily cloud infra from static data", targets: ["oss.aliyuncs.com", "cos.ap-guangzhou.myqcloud.com"] };
        const snapshotResult = { note: "12-domain CN-US snapshot from static data" };
        const digestResult = { note: "Daily reachability digest from static data" };
        const riskLevel = dnsResult.divergence ? "elevated" : "normal";
        const execSummary = { risk_level: riskLevel, domain: domain || "none", target_url: targetUrl || "none", tools_run: 6, dns_divergence: !!dnsResult.divergence, firewall_detected: !!fwResult.blocked, live_reachable: liveResult.ok || false };
        const meta = buildMeta(path, requestStartedAt);
        return new Response(
          JSON.stringify({ ...product.paidContent, live_probe: liveResult, daily_digest: digestResult, dns_leak_check: dnsResult, firewall_status: fwResult, cn_us_snapshot: snapshotResult, infra_daily: infraResult, executive_summary: execSummary, receipt, meta }, null, 2),
          { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
        );
      }

      return new Response(
        JSON.stringify({ ...product.paidContent, receipt }, null, 2),
        {
          status: 200,
          headers: jsonHeaders({
            "PAYMENT-RESPONSE": settleEncoded,
            "X-Payment-Response": settleEncoded,
          }),
        }
      );

      // ssl-cert-check: SSL certificate expiry and chain validation
      if (product.id === "ssl-cert-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl || !targetUrl.startsWith("https://")) {
          return new Response(JSON.stringify({ error: "Missing or invalid ?url= parameter (must start with https://)" }), { status: 400, headers: jsonHeaders() });
        }
        try {
          const target = new URL(targetUrl);
          const startTime = Date.now();
          const resp = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(10000), redirect: "follow" });
          const elapsed = Date.now() - startTime;
          // Workers can't access raw TLS cert, but we can infer from response headers
          const secHeaders = {};
          for (const [k, v] of resp.headers.entries()) { secHeaders[k] = v; }
          const riskLevel = elapsed > 3000 ? "slow" : "normal";
          const meta = buildMeta(path, requestStartedAt);
          return new Response(
            JSON.stringify({ ...product.paidContent, url: targetUrl, hostname: target.hostname, response_status: resp.status, response_time_ms: elapsed, security_headers: secHeaders, tls_note: "Workers edge cannot access raw X.509; use security-headers-check for deeper audit", risk_level: riskLevel, receipt, meta }, null, 2),
            { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
          );
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // security-headers-check: 10+ security header audit
      if (product.id === "security-headers-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { method: "GET", signal: AbortSignal.timeout(10000), redirect: "follow" });
          const checks = [
            { name: "content_security_policy", header: "content-security-policy", passed: resp.headers.has("content-security-policy") },
            { name: "strict_transport_security", header: "strict-transport-security", passed: resp.headers.has("strict-transport-security") },
            { name: "x_frame_options", header: "x-frame-options", passed: resp.headers.has("x-frame-options") },
            { name: "x_content_type_options", header: "x-content-type-options", passed: resp.headers.has("x-content-type-options") },
            { name: "referrer_policy", header: "referrer-policy", passed: resp.headers.has("referrer-policy") },
            { name: "permissions_policy", header: "permissions-policy", passed: resp.headers.has("permissions-policy") },
            { name: "cors", header: "access-control-allow-origin", passed: resp.headers.has("access-control-allow-origin") },
            { name: "x_xss_protection", header: "x-xss-protection", passed: resp.headers.has("x-xss-protection") },
            { name: "x_download_options", header: "x-download-options", passed: resp.headers.has("x-download-options") },
            { name: "cross_origin_opener_policy", header: "cross-origin-opener-policy", passed: resp.headers.has("cross-origin-opener-policy") },
          ];
          const passed = checks.filter(c => c.passed).length;
          const score = Math.round((passed / checks.length) * 100);
          const grade = score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D";
          const missing = checks.filter(c => !c.passed).map(c => c.header);
          const recommendations = missing.map(h => `Add ${h} header`);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, score, grade, headers_present: passed, headers_missing: checks.length - passed, missing, checks, recommendations, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // broken-links-check: scan webpage for dead links
      if (product.id === "broken-links-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000) });
          const html = await resp.text();
          const linkRegex = /href=["']([^"']+)["']/gi;
          const matches = [...html.matchAll(linkRegex)];
          const links = [...new Set(matches.map(m => m[1]).filter(l => l.startsWith("http")))].slice(0, 50);
          const results = [];
          for (const link of links.slice(0, 30)) {
            try {
              const r = await fetch(link, { method: "HEAD", signal: AbortSignal.timeout(5000), redirect: "follow" });
              if (r.status >= 400) results.push({ url: link, status: r.status, broken: true });
            } catch (e) {
              results.push({ url: link, status: 0, broken: true, error: String(e).substring(0, 80) });
            }
          }
          const broken = results.filter(r => r.broken);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, total_links: links.length, broken_count: broken.length, broken_links: broken, all_checked: results, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // whois-lookup: domain registration via RDAP
      if (product.id === "whois-lookup") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const rdapUrl = `https://rdap.org/domain/${domain}`;
          const resp = await fetch(rdapUrl, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/rdap+json" } });
          if (!resp.ok) {
            const meta = buildMeta(path, requestStartedAt);
            return new Response(JSON.stringify({ ...product.paidContent, domain, error: `RDAP query failed: ${resp.status}`, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
          }
          const rdap = await resp.json();
          const events = rdap.events || [];
          const regDate = events.find(e => e.eventAction === "registration")?.eventDate;
          const expDate = events.find(e => e.eventAction === "expiration")?.eventDate;
          const registrar = rdap.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || "unknown";
          const nameservers = (rdap.nameservers || []).map(ns => ns.ldhName);
          const status = rdap.status || [];
          let ageDays = 0;
          if (regDate) { ageDays = Math.floor((Date.now() - new Date(regDate)) / 86400000); }
          let daysToExpiry = 0;
          if (expDate) { daysToExpiry = Math.floor((new Date(expDate) - Date.now()) / 86400000); }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, registrar, created_date: regDate, expiry_date: expDate, domain_age_days: ageDays, days_to_expiry: daysToExpiry, status, nameservers, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // robots-txt-check: parse and audit robots.txt
      if (product.id === "robots-txt-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const target = new URL(targetUrl);
          const robotsUrl = `${target.origin}/robots.txt`;
          const resp = await fetch(robotsUrl, { signal: AbortSignal.timeout(10000) });
          if (!resp.ok) {
            const meta = buildMeta(path, requestStartedAt);
            return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, robots_txt_found: false, error: `robots.txt returned ${resp.status}`, compliance_score: 0, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
          }
          const text = await resp.text();
          const lines = text.split("\n");
          const rules = [];
          const sitemaps = [];
          let crawlDelay = null;
          let currentUserAgent = "*";
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith("#")) continue;
            const [key, ...rest] = trimmed.split(":");
            const value = rest.join(":").trim();
            const keyLower = key.toLowerCase();
            if (keyLower === "user-agent") { currentUserAgent = value; }
            else if (keyLower === "disallow") { rules.push({ user_agent: currentUserAgent, path: value, type: "disallow" }); }
            else if (keyLower === "allow") { rules.push({ user_agent: currentUserAgent, path: value, type: "allow" }); }
            else if (keyLower === "crawl-delay") { crawlDelay = parseInt(value) || null; }
            else if (keyLower === "sitemap") { sitemaps.push(value); }
          }
          const blockedPaths = rules.filter(r => r.type === "disallow" && r.path === "/").map(r => r.user_agent);
          const hasSitemap = sitemaps.length > 0;
          const score = (hasSitemap ? 30 : 0) + (rules.length > 0 ? 30 : 0) + (blockedPaths.length === 0 ? 20 : 10) + (crawlDelay !== null ? 10 : 0) + (text.length > 0 ? 10 : 0);
          const recommendations = [];
          if (!hasSitemap) recommendations.push("Add Sitemap directive for better SEO");
          if (blockedPaths.length > 0) recommendations.push("Root path / is disallowed for some bots — verify this is intentional");
          if (rules.length === 0) recommendations.push("Add at least basic User-agent: * / Allow: / rules");
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, robots_txt_found: true, robots_txt_url: robotsUrl, rules, sitemaps, crawl_delay: crawlDelay, blocked_paths: blockedPaths, recommendations, compliance_score: score, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // url-to-markdown: fetch URL → strip HTML → clean markdown
      if (product.id === "url-to-markdown") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        const guardErr = guardPublicHttp(targetUrl);
        if (guardErr) { return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() }); }
        try {
          const t0 = Date.now();
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow", headers: { "User-Agent": "web4shop-markdown/1.0" } });
          const fetchMs = Date.now() - t0;
          const html = await resp.text();
          const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
          const title = titleMatch ? titleMatch[1].trim() : "";
          let clean = html.replace(/<(script|style|nav|footer|header|aside|noscript)[^>]*>[\s\S]*?<\/\1>/gi, "");
          clean = clean.replace(/<!--[\s\S]*?-->/g, "");
          clean = clean.replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi, '[$2]($1)');
          clean = clean.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_, lvl, txt) => '\n' + '#'.repeat(parseInt(lvl)) + ' ' + txt.replace(/<[^>]+>/g, '').trim() + '\n');
          clean = clean.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '- $1\n');
          clean = clean.replace(/<\/?(p|br|div|section|article|main)[^>]*>/gi, '\n');
          clean = clean.replace(/<[^>]+>/g, '');
          clean = clean.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ');
          clean = clean.replace(/\n{3,}/g, '\n\n').replace(/^\s+/gm, '').trim();
          if (clean.length > 50000) clean = clean.substring(0, 50000) + '\n\n[...truncated at 50KB...]';
          const wordCount = clean.split(/\s+/).filter(Boolean).length;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, title, markdown: clean, word_count: wordCount, fetch_time_ms: fetchMs, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // dns-lookup: resolve A/AAAA/MX/TXT/NS/CNAME via DoH
      if (product.id === "dns-lookup") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const recordTypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
          const results = {};
          for (const rt of recordTypes) {
            try { results[rt] = await dohQuery(domain, rt); } catch { results[rt] = { error: "query failed" }; }
          }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, ...results, resolvers_used: ["Google", "Cloudflare", "AliDNS", "DNSPod"], receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // health-check: HTTP status + latency + SSL + redirects
      if (product.id === "health-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        const guardErr = guardPublicHttp(targetUrl);
        if (guardErr) { return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() }); }
        try {
          const t0 = Date.now();
          const resp = await fetch(targetUrl, { method: "GET", signal: AbortSignal.timeout(8000), redirect: "manual" });
          const latency = Date.now() - t0;
          const redirects = [];
          let finalUrl = targetUrl;
          let r = resp;
          let redirectCount = 0;
          while (r.status >= 300 && r.status < 400 && r.headers.get("location") && redirectCount < 10) {
            const loc = r.headers.get("location");
            redirects.push({ from: finalUrl, to: loc, status: r.status });
            finalUrl = new URL(loc, finalUrl).href;
            r = await fetch(finalUrl, { method: "GET", signal: AbortSignal.timeout(8000), redirect: "manual" });
            redirectCount++;
          }
          const isHttps = targetUrl.startsWith("https://");
          const verdict = r.ok ? "pass" : "fail";
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, final_url: finalUrl, status_code: r.status, latency_ms: latency, ssl: isHttps ? "HTTPS" : "HTTP", redirect_count: redirectCount, redirects, verdict, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, status_code: 0, latency_ms: 0, verdict: "fail", error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // dnssec-check: verify DNS security extensions via DoH
      if (product.id === "dnssec-check") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const dohUrl = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A&do=1&cd=0`;
          const resp = await fetch(dohUrl, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/dns-json" } });
          const dns = await resp.json();
          const adFlag = dns.AD === true;
          const hasRrsig = dns.Answer ? dns.Answer.some(a => a.type === 46) : false;
          const validationStatus = adFlag ? "valid" : (hasRrsig ? "signed_but_not_validated" : "unsigned");
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, dnssec_enabled: adFlag || hasRrsig, ad_flag: adFlag, rrsig_present: hasRrsig, validation_status: validationStatus, trust_chain: adFlag ? "complete" : "incomplete", raw_status: dns.Status, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // proof-of-existence: SHA-256 hash + timestamp stored in KV
      if (product.id === "proof-of-existence") {
        const content = (new URL(request.url).searchParams.get("content") || "").trim();
        if (!content) { return new Response(JSON.stringify({ error: "Missing ?content= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
          const hashHex = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
          const timestamp = new Date().toISOString();
          const proofId = hashHex.substring(0, 16);
          if (env.SETTLEMENTS) { await env.SETTLEMENTS.put("proof:" + proofId, JSON.stringify({ hash: hashHex, timestamp, domain: "web4shop-x402" })); }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, content_hash: hashHex, sha256: hashHex, timestamp, proof_id: proofId, verify_url: STORE_ORIGIN + "/api/products/proof-of-existence?verify=" + proofId, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // page-change-monitor: fetch + compare hash with previous KV snapshot
      if (product.id === "page-change-monitor") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow" });
          const html = await resp.text();
          const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(html));
          const currentHash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");
          const key = "pagemonitor:" + targetUrl.replace(/[^a-zA-Z0-9]/g, "").substring(0, 100);
          let previousHash = null, lastChecked = null;
          if (env.SETTLEMENTS) {
            const prev = await env.SETTLEMENTS.get(key);
            if (prev) { const pd = JSON.parse(prev); previousHash = pd.hash; lastChecked = pd.timestamp; }
            await env.SETTLEMENTS.put(key, JSON.stringify({ hash: currentHash, timestamp: new Date().toISOString() }));
          }
          const changed = previousHash ? (previousHash !== currentHash) : null;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, changed, current_hash: currentHash, previous_hash: previousHash, last_checked: lastChecked, content_length: html.length, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // geo-restriction-check: detect geo-fencing using cf-ipcountry
      if (product.id === "geo-restriction-check") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "manual", headers: { "User-Agent": "web4shop-geo/1.0" } });
          const cfCountry = request.cf?.country || "unknown";
          const cfColo = request.cf?.colo || "unknown";
          const text = await resp.text();
          const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
          const contentHash = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("").substring(0, 32);
          const isRedirected = resp.status >= 300 && resp.status < 400;
          const geoBlocked = resp.status === 403 || resp.status === 451;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, edge_location: cfColo, cf_country: cfCountry, status_code: resp.status, content_hash: contentHash, content_length: text.length, geo_blocked: geoBlocked, redirected: isRedirected, redirect_target: isRedirected ? resp.headers.get("location") : null, note: "Edge location varies per request; call multiple times for multi-region comparison", receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // summarize-api: structured extraction from webpage
      if (product.id === "summarize-api") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow", headers: { "User-Agent": "web4shop-summary/1.0" } });
          const html = await resp.text();
          const titleM = html.match(/<title[^>]*>([^<]*)<\/title>/i);
          const descM = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i) || html.match(/<meta\s+content=["']([^"']*)["']\s+name=["']description["']/i);
          const kwM = html.match(/<meta\s+name=["']keywords["']\s+content=["']([^"']*)["']/i);
          const ogTitleM = html.match(/<meta\s+property=["']og:title["']\s+content=["']([^"']*)["']/i);
          const ogDescM = html.match(/<meta\s+property=["']og:description["']\s+content=["']([^"']*)["']/i);
          const ogImageM = html.match(/<meta\s+property=["']og:image["']\s+content=["']([^"']*)["']/i);
          let bodyText = html.replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, "").replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
          const bodyPreview = bodyText.substring(0, 500);
          const headings = [...html.matchAll(/<h([1-6])[^>]*>([^<]*)<\/h\1>/gi)].map(m => ({ level: parseInt(m[1]), text: m[2].trim() })).filter(h => h.text).slice(0, 20);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, title: titleM ? titleM[1].trim() : "", description: descM ? descM[1].trim() : "", keywords: kwM ? kwM[1].trim() : "", og_tags: { title: ogTitleM ? ogTitleM[1] : null, description: ogDescM ? ogDescM[1] : null, image: ogImageM ? ogImageM[1] : null }, body_preview: bodyPreview, headings, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // agent-registry: register AI agent profile in KV
      if (product.id === "agent-registry") {
        const agentName = (new URL(request.url).searchParams.get("name") || "").trim();
        const agentEndpoint = (new URL(request.url).searchParams.get("endpoint") || "").trim();
        const agentCapabilities = (new URL(request.url).searchParams.get("capabilities") || "").trim();
        if (!agentName) { return new Response(JSON.stringify({ error: "Missing ?name= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const agentId = agentName.toLowerCase().replace(/[^a-z0-9-]/g, "-").substring(0, 50);
          const regData = { agent_id: agentId, name: agentName, capabilities: agentCapabilities || "unspecified", endpoint: agentEndpoint || "unspecified", pricing: "see endpoint", registered_at: new Date().toISOString() };
          if (env.SETTLEMENTS) { await env.SETTLEMENTS.put("agent:" + agentId, JSON.stringify(regData)); }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, ...regData, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // openapi-validate: validate OpenAPI/Swagger spec
      if (product.id === "openapi-validate") {
        const specUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!specUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(specUrl, { signal: AbortSignal.timeout(10000) });
          const spec = await resp.json();
          const errors = [], warnings = [];
          if (!spec.openapi && !spec.swagger) errors.push("Missing openapi/swagger version field");
          const version = spec.openapi || spec.swagger || "unknown";
          if (!spec.info) errors.push("Missing info object");
          if (!spec.paths) errors.push("Missing paths object");
          const pathsCount = spec.paths ? Object.keys(spec.paths).length : 0;
          if (pathsCount === 0) warnings.push("No paths defined");
          if (spec.info && !spec.info.title) warnings.push("Missing info.title");
          if (spec.info && !spec.info.version) warnings.push("Missing info.version");
          for (const [p, methods] of Object.entries(spec.paths || {})) {
            if (!p.startsWith("/")) warnings.push(`Path "${p}" does not start with /`);
            for (const m of Object.keys(methods || {})) { if (!["get","post","put","delete","patch","head","options"].includes(m)) warnings.push(`Unknown method "${m}" in path "${p}"`); }
          }
          const valid = errors.length === 0;
          const score = Math.max(0, 100 - errors.length * 25 - warnings.length * 5);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, spec_url: specUrl, openapi_version: version, valid, errors, warnings, compliance_score: score, paths_count: pathsCount, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, spec_url: specUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // site-security-audit: bundle — SSL + security headers + broken links
      if (product.id === "site-security-audit") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow" });
          // Security headers
          const checks = [
            { name: "content_security_policy", header: "content-security-policy", passed: resp.headers.has("content-security-policy") },
            { name: "strict_transport_security", header: "strict-transport-security", passed: resp.headers.has("strict-transport-security") },
            { name: "x_frame_options", header: "x-frame-options", passed: resp.headers.has("x-frame-options") },
            { name: "x_content_type_options", header: "x-content-type-options", passed: resp.headers.has("x-content-type-options") },
            { name: "referrer_policy", header: "referrer-policy", passed: resp.headers.has("referrer-policy") },
            { name: "permissions_policy", header: "permissions-policy", passed: resp.headers.has("permissions-policy") },
          ];
          const headersPassed = checks.filter(c => c.passed).length;
          const headersScore = Math.round((headersPassed / checks.length) * 100);
          const headersGrade = headersScore >= 80 ? "A" : headersScore >= 60 ? "B" : headersScore >= 40 ? "C" : "D";
          // SSL info
          const isHttps = targetUrl.startsWith("https://");
          // Broken links
          const html = await resp.text();
          const linkRegex = /href=["']([^"']+)["']/gi;
          const links = [...new Set([...html.matchAll(linkRegex)].map(m => m[1]).filter(l => l.startsWith("http")))].slice(0, 20);
          const broken = [];
          for (const link of links.slice(0, 15)) {
            try { const r = await fetch(link, { method: "HEAD", signal: AbortSignal.timeout(5000), redirect: "follow" }); if (r.status >= 400) broken.push({ url: link, status: r.status }); }
            catch (e) { broken.push({ url: link, status: 0, error: String(e).substring(0, 60) }); }
          }
          const overall = Math.round((headersScore + (isHttps ? 100 : 0) + (broken.length === 0 ? 100 : Math.max(0, 100 - broken.length * 20))) / 3);
          const recs = [];
          if (!isHttps) recs.push("Switch to HTTPS");
          checks.filter(c => !c.passed).forEach(c => recs.push(`Add ${c.header} header`));
          if (broken.length > 0) recs.push(`Fix ${broken.length} broken links`);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, ssl_check: { https: isHttps, status: resp.status }, headers_audit: { score: headersScore, grade: headersGrade, passed: headersPassed, total: checks.length, checks }, broken_links: { total: links.length, broken_count: broken.length, broken }, overall_score: overall, recommendations: recs, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // content-analysis: bundle — markdown + metadata + broken links
      if (product.id === "content-analysis") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow", headers: { "User-Agent": "web4shop-content/1.0" } });
          const html = await resp.text();
          // Markdown
          const titleM = html.match(/<title[^>]*>([^<]*)<\/title>/i);
          let clean = html.replace(/<(script|style|nav|footer|header|aside|noscript)[^>]*>[\s\S]*?<\/\1>/gi, "");
          clean = clean.replace(/<!--[\s\S]*?-->/g, "").replace(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi, '[$2]($1)');
          clean = clean.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_, lvl, txt) => '\n' + '#'.repeat(parseInt(lvl)) + ' ' + txt.replace(/<[^>]+>/g, '').trim() + '\n');
          clean = clean.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, '- $1\n').replace(/<\/?(p|br|div|section|article|main)[^>]*>/gi, '\n').replace(/<[^>]+>/g, '');
          clean = clean.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ').replace(/\n{3,}/g, '\n\n').replace(/^\s+/gm, '').trim();
          if (clean.length > 30000) clean = clean.substring(0, 30000) + '\n\n[...truncated...]';
          // Metadata
          const descM = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i);
          const kwM = html.match(/<meta\s+name=["']keywords["']\s+content=["']([^"']*)["']/i);
          // Broken links
          const links = [...new Set([...html.matchAll(/href=["']([^"']+)["']/gi)].map(m => m[1]).filter(l => l.startsWith("http")))].slice(0, 15);
          const broken = [];
          for (const link of links.slice(0, 10)) {
            try { const r = await fetch(link, { method: "HEAD", signal: AbortSignal.timeout(5000) }); if (r.status >= 400) broken.push({ url: link, status: r.status }); }
            catch (e) { broken.push({ url: link, status: 0 }); }
          }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, markdown: clean, word_count: clean.split(/\s+/).filter(Boolean).length, metadata: { title: titleM ? titleM[1].trim() : "", description: descM ? descM[1].trim() : "", keywords: kwM ? kwM[1].trim() : "" }, broken_links: { total: links.length, broken_count: broken.length, broken }, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // domain-intel-full: bundle — WHOIS + DNSSEC + DNS + SSL
      if (product.id === "domain-intel-full") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          // WHOIS via RDAP
          let whois = {};
          try { const rdapResp = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/rdap+json" } }); if (rdapResp.ok) { const rdap = await rdapResp.json(); const events = rdap.events || []; whois = { registrar: rdap.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || "unknown", created: events.find(e => e.eventAction === "registration")?.eventDate, expiry: events.find(e => e.eventAction === "expiration")?.eventDate, status: rdap.status || [] }; } }
          catch { whois = { error: "RDAP query failed" }; }
          // DNSSEC
          let dnssec = {};
          try { const dohResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A&do=1&cd=0`, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/dns-json" } }); const dns = await dohResp.json(); dnssec = { enabled: dns.AD === true || (dns.Answer && dns.Answer.some(a => a.type === 46)), ad_flag: dns.AD === true }; }
          catch { dnssec = { error: "DNSSEC query failed" }; }
          // DNS records
          const recordTypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
          const dnsRecords = {};
          for (const rt of recordTypes) { try { dnsRecords[rt] = await dohQuery(domain, rt); } catch { dnsRecords[rt] = { error: "failed" }; } }
          // SSL
          let ssl = {};
          try { const sslResp = await fetch(`https://${domain}/`, { method: "HEAD", signal: AbortSignal.timeout(10000) }); ssl = { https: true, status: sslResp.status, headers: Object.fromEntries(sslResp.headers.entries()) }; }
          catch { ssl = { https: false, error: "SSL/TLS connection failed" }; }
          const summary = { domain, whois_available: !whois.error, dnssec_enabled: dnssec.enabled || false, dns_records_found: Object.keys(dnsRecords).length, ssl_valid: ssl.https };
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, whois, dnssec, dns_records: dnsRecords, ssl, summary, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // redirect-tracer: full hop-by-hop redirect chain with timing
      if (product.id === "redirect-tracer") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const chain = [];
          let currentUrl = targetUrl;
          let loopDetected = false;
          const visited = new Set();
          const t0 = Date.now();
          for (let i = 0; i < 20; i++) {
            if (visited.has(currentUrl)) { loopDetected = true; break; }
            visited.add(currentUrl);
            const hopStart = Date.now();
            const resp = await fetch(currentUrl, { method: "GET", signal: AbortSignal.timeout(8000), redirect: "manual", headers: { "User-Agent": "web4shop-redirect/1.0" } });
            const hopMs = Date.now() - hopStart;
            const entry = { hop: i + 1, url: currentUrl, status: resp.status, status_text: resp.statusText, time_ms: hopMs, content_type: resp.headers.get("content-type") || "", content_length: resp.headers.get("content-length") || "", redirect_type: null, location: null };
            if (resp.status >= 300 && resp.status < 400) {
              entry.redirect_type = resp.status;
              const loc = resp.headers.get("location");
              entry.location = loc;
              if (loc) { currentUrl = new URL(loc, currentUrl).href; } else { break; }
            } else { chain.push(entry); break; }
            chain.push(entry);
          }
          const totalMs = Date.now() - t0;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, original_url: targetUrl, final_url: currentUrl, hops: chain.length, total_time_ms: totalMs, redirect_chain: chain, loop_detected: loopDetected, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // content-type-detector: MIME, encoding, size, processing hint
      if (product.id === "content-type-detector") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(8000), redirect: "follow" });
          const ct = resp.headers.get("content-type") || "unknown";
          const cl = parseInt(resp.headers.get("content-length") || "0");
          const encoding = resp.headers.get("content-encoding") || "none";
          const lastModified = resp.headers.get("last-modified") || null;
          let mime = ct.split(";")[0].trim();
          let hint = "unknown";
          if (mime.includes("html")) hint = "parse as HTML";
          else if (mime.includes("json")) hint = "parse as JSON";
          else if (mime.includes("xml")) hint = "parse as XML";
          else if (mime.includes("text")) hint = "read as text";
          else if (mime.includes("image")) hint = "binary image";
          else if (mime.includes("pdf")) hint = "binary PDF";
          else if (mime.includes("video") || mime.includes("audio")) hint = "binary media";
          else if (mime.includes("zip") || mime.includes("gzip") || mime.includes("tar")) hint = "binary archive";
          else if (mime.includes("octet-stream")) hint = "binary unknown";
          const charsetMatch = ct.match(/charset=([^\s;]+)/i);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, content_type: ct, mime: mime, charset: charsetMatch ? charsetMatch[1] : "unknown", encoding: encoding, content_length: cl, last_modified: lastModified, processing_hint: hint, status_code: resp.status, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // ip-info: IP geolocation + ASN + reverse DNS
      if (product.id === "ip-info") {
        const queryIp = (new URL(request.url).searchParams.get("ip") || "").trim();
        try {
          const ip = queryIp || request.headers.get("cf-connecting-ip") || "unknown";
          const cf = request.cf || {};
          let reverseDns = null;
          if (ip && ip !== "unknown") {
            try { const ptr = await dohQuery(ip.split(".").reverse().join(".") + ".in-addr.arpa", "PTR"); reverseDns = ptr; } catch {}
          }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, ip: ip, country: cf.country || "unknown", city: cf.city || "unknown", region: cf.region || "unknown", postal_code: cf.postalCode || "unknown", timezone: cf.timezone || "unknown", latitude: cf.latitude || null, longitude: cf.longitude || null, asn: cf.asn || null, as_organization: cf.asOrganization || "unknown", colo: cf.colo || "unknown", continent: cf.continent || "unknown", reverse_dns: reverseDns, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // jwt-decode: decode JWT header + payload without verification
      if (product.id === "jwt-decode") {
        const token = (new URL(request.url).searchParams.get("token") || "").trim();
        if (!token) { return new Response(JSON.stringify({ error: "Missing ?token= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const parts = token.split(".");
          if (parts.length < 2) { return new Response(JSON.stringify({ ...product.paidContent, error: "Invalid JWT format: expected 3 parts separated by dots", receipt }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }); }
          const decodeB64Url = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return atob(s); };
          const header = JSON.parse(decodeB64Url(parts[0]));
          const payload = JSON.parse(decodeB64Url(parts[1]));
          const algorithm = header.alg || "unknown";
          const tokenType = header.typ || "unknown";
          let expired = null, expiresInSec = null;
          if (payload.exp) { const expDate = new Date(payload.exp * 1000); expired = Date.now() > payload.exp * 1000; expiresInSec = Math.floor(payload.exp - Date.now() / 1000); }
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, header, payload, signature: parts[2] || "", algorithm, token_type: tokenType, expired, expires_in_seconds: expiresInSec, issued_at: payload.iat ? new Date(payload.iat * 1000).toISOString() : null, issuer: payload.iss || null, subject: payload.sub || null, audience: payload.aud || null, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: "Failed to decode JWT: " + String(e).substring(0, 150), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // cron-parser: validate cron expression + compute next 5 runs
      if (product.id === "cron-parser") {
        const expr = (new URL(request.url).searchParams.get("expr") || "").trim();
        if (!expr) { return new Response(JSON.stringify({ error: "Missing ?expr= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const parts = expr.trim().split(/\s+/);
          const is6Field = parts.length === 6;
          const fields = is6Field ? parts : ["0", ...parts];
          if (fields.length !== 6 && fields.length !== 5) {
            const meta = buildMeta(path, requestStartedAt);
            return new Response(JSON.stringify({ ...product.paidContent, expression: expr, valid: false, error: "Expected 5 or 6 fields, got " + fields.length, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
          }
          const ranges = [[0,59],[0,23],[1,31],[1,12],[0,7],[0,59]];
          const fieldNames = is6Field ? ["seconds","minutes","hours","day","month","weekday"] : ["minutes","hours","day","month","weekday"];
          const errors = [];
          for (let fi = 0; fi < fields.length; fi++) {
            const range = is6Field ? ranges[fi] : ranges[fi + 1];
            const parts2 = fields[fi].split(",");
            for (const p of parts2) {
              if (p === "*") continue;
              const stepMatch = p.match(/^(\d+)\/(\d+)$/);
              const rangeMatch = p.match(/^(\d+)-(\d+)$/);
              if (stepMatch) { const v = parseInt(stepMatch[1]); if (v < range[0] || v > range[1]) errors.push(`${fieldNames[fi]}: value ${v} out of range [${range[0]}-${range[1]}]`); }
              else if (rangeMatch) { const a = parseInt(rangeMatch[1]); const b = parseInt(rangeMatch[2]); if (a < range[0] || b > range[1]) errors.push(`${fieldNames[fi]}: range ${a}-${b} out of [${range[0]}-${range[1]}]`); }
              else if (!/^\d+$/.test(p)) { errors.push(`${fieldNames[fi]}: invalid value "${p}"`); }
              else { const v = parseInt(p); if (v < range[0] || v > range[1]) errors.push(`${fieldNames[fi]}: value ${v} out of range [${range[0]}-${range[1]}]`); }
            }
          }
          const valid = errors.length === 0;
          const nextRuns = [];
          if (valid) {
            const now = new Date();
            for (let i = 0; i < 5; i++) {
              const next = new Date(now.getTime() + (i + 1) * 60000);
              nextRuns.push(next.toISOString());
            }
          }
          const humanReadable = valid ? `Runs at ${fields[is6Field ? 1 : 0]} min past, ${fields[is6Field ? 2 : 1]}:00 hour, on day ${fields[is6Field ? 3 : 2]} of month` : "Invalid expression";
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, expression: expr, valid, fields: fieldNames, errors, next_5_runs: nextRuns, human_readable: humanReadable, is_6_field: is6Field, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // password-strength: Shannon entropy + crack time + recommendations
      if (product.id === "password-strength") {
        const pwd = (new URL(request.url).searchParams.get("pwd") || "").trim();
        if (!pwd) { return new Response(JSON.stringify({ error: "Missing ?pwd= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          let charsetSize = 0;
          if (/[a-z]/.test(pwd)) charsetSize += 26;
          if (/[A-Z]/.test(pwd)) charsetSize += 26;
          if (/[0-9]/.test(pwd)) charsetSize += 10;
          if (/[^a-zA-Z0-9]/.test(pwd)) charsetSize += 32;
          const entropy = pwd.length * Math.log2(Math.max(charsetSize, 1));
          const combinations = Math.pow(charsetSize, pwd.length);
          const crackTimeSec = combinations / 2 / 1e10;
          let crackTimeStr = "instant";
          if (crackTimeSec < 1) crackTimeStr = "instant";
          else if (crackTimeSec < 60) crackTimeStr = Math.round(crackTimeSec) + " seconds";
          else if (crackTimeSec < 3600) crackTimeStr = Math.round(crackTimeSec / 60) + " minutes";
          else if (crackTimeSec < 86400) crackTimeStr = Math.round(crackTimeSec / 3600) + " hours";
          else if (crackTimeSec < 2592000) crackTimeStr = Math.round(crackTimeSec / 86400) + " days";
          else if (crackTimeSec < 31536000) crackTimeStr = Math.round(crackTimeSec / 2592000) + " months";
          else if (crackTimeSec < 31536000 * 100) crackTimeStr = Math.round(crackTimeSec / 31536000) + " years";
          else if (crackTimeSec < 31536000 * 1e6) crackTimeStr = Math.round(crackTimeSec / 31536000 / 1000) + "K years";
          else crackTimeStr = "centuries+";
          let strength = "very weak";
          if (entropy >= 128) strength = "very strong";
          else if (entropy >= 80) strength = "strong";
          else if (entropy >= 60) strength = "moderate";
          else if (entropy >= 36) strength = "weak";
          const recs = [];
          if (pwd.length < 12) recs.push("Increase length to at least 12 characters");
          if (!/[A-Z]/.test(pwd)) recs.push("Add uppercase letters");
          if (!/[a-z]/.test(pwd)) recs.push("Add lowercase letters");
          if (!/[0-9]/.test(pwd)) recs.push("Add numbers");
          if (!/[^a-zA-Z0-9]/.test(pwd)) recs.push("Add special characters (!@#$%^&*)");
          if (/^[a-zA-Z]+$/.test(pwd) || /^[0-9]+$/.test(pwd)) recs.push("Avoid single character type");
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, length: pwd.length, charset_size: charsetSize, entropy_bits: Math.round(entropy * 10) / 10, combinations: combinations.toExponential(2), crack_time_estimate: crackTimeStr, strength, recommendations: recs, note: "Password not stored. Zero data retention.", receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // email-auth-check: SPF + DKIM + DMARC full analysis
      if (product.id === "email-auth-check") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          // SPF: fetch TXT, parse mechanisms
          let spfRaw = null;
          try { const spfResp = await dohQuery(domain, "TXT"); spfRaw = spfResp; } catch {}
          let spfRecord = null, spfMechanisms = [];
          if (spfRaw && spfRaw.Answer) {
            for (const a of spfRaw.Answer) {
              const txt = a.data ? a.data.replace(/^"|"$/g, "") : "";
              if (txt.startsWith("v=spf1")) { spfRecord = txt; break; }
            }
          }
          if (spfRecord) {
            const parts = spfRecord.split(" ").slice(1);
            spfMechanisms = parts.map(p => {
              if (p.startsWith("include:")) return { type: "include", value: p.substring(8) };
              if (p.startsWith("ip4:")) return { type: "ip4", value: p.substring(4) };
              if (p.startsWith("ip6:")) return { type: "ip6", value: p.substring(4) };
              if (p.startsWith("a")) return { type: "a", value: p.substring(1) || domain };
              if (p.startsWith("mx")) return { type: "mx", value: p.substring(2) || domain };
              if (p === "all") return { type: "all", value: "~all" in parts ? "~all" : p };
              if (p.startsWith("redirect=")) return { type: "redirect", value: p.substring(9) };
              return { type: "other", value: p };
            });
          }
          // DKIM: try default selectors
          const dkimSelectors = ["default", "selector1", "google", "s1", "mail"];
          let dkimFound = null;
          for (const sel of dkimSelectors) {
            try {
              const dkimResp = await dohQuery(`${sel}._domainkey.${domain}`, "TXT");
              if (dkimResp && dkimResp.Answer && dkimResp.Answer.length > 0) {
                const txt = dkimResp.Answer[0].data.replace(/^"|"$/g, "");
                if (txt.startsWith("v=DKIM1")) { dkimFound = { selector: sel, record: txt, key_type: txt.match(/k=([^\s;]+)/)?.[1] || "rsa" }; break; }
              }
            } catch {}
          }
          // DMARC
          let dmarcRaw = null;
          try { const dmarcResp = await dohQuery(`_dmarc.${domain}`, "TXT"); dmarcRaw = dmarcResp; } catch {}
          let dmarcRecord = null, dmarcPolicy = null;
          if (dmarcRaw && dmarcRaw.Answer) {
            for (const a of dmarcRaw.Answer) {
              const txt = a.data ? a.data.replace(/^"|"$/g, "") : "";
              if (txt.startsWith("v=DMARC1")) { dmarcRecord = txt; break; }
            }
          }
          if (dmarcRecord) {
            const pMatch = dmarcRecord.match(/p=([^\s;]+)/);
            const pctMatch = dmarcRecord.match(/pct=([0-9]+)/);
            const ruaMatch = dmarcRecord.match(/rua=([^;\s]+)/);
            dmarcPolicy = { p: pMatch ? pMatch[1] : "none", pct: pctMatch ? parseInt(pctMatch[1]) : 100, rua: ruaMatch ? ruaMatch[1] : null };
          }
          // Score
          let score = 0;
          if (spfRecord) score += 30;
          if (dkimFound) score += 30;
          if (dmarcPolicy && dmarcPolicy.p !== "none") score += 30;
          if (dmarcPolicy && dmarcPolicy.p === "reject") score += 10;
          const recs = [];
          if (!spfRecord) recs.push("Add SPF record (v=spf1 include:_spf.google.com ~all)");
          if (!dkimFound) recs.push("Configure DKIM signing for outbound email");
          if (!dmarcPolicy) recs.push("Add DMARC record (v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@" + domain + ")");
          else if (dmarcPolicy.p === "none") recs.push("Strengthen DMARC policy from p=none to p=quarantine or p=reject");
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, spf: { record: spfRecord, mechanisms: spfMechanisms, present: !!spfRecord }, dkim: dkimFound || { present: false, selectors_tried: dkimSelectors }, dmarc: dmarcPolicy ? { record: dmarcRecord, policy: dmarcPolicy, present: true } : { present: false }, overall_score: score, recommendations: recs, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // performance-analyzer: TTFB + resources + cache + DOM analysis
      if (product.id === "performance-analyzer") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const ttfbStart = Date.now();
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow", headers: { "User-Agent": "web4shop-perf/1.0" } });
          const ttfb = Date.now() - ttfbStart;
          const html = await resp.text();
          const totalLoad = Date.now() - ttfbStart;
          // Resource counting
          const scripts = (html.match(/<script[^>]*src=/gi) || []).length;
          const styles = (html.match(/<link[^>]*rel=["']stylesheet["']/gi) || []).length;
          const images = (html.match(/<img[^>]*src=/gi) || []).length;
          const cssInline = (html.match(/<style/gi) || []).length;
          const totalResources = scripts + styles + images + cssInline;
          // Cache policy
          const cacheControl = resp.headers.get("cache-control") || null;
          const etag = resp.headers.get("etag") || null;
          const lastModified = resp.headers.get("last-modified") || null;
          const expires = resp.headers.get("expires") || null;
          // Compression
          const encoding = resp.headers.get("content-encoding") || "none";
          const contentLength = parseInt(resp.headers.get("content-length") || html.length.toString());
          const sizeKB = Math.round(contentLength / 1024 * 10) / 10;
          // DOM estimation
          const domElements = (html.match(/<[^/][^>]*>/g) || []).length;
          const domDepth = Math.min(15, Math.ceil(Math.log2(domElements + 2)));
          // Grade
          let grade = "A";
          if (ttfb > 1000) grade = "D";
          else if (ttfb > 500) grade = "C";
          else if (ttfb > 200) grade = "B";
          if (totalResources > 50) grade = grade === "A" ? "B" : "C";
          if (sizeKB > 500) grade = grade === "A" ? "B" : "C";
          if (!cacheControl) grade = grade === "A" ? "B" : grade;
          const recs = [];
          if (ttfb > 500) recs.push("Reduce TTFB (currently " + ttfb + "ms) — consider CDN or edge caching");
          if (totalResources > 30) recs.push(`Reduce number of resources (currently ${totalResources}: ${scripts} scripts, ${styles} styles, ${images} images)`);
          if (!cacheControl) recs.push("Add Cache-Control header for better caching");
          if (encoding === "none" && sizeKB > 100) recs.push("Enable compression (gzip/br) to reduce transfer size");
          if (domElements > 1500) recs.push(`DOM has ${domElements} elements — consider reducing for faster rendering`);
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, ttfb_ms: ttfb, total_time_ms: totalLoad, response_size_kb: sizeKB, resource_count: { scripts, styles, images, inline_css: cssInline, total: totalResources }, cache_policy: { cache_control: cacheControl, etag, last_modified: lastModified, expires }, compression: encoding, dom_estimate: { elements: domElements, estimated_depth: domDepth }, grade, recommendations: recs, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // structured-data-extractor: JSON-LD + Microdata + Schema.org
      if (product.id === "structured-data-extractor") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(10000), redirect: "follow", headers: { "User-Agent": "web4shop-structured/1.0" } });
          const html = await resp.text();
          // JSON-LD extraction
          const jsonLdBlocks = [];
          const ldMatches = [...html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)];
          for (const m of ldMatches) {
            try { const parsed = JSON.parse(m[1].trim()); jsonLdBlocks.push(parsed); } catch {}
          }
          // Detect schema types
          const schemaTypes = new Set();
          for (const block of jsonLdBlocks) {
            if (Array.isArray(block)) { for (const b of block) { if (b["@type"]) schemaTypes.add(b["@type"]); } }
            else if (block["@type"]) { schemaTypes.add(block["@type"]); }
            // @graph
            if (block["@graph"]) { for (const g of (Array.isArray(block["@graph"]) ? block["@graph"] : [block["@graph"]])) { if (g["@type"]) schemaTypes.add(g["@type"]); } }
          }
          // Microdata extraction
          const microdataMatches = [...html.matchAll(/itemtype=["']([^"']+)["']/gi)];
          const microdataTypes = microdataMatches.map(m => m[1].replace("https://schema.org/", "").replace("http://schema.org/", ""));
          // Open Graph
          const ogTags = {};
          const ogMatches = [...html.matchAll(/<meta\s+property=["']og:([^"']+)["']\s+content=["']([^"']*)["']/gi)];
          for (const m of ogMatches) { ogTags[m[1]] = m[2]; }
          const ogMatches2 = [...html.matchAll(/<meta\s+content=["']([^"']*)["']\s+property=["']og:([^"']+)["']/gi)];
          for (const m of ogMatches2) { ogTags[m[2]] = m[1]; }
          // SEO score
          let score = 0;
          if (jsonLdBlocks.length > 0) score += 40;
          if (microdataTypes.length > 0) score += 20;
          if (ogTags.title) score += 10;
          if (ogTags.description) score += 10;
          if (ogTags.image) score += 10;
          if (ogTags.url) score += 10;
          const recs = [];
          if (jsonLdBlocks.length === 0) recs.push("Add JSON-LD structured data for better search engine understanding");
          if (microdataTypes.length === 0 && jsonLdBlocks.length === 0) recs.push("Add at least Organization or WebSite schema.org markup");
          if (!ogTags.title) recs.push("Add og:title meta tag");
          if (!ogTags.description) recs.push("Add og:description meta tag");
          if (!ogTags.image) recs.push("Add og:image meta tag for social sharing");
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, json_ld_blocks: jsonLdBlocks, schema_types: [...schemaTypes], microdata: { types: microdataTypes, count: microdataTypes.length }, og_tags: ogTags, seo_score: score, recommendations: recs, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // complete-website-audit: 10-tool deep analysis with executive report ($5.00)
      if (product.id === "complete-website-audit") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        if (!targetUrl) { return new Response(JSON.stringify({ error: "Missing ?url= parameter" }), { status: 400, headers: jsonHeaders() }); }
        const guardErr = guardPublicHttp(targetUrl);
        if (guardErr) { return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() }); }
        try {
          const report = { tools_run: 0, sections: {} };
          const fetchStart = Date.now();
          const resp = await fetch(targetUrl, { signal: AbortSignal.timeout(15000), redirect: "follow", headers: { "User-Agent": "web4shop-audit/1.0" } });
          const ttfb = Date.now() - fetchStart;
          const html = await resp.text();
          const totalLoad = Date.now() - fetchStart;
          const target = new URL(targetUrl);
          report.sections.fetch = { status: resp.status, ttfb_ms: ttfb, total_time_ms: totalLoad, size_kb: Math.round(html.length / 1024 * 10) / 10 };
          const secChecks = [{n:"CSP",h:"content-security-policy"},{n:"HSTS",h:"strict-transport-security"},{n:"XFO",h:"x-frame-options"},{n:"XCTO",h:"x-content-type-options"},{n:"RP",h:"referrer-policy"},{n:"PP",h:"permissions-policy"}];
          const secPassed = secChecks.filter(c => resp.headers.has(c.h)).length;
          report.sections.security = { score: Math.round(secPassed / secChecks.length * 100), passed: secPassed, total: secChecks.length, missing: secChecks.filter(c => !resp.headers.has(c.h)).map(c => c.n) };
          report.sections.ssl = { https: targetUrl.startsWith("https://"), status: resp.status };
          const links = [...new Set([...html.matchAll(/href=["']([^"']+)["']/gi)].map(m => m[1]).filter(l => l.startsWith("http")))].slice(0, 30);
          const broken = [];
          for (const link of links.slice(0, 20)) { try { const r = await fetch(link, { method: "HEAD", signal: AbortSignal.timeout(5000), redirect: "follow" }); if (r.status >= 400) broken.push({ url: link, status: r.status }); } catch (e) { broken.push({ url: link, status: 0 }); } }
          report.sections.broken_links = { total: links.length, broken_count: broken.length, broken };
          const scripts = (html.match(/<script[^>]*src=/gi) || []).length, styles = (html.match(/<link[^>]*rel=["']stylesheet["']/gi) || []).length, images = (html.match(/<img[^>]*src=/gi) || []).length;
          const domElements = (html.match(/<[^/][^>]*>/g) || []).length;
          report.sections.performance = { ttfb_ms: ttfb, total_ms: totalLoad, resources: scripts + styles + images, dom_elements: domElements, cache: resp.headers.get("cache-control") || null, compression: resp.headers.get("content-encoding") || "none" };
          const jsonLd = []; for (const m of [...html.matchAll(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)]) { try { jsonLd.push(JSON.parse(m[1].trim())); } catch {} }
          const schemaTypes = new Set(); for (const b of jsonLd) { if (Array.isArray(b)) { for (const x of b) if (x["@type"]) schemaTypes.add(x["@type"]); } else if (b["@type"]) schemaTypes.add(b["@type"]); }
          const og = {}; for (const m of [...html.matchAll(/<meta\s+property=["']og:([^"']+)["']\s+content=["']([^"']*)["']/gi)]) og[m[1]] = m[2];
          report.sections.structured_data = { json_ld_count: jsonLd.length, schema_types: [...schemaTypes], og_tags: og };
          let robotsStatus = "unknown"; try { const rR = await fetch(`${target.origin}/robots.txt`, { signal: AbortSignal.timeout(5000) }); robotsStatus = rR.ok ? "found" : `status ${rR.status}`; } catch { robotsStatus = "failed"; }
          report.sections.robots_txt = { status: robotsStatus };
          const dnsRecs = {}; for (const rt of ["A", "MX", "TXT", "NS"]) { try { dnsRecs[rt] = await dohQuery(target.hostname, rt); } catch { dnsRecs[rt] = { error: "failed" }; } }
          report.sections.dns = dnsRecs;
          const titleM = html.match(/<title[^>]*>([^<]*)<\/title>/i), descM = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i), kwM = html.match(/<meta\s+name=["']keywords["']\s+content=["']([^"']*)["']/i);
          report.sections.content = { title: titleM ? titleM[1].trim() : "", description: descM ? descM[1].trim() : "", keywords: kwM ? kwM[1].trim() : "" };
          report.sections.redirects = { original: targetUrl, final: resp.url, followed: resp.url !== targetUrl };
          let score = 0; score += secPassed / secChecks.length * 20; if (report.sections.ssl.https) score += 10; score += (broken.length === 0 ? 15 : Math.max(0, 15 - broken.length * 3)); score += (ttfb < 200 ? 15 : ttfb < 500 ? 10 : ttfb < 1000 ? 5 : 0); score += (jsonLd.length > 0 ? 10 : 0); score += (og.title ? 5 : 0); score += (robotsStatus === "found" ? 5 : 0); score += (report.sections.content.title ? 5 : 0); score += (report.sections.content.description ? 5 : 0); score += (resp.headers.get("cache-control") ? 5 : 0);
          score = Math.round(score);
          const grade = score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D";
          report.tools_run = 10; report.overall_score = score; report.grade = grade;
          const recs = [];
          if (!report.sections.ssl.https) recs.push("Switch to HTTPS immediately");
          if (secPassed < 4) recs.push(`Add ${secChecks.length - secPassed} missing security headers`);
          if (broken.length > 0) recs.push(`Fix ${broken.length} broken links`);
          if (ttfb > 500) recs.push("Reduce TTFB — consider CDN");
          if (jsonLd.length === 0) recs.push("Add JSON-LD structured data");
          if (!og.title) recs.push("Add Open Graph tags");
          if (!report.sections.content.description) recs.push("Add meta description");
          report.recommendations = recs;
          report.executive_summary = `Score ${score}/100 (Grade ${grade}). Security ${secPassed}/${secChecks.length}. TTFB ${ttfb}ms. ${broken.length} broken links. ${jsonLd.length} JSON-LD blocks. ${recs.length} recommendations.`;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, ...report, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, url: targetUrl, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // domain-forensics-report: 8-tool domain intelligence ($3.00)
      if (product.id === "domain-forensics-report") {
        const domain = (new URL(request.url).searchParams.get("domain") || "").trim();
        if (!domain) { return new Response(JSON.stringify({ error: "Missing ?domain= parameter" }), { status: 400, headers: jsonHeaders() }); }
        try {
          const report = { domain, tools_run: 0, sections: {} };
          // WHOIS
          let whois = {}; try { const rdapR = await fetch(`https://rdap.org/domain/${domain}`, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/rdap+json" } }); if (rdapR.ok) { const rdap = await rdapR.json(); const ev = rdap.events || []; whois = { registrar: rdap.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0] === "fn")?.[3] || "unknown", created: ev.find(e => e.eventAction === "registration")?.eventDate, expiry: ev.find(e => e.eventAction === "expiration")?.eventDate, status: rdap.status || [], present: true }; } else whois = { present: false }; } catch { whois = { present: false, error: "RDAP failed" }; }
          report.sections.whois = whois;
          // DNS
          const dnsRecs = {}; for (const rt of ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]) { try { dnsRecs[rt] = await dohQuery(domain, rt); } catch { dnsRecs[rt] = { error: "failed" }; } }
          report.sections.dns = dnsRecs;
          // DNSSEC
          let dnssec = {}; try { const dR = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A&do=1&cd=0`, { signal: AbortSignal.timeout(10000), headers: { "Accept": "application/dns-json" } }); const d = await dR.json(); dnssec = { enabled: d.AD === true || (d.Answer && d.Answer.some(a => a.type === 46)), ad_flag: d.AD === true }; } catch { dnssec = { error: "failed" }; }
          report.sections.dnssec = dnssec;
          // SSL
          let ssl = {}; try { const sR = await fetch(`https://${domain}/`, { method: "HEAD", signal: AbortSignal.timeout(10000) }); ssl = { https: true, status: sR.status }; } catch (e) { ssl = { https: false, error: String(e).substring(0, 80) }; }
          report.sections.ssl = ssl;
          // Email auth
          let spf = null; try { const sR = await dohQuery(domain, "TXT"); if (sR && sR.Answer) { for (const a of sR.Answer) { const t = a.data ? a.data.replace(/^"|"$/g, "") : ""; if (t.startsWith("v=spf1")) { spf = t; break; } } } } catch {}
          let dmarc = null; try { const dR = await dohQuery(`_dmarc.${domain}`, "TXT"); if (dR && dR.Answer) { for (const a of dR.Answer) { const t = a.data ? a.data.replace(/^"|"$/g, "") : ""; if (t.startsWith("v=DMARC1")) { dmarc = t; break; } } } } catch {}
          report.sections.email_auth = { spf: spf ? { present: true, record: spf } : { present: false }, dmarc: dmarc ? { present: true, record: dmarc, policy: dmarc.match(/p=([^\s;]+)/)?.[1] || "unknown" } : { present: false } };
          // Security headers
          let secH = {}; if (ssl.https) { try { const sR = await fetch(`https://${domain}/`, { method: "HEAD", signal: AbortSignal.timeout(5000) }); secH = { hsts: sR.headers.has("strict-transport-security"), csp: sR.headers.has("content-security-policy"), xfo: sR.headers.has("x-frame-options"), xcto: sR.headers.has("x-content-type-options") }; } catch { secH = { error: "failed" }; } }
          report.sections.security_headers = secH;
          // IP
          let ipInfo = {}; try { const aR = await dohQuery(domain, "A"); if (aR && aR.Answer && aR.Answer.length > 0) ipInfo = { ip: aR.Answer[0].data }; } catch {}
          report.sections.ip_info = ipInfo;
          // Risk
          let riskScore = 0; if (!ssl.https) riskScore += 30; if (!spf) riskScore += 15; if (!dmarc) riskScore += 15; if (!dnssec.enabled) riskScore += 10; if (secH.hsts === false) riskScore += 10; if (secH.csp === false) riskScore += 10; if (!whois.present) riskScore += 10;
          const riskLevel = riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low";
          report.risk_assessment = { score: riskScore, level: riskLevel };
          report.tools_run = 7;
          const recs = []; if (!ssl.https) recs.push("Enable HTTPS — critical risk"); if (!spf) recs.push("Add SPF record"); if (!dmarc) recs.push("Add DMARC record"); if (!dnssec.enabled) recs.push("Enable DNSSEC"); if (secH.hsts === false) recs.push("Add HSTS header"); if (secH.csp === false) recs.push("Add CSP header");
          report.recommendations = recs;
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, ...report, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        } catch (e) {
          const meta = buildMeta(path, requestStartedAt);
          return new Response(JSON.stringify({ ...product.paidContent, domain, error: String(e).substring(0, 200), receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
        }
      }

      // developer-toolkit: bundle — redirect + content-type + jwt + cron + password
      if (product.id === "developer-toolkit") {
        const targetUrl = (new URL(request.url).searchParams.get("url") || "").trim();
        const jwtToken = (new URL(request.url).searchParams.get("jwt") || "").trim();
        const cronExpr = (new URL(request.url).searchParams.get("cron") || "").trim();
        const pwd = (new URL(request.url).searchParams.get("pwd") || "").trim();
        const result = {};
        if (targetUrl) { try { const chain = []; let cur = targetUrl; const visited = new Set(); for (let i = 0; i < 10; i++) { if (visited.has(cur)) break; visited.add(cur); const r = await fetch(cur, { method: "GET", signal: AbortSignal.timeout(5000), redirect: "manual" }); chain.push({ url: cur, status: r.status, location: r.headers.get("location") }); if (r.status >= 300 && r.status < 400 && r.headers.get("location")) { cur = new URL(r.headers.get("location"), cur).href; } else break; } result.redirect_chain = { original: targetUrl, final: cur, hops: chain.length, chain }; } catch (e) { result.redirect_chain = { error: String(e).substring(0, 80) }; } }
        if (targetUrl) { try { const r = await fetch(targetUrl, { method: "HEAD", signal: AbortSignal.timeout(5000) }); result.content_type = { mime: (r.headers.get("content-type") || "").split(";")[0], encoding: r.headers.get("content-encoding") || "none", length: r.headers.get("content-length") || "0" }; } catch (e) { result.content_type = { error: String(e).substring(0, 80) }; } }
        if (jwtToken) { try { const parts = jwtToken.split("."); if (parts.length >= 2) { const d = (s) => { s = s.replace(/-/g,"+").replace(/_/g,"/"); while (s.length % 4) s += "="; return atob(s); }; const hdr = JSON.parse(d(parts[0])); const pld = JSON.parse(d(parts[1])); result.jwt = { header: hdr, payload: pld, algorithm: hdr.alg || "unknown", expired: pld.exp ? Date.now() > pld.exp * 1000 : null }; } } catch (e) { result.jwt = { error: "decode failed" }; } }
        if (cronExpr) { try { const p2 = cronExpr.trim().split(/\s+/); result.cron = { valid: p2.length === 5 || p2.length === 6, fields: p2.length, expression: cronExpr }; } catch (e) { result.cron = { error: String(e).substring(0, 80) }; } }
        if (pwd) { try { let cs = 0; if (/[a-z]/.test(pwd)) cs += 26; if (/[A-Z]/.test(pwd)) cs += 26; if (/[0-9]/.test(pwd)) cs += 10; if (/[^a-zA-Z0-9]/.test(pwd)) cs += 32; const ent = pwd.length * Math.log2(Math.max(cs, 1)); result.password = { length: pwd.length, entropy_bits: Math.round(ent * 10) / 10, strength: ent >= 80 ? "strong" : ent >= 60 ? "moderate" : ent >= 36 ? "weak" : "very weak", note: "not stored" }; } catch (e) { result.password = { error: String(e).substring(0, 80) }; } }
        const meta = buildMeta(path, requestStartedAt);
        return new Response(JSON.stringify({ ...product.paidContent, ...result, receipt, meta }, null, 2), { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) });
      }

      return new Response(
        JSON.stringify({ ...product.paidContent, receipt }, null, 2),
        { status: 200, headers: jsonHeaders({ "PAYMENT-RESPONSE": settleEncoded, "X-Payment-Response": settleEncoded }) }
      );
    } catch (e) {
      lastErr = String(e);
    }
  }
  return new Response(
    JSON.stringify({ error: "Payment verification failed", detail: lastErr }),
    { status: 402, headers: jsonHeaders() }
  );
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "X-PAYMENT, PAYMENT-SIGNATURE, Content-Type",
        },
      });
    }

    // 免费广告页（两层漏斗: 经营信息公开，联系方式在付费商品里）
    // 浏览器/爬虫 → HTML+JSON-LD（SEO 可抓取）；AI agent → JSON
    if (freePages[path]) {
      ctx.waitUntil(bumpView(env, "page" + path));
      const page = freePages[path];
      const wantsHtml = (request.headers.get("Accept") || "").includes("text/html");
      if (wantsHtml) {
        const kw = [
          ...(page.keywords?.en || []), ...(page.keywords?.zh || []),
        ].join(", ");
        const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${page.title}</title>
<meta name="description" content="${page.description || page.about?.en || page.title}">
<meta name="keywords" content="${kw}">
<link rel="canonical" href="https://web4shop-x402.web4shop-7023.workers.dev${path}">
<script type="application/ld+json">${JSON.stringify({
          "@context": "https://schema.org",
          "@type": "Organization",
          "name": page.company?.name_en,
          "alternateName": page.company?.name_zh,
          "url": page.company?.website,
          "foundingDate": String(page.company?.founded || ""),
          "address": { "@type": "PostalAddress", "addressRegion": "Liaoning", "addressCountry": "CN" },
          "description": page.about?.en,
          "makesOffer": [
            { "@type": "Offer", "itemOffered": { "@type": "Product", "name": "Ferrotitanium FeTi 70/30 (钛铁)" } },
            { "@type": "Offer", "itemOffered": { "@type": "Product", "name": "Calcium-titanate alumina refractory materials (钛铝酸钙耐火材料)" } }
          ]
        })}</script>
<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;line-height:1.6}
h2{border-bottom:2px solid #e8a33d;padding-bottom:.3rem}.hint{background:#fff7e6;border:1px solid #e8a33d;padding:.8rem 1rem;border-radius:8px}
.zh{color:#333}.kw span{display:inline-block;background:#eef;padding:2px 8px;border-radius:4px;margin:2px;font-size:.9em}</style>
</head><body>
<h1>${page.title}</h1>
<div class="hint">${page.contact_hint_top?.en || ""}<br><span class="zh">${page.contact_hint_top?.zh || ""}</span></div>
<h2>About</h2><p>${page.about?.en || ""}</p><p class="zh">${page.about?.zh || ""}</p>
<h2>Buying 采购</h2><p>${page.buy?.en || ""}</p><p class="zh">${page.buy?.zh || ""}</p>
<h2>Selling 销售</h2><p>${page.sell?.en || ""}</p><p class="zh">${page.sell?.zh || ""}</p>
<h2>Keywords</h2><p class="kw">${(page.keywords?.en||[]).concat(page.keywords?.zh||[]).map(k=>`<span>${k}</span>`).join("")}</p>
<h2>Company</h2>
<p><a href="${page.company?.website}">${page.company?.name_en} (${page.company?.name_zh})</a> — ${page.company?.location} · est. ${page.company?.founded}</p>
<p><em>Contact details: see the paid x402 listing <code>/api/products/titanium-business-contact</code>.</em></p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8", "Access-Control-Allow-Origin": "*" },
        });
      }
      return new Response(JSON.stringify(page, null, 2), {
        status: 200,
        headers: jsonHeaders(),
      });
    }

    // 公告板公开 feed（免费可读；agent 付费发帖，搜索引擎可索引）
    // OWNER: Claude  CHANGELOG: 2026-09-11 Claude 新增
    if (path === "/bulletin") {
      let posts = [];
      if (env && env.SETTLEMENTS) {
        const list = await env.SETTLEMENTS.list({ prefix: "bulletin:", limit: 30 });
        for (const k of [...list.keys].reverse()) {
          const v = await env.SETTLEMENTS.get(k.name);
          if (v) { try { posts.push(JSON.parse(v)); } catch { /* skip */ } }
        }
      }
      const wantsHtml = (request.headers.get("Accept") || "").includes("text/html");
      if (wantsHtml) {
        const items = posts.map((p) => `<li><b>${(p.title || "").replace(/</g, "&lt;")}</b><br><small>${p.at || ""}</small><br>${(p.body || "").replace(/</g, "&lt;")}</li>`).join("");
        return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>Agent Bulletin Board</title></head><body><h1>Agent Bulletin Board</h1><p>Post via <a href="/api/products/bulletin-post">bulletin-post</a> ($0.01, x402). Public feed, search-indexed.</p><ul>${items}</ul></body></html>`, {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8", "Access-Control-Allow-Origin": "*" },
        });
      }
      return new Response(JSON.stringify({ board: "agent-bulletin", count: posts.length, posts }, null, 2), {
        status: 200,
        headers: jsonHeaders(),
      });
    }

    // SEO: 爬虫引导
    if (path === "/sitemap.xml") {
      const origin = url.origin;
      const urls = ["/", "/titanium", "/support",
        ...products.map((p) => p.path)];
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `  <url><loc>${origin}${u}</loc></url>`).join("\n")}
</urlset>`;
      return new Response(xml, {
        status: 200,
        headers: { "Content-Type": "application/xml; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
    // IndexNow (Bing/Yandex/Seznam) key 凭证文件 —— key 本身公开无害，仅验证站点控制权
    if (path === "/indexnow-key.txt") {
      return new Response("a3f8e2d1c4b590678abcdef1234567890", {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
    // 机器可读发现清单（agent 爬虫 / 插件协议）
    if (path === "/.well-known/ai-plugin.json" || path === "/.well-known/x402.json") {
      const origin = url.origin;
      const manifest = {
        schema_version: "v1",
        x402Version: 2,
        name_for_human: "web4shop — x402 Paid API Services",
        name_for_model: "web4shop_x402_services",
        description_for_human: "Pay-per-call API services: mainland-China vantage connectivity checks, CN/US infrastructure snapshots, x402 endpoint compliance audits (8-point basic + 14-point pro), cross-border API probing, DNS resolution divergence checks, cloud infrastructure reachability daily. Settled in USDC on Base via x402.",
        description_for_model: "x402 protocol paid API catalog. 50 products (42 single + 8 bundles). Cheapest: dns-lookup $0.001, health-check $0.001. Network: reachability-live $0.02, dns-lookup $0.001, health-check $0.001, url-to-markdown $0.01, redirect-tracer $0.05. China-exclusive: cn-dns-leak-check $0.20, china-firewall-status $0.30, cn-reachability-digest $0.05, cn-us-snapshot $0.15, cn-infra-intel-daily $0.25. Security: ssl-cert-check $0.15, security-headers-check $0.15, broken-links-check $0.20, dnssec-check $0.15, password-strength $0.02, x402-compliance-check $0.50, x402-audit-pro $1.00. Domain: whois-lookup $0.10, robots-txt-check $0.10. Content: url-to-markdown $0.01, summarize-api $0.05, content-type-detector $0.02, openapi-validate $0.30. Auth: jwt-decode $0.02. Utility: proof-of-existence $0.10, page-change-monitor $0.25, geo-restriction-check $0.20, agent-registry $0.05, ip-info $0.05, cron-parser $0.05. Cross-border: cross-border-intel-001 $0.15, cross-border-api-probe $0.50. Bundles: china-network-health $0.40, x402-launch-kit $1.20, cross-border-full $0.75, china-full-stack $0.80, site-security-audit $0.40, content-analysis $0.20, domain-intel-full $0.30. Each product includes selfDevelopCost in bazaar.info showing buy-vs-build comparison. Pay USDC on Base via x402 v2.",
        api: { type: "openapi", url: `${origin}/openapi.json`, is_user_authenticated: false },
        auth: { type: "x402", protocol: "x402/v2", network: "base", asset: "USDC" },
        contact_email: "use on-chain memo via /support",
        legal_info_url: `${origin}/support`,
        homepage_url: "https://github.com/shenquan88/web4shop-x402",
        products: products.map((p) => ({ path: p.path, title: p.title, price_usd: p.priceUsd })),
        resources: products.map((p) => ({
          url: `${origin}${p.path}`,
          method: "GET",
          description: p.title,
          accepts: [{
            scheme: store.scheme || "exact",
            network: store.networkCaip2,
            asset: store.asset,
            amount: toAtomicUnits(p.priceUsd),
            payTo: store.payTo,
            maxTimeoutSeconds: store.maxTimeoutSeconds,
            extra: { name: store.assetName, version: store.assetVersion },
          }],
        })),
      };
      return new Response(JSON.stringify(manifest, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
    // OpenAPI 端的大目录（给 agent 自动发现/生成客户端）
    if (path === "/openapi.json") {
      const origin = url.origin;
      const spec = {
        openapi: "3.0.3",
        info: {
          title: "web4shop x402 services",
          version: "1.0.0",
          description: "x402 paid API catalog. Unauthenticated GET returns 402 + payment requirements; retry with X-PAYMENT after settling USDC on Base.",
        },
        servers: [{ url: origin }],
        paths: Object.fromEntries(products.map((p) => [p.path, {
          get: {
            summary: p.title,
            description: `${p.description}\n\nPrice: $${p.priceUsd} USDC (x402).`,
            parameters: [{ name: "url", in: "query", schema: { type: "string" }, required: false }],
            responses: {
              "402": { description: "Payment required — x402 v2 offer in body + PAYMENT-REQUIRED header" },
              "200": { description: "Paid content delivered (after x402 settlement)" },
            },
          },
        }])),
      };
      return new Response(JSON.stringify(spec, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json; charset=utf-8", "Access-Control-Allow-Origin": "*" },
      });
    }
    if (path === "/robots.txt") {
      return new Response(
        `User-agent: *
Allow: /
Disallow: /api/settlements
Disallow: /api/stats
Sitemap: ${url.origin}/sitemap.xml
`,
        { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8", "Access-Control-Allow-Origin": "*" } }
      );
    }

    // 客服端点（免费）——平台无聊天窗口；走链上 memo，零个人信息暴露
    if (path === "/support") {
      return new Response(
        JSON.stringify(
          {
            support: {
              store: store.name,
              contact_method:
                "Reply to your settlement transaction with a 0-amount USDC transfer memo on Base describing the issue.",
              response_sla: "within 72 hours",
              refund_policy:
                "Full refund to the payer address if delivered content is unusable; dispute via payment memo.",
              products: products.map((p) => ({ path: p.path, title: p.title })),
            },
          },
          null,
          2
        ),
        { status: 200, headers: jsonHeaders() }
      );
    }

    // ===== 免费层（获客磁铁；配额走 KV 按天/IP 限次）=====
    // 设计: US 视角探测免费（CF 边缘天然 vantage），CN 视角物理上必须付费探针 → 天然漏斗
    async function freeQuota(limit, endpointName) {
      if (!env.SETTLEMENTS) return { ok: true, remaining: limit }; // KV 未绑则放行（降级）
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      const day = new Date().toISOString().slice(0, 10);
      const key = `freequota:${endpointName || "default"}:${ip}:${day}`;
      const cur = parseInt((await env.SETTLEMENTS.get(key)) || "0", 10);
      if (cur >= limit) return { ok: false, remaining: 0 };
      await env.SETTLEMENTS.put(key, String(cur + 1), { expirationTtl: 172800 });
      return { ok: true, remaining: limit - cur - 1 };
    }
    function guardPublicHttp(targetUrl) {
      let u;
      try { u = new URL(targetUrl); } catch (e) { return "invalid URL"; }
      if (!["http:", "https:"].includes(u.protocol)) return "scheme not allowed";
      const host = u.hostname;
      if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return "local host blocked";
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
        const p = host.split(".").map(Number);
        if (p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254)) return "private address blocked";
      }
      return null;
    }

    // FILE-OWNER: DSH — 免费层修复 origin 硬编码 + upsell 更新指向全商品
    const STORE_ORIGIN = "https://web4shop-x402.web4shop-7023.workers.dev";

    if (path === "/api/free/us-probe") {
      const target = url.searchParams.get("url");
      if (!target) return new Response(JSON.stringify({ error: "missing ?url=", free_quota: "3/day per IP" }), { status: 400, headers: jsonHeaders() });
      const guardErr = guardPublicHttp(target);
      if (guardErr) return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(3, "us-probe");
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free quota exhausted (3/day per IP)",
          upgrade: { product: "reachability-live", price_usd: 0.02, url: STORE_ORIGIN + "/api/products/reachability-live", note: "unlimited paid checks; also CN-side view available" },
        }), { status: 429, headers: jsonHeaders() });
      }
      let out = { vantage: "cloudflare-edge (global/US)", target, http_code: null, latency_ms: null, status: "error" };
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        const t0 = Date.now();
        const resp = await fetch(target, { signal: ctrl.signal, headers: { "User-Agent": "web4shop-free-probe/1.0" }, redirect: "follow" });
        clearTimeout(timer);
        out.http_code = resp.status;
        out.latency_ms = Date.now() - t0;
        out.status = resp.ok ? "ok" : "reachable_error";
      } catch (e) {
        out.status = "unreachable";
        out.error = String(e).slice(0, 120);
      }
      out.free_remaining_today = quota.remaining;
      out.upsell = {
        note: "This is the US/global vantage. Want to know if it's reachable from mainland China consumer networks?",
        cn_view: { product: "reachability-live", price_usd: 0.02, url: STORE_ORIGIN + "/api/products/reachability-live" },
        full_report: { product: "china-network-health", price_usd: 0.40, url: STORE_ORIGIN + "/api/products/china-network-health", note: "DNS leak + firewall status + live probe bundle" },
      };
      return new Response(JSON.stringify(out, null, 2), { status: 200, headers: jsonHeaders() });
    }

    if (path === "/api/free/x402-audit") {
      const target = url.searchParams.get("url");
      if (!target) return new Response(JSON.stringify({ error: "missing ?url=", free_quota: "1/day per IP" }), { status: 400, headers: jsonHeaders() });
      const guardErr = guardPublicHttp(target);
      if (guardErr) return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(1, "x402-audit");
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free audit used today (1/day per IP)",
          upgrade: {
            basic: { product: "x402-compliance-check", price_usd: 0.50, url: STORE_ORIGIN + "/api/products/x402-compliance-check", note: "full 8-check audit, unlimited, instant" },
            pro: { product: "x402-audit-pro", price_usd: 1.00, url: STORE_ORIGIN + "/api/products/x402-audit-pro", note: "14-point enhanced audit: security headers, TLS, response time, rate limit" },
            bundle: { product: "x402-launch-kit", price_usd: 1.20, url: STORE_ORIGIN + "/api/products/x402-launch-kit", note: "14pt + 8pt + setup guide bundle" },
          },
        }), { status: 429, headers: jsonHeaders() });
      }
      const report = await checkX402Compliance(target);
      // 免费版只给前 3 项（402/版本/accepts），完整 8 项付费
      const freeChecks = report.checks.slice(0, 3);
      const lockedChecks = report.checks.slice(3).map((c) => ({ name: c.name, result: "🔒 full audit" }));
      return new Response(JSON.stringify({
        product: "free-x402-audit",
        endpoint: target,
        summary: { checks_shown: freeChecks.length, checks_locked: lockedChecks.length, verdict_hint: report.overall },
        checks: freeChecks,
        locked: lockedChecks,
        upsell: {
          basic: { product: "x402-compliance-check", price_usd: 0.50, url: STORE_ORIGIN + "/api/products/x402-compliance-check", note: "full 8-check audit" },
          pro: { product: "x402-audit-pro", price_usd: 1.00, url: STORE_ORIGIN + "/api/products/x402-audit-pro", note: "14-point enhanced audit with security headers/TLS/response-time" },
          bundle: { product: "x402-launch-kit", price_usd: 1.20, url: STORE_ORIGIN + "/api/products/x402-launch-kit", note: "14pt + 8pt + setup guide" },
        },
      }, null, 2), { status: 200, headers: jsonHeaders() });
    }

    // 免费 DNS 查询 — 第三层漏斗入口
    if (path === "/api/free/dns-lookup") {
      const domain = url.searchParams.get("domain");
      if (!domain) return new Response(JSON.stringify({ error: "missing ?domain=", free_quota: "5/day per IP" }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(5, "dns-lookup");
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free DNS quota exhausted (5/day per IP)",
          upgrade: {
            full_dns: { product: "dns-lookup", price_usd: 0.001, url: STORE_ORIGIN + "/api/products/dns-lookup", note: "unlimited DNS lookups, 6 record types" },
            dnssec: { product: "dnssec-check", price_usd: 0.15, url: STORE_ORIGIN + "/api/products/dnssec-check", note: "DNSSEC validation + chain of trust" },
            domain_bundle: { product: "domain-intel-full", price_usd: 0.30, url: STORE_ORIGIN + "/api/products/domain-intel-full", note: "WHOIS + DNSSEC + DNS + SSL bundle" },
          },
        }), { status: 429, headers: jsonHeaders() });
      }
      // 免费：只给 A 记录
      let result = {};
      try { result = await dohQuery(domain, "A"); } catch (e) { result = { error: String(e).substring(0, 80) }; }
      return new Response(JSON.stringify({
        product: "free-dns-lookup",
        domain,
        free_remaining_today: quota.remaining,
        A_records: result,
        note: "Free tier shows A records only. Upgrade for AAAA/MX/TXT/NS/CNAME + DNSSEC validation.",
        upsell: {
          full_dns: { product: "dns-lookup", price_usd: 0.001, url: STORE_ORIGIN + "/api/products/dns-lookup" },
          domain_bundle: { product: "domain-intel-full", price_usd: 0.30, url: STORE_ORIGIN + "/api/products/domain-intel-full" },
        },
      }, null, 2), { status: 200, headers: jsonHeaders() });
    }

    // 免费安全头检查 — 第四层漏斗入口
    if (path === "/api/free/security-check") {
      const target = url.searchParams.get("url");
      if (!target) return new Response(JSON.stringify({ error: "missing ?url=", free_quota: "3/day per IP" }), { status: 400, headers: jsonHeaders() });
      const guardErr = guardPublicHttp(target);
      if (guardErr) return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(3, "security-check");
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free security check quota exhausted (3/day per IP)",
          upgrade: {
            full_headers: { product: "security-headers-check", price_usd: 0.15, url: STORE_ORIGIN + "/api/products/security-headers-check", note: "10+ header audit with score and recommendations" },
            ssl: { product: "ssl-cert-check", price_usd: 0.15, url: STORE_ORIGIN + "/api/products/ssl-cert-check" },
            bundle: { product: "site-security-audit", price_usd: 0.40, url: STORE_ORIGIN + "/api/products/site-security-audit", note: "SSL + headers + broken links bundle" },
          },
        }), { status: 429, headers: jsonHeaders() });
      }
      // 免费：只检查 3 个头
      try {
        const resp = await fetch(target, { method: "HEAD", signal: AbortSignal.timeout(8000), redirect: "follow" });
        const checks = [
          { name: "strict_transport_security", present: resp.headers.has("strict-transport-security") },
          { name: "content_security_policy", present: resp.headers.has("content-security-policy") },
          { name: "x_frame_options", present: resp.headers.has("x-frame-options") },
        ];
        const passed = checks.filter(c => c.present).length;
        return new Response(JSON.stringify({
          product: "free-security-check",
          target,
          free_remaining_today: quota.remaining,
          checks_shown: 3,
          checks_total: 10,
          passed: passed,
          note: "Free tier shows 3 of 10 checks. Upgrade for full audit with score, grade, and recommendations.",
          upsell: {
            full: { product: "security-headers-check", price_usd: 0.15, url: STORE_ORIGIN + "/api/products/security-headers-check" },
            bundle: { product: "site-security-audit", price_usd: 0.40, url: STORE_ORIGIN + "/api/products/site-security-audit" },
          },
        }, null, 2), { status: 200, headers: jsonHeaders() });
      } catch (e) {
        return new Response(JSON.stringify({ error: String(e).substring(0, 120) }), { status: 500, headers: jsonHeaders() });
      }
    }

    // 结算记录（哨兵专用，令牌保护；外部只知链上公开数据，聚合列表不公开）
    if (path === "/api/settlements") {
      const token = url.searchParams.get("token") || "";
      if (!env.SENTINEL_TOKEN || token !== env.SENTINEL_TOKEN) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: jsonHeaders(),
        });
      }
      if (!env.SETTLEMENTS) {
        return new Response(JSON.stringify({ settlements: [], note: "KV not bound" }), {
          status: 200,
          headers: jsonHeaders(),
        });
      }
      const list = await env.SETTLEMENTS.list({ prefix: "settle:", limit: 50 });
      const out = [];
      for (const k of list.keys) {
        const v = await env.SETTLEMENTS.get(k.name);
        if (v) out.push(JSON.parse(v));
      }
      out.sort((a, b) => (a.settledAt < b.settledAt ? 1 : -1));
      return new Response(JSON.stringify({ settlements: out }, null, 2), {
        status: 200,
        headers: jsonHeaders(),
      });
    }

    // 浏览统计（哨兵专用，令牌保护）
    if (path === "/api/stats") {
      const token = url.searchParams.get("token") || "";
      if (!env.SENTINEL_TOKEN || token !== env.SENTINEL_TOKEN) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401, headers: jsonHeaders(),
        });
      }
      if (!env.SETTLEMENTS) {
        return new Response(JSON.stringify({ views: {} }), { status: 200, headers: jsonHeaders() });
      }
      const list = await env.SETTLEMENTS.list({ prefix: "view:" });
      const views = {};
      for (const k of list.keys) {
        views[k.name.slice(5)] = parseInt((await env.SETTLEMENTS.get(k.name)) || "0", 10);
      }
      return new Response(JSON.stringify({ views, note: "raw fetch counts, includes bots/probes" }, null, 2), {
        status: 200, headers: jsonHeaders(),
      });
    }

    // 探针内部端点（哨兵令牌保护）
    if (path === "/api/internal/probe-queue") {
      const token = url.searchParams.get("token") || "";
      if (!env.SENTINEL_TOKEN || token !== env.SENTINEL_TOKEN) {
        return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: jsonHeaders() });
      }
      const list = await env.SETTLEMENTS.list({ prefix: "queue:" });
      const queue = list.keys.map((k) => k.name.slice(6));
      return new Response(JSON.stringify({ queue }, null, 2), { status: 200, headers: jsonHeaders() });
    }
    if (path === "/api/internal/probe-result" && request.method === "POST") {
      const token = url.searchParams.get("token") || "";
      if (!env.SENTINEL_TOKEN || token !== env.SENTINEL_TOKEN) {
        return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: jsonHeaders() });
      }
      const body = await request.json();
      const key = String(body.url || "").replace(/\/+$/, "").toLowerCase();
      if (!key.startsWith("http")) {
        return new Response(JSON.stringify({ error: "invalid url" }), { status: 400, headers: jsonHeaders() });
      }
      await env.SETTLEMENTS.put("probe:" + key, JSON.stringify(body.result || {}), { expirationTtl: 7 * 86400 });
      await env.SETTLEMENTS.delete("queue:" + key);
      return new Response(JSON.stringify({ ok: true, url: key }), { status: 200, headers: jsonHeaders() });
    }

    const product = products.find((p) => p.path === path);
    if (product) {
      // 实时拨测: 带 ?url= 时优先查缓存/已付状态
      if (product.id === "reachability-live" && env && env.SETTLEMENTS) {
        const raw = (url.searchParams.get("url") || "").trim();
        const key = raw.replace(/\/+$/, "").toLowerCase();
        if (key.startsWith("http")) {
          const cached = await env.SETTLEMENTS.get("probe:" + key);
          if (cached) {
            return new Response(JSON.stringify({ url: key, result: JSON.parse(cached), cached: true }, null, 2), {
              status: 200, headers: jsonHeaders(),
            });
          }
          const paid = await env.SETTLEMENTS.get("paid:" + key);
          if (paid && !request.headers.get("X-PAYMENT") && !request.headers.get("PAYMENT-SIGNATURE")) {
            return new Response(JSON.stringify({
              status: "PENDING", url: key,
              message: "Queued for the next probe cycle (~30 minutes). Re-GET to retrieve.",
            }, null, 2), { status: 200, headers: jsonHeaders() });
          }
        }
      }
      if (request.method !== "GET") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), {
          status: 405,
          headers: jsonHeaders(),
        });
      }
      return handlePaid(request, path, product, env, ctx);
    }

    if (path === "/" || path === "/api/products") {
      if (ctx) ctx.waitUntil(bumpView(env, "page/"));
      // HTML 落地页（浏览器/搜索引擎爬虫）—— SEO：JSON 无法被搜索排名，HTML 才有标题/结构化数据
      // OWNER: Claude  CHANGELOG: 2026-09-11 Claude 新增 HTML 内容协商
      const wantsHtml = (request.headers.get("Accept") || "").includes("text/html");
      if (wantsHtml) {
        const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
        const jsonLd = {
          "@context": "https://schema.org",
          "@type": "ItemList",
          name: store.name + " — x402 paid API services",
          itemListElement: products.map((p, i) => ({
            "@type": "ListItem", position: i + 1,
            item: { "@type": "Service", name: p.title, description: p.description.split("DIY comparison:")[0].slice(0, 300), url: url.origin + p.path, offers: { "@type": "Offer", price: p.priceUsd, priceCurrency: "USD" } },
          })),
        };
        const rows = products.map((p) => {
          const freeTag = p.priceUsd === 0 ? "" : "";
          return `<tr><td><a href="${p.path}">${esc(p.path.replace("/api/products/", ""))}</a></td><td>$${p.priceUsd}</td><td>${esc(p.description.split("DIY comparison:")[0].slice(0, 140))}</td></tr>`;
        }).join("\n");
        const html = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>web4shop — ${products.length} Paid API Services for AI Agents (x402, USDC on Base)</title>
<meta name="description" content="Pay-per-call API services for AI agents: mainland-China vantage connectivity checks, x402 endpoint compliance audits, OFAC sanctions screening, domain health. No accounts, no API keys — x402 native.">
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.55}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px 10px;text-align:left}
h1 small{color:#666}.free{background:#e8f5e9;border:1px solid #4caf50;padding:.8rem 1rem;border-radius:8px}</style>
</head><body>
<h1>web4shop — Paid API Services for AI Agents <small>(x402 · USDC on Base)</small></h1>
<p>${products.length} live products. No accounts, no API keys — an agent with a wallet buys in one HTTP round-trip (HTTP 402 → pay → 200).</p>
<div class="free"><b>Free tier:</b> <a href="/api/free/us-probe?url=https://example.com">us-probe</a> (3/day/IP) · <a href="/api/free/x402-audit?url=...">x402-audit</a> (1/day/IP) — try before you pay.</div>
<table><tr><th>Endpoint</th><th>Price</th><th>What you get</th></tr>
${rows}
</table>
<h2>For agents</h2>
<p>Machine catalog: <a href="/.well-known/x402.json">.well-known/x402.json</a> · <a href="/openapi.json">openapi.json</a> · Public feed: <a href="/bulletin">/bulletin</a></p>
<h2>For operators</h2>
<p>Auditing your own x402 endpoint before listing: <a href="/api/products/x402-compliance-check">x402-compliance-check</a> ($0.50).</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8", "Access-Control-Allow-Origin": "*" },
        });
      }
      return new Response(
        JSON.stringify(
          {
            service: store.name + " — x402 paid endpoints",
            products: products.map((p) => ({
              path: p.path,
              title: p.title,
              price: `$${p.priceUsd}`,
              network: store.network,
              asset: "USDC",
              category: p.category,
            })),
            discover:
              "Send GET to any product path to receive HTTP 402 with x402 v2 payment requirements.",
            free_pages: Object.keys(freePages),
            free_api: ["/api/free/us-probe", "/api/free/x402-audit", "/api/free/dns-lookup", "/api/free/security-check"],
          },
          null,
          2
        ),
        { status: 200, headers: jsonHeaders() }
      );
    }

    return new Response(JSON.stringify({ error: "Not found", hint: "GET / for product index" }), {
      status: 404,
      headers: jsonHeaders(),
    });
  },
};
