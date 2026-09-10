// FILE-OWNER: DSH
// FILE-PURPOSE: x402 付费端点 Cloudflare Worker 主入口
// LAST-MODIFIED-BY: DSH @ 2026-09-10
// DO-NOT-MODIFY-WITHOUT: DSH 确认（subagent 委派时必须先读此备注）

/**
 * Web4 x402 Paid Endpoint — Cloudflare Worker (data-driven)
 *
 * 商品目录在 products.json（单一事实源）。加商品 = 改 JSON → `pwsh publish.ps1`。
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
  return {
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
        name_for_human: "web4shop — x402 Paid API Services",
        name_for_model: "web4shop_x402_services",
        description_for_human: "Pay-per-call API services: mainland-China vantage connectivity checks, CN/US infrastructure snapshots, x402 endpoint compliance audits (8-point basic + 14-point pro), cross-border API probing, DNS resolution divergence checks, cloud infrastructure reachability daily. Settled in USDC on Base via x402.",
        description_for_model: "x402 protocol paid API catalog. Request any product path unauthenticated to receive HTTP 402 with an accepts[] payment offer (scheme exact, network base, USDC). Pay via EIP-3009 transferWithAuthorization and retry with the X-PAYMENT header to receive content. Products: umbrella ($0.01, cheapest full-flow test), reachability-live ($0.02, live CN probe of any URL), cn-reachability-digest ($0.05), cn-us-reachability-snapshot ($0.15, 12-domain CN vs US comparison), cross-border-intel-001 ($0.30), x402-compliance-check ($0.50, instant 8-point audit), x402-audit-pro ($1.00, 14-point enhanced audit with security headers/TLS/response-time/content-type/rate-limit/price-transparency), cn-infra-intel-daily ($0.25, daily cloud infra reachability: Aliyun/Tencent/AWS-CN/Cloudflare-CN), cross-border-api-probe ($0.50, three-vantage API reachability comparison), cn-dns-leak-check ($0.20, DNS resolution divergence across 4 resolvers via DoH), china-firewall-status ($0.30, network connectivity status with DNS divergence analysis).",
        api: { type: "openapi", url: `${origin}/openapi.json`, is_user_authenticated: false },
        auth: { type: "x402", protocol: "x402/v2", network: "base", asset: "USDC" },
        contact_email: "use on-chain memo via /support",
        legal_info_url: `${origin}/support`,
        homepage_url: "https://github.com/shenquan88/web4shop-x402",
        products: products.map((p) => ({ path: p.path, title: p.title, price_usd: p.priceUsd })),
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
    async function freeQuota(limit) {
      if (!env.SETTLEMENTS) return { ok: true, remaining: limit }; // KV 未绑则放行（降级）
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      const day = new Date().toISOString().slice(0, 10);
      const key = `freequota:${ip}:${day}`;
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

    if (path === "/api/free/us-probe") {
      const target = url.searchParams.get("url");
      if (!target) return new Response(JSON.stringify({ error: "missing ?url=", free_quota: "3/day per IP" }), { status: 400, headers: jsonHeaders() });
      const guardErr = guardPublicHttp(target);
      if (guardErr) return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(3);
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free quota exhausted (3/day per IP)",
          upgrade: { product: "reachability-live", price_usd: 0.02, url: origin + "/api/products/reachability-live", note: "unlimited paid checks; also CN-side view available" },
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
        cn_view: { product: "reachability-live", price_usd: 0.02, url: origin + "/api/products/reachability-live" },
      };
      return new Response(JSON.stringify(out, null, 2), { status: 200, headers: jsonHeaders() });
    }

    if (path === "/api/free/x402-audit") {
      const target = url.searchParams.get("url");
      if (!target) return new Response(JSON.stringify({ error: "missing ?url=", free_quota: "1/day per IP" }), { status: 400, headers: jsonHeaders() });
      const guardErr = guardPublicHttp(target);
      if (guardErr) return new Response(JSON.stringify({ error: guardErr }), { status: 400, headers: jsonHeaders() });
      const quota = await freeQuota(1);
      if (!quota.ok) {
        return new Response(JSON.stringify({
          error: "free audit used today (1/day per IP)",
          upgrade: { product: "x402-compliance-check", price_usd: 0.5, url: origin + "/api/products/x402-compliance-check", note: "full 8-check audit, unlimited, instant" },
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
        upsell: { full_audit: { product: "x402-compliance-check", price_usd: 0.5, url: origin + "/api/products/x402-compliance-check" } },
      }, null, 2), { status: 200, headers: jsonHeaders() });
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
