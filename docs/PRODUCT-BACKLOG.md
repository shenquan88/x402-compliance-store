<!-- FILE-OWNER: DSH | PURPOSE: 待开发产品需求清单（基于真实 GitHub issues 搜索）| DO-NOT-MODIFY-WITHOUT: DSH 确认 -->

# 待开发产品需求清单

> 基于 GitHub Issues 搜索（2026-09-10）整理的真实需求。
> 我们现在没有这些商品，但能开发。空闲或做周边产品时顺道开发。

## 优先级 P1 — 需求量大 + Workers 可实现

### 1. ssl-cert-check — SSL 证书到期检查 $0.15
- **需求来源**: 9489 个 GitHub issues 关于 SSL 证书问题
- **功能**: 输入 URL → 返回证书颁发者、到期日、剩余天数、域名匹配、链完整性
- **自开发成本**: $1-3 token + 15 min + TLS 证书知识
- **Workers 可行性**: ✅ fetch + 读取响应头中的证书信息
- **竞品**: SSL Labs（但不开源、不支持 x402、不按次收费）

### 2. security-headers-check — 安全头检查 $0.15
- **需求来源**: 48572 个 issues（CSP, HSTS, CORS, X-Frame-Options）
- **功能**: 输入 URL → 检查 10+ 安全头 → 返回评分 + 缺失项 + 修复建议
- **自开发成本**: $1-3 token + 15 min + OWASP 安全知识
- **Workers 可行性**: ✅ fetch + 读 response headers
- **竞品**: securityheaders.com（不支持 x402、不按次收费）

### 3. broken-links-check — 死链检查 $0.20
- **需求来源**: 76487 个 issues
- **功能**: 输入 URL → 抓取页面 → 解析所有链接 → 逐个检查状态码 → 返回死链列表
- **自开发成本**: $2-5 token + 20 min + HTML 解析
- **Workers 可行性**: ✅ fetch HTML + 正则提取链接 + 逐个 fetch
- **竞品**: W3C Link Checker（不支持 x402）

### 4. whois-lookup — 域名 WHOIS 查询 $0.10
- **需求来源**: 4913 个 issues
- **功能**: 输入域名 → RDAP 查询 → 返回注册商、注册日、到期日、状态
- **自开发成本**: $0.50-2 token + 10 min + RDAP 协议
- **Workers 可行性**: ✅ RDAP 是 HTTP 协议
- **竞品**: whois.com（不支持 x402、不按次收费）

### 5. robots-txt-check — robots.txt 合规检查 $0.10
- **需求来源**: 1903 个 issues
- **功能**: 输入 URL → 获取 robots.txt → 解析规则 → 检查是否正确配置 → 返回建议
- **自开发成本**: $0.50-1 token + 10 min
- **Workers 可行性**: ✅ fetch + 解析文本

## 优先级 P2 — 需求中等 + 可实现

### 6. dnssec-check — DNSSEC 验证 $0.15
- **需求来源**: 8607 个 issues
- **功能**: 输入域名 → DoH 查询 + 验证 DNSSEC 签名 → 返回验证状态
- **Workers 可行性**: ✅ DoH 支持 DNSSEC（需要 DoH 设置 do=1）

### 7. openapi-validate — OpenAPI 规范验证 $0.30
- **需求来源**: 10403 个 issues
- **功能**: 输入 OpenAPI JSON URL → 验证结构 → 返回错误 + 建议
- **Workers 可行性**: ✅ fetch + JSON 解析 + schema 验证

### 8. proof-of-existence — 内容存在证明 $0.10
- **需求来源**: 14 个 issues（小众但价值高）
- **功能**: 输入内容 → 计算 SHA-256 → 存储 hash + 时间戳到 KV → 返回证明
- **Workers 可行性**: ✅ crypto.subtle + KV 存储

### 9. page-change-monitor — 网页变更监控 $0.25
- **需求来源**: 78144 个 issues（change monitor, website diff）
- **功能**: 输入 URL → 抓取内容 → 计算 hash → 与上次对比 → 返回变更摘要
- **Workers 可行性**: ✅ fetch + KV 存储上次内容

### 10. geo-restriction-check — 地理限制检测 $0.20
- **需求来源**: 2324 个 issues
- **功能**: 输入 URL → 从 Workers 全球边缘节点请求 → 检测是否返回地理限制 → 返回各国可达性
- **Workers 可行性**: ✅ Workers 部署在全球边缘

## 优先级 P3 — 有需求但需要更多资源

### 11. ip-geolocation — IP 地理位置 $0.10
- 需要外部 API（免费的有 Cloudflare 自带的 cf-ipcountry）
- Workers 可行性: ✅ 用 request.cf 获取地理位置

### 12. tls-version-check — TLS 版本检测 $0.15
- 需要原始 TLS 握手 → Workers 不支持
- 替代方案: 通过 HTTP 头推断（有限）

### 13. ct-log-check — 证书透明度日志检查 $0.15
- 查询 Google CT 日志 API
- Workers 可行性: ✅ HTTP 查询

## 开发计划

| 阶段 | 商品 | 预计开发时间 | 价格 |
|---|---|---|---|
| 空闲时顺道 | ssl-cert-check | 30 min | $0.15 |
| 空闲时顺道 | security-headers-check | 20 min | $0.15 |
| 空闲时顺道 | whois-lookup | 15 min | $0.10 |
| 做周边时 | broken-links-check | 40 min | $0.20 |
| 做周边时 | robots-txt-check | 15 min | $0.10 |
| 做周边时 | dnssec-check | 20 min | $0.15 |
| 做周边时 | proof-of-existence | 20 min | $0.10 |
| 后续 | openapi-validate | 30 min | $0.30 |
| 后续 | page-change-monitor | 40 min | $0.25 |
| 后续 | geo-restriction-check | 30 min | $0.20 |

## 套餐规划（待单品开发完成后）

| 套餐 | 包含 | 单买总价 | 套餐价 |
|---|---|---|---|
| site-health-check | ssl-cert + security-headers + broken-links + robots | $0.60 | $0.45 |
| domain-intel-full | whois + dnssec + ssl-cert + ct-log | $0.55 | $0.40 |
| full-security-audit | security-headers + ssl-cert + x402-audit-pro | $1.30 | $1.00 |
