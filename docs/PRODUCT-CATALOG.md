<!-- FILE-OWNER: DSH | PURPOSE: SEO product documentation | DO-NOT-MODIFY-WITHOUT: DSH 确认 -->

# x402 Paid API Services — Product Catalog

> 12 x402 v2 compliant paid API endpoints. USDC micropayments on Base. No API key, no account — just pay per call.

## What is x402?

x402 is an HTTP-native payment protocol. When you request a paid endpoint without payment, the server responds with HTTP 402 (Payment Required) and a base64-encoded payment header. Pay USDC on Base, retry with the payment proof, and get your content.

## Services

### 1. x402 Compliance Audit Pro — .00
**Endpoint:** GET /api/products/x402-audit-pro?url=TARGET_URL

14-point x402 protocol compliance audit of any endpoint:
1. HTTP 402 response format
2. x402Version field
3. accepts[] structure
4. Accept schema validation
5. PAYMENT-REQUIRED header
6. Resource metadata
7. Bazaar extension
8. Bazaar info
9. Security headers (CORS, CSP, HSTS)
10. SSL/TLS certificate validity
11. Response time benchmark
12. Content-Type compliance
13. Rate limiting detection
14. Price transparency

**Unique:** Only x402 compliance audit tool in the ecosystem.

### 2. x402 Compliance Check — .50
**Endpoint:** GET /api/products/x402-compliance-check

8-point compliance audit (lighter version of audit pro).

### 3. Cross-Border API Probe — .50
**Endpoint:** GET /api/products/cross-border-api-probe?target=URL

Three-vantage point API reachability comparison:
- Cloudflare edge (global)
- DNS-over-HTTPS (Google/Cloudflare)
- Mainland China VPS (23.173.216.42)

Returns: per-location reachability, latency, DNS resolution, SSL status.

### 4. China Firewall Status — .30
**Endpoint:** GET /api/products/china-firewall-status?target=DOMAIN

Detects GFW blockade status for any domain:
- DNS divergence analysis (4 resolvers)
- International HTTP probe
- China VPS direct probe
- Blockade type classification

### 5. CN Infrastructure Intel Daily — .25
**Endpoint:** GET /api/products/cn-infra-intel-daily

Daily mainland China cloud infrastructure reachability report:
- Alibaba Cloud (oss.aliyuncs.com)
- Tencent Cloud (cos.ap-guangzhou.myqcloud.com)
- AWS China
- Cloudflare CN nodes

### 6. CN DNS Leak Check — .20
**Endpoint:** GET /api/products/cn-dns-leak-check?domain=DOMAIN

DNS resolution pollution/hijack detection across 4 resolvers:
- Google DNS (dns.google)
- Cloudflare (1.1.1.1)
- AliDNS (dns.alidns.com)
- DNSPod (doh.pub)

### 7. CN-US Reachability Snapshot — .15
**Endpoint:** GET /api/products/cn-us-reachability-snapshot

12-domain China vs US reachability comparison with divergence flags.

### 8. Cross-Border Intel — .15
**Endpoint:** GET /api/products/cross-border-intel-001

Cross-border infrastructure intelligence report.

### 9. CN Reachability Digest — .05
**Endpoint:** GET /api/products/cn-reachability-digest

Daily mainland China probe results summary.

### 10. Business Contact — .10
**Endpoint:** GET /api/products/titanium-business-contact

Company contact information endpoint.

### 11. Live URL Probe — .02
**Endpoint:** GET /api/products/reachability-live?url=TARGET_URL

Live URL reachability probe from mainland China VPS.

### 12. Umbrella — .01
**Endpoint:** GET /api/products/umbrella

Hello world test endpoint. Cheapest full-flow x402 test.

## How to Buy

1. GET the endpoint URL without payment headers → receive HTTP 402 + PAYMENT-REQUIRED header
2. Decode the base64 PAYMENT-REQUIRED header to get payment details (amount, payTo, asset, network)
3. Send USDC on Base to the payTo address (via x402 facilitator or direct transfer)
4. GET the endpoint URL again with X-PAYMENT header containing the payment proof
5. Receive HTTP 200 + content

## Technical Details

- **Protocol:** x402 v2
- **Network:** Base (eip155:8453)
- **Asset:** USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)
- **Payment Address:** 0xd29D93F0A5E161F1F286F5Cd5Afeb718837C15E1
- **Facilitator:** https://facilitator.openx402.ai
- **Bazaar Extension:** Supported
- **Hosting:** Cloudflare Workers (global edge, zero cold start)

## Links

- [Live Store](https://web4shop-x402.web4shop-7023.workers.dev)
- [GitHub Repository](https://github.com/shenquan88/x402-compliance-store)
- [API Documentation](docs/API.md)
- [Compliance Report](docs/compliance-report.json)