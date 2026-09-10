# web4shop — x402 Paid API Store

> 37 products on x402 v2 | USDC on Base | Pay-per-call | No API keys needed
> Worker version: d7ca867c | Last updated: 2026-09-11

## What is this?

A store of API services that use the x402 protocol for autonomous AI agent payments. AI agents send a GET request, receive HTTP 402 with payment requirements, pay USDC on Base, and get the content back. No signup, no API keys, no subscriptions.

**Base URL:** `https://web4shop-x402.web4shop-7023.workers.dev`

## Products (37 total)

### China-Exclusive (our moat — no competitors have CN vantage)

| Product | Price | Description |
|---|---|---|
| reachability-live | `\.02` | Live URL probe from mainland China |
| cn-reachability-digest | `\.05` | Daily CN reachability summary |
| cn-us-reachability-snapshot | `\.15` | 12-domain CN vs US comparison |
| cn-dns-leak-check | `\.20` | DNS resolution divergence (4 resolvers via DoH) |
| cn-infra-intel-daily | `\.25` | Daily cloud infra: Aliyun/Tencent/AWS-CN/CF-CN |
| china-firewall-status | `\.30` | Network connectivity status with DNS divergence |

### Security & Compliance

| Product | Price | Description |
|---|---|---|
| ssl-cert-check | `\.15` | SSL certificate expiry, issuer, chain |
| security-headers-check | `\.15` | 10+ security headers audit (CSP, HSTS, CORS) |
| broken-links-check | `\.20` | Dead link scanner for any URL |
| dnssec-check | `\.15` | DNSSEC validation and chain of trust |
| x402-compliance-check | `\.50` | 8-point x402 endpoint audit |
| x402-audit-pro | `\.00` | 14-point enhanced audit + security |

### Network & DNS

| Product | Price | Description |
|---|---|---|
| dns-lookup | `\.001` | A/AAAA/MX/TXT/NS/CNAME via DoH (4 resolvers) |
| health-check | `\.001` | HTTP status + latency + SSL + redirects |
| url-to-markdown | `\.01` | Clean Markdown extraction from any URL |
| domain-health | `\.02` | 4-point domain health audit |

### Domain Intelligence

| Product | Price | Description |
|---|---|---|
| whois-lookup | `\.10` | RDAP domain registration lookup |
| robots-txt-check | `\.10` | robots.txt compliance and SEO audit |

### Content & Analysis

| Product | Price | Description |
|---|---|---|
| summarize-api | `\.05` | Structured metadata extraction from any URL |
| openapi-validate | `\.30` | OpenAPI/Swagger spec validation |

### Utility

| Product | Price | Description |
|---|---|---|
| proof-of-existence | `\.10` | SHA-256 hash + timestamp proof |
| page-change-monitor | `\.25` | Webpage change detection (KV hash comparison) |
| geo-restriction-check | `\.20` | Geographic content restriction detection |
| agent-registry | `\.05` | AI agent registration and discovery |

### Cross-Border

| Product | Price | Description |
|---|---|---|
| cross-border-intel-001 | `\.15` | Cross-border network intelligence |
| cross-border-api-probe | `\.50` | Three-vantage API reachability comparison |

### Bundles (save 85-92%+ vs self-development)

| Bundle | Price | Includes |
|---|---|---|
| china-network-health | `\.40` | DNS leak + firewall + live probe |
| x402-launch-kit | `\.20` | 14pt audit + 8pt check + setup guide |
| cross-border-full | `\.75` | API probe + CN-US snapshot + infra daily |
| china-full-stack | `\.80` | All 6 China products in one report |
| site-security-audit | `\.40` | SSL + headers + broken links |
| content-analysis | `\.20` | Markdown + metadata + broken links |
| domain-intel-full | `\.30` | WHOIS + DNSSEC + DNS + SSL |

### Other

| Product | Price | Description |
|---|---|---|
| umbrella | `\.01` | Cheapest full-flow x402 test |
| titanium-business-contact | `\.10` | Ferrotitanium supplier contact info |
| ofac-screen | `\.25` | OFAC sanctions screening |

## Free Tier (no payment needed)

| Endpoint | Quota | What you get |
|---|---|---|
| `/api/free/us-probe?url=` | 3/day | US/global URL probe (status + latency) |
| `/api/free/x402-audit?url=` | 1/day | 3 of 8 x402 compliance checks |
| `/api/free/dns-lookup?domain=` | 5/day | A records only (upgrade for full) |
| `/api/free/security-check?url=` | 3/day | 3 of 10 security header checks |

## How to use

1. Send `GET` to any product path (e.g. `/api/products/dns-lookup?domain=example.com`)
2. Receive `HTTP 402` with `PAYMENT-REQUIRED` header (base64 encoded)
3. Decode the header to get payment details (amount, payTo address, USDC on Base)
4. Pay via x402 protocol (USDC transfer on Base)
5. Re-send `GET` with `X-PAYMENT` header
6. Receive `HTTP 200` with content + receipt

## selfDevelopCost

Every 402 response includes a `selfDevelopCost` field in the bazaar extension showing:
- Token cost to self-develop (e.g. `\-5`)
- Time required (e.g. `15 min`)
- Required infrastructure (e.g. `Mainland China VPS`)
- Required expertise
- Buy vs Build comparison (e.g. "Buy `\.02` vs self-dev `\-5`. Save 98%+")

## Documentation

- [Product Backlog](docs/PRODUCT-BACKLOG.md) — 13 pending products from real GitHub demand
- [Buy vs Build Compass](docs/BUY-VS-BUILD-COMPASS.md) — AI decision model
- [Multi-Tier Pricing](docs/MULTI-TIER-PRICING.md) — Future layered pricing design
- [Product Strategy](docs/product-strategy.md) — P0/P1/P2 product strategy
- [Flywheel](docs/FLYWHEEL.md) — Virtuous cycle philosophy

## License

MIT