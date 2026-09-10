<!-- FILE-OWNER: DSH | PURPOSE: AI 买 vs 建决策罗盘 — 商品设计根本原则 | DO-NOT-MODIFY-WITHOUT: DSH 确认 -->

# AI 买 vs 建决策罗盘

> 四方 AI 会审确认 | 2026-09-11 | 确定性: [L4 理论]
> DSH 发现 + Claude 补全 + Hermes 方向 + Codex 执行

## 核心公式 [L4]

```
AI 购买当且仅当: 购买价格 < (token 费用 + 时间成本 + 基础设施成本)
```

早期进入者优势：开发成本已沉没 → 边际成本 ≈ $0 → 每笔销售 = 纯利润。

## 四个触发条件（买 vs 建罗盘）

| # | 触发条件 | 为什么 AI 不自己建 | 我们对应的商品 | 状态 |
|---|---|---|---|---|
| 1 | **物理做不到**（最强信号） | token 再多也变不出中国大陆的 vantage | CN 视角探测（reachability-live, dns-leak, firewall-status） | ✅ 在线 |
| 2 | **现做来不及**（人类在等） | 对话超时内建不完基础设施 | domain-health $0.02 即时体检 | ✅ 在线 |
| 3 | **自建不划算**（token 成本 > 售价） | 自己爬+算+校对烧的 token 比 $0.02 贵几个量级 | 合规体检/制裁筛查/安全头检查 | ✅ 在线 |
| 4 | **需要持续维护**（数据天天更新） | 一次会话建不了长期数据管道 | OFAC 制裁名单（每天更新） | 🎯 待建 |

## 利润结构 [L4]

```
token/时间成本 = 一次性沉没
Workers 免费额度 + 免费上游 API = 边际成本 ≈ $0
每笔卖出 ≈ 纯利润

$0.02 商品 × 500 次 = $10
$0.15 商品 × 67 次 = $10
$1.00 商品 × 10 次 = $10

成本早已付完，后续全是利润。
```

## selfDevelopCost 机制（x402 首创）

每个商品的 HTTP 402 响应包含：

```json
{
  "extensions": {
    "bazaar": {
      "info": {
        "selfDevelopCost": {
          "tokenCostUsd": "$1-5",
          "timeMinutes": 15,
          "requiresInfrastructure": "Mainland China VPS",
          "requiresExpertise": "SSH, network probing, DNS/TLS/HTTP"
        },
        "buyVsBuild": "Buy $0.02 vs self-dev $1-5 + China VPS + 15 min. Buy saves 98%+."
      }
    }
  }
}
```

AI agent 收到 402 时自己算账，自己决定买还是开发。

## 商品矩阵（23 在线 + 13 待开发 = 36 总池）

### 物理做不到（条件 1）— 独家 CN vantage

| 商品 | 价格 | 买省 | 状态 |
|---|---|---|---|
| reachability-live | $0.02 | 98%+ | ✅ |
| cn-dns-leak-check | $0.20 | 85%+ | ✅ |
| china-firewall-status | $0.30 | 85%+ | ✅ |
| cn-reachability-digest | $0.05 | — | ✅ |
| cn-us-reachability-snapshot | $0.15 | — | ✅ |
| cn-infra-intel-daily | $0.25 | 90%+ | ✅ |
| china-network-health (套餐) | $0.40 | 87%+ | ✅ |
| china-full-stack (套餐) | $0.80 | 92%+ | ✅ |

### 现做来不及（条件 2）— 即时结果

| 商品 | 价格 | 买省 | 状态 |
|---|---|---|---|
| domain-health | $0.02 | — | ✅ |
| umbrella | $0.01 | — | ✅ |
| ssl-cert-check | $0.15 | 85%+ | ✅ |
| security-headers-check | $0.15 | 85%+ | ✅ |
| broken-links-check | $0.20 | 90%+ | ✅ |
| whois-lookup | $0.10 | 80%+ | ✅ |
| robots-txt-check | $0.10 | 80%+ | ✅ |

### 自建不划算（条件 3）— token 成本 > 售价

| 商品 | 价格 | 买省 | 状态 |
|---|---|---|---|
| x402-compliance-check | $0.50 | 83%+ | ✅ |
| x402-audit-pro | $1.00 | 80%+ | ✅ |
| cross-border-api-probe | $0.50 | 75%+ | ✅ |
| cross-border-intel-001 | $0.15 | — | ✅ |
| titanium-business-contact | $0.10 | — | ✅ |
| x402-launch-kit (套餐) | $1.20 | 85%+ | ✅ |
| cross-border-full (套餐) | $0.75 | 89%+ | ✅ |

### 需要持续维护（条件 4）— 🎯 待开发

| 商品 | 价格 | 维护频率 | 状态 |
|---|---|---|---|
| ofac-sanctions-screen | $0.25 | 每日更新制裁名单 | 🎯 待建 |
| page-change-monitor | $0.25 | 持续监控+KV存储 | 🎯 待建 |
| dnssec-check | $0.15 | DNS 签名验证 | 🎯 待建 |
| openapi-validate | $0.30 | 规范验证 | 🎯 待建 |
| proof-of-existence | $0.10 | hash+时间戳存储 | 🎯 待建 |
| geo-restriction-check | $0.20 | 全球边缘检测 | 🎯 待建 |
| ip-geolocation | $0.10 | — | 🎯 待建 |
| ct-log-check | $0.15 | 证书透明度 | 🎯 待建 |

## 免费层漏斗（已修复 origin bug）

```
免费 us-probe (3次/天) → upsell → reachability-live $0.02 + china-network-health $0.40
免费 x402-audit (1次/天) → upsell → x402-compliance-check $0.50 + x402-audit-pro $1.00 + x402-launch-kit $1.20
```

origin 已从 `url.origin` 改为硬编码 `STORE_ORIGIN`，避免代理/自定义域名场景下 origin 错误。

## Worker 版本

当前: b1504e40 (23 商品, origin 修复, upsell 更新)
