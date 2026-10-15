# cdn-recon — CDN/WAF 识别与域名侦察

> 仅用于**自有资产或已获授权目标**的安全研究。

## 何时使用
用户提到任意以下关键词时加载本技能：
`CDN 识别`、`查 CDN`、`WAF 探测`、`域名侦察`、`这是哪家 CDN`、
`回源`、`源站`、`Cloudflare/Akamai/CloudFront/EdgeOne/阿里CDN/网宿/华为`、
`CNAME 链`、`子域名`、`DNS 记录枚举`、`证书透明度`、`空间测绘`。

## 能力
| 能力 | 命令 |
|------|------|
| 综合识别（DNS+CNAME+HTTP头+IP段四路投票） | `python3 scripts/cdn_detect.py <域名>` |
| 仅 DNS 分析（不发 HTTP） | `python3 scripts/cdn_detect.py <域名> --no-http` |
| JSON 输出（供管道加工） | `python3 scripts/cdn_detect.py <域名> --json` |
| 深度检查（TLS 证书/cf-ray POP/全部响应头/IPv6） | `python3 scripts/cdn_detect.py <域名> --deep` |
| 深度检查 + JSON | `python3 scripts/cdn_detect.py <域名> --deep --json` |
| 重建/更新指纹库 | `python3 scripts/_gen_fp.py` |

## 识别原理（四路信号投票）
1. **DNS CNAME 链** — 逐级解析，命中如 `*.cdn.cloudflare.net`（+3/命中）
2. **HTTP 响应头** — `cf-ray`/`x-amz-cf-id`/`x-hw-via` 等专属头（+3/命中）
3. **Server 头** — `server: cloudflare`（+2）
4. **IP 段** — A 记录落入厂商公告网段（+2）
5. （辅）**NS 记录**（+1）、**Set-Cookie**（+2）

得分越高越可信；≥6 基本可确认。输出按分数排序。

## 通用兜底流程（自动识别 CDN 类）
```
1. dig +short <domain> CNAME         # 有 CNAME 后缀 → 直接查表
2. dig +short <domain> NS            # NS 归属托管商
3. curl -sSI <domain> | tr A-Z a-z   # 看 server / 专属头 / set-cookie
4. dig +short <domain> A             # IP 段归属
5. 以上任一命中即判厂商；多信号冲突时以 CNAME+专属头为准
6. 全不中 → 空间搜索引擎交叉验证（见 references/fallback.md）
```

## 各厂商专属特征速查
详见 `references/fingerprints.json`（结构化，15 家）与 `references/fingerprints.md`（人读版）。

| 厂商 | 最强信号 |
|------|----------|
| Cloudflare | `server: cloudflare` + `cf-ray` |
| AWS CloudFront | `x-amz-cf-id` / CNAME `*.cloudfront.net` |
| Akamai | `X-Akamai-*` / CNAME `*.akamaiedge.net` |
| Azure CDN/FrontDoor | `x-azure-ref` / CNAME `*.azurefd.net` |
| Fastly | `x-fastly-request-id` / CNAME `*.fastly.net` |
| 阿里云 CDN | CNAME `*.kunlun.com`/`*.aliyuncs.com` |
| 腾讯 EdgeOne | CNAME `*.dnsv1.com` / `x-nws-log-uuid` |
| 华为云 CDN | `x-hw-via` / CNAME `*.hwcdn.net` |
| 网宿 | CNAME `*.wscdns.com` |
| 百度云 CDN | CNAME `*.bdydns.com` / `x-bce-*` |
| Imperva | `x-iinfo` / Cookie `incap_ses` |
| Sucuri | `x-sucuri-id` |
| CDN77/KeyCDN | CNAME `*.cdn77.org`/`*.kxcdn.com` |
| Vercel/Netlify | `x-vercel-id` / `x-nf-request-id` |
| 加速乐/云盾 | Cookie `__jsluid` / CNAME `*.jiasule.com` |

## 目录结构
```
cdn-recon/
├── SKILL.md                    # 本文件
├── references/
│   ├── fingerprints.json       # 结构化指纹库（脚本读取）
│   ├── fingerprints.md         # 人读版特征表（含回源/泄露手法）
│   └── fallback.md             # 未知 CDN 兜底流程
└── scripts/
    ├── cdn_detect.py           # 核心识别脚本（无第三方依赖）
    └── _gen_fp.py              # 指纹库生成器
```

## 依赖
仅需 Termux 自带：`python3`、`dig`（ldns/dnsutils）、`curl`。无 pip / npm 依赖。

## 实测样例（2026-10 已验证）
```
$ python3 scripts/cdn_detect.py example.com
[11] ███████████ Cloudflare
     依据: Header:cf-ray, Header:cf-cache-status, Server~cloudflare, NS~ns.cloudflare.com, IP~104.20.

$ python3 scripts/cdn_detect.py cdn.jsdelivr.net
[16] ████████████ Cloudflare
     依据: CNAME~cdn.cloudflare.net, Header:cf-ray, Server~cloudflare, IP~104.17.

$ python3 scripts/cdn_detect.py aaaooo.xyz --deep
[ 8] ████████ Cloudflare
     依据: Header:cf-ray, Server~cloudflare, NS~ns.cloudflare.com, IP~104.21.
--- 深度检查 ---
cf-ray POP: LHR
证书 Issuer: Google Trust Services (CN=WE1)
  ↳ 提示: 免费 DV 证书（…），不泄露源站
  ↳ 铁证: /cdn-cgi/ 路径 = Cloudflare 独有
```

## 限制与注意
- **误报控制**：已剔除通用头（`via`/`x-served-by`/`timing-allow-origin`）避免跨厂商误报。
- **CNAME 隐藏**：无 CNAME ≠ 无 CDN；可能是 CNAME 拉平（flattening）或双层 CDN，需靠 HTTP 头+IP 段补充判断。
- **CF 非代理**：Cloudflare 非代理 IP（灰云）可直达源站，识别出的 IP 可能就是源站。
- **主动探测**：`--no-http` 可纯被动（只查 DNS）；发包前确认目标授权。
- IP 段表为常用段，非全集；新增厂商请在 `_gen_fp.py` 中补规则后重跑。
