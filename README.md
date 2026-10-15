# cdn-recon · CDN / WAF 识别与域名侦察

> **给一个域名，判断它是不是 CDN、是哪家 CDN/WAF，并给出判定依据。**
> 纯 `dig` + `curl` 实现，无任何 pip / npm 依赖，专为 Termux / 手机设计。

**中文说明 · [SKILL.md](SKILL.md)（技能定义） · [references/](references)（指纹库）**

---

## ⚠️ 免责声明（务必先读）

**本项目仅用于自有资产，或已获得书面授权的目标。**

- 请勿对未授权目标做任何扫描、探测或回源尝试。
- 默认模式会发送 HTTP HEAD 请求；需要完全被动时用 `--no-http`（只查 DNS，不发出任何 HTTP 请求）。
- 使用者须自行确认授权范围，并遵守所在地法律法规及目标服务条款。
- 作者不对任何滥用行为或由此产生的后果负责。

---

## ✨ 功能

| 能力 | 说明 |
|---|---|
| **四路信号投票** | DNS CNAME 链 + HTTP 专属头 + Server 头 + IP 段，综合打分并从高到低排序 |
| **15 家厂商指纹** | Cloudflare、Akamai、AWS CloudFront、阿里云、腾讯 EdgeOne、华为云、网宿、Azure、Fastly、Imperva、Sucuri、百度云、CDN77/KeyCDN、Vercel/Netlify、加速乐 |
| **深度检查** | `--deep` 追加：TLS 证书、`cf-ray` POP、全部响应头、IPv6(AAAA) |
| **JSON 输出** | `--json`，方便脚本 / 管道二次加工 |
| **完全被动模式** | `--no-http`：只分析 DNS，不发包 |
| **零第三方依赖** | 只用系统自带 `dig` 与 `curl` |

---

## 📦 环境要求

| 依赖 | 用途 | Termux 安装 |
|---|---|---|
| `python3` | 运行脚本（3.8+） | `pkg install python` |
| `dig` | 查 CNAME / A / AAAA / NS | `pkg install dnsutils` |
| `curl` | 取响应头与证书 | `pkg install curl` |

Python 侧**不需要安装任何第三方包**（无 requirements.txt）。

---

## 🚀 安装

```bash
git clone https://github.com/dateName/CDNskill.git
cd CDNskill

# Termux 一次性装齐依赖
pkg install -y python dnsutils curl git
```

---

## ▶️ 快速开始

```bash
./run.sh example.com                          # 快捷入口
python3 scripts/cdn_detect.py example.com     # 等价写法
```

输出示例：

```text
=== CDN/域名侦察: example.com ===
HTTP: HTTP/2 200
Server: cloudflare
NS: ns.cloudflare.com
CNAME 链: (直连，无 CNAME)
A 记录: 104.20.x.x

--- 识别结果 ---
  [11] ███████████ Cloudflare
        依据: Header:cf-ray, Header:cf-cache-status, Server~cloudflare, NS~ns.cloudflare.com, IP~104.20.
```

方括号里的数字是**得分**，≥6 基本可确认；多厂商命中时按分数排序，第一个即最可能。

---

## 🔧 参数说明

| 参数 | 作用 | 是否发包 |
|---|---|---|
| `<目标>` | 必填。域名或 URL，例如 `example.com`、`https://www.aliyun.com` | — |
| `--no-http` | 只做 DNS 分析（CNAME / NS / A / AAAA），不发送 HTTP 请求 | **不发包** |
| `--json` | 以 JSON 输出，便于程序处理 | 取决于是否同时加 `--no-http` |
| `--deep` | 深度检查：TLS 证书、`cf-ray` POP、全部响应头、IPv6 | 会发 HTTP/HTTPS |
| `-h` / `--help` | 查看帮助 | 否 |

参数可以叠加，例如 `--deep --json`、`--no-http --json`。

---

## 📖 用法示例

| 场景 | 命令 |
|---|---|
| 综合识别 | `python3 scripts/cdn_detect.py example.com` |
| 只看 DNS，完全不发包 | `python3 scripts/cdn_detect.py example.com --no-http` |
| 输出 JSON 供脚本消费 | `python3 scripts/cdn_detect.py example.com --json` |
| 深度检查（证书 / POP / 全部头 / IPv6） | `python3 scripts/cdn_detect.py example.com --deep` |
| 深度 + JSON | `python3 scripts/cdn_detect.py example.com --deep --json` |
| 只取最高分厂商 | `python3 scripts/cdn_detect.py example.com --json | jq -r '.matches[0].vendor'` |
| 重建 / 更新指纹库 | `python3 scripts/_gen_fp.py` |

---

## 🧠 识别原理（四路信号投票）

对指纹库里的每个厂商分别打分，命中即累加：

| 信号 | 权重 | 例子 |
|---|---|---|
| **CNAME 链命中** | **+3** | `*.cdn.cloudflare.net`、`*.cloudfront.net`、`*.kunlun.com` |
| **专属响应头命中** | **+3** | `cf-ray`、`x-amz-cf-id`、`x-hw-via` |
| **Server 头命中** | +2 | `server: cloudflare` |
| **IP 段命中** | +2 | A 记录落入厂商公告网段，如 `104.16.` |
| **Set-Cookie 命中** | +2 | `incap_ses_*`（Imperva）、`__jsluid`（加速乐） |
| **NS 记录命中** | +1 | `ns.cloudflare.com` |

**CNAME 会逐级跟踪**（最多 6 层），所以多层 CNAME 链也能命中。

没有 CNAME 不代表没有 CDN —— 可能是 CNAME 拉平（flattening）或双层 CDN，这时依靠 HTTP 头 + IP 段补充判断。

---

## 🧾 JSON 输出结构

用 `--json` 得到如下结构（`--deep` 时会多出 `deep` 字段）：

```json
{
  "host": "example.com",
  "cname_chain": ["example.com.edgekey.net"],
  "a_ips": ["104.20.1.2"],
  "aaaa": ["2606:4700::1"],
  "ns": ["ns.cloudflare.com"],
  "http_status": "HTTP/2 200",
  "server": "cloudflare",
  "matches": [
    {
      "vendor": "Cloudflare",
      "key": "cloudflare",
      "score": 11,
      "reasons": ["Header:cf-ray", "Server~cloudflare", "IP~104.20."],
      "note": "……厂商备注……"
    }
  ],
  "deep": {
    "cf_ray_pop": "LHR",
    "cert": {
      "issuer_o": "Google Trust Services",
      "issuer_cn": "WE1",
      "subject_cn": "example.com",
      "protocol": "TLSv1.3",
      "not_before": "……",
      "not_after": "……",
      "san": ["example.com", "www.example.com"]
    },
    "all_headers": { "content-type": "text/html", "cf-ray": "..." }
  }
}
```

---

## 🏢 内置指纹速查（节选）

| 厂商 | 最强信号 |
|---|---|
| Cloudflare | `server: cloudflare` + `cf-ray` |
| AWS CloudFront | `x-amz-cf-id` / CNAME `*.cloudfront.net` |
| Akamai | `X-Akamai-*` / CNAME `*.akamaiedge.net` |
| Azure CDN / FrontDoor | `x-azure-ref` / CNAME `*.azurefd.net` |
| Fastly | `x-fastly-request-id` / CNAME `*.fastly.net` |
| 阿里云 CDN | CNAME `*.kunlun.com` / `*.aliyuncs.com` |
| 腾讯 EdgeOne | CNAME `*.dnsv1.com` / `x-nws-log-uuid` |
| 华为云 CDN | `x-hw-via` / CNAME `*.hwcdn.net` |
| 网宿 CDN | CNAME `*.wscdns.com` |
| 百度云 CDN | CNAME `*.bdydns.com` / `x-bce-*` |
| Imperva | `x-iinfo` / Cookie `incap_ses_*` |
| Sucuri | `x-sucuri-id` |
| CDN77 / KeyCDN | CNAME `*.cdn77.org` / `*.kxcdn.com` |
| Vercel / Netlify | `x-vercel-id` / `x-nf-request-id` |
| 加速乐 / 云盾 | Cookie `__jsluid` / CNAME `*.jiasule.com` |

完整结构化指纹见 [references/fingerprints.json](references/fingerprints.json)，
含**回源与源站泄露手法**的人读版见 [references/fingerprints.md](references/fingerprints.md)。

---

## 📂 目录结构

```text
CDNskill/
├── SKILL.md                     技能定义（何时加载、能力清单）
├── run.sh                       快捷入口
├── scripts/
│   ├── cdn_detect.py            核心识别脚本（零依赖）
│   └── _gen_fp.py               指纹库生成 / 更新
├── references/
│   ├── fingerprints.json        结构化指纹库（脚本读取）
│   ├── fingerprints.md          人读版特征表（含回源手法）
│   └── fallback.md              未知 CDN 的兜底流程
├── LICENSE
└── README.md
```

---

## ❓ 限制与注意

- **误报控制**：已剔除通用头（`via`、`x-served-by`、`timing-allow-origin`），避免跨厂商误报。
- **CNAME 隐藏**：无 CNAME ≠ 无 CDN，可能是 CNAME 拉平或双层 CDN，需靠 HTTP 头 + IP 段补充判断。
- **Cloudflare 灰云**：非代理 IP（灰云）可直达源站，此时识别出的 IP 可能就是源站。
- **IP 段非全集**：内置为常用网段；新增厂商请在 `scripts/_gen_fp.py` 补规则后重跑。
- **证书失败**：非 443 端口或超时时，`--deep` 的证书部分会显示获取失败，属正常。
- **主动探测**：只有 `--no-http` 才是完全被动；其余模式会向目标发送请求，请先确认授权。

---

## 📜 许可

见 [LICENSE](LICENSE)。
