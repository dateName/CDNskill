# CDN/WAF 特征表（人读版）

> 结构化版本见 `fingerprints.json`。本文件补充**回源/源站泄露/调试头**手法。

## 表：厂商 — 回源特征 — 调试/泄露信号

| # | 厂商 | CNAME 后缀 | 专属响应头 | 回源/源站线索 | 调试/泄露头 |
|---|------|-----------|-----------|--------------|------------|
| 1 | **Cloudflare** | `cdn.cloudflare.net` | `cf-ray`,`cf-cache-status` | 非代理端口直达、直连 IP 可绕 | `cf-ray` 后缀=POP |
| 2 | **Akamai** | `*.akamaiedge.net`,`*.edgekey.net` | `X-Akamai-*` | SureRoute 测试对象、Staging 网络 | Ghost 调试头、`X-Served-By` 泄露边缘节点 |
| 3 | **AWS CloudFront** | `*.cloudfront.net` | `x-amz-cf-id`,`x-amz-cf-pop` | 回源 Host 差异、ECS 网段、OSS/FC 判断 | S3 Bucket 源站、ALB 域名、AWS IP 段筛选 |
| 4 | **阿里云 CDN/DCDN** | `*.kunlun.com`,`*.aliyuncs.com` | `eagleid`,`ali-swift-stat-*` | 回源不验证 Host | `Via` 头、Tengine |
| 5 | **腾讯云 EdgeOne/CDN** | `*.dnsv1.com`,`*.edgeone.ai` | `eo-cache-status` | — | `X-NWS-LOG-UUID` 调试头泄露 |
| 6 | **网宿 CDN** | `*.wscdns.com`,`*.ourwebcdn.com` | `x-ws-request-id` | 运营商网段特征、历史 DNS | 高泄露率 |
| 7 | **华为云 CDN** | `*.hwcdn.net`,`*.cdnhwc*.com` | `x-hw-via` | ECS 网段 | `X-HW-Via` 调试头 |
| 8 | **Azure CDN/FrontDoor** | `*.azureedge.net`,`*.azurefd.net` | `x-azure-ref` | Azure VM 域名 | `x-fd-healthprobe`（health probe 泄露） |
| 9 | **Fastly** | `*.fastly.net` | `x-fastly-request-id`,`x-cache-hits` | Anycast 特征、Shield 区域 | `X-Served-By` 泄露 |
| 10 | **Imperva/Incapsula** | `*.incapdns.net` | `x-iinfo`,`x-cdn` | — | `X-Iinfo` 泄露（含节点/时间戳） |
| 11 | **Sucuri WAF** | `*.sucuri.net`,`*.cloudproxy.net` | `x-sucuri-id` | — | `X-Sucuri-ID` |
| 12 | **百度云 CDN** | `*.bdydns.com`,`*.bcecdn.com` | `x-bce-request-id` | BCH/BOS 源站 | 高泄露率、非标准端口 |
| 13 | **CDN77/KeyCDN/StackPath** | `*.cdn77.org`,`*.kxcdn.com` | `x-cdn77`,`x-keycdn` | 历史 DNS 泄露 | — |
| 14 | **Vercel/Netlify** | `*.vercel-dns.com`,`*.netlify.app` | `x-vercel-id`,`x-nf-request-id` | — | 部署 ID 泄露 |
| 15 | **加速乐/云盾/安全宝** | `*.jiasule.com`,`*.anquanbao.com` | Cookie `__jsluid` | 非标准端口可达 | 历史 DNS 高泄露率 |

---

## 通用源站发现思路（授权前提下）

1. **CNAME 拉平/无 CNAME**：直接看 A 记录 IP 段归属，非 CDN 段则疑为源站。
2. **非标准端口直达**：CDN 通常只代理 80/443；源站可能在 8080/8443 等裸露。
3. **回源不验证 Host**：直接以 IP 访问并带目标 Host，若响应正常则命中源站。
4. **历史 DNS**：查历史解析记录，找 CDN 接入前的原始 IP。
5. **证书透明度（crt.sh）**：查证书里的子域与域名，扩大资产面。
6. **空间搜索引擎**：Shodan/Censys/Fofa 按证书/标题/图标反查。
7. **邮件头/SPF**：MX 和 TXT 常泄露真实源站网段。

> 以上仅为识别方法论；实际探测须对**自有或已授权**资产进行。
