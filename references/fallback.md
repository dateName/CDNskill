# 未知 CDN 兜底流程

当 `cdn_detect.py` 四路信号全不命中时，按以下步骤人工研判。

## 步骤 1：确认是否真的在 CDN 后面
```bash
dig +short <domain> CNAME     # 空 → 可能直连，也可能 CNAME 拉平
dig +short <domain> A         # 拿到 IP
```
- 多个 A 记录且地理分散（用 `dig @8.8.8.8` vs 本地 DNS 对比）→ 疑似 Anycast CDN
- 单 IP 且归属清晰 → 可能是源站或单点 CDN

## 步骤 2：HTTP 头深挖
```bash
curl -sSI https://<domain> | tr 'A-Z' 'a-z' | sort
```
关注可疑自定义头：`x-*`、`*-via`、`*-cache-*`、`*-served-by`、`*-request-id`。
拿这些头名去搜索引擎/Censys 反查 → 常能定位厂商。

## 步骤 3：TLS 证书
```bash
# 无 openssl 时用 python
python3 - <<'PY'
import ssl,socket
ctx=ssl.create_default_context()
with socket.create_connection(("<domain>",443),timeout=10) as s:
    with ctx.wrap_socket(s,server_hostname="<domain>") as ss:
        c=ss.getpeercert()
        print("issuer:",dict(x[0] for x in c["issuer"]))
        print("subject:",dict(x[0] for x in c["subject"]))
        print("SAN:",c.get("subjectAltName"))
PY
```
Issuer 常暴露 CDN（如 `*.cloudflare`、`DigiCert + Akamai`）。

## 步骤 4：证书透明度 / 空间测绘（需允许外联，仅 HTTP/HTTPS）
- **crt.sh**：`curl -s 'https://crt.sh/?q=%25.<domain>&output=json'`（查子域）
- **空间测绘交叉验证**：用上一步拿到的证书指纹/HTTP 头/图标 hash，去 Shodan/Censys/Fofa 反查已识别的资产集群。

## 步骤 5：IP 段与 ASN
```bash
whois <ip> | grep -iE 'orgname|netname|descr|country'
```
ASN 常直接对应 CDN 厂商（如 Cloudflare AS13335、Akamai AS20940、Fastly AS54113）。

## 决策树
```
有 CNAME 后缀? ── 是 → 查 fingerprints.json → 命中
                └─ 否 → 有专属响应头?
                          ├─ 是 → 反查头名 → 命中
                          ├─ 否 → 证书 issuer 含 CDN? → 命中
                          └─ 否 → IP 段/ASN 归属
                                    ├─ 命中 → 判厂商
                                    └─ 全否 → 未知厂商，记录特征备查
```

## 记录模板（新增厂商时）
```json
"vendor_key": {
  "name": "显示名",
  "cname": [],
  "header": [],
  "server": [],
  "ns": [],
  "cookie": [],
  "ip": [],
  "note": "识别要点/回源线索"
}
```
补进 `scripts/_gen_fp.py` 后重跑 `python3 scripts/_gen_fp.py`。

---

## Cloudflare 铁证判据（优先级从高到低）

当信号不够明确、或需要给出「确凿结论」时，按以下判据逐条核对。
其中第 1 条为**不可伪装**的强证据。

1. **`/cdn-cgi/` 路径（`speculation-rules` 头）→ CF 独有，不可伪装**
   - 响应头出现 `speculation-rules: "/cdn-cgi/speculation"`
   - 或任意资源路径含 `/cdn-cgi/`（如 `/cdn-cgi/trace`、`/cdn-cgi/challenge-platform/`）
   - 其它厂商无此路径命名空间 → 命中即可直接判定 Cloudflare
   ```bash
   curl -sSI https://<domain> | grep -i speculation-rules
   curl -s  https://<domain>/cdn-cgi/trace      # 返回 cf 的 key=value 明文
   ```

2. **`cf-ray` 后缀 = POP 机场代码**
   - 形如 `a47604009c761945-FRA`，`-` 后为三字 IATA 机场码（FRA=法兰克福、LHR=伦敦、SIN=新加坡…）
   - 可据此推断用户就近接入的 CF 机房，佐证「确实经过 CF 边缘」
   - `--deep` 会自动解析并打印该 POP

3. **`cf-nel` / `a.nel.cloudflare.com` → CF 错误上报**
   - 响应头 `cf-nel`，或 `report-to`/`nel` 指向 `a.nel.cloudflare.com`
   - 属于 CF 的网络错误日志（NEL）上报通道

4. **IPv6 `2606:4700::/32` → CF 官方段**
   - CF 同时使用 `104.x`/`172.6x` 的 A 记录与 `2606:4700::/32` 的 AAAA
   - AAAA 落在该段是强旁证（配合 `server: cloudflare`）

5. **免费 DV 证书（Google Trust Services / Let's Encrypt）不泄露源站**
   - Issuer 常见 `Google Trust Services`（CN=`WE1`）或 `Let's Encrypt`
   - 这是 CF 免费版 Universal SSL 的默认签发方，**证书本身不含源站信息**，不能据此推源站
   - 若 Issuer 为 `Cloudflare TLS Issuing ECC CA 3`（SSL Corporation）亦为 CF 自签体系

### 判据权重建议
| 判据 | 强度 | 可伪装 |
|------|------|--------|
| `/cdn-cgi/` 路径 | ★★★★★ | 否 |
| `cf-ray` 头 | ★★★★☆ | 较难 |
| `cf-nel` / nel 上报 | ★★★★☆ | 较难 |
| AAAA `2606:4700::/32` | ★★★☆☆ | 否（段归属） |
| NS `*.ns.cloudflare.com` | ★★★☆☆ | 可（可改 NS） |
| 免费 DV 证书 | ★★☆☆☆ | 可（任何站都能签） |
