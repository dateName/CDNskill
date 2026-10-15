#!/usr/bin/env python3
"""
cdn_detect.py — CDN/WAF/域名侦察自动识别
用法:
    python3 cdn_detect.py <域名或URL> [--no-http] [--json] [--deep]
示例:
    python3 cdn_detect.py example.com
    python3 cdn_detect.py https://www.aliyun.com --json
    python3 cdn_detect.py aaaooo.xyz --deep

原理: 四路信号投票
  1) DNS CNAME 链后缀   2) HTTP 响应头名   3) Server 头    4) IP 段
  外加 Set-Cookie、NS 记录。全部经 dig/curl（无第三方依赖）。
  --deep 追加: TLS 证书、cf-ray POP、全部响应头、IPv6(AAAA)。
仅用于自有资产或已获授权目标的安全研究。
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FP_PATH = os.path.normpath(os.path.join(HERE, "..", "references", "fingerprints.json"))

# ---------- 工具封装 ----------
def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def dig(domain, rtype):
    out = run(["dig", "+short", domain, rtype, "+time=5", "+tries=1"])
    res = []
    for l in out.splitlines():
        l = l.strip()
        # 过滤 dig 的错误/注释行（如 ;; communications error / ;; connection timed out）
        if not l or l.startswith(";"):
            continue
        res.append(l)
    return res

def http_headers(url, timeout=20):
    """返回 (status_line, headers_dict, set_cookie_list)。curl 不跟随重定向。"""
    out = run(["curl", "-sSI", "--max-time", str(timeout),
               "-A", "Mozilla/5.0 (cdn-detect)", url])
    headers = {}
    cookies = []
    status = ""
    for line in out.splitlines():
        if line.lower().startswith("http/"):
            status = line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            headers[k] = v
            if k == "set-cookie":
                cookies.append(v)
    return status, headers, cookies

# ---------- 深度检查（补丁 1）----------
def tls_cert(host, timeout=15):
    """连接 443 取证书信息。无 openssl 依赖，用标准库 ssl。返回 dict 或 None。"""
    import socket
    import ssl as _ssl
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
                issuer = {k: v for x in c.get("issuer", []) for k, v in x}
                subject = {k: v for x in c.get("subject", []) for k, v in x}
                san = [f"{t}:{v}" for t, v in c.get("subjectAltName", [])]
                return {
                    "issuer_o": issuer.get("organizationName", ""),
                    "issuer_cn": issuer.get("commonName", ""),
                    "subject_cn": subject.get("commonName", ""),
                    "not_before": c.get("notBefore", ""),
                    "not_after": c.get("notAfter", ""),
                    "protocol": ss.version(),
                    "san": san,
                }
    except Exception:
        return None

def cf_ray_pop(headers):
    """从 cf-ray 头解析 Cloudflare POP 机场代码，如 'xxxx-FRA' -> 'FRA'。"""
    ray = headers.get("cf-ray", "")
    if "-" in ray:
        return ray.rsplit("-", 1)[-1].strip().upper()
    return ""

# ---------- 归一化 ----------
def normalize(target):
    t = target.strip()
    url = t if re.match(r"^https?://", t) else "https://" + t
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    return host, url

# ---------- 打分匹配 ----------
def detect(host, url, use_http=True, deep=False):
    fp = json.load(open(FP_PATH, encoding="utf-8"))

    # 收集信号
    cnames = dig(host, "CNAME")
    # 逐级解析 CNAME 链
    chain = list(cnames)
    seen = set(cnames)
    cur = cnames
    for _ in range(6):
        nxt = []
        for c in cur:
            nc = dig(c.rstrip("."), "CNAME")
            for x in nc:
                if x not in seen:
                    seen.add(x)
                    chain.append(x)
                    nxt.append(x)
        if not nxt:
            break
        cur = nxt

    a_ips = dig(host, "A")
    aaaa = dig(host, "AAAA")
    ns = dig(host, "NS")
    ns_str = " ".join(ns).lower()

    status, headers, cookies = ("", {}, [])
    if use_http:
        status, headers, cookies = http_headers(url)
    server = headers.get("server", "").lower()
    hdr_names = set(headers.keys())
    cookie_str = " | ".join(cookies).lower()
    chain_str = " ".join(chain).lower()
    ip_str = " ".join(a_ips)

    results = []
    for key, v in fp.items():
        if key.startswith("_"):
            continue
        score = 0
        reasons = []
        # cname
        for pat in v.get("cname", []):
            if pat in chain_str:
                score += 3
                reasons.append(f"CNAME~{pat}")
        # header
        for pat in v.get("header", []):
            if pat in hdr_names:
                score += 3
                reasons.append(f"Header:{pat}")
        # server
        for pat in v.get("server", []):
            if pat and pat in server:
                score += 2
                reasons.append(f"Server~{pat}")
        # ns
        for pat in v.get("ns", []):
            if pat and pat in ns_str:
                score += 1
                reasons.append(f"NS~{pat}")
        # cookie
        for pat in v.get("cookie", []):
            if pat and pat.lower() in cookie_str:
                score += 2
                reasons.append(f"Cookie~{pat}")
        # ip 段
        for pat in v.get("ip", []):
            if pat and ip_str.startswith(pat) or (pat and re.search(r"(^| )" + re.escape(pat), ip_str)):
                score += 2
                reasons.append(f"IP~{pat}")
                break
        if score > 0:
            results.append({
                "vendor": v["name"],
                "key": key,
                "score": score,
                "reasons": reasons,
                "note": v.get("note", ""),
            })

    results.sort(key=lambda x: x["score"], reverse=True)
    out = {
        "host": host,
        "cname_chain": chain,
        "a_ips": a_ips,
        "aaaa": aaaa,
        "ns": ns,
        "http_status": status,
        "server": headers.get("server", ""),
        "matches": results,
    }
    if deep:
        out["deep"] = {
            "cf_ray_pop": cf_ray_pop(headers),
            "cert": tls_cert(host),
            "all_headers": dict(sorted(headers.items())),
        }
    return out

# ---------- 输出 ----------
def print_report(r, as_json=False):
    if as_json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return
    print(f"\n=== CDN/域名侦察: {r['host']} ===")
    print(f"HTTP: {r['http_status'] or '(未请求/无响应)'}")
    print(f"Server: {r['server'] or '(无)'}")
    print(f"NS: {', '.join(r['ns']) or '(无)'}")
    print(f"CNAME 链: {' -> '.join(r['cname_chain']) or '(直连，无 CNAME)'}")
    print(f"A 记录: {', '.join(r['a_ips']) or '(无)'}")
    if r.get("aaaa"):
        print(f"AAAA  : {', '.join(r['aaaa'])}")
    print("\n--- 识别结果 ---")
    if not r["matches"]:
        print("未匹配到已知 CDN/WAF 指纹。")
        if not r["cname_chain"]:
            print("提示: 无 CNAME 通常表示可能是源站直连，或使用了 CNAME 隐藏的双层 CDN。")
    for m in r["matches"]:
        bar = "█" * min(m["score"], 12)
        print(f"  [{m['score']:>2}] {bar} {m['vendor']}")
        print(f"        依据: {', '.join(m['reasons'])}")
        if m["note"]:
            print(f"        备注: {m['note']}")

    # 深度检查打印块（补丁 3a）
    d = r.get("deep")
    if d:
        print("\n--- 深度检查 ---")
        if d.get("cf_ray_pop"):
            print(f"cf-ray POP: {d['cf_ray_pop']}")
        cert = d.get("cert")
        if cert:
            print(f"证书 Issuer: {cert['issuer_o']} (CN={cert['issuer_cn']})")
            print(f"证书 Subject: {cert['subject_cn']}  协议: {cert['protocol']}")
            print(f"有效期: {cert['not_before']} -> {cert['not_after']}")
            san = cert.get("san", [])
            print(f"SAN({len(san)}): {', '.join(san) if san else '(无)'}")
            iss = (cert["issuer_o"] + cert["issuer_cn"]).lower()
            if "google trust" in iss or "let's encrypt" in iss:
                print("  ↳ 提示: 免费 DV 证书（常见于 Cloudflare 免费版 Universal SSL），不泄露源站")
        else:
            print("证书: (获取失败，可能非 443 或超时)")
        hdrs = d.get("all_headers", {})
        if "speculation-rules" in hdrs or "/cdn-cgi/" in str(hdrs):
            print("  ↳ 铁证: /cdn-cgi/ 路径 = Cloudflare 独有")


def main():
    ap = argparse.ArgumentParser(description="CDN/WAF/域名侦察识别")
    ap.add_argument("target", help="域名或 URL")
    ap.add_argument("--no-http", action="store_true", help="只做 DNS 分析，不发 HTTP 请求")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--deep", action="store_true",
                    help="深度检查：TLS 证书、cf-ray POP、全部响应头、IPv6")
    args = ap.parse_args()

    if not os.path.exists(FP_PATH):
        print(f"指纹库缺失: {FP_PATH}", file=sys.stderr)
        sys.exit(1)

    host, url = normalize(args.target)
    r = detect(host, url, use_http=not args.no_http, deep=args.deep)
    print_report(r, as_json=args.json)


if __name__ == "__main__":
    main()
