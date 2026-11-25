#!/usr/bin/env python3
"""egress_matrix —— 从一台机器出发，量一张「哪些开发/AI 端点真的够得着」的表。

每个端点记四件事，分开记，因为它们失败时长的样子不一样：
  1. dns        域名能不能解析（解析失败 vs 连不上，是两回事）
  2. tcp        裸 TCP :443 能不能连（超时 / refused / ok）
  3. connect    经代理 CONNECT 的状态码（403 = 代理策略拒绝；超时 = 网络不通）
  4. tls        TLS 对端证书的 issuer（非公共 CA = 被中间人解密）
  5. http       GET 的状态码、Content-Type、body 长度
然后给一个 verdict。verdict 是**推断**，原始字段才是观测。

用法:
  python3 egress_matrix.py                      # 直连 + 代理，输出 md 与 json
  python3 egress_matrix.py --proxy http://127.0.0.1:8080
  python3 egress_matrix.py --hosts api.openai.com,pypi.org
环境变量: EGRESS_PROXY / http_proxy
仅用标准库。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.error
import urllib.request

TIMEOUT = 6.0
UA = "egress-matrix/1.0 (+https://github.com/WhaleFYu/egress-matrix)"

DEFAULT_HOSTS = [
    # 推理 / 模型
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.deepseek.com", "dashscope.aliyuncs.com", "open.bigmodel.cn",
    "api.moonshot.cn", "ark.cn-beijing.volces.com", "api.siliconflow.cn",
    "api.minimax.chat", "qianfan.baidubce.com", "aip.baidubce.com",
    "api.hunyuan.cloud.tencent.com", "api.together.xyz", "api.groq.com",
    "api.mistral.ai", "openrouter.ai", "api.cohere.com", "api.replicate.com",
    "huggingface.co", "inference.ai.azure.com",
    "text.pollinations.ai/openai", "models.github.ai/inference/chat/completions",
    # 包与镜像
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "crates.io",
    "proxy.golang.org", "repo.maven.apache.org", "registry-1.docker.io",
    "ghcr.io", "cdn.jsdelivr.net", "unpkg.com", "storage.googleapis.com",
    "s3.amazonaws.com",
    # 代码 / 文档 / 社区
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "gitlab.com", "gitee.com",
    "dev.to", "hashnode.com", "juejin.cn", "cnblogs.com", "ifdian.net",
    # 其他
    "api.telegram.org", "smtp.qq.com", "imap.qq.com",
]


def _t(fn, *a, **kw):
    t0 = time.time()
    try:
        return {"ok": True, "v": fn(*a, **kw), "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"[:160], "ms": int((time.time() - t0) * 1000)}


def dns(host):
    r = _t(lambda: sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)}))
    return {"ok": r["ok"], "ips": r.get("v", [])[:3], "err": r.get("err"), "ms": r["ms"]}


def tcp(host):
    r = _t(lambda: socket.create_connection((host, 443), TIMEOUT).close())
    return {"ok": r["ok"], "err": r.get("err"), "ms": r["ms"]}


def _proxy_connect(host, proxy):
    """返回 (status_line_or_None, error)。403=策略拒绝，超时/ECONNREFUSED=网络层。"""
    p = urllib.parse.urlparse(proxy if "//" in proxy else "http://" + proxy)
    s = socket.create_connection((p.hostname, p.port or 8080), TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    buf = b""
    while b"\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head = buf.split(b"\r\n")[0].decode("latin1", "replace")
    return head, s


def connect_status(host, proxy):
    if not proxy:
        return {"status": None, "err": "no-proxy-configured"}
    try:
        head, s = _proxy_connect(host, proxy)
        s.close()
        return {"status": head, "err": None}
    except Exception as e:
        return {"status": None, "err": f"{type(e).__name__}: {e}"[:160]}


def tls_issuer(host, proxy):
    """直连时用系统 CA 校验（失败即报错，不降级）；走代理时不校验链，只为读 issuer。"""
    def go():
        if proxy:
            head, s = _proxy_connect(host, proxy)
            if " 200" not in head:
                s.close()
                raise RuntimeError("CONNECT " + head[:40])
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # 只读 issuer，不做信任判断
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
            return _issuer_from_der(der)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), TIMEOUT) as raw, ctx.wrap_socket(raw, server_hostname=host) as ss:
            return dict(x[0] for x in ss.getpeercert()["issuer"])
    r = _t(go)
    return {"ok": r["ok"], "issuer": r.get("v"), "err": r.get("err")}


def _issuer_from_der(der):
    # 极简 DER 扫描：够读 CN/O 就够了，不引第三方库
    try:
        import hashlib
        # 用 ssl 解析不了裸 DER 的 issuer，这里退化为指纹 + 已知映射
        return {"sha256": hashlib.sha256(der).hexdigest()[:16]}
    except Exception:
        return {}


def http_probe(host, proxy, path="/"):
    """走 urllib 的 ProxyHandler：它会正确地先 CONNECT 再在隧道里做 TLS。
    （手写 HTTPSConnection(proxy)+set_tunnel 会把 TLS 握到代理自己身上，量出来的全是代理的假响应。）"""
    import urllib.request
    t0 = time.time()
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else [urllib.request.ProxyHandler({})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(f"https://{host}{path or '/'}", headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            body = r.read(4096)
            return {"status": r.status, "ctype": (r.headers.get("Content-Type") or "")[:40],
                    "bytes": len(body), "preview": body[:60].decode("utf-8", "replace"),
                    "ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        body = e.read(4096)
        return {"status": e.code, "ctype": (e.headers.get("Content-Type") or "")[:40],
                "bytes": len(body), "preview": body[:60].decode("utf-8", "replace"),
                "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"status": None, "err": f"{type(e).__name__}: {e}"[:120], "ms": int((time.time() - t0) * 1000)}


CAP_MARKERS = ("download traffic cap", "traffic cap reached", "experiment web download")


def is_cap_body(text):
    low = (text or "").lower()
    return any(m in low for m in CAP_MARKERS)


def verdict(row):
    c = row["connect"]
    st = c.get("status") or ""
    if c.get("err") and "no-proxy" not in c["err"]:
        e = c["err"].lower()
        if "timeout" in e or "timed out" in e:
            return "NETWORK-TIMEOUT"
        if "refused" in e:
            return "NETWORK-REFUSED"
        if "resolve" in e or "gaierror" in e:
            return "DNS-FAIL"
        return "PROXY-ERROR"
    if " 403" in st or " 407" in st:
        return "PROXY-POLICY-DENY"
    if st and " 200" not in st:
        return "PROXY-" + st.split(" ")[1] if " " in st else "PROXY-ODD"
    h = row["http"]
    if is_cap_body(h.get("preview") or "") or is_cap_body(h.get("err") or ""):
        return "CAP-THROTTLED"
    b = h.get("bytes")
    # 0 字节的 403/404 不是"桩"，是另一种值得单列的东西：正常端点（crates.io、阿里云百炼……）不会在
    # 自己的路径上回一个空 body，这种响应很可能是中间层合成的"礼貌拒绝"。以前它被误报成 STUB-FAKE-OK。
    if h.get("status") and (b == 0 or b is None and h.get("preview") == ""):
        return "EMPTY-REPLY"
    if h.get("status") and isinstance(b, int) and 0 < b <= 8 and "json" not in (h.get("ctype") or ""):
        return "STUB-FAKE-OK"
    # 502/503/504 且 body 是中间层自己写的话术（如 "Upstream fetch failed"）——
    # 失败发生在「出口 → 源站」这一段，既不是源站回了错，也不是策略拒绝了这次请求。
    # 以前这类会被算成 REACHABLE（"拿到状态码就算通"），把中间层的故障记成了端点的可用。
    if h.get("status") in (502, 503, 504):
        body = (h.get("preview") or "").lower()
        if any(k in body for k in ("upstream fetch failed", "cannot connect to", "bad gateway", "proxy error")):
            return "RELAY-5XX"
    if h.get("status"):
        return "REACHABLE"
    # 走到这里：隧道建起来了（CONNECT 200）、但 HTTP 没有回状态码。
    # 以前这里会落进 "DNS-FAIL"——因为沙箱里裸 DNS 恒失败，这个 check 永远为 False，
    # 于是 11 个"隧道通但请求挂死"的主机被误标成"域名解析失败"。DNS 检查只在**无代理**时才有意义。
    err = (h.get("err") or "").lower()
    if "timeout" in err or "timed out" in err:
        return "HANG-IN-TUNNEL"
    if not row["dns"]["ok"] and not row["connect"].get("status"):
        return "DNS-FAIL"
    return "TLS-OR-HTTP-FAIL"


def probe(host, proxy):
    """host 可以写成 "example.com/v1/models"：域名部分做 DNS/TCP/TLS/CONNECT，
    路径部分用于 GET。API 主机常常在 "/" 上挂死而在真实端点上正常——只用根路径测，
    会把一个可用端点判成 HANG-IN-TUNNEL。"""
    name, _, path = host.partition("/")
    path = ("/" + path) if path else "/"
    row = {"host": host, "dns": dns(name), "tcp": tcp(name),
           "connect": connect_status(name, proxy), "tls": tls_issuer(name, proxy),
           "http": http_probe(name, proxy, path)}
    row["verdict"] = verdict(row)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default=os.environ.get("EGRESS_PROXY") or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or "")
    ap.add_argument("--hosts", default="")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    hosts = [h.strip() for h in a.hosts.split(",") if h.strip()] or DEFAULT_HOSTS

    print(f"# egress matrix  {time.strftime('%Y-%m-%d %H:%M:%S %Z')}  host={socket.gethostname()}  "
          f"proxy={a.proxy or '(direct)'}  hosts={len(hosts)}", file=sys.stderr)
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(probe, h, a.proxy): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            try:
                rows.append(f.result())
            except Exception as e:
                rows.append({"host": futs[f], "verdict": "PROBE-CRASH", "err": str(e)[:120]})
    order = {h: i for i, h in enumerate(hosts)}
    rows.sort(key=lambda r: order.get(r["host"], 99))

    out = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "proxy": a.proxy or None,
           "host": socket.gethostname(), "rows": rows}
    path = a.out or f"results/matrix-{time.strftime('%Y%m%d-%H%M')}.json"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)

    print("\n| host | verdict | connect | http | bytes |")
    print("|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['host']} | {r['verdict']} | {str(r['connect'].get('status') or r['connect'].get('err'))[:28]} "
              f"| {r['http'].get('status') or r['http'].get('err', '')[:22]} | {r['http'].get('bytes', '')} |")
    caps = [r for r in rows if r.get("verdict") == "CAP-THROTTLED"]
    if len(caps) >= 3:
        bodies = {(r["http"].get("preview") or "")[:40] for r in caps}
        print(f"\n## 全局限额信号\n\n{len(caps)}/{len(rows)} 个端点返回同一段报文（{len(bodies)} 种不同 body）。"
              f"\n跨主机同文 = 中间层在回话，不是上游限流。此时任何「可达性」结论都无效，先等窗口恢复。")
    print(f"\nJSON -> {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
