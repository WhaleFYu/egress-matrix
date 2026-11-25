#!/usr/bin/env python3
"""量一条出口的「单次响应字节上限」——以及 Range 能不能分段取。

为什么值得单独量：
- 这个值决定了你在这台机器上能不能 `pip install` 一个 5 MB 的包、能不能拉一个大 JSON。
- 失败方式极具误导性：连接成功、状态 200、TLS 正常，**只是内容少了**。JSON 解析器报
  "Unterminated string"，看起来像上游坏了；pip 报 JSONDecodeError，看起来像索引坏了。
- 如果服务端声明了 Content-Length 而你只收到 N 字节，这就是"被截断"的硬证据；
  再拿一个明显更大的文件量一次，若两次都停在同一个 N，说明上限在中间层而不是端点。

用法:
  python3 download_cap.py https://models.dev/api.json https://example.com/big.tgz
  python3 download_cap.py --json out.json URL...
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

UA = "egress-cap/1.0"
TIMEOUT = 40
HARD_STOP = 256 * 1024 * 1024        # 别真把 200 MB 拉下来
CAP_CANDIDATE = 2 * 1024 * 1024      # 2 MiB：本机实测到的单响应上限（见 results/download-cap.json）


def _opener(proxy):
    h = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy \
        else [urllib.request.ProxyHandler({})]
    return urllib.request.build_opener(*h)


def fetch(url, proxy, headers=None):
    """流式读，数真实收到的字节；同时记录声明的 Content-Length。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*", **(headers or {})})
    t0 = time.time()
    got, declared, status, extra = 0, None, None, {}
    try:
        with _opener(proxy).open(req, timeout=TIMEOUT) as r:
            status = r.status
            declared = r.headers.get("Content-Length")
            extra = {k.lower(): v for k, v in r.headers.items() if k.lower().startswith(("content-range", "content-type", "transfer-encoding"))}
            while got < HARD_STOP:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
    except urllib.error.HTTPError as e:
        status = e.code
        declared = e.headers.get("Content-Length")
        try:
            got = len(e.read())
        except Exception:
            pass
    except Exception as e:
        return {"url": url, "status": None, "err": f"{type(e).__name__}: {e}"[:140],
                "ms": int((time.time() - t0) * 1000)}
    return {"url": url, "status": status, "declared": int(declared) if declared and declared.isdigit() else None,
            "received": got, "ms": int((time.time() - t0) * 1000), **extra}


def probe_range(url, proxy, start=1000, end=1999):
    """请求一小段：206 + Content-Range 才说明分段真的被支持；200 则是被无视。"""
    r = fetch(url, proxy, {"Range": f"bytes={start}-{end}"})
    r["asked"] = f"bytes={start}-{end}"
    r["range_honored"] = bool(r.get("status") == 206 and r.get("content-range"))
    return r


def main():
    proxy = os.environ.get("EGRESS_PROXY") or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or ""
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out_json = None
    if "--json" in sys.argv:
        i = sys.argv.index("--json")
        out_json = sys.argv[i + 1]
        args = [a for a in args if a != out_json]
    if not args:
        print(__doc__)
        return 1

    rows = []
    for url in args:
        full = fetch(url, proxy)
        rng = probe_range(url, proxy)
        got = full.get("received") or 0
        # 上限的判据不能只看"收的比声明的少"：中间层会把自己截断后的长度**改写成 Content-Length**，
        # 于是 declared == received，看起来"完整"。可用的判据有两个：
        #   1) 正好停在 2 的整数次幂（2097152 = 2 MiB），而不是文件的自然长度；
        #   2) 两个明显不同大小的文件停在同一字节数。
        full["at_cap"] = bool(got and got == CAP_CANDIDATE)
        trunc = (full.get("declared") and full.get("received") is not None
                 and full["received"] < full["declared"])
        full["truncated"] = bool(trunc or full["at_cap"])
        rows.append({"url": url, "full": full, "range": rng})
        d = full.get("declared")
        print(f"- {url}\n"
              f"    status={full.get('status')} declared={d} received={full.get('received')} "
              f"truncated={'YES' if trunc else 'no'} {full.get('ms')}ms"
              + (f"  缺失 {d - full['received']} 字节" if trunc else ""))
        print(f"    Range {rng['asked']} -> {rng.get('status')} "
              f"honored={'yes' if rng.get('range_honored') else 'NO'} "
              f"received={rng.get('received')}")

    sizes = [r["full"].get("received") for r in rows if r["full"].get("at_cap")]
    if len(sizes) >= 2 and len(set(sizes)) == 1:
        print(f"\n{len(sizes)} 个不同大小的文件都停在同一个字节数 ({sizes[0]} = 2 MiB)："
              f"上限在中间层，不在这些端点。")
        print("注意：这不是「绕过配额」的理由——它是平台自己的出口策略。工程量级的应对是："
              "选零依赖/小体积的工具，别指望在这台机器上装 5 MB 的包。")
    honored = [r for r in rows if r["range"].get("status") == 206]
    if honored and len(honored) == len(rows):
        print("Range 被端点兑现（206），但中间层仍只给 2 MiB 窗口；本机不打算用它去超平台配额。")
    elif rows:
        print("Range 未被兑现（回 200 且重发整段）：分段也救不了这个上限。")

    if out_json:
        os.makedirs(os.path.dirname(out_json) or ".", exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "proxy": proxy or None,
                       "rows": rows}, f, ensure_ascii=False, indent=1)
        print(f"JSON -> {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
