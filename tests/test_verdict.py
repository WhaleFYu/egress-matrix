"""verdict() 的回归测试。

这两个 case 都是从真实误判里长出来的，别删：

1. `HANG-IN-TUNNEL`：沙箱里裸 DNS 恒失败，所以 `dns.ok` 永远是 False；
   以前 verdict 的最后一行是 `if not row["dns"]["ok"]: return "DNS-FAIL"`，
   于是 11 个"隧道通了但请求挂死"的主机被统一标成"域名解析失败"——
   一个听起来像"你配错了 DNS"的结论，实际上答案是"这条主机名这条路不通"。

2. `EMPTY-REPLY`：403/404 且 body 恰好 0 字节，被 `bytes <= 8` 的启发式吃进 `STUB-FAKE-OK`。
   桩是 `200 + 4 字节 OK`；0 字节的空 403 是另一种东西（更像中间层合成的拒绝）。

跑法：`python3 tests/test_verdict.py`（零依赖、不联网）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from egress_matrix import verdict  # noqa: E402


def row(http=None, connect=None, dns_ok=False):
    return {
        "host": "example.com",
        "dns": {"ok": dns_ok},
        "tcp": {"ok": False},
        "connect": connect if connect is not None else {"status": "HTTP/1.1 200 Connection Established"},
        "tls": {"ok": True},
        "http": http or {},
    }


class VerdictTest(unittest.TestCase):
    def test_hang_in_tunnel(self):
        r = row(http={"status": None, "err": "TimeoutError: The read operation timed out", "ms": 6063})
        self.assertEqual(verdict(r), "HANG-IN-TUNNEL")

    def test_empty_reply_is_not_a_stub(self):
        r = row(http={"status": 404, "bytes": 0, "preview": "", "ctype": "text/html"})
        self.assertEqual(verdict(r), "EMPTY-REPLY")

    def test_real_stub_still_detected(self):
        r = row(http={"status": 200, "bytes": 4, "ctype": "text/plain", "preview": "OK\r\n"})
        self.assertEqual(verdict(r), "STUB-FAKE-OK")

    def test_policy_deny(self):
        r = row(connect={"status": "HTTP/1.1 403 Forbidden", "err": None})
        self.assertEqual(verdict(r), "PROXY-POLICY-DENY")

    def test_reachable_on_endpoint_error(self):
        r = row(http={"status": 401, "bytes": 120, "ctype": "application/json", "ms": 900})
        self.assertEqual(verdict(r), "REACHABLE")

    def test_cap_throttled(self):
        r = row(http={"status": 429, "bytes": 45, "ctype": "text/plain",
                      "preview": "Experiment web download traffic cap reached."})
        self.assertEqual(verdict(r), "CAP-THROTTLED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
