"""`assess()` 的回归测试：一张表必须先能证明自己不是谎话。

案子来自 2026-11-26 05:30 那轮：cron 拉起探针时没有代理变量，探针走直连、直连没有解析器，
49 个端点全落成 DNS-FAIL。文件写成了、INDEX 也生成了，表上看起来像「49 个端点同时不可达」。
所以这里钉住两件事：
  1. 无代理 + 大面积 DNS 失败 = 不合格（这轮什么都没测）；
  2. 跨主机同一段限额文案 = 不合格（说话的是中间层，不是端点）。
反过来也要钉住：有代理的正常一轮不能被误伤。

跑法：`python3 tests/test_assess.py`（零依赖、不联网）
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from egress_matrix import assess  # noqa: E402

PROXY = "http://127.0.0.1:18081"


def rows(verdict, n):
    return [{"host": f"h{i}.example.com", "verdict": verdict} for i in range(n)]


class AssessTest(unittest.TestCase):
    def test_no_proxy_all_dns_fail_is_invalid(self):
        valid, reasons = assess(rows("DNS-FAIL", 49), "")
        self.assertFalse(valid)
        self.assertIn("no-proxy", reasons[0])

    def test_no_proxy_half_dns_fail_is_invalid(self):
        valid, reasons = assess(rows("DNS-FAIL", 25) + rows("REACHABLE", 25), None)
        self.assertFalse(valid)

    def test_no_proxy_but_resolvable_is_valid(self):
        """直连也可能真的能用（别的机器上就是这么跑的）；不能因为「没配代理」一律判废。"""
        valid, _ = assess(rows("REACHABLE", 40) + rows("PROXY-POLICY-DENY", 9), "")
        self.assertTrue(valid)

    def test_global_cap_is_invalid(self):
        valid, reasons = assess(rows("CAP-THROTTLED", 20) + rows("REACHABLE", 29), PROXY)
        self.assertFalse(valid)
        self.assertIn("global-cap", reasons[0])

    def test_single_cap_row_is_not_invalid(self):
        """个别端点自己限流是正常现象，不能把整轮丢掉。"""
        valid, _ = assess(rows("CAP-THROTTLED", 2) + rows("REACHABLE", 47), PROXY)
        self.assertTrue(valid)

    def test_healthy_round_is_valid(self):
        r = (rows("REACHABLE", 30) + rows("HANG-IN-TUNNEL", 11) + rows("EMPTY-REPLY", 4)
             + rows("PROXY-POLICY-DENY", 1) + rows("PROBE-CRASH", 1))
        valid, reasons = assess(r, PROXY)
        self.assertTrue(valid, reasons)

    def test_empty_round(self):
        valid, _ = assess([], PROXY)
        self.assertTrue(valid)  # 空表不是谎话，只是没数据


if __name__ == "__main__":
    unittest.main(verbosity=2)
