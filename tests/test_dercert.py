"""dercert 的回归测试：证书里"谁签的"这件事必须能被机器读出来。

这个文件存在的理由是一段真实的自我欺骗：egress_matrix 的 README 早就写着
「TLS issuer = CN = Local Network Proxy CA」，但代码里 `_issuer_from_der()` 只做了
`sha256(der)[:16]` 并把这个指纹命名为 `issuer`。指纹能回答「是不是同一张证书」，
**永远回答不了「签发者是谁」**——所以那条结论当时没有任何代码在支撑。

现在 `_describe()` 用这里的解析器读 issuer/subject。测试用两种来源：
  1. 本机 `/usr/local/share/ca-certificates/local-net-proxy.crt`（自签根，subject == issuer）；
  2. 现场用 openssl 造的一张自签证书（CN/O 带非 ASCII，日期落在 2050 年后 = 走 GeneralizedTime）。
     UTCTime 与 GeneralizedTime 是两条不同的解析分支，只测其中一条等于没测另一条。

跑法：`python3 tests/test_dercert.py`（零依赖、不联网）
"""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dercert  # noqa: E402

LOCAL_CA = "/usr/local/share/ca-certificates/local-net-proxy.crt"


class DerCertTest(unittest.TestCase):
    def test_local_proxy_ca_matches_openssl(self):
        """和 `openssl x509 -subject -issuer -dates` 逐字段对齐。"""
        if not os.path.exists(LOCAL_CA):
            self.skipTest("no local proxy CA on this box")
        with open(LOCAL_CA, "rb") as fh:
            info = dercert.parse(dercert.pem_to_der(fh.read()))
        self.assertEqual(info["issuer"]["CN"], "Local Network Proxy CA")
        self.assertEqual(info["issuer"]["O"], "Local Network")
        self.assertEqual(info["subject"], info["issuer"])
        self.assertTrue(info["self_signed"])
        self.assertEqual(info["not_after"], "2036-11-20T13:49:45Z")
        self.assertEqual(info["sha256"][:8], "7cb5fe10")
        self.assertEqual(info["sha256"][:8], "7cb5fe10")  # openssl: 7C:B5:FE:10…

    def test_generalized_time_and_utf8_name(self):
        """2050 年后的日期只能用 GeneralizedTime（0x18）；非 ASCII 值只能靠 UTF8String（0x0C）。"""
        with tempfile.TemporaryDirectory() as td:
            key, crt = os.path.join(td, "k.pem"), os.path.join(td, "c.pem")
            # -utf8 不能省：不加它 openssl 会把入参的每个字节当 latin1 字符再编码成 UTF-8，
            # 证书里存的是一段**双重编码**的乱码。第一次写这个测试就是踩在这里——
            # 报错的是测试夹具，不是解析器（解析器如实读出了那份乱码）。
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", key, "-out", crt, "-days", "12000", "-utf8",
                            "-subj", "/C=CN/O=测试组织/CN=测试签发者 中文"],
                           check=True, capture_output=True)
            with open(crt, "rb") as fh:
                info = dercert.parse(dercert.pem_to_der(fh.read()))
        self.assertEqual(info["issuer"]["CN"], "测试签发者 中文")
        self.assertEqual(info["issuer"]["O"], "测试组织")
        self.assertEqual(info["issuer"]["C"], "CN")
        self.assertIsNotNone(info["not_after"])
        self.assertRegex(info["not_after"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        # notBefore 是 2026 → UTCTime(0x17)；notAfter 是 2059 → GeneralizedTime(0x18)。
        # 这一张证书同时覆盖两条时间分支：两个年份都读对，才说明分支都走通了。
        self.assertEqual(info["not_before"][:4], "2026")
        self.assertGreater(int(info["not_after"][:4]), 2049)

    def test_bad_input_raises(self):
        for junk in (b"", b"\x30\x00", b"\x02\x01\x00", b"not a certificate at all"):
            with self.assertRaises(dercert.DERError):
                dercert.parse(junk)

    def test_pem_with_junk_lines(self):
        if not os.path.exists(LOCAL_CA):
            self.skipTest("no local proxy CA on this box")
        with open(LOCAL_CA, "rb") as fh:
            pem = b"Bag Attributes\n    friendlyName: x\nX509v3\tSubject: ...\n" + fh.read()
        self.assertTrue(dercert.pem_to_der(pem).startswith(b"\x30"))


class LocalAnchorTest(unittest.TestCase):
    def test_local_anchors_finds_the_proxy_ca(self):
        """`/usr/local/share/ca-certificates` 是「本机自己加的根」目录：正常云主机是空的。

        它不空，就等于「这台机器上有东西能签发任意站点的证书，而且被自己信任」——
        `mitm_local_ca` 这个判据就建立在这一点上。
        """
        if not os.path.exists(LOCAL_CA):
            self.skipTest("no local proxy CA on this box")
        anchors = dercert.local_anchors()
        cns = {(a.get("subject") or {}).get("CN") for a in anchors}
        self.assertIn("Local Network Proxy CA", cns)


if __name__ == "__main__":
    unittest.main(verbosity=2)
