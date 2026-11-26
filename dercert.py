#!/usr/bin/env python3
"""dercert —— 用标准库读一张 X.509 证书里**值得怀疑**的那几个字段。

为什么需要它：`egress_matrix` 的第 ③ 类观测是"连上了、也有内容，但内容被中间人解密过"。
判这一条的唯一证据是**对端证书的签发者（issuer）**。而 `ssl.SSLSocket.getpeercert()` 在
`CERT_NONE` 模式下返回 `{}`（它只在 `CERT_REQUIRED` 且校验成功时才有结构化输出），
所以"走代理读 issuer"这条路只能拿 `binary_form=True` 的裸 DER —— 于是需要一个 DER 解析器。

此前的实现只对 DER 取了 sha256 前 16 位，然后把这个指纹叫 `issuer`：
它能告诉你"每次是同一张证书"，但**永远答不了"签发者是谁"**，也就无法区分
"这家站点用 Let's Encrypt" 和 "这条出口在拆我的 TLS"。指纹不是 issuer，名字才是。

输出字段（用 openssl x509 的措辞，方便对照）：
  subject  / issuer : {"CN": ..., "O": ..., "C": ...}（只收常见 RDN，其余放 "_other": [[oid, val], ...]）
  not_before / not_after : ISO-8601（UTC）
  serial / sha256    : 便于人工比对
  self_signed        : subject == issuer（自签根，或代理自己签的根）

只做解析、不做信任判断：信任是调用方的事（见 local_anchors()）。
仅用标准库。
"""
from __future__ import annotations

import datetime as _dt
import hashlib

# RDN 的 OID -> 字段名。只列会用到的：看到 "CN = Local Network Proxy CA" 就够下结论了。
_RDN = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.4.5": "serialNumber",
    "0.9.2342.19200300.100.1.25": "DC",
}

_UNIVERSAL_STRING = {0x0C, 0x13, 0x16, 0x14, 0x1A, 0x1E, 0x1B, 0x1C}


class DERError(ValueError):
    pass


def _tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """读一个 TLV，返回 (tag, content_start, content_end)。不复制内容。"""
    if i + 2 > len(buf):
        raise DERError(f"truncated header at {i}")
    tag = buf[i]
    ln = buf[i + 1]
    p = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise DERError(f"bad length form 0x{ln:02x} at {i}")
        if p + n > len(buf):
            raise DERError("truncated long length")
        ln = int.from_bytes(buf[p:p + n], "big")
        p += n
    end = p + ln
    if end > len(buf):
        raise DERError(f"truncated content at {i} (need {ln})")
    return tag, p, end


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    i = start
    while i < end:
        tag, cs, ce = _tlv(buf, i)
        out.append((tag, cs, ce))
        i = ce
    return out


def _oid(b: bytes) -> str:
    if not b:
        return ""
    first = b[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for byte in b[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _string(tag: int, b: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return b.decode("utf-16-be", "replace")
    if tag == 0x1B:  # GeneralString
        return b.decode("latin1", "replace")
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin1", "replace")


def _name(buf: bytes, start: int, end: int) -> dict:
    """Name ::= SEQUENCE OF RDN；RDN ::= SET OF AttributeTypeAndValue。"""
    out: dict = {}
    other: list[list[str]] = []
    for _stag, ss, se in _children(buf, start, end):          # 每个 RDN（SET）
        for _atag, as_, ae in _children(buf, ss, se):        # 每个 ATV（SEQUENCE）
            kids = _children(buf, as_, ae)
            if len(kids) < 2:
                continue
            otag, os_, oe = kids[0]
            vtag, vs, ve = kids[1]
            key = _RDN.get(_oid(buf[os_:oe]))
            val = _string(vtag, buf[vs:ve])
            if key:
                out[key] = f"{out[key]}, {val}" if key in out else val
            else:
                other.append([_oid(buf[os_:oe]), val])
    if other:
        out["_other"] = other
    return out


def _time(tag: int, b: bytes) -> str | None:
    s = b.decode("ascii", "replace")
    try:
        if tag == 0x17:      # UTCTime: YYMMDDHHMMSSZ（RFC 5280 要求带 Z）
            yy = int(s[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            t = _dt.datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]),
                             int(s[10:12]), tzinfo=_dt.timezone.utc)
        elif tag == 0x18:    # GeneralizedTime: YYYYMMDDHHMMSSZ
            t = _dt.datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]),
                             int(s[12:14]), tzinfo=_dt.timezone.utc)
        else:
            return None
    except (ValueError, IndexError):
        return None
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(der: bytes) -> dict:
    """Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }"""
    tag, cs, ce = _tlv(der, 0)
    if tag != 0x30:
        raise DERError(f"certificate is not a SEQUENCE (tag 0x{tag:02x})")
    top = _children(der, cs, ce)
    if not top:
        raise DERError("empty certificate")
    ttag, ts, te = top[0]
    if ttag != 0x30:
        raise DERError("tbsCertificate is not a SEQUENCE")
    f = _children(der, ts, te)
    # version 是 [0] EXPLICIT，出现时 tbs 的子项整体后移一位
    off = 1 if f and f[0][0] == 0xA0 else 0
    if len(f) < off + 6:
        raise DERError("tbsCertificate too short")
    serial_t, ss, se = f[off + 0]
    issuer_t, is_, ie = f[off + 2]
    val_t, vs, ve = f[off + 3]
    subj_t, us, ue = f[off + 4]
    if issuer_t != 0x30 or subj_t != 0x30 or val_t != 0x30:
        raise DERError("unexpected field order in tbsCertificate")
    issuer = _name(der, is_, ie)
    subject = _name(der, us, ue)
    nb = na = None
    vkids = _children(der, vs, ve)
    if len(vkids) >= 2:
        nb = _time(vkids[0][0], der[vkids[0][1]:vkids[0][2]])
        na = _time(vkids[1][0], der[vkids[1][1]:vkids[1][2]])
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": nb,
        "not_after": na,
        "serial": der[ss:se].hex()[:32],
        "sha256": hashlib.sha256(der).hexdigest(),
        "self_signed": issuer == subject,
    }


def pem_to_der(pem: bytes) -> bytes:
    import base64
    body = []
    inside = False
    for line in pem.splitlines():
        s = line.strip()
        if s.startswith(b"-----BEGIN CERTIFICATE"):
            inside = True
            continue
        if s.startswith(b"-----END CERTIFICATE"):
            break
        if inside:
            body.append(s)
    if not body:
        raise DERError("no PEM CERTIFICATE block found")
    return base64.b64decode(b"".join(body))


def local_anchors(dirs: tuple[str, ...] = ("/usr/local/share/ca-certificates",)) -> list[dict]:
    """列出**本机管理员额外装进信任库**的根证书。

    这是判 MITM 的那个关键区分：操作系统自带的 ~150 个公共根是"大家都有"的公信锚；
    `update-ca-certificates` 只从这里扫描 `*.crt`，装进来的都是"这台机器自己加的"——
    一台正常云主机的这个目录应当是空的。它不空，就说明有一条中间人能签发任意站点的证书，
    而且被这台机器信任。
    """
    import glob
    import os
    out = []
    for d in dirs:
        for p in sorted(glob.glob(os.path.join(d, "**", "*.crt"), recursive=True)):
            try:
                with open(p, "rb") as fh:
                    info = parse(pem_to_der(fh.read()))
            except Exception as e:  # 坏文件不该让整件事失败
                out.append({"path": p, "error": f"{type(e).__name__}: {e}"})
                continue
            info["path"] = p
            out.append(info)
    return out


if __name__ == "__main__":
    import sys
    args = sys.argv[1:] or ["/usr/local/share/ca-certificates/local-net-proxy.crt"]
    for a in args:
        with open(a, "rb") as fh:
            raw = fh.read()
        der = pem_to_der(raw) if b"-----BEGIN" in raw else raw
        import json
        print(json.dumps(parse(der), ensure_ascii=False, indent=1))
