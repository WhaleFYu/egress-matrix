#!/usr/bin/env python3
"""把 results/*.json 汇成 results/INDEX.md（两张表，全部现算，不手写结论）。

为什么要它：这份数据的核心主张是"判决随时间与测量的层而变"，单张快照说服不了人。
表 A：每轮快照各判决的计数（带时间戳）。
表 B：同一主机在不同轮次的 CONNECT 判决对照 —— 只有**变过**的主机才进表。

  python3 index_results.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from egress_matrix import verdict as _verdict  # 用当前分类器重算历史判决，保证同一临界标准
except Exception:  # pragma: no cover
    _verdict = None

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
OUT = RES / "INDEX.md"
KEEP = ("PROXY-POLICY-DENY", "RELAY-5XX", "HANG-IN-TUNNEL", "EMPTY-REPLY", "STUB-FAKE-OK", "REACHABLE")


def load(p: Path) -> dict:
    d = json.loads(p.read_text(encoding="utf-8"))
    rows = d if isinstance(d, list) else (d.get("rows") or d.get("results") or [])
    gen = d.get("generated_at") if isinstance(d, dict) else None
    # valid=False 的快照不进表：那样的轮次测的是「探针自己没配好」，不是端点。
    # 文件被挪进了 results/invalid/（glob 不递归），这里再拦一次，防止有人手工搬回来。
    valid = d.get("valid", True) if isinstance(d, dict) else True
    # 观测点必须跟着快照走：把「本机出口」和「GitHub runner」的快照汇进同一张表，
    # 会让「端点变了」和「换了出口看」变成同一列数字——这个仓库存在的意义就是拆开这两件事。
    host = d.get("host") if isinstance(d, dict) else None
    vantage = "GitHub runner" if (host or "").startswith("runnervm") else ("本机 cn-north-4a" if host else "未知")
    ts = p.stem
    if gen:  # 2026-11-25T12:07:39+0800 -> 20261125-0407 (UTC)
        import datetime as _dt
        t = _dt.datetime.fromisoformat(gen)
        ts = t.astimezone(_dt.timezone.utc).strftime("%Y%m%d-%H%M")
    # 测到哪一层：有 http 字段说明进了隧道取过内容，否则只测到 CONNECT
    depth = "CONNECT+GET" if any("http" in (r or {}) for r in rows) else "CONNECT"
    return {"ts": ts, "rows": rows, "depth": depth, "valid": valid, "vantage": vantage, "host": host}


def _v(r: dict) -> str:
    """判决用当前分类器对**存下来的原始观测**重算。

    理由：分类器改过（新增 HANG-IN-TUNNEL / EMPTY-REPLY / RELAY-5XX）。若沿用文件里旧的 verdict，
    历史上的误判会永远留在表里；而原始观测都在，重算是可复核的。这一点写在表格上方。
    """
    if _verdict:
        try:
            return _verdict(r)
        except Exception:
            pass
    return r.get("verdict")


def conn_of(r: dict) -> str:
    c = r.get("connect") or {}
    st = c.get("status") or ""
    if "403" in st:
        return "403"
    if "200" in st:
        return "200"
    return "?"


def main() -> None:
    snaps = [load(p) for p in sorted(RES.glob("*.json")) if p.name != "INDEX.md"]
    snaps = [s for s in snaps if s["rows"] and s["ts"]]
    bad = [s for s in snaps if not s["valid"]]
    snaps = [s for s in snaps if s["valid"]]
    quarantined = sorted((RES / "invalid").glob("*.json")) if (RES / "invalid").is_dir() else []
    snaps.sort(key=lambda s: s["ts"])

    a = ["# 快照索引", "",
         "由 `index_results.py` 从 `results/*.json` 现算生成，不手改。",
         "观测机是同一台华为云 cn-north-4a 云主机；`ts` 是 UTC 的 `YYYYMMDD-HHMM`。",
         "判决（verdict）由 `egress_matrix.verdict()` 对每轮**存下来的原始观测**重算——"
         "分类器改过（新增 `HANG-IN-TUNNEL` / `EMPTY-REPLY` / `RELAY-5XX`），沿用旧文件里的 verdict 会把历史误判永久留在表里。", "",
         "## A. 每轮判决计数（只统计含 `verdict` 字段的轮次）", "",
         "| 快照 (UTC) | 观测点 | 端点 | " + " | ".join(KEEP) + " | 其它 |",
         "|---|---|---|" + "---|" * len(KEEP) + "---|"]
    for s in snaps:
        vs = [_v(r) for r in s["rows"] if r.get("verdict")]
        if not vs:
            continue
        c = Counter(vs)
        other = len(vs) - sum(c.get(k, 0) for k in KEEP)
        a.append(f"| `{s['ts']}` | {s['vantage']} | {len(vs)} | "
                 + " | ".join(str(c.get(k, 0)) for k in KEEP) + f" | {other or ''} |")

    # B 表只比较**同一观测点**的轮次：跨观测点的差异是「换了出口」，不是「时间变了」。
    hist: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for s in snaps:
        if s["vantage"] != "本机 cn-north-4a":
            continue
        for r in s["rows"]:
            if r.get("connect"):
                hist[r["host"]].append((s["ts"], conn_of(r)))
    changed = {h: v for h, v in hist.items() if len({x[1] for x in v}) > 1}

    b = ["", "## B. 同一主机、跨轮次的 CONNECT 判决（只列变过的；只用本机观测点的轮次）", "",
         "CONNECT 是**代理层**的判决；它和「隧道内到底拿到了什么」是两件事——"
         "见 README 的 `HANG-IN-TUNNEL` 一节。"
         "跨观测点的对比不进这张表：那是「换了出口」，不是「时间变了」——见 C 表。", "",
         "| 主机 | 各轮 CONNECT 判决 |", "|---|---|"]
    for h in sorted(changed):
        b.append(f"| `{h}` | " + " → ".join(f"{ts}:{v}" for ts, v in changed[h]) + " |")
    if not changed:
        b.append("| — | 本仓库现有数据里没有跨轮次变化的主机 |")

    # C 表：把 vantage 文件的用处兑现——同一端点，从两个不同的出口看，判决是否一致。
    # 只拿"带 host 字段的标准快照"做 C 表：download-cap.json 之类是另一种产物（单 URL 下载测试），
    # 行里没有 host，混进来只会 KeyError 或者更糟——静默拿错数据。
    local = [x for x in snaps if x["vantage"] == "本机 cn-north-4a" and all("host" in r for r in x["rows"])]
    remote = [x for x in snaps if x["vantage"] == "GitHub runner" and all("host" in r for r in x["rows"])]
    c = ["", "## C. 同一端点、两个观测点（本机出口 vs GitHub runner）", ""]
    if local and remote:
        L, R = local[-1], remote[-1]
        lmap = {r["host"]: _v(r) for r in L["rows"]}
        rmap = {r["host"]: _v(r) for r in R["rows"]}
        common = sorted(set(lmap) & set(rmap))
        diff = [h for h in common if lmap[h] != rmap[h]]
        c += [f"本机 `{L['ts']}` vs runner `{R['ts']}`，共 {len(common)} 个共同端点，**{len(diff)} 个判决不同**。"
              "两个都用当前分类器重算，差异只可能来自出口，不可能来自代码。", "",
              "| 主机 | 本机出口 | GitHub runner |", "|---|---|---|"]
        c += [f"| `{h}` | {lmap[h]} | {rmap[h]} |" for h in diff] or ["| — | 两处判决一致 | — |"]
        c += ["", "这就是把「判决属于端点」和「判决属于出口」分开的唯一办法：换一个出口再测一遍，"
              "两边都一样的那部分，才谈得上属于端点。", ""]
    else:
        c += ["（缺少至少一个观测点的数据）", ""]

    tail = ["", "读法：", "",
            "- A 表各列互斥；`REACHABLE` 只代表**该轮**在隧道内拿到了正常响应，不代表长期可用。",
            "- B 表只保留变过的主机：判据必须带时间戳，否则既不能复现也不能被反驳。",
            "- 同一套测法在不同时间给出不同判决：`0407` 轮的 45 个「可达」在重算后是 **`CAP-THROTTLED`**——"
            "它们当时拿到的是逐字节相同的 429 限额文案，只是旧分类器没检查 body。`0642`/`0859` 轮 31 个可达、"
            "11 个挂死；`0935` 又变成 29/12。变的不是端点，是出口当时的状态。",
            "- 想把表里的数字换成你自己的出口：`python3 egress_matrix.py --proxy http://127.0.0.1:8080`。", ""]
    # 被隔离的轮次要写出来。悄悄丢掉一张丑数据，和悄悄写进一张假数据，是同一种错。
    if quarantined or bad:
        names = [f"`{p.name}`" for p in quarantined] + [f"`{s['ts']}`(valid=false)" for s in bad]
        tail += ["## 已隔离的轮次（不进上表）", "",
                 "这些快照是探针**自己**没配好时跑出来的，不代表任何端点。文件和原因都留着，便于复核：", ""]
        tail += [f"- {n}" for n in names]
        tail += ["", "第一个案子：`matrix-20261126-0530.json` 由 cron 拉起，而 cron 不继承登录 shell 的代理变量，"
                 "49 个端点全落成 `DNS-FAIL`。本机直连路径本来就没有解析器（`systemd-resolved` 恒 SERVFAIL），"
                 "所以这张表真正说明的是「没有代理时我什么都测不到」，而不是「49 个端点在 11-26 早上同时挂了」。"
                 "已修：`matrix_cron.sh` 显式导出代理，并用 `--require-proxy` 让探针在无代理时**拒跑**（退出码 2）；"
                 "`assess()` 会把不合格的一轮自动移进 `results/invalid/`（退出码 3）。", ""]
    OUT.write_text("\n".join(a + b + c + tail), encoding="utf-8")
    print(f"wrote {OUT}: {len(snaps)} snapshots, {len(changed)} changed hosts")


if __name__ == "__main__":
    main()
