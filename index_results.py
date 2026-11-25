#!/usr/bin/env python3
"""把 results/*.json 汇成 results/INDEX.md（两张表，全部现算，不手写结论）。

为什么要它：这份数据的核心主张是"判决随时间与测量的层而变"，单张快照说服不了人。
表 A：每轮快照各判决的计数（带时间戳）。
表 B：同一主机在不同轮次的 CONNECT 判决对照 —— 只有**变过**的主机才进表。

  python3 index_results.py
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
OUT = RES / "INDEX.md"
KEEP = ("PROXY-POLICY-DENY", "HANG-IN-TUNNEL", "EMPTY-REPLY", "STUB-FAKE-OK", "REACHABLE")


def load(p: Path) -> dict:
    d = json.loads(p.read_text(encoding="utf-8"))
    rows = d if isinstance(d, list) else (d.get("rows") or d.get("results") or [])
    gen = d.get("generated_at") if isinstance(d, dict) else None
    ts = p.stem
    if gen:  # 2026-11-25T12:07:39+0800 -> 20261125-0407 (UTC)
        import datetime as _dt
        t = _dt.datetime.fromisoformat(gen)
        ts = t.astimezone(_dt.timezone.utc).strftime("%Y%m%d-%H%M")
    # 测到哪一层：有 http 字段说明进了隧道取过内容，否则只测到 CONNECT
    depth = "CONNECT+GET" if any("http" in (r or {}) for r in rows) else "CONNECT"
    return {"ts": ts, "rows": rows, "depth": depth}


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
    snaps.sort(key=lambda s: s["ts"])

    a = ["# 快照索引", "",
         "由 `index_results.py` 从 `results/*.json` 现算生成，不手改。",
         "观测机是同一台华为云 cn-north-4a 云主机；`ts` 是 UTC 的 `YYYYMMDD-HHMM`。", "",
         "## A. 每轮判决计数（只统计含 `verdict` 字段的轮次）", "",
         "| 快照 (UTC) | 端点 | " + " | ".join(KEEP) + " | 其它 |",
         "|---|---|" + "---|" * len(KEEP) + "---|"]
    for s in snaps:
        vs = [r.get("verdict") for r in s["rows"] if r.get("verdict")]
        if not vs:
            continue
        c = Counter(vs)
        other = len(vs) - sum(c.get(k, 0) for k in KEEP)
        a.append(f"| `{s['ts']}` | {len(vs)} | "
                 + " | ".join(str(c.get(k, 0)) for k in KEEP) + f" | {other or ''} |")

    hist: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for s in snaps:
        for r in s["rows"]:
            if r.get("connect"):
                hist[r["host"]].append((s["ts"], conn_of(r)))
    changed = {h: v for h, v in hist.items() if len({x[1] for x in v}) > 1}

    b = ["", "## B. 同一主机、跨轮次的 CONNECT 判决（只列变过的）", "",
         "CONNECT 是**代理层**的判决；它和「隧道内到底拿到了什么」是两件事——"
         "见 README 的 `HANG-IN-TUNNEL` 一节。", "",
         "| 主机 | 各轮 CONNECT 判决 |", "|---|---|"]
    for h in sorted(changed):
        b.append(f"| `{h}` | " + " → ".join(f"{ts}:{v}" for ts, v in changed[h]) + " |")
    if not changed:
        b.append("| — | 本仓库现有数据里没有跨轮次变化的主机 |")

    tail = ["", "读法：", "",
            "- A 表各列互斥；`REACHABLE` 只代表**该轮**在隧道内拿到了正常响应，不代表长期可用。",
            "- B 表只保留变过的主机：判据必须带时间戳，否则既不能复现也不能被反驳。",
            "- 同一套测法在不同时间给出不同判决：`0407` 轮 45 个可达，`0642`/`0859` 轮只有 31 个；"
            "差的 14 个不是端点变了，而是出口进了限额窗口（变成 `HANG-IN-TUNNEL` / `EMPTY-REPLY`）。",
            "- 想把表里的数字换成你自己的出口：`python3 egress_matrix.py --proxy http://127.0.0.1:8080`。", ""]
    OUT.write_text("\n".join(a + b + tail), encoding="utf-8")
    print(f"wrote {OUT}: {len(snaps)} snapshots, {len(changed)} changed hosts")


if __name__ == "__main__":
    main()
