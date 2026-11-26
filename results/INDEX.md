# 快照索引

由 `index_results.py` 从 `results/*.json` 现算生成，不手改。
观测机是同一台华为云 cn-north-4a 云主机；`ts` 是 UTC 的 `YYYYMMDD-HHMM`。
判决（verdict）由 `egress_matrix.verdict()` 对每轮**存下来的原始观测**重算——分类器改过（新增 `HANG-IN-TUNNEL` / `EMPTY-REPLY` / `RELAY-5XX`），沿用旧文件里的 verdict 会把历史误判永久留在表里。

## A. 每轮判决计数（只统计含 `verdict` 字段的轮次）

| 快照 (UTC) | 观测点 | 端点 | PROXY-POLICY-DENY | RELAY-5XX | HANG-IN-TUNNEL | EMPTY-REPLY | STUB-FAKE-OK | REACHABLE | 其它 |
|---|---|---|---|---|---|---|---|---|---|
| `20261125-0407` | 本机 cn-north-4a | 47 | 2 | 0 | 0 | 0 | 0 | 0 | 45 |
| `20261125-0412` | 本机 cn-north-4a | 6 | 1 | 0 | 0 | 0 | 0 | 0 | 5 |
| `20261125-0642` | 本机 cn-north-4a | 47 | 1 | 0 | 11 | 4 | 0 | 31 |  |
| `20261125-0859` | 本机 cn-north-4a | 47 | 1 | 0 | 11 | 4 | 0 | 31 |  |
| `20261125-0935` | 本机 cn-north-4a | 47 | 1 | 1 | 12 | 4 | 0 | 29 |  |
| `20261125-0952` | 本机 cn-north-4a | 47 | 2 | 0 | 10 | 4 | 0 | 31 |  |
| `20261125-1050` | 本机 cn-north-4a | 49 | 1 | 0 | 13 | 4 | 1 | 30 |  |
| `20261125-1056` | GitHub runner | 49 | 0 | 0 | 0 | 6 | 1 | 39 | 3 |
| `20261126-0214` | 本机 cn-north-4a | 49 | 1 | 0 | 9 | 4 | 1 | 34 |  |
| `20261126-0226` | 本机 cn-north-4a | 49 | 1 | 0 | 12 | 4 | 1 | 31 |  |

## B. 同一主机、跨轮次的 CONNECT 判决（只列变过的；只用本机观测点的轮次）

CONNECT 是**代理层**的判决；它和「隧道内到底拿到了什么」是两件事——见 README 的 `HANG-IN-TUNNEL` 一节。跨观测点的对比不进这张表：那是「换了出口」，不是「时间变了」——见 C 表。

| 主机 | 各轮 CONNECT 判决 |
|---|---|
| `api.mistral.ai` | 20261125-0407:200 → 20261125-0642:200 → 20261125-0859:200 → 20261125-0935:200 → 20261125-0952:403 → 20261125-1050:200 → 20261126-0214:200 → 20261126-0226:200 |
| `api.openai.com` | 20261125-0407:403 → 20261125-0412:200 → 20261125-0642:200 → 20261125-0859:200 → 20261125-0935:200 → 20261125-0952:200 → 20261125-1050:200 → 20261126-0214:200 → 20261126-0226:200 |

## C. 同一端点、两个观测点（本机出口 vs GitHub runner）

本机 `20261126-0226` vs runner `20261125-1056`，共 49 个共同端点，**14 个判决不同**。两个都用当前分类器重算，差异只可能来自出口，不可能来自代码。

| 主机 | 本机出口 | GitHub runner |
|---|---|---|
| `api.anthropic.com` | REACHABLE | EMPTY-REPLY |
| `api.mistral.ai` | HANG-IN-TUNNEL | REACHABLE |
| `api.openai.com` | HANG-IN-TUNNEL | REACHABLE |
| `api.telegram.org` | HANG-IN-TUNNEL | REACHABLE |
| `generativelanguage.googleapis.com` | HANG-IN-TUNNEL | EMPTY-REPLY |
| `ghcr.io` | HANG-IN-TUNNEL | REACHABLE |
| `github.com` | HANG-IN-TUNNEL | REACHABLE |
| `gitlab.com` | HANG-IN-TUNNEL | REACHABLE |
| `huggingface.co` | HANG-IN-TUNNEL | REACHABLE |
| `imap.qq.com` | HANG-IN-TUNNEL | TLS-OR-HTTP-FAIL |
| `inference.ai.azure.com` | PROXY-POLICY-DENY | DNS-FAIL |
| `proxy.golang.org` | HANG-IN-TUNNEL | REACHABLE |
| `registry-1.docker.io` | HANG-IN-TUNNEL | REACHABLE |
| `smtp.qq.com` | HANG-IN-TUNNEL | TLS-OR-HTTP-FAIL |

这就是把「判决属于端点」和「判决属于出口」分开的唯一办法：换一个出口再测一遍，两边都一样的那部分，才谈得上属于端点。


读法：

- A 表各列互斥；`REACHABLE` 只代表**该轮**在隧道内拿到了正常响应，不代表长期可用。
- B 表只保留变过的主机：判据必须带时间戳，否则既不能复现也不能被反驳。
- 同一套测法在不同时间给出不同判决：`0407` 轮的 45 个「可达」在重算后是 **`CAP-THROTTLED`**——它们当时拿到的是逐字节相同的 429 限额文案，只是旧分类器没检查 body。`0642`/`0859` 轮 31 个可达、11 个挂死；`0935` 又变成 29/12。变的不是端点，是出口当时的状态。
- 想把表里的数字换成你自己的出口：`python3 egress_matrix.py --proxy http://127.0.0.1:8080`。

## 已隔离的轮次（不进上表）

这些快照是探针**自己**没配好时跑出来的，不代表任何端点。文件和原因都留着，便于复核：

- `matrix-20261126-0530.json`

第一个案子：`matrix-20261126-0530.json` 由 cron 拉起，而 cron 不继承登录 shell 的代理变量，49 个端点全落成 `DNS-FAIL`。本机直连路径本来就没有解析器（`systemd-resolved` 恒 SERVFAIL），所以这张表真正说明的是「没有代理时我什么都测不到」，而不是「49 个端点在 11-26 早上同时挂了」。已修：`matrix_cron.sh` 显式导出代理，并用 `--require-proxy` 让探针在无代理时**拒跑**（退出码 2）；`assess()` 会把不合格的一轮自动移进 `results/invalid/`（退出码 3）。
