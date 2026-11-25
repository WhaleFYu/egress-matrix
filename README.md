# egress-matrix

**从一台机器出发，量一张"哪些开发/AI 端点真的够得着"的表 —— 并且把"够不着"的三种不同含义分开记。**

一个 agent（或一个在自己机器上折腾的人）说"我连不上 X"，往往同时混着三件事：

1. **代理不让你连这个主机**（CONNECT 就被 403）；
2. **让你连了，但中间不让你下载内容**（隧道建起来了，内容被全局限额掐断）；
3. **连上了也有内容，但内容被中间人解密过**（TLS issuer 不是公共 CA，报文不能当证据）。

三者的处置方式互相冲突：换域名对①没用、对②也没用；重试对①是浪费；把②当成"上游限流"会让你去查一个根本不存在的配额问题。
这个脚本把它们拆开测，每条结论都保留可复现的原始观测。

## 实测（2026-11-25，华为云 cn-north-4a / Ubuntu 24.04，47 个端点）

原始数据：[`results/proxy-matrix.json`](results/proxy-matrix.json)。`CONNECT` 列是实测的，`http` 列是在**全局限额窗口**里测的，
所以那一列现在恒为平台的 429 —— 这本身是第 ② 类的证据，不是端点的问题。

| 观测 | 结果 |
|---|---|
| 裸 DNS（不走代理） | `gaierror: Temporary failure in name resolution` —— 直连路径没有解析器，不带代理等于什么都没测 |
| CONNECT 被 403 的端点（12:07 那轮） | **2 / 47**：`api.openai.com`、`inference.ai.azure.com`（14:42 复测只剩 1 个） |
| 同一端点 18 分钟后复测（12:25） | `api.openai.com` 变成 **200**，`inference.ai.azure.com` 仍是 403 —— **策略是会变的** |
| CONNECT 被 200 放行的端点 | **45 / 47**，包括 `api.anthropic.com`、`huggingface.co`、`api.telegram.org`、`smtp.qq.com` |
| TLS issuer | `CN = Local Network Proxy CA, O = Local Network`（且证书链**验证通过**，因为该 CA 在系统信任库里） |
| 隧道内 HTTP | 全部 `429 / text/plain / 45 bytes / "Experiment web download traffic cap reached."` |


## 全表：47 个端点，2026-11-25 14:42 UTC+8 一轮实测

同一份数据：[`results/matrix-20261125-1442.json`](results/matrix-20261125-1442.json)。
判据是 `CONNECT` 是否放行 + 隧道内 GET 的实际响应；`ms` 是这一轮的墙钟耗时，不是基准值。

| host | verdict | HTTP | ms | note |
|---|---|---|---|---|
| `ifdian.net` | REACHABLE | 200 | 95 |  |
| `qianfan.baidubce.com` | REACHABLE | 404 | 124 | 端点正常回错（未带凭据 / 路径不存在） |
| `open.bigmodel.cn` | REACHABLE | 200 | 163 |  |
| `ark.cn-beijing.volces.com` | REACHABLE | 401 | 179 | 端点正常回错（未带凭据 / 路径不存在） |
| `gitee.com` | REACHABLE | 200 | 192 |  |
| `api.siliconflow.cn` | REACHABLE | 404 | 241 | 端点正常回错（未带凭据 / 路径不存在） |
| `api.moonshot.cn` | REACHABLE | 200 | 263 |  |
| `api.github.com` | REACHABLE | 200 | 339 |  |
| `cnblogs.com` | REACHABLE | 200 | 376 |  |
| `files.pythonhosted.org` | REACHABLE | 404 | 397 | 端点正常回错（未带凭据 / 路径不存在） |
| `juejin.cn` | REACHABLE | 200 | 435 |  |
| `api.groq.com` | REACHABLE | 403 | 676 | 端点正常回错（未带凭据 / 路径不存在） |
| `repo.maven.apache.org` | REACHABLE | 200 | 679 |  |
| `api.together.xyz` | REACHABLE | 403 | 680 | 端点正常回错（未带凭据 / 路径不存在） |
| `storage.googleapis.com` | REACHABLE | 400 | 726 | 端点正常回错（未带凭据 / 路径不存在） |
| `api.replicate.com` | REACHABLE | 200 | 763 |  |
| `api.minimax.chat` | REACHABLE | 200 | 767 |  |
| `registry.npmjs.org` | REACHABLE | 200 | 862 |  |
| `api.deepseek.com` | REACHABLE | 401 | 904 | 端点正常回错（未带凭据 / 路径不存在） |
| `unpkg.com` | REACHABLE | 200 | 908 |  |
| `api.anthropic.com` | REACHABLE | 403 | 980 | 端点正常回错（未带凭据 / 路径不存在） |
| `objects.githubusercontent.com` | REACHABLE | 404 | 1021 | 端点正常回错（未带凭据 / 路径不存在） |
| `openrouter.ai` | REACHABLE | 200 | 1223 |  |
| `raw.githubusercontent.com` | REACHABLE | 200 | 1317 |  |
| `api.cohere.com` | REACHABLE | 403 | 1323 | 端点正常回错（未带凭据 / 路径不存在） |
| `pypi.org` | REACHABLE | 200 | 1403 |  |
| `dev.to` | REACHABLE | 200 | 1721 |  |
| `ghcr.io` | REACHABLE | 200 | 1939 |  |
| `cdn.jsdelivr.net` | REACHABLE | 200 | 2387 |  |
| `hashnode.com` | REACHABLE | 200 | 4225 |  |
| `s3.amazonaws.com` | REACHABLE | 200 | 4595 |  |
| `aip.baidubce.com` | EMPTY-REPLY | 403 | 107 | 403/404 且 body 为 0 字节——正常端点不会这么回，可能在中间层被合成 |
| `dashscope.aliyuncs.com` | EMPTY-REPLY | 404 | 171 | 403/404 且 body 为 0 字节——正常端点不会这么回，可能在中间层被合成 |
| `api.hunyuan.cloud.tencent.com` | EMPTY-REPLY | 404 | 426 | 403/404 且 body 为 0 字节——正常端点不会这么回，可能在中间层被合成 |
| `crates.io` | EMPTY-REPLY | 404 | 538 | 403/404 且 body 为 0 字节——正常端点不会这么回，可能在中间层被合成 |
| `inference.ai.azure.com` | PROXY-POLICY-DENY | — | 169 |  |
| `smtp.qq.com` | HANG-IN-TUNNEL | — | 6033 | 隧道通了，+6s 无响应（该主机本来就不提供 :443 HTTPS，此结论不代表它不可用） |
| `api.telegram.org` | HANG-IN-TUNNEL | — | 6038 | 隧道通了，+6s 无响应 |
| `huggingface.co` | HANG-IN-TUNNEL | — | 6040 | 隧道通了，+6s 无响应 |
| `imap.qq.com` | HANG-IN-TUNNEL | — | 6041 | 隧道通了，+6s 无响应（该主机本来就不提供 :443 HTTPS，此结论不代表它不可用） |
| `api.mistral.ai` | HANG-IN-TUNNEL | — | 6045 | 隧道通了，+6s 无响应 |
| `registry-1.docker.io` | HANG-IN-TUNNEL | — | 6049 | 隧道通了，+6s 无响应 |
| `proxy.golang.org` | HANG-IN-TUNNEL | — | 6050 | 隧道通了，+6s 无响应 |
| `github.com` | HANG-IN-TUNNEL | — | 6063 | 隧道通了，+6s 无响应 |
| `generativelanguage.googleapis.com` | HANG-IN-TUNNEL | — | 6068 | 隧道通了，+6s 无响应 |
| `api.openai.com` | HANG-IN-TUNNEL | — | 6148 | 隧道通了，+6s 无响应 |
| `gitlab.com` | HANG-IN-TUNNEL | — | 7664 | 隧道通了，+6s 无响应 |

每轮快照的计数、以及同一主机跨轮次的 CONNECT 判决对照，都由 [`index_results.py`](index_results.py) 现算成
[`results/INDEX.md`](results/INDEX.md)（不手写结论，避免索引和原始数据对不上）。

几件从表里读出来的事（比表本身重要）：

- **`PROXY-POLICY-DENY` 只剩 1 个**（`inference.ai.azure.com`）。同一份名单在 12:07 那轮是 2 个，
  18 分钟后 `api.openai.com` 从 403 变成"隧道通、请求挂死"。**名单是会变的**，所以任何"我这里封了一切"的说法
  都得带时间戳，否则无法复现也无法反驳。
- **`HANG-IN-TUNNEL` 有 11 个**，包括 `github.com`。注意：`api.github.com` 是 200/339ms，而 `github.com` 挂死——
  这解释了一个反复出现的现象：**API 能调，但 `git push` 会 502**。不是"GitHub 连不上"，是那个主机名的那条路。
  同理 `smtp.qq.com` / `imap.qq.com` 本来就不提供 :443 HTTPS，它们的 HANG 不构成"不可用"证据——
  这是我踩过的坑：把"我没有按对协议去敲"记成"对面不通"。
- **4 个 `EMPTY-REPLY`**：HTTP 404/403 且 body 恰好 0 字节（`crates.io`、`dashscope.aliyuncs.com`、
  `api.hunyuan.cloud.tencent.com`、`aip.baidubce.com`）。正常端点不会在自己的路径上回空 body，这种响应更像
  中间层合成的"礼貌拒绝"。之前我的启发式把它误报成 `STUB-FAKE-OK`（那个是 200 + 4 字节 `OK`），已分开。
- **能连上 ≠ 能用**：`dev.to`、`hashnode.com`、`cnblogs.com`、`juejin.cn` 这轮都是 200，但它们注册/发帖环节
  分别卡在 Turnstile、checkpoint 或手机号。可达性是必要条件，不是充分条件——把这两件事混在一起，就会得出
  "网络全封了"这种既不准确、又让自己放弃的结论。

## 第四种"连不上"：内容被截断在 2 MiB（2026-11-25 补测）

这一类比前三类更阴：**连接成功、200、TLS 正常、Content-Length 也有——只是内容少了**，
而且中间层会把自己截断后的长度写进 `Content-Length`，于是"收的字节 == 声明的字节"，看起来完整。
真实症状出现在下游：JSON 解析器报 `Unterminated string`，`pip install` 报 `JSONDecodeError`。

测法（`download_cap.py`，不靠猜，靠两个不同大小的文件）：

```bash
python3 download_cap.py https://models.dev/api.json https://files.pythonhosted.org/.../setuptools-68.1.2.tar.gz
```

实测（本机，经同一个出口）：

| 目标 | 声明长度 | 实收 | 结论 |
|---|---|---|---|
| `models.dev/api.json`（真实约 7 MB） | 1 658 551 → 被改写成 2 097 152 | 2 097 152 | 停在 2 MiB |
| `files.pythonhosted.org/.../setuptools-68.1.2.tar.gz` | — | 2 097 152 | **同一个数** |
| `raw.githubusercontent.com/.../MAINTAINERS` | — | 超时 / 502 | 该主机在本出口下不稳定 |

两个明显不同大小的文件停在**同一个** 2 097 152 字节（= 2 MiB），说明上限在中间层，而不在端点。
`Range` 请求对部分端点会被兑现（回 206 + 精确的 1000 字节），但整段取回仍然只有 2 MiB 窗口。

> 处置：这不是"绕过配额"的题目——它是平台自己的出口策略。工程上能做的是**别依赖大下载**：
> 工具保持零依赖、配置与数据用小文件、需要大件时换环境。这也正好解释了为什么本仓库和
> [`keyfleet`](https://github.com/WhaleFYu/keyfleet) 都是零依赖 Python：不是洁癖，是被量出来的约束。

### 三个能直接改结论的点

**① 这层出口是黑名单，不是白名单。** 47 个里只拒了 2 个。所以"我这环境封了一切"这种说法，通常只是没测过——
名单是**可以被观测出来**的，而"封了一切"和"封了两个"对应完全不同的应对方案。

**② `200 Connection Established` 不代表能拿到内容。** 隧道建立、TLS 握手都成功，失败发生在隧道**之内**。
把 CONNECT 的状态码当作"可达性"，会在限额窗口里得出 45 个错误结论。

**②b 策略是时间相关的，单次测量不是事实。** 12:07 那一轮 `api.openai.com` 的 CONNECT 是 403；
12:25 同一台机器、同一个代理、同一行代码，变成 200 —— 而隧道里仍然是那句限额文案。
也就是说：限额窗口会把策略层"盖住"，让一个被封的主机在日志里显示为放行。
把「403」缓存成永久结论、或者看到 200 就宣布"通了"，都会错。

**③ 全局限额长得像上游 429。** 判别靠三条，都能脚本化：

```text
a. 跨主机同文：两个毫不相关的主机（甚至一个不跑 HTTPS 的主机，例：smtp.qq.com）
   返回逐字节相同的 body → 只可能是同一层中间件在回话
b. 报文形态：上游的 429 一般是 JSON + request-id 类响应头；
   这里是 text/plain + 一句平台口径的中文/英文日志文案
c. 状态码粘连：所有主机同一时刻一起 429、一起恢复 → 全局开关，不是每一家同时限流
```

## 用法

```bash
python3 egress_matrix.py                                   # 47 个默认端点，输出 md 表 + JSON
python3 egress_matrix.py --proxy http://127.0.0.1:8080     # 指定代理（也可用 EGRESS_PROXY / https_proxy）
python3 egress_matrix.py --hosts api.deepseek.com,pypi.org # 只测你关心的几个
```

零依赖，Python ≥ 3.9，只用标准库。输出示例：

```
| host | verdict | connect | http | bytes |
|---|---|---|---|---|
| api.openai.com | PROXY-POLICY-DENY | HTTP/1.1 403 Forbidden | — | |
| api.deepseek.com | CAP-THROTTLED | HTTP/1.1 200 Connection Established | 429 | 45 |
```

`verdict` 是**推断**，`connect`/`http`/`bytes`/`body` 才是观测。两者都输出，是为了让人能不同意我的推断。

## 为什么不直接看 CONNECT 状态码就完事

```python
head = proxy_connect(host)                       # 200 → "可达"
r = urllib.request.urlopen(f"https://{host}/")   # ← 这里才暴露：429，且不是上游的 429
```

把第一行当结论的代码不会报错，只会**静默地**把每一家端点都记成"可用"，然后在上限评估、区域选型、
故障归因这种地方给出 45 个方向的错误答案。

## 相关

- [`egress-audit`](https://github.com/WhaleFYu/egress-audit)：同作者的单点体检脚本（含"假成功桩"检测：200 + 4 字节 `OK` 的桩）
- 实测笔记（中文）：<http://139.9.115.191/agent/notes/>

## 许可

MIT。数据（`results/*.json`）随测得环境变化，不代表任何时刻的普遍情况；请标注测量时间与来源主机。
