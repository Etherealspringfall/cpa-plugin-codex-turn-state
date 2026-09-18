# cpa-plugin-codex-turn-state

CLIProxyAPI（CPA）原生插件。在单个 `(账号, 模型)` 桶内复用官方 Codex
`X-Codex-Turn-State` 值：采到正常态的 **292** 存进库，业务请求发往上游前把库存的
292 装上去，绕开降级态 **312**。

插件从不伪造值，也从不跨账号或跨模型复用。它读写的头只有
`X-Codex-Turn-State` 一个。

关于这个值到底是什么（带签发时间戳的 Fernet 令牌）、为什么两种长度正好差一个
AES 块、有效期怎么算，见 [FINDINGS.md](FINDINGS.md)。

## 不可配置的规则

以下四条写死在代码里：

1. state 值**绝不**跨账号复用。
2. state 值**绝不**跨模型复用，同一账号内也不行。
3. 同账号同模型的复用**可以跨 IP**。
4. 模板在 `ttl_seconds`（默认 3600）后过期，**从令牌自带的 Fernet 时间戳起算**，
   不是从代理看到它的时刻起算。

第 4 条是硬墙：有效期签在令牌内部，过期的值上游会直接拒绝
（`Encrypted content could not be decrypted`），不会静默忽略。所以一个在生命
周期后段才被采到的模板，绝不能当成新鲜的再算一个完整 TTL。

## 架构

一个进程同时做三件事，共用一个 store：

```
① 离线探测（主动）   插件 ──直连──> chatgpt.com        采 292 ──┐
                     不经过 CPA、不改 CPA 任何状态              │
                                                                ├─> store
② 被动采集（免费）   业务流量 ─> CPA ─> 上游                    │
                                  └─ 响应头里的 292 ────────────┘
                                                                │
③ 业务替换           业务请求 ─> CPA ─> 读 store 装头 ─> 上游 <─┘
```

> **历史注记**：早期版本是「探测/业务二选一、同一进程不能兼任」。那个限制来自
> 当时的采集方式——靠 CPA 的响应钩子采、靠「只启用一个号」来归属，于是探测期
> 必须停业务。现在探测直连上游、自己握着 token，归属天然精确，**限制已经不存在
> 了**。`role` 现在只决定「要不要替换」，不再决定「能不能采」。

### ① 离线探测：直连上游，不碰 CPA

探测**不再经过 CPA**，也**不再操控 CPA**：

- 读每个账号自己的 `access_token`（只读的管理 API 调用）
- 直连 `POST https://chatgpt.com/backend-api/codex/responses`
- 因为握着 token，**归属是确定的**——不需要停用其它账号，所有账号可并行

三条铁律：

| 规则 | 为什么 |
|---|---|
| **只读 CPA** | 只有 `auth-files` 列表和 `auth-files/download` 两个 GET。不写启用位、不写 `proxy_url`、不碰全局 `proxy-url` |
| **绝不刷新 token** | 刷新可能轮换 refresh token，把 CPA 正在用的凭据顶掉。过期的号直接跳过，等 CPA 自己刷。实测 access_token 有效期好几天，跳过代价近零 |
| **只存 292** | 312 是降级态，永不入库 |

### ② 被动采集：零额度，而且自限

桶空的时候，该桶的业务请求不会被装头，于是**上游会正常铸一个新的 turn-state**。
插件在响应钩子上读它——请求本来就要发，**不花一分额度**。

这和 ③ 构成一个自洽闭环：

```
桶里有卡  →  ③ 装头  →  上游【不再铸】新 turn-state  →  ② 没得采（也不需要）
桶里没卡  →  ③ 放行  →  上游【会铸】turn-state       →  ② 292 直接入库 ✅
```

**最需要卡的时候采集正好发生，不需要的时候自动停。** 不用额外的开关或限流，因为
它不产生任何额外请求。

> 早期文档说「业务端从业务流量采是在赌某个请求碰巧带着能用的 292」——那说的是从
> **请求**里采（客户端自带的头，来路不明，至今仍然禁止）。这里采的是**上游响应**
> 里刚铸出来的头，是两回事。

采集覆盖两条响应路径：

| 上游响应形态 | 钩子 | 头从哪来 |
|---|---|---|
| 非流式 | `response.intercept_after` | `ResponseHeaders` |
| SSE 流式（Codex 实际走这条） | `response.intercept_stream_chunk` 的 header-init（`ChunkIndex == -1`） | `ResponseHeaders` |

CPA 给钩子的是**未被剥离的上游原始响应头**——`downstreamHeadersAfterInterceptors`
的剥离发生在钩子**之后**，只影响发给客户端的那份。所以客户端收不到这个头，插件
却看得到。

WebSocket 路径（`websocket.response_event`）不暴露 HTTP 响应头，采不到，只保留一行
诊断日志。

#### ⚠️ 归属要靠 RequestID 接力

CPA 给两个钩子的是**两个不同的 metadata map**：

```
handlers_interceptors.go:565  请求钩子 ← req.Metadata    publishSelectedAuthMetadata 写的是这个
handlers_interceptors.go:595  响应钩子 ← opts.Metadata   另一个对象，从没被写入账号
```

两个都叫 `Metadata`，所以很容易以为是同一份。**不是**——响应侧的 `selected_auth_id`
永远是空的，实测 `auth=-`。

好在两个钩子带的 `RequestID` 是同一个（`:556` 与 `:584`），所以请求钩子把
`RequestID → 账号` 记下来，响应钩子凭 ID 取回、**取完即删**。这不是推断：relay 的
就是 CPA 自己选的那个号，只是跨过了一个会丢掉它的钩子边界。

只 relay **observed** 的账号；inferred 的是本次请求自己的猜测，不外传。

### ③ 业务替换

- 只在 `request.intercept_after` 里改写。
- 启动和 reconfigure 时扫描 store 装入未过期的 292；store 更新后能重载。
- **禁止**从业务**请求**更新 store（`harvest_inband` 对 business 强制 false）。
- 换头时先 `ClearHeaders` 再写值，避免大小写不同导致出现两份。
- 无模板 / 已过期 / 键不全：**不动头**，打 `pass`。

## 探测的节奏与限速

这一节是拿事故换来的，改之前先读。

**2026-09-18 的教训**：10 个代理背靠背连打，4 秒 60 发、单账号约 7.5 发/秒，上游
回了 21 个 429——**那个限速是自己招来的**，前几发还是正常的 312。代理池越大，这
个突刺越尖。

现在的四条约束：

| 约束 | 值 | 作用 |
|---|---|---|
| 三元组冷却 | 55 分钟 | 同一个 `(出口, 账号, 模型)` 最多 55 分钟打一次 |
| 出口间隔 | 2 秒 | 同一个桶的两个出口之间必须隔开 |
| 同账号串行 | 1 | 一个账号同时只有一个请求在飞 |
| 429 退避 | 10 分钟 | 拿到 429/401/403 立刻**中止走池**，整个账号退避 |

### 312 和 429 不是一回事

```
312  = 这个出口的 IP 对该(账号,模型)被限流  →  换下一个出口是对的 ✅
429  = 你请求太快了（账号级别）             →  换出口只会更糟 ❌
```

把所有非 200 都当成「换下一个出口」正是上面那次 429 雪崩的原因。

### 为什么冷却是 55 分钟而不是 60

卡活 3600 秒，续期在**到期前 5 分钟**（即 T+55min）触发。冷却若取整 60 分钟，
会把自己的续期挡掉，让卡每轮空窗 5 分钟。55 让两者刚好对齐。

### 走代理池的顺序

账号 `i` 从 `pool[i % N]` 开始，然后按顺序走完一圈。冷却键**包含出口 URL**，所以：

- 新加的代理没有冷却记录 → **立刻可试**，不用等
- 把写错的代理改对，字符串变了 → 也是新键 → 立刻重试

小时请求上限 = `出口数 × 账号数 × 模型数`（每个三元组 55 分钟一次）。**加代理会
抬高这个上限，但不会提高瞬时速率**——瞬时速率由出口间隔和同账号串行决定，那才是
429 的成因。

### 续期只能靠主动探测

桶一满，业务就开始装头，上游随即不再铸新头，**被动采集对那个桶就哑了**。所以：

```
桶空 → 被动采集能补（免费、高频）
桶满 → 只有主动探测能在 T+55min 去续
     → 续不上就过期 → 桶变空 → 被动采集重新接管（自愈，但有空窗）
```

**点「停止探测」不会停掉被动采集**，但会失去续期。

## 为什么业务端的改写能到上游

插件在 `request.intercept_after` 里写的头，要经过 CPA 内部五道才落到发往上游的
请求上。这条链路值得留档——它不是想当然成立的，而且升级 CPA 时可能被悄悄改掉。

以下行号对应 `CLIProxyAPI/v7 v7.3.4`：

| # | 位置 | 做了什么 |
|---|---|---|
| 1 | `sdk/api/handlers/handlers_interceptors.go:485` | 插件 `request.intercept_after` 的返回值合并进 `opts.Headers` |
| 2 | `internal/runtime/executor/codex_executor_execute.go:84`（非流式）<br>`internal/runtime/executor/codex_executor_stream.go:92`（流式） | 调用 `applyCodexHeaders(...)`，把 `opts.Headers` 作为 `clientHeaders[0]` 传进去 |
| 3 | `internal/runtime/executor/codex_executor_request.go:281-283` | `if len(clientHeaders) > 0 && clientHeaders[0] != nil { ginHeaders = clientHeaders[0] }` —— `ginHeaders` **就是插件改过的那份** |
| 4 | `internal/runtime/executor/codex_executor_request.go:334` | `misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-State", "")` |
| 5 | `internal/misc/header_utils.go:72-76` | `EnsureHeader`：source 非空则 `target.Set(key, val)` **无条件覆盖** |

> ### ⚠️ 升级 CPA 后必须回归这条链路
>
> 如果将来的 CPA 版本动了第 2 步的 `clientHeaders` 传参、或第 5 步的覆盖优先级，
> 业务端会**静默失效**：日志照常打 `inject`/`substitute`，但上游收到的仍是 312。
>
> **升级后要实打实验一次**：看 CPA 的请求日志，确认到达上游的是 292。

这条只关系**业务端**（往上游写请求头）。采集读的是**响应**头，走另一条路径。

## 分桶

桶键 = `selected_auth_id`（账号 JSON 的**文件名**）+ 官方 `model` 字符串，中间用
`\x00` 拼接（不可碰撞）。

| 组成 | 来源 |
|---|---|
| 账号 | 请求钩子的 `Metadata["selected_auth_id"]`；离线探测则是它自己持有 token 的那个账号 |
| 模型 | 请求/响应里的 `Model` |

桶键**不含 IP**：同账号同模型跨 IP 可以复用（规则 3）。

本部署当前的目标模型（必须带横线，不要写成 `gpt5.5`）：

```
gpt-5.5
gpt-5.6-sol
gpt-5.6-terra
gpt-6-astra
```

看板的模型勾选框有一份内置候选清单（`knownCodexModels`），它只是**菜单**——清单
过时最多少几个勾选框，不影响手写的模型 id 生效。

## Store 格式

目录权限 `0700`，文件 `0600`，属主要让 CPA 进程读写得到。

```
<store_dir>/
  index.json
  <账号JSON文件名>/
    <模型>.json
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `auth_id` | string | 账号 JSON 文件名 |
| `model` | string | 官方模型 id |
| `len` | int | 值长度，必须是 292 |
| `value` | string | 292 字符的官方 `X-Codex-Turn-State` |
| `issued_at` | RFC3339 | 令牌自带 Fernet 时间戳换算出的签发时间 |
| `harvested_at` | RFC3339 | 写盘时刻 |
| `attribution` | string | `observed` / `inferred` |

写入规则：

- `len != 292`：**拒绝写入**。312 永远不入库。
- **原子写**：先写临时文件再 `rename`。
- 同桶**覆盖**旧值。
- 已过期的文件：业务加载时跳过；探测可以覆盖重采。

`index.json` 列出每个桶的 `ready` / `issued_at` / `expires_at`，**不放 `value`**。

## 配置

| 键 | 默认 | 含义 |
|---|---|---|
| `role` | `business` | `business` = 做替换；`probe` = 不替换。**采集在两种角色下都开** |
| `store_dir` | `""` | store 目录，**容器内路径** |
| `template_length` | 292 | 作为可复用模板采集的值长度 |
| `replace_length` | 312 | 降级态长度 |
| `ttl_seconds` | 3600 | 模板可用时长，从令牌自己的 Fernet 时间戳起算 |
| `inject_mode` | `replace-only` | 见下。只接受 `always` / `replace-only`，其它非空值拒绝启动 |
| `harvest_inband` | false | 是否从业务**请求**采。**business 强制 false** |
| `dry_run` | false | 逻辑照走、照打日志，但不真改头。**不影响采集** |
| `log_decisions` | true | 每个决定打一行 |
| `models` | `[]` | 目标模型清单 |
| `probe_accounts` | `[]` | 探测覆盖哪几个账号（文件名） |
| `probe_proxies` | `[]` | 探测出口池，**明文回传**（见下） |
| `probe_management_key` | `""` | **只读**用：拉账号清单 + 下载各账号 token |
| `probe_base_url` | `http://127.0.0.1:8317` | CPA 自己的管理接口地址 |
| `probe_api_key` | `""` | **已废弃**，留空即可 |

`probe_api_key` 曾经是「打 CPA `/v1/responses`」用的。离线探测直连上游、用账号
自己的 token 鉴权，**不再需要它**。字段保留只为兼容旧配置。

### `probe_accounts` / `probe_proxies` 只影响探测

这两项**不是白名单**。业务替换的判据只有：桶 `(账号, 模型)` 里有没有未过期的
292。把账号从 `probe_accounts` 去掉**不会**让它停止被替换——只是主动探测不再给它
采（被动采集仍然会）。

改这两项**不会清空已有模板**（`templatesInvalidatedBy` 不含它们）：在看板上勾范围
是最常见的 `configure` 触发源，在那里清模板等于每勾一次就扔掉一批还能用的卡。

**空范围 = 拒绝开跑**，不会退化成打全量。

### `probe_proxies` 现在是明文回传

> **这是操作员明确要求的取舍，不是疏漏。**
> 早期版本在 status 里只回脱敏形式，结果是每次编辑探测范围都要把所有密码重打
> 一遍，基本没法用。现在 status 直接回原值。

| 出口 | 回传什么 |
|---|---|
| 匿名 `/v0/resource/plugins/codex-turn-state/status` | **明文** `probe_proxies` + `probe_proxy_count` |
| 日志 / `index.json` / 决策行 | **永不出现**，一律走 `maskProxyURL` |

也就是说：**这份清单对任何够得到本插件的东西都可读**。CPA 只绑 `127.0.0.1`，前提
是已经在这台机器上。

> ### ⚠️ 往 `statusResponse` 里加字段前先读这段
>
> `handleStatus` 同时服务**匿名** resource 路由和鉴权 management 路由，两边返回
> **同一个结构体**，没有按路由过滤。
>
> **加进 `statusResponse` 的任何东西都是公开的。** 加错地方不会报错、不会有日志。

账号文件名里带客户邮箱，所以看板显示的是打码后的 `620f5a42…pro`。两个 helper
（`maskAuthLabel` / `probeShortAuth`）都**先丢掉含 `@` 的段再取首尾**——邮箱在末段
时，先取首尾再丢会把地址原样打出来。

### 全局 `proxy-url` 永远不碰

它承载 Kimi、xAI 和全部日常流量。探测用的代理只活在探测自己的 HTTP 客户端里，
**不再写进任何账号的 `proxy_url`**（早期版本会写，现在这条路径整个删掉了）。

`socks5h://` 会被归一化成 `socks5://`：`net/http` 不认前者、会当成 HTTP 代理拨错。
两者只差域名在哪解析，而 Go 的 socks5 拨号本来就把主机名交给代理，所以改写是等价的。

### `inject_mode`

- `replace-only` — **只**改写已经带着 312 的请求。
- `always` — 把库存模板装到该桶的**每一个**请求上：没有就加，有别的就换掉。

> **本部署线上用的是 `always`**，由操作员明确指示（原话：「没有头的也装这个 292
> 发过去」）。早期文档写的「拍板用 replace-only，不要改成 always」**已作废**。

取值只接受这两个，拼错（比如 `replace_only`）会当场失败而不是静默退化。

### 改哪些键会清空已有模板

改 `template_length`、`replace_length`、`ttl_seconds` 会清空所有桶。`dry_run` 和
`log_decisions` 不会——它们决定的是拿模板做什么，不是模板还算不算数。

宿主 reconfigure 的频率远高于配置真正变化的频率（光启动就五次），每次都清会让缓存
永远是空的。

完整配置块见 [`config.example.yaml`](config.example.yaml)。

## 日志

```
[codex-turn-state] harvest auth=<账号JSON文件名> model=gpt-5.5 len=292 (template stored)
[codex-turn-state] inject  auth=<账号JSON文件名> model=gpt-5.5 len=0   (added (request carried no state))
[codex-turn-state] pass    auth=<账号JSON文件名> model=gpt-6-astra len=312 (upstream issued degraded state…)
[codex-turn-state] skip    auth=-                model=-        len=292 (incomplete bucket key)
```

| 决定 | 含义 |
|---|---|
| `harvest` | 一个 292 写进了 store（来自离线探测或被动采集） |
| `substitute` | 把请求里的 312 换成了库存 292 |
| `inject` | `always` 模式下给本来没头的请求装上了 292 |
| `pass` | 不动这个请求，`reason` 说明为什么 |
| `skip` | 桶键不全，无法归属 |

探测运行的转录另有一份（`probe_run.lines`，看板上可见），账号名在那里是打码的。

**值本身永远不进日志。** `X-Codex-Turn-State` 是凭据相邻的机密：不打日志、不进
仓库、不贴 PR、不贴聊天。

## 管理 API 与看板页面

**整个看板全程免密钥**（操作员原话：「整个插件页面不需要任何密钥」）。页面在 CPAMP
菜单里叫 **`Codex Turn-State`**。

| 路由（`/v0/resource/plugins/codex-turn-state/` 前缀） | 鉴权 | 说明 |
|---|---|---|
| `/dashboard` | 否 | 看板页面本体（菜单项） |
| `/status` | 否 | 只读状态，供页面轮询 |
| `/ops/choices` | 否 | 可选账号/模型清单，供勾选框渲染（**只读，免 confirm**） |
| `/ops/probe/start`、`/ops/probe/cancel` | 否 | 启停探测，需 `confirm=1` |
| `/ops/dry-run`、`/ops/role`、`/ops/clear`、`/ops/selftest`、`/ops/scope` | 否 | 需 `confirm=1` |
| `GET /v0/management/codex-turn-state/config` | **是** | 唯一还带密钥的路由 |

这些都是 **GET-only**（宿主规则），所以参数只能进 query，`confirm=1` 用来挡预取。

### 为什么外壳页面不鉴权

浏览器地址栏导航**带不上** `Authorization` 头，所以任何要用浏览器直接打开的页面都
不能挂在鉴权路由下。CPA 自己的 `/management.html` 就是这么处理的
（`server_routes.go:54` 直接挂在 engine 上，没套 `h.Middleware()`）。

### 插件不能持久化自己的配置

宿主没给插件保存配置的接口（`host.*` 里只有 `host.auth.save`）。所以探测范围由插件
自己写 `probe-scope.json`（在 `store_dir`，重启存活，**覆盖 config.yaml**），而
`dry_run` / `role` 走 CPA 原生的：

```
PATCH /v0/management/plugins/codex-turn-state/config     （浅合并，热生效不用重启）
```

> ⚠️ 别在 `PATCH` 之后紧接着调 `/ops/role` 之类的免密路由：角色处理器会把**内存里
> 那份还没更新的**配置写回去，把刚 PATCH 的值覆盖掉。踩过一次。

### ⚠️ 两个路由注册脚枪：注册时静默出错，运行时才暴露

**一、数据路由绝对不能带 `Menu` 字段。**
`routeDeclaresLegacyMenuResource`（`internal/pluginhost/management.go:156`）会把带
`Menu` 的 GET 路由**降级注册到不鉴权的 resource 前缀下**。只有外壳路由该带 `Menu`。

**二、`ResourceRoute.Path` 不能是 `"/"`。**
`management.go:212-214` 里 `TrimRight(path,"/")` 之后是空串就 `return false`，
**这条路由压根没被注册**，症状是运行时 404，日志一个字都没有。所以外壳挂在
`/dashboard` 而不是插件根。

### 「连通性自检」不会产生桶

插件通过 `host.model.execute` 发出的请求会被宿主标记为**跳过调用方自己的拦截器**
（`host_callbacks_unix.go:43` → `host_callbacks.go:304` → `:306`），所以自检的响应
不经过本插件的响应钩子，采不到 292。

它的用途是把两类故障分开：**通** = 账号可用、协议对、上游可达，问题在采集链路；
**不通** = 账号或协议本身有问题。

> 早期文档由此推出「所以采集必须走公开代理接口、必须停用其它账号来定向」。
> **那个结论已经作废**——离线探测直连上游、自己握着 token，归属天然精确，不需要
> 停任何号。

## 构建

构建在一次性 Go 容器里跑，宿主只需要 Docker：

```bash
scripts/build.sh                      # -> build/linux/amd64/codex-turn-state.so
GO_IMAGE=golang:1.26 scripts/build.sh /custom/out
```

这是一个 cgo `c-shared` 库，走稳定的 C ABI + JSON 信封协议，**不是** Go `plugin`
包的库，所以**不需要**和宿主完全相同的 Go 工具链。必须对上的是
`pluginabi.ABIVersion`（1）和 `pluginabi.SchemaVersion`（6）。

## 安装

插件 ID 是去掉扩展名的文件名，`-v<版本>` 后缀会被解析成版本号：

```bash
cp build/linux/amd64/codex-turn-state.so \
   <plugins-dir>/linux/amd64/codex-turn-state-v0.1.0.so
```

**换 `.so` 必须重启 CPA**，插件不热加载 `.so`。换的时候先 `cp` 到临时名再 `mv`
覆盖（同文件系统 rename）——直接 `cp` 盖一个正在被 mmap 的文件有 SIGBUS 风险。

| 改什么 | 要不要重启 |
|---|---|
| 配置键值（`dry_run`、`store_dir` 等） | 不要，热生效 |
| `.so` 文件本身 | **必须重启** |

重启 CPA 只停约 2 秒，但 sub2api 会给账号冷却，业务实际降级约 4 分钟。

部署步骤、停服窗口、验收清单见 [DEPLOY.md](DEPLOY.md)。

## License

MIT
