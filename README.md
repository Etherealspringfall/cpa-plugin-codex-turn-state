# cpa-plugin-codex-turn-state

CLIProxyAPI（CPA）原生插件。在单个 `(账号, 模型)` 桶内复用官方 Codex
`X-Codex-Turn-State` 值：**探测端**从上游响应采集正常态的 292，**业务端**在看到
降级态的 312 时整段换成库存的 292。

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

## 双角色架构

插件是被动拦截器：它只能**延用**一个已经存在的正常态值，不能**铸造**一个。
铸造新模板是探测端的活，业务流量不为采集买单。

```
role: probe      Codex 请求 ──> CPA ──> 上游
（拿头端）                       │
                                 └─ 响应头 292 ──> store 落盘
                                                     │
role: business   业务流量 ──> CPA ──> 读 store，312 换 292 ──> 上游
（接下游）
```

**为什么必须分开**：业务端如果顺手从业务流量里采，就是在赌「某个请求碰巧带着
一个能用的 292」。这个赌注在降级时段恰好最不可能赢——而那正是最需要它的时候。
所以业务端只读盘，采集由探测端在受控条件下完成。

两个角色**不能同一进程、同一时刻**既探测又接下游。一台 CPA 分时段切换角色即可，
拆两个容器可以后做，不是第一期必做。

### `role: probe`（探测端）

- 打开响应侧钩子，从**上游响应头**里采 `X-Codex-Turn-State`。
- 只有长度**正好 292**、且 `selected_auth_id` 与 `model` 都在，才写入 store。
- 312 或其它长度：不入库，打 `pass length not template`。
- 账号或模型缺失：不写盘，打 `skip incomplete bucket key`。
- **探测请求上禁止做 312→292 替换**——换了就采不到新头了。
- 探测端只写盘，不改任何请求。

采集覆盖两条路径：

| 上游响应形态 | 钩子 | 头从哪来 |
|---|---|---|
| 非流式 | `response.intercept_after` | `ResponseHeaders` |
| SSE 流式 | `response.intercept_stream_chunk` 的 header-init 那一次（`ChunkIndex == -1`） | `ResponseHeaders` |

> WebSocket 路径（`websocket.response_event`）在本 SDK 版本里**不暴露 HTTP 响应
> 头**——该事件只带 `EventType` 和 `Payload`。所以它采不到 292，插件只把它实现
> 成一行诊断日志，用来证明这条路有没有被走到。Codex 走的是 `/v1/responses`
> （非流式响应 + SSE），上表两条已经覆盖。

### `role: business`（业务端）

- 只用 `request.intercept_after` 做替换。
- 启动和 reconfigure 时扫描 store，装入未过期的 292；store 文件更新后能重载。
- **禁止**从业务请求或响应更新 store 或内存模板。
- 替换条件（三条**同时**满足才换）：
  1. 请求带 `X-Codex-Turn-State`
  2. 长度 == `replace_length`（312）
  3. 桶 `(selected_auth_id, model)` 有未过期的 292
- 换头时先 `ClearHeaders` 再写值，避免大小写拼写不同导致出现两份。
- 无模板 / 已过期 / 键不全：**不动头**，打 `pass`。
- 没有这个头的请求**不会被强灌** 292。

角色从 `probe` 切到 `business` 时，清空探测期的内存态，只从 store 重新加载。

## 为什么业务端的改写能到上游

插件在 `request.intercept_after` 里写的头，要经过 CPA 内部五道才落到发往上游的
请求上。这条链路值得留档——它不是想当然成立的，而且升级 CPA 时可能被悄悄改掉。

以下行号对应 `CLIProxyAPI/v7 v7.3.4`：

| # | 位置 | 做了什么 |
|---|---|---|
| 1 | `sdk/api/handlers/handlers_interceptors.go:485` | 插件 `request.intercept_after` 的返回值合并进 `opts.Headers` |
| 2 | `internal/runtime/executor/codex_executor_execute.go:84`（非流式）<br>`internal/runtime/executor/codex_executor_stream.go:92`（流式） | 调用 `applyCodexHeaders(httpReq, auth, apiKey, stream, e.cfg, opts.Headers)`，把 `opts.Headers` 作为 `clientHeaders[0]` 传进去 |
| 3 | `internal/runtime/executor/codex_executor_request.go:281-283` | `if len(clientHeaders) > 0 && clientHeaders[0] != nil { ginHeaders = clientHeaders[0] }` —— 于是 `ginHeaders` **就是插件改过的那份**，不是 gin 的原始客户端头 |
| 4 | `internal/runtime/executor/codex_executor_request.go:334` | `misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-State", "")` —— CPA 专门为这个头写了一行 |
| 5 | `internal/misc/header_utils.go:72-76` | `EnsureHeader` 第一分支：source 非空则 `target.Set(key, val)` **无条件覆盖** |

第 3 步和第 5 步是关键：`clientHeaders[0]` 的替换让插件的版本成为 source，而
`EnsureHeader` 的「source 覆盖 target」优先级正是插件的 292 能顶掉原值送到上游
的原因。不需要在账号 JSON 里做任何配置。

> ### ⚠️ 升级 CPA 后必须回归这条链路
>
> 如果将来的 CPA 版本动了第 2 步 `applyCodexHeaders` 的 `clientHeaders` 传参、
> 或者第 5 步 `EnsureHeader` 的覆盖优先级，业务端会**静默失效**：
> 插件日志照常打 `substitute`，但上游收到的仍然是 312。
>
> 日志是看不出来的——`substitute` 只说明插件做了决定，不说明决定生效了。
> **升级 CPA 后要实打实验一次**：发一个带 312 的请求，抓包或看上游请求日志，
> 确认到达上游的是 292。把这条列进升级后的回归检查项。

注意这条只关系**业务端**（往上游写请求头）。探测端读的是**响应**头，走的是另
一条路径，不经过上面这五步。

## 分桶

桶键 = `selected_auth_id`（账号 JSON 的**文件名**）+ 官方 `model` 字符串，中间用
`\x00` 拼接（不可碰撞）。

| 组成 | 来源 |
|---|---|
| 账号 | `Metadata["selected_auth_id"]`——调度器实际选中的凭据 |
| 模型 | 请求/响应里的 `Model`——实际发往上游的模型 |

桶键**不含 IP**：同账号同模型跨 IP 可以复用（规则 3）。两侧（探测写、业务读）
必须用同一个模型字段口径，否则桶对不上。

本部署的目标模型清单（必须带横线，不要写成 `gpt5.5`）：

```
gpt-5.5
gpt-5.6-luna
gpt-5.6-terra
gpt-5.6-sol
gpt-6-astra
```

## Store 格式

探测端写、业务端只读。目录权限 `0700`，文件权限 `0600`，属主要让 CPA 进程读写
得到。

```
<store_dir>/
  index.json
  <账号JSON文件名>/
    <模型>.json
```

### 桶文件 `<账号>/<模型>.json`

| 字段 | 类型 | 说明 |
|---|---|---|
| `auth_id` | string | 账号 JSON 文件名 |
| `model` | string | 官方模型 id |
| `len` | int | 值长度，必须是 292 |
| `value` | string | 292 字符的官方 `X-Codex-Turn-State` |
| `issued_at` | RFC3339 | 令牌自带 Fernet 时间戳换算出的签发时间 |
| `harvested_at` | RFC3339 | 写盘时刻 |

示例（`value` 用探测拿到的真值；**文档、仓库、PR、聊天里一律不写真实密文**）：

```json
{
  "auth_id": "<账号JSON文件名>",
  "model": "gpt-5.6-sol",
  "len": 292,
  "value": "<292 字符的官方 X-Codex-Turn-State>",
  "issued_at": "2026-09-18T04:11:07Z",
  "harvested_at": "2026-09-18T04:11:07Z"
}
```

### 写入规则

- `len != 292`：**拒绝写入**。312 永远不入库。
- **原子写**：先写临时文件，再 `rename` 到位。
- 同桶**覆盖**旧的 292。
- `issued_at + ttl_seconds <= now` 的文件：业务加载时**跳过**；探测可以覆盖重采。

### `index.json`

列出每个 `(auth_id, model)` 的 `ready` / `issued_at` / `expires_at`，
**不放 `value`**。用于人工检查和探测端判断是否齐活。

探测的 `--until-complete` 以「清单内每个桶都有未过期的 292 文件」为准，
**不以 HTTP 200 为准**。

## 配置

| 键 | 默认 | 含义 |
|---|---|---|
| `role` | `business` | `probe` = 拿头端（采集写盘）；`business` = 接下游（只读替换）。**缺失时默认 `business`** 这个安全侧取值；非空但非法的值会拒绝启动 |
| `store_dir` | `""` | store 目录，**容器内路径**。空字符串 = 不落盘也不读盘 |
| `template_length` | 292 | 作为可复用模板采集的值长度 |
| `replace_length` | 312 | 会被模板覆盖掉的值长度 |
| `ttl_seconds` | 3600 | 模板可用时长，从令牌自己的 Fernet 时间戳起算 |
| `inject_mode` | `replace-only` | 见下。取值只接受 `always` 和 `replace-only`，**其它非空值一律拒绝启动** |
| `harvest_inband` | false | 业务端是否也从业务流量采。**业务角色强制 false** |
| `dry_run` | false | 逻辑照走、照打日志，但不真改头 |
| `log_decisions` | true | 每个决定打一行 |
| `models` | `[]` | 目标模型清单。和 `probe_accounts` 一起构成探测范围 |
| `probe_accounts` | `[]` | 探测覆盖哪几个账号（文件名）。**只影响探测** |
| `probe_proxies` | `[]` | 探测时逐桶尝试的出口。**只影响探测**，带密码 |

### `probe_accounts` / `probe_proxies` —— 只影响探测

这两项**不是白名单**。业务路径一行都不读它们，`interceptAfterAuth` 和
`decideHeader` 里没有任何地方引用，有测试守着这条。

业务替换的判据从头到尾只有三条：

1. 请求带 `X-Codex-Turn-State`
2. 长度等于 `replace_length`（312）
3. 该 `(账号, 模型)` 桶里有未过期的 292

所以把一个账号从 `probe_accounts` 里去掉，**不会**让它停止被替换 —— 只是没人
给它采桶，它自然就没得换（空窗）。反过来，加进来也不会凭空生成桶：采集只有
`scripts/probe.py` 一条路。

改这两项**不会清空已有模板**（`templatesInvalidatedBy` 不含它们）。这点是刻意
的：在看板上勾选范围是 `configure` 最常见的触发源，在那里清模板等于操作员每勾
一次框就扔掉一批还能用的卡。

**空范围 = 拒绝开跑。** `probe.py` 在 `probe_accounts` 或 `models` 为空时以非 0
退出，不会退化成打全量。探测要停对外业务、每个桶烧一次上游请求，「没选就等于
全选」是唯一事后补救不了的错误。

#### `probe_proxies` 是这段配置里唯一的机密

值里带密码，所以它的暴露面是被刻意收窄的：

| 出口 | 回传什么 |
|---|---|
| 匿名 `/v0/resource/plugins/codex-turn-state/status` | 只有 `probe_proxy_count` 和 `probe_proxies_masked` |
| 鉴权 `GET /v0/management/codex-turn-state/status` | **同样只有脱敏形式** |
| 鉴权 `GET /v0/management/codex-turn-state/config` | 完整值，供看板回填编辑 |
| 日志 / `index.json` / 决策行 | 永不出现 |

> ### ⚠️ 往 `statusResponse` 里加字段前先读这段
>
> `handleStatus` 同时服务**匿名**的 resource 路由和鉴权的 management 路由，
> 两边返回**同一个结构体**，没有按路由做过滤。
>
> 所以：**加进 `statusResponse` 的任何东西都是公开的。** 这就是为什么完整代理
> 列表在 `configResponse` 而不在这里。加错地方不会报错、不会有日志，只会把密码
> 发出去。

脱敏统一走 `maskProxyURL`：userinfo 整段换成 `***`（不做「留前两位」，密码长度
本身就是线索），**解析不了的返回固定占位符而不是原值** —— 解析失败的那条往往正
是密码里混了怪字符的那条。

#### per-account 代理：读写都走哪里

```
写   PATCH /v0/management/auth-files/fields      {"name":…, "proxy_url":…, "auth_index":…}
读   GET   /v0/management/auth-files/download?name=…
```

**读回不能用列表接口。** `GET /v0/management/auth-files` 的条目里没有 `proxy_url`
（CPA 7.3.4 的列表 DTO 不带它）—— 早先据此断言「这台 CPA 不支持 per-account 代
理」是错的：字段在**账号文件本身**里，下载那条路由读得到。2026-09-18 已在 CPA
v7.3.4 上实测打通，`probe.py` 的日志会打出 `(verified by read-back)`。

写完**必须读回确认**。一条返回 200 却没生效的 PATCH，表现成「每个出口都采不到
292」，而真因是出口压根没换过 —— 那会把一整个停服窗口浪费在查上游上。所以读回
对不上时直接中止整轮，而不是当成「这个代理不行」记一笔继续。

全局 `proxy-url` **永远不碰**：它承载 Kimi、xAI 和全部日常流量。

### `inject_mode`

- `replace-only` — **只**改写已经带着 `replace_length`（312）值的请求，即只纠正
  观察到的降级态。没这个头、或长度不是 312，一律不动。
- `always` — 把库存模板强加到该桶的**每一个**请求上：没有就加，有别的就换掉。

> **本部署已拍板用 `replace-only`，不要改成 `always`。**
> `always` 会在业务请求本来没有这个头时强灌一个 292 —— 这是明令禁止的行为。

默认值就是 `replace-only`，所以漏写这个键也是安全的。但仍然建议在 config 里
**显式写出来**，让读配置的人一眼看到口径，不必去翻代码里的默认值。

取值只接受 `always` 和 `replace-only` 两个。**任何其它非空值都会让 `configure`
直接报错、插件拒绝启动**——拼错（比如写成 `replace_only`）不会静默退化成
`always`，而是当场失败。这是刻意的：静默退化的后果正好是被禁止的强灌行为。

### `harvest_inband` 的键名

主键名是 `harvest_inband`（中间**没有**下划线）。旧版本用过
`harvest_in_band`，仅作向后兼容别名保留。新配置一律写 `harvest_inband`。

`role: business` 且 `harvest_inband: true` 时，插件强制把它关掉并打一行错误
日志——业务端不采头是产品规则，不是可选项。

### 改哪些键会清空已有模板

改 `template_length`、`replace_length`、`ttl_seconds` 会清空所有桶，保证模板
不会活得比它被采集时所依据的规则更久。`dry_run` 和 `log_decisions` 不会——
它们决定的是拿模板做什么，不是模板还算不算数。所以 dry-run 期间采到的模板能
活过切到 `dry_run: false` 的那一刻。

这点重要，是因为宿主 reconfigure 的频率远高于配置真正变化的频率：光启动就五
次，CPA 每次自己重写 `config.yaml` 还会再来一次。每次都清就会让缓存永远是空的。

完整配置块见 [`config.example.yaml`](config.example.yaml)。

## 日志

决定写进 CPA 进程日志，一个决定一行：

```
[codex-turn-state] harvest    auth=<账号JSON文件名> model=gpt-5.5       len=292 (template stored)
[codex-turn-state] substitute auth=<账号JSON文件名> model=gpt-5.5       len=312 (expires in 41m18s)
[codex-turn-state] pass       auth=<账号JSON文件名> model=gpt-5.6-terra len=312 (no live template for bucket)
[codex-turn-state] skip       auth=-                model=-             len=292 (incomplete bucket key)
```

| 决定 | 含义 |
|---|---|
| `harvest` | 探测端把一个 292 写进了 store |
| `substitute` | 业务端把请求里的 312 换成了库存 292（`dry_run: true` 时照打，但不真改） |
| `pass` | 不动这个请求，`reason` 说明为什么 |
| `skip` | 桶键不全，无法归属，`reason` 说明缺什么 |

字段只有 auth / model / **len** / 决定 / reason。`reason` 可以带
「expires in …」这类时间信息。

**值本身永远不进日志。** `X-Codex-Turn-State` 是凭据相邻的机密：不打进日志、
不提交进仓库、不贴进 PR、不贴进聊天。

## 管理 API 与看板页面

插件注册了一个看板页面和三条数据接口。页面在 CPAMP 菜单里叫
**`Codex Turn-State`**。

| 路由 | 前缀 | 鉴权 |
|---|---|---|
| `/dashboard`（菜单项 `Codex Turn-State`） | `/v0/resource/plugins/codex-turn-state/dashboard` | **否** |
| `GET /codex-turn-state/status` | `/v0/management/` | 是 |
| `POST /codex-turn-state/buckets/clear` | `/v0/management/` | 是 |
| `POST /codex-turn-state/selftest` | `/v0/management/` | 是 |

密钥走 `X-Management-Key` 头或 `Authorization: Bearer`，**没有 cookie、也不接受
query 参数**（`handlers/management/handler.go:277-287`）。页面让用户手动粘密钥，
只存进 `sessionStorage`——关掉标签页就没了，不落盘、不进 URL。

### 为什么外壳页面不鉴权

浏览器地址栏导航**带不上** `Authorization` 头。所以任何需要用浏览器直接打开的
页面，都不能挂在鉴权路由下面，否则点开就是 401。

CPA 自己的 `/management.html` 就是这么处理的：`server_routes.go:54` 直接挂在
engine 上，没有套 `h.Middleware()`。

本插件照搬这个模式：外壳是**零数据**的 HTML + JS，本身不含任何桶、账号或令牌
信息；所有数据都由页面在浏览器里带着密钥去调上表那三条鉴权接口拿。外壳公开
可读，但读它什么也读不到。

### ⚠️ 两个路由注册脚枪：注册阶段静默出错，运行时才暴露

改路由注册的时候要绕开这两条。它们的共性是**注册的那一刻没有任何报错、没有任何
日志**，症状要等到真去请求时才出现，而且症状看起来都不像是注册的问题。

#### 一、数据路由绝对不能带 `Menu` 字段

CPA 的 `routeDeclaresLegacyMenuResource`（`internal/pluginhost/management.go:156`）
会把**带 `Menu` 字段的 GET 路由降级注册到不鉴权的 resource 前缀下**。

也就是说：给 `GET /codex-turn-state/status` 加一个 `Menu` 字段，它就从鉴权接口
变成**公开接口**了——桶的就绪情况、账号文件名全部公开可读。

规则：

- **只有**外壳路由带 `Menu`（它本来就该是公开的、且零数据）。
- 三条数据路由**一个都不许带 `Menu`**。

症状：不带密钥请求也能拿到数据（本该 401）。已有测试守着这一条，不要绕过它。

#### 二、`ResourceRoute.Path` 不能注册成 `"/"`

外壳路由的路径必须是**具名子路径**（本插件用 `/dashboard`），不能是插件根
`"/"`。`internal/pluginhost/management.go:212-214`：

```go
path = strings.TrimRight(path, "/")
if path == "" {
    return "", false
}
```

`"/"` 被 `TrimRight` 掉之后是空串，直接 `return false` —— **这条路由压根没被注册
进去**。

症状：请求 404。而且 404 看起来特别像分发出了 bug、或者路径拼错了，很容易往那个
方向查半天。实际上是注册阶段就被悄悄丢弃了，日志里一个字都没有。

所以外壳挂在：

```
/v0/resource/plugins/codex-turn-state/dashboard
```

不是 `/v0/resource/plugins/codex-turn-state/`（后者实测 404）。

### ⚠️ 「连通性自检」不会产生桶

`POST /codex-turn-state/selftest` 按钮**能打通上游、会消耗额度，但永远不产生
桶**。

原因是宿主的防递归设计：插件通过 `host.model.execute` 发出的请求，会被宿主标记
为**跳过调用方插件自己的拦截器**（`host_callbacks_unix.go:43` →
`host_callbacks.go:304` → `:306`）。插件自己发的请求不会再回到插件自己手里，
否则就无限套娃了。

后果是：自检请求的响应**不经过本插件的响应钩子**，所以采不到那个 292，也就写不
出桶文件。

**这个按钮的用途是把两类故障分开：**

| 自检结果 | 说明 |
|---|---|
| 通 | 账号可用、协议对、上游可达。问题在采集链路上 |
| 不通 | 账号或协议本身就有问题，先修这个，探测跑了也白跑 |

**真正的采集只有 `scripts/probe.py` 一条路。** 不要点着自检按钮等桶出现——
它永远不会出现。

### 自检可以定点到某个账号

自检接受一个**可选**的 `auth_id`，用来定点检查某个「账号 + 模型」组合：

```http
POST /v0/management/codex-turn-state/selftest
Content-Type: application/json

{"model": "gpt-5.6-sol", "auth_id": "codex-x.json"}
```

`auth_id` 不传就是「不指定，随调度器挑」。响应：

```json
{
  "reached": true,
  "status_code": 200,
  "model": "gpt-5.6-sol",
  "auth_id": "codex-x.json",
  "targeted": true,
  "harvested": false,
  "note": "...",
  "error": ""
}
```

定向能力来自 `pluginapi.HostModelExecutionRequest.AuthID`——注释写的是
*optionally locks execution to an exact credential ID*，
`internal/pluginhost/host_callbacks.go:330` 的 `modelExecutionRequestFromPlugin`
把它原样透传下去。

`targeted` 字段要单独说一下：**不传 `auth_id` 时，我们无法得知实际用了哪个号**
——`HostModelExecutionResponse` 里不含账号标识。所以 `targeted: false` 表达的是
「**我们没问、也问不出来**」，它和「调度器没选到号」是两回事，不要混为一谈。

`harvested` 恒为 `false`，原因见上一节。

### ⚠️ 不对称：能定向的采不到，能采到的不能定向

这条一定要看明白，否则会反复纠结「为什么自检不用停号，探测却非要停」。

| | 自检 `POST /selftest` | 采集 `scripts/probe.py` |
|---|---|---|
| 走哪条路 | 插件的 host 调用 `host.model.execute` | CPA 的**公开代理接口** |
| 能否指定账号 | **能**，有 `AuthID` 字段锁定凭据 | **不能**，那条路径没有这个字段 |
| 要不要停用其它号 | **不需要** | **需要**，只能靠停用别的号来定向 |
| 响应过不过本插件的钩子 | **不过**（宿主跳过调用方自己的拦截器） | **过**，所以采得到 |
| 能不能落桶 | 不能 | 能 |

两句话概括：

- **自检能定向，但采不到。** 它走的 host 调用会被宿主跳过本插件的响应拦截器
  （`host_callbacks_unix.go:43` → `host_callbacks.go:304` → `:306`），
  这和上一节自检不落盘是**同一个原因**。
- **采集能采到，但不能定向。** `probe.py` 走公开代理接口才能让响应经过本插件的
  钩子，而那条路径没有 `AuthID` 这种东西。

**所以采集不能改走插件的 host 调用来图省事**——改了就采不到任何东西了。

结论：规格第 7 节那句「CPA 调度只会选已启用的号，**不要假定能指定账号**」对
`probe.py` **仍然成立**。`probe.py` 里的账号启用状态**快照 + 恢复**机制是必需
的，不是冗余设计，不要因为「自检都能定向了」就把它删掉。

### 切 `role` 之后可能需要重启

能力声明（`response_interceptor` 等）是**注册时**上报的，而 `probe` 和
`business` 声明的能力集不一样。配置热重载不一定会重新协商能力。

所以切完 `role` 后，如果看板上的 `role` 没变、或者探测跑起来一个桶都不出，
**重启一次 `cli-proxy-api`**。页面上也有这条提示。

### 插件不能持久化自己的配置

宿主没有给插件提供保存配置的接口——`host.*` 系列方法里只有 `host.auth.save`，
没有对应的 config 保存。

所以页面上翻 `dry_run`、切 `role` 走的不是插件自己的接口，而是 CPA 原生的：

```
PATCH /v0/management/plugins/codex-turn-state/config
```

这是**浅合并**：只提交要改的键，没提交的键保持原值。

**改配置是热生效的，不需要重启**（2026-09-18 实测确认：`PATCH` 返回 200，插件
当场重新加载配置）。

别和 `.so` 搞混——**换 `.so` 必须重启**，插件不热加载 `.so`：

| 改什么 | 要不要重启 |
|---|---|
| 配置的键值（`dry_run`、`store_dir` 等） | **不要**，热生效 |
| `role` | 热生效，但能力集变了可能要重启，见上一节 |
| `.so` 文件本身 | **必须重启** |

## 构建

构建在一次性 Go 容器里跑，宿主只需要 Docker：

```bash
scripts/build.sh                      # -> build/linux/amd64/codex-turn-state.so
GO_IMAGE=golang:1.26 scripts/build.sh /custom/out
```

这是一个 cgo `c-shared` 库，走稳定的 C ABI + JSON 信封协议，**不是** Go
`plugin` 包的库。所以它**不需要**用和宿主二进制完全相同的 Go 工具链来编译。
必须对上的是 `pluginabi.ABIVersion`（1）和 `pluginabi.SchemaVersion`（6），
这两个来自 `go/go.mod` 里钉住的 `CLIProxyAPI/v7` 模块版本。

## 安装

插件 ID 是去掉扩展名的文件名，`-v<版本>` 后缀会被解析成版本号。产物要按这个
规则命名：

```bash
cp build/linux/amd64/codex-turn-state.so \
   <plugins-dir>/linux/amd64/codex-turn-state-v0.1.0.so
```

CPA **不会热加载**新增的 `.so`，进程必须重启插件才会出现。配置的热重载是另一
回事——改 `config.yaml` 里已加载插件的参数不需要重启。

部署步骤、停服窗口、验收清单见 [DEPLOY.md](DEPLOY.md)。

## License

MIT
