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
| `models` | `[]` | 目标模型清单，用于完整性核对 |

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
