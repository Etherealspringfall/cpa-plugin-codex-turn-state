# cpa-plugin-codex-turn-state

CLIProxyAPI（CPA）原生插件。在单个 `(账号, 模型)` 桶内复用官方 Codex
`X-Codex-Turn-State`：采到正常态的 **292** 存库，业务请求发往上游前装上去，绕开
降级态 **312**。

插件从不伪造值，只读写 `X-Codex-Turn-State` 一个头。

令牌本身是什么（带签发时间戳的 Fernet）见 [FINDINGS.md](FINDINGS.md)，
部署与运维见 [DEPLOY.md](DEPLOY.md)。

## 四条硬规则（写死在代码里）

1. **绝不**跨账号复用。
2. **绝不**跨模型复用，同一账号内也不行。
3. 同账号同模型**可以跨 IP**。
4. `ttl_seconds`（默认 3600）**从令牌自带的 Fernet 时间戳起算**，不是从看到它的
   时刻起算。

第 4 条是硬墙：有效期签在令牌内部，过期的值上游直接拒绝
（`Encrypted content could not be decrypted`）。

## 架构

一个进程三件事，共用一个 store：

```
① 离线探测   插件 ──直连──> chatgpt.com          采 292 ─┐
             不经过 CPA、不改 CPA 任何状态               │
                                                         ├─> store
② 被动采集   业务流量 ─> CPA ─> 上游                     │
                          └─ 响应头里的 292 ─────────────┘
                                                         │
③ 业务替换   业务请求 ─> CPA ─> 读 store 装头 ─> 上游 <──┘
```

**① 离线探测**：读账号自己的 `access_token` 直连上游。因为握着 token，归属是确定
的——不停任何账号，所有账号可并行。三条铁律：**只读 CPA**（只有 auth-files 列表
和 download 两个 GET）、**绝不刷新 token**（刷新可能轮换 refresh token 顶掉 CPA
正在用的凭据；过期就跳过）、**只存 292**。

**② 被动采集**：桶空时请求不被装头，上游照常铸一个新 turn-state，插件在响应钩子
上免费读走。**零额度**，而且自限：

```
桶有卡 → ③ 装头 → 上游【不再铸】→ ② 自动哑掉（也不需要）
桶没卡 → ③ 放行 → 上游【会铸】  → ② 直接入库 ✅
```

从业务**请求**里采仍然禁止（来路不明），`harvest_inband` 对 business 强制 false。

**③ 业务替换**：只在 `request.intercept_after` 改写；先 `ClearHeaders` 再写值，
避免大小写不同出现两份；无卡/过期/键不全一律不动头。

> `role` 现在只决定**要不要替换**，不再决定能不能采。早期"两个角色不能同一进程
> 兼任"的限制来自旧的采集方式，已不存在。

## 两个代理池

**静态池 `probe_proxies`**：一条 URL = 一个固定 IP。
**轮换池 `probe_proxies_rotating`**：一条 URL = 一个住宅网关，**每次连接都换地址**。

分开不是写法问题，是**稀缺的东西不一样**：静态池稀缺的是那个 IP 的额度，轮换池
稀缺的是账号的容忍度（IP 用不完）。所以 312 之后该怎么办正好相反 ——

| | 静态池 | 轮换池 |
|---|---|---|
| 每个桶的机会 | 每条 URL 各 1 次（走池） | 同一条连试 **10 次**，轮流用池里各条 |
| 重拨同一条 | 同一个 IP，**没意义** | **新地址，真机会** |
| 冷却键 | `(出口, 账号, 模型)` | `(账号, 模型)`，与出口无关 |
| 成功后 | 55 分钟 | 55 分钟 |
| **失败后** | 55 分钟 | **10 分钟** |

**放错池子是静默的**：轮换代理放进静态池，每个桶 55 分钟只会被试一次，白白丢掉它
每次换 IP 的能力。看板的「测试连通性」会采两个样本当场核对，**只报能被证伪的那个
方向**（静态池里的一条给出两个地址 = 铁证；轮换池里一条两次同地址 = 不能说明什么，
不报）。

**顺序：静态池优先**。静态额度会过期（每 IP 每窗口 1 次，不用就没了），轮换池随时
能取，所以先花会过期的那份。两池都空才走本机直连——**只配了轮换池时不会直连**。

## 探测的节奏与限速

| 约束 | 值 | 作用 |
|---|---|---|
| 静态三元组冷却 | 55 分钟 | 同一 `(出口, 账号, 模型)` 最多 55 分钟一次 |
| 轮换池预算 | 10 次 / 10 分钟 | 每个 `(账号, 模型)` 一轮最多 10 次，失败歇 10 分钟 |
| 出口间隔 | 2 秒 | 两次上游调用之间隔开 |
| 同账号串行 | 1 | 一个账号同时只有一个请求在飞 |
| 429 退避 | 10 分钟 | 拿到 429/401/403 **中止**，整个账号退避 |

**312 和 429 不是一回事**：312 是「这个出口的 IP 被限」→ 换下一个出口是对的；
429 是「你请求太快了」（账号级）→ 换出口只会更糟。把非 200 一律当成换出口，实测
会在 4 秒内打出 60 发、单账号 7.5 发/秒，被上游回 21 个 429。

**冷却取 55 不取 60**：续期在 T+55min 触发，取 60 会挡掉自己的续期。

账号 `i` 从 `pool[i % N]` 开始走一圈。静态冷却键**含出口 URL**，所以新加的代理
**立刻可试**。

轮换池的上限是 `10 次/10 分钟/桶` ≈ 60 次/小时/桶，比静态池高得多 —— 这是刻意的，
因为每一次都是一个新地址。它**不提高瞬时速率**（串行 + 2 秒间隔照旧，那才是 429
的成因）。**没有递增退避**：账号级降级会一直回 312 而不是 429，这种情况下没有自动
刹车，只有 429 那条路径会踩停。

**续期只能靠主动探测**：桶一满上游就不再铸头，被动采集哑掉。停探测不影响被动采集
和业务替换，但会失去续期——卡过期后桶变空，被动采集重新接管（自愈，有空窗）。

## 分桶与 store

桶键 = `selected_auth_id`（账号 JSON **文件名**）+ 官方 `model`，用 `\x00` 拼接。
**不含 IP**（规则 3）。

```
<store_dir>/
  index.json            # ready / issued_at / expires_at，不放 value
  <账号JSON文件名>/
    <模型>.json          # auth_id model len value issued_at harvested_at attribution
```

`len != 292` 拒绝写入；原子写（临时文件 + `rename`）；同桶覆盖；目录 `0700`、
文件 `0600`。

当前目标模型（必须带横线）：`gpt-5.5` `gpt-5.6-sol` `gpt-5.6-terra` `gpt-6-astra`。

## 配置

| 键 | 默认 | 含义 |
|---|---|---|
| `role` | `business` | `business` = 做替换；`probe` = 不替换。**采集两种角色都开** |
| `store_dir` | `""` | store 目录，**容器内路径** |
| `template_length` / `replace_length` | 292 / 312 | 模板长度 / 降级态长度 |
| `ttl_seconds` | 3600 | 从令牌自己的 Fernet 时间戳起算 |
| `inject_mode` | `replace-only` | `always` = 每个请求都装（没有就加）。只接受这两个值 |
| `harvest_inband` | false | 从业务**请求**采。**business 强制 false** |
| `dry_run` | false | 照走照打日志但不真改头。**不影响采集** |
| `log_decisions` | true | 每个决定一行 |
| `models` / `probe_accounts` | `[]` | 探测范围 |
| `probe_proxies` / `probe_proxies_rotating` | `[]` | 静态出口池 / 轮换出口池，规则不同见上 |
| `probe_management_key` | `""` | **只读**用：拉账号清单 + 下载 token |
| `probe_base_url` | `127.0.0.1:8317` | CPA 管理接口地址 |

**本部署线上是 `inject_mode: always`**（操作员明确指示）。

`probe_accounts` / 两个代理池 **都不是白名单**：业务替换只看「桶里有没有未过期
的 292」。把账号从范围里去掉不会让它停止被替换，只是主动探测不再给它采。改这两项
**不会清空已有模板**（改 `template_length` / `replace_length` / `ttl_seconds` 才会）。

代理格式：`scheme://用户:密码@主机:端口`，scheme ∈ `socks5` `socks5h` `http`
`https`。**必须带 scheme**；密码里的 `@ : / #` 要转义。`socks5h` 会归一化成
`socks5`（`net/http` 不认前者）。

完整配置见 [`config.example.yaml`](config.example.yaml)。

## 看板

**全程免密钥**。CPAMP 菜单里叫 `Codex Turn-State`，路径 `/dashboard`。

勾账号、勾模型、填代理池 → 保存 → 点「探测」。改了范围不用重点，续期循环每 60 秒
重读一次。代理那一栏的「追加」只往清单末尾加（顺序 = 探测顺序），不会动已有的行。

**「测试连通性」**逐条测代理能不能到 OpenAI，**不花额度**：请求不带任何凭据，
上游回 `401` 就说明这条出口是通的。`403` = 出口被拒、`429` = 被限速、连不上 =
`不通`，三者分开报，因为去处完全不同。顺带显示每条的出口地址/国家/CF 机房，并**核对你把它放在哪个池子**
（静态池里的一条给出两个地址就标 ⚠）。**静态池**的出口地址数少于条数，说明好几条
其实共用一个出口——这是页面上唯一能看出这件事的地方；轮换池不算进这个数，它本来
就该每次都不一样。测的是**已保存**的池子，改完先保存。

免密钥路由（`/v0/resource/plugins/codex-turn-state/` 前缀，**GET-only**）：
`/dashboard` `/status` `/ops/choices`（只读免 confirm）、
`/ops/probe/start|cancel` `/ops/dry-run` `/ops/role` `/ops/clear` `/ops/selftest`
`/ops/scope` `/ops/proxy-check`（需 `confirm=1`）。唯一还带密钥的是
`GET /v0/management/codex-turn-state/config`。

探测范围存插件自己的 `probe-scope.json`（在 `store_dir`，**覆盖 config.yaml**），
因为宿主没给插件保存配置的接口。

## 日志

```
[codex-turn-state] harvest auth=<账号文件名> model=gpt-5.5 len=292 (template stored)
[codex-turn-state] inject  auth=<账号文件名> model=gpt-5.5 len=0   (added …)
[codex-turn-state] pass    auth=<账号文件名> model=gpt-6-astra len=312 (…)
```

`harvest` 入库 / `substitute` 312→292 / `inject` 给没头的装上 / `pass` 不动 /
`skip` 桶键不全。**值本身永远不进日志**，不进仓库、不贴 PR、不贴聊天。

## ⚠️ 改代码前必看的五个坑

1. **加进 `statusResponse` 的任何字段都是公开的**——`handleStatus` 同时服务匿名
   resource 路由和鉴权 management 路由，共用同一个结构体，不按路由过滤。
   `probe_proxies` 现在就是明文回传的（操作员要求，避免每次编辑都重打密码）。
2. **数据路由不能带 `Menu` 字段**——带了会被降级注册到**不鉴权**的 resource 前缀
   下（`internal/pluginhost/management.go:156`）。只有外壳路由该带。
3. **`ResourceRoute.Path` 不能是 `"/"`**——`TrimRight` 后是空串直接丢弃，
   **注册时无声、运行时 404**（`management.go:212`）。所以看板在 `/dashboard`。
4. **两个钩子拿的是两个不同的 metadata map**——请求侧
   （`handlers_interceptors.go:565`）有 `selected_auth_id`，响应侧（`:595`）
   **永远没有**。归属靠两边相同的 `RequestID` 接力（`:556`/`:584`）。
5. **账号名打码要先丢含 `@` 的段再取首尾**，否则邮箱在末段时会原样打出来。

### 升级 CPA 后必须回归请求头链路

插件写的头要经过 CPA 内部五步才落到发往上游的请求上，关键是
`codex_executor_request.go:281` 把插件改过的 headers 当成 `ginHeaders`，再由
`misc.EnsureHeader`（`header_utils.go:72`）**无条件覆盖**。

CPA 一旦动了这两处，业务端会**静默失效**：日志照常打 `inject`，上游收到的仍是
312。**升级后要看 CPA 请求日志实打实验一次。**

### 「连通性自检」不产生桶

插件通过 `host.model.execute` 发的请求会被宿主**跳过调用方自己的拦截器**，所以
自检采不到 292。它只用来区分「账号/协议不通」和「采集链路有问题」。

## 构建与安装

```bash
scripts/build.sh          # -> build/linux/amd64/codex-turn-state.so，宿主只需 Docker
```

cgo `c-shared` 库，走 C ABI + JSON 信封，**不是** Go `plugin` 包，所以不需要和宿主
相同的工具链。必须对上 `pluginabi.ABIVersion`（1）和 `SchemaVersion`（6）。

插件 ID 是去掉扩展名的文件名，`-v<版本>` 会被解析成版本号：

```bash
cp build/linux/amd64/codex-turn-state.so \
   <plugins-dir>/linux/amd64/codex-turn-state-v0.1.0.so
```

**换 `.so` 必须重启 CPA**（配置键值是热加载的，不用重启）。部署流程、回滚、排障见
[DEPLOY.md](DEPLOY.md)。

## License

MIT
