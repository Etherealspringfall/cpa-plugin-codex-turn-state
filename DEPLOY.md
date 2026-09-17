# 部署与执行清单

CPA Turn-State：探测 / 业务分离。

口径已经定死：**只换 312（`replace-only`）**；业务端不采头；探测先齐再开业务。

本文按规格第 9 节的步骤序编排。**第 0 步必须先做完，再动业务逻辑。**

---

## 开工前必读的三条

### ⚠️ 1. 第 8 步「停对外业务」是真实停服窗口，要提前挑时段

这不是一句形式化的提醒。已知的实测数据：

| 事项 | 实测 |
|---|---|
| CPA 容器本身重启 | 约 **2 秒** |
| sub2api 因此给账号 3 的冷却 | 约 **10 分钟** |
| 业务实际降级时长 | 约 **4 分钟** |

**再叠加探测本身的时间**：5 个账号 × 5 个模型 = **25 个桶**，每个桶至少要一次
成功的上游请求，还要算上账号切换和失败重试。

整个窗口 = 重启影响 + 25 桶探测。**开始之前先和用户确认时段**，不要自行开始。

### ⚠️ 2. `role` 缺失时默认 `business`

这是刻意的安全侧取值，也是为了解决步骤序里的一个矛盾：第 6 步先部署 `.so` 并
重启 CPA，第 7 步才把 `role: probe` 写进 config。如果把「`role` 缺失」也判为
非法而拒绝启动，第 6 步和第 7 步之间插件会注册失败。

所以：

- `role` **缺失** → 按 `business` 处理。此时若 `store_dir` 也没配，插件是纯
  no-op：不写盘、不采集、不改任何请求。
- `role` **非空但非法**（既不是 `probe` 也不是 `business`）→ 拒绝启动。

### ⚠️ 3. 插件目录必须是挂载出来的，不要退回容器可写层

插件如果装在容器可写层，**CPA 升级会把它冲掉**。本部署已经把 `./cpa-plugins`
挂载出来修掉了这个问题。后续任何调整都不要退回去。

---

## 第 0 步：先做这五件，再写业务逻辑

### 0.1 备份 `.so` 和 `config.yaml`

```bash
TS=$(date +%Y%m%d-%H%M)
cp /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so \
   /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so.bak-$TS
cp /home/dnc/cpamp-deploy/cpa-data/config.yaml \
   /home/dnc/cpamp-deploy/cpa-data/config.yaml.bak-$TS
ls -la /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/
```

### 0.2 建 store 目录，权限对

宿主侧路径 `/home/dnc/cpamp-deploy/cpa-data/turn-state-store/`，
容器内是 `/data/turn-state-store/`（`cpa-data` 已挂到容器 `/data`）。

```bash
mkdir -p /home/dnc/cpamp-deploy/cpa-data/turn-state-store
chmod 0700 /home/dnc/cpamp-deploy/cpa-data/turn-state-store
ls -ld /home/dnc/cpamp-deploy/cpa-data/turn-state-store
```

要求：目录 `0700`、文件 `0600`，**属主必须让 CPA 进程读写得到**。

```bash
docker exec cli-proxy-api id
docker exec cli-proxy-api ls -ld /data/turn-state-store
docker exec cli-proxy-api touch /data/turn-state-store/.wtest \
  && docker exec cli-proxy-api rm /data/turn-state-store/.wtest \
  && echo "CPA 可写 OK"
```

最后一条要真的通过再往下走。写不进去的话，后面探测会静默采不到东西。

#### ⚠️ 属主不对等：CPA 是 root，你不是

实测结果：

| | 值 |
|---|---|
| CPA 容器里的进程 | `uid=0(root)`（`docker exec cli-proxy-api id`） |
| 宿主上 `cpa-data` 的属主 | `dnc:dnc` |

所以**插件写出来的桶文件是 `root:root 0600`**——宿主上以普通用户身份跑的脚本
**读不了**它们。

这正是 `scripts/probe.py` 改成**走 `status` 接口拿就绪度、不再直接读文件**的
原因：探测脚本以普通用户跑，读不到 root 写的桶文件，只能问插件自己。这个设计不
是绕远路，是属主决定的。

需要在宿主上直接看文件时（降级手段），加 `sudo`：

```bash
sudo find /home/dnc/cpamp-deploy/cpa-data/turn-state-store -name '*.json' | sort
sudo cat /home/dnc/cpamp-deploy/cpa-data/turn-state-store/index.json
```

同源问题还有一处：`auths/` 下也有 root 属主的账号文件，普通用户清点会**静默漏
号**。见 0.4。**凡是清点 CPA 自己管理的状态，优先走接口。**

### 0.3 确认能编、产物能被容器加载

```bash
cd /home/dnc/cpa-plugin-codex-turn-state
gofmt -l go/                 # 无输出 = 格式化过了
bash scripts/build.sh        # -> build/linux/amd64/codex-turn-state.so
ls -la build/linux/amd64/
```

**宿主不需要装 Go。** `scripts/build.sh` 在一次性 `golang:1.26` 容器里编，宿主
只要有 Docker。实测编译耗时约 **2.5 秒**（模块缓存已暖）。

必须对上的是 `pluginabi.ABIVersion`（1）和 `pluginabi.SchemaVersion`（6），
来自 `go/go.mod` 里钉住的 `CLIProxyAPI/v7 v7.3.4`——和 CPA 镜像
`eceasy/cli-proxy-api:latest` 的版本要一致。

#### glibc 兼容性检查（每次都要做）

这是 cgo `c-shared` 产物，动态链接 glibc。编译镜像和运行镜像的 glibc 版本不是
一回事：

| | 发行版 | glibc |
|---|---|---|
| 编译用 `golang:1.26` | Debian 13 (trixie) | 2.41 |
| 运行用 CPA 容器 | Debian 12 (bookworm) | 2.36 |

**高版本 glibc 编出来的东西，在低版本上可能跑不起来。** 当前这一组合已经验证过
依赖解析干净、无 `version not found`，但**将来 Go 镜像基底再往上跳时这个前提会
失效**。

所以每次编完，都要**在和 CPA 完全相同的镜像里**验一次：

```bash
docker run --rm \
  -v /home/dnc/cpa-plugin-codex-turn-state/build/linux/amd64:/chk:ro \
  --entrypoint ldd \
  eceasy/cli-proxy-api:latest /chk/codex-turn-state.so
```

输出里每一行都要解析到具体路径。出现 `not found` 或
`version 'GLIBC_2.xx' not found` 就是不兼容，**不要部署**——换低版本 Go 镜像
重编（`GO_IMAGE=golang:1.25-bookworm scripts/build.sh`）。

这是唯一能在部署前发现这类问题的手段。真部署上去才发现的话，表现是 CPA 启动时
插件加载失败，而那时业务已经重启过了。

### 0.4 记下 5 个账号文件名

**用管理 API 查，不要 `ls` 读文件：**

```bash
curl -s -H "Authorization: Bearer $KEY" \
  http://127.0.0.1:8317/v0/management/auth-files
```

#### ⚠️ 为什么不能读文件

实测发现：`cpa-data/auths/` 下**有账号文件是 root 属主**——CPA 以 root 身份刷新
token 时把属主改掉了。宿主上以普通用户去读会 `PermissionError`。

坏就坏在它的**失败方式**：清点会少一个号，而且**不报错**，只是那一行读不出来。
很容易被当成「文件损坏」去查，实际上文件好好的，只是你没权限。

管理 API 不受属主影响，是**权威来源**。

这和 0.2 里 store 目录那个 root 属主问题**同源**：CPA 是 root，你不是。凡是要
清点 CPA 自己管理的状态，优先走接口，不要在宿主上读文件。

实在要读文件时加 `sudo`：

```bash
sudo ls /home/dnc/cpamp-deploy/cpa-data/auths/codex-*.json | grep -v '\.bak'
```

把查到的 5 个文件名填进下表。**只填文件名，不要写 token、不要贴文件内容。**

| # | 账号 JSON 文件名 | 探测完成 |
|---|---|---|
| 1 | `<部署时填入>` | ☐ |
| 2 | `<部署时填入>` | ☐ |
| 3 | `<部署时填入>` | ☐ |
| 4 | `<部署时填入>` | ☐ |
| 5 | `<部署时填入>` | ☐ |

这 5 个是 `auths/` 下现有的全部 Codex 账号。**实际这次要探几个号，见第 8 步
之前的确认要求**——不要默认就是 5 个。

### 0.5 验证看板页面可达

> **执行时机：第 6 步部署完新 `.so` 并重启 CPA 之后。** 页面是新 `.so` 带来
> 的，部署前它还不存在。列在第 0 步是为了不漏掉这项验收。

插件注册了一个看板页面和三条数据接口，详见 [README.md](README.md) 的
「管理 API 与看板页面」。

**先用命令行确认接口活着**（`X-Management-Key` 或 `Authorization: Bearer`，
没有 cookie、不接受 query 参数）：

```bash
# 外壳页面：不鉴权，应返回 HTML
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:8317/v0/resource/plugins/codex-turn-state/

# status：鉴权，不带密钥应 401
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:8317/v0/management/codex-turn-state/status

# status：带密钥应 200 + JSON
curl -s -H 'X-Management-Key: <管理密钥>' \
  http://127.0.0.1:8317/v0/management/codex-turn-state/status
```

三条的预期分别是 `200`、`401`、`200 + JSON`。**第二条必须是 401**——如果不带
密钥也能拿到数据，说明数据路由被降级成公开的了，参见 README 里
「数据路由绝对不能带 `Menu` 字段」那一节，立即停下来查路由注册。

**再用浏览器确认页面**：

CPA 只监听 `127.0.0.1:8317`，浏览器要访问得先开隧道：

```bash
ssh -N -L 8317:127.0.0.1:8317 ovh
```

然后在 CPAMP 菜单里找到 **`Codex Turn-State`**，点开，粘管理密钥，确认能拉到
status 数据（桶数、`role`、`dry_run` 当前值）。密钥只存 `sessionStorage`，
关标签页就没了，每次打开都要重新粘。

> ⚠️ 页面上的「连通性自检」按钮**能打通上游、会消耗额度，但永远不产生桶**——
> 宿主的防递归设计让插件自己发的请求不经过自己的响应钩子。它只能证明账号和
> 协议通不通。**真正的采集只有第 9 步的 `scripts/probe.py` 一条路**，不要点着
> 自检等桶出现。详见 README。

---

## 第 5~14 步

### 5. 改 `main.go` + 写测试，本地/容器里测过

规格第 8 节要求的 9 个测试，全部不连上游，用假的 292/312 字符串
（任意合法长度即可，**不要用生产日志里的真值**）：

1. 不同 `auth_id` 的 292 不能被另一号 substitute。
2. 同号 `gpt-5.6-sol` 的 292 不能套到 `gpt-6-astra`。
3. 分桶键不含 IP；两套不同 IP 元数据不影响命中。
4. `issued_at` 超过 3600s 的文件不加载、不替换。
5. 312 响应不得写入 store。
6. 业务请求自带 292 **不得**覆盖 store。
7. `replace-only`：无头或长度 ≠ 312 不改请求。
8. `dry_run: true` 时响应里 Headers 仍为空 / noop。
9. 写 store 后业务加载能读到同一桶。

```bash
cd /home/dnc/cpa-plugin-codex-turn-state
gofmt -l go/
cd go && go test ./... && cd ..
```

`gofmt` 和 `go test` 必须通过。**不要说「没跑编译」。**

### 6. 编 `.so`，备份旧文件，部署，重启/重载 CPA ⚠️ 影响线上

```bash
cd /home/dnc/cpa-plugin-codex-turn-state
bash scripts/build.sh

TS=$(date +%Y%m%d-%H%M)
cp /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so \
   /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so.bak-$TS

cp build/linux/amd64/codex-turn-state.so \
   /home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so

docker restart cli-proxy-api
docker logs cli-proxy-api --since 2m 2>&1 | grep -i codex-turn-state
```

**覆盖前一定先拷 `.bak-<时间戳>`。**

CPA 不热加载新的 `.so`，进程必须重启。日志里应当出现
`plugin loaded plugin_id=codex-turn-state`，以及一行 `configured …` 打出当前
`role` / `store_dir` / `inject_mode` / `dry_run`。

此时 config 里还没有 `role`，按第 2 条须知会落到 `business`，且 `store_dir`
未配 → 纯 no-op。这是预期状态。

**部署完这里就去做第 0.5 步**（验证看板页面可达 + 三条接口鉴权正确）。页面是
这个新 `.so` 带来的，到这一步才存在。

### 7. yaml 设 `role: probe`

改 `/home/dnc/cpamp-deploy/cpa-data/config.yaml` 的
`plugins.configs.codex-turn-state`，照
[`config.example.yaml`](config.example.yaml) 填。探测时段：

```yaml
      role: probe
      store_dir: /data/turn-state-store
      inject_mode: replace-only
      harvest_inband: false
```

`dry_run` 探测时段随意——探测端不做替换。

CPA 热重载配置，这步**不需要重启**。确认日志里 `configured` 那行的 `role` 已
经变成 `probe`：

```bash
docker logs cli-proxy-api --since 2m 2>&1 | grep -i "codex-turn-state.*configured"
```

> 如果热重载后 `role` 没变、或响应钩子没被调用，重启一次 `cli-proxy-api`
> 再看。能力声明是在注册时上报的。

### 8. 停对外业务，或停用全部 Codex 账号 ⚠️ 停服窗口

**开始前要和用户确认两件事，缺一不可：**

1. **时段**——参见开头第 1 条须知的时长估算。
2. **这次实际探几个号**。文档里的 25 个桶是按 5 号 × 5 模型的满配算的，
   但探测耗额度、也占停服窗口。**不要看到 25 这个数字就自行开跑。**
   确认下来只探 3 个号，那验收标准就是 15 个桶，并且第 10 步必须点名写清
   哪几个号没探、为什么。

两种做法二选一：停掉对外入口，或者在 CPA 里把全部 Codex 账号停用（探测脚本会
按账号逐个启用）。

理由：探测要精确知道每个 292 属于哪个账号。CPA 的调度只会在**已启用**的账号里
选，不要假定能在请求层面指定账号。

> **「自检不是能指定 `auth_id` 吗，为什么探测还要停号？」**
>
> 因为两条路不一样：自检走插件的 host 调用，有 `AuthID` 字段能锁定凭据，但那条
> 路的响应**会被宿主跳过本插件的拦截器**，所以采不到、不落桶。`probe.py` 必须
> 走公开代理接口才能让响应经过插件钩子，而那条路径**没有**指定账号的字段。
>
> **能定向的采不到，能采到的不能定向。** 详见 [README.md](README.md) 的
> 「⚠️ 不对称」一节。所以这一步的停号**不能省**。

### 9. 跑 `probe --until-complete`

```bash
cd /home/dnc/cpa-plugin-codex-turn-state
python3 scripts/probe.py --until-complete
```

行为要点：

- 外层按账号：每次只启用一个 Codex 账号。
- 内层按模型：对该号的 5 个模型各发一个最小官方请求，`model` 用清单里的官方
  id（带横线）。请求**不要**带旧的 `X-Codex-Turn-State`。
- 成功标准是「store 里出现该桶未过期的 292」，**不是 HTTP 200**。
- 该号 5 个模型齐了再换下一号。
- 全部目标桶都有未过期 292 才退出 0，否则非 0。

**探测会耗额度**：每个 `(账号, 模型)` 成功一次即可，不要和业务混打。

`gpt-5.6-luna` 在历史收割里可能没有，但清单里**仍必须探测**，缺了不准宣称
complete。

可选参数：`--account <json名>` 只探一个号，`--model <id>` 只探一个模型。

### 10. 人工检查 store：5×5

**首选走 `status` 接口**——桶文件是 `root:root 0600`，普通用户读不了（见
0.2）：

```bash
curl -s -H 'X-Management-Key: <管理密钥>' \
  http://127.0.0.1:8317/v0/management/codex-turn-state/status
```

或者直接在看板页面上看（第 0.5 步开的隧道）。

需要落到文件层面核对时，加 `sudo`：

```bash
sudo find /home/dnc/cpamp-deploy/cpa-data/turn-state-store -name '*.json' | sort
sudo cat /home/dnc/cpamp-deploy/cpa-data/turn-state-store/index.json
```

要确认：

- 25 个桶文件都在，按 `<账号>/<模型>.json` 分目录。
- `index.json` 里每个桶 `ready: true`，`expires_at` 都还没到。
- **没有任何 312 文件**。

**缺桶不要开业务。** 如果确实只启用了部分账号，把实际启用了哪些号、缺了谁写
进交付文档，不要含糊带过。

### 11. yaml 切 `role: business`，重载

```yaml
      role: business
      store_dir: /data/turn-state-store
      inject_mode: replace-only   # 已拍板，不要改成 always
      harvest_inband: false       # 业务必须 false
      dry_run: true               # 先 true
```

重载后看日志确认**装入了多少条**模板：

```bash
docker logs cli-proxy-api --since 2m 2>&1 | grep -i "codex-turn-state.*configured"
```

角色从 `probe` 切到 `business` 会清空探测期的内存态，只从 store 重新加载。
装入条数应该和第 10 步数出来的桶数对得上。

### 12. 启用业务账号，放下游，看 `substitute`

`dry_run: true` 状态下放真实流量进来。日志里应当出现 `substitute` 行，并且：

- `auth` 和 `model` 与请求实际使用的一致；
- 出发到上游的头**仍然是 312**（因为 dry-run 不真改）。

抓包或看请求日志确认第二点。这一步是在证明「逻辑对了但还没动手」。

### 13. 确认无跨号 / 跨模型后，`dry_run: false`

确认第 12 步的 `substitute` 行没有任何一条把 A 号的模板用到 B 号、或把甲模型的
模板用到乙模型之后：

```yaml
      dry_run: false
```

热重载，无需重启。从这一刻起插件真的开始改写线上请求。

**回滚**：把 `dry_run` 改回 `true` 即可，同样热重载生效。

### 14.（可选）cron 在过期前补采

模板 1 小时过期。过期桶业务会自动停止替换，直到新的 292 进盘——不会用旧值去
撞上游的 `could not be decrypted`。

如果要持续保温，让 cron 在过期前再跑一轮探测补采。注意这仍然会耗额度，并且
探测和业务不要同时打。

> **不要**改 `harvest.sh` 去写 store。`/home/dnc/turn-state-harvest/` 下的日志
> 扫描 tsv 可以留作**对照**，但**禁止当业务输入**。

---

## 验收清单

做完必须交证据，`value` 可以打码。

- [ ] `go test` / `gofmt` 通过，`.so` 时间戳已更新，CPA 日志
      `plugin loaded plugin_id=codex-turn-state`
- [ ] store 按 `(账号, 模型)` 分目录，无 312 文件
- [ ] 探测日志：只启用一个号时写入的 `auth_id` 就是该号
- [ ] 业务 `dry_run: true` 时有 `substitute`，抓包/请求日志出发头仍是 312
- [ ] `dry_run: false` 后同号同模型 312 变成 292
- [ ] 换模型不套用上一模型；换账号不套用上一号
- [ ] 过期文件不再替换
- [ ] 业务请求带 292 时 store 内容不变
- [ ] 无头请求不被强灌 292

以上 9 项是规格第 10 节的原文。以下是管理 API / 看板页面带来的补充项
（规格写定之后才加的功能）：

- [ ] `ldd` 在 CPA 同款镜像里检查 `.so`，依赖全部解析干净、无 `version not found`
- [ ] CPAMP 菜单里出现 `Codex Turn-State`，粘密钥后能拉到 status
- [ ] **不带密钥请求 `/v0/management/codex-turn-state/status` 返回 401**
      （返回 200 说明数据路由被降级成公开的了，立即停下来查 `Menu` 字段）

给同事的回执只需要：账号文件名、模型、长度、决定、时间。**不要贴 state。**

---

## 做完怎么回

用几行交清楚：

- 改了哪些文件
- `.so` 路径和时间
- `role` 当前值
- `dry_run` 当前值
- store 里就绪的 `(账号, 模型)` 个数
- 探测是否 `--until-complete` 成功
- 验收勾了哪些

缺的桶要**点名**（账号文件名 + 模型），不要贴 `value`。

---

## 明确不要动

- 不要改 CPA 官方源码/镜像来「抄近路」，用插件 + 脚本。
- 不要改另外 4 个请求头。
- 不要把 A 号日志里的值写入 B 号 store。
- 不要用 `captures.tsv` 灌业务。
- 不要把完整 Turn-State、管理密钥、token 写进 git、README、PR、聊天。
- 不要默认 `inject_mode: always`。
- 不要跳过第 0 步和编译。
