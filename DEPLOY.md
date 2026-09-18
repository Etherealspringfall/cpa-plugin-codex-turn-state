# 部署与运维

本文是**已上线系统**的运维手册：发新版、回滚、日常操作、排障。

> **旧版本的这份文档是「首次上线剧本」**，里面有一条现在会造成实际损失：
> 第 8 步「停对外业务，或停用全部 Codex 账号 ⚠️ 停服窗口」。
> **探测早已不需要停服、也不需要停任何账号**——它直连上游、自己握着 token，
> 归属天然精确。照旧文档操作会白停一次业务。整篇已按现状重写。

---

## 当前线上状态

| 项 | 值 |
|---|---|
| CPA 容器 | `cli-proxy-api`（**以 root 跑**） |
| 插件路径 | `/home/dnc/cpamp-deploy/cpa-plugins/linux/amd64/codex-turn-state-v0.1.0.so` |
| store | 容器内 `/data/turn-state-store`，宿主 `/home/dnc/cpamp-deploy/cpa-data/turn-state-store` |
| config | `/home/dnc/cpamp-deploy/cpa-data/config.yaml` |
| 角色 | `role=business`、`inject_mode=always`、`dry_run=false` |
| 看板 | CPAMP 菜单 `Codex Turn-State`，**全程免密钥** |

三条路径同时在跑：离线探测（主动）、业务顺带采集（免费）、业务替换。
架构说明见 [README.md](README.md)。

---

## 日常运维：全在看板上点

**不需要开终端，不需要输任何密钥。**

1. 打开 CPAMP 菜单里的 `Codex Turn-State`
2. **探测范围**：勾账号、勾模型（复选框，账号名里的客户邮箱已打码成 `620f5a42…pro`）
3. **代理池**：一行一个，明文显示、不用每次重填
4. 保存 → 点 **「探测」** 启动

### 代理格式

```
socks5://用户:密码@主机:端口
socks5h://…        ← 自动按 socks5 处理
http://…  https://…
```

**必须带 `scheme://`**（只写 `1.2.3.4:1080` 会被判非法）。密码里有 `@ : / #`
要转义（`%40` `%3A` `%2F` `%23`）。填错不会让插件挂掉，会被丢进 `config_errors`。

填完点 **「测试连通性」** 逐条验一遍再保存探测范围。它**不花额度**（请求不带凭据，
`401` 就是通），`403`/`429`/连不上分开报。留意汇总里的**出口地址数**：小于代理条数
就说明有几条共用同一个出口，等于花了钱没换到出口。它测的是**已保存**的池子，所以
顺序是「追加 → 保存范围 → 测试连通性」。

### 改了范围要不要重新点探测

不用。续期循环每 60 秒重读一次范围，新范围下一拍自动生效。
**新加的代理没有冷却记录，会被立刻尝试**，不用等 55 分钟。

想立刻全量重填就「取消」再「探测」。

### 「停止探测」会停掉什么

| | 停止后 |
|---|---|
| 主动探测 + 续期 | **停** |
| 被动采集（业务流量顺带采） | **不停**，照常工作 |
| 业务替换 | **不停**，继续用库存卡 |

代价是**没人续期**：卡到期后会过期 → 桶变空 → 被动采集重新接管（自愈，但有空窗）。

**CPA 重启会杀掉探测 goroutine**，重启后要去看板重新点一次「探测」。被动采集和
业务替换不受影响（它们是钩子，不是 goroutine）。

---

## 发新版 `.so`

### ⚠️ 服务器上那个 repo 是脏的，不要在它上面 git 操作

`/home/dnc/cpa-plugin-codex-turn-state` 停在旧提交、带一堆未提交改动和旧的
untracked 文件。**从 GitHub 新克隆到 `/tmp` 编译**，别碰它。

### 完整流程

```bash
set -e
BUILD=/tmp/cts-$(date +%H%M%S)
git clone -q https://github.com/arden-aaai/cpa-plugin-codex-turn-state.git $BUILD
cd $BUILD && git log -1 --format="HEAD: %h %s"
bash scripts/build.sh                      # -> build/linux/amd64/codex-turn-state.so

DIR=/home/dnc/cpamp-deploy/cpa-plugins/linux/amd64
LIVE=$DIR/codex-turn-state-v0.1.0.so

# 滚动备份：只留一个回滚点，否则这里会堆到上百 MB
rm -f $DIR/codex-turn-state-v0.1.0.so.bak-*
cp -p "$LIVE" "$LIVE.bak-$(date +%Y%m%d-%H%M)"

# 原子换：先 cp 到临时名，再 mv 覆盖
cp $BUILD/build/linux/amd64/codex-turn-state.so "$DIR/.cts.new"
mv -f "$DIR/.cts.new" "$LIVE"

docker restart cli-proxy-api && sleep 10
curl -s -o /dev/null -w "healthz: %{http_code}\n" http://127.0.0.1:8317/healthz

set +e                                     # ← 见下，清理失败不能中断部署
chmod -R u+rwX $BUILD 2>/dev/null; rm -rf $BUILD 2>/dev/null
```

#### 为什么用 `mv` 不用 `cp` 覆盖

同文件系统的 `mv` 是 rename，运行中的 CPA 继续持有旧 inode。直接 `cp` 盖一个
**正在被 mmap 的 `.so`** 有 SIGBUS 风险。

#### ⚠️ `set -e` + 清理 `/tmp` 会中断部署

Go 模块缓存是 **0444/0555 只读**的，`rm -rf` 会 `Permission denied`。在 `set -e`
下这会让脚本**直接退出**——踩过一次：第一条 `rm -rf` 失败，后面的编译和换文件
**一步都没执行**，而输出全是 rm 报错，看起来像只是清理失败。

两条防线：**用带时间戳的新目录**（不复用旧路径），**清理前 `set +e`**。

#### glibc 兼容性检查（每次都做）

这是 cgo `c-shared` 产物，动态链接 glibc。编译镜像和运行镜像不是一回事：

| | 发行版 | glibc |
|---|---|---|
| `golang:1.26` | Debian 13 trixie | 2.41 |
| CPA 容器 | Debian 12 bookworm | 2.36 |

**高版本编出来的在低版本上可能跑不起来。** 当前组合已验证干净，但 Go 镜像基底
再往上跳时这个前提会失效。

```bash
docker run --rm -v $BUILD/build/linux/amd64:/chk:ro \
  --entrypoint ldd eceasy/cli-proxy-api:latest /chk/codex-turn-state.so
```

出现 `not found` 或 `version 'GLIBC_2.xx' not found` 就**不要部署**，换
`GO_IMAGE=golang:1.25-bookworm` 重编。这是唯一能在部署前发现这类问题的手段——
真部署上去才发现的话，业务已经重启过了。

### 重启的代价

| 事项 | 实测 |
|---|---|
| CPA 容器重启 | 约 **2 秒** |
| sub2api 给账号的冷却 | 约 **10 分钟** |
| 业务实际降级 | 约 **4 分钟** |

`.so` **必须重启才生效**；配置键值是热加载的，不用重启。

### 重启后的两个正常现象

1. **探测不会自动启动**——要去看板点。
2. **短暂的 `auth=-`**：归属靠请求钩子记下的 `RequestID → 账号` 内存表，重启时
   清空，所以「请求在重启前、响应在重启后」的那批采集对不上账号。几秒后自愈，
   不用管。

### 部署后验证

```bash
RES=http://127.0.0.1:8317/v0/resource/plugins/codex-turn-state
curl -s -o /dev/null -w "healthz: %{http_code}\n" http://127.0.0.1:8317/healthz
curl -s "$RES/status"        | head -c 300      # 角色/配置是否保住
curl -s "$RES/ops/choices"   | head -c 300      # 新路由是否在（旧 .so 会 404）
curl -s "$RES/dashboard" | grep -c "fetchChoices"   # 看板是不是新版
```

看日志确认插件加载：

```bash
docker logs cli-proxy-api --since 2m 2>&1 | grep -i "codex-turn-state.*configured"
```

---

## 回滚

```bash
DIR=/home/dnc/cpamp-deploy/cpa-plugins/linux/amd64
LIVE=$DIR/codex-turn-state-v0.1.0.so
BAK=$(ls -1t $DIR/codex-turn-state-v0.1.0.so.bak-* | head -1)
cp "$BAK" "$DIR/.cts.rollback" && mv -f "$DIR/.cts.rollback" "$LIVE"
docker restart cli-proxy-api
```

只保留一个回滚点。任何历史版本都能从 git 在 30 秒内重编出来，不需要囤 `.bak`。

**更快的回滚**：如果问题出在行为而不是崩溃，先把 `dry_run` 翻成 `true`
（热生效、不用重启），插件立刻停止改写任何请求。

---

## 排障速查

| 症状 | 多半是 |
|---|---|
| 日志里 `auth=-`，采集不落盘 | 刚重启，`RequestID` 内存表空。等几秒自愈 |
| 探测点了没反应、转录只有一行 | 全部三元组在 55 分钟冷却里。加个新代理即可立刻重试 |
| 上游大量 `http=429` | 请求太密。检查是否退回了「无间隔连打整个代理池」 |
| 所有桶都是 312 | 上游账号级窗口关着。换 IP 无效，等窗口或换号 |
| 探测老是换不到好出口 | 点「测试连通性」。全 `403` = 出口被拒；出口地址数 < 代理条数 = 多条共用一个出口 |
| `/ops/choices` 404 | 跑的还是旧 `.so`，没重启或没换成功 |
| 看板能开但账号列表空 | `probe_management_key` 没配，或 CPA 401 |
| 日志打 `inject` 但上游收到的仍是 312 | CPA 升级动了请求头链路，见 README「升级 CPA 后必须回归这条链路」 |
| 宿主上 `ls` 桶文件 `PermissionError` | CPA 是 root、你不是。加 `sudo`，或走 status 接口 |

### 清点 CPA 的状态一律走接口，不要读文件

`auths/` 和 store 下都有 **root 属主**的文件。宿主上以普通用户读会
`PermissionError`，而且失败方式很坏：**清点会少一个号且不报错**，很容易当成
「文件损坏」去查。

```bash
# 权威来源
curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:8317/v0/management/auth-files

# 真要读文件
sudo find /home/dnc/cpamp-deploy/cpa-data/turn-state-store -name '*.json' | sort
```

管理密钥在 `~/cpamp-deploy/keeper.env`（`CPA_MANAGEMENT_KEY`）。
**别把密钥明文写进命令行**——会被内容分类器拦，走 env 文件是干净解法。

---

## 明确不要动

- 不要改 CPA 官方源码/镜像来「抄近路」，用插件。
- 不要动另外 4 个 `X-Codex-*` 请求头。
- 不要把 A 号的值写进 B 号的桶。
- 不要让**探测**去改 CPA 的任何状态（启用位、账号 `proxy_url`、全局 `proxy-url`）
  ——那条路径已经整个删掉了，不要重新引入。
- 不要重新引入「探测期只启用一个号」那套归属推断——离线探测握着 token，归属是
  确定的。
- 不要刷新账号 token。过期就跳过，等 CPA 自己刷。
- 不要把完整 Turn-State、管理密钥、token 写进 git、README、PR、聊天。
- 不要把插件装回容器可写层（CPA 升级会冲掉）。`./cpa-plugins` 挂载不能退回去。
- 不要在服务器那个脏 repo 上做 git 操作。

---

## 交付回执写什么

- `.so` 路径和时间戳、对应的 git 提交
- `role` / `inject_mode` / `dry_run` 当前值
- store 里就绪的 `(账号, 模型)` 个数
- 验证过哪几项

账号只写**文件名**，**不要贴 `value`、不要贴 token、不要贴带密码的代理 URL**。
