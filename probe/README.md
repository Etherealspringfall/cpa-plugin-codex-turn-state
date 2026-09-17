# harvest_probe — the 拿头端 (header-harvesting side)

> ## ⚠️ 已废弃，不要运行 —— 请用 `scripts/probe.py`
>
> 这份探测器是**旧架构**的，和当前插件不兼容。留档仅为参考它对 Fernet 时间戳
> 和 honeymoon 的处理思路，**不要执行**。三处硬冲突：
>
> | | 本目录（旧） | `scripts/probe.py`（现行） |
> |---|---|---|
> | store 格式 | 单文件 `turn-state-store.json`，键 `<auth_id>::<model>` | 目录 `turn-state-store/<auth_id>/<model>.json` + `index.json` |
> | 采集来源 | 扫 CPA 的**请求日志** | 插件从**上游响应头**采（`response.intercept_after`） |
> | 模型清单 | 故意排除 `gpt-5.5` | 五个全探，`gpt-5.5` 包含在内（已由用户拍板） |
>
> 跑它的后果是**静默失败**：会烧额度，写出的文件当前插件根本不读，而日志上
> 看不出异常。排障时如果发现 store 目录空但存在一个 `turn-state-store.json`
> 文件，多半就是有人跑了这个。

The plugin (business side) can only *reuse* a normal-state `X-Codex-Turn-State`
it already has. Something has to *mint* fresh ones, per `(account, model)`,
before their 1-hour clock runs out. That is this probe.

It is deliberately separate from business traffic: business requests never fire
harvesting requests, they only consume what the probe has already stored.

```
harvest_probe.py  --fire codex-->  CPA  --logs-->  turn-state-store.json
     (拿头端)                                              |
                                                          v
business traffic  --------------------------->  codex-turn-state plugin (reads store, injects)
```

## What one round does

For each model that has no live template (or one about to expire):

1. `rotate_exit_ip()` — point the account at a fresh exit IP (the honeymoon).
   *No-op until the residential proxy pool is wired in; see the TODO in the code.*
2. Fire a minimal `codex exec -m <model> harvest`.
3. Watch CPA's request log; the moment the upstream turn-state appears, **kill
   codex** — only the header is needed, not a full completion.
4. If the token is normal-state (`length == 292`), decode its Fernet issuance
   time and write `<auth_id>::<model>` into the store. A `312` means this exit
   is not in a honeymoon; the bucket is left for the next round / next IP.

The token value is written only to the store (0600) and never printed. Logs show
lengths, models, and decisions only.

## Run it (on the probe host, e.g. OVH)

```bash
# one sweep, to check it works
python3 probe/harvest_probe.py --once

# probe-first phase: fill every target bucket, then exit ("先做完再开业务")
python3 probe/harvest_probe.py --until-complete

# ongoing: keep every bucket warm (1h expiry means it must keep refreshing)
python3 probe/harvest_probe.py
```

The intended sequence is: run `--until-complete` first so every `(account,
model)` bucket holds a fresh 292, **then** open the business side (enable
injection). After that, run it continuously to keep buckets from expiring.

### Multiple accounts

CPA's scheduler picks whichever account is enabled; you cannot tell codex to use
a specific one. To probe account by account, enable one account at a time in CPA
(disable the others), let the probe fill that account's models, then switch to
the next. With a single enabled account the probe simply fills that account's
buckets. `--until-complete` treats "complete" as every model in `PROBE_MODELS`
having at least one live template.

Or as a background service (survives logout):

```bash
nohup python3 ~/cpa-plugin-codex-turn-state/probe/harvest_probe.py \
  >> ~/turn-state-harvest/probe.log 2>&1 &
```

## Configuration (environment)

| Var | Default | Meaning |
|---|---|---|
| `PROBE_MODELS` | `gpt-5.6-luna,gpt-5.6-terra,gpt-5.6-sol,gpt-6-astra` | models to keep warm (gpt-5.5 excluded on purpose) |
| `PROBE_STORE_PATH` | `~/cpamp-deploy/cpa-data/turn-state-store.json` | store file (host path; container sees `/data/turn-state-store.json`) |
| `PROBE_LOGS_DIR` | `~/cpamp-deploy/cpa-data/auths/logs` | CPA request logs |
| `PROBE_CODEX_BIN` | `~/.local/bin/codex` | codex CLI |
| `PROBE_TTL_SECONDS` | `3600` | token lifetime — keep equal to the plugin's `ttl_seconds` |
| `PROBE_REFRESH_BEFORE` | `600` | refresh a bucket when under this many seconds remain |
| `PROBE_ATTEMPT_TIMEOUT` | `60` | seconds to wait for one codex attempt's turn-state |
| `PROBE_SWEEP_INTERVAL` | `60` | seconds between full sweeps |

## Requirements

- CPA request logging must be on (`request-log: true`, `commercial-mode: false`),
  otherwise the upstream turn-state is not recorded and the probe has nothing to
  read.
- `codex` configured to route through CPA with `CPA_API_KEY` available (the probe
  loads it from `~/.codex/cpa.env` if not already in the environment).
- The store key the probe writes (`<auth_id>::<model>`) is exactly what the
  plugin computes from `selected_auth_id` + model, so they line up with no extra
  configuration.
