# cpa-plugin-codex-turn-state

A CLIProxyAPI (CPA) native plugin that reuses an official Codex
`X-Codex-Turn-State` value within a single `(account, model)` bucket.

## Rules

These are enforced in code and are not configurable:

1. A state value is never shared across accounts.
2. A state value is never shared across models.
3. Reuse inside one bucket is allowed regardless of client IP.
4. A harvested template expires after `ttl_seconds` (default 3600).

The plugin never fabricates a value. Substitution only ever uses a value that
was previously observed on a genuine request belonging to the same bucket.
The only header it reads or writes is `X-Codex-Turn-State`.

## How it works

The plugin registers the `request_interceptor` capability and acts on
`request.intercept_after`, which CPA calls after credential selection and
before executor translation. At that point both halves of the bucket key are
known:

| Part | Source |
|---|---|
| account | `Metadata["selected_auth_id"]` — the auth ID picked by the scheduler |
| model | `RequestInterceptRequest.Model` — the selected upstream model |

Per request:

| Observed value length | Action |
|---|---|
| `template_length` (292) | store as this bucket's template, reset TTL |
| `replace_length` (312) | overwrite with this bucket's template if one is live |
| anything else, or no header | pass through untouched |

If `selected_auth_id` or the model is missing, the request is left alone — an
incomplete key cannot be attributed to a bucket, and guessing would break
rules 1 and 2.

## Dependency: the account-level `$Header` placeholder

**The plugin alone is not enough.** CPA's HTTP path for `POST /v1/responses`
forwards a fixed allowlist of Codex headers upstream, and
`X-Codex-Turn-State` is not on it. The chain only completes if each Codex
account JSON under `auths/` carries the passthrough placeholder:

```json
"headers": {
  "X-Codex-Turn-State": "$X-Codex-Turn-State"
}
```

Full path of a substituted value:

```
plugin writes opts.Headers
  -> codex executor reads opts.Headers as ginHeaders
  -> util.ApplyCustomHeadersFromAttrs resolves $X-Codex-Turn-State
  -> header lands on the upstream request
```

Remove the placeholder and the plugin still runs and still logs, but nothing
it decides ever reaches the wire.

## Build

The build runs in a throwaway Go container, so the host only needs Docker:

```bash
scripts/build.sh                # -> build/linux/amd64/codex-turn-state.so
GO_IMAGE=golang:1.26 scripts/build.sh /custom/out
```

This is a cgo `c-shared` library talking the stable C ABI + JSON envelope
protocol, not a Go `plugin` package library. It therefore does **not** need to
be built with the exact Go toolchain that built the host binary. What must
match is `pluginabi.ABIVersion` (1) and `pluginabi.SchemaVersion` (6),
which come from the pinned `CLIProxyAPI/v7` module version in `go/go.mod`.

## Install

Plugin ID is the file name without extension, with an optional `-v<version>`
suffix parsed as the version. Name the artifact accordingly:

```bash
cp build/linux/amd64/codex-turn-state.so \
   <plugins-dir>/linux/amd64/codex-turn-state-v0.1.0.so
```

Then enable it in `config.yaml`:

```yaml
plugins:
  enabled: true
  configs:
    codex-turn-state:
      enabled: true
      priority: 100
      template_length: 292
      replace_length: 312
      ttl_seconds: 3600
      dry_run: true
      log_decisions: true
```

CPA does not hot-load a newly added `.so`; the process must be restarted
before the plugin appears.

## Config

| Key | Default | Meaning |
|---|---|---|
| `template_length` | 292 | value length harvested as a reusable template |
| `replace_length` | 312 | value length overwritten by a template |
| `ttl_seconds` | 3600 | how long a harvested template stays usable |
| `dry_run` | false | log decisions without rewriting the header |
| `log_decisions` | true | emit one line per harvest/substitute decision |

Changing any of these clears every bucket, so a template can never outlive the
rules it was harvested under.

Start with `dry_run: true`. It exercises the whole path — bucketing, TTL,
length matching — and reports what it *would* do, while leaving live traffic
untouched.

## Observability

Decisions go to the CPA process log, one line each:

```
[codex-turn-state] harvest auth=codex-<id>-<label>.json model=gpt-5.5 len=292 (template stored)
[codex-turn-state] substitute auth=codex-<id>-<label>.json model=gpt-5.5 len=312 (template age 4m12s)
[codex-turn-state] pass auth=codex-<id>-<label>.json model=gpt-5.6-terra len=312 (no template for bucket)
```

Only bucket identity, decision and **length** are logged. The state value is
credential-adjacent and is never written to the log.

## Verifying

With `dry_run: false`, on one account and one model:

- send a request carrying a `replace_length` value; the upstream request
  should carry the bucket's `template_length` value instead
- switch model: the previous model's template must not be applied
- switch account: nothing may be applied
- wait past `ttl_seconds`: substitution stops until a fresh template is
  harvested

## License

MIT
