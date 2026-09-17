# Findings: what `X-Codex-Turn-State` is and why reuse works

This documents what the plugin is actually manipulating. No token values, keys,
account identifiers, or infrastructure details appear here — only the structure
and the observable behaviour.

## The reuse rules (the spec this plugin enforces)

1. A `state` value **cannot** be reused across accounts.
2. A `state` value **cannot** be reused across models, even within one account.
3. A `state` value for the **same account + same model can be reused across IPs**.
4. A `state` value is valid for **1 hour**.

The plugin keys every template on `(account, model)` and never crosses either
boundary, which is exactly rules 1–3. Rule 4 is the token's own lifetime — see
below.

## `X-Codex-Turn-State` is a Fernet token

The value is a Fernet token, base64url-encoded:

```
0x80  (1 byte, version)
ts    (8 bytes, big-endian Unix seconds — issuance time)
IV    (16 bytes)
ciphertext (AES-CBC, multiple of 16 bytes)
HMAC  (32 bytes)
```

Every observed value begins with the `0x80` version byte (`gAAAAA…` once
base64url-encoded). The 8-byte timestamp is the token's **issuance time**, and
it can be read without any key:

```python
import base64, struct
from datetime import datetime, timezone

def issued_at(token: str):
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    version = raw[0]                          # 0x80
    ts = struct.unpack(">Q", raw[1:9])[0]     # issuance time, Unix seconds
    return version, datetime.fromtimestamp(ts, timezone.utc)
```

Observed: the embedded timestamp equals the moment the value first appears on a
response, to the second. Tokens are **issued fresh per turn**, not recycled — so
every captured value starts its 1-hour clock the instant it is minted. This is
why rule 4 is a hard wall: the expiry is signed into the token, and a stale
value is rejected upstream rather than silently ignored.

## Two lengths, and what the difference is

| State | base64 chars | decoded bytes |
|---|---:|---:|
| normal | 292 | 217 |
| throttled | 312 | 233 |

The difference is **exactly 16 bytes — one AES-CBC block**. The longer value is
not a different kind of token; it is the same structure carrying one extra
encrypted block. In practice:

- **292 (217 bytes)** corresponds to the normal serving state.
- **312 (233 bytes)** corresponds to the throttled/degraded serving state.

Because the extra content is inside the ciphertext, the state is invisible from
outside except through this length tell — which is what makes the 16-byte
difference a reliable, byte-exact indicator rather than a guess.

## Behaviour notes

- A request that lands in the degraded path commonly surfaces as
  `server_is_overloaded`. Treat that error together with a 312-length state as
  one signal, not two independent ones.
- `Encrypted content could not be decrypted` appears when a token is replayed
  after its window, or mid-rotation. This is the failure mode a naïve
  "inject any captured value" approach hits — and the reason expiry must be
  keyed on the token's own timestamp, not on when the proxy happened to see it.

## What the plugin does with this

`request.intercept_after` sees the value a genuine Codex client echoes back on a
follow-up turn. When that value is a 292 the plugin stores it for the bucket;
when it is a 312 the plugin overwrites it with the bucket's live 292 before the
request goes upstream. Expiry is computed from the token's embedded Fernet
timestamp (`fernetIssuedAt` in `go/main.go`), so a template harvested late in
its life is not mistaken for a fresh one.

The plugin can only **prolong** a state it has already observed on a real
request for that bucket; it never fabricates a value and never crosses the
account or model boundary.
