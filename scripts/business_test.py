#!/usr/bin/env python3
"""
business_test.py — mechanism verifier for the codex-turn-state BUSINESS side.

This is NOT a harvester. Real harvesting is always probe.py, which mints genuine
292s by hitting the upstream. This tool exists only to prove the *substitution*
path end to end — "business sees a 312, the plugin swaps in the stored 292" —
which is spec §9 steps 11-13. It does that with a SYNTHETIC 292 so it works even
when the upstream is throttled and no real 292 can be captured (the situation
right now: both Codex accounts return 312 / NO_MORE_RETRY).

Three modes:

  --seed    Write a synthetic 292 into the store for one (auth_id, model), so the
            business plugin has a template to substitute. Marked attribution=
            "synthetic" so it is unmistakable in dashboards and audits.

  --send    Fire one /v1/responses request carrying a 312-length
            X-Codex-Turn-State, then report the plugin's decision line. In
            replace-only mode the plugin keys on length alone, so a synthetic 312
            is enough to trigger a substitute.

  --unseed  Delete the synthetic bucket again.

⚠️  THE SEEDED 292 IS FAKE. With dry_run:false the business plugin will inject it
    upstream and the upstream will reject it (it is not a real token). So only
    seed when there is NO real customer traffic on the account, and ALWAYS
    --unseed when done. This tool refuses to pretend the data is real: the
    attribution field says "synthetic" and this banner prints on every seed.

ENVIRONMENT
  CPA_API_KEY   (required for --send)  Bearer token for /v1/responses. Same key
                probe.py uses. Never written to disk or printed.

Token values are credential-adjacent and are never printed: the synthetic value
is written only to the store file, and plugin log lines are passed through
redact() before display.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

# CPA is on loopback; bypass any proxy in the environment, exactly as probe.py
# does, so these calls are not swallowed and turned into bogus 502s.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

HOME = Path(os.path.expanduser("~"))

DEFAULT_BASE_URL = "http://127.0.0.1:8317"
DEFAULT_STORE_DIR = HOME / "cpamp-deploy" / "cpa-data" / "turn-state-store"
DEFAULT_CONTAINER = "cli-proxy-api"

TEMPLATE_LEN = 292   # normal serving state — the length the plugin treats as a template
REPLACE_LEN = 312    # throttled/degraded state — the length replace-only rewrites
TTL_SECONDS = 3600   # matches the plugin's ttl_seconds; only used to fill expires_at

# Decoded byte counts that base64url-encode to exactly the two lengths, matching
# the real token structure from FINDINGS.md (292 chars = 217 bytes ending "==",
# 312 chars = 233 bytes ending "="). Encoding is verified at call time regardless.
_BYTES_FOR_LEN = {TEMPLATE_LEN: 217, REPLACE_LEN: 233}

TURN_STATE_HEADER = "X-Codex-Turn-State"
LOG_PREFIX = "[business-test]"

# Decision keywords the plugin emits, per go/main.go's logDecision.
_DECISIONS = ("substitute", "inject", "harvest", "pass", "skip")


def log(msg: str) -> None:
    print(f"{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {LOG_PREFIX} {msg}", flush=True)


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"{LOG_PREFIX} error: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(code)


# ----------------------------------------------------------------------------
# Redaction. A Fernet token base64url-encodes a leading 0x80 version byte, which
# always renders as the literal prefix "gAAAAA"; that makes any turn-state value
# greppable without decoding. Keys and bearer tokens are stripped too.
# ----------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"gAAAAA[A-Za-z0-9_\-=]{16,}")
_APIKEY_RE = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}")


def redact(text: str) -> str:
    text = _TOKEN_RE.sub("<turn-state redacted>", text)
    text = _APIKEY_RE.sub("<api-key redacted>", text)
    text = _BEARER_RE.sub(r"\1<redacted>", text)
    return text


# ----------------------------------------------------------------------------
# Time helpers.
# ----------------------------------------------------------------------------

def rfc3339(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


# ----------------------------------------------------------------------------
# Synthetic token construction.
#
# The value must be EXACTLY `target_len` base64url characters, because the plugin
# keys entirely on string length (len(value) == template_length / replace_length)
# and, for the stored 292, would ship a malformed token upstream if the length
# were off by a padding character. So we build the real Fernet byte layout —
# 0x80 version byte + 8-byte big-endian issuance timestamp + filler — to the byte
# count that is known to encode to that length, then assert the encoded length
# before returning. A mismatch is a hard failure, never a silently wrong token.
# ----------------------------------------------------------------------------

def make_synthetic_token(target_len: int, issued_unix: int) -> str:
    if target_len not in _BYTES_FOR_LEN:
        die(f"no known byte count for a {target_len}-char token "
            f"(supported: {sorted(_BYTES_FOR_LEN)})")
    n_bytes = _BYTES_FOR_LEN[target_len]
    # 0x80 version + 8-byte timestamp so the token decodes to a real issuance
    # time (set to `issued_unix`); the rest is filler with a recognizable marker.
    prefix = bytes([0x80]) + struct.pack(">Q", issued_unix)
    filler = (b"SYNTHETIC-CODEX-TURN-STATE-DO-NOT-SHIP-"
              * ((n_bytes // 39) + 1))[: n_bytes - len(prefix)]
    raw = prefix + filler
    token = base64.urlsafe_b64encode(raw).decode("ascii")
    if len(token) != target_len:
        die(f"internal error: built a {len(token)}-char token, wanted {target_len}")
    return token


# ----------------------------------------------------------------------------
# Store I/O. Bucket file format is spec §4:
#   <store_dir>/<auth_id>/<model>.json
#   {auth_id, model, len, value, issued_at, harvested_at, attribution}
# index.json is a value-free summary the plugin/dashboards read.
#
# Writes are atomic (temp file + os.replace) and 0600, matching the plugin. In
# this deployment the store dir is dnc-owned, so dnc can create the per-auth
# subdir and file; the plugin runs as root and can still read them.
# ----------------------------------------------------------------------------

def _atomic_write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    old_umask = os.umask(0o077)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        os.umask(old_umask)


def bucket_path(store_dir: Path, auth_id: str, model: str) -> Path:
    return store_dir / auth_id / f"{model}.json"


def index_path(store_dir: Path) -> Path:
    return store_dir / "index.json"


def update_index(store_dir: Path, auth_id: str, model: str,
                 issued: int, remove: bool = False) -> None:
    """Upsert or drop this bucket in index.json. Best-effort: a summary file the
    plugin may own means we cannot always write it, and the per-bucket file is
    what actually drives substitution, so a failure here only warns."""
    path = index_path(store_dir)
    doc: dict = {"version": 1, "buckets": []}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("buckets"), list):
                doc = loaded
        except Exception as exc:
            log(f"index.json unreadable ({exc}); rewriting a fresh one")

    buckets = [b for b in doc.get("buckets", [])
               if not (b.get("auth_id") == auth_id and b.get("model") == model)]
    if not remove:
        buckets.append({
            "auth_id": auth_id,
            "model": model,
            "ready": True,
            "issued_at": rfc3339(issued),
            "expires_at": rfc3339(issued + TTL_SECONDS),
            "attribution": "synthetic",
        })
    doc["buckets"] = buckets
    doc["generated_at"] = rfc3339(int(time.time()))
    try:
        _atomic_write_json(path, doc)
    except PermissionError:
        log(f"note: cannot write {path} (likely root-owned); skipping index "
            f"update. The bucket file is what the plugin substitutes from, so "
            f"this does not affect the test.")


def seed(store_dir: Path, auth_id: str, model: str) -> int:
    now = int(time.time())
    token = make_synthetic_token(TEMPLATE_LEN, now)
    path = bucket_path(store_dir, auth_id, model)
    doc = {
        "auth_id": auth_id,
        "model": model,
        "len": TEMPLATE_LEN,
        "value": token,
        "issued_at": rfc3339(now),
        "harvested_at": rfc3339(now),
        # Not "observed" / "inferred": this must be recognizable as fake data.
        "attribution": "synthetic",
    }
    try:
        _atomic_write_json(path, doc)
    except PermissionError:
        die(f"cannot write {path}: permission denied.\n"
            f"  The per-auth subdir may already exist as root (created by the\n"
            f"  plugin). Remove it first, or seed under an auth_id the plugin\n"
            f"  has not written yet.")
    update_index(store_dir, auth_id, model, now)
    log("=" * 70)
    log("SEEDED A SYNTHETIC 292 -- THIS IS FAKE TEST DATA.")
    log(f"  bucket   {path}")
    log(f"  auth_id  {auth_id}")
    log(f"  model    {model}")
    log(f"  len      {TEMPLATE_LEN}  attribution=synthetic  fresh (issued now)")
    log("  With dry_run:false the plugin WILL inject this upstream and it WILL")
    log("  be rejected -- only seed with no real traffic, and --unseed when done.")
    log("=" * 70)
    return 0


def unseed(store_dir: Path, auth_id: str, model: str) -> int:
    path = bucket_path(store_dir, auth_id, model)
    removed = False
    try:
        path.unlink()
        removed = True
    except FileNotFoundError:
        log(f"no bucket file at {path} (already gone)")
    except PermissionError:
        die(f"cannot delete {path}: permission denied (root-owned?).")
    # Drop the now-empty per-auth dir if we can; harmless if it is not empty.
    try:
        path.parent.rmdir()
    except OSError:
        pass
    update_index(store_dir, auth_id, model, 0, remove=True)
    if removed:
        log(f"removed synthetic bucket auth={auth_id} model={model}")
    return 0


def peek_bucket_len(store_dir: Path, auth_id: str, model: str) -> int | None:
    """Return the stored template's len, or None if absent/unreadable. Used only
    to warn before --send that a template exists; never reads the value."""
    path = bucket_path(store_dir, auth_id, model)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (PermissionError, Exception):
        return None
    return int(doc.get("len") or 0)


# ----------------------------------------------------------------------------
# HTTP — one request, minimal, mirrors probe.py's mint request plus the header.
# ----------------------------------------------------------------------------

def send_312(base_url: str, api_key: str, model: str, http_timeout: int) -> tuple[int, str]:
    """POST /v1/responses carrying a 312-length X-Codex-Turn-State.

    The request body is identical to probe.py's mint request (the shape already
    confirmed to reach the upstream). The extra header is a synthetic 312; in
    replace-only mode the plugin decides on length alone, so its content is
    irrelevant and it is stripped/replaced before the request leaves CPA.
    """
    token_312 = make_synthetic_token(REPLACE_LEN, int(time.time()))
    payload = {
        "model": model,
        "input": "ping",
        "stream": False,
        "max_output_tokens": 16,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        TURN_STATE_HEADER: token_312,
    }
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/responses", data=data, headers=headers, method="POST")
    try:
        with _OPENER.open(request, timeout=http_timeout) as response:
            body = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read() or b""
        status = exc.code
    except urllib.error.URLError as exc:
        return 0, f"connection error: {exc.reason}"

    if 200 <= status < 300:
        return status, "ok"
    text = redact(body.decode("utf-8", errors="replace").strip())
    if len(text) > 600:
        text = text[:600] + f" ...[+{len(text) - 600} chars]"
    return status, text or "(empty body)"


# ----------------------------------------------------------------------------
# Plugin decisions from container logs.
# ----------------------------------------------------------------------------

def read_decisions(container: str, since_seconds: int) -> list[str]:
    """Return redacted plugin decision lines from the last `since_seconds`.

    docker logs writes to both stdout and stderr depending on the driver, so
    both are scanned. Nothing here parses the token; lines are redacted anyway.
    """
    try:
        result = subprocess.run(
            ["docker", "logs", container, "--since", f"{since_seconds}s"],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        die("docker not found on PATH; run this on the CPA host")
    except subprocess.TimeoutExpired:
        die(f"`docker logs {container}` timed out")

    combined = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 and not combined.strip():
        die(f"`docker logs {container}` failed (exit {result.returncode}); "
            f"is the container name right?")

    out = []
    for line in combined.splitlines():
        if "codex-turn-state" not in line:
            continue
        if not any(d in line for d in _DECISIONS):
            continue
        out.append(redact(line).rstrip())
    return out


# ----------------------------------------------------------------------------
# CLI.
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="business_test.py",
        description="Verify the business-side 312->292 substitution with a "
                    "synthetic template. Mechanism check only; real harvesting "
                    "is probe.py.",
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--seed", action="store_true",
                      help="write a synthetic 292 into the store for --auth-id/--model")
    mode.add_argument("--send", action="store_true",
                      help="send one request with a 312 header and report the "
                           "plugin's decision")
    mode.add_argument("--unseed", action="store_true",
                      help="delete the synthetic bucket for --auth-id/--model")

    p.add_argument("--model", required=True, help="model id, e.g. gpt-5.6-sol")
    p.add_argument("--auth-id",
                   help="auth file name, e.g. codex-foo.json "
                        "(required for --seed/--unseed; optional label for --send)")
    p.add_argument("--store-dir", default=str(DEFAULT_STORE_DIR),
                   help=f"host path of the plugin's store_dir (default: {DEFAULT_STORE_DIR})")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL,
                   help=f"CPA base URL (default: {DEFAULT_BASE_URL})")
    p.add_argument("--container", default=DEFAULT_CONTAINER,
                   help=f"CPA container name for docker logs (default: {DEFAULT_CONTAINER})")
    p.add_argument("--since", type=int, default=60,
                   help="seconds of container log to scan for the decision (default 60)")
    p.add_argument("--http-timeout", type=int, default=120,
                   help="seconds to wait on the upstream request (default 120)")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    store_dir = Path(args.store_dir)

    if args.seed or args.unseed:
        if not args.auth_id:
            die("--auth-id is required for --seed/--unseed")
        if args.seed:
            return seed(store_dir, args.auth_id, args.model)
        return unseed(store_dir, args.auth_id, args.model)

    # --send
    api_key = os.environ.get("CPA_API_KEY", "").strip()
    if not api_key:
        die("CPA_API_KEY is not set (needed to send /v1/responses).")

    # Warn if there is no template to substitute — without one the plugin will
    # `pass`, not `substitute`, and the test would look like a failure when the
    # real cause is a missing seed. Only checks when an auth_id is given and the
    # bucket file is readable by this user.
    if args.auth_id:
        stored = peek_bucket_len(store_dir, args.auth_id, args.model)
        if stored is None:
            log(f"note: no readable synthetic template at "
                f"{bucket_path(store_dir, args.auth_id, args.model)} — if none is "
                f"seeded, expect `pass`, not `substitute`. (--seed first.)")
        elif stored != TEMPLATE_LEN:
            log(f"note: seeded template len={stored}, expected {TEMPLATE_LEN}")

    log(f"sending /v1/responses model={args.model} with a {REPLACE_LEN}-char "
        f"{TURN_STATE_HEADER}")
    t0 = time.time()
    status, note = send_312(args.base_url, api_key, args.model, args.http_timeout)
    if status and 200 <= status < 300:
        log(f"http={status}")
    else:
        log(f"http={status} body={note}")

    # Give CPA a moment to flush the decision line, then read a window that is at
    # least as wide as the request took plus a margin.
    time.sleep(1.5)
    window = max(args.since, int(time.time() - t0) + 5)
    decisions = read_decisions(args.container, window)
    if not decisions:
        log(f"no codex-turn-state decision line in the last {window}s. Check the "
            f"plugin is loaded (docker logs {args.container} | grep 'plugin "
            f"loaded') and that log_decisions is true.")
        return 1

    log(f"plugin decision line(s) in the last {window}s:")
    for line in decisions:
        print(f"    {line}", flush=True)

    substituted = any("substitute" in d for d in decisions)
    if substituted:
        log("saw `substitute` -- the plugin swapped the 312 for the stored 292. "
            "With dry_run:true the upstream still received the 312; with "
            "dry_run:false it received the synthetic 292 (and will reject it).")
    else:
        log("did NOT see `substitute`. Likely causes: no template seeded for "
            "this bucket, dry-run decision logged as a different label, or the "
            "request landed on a different (auth_id, model).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
