#!/usr/bin/env python3
"""
harvest_probe.py — the 拿头端 (header-harvesting side).

This is the counterpart to the codex-turn-state CPA plugin. Its only job is to
keep a fresh, normal-state X-Codex-Turn-State (a "292") on hand for every
(account, model) bucket, and write it into a JSON store that the plugin reads.

Why a separate process, not the plugin:
  The plugin is a passive request interceptor — it can only rewrite requests
  that flow through it. It cannot originate traffic. Minting a fresh normal-state
  token requires actually issuing a request (ideally from a fresh exit IP, in
  the "honeymoon" window), so that is done here, out of band, and the business
  traffic never pays for harvesting.

How it works, per bucket that needs a refresh:
  1. (optional) rotate the account's exit IP to a fresh one from the proxy pool.
  2. fire a minimal `codex exec` for the target model.
  3. as soon as the upstream response turn-state shows up in CPA's request log,
     kill codex — we only need the header, not a full completion.
  4. if that token is a normal-state one (length == TEMPLATE_LEN), decode its
     Fernet issuance time and write it to the store as <auth_id>::<model>.
     A degraded-state token (REPLACE_LEN) means this IP is not in a honeymoon;
     the bucket is left for the next round / next IP.

The token value is credential-adjacent: it is written only to the store file
(0600) and never printed. Logs carry lengths, models, and decisions only.

No secrets, keys, or account emails are hard-coded here.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# ----------------------------------------------------------------------------
# Configuration (override via environment).
# ----------------------------------------------------------------------------

HOME = Path(os.path.expanduser("~"))

# Models to keep a live template for. gpt-5.5 is intentionally excluded: its
# value is not usable per the operator's rules.
MODELS = os.environ.get(
    "PROBE_MODELS",
    "gpt-5.6-luna,gpt-5.6-terra,gpt-5.6-sol,gpt-6-astra",
).split(",")

# Store the plugin reads. Must equal the plugin's store_path as seen from the
# host (the plugin sees it at /data/... inside the CPA container).
STORE_PATH = Path(os.environ.get(
    "PROBE_STORE_PATH",
    str(HOME / "cpamp-deploy" / "cpa-data" / "turn-state-store.json"),
))

# CPA request logs, where the upstream turn-state and auth_id are recorded.
LOGS_DIR = Path(os.environ.get(
    "PROBE_LOGS_DIR",
    str(HOME / "cpamp-deploy" / "cpa-data" / "auths" / "logs"),
))

CODEX_BIN = os.environ.get("PROBE_CODEX_BIN", str(HOME / ".local" / "bin" / "codex"))
CODEX_WORKDIR = Path(os.environ.get("PROBE_CODEX_WORKDIR", str(HOME / "codex-work")))
CPA_ENV_FILE = Path(os.environ.get("PROBE_CPA_ENV", str(HOME / ".codex" / "cpa.env")))

TEMPLATE_LEN = int(os.environ.get("PROBE_TEMPLATE_LEN", "292"))
REPLACE_LEN = int(os.environ.get("PROBE_REPLACE_LEN", "312"))
TTL_SECONDS = int(os.environ.get("PROBE_TTL_SECONDS", "3600"))
# Refresh a bucket when it has less than this many seconds of life left, so the
# business side never finds an empty bucket.
REFRESH_BEFORE = int(os.environ.get("PROBE_REFRESH_BEFORE", "600"))
# How long to wait for a single codex attempt's turn-state to appear.
ATTEMPT_TIMEOUT = int(os.environ.get("PROBE_ATTEMPT_TIMEOUT", "60"))
# Sleep between full sweeps of all buckets.
SWEEP_INTERVAL = int(os.environ.get("PROBE_SWEEP_INTERVAL", "60"))

LOG_PREFIX = "[harvest-probe]"


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {LOG_PREFIX} {msg}", flush=True)


# ----------------------------------------------------------------------------
# Fernet timestamp — the token's own issuance time. No key needed.
# ----------------------------------------------------------------------------

def fernet_issued_at(token: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None
    if len(raw) < 9 or raw[0] != 0x80:
        return None
    return struct.unpack(">Q", raw[1:9])[0]


# ----------------------------------------------------------------------------
# Store I/O — atomic, 0600, preserves other buckets.
# ----------------------------------------------------------------------------

def load_store() -> dict:
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        doc = {}
    except Exception as exc:  # corrupt file: start clean but keep a backup
        log(f"store unreadable ({exc}); starting a fresh one")
        doc = {}
    doc.setdefault("version", 1)
    doc.setdefault("templates", {})
    return doc


def save_store(doc: dict) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".json.tmp")
    old_umask = os.umask(0o077)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, separators=(",", ":"))
        os.chmod(tmp, 0o600)
        os.replace(tmp, STORE_PATH)
    finally:
        os.umask(old_umask)


def bucket_live_seconds(doc: dict, key: str, now: int) -> int:
    entry = doc["templates"].get(key)
    if not entry:
        return 0
    issued = entry.get("issued_unix") or 0
    if issued <= 0:
        issued = fernet_issued_at(entry.get("token", "")) or 0
    remaining = (issued + TTL_SECONDS) - now
    return max(0, remaining)


# ----------------------------------------------------------------------------
# CPA request-log parsing: pull auth_id + upstream turn-state for our model.
# ----------------------------------------------------------------------------

@dataclass
class Captured:
    auth_id: str
    model: str
    token: str
    length: int


def _section(text: str, start_marker: str, end_markers: tuple[str, ...]) -> str:
    i = text.find(start_marker)
    if i < 0:
        return ""
    i += len(start_marker)
    end = len(text)
    for m in end_markers:
        j = text.find(m, i)
        if 0 <= j < end:
            end = j
    return text[i:end]


def parse_log(path: Path, model: str) -> Captured | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    # Confirm this log is for the model we fired.
    body = _section(text, "=== REQUEST BODY ===", ("=== API",))
    if f'"model":"{model}"' not in body.replace(" ", "") and \
       f'"model": "{model}"' not in body:
        return None

    # Upstream response turn-state.
    resp = _section(text, "=== API RESPONSE", ("=== RESPONSE ===",))
    token = ""
    for line in resp.splitlines():
        if line.lower().startswith("x-codex-turn-state:"):
            token = line.split(":", 1)[1].strip()
            break
    if not token:
        return None

    # auth_id from the "Auth: provider=... auth_id=... label=..." line.
    auth_id = ""
    for line in text.splitlines():
        if line.startswith("Auth:") and "auth_id=" in line:
            for part in line.split():
                if part.startswith("auth_id="):
                    auth_id = part.split("=", 1)[1]
                    break
            if auth_id:
                break
    if not auth_id:
        return None

    return Captured(auth_id=auth_id, model=model, token=token, length=len(token))


def newest_logs_since(since_mtime: float) -> list[Path]:
    try:
        files = [p for p in LOGS_DIR.glob("v1-responses-*.log")
                 if p.stat().st_mtime > since_mtime]
    except FileNotFoundError:
        return []
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


# ----------------------------------------------------------------------------
# Exit-IP rotation — pluggable. Wired to the residential proxy pool later.
# ----------------------------------------------------------------------------

def rotate_exit_ip(model: str) -> None:
    """Point the account at a fresh exit IP before harvesting.

    TODO(pool): when the dynamic residential proxy pool is available, pick the
    next unused endpoint and set the account's proxy_url (CPA hot-reloads the
    auth file). Until then this is a no-op and harvesting uses the account's
    current exit — which only yields a 292 when that exit already happens to be
    in a honeymoon window.
    """
    return


# ----------------------------------------------------------------------------
# Fire codex, capture the turn-state, kill codex once we have it.
# ----------------------------------------------------------------------------

def codex_env() -> dict:
    env = dict(os.environ)
    if "CPA_API_KEY" not in env and CPA_ENV_FILE.exists():
        for line in CPA_ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("CPA_API_KEY="):
                env["CPA_API_KEY"] = line.split("=", 1)[1].strip()
    return env


def harvest_model(model: str) -> Captured | None:
    rotate_exit_ip(model)
    CODEX_WORKDIR.mkdir(parents=True, exist_ok=True)
    baseline = time.time()

    proc = subprocess.Popen(
        [CODEX_BIN, "exec", "--sandbox", "read-only", "--skip-git-repo-check",
         "-m", model, "harvest"],
        cwd=str(CODEX_WORKDIR),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=codex_env(),
    )

    captured: Captured | None = None
    deadline = baseline + ATTEMPT_TIMEOUT
    try:
        while time.time() < deadline:
            for path in newest_logs_since(baseline - 1):
                cap = parse_log(path, model)
                if cap:
                    captured = cap
                    break
            if captured:
                break
            if proc.poll() is not None:
                # codex finished; give the log a moment to flush, then scan once.
                time.sleep(0.5)
                for path in newest_logs_since(baseline - 1):
                    cap = parse_log(path, model)
                    if cap:
                        captured = cap
                        break
                break
            time.sleep(0.4)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    return captured


# ----------------------------------------------------------------------------
# Main loop.
# ----------------------------------------------------------------------------

def sweep_once() -> None:
    doc = load_store()
    now = int(time.time())
    changed = False

    for model in MODELS:
        model = model.strip()
        if not model:
            continue

        # Skip buckets that still have comfortable life left. We don't know the
        # auth_id until we fire, so we check every stored key ending in ::model.
        best_left = 0
        for key in doc["templates"]:
            if key.endswith("::" + model):
                best_left = max(best_left, bucket_live_seconds(doc, key, now))
        if best_left > REFRESH_BEFORE:
            log(f"{model}: live template has {best_left}s left, skip")
            continue

        cap = harvest_model(model)
        if cap is None:
            log(f"{model}: no turn-state captured this attempt")
            continue
        if cap.length == REPLACE_LEN:
            log(f"{model}: got a degraded {cap.length} (no honeymoon on this exit)")
            continue
        if cap.length != TEMPLATE_LEN:
            log(f"{model}: unexpected length {cap.length}, ignoring")
            continue

        issued = fernet_issued_at(cap.token) or now
        key = f"{cap.auth_id}::{cap.model}"
        doc["templates"][key] = {"token": cap.token, "issued_unix": issued}
        changed = True
        log(f"{model}: stored normal-state template, {issued + TTL_SECONDS - now}s of life")

    # Drop expired entries so the store stays small.
    for key in list(doc["templates"]):
        if bucket_live_seconds(doc, key, now) <= 0:
            del doc["templates"][key]
            changed = True

    if changed:
        save_store(doc)


def store_complete(now: int) -> bool:
    """True when every target model has at least one live template stored."""
    doc = load_store()
    for model in MODELS:
        model = model.strip()
        if not model:
            continue
        best = 0
        for key in doc["templates"]:
            if key.endswith("::" + model):
                best = max(best, bucket_live_seconds(doc, key, now))
        if best <= 0:
            return False
    return True


def main() -> int:
    # --once           one sweep, then exit
    # --until-complete  loop until every target bucket has a live template (the
    #                   "先做完再开业务" phase), then exit so business can open
    once = "--once" in sys.argv
    until_complete = "--until-complete" in sys.argv
    log(f"models={MODELS} store={STORE_PATH} until_complete={until_complete}")
    while True:
        try:
            sweep_once()
        except Exception as exc:  # never let one bad sweep kill the loop
            log(f"sweep error: {exc}")
        if until_complete and store_complete(int(time.time())):
            log("all target buckets have a live template — probe phase complete")
            return 0
        if once:
            return 0
        time.sleep(SWEEP_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
