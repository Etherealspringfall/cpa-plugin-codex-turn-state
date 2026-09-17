#!/usr/bin/env python3
"""
probe.py — the 拿头端 (harvest side), response-based.

Drives CPA so that every (account, model) bucket ends up with a fresh, official
292-char X-Codex-Turn-State on disk, where the codex-turn-state plugin running
in `role: business` can read it.

How this differs from the older probe/harvest_probe.py:
  The old one scraped CPA's *request* logs, i.e. it waited for a genuine Codex
  client to echo a token back on a follow-up turn. This one does not parse logs
  at all. The plugin in `role: probe` intercepts the *upstream response* and
  writes the bucket file itself; this script's only jobs are (a) to point CPA at
  exactly one account, (b) to fire one minimal request per model, and (c) to
  wait for the bucket file to appear. Success is "a qualifying file is on disk",
  never "the HTTP call returned 200".

Why we steer by enabling/disabling accounts instead of naming one per request:
  CPA's scheduler picks a credential itself; the wire protocol has no "use this
  auth" knob, and guessing would break the whole point of per-account bucketing.
  The only reliable way to attribute a harvested token to a known account is to
  make that account the sole enabled candidate for the duration of its probe.

  ==> That means: while this script runs, every other Codex account is DISABLED.
      Business traffic must be stopped first (see DEPLOY.md / spec §9 step 8).

SIDE EFFECTS
  - Flips the `disabled` flag on Codex auth files via the CPA management API.
  - Consumes quota: one upstream request per (account, model) that is not
    already covered by a live bucket.
  - Writes a state snapshot file (0600) so the flips can always be undone.

  Account state is snapshotted BEFORE the first mutation and restored on every
  exit path — normal return, exception, SIGINT, SIGTERM. If restoration fails,
  the snapshot is deliberately left behind and the exact `--restore` command is
  printed. A probe that dies without restoring would leave the operator's
  accounts switched off, which is the worst failure mode this script has.

ENVIRONMENT
  CPA_MANAGEMENT_KEY  (required)  Bearer token for /v0/management/*.
  CPA_API_KEY         (required unless --dry-run/--restore)  Bearer token for
                      /v1/responses. This is a different key from the one above.
  Neither is ever written to disk or printed. Only key *presence* is logged.

The harvested token itself is credential-adjacent: it lives only in the bucket
file the plugin writes (0600). This script reads it solely to verify the length
and the embedded timestamp, and never prints it.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import json
import os
import signal
import struct
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

# CPA is on loopback. A proxy set in the environment (http_proxy/all_proxy — and
# something is usually set on this host) would otherwise swallow these calls and
# surface as bogus 502s, so every request here goes direct.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# ----------------------------------------------------------------------------
# Defaults. Every one of these is overridable on the command line.
# ----------------------------------------------------------------------------

HOME = Path(os.path.expanduser("~"))

DEFAULT_BASE_URL = "http://127.0.0.1:8317"
DEFAULT_STORE_DIR = HOME / "cpamp-deploy" / "cpa-data" / "turn-state-store"
DEFAULT_AUTHS_DIR = HOME / "cpamp-deploy" / "cpa-data" / "auths"
DEFAULT_SNAPSHOT = HOME / ".cache" / "codex-turn-state" / "auth-state-snapshot.json"

# The official model ids, hyphens and all. A typo here silently probes a model
# that does not exist, so the list is spelled out rather than derived.
DEFAULT_MODELS = [
    "gpt-5.5",
    "gpt-5.6-luna",
    "gpt-5.6-terra",
    "gpt-5.6-sol",
    "gpt-6-astra",
]

TEMPLATE_LEN = 292   # normal serving state — the only length worth storing
REPLACE_LEN = 312    # throttled/degraded state — never a template
TTL_SECONDS = 3600   # matches the plugin's ttl_seconds

LOG_PREFIX = "[probe]"


def log(msg: str) -> None:
    print(f"{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {LOG_PREFIX} {msg}", flush=True)


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"{LOG_PREFIX} error: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(code)


# ----------------------------------------------------------------------------
# Fernet timestamp. The token carries its own issuance time in clear, so expiry
# can be checked without any key. See FINDINGS.md.
# ----------------------------------------------------------------------------

def fernet_issued_at(token: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None
    if len(raw) < 9 or raw[0] != 0x80:
        return None
    return struct.unpack(">Q", raw[1:9])[0]


def parse_rfc3339(value: str) -> int | None:
    """Seconds since epoch from an RFC3339 string, or None."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


# ----------------------------------------------------------------------------
# HTTP. Plain urllib so the script has no dependencies beyond the stdlib — the
# OVH host has no package manager story for this.
# ----------------------------------------------------------------------------

class HTTPResult:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self.body = body
        self.headers = headers

    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None


def http_call(
    method: str,
    url: str,
    token: str,
    payload: dict | None = None,
    timeout: int = 30,
) -> HTTPResult:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return HTTPResult(
                response.status,
                response.read(),
                {k.lower(): v for k, v in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        # An HTTPError is still a real response; the caller decides what a
        # non-2xx means. 401 vs 404 in particular must stay distinguishable:
        # 401 is a bad management key, 404 is a wrong path. Collapsing them
        # sends whoever is debugging this down the wrong road.
        return HTTPResult(
            exc.code,
            exc.read() or b"",
            {k.lower(): v for k, v in (exc.headers or {}).items()},
        )
    except urllib.error.URLError as exc:
        raise ConnectionError(f"{method} {url}: {exc.reason}") from exc


def explain_status(result: HTTPResult, what: str) -> str:
    if result.status == 401:
        return (f"{what}: 401 unauthorized — CPA_MANAGEMENT_KEY is wrong or not "
                f"accepted. This is an auth failure, not a bad path.")
    if result.status == 403:
        return f"{what}: 403 forbidden — the key was accepted but lacks access."
    if result.status == 404:
        return (f"{what}: 404 not found — the endpoint path is wrong for this CPA "
                f"version (auth would have failed with 401 instead).")
    body = result.body.decode("utf-8", errors="replace")[:200]
    return f"{what}: HTTP {result.status} {body}"


# ----------------------------------------------------------------------------
# CPA management API.
# ----------------------------------------------------------------------------

class CPA:
    def __init__(self, base_url: str, mgmt_key: str, api_key: str, dry_run: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.mgmt_key = mgmt_key
        self.api_key = api_key
        self.dry_run = dry_run

    # -- health ------------------------------------------------------------

    def healthy(self) -> bool:
        # /healthz, not /status — the latter does not exist on this build.
        try:
            result = http_call("GET", f"{self.base_url}/healthz", "", timeout=10)
        except ConnectionError as exc:
            log(f"health check failed: {exc}")
            return False
        if result.status != 200:
            log(explain_status(result, "GET /healthz"))
            return False
        return True

    # -- auth files --------------------------------------------------------

    def list_auth_files(self) -> list[dict]:
        url = f"{self.base_url}/v0/management/auth-files"
        result = http_call("GET", url, self.mgmt_key)
        if result.status != 200:
            die(explain_status(result, "GET /v0/management/auth-files"))
        doc = result.json() or {}
        files = doc.get("files")
        if not isinstance(files, list):
            die("GET /v0/management/auth-files returned no 'files' array")
        return files

    def list_codex_auths(self) -> list[dict]:
        """Codex auth files only, .bak excluded.

        Filtering is by provider when CPA reports one and by filename otherwise;
        a `.bak` file is an operator's backup copy and must never be enabled.
        """
        out = []
        for entry in self.list_auth_files():
            name = str(entry.get("name") or "").strip()
            if not name or name.endswith(".bak") or ".bak" in name:
                continue
            provider = str(entry.get("provider") or entry.get("type") or "").strip().lower()
            if provider == "codex" or (name.startswith("codex-") and name.endswith(".json")):
                out.append(entry)
        out.sort(key=lambda e: str(e.get("name", "")))
        return out

    def set_disabled(self, entry: dict, disabled: bool) -> None:
        name = str(entry.get("name") or "")
        auth_index = str(entry.get("auth_index") or "")
        verb = "disable" if disabled else "enable"
        if self.dry_run:
            log(f"DRY-RUN would {verb} {name}")
            return
        payload: dict[str, Any] = {"name": name, "disabled": disabled}
        if auth_index:
            payload["auth_index"] = auth_index
        url = f"{self.base_url}/v0/management/auth-files/status"
        result = http_call("PATCH", url, self.mgmt_key, payload)
        if result.status != 200:
            raise RuntimeError(explain_status(result, f"PATCH status ({verb} {name})"))

    # -- upstream request --------------------------------------------------

    def fire(self, model: str, timeout: int) -> tuple[int, str]:
        """Send one minimal /v1/responses request. Returns (status, short note).

        The request deliberately carries NO X-Codex-Turn-State header: sending a
        stale one would either be rewritten by a misconfigured plugin or cause
        the upstream to reuse an old turn, and either way we would not get a
        freshly minted token back.

        A non-2xx here is not fatal. The plugin harvests from the response
        headers, and those are present on error responses too; the authority on
        success is the bucket file, checked by the caller.
        """
        if self.dry_run:
            log(f"DRY-RUN would POST /v1/responses model={model}")
            return 0, "dry-run"

        payload = {
            "model": model,
            "input": "ping",
            "stream": False,
            # Keep the completion as small as the API allows: this call exists
            # to mint a turn-state, not to produce text. Quota is real money.
            "max_output_tokens": 16,
        }
        url = f"{self.base_url}/v1/responses"
        try:
            result = http_call("POST", url, self.api_key, payload, timeout=timeout)
        except ConnectionError as exc:
            return 0, str(exc)
        note = "ok" if 200 <= result.status < 300 else \
            result.body.decode("utf-8", errors="replace")[:160]
        return result.status, note


# ----------------------------------------------------------------------------
# Store inspection. The plugin writes these files; we only read them.
# ----------------------------------------------------------------------------

class Bucket:
    def __init__(self, auth_id: str, model: str, length: int, issued_at: int) -> None:
        self.auth_id = auth_id
        self.model = model
        self.length = length
        self.issued_at = issued_at

    def seconds_left(self, now: int, ttl: int = TTL_SECONDS) -> int:
        return max(0, (self.issued_at + ttl) - now)

    def ready(self, now: int, ttl: int = TTL_SECONDS) -> bool:
        return self.length == TEMPLATE_LEN and self.seconds_left(now, ttl) > 0


def bucket_path(store_dir: Path, auth_id: str, model: str) -> Path:
    return store_dir / auth_id / f"{model}.json"


def read_bucket(store_dir: Path, auth_id: str, model: str) -> Bucket | None:
    """Parse one bucket file, or None when it is missing/unusable.

    The stored `issued_at` is cross-checked against the token's own Fernet
    timestamp. They should agree; when they do not, the token wins, because the
    upstream enforces its window against the signed timestamp and nothing else.
    """
    path = bucket_path(store_dir, auth_id, model)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as exc:
        log(f"bucket unreadable auth={auth_id} model={model}: {exc}")
        return None

    value = str(doc.get("value") or "")
    length = int(doc.get("len") or len(value))
    issued = parse_rfc3339(str(doc.get("issued_at") or "")) or 0
    from_token = fernet_issued_at(value)
    if from_token and from_token != issued:
        log(f"bucket issued_at disagrees with token auth={auth_id} model={model}"
            f" (file={issued} token={from_token}); trusting the token")
        issued = from_token
    if issued <= 0:
        return None
    # auth_id comes from the *file*, not from the path we looked under, so the
    # caller can catch a token that CPA attributed to a different account than
    # the one we enabled (spec §10: 只启用一个号时写入的 auth_id 就是该号).
    recorded_auth = str(doc.get("auth_id") or "").strip() or auth_id
    return Bucket(auth_id=recorded_auth, model=model, length=length, issued_at=issued)


def targets(auths: list[str], models: list[str]) -> list[tuple[str, str]]:
    return [(a, m) for a in auths for m in models]


def missing_buckets(
    store_dir: Path, auths: list[str], models: list[str], now: int
) -> list[tuple[str, str]]:
    out = []
    for auth_id, model in targets(auths, models):
        bucket = read_bucket(store_dir, auth_id, model)
        if bucket is None or not bucket.ready(now):
            out.append((auth_id, model))
    return out


# ----------------------------------------------------------------------------
# Account state snapshot + restore. The safety net for the whole script.
# ----------------------------------------------------------------------------

class StateGuard:
    """Remembers every Codex account's `disabled` flag and puts it all back.

    Registered with atexit and wired to SIGINT/SIGTERM, so a Ctrl-C halfway
    through a probe still restores. restore() is idempotent and verifies itself
    by re-reading the account list; the snapshot file is removed only after that
    verification passes, so a failed restore always leaves a recovery path.
    """

    def __init__(self, cpa: CPA, snapshot_path: Path) -> None:
        self.cpa = cpa
        self.snapshot_path = snapshot_path
        self.original: dict[str, bool] = {}
        self.entries: dict[str, dict] = {}
        self.armed = False
        self.restored = False

    def arm(self, auths: list[dict]) -> None:
        """Record current state and persist it before anything is mutated."""
        self.original = {str(e.get("name")): bool(e.get("disabled")) for e in auths}
        self.entries = {str(e.get("name")): e for e in auths}
        doc = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.cpa.base_url,
            "accounts": [
                {
                    "name": name,
                    "auth_index": str(self.entries[name].get("auth_index") or ""),
                    "disabled": disabled,
                }
                for name, disabled in sorted(self.original.items())
            ],
        }
        if self.cpa.dry_run:
            log(f"DRY-RUN would snapshot {len(self.original)} account states")
            self.armed = True
            return

        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        old_umask = os.umask(0o077)
        try:
            tmp = self.snapshot_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.snapshot_path)
        finally:
            os.umask(old_umask)
        self.armed = True
        log(f"snapshot of {len(self.original)} account states -> {self.snapshot_path}")

    def restore(self) -> bool:
        if not self.armed or self.restored or self.cpa.dry_run:
            return True
        self.restored = True  # set first: never loop if restore itself throws

        log("restoring original account enable/disable state")
        failures = []
        for name, disabled in sorted(self.original.items()):
            entry = self.entries.get(name) or {"name": name}
            try:
                self.cpa.set_disabled(entry, disabled)
            except Exception as exc:
                failures.append(f"{name}: {exc}")

        # Verify by re-reading rather than trusting the PATCH responses.
        try:
            current = {str(e.get("name")): bool(e.get("disabled"))
                       for e in self.cpa.list_codex_auths()}
            for name, want in self.original.items():
                if name in current and current[name] != want:
                    failures.append(f"{name}: still disabled={current[name]}, want {want}")
        except SystemExit:
            failures.append("could not re-list auth files to verify restore")
        except Exception as exc:
            failures.append(f"verification failed: {exc}")

        if failures:
            for line in failures:
                log(f"RESTORE FAILED {line}")
            log("!! accounts may be left in the wrong state. Recover with:")
            log(f"!!   CPA_MANAGEMENT_KEY=... python3 {Path(__file__).name} "
                f"--restore {self.snapshot_path}")
            return False

        try:
            self.snapshot_path.unlink()
        except FileNotFoundError:
            pass
        log("account state restored and verified")
        return True


def restore_from_file(cpa: CPA, path: Path) -> int:
    """Standalone recovery path: re-apply a snapshot written by an earlier run."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        die(f"cannot read snapshot {path}: {exc}")
    accounts = doc.get("accounts") or []
    if not accounts:
        die(f"snapshot {path} lists no accounts")

    log(f"restoring {len(accounts)} account states from {path}"
        f" (captured {doc.get('captured_at', 'unknown')})")
    failures = []
    for item in accounts:
        entry = {"name": item.get("name"), "auth_index": item.get("auth_index") or ""}
        try:
            cpa.set_disabled(entry, bool(item.get("disabled")))
            log(f"  {item.get('name')} -> disabled={bool(item.get('disabled'))}")
        except Exception as exc:
            failures.append(f"{item.get('name')}: {exc}")
    if failures:
        for line in failures:
            log(f"RESTORE FAILED {line}")
        return 1
    if not cpa.dry_run:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    log("restore complete")
    return 0


# ----------------------------------------------------------------------------
# The probe itself.
# ----------------------------------------------------------------------------

def probe_bucket(
    cpa: CPA,
    store_dir: Path,
    auth_id: str,
    model: str,
    args: argparse.Namespace,
) -> bool:
    """Fire requests for one bucket until a qualifying file lands, or give up."""
    before = read_bucket(store_dir, auth_id, model)
    before_issued = before.issued_at if before else 0

    for attempt in range(1, args.retries + 1):
        status, note = cpa.fire(model, timeout=args.http_timeout)
        if cpa.dry_run:
            return True
        log(f"  attempt {attempt}/{args.retries} model={model} http={status}"
            + ("" if status and 200 <= status < 300 else f" note={note}"))

        # Poll for the plugin's write. HTTP status is deliberately not a gate:
        # the header rides on error responses too, and the file is the contract.
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            now = int(time.time())
            bucket = read_bucket(store_dir, auth_id, model)
            if bucket and bucket.issued_at > before_issued:
                if bucket.length == TEMPLATE_LEN and bucket.ready(now):
                    log(f"  stored auth={auth_id} model={model} len={bucket.length}"
                        f" ttl_left={bucket.seconds_left(now)}s")
                    return True
                if bucket.length == REPLACE_LEN:
                    log(f"  got degraded len={REPLACE_LEN} auth={auth_id} model={model}"
                        f" — not a template, will retry")
                    before_issued = bucket.issued_at
                    break
            time.sleep(0.5)
        else:
            log(f"  timeout after {args.timeout}s waiting for a bucket file"
                f" auth={auth_id} model={model}")

    return False


def probe_account(
    cpa: CPA,
    guard: StateGuard,
    store_dir: Path,
    entry: dict,
    models: list[str],
    args: argparse.Namespace,
) -> dict[str, bool]:
    """Make `entry` the only enabled Codex account, then probe every model."""
    auth_id = str(entry.get("name"))
    log(f"account {auth_id}: making it the sole enabled Codex account")

    for other in guard.entries.values():
        name = str(other.get("name"))
        want_disabled = (name != auth_id)
        try:
            cpa.set_disabled(other, want_disabled)
        except Exception as exc:
            log(f"  could not set {name} disabled={want_disabled}: {exc}")
            raise

    # CPA reloads auth state asynchronously; firing immediately can still hit
    # the previous candidate set and attribute the token to the wrong account.
    if not cpa.dry_run and args.settle > 0:
        time.sleep(args.settle)

    results: dict[str, bool] = {}
    now = int(time.time())
    for model in models:
        existing = read_bucket(store_dir, auth_id, model)
        if existing and existing.ready(now) and not args.force:
            log(f"  skip auth={auth_id} model={model}: live template,"
                f" {existing.seconds_left(now)}s left")
            results[model] = True
            continue
        results[model] = probe_bucket(cpa, store_dir, auth_id, model, args)

        # Sanity check the spec's acceptance criterion: with one account
        # enabled, the written bucket must belong to that account.
        written = read_bucket(store_dir, auth_id, model)
        if written and written.auth_id and written.auth_id != auth_id:
            log(f"  WARNING bucket file records auth_id={written.auth_id}"
                f" but we enabled {auth_id} — do not trust this store")
    return results


def run_pass(
    cpa: CPA,
    guard: StateGuard,
    store_dir: Path,
    auths: list[dict],
    models: list[str],
    args: argparse.Namespace,
) -> bool:
    """One full sweep. Returns True when every target bucket is ready."""
    for entry in auths:
        probe_account(cpa, guard, store_dir, entry, models, args)

    now = int(time.time())
    names = [str(e.get("name")) for e in auths]
    missing = missing_buckets(store_dir, names, models, now)
    total = len(names) * len(models)
    log(f"pass complete: {total - len(missing)}/{total} buckets ready")
    for auth_id, model in missing:
        log(f"  missing auth={auth_id} model={model}")
    return not missing


def confirm_or_exit(auths: list[dict], args: argparse.Namespace) -> None:
    names = ", ".join(str(e.get("name")) for e in auths)
    log("=" * 68)
    log("This will DISABLE every Codex account except the one being probed.")
    log(f"Accounts in scope: {names}")
    log("Business traffic must already be stopped (spec §9 step 8).")
    log("=" * 68)
    if args.yes or args.dry_run:
        return
    if not sys.stdin.isatty():
        # Non-interactive (cron, nohup): proceed, but the banner above is in the
        # log so the operator can see what happened.
        return
    answer = input("Type 'yes' to continue: ").strip().lower()
    if answer != "yes":
        die("aborted by operator", code=1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe.py",
        description="Harvest official 292-char X-Codex-Turn-State per (account, model).",
    )
    parser.add_argument("--until-complete", action="store_true",
                        help="keep sweeping until every target bucket holds a live "
                             "292; exit 0 only then, non-zero otherwise")
    parser.add_argument("--once", action="store_true",
                        help="a single sweep (the default when --until-complete "
                             "is not given)")
    parser.add_argument("--account", metavar="JSONNAME",
                        help="probe only this auth file name, e.g. codex-foo.json")
    parser.add_argument("--model", metavar="ID",
                        help="probe only this model id")
    parser.add_argument("--models", metavar="CSV",
                        help=f"override the model list (default: {','.join(DEFAULT_MODELS)})")
    parser.add_argument("--force", action="store_true",
                        help="re-probe buckets that already hold a live template")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the enable/disable flips and requests that would "
                             "happen; change nothing, send nothing")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="skip the interactive confirmation")
    parser.add_argument("--restore", metavar="FILE",
                        help="re-apply an account-state snapshot and exit "
                             "(manual recovery after a failed restore)")
    parser.add_argument("--store-dir", default=str(DEFAULT_STORE_DIR),
                        help="host path of the plugin's store_dir "
                             f"(default: {DEFAULT_STORE_DIR})")
    parser.add_argument("--auths-dir", default=str(DEFAULT_AUTHS_DIR),
                        help=f"auth file directory, used as a cross-check "
                             f"(default: {DEFAULT_AUTHS_DIR})")
    parser.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT),
                        help=f"where to write the state snapshot "
                             f"(default: {DEFAULT_SNAPSHOT})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"CPA base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--timeout", type=int, default=90,
                        help="seconds to wait for a bucket file after firing (default 90)")
    parser.add_argument("--http-timeout", type=int, default=120,
                        help="seconds to wait on the upstream request (default 120)")
    parser.add_argument("--retries", type=int, default=2,
                        help="attempts per bucket before giving up (default 2)")
    parser.add_argument("--settle", type=float, default=2.0,
                        help="seconds to wait after flipping account state, before "
                             "firing (default 2)")
    parser.add_argument("--sweep-interval", type=int, default=60,
                        help="seconds between sweeps in --until-complete (default 60)")
    parser.add_argument("--max-sweeps", type=int, default=10,
                        help="give up after this many sweeps in --until-complete "
                             "(default 10); prevents an unbounded quota burn")
    return parser


def cross_check_disk(auths: list[dict], auths_dir: Path) -> None:
    """Warn when CPA's view and the on-disk codex-*.json set disagree.

    The management API is authoritative for what CPA will actually schedule, but
    a mismatch usually means a file was added or removed without a reload, and
    silently probing the wrong set is worse than a noisy warning.
    """
    try:
        on_disk = {p.name for p in auths_dir.glob("codex-*.json")
                   if not p.name.endswith(".bak") and ".bak" not in p.name}
    except Exception as exc:
        log(f"could not read {auths_dir} for cross-check: {exc}")
        return
    known = {str(e.get("name")) for e in auths}
    for name in sorted(on_disk - known):
        log(f"note: {name} exists on disk but CPA does not list it")
    for name in sorted(known - on_disk):
        log(f"note: CPA lists {name} but it is not in {auths_dir}")


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    mgmt_key = os.environ.get("CPA_MANAGEMENT_KEY", "").strip()
    api_key = os.environ.get("CPA_API_KEY", "").strip()
    if not mgmt_key:
        die("CPA_MANAGEMENT_KEY is not set.\n"
            "  Set it in the shell that runs this script, e.g.\n"
            "    read -rs CPA_MANAGEMENT_KEY && export CPA_MANAGEMENT_KEY\n"
            "  It is the plaintext management key, not the bcrypt hash in config.yaml.")
    if not api_key and not (args.dry_run or args.restore):
        die("CPA_API_KEY is not set (needed to send /v1/responses).\n"
            "  This is a different key from CPA_MANAGEMENT_KEY.")

    cpa = CPA(args.base_url, mgmt_key, api_key, args.dry_run)

    if args.restore:
        return restore_from_file(cpa, Path(args.restore))

    store_dir = Path(args.store_dir)
    models = DEFAULT_MODELS if not args.models else \
        [m.strip() for m in args.models.split(",") if m.strip()]
    if args.model:
        if args.model not in models:
            log(f"note: {args.model} is not in the default list {models}")
        models = [args.model]

    if not cpa.healthy():
        die("CPA is not answering on /healthz; refusing to touch account state")

    auths = cpa.list_codex_auths()
    if not auths:
        die("no Codex auth files reported by CPA")
    cross_check_disk(auths, Path(args.auths_dir))

    if args.account:
        auths = [e for e in auths if str(e.get("name")) == args.account]
        if not auths:
            die(f"account {args.account} not found among CPA's Codex auth files")

    log(f"store_dir={store_dir}")
    log(f"accounts={[str(e.get('name')) for e in auths]}")
    log(f"models={models}")
    log(f"keys: management={'set' if mgmt_key else 'MISSING'} "
        f"api={'set' if api_key else 'MISSING'}")

    confirm_or_exit(auths, args)

    # The guard must see every Codex account, not just the filtered subset:
    # probing one account still disables all the others, so all of them have to
    # be restorable.
    guard = StateGuard(cpa, Path(args.snapshot))
    guard.arm(cpa.list_codex_auths())

    # Restore on every exit path. atexit covers normal return and uncaught
    # exceptions; the signal handlers turn a Ctrl-C or a `kill` into SystemExit
    # so that atexit still runs rather than the process dying where it stands.
    atexit.register(guard.restore)

    def on_signal(signum, _frame):
        log(f"received signal {signum}; restoring account state before exit")
        raise SystemExit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError):
            pass  # not on the main thread, or not supported on this platform

    names = [str(e.get("name")) for e in auths]
    sweeps = 0
    complete = False
    try:
        while True:
            sweeps += 1
            log(f"--- sweep {sweeps} ---")
            complete = run_pass(cpa, guard, store_dir, auths, models, args)
            if complete:
                log("every target bucket holds a live 292 — probe phase complete")
                break
            if not args.until_complete:
                break
            if sweeps >= args.max_sweeps:
                log(f"giving up after {sweeps} sweeps (--max-sweeps)")
                break
            log(f"sleeping {args.sweep_interval}s before the next sweep")
            time.sleep(args.sweep_interval)
    finally:
        guard.restore()

    if args.dry_run:
        return 0
    if args.until_complete:
        # Exit code is the contract: 0 only when the store is genuinely complete,
        # so DEPLOY.md step "先做完再开业务" can gate on it.
        now = int(time.time())
        missing = missing_buckets(store_dir, names, models, now)
        if missing:
            log(f"incomplete: {len(missing)} bucket(s) still missing")
            return 1
        return 0
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
