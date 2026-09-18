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
  exactly one account, (b) to fire one minimal request per model, and (c) to ask
  the plugin whether the bucket is ready. Success is "the plugin reports the
  bucket ready", never "the HTTP call returned 200".

Why readiness comes from the management API and not from the store files:
  CPA runs as root inside its container, so the bucket files it writes are
  root:root 0600 inside root:root 0700 per-account directories. This script runs
  as an ordinary host user and cannot read — or even enter — any of them. Asking
  the plugin over GET /v0/management/codex-turn-state/status is the only path
  that works unprivileged, and it is the safer one too: that response reports
  ready/seconds_left and carries no token values, so this script never holds a
  turn-state in memory. Reading files directly survives only as a fallback for
  an older .so that predates the endpoint.

Where the scope comes from:
  probe_accounts, models and probe_proxies are read from the plugin's own config
  (GET /v0/management/codex-turn-state/config), so the dashboard and this script
  cannot disagree about what "complete" means. There is no built-in fallback: an
  empty selection is refused, not silently widened to everything. Probing is a
  stop-the-world operation that spends an upstream request per bucket, and
  "it defaulted to all of them" is the one mistake that cannot be undone.

Why each bucket is tried through several exits:
  Rule 3 says a template harvested on one IP works from another, so the exit only
  has to be good for the few seconds it takes to mint the token. probe_proxies is
  that list of exits, tried in order, per bucket, by PATCHing the probed
  account's OWN proxy field. A candidate that times out or yields a degraded 312
  is not an error -- it means that exit is not in a honeymoon, which is what the
  next candidate is for. The global proxy-url is never touched: it carries Kimi,
  xAI and all daily traffic.

  ⚠ The route and field used for that PATCH are UNVERIFIED against a running CPA
  (see CPA.PROXY_ROUTE / CPA.PROXY_FIELD). If they are wrong the write silently
  does nothing and every candidate then "fails", while the real cause is that the
  exit never changed. Two guards exist because of that: the run refuses to start
  when the field cannot be read back, and a PATCH that cannot be confirmed aborts
  rather than counting as a failed candidate.

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

The harvested token itself is credential-adjacent and never enters this process:
it lives only in the bucket file the plugin writes. Upstream error bodies are
passed through redact() before they reach the log.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import signal
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
REPLACE_LEN = 312    # throttled/degraded state, never a template. Recorded here
                     # for reference; readiness is the plugin's call, not ours.
TTL_SECONDS = 3600   # matches the plugin's ttl_seconds

LOG_PREFIX = "[probe]"


def log(msg: str) -> None:
    print(f"{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} {LOG_PREFIX} {msg}", flush=True)


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"{LOG_PREFIX} error: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(code)


# ----------------------------------------------------------------------------
# Redaction. Upstream error bodies have to be shown verbatim enough to identify
# a protocol mismatch, but they may echo headers or credentials back at us.
# ----------------------------------------------------------------------------

# A Fernet token base64url-encodes a leading 0x80 version byte, which always
# renders as the literal prefix "gAAAAA". That makes turn-state values greppable
# without decoding anything. See FINDINGS.md.
_TOKEN_RE = re.compile(r"gAAAAA[A-Za-z0-9_\-=]{16,}")
_APIKEY_RE = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}")
# Userinfo in any URL, which in this script means a proxy's credentials. Matched
# on the scheme://...@ shape rather than against the configured proxy list: a URL
# echoed back inside an upstream error body has to be caught too, and that one is
# never in any list we hold.
_URLAUTH_RE = re.compile(r"(?i)\b([a-z0-9+.\-]+://)[^/\s@]+@")


def redact(text: str) -> str:
    """Strip anything credential-shaped out of text bound for the log."""
    text = _TOKEN_RE.sub("<turn-state redacted>", text)
    text = _APIKEY_RE.sub("<api-key redacted>", text)
    text = _BEARER_RE.sub(r"\1<redacted>", text)
    text = _URLAUTH_RE.sub(r"\1***@", text)
    return text


def mask_proxy(url: str) -> str:
    """Render one proxy URL safe to log.

    Mirrors maskProxyURL in go/main.go, deliberately: the two sides describe the
    same exits to the same operator, and a proxy that reads differently in the
    dashboard and in the probe log is one the operator has to reconcile by hand.

    A value this cannot make sense of is replaced wholesale rather than passed
    through. Something too malformed to contain "://" is exactly the entry most
    likely to be a mistyped password, and echoing it back "because it did not
    look like a URL" would publish the thing this function exists to hide.
    """
    text = (url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        return "<unparsable proxy url>"
    scheme, _, rest = text.partition("://")
    if "@" not in rest.split("/", 1)[0]:
        return text
    _, _, hostpart = rest.partition("@")
    return f"{scheme}://***@{hostpart}"


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
    extra_headers: dict[str, str] | None = None,
) -> HTTPResult:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)

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

    # -- plugin status -----------------------------------------------------

    def plugin_status(self) -> dict | None:
        """GET the plugin's read-only status, or None when it is not there.

        This is the authoritative source of bucket readiness. The bucket files
        themselves are written by CPA running as root inside the container and
        land as root-owned 0600 files under root-owned 0700 directories, so a
        probe running as an ordinary host user cannot read them at all. The
        status endpoint reports ready/seconds_left and deliberately carries no
        token values, so it is both the only reliable path and the safer one.

        None means HTTP 404: an older .so is loaded that has no management API.
        Every other failure is fatal — degrading to the filesystem on, say, a
        401 would just produce a confusing permission error downstream.
        """
        url = f"{self.base_url}/v0/management/codex-turn-state/status"
        # Send both accepted forms: this CPA build takes Authorization: Bearer,
        # and the plugin's own handler documents X-Management-Key.
        result = http_call("GET", url, self.mgmt_key,
                           extra_headers={"X-Management-Key": self.mgmt_key})
        if result.status == 404:
            return None
        if result.status != 200:
            die(explain_status(result, "GET /v0/management/codex-turn-state/status"))
        doc = result.json()
        if not isinstance(doc, dict):
            die("plugin status endpoint returned a non-object body")
        return doc

    def plugin_config(self) -> dict | None:
        """GET the plugin's editable config, or None when the route is absent.

        This is the only place the full proxy list can be read: the status
        document deliberately carries just a count and masked forms, because it
        is also served anonymously. Here the management key is required, and this
        script has one by construction -- it cannot enable or disable an account
        without it -- so the authenticated route is free to use regardless of how
        the dashboard is configured.
        """
        url = f"{self.base_url}/v0/management/codex-turn-state/config"
        result = http_call("GET", url, self.mgmt_key,
                           extra_headers={"X-Management-Key": self.mgmt_key})
        if result.status == 404:
            return None
        if result.status != 200:
            die(explain_status(result, "GET /v0/management/codex-turn-state/config"))
        doc = result.json()
        if not isinstance(doc, dict):
            die("plugin config endpoint returned a non-object body")
        return doc

    # -- per-account exit --------------------------------------------------
    #
    # ⚠ THE ROUTE AND FIELD NAME BELOW ARE UNVERIFIED.
    #
    # They come from the handover document. GET /v0/management/auth-files was
    # observed returning no proxy-shaped field at all, so nothing has confirmed
    # end to end that CPA accepts this write. Both are isolated here so a
    # correction is a one-line change.
    #
    # All the failure handling follows from that uncertainty. If the route or the
    # field is wrong the PATCH silently does nothing, every candidate then fails
    # to produce a 292, and the run reports "every proxy is bad" while the real
    # cause is that the exit never changed. That misdiagnosis costs an entire
    # stop-the-world probe window, so a PATCH that cannot be shown to have taken
    # effect aborts the run rather than being counted as a failed candidate.

    PROXY_FIELD = "proxy_url"
    PROXY_ROUTE = "/v0/management/auth-files/fields"

    def _proxy_failure(self, name: str, shown: str, detail: str) -> str:
        return (
            f"could not switch the exit for {name} to {shown}: {detail}\n"
            f"  ABORTING. The proxy was NOT changed, so any result from this run\n"
            f"  would say nothing about the proxies -- it would only show that the\n"
            f"  account's existing exit did or did not yield a 292.\n"
            f"  Route and field are unverified against this CPA build:\n"
            f"    PATCH {self.PROXY_ROUTE}  field {self.PROXY_FIELD!r}\n"
            f"  Confirm both before re-running; correct them in CPA.PROXY_ROUTE /\n"
            f"  CPA.PROXY_FIELD if they differ."
        )

    def _read_proxy(self, name: str) -> str | None:
        """Read one account's proxy_url from the auth file download.

        GET /v0/management/auth-files does not include proxy_url (CPA 7.3.4
        list DTO omits it). The file itself does; download is the read-back.
        Returns None only when the file cannot be read. Missing field => "".
        """
        from urllib.parse import quote
        url = f"{self.base_url}/v0/management/auth-files/download?name={quote(name)}"
        result = http_call("GET", url, self.mgmt_key)
        if result.status != 200:
            return None
        try:
            doc = result.json()
        except Exception:
            return None
        if not isinstance(doc, dict):
            return None
        if "proxy_url" in doc:
            return str(doc.get("proxy_url") or "")
        meta = doc.get("metadata")
        if isinstance(meta, dict) and "proxy_url" in meta:
            return str(meta.get("proxy_url") or "")
        return ""

    def proxy_field_is_readable(self) -> bool:
        # List order is alphabetical and includes non-file/virtual auths.
        # Download 404 on the first row must not disable rotation.
        for entry in self.list_auth_files():
            name = str(entry.get("name") or "")
            if not name.endswith(".json"):
                continue
            if self._read_proxy(name) is not None:
                return True
        return False

    def set_proxy(self, entry: dict, proxy_url: str, fatal: bool = True) -> None:
        """Point one account at one exit. An empty value clears the override.

        Only ever the probed account's own field. The global proxy-url in CPA's
        config is never touched: it carries Kimi, xAI and all daily traffic, and
        repointing that would move far more than this run.

        fatal=False is for the restore path, which must keep going and put every
        remaining account back rather than exiting on the first problem.
        """
        name = str(entry.get("name") or "")
        auth_index = str(entry.get("auth_index") or "")
        shown = mask_proxy(proxy_url) or "(none)"
        if self.dry_run:
            log(f"DRY-RUN would set {name} {self.PROXY_FIELD}={shown}")
            return

        def fail(detail: str) -> None:
            message = self._proxy_failure(name, shown, detail)
            if fatal:
                die(message)
            raise RuntimeError(message)

        payload: dict[str, Any] = {"name": name, self.PROXY_FIELD: proxy_url}
        if auth_index:
            payload["auth_index"] = auth_index
        url = f"{self.base_url}{self.PROXY_ROUTE}"
        try:
            result = http_call("PATCH", url, self.mgmt_key, payload)
        except ConnectionError as exc:
            fail(str(exc))
            return
        if result.status != 200:
            fail(explain_status(result, f"PATCH {self.PROXY_ROUTE}"))
            return

        observed = self._read_proxy(name)
        if observed is None:
            # Should be unreachable: main refuses to rotate when the field is not
            # readable. Kept because "we could not check" must never be logged in
            # the same words as "we checked and it was right".
            log(f"  exit -> {shown} for {name}"
                f" (HTTP 200, but {self.PROXY_FIELD} is not echoed back —"
                f" UNCONFIRMED)")
            return
        if observed.strip() != proxy_url.strip():
            fail(f"the PATCH returned 200 but {self.PROXY_FIELD} reads back as "
                 f"{mask_proxy(observed) or '(none)'}")
            return
        log(f"  exit -> {shown} for {name} (verified by read-back)")

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
        success is the plugin's status endpoint, checked by the caller.

        The error body is reported at length (redacted) rather than summarised:
        the very first real run exists to confirm that /v1/responses is the
        protocol Codex actually speaks here, and "failed" with no body is
        useless for telling a wrong route from a wrong payload shape.
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
        if 200 <= result.status < 300:
            return result.status, "ok"
        body = redact(result.body.decode("utf-8", errors="replace").strip())
        if len(body) > 600:
            body = body[:600] + f" ...[+{len(body) - 600} chars]"
        return result.status, body or "(empty body)"


# ----------------------------------------------------------------------------
# Bucket readiness.
#
# The source of truth is the plugin's management API, NOT the store files. CPA
# runs as root inside its container, so the bucket files it writes are root:root
# 0600 inside root:root 0700 per-account directories. A probe running as an
# ordinary host user gets EACCES on every one of them — and a readiness check
# that silently treats EACCES as "not ready" would loop forever while blaming
# the upstream for never issuing a 292.
#
# The API is also strictly safer: it reports ready/seconds_left and no token
# values, so this script never holds a turn-state in memory at all.
# ----------------------------------------------------------------------------

class Bucket:
    def __init__(self, auth_id: str, model: str, ready: bool,
                 seconds_left: int, issued_at: int) -> None:
        self.auth_id = auth_id
        self.model = model
        self.ready = ready
        self.seconds_left = seconds_left
        # Epoch seconds, used only to tell a freshly minted token from the one
        # that was already in the bucket before we fired.
        self.issued_at = issued_at


def bucket_path(store_dir: Path, auth_id: str, model: str) -> Path:
    return store_dir / auth_id / f"{model}.json"


class Readiness:
    """Snapshot of every bucket's state, from the API or (legacy) from disk."""

    def __init__(self, buckets: dict[tuple[str, str], Bucket], source: str) -> None:
        self.buckets = buckets
        self.source = source

    def get(self, auth_id: str, model: str) -> Bucket | None:
        return self.buckets.get((auth_id, model))

    def missing(self, auths: list[str], models: list[str]) -> list[tuple[str, str]]:
        out = []
        for auth_id in auths:
            for model in models:
                bucket = self.get(auth_id, model)
                if bucket is None or not bucket.ready:
                    out.append((auth_id, model))
        return out


def readiness_from_status(doc: dict) -> Readiness:
    """Build a Readiness from the plugin status document."""
    buckets: dict[tuple[str, str], Bucket] = {}
    for item in doc.get("buckets") or []:
        if not isinstance(item, dict):
            continue
        auth_id = str(item.get("auth_id") or "").strip()
        model = str(item.get("model") or "").strip()
        if not auth_id or not model:
            continue
        buckets[(auth_id, model)] = Bucket(
            auth_id=auth_id,
            model=model,
            ready=bool(item.get("ready")),
            seconds_left=int(item.get("seconds_left") or 0),
            issued_at=parse_rfc3339(str(item.get("issued_at") or "")) or 0,
        )
    return Readiness(buckets, "management API")


def readiness_from_disk(
    store_dir: Path, auths: list[str], models: list[str], now: int
) -> Readiness:
    """Legacy fallback for an old .so with no management API.

    Only `len`, `issued_at` and `auth_id` are read; the `value` field is never
    touched, so the token stays out of this process even on this path.

    A permission error is fatal rather than "not ready": it means the files are
    root-owned and this user cannot see them, which is a deployment problem, not
    an upstream one. Saying so plainly here saves an hour of chasing the wrong
    thing.
    """
    buckets: dict[tuple[str, str], Bucket] = {}
    for auth_id in auths:
        for model in models:
            path = bucket_path(store_dir, auth_id, model)
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except PermissionError:
                die(f"cannot read {path}: permission denied.\n"
                    f"  CPA runs as root in its container, so bucket files are\n"
                    f"  root-owned 0600 under root-owned 0700 directories, and\n"
                    f"  this script is running as "
                    f"{os.environ.get('USER') or os.environ.get('USERNAME') or 'a non-root user'}.\n"
                    f"  This is NOT 'the upstream issued no 292'.\n"
                    f"  Fix by deploying the .so that serves\n"
                    f"    GET /v0/management/codex-turn-state/status\n"
                    f"  (the supported path), or re-run this script under sudo.")
            except Exception as exc:
                log(f"bucket unreadable auth={auth_id} model={model}: {exc}")
                continue

            length = int(doc.get("len") or 0)
            issued = parse_rfc3339(str(doc.get("issued_at") or "")) or 0
            if issued <= 0:
                continue
            seconds_left = max(0, (issued + TTL_SECONDS) - now)
            # auth_id comes from the file, not the path we looked under, so a
            # token CPA attributed to a different account is still catchable
            # (spec §10: 只启用一个号时写入的 auth_id 就是该号).
            recorded = str(doc.get("auth_id") or "").strip() or auth_id
            buckets[(auth_id, model)] = Bucket(
                auth_id=recorded,
                model=model,
                ready=(length == TEMPLATE_LEN and seconds_left > 0),
                seconds_left=seconds_left,
                issued_at=issued,
            )
    return Readiness(buckets, "store files (legacy fallback)")


def read_readiness(
    cpa: CPA, store_dir: Path, auths: list[str], models: list[str]
) -> Readiness:
    """Current bucket state, preferring the API and falling back only on 404."""
    doc = cpa.plugin_status()
    if doc is not None:
        return readiness_from_status(doc)
    return readiness_from_disk(store_dir, auths, models, int(time.time()))


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
        # The exit each account had before the run. None means CPA did not report
        # the field at all, so there is nothing to put back -- and nothing that
        # could be put back correctly. main() refuses to rotate proxies in that
        # case, so a None here also means no proxy was ever set by this run.
        self.original_proxy: dict[str, str | None] = {}
        self.entries: dict[str, dict] = {}
        self.armed = False
        self.restored = False

    def arm(self, auths: list[dict]) -> None:
        """Record current state and persist it before anything is mutated."""
        self.original = {str(e.get("name")): bool(e.get("disabled")) for e in auths}
        self.entries = {str(e.get("name")): e for e in auths}
        self.original_proxy = {}
        for e in auths:
            name = str(e.get("name") or "")
            got = self.cpa._read_proxy(name)
            self.original_proxy[name] = "" if got is None else got
        doc = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.cpa.base_url,
            "accounts": [
                {
                    "name": name,
                    "auth_index": str(self.entries[name].get("auth_index") or ""),
                    "disabled": disabled,
                    # Written in the clear, like the rest of this file: the
                    # snapshot is 0600 and exists precisely so a failed run can
                    # be undone by hand. A masked value would be useless for
                    # that. It is never logged -- see restore().
                    CPA.PROXY_FIELD: self.original_proxy.get(name),
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

        log("restoring original account exit and enable/disable state")
        failures = []
        # Exits first, then the enable flags. An account that ends up enabled is
        # immediately schedulable, so it must already be pointing at its own
        # original exit by then -- otherwise live traffic could briefly leave
        # through a probe proxy.
        for name, original in sorted(self.original_proxy.items()):
            if original is None:
                continue  # never snapshotted, never changed
            entry = self.entries.get(name) or {"name": name}
            try:
                self.cpa.set_proxy(entry, original, fatal=False)
            except Exception as exc:
                failures.append(f"{name}: exit not restored: {redact(str(exc))}")
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
        # Same order as StateGuard.restore: exit before enable flag, so an
        # account is never schedulable while still pointing at a probe exit.
        original_proxy = item.get(CPA.PROXY_FIELD)
        if original_proxy is not None:
            try:
                cpa.set_proxy(entry, str(original_proxy), fatal=False)
            except Exception as exc:
                failures.append(f"{item.get('name')}: exit: {redact(str(exc))}")
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
    entry: dict,
    model: str,
    proxies: list[str],
    args: argparse.Namespace,
) -> bool:
    """Fill one bucket, trying each configured exit in turn.

    Returns True as soon as the plugin reports the bucket ready. A candidate that
    times out, or that yields a degraded 312, is not an error: it means that exit
    is not in a honeymoon right now, which is exactly what the next candidate is
    for. Only a failure to *switch* the exit aborts -- see CPA.set_proxy.
    """
    auth_id = str(entry.get("name") or "")
    before = read_readiness(cpa, store_dir, [auth_id], [model]).get(auth_id, model)
    before_issued = before.issued_at if before else 0

    # With exits configured, each one gets a single request: the point of a
    # candidate list is to move on, and re-firing through an exit that just
    # produced a 312 spends quota to learn the same thing twice. With no exits
    # configured there is nothing to move on to, so the old retry behaviour on
    # the account's existing exit is what remains.
    attempts: list[str | None] = list(proxies) if proxies else [None] * max(1, args.retries)

    for index, candidate in enumerate(attempts, start=1):
        label = f"exit {index}/{len(attempts)}" if proxies else f"attempt {index}/{len(attempts)}"
        if candidate is not None:
            cpa.set_proxy(entry, candidate)
            if not cpa.dry_run and args.settle > 0:
                time.sleep(args.settle)

        status, note = cpa.fire(model, timeout=args.http_timeout)
        if cpa.dry_run:
            return True
        if status and 200 <= status < 300:
            log(f"  {label} model={model} http={status}")
        else:
            # Full body, not a summary: on the first real run this is how a
            # wrong route or payload shape gets identified. redact() strips any
            # proxy userinfo the upstream echoed back.
            log(f"  {label} model={model} http={status} body={redact(note)}")

        # Poll the plugin for its own view. HTTP status is deliberately not a
        # gate: the header rides on error responses too, and readiness is the
        # contract. Polling is per-second because each check is now an API call.
        deadline = time.time() + args.timeout
        while time.time() < deadline:
            bucket = read_readiness(cpa, store_dir, [auth_id], [model]).get(auth_id, model)
            if bucket and bucket.issued_at > before_issued:
                if bucket.ready:
                    log(f"  ready auth={auth_id} model={model}"
                        f" ttl_left={bucket.seconds_left}s")
                    return True
                # A new token landed but the plugin does not call it ready — a
                # degraded 312, which is never a template. This exit is not in a
                # honeymoon; try the next one.
                log(f"  degraded state for auth={auth_id} model={model}"
                    f" — this exit yielded no template, moving on")
                before_issued = bucket.issued_at
                break
            time.sleep(1.0)
        else:
            log(f"  timeout after {args.timeout}s waiting for a ready bucket"
                f" auth={auth_id} model={model}")

    return False


def probe_account(
    cpa: CPA,
    guard: StateGuard,
    store_dir: Path,
    entry: dict,
    models: list[str],
    proxies: list[str],
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
    try:
        current = read_readiness(cpa, store_dir, [auth_id], models)
        for model in models:
            existing = current.get(auth_id, model)
            if existing and existing.ready and not args.force:
                log(f"  skip auth={auth_id} model={model}: live template,"
                    f" {existing.seconds_left}s left")
                results[model] = True
                continue
            results[model] = probe_bucket(cpa, store_dir, entry, model, proxies, args)

            # Sanity check the spec's acceptance criterion: with one account
            # enabled, the stored bucket must belong to that account.
            written = read_readiness(cpa, store_dir, [auth_id], [model]).get(auth_id, model)
            if written and written.auth_id and written.auth_id != auth_id:
                log(f"  WARNING bucket records auth_id={written.auth_id}"
                    f" but we enabled {auth_id} — do not trust this store")
    finally:
        # This account's exit goes back before we move to the next one, so at
        # most one account is ever pointed at a probe proxy. The finally matters:
        # an abort partway through the models must not leave it behind. The
        # StateGuard would catch it on the way out, but only after every other
        # account had already been re-enabled.
        original = guard.original_proxy.get(auth_id)
        if original is not None and proxies:
            try:
                cpa.set_proxy(entry, original, fatal=False)
            except Exception as exc:
                log(f"  WARNING could not restore the exit for {auth_id}:"
                    f" {redact(str(exc))}")
    return results


def run_pass(
    cpa: CPA,
    guard: StateGuard,
    store_dir: Path,
    auths: list[dict],
    models: list[str],
    proxies: list[str],
    args: argparse.Namespace,
) -> bool:
    """One full sweep. Returns True when every target bucket is ready."""
    for entry in auths:
        probe_account(cpa, guard, store_dir, entry, models, proxies, args)

    names = [str(e.get("name")) for e in auths]
    missing = read_readiness(cpa, store_dir, names, models).missing(names, models)
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
    parser.add_argument("--once", action="store_true",
                        help="accepted for compatibility; the script always runs "
                             "exactly one sweep and then exits")
    parser.add_argument("--account", metavar="JSONNAME",
                        help="probe only this auth file name, e.g. codex-foo.json")
    parser.add_argument("--accounts", metavar="CSV",
                        help="override the configured probe_accounts for this run "
                             "only; comma-separated auth file names")
    parser.add_argument("--proxies-file", metavar="PATH",
                        help="override the configured probe_proxies for this run "
                             "only; one URL per line, blank lines and # comments "
                             "ignored. The file is read, never written, and its "
                             "contents are never logged in full")
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
                        help="host path of the plugin's store_dir. Only used by "
                             "the legacy fallback when the plugin has no "
                             "management API; readiness normally comes from the "
                             f"API (default: {DEFAULT_STORE_DIR})")
    parser.add_argument("--auths-dir", default=str(DEFAULT_AUTHS_DIR),
                        help=f"auth file directory, used as a cross-check "
                             f"(default: {DEFAULT_AUTHS_DIR})")
    parser.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT),
                        help=f"where to write the state snapshot "
                             f"(default: {DEFAULT_SNAPSHOT})")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL,
                        help=f"CPA base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--timeout", type=int, default=8,
                        help="seconds to wait for a bucket file after firing (default 8)")
    parser.add_argument("--http-timeout", type=int, default=120,
                        help="seconds to wait on the upstream request (default 120)")
    parser.add_argument("--retries", type=int, default=2,
                        help="attempts per bucket before giving up (default 2)")
    parser.add_argument("--settle", type=float, default=2.0,
                        help="seconds to wait after flipping account state, before "
                             "firing (default 2)")
    return parser


def read_proxies_file(path: Path) -> list[str]:
    """One proxy URL per line; blank lines and # comments ignored.

    Order is preserved because it is the try order. Nothing here is logged: the
    caller masks before printing, and a parse error names the line number rather
    than quoting the line, which would defeat the masking entirely.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        die(f"cannot read {path}: {exc}")
    out: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            die(f"{path}:{lineno}: not a URL (no scheme). "
                f"The line is not quoted here on purpose — it may be a password.")
        out.append(line)
    if not out:
        die(f"{path} contains no proxy URLs")
    return out


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

    if not cpa.healthy():
        die("CPA is not answering on /healthz; refusing to touch account state")

    # Pre-flight the plugin before touching any account state. In `business`
    # role the plugin harvests nothing, so a probe run would disable four
    # accounts, spend quota on 25 requests and come back with an empty store.
    # Failing here costs nothing; failing at the end costs a probe window.
    status = cpa.plugin_status()
    if status is None:
        log("note: no codex-turn-state management API (404) — the loaded .so"
            " predates it. Falling back to reading store files directly, which"
            " requires this user to be able to read them.")
        log(f"note: fallback will read {args.store_dir}")
    else:
        role = str(status.get("role") or "").strip().lower()
        log(f"plugin: role={role or '(unset)'} dry_run={status.get('dry_run')}"
            f" inject_mode={status.get('inject_mode')}"
            f" store_dir={status.get('store_dir')}")
        if role != "probe":
            die(f"plugin role is {role or '(unset)'}, not 'probe'.\n"
                f"  A probe run in this role harvests nothing: only role=probe\n"
                f"  intercepts upstream responses and writes the store.\n"
                f"  Set role: probe in plugins.configs.codex-turn-state and let\n"
                f"  CPA reload before re-running. Refusing to touch account\n"
                f"  state or spend quota.")
    # ---- probe scope ----------------------------------------------------
    #
    # The scope comes from the plugin's own config, so the dashboard and this
    # script cannot disagree about what "complete" means. There is deliberately
    # no fallback to a built-in list: probing is a stop-the-world operation that
    # spends quota per bucket, and defaulting to everything when the operator
    # has selected nothing is the one mistake that cannot be undone afterwards.
    config = cpa.plugin_config() or {}
    scope_accounts = [str(a).strip() for a in (config.get("probe_accounts") or []) if str(a).strip()]
    scope_models = [str(m).strip()
                    for m in (config.get("models") or (status or {}).get("models") or [])
                    if str(m).strip()]
    scope_proxies = [str(p).strip() for p in (config.get("probe_proxies") or []) if str(p).strip()]

    if args.accounts:
        scope_accounts = [a.strip() for a in args.accounts.split(",") if a.strip()]
    if args.account:
        scope_accounts = [args.account]
    if args.models:
        scope_models = [m.strip() for m in args.models.split(",") if m.strip()]
    if args.model:
        scope_models = [args.model]
    if args.proxies_file:
        scope_proxies = read_proxies_file(Path(args.proxies_file))

    if not scope_accounts:
        die("no probe accounts selected.\n"
            "  Set probe_accounts in plugins.configs.codex-turn-state (the\n"
            "  dashboard's 探测范围 section writes it), or pass --accounts.\n"
            "  Refusing to probe every account by default: each bucket costs an\n"
            "  upstream request, and this run disables every account it is not\n"
            "  currently probing.")
    if not scope_models:
        die("no probe models selected.\n"
            "  Set models in plugins.configs.codex-turn-state, or pass --models.\n"
            "  Refusing to fall back to the full model list for the same reason.")

    models = scope_models
    if status is not None:
        plugin_models = [str(m) for m in (status.get("models") or [])]
        if plugin_models:
            unknown = [m for m in models if m not in plugin_models]
            if unknown:
                log(f"note: {unknown} not in the plugin's configured model list"
                    f" {plugin_models}")

    auths = cpa.list_codex_auths()
    if not auths:
        die("no Codex auth files reported by CPA")
    cross_check_disk(auths, Path(args.auths_dir))

    known_names = {str(e.get("name")) for e in auths}
    unknown_accounts = [name for name in scope_accounts if name not in known_names]
    if unknown_accounts:
        die(f"these selected accounts are not among CPA's Codex auth files: "
            f"{unknown_accounts}\n"
            f"  CPA knows: {sorted(known_names)}\n"
            f"  Fix the selection rather than letting the run quietly cover less\n"
            f"  than was asked for.")
    auths = [e for e in auths if str(e.get("name")) in set(scope_accounts)]

    # Rotation is gated on being able to read the field back. Without that there
    # is no way to tell a working PATCH from one CPA ignored, and -- worse -- no
    # way to record what an account's exit was before the run, so no way to put
    # it back. Failing here costs nothing; discovering it mid-run costs the
    # window and can leave an account pointing at a probe proxy.
    if scope_proxies and not args.dry_run:
        if not cpa.proxy_field_is_readable():
            log("warning: auth-file download could not confirm proxy_url; "
                "will still rotate and restore to empty (global proxy-url)")

    log(f"store_dir={store_dir}")
    log(f"accounts={[str(e.get('name')) for e in auths]}")
    log(f"models={models}")
    # Count and masks only. The list may carry credentials, and this line is the
    # first thing pasted into a ticket when a run goes wrong.
    log(f"exits={len(scope_proxies)}"
        + (f" {[mask_proxy(p) for p in scope_proxies]}" if scope_proxies else " (using each account's existing exit)"))
    log(f"targets={len(auths) * len(models)} buckets")
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

    complete = False
    try:
        log("--- sweep 1 ---")
        complete = run_pass(cpa, guard, store_dir, auths, models, scope_proxies, args)
        if complete:
            log("every target bucket holds a live 292")
        else:
            log("sweep finished; some buckets are still missing")
    finally:
        guard.restore()

    if args.dry_run:
        return 0
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
