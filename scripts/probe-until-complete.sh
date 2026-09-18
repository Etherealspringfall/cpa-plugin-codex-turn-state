#!/usr/bin/env bash
#
# probe-until-complete.sh — run the harvest probe until every target bucket
# holds a live 292, then exit 0. Non-zero means the store is NOT complete and
# business must stay closed (spec §9 step 10: 缺桶不要开业务).
#
# This is the gate DEPLOY.md calls between "probe phase" and "open business".
# It is a thin wrapper: every flag probe.py accepts can be passed through, e.g.
#
#   ./probe-until-complete.sh --accounts codex-foo.json,codex-bar.json
#   ./probe-until-complete.sh --account codex-foo.json
#   ./probe-until-complete.sh --dry-run
#
# SCOPE
#   "Every target bucket" means probe_accounts × models as configured in
#   plugins.configs.codex-turn-state -- NOT a fixed 5x5 matrix. probe.py reads
#   that scope from the plugin itself, so this gate and the dashboard cannot
#   disagree about what complete means. An empty selection makes probe.py exit
#   non-zero without probing anything, rather than defaulting to everything.
#
# SIDE EFFECTS
#   Inherited from probe.py: it disables every Codex account except the one
#   being probed, restores each account's exit and enable flag on the way out
#   (including on Ctrl-C), and spends one upstream request per bucket per exit
#   tried. Business traffic must already be stopped before running this.
#
# ENVIRONMENT
#   CPA_MANAGEMENT_KEY  (required)  Bearer token for /v0/management/*
#   CPA_API_KEY         (required)  Bearer token for /v1/responses
#
# Neither key is read from or written to a file here; both must be exported by
# the caller so they never land in shell history or on disk.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${CPA_MANAGEMENT_KEY:-}" ]]; then
	echo "probe-until-complete: CPA_MANAGEMENT_KEY is not set" >&2
	echo "  read -rs CPA_MANAGEMENT_KEY && export CPA_MANAGEMENT_KEY" >&2
	exit 2
fi

if [[ -z "${CPA_API_KEY:-}" ]]; then
	echo "probe-until-complete: CPA_API_KEY is not set" >&2
	echo "  (this is a different key from CPA_MANAGEMENT_KEY)" >&2
	exit 2
fi

exec python3 "${script_dir}/probe.py" --until-complete "$@"
