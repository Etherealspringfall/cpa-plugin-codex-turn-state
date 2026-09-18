// Management API for the codex-turn-state plugin.
//
// This plugin is deployed keyless by the operator's explicit, repeated choice:
// opening the dashboard and every action on it work with no management key. The
// box binds CPA to 127.0.0.1 and is reachable only through an SSH tunnel, so
// "keyless" means "anyone who can reach the tunnel", which in practice is the
// operator. That decision is what shapes the two route kinds below.
//
//   - Everything the dashboard uses -- the HTML shell, the status document, and
//     every action it offers (dry_run, role, clear, selftest, scope save, probe
//     start and probe cancel) -- is a ResourceRoute.
//     Those are served under /v0/resource/plugins/<id>/ and the host does NOT
//     authenticate them ("Resource requests are not management-authenticated" --
//     pluginapi). The host also hard-restricts them to GET (ServeResourceHTTP
//     rejects any other method) and passes the query string but no body, so the
//     action routes read their parameters from the query and guard against an
//     accidental firing with confirm=1 rather than with a key.
//
//   - The same clear and selftest operations are ALSO exposed as authenticated
//     ManagementRoutes under /v0/management/ (POST, reading a JSON body), for a
//     script that holds the management key. Those are not what the dashboard
//     calls; they are the keyed API path kept alongside the keyless one. Their
//     Menu field is left empty: a GET route that declares one is re-registered
//     under the resource prefix (routeDeclaresLegacyMenuResource in the host),
//     which would matter only for a GET, but the rule is kept in view here.
//
// No response from any route in this file contains a template value. The store
// holds credential-adjacent secrets; the dashboard needs readiness and expiry,
// and readiness and expiry are all it gets. The status document does expose each
// bucket's auth_id, which is the credential filename and contains the customer
// email -- an accepted consequence of an anonymously readable status.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

//go:embed ui.html
var dashboardHTML []byte

// Route suffixes. The host hands back a path that may be absolute or relative
// depending on how it resolved the registration, so dispatch matches on the
// suffix rather than on equality.
const (
	routeStatus       = "/codex-turn-state/status"
	routeBucketsClear = "/codex-turn-state/buckets/clear"
	// Named selftest, not probe: it cannot harvest, and sharing a name with
	// scripts/probe.py would invite exactly the wrong conclusion from a green
	// result. See selftestNote.
	routeSelftest = "/codex-turn-state/selftest"
	// routeDashboard is relative to the plugin's own resource prefix, so the
	// browser-facing URL is /v0/resource/plugins/codex-turn-state/dashboard.
	routeDashboard = "/dashboard"
	// routeStatusResource is the unauthenticated, resource-prefix alias of the
	// status route: /v0/resource/plugins/codex-turn-state/status. Its resolved
	// path ends in the same /codex-turn-state/status suffix routeStatus matches
	// on, so both dispatch to handleStatus with no extra case. It exists so the
	// dashboard can render on open, before the operator has entered any key.
	routeStatusResource = "/status"
	// routeConfig returns the configuration verbatim. The dashboard no longer
	// needs it -- the status document carries the proxy list in the clear now --
	// but it stays exactly where it is, behind the management key and with no
	// resource alias, because "the config, verbatim" is the shape any future
	// secret lands in by default. probe_api_key and probe_management_key are
	// already two such secrets, and neither is in configResponse for precisely
	// that reason. An alias here would publish whatever this route grows next,
	// with no error and no log line.
	routeConfig = "/codex-turn-state/config"

	// The keyless action routes. These are ResourceRoutes, so the host serves
	// them without a management key and restricts them to GET (see the package
	// comment). They exist because the operator chose keyless operation: the four
	// actions the dashboard offers -- flip dry_run, switch role, clear buckets,
	// run a self-test -- carry no secret, so exposing them anonymously leaks
	// nothing the anonymous status did not already. The proxy editor is
	// deliberately NOT among them: it reads and writes proxy userinfo, and that
	// stays behind routeConfig and CPA's authenticated config PATCH.
	//
	// They are GET routes that change state, so each requires confirm=1 -- not as
	// authentication, but so a bare navigation, a link prefetch or a crawler
	// cannot fire one just by loading the URL. The suffixes carry an /ops/ segment
	// so they cannot collide with the /buckets/clear or /selftest management
	// routes under suffix matching.
	routeOpsDryRun   = "/ops/dry-run"
	routeOpsRole     = "/ops/role"
	routeOpsClear    = "/ops/clear"
	routeOpsSelftest = "/ops/selftest"
	// routeOpsScope saves the probe scope, keyless like the rest of /ops.
	//
	// It writes the plugin's own scope file rather than CPA's config.yaml,
	// because the host offers no way for a plugin to persist its configuration
	// and the route that would (PATCH /v0/management/plugins/<id>/config) is
	// authenticated -- a key in front of the one screen that must not need one.
	routeOpsScope = "/ops/scope"
	// The probe runner's two controls, keyless like the rest of /ops and for the
	// same reason: the whole point of running a probe from the dashboard is that
	// nobody has to type a key to do it. The bearers the run itself needs come
	// from probe_api_key and probe_management_key in the config, which is why
	// neither route takes one and why neither response can ever echo one.
	//
	// Being in the resource list is deliberate, not incidental. A GET management
	// route that declares a Menu is silently re-registered under the
	// unauthenticated resource prefix (routeDeclaresLegacyMenuResource in the
	// host), which is how a route ends up keyless by accident; these are keyless
	// by choice, declared where keyless routes belong.
	//
	// Start spends real quota and cancel stops a run in flight, so both go through
	// handleOpsResource and both require confirm=1.
	routeOpsProbeStart  = "/ops/probe/start"
	routeOpsProbeCancel = "/ops/probe/cancel"
)

// managementRegister answers management.register with the route table.
func managementRegister(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRegistrationRequest
	if len(raw) > 0 {
		// A malformed registration request is not worth failing over: the paths
		// below are fixed, and the host resolves relative ones itself.
		_ = json.Unmarshal(raw, &req)
	}

	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: routeStatus},
			{Method: http.MethodPost, Path: routeBucketsClear},
			{Method: http.MethodPost, Path: routeSelftest},
			// No Menu, like every other data route here. A GET route that
			// declares one is re-registered under the unauthenticated resource
			// prefix (routeDeclaresLegacyMenuResource in the host), which on this
			// route specifically would publish the proxy passwords.
			{Method: http.MethodGet, Path: routeConfig},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				// Not "/". normalizeResourceRoute trims trailing slashes and
				// rejects the empty result, so registering the plugin root
				// drops the route with no log line -- the only symptom is a
				// 404 at request time, long after the registration that
				// silently discarded it.
				Path:        routeDashboard,
				Menu:        "Codex Turn-State",
				Description: "探测/业务状态看板：桶就绪度、角色、dry_run",
			},
			{
				// Read-only status, unauthenticated by virtue of the resource
				// prefix. No Menu: it is data the dashboard fetches, not a page
				// to navigate to, and it must not be confused with routeDashboard.
				//
				// Privacy note for anyone about to expose port 8317: this makes
				// the status document anonymously readable, and each bucket's
				// auth_id is the credential filename, which contains the customer
				// email. That is the user's informed choice (they asked for a
				// no-login page).
				Path:        routeStatusResource,
				Description: "只读状态（无需鉴权），供看板拉取",
			},
			// The keyless actions. Unauthenticated by virtue of the resource
			// prefix, GET-only by the host's rule, guarded by confirm=1 rather than
			// by a key. None of them echoes probe_api_key or probe_management_key,
			// which are the only values on this plugin that are never displayed at
			// all. No Menu: the dashboard fires these with fetch, they are not
			// pages to navigate to.
			{Path: routeOpsDryRun, Description: "翻转 dry_run（无需鉴权，需 confirm=1）"},
			{Path: routeOpsRole, Description: "切换 role（无需鉴权，需 confirm=1）"},
			{Path: routeOpsClear, Description: "清空桶（无需鉴权，需 confirm=1）"},
			{Path: routeOpsSelftest, Description: "连通性自检（无需鉴权，需 confirm=1，烧额度）"},
			// Saving the scope is keyless like the other four, and so is reading
			// the proxy list back: the status document now carries it in the
			// clear (see statusResponse), at the operator's explicit instruction,
			// because the write-only masked editor meant retyping every password
			// on every scope edit. routeConfig stays behind the key regardless --
			// see the comment there.
			{Path: routeOpsScope, Description: "保存探测范围（无需鉴权，需 confirm=1）"},
			// The probe runner's controls. Keyless and confirm=1 guarded like the
			// rest of /ops; the run authenticates with the configured probe keys,
			// so the operator never supplies one.
			{Path: routeOpsProbeStart, Description: "启动探测运行（无需鉴权，需 confirm=1，烧额度）"},
			{Path: routeOpsProbeCancel, Description: "取消探测运行（无需鉴权，需 confirm=1）"},
		},
	})
}

// managementHandle dispatches one management or resource request.
func managementHandle(raw []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return okEnvelope(managementError(http.StatusBadRequest, "could not decode the management request"))
	}

	path := strings.TrimRight(strings.TrimSpace(req.Path), "/")
	method := strings.ToUpper(strings.TrimSpace(req.Method))

	switch {
	case hasRouteSuffix(path, routeStatus):
		if method != http.MethodGet && method != "" {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "status is a GET route"))
		}
		return okEnvelope(handleStatus())
	case hasRouteSuffix(path, routeConfig):
		if method != http.MethodGet && method != "" {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "config is a GET route"))
		}
		// The one route that is NOT keyless. Everything the dashboard does works
		// without a key, this route included -- the page stopped calling it when
		// the status document started carrying the proxy list in the clear -- but
		// it keeps its key because it returns the configuration verbatim, which is
		// where the two probe bearers would surface if they were ever added to
		// configResponse.
		//
		// The resource prefix is the unauthenticated one, so a request arriving
		// through it means an alias was registered somewhere it should not have
		// been. The passwords stop here rather than being served.
		if isResourcePath(path) {
			return okEnvelope(managementError(http.StatusNotFound, "no such codex-turn-state route: "+req.Path))
		}
		return okEnvelope(handleConfig())
	case hasRouteSuffix(path, routeBucketsClear):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "buckets/clear is a POST route"))
		}
		return okEnvelope(handleBucketsClear(req.Body))
	case hasRouteSuffix(path, routeSelftest):
		if method != http.MethodPost {
			return okEnvelope(managementError(http.StatusMethodNotAllowed, "selftest is a POST route"))
		}
		return okEnvelope(handleSelftest(req.Body))
	case hasRouteSuffix(path, routeOpsDryRun),
		hasRouteSuffix(path, routeOpsRole),
		hasRouteSuffix(path, routeOpsClear),
		hasRouteSuffix(path, routeOpsSelftest),
		hasRouteSuffix(path, routeOpsScope),
		hasRouteSuffix(path, routeOpsProbeStart),
		hasRouteSuffix(path, routeOpsProbeCancel):
		// The keyless actions. Reached only through the resource prefix (they are
		// registered as resources, not management routes), so they arrive with a
		// query and no body and no key; handleOpsResource enforces GET and
		// confirm=1 before doing anything.
		return okEnvelope(handleOpsResource(path, method, req.Query))
	case isDashboardPath(path):
		return okEnvelope(handleDashboard())
	default:
		return okEnvelope(managementError(http.StatusNotFound, "no such codex-turn-state route: "+req.Path))
	}
}

// hasRouteSuffix matches a resolved path against a registered suffix. The host
// may present "/codex-turn-state/status" or the full
// "/v0/management/codex-turn-state/status"; both must land on the same handler.
func hasRouteSuffix(path, suffix string) bool {
	return strings.EqualFold(path, suffix) || strings.HasSuffix(strings.ToLower(path), strings.ToLower(suffix))
}

// isDashboardPath recognises the resource root, and only that. Matching on the
// plugin id alone would also catch /v0/management/codex-turn-state, which would
// serve the HTML shell from the authenticated management prefix -- harmless in
// itself, but it turns every mistyped management path into a 200 and hides the
// typo. The resource prefix is what distinguishes the browser-navigable route.
func isDashboardPath(path string) bool {
	return isResourcePath(path)
}

// isResourcePath reports whether a resolved path came in through the host's
// resource prefix, which is the unauthenticated one ("Resource requests are not
// management-authenticated" -- pluginapi). It is the only signal this handler
// has about whether a key was required, so any route that must never answer
// anonymously checks it.
func isResourcePath(path string) bool {
	return strings.Contains(strings.ToLower(path), "/resource/plugins/")
}

// handleDashboard serves the shell. It is deliberately data-free -- see the
// package comment for why that is not an oversight.
func handleDashboard() pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
			// The shell embeds a build of the dashboard; a cached copy after an
			// upgrade would show an old page against a new API.
			"Cache-Control": []string{"no-store"},
			// Nothing here is meant to be framed or sniffed.
			"X-Content-Type-Options": []string{"nosniff"},
		},
		Body: dashboardHTML,
	}
}

// handleOpsResource dispatches the keyless actions. It is reached only
// through the resource prefix, so it has no key to check; instead it enforces the
// two things that make a keyless GET action safe enough for a localhost-only
// dashboard: the method really is GET, and confirm=1 is present so nothing fires
// from a bare navigation, a link prefetch or a crawler. Everything past this
// point changes state or spends quota.
func handleOpsResource(path, method string, q url.Values) pluginapi.ManagementResponse {
	if method != http.MethodGet && method != "" {
		return managementError(http.StatusMethodNotAllowed, "keyless action routes are GET-only")
	}
	if strings.TrimSpace(q.Get("confirm")) != "1" {
		return managementError(http.StatusBadRequest,
			"this action changes state or spends quota; it requires confirm=1 so it cannot fire from a bare navigation or a prefetch")
	}
	switch {
	case hasRouteSuffix(path, routeOpsDryRun):
		return handleDryRunResource(q)
	case hasRouteSuffix(path, routeOpsRole):
		return handleRoleResource(q)
	case hasRouteSuffix(path, routeOpsClear):
		return clearBuckets(clearRequestFromQuery(q))
	case hasRouteSuffix(path, routeOpsSelftest):
		return runSelftest(selftestRequestFromQuery(q))
	case hasRouteSuffix(path, routeOpsScope):
		return handleScopeSave(q)
	case hasRouteSuffix(path, routeOpsProbeStart):
		return handleProbeStartResource()
	case hasRouteSuffix(path, routeOpsProbeCancel):
		return handleProbeCancelResource()
	default:
		return managementError(http.StatusNotFound, "no such keyless action route")
	}
}

// handleProbeStartResource starts a probe run and answers with the run's state.
//
// A start that fails because a run is already in flight is a 409, not a 400: the
// request was well formed and the caller has nothing to fix, which is exactly
// what a browser refresh or a double click produces, and 400 would send the
// dashboard to the "your request is wrong" branch for something that is merely
// "already happening".
//
// Which of the two it was is decided from the runner's own state rather than by
// matching words in the error message. Message text is not a contract; a reword
// on the runner's side would silently start returning 400 for a running probe,
// and nothing would fail until an operator wondered why the page was complaining.
// The narrow cost is that a run finishing between the failed start and this
// snapshot reports 400 -- with the runner's own message attached either way.
func handleProbeStartResource() pluginapi.ManagementResponse {
	if errStart := probeRunStart(); errStart != nil {
		status := http.StatusBadRequest
		if probeRunSnapshot().Running {
			status = http.StatusConflict
		}
		return managementError(status, errStart.Error())
	}
	// Freshly taken rather than assumed: the run is already going, so this is the
	// first progress the page can show, and inventing a zeroed "about to start"
	// state would be a claim about something we did not look at.
	return jsonResponse(http.StatusOK, probeRunSnapshot())
}

// probeCancelResponse reports whether a cancel actually stopped anything, with
// the resulting run state alongside. The two are separate answers: "there was
// nothing to cancel" and "a run was cancelled" both end with a stopped runner,
// and a page that only saw the end state could not tell the operator which of the
// two their click did. The field is named probe_run to match the status document,
// so one decoder reads both.
type probeCancelResponse struct {
	Cancelled bool          `json:"cancelled"`
	ProbeRun  probeRunState `json:"probe_run"`
}

// handleProbeCancelResource asks the runner to stop. Cancelling when nothing is
// running is not an error -- it is the state the caller wanted -- so it answers
// 200 with cancelled=false rather than a 404 the dashboard would have to special
// case.
func handleProbeCancelResource() pluginapi.ManagementResponse {
	cancelled := probeRunCancel()
	return jsonResponse(http.StatusOK, probeCancelResponse{
		Cancelled: cancelled,
		ProbeRun:  probeRunSnapshot(),
	})
}

// clearRequestFromQuery builds a clearRequest from the keyless clear route's
// query: ?all=1 to wipe, or ?auth_id=..&model=.. for one bucket. clearBuckets
// then applies the same validation and path-sanitising the POST route gets, so a
// crafted auth_id cannot escape the store on this path either.
func clearRequestFromQuery(q url.Values) clearRequest {
	return clearRequest{
		AuthID: strings.TrimSpace(q.Get("auth_id")),
		Model:  strings.TrimSpace(q.Get("model")),
		All:    queryTrue(q.Get("all")),
	}
}

// selftestRequestFromQuery builds a selftestRequest from the keyless selftest
// route's query: ?model=..&auth_id=.. with auth_id optional.
func selftestRequestFromQuery(q url.Values) selftestRequest {
	return selftestRequest{
		Model:  strings.TrimSpace(q.Get("model")),
		AuthID: strings.TrimSpace(q.Get("auth_id")),
	}
}

// handleDryRunResource flips dry_run from the keyless route and persists it so a
// CPA restart keeps the operator's choice (see runtimeOverride in main.go). A
// dry_run change does not invalidate templates, so swapConfigLocked leaves the
// cache and the tallies alone; it is used only so there is one place that swaps
// the running config.
func handleDryRunResource(q url.Values) pluginapi.ManagementResponse {
	value, ok := parseBoolParam(q.Get("value"))
	if !ok {
		return managementError(http.StatusBadRequest, `"value" must be one of on/off/true/false/1/0`)
	}
	state.mu.Lock()
	cfg := state.config
	cfg.DryRun = value
	swapConfigLocked(cfg)
	dir := cfg.StoreDir
	role := cfg.Role
	state.mu.Unlock()

	persisted := true
	warning := ""
	if err := writeRuntimeOverride(dir, role, value); err != nil {
		// The in-process change already took effect; only persistence failed, so a
		// restart would revert it. Say so rather than report a clean success.
		persisted = false
		warning = "restart will revert: " + err.Error()
		log.Printf(logPrefix+"dry_run set to %t but persisting the override failed: %v", value, err)
	} else {
		log.Printf(logPrefix+"dry_run set to %t via dashboard (keyless)", value)
	}
	return jsonResponse(http.StatusOK, map[string]any{"dry_run": value, "persisted": persisted, "warning": warning})
}

// handleRoleResource switches role from the keyless route and persists it. A role
// change clears the template cache and resets the tallies (swapConfigLocked),
// exactly as a config-file role change does; persisting it is what lets the
// switch survive the CPA restart a role change may need to renegotiate its hooks.
func handleRoleResource(q url.Values) pluginapi.ManagementResponse {
	role := strings.ToLower(strings.TrimSpace(q.Get("value")))
	if role != roleProbe && role != roleBusiness {
		return managementError(http.StatusBadRequest,
			fmt.Sprintf(`"value" must be %q or %q`, roleProbe, roleBusiness))
	}
	state.mu.Lock()
	cfg := state.config
	if role == roleProbe && strings.TrimSpace(cfg.StoreDir) == "" {
		state.mu.Unlock()
		return managementError(http.StatusConflict, "role probe requires store_dir, which is not configured")
	}
	cfg.Role = role
	// Harvesting from business traffic is prohibited; mirror configure's guard so
	// the keyless path cannot leave business with harvest_inband on.
	if role == roleBusiness {
		cfg.HarvestInband = false
	}
	swapConfigLocked(cfg)
	dir := cfg.StoreDir
	dryRun := cfg.DryRun
	state.mu.Unlock()

	persisted := true
	warning := ""
	if err := writeRuntimeOverride(dir, role, dryRun); err != nil {
		persisted = false
		warning = "restart will revert: " + err.Error()
		log.Printf(logPrefix+"role set to %s but persisting the override failed: %v", role, err)
	} else {
		log.Printf(logPrefix+"role set to %s via dashboard (keyless)", role)
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"role":      role,
		"persisted": persisted,
		"warning":   warning,
		"note":      "若切换后发现钩子没被重新协商（probe 采不到 / business 不替换），重启一次 CPA。",
	})
}

// queryTrue reads a query flag as a boolean, treating the common truthy spellings
// as true and everything else -- including absence -- as false. Used for ?all=.
func queryTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// parseBoolParam reads an explicit boolean value and reports whether it was
// recognised, so a dry_run toggle can reject a typo (ok=false) rather than
// silently reading it as off.
func parseBoolParam(v string) (value bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true, true
	case "0", "false", "off", "no":
		return false, true
	}
	return false, false
}

// statusBucket is one (account, model) cell of the readiness matrix.
type statusBucket struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	Ready  bool   `json:"ready"`
	// Len is the length recorded in the bucket file, or 0 when no file exists.
	// It is reported as found rather than assumed: writeStoreRecord refuses
	// anything but a template length, so in principle only 292 can be on disk,
	// but hard-coding that would blind the probe to the one case it most needs
	// to tell apart. "harvested a degraded 312" means the path works and the
	// exit IP is wrong; "nothing on disk" means the path is broken. Both look
	// like ready=false, and they call for opposite next steps.
	Len       int    `json:"len"`
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	// Enabled is the credential's state, repeated on every cell of its row so
	// the page can grey a row out without a second lookup. A disabled account is
	// still listed: dropping the row during a probe would make a bucket look
	// lost rather than merely unreachable, and "not harvested because the
	// account is off" is a different finding from "not harvested".
	//
	// When accounts_source is "store" this is not authoritative -- the credential
	// list was unavailable, so it is reported true rather than inventing a
	// disabled state nobody observed.
	Enabled bool `json:"enabled"`
	// Attribution is "observed" when the host named the account, "inferred" when
	// it was deduced from a sole enabled account during probing, and empty for
	// a bucket written before the field existed. Surfaced so an operator can
	// audit which buckets rest on a deduction rather than on what CPA reported.
	Attribution string `json:"attribution"`
	SecondsLeft int64  `json:"seconds_left"`
}

type statusResponse struct {
	Role           string         `json:"role"`
	DryRun         bool           `json:"dry_run"`
	InjectMode     string         `json:"inject_mode"`
	TTLSeconds     int            `json:"ttl_seconds"`
	TemplateLength int            `json:"template_length"`
	ReplaceLength  int            `json:"replace_length"`
	StoreDir       string         `json:"store_dir"`
	Models         []string       `json:"models"`
	Buckets        []statusBucket `json:"buckets"`
	TargetsTotal   int            `json:"targets_total"`
	TargetsReady   int            `json:"targets_ready"`
	// AccountsSource is "host" when the credential list came from
	// host.auth.list, and "store" when that was unavailable and the accounts
	// were inferred from whatever the store already holds. The difference
	// matters: under "store" a never-probed account is invisible, so an empty
	// matrix means "we could not ask", not "there is nothing to probe".
	AccountsSource string           `json:"accounts_source"`
	AccountsError  string           `json:"accounts_error,omitempty"`
	Counters       decisionCounters `json:"counters"`
	CountersSince  string           `json:"counters_since"`
	GeneratedAt    string           `json:"generated_at"`
	StoreError     string           `json:"store_error,omitempty"`

	// ---- probe scope ----
	//
	// EVERY FIELD BELOW IS ANONYMOUSLY READABLE. This struct is serialised by
	// handleStatus, which answers on both /v0/management/codex-turn-state/status
	// and the unauthenticated /v0/resource/plugins/codex-turn-state/status. There
	// is no per-route filtering: whatever is added here is public.
	//
	// probe_proxies used to appear here only as a count and a masked list. It no
	// longer does, and the honest record of why:
	//
	//   - The operator asked for it, explicitly, after the masked field made the
	//     editor unusable. A textarea seeded with "socks5h://***@exit:1080" can
	//     only be saved by retyping every entry, so every scope edit cost the
	//     whole proxy list -- which is what they were told to do, and refused.
	//   - It is their system and their call. This comment records the change, not
	//     an argument about it.
	//   - The blast radius is "already on the box": CPA binds to 127.0.0.1 and is
	//     reached through an SSH tunnel, so the reader of this document is someone
	//     who could read config.yaml anyway.
	//
	// What that does NOT mean: this list is now readable by anything that can
	// reach the plugin, keyless, including any other process on the host. Masking
	// therefore stays everywhere else -- every log line and every configErrors
	// complaint still goes through maskProxyURL, because a log is copied into
	// tickets and chat windows and a status fetch is not.
	//
	// The rest of the rule is unchanged and is the part to keep: anything added
	// here is public. probe_api_key and probe_management_key are consequently NOT
	// here in any form, not even a masked one.
	ProbeAccounts   []string `json:"probe_accounts"`
	ProbeProxyCount int      `json:"probe_proxy_count"`
	// ProbeProxies is plaintext, at the operator's explicit instruction. See
	// above.
	ProbeProxies []string `json:"probe_proxies"`
	// ConfigErrors lists probe-scope entries that were rejected at configure
	// time. They are not fatal, which is exactly why they need to be visible:
	// the scope silently covers less than whoever edited it believes.
	ConfigErrors []string `json:"config_errors,omitempty"`
	// ProbeRun is the in-plugin probe runner's live progress, so the dashboard can
	// poll one document instead of two. Anonymously readable like everything else
	// here, which is the constraint on what the runner may put in Lines: progress
	// and outcomes, never a key and never a template value.
	ProbeRun probeRunState `json:"probe_run"`
}

// statusAccount is one credential row of the readiness matrix.
type statusAccount struct {
	AuthID  string
	Enabled bool
}

// handleStatus reports configuration, bucket readiness and decision tallies.
//
// Reachable both authenticated (/v0/management/...) and anonymously
// (/v0/resource/plugins/codex-turn-state/status); see managementRegister for
// why the anonymous alias exists and what it exposes. It stays strictly
// read-only, and it never emits a template value -- only lengths, readiness and
// timestamps -- so anonymous read is bounded to that.
func handleStatus() pluginapi.ManagementResponse {
	now := time.Now()

	state.mu.Lock()
	cfg := state.config
	counts := state.counts
	countsAt := state.countsAt
	configErrors := append([]string(nil), state.configErrors...)
	state.mu.Unlock()

	out := statusResponse{
		Role:           cfg.Role,
		DryRun:         cfg.DryRun,
		InjectMode:     cfg.InjectMode,
		TTLSeconds:     cfg.TTLSeconds,
		TemplateLength: cfg.TemplateLength,
		ReplaceLength:  cfg.ReplaceLength,
		StoreDir:       cfg.StoreDir,
		Models:         append([]string(nil), cfg.Models...),
		Counters:       counts,
		CountersSince:  countsAt.UTC().Format(time.RFC3339),
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		Buckets:        []statusBucket{},
		ProbeAccounts:  append([]string(nil), cfg.ProbeAccounts...),
		// Plaintext, at the operator's explicit instruction -- see the comment on
		// the field. The count stays alongside it because the page reads it
		// without having to count a list it may be rendering lazily.
		ProbeProxyCount: len(cfg.ProbeProxies),
		ProbeProxies:    append([]string(nil), cfg.ProbeProxies...),
		ConfigErrors:    configErrors,
		// Taken outside state.mu on purpose: the runner keeps its own lock, and
		// reaching for it while holding this one is how two locks become a
		// deadlock. Nothing above needs the two views to be consistent with each
		// other.
		ProbeRun: probeRunSnapshot(),
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	// [] rather than null: the page assigns this straight into its editor, and a
	// null would render as the string "null" in the textarea.
	if out.ProbeProxies == nil {
		out.ProbeProxies = []string{}
	}

	records, errScan := scanStoreRecords(cfg.StoreDir)
	if errScan != nil {
		// A store that cannot be read is worth surfacing rather than rendering as
		// "no buckets ready", which looks identical to a probe that never ran.
		// The matrix is still built below from the credential list: every cell
		// reads not-ready, which is the truth -- nothing in an unreadable store
		// can be used -- and the operator keeps the account list to act on.
		out.StoreError = errScan.Error()
		records = nil
	}

	ttl := cfg.ttl()
	onDisk := make(map[string]storeRecord, len(records))
	for _, rec := range records {
		onDisk[bucketKey(rec.AuthID, rec.Model)] = rec
	}

	// The matrix is the set of buckets we intend to fill, not the set already
	// filled. Deriving the accounts from the store alone would make the page
	// emptiest at the moment it matters most -- straight after a deploy, when
	// nothing has been harvested and the operator needs to see "0 of 25" and
	// pick an account to self-test against.
	accounts, accountsSource, errAccounts := statusAccounts(records)
	out.AccountsSource = accountsSource
	if errAccounts != nil {
		// Degraded, not failed: the store-derived matrix is still worth showing.
		// Saying so beats the silent empty array this replaced.
		out.AccountsError = errAccounts.Error()
	}
	// A configured probe scope replaces the rows rather than filtering them. The
	// two differ for an account that is in the scope but that the host did not
	// report: filtering would drop it, and the operator would see a smaller
	// matrix than the scope they saved with nothing saying why. Keeping the row
	// and marking it not-enabled states the problem instead.
	//
	// The enabled flag still comes from the host wherever the host knows the
	// account, so a scoped row greys out for the same reason an unscoped one
	// does.
	if len(cfg.ProbeAccounts) > 0 {
		known := make(map[string]bool, len(accounts))
		for _, account := range accounts {
			known[account.AuthID] = account.Enabled
		}
		scoped := make([]statusAccount, 0, len(cfg.ProbeAccounts))
		for _, name := range cfg.ProbeAccounts {
			enabled, seen := known[name]
			// Unknown to the host means unreachable right now, which is what
			// enabled=false means everywhere else on this page.
			scoped = append(scoped, statusAccount{AuthID: name, Enabled: seen && enabled})
		}
		accounts = scoped
	}

	models := out.Models
	if len(models) == 0 {
		// No configured list: fall back to whatever the store knows about, so the
		// page is still useful before models is filled in.
		modelSeen := make(map[string]bool)
		for _, rec := range records {
			modelSeen[rec.Model] = true
		}
		for model := range modelSeen {
			models = append(models, model)
		}
		sort.Strings(models)
	}

	enabledByAuth := make(map[string]bool, len(accounts))
	for _, account := range accounts {
		enabledByAuth[account.AuthID] = account.Enabled
	}

	// targetsReady counts the intended matrix only, so it is tallied here rather
	// than over out.Buckets at the end -- that slice also carries the drift rows
	// appended below, and a stale bucket left over from an earlier, wider scope
	// would otherwise count towards the current scope's progress.
	targetsTotal := 0
	targetsReady := 0
	seen := make(map[string]bool, len(accounts)*len(models))
	for _, account := range accounts {
		for _, model := range models {
			cell := bucketStatus(onDisk, account.AuthID, model, now, ttl, cfg.TemplateLength)
			cell.Enabled = account.Enabled
			out.Buckets = append(out.Buckets, cell)
			seen[bucketKey(account.AuthID, model)] = true
			targetsTotal++
			if cell.Ready {
				targetsReady++
			}
		}
	}
	// Anything on disk that the matrix above does not cover -- a model no longer
	// in the configured list, or an account the host did not report -- is still
	// shown. That drift is exactly the kind worth seeing rather than hiding.
	for _, rec := range records {
		key := bucketKey(rec.AuthID, rec.Model)
		if seen[key] {
			continue
		}
		seen[key] = true
		cell := bucketStatus(onDisk, rec.AuthID, rec.Model, now, ttl, cfg.TemplateLength)
		enabled, known := enabledByAuth[rec.AuthID]
		cell.Enabled = !known || enabled
		out.Buckets = append(out.Buckets, cell)
	}

	// Stable order, or the page's rows and columns reshuffle on every refresh.
	sort.Slice(out.Buckets, func(i, j int) bool {
		if out.Buckets[i].AuthID != out.Buckets[j].AuthID {
			return out.Buckets[i].AuthID < out.Buckets[j].AuthID
		}
		return out.Buckets[i].Model < out.Buckets[j].Model
	})

	// The intended matrix, not len(out.Buckets): "8 of 25" when the operator
	// scoped the run to 2 accounts × 2 models would be reporting progress against
	// a target nobody chose. Drift rows stay visible in Buckets but out of the
	// denominator.
	out.TargetsTotal = targetsTotal
	out.TargetsReady = targetsReady

	return jsonResponse(http.StatusOK, out)
}

// configResponse is the editable configuration, proxies included verbatim.
//
// It exists because the dashboard used to refill its editor from here -- a form
// seeded from masked strings writes "***" back over the passwords on the first
// save. The status document now carries the proxy list itself, so the page no
// longer calls this at all; it is kept as the keyed view of the configuration.
//
// What it must never grow: probe_api_key or probe_management_key. Those are not
// editable from anywhere and are not displayed anywhere, so there is nothing for
// a form to refill, and a field here would be a secret one accidental resource
// alias away from being anonymous.
type configResponse struct {
	Role           string   `json:"role"`
	StoreDir       string   `json:"store_dir"`
	Models         []string `json:"models"`
	ProbeAccounts  []string `json:"probe_accounts"`
	ProbeProxies   []string `json:"probe_proxies"`
	DryRun         bool     `json:"dry_run"`
	InjectMode     string   `json:"inject_mode"`
	TTLSeconds     int      `json:"ttl_seconds"`
	TemplateLength int      `json:"template_length"`
	ReplaceLength  int      `json:"replace_length"`
	ConfigErrors   []string `json:"config_errors,omitempty"`
}

// handleConfig serves the editable configuration behind the management key.
//
// It is deliberately read-only. Writes go through CPA's own
// PATCH /v0/management/plugins/codex-turn-state/config, which the dashboard
// already uses for dry_run and role: the host owns persisting plugin config --
// there is no host.config.save callback -- so a write route here could only
// change the in-memory copy, which the next reconfigure would silently revert.
func handleConfig() pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	configErrors := append([]string(nil), state.configErrors...)
	state.mu.Unlock()

	out := configResponse{
		Role:           cfg.Role,
		StoreDir:       cfg.StoreDir,
		Models:         append([]string(nil), cfg.Models...),
		ProbeAccounts:  append([]string(nil), cfg.ProbeAccounts...),
		ProbeProxies:   append([]string(nil), cfg.ProbeProxies...),
		DryRun:         cfg.DryRun,
		InjectMode:     cfg.InjectMode,
		TTLSeconds:     cfg.TTLSeconds,
		TemplateLength: cfg.TemplateLength,
		ReplaceLength:  cfg.ReplaceLength,
		ConfigErrors:   configErrors,
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	if out.ProbeProxies == nil {
		out.ProbeProxies = []string{}
	}
	return jsonResponse(http.StatusOK, out)
}

type scopeSaveResponse struct {
	Saved              bool     `json:"saved"`
	Fields             []string `json:"fields"`
	ProbeAccounts      []string `json:"probe_accounts"`
	Models             []string `json:"models"`
	ProbeProxyCount    int      `json:"probe_proxy_count"`
	ProbeProxiesMasked []string `json:"probe_proxies_masked"`
	TargetsTotal       int      `json:"targets_total"`
	ConfigErrors       []string `json:"config_errors,omitempty"`
	Note               string   `json:"note"`
}

// handleScopeSave persists the probe scope from the keyless route's query.
//
// Which lists to replace is named explicitly in `fields` rather than inferred
// from which parameters are present. The two differ for an empty list, and the
// difference matters: "the operator cleared the proxies" and "the page did not
// send any proxies this time" arrive as the same query, and guessing wrong wipes
// a list of credentials that cannot be recovered from anywhere else.
//
// Values arrive as repeated parameters: account=a&account=b&model=x&proxy=…
// A query string is the only channel available -- the host serves resource
// routes as GET with no body -- so proxy userinfo does travel in the URL. It
// does not reach any log: CPA records upstream /v1/* calls, not management-plane
// request lines, and this plugin never logs a proxy unmasked.
func handleScopeSave(q url.Values) pluginapi.ManagementResponse {
	requested := map[string]bool{}
	for _, field := range strings.Split(q.Get("fields"), ",") {
		if name := strings.ToLower(strings.TrimSpace(field)); name != "" {
			requested[name] = true
		}
	}
	if len(requested) == 0 {
		return managementError(http.StatusBadRequest,
			`"fields" is required: name which lists to replace, e.g. fields=accounts,models,proxies. `+
				`Without it an empty query would be indistinguishable from "clear everything".`)
	}
	for name := range requested {
		switch name {
		case "accounts", "models", "proxies":
		default:
			return managementError(http.StatusBadRequest,
				"unknown field "+name+"; expected accounts, models or proxies")
		}
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if strings.TrimSpace(cfg.StoreDir) == "" {
		return managementError(http.StatusConflict,
			"store_dir is not configured, so there is nowhere to save the probe scope")
	}

	accounts, models, proxies := cfg.ProbeAccounts, cfg.Models, cfg.ProbeProxies
	if requested["accounts"] {
		accounts = q["account"]
	}
	if requested["models"] {
		models = q["model"]
	}
	if requested["proxies"] {
		proxies = q["proxy"]
	}

	accounts, models, proxies, problems := normaliseProbeScope(accounts, models, proxies)

	scope := probeScope{
		Accounts:  accounts,
		Models:    models,
		Proxies:   proxies,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if errWrite := writeProbeScope(cfg.StoreDir, scope); errWrite != nil {
		return managementError(http.StatusInternalServerError,
			"could not save the probe scope: "+errWrite.Error())
	}

	// Applied in memory as well as on disk, so the change is live without
	// waiting for the host's next reconfigure. Templates are deliberately left
	// alone: scope says which buckets the next probe run covers, not whether a
	// template already held is still genuine.
	state.mu.Lock()
	state.config.ProbeAccounts = accounts
	state.config.Models = models
	state.config.ProbeProxies = proxies
	state.configErrors = problems
	state.mu.Unlock()

	log.Printf(logPrefix+"probe scope saved: accounts=%d models=%d proxies=%d (fields=%s)",
		len(accounts), len(models), len(proxies), q.Get("fields"))
	for _, problem := range problems {
		log.Printf(logPrefix+"config error (probe scope, not fatal): %s", problem)
	}

	out := scopeSaveResponse{
		Saved:              true,
		Fields:             sortedKeys(requested),
		ProbeAccounts:      accounts,
		Models:             models,
		ProbeProxyCount:    len(proxies),
		ProbeProxiesMasked: maskProxyURLs(proxies),
		TargetsTotal:       len(accounts) * len(models),
		ConfigErrors:       problems,
		Note: "已保存到插件自己的 scope 文件，立即生效，覆盖 config.yaml 里的同名项。" +
			"采集仍须在宿主上运行 scripts/probe.py --until-complete。",
	}
	if out.ProbeAccounts == nil {
		out.ProbeAccounts = []string{}
	}
	if out.Models == nil {
		out.Models = []string{}
	}
	return jsonResponse(http.StatusOK, out)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// statusAccounts lists the credentials the readiness matrix should have a row
// for. It asks the host first, because only the host knows about an account that
// has never been harvested. When the host cannot answer it falls back to the
// accounts the store mentions and says so, so a caller can tell a real "no
// accounts" from "could not ask".
//
// Every Codex credential is returned, disabled ones included, each carrying its
// state -- see statusBucket.Enabled for why a disabled account keeps its row.
func statusAccounts(records []storeRecord) ([]statusAccount, string, error) {
	accounts, errList := listCodexAuths()
	if errList == nil {
		return accounts, "host", nil
	}

	seen := make(map[string]bool)
	var fallback []statusAccount
	for _, rec := range records {
		if seen[rec.AuthID] {
			continue
		}
		seen[rec.AuthID] = true
		// Enabled is unknown on this path. Reported true because a credential
		// that produced a bucket was working at the time, and marking it
		// disabled would assert something never observed; accounts_source is
		// what tells the caller not to trust this field.
		fallback = append(fallback, statusAccount{AuthID: rec.AuthID, Enabled: true})
	}
	sort.Slice(fallback, func(i, j int) bool { return fallback[i].AuthID < fallback[j].AuthID })
	return fallback, "store", errList
}

// The credential list is cached for the harvest path, which would otherwise ask
// the host once per upstream response. The window is deliberately tiny: the one
// thing that changes during a probe run is exactly which account is enabled, and
// attributing a template to an account that was switched off two seconds ago is
// the failure this cache must not cause.
//
// handleStatus deliberately does not use it. The dashboard is read by a person
// deciding what to do next, it is requested rarely, and it should show the
// credential states as they are rather than as they were.
const authListCacheTTL = 2 * time.Second

var (
	authListMu      sync.Mutex
	authListCache   []statusAccount
	authListErr     error
	authListFetched time.Time
)

// codexAuthLister returns the current Codex credentials. It is a package
// variable rather than a direct call so tests can inject a fixed list and
// exercise the attribution fallbacks on both the harvest and substitution
// paths -- above all the two-accounts case, where refusing to guess is what
// keeps one account's template off another account's request. Production leaves
// it pointed at the real host-backed lister.
var codexAuthLister = listCodexAuths

// cachedCodexAuths is codexAuthLister behind a short cache. The lookup happens
// under the mutex so a burst of concurrent responses produces one call rather
// than one each.
func cachedCodexAuths() ([]statusAccount, error) {
	authListMu.Lock()
	defer authListMu.Unlock()
	if !authListFetched.IsZero() && time.Since(authListFetched) < authListCacheTTL {
		return authListCache, authListErr
	}
	authListCache, authListErr = codexAuthLister()
	authListFetched = time.Now()
	return authListCache, authListErr
}

// resetAuthCache clears the cached credential list so the next cachedCodexAuths
// call goes back to codexAuthLister immediately. It exists for tests: after
// injecting a new codexAuthLister they must drop the 2-second cache, or a stale
// entry from a previous case would answer instead. Not used in production, where
// the cache is meant to persist for its full window.
func resetAuthCache() {
	authListMu.Lock()
	defer authListMu.Unlock()
	authListCache = nil
	authListErr = nil
	authListFetched = time.Time{}
}

// listCodexAuths returns every Codex credential the host knows about, sorted by
// name, with the enabled state it reports.
func listCodexAuths() ([]statusAccount, error) {
	var listed struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if errCall := hostCallJSON("host.auth.list", map[string]any{}, &listed); errCall != nil {
		return nil, errCall
	}
	var out []statusAccount
	for _, file := range listed.Files {
		if !isCodexAuth(file) {
			continue
		}
		name := strings.TrimSpace(file.Name)
		if name == "" {
			continue
		}
		// An unavailable credential cannot answer a request either, so it is
		// reported the same way a disabled one is: the operator's question is
		// "can this bucket be filled right now", not "which flag is set".
		out = append(out, statusAccount{AuthID: name, Enabled: !file.Disabled && !file.Unavailable})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AuthID < out[j].AuthID })
	return out, nil
}

func isCodexAuth(file pluginapi.HostAuthFileEntry) bool {
	if strings.EqualFold(strings.TrimSpace(file.Provider), "codex") ||
		strings.EqualFold(strings.TrimSpace(file.Type), "codex") {
		return true
	}
	// Provider is not always populated on file-backed credentials; the naming
	// convention is the fallback scripts/probe.py uses too.
	name := strings.ToLower(strings.TrimSpace(file.Name))
	return strings.HasPrefix(name, "codex-") && strings.HasSuffix(name, ".json")
}

// bucketStatus renders one cell. A record that is expired, future-stamped or the
// wrong length reports ready=false with no time left, matching exactly what the
// business role would decide about it.
func bucketStatus(onDisk map[string]storeRecord, auth, model string, now time.Time, ttl time.Duration, templateLength int) statusBucket {
	cell := statusBucket{AuthID: auth, Model: model}
	rec, found := onDisk[bucketKey(auth, model)]
	if !found {
		return cell
	}
	// Set before the parse check: a record with an unreadable issued_at still
	// tells the operator what length was harvested, which is the whole point.
	cell.Len = rec.Len
	cell.Attribution = rec.Attribution
	issued, okIssued := recordIssuedAt(rec)
	if !okIssued {
		return cell
	}
	expires := issued.Add(ttl)
	cell.IssuedAt = issued.UTC().Format(time.RFC3339)
	cell.ExpiresAt = expires.UTC().Format(time.RFC3339)
	// Same rule as loadStore, via the same function -- see recordUsable.
	cell.Ready = recordUsable(rec, issued, now, ttl, templateLength)
	if cell.Ready {
		if left := int64(expires.Sub(now).Seconds()); left > 0 {
			cell.SecondsLeft = left
		}
	}
	return cell
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

type clearRequest struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
	All    bool   `json:"all"`
}

type clearedBucket struct {
	AuthID string `json:"auth_id"`
	Model  string `json:"model"`
}

type clearResponse struct {
	Cleared int             `json:"cleared"`
	Buckets []clearedBucket `json:"buckets"`
}

// handleBucketsClear deletes one bucket file or all of them, rewrites index.json
// and drops the in-memory view so the next request re-reads from disk.
func handleBucketsClear(body []byte) pluginapi.ManagementResponse {
	var req clearRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if errUnmarshal := json.Unmarshal(body, &req); errUnmarshal != nil {
			return managementError(http.StatusBadRequest, "could not decode the request body as JSON")
		}
	}
	return clearBuckets(req)
}

// clearBuckets is the shared core behind both the authenticated POST route
// (handleBucketsClear, which decodes a JSON body) and the keyless GET route
// (clearRequestFromQuery, which builds the same struct from the query string).
// They differ only in where the clearRequest comes from; the deletion, index
// rewrite and cache invalidation below are identical for both.
func clearBuckets(req clearRequest) pluginapi.ManagementResponse {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	dir := strings.TrimSpace(cfg.StoreDir)
	if dir == "" {
		return managementError(http.StatusConflict, "store_dir is not configured, so there is no store to clear")
	}

	namesBucket := strings.TrimSpace(req.AuthID) != "" || strings.TrimSpace(req.Model) != ""

	var targets []clearedBucket
	switch {
	case req.All && namesBucket:
		// Contradictory: one reading wipes the store, the other removes a single
		// file. Guessing would mean guessing in the destructive direction.
		return managementError(http.StatusBadRequest,
			`"all" cannot be combined with "auth_id" or "model" -- send one or the other`)
	case req.All:
		records, errScan := scanStoreRecords(dir)
		if errScan != nil {
			return managementError(http.StatusInternalServerError, "could not read the store: "+errScan.Error())
		}
		for _, rec := range records {
			targets = append(targets, clearedBucket{AuthID: rec.AuthID, Model: rec.Model})
		}
	case strings.TrimSpace(req.AuthID) != "" && strings.TrimSpace(req.Model) != "":
		targets = append(targets, clearedBucket{AuthID: req.AuthID, Model: req.Model})
	default:
		return managementError(http.StatusBadRequest, `give either {"all":true} or both "auth_id" and "model"`)
	}

	cleared := 0
	var done []clearedBucket
	for _, target := range targets {
		// auth_id and model arrive from the caller, so the same sanitiser the
		// harvest path uses guards the delete: without it a crafted pair could
		// name a file outside the store.
		rel, errPath := bucketRelPath(target.AuthID, target.Model)
		if errPath != nil {
			return managementError(http.StatusBadRequest, errPath.Error())
		}
		errRemove := os.Remove(filepath.Join(dir, rel))
		if errRemove != nil {
			if os.IsNotExist(errRemove) {
				continue
			}
			return managementError(http.StatusInternalServerError, "could not remove bucket: "+errRemove.Error())
		}
		cleared++
		done = append(done, target)
	}

	if cleared > 0 {
		now := time.Now()
		if errIndex := writeStoreIndex(dir, now, cfg.ttl(), cfg.TemplateLength); errIndex != nil {
			log.Printf(logPrefix+"index rewrite after clear failed: %v", errIndex)
		}
		// Without this the page would show the bucket gone while the business
		// role kept substituting from the copy it already had in memory.
		state.mu.Lock()
		for _, target := range done {
			delete(state.buckets, bucketKey(target.AuthID, target.Model))
			delete(state.store, bucketKey(target.AuthID, target.Model))
		}
		state.storeMod = time.Time{}
		state.storeChecked = time.Time{}
		state.mu.Unlock()
		log.Printf(logPrefix+"cleared %d bucket(s)", cleared)
	}

	if done == nil {
		done = []clearedBucket{}
	}
	return jsonResponse(http.StatusOK, clearResponse{Cleared: cleared, Buckets: done})
}

type selftestRequest struct {
	Model  string `json:"model"`
	AuthID string `json:"auth_id"`
}

type selftestResponse struct {
	// Reached reports whether the request got to the upstream and came back with
	// an answer. An upstream 429, 401 or a JSON error body all count as reached:
	// the path works and the upstream declined, which is a different problem from
	// the request never arriving, and the two call for opposite next steps --
	// wait and retry, versus go and look at the network.
	Reached    bool   `json:"reached"`
	StatusCode int    `json:"status_code"`
	Model      string `json:"model"`
	AuthID     string `json:"auth_id"`
	// Targeted reports whether auth_id above is a credential we asked for or
	// merely an empty string. It exists so the two cannot be confused: an empty
	// auth_id never means "the scheduler chose nothing", it means we did not ask
	// and cannot find out.
	Targeted  bool `json:"targeted"`
	Harvested bool `json:"harvested"`
	// UpstreamErrorCode is the "code" out of an upstream error body, when there
	// was one. This is the most actionable field on a failed self-test:
	// server_is_overloaded is the same signal as a degraded 312 (see
	// FINDINGS.md), so seeing it means no 292 is available to harvest right now
	// and the answer is to wait, not to go hunting for a broken link.
	UpstreamErrorCode string `json:"upstream_error_code"`
	UpstreamErrorType string `json:"upstream_error_type"`
	Note              string `json:"note"`
	Error             string `json:"error,omitempty"`
}

// upstreamErrorBody is the OpenAI-style error envelope the upstream returns.
// Receiving one at all is the proof that the request arrived: a transport
// failure cannot produce the upstream's own error schema.
type upstreamErrorBody struct {
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// The self-test notes.
//
// harvested is a constant false in both, not a runtime check, because nothing
// this handler can do would make it true -- pinning AuthID does not change it.
// CPA sets SkipInterceptorPluginID to the calling plugin's own id for host
// callbacks: the native loader tags the call context with the plugin id
// (internal/pluginhost/host_callbacks_unix.go:43), callHostModelExecute reads it
// back as skipPluginID (host_callbacks.go:304), and
// modelExecutionRequestFromPlugin puts it in SkipInterceptorPluginID
// (host_callbacks.go:306). That is the host's guard against a plugin re-entering
// itself, and it means a request issued from here cannot pass through this
// plugin's own response interceptor. So it can prove the path is alive; it can
// never fill a bucket.
const (
	selftestNote = "连通性自检不会落盘：host.model.execute 会跳过本插件的响应拦截器。采集请用 scripts/probe.py。"
	// Said plainly rather than left to inference: HostModelExecutionResponse
	// carries only StatusCode, Headers and Body, so when we do not pin a
	// credential there is no way to learn which one answered. Reporting a guess
	// would be worse than reporting nothing.
	selftestNoteUntargeted = selftestNote +
		" 本次未指定 auth_id，由调度器选号；上游响应不含账号标识，因此无法得知实际使用的是哪个号。要定点检查请传 auth_id。"
	// Appended when the upstream answered with an error but the host did not
	// pass its HTTP status through. status_code stays 0 rather than being
	// invented; this says so, so nobody reads the 0 as "no response".
	selftestNoteNoStatus = " 上游返回了错误但宿主未透传 HTTP 状态码，故 status_code 为 0；请看 upstream_error_code 和 error 原文。"
)

// handleSelftest sends one minimal request and reports whether it reached the
// upstream. It answers exactly one question -- "is the path alive?" -- and
// deliberately does not gate on role or on how many credentials are enabled:
// the moment this is most useful is when something is already wrong, and
// refusing to answer because the role looks unusual would withhold the one
// diagnostic the operator came for.
//
// An optional auth_id pins the credential, which turns this into a check of one
// exact (account, model) pair without having to disable anything. Left out, the
// scheduler chooses and the answer says so rather than guessing.
//
// This handler never enables or disables a credential. That needs a snapshot
// and a guaranteed restore (scripts/probe.py has both, including signal
// handlers and a --restore fallback); a half-completed toggle here would leave
// the operator's accounts switched off with nothing to put them back.
func handleSelftest(body []byte) pluginapi.ManagementResponse {
	var req selftestRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if errUnmarshal := json.Unmarshal(body, &req); errUnmarshal != nil {
			return managementError(http.StatusBadRequest, "could not decode the request body as JSON")
		}
	}
	return runSelftest(req)
}

// runSelftest is the shared core behind the authenticated POST route
// (handleSelftest, JSON body) and the keyless GET route (selftestRequestFrom
// Query). The self-test issues one real upstream request and spends quota, so on
// the keyless path handleOpsResource has already required confirm=1 before this
// runs.
func runSelftest(req selftestRequest) pluginapi.ManagementResponse {
	model := strings.TrimSpace(req.Model)
	if model == "" {
		return managementError(http.StatusBadRequest, `"model" is required`)
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// The one guard worth keeping: a typo in a model id spends quota on a
	// request that was never going to tell us anything.
	if len(cfg.Models) > 0 && !containsFold(cfg.Models, model) {
		return managementError(http.StatusBadRequest,
			fmt.Sprintf("model %q is not in the configured models list", model))
	}

	// auth_id is optional. When present it is caller-supplied input that gets
	// interpolated into an outbound request, so it goes through the same
	// sanitiser the store path uses -- one rule for "is this identifier safe to
	// pass on", rather than a second one that could drift from it.
	//
	// Whether the credential exists is deliberately not checked here. The
	// scheduler owns that answer, and inventing our own "no such account" would
	// mean maintaining a second view of the credential list that could disagree
	// with the real one. An unknown id comes back as an upstream error, reported
	// verbatim.
	authID := strings.TrimSpace(req.AuthID)
	if authID != "" {
		if _, errAuth := bucketRelPath(authID, model); errAuth != nil {
			return managementError(http.StatusBadRequest, "unsafe auth_id or model: "+errAuth.Error())
		}
	}

	// Checked after the input is validated, so a malformed request still gets
	// the specific 4xx naming what is wrong with it.
	//
	// This fails rather than answering 200 with reached=false. Without a callback
	// table the self-test never ran, and a 200 would put "we could not ask" in the
	// same shape as "we asked and got nothing" -- the one confusion this endpoint
	// exists to prevent. A caller that only reads the status code still gets the
	// message; a caller that reads the body gets the reason.
	if !hostAPIAvailable() {
		log.Printf(logPrefix + "selftest could not run: no host callback table")
		return managementError(http.StatusServiceUnavailable,
			"this plugin holds no host callback table, so it could not issue any request. "+
				"The self-test did not run; this says nothing about the upstream. "+
				"The plugin was loaded without a host API, which is a loader problem.")
	}

	out := selftestResponse{
		Model:     model,
		AuthID:    authID,
		Targeted:  authID != "",
		Harvested: false,
		Note:      selftestNote,
	}
	if !out.Targeted {
		out.Note = selftestNoteUntargeted
	}

	// A deliberately minimal turn, with no X-Codex-Turn-State attached: sending
	// a stale value is what stops the upstream minting a fresh one, and even a
	// self-test should not teach the upstream to reuse an old state.
	payload := map[string]any{
		"model": model,
		"input": []map[string]any{{
			"role":    "user",
			"content": []map[string]any{{"type": "input_text", "text": "ping"}},
		}},
		"store": false,
	}
	rawBody, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return managementError(http.StatusInternalServerError, errMarshal.Error())
	}

	exec := pluginapi.HostModelExecutionRequest{
		EntryProtocol: "openai-responses",
		ExitProtocol:  "openai-responses",
		Model:         model,
		Stream:        false,
		Body:          rawBody,
		Headers:       http.Header{"Content-Type": []string{"application/json"}},
		// Empty means "scheduler's choice"; the host omits the field when unset.
		AuthID: authID,
	}

	var execResp pluginapi.HostModelExecutionResponse
	errCall := hostCallJSON("host.model.execute", exec, &execResp)
	if errCall == nil {
		out.Reached = true
		out.StatusCode = execResp.StatusCode
		log.Printf(logPrefix+"selftest reached upstream model=%s auth=%s targeted=%t status=%d",
			orDash(model), orDash(authID), out.Targeted, out.StatusCode)
		return jsonResponse(http.StatusOK, out)
	}

	// The host collapses an upstream rejection into an error envelope rather than
	// a response carrying the status, so "reached but refused" has to be
	// recovered from the message text. Two signals, in order of strength:
	//
	//  1. An upstream error body. Observed in practice as
	//     host_call_failed: {"error":{"type":"service_unavailable_error",
	//     "code":"server_is_overloaded",...}}. Only the upstream produces that
	//     schema, so receiving it is proof the request arrived -- this is the
	//     case that used to be misreported as reached=false, sending operators
	//     to check the network when the real answer was "it is overloaded".
	//  2. The host's own "failed with status N" phrasing.
	//
	// Neither present means a genuine transport failure, and only then is
	// reached=false the honest answer. The raw message is passed through in
	// every branch so the operator is never left with only our classification.
	out.Error = errCall.Error()
	upstream, okUpstream := upstreamErrorFrom(out.Error)
	status, okStatus := statusFromExecutionError(out.Error)
	switch {
	case okUpstream:
		out.Reached = true
		out.UpstreamErrorCode = strings.TrimSpace(upstream.Error.Code)
		out.UpstreamErrorType = strings.TrimSpace(upstream.Error.Type)
		if okStatus {
			out.StatusCode = status
		} else {
			out.Note += selftestNoteNoStatus
		}
	case okStatus:
		out.Reached = true
		out.StatusCode = status
	}
	log.Printf(logPrefix+"selftest model=%s auth=%s targeted=%t reached=%t status=%d upstream_code=%s",
		orDash(model), orDash(authID), out.Targeted, out.Reached, out.StatusCode, orDash(out.UpstreamErrorCode))
	return jsonResponse(http.StatusOK, out)
}

// upstreamErrorFrom pulls an upstream error body out of the host's error text,
// which wraps it in a prefix ("host_call_failed: {...}"). A Decoder is used
// rather than Unmarshal so trailing text after the JSON value is tolerated.
//
// A body counts only if it carries at least one populated field: an unrelated
// JSON object that happens to appear in a message must not be mistaken for the
// upstream answering.
func upstreamErrorFrom(message string) (upstreamErrorBody, bool) {
	idx := strings.Index(message, "{")
	if idx < 0 {
		return upstreamErrorBody{}, false
	}
	var body upstreamErrorBody
	if errDecode := json.NewDecoder(strings.NewReader(message[idx:])).Decode(&body); errDecode != nil {
		return upstreamErrorBody{}, false
	}
	if body.Error.Type == "" && body.Error.Code == "" && body.Error.Message == "" {
		return upstreamErrorBody{}, false
	}
	return body, true
}

// statusFromExecutionError recovers an upstream status code from the host's
// error text. modelExecutionError renders a status-bearing failure as
// "... failed with status <code>".
//
// The marker is the full phrase rather than just "status ": the message may now
// carry an upstream JSON body, and a "status" appearing inside an upstream
// message string would otherwise be read as an HTTP code.
func statusFromExecutionError(message string) (int, bool) {
	const marker = "failed with status "
	idx := strings.LastIndex(message, marker)
	if idx < 0 {
		return 0, false
	}
	digits := strings.TrimSpace(message[idx+len(marker):])
	end := 0
	for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	status := 0
	for _, char := range digits[:end] {
		status = status*10 + int(char-'0')
	}
	if status < 100 || status > 599 {
		return 0, false
	}
	return status, true
}

// hostCallJSON marshals a host callback, unwraps the RPC envelope and decodes
// the result. The host reports failures inside the envelope as well as through
// the return code, so both are checked.
func hostCallJSON(method string, payload any, out any) error {
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return errMarshal
	}
	response, errCall := hostCall(method, raw)
	if errCall != nil {
		return errCall
	}
	if len(response) == 0 {
		return fmt.Errorf("host call %s returned nothing", method)
	}
	var env envelope
	if errUnmarshal := json.Unmarshal(response, &env); errUnmarshal != nil {
		return fmt.Errorf("decode %s response: %w", method, errUnmarshal)
	}
	if !env.OK {
		if env.Error != nil {
			return fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return fmt.Errorf("host call %s failed", method)
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// jsonResponse renders a management payload. Schema 6 hosts return JSON without
// HTML entity escaping, so the body reaches the browser as written.
func jsonResponse(status int, payload any) pluginapi.ManagementResponse {
	body, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return managementError(http.StatusInternalServerError, "could not encode the response")
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}

// managementError returns a structured error. Handlers return these rather than
// panicking: a panic in a native plugin takes the whole CPA process with it.
func managementError(status int, message string) pluginapi.ManagementResponse {
	body, errMarshal := json.Marshal(map[string]string{"error": message})
	if errMarshal != nil {
		body = []byte(`{"error":"internal error"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}
