// Management API for the codex-turn-state plugin.
//
// Two kinds of route are registered, and the difference matters:
//
//   - The HTML shell is a ResourceRoute. Those are served under
//     /v0/resource/plugins/<id>/ and the host does NOT authenticate them
//     ("Resource requests are not management-authenticated" -- pluginapi). So
//     the shell carries no data whatsoever: it is markup and script, and every
//     byte of state it displays is fetched afterwards by the browser from the
//     authenticated routes below, with the operator's management key attached.
//
//   - Everything that reads or changes state is a ManagementRoute with no Menu.
//     Those are served under /v0/management/ behind the host's management
//     middleware. The Menu field is deliberately left empty on all of them: a
//     GET route that declares one is re-registered under the resource prefix
//     instead (routeDeclaresLegacyMenuResource in the host), which would quietly
//     strip the authentication off the very routes that need it.
//
// No response from any route in this file contains a template value. The store
// holds credential-adjacent secrets; the dashboard needs readiness and expiry,
// and readiness and expiry are all it gets.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
				// no-login page). clear and selftest are deliberately NOT mirrored
				// here -- they are destructive or spend quota, so they stay behind
				// the management key.
				Path:        routeStatusResource,
				Description: "只读状态（无需鉴权），供看板拉取",
			},
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
	}
	if out.Models == nil {
		out.Models = []string{}
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

	seen := make(map[string]bool, len(accounts)*len(models))
	for _, account := range accounts {
		for _, model := range models {
			cell := bucketStatus(onDisk, account.AuthID, model, now, ttl, cfg.TemplateLength)
			cell.Enabled = account.Enabled
			out.Buckets = append(out.Buckets, cell)
			seen[bucketKey(account.AuthID, model)] = true
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

	out.TargetsTotal = len(out.Buckets)
	for _, bucket := range out.Buckets {
		if bucket.Ready {
			out.TargetsReady++
		}
	}

	return jsonResponse(http.StatusOK, out)
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

// cachedCodexAuths is listCodexAuths behind a short cache. The host call happens
// under the mutex so a burst of concurrent responses produces one lookup rather
// than one each.
func cachedCodexAuths() ([]statusAccount, error) {
	authListMu.Lock()
	defer authListMu.Unlock()
	if !authListFetched.IsZero() && time.Since(authListFetched) < authListCacheTTL {
		return authListCache, authListErr
	}
	authListCache, authListErr = listCodexAuths()
	authListFetched = time.Now()
	return authListCache, authListErr
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
		log.Printf(logPrefix+"cleared %d bucket(s) via management API", cleared)
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
