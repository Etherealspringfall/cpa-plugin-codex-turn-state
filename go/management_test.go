package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// Paths are spelled out rather than imported from the implementation. These
// tests are the contract for the management surface: renaming a route in
// production should break them loudly, not have them follow along.
const (
	mgmtStatusPath   = "/v0/management/codex-turn-state/status"
	mgmtClearPath    = "/v0/management/codex-turn-state/buckets/clear"
	mgmtSelftestPath = "/v0/management/codex-turn-state/selftest"
	mgmtResourcePath = "/v0/resource/plugins/codex-turn-state/"
)

// --- wire shapes ---------------------------------------------------------
//
// Decoded into local structs so the tests do not bind to internal type names.
// The pluginapi management types carry no JSON tags, so they travel under their
// Go field names -- StatusCode, Headers, Body -- which is what these mirror.

type mgmtResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers"`
	Body       []byte      `json:"Body"`
}

type mgmtRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type mgmtRegistration struct {
	Routes    []mgmtRoute `json:"routes"`
	Resources []mgmtRoute `json:"resources"`
}

type mgmtBucket struct {
	AuthID      string `json:"auth_id"`
	Model       string `json:"model"`
	Ready       bool   `json:"ready"`
	Len         int    `json:"len"`
	Enabled     bool   `json:"enabled"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	SecondsLeft int64  `json:"seconds_left"`
}

type mgmtCounters struct {
	Harvest    int64 `json:"harvest"`
	Substitute int64 `json:"substitute"`
	Pass       int64 `json:"pass"`
	Skip       int64 `json:"skip"`
}

type mgmtStatus struct {
	Role           string       `json:"role"`
	DryRun         bool         `json:"dry_run"`
	InjectMode     string       `json:"inject_mode"`
	TTLSeconds     int          `json:"ttl_seconds"`
	TemplateLength int          `json:"template_length"`
	ReplaceLength  int          `json:"replace_length"`
	StoreDir       string       `json:"store_dir"`
	Models         []string     `json:"models"`
	Buckets        []mgmtBucket `json:"buckets"`
	TargetsTotal   int          `json:"targets_total"`
	TargetsReady   int          `json:"targets_ready"`
	// AccountsSource is "host" when the credential list came from
	// host.auth.list and "store" when it had to be inferred from what the store
	// already holds. Under "store" a never-probed account is invisible, so the
	// distinction is what stops an empty matrix reading as "nothing to probe".
	AccountsSource string       `json:"accounts_source"`
	AccountsError  string       `json:"accounts_error"`
	StoreError     string       `json:"store_error"`
	Counters       mgmtCounters `json:"counters"`
}

type mgmtClearResult struct {
	Cleared int `json:"cleared"`
}

// mgmtSelftestResult mirrors the selftest body. Harvested is spelled out here
// even though it is always false: the field existing and reading false is the
// contract, so it has to be decoded to be asserted.
//
// AuthID is a request-side echo, never a discovery.
//
// Reading back which credential answered is not possible: CPA's
// HostModelExecutionResponse carries only StatusCode, Headers and Body, with no
// account identity anywhere, and no auth-id response header exists to look for.
// An earlier revision guessed at header names; that whole approach was removed
// because it could only ever invent an answer.
//
// The direction that does work is the request side.
// pluginapi.HostModelExecutionRequest.AuthID "optionally locks execution to an
// exact credential ID" and the host forwards it verbatim
// (internal/pluginhost/host_callbacks.go:330). So the plugin does not learn
// which account was used -- it decides, and echoes back what it asked for.
//
// Targeted exists because auth_id alone is ambiguous. An empty auth_id could be
// read as "the scheduler picked nothing", which never happens; what it actually
// means is "we did not specify one, and cannot find out which was used".
// targeted:false says that out loud, so nobody reads an empty string as a
// finding. See TestSelftestEchoesTargetingHonestly and
// TestSelftestAuthIDIsNeverFabricated.
type mgmtSelftestResult struct {
	Reached    bool   `json:"reached"`
	StatusCode int    `json:"status_code"`
	Model      string `json:"model"`
	AuthID     string `json:"auth_id"`
	Targeted   bool   `json:"targeted"`
	Harvested  bool   `json:"harvested"`
	Note       string `json:"note"`
	Error      string `json:"error"`
}

// --- drivers -------------------------------------------------------------

// decodeMgmtEnvelope unwraps the plugin's ok/error envelope. Kept separate from
// main_test.go's interceptAfter so a failing management call reports the
// plugin's own error text instead of a generic decode failure.
func decodeMgmtEnvelope(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v (raw: %s)", err, truncateMgmtLog(raw))
	}
	if !env.OK {
		t.Fatalf("plugin returned an error envelope: %+v", env.Error)
	}
	return env.Result
}

// truncateMgmtLog keeps a failure message readable when a body is large. It also
// means a leaked token would not be splashed across the full test log.
func truncateMgmtLog(raw []byte) string {
	const limit = 200
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "..."
}

// driveManagement drives one management.handle call end to end.
func driveManagement(t *testing.T, method, path string, body []byte) mgmtResponse {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Method":  method,
		"Path":    path,
		"Headers": http.Header{},
		"Query":   url.Values{},
		"Body":    body,
	})
	if err != nil {
		t.Fatalf("marshal management request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementHandle, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.handle) %s %s: %v", method, path, errHandle)
	}
	var resp mgmtResponse
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &resp); errUnmarshal != nil {
			t.Fatalf("decode management response: %v", errUnmarshal)
		}
	}
	// Zero means 200 per the SDK contract; normalise so callers compare one
	// value rather than two.
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp
}

// driveManagementJSON drives a call whose body is a JSON object.
func driveManagementJSON(t *testing.T, method, path string, payload any) mgmtResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return driveManagement(t, method, path, body)
}

// driveManagementRegister drives management.register and returns the declared routes.
func driveManagementRegister(t *testing.T) mgmtRegistration {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"Plugin":           map[string]any{"Name": "codex-turn-state"},
		"BasePath":         "/v0/management",
		"ResourceBasePath": "/v0/resource/plugins/codex-turn-state",
	})
	if err != nil {
		t.Fatalf("marshal management registration request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodManagementRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(management.register): %v", errHandle)
	}
	var reg mgmtRegistration
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode management registration: %v", errUnmarshal)
		}
	}
	return reg
}

// mustManagementStatus fetches and decodes the status document.
func mustManagementStatus(t *testing.T) mgmtStatus {
	t.Helper()
	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	return status
}

// probeRoleConfig is a probe-role config pointed at dir. businessConfig already
// exists in main_test.go; this is its counterpart.
func probeRoleConfig(dir string) string {
	return fmt.Sprintf(`role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
harvest_inband: false
inject_mode: replace-only
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// businessConfigWithModels is businessConfig (main_test.go) plus a models list.
// The self-test validates its model against that list in either role, so a
// business-role fixture without one could only ever produce a 400 and would
// never reach the behaviour under test.
func businessConfigWithModels(dir string) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
harvest_inband: false
inject_mode: replace-only
dry_run: true
log_decisions: false
models:
  - gpt-5.5
  - gpt-5.6-sol
`, dir)
}

// probeRoleConfigModels is probeRoleConfig with a caller-chosen model list, so
// a test can vary the width of the readiness matrix.
func probeRoleConfigModels(dir string, models ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
harvest_inband: false
inject_mode: replace-only
dry_run: true
log_decisions: false
models:
`, dir)
	for _, model := range models {
		fmt.Fprintf(&b, "  - %s\n", model)
	}
	return b.String()
}

// seedMgmtBucket writes one synthetic bucket and returns the token it stored, so a
// caller can assert that exact value never reaches a response body.
func seedMgmtBucket(t *testing.T, dir, authID, model string, issued time.Time) string {
	t.Helper()
	rec := storeRecordFor(authID, model, issued, 292)
	mustWriteRecord(t, dir, rec)
	if err := writeStoreIndex(dir, wallClock(), testTTL, 292); err != nil {
		t.Fatalf("writeStoreIndex: %v", err)
	}
	return rec.Value
}

// mgmtBucketByKey finds one bucket in a status document.
func mgmtBucketByKey(status mgmtStatus, authID, model string) (mgmtBucket, bool) {
	for _, bucket := range status.Buckets {
		if bucket.AuthID == authID && bucket.Model == model {
			return bucket, true
		}
	}
	return mgmtBucket{}, false
}

// --- 1. secrecy ----------------------------------------------------------

// The whole design rests on values never leaving the store. The status document
// is the most likely place to leak one by accident, because it is assembled
// from the very records that hold them.
func TestManagementStatusNeverLeaksTokenValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-5 * time.Minute)
	secrets := []string{
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued),
		seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued),
		seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued),
	}

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	body := string(resp.Body)
	for i, secret := range secrets {
		// A 40-character prefix is far past the point where a collision could
		// be accidental, and short enough to catch a truncated leak.
		needle := secret[:40]
		if strings.Contains(body, needle) {
			t.Errorf("status body leaked token %d", i)
		}
	}
	// Guard against the assertion passing because the body is empty or the
	// buckets never made it in: the test must be looking at real data.
	if len(resp.Body) == 0 {
		t.Fatal("status body is empty; the leak assertions above proved nothing")
	}
	// The status document enumerates *target* buckets -- configured models
	// crossed with the accounts seen -- so missing ones show up as not-ready
	// rather than being absent. Asserting a total would therefore be asserting
	// that arithmetic, not that the leak checks saw real data. Checking the
	// seeded buckets are present and ready is the assertion that matters.
	status := mustManagementStatus(t)
	for _, want := range [][2]string{
		{"codex-alpha.json", "gpt-5.5"},
		{"codex-alpha.json", "gpt-5.6-sol"},
		{"codex-beta.json", "gpt-5.5"},
	} {
		bucket, ok := mgmtBucketByKey(status, want[0], want[1])
		if !ok || !bucket.Ready {
			t.Fatalf("seeded bucket %s/%s is not reported ready; the leak assertions above were not exercised against real records", want[0], want[1])
		}
	}
}

// The resource shell is served on the unauthenticated prefix. It must therefore
// be a fixed asset: the moment it renders anything derived from runtime state,
// that state is public. Byte equality across a store mutation is the assertion
// that keeps it honest.
func TestResourceShellIsStaticAndDataFree(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	before := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if before.StatusCode != http.StatusOK {
		t.Fatalf("resource shell returned %d, want 200", before.StatusCode)
	}
	if len(before.Body) == 0 {
		t.Fatal("resource shell body is empty; nothing was actually served")
	}

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-secret-account.json", "gpt-5.6-sol", issued)

	after := driveManagement(t, http.MethodGet, mgmtResourcePath, nil)
	if string(before.Body) != string(after.Body) {
		t.Error("resource shell changed after the store changed; it is rendering runtime state on an unauthenticated route")
	}

	shell := string(after.Body)
	for _, forbidden := range []string{
		secret[:40],
		"codex-secret-account.json",
		dir,
	} {
		if strings.Contains(shell, forbidden) {
			t.Errorf("resource shell embedded runtime data: %q", truncateMgmtLog([]byte(forbidden)))
		}
	}
}

// --- 2. capability and route declaration ---------------------------------

func TestRegistrationAdvertisesManagementAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	raw, err := json.Marshal(map[string]any{
		"config_yaml":    []byte(probeRoleConfig(dir)),
		"schema_version": 6,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	out, errHandle := handleMethod(pluginabi.MethodPluginRegister, raw)
	if errHandle != nil {
		t.Fatalf("handleMethod(plugin.register): %v", errHandle)
	}
	var reg struct {
		Capabilities map[string]any `json:"capabilities"`
	}
	if result := decodeMgmtEnvelope(t, out); len(result) > 0 {
		if errUnmarshal := json.Unmarshal(result, &reg); errUnmarshal != nil {
			t.Fatalf("decode registration: %v", errUnmarshal)
		}
	}
	enabled, ok := reg.Capabilities["management_api"].(bool)
	if !ok {
		t.Fatalf("registration does not declare management_api at all; capabilities: %v", reg.Capabilities)
	}
	if !enabled {
		t.Error("management_api is false; the management routes will never be mounted")
	}
}

// This is the sharpest footgun on the management surface. CPA's
// routeDeclaresLegacyMenuResource (internal/pluginhost/management.go:156) treats
// any GET route carrying a Menu label as a *legacy resource*, and re-registers
// it under /v0/resource/plugins/<id>/ -- which is not management-authenticated.
// Putting a Menu on the status route would therefore publish the whole status
// document, silently, with no other symptom.
func TestManagementDataRoutesCarryNoMenu(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Routes) == 0 {
		t.Fatal("no management routes declared; this test would pass vacuously")
	}
	for _, route := range reg.Routes {
		if strings.TrimSpace(route.Menu) != "" {
			t.Errorf("management route %s %s carries Menu=%q, which demotes it to the unauthenticated resource prefix",
				route.Method, route.Path, route.Menu)
		}
	}
}

func TestManagementRegisterExposesExactlyOneMenuResource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)
	if len(reg.Resources) != 1 {
		t.Fatalf("declared %d resources, want exactly 1 (the HTML shell)", len(reg.Resources))
	}
	if strings.TrimSpace(reg.Resources[0].Menu) == "" {
		t.Error("the shell resource has no Menu label, so it will not appear in the management centre")
	}
}

// --- 3. buckets/clear ----------------------------------------------------

func TestClearSingleBucketLeavesOthersIntact(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued)

	resp := driveManagementJSON(t, http.MethodPost, mgmtClearPath, map[string]any{
		"auth_id": "codex-alpha.json",
		"model":   "gpt-5.5",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var result mgmtClearResult
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if result.Cleared != 1 {
		t.Errorf("cleared %d buckets, want 1", result.Cleared)
	}

	status := mustManagementStatus(t)
	cleared, found := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if found && cleared.Ready {
		t.Error("the cleared bucket is still reported ready; the in-memory cache outlived the file")
	}
	for _, survivor := range [][2]string{
		{"codex-alpha.json", "gpt-5.6-sol"},
		{"codex-beta.json", "gpt-5.5"},
	} {
		bucket, ok := mgmtBucketByKey(status, survivor[0], survivor[1])
		if !ok || !bucket.Ready {
			t.Errorf("clearing one bucket also took out %s/%s", survivor[0], survivor[1])
		}
	}
}

func TestClearAllBucketsRemovesEveryRecord(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued)

	resp := driveManagementJSON(t, http.MethodPost, mgmtClearPath, map[string]any{"all": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear all returned %d, want 200 (body: %s)", resp.StatusCode, truncateMgmtLog(resp.Body))
	}
	var result mgmtClearResult
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatalf("decode clear result: %v", err)
	}
	if result.Cleared != 3 {
		t.Errorf("cleared %d buckets, want 3", result.Cleared)
	}

	for _, rel := range regularFiles(t, dir) {
		if strings.HasSuffix(rel, "/"+indexFileName) || rel == indexFileName {
			continue
		}
		t.Errorf("bucket file survived clear-all: %s", rel)
	}
	for _, bucket := range mustManagementStatus(t).Buckets {
		if bucket.Ready {
			t.Errorf("bucket %s/%s still ready after clear-all", bucket.AuthID, bucket.Model)
		}
	}
}

// The clear endpoint takes an account and a model straight from a request body
// and turns them into a filesystem path. Without sanitising, "auth_id": ".."
// walks out of the store and deletes whatever is next door.
func TestClearBucketRejectsPathTraversal(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "store")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	// The sentinel sits one level above the store, exactly where "../<model>"
	// lands. Its name matches the <model>.json shape so a successful traversal
	// would actually remove it.
	sentinel := filepath.Join(base, "sentinel.json")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	cases := []struct {
		name   string
		authID string
		model  string
	}{
		{"parent via auth", "..", "sentinel"},
		{"parent via model", "codex-alpha.json", "../sentinel"},
		{"nested parent", "../..", "sentinel"},
		{"slash in auth", "codex/../..", "sentinel"},
		{"backslash in auth", `..\..`, "sentinel"},
		{"absolute model", "codex-alpha.json", filepath.ToSlash(sentinel)},
		{"empty auth", "", "gpt-5.5"},
		{"empty model", "codex-alpha.json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtClearPath, map[string]any{
				"auth_id": tc.authID,
				"model":   tc.model,
			})
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("traversal accepted: status %d, want 4xx", resp.StatusCode)
			}
			if _, err := os.Stat(sentinel); err != nil {
				t.Fatalf("sentinel outside the store was removed: %v", err)
			}
		})
	}

	// The legitimate bucket must still be there: a blanket refusal that also
	// broke normal clears would pass every assertion above.
	if _, err := os.Stat(filepath.Join(dir, "codex-alpha.json", "gpt-5.5.json")); err != nil {
		t.Fatalf("the ordinary bucket was collateral damage: %v", err)
	}
}

func TestClearBucketRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := snapshotDir(t, dir)

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("this is not json")},
		{"empty body", nil},
		{"empty object", []byte(`{}`)},
		{"model without auth", []byte(`{"model":"gpt-5.5"}`)},
		{"auth without model", []byte(`{"auth_id":"codex-alpha.json"}`)},
		{"all and auth together", []byte(`{"all":true,"auth_id":"codex-alpha.json","model":"gpt-5.5"}`)},
		{"json array", []byte(`["codex-alpha.json"]`)},
		{"wrong types", []byte(`{"auth_id":42,"model":true}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtClearPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
	if !equalSnapshots(before, snapshotDir(t, dir)) {
		t.Error("a rejected clear still modified the store")
	}
}

// --- 4. selftest ---------------------------------------------------------
//
// This route used to be /probe and claimed to harvest. It cannot: a request
// issued through host.model.execute is marked to skip the calling plugin's own
// interceptors (host_callbacks_unix.go:43 -> host_callbacks.go:304 -> :306), so
// the response never reaches interceptResponse and nothing is ever stored. It
// is now a connectivity self-test, and the tests below encode that.

// The self-test says nothing about buckets, so it is not a probe-role
// operation. Refusing it under role: business would only stop an operator
// checking whether the business role can still reach upstream -- which is
// exactly when they most want to ask.
func TestSelftestWorksRegardlessOfRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func(dir string) string
	}{
		{"probe", probeRoleConfig},
		{"business", func(dir string) string { return businessConfigWithModels(dir) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mustConfigure(t, tc.cfg(dir))

			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
			// Without a host API the call cannot succeed, so the assertion is
			// about *why* it failed: never because of the role.
			if resp.StatusCode == http.StatusConflict {
				t.Errorf("selftest refused with 409 under role %s: %s", tc.name, truncateMgmtLog(resp.Body))
			}
			if strings.Contains(strings.ToLower(string(resp.Body)), "role") {
				t.Errorf("selftest under role %s blamed the role: %s", tc.name, truncateMgmtLog(resp.Body))
			}
		})
	}
}

// The model must be one the operator configured. Firing at an arbitrary string
// would spend quota on a model nobody is tracking.
func TestSelftestRejectsUnconfiguredModel(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-4-turbo"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("selftest with an unconfigured model returned %d, want 400", resp.StatusCode)
	}
	// A configured one must get past this guard, or the assertion above would
	// hold for the wrong reason.
	next := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})
	if next.StatusCode == http.StatusBadRequest {
		t.Error("a configured model was also rejected as unconfigured")
	}
}

// Without a host API there is nothing to execute against. A self-test reports
// its finding in the body rather than as an HTTP error -- 200 means "the
// self-test ran", and `reached` carries the answer -- so what has to hold here
// is that it reports honestly: it did not reach, it harvested nothing, and it
// left the store alone. Claiming reached on a call that never left the process
// is the failure this guards against.
func TestSelftestFailsClosedWithoutHostAPI(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{"model": "gpt-5.5"})

	// 503, and deliberately not 200 or a loose >= 400.
	//
	// This assertion was rewritten three times while the endpoint was being
	// built -- >= 400, then 200 with reached:false, then back to 503 -- so the
	// reasoning is recorded here rather than left to be re-derived. It is
	// settled: do not widen or relax it.
	//
	// Two failures look similar from the outside and are not:
	//
	//   no host callback table  -- the self-test never ran. The plugin did not
	//                              get its host interface, so nothing was
	//                              attempted. This says nothing whatsoever
	//                              about upstream.
	//   host present, no answer -- the self-test ran and the path is broken.
	//                              That is what reached:false means, and it is
	//                              reported with 200 because the self-test
	//                              itself succeeded in finding out.
	//
	// Reporting the first as 200 + reached:false sends an operator to check the
	// network, the credentials and the upstream, when the actual fault is that
	// the plugin was loaded wrong. That is an expensive detour, and it lands
	// hardest during a 3am incident -- which is exactly when someone reaches
	// for a self-test. 503 Service Unavailable is the accurate statement: this
	// service is unavailable, not the one behind it.
	//
	// The 503 body comes from managementError, which carries only `error`.
	// There is deliberately no `note`: note explains why a run that *did*
	// happen stored nothing, and no run happened here.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("selftest with no host API returned %d, want 503: %s", resp.StatusCode, truncateMgmtLog(resp.Body))
	}

	var result mgmtSelftestResult
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatalf("decode selftest result: %v (body: %s)", err, truncateMgmtLog(resp.Body))
	}
	if result.Reached {
		t.Error("selftest claimed it reached upstream with no host API available")
	}
	if result.Harvested {
		t.Error("selftest claimed a harvest; it structurally cannot harvest")
	}
	if strings.TrimSpace(result.Error) == "" {
		t.Error("the 503 carries no explanation, leaving the operator with no reason")
	}
	if files := regularFiles(t, dir); len(files) != 0 {
		t.Errorf("a failed selftest still wrote to the store: %v", files)
	}
}

func TestSelftestRejectsMalformedBody(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name string
		body []byte
	}{
		{"not json", []byte("nope")},
		{"empty body", nil},
		{"no model", []byte(`{}`)},
		{"empty model", []byte(`{"model":""}`)},
		{"wrong type", []byte(`{"model":42}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagement(t, http.MethodPost, mgmtSelftestPath, tc.body)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("malformed selftest body accepted: status %d, want 4xx", resp.StatusCode)
			}
		})
	}
}

// auth_id is caller-supplied and gets interpolated into an outbound request, so
// it goes through the same sanitiser as a store path. The cases mirror
// TestClearBucketRejectsPathTraversal: one rule for "is this identifier safe to
// pass on" rather than two that can drift apart.
//
// The ordering matters as much as the rejection. The sanitiser runs before the
// host-availability check, so a bad auth_id gets its own specific 400 instead
// of being masked by the 503 -- an operator who typo'd an account name is told
// that, not told the plugin is unloaded.
func TestSelftestRejectsUnsafeAuthID(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	cases := []struct {
		name   string
		authID string
	}{
		{"parent", ".."},
		{"nested parent", "../.."},
		{"slash", "codex/../.."},
		{"backslash", `..\..`},
		{"leading slash", "/etc/passwd"},
		{"embedded null", "codex\x00.json"},
	}
	// An all-whitespace auth_id is deliberately absent from that list. The
	// implementation trims before testing for emptiness, so "   " means "I did
	// not ask to target anything" -- identical to omitting the field -- rather
	// than an unsafe value. Rejecting it would make a blank form field an error
	// instead of a default.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
				"model":   "gpt-5.5",
				"auth_id": tc.authID,
			})
			// 400 specifically, not merely "an error": a 503 here would mean
			// the unsafe value slipped past the sanitiser and was only stopped
			// by the missing host API, which would not stop it in production.
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("unsafe auth_id %q returned %d, want 400: %s",
					tc.authID, resp.StatusCode, truncateMgmtLog(resp.Body))
			}
		})
	}

	// A well-formed account name must get *past* the sanitiser, or every
	// assertion above would hold for the wrong reason. It stops at the 503
	// because this process has no host API -- which is the proof it got through.
	ok := driveManagementJSON(t, http.MethodPost, mgmtSelftestPath, map[string]any{
		"model":   "gpt-5.5",
		"auth_id": "codex-alpha.json",
	})
	if ok.StatusCode == http.StatusBadRequest {
		t.Errorf("a well-formed auth_id was rejected as unsafe: %s", truncateMgmtLog(ok.Body))
	}

	// Deliberately not tested: whether a *nonexistent* account is rejected.
	// The implementation passes an unknown id straight through and lets the
	// scheduler answer, rather than keeping a second view of the credential
	// list that could disagree with the real one. Asserting a 4xx here would
	// pin a contract that does not exist.
}

// managementFuncBody returns the source text of one top-level function in
// management.go. Used by the assertions below, which pin properties that cannot
// be reached behaviourally: the self-test bails at the host-availability check
// long before it builds a response, so anything downstream of that check is
// only observable in the source.
func managementFuncBody(t *testing.T, name string) string {
	t.Helper()
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "func "+name+"(")
	if start < 0 {
		t.Fatalf("management.go has no func %s; the selftest contract requires it", name)
	}
	// Top-level functions close with a brace in column zero.
	end := strings.Index(text[start:], "\n}")
	if end < 0 {
		t.Fatalf("could not find the end of func %s", name)
	}
	return text[start : start+end]
}

// auth_id must only ever be echoed from what the caller asked for.
//
// CPA reports no credential identity on the way back: HostModelExecutionResponse
// carries only StatusCode, Headers and Body, and a sweep of the CPA source found
// no auth-id response header of any name. This is settled, not merely
// unconfirmed -- there is nothing to look for. So any auth_id the plugin did
// not receive as input is fabricated -- and a fabricated account name in a
// self-test result is worse than an empty one, because an operator will act on
// it: check that account's quota, disable it, hand it to a colleague. The empty
// string is honest and `targeted` says why it is empty.
//
// Asserted at source level because the response is only built after the
// host-availability check, which a unit test cannot get past.
func TestSelftestAuthIDIsNeverFabricated(t *testing.T) {
	body := managementFuncBody(t, "handleSelftest")

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(body[idx:], "AuthID")
		if at < 0 {
			break
		}
		at += idx
		idx = at + len("AuthID")

		rest := strings.TrimLeft(body[idx:], " \t")
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		// authID is the sanitised value taken from the request body. Anything
		// else -- a header lookup, a helper that inspects the response -- is a
		// guess dressed up as an answer.
		if !strings.HasPrefix(value, "authID") {
			line := strings.Count(body[:at], "\n")
			t.Errorf("handleSelftest assigns AuthID from %q (about %d lines into the function); "+
				"it must come from the caller-supplied authID, because CPA reports no credential on the response",
				truncateMgmtLog([]byte(value[:min(50, len(value))])), line)
		}
	}
	if assignments == 0 {
		t.Error("no assignment to AuthID found in handleSelftest; this test would pass vacuously")
	}
}

// The echo must be verbatim and `targeted` must be derived from it.
//
// Nothing else covers this. If the echo ever crosses wires -- reporting the
// account the caller did not name -- a self-test run against a suspect account
// would come back describing a healthy different one, and the operator would
// clear the wrong credential. And if `targeted` were hard-coded or computed
// from something other than "was an auth_id supplied", an empty auth_id would
// stop being readable: the whole point of the flag is that auth_id:"" plus
// targeted:false means "we never asked", which is a different statement from
// anything the scheduler did.
//
// Source level for the same reason as the tests around it: the response is
// built after the host-availability check, which a unit test cannot pass.
func TestSelftestEchoesTargetingHonestly(t *testing.T) {
	body := managementFuncBody(t, "handleSelftest")

	at := strings.Index(body, "selftestResponse{")
	if at < 0 {
		t.Fatal("handleSelftest builds no selftestResponse; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the selftestResponse literal")
	}
	literal := body[at : at+end]

	// The echo is the sanitised request value, unmodified.
	if !strings.Contains(literal, "AuthID:") {
		t.Error("the selftestResponse does not set AuthID, so the caller is never told which account was targeted")
	} else if !strings.Contains(literal, "AuthID:    authID") && !strings.Contains(literal, "AuthID: authID") {
		t.Errorf("AuthID is not echoed verbatim from the request; literal was:\n%s", literal)
	}

	// targeted must be "did the caller supply one", nothing else.
	if !strings.Contains(literal, `Targeted:  authID != ""`) && !strings.Contains(literal, `Targeted: authID != ""`) {
		t.Errorf(`Targeted is not derived from 'authID != ""'; it must say whether the caller asked, not anything about the outcome. Literal was:`+"\n%s", literal)
	}
}

// Targeting must actually be applied, not merely reported.
//
// targeted:true is a claim that this self-test exercised one specific
// credential. If auth_id is validated and echoed but never put on the outbound
// HostModelExecutionRequest, the scheduler picks whichever account it likes and
// the result describes a request that was never made. An operator testing a
// suspect account would read a clean result for a different one -- the exact
// wrong conclusion, delivered confidently.
//
// HostModelExecutionRequest.AuthID is documented as "optionally locks execution
// to an exact credential ID" and is passed through verbatim by the host
// (internal/pluginhost/host_callbacks.go:330), so setting it is all that is
// required.
func TestSelftestTargetingIsActuallyApplied(t *testing.T) {
	body := managementFuncBody(t, "handleSelftest")

	at := strings.Index(body, "HostModelExecutionRequest{")
	if at < 0 {
		t.Fatal("handleSelftest builds no HostModelExecutionRequest; this test would pass vacuously")
	}
	end := strings.Index(body[at:], "\n\t}")
	if end < 0 {
		t.Fatal("could not find the end of the HostModelExecutionRequest literal")
	}
	literal := body[at : at+end]

	if !strings.Contains(literal, "AuthID:") {
		t.Error("the outbound HostModelExecutionRequest does not set AuthID, " +
			"so auth_id is validated and echoed but never applied: targeted:true would describe a request that was never targeted")
	}
}

// harvested must be a hard-coded false, never a computed value.
//
// The self-test genuinely cannot harvest -- the host marks its request to skip
// this plugin's own interceptors -- so any code that decides the field at
// runtime is expressing a belief that is false, and would eventually report a
// harvest that did not happen. An operator trusting that would then stop
// probing. Because the field can only be observed on a successful call, and a
// unit test has no host API to produce one, this is asserted at the source
// level: every assignment to Harvested must be the literal false.
func TestSelftestNeverClaimsHarvest(t *testing.T) {
	src, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}
	text := string(src)

	const field = "Harvested"
	if !strings.Contains(text, field) {
		t.Fatalf("management.go has no %s field; the selftest contract requires one reported as false", field)
	}

	assignments := 0
	for idx := 0; ; {
		at := strings.Index(text[idx:], field)
		if at < 0 {
			break
		}
		at += idx
		idx = at + len(field)

		rest := strings.TrimLeft(text[idx:], " \t")
		// Struct-literal form "Harvested: <value>" and assignment form
		// "Harvested = <value>" are the two ways the value gets set. A field
		// declaration ("Harvested bool `json:...`") and prose in comments are
		// neither, and are skipped.
		var value string
		switch {
		case strings.HasPrefix(rest, ":") && !strings.HasPrefix(rest, ":="):
			value = strings.TrimLeft(rest[1:], " \t")
		case strings.HasPrefix(rest, "="):
			value = strings.TrimLeft(rest[1:], " \t")
		default:
			continue
		}
		assignments++
		if !strings.HasPrefix(value, "false") {
			line := 1 + strings.Count(text[:at], "\n")
			t.Errorf("management.go:%d assigns %s a computed value (%q); it must be the literal false, because the selftest structurally cannot harvest",
				line, field, truncateMgmtLog([]byte(value[:min(40, len(value))])))
		}
	}
	if assignments == 0 {
		t.Error("no assignment to Harvested found; this test would pass vacuously")
	}
}

// --- 5. unknown paths and malformed input --------------------------------

func TestManagementUnknownPathReturns404(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	// "/v0/management/codex-turn-state" and "" are deliberately absent: the
	// implementation maps any path ending in the plugin id -- and the empty
	// path -- onto the data-free dashboard shell (isDashboardPath in
	// management.go), because the resource route arrives as the plugin root.
	// Serving the shell there is a choice, not a bug, and the shell carries no
	// data. These are the paths that must genuinely 404.
	for _, path := range []string{
		"/v0/management/codex-turn-state/nope",
		"/v0/management/other-plugin/status",
		"/v0/management/codex-turn-state/status/extra",
		"/v0/management/codex-turn-state/buckets",
	} {
		t.Run(path, func(t *testing.T) {
			resp := driveManagement(t, http.MethodGet, path, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("unknown path %q returned %d, want 404", path, resp.StatusCode)
			}
		})
	}
}

// A wrong method on a known path must not fall through to the handler.
func TestManagementRejectsWrongMethod(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))
	before := snapshotDir(t, dir)

	cases := []struct{ method, path string }{
		{http.MethodPost, mgmtStatusPath},
		{http.MethodDelete, mgmtStatusPath},
		{http.MethodGet, mgmtClearPath},
		{http.MethodGet, mgmtSelftestPath},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := driveManagement(t, tc.method, tc.path, nil)
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("%s %s returned %d, want 4xx", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
	if !equalSnapshots(before, snapshotDir(t, dir)) {
		t.Error("a wrong-method call still modified the store")
	}
}

// handleMethod must not panic on input the host would never send but an
// attacker on the management port could.
func TestManagementHandleSurvivesMalformedInput(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	for _, raw := range [][]byte{
		nil,
		[]byte(""),
		[]byte("{"),
		[]byte("[]"),
		[]byte(`{"Method":42}`),
		[]byte(`{"Path":null,"Method":null}`),
	} {
		// A panic here fails the test by unwinding; an error return is a
		// perfectly good outcome too. The only unacceptable result is a crash,
		// which would take the whole CPA process down with it.
		if _, err := handleMethod(pluginabi.MethodManagementHandle, raw); err != nil {
			t.Logf("management.handle rejected %q: %v", truncateMgmtLog(raw), err)
		}
	}
}

// --- 6. counters ---------------------------------------------------------

// Counters are process-global and every other test in this package also drives
// decisions, so the assertions compare deltas. Absolute values would make this
// test depend on execution order.
func TestManagementCountersTrackDecisions(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, businessConfig(dir, false))

	issued := wallClock().Add(-time.Minute)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)

	base := mustManagementStatus(t).Counters

	// A 312 on a bucket that holds a live 292: one substitute.
	interceptAfter(t, request("codex-alpha.json", "gpt-5.5", fakeToken(312, issued)))
	// A bucket with no template at all: one pass.
	interceptAfter(t, request("codex-beta.json", "gpt-5.6-sol", fakeToken(312, issued)))
	// No auth id: one skip.
	noAuth := request("", "gpt-5.5", fakeToken(312, issued))
	interceptAfter(t, noAuth)

	after := mustManagementStatus(t).Counters
	if got := after.Substitute - base.Substitute; got != 1 {
		t.Errorf("substitute delta = %d, want 1", got)
	}
	if got := after.Pass - base.Pass; got < 1 {
		t.Errorf("pass delta = %d, want at least 1", got)
	}
	if got := after.Skip - base.Skip; got < 1 {
		t.Errorf("skip delta = %d, want at least 1", got)
	}
}

// --- status content ------------------------------------------------------

func TestStatusReflectsConfiguredValues(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.Role != roleProbe {
		t.Errorf("role = %q, want %q", status.Role, roleProbe)
	}
	if !status.DryRun {
		t.Error("dry_run = false, want true")
	}
	if status.InjectMode != "replace-only" {
		t.Errorf("inject_mode = %q, want replace-only", status.InjectMode)
	}
	if status.TTLSeconds != 3600 {
		t.Errorf("ttl_seconds = %d, want 3600", status.TTLSeconds)
	}
	if status.TemplateLength != 292 || status.ReplaceLength != 312 {
		t.Errorf("lengths = %d/%d, want 292/312", status.TemplateLength, status.ReplaceLength)
	}
	if len(status.Models) != 2 {
		t.Errorf("models = %v, want the 2 configured", status.Models)
	}
}

// The per-bucket len reports the *length* of the stored value, never the value.
// A length is a safe thing to publish -- it is the whole tell this plugin keys
// on, 292 against 312 -- but a field sitting right next to the token is exactly
// where one gets pasted by accident, so this asserts both halves: the number is
// a plausible length, and the document still carries no token.
func TestStatusBucketLenIsALengthNotAValue(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	issued := wallClock().Add(-time.Minute)
	secret := seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)

	resp := driveManagement(t, http.MethodGet, mgmtStatusPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status returned %d, want 200", resp.StatusCode)
	}
	if strings.Contains(string(resp.Body), secret[:40]) {
		t.Fatal("status leaked the token value alongside its length")
	}

	var status mgmtStatus
	if err := json.Unmarshal(resp.Body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	stored, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if !ok {
		t.Fatal("the seeded bucket is missing from status")
	}
	if stored.Len != 292 {
		t.Errorf("len = %d for a stored 292-character template, want 292", stored.Len)
	}
	// A bucket that was never harvested has no value and so no length.
	missing, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the unharvested target bucket is missing from status")
	}
	if missing.Len != 0 {
		t.Errorf("len = %d for a bucket that was never harvested, want 0", missing.Len)
	}
}

// --- 7. the readiness matrix --------------------------------------------

// Degradation must be visible. A unit test has no host API, so host.auth.list
// always fails here and the account list falls back to whatever the store
// happens to hold -- which is precisely the state where the page is most
// misleading if it says nothing: a never-probed account is invisible, so an
// empty or short matrix reads as "there is nothing to probe" when it means "we
// could not ask what there is".
//
// Silent degradation has been the recurring failure on this surface, so this
// asserts both halves: the source is named, and the reason is carried.
func TestStatusReportsDegradedAccountSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", wallClock().Add(-time.Minute))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q with no host API, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("accounts_error is empty on the degraded path, so the fallback is silent")
	}
}

// The matrix is the set of buckets we intend to fill, not the set already
// filled. Straight after a deploy nothing is harvested, and that is exactly
// when an operator needs to see "0 of N" and pick something to act on.
func TestStatusMatrixCoversEveryTarget(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol"))

	issued := wallClock().Add(-time.Minute)
	// Two accounts become visible through the store (the degraded path derives
	// them from records), crossed with two configured models: a 2x2 matrix of
	// which only three cells are filled.
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", issued)

	status := mustManagementStatus(t)
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
	if status.TargetsTotal != 4 {
		t.Errorf("targets_total = %d for 2 accounts x 2 models, want 4", status.TargetsTotal)
	}

	// The unharvested cell must be present and honest about being empty.
	gap, ok := mgmtBucketByKey(status, "codex-beta.json", "gpt-5.6-sol")
	if !ok {
		t.Fatal("the never-harvested combination is missing from the matrix; the page would not show it as a gap")
	}
	if gap.Ready {
		t.Error("a never-harvested cell reports ready")
	}
	if gap.Len != 0 {
		t.Errorf("a never-harvested cell reports len = %d, want 0", gap.Len)
	}
	if gap.IssuedAt != "" || gap.ExpiresAt != "" {
		t.Errorf("a never-harvested cell carries timestamps: issued=%q expires=%q", gap.IssuedAt, gap.ExpiresAt)
	}
	if gap.SecondsLeft != 0 {
		t.Errorf("a never-harvested cell reports seconds_left = %d, want 0", gap.SecondsLeft)
	}

	// Reverse control: widen the model list and the matrix must widen with it.
	// Without this, an implementation that just listed on-disk records would
	// satisfy every assertion above.
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol", "gpt-6-astra"))
	wider := mustManagementStatus(t)
	if wider.TargetsTotal != 6 {
		t.Errorf("targets_total = %d after adding a third model to 2 accounts, want 6", wider.TargetsTotal)
	}
}

// targets_ready backs the "18 of 25" counter at the top of the page. If it is
// computed separately from the cells it summarises, the two drift and the
// number becomes a confident lie.
func TestStatusTargetsReadyMatchesBuckets(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5", "gpt-5.6-sol"))

	fresh := wallClock().Add(-time.Minute)
	stale := wallClock().Add(-2 * time.Hour)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", fresh)
	seedMgmtBucket(t, dir, "codex-beta.json", "gpt-5.5", fresh)
	// An expired record keeps its cell but must not be counted ready.
	writeRawRecord(t, dir, storeRecordFor("codex-alpha.json", "gpt-5.6-sol", stale, 292))

	status := mustManagementStatus(t)
	counted := 0
	for _, bucket := range status.Buckets {
		if bucket.Ready {
			counted++
		}
	}
	if status.TargetsReady != counted {
		t.Errorf("targets_ready = %d but %d cells report ready", status.TargetsReady, counted)
	}
	if status.TargetsReady != 2 {
		t.Errorf("targets_ready = %d, want 2 (the expired record must not count)", status.TargetsReady)
	}
}

// The page re-fetches on a timer. Unstable ordering would make rows and columns
// jump under the operator's cursor mid-read.
func TestStatusBucketOrderIsStable(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.6-sol", "gpt-5.5"))

	issued := wallClock().Add(-time.Minute)
	// Seeded out of order on purpose, so a pass-through of map or disk order
	// would not accidentally come out sorted.
	seedMgmtBucket(t, dir, "codex-zulu.json", "gpt-5.6-sol", issued)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	seedMgmtBucket(t, dir, "codex-mike.json", "gpt-5.6-sol", issued)

	first := mustManagementStatus(t)
	second := mustManagementStatus(t)

	if len(first.Buckets) != len(second.Buckets) {
		t.Fatalf("two consecutive calls returned %d and %d buckets", len(first.Buckets), len(second.Buckets))
	}
	for i := range first.Buckets {
		if first.Buckets[i].AuthID != second.Buckets[i].AuthID || first.Buckets[i].Model != second.Buckets[i].Model {
			t.Fatalf("order changed between calls at index %d: %s/%s then %s/%s",
				i, first.Buckets[i].AuthID, first.Buckets[i].Model,
				second.Buckets[i].AuthID, second.Buckets[i].Model)
		}
	}
	// Stable is not enough on its own -- a consistently wrong order is stable
	// too. The contract is (auth_id, model) lexicographic.
	for i := 1; i < len(first.Buckets); i++ {
		prev, cur := first.Buckets[i-1], first.Buckets[i]
		if prev.AuthID > cur.AuthID || (prev.AuthID == cur.AuthID && prev.Model > cur.Model) {
			t.Errorf("buckets are not sorted by (auth_id, model): %s/%s precedes %s/%s",
				prev.AuthID, prev.Model, cur.AuthID, cur.Model)
		}
	}
}

// An empty store must not produce a bare empty array with no explanation. On
// the degraded path there is genuinely nothing to list -- the accounts can only
// come from records that do not exist -- so the empty matrix is correct, but it
// has to arrive labelled. "We could not ask" and "there is nothing to probe"
// render identically otherwise, and this is the defect that motivated the
// accounts_source field.
func TestStatusEmptyStoreStillNamesItsSource(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	status := mustManagementStatus(t)
	if status.AccountsSource != "store" {
		t.Errorf("accounts_source = %q, want %q", status.AccountsSource, "store")
	}
	if strings.TrimSpace(status.AccountsError) == "" {
		t.Error("an empty matrix arrived with no accounts_error, so it reads as 'nothing to probe'")
	}
	if status.TargetsReady != 0 {
		t.Errorf("targets_ready = %d on an empty store, want 0", status.TargetsReady)
	}
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
}

// A record for a model that is no longer configured still has to appear.
// Dropping it would hide the drift: an operator who trimmed the model list
// would never learn that stale buckets are still on disk being served from.
func TestStatusListsBucketsOutsideTheMatrix(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfigModels(dir, "gpt-5.5"))

	issued := wallClock().Add(-time.Minute)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", issued)
	// Not in the configured model list.
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-6-astra", issued)

	status := mustManagementStatus(t)
	drifted, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-6-astra")
	if !ok {
		t.Fatal("a bucket for an unconfigured model was dropped from status; the drift becomes invisible")
	}
	if !drifted.Ready {
		t.Error("the drifted bucket is on disk and live, but reports not ready")
	}
	if status.TargetsTotal != len(status.Buckets) {
		t.Errorf("targets_total = %d but buckets has %d entries", status.TargetsTotal, len(status.Buckets))
	}
}

// An expired record must be reported as not ready. The page uses this to decide
// whether a bucket needs re-probing, so agreeing with loadStore is the point.
func TestStatusMarksExpiredBucketsNotReady(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	fresh := wallClock().Add(-time.Minute)
	stale := wallClock().Add(-2 * time.Hour)
	seedMgmtBucket(t, dir, "codex-alpha.json", "gpt-5.5", fresh)
	writeRawRecord(t, dir, storeRecordFor("codex-alpha.json", "gpt-5.6-sol", stale, 292))
	if err := writeStoreIndex(dir, wallClock(), testTTL, 292); err != nil {
		t.Fatalf("writeStoreIndex: %v", err)
	}

	status := mustManagementStatus(t)
	live, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.5")
	if !ok || !live.Ready {
		t.Error("the fresh bucket is not reported ready")
	}
	expired, ok := mgmtBucketByKey(status, "codex-alpha.json", "gpt-5.6-sol")
	if ok && expired.Ready {
		t.Error("an expired bucket is reported ready; the page would show it as usable and --until-complete would stop early")
	}
}
