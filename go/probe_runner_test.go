package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for the in-plugin probe runner.
//
// The load-bearing properties here are not "did it fill a bucket" -- that needs a
// real upstream -- but the three that cost something when they are wrong:
//
//   - a sweep never starts in a role that must not flip credential state, on an
//     empty selection, or without the two keys it needs;
//   - credential state is always put back, exits before enable flags, including
//     when the operator pressed stop halfway;
//   - no proxy password reaches the transcript or the run error, because both
//     are rendered on a page that needs no management key.
//
// Every proxy string below is fabricated and points at .invalid, which RFC 2606
// reserves and which can never resolve. testProxySecret and testProxyWithPW come
// from probe_scope_test.go, deliberately: one password, greppable from one place.

// --- fake CPA ------------------------------------------------------------

// fakeAuthSeed describes one credential the fake CPA should publish.
type fakeAuthSeed struct {
	name string
	// authIndex is raw JSON -- "0" or `"a"` -- so the fake can publish both
	// shapes CPA has been seen to use and check that the runner echoes back
	// exactly what it was given.
	authIndex string
	disabled  bool
	proxyURL  string
}

type fakeAuth struct {
	seed     fakeAuthSeed
	disabled bool
	proxyURL string
}

// fakeCPA stands in for CPA's own public API: the four management calls a sweep
// makes and the one upstream POST.
//
// It keeps real per-credential state, which matters: setProxyVerified only earns
// its keep against a server that can answer a read-back honestly, and a fake that
// returned 200 to everything would pass these tests while the production failure
// mode -- a PATCH that answers 200 and changes nothing -- went untested. That
// mode is available here as ignoreProxyWrites.
type fakeCPA struct {
	mu     sync.Mutex
	server *httptest.Server

	order    []string
	accounts map[string]*fakeAuth
	// proxyAtEnable records the exit each credential was pointing at the instant
	// it was re-enabled. That is the hazard the restore order exists to prevent,
	// so it is observed directly rather than inferred from the call sequence.
	proxyAtEnable map[string]string

	// ignoreProxyWrites answers 200 to PATCH .../fields and changes nothing.
	ignoreProxyWrites bool
	// onFire runs inside the /v1/responses handler, i.e. while the sweep is
	// waiting on it. It is how a test reaches in mid-run.
	onFire func()
	// gate holds every request until it is closed, so a test can keep a run open.
	gate chan struct{}
}

func newFakeCPA(t *testing.T, seeds ...fakeAuthSeed) *fakeCPA {
	t.Helper()
	fake := &fakeCPA{
		accounts:      make(map[string]*fakeAuth, len(seeds)),
		proxyAtEnable: make(map[string]string, len(seeds)),
	}
	for _, seed := range seeds {
		fake.accounts[seed.name] = &fakeAuth{seed: seed, disabled: seed.disabled, proxyURL: seed.proxyURL}
	}
	fake.server = httptest.NewServer(fake)
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeCPA) record(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, fmt.Sprintf(format, args...))
}

func (f *fakeCPA) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

func (f *fakeCPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.gate != nil {
		<-f.gate
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthFiles:
		f.record("files")
		f.writeJSON(w, map[string]any{"files": f.fileList()})
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthDownload:
		f.serveDownload(w, r)
	case r.Method == http.MethodPatch && r.URL.Path == probeRouteAuthFields:
		f.servePatchFields(w, r)
	case r.Method == http.MethodPatch && r.URL.Path == probeRouteAuthStatus:
		f.servePatchStatus(w, r)
	case r.Method == http.MethodPost && r.URL.Path == probeRouteResponses:
		f.serveFire(w, r)
	default:
		http.Error(w, `{"error":"no such route"}`, http.StatusNotFound)
	}
}

func (f *fakeCPA) fileList() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, 0, len(f.accounts))
	for _, account := range f.accounts {
		out = append(out, map[string]any{
			"name":       account.seed.name,
			"auth_index": json.RawMessage(account.seed.authIndex),
			"disabled":   account.disabled,
			"provider":   "codex",
		})
	}
	return out
}

func (f *fakeCPA) serveDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f.record("download %s", name)
	f.mu.Lock()
	account, found := f.accounts[name]
	proxy := ""
	if found {
		proxy = account.proxyURL
	}
	f.mu.Unlock()
	if !found {
		http.Error(w, `{"error":"no such credential"}`, http.StatusNotFound)
		return
	}
	f.writeJSON(w, map[string]any{"type": "codex", probeProxyField: proxy})
}

// patchBody is the shape both PATCH routes accept. proxy_url is a pointer so the
// fake can tell "not in this request" from "set to empty".
type patchBody struct {
	Name      string          `json:"name"`
	Disabled  bool            `json:"disabled"`
	ProxyURL  *string         `json:"proxy_url"`
	AuthIndex json.RawMessage `json:"auth_index"`
}

// decodePatch also enforces the auth_index contract: the runner passes CPA's own
// raw JSON straight back, so anything else here means it has started guessing at
// the field's type -- which would address the write at the wrong credential.
func (f *fakeCPA) decodePatch(w http.ResponseWriter, r *http.Request) (*fakeAuth, patchBody, bool) {
	var body patchBody
	if errDecode := json.NewDecoder(r.Body).Decode(&body); errDecode != nil {
		http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
		return nil, body, false
	}
	f.mu.Lock()
	account, found := f.accounts[body.Name]
	f.mu.Unlock()
	if !found {
		http.Error(w, `{"error":"no such credential"}`, http.StatusNotFound)
		return nil, body, false
	}
	if got := strings.TrimSpace(string(body.AuthIndex)); got != account.seed.authIndex {
		http.Error(w, `{"error":"auth_index was not echoed back verbatim"}`, http.StatusBadRequest)
		return nil, body, false
	}
	return account, body, true
}

func (f *fakeCPA) servePatchFields(w http.ResponseWriter, r *http.Request) {
	account, body, ok := f.decodePatch(w, r)
	if !ok {
		return
	}
	value := ""
	if body.ProxyURL != nil {
		value = *body.ProxyURL
	}
	// Recorded by position in the seeded list rather than by value: a recorded
	// call is printed on failure, and a proxy URL printed there would put the
	// password in the test log.
	f.record("fields %s", body.Name)
	if !f.ignoreProxyWrites {
		f.mu.Lock()
		account.proxyURL = value
		f.mu.Unlock()
	}
	f.writeJSON(w, map[string]any{"status": "ok"})
}

func (f *fakeCPA) servePatchStatus(w http.ResponseWriter, r *http.Request) {
	account, body, ok := f.decodePatch(w, r)
	if !ok {
		return
	}
	f.record("status %s disabled=%t", body.Name, body.Disabled)
	f.mu.Lock()
	account.disabled = body.Disabled
	if !body.Disabled {
		f.proxyAtEnable[body.Name] = account.proxyURL
	}
	f.mu.Unlock()
	f.writeJSON(w, map[string]any{"status": "ok"})
}

func (f *fakeCPA) serveFire(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Model string `json:"model"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.record("fire %s", body.Model)
	if r.Header.Get(turnStateHeader) != "" {
		// Sending a stale state is what stops the upstream minting a fresh one,
		// so a sweep that grew this header would silently harvest nothing.
		http.Error(w, `{"error":"the probe must not send `+turnStateHeader+`"}`, http.StatusBadRequest)
		return
	}
	if f.onFire != nil {
		f.onFire()
	}
	f.writeJSON(w, map[string]any{"id": "resp_test", "output": []any{}})
}

func (f *fakeCPA) writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// state reports one credential's current disabled flag and exit.
func (f *fakeCPA) state(name string) (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	account := f.accounts[name]
	if account == nil {
		return false, ""
	}
	return account.disabled, account.proxyURL
}

func (f *fakeCPA) exitAtEnable(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proxyAtEnable[name]
}

// --- helpers -------------------------------------------------------------

// probeTestAccount and probeTestModel are spelled unlike anything in the other
// test files on purpose: the store cache is process-global, and a bucket key
// shared with another test could make a sweep decide there is nothing to fill.
const (
	probeTestAccount = "codex-runner-a.json"
	probeTestOther   = "codex-runner-b.json"
	probeTestModel   = "gpt-runner-1"
)

// probeConfigOptions is one test's config, as fields rather than as YAML text.
// A case that wants one thing missing clears one field; appending an override
// line to a rendered document would just produce a duplicate key, which is a
// yaml.v3 error rather than an override.
type probeConfigOptions struct {
	dir      string
	baseURL  string
	role     string
	apiKey   string
	mgmtKey  string
	accounts []string
	models   []string
	proxies  []string
}

// probeTestOptions is a complete, startable probe config. Cases narrow it.
func probeTestOptions(dir, baseURL string) probeConfigOptions {
	return probeConfigOptions{
		dir:      dir,
		baseURL:  baseURL,
		role:     roleProbe,
		apiKey:   "test-api-key",
		mgmtKey:  "test-mgmt-key",
		accounts: []string{probeTestAccount},
		models:   []string{probeTestModel},
	}
}

func probeTestConfig(t *testing.T, opts probeConfigOptions) string {
	t.Helper()
	var builder strings.Builder
	fmt.Fprintf(&builder, "role: %s\nstore_dir: %q\nlog_decisions: false\n", opts.role, opts.dir)
	fmt.Fprintf(&builder, "probe_base_url: %q\n", opts.baseURL)
	fmt.Fprintf(&builder, "probe_api_key: %q\nprobe_management_key: %q\n", opts.apiKey, opts.mgmtKey)
	for _, block := range []struct {
		key    string
		values []string
	}{
		{"probe_accounts", opts.accounts},
		{"models", opts.models},
		{"probe_proxies", opts.proxies},
	} {
		if len(block.values) == 0 {
			continue
		}
		fmt.Fprintf(&builder, "%s:\n", block.key)
		for _, value := range block.values {
			fmt.Fprintf(&builder, "  - %q\n", value)
		}
	}
	return builder.String()
}

// resetProbeRunner returns the package-level runner and store cache to a clean
// state, and makes sure no sweep from an earlier case is still in flight.
//
// The store cache matters as much as the runner: refreshStoreLocked keeps its
// last scan in a process-global field, and a map left behind by another test
// could report a bucket live and make a sweep decide it has nothing to do.
func resetProbeRunner(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		probeRunCancel()
		waitForProbeRun(t)
		probeRunner.mu.Lock()
		probeRunner.run = probeRunState{}
		probeRunner.mu.Unlock()
		state.mu.Lock()
		state.buckets = make(map[string]templateEntry)
		state.store = nil
		state.storeMod = time.Time{}
		state.storeChecked = time.Time{}
		state.mu.Unlock()
	})
	probeRunner.mu.Lock()
	probeRunner.run = probeRunState{}
	probeRunner.cancel = nil
	probeRunner.mu.Unlock()
	state.mu.Lock()
	state.buckets = make(map[string]templateEntry)
	state.store = nil
	state.storeMod = time.Time{}
	state.storeChecked = time.Time{}
	state.mu.Unlock()
}

// shrinkProbeWaits collapses the runner's three waits for the duration of one
// test. Without it every case spends seconds asleep in a settle that exists for
// a real CPA's asynchronous credential reload.
func shrinkProbeWaits(t *testing.T) {
	t.Helper()
	settle, bucket, poll := probeSettle, probeBucketWait, probePollEvery
	probeSettle, probeBucketWait, probePollEvery = time.Millisecond, 150*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { probeSettle, probeBucketWait, probePollEvery = settle, bucket, poll })
}

// waitForProbeRun blocks until no sweep is running and returns the final state.
func waitForProbeRun(t *testing.T) probeRunState {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		run := probeRunSnapshot()
		if !run.Running {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe run did not finish; last state %+v", run)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// seedLiveTemplate stands in for a harvest that has already happened. The probe
// role's harvestFromResponse writes to this same map, so a sweep sees exactly
// what it would see after a successful fire.
func seedLiveTemplate(account, model string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.buckets[bucketKey(account, model)] = templateEntry{
		value:    strings.Repeat("t", 292),
		issuedAt: time.Now(),
	}
}

func lastIndexPrefix(values []string, prefix string) int {
	found := -1
	for index, value := range values {
		if strings.HasPrefix(value, prefix) {
			found = index
		}
	}
	return found
}

func firstIndexPrefix(values []string, prefix string) int {
	for index, value := range values {
		if strings.HasPrefix(value, prefix) {
			return index
		}
	}
	return -1
}

// --- refusals ------------------------------------------------------------

func TestProbeRunStartRefusesBusinessRole(t *testing.T) {
	// The most important refusal in the file. A sweep disables every Codex
	// credential but one; a business process doing that would take customer
	// traffic down to fill a bucket it does not even write.
	resetProbeRunner(t)
	dir := t.TempDir()
	opts := probeTestOptions(dir, "http://127.0.0.1:1")
	opts.role = roleBusiness
	mustConfigure(t, probeTestConfig(t, opts))

	errStart := probeRunStart()
	if errStart == nil {
		t.Fatal("probeRunStart accepted a run in role business")
	}
	if !strings.Contains(errStart.Error(), roleProbe) {
		t.Fatalf("the refusal does not say which role is required: %v", errStart)
	}
	if probeRunSnapshot().Running {
		t.Fatal("a refused start left the runner marked as running")
	}
}

func TestProbeRunStartRefusesIncompleteConfig(t *testing.T) {
	// Each of these costs something when it is missing: an empty selection would
	// otherwise have to mean "every account", and a missing key turns a
	// stop-the-world window into a run of 401s with the credentials already
	// flipped.
	tests := []struct {
		name   string
		narrow func(opts *probeConfigOptions)
		want   string
	}{
		{
			name:   "no accounts selected",
			narrow: func(opts *probeConfigOptions) { opts.accounts = nil },
			want:   "probe_accounts",
		},
		{
			name:   "no models selected",
			narrow: func(opts *probeConfigOptions) { opts.models = nil },
			want:   "models",
		},
		{
			name:   "no api key",
			narrow: func(opts *probeConfigOptions) { opts.apiKey = "" },
			want:   "probe_api_key",
		},
		{
			name:   "no management key",
			narrow: func(opts *probeConfigOptions) { opts.mgmtKey = "" },
			want:   "probe_management_key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetProbeRunner(t)
			dir := t.TempDir()
			opts := probeTestOptions(dir, "http://127.0.0.1:1")
			tc.narrow(&opts)
			mustConfigure(t, probeTestConfig(t, opts))

			errStart := probeRunStart()
			if errStart == nil {
				t.Fatalf("probeRunStart accepted a config with %s missing", tc.want)
			}
			if !strings.Contains(errStart.Error(), tc.want) {
				t.Fatalf("the refusal does not name %s: %v", tc.want, errStart)
			}
			if _, errStat := os.Stat(probeRestorePath(dir)); errStat == nil {
				t.Fatal("a refused start wrote a restore file, so it did not change nothing")
			}
		})
	}
}

func TestProbeRunStartIsSingleFlight(t *testing.T) {
	// Two sweeps at once is the worst way this can go wrong: the second would
	// snapshot the first one's half-disabled state as the original and then
	// restore to that, turning a temporary flip into a permanent one.
	resetProbeRunner(t)
	shrinkProbeWaits(t)

	fake := newFakeCPA(t,
		fakeAuthSeed{name: probeTestAccount, authIndex: "0"},
		fakeAuthSeed{name: probeTestOther, authIndex: `"b"`},
	)
	// The gate holds the first sweep inside its very first call, so the second
	// start is guaranteed to arrive while a run is genuinely in flight.
	fake.gate = make(chan struct{})

	dir := t.TempDir()
	mustConfigure(t, probeTestConfig(t, probeTestOptions(dir, fake.server.URL)))
	// Nothing left to fill, so once the gate opens the sweep snapshots, finds no
	// targets and restores. The point of this case is the refusal, not the sweep.
	seedLiveTemplate(probeTestAccount, probeTestModel)

	var wait sync.WaitGroup
	results := make([]error, 2)
	for index := range results {
		wait.Add(1)
		go func(slot int) {
			defer wait.Done()
			results[slot] = probeRunStart()
		}(index)
	}
	wait.Wait()

	started := 0
	for _, errStart := range results {
		if errStart == nil {
			started++
			continue
		}
		if !strings.Contains(errStart.Error(), "already in flight") {
			t.Fatalf("the losing start gave an unexpected reason: %v", errStart)
		}
	}
	if started != 1 {
		t.Fatalf("%d of 2 concurrent starts were accepted, want exactly 1", started)
	}

	close(fake.gate)
	run := waitForProbeRun(t)
	if run.Error != "" {
		t.Fatalf("the sweep reported an error: %s", run.Error)
	}
}

// --- restore -------------------------------------------------------------

func TestProbeSweepRestoresExitsBeforeEnableFlags(t *testing.T) {
	// The ordering rule: an account that ends up enabled is immediately
	// schedulable, so it has to be back on its own exit before the enable flag is
	// flipped -- otherwise live business traffic briefly leaves through a probe
	// exit. The cancel is in the same test because the restore matters most on
	// exactly the path an operator triggers by hand.
	resetProbeRunner(t)
	shrinkProbeWaits(t)

	const originalExit = "socks5h://exit-original.invalid:1080"
	fake := newFakeCPA(t,
		fakeAuthSeed{name: probeTestAccount, authIndex: "0", proxyURL: originalExit},
		fakeAuthSeed{name: probeTestOther, authIndex: `"b"`, disabled: true},
	)
	fake.onFire = func() {
		// Stop the run with a probe exit already pinned and a credential already
		// disabled, which is the state a restore has to cope with.
		if !probeRunCancel() {
			t.Error("probeRunCancel found nothing running while the sweep was firing")
		}
	}

	dir := t.TempDir()
	opts := probeTestOptions(dir, fake.server.URL)
	opts.proxies = []string{testProxyWithPW}
	mustConfigure(t, probeTestConfig(t, opts))

	if errStart := probeRunStart(); errStart != nil {
		t.Fatalf("probeRunStart refused a complete config: %v", errStart)
	}
	waitForProbeRun(t)

	calls := fake.calls()
	firedAt := firstIndexPrefix(calls, "fire ")
	if firedAt < 0 {
		t.Fatalf("the sweep never fired a request: %v", calls)
	}
	lastExit := lastIndexPrefix(calls, "fields ")
	lastFlag := lastIndexPrefix(calls, "status ")
	if lastExit < firedAt {
		t.Fatalf("no exit was written after the sweep stopped, so nothing was restored: %v", calls)
	}
	if lastExit > lastFlag {
		t.Fatalf("the exit was restored after the enable flags, which leaves live traffic on a probe exit: %v", calls)
	}

	// Observed directly rather than inferred: this is the actual hazard.
	if got := fake.exitAtEnable(probeTestAccount); got != originalExit {
		t.Fatalf("%s was re-enabled while pointing at %s, want its own exit back first",
			probeTestAccount, maskProxyURL(got))
	}

	for _, want := range []struct {
		name     string
		disabled bool
		exit     string
	}{
		{probeTestAccount, false, originalExit},
		{probeTestOther, true, ""},
	} {
		disabled, exit := fake.state(want.name)
		if disabled != want.disabled {
			t.Fatalf("%s ended disabled=%t, want %t", want.name, disabled, want.disabled)
		}
		if exit != want.exit {
			t.Fatalf("%s ended on %s, want its original exit back", want.name, maskProxyURL(exit))
		}
	}
}

func TestProbeRestoreFileLivesOnlyForTheRun(t *testing.T) {
	// The file is the whole reason a crash is survivable: probe.py's in-memory
	// snapshot was lost with the process, and that cost a real incident. It has to
	// exist for as long as credentials are flipped, and go away when they are not.
	resetProbeRunner(t)
	shrinkProbeWaits(t)

	fake := newFakeCPA(t,
		fakeAuthSeed{name: probeTestAccount, authIndex: "0"},
		fakeAuthSeed{name: probeTestOther, authIndex: `"b"`},
	)
	dir := t.TempDir()
	// Atomic because onFire runs on the fake server's goroutine while this one is
	// blocked in waitForProbeRun.
	var existedMidRun atomic.Bool
	fake.onFire = func() {
		_, errStat := os.Stat(probeRestorePath(dir))
		existedMidRun.Store(errStat == nil)
		// Stand in for harvestFromResponse, which in production has already run by
		// the time this response reaches the sweep. Without it the sweep waits out
		// probeBucketWait for a template that is never coming.
		seedLiveTemplate(probeTestAccount, probeTestModel)
	}

	mustConfigure(t, probeTestConfig(t, probeTestOptions(dir, fake.server.URL)))

	if errStart := probeRunStart(); errStart != nil {
		t.Fatalf("probeRunStart refused a complete config: %v", errStart)
	}
	run := waitForProbeRun(t)

	if !existedMidRun.Load() {
		t.Fatalf("%s did not exist while credentials were flipped, so a crash there would have been unrecoverable", probeRestoreFileName)
	}
	if run.Error != "" {
		t.Fatalf("the sweep reported an error: %s", run.Error)
	}
	if run.Total != 1 || run.Done != 1 {
		t.Fatalf("progress ended at %d/%d, want 1/1", run.Done, run.Total)
	}
	if _, errStat := os.Stat(probeRestorePath(dir)); !os.IsNotExist(errStat) {
		t.Fatalf("%s survived a clean finish (%v); the next start would refuse for no reason", probeRestoreFileName, errStat)
	}
}

// --- secrets -------------------------------------------------------------

func TestProbeRunNeverLeaksAProxyPassword(t *testing.T) {
	// Lines is rendered on a page that needs no management key, and the run error
	// goes to the same place. This drives the one path that formats a proxy URL
	// into an error by design: a PATCH that answers 200 and does not take.
	resetProbeRunner(t)
	shrinkProbeWaits(t)

	fake := newFakeCPA(t,
		fakeAuthSeed{name: probeTestAccount, authIndex: "0", proxyURL: "socks5h://exit-original.invalid:1080"},
	)
	fake.ignoreProxyWrites = true

	dir := t.TempDir()
	opts := probeTestOptions(dir, fake.server.URL)
	opts.proxies = []string{testProxyWithPW}
	mustConfigure(t, probeTestConfig(t, opts))

	if errStart := probeRunStart(); errStart != nil {
		t.Fatalf("probeRunStart refused a complete config: %v", errStart)
	}
	run := waitForProbeRun(t)

	// An unconfirmed switch must abort rather than count as a failed exit: every
	// candidate would otherwise "fail" while the real cause is that the exit never
	// changed, and that misdiagnosis costs a whole probe window.
	if run.Error == "" {
		t.Fatal("a PATCH that answered 200 and changed nothing was accepted as a switch")
	}
	if !strings.Contains(run.Error, "did not take") {
		t.Fatalf("the error does not say the write did not take: %s", run.Error)
	}
	if firstIndexPrefix(fake.calls(), "fire ") >= 0 {
		t.Fatal("the sweep fired through an unverified exit")
	}

	for _, text := range append(append([]string(nil), run.Lines...), run.Error, run.Current) {
		if strings.Contains(text, testProxySecret) {
			t.Fatalf("a proxy password reached the run state: %q", text)
		}
	}
	if !strings.Contains(strings.Join(run.Lines, "\n")+run.Error, "***@") {
		t.Fatal("no masked proxy appears anywhere, so this test proved nothing")
	}
}
