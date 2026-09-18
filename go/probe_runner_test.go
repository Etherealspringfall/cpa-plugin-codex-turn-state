package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the offline (CPA-free) harvester.
//
// The load-bearing properties are no longer "did it flip credential state back"
// -- it never flips any -- but the ones that cost something when wrong:
//
//   - a run never starts on an empty selection or without the management key;
//   - a 292 is stored under the credential FILE NAME, because that is the key the
//     business role looks up; a 312 (throttled) is never stored;
//   - an expired access token is skipped, never refreshed (refreshing could
//     rotate CPA's refresh token and break live traffic);
//   - the proxy pool is assigned in order and falls through on a dead exit;
//   - renewal re-harvests a bucket near expiry;
//   - no proxy password and no token reach the transcript, which is served with
//     no key.
//
// The fake CPA serves only the two read-only GETs the harvester makes. A separate
// fake upstream stands in for chatgpt.com. testProxySecret comes from
// probe_scope_test.go, deliberately: one password, greppable from one place.

// --- fake CPA (read-only) ------------------------------------------------

// fakeCredSeed is one credential the fake CPA publishes and hands out on
// download. exp is the access token's expiry; zero means "days from now".
type fakeCredSeed struct {
	name      string
	accountID string
	proxyURL  string
	disabled  bool
	exp       time.Time
	// noToken drops the access_token from the download, standing in for a
	// credential file the harvester cannot use.
	noToken bool
}

type fakeCPA struct {
	mu     sync.Mutex
	server *httptest.Server
	seeds  map[string]fakeCredSeed
	order  []string
}

// encodeJWT builds a token whose payload carries just the two non-secret claims
// the harvester reads: exp and the chatgpt account id. The header segment "e30"
// is base64url("{}"), enough for probeJWTClaims, which only decodes the payload.
func encodeJWT(exp time.Time, accountID string) string {
	claims := map[string]any{
		"exp":                         exp.Unix(),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": accountID},
	}
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func newFakeCPA(t *testing.T, seeds ...fakeCredSeed) *fakeCPA {
	t.Helper()
	fake := &fakeCPA{seeds: make(map[string]fakeCredSeed, len(seeds))}
	for _, seed := range seeds {
		if seed.exp.IsZero() {
			seed.exp = time.Now().Add(72 * time.Hour)
		}
		fake.seeds[seed.name] = seed
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
	switch {
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthFiles:
		f.record("files")
		f.writeJSON(w, map[string]any{"files": f.fileList()})
	case r.Method == http.MethodGet && r.URL.Path == probeRouteAuthDownload:
		f.serveDownload(w, r)
	default:
		// A write route reaching the fake is itself a failure: this harvester must
		// never call one. Answering 405 makes such a regression loud.
		http.Error(w, `{"error":"the offline harvester must not call this route"}`, http.StatusMethodNotAllowed)
	}
}

func (f *fakeCPA) fileList() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, 0, len(f.seeds))
	for _, seed := range f.seeds {
		out = append(out, map[string]any{
			"name":     seed.name,
			"provider": "codex",
			"disabled": seed.disabled,
		})
	}
	return out
}

func (f *fakeCPA) serveDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f.record("download %s", name)
	f.mu.Lock()
	seed, found := f.seeds[name]
	f.mu.Unlock()
	if !found {
		http.Error(w, `{"error":"no such credential"}`, http.StatusNotFound)
		return
	}
	blob := map[string]any{
		"account_id":    seed.accountID,
		"proxy_url":     seed.proxyURL,
		"type":          "codex",
		"disabled":      seed.disabled,
		"email":         "someone@example.com",
		"refresh_token": "refresh-must-never-be-used",
	}
	if !seed.noToken {
		blob["access_token"] = encodeJWT(seed.exp, seed.accountID)
	}
	f.writeJSON(w, blob)
}

func (f *fakeCPA) writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// --- fake upstream (chatgpt.com stand-in) --------------------------------

type upstreamCall struct {
	model         string
	authorization string
	accountID     string
	sessionID     string
	sentTurnState bool
}

type fakeUpstream struct {
	mu     sync.Mutex
	server *httptest.Server
	calls  []upstreamCall
	// status and tsLen shape the response: a 200 with a tsLen-long turn-state is
	// a harvestable template; 312 is the degraded state; a non-200 is a rejection.
	status int
	tsLen  int
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	upstream := &fakeUpstream{status: http.StatusOK, tsLen: 292}
	upstream.server = httptest.NewServer(upstream)
	t.Cleanup(upstream.server.Close)
	return upstream
}

func (u *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Model string `json:"model"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	u.mu.Lock()
	u.calls = append(u.calls, upstreamCall{
		model:         body.Model,
		authorization: r.Header.Get("Authorization"),
		accountID:     r.Header.Get("Chatgpt-Account-Id"),
		sessionID:     r.Header.Get("Session-Id"),
		sentTurnState: r.Header.Get(turnStateHeader) != "",
	})
	status, tsLen := u.status, u.tsLen
	u.mu.Unlock()

	// The turn-state begins with the real Fernet prefix so the redaction path is
	// exercised on a realistic value; only its length is ever asserted on.
	if status == http.StatusOK && tsLen >= 6 {
		w.Header().Set(turnStateHeader, "gAAAAA"+strings.Repeat("x", tsLen-6))
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
}

func (u *fakeUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *fakeUpstream) snapshot() []upstreamCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamCall(nil), u.calls...)
}

// --- helpers -------------------------------------------------------------

// Spelled unlike anything in the other test files: the store cache is
// process-global, and a bucket key shared with another test could make a run
// decide there is nothing to fill.
const (
	probeTestAccount = "codex-runnera-a@example.com-pro.json"
	probeTestOther   = "codex-runnerb-b@example.com-pro.json"
	probeTestModel   = "gpt-runner-1"
)

type probeConfigOptions struct {
	dir      string
	baseURL  string
	role     string
	mgmtKey  string
	accounts []string
	models   []string
	proxies  []string

	templateLen int
	replaceLen  int
	ttlSeconds  int
}

func probeTestOptions(dir, baseURL string) probeConfigOptions {
	return probeConfigOptions{
		dir:         dir,
		baseURL:     baseURL,
		role:        roleProbe,
		mgmtKey:     "test-mgmt-key",
		accounts:    []string{probeTestAccount},
		models:      []string{probeTestModel},
		templateLen: 292,
		replaceLen:  312,
		ttlSeconds:  3600,
	}
}

func probeTestConfig(opts probeConfigOptions) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "role: %s\nstore_dir: %q\nlog_decisions: false\n", opts.role, opts.dir)
	fmt.Fprintf(&builder, "template_length: %d\nreplace_length: %d\nttl_seconds: %d\n", opts.templateLen, opts.replaceLen, opts.ttlSeconds)
	fmt.Fprintf(&builder, "probe_base_url: %q\n", opts.baseURL)
	fmt.Fprintf(&builder, "probe_management_key: %q\n", opts.mgmtKey)
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

// resetProbeRunner returns the package-level runner, the claim guard, and the
// store cache to a clean state, and makes sure no run from an earlier case is
// still in flight.
func resetProbeRunner(t *testing.T) {
	t.Helper()
	clear := func() {
		probeRunner.mu.Lock()
		probeRunner.run = probeRunState{}
		probeRunner.cancel = nil
		probeRunner.mu.Unlock()
		probeActive.mu.Lock()
		probeActive.set = make(map[string]bool)
		probeActive.mu.Unlock()
		state.mu.Lock()
		state.buckets = make(map[string]templateEntry)
		state.store = nil
		state.storeMod = time.Time{}
		state.storeChecked = time.Time{}
		state.mu.Unlock()
	}
	t.Cleanup(func() {
		probeRunCancel()
		waitForProbeRun(t)
		clear()
	})
	clear()
}

// setUpstream points the harvester at a fake upstream for one test.
func setUpstream(t *testing.T, rawURL string) {
	t.Helper()
	previous := probeUpstreamURL
	probeUpstreamURL = rawURL
	t.Cleanup(func() { probeUpstreamURL = previous })
}

// fastRenew shrinks the renewal cadence for one test. Production never writes
// these; a real run checks once a minute.
func fastRenew(t *testing.T, interval, threshold time.Duration) {
	t.Helper()
	prevInterval, prevThreshold := probeRenewInterval, probeRenewThreshold
	probeRenewInterval, probeRenewThreshold = interval, threshold
	t.Cleanup(func() { probeRenewInterval, probeRenewThreshold = prevInterval, prevThreshold })
}

// waitForProbeRun blocks until no run is marked running. It is for the failure
// paths, which return; a healthy run enters the renewal loop and stays up until
// cancelled, so success cases wait on progress instead.
func waitForProbeRun(t *testing.T) probeRunState {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		run := probeRunSnapshot()
		if !run.Running {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe run did not finish; last state %+v", run)
			return run
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitUntil polls a condition to a deadline. The harvest is concurrent, so the
// assertions wait for an observable effect rather than sleeping a fixed time.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// waitForInitialFill waits for the one-off fill pass to reach Total, i.e. every
// selected bucket has been attempted once.
func waitForInitialFill(t *testing.T) {
	t.Helper()
	waitUntil(t, "initial fill to finish", func() bool {
		run := probeRunSnapshot()
		return run.Total > 0 && run.Done >= run.Total
	})
}

func storedBucket(account, model string) (templateEntry, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	entry, ok := state.buckets[bucketKey(account, model)]
	return entry, ok
}

// startProbeRun starts a run and registers a cleanup that stops it and waits for
// the goroutine to exit. It is called after setUpstream/fastRenew, so its cleanup
// runs FIRST in the LIFO order: the renewal goroutine is fully stopped before any
// package var it reads (probeUpstreamURL, the renewal cadence) is restored, which
// a still-live goroutine would otherwise race on.
func startProbeRun(t *testing.T) {
	t.Helper()
	if errStart := probeRunStart(); errStart != nil {
		t.Fatalf("probeRunStart refused a complete config: %v", errStart)
	}
	t.Cleanup(func() {
		probeRunCancel()
		waitForProbeRun(t)
	})
}

// --- refusals ------------------------------------------------------------

func TestProbeRunStartRefusesIncompleteConfig(t *testing.T) {
	// Each of these costs something when missing: an empty selection would
	// otherwise have to mean "every account", spending quota on credentials the
	// operator did not pick; a missing key means the harvester cannot read the
	// account list at all; no store_dir means a harvest has nowhere to land.
	tests := []struct {
		name   string
		narrow func(opts *probeConfigOptions)
		want   string
	}{
		{"no accounts", func(o *probeConfigOptions) { o.accounts = nil }, "probe_accounts"},
		{"no models", func(o *probeConfigOptions) { o.models = nil }, "models"},
		{"no management key", func(o *probeConfigOptions) { o.mgmtKey = "" }, "probe_management_key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetProbeRunner(t)
			dir := t.TempDir()
			opts := probeTestOptions(dir, "http://127.0.0.1:1")
			tc.narrow(&opts)
			mustConfigure(t, probeTestConfig(opts))

			errStart := probeRunStart()
			if errStart == nil {
				t.Fatalf("probeRunStart accepted a config with %s missing", tc.want)
			}
			if !strings.Contains(errStart.Error(), tc.want) {
				t.Fatalf("the refusal does not name %s: %v", tc.want, errStart)
			}
			if probeRunSnapshot().Running {
				t.Fatal("a refused start left the runner marked as running")
			}
		})
	}
}

func TestProbeRunStartRefusesEmptyStoreDir(t *testing.T) {
	// store_dir is validated at configure for role probe, so this drives the
	// refusal directly: a run built in-process with no store has nowhere to write
	// a template for the business role to read.
	resetProbeRunner(t)
	opts := probeTestOptions("", "http://127.0.0.1:1")
	state.mu.Lock()
	state.config = pluginConfig{
		Role:               roleProbe,
		ProbeManagementKey: opts.mgmtKey,
		ProbeAccounts:      opts.accounts,
		Models:             opts.models,
		TemplateLength:     292,
		ReplaceLength:      312,
	}
	state.mu.Unlock()

	errStart := probeRunStart()
	if errStart == nil || !strings.Contains(errStart.Error(), "store_dir") {
		t.Fatalf("probeRunStart did not refuse an empty store_dir: %v", errStart)
	}
}

func TestProbeRunStartIsSingleFlight(t *testing.T) {
	// The run now owns the renewal loop and stays up until cancelled, so a second
	// start must be refused rather than starting a second loop on the same buckets.
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))

	startProbeRun(t)
	errSecond := probeRunStart()
	if errSecond == nil {
		t.Fatal("a second start was accepted while a run was already going")
	}
	if !strings.Contains(errSecond.Error(), "already running") {
		t.Fatalf("the second refusal gave an unexpected reason: %v", errSecond)
	}
}

// --- harvest -------------------------------------------------------------

func TestProbeStoresA292UnderTheFileName(t *testing.T) {
	// The one property the business side depends on: a harvested template is keyed
	// by the credential FILE NAME, because that is exactly what the request hook
	// reads out of selected_auth_id. Also asserts the request went out authorised
	// and did NOT carry a turn-state up (which would stop the upstream minting one).
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	upstream.tsLen = 292
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)

	entry, ok := storedBucket(probeTestAccount, probeTestModel)
	if !ok {
		t.Fatalf("no bucket stored under the file name %q", probeTestAccount)
	}
	if len(entry.value) != 292 {
		t.Fatalf("stored template length = %d, want 292", len(entry.value))
	}

	calls := upstream.snapshot()
	if len(calls) != 1 {
		t.Fatalf("upstream received %d calls, want exactly 1", len(calls))
	}
	call := calls[0]
	if !strings.HasPrefix(call.authorization, "Bearer ") {
		t.Fatalf("upstream call was not authorised: %q", call.authorization)
	}
	if call.accountID != "acct-a" {
		t.Fatalf("upstream call carried account id %q, want acct-a", call.accountID)
	}
	if call.sessionID == "" {
		t.Fatal("upstream call carried no Session-Id")
	}
	if call.sentTurnState {
		t.Fatal("the probe sent a turn-state upstream, which stops a fresh one being minted")
	}
}

func TestProbeSkipsThrottled312(t *testing.T) {
	// A 312 is the degraded/throttled state, not a template. Storing it would hand
	// the business role the very state this plugin exists to route around.
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	upstream.tsLen = 312
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)

	if _, ok := storedBucket(probeTestAccount, probeTestModel); ok {
		t.Fatal("a 312 degraded state was stored as a template")
	}
	joined := strings.Join(probeRunSnapshot().Lines, "\n")
	if !strings.Contains(joined, "degraded") {
		t.Fatalf("the transcript does not explain the 312 was skipped: %s", joined)
	}
}

func TestProbeSkipsExpiredTokenWithoutRefreshing(t *testing.T) {
	// The safety rule: an expired access token is skipped, never refreshed --
	// refreshing could rotate CPA's refresh token and break live traffic. With the
	// only account expired the run fails cleanly, and the upstream is never called,
	// so nothing was refreshed and nothing was fired on a dead token.
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{
		name:      probeTestAccount,
		accountID: "acct-a",
		exp:       time.Now().Add(-1 * time.Minute),
	})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	run := waitForProbeRun(t)

	if run.Error == "" {
		t.Fatal("a run with only an expired credential did not fail")
	}
	if upstream.count() != 0 {
		t.Fatalf("upstream was called %d times on an expired token; it must be skipped", upstream.count())
	}
	if !strings.Contains(strings.Join(run.Lines, "\n"), "expired") {
		t.Fatalf("the transcript does not say the token was skipped as expired: %v", run.Lines)
	}
}

func TestProbeUnreadableTokenIsSkipped(t *testing.T) {
	// A credential file with no access_token is unusable but must not crash the
	// run; it is dropped with a line, and a run with nothing left fails cleanly.
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a", noToken: true})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	run := waitForProbeRun(t)
	if run.Error == "" {
		t.Fatal("a run whose only credential had no token did not fail")
	}
	if upstream.count() != 0 {
		t.Fatal("the upstream was called for a credential with no token")
	}
}

// --- proxy pool ----------------------------------------------------------

func TestProbeExitsAssignInOrderWithFallback(t *testing.T) {
	// The operator's rule: account i starts at exit i, then the rest in order,
	// wrapping once, so every account has a full fallback sequence. An empty pool
	// is one direct attempt.
	got := probeExits([]string{"p0", "p1", "p2"}, 0)
	if fmt.Sprint(got) != fmt.Sprint([]string{"p0", "p1", "p2"}) {
		t.Fatalf("account 0 order = %v, want p0,p1,p2", got)
	}
	got = probeExits([]string{"p0", "p1", "p2"}, 1)
	if fmt.Sprint(got) != fmt.Sprint([]string{"p1", "p2", "p0"}) {
		t.Fatalf("account 1 order = %v, want p1,p2,p0", got)
	}
	got = probeExits(nil, 0)
	if len(got) != 1 || got[0] != "" {
		t.Fatalf("empty pool order = %v, want a single direct attempt", got)
	}
}

func TestProbeFallsThroughToNextExitOnTransportFailure(t *testing.T) {
	// A dead first exit must not lose the harvest: the account falls through to the
	// next exit in its sequence. The pool is handed straight to probeHarvestBucket
	// so the direct entry ("") survives -- normaliseProbeScope trims an empty proxy
	// from a configured pool, which is right in production (an empty pool already
	// means direct) but would erase the exact second exit this case needs.
	resetProbeRunner(t)
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	cfg := pluginConfig{
		StoreDir:       t.TempDir(),
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
	}
	cred := probeCredential{name: probeTestAccount, accessToken: "token-a", accountID: "acct-a"}
	pool := newProbeClientPool()
	defer pool.closeIdle()

	// Exit 0 is a closed port (instant connection refused); exit 1 is direct.
	probeHarvestBucket(context.Background(), cfg, pool, cred, probeTestModel, []string{"http://127.0.0.1:1", ""}, 0)

	if _, ok := storedBucket(probeTestAccount, probeTestModel); !ok {
		t.Fatal("the bucket was not filled, so the fallback to the second exit did not happen")
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream received %d calls, want 1 (only the working exit)", upstream.count())
	}
	if !strings.Contains(strings.Join(probeRunSnapshot().Lines, "\n"), "trying next") {
		t.Fatal("no transport-failure fallthrough was logged")
	}
}

// --- renewal -------------------------------------------------------------

func TestProbeRenewsBucketNearingExpiry(t *testing.T) {
	// After the initial fill the run stays up and tops up buckets near expiry. With
	// a large threshold the freshly filled bucket is immediately due, so a second
	// upstream call is proof the renewal loop is running.
	resetProbeRunner(t)
	fastRenew(t, 15*time.Millisecond, 2*time.Hour)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	mustConfigure(t, probeTestConfig(probeTestOptions(t.TempDir(), fake.server.URL)))
	startProbeRun(t)
	waitForInitialFill(t)
	waitUntil(t, "a renewal fire", func() bool { return upstream.count() >= 2 })
}

// --- secrets -------------------------------------------------------------

func TestProbeRunNeverLeaksAProxyPassword(t *testing.T) {
	// Lines, the run error and Current are all rendered on a page that needs no
	// key. A proxy with a password, used as a dead exit, must appear masked in the
	// transport-failure line and never in the clear.
	resetProbeRunner(t)
	fake := newFakeCPA(t, fakeCredSeed{name: probeTestAccount, accountID: "acct-a"})
	upstream := newFakeUpstream(t)
	setUpstream(t, upstream.server.URL)

	opts := probeTestOptions(t.TempDir(), fake.server.URL)
	// A password-bearing exit at a refused port: it fails fast, and the failure is
	// logged through the masking path.
	opts.proxies = []string{"http://prober:" + testProxySecret + "@127.0.0.1:1"}
	mustConfigure(t, probeTestConfig(opts))
	startProbeRun(t)
	waitForInitialFill(t)

	run := probeRunSnapshot()
	for _, text := range append(append([]string(nil), run.Lines...), run.Error, run.Current) {
		if strings.Contains(text, testProxySecret) {
			t.Fatalf("a proxy password reached the run state: %q", text)
		}
	}
	if !strings.Contains(strings.Join(run.Lines, "\n"), "***@") {
		t.Fatal("no masked proxy appears anywhere, so this test proved nothing")
	}
}

func TestProbeShortAuthMasksTheEmail(t *testing.T) {
	// Account names carry a customer email and are shown on the keyless transcript,
	// so probeShortAuth must keep only the stable hex and tier and drop the email.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"normal", "codex-620f5a42-luo.swmu@gmail.com-pro.json", "620f5a42…pro"},
		{"email with dashes", "codex-deadbeef-first-last@x.com-pro.json", "deadbeef…pro"},
		{"no email", "codex-abcdef.json", "abcdef"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeShortAuth(tc.in)
			if got != tc.want {
				t.Fatalf("probeShortAuth(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "@") {
				t.Fatalf("probeShortAuth(%q) leaked an email: %q", tc.in, got)
			}
		})
	}
}
