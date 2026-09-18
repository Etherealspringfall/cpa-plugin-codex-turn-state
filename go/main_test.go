package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// The header and metadata key are spelled out here rather than reused from
// main.go: these tests are the contract, and a rename on the production side
// should break them loudly instead of following along silently.
const (
	testHeader  = "X-Codex-Turn-State"
	testAuthKey = "selected_auth_id"
)

// Fixed reference instant for the pure functions, which all take an explicit
// now. Using a frozen clock there keeps those runs reproducible and stops them
// going flaky near an hour boundary.
var testNow = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

const testTTL = time.Hour

// wallClock is the instant the plugin itself will see. The request path reads
// time.Now() internally, so fixtures feeding handleMethod must be anchored to
// the real clock — a frozen future timestamp would look *fresh* to the plugin
// and quietly invert the expiry tests.
//
// Truncated to the second because issued_at round-trips through RFC3339, which
// carries no sub-second precision.
func wallClock() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// storeDirLine renders a store_dir setting for a throwaway directory. The probe
// role refuses to start without one.
func storeDirLine(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("store_dir: %q\n", t.TempDir())
}

// tokenByteLen maps an X-Codex-Turn-State base64 length to the decoded byte
// length observed upstream (FINDINGS.md): 292 characters decode to 217 bytes
// and 312 characters decode to 233 bytes — a difference of exactly one 16-byte
// AES-CBC block, which is the whole tell this plugin keys on.
var tokenByteLen = map[int]int{292: 217, 312: 233}

// fakeToken returns a synthetic Fernet token of exactly n base64 characters
// whose embedded timestamp is issued.
//
// Every value used in these tests is fabricated. No production
// X-Codex-Turn-State value is read, committed, or logged here.
func fakeToken(n int, issued time.Time) string {
	return fakeTokenSeed(n, issued, 0x5a)
}

// fakeTokenSeed is fakeToken with a caller-chosen filler byte, so two tokens
// minted at the same instant still differ. That matters for the cross-account
// and cross-model tests, where the point is that two distinct values must not
// be swapped for one another.
func fakeTokenSeed(n int, issued time.Time, seed byte) string {
	size, ok := tokenByteLen[n]
	if !ok {
		panic(fmt.Sprintf("fakeTokenSeed: no decoded byte length known for %d base64 chars", n))
	}
	raw := make([]byte, size)
	raw[0] = 0x80
	binary.BigEndian.PutUint64(raw[1:9], uint64(issued.Unix()))
	for i := 9; i < size; i++ {
		raw[i] = seed + byte(i)
	}
	// Padded URLEncoding, not RawURLEncoding: the real header carries its "="
	// padding, and fernetIssuedAt trims it back off before decoding.
	out := base64.URLEncoding.EncodeToString(raw)
	if len(out) != n {
		panic(fmt.Sprintf("fakeTokenSeed: encoded to %d chars, want %d", len(out), n))
	}
	return out
}

// configureYAML drives the real plugin.register path with the given config so
// role normalisation, aliasing and validation are exercised exactly as the host
// exercises them. The envelope is built from a map rather than the internal
// request struct to keep the tests off private type names.
func configureYAML(t *testing.T, cfgYAML string) error {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"config_yaml":    []byte(cfgYAML),
		"schema_version": 6,
	})
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	t.Cleanup(resetPluginConfig)
	return configure(raw)
}

// mustConfigure fails the test when the config is rejected.
func mustConfigure(t *testing.T, cfgYAML string) {
	t.Helper()
	if err := configureYAML(t, cfgYAML); err != nil {
		t.Fatalf("configure rejected a valid config: %v", err)
	}
}

// captureLog redirects the standard logger for the duration of fn and returns
// everything it wrote.
//
// It exists for the probe keys, which must never reach a log line. A log is the
// one output that cannot be checked after the fact: by the time a test could
// look, the line has already gone to stderr and into whatever collects it. The
// flags are zeroed so an assertion reads the message rather than a timestamp.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buffer bytes.Buffer
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	fn()
	return buffer.String()
}

// resetPluginConfig restores the package-level config between tests. Store
// caching is left alone: it is per-directory and every test gets its own
// t.TempDir(). configErrors is cleared alongside the config because the two are
// written together by configure, and a complaint left behind by one test would
// surface in the next test's status document.
func resetPluginConfig() {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.config = defaultConfig()
	state.configErrors = nil
}

// businessConfig is a business-role config pointed at dir.
func businessConfig(dir string, dryRun bool) string {
	return fmt.Sprintf(`role: business
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
harvest_inband: false
inject_mode: replace-only
dry_run: %t
log_decisions: false
`, dir, dryRun)
}

// interceptAfter runs one request through the real request.intercept_after
// dispatch and returns the decoded plugin response.
func interceptAfter(t *testing.T, req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal intercept request: %v", err)
	}
	out, err := handleMethod(pluginabi.MethodRequestInterceptAfter, raw)
	if err != nil {
		t.Fatalf("handleMethod(request.intercept_after): %v", err)
	}
	// Decoded into a local shape so the tests do not depend on the internal
	// envelope type name.
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if errUnmarshal := json.Unmarshal(out, &env); errUnmarshal != nil {
		t.Fatalf("decode envelope: %v", errUnmarshal)
	}
	if !env.OK {
		t.Fatalf("plugin returned an error envelope: %+v", env.Error)
	}
	var resp pluginapi.RequestInterceptResponse
	if len(env.Result) > 0 {
		if errUnmarshal := json.Unmarshal(env.Result, &resp); errUnmarshal != nil {
			t.Fatalf("decode intercept response: %v", errUnmarshal)
		}
	}
	return resp
}

// request builds a minimal intercept request for one bucket.
func request(authID, model, headerValue string) pluginapi.RequestInterceptRequest {
	req := pluginapi.RequestInterceptRequest{
		Model:    model,
		Metadata: map[string]any{testAuthKey: authID},
		Headers:  http.Header{},
	}
	if headerValue != "" {
		req.Headers.Set(testHeader, headerValue)
	}
	return req
}

// outgoingHeader reports the value the plugin wants on the wire, or "" when it
// left the request alone.
func outgoingHeader(resp pluginapi.RequestInterceptResponse) string {
	if resp.Headers == nil {
		return ""
	}
	for key, values := range resp.Headers {
		if !equalFoldASCII(key, testHeader) {
			continue
		}
		for _, value := range values {
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// --- token helper sanity -------------------------------------------------

func TestFakeTokenMatchesObservedLengths(t *testing.T) {
	for _, n := range []int{292, 312} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			token := fakeToken(n, testNow)
			if len(token) != n {
				t.Fatalf("fakeToken produced %d chars, want %d", len(token), n)
			}
			issued, ok := fernetIssuedAt(token)
			if !ok {
				t.Fatal("fernetIssuedAt refused a synthetic token; the fixture no longer matches the real format")
			}
			if !issued.Equal(testNow) {
				t.Fatalf("embedded timestamp = %s, want %s", issued.UTC(), testNow)
			}
		})
	}
}

func TestFakeTokenSeedProducesDistinctValues(t *testing.T) {
	a := fakeTokenSeed(292, testNow, 0x11)
	b := fakeTokenSeed(292, testNow, 0x22)
	if a == b {
		t.Fatal("two seeds produced the same token; the isolation tests would be vacuous")
	}
	if len(a) != 292 || len(b) != 292 {
		t.Fatalf("lengths = %d/%d, want 292/292", len(a), len(b))
	}
}

func TestFernetIssuedAtRejectsNonFernet(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"not base64", "!!!!not base64!!!!"},
		{"too short", base64.URLEncoding.EncodeToString([]byte{0x80, 0x00})},
		{"wrong version byte", base64.URLEncoding.EncodeToString(make([]byte, 32))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := fernetIssuedAt(tc.value); ok {
				t.Fatalf("fernetIssuedAt accepted %q", tc.name)
			}
		})
	}
}

// --- §8.1 no reuse across accounts ---------------------------------------

func TestTemplateNeverCrossesAccountBoundary(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)

	// Only account A has a harvested template.
	mustWriteRecord(t, dir, storeRecordFor("codex-a.json", "gpt-5.6-sol", issued, 292))

	loaded, err := loadStore(dir, now, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded[bucketKey("codex-a.json", "gpt-5.6-sol")]; !ok {
		t.Fatal("account A's own bucket did not load")
	}
	if _, ok := loaded[bucketKey("codex-b.json", "gpt-5.6-sol")]; ok {
		t.Fatal("account B resolved to a template harvested for account A")
	}

	// Account B arrives degraded. With no template of its own it must be left
	// untouched rather than borrowing A's.
	mustConfigure(t, businessConfig(dir, false))
	degraded := fakeTokenSeed(312, now, 0x77)
	resp := interceptAfter(t, request("codex-b.json", "gpt-5.6-sol", degraded))
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("account B's request was rewritten (len %d); cross-account reuse is forbidden", len(got))
	}
}

// --- §8.2 no reuse across models -----------------------------------------

func TestTemplateNeverCrossesModelBoundary(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const auth = "codex-a.json"

	mustWriteRecord(t, dir, storeRecordFor(auth, "gpt-5.6-sol", issued, 292))

	loaded, err := loadStore(dir, now, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded[bucketKey(auth, "gpt-6-astra")]; ok {
		t.Fatal("gpt-6-astra resolved to the template harvested for gpt-5.6-sol")
	}

	mustConfigure(t, businessConfig(dir, false))
	degraded := fakeTokenSeed(312, now, 0x77)

	resp := interceptAfter(t, request(auth, "gpt-6-astra", degraded))
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("gpt-6-astra was rewritten (len %d); cross-model reuse is forbidden", len(got))
	}

	// Control: the model that does own a template is still served.
	resp = interceptAfter(t, request(auth, "gpt-5.6-sol", degraded))
	if got := outgoingHeader(resp); len(got) != 292 {
		t.Fatalf("gpt-5.6-sol got %d-char header, want its own 292 template", len(got))
	}
}

// --- §8.3 bucket key carries no IP ---------------------------------------

func TestBucketIsIPIndependent(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-terra"
	)
	rec := storeRecordFor(auth, model, issued, 292)
	mustWriteRecord(t, dir, rec)
	mustConfigure(t, businessConfig(dir, false))

	degraded := fakeTokenSeed(312, now, 0x77)

	// Two requests for the same bucket carrying entirely different IP
	// metadata and forwarding headers must land on the same template.
	first := request(auth, model, degraded)
	first.Metadata["client_ip"] = "203.0.113.7"
	first.Headers.Set("X-Forwarded-For", "203.0.113.7")

	second := request(auth, model, degraded)
	second.Metadata["client_ip"] = "198.51.100.42"
	second.Headers.Set("X-Forwarded-For", "198.51.100.42")

	gotFirst := outgoingHeader(interceptAfter(t, first))
	gotSecond := outgoingHeader(interceptAfter(t, second))

	if gotFirst != rec.Value || gotSecond != rec.Value {
		t.Fatalf("IP changed the outcome: first=%d chars, second=%d chars, want both to be the stored 292",
			len(gotFirst), len(gotSecond))
	}
}

// --- §8.4 expiry is a hard wall ------------------------------------------

func TestExpiredTemplateNeverSubstituted(t *testing.T) {
	dir := t.TempDir()
	const (
		auth  = "codex-a.json"
		model = "gpt-5.5"
	)
	// Issued just over the TTL ago: still on disk, no longer usable.
	now := wallClock()
	expired := now.Add(-testTTL - time.Minute)
	writeRawRecord(t, dir, storeRecordFor(auth, model, expired, 292))

	mustConfigure(t, businessConfig(dir, false))
	degraded := fakeTokenSeed(312, now, 0x77)
	resp := interceptAfter(t, request(auth, model, degraded))
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("an expired template was substituted (len %d); replaying it would fail upstream", len(got))
	}
}

// --- §8.6 business traffic never feeds the store -------------------------

func TestBusinessRoleNeverWritesStore(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-luna"
	)
	stored := storeRecordFor(auth, model, issued, 292)
	mustWriteRecord(t, dir, stored)

	before := snapshotDir(t, dir)

	mustConfigure(t, businessConfig(dir, false))

	// A business request arrives carrying its own, different, valid 292. The
	// spec forbids the business side from harvesting it.
	selfSupplied := fakeTokenSeed(292, now, 0x33)
	if selfSupplied == stored.Value {
		t.Fatal("fixture error: the self-supplied token matches the stored one")
	}
	interceptAfter(t, request(auth, model, selfSupplied))

	// A fresh bucket the store has never seen must not be created either.
	interceptAfter(t, request("codex-z.json", "gpt-6-astra", fakeTokenSeed(292, now, 0x44)))

	after := snapshotDir(t, dir)
	if !equalSnapshots(before, after) {
		t.Fatalf("business traffic mutated the store\nbefore: %v\nafter:  %v", before, after)
	}
}

// --- §8.7 replace-only only touches degraded state -----------------------

func TestReplaceOnlyOnlyRewritesDegradedState(t *testing.T) {
	issued := testNow.Add(-10 * time.Minute)
	tmpl := templateEntry{value: fakeTokenSeed(292, issued, 0x5a), issuedAt: issued}

	replaceOnly := defaultConfig()
	replaceOnly.InjectMode = "replace-only"
	replaceOnly.TemplateLength = 292
	replaceOnly.ReplaceLength = 312

	tests := []struct {
		name        string
		value       string
		wantRewrite bool
	}{
		{"no header at all", "", false},
		{"already a template", fakeTokenSeed(292, testNow, 0x66), false},
		{"unexpected length", "short-value", false},
		{"degraded 312", fakeTokenSeed(312, testNow, 0x77), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, replacement := decideHeader(replaceOnly, tc.value, tmpl, true, false, testNow)
			if tc.wantRewrite && replacement != tmpl.value {
				t.Fatalf("expected the stored template, got %d chars", len(replacement))
			}
			if !tc.wantRewrite && replacement != "" {
				t.Fatalf("replace-only rewrote a %d-char value it should have left alone", len(tc.value))
			}
		})
	}

	// Contrast: the forbidden "always" mode would force the header on. This
	// asserts the replace-only guard is load-bearing rather than vacuous.
	t.Run("always mode is the behaviour replace-only suppresses", func(t *testing.T) {
		always := replaceOnly
		always.InjectMode = "always"
		if _, _, replacement := decideHeader(always, "", tmpl, true, false, testNow); replacement == "" {
			t.Fatal("always mode did not inject; the replace-only cases above prove nothing")
		}
	})
}

func TestNoTemplateMeansNoRewrite(t *testing.T) {
	cfg := defaultConfig()
	cfg.InjectMode = "replace-only"
	degraded := fakeTokenSeed(312, testNow, 0x77)
	_, _, replacement := decideHeader(cfg, degraded, templateEntry{}, false, false, testNow)
	if replacement != "" {
		t.Fatalf("rewrote a request with no live template for its bucket (%d chars)", len(replacement))
	}
}

// --- §8.8 dry_run changes nothing on the wire ----------------------------

func TestDryRunReturnsNoop(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	mustWriteRecord(t, dir, storeRecordFor(auth, model, issued, 292))

	degraded := fakeTokenSeed(312, now, 0x77)

	mustConfigure(t, businessConfig(dir, true))
	resp := interceptAfter(t, request(auth, model, degraded))
	if len(resp.Headers) != 0 {
		t.Fatalf("dry_run returned %d header(s); it must be a no-op on the wire", len(resp.Headers))
	}
	if len(resp.ClearHeaders) != 0 {
		t.Fatalf("dry_run returned ClearHeaders %v; it must be a no-op on the wire", resp.ClearHeaders)
	}
}

func TestDryRunFalseDoesSubstitute(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	rec := storeRecordFor(auth, model, issued, 292)
	mustWriteRecord(t, dir, rec)

	mustConfigure(t, businessConfig(dir, false))
	resp := interceptAfter(t, request(auth, model, fakeTokenSeed(312, now, 0x77)))
	if got := outgoingHeader(resp); got != rec.Value {
		t.Fatalf("substitution did not happen with dry_run off (got %d chars)", len(got))
	}
	// ClearHeaders first, or a non-canonical spelling survives alongside.
	if len(resp.ClearHeaders) == 0 {
		t.Fatal("substitution did not clear the incoming header first; a duplicate could survive")
	}
}

// --- probe role must not rewrite (spec §6.1) -----------------------------

func TestProbeRoleNeverRewritesRequests(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	issued := now.Add(-5 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	mustWriteRecord(t, dir, storeRecordFor(auth, model, issued, 292))

	mustConfigure(t, fmt.Sprintf(`role: probe
store_dir: %q
template_length: 292
replace_length: 312
ttl_seconds: 3600
inject_mode: replace-only
dry_run: false
log_decisions: false
`, dir))

	resp := interceptAfter(t, request(auth, model, fakeTokenSeed(312, now, 0x77)))
	if len(resp.Headers) != 0 || len(resp.ClearHeaders) != 0 {
		t.Fatal("the probe role rewrote a request; substituting on probe traffic would stop new 292s being minted")
	}
}

// --- §8.11 config: inband alias and business force-off -------------------

func TestConfigureHarvestInbandAliasAndBusinessForceOff(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "spec spelling on probe",
			yaml: "role: probe\nharvest_inband: true\n",
			want: true,
		},
		{
			name: "legacy alias on probe",
			yaml: "role: probe\nharvest_in_band: true\n",
			want: true,
		},
		{
			name: "business forces it off",
			yaml: "role: business\nharvest_inband: true\n",
			want: false,
		},
		{
			name: "business forces the alias off too",
			yaml: "role: business\nharvest_in_band: true\n",
			want: false,
		},
		{
			name: "default is off",
			yaml: "role: probe\n",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The probe role refuses to start without somewhere to write.
			mustConfigure(t, tc.yaml+storeDirLine(t))
			state.mu.Lock()
			got := state.config.HarvestInband
			state.mu.Unlock()
			if got != tc.want {
				t.Fatalf("HarvestInband = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestConfigureRoleValidation(t *testing.T) {
	t.Run("missing role defaults to business", func(t *testing.T) {
		mustConfigure(t, "template_length: 292\nreplace_length: 312\n")
		state.mu.Lock()
		got := state.config.Role
		state.mu.Unlock()
		if got != roleBusiness {
			t.Fatalf("Role = %q, want %q: an absent role must fail safe to the non-writing side, "+
				"and DEPLOY.md step 6 installs the .so before step 7 sets the role", got, roleBusiness)
		}
	})

	t.Run("invalid role is rejected", func(t *testing.T) {
		if err := configureYAML(t, "role: probesque\n"); err == nil {
			t.Fatal("configure accepted an invalid role")
		}
	})

	t.Run("probe and business are both accepted", func(t *testing.T) {
		for _, role := range []string{roleProbe, roleBusiness} {
			if err := configureYAML(t, "role: "+role+"\n"+storeDirLine(t)); err != nil {
				t.Fatalf("configure rejected role %q: %v", role, err)
			}
		}
	})

	t.Run("probe without a store_dir is rejected", func(t *testing.T) {
		// A probe with nowhere to write would report success while harvesting
		// nothing, and --until-complete would never terminate.
		if err := configureYAML(t, "role: probe\n"); err == nil {
			t.Fatal("configure accepted a probe with no store_dir")
		}
	})
}

// TestInjectAlwaysOnlySuppressedByExactSpelling pins the last line of defence,
// not the first.
//
// injectAlways treats everything that is not exactly "replace-only" as the
// forcing mode, so a typo reaching it would become the one behaviour the spec
// prohibits. What actually stops a typo is the validation in configure, which
// rejects any mode outside {replace-only, always} at startup — see
// TestConfigureInjectModeValidation. This test covers the case where some
// future path builds a pluginConfig without going through configure: the
// decision itself must still honour only the exact spelling.
//
// Both tests are load-bearing. Deleting either one reopens the hole from a
// different direction.
func TestInjectAlwaysOnlySuppressedByExactSpelling(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"replace-only", false},
		{"  replace-only  ", false},
		{"REPLACE-ONLY", false},
		{"always", true},
		// A config that never passed through configure can still carry these.
		// configure would have rejected the underscore and normalised the empty
		// string; here, both fall through to the forcing mode.
		{"", true},
		{"replace_only", true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.mode), func(t *testing.T) {
			cfg := defaultConfig()
			cfg.InjectMode = tc.mode
			if got := cfg.injectAlways(); got != tc.want {
				t.Fatalf("injectAlways() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestIsProbe(t *testing.T) {
	probe := defaultConfig()
	probe.Role = roleProbe
	if !probe.isProbe() {
		t.Fatal("role probe did not report isProbe")
	}
	business := defaultConfig()
	business.Role = roleBusiness
	if business.isProbe() {
		t.Fatal("role business reported isProbe")
	}
}

// --- the single expiry rule ----------------------------------------------

// TestTemplateUsableExpiryBoundary pins the exact boundary spec §4 asks for:
// "issued_at + 3600s <= now" is expired. The three call sites used to disagree
// about whether the instant of expiry itself still counted; they now all route
// through templateUsable, and this table is what stops one of them drifting
// back to a strict ">" comparison.
func TestTemplateUsableExpiryBoundary(t *testing.T) {
	issued := testNow

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"issued this instant", issued, true},
		{"one second into the window", issued.Add(time.Second), true},
		{"one second before expiry", issued.Add(testTTL - time.Second), true},
		// The spec's wording: issued_at + ttl <= now is expired, so the instant
		// of expiry is already too late.
		{"exactly at expiry", issued.Add(testTTL), false},
		{"one second past expiry", issued.Add(testTTL + time.Second), false},
		{"long past expiry", issued.Add(24 * time.Hour), false},
		// now precedes issued_at: the token claims to have been signed in the
		// future, which no honest upstream timestamp can be.
		{"one second before it was issued", issued.Add(-time.Second), false},
		{"issued far in the future", issued.Add(-30 * time.Minute), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := templateUsable(issued, tc.now, testTTL); got != tc.want {
				t.Fatalf("templateUsable(issued=%s, now=%s, ttl=%s) = %t, want %t",
					issued.UTC(), tc.now.UTC(), testTTL, got, tc.want)
			}
		})
	}
}

// TestFutureTemplateNeverSubstituted covers the substitution path: a template
// stamped in the future must not reach a live request.
//
// Written the natural way, an age comparison reads a future timestamp as
// "brand new" and keeps doing so for as long as the skew lasts. The upstream
// would answer "Encrypted content could not be decrypted" while the decision
// log showed a clean substitute.
func TestFutureTemplateNeverSubstituted(t *testing.T) {
	dir := t.TempDir()
	now := wallClock()
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	// Stamped half an hour ahead: well inside the TTL by a naive age check.
	future := now.Add(30 * time.Minute)
	writeRawRecord(t, dir, storeRecordFor(auth, model, future, 292))

	mustConfigure(t, businessConfig(dir, false))
	resp := interceptAfter(t, request(auth, model, fakeTokenSeed(312, now, 0x77)))
	if got := outgoingHeader(resp); got != "" {
		t.Fatalf("a future-stamped template was substituted (len %d); a naive age check reads it as brand new", len(got))
	}
}

// --- inject_mode validation ----------------------------------------------

// TestConfigureInjectModeValidation is the first line of defence against the
// typo that would turn on the prohibited forcing mode. See the comment on
// TestInjectAlwaysOnlySuppressedByExactSpelling for the second.
func TestConfigureInjectModeValidation(t *testing.T) {
	t.Run("default is replace-only", func(t *testing.T) {
		if got := defaultConfig().InjectMode; got != "replace-only" {
			t.Fatalf("defaultConfig().InjectMode = %q, want %q: forcing must never be what you get by omission", got, "replace-only")
		}
		if defaultConfig().injectAlways() {
			t.Fatal("the default config reports injectAlways")
		}
	})

	accepted := []struct {
		name            string
		mode            string
		wantInjectAlway bool
	}{
		{"replace-only", "inject_mode: replace-only\n", false},
		{"always", "inject_mode: always\n", true},
		// An explicitly blank value must be pinned to the safe mode rather than
		// falling through injectAlways as "not replace-only" and forcing.
		{"empty string normalises to replace-only", "inject_mode: \"\"\n", false},
		{"key omitted entirely", "", false},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			mustConfigure(t, "role: business\n"+tc.mode)
			state.mu.Lock()
			cfg := state.config
			state.mu.Unlock()
			if got := cfg.injectAlways(); got != tc.wantInjectAlway {
				t.Fatalf("injectAlways() = %t, want %t (inject_mode normalised to %q)", got, tc.wantInjectAlway, cfg.InjectMode)
			}
			if !tc.wantInjectAlway && cfg.InjectMode != "replace-only" {
				t.Fatalf("inject_mode normalised to %q, want %q", cfg.InjectMode, "replace-only")
			}
		})
	}

	rejected := []struct {
		name string
		mode string
	}{
		// The exact spelling the spec calls out. Before validation existed this
		// silently became the forcing mode.
		{"underscore instead of hyphen", "replace_only"},
		{"space instead of hyphen", "replace only"},
		{"plausible synonym", "substitute-only"},
		{"typo in always", "alwyas"},
		{"unrelated value", "off"},
	}
	for _, tc := range rejected {
		t.Run(tc.name+" is rejected", func(t *testing.T) {
			err := configureYAML(t, "role: business\ninject_mode: "+tc.mode+"\n")
			if err == nil {
				t.Fatalf("configure accepted inject_mode %q; an unrecognised value must fail loudly rather than become the forcing mode", tc.mode)
			}
			if !strings.Contains(err.Error(), "inject_mode") {
				t.Fatalf("error does not mention inject_mode, so an operator cannot act on it: %v", err)
			}
		})
	}
}

// probe_base_url defaults to CPA's own loopback listener, because the plugin runs
// inside the process it probes. An explicitly empty value is pinned to the same
// default rather than left blank: an empty base URL fails deep inside a probe run
// as a transport error, which reads as "the upstream is down" when the truth is
// "the setting is blank".
func TestProbeBaseURLDefaultsToLoopback(t *testing.T) {
	if got := defaultConfig().ProbeBaseURL; got != defaultProbeBaseURL {
		t.Fatalf("defaultConfig().ProbeBaseURL = %q, want %q", got, defaultProbeBaseURL)
	}

	for name, cfgYAML := range map[string]string{
		"absent":           "role: business\n",
		"explicitly empty": "role: business\nprobe_base_url: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			mustConfigure(t, cfgYAML)
			state.mu.Lock()
			got := state.config.ProbeBaseURL
			state.mu.Unlock()
			if got != defaultProbeBaseURL {
				t.Fatalf("probe_base_url = %q, want the default %q", got, defaultProbeBaseURL)
			}
		})
	}

	// The control: a configured value is of course kept, or the two cases above
	// would pass against a function that ignored the setting entirely.
	t.Run("configured value wins", func(t *testing.T) {
		mustConfigure(t, "role: business\nprobe_base_url: http://127.0.0.1:9317\n")
		state.mu.Lock()
		got := state.config.ProbeBaseURL
		state.mu.Unlock()
		if got != "http://127.0.0.1:9317" {
			t.Fatalf("probe_base_url = %q, want the configured value", got)
		}
	})
}
