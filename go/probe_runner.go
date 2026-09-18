// In-plugin probe runner: the port of scripts/probe.py's sweep.
//
// # Why this makes a real HTTP request instead of calling host.model.execute
//
// The host tags every plugin-issued execution with SkipInterceptorPluginID set
// to the calling plugin's own id, so a request fired through host.model.execute
// is routed *past* this plugin's response interceptor and can never reach
// harvestFromResponse. That is why the self-test says, in so many words, that it
// cannot collect: it can prove the path is alive, it can never fill a bucket.
//
// A sweep has to travel the normal interceptor chain, and the only way to do
// that from inside the process is to be an ordinary client of CPA's public API:
// POST /v1/responses on CPA's own listener, with a real API key, exactly as
// scripts/probe.py does from the host side.
//
// # What it inherits from scripts/probe.py
//
// The shape is deliberately the same, because that script is the proven
// reference: snapshot account state before touching anything, make one account
// the sole enabled Codex credential so the harvest can be attributed, try each
// configured exit in turn, and restore on every exit path.
//
// Two things are different on purpose, and both are improvements the script
// could not make:
//
//   - Readiness is read from this process's own store rather than polled over
//     the management API. The harvest happens on the response interceptor in
//     this very process, so by the time the POST returns the bucket is already
//     written; the wait only has to absorb the store scan's throttle.
//   - The proxy read-back goes to the credential file itself
//     (auth-files/download) rather than to the auth-files listing. The listing
//     carries no per-account proxy field on this CPA build, which is exactly
//     what stopped the script rotating exits here.
//
// # What must never leak out of this file
//
// Lines is rendered on a page that needs no management key. A proxy URL's
// userinfo must therefore never reach Lines, nor an error string, nor the
// process log: every proxy value is rendered through maskProxyURL, and
// everything bound for Lines passes through probeRedact as a second line of
// defence. The two keys this file holds -- probe_api_key and
// probe_management_key -- are never logged or returned in any form.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// probeRestoreFileName holds the pre-run account state, in the store directory
// this plugin owns.
//
// scripts/probe.py keeps its snapshot in memory and in a file for the same
// reason, and the memory half is not enough: a snapshot that exists only in a
// process is lost the moment that process dies, and a sweep that dies after
// disabling three of four accounts leaves the operator's credentials switched
// off with nothing to put them back. That is not hypothetical here -- it cost a
// real incident. The file is what makes the undo survive a plugin panic or a CPA
// restart.
const probeRestoreFileName = "probe-restore.json"

// The routes this runner drives. They are named here rather than spelled inline
// so a correction for a different CPA build is a one-line change, which is the
// lesson scripts/probe.py records against CPA.PROXY_ROUTE.
const (
	probeRouteAuthFiles    = "/v0/management/auth-files"
	probeRouteAuthStatus   = "/v0/management/auth-files/status"
	probeRouteAuthFields   = "/v0/management/auth-files/fields"
	probeRouteAuthDownload = "/v0/management/auth-files/download"
	probeRouteResponses    = "/v1/responses"
	// probeProxyField is the credential field carrying one account's own exit.
	// CPA's global proxy-url is a different setting entirely and is never written
	// from here: it carries Kimi, xAI and all daily traffic.
	probeProxyField = "proxy_url"
)

const (
	// probeMaxLines bounds the transcript. A sweep over four accounts and five
	// models emits a few hundred lines; keeping the last forty is enough to say
	// where it stopped and why, and it means the run state cannot grow without
	// limit in a process that is meant to stay up for weeks.
	probeMaxLines = 40

	probeFireTimeout    = 120 * time.Second
	probeMgmtTimeout    = 30 * time.Second
	probeRestoreTimeout = 2 * time.Minute

	// probeMaxBodyBytes caps what is read from a response. The bodies of interest
	// are small JSON documents; an unbounded read here would let a misrouted
	// request pull an arbitrary amount into the plugin's heap.
	probeMaxBodyBytes = 64 << 10
)

// The three waits below are vars rather than consts so the tests can shrink
// them; nothing in production writes to them. A sweep against a fake CPA
// otherwise spends its whole time asleep, and a test suite that takes half a
// minute to say "the restore ran in the right order" is one nobody runs.
var (
	// probeBucketWait is how long one exit gets to produce a live template.
	//
	// Eight seconds against scripts/probe.py's ninety, and the difference is not
	// impatience. The script polled CPA's management API from another process, so
	// the harvest, the store write and the index update all had to land before it
	// could see anything. Here the harvest runs on the response interceptor in
	// this same process, before the POST above it returns: anything that is going
	// to arrive has already arrived, and this window only has to absorb the
	// one-second throttle in refreshStoreLocked.
	probeBucketWait = 8 * time.Second
	probePollEvery  = time.Second

	// probeSettle is the pause after flipping credential state. CPA reloads that
	// state asynchronously, and firing immediately can still hit the previous
	// candidate set -- which would attribute the harvest to the wrong account,
	// the one error per-account bucketing exists to prevent.
	probeSettle = 2 * time.Second
)

// probeRunState is the snapshot the dashboard polls. It carries progress and
// prose and no credential of any kind: see the file comment on Lines.
type probeRunState struct {
	Running    bool     `json:"running"`
	StartedAt  string   `json:"started_at,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Done       int      `json:"done"`
	Total      int      `json:"total"`
	Current    string   `json:"current,omitempty"`
	Lines      []string `json:"lines,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// probeRunner holds the single in-process run. There is deliberately only one at
// a time: a sweep disables every Codex account but one, so a second sweep
// starting mid-flight would snapshot the first one's mutations as the "original"
// state and then restore to that -- turning a temporary flip into a permanent
// one.
var probeRunner struct {
	mu     sync.Mutex
	run    probeRunState
	cancel context.CancelFunc
}

// probeTarget is one bucket the sweep intends to fill.
type probeTarget struct {
	account string
	model   string
}

// probeRunStart validates the run and launches it in the background. It returns
// nil once the goroutine is on its way, or an error explaining the refusal --
// and a refusal changes nothing at all.
func probeRunStart() error {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// Role first. Every other refusal below is about a run that could not work;
	// this one is about a run that must not happen: the sweep flips the disabled
	// flag on live credentials, and a business process doing that would take
	// customer traffic down to fill a bucket it does not even write.
	if !cfg.isProbe() {
		return fmt.Errorf("role is %q, not %q: a sweep disables every Codex credential except the one being probed, which a business process must never do", cfg.Role, roleProbe)
	}

	accounts := append([]string(nil), cfg.ProbeAccounts...)
	models := append([]string(nil), cfg.Models...)
	proxies := append([]string(nil), cfg.ProbeProxies...)

	switch {
	case len(accounts) == 0:
		// No fallback to "all of them". Probing is stop-the-world and spends one
		// upstream request per bucket, so "nothing selected means everything" is
		// the single mistake that cannot be undone afterwards.
		return fmt.Errorf("probe_accounts is empty, so there is nothing to probe; refusing to widen an empty selection to every credential")
	case len(models) == 0:
		return fmt.Errorf("models is empty, so there is no bucket to fill; refusing to fall back to the full model list")
	case strings.TrimSpace(cfg.ProbeAPIKey) == "":
		return fmt.Errorf("probe_api_key is not set; it is the Bearer token for POST %s, and a different key from probe_management_key", probeRouteResponses)
	case strings.TrimSpace(cfg.ProbeManagementKey) == "":
		return fmt.Errorf("probe_management_key is not set; without it the sweep cannot enable or disable a credential")
	case strings.TrimSpace(cfg.StoreDir) == "":
		// configure already refuses role=probe with no store_dir; this is here so
		// a future relaxation there cannot silently remove the restore file.
		return fmt.Errorf("store_dir is empty, so there is nowhere to write %s -- the file that makes the undo survive a crash", probeRestoreFileName)
	}

	// A restore file left behind means an earlier sweep died, or its restore
	// failed, with credentials still flipped. Snapshotting now would record that
	// half-disabled state as the original and make it permanent, which is the
	// exact incident the file exists to prevent -- so this refuses rather than
	// overwriting it.
	restorePath := probeRestorePath(cfg.StoreDir)
	if _, errStat := os.Stat(restorePath); errStat == nil {
		return fmt.Errorf("%s still exists, so an earlier sweep did not finish putting credential state back; starting now would snapshot that state as the original and make it permanent. Re-apply or delete that file first", restorePath)
	}

	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if probeRunner.run.Running {
		return fmt.Errorf("a probe sweep is already in flight; stop it before starting another")
	}

	ctx, cancel := context.WithCancel(context.Background())
	probeRunner.cancel = cancel
	probeRunner.run = probeRunState{
		Running:   true,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	go probeSweep(ctx, cfg, accounts, models, proxies)
	return nil
}

// probeRunCancel asks the running sweep to stop. It returns false when nothing
// was running. Cancellation is a request, not a kill: the sweep still restores
// every credential it touched before it reports itself finished.
func probeRunCancel() bool {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if !probeRunner.run.Running || probeRunner.cancel == nil {
		return false
	}
	probeRunner.cancel()
	probeRunner.run.Lines = probeAppendLine(probeRunner.run.Lines, "stop requested; the sweep will restore credential state before it finishes")
	return true
}

// probeRunSnapshot returns a copy of the run state, Lines included. The copy is
// what makes it safe to hand to a JSON encoder while the sweep keeps appending.
func probeRunSnapshot() probeRunState {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	out := probeRunner.run
	out.Lines = append([]string(nil), probeRunner.run.Lines...)
	return out
}

// probeRunUpdate mutates the run state under the one mutex that guards it.
func probeRunUpdate(mutate func(run *probeRunState)) {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	mutate(&probeRunner.run)
}

// probeRunLog appends one line to the transcript and mirrors it to the process
// log.
//
// Every line goes through probeRedact first. Callers are expected to have masked
// any proxy URL already, with maskProxyURL; this is the second line of defence,
// not the first, and it exists because Lines is served to a reader who has
// presented no key.
func probeRunLog(format string, args ...any) {
	line := probeRedact(fmt.Sprintf(format, args...))
	probeRunUpdate(func(run *probeRunState) {
		run.Lines = probeAppendLine(run.Lines, line)
	})
	log.Printf("%sprobe %s", logPrefix, line)
}

// probeRunFail records the reason a sweep stopped. The first error wins: what
// went wrong first is what the operator needs, and anything that happened after
// it is a consequence.
func probeRunFail(errRun error) {
	if errRun == nil {
		return
	}
	message := probeRedact(errRun.Error())
	probeRunUpdate(func(run *probeRunState) {
		if run.Error == "" {
			run.Error = message
		}
		run.Lines = probeAppendLine(run.Lines, "error: "+message)
	})
	log.Printf("%sprobe error: %s", logPrefix, message)
}

// probeRunFinish marks the sweep over. It is the outermost defer in probeSweep,
// so it runs after the restore has had its say.
func probeRunFinish() {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	probeRunner.run.Running = false
	probeRunner.run.Current = ""
	probeRunner.run.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if probeRunner.cancel != nil {
		probeRunner.cancel()
		probeRunner.cancel = nil
	}
}

// probeAppendLine adds one timestamped line and keeps the transcript bounded.
func probeAppendLine(lines []string, line string) []string {
	lines = append(lines, time.Now().UTC().Format("15:04:05")+" "+line)
	if len(lines) > probeMaxLines {
		// Copied rather than resliced: a reslice would keep the whole original
		// backing array alive, which is the opposite of the point.
		lines = append([]string(nil), lines[len(lines)-probeMaxLines:]...)
	}
	return lines
}

// probeSweep is the whole run, and the only goroutine this file starts.
func probeSweep(ctx context.Context, cfg pluginConfig, accounts, models, proxies []string) {
	// Registered first, so it runs last: the state is not "finished" until the
	// restore below has run.
	defer probeRunFinish()
	// A panic in a native plugin takes the whole CPA process with it, so this
	// goroutine catches its own. The restore defer is registered further down and
	// therefore runs *before* this one, which is what makes a panic still put
	// credential state back.
	defer func() {
		if recovered := recover(); recovered != nil {
			probeRunFail(fmt.Errorf("probe sweep panicked: %v", recovered))
		}
	}()

	client := newProbeClient(cfg)
	defer client.http.CloseIdleConnections()

	auths, errList := client.listCodexAuths(ctx)
	if errList != nil {
		probeRunFail(fmt.Errorf("could not list Codex credentials: %w", errList))
		return
	}
	if len(auths) == 0 {
		probeRunFail(fmt.Errorf("CPA reports no Codex credentials, so there is nothing to enable"))
		return
	}

	// A selected account CPA does not know about would make the sweep quietly
	// cover less than was asked for, so it stops the run instead.
	known := make(map[string]bool, len(auths))
	for _, auth := range auths {
		known[auth.Name] = true
	}
	for _, account := range accounts {
		if !known[account] {
			probeRunFail(fmt.Errorf("selected account %q is not among CPA's Codex credentials; fix the selection rather than letting the sweep cover less than was asked for", account))
			return
		}
	}

	snapshot, errSnapshot := client.snapshotAccounts(ctx, auths)
	if errSnapshot != nil {
		probeRunFail(fmt.Errorf("could not snapshot credential state: %w", errSnapshot))
		return
	}

	// Rotation is gated on having read each probed account's own exit back.
	// Without that there is no way to tell a working PATCH from one CPA ignored,
	// and -- worse -- no way to record what the exit was before the run, so no way
	// to put it back. Failing here costs nothing; discovering it mid-sweep costs
	// the window and can leave a credential pointed at a probe exit.
	if len(proxies) > 0 {
		for _, account := range accounts {
			if entry := probeEntryFor(snapshot, account); entry == nil || entry.ProxyURL == nil {
				probeRunFail(fmt.Errorf("%d probe exit(s) are configured, but %s's own %s could not be read back from GET %s, so a switch could be neither confirmed nor undone; clear probe_proxies to probe on each credential's existing exit", len(proxies), account, probeProxyField, probeRouteAuthDownload))
				return
			}
		}
	}

	// Persisted before the first mutation, never after: a snapshot written
	// afterwards would be a snapshot of the damage.
	if errWrite := writeProbeRestore(cfg.StoreDir, client.baseURL, snapshot); errWrite != nil {
		probeRunFail(fmt.Errorf("could not write %s, so the flips would not be undoable after a crash; refusing to touch credential state: %w", probeRestorePath(cfg.StoreDir), errWrite))
		return
	}
	probeRunLog("snapshot of %d credential state(s) written to %s", len(snapshot), probeRestorePath(cfg.StoreDir))

	// touched records which credentials this sweep repointed. The restore closes
	// over it, so it sees every entry added between here and the return.
	touched := make(map[string]bool, len(accounts))
	defer probeRestore(cfg.StoreDir, client, snapshot, touched)

	targets := probePendingTargets(cfg, accounts, models)
	probeRunUpdate(func(run *probeRunState) { run.Total = len(targets) })
	probeRunLog("sweep over %d account(s) x %d model(s): %d bucket(s) to fill, %d exit(s) configured",
		len(accounts), len(models), len(targets), len(proxies))
	if len(targets) == 0 {
		probeRunLog("every selected bucket already holds a live template; nothing to fire")
		return
	}

	// sole is the credential currently left enabled. Targets arrive grouped by
	// account, so this flips once per account rather than once per bucket -- the
	// same shape scripts/probe.py has, and each flip costs one PATCH per
	// credential plus a settle.
	sole := ""
	for _, target := range targets {
		if ctx.Err() != nil {
			probeRunLog("stopped on request")
			return
		}
		probeRunUpdate(func(run *probeRunState) { run.Current = target.account + " / " + target.model })

		if sole != target.account {
			if errEnable := client.enableOnly(ctx, auths, target.account); errEnable != nil {
				probeRunFail(fmt.Errorf("could not make %s the sole enabled Codex credential: %w", target.account, errEnable))
				return
			}
			sole = target.account
			probeRunLog("%s is now the sole enabled Codex credential", target.account)
			if !probeSleep(ctx, probeSettle) {
				probeRunLog("stopped on request")
				return
			}
		}

		harvested, errFatal := probeOneBucket(ctx, cfg, client, target, proxies, snapshot, touched)
		if errFatal != nil {
			probeRunFail(errFatal)
			return
		}
		probeRunUpdate(func(run *probeRunState) { run.Done++ })
		if harvested {
			probeRunLog("ready %s / %s", target.account, target.model)
			continue
		}
		probeRunLog("no template for %s / %s", target.account, target.model)
	}
}

// probeOneBucket fills one bucket, trying each configured exit in turn.
//
// It returns (true, nil) as soon as the bucket goes live. A candidate that times
// out is not an error: it means that exit is not in a honeymoon right now, which
// is exactly what the next candidate is for. The only fatal outcome is a failure
// to *switch* the exit -- see setProxyVerified.
func probeOneBucket(ctx context.Context, cfg pluginConfig, client *probeClient, target probeTarget, proxies []string, snapshot []probeRestoreEntry, touched map[string]bool) (bool, error) {
	// A nil entry means "leave the credential's own exit alone", which is what an
	// empty probe_proxies asks for. It is not the same as an empty string: an
	// empty string would clear the credential's override, and that is a change
	// this path must not make.
	attempts := make([]*string, 0, len(proxies)+1)
	if len(proxies) == 0 {
		attempts = append(attempts, nil)
	} else {
		for index := range proxies {
			attempts = append(attempts, &proxies[index])
		}
	}

	for index, candidate := range attempts {
		if ctx.Err() != nil {
			return false, nil
		}
		if candidate != nil {
			entry := probeEntryFor(snapshot, target.account)
			if entry == nil {
				return false, fmt.Errorf("no snapshot entry for %s, so its exit could not be changed safely", target.account)
			}
			// Marked before the write, not after. A PATCH that answers 200 and
			// then fails its read-back may still have changed something, and an
			// exit we are unsure about is exactly the one that must be restored.
			touched[target.account] = true
			if errProxy := client.setProxyVerified(ctx, entry, *candidate); errProxy != nil {
				return false, errProxy
			}
			probeRunLog("exit %d/%d for %s -> %s (verified by read-back)", index+1, len(attempts), target.account, probeShowProxy(*candidate))
			if !probeSleep(ctx, probeSettle) {
				return false, nil
			}
		}

		status, note := client.fire(ctx, target.model)
		probeRunLog("fired %s on %s: http=%d%s", target.model, target.account, status, note)

		if probeWaitForBucket(ctx, cfg, target) {
			return true, nil
		}
		if candidate != nil {
			probeRunLog("exit %d/%d yielded no template for %s within %s", index+1, len(attempts), target.model, probeBucketWait)
		}
	}
	return false, nil
}

// probeWaitForBucket polls this process's own store until the bucket holds a
// live template, or the window closes.
//
// It cannot tell a degraded 312 from silence, and deliberately does not try.
// The store only ever holds template-length values -- writeStoreRecord refuses
// anything else -- so an exit that answered with a degraded state and one that
// answered with nothing look identical from here. The response is the same
// either way: move to the next exit.
func probeWaitForBucket(ctx context.Context, cfg pluginConfig, target probeTarget) bool {
	deadline := time.Now().Add(probeBucketWait)
	for {
		if probeBucketLive(cfg, target) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		if !probeSleep(ctx, probePollEvery) {
			return false
		}
	}
}

// probeBucketLive asks the same two functions the business path asks, so "already
// live" here means exactly what it means at substitution time. Anything else and
// a sweep could report a bucket filled that the business role would still refuse
// to use.
func probeBucketLive(cfg pluginConfig, target probeTarget) bool {
	now := time.Now()
	state.mu.Lock()
	defer state.mu.Unlock()
	state.refreshStoreLocked(cfg, now)
	_, live := state.freshestTemplateLocked(target.account, target.model, now, cfg.ttl())
	return live
}

// probePendingTargets lists the buckets in scope that do not already hold a live
// template, account-major so the sweep flips credential state once per account.
func probePendingTargets(cfg pluginConfig, accounts, models []string) []probeTarget {
	out := make([]probeTarget, 0, len(accounts)*len(models))
	for _, account := range accounts {
		for _, model := range models {
			target := probeTarget{account: account, model: model}
			if probeBucketLive(cfg, target) {
				continue
			}
			out = append(out, target)
		}
	}
	return out
}

// probeSleep waits for the given duration and reports whether the run is still
// wanted. It returns false as soon as the sweep is cancelled, which is what
// makes a stop take effect inside a settle or a poll rather than at the end of
// the current bucket.
func probeSleep(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// --- restore -------------------------------------------------------------

// probeRestoreEntry is one credential's pre-run state.
type probeRestoreEntry struct {
	Name string `json:"name"`
	// AuthIndex is echoed back to CPA verbatim as the JSON it arrived as, so this
	// code never has to decide whether it is a string or a number. Guessing wrong
	// would address a PATCH at the wrong credential.
	AuthIndex json.RawMessage `json:"auth_index,omitempty"`
	Disabled  bool            `json:"disabled"`
	// ProxyURL is a pointer so "CPA does not expose this credential's exit" stays
	// distinct from "this credential has no exit set". The first means there is
	// nothing to put back and nothing that could be put back correctly; the
	// second means put an empty value back.
	//
	// It is written to the restore file in the clear, like the rest of that file:
	// the file is 0600 and exists precisely so a failed run can be undone by
	// hand, and a masked value would be useless for that. It is never logged --
	// see probeRestore, which renders it through maskProxyURL.
	ProxyURL *string `json:"proxy_url"`
}

// probeRestoreFile is the on-disk snapshot.
type probeRestoreFile struct {
	CapturedAt string              `json:"captured_at"`
	BaseURL    string              `json:"base_url"`
	Accounts   []probeRestoreEntry `json:"accounts"`
}

func probeRestorePath(storeDir string) string {
	return filepath.Join(strings.TrimSpace(storeDir), probeRestoreFileName)
}

// probeEntryFor finds one credential's snapshot entry, or nil.
func probeEntryFor(snapshot []probeRestoreEntry, name string) *probeRestoreEntry {
	for index := range snapshot {
		if snapshot[index].Name == name {
			return &snapshot[index]
		}
	}
	return nil
}

// writeProbeRestore persists the snapshot. The 0600 comes from atomicWrite,
// which creates through os.CreateTemp and renames into place, so no reader ever
// sees a half-written snapshot -- and a snapshot read half-written is a restore
// that puts back half a state.
func writeProbeRestore(storeDir, baseURL string, snapshot []probeRestoreEntry) error {
	dir := strings.TrimSpace(storeDir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty")
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	doc := probeRestoreFile{
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		BaseURL:    baseURL,
		Accounts:   snapshot,
	}
	data, errMarshal := json.MarshalIndent(doc, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	return atomicWrite(probeRestorePath(dir), append(data, '\n'))
}

// probeRestore puts every credential back the way the snapshot found it. It runs
// from a defer, so it runs on the clean path, on an abort, on a stop and on a
// panic.
//
// Exits first, then the enable flags, and that order is the point: a credential
// that ends up enabled is immediately schedulable, so it must already be
// pointing at its own original exit by then. Re-enabling first would put live
// business traffic through a probe exit for as long as the second loop takes.
//
// The context is a fresh one rather than the sweep's. The commonest reason this
// function runs at all is that the sweep was cancelled, and a cancelled context
// would fail every call here instantly -- turning "the operator pressed stop"
// into "every credential is left switched off".
func probeRestore(storeDir string, client *probeClient, snapshot []probeRestoreEntry, touched map[string]bool) {
	ctx, cancel := context.WithTimeout(context.Background(), probeRestoreTimeout)
	defer cancel()

	probeRunLog("restoring credential exits, then enable/disable state")
	var failures []string

	for index := range snapshot {
		entry := &snapshot[index]
		// Only the credentials this sweep actually repointed. Writing an unchanged
		// value back to a credential nobody touched is still a write to someone
		// else's file, and the rule here is that a sweep only ever sets the probed
		// account's own exit.
		if entry.ProxyURL == nil || !touched[entry.Name] {
			continue
		}
		if errProxy := client.setProxyVerified(ctx, entry, *entry.ProxyURL); errProxy != nil {
			// Collected, not returned: every remaining credential still has to be
			// put back, and stopping at the first problem is how a partial restore
			// becomes a total one.
			failures = append(failures, entry.Name+": exit not restored: "+probeRedact(errProxy.Error()))
			continue
		}
		probeRunLog("exit restored for %s -> %s", entry.Name, probeShowProxy(*entry.ProxyURL))
	}

	for index := range snapshot {
		entry := &snapshot[index]
		if errStatus := client.setDisabled(ctx, entry.Name, entry.AuthIndex, entry.Disabled); errStatus != nil {
			failures = append(failures, entry.Name+": "+probeRedact(errStatus.Error()))
		}
	}

	// Verified by re-reading rather than by trusting the PATCH answers. A 200 that
	// did not take is the failure this whole file is shaped around, and the enable
	// flags are the half that matters most: getting them wrong leaves the
	// operator's credentials switched off.
	if observed, errObserve := client.listCodexAuths(ctx); errObserve != nil {
		failures = append(failures, "could not re-list credentials to verify the restore: "+probeRedact(errObserve.Error()))
	} else {
		current := make(map[string]bool, len(observed))
		for _, auth := range observed {
			current[auth.Name] = auth.Disabled
		}
		for index := range snapshot {
			entry := &snapshot[index]
			if got, found := current[entry.Name]; found && got != entry.Disabled {
				failures = append(failures, fmt.Sprintf("%s: still disabled=%t, want %t", entry.Name, got, entry.Disabled))
			}
		}
	}

	if len(failures) > 0 {
		for _, failure := range failures {
			probeRunLog("RESTORE FAILED %s", failure)
		}
		// The snapshot file is deliberately left behind: it is the only recovery
		// path left, and the next probeRunStart refuses while it is there, which
		// stops a second sweep cementing the damage.
		probeRunLog("credentials may be left in the wrong state; %s has been kept so the flips can be re-applied by hand", probeRestorePath(storeDir))
		probeRunUpdate(func(run *probeRunState) {
			if run.Error == "" {
				run.Error = "restore incomplete: credentials may be left in the wrong state, see the log"
			}
		})
		return
	}

	if errRemove := os.Remove(probeRestorePath(storeDir)); errRemove != nil && !os.IsNotExist(errRemove) {
		probeRunLog("could not remove %s: %s", probeRestorePath(storeDir), probeRedact(errRemove.Error()))
		return
	}
	probeRunLog("credential state restored and verified")
}

// --- CPA client ----------------------------------------------------------

// probeAuthFile is one entry of GET /v0/management/auth-files.
type probeAuthFile struct {
	Name      string          `json:"name"`
	AuthIndex json.RawMessage `json:"auth_index,omitempty"`
	Disabled  bool            `json:"disabled"`
	Provider  string          `json:"provider"`
	Type      string          `json:"type"`
}

type probeHTTPResult struct {
	status int
	body   []byte
}

// probeClient is this sweep's connection to CPA's public API.
type probeClient struct {
	baseURL string
	apiKey  string
	mgmtKey string
	http    *http.Client
}

func newProbeClient(cfg pluginConfig) *probeClient {
	// configure already fills an empty probe_base_url with defaultProbeBaseURL, so
	// this only catches a config built in-process -- a test, or a future caller
	// that skips configure. It reuses main.go's constant rather than repeating the
	// literal: two defaults that could drift apart is how a probe ends up talking
	// to the wrong port and reporting it as the upstream being down.
	base := strings.TrimRight(strings.TrimSpace(cfg.ProbeBaseURL), "/")
	if base == "" {
		base = defaultProbeBaseURL
	}
	return &probeClient{
		baseURL: base,
		apiKey:  strings.TrimSpace(cfg.ProbeAPIKey),
		mgmtKey: strings.TrimSpace(cfg.ProbeManagementKey),
		http: &http.Client{
			// Proxy is nil on purpose, and it is not a detail. This box has
			// http_proxy/all_proxy set for the traffic CPA relays; the default
			// transport honours those, and every call here would then be sent to
			// an exit that cannot reach CPA's own listener and come back as a
			// bogus 502. scripts/probe.py builds its opener with an empty
			// ProxyHandler for exactly this reason.
			//
			// Timeouts are per call, via context, because the one POST wants two
			// minutes and the management calls want thirty seconds.
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// call issues one request and returns the status alongside the body.
//
// A non-2xx comes back as a result, not as an error: 401 and 404 must stay
// distinguishable -- 401 is a rejected management key, 404 is a path this CPA
// build does not serve -- and collapsing them into "the call failed" sends
// whoever is debugging this down the wrong road. Only a transport failure is an
// error.
func (c *probeClient) call(ctx context.Context, method, path, token string, payload any, timeout time.Duration) (probeHTTPResult, error) {
	var body io.Reader
	if payload != nil {
		raw, errMarshal := json.Marshal(payload)
		if errMarshal != nil {
			return probeHTTPResult{}, errMarshal
		}
		body = bytes.NewReader(raw)
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, errNew := http.NewRequestWithContext(callCtx, method, c.baseURL+path, body)
	if errNew != nil {
		return probeHTTPResult{}, errNew
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}

	response, errDo := c.http.Do(request)
	if errDo != nil {
		return probeHTTPResult{}, errDo
	}
	defer func() { _ = response.Body.Close() }()

	raw, errRead := io.ReadAll(io.LimitReader(response.Body, probeMaxBodyBytes))
	if errRead != nil {
		return probeHTTPResult{status: response.StatusCode}, errRead
	}
	return probeHTTPResult{status: response.StatusCode, body: raw}, nil
}

// probeExplainStatus names which of the three things went wrong, in the words
// that point at the fix.
func probeExplainStatus(result probeHTTPResult, what string) error {
	switch result.status {
	case http.StatusUnauthorized:
		return fmt.Errorf("%s: 401 unauthorized -- probe_management_key is wrong or not accepted; this is an auth failure, not a bad path", what)
	case http.StatusForbidden:
		return fmt.Errorf("%s: 403 forbidden -- the key was accepted but lacks access", what)
	case http.StatusNotFound:
		return fmt.Errorf("%s: 404 not found -- this CPA build does not serve that path (a bad key would have answered 401)", what)
	}
	return fmt.Errorf("%s: HTTP %d %s", what, result.status, probeTruncate(probeRedact(string(result.body)), 200))
}

// listCodexAuths returns CPA's Codex credentials, .bak copies excluded.
//
// The filter follows scripts/probe.py and isCodexAuth: provider when CPA reports
// one, the naming convention otherwise. A .bak file is an operator's backup copy
// and must never be enabled.
func (c *probeClient) listCodexAuths(ctx context.Context) ([]probeAuthFile, error) {
	result, errCall := c.call(ctx, http.MethodGet, probeRouteAuthFiles, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthFiles)
	}
	var doc struct {
		Files []probeAuthFile `json:"files"`
	}
	if errUnmarshal := json.Unmarshal(result.body, &doc); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not the expected {\"files\":[...]} document: %w", probeRouteAuthFiles, errUnmarshal)
	}
	out := make([]probeAuthFile, 0, len(doc.Files))
	for _, file := range doc.Files {
		name := strings.TrimSpace(file.Name)
		if name == "" || strings.Contains(name, ".bak") {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(file.Provider))
		kind := strings.ToLower(strings.TrimSpace(file.Type))
		lower := strings.ToLower(name)
		if provider != "codex" && kind != "codex" &&
			!(strings.HasPrefix(lower, "codex-") && strings.HasSuffix(lower, ".json")) {
			continue
		}
		file.Name = name
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// snapshotAccounts records every Codex credential's disabled flag and its own
// exit, before anything is mutated.
//
// The exit is read out of the credential file rather than out of the listing,
// because the listing does not carry it: as of 2026-09-18 GET
// /v0/management/auth-files echoes no per-account proxy field on this build,
// which is precisely what stops scripts/probe.py rotating exits here.
//
// A credential whose exit cannot be read gets a nil ProxyURL -- "nothing to put
// back, and nothing that could be put back correctly". probeSweep refuses to
// rotate in that case rather than switching blind.
func (c *probeClient) snapshotAccounts(ctx context.Context, auths []probeAuthFile) ([]probeRestoreEntry, error) {
	out := make([]probeRestoreEntry, 0, len(auths))
	for _, auth := range auths {
		entry := probeRestoreEntry{
			Name:      auth.Name,
			AuthIndex: auth.AuthIndex,
			Disabled:  auth.Disabled,
		}
		value, readable, errRead := c.readProxyURL(ctx, auth.Name)
		if errRead != nil {
			// A transport failure before any mutation is a reason to stop, not to
			// carry on with an incomplete snapshot: if CPA cannot be reached now,
			// it cannot be reached to undo anything either.
			return nil, fmt.Errorf("reading %s for %s: %w", probeProxyField, auth.Name, errRead)
		}
		if readable {
			entry.ProxyURL = &value
		}
		out = append(out, entry)
	}
	return out, nil
}

// readProxyURL reports the exit recorded in one credential file.
//
// readable=false means CPA did not give us the file at all -- a build without
// the download route answers 404, and that is the expected shape rather than an
// error. A file that parses but carries no proxy_url is readable with an empty
// value: absent and empty mean the same thing to CPA, and treating them alike is
// what lets a cleared override verify correctly.
func (c *probeClient) readProxyURL(ctx context.Context, name string) (string, bool, error) {
	path := probeRouteAuthDownload + "?name=" + url.QueryEscape(name)
	result, errCall := c.call(ctx, http.MethodGet, path, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return "", false, errCall
	}
	if result.status != http.StatusOK {
		return "", false, nil
	}
	var doc map[string]any
	if errUnmarshal := json.Unmarshal(result.body, &doc); errUnmarshal != nil {
		return "", false, nil
	}
	value, _ := doc[probeProxyField].(string)
	return strings.TrimSpace(value), true, nil
}

// setProxy points one credential at one exit, without checking that it took.
// Only setProxyVerified should call it.
func (c *probeClient) setProxy(ctx context.Context, entry *probeRestoreEntry, proxyURL string) error {
	payload := map[string]any{
		"name":          entry.Name,
		probeProxyField: proxyURL,
	}
	if probeHasAuthIndex(entry.AuthIndex) {
		payload["auth_index"] = entry.AuthIndex
	}
	result, errCall := c.call(ctx, http.MethodPatch, probeRouteAuthFields, c.mgmtKey, payload, probeMgmtTimeout)
	if errCall != nil {
		return errCall
	}
	if result.status != http.StatusOK {
		return probeExplainStatus(result, "PATCH "+probeRouteAuthFields)
	}
	return nil
}

// setProxyVerified points one credential at one exit and proves it took.
//
// Only ever the probed credential's own field. CPA's global proxy-url is never
// written from here: it carries Kimi, xAI and all daily traffic, and repointing
// that would move far more than one sweep.
//
// The read-back is the whole point of this function. A PATCH that answers 200
// and changes nothing is the failure that looks like success: every exit then
// appears to yield no template, while the real cause is that the exit never
// changed at all. That misdiagnosis costs a whole stop-the-world window, so an
// unconfirmed switch aborts the sweep rather than being counted as a failed
// candidate.
//
// Neither the wanted nor the observed value is ever rendered raw -- both go
// through maskProxyURL, because this error text reaches Lines.
func (c *probeClient) setProxyVerified(ctx context.Context, entry *probeRestoreEntry, proxyURL string) error {
	if errSet := c.setProxy(ctx, entry, proxyURL); errSet != nil {
		return fmt.Errorf("could not switch the exit for %s to %s: %w", entry.Name, probeShowProxy(proxyURL), errSet)
	}
	observed, readable, errRead := c.readProxyURL(ctx, entry.Name)
	if errRead != nil {
		return fmt.Errorf("the exit for %s was PATCHed to %s but the read-back failed: %w", entry.Name, probeShowProxy(proxyURL), errRead)
	}
	if !readable {
		return fmt.Errorf("the exit for %s was PATCHed to %s and CPA answered 200, but GET %s does not report %s back, so the switch cannot be confirmed; a sweep on an unconfirmed exit would only measure the credential's existing exit", entry.Name, probeShowProxy(proxyURL), probeRouteAuthDownload, probeProxyField)
	}
	if observed != strings.TrimSpace(proxyURL) {
		return fmt.Errorf("the exit for %s was PATCHed to %s and CPA answered 200, but it reads back as %s, so the write did not take", entry.Name, probeShowProxy(proxyURL), probeShowProxy(observed))
	}
	return nil
}

// setDisabled flips one credential's enable flag.
func (c *probeClient) setDisabled(ctx context.Context, name string, authIndex json.RawMessage, disabled bool) error {
	payload := map[string]any{"name": name, "disabled": disabled}
	if probeHasAuthIndex(authIndex) {
		payload["auth_index"] = authIndex
	}
	result, errCall := c.call(ctx, http.MethodPatch, probeRouteAuthStatus, c.mgmtKey, payload, probeMgmtTimeout)
	if errCall != nil {
		return errCall
	}
	if result.status != http.StatusOK {
		verb := "enable"
		if disabled {
			verb = "disable"
		}
		return probeExplainStatus(result, fmt.Sprintf("PATCH %s (%s %s)", probeRouteAuthStatus, verb, name))
	}
	return nil
}

// enableOnly makes one credential the sole enabled Codex candidate.
//
// This is mandatory, not a convenience. CPA's scheduler picks the credential
// itself and the wire protocol has no "use this auth" knob, so the only reliable
// way to attribute a harvested template to a known account is to make that
// account the only one that could have answered. Guessing instead would break
// the per-account bucketing this plugin exists to enforce.
//
// ==> While a sweep runs, every other Codex credential is DISABLED. Business
// traffic must already be stopped.
func (c *probeClient) enableOnly(ctx context.Context, auths []probeAuthFile, keep string) error {
	for _, auth := range auths {
		if errSet := c.setDisabled(ctx, auth.Name, auth.AuthIndex, auth.Name != keep); errSet != nil {
			return errSet
		}
	}
	return nil
}

// fire sends exactly one minimal request and reports what came back.
//
// The request carries NO X-Codex-Turn-State header, deliberately: sending a
// stale value makes the upstream reuse that turn instead of minting a fresh
// state, and a fresh state is the only thing this call exists to produce.
//
// A non-2xx is not a failure. The plugin harvests from the response headers, and
// those ride on error responses too; the authority on success is the bucket
// going live, which the caller checks.
func (c *probeClient) fire(ctx context.Context, model string) (int, string) {
	payload := map[string]any{
		"model":  model,
		"input":  "ping",
		"stream": false,
		// As small as the API allows. This call exists to mint a turn-state, not
		// to produce text, and quota is real money.
		"max_output_tokens": 16,
	}
	result, errCall := c.call(ctx, http.MethodPost, probeRouteResponses, c.apiKey, payload, probeFireTimeout)
	if errCall != nil {
		return 0, " (" + probeRedact(errCall.Error()) + ")"
	}
	if result.status >= 200 && result.status < 300 {
		return result.status, ""
	}

	// The upstream's own error code is the actionable part:
	// server_is_overloaded is the same signal as a degraded 312 (FINDINGS.md),
	// i.e. "no template is available right now, try the next exit" rather than
	// "something is broken".
	note := ""
	if upstream, okUpstream := upstreamErrorFrom(string(result.body)); okUpstream {
		note = " code=" + orDash(upstream.Error.Code) + " type=" + orDash(upstream.Error.Type)
	}
	// The body itself goes to the process log and never to Lines. It is the one
	// thing that identifies a wrong route or a wrong payload shape on a first
	// real run, which is why it is kept at all -- but it is upstream-controlled
	// text that may echo a URL back at us, and Lines is served without a key.
	log.Printf("%sprobe fire model=%s http=%d body=%s", logPrefix, model, result.status,
		probeTruncate(probeRedact(string(result.body)), 600))
	return result.status, note
}

// probeHasAuthIndex reports whether CPA gave us an auth_index worth echoing back.
func probeHasAuthIndex(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null" && trimmed != `""`
}

// --- redaction -----------------------------------------------------------

var (
	// Userinfo in any URL, which here means a proxy's credentials. Matched on the
	// scheme://...@ shape rather than against the configured list: a URL echoed
	// back inside an upstream error body has to be caught too, and that one is
	// never in any list we hold.
	probeURLAuthRE = regexp.MustCompile(`(?i)\b([a-z0-9+.\-]+://)[^/\s@]+@`)
	// A Fernet token base64url-encodes a leading 0x80 version byte, which always
	// renders as the literal prefix "gAAAAA" (FINDINGS.md). That makes a
	// turn-state greppable without decoding anything.
	probeTokenRE = regexp.MustCompile(`gAAAAA[A-Za-z0-9_\-=]{16,}`)
	// Any Bearer credential echoed back at us, ours included.
	probeBearerRE = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._\-]{16,}`)
)

// probeRedact strips anything credential-shaped out of text bound for Lines, the
// run error, or the process log. It mirrors redact() in scripts/probe.py.
func probeRedact(text string) string {
	text = probeTokenRE.ReplaceAllString(text, "<turn-state redacted>")
	text = probeBearerRE.ReplaceAllString(text, "${1}<redacted>")
	return probeURLAuthRE.ReplaceAllString(text, "${1}***@")
}

// probeShowProxy renders one exit safe to display, distinguishing "no exit set"
// from an exit that happens to mask to an empty string.
func probeShowProxy(raw string) string {
	if masked := maskProxyURL(raw); masked != "" {
		return masked
	}
	return "(none)"
}

// probeTruncate bounds a quoted body, saying how much was dropped so nobody
// reads a cut-off JSON document as a malformed one.
func probeTruncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + fmt.Sprintf(" ...[+%d chars]", len(text)-limit)
}
