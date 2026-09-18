// In-plugin offline harvester: collects X-Codex-Turn-State straight from the
// upstream, without routing through CPA or touching any CPA state.
//
// # Why direct, and why that is safe
//
// The earlier design harvested by driving CPA: it disabled every Codex account
// but one (so a harvest on CPA's own response hook could be attributed), PATCHed
// a proxy into the credential, POSTed to CPA's /v1/responses, and restored all
// of that afterwards. It cost a real incident when a run died mid-flip and left
// credentials disabled, and it could never run alongside business traffic.
//
// This harvester instead reads each account's own access_token out of its
// credential file (a read-only management call, never a write) and calls
// https://chatgpt.com/backend-api/codex/responses directly, as that account,
// through that account's own exit. CPA never sees the request. Because we hold
// the token, the harvest is attributed with certainty -- no sole-enablement, so
// every account stays enabled and every account × model can fire in parallel.
//
// Three rules make it safe to run against live credentials:
//   - It never writes anything to CPA. The only CPA calls are two GETs:
//     auth-files (the account list) and auth-files/download (one token).
//   - It never refreshes a token. An expired token is skipped and left for CPA
//     to refresh in its own business; refreshing here could rotate the refresh
//     token and break live traffic. (Access tokens were measured good for days,
//     so this costs almost nothing.)
//   - Substitution and harvest now coexist in one process: the business role
//     reads the store on the request hook while this goroutine fills it.
//
// # Renewal
//
// A harvested token lives ~3600s. The run does not stop after the first fill: it
// keeps a background loop that tops up any in-scope bucket once it drops under a
// few minutes of life left, so the store stays warm for as long as CPA serves
// traffic. That is the operator's "最后5分钟再获取一遍".
//
// # What must never leak out of this file
//
// probeRunState.Lines is rendered on a page that needs no key. No token,
// turn-state value, or proxy userinfo may reach it: proxies render through
// probeShowProxy/maskProxyURL, account names through probeShortAuth (they carry
// a customer email), and everything bound for Lines passes probeRedact as a
// second line of defence. The management key this file reads is never logged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The two read-only management routes this harvester uses. Named here rather
// than inline so a correction for a different CPA build is a one-line change.
// Nothing else is called on CPA -- there is deliberately no write route in this
// file any more.
const (
	probeRouteAuthFiles    = "/v0/management/auth-files"
	probeRouteAuthDownload = "/v0/management/auth-files/download"
)

// The upstream endpoint and the client identity a probe presents. Both are vars
// so a test can point them at an httptest server; production never writes them.
// probeUserAgent mirrors a real codex-tui build, and the call goes out as the
// same account CPA uses, from the same box -- so the upstream sees nothing it
// would not see from ordinary Codex traffic.
var (
	probeUpstreamURL = "https://chatgpt.com/backend-api/codex/responses"
	probeUserAgent   = "codex-tui/0.154.0 (Ubuntu 24.04; x86_64) OVH (codex-tui; 0.154.0)"
)

const (
	// probeMaxLines bounds the transcript. Keeping the last forty lines is enough
	// to say where a run is and why, and it means the run state cannot grow
	// without limit in a process meant to stay up for weeks.
	probeMaxLines = 40

	// probeFireTimeout bounds one upstream call. Only the response headers are
	// wanted and they arrive before the SSE body, so this is generous; it exists
	// to stop a hung exit pinning a goroutine.
	probeFireTimeout = 60 * time.Second
	probeMgmtTimeout = 30 * time.Second

	// probeMaxInFlight bounds how many upstream requests are open at once across
	// the whole run. Attribution no longer needs serialising -- each call carries
	// its own token -- so this is politeness, not correctness: a scope of four
	// accounts and several models should not open twenty sockets at once.
	probeMaxInFlight = 4

	// probeMaxBodyBytes caps what is read from a response. Only headers matter, so
	// this is just a small polite drain that lets a socket be reused without
	// pulling an SSE stream into the heap.
	probeMaxBodyBytes = 1 << 10
)

// Renewal cadence. Vars so tests can shrink them; production never writes them.
// A bucket is topped up once its 3600s token has under probeRenewThreshold of
// life left, checked every probeRenewInterval.
var (
	probeRenewInterval  = 60 * time.Second
	probeRenewThreshold = 5 * time.Minute

	// probeExitCooldown is the minimum gap between two upstream calls on the same
	// (exit, account, model) triple, and it is the whole answer to the defect this
	// replaced: a bucket that could not be filled was re-fired every tick forever.
	// Measured on 2026-09-18, that was 540 upstream calls an hour, every one of
	// them a 312, all against credentials that were already being throttled --
	// which is precisely the pattern a rate limiter punishes.
	//
	// 55 minutes rather than 60 on purpose. A harvested template lives ttl (3600s)
	// and the renewal loop refreshes it once it drops under probeRenewThreshold,
	// i.e. at T+55m. A 60-minute cooldown would block that refresh and let the card
	// lapse for five minutes on every cycle; 55 lines the two up exactly.
	probeExitCooldown = 55 * time.Minute
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
// a time: the run owns the renewal loop, and a second run would start a second
// loop harvesting the same buckets on the same credentials for no gain. The run
// no longer mutates any CPA state -- the harvest is a direct call to the
// upstream -- so a stop is a clean cancel with nothing to put back.
var probeRunner struct {
	mu     sync.Mutex
	run    probeRunState
	cancel context.CancelFunc
}

// probeTarget is one bucket the harvester intends to fill.
type probeTarget struct {
	account string
	model   string
}

// probeCredential is one account's usable state, read once from its credential
// file. It holds a secret (accessToken) and must never be logged.
type probeCredential struct {
	name        string
	accessToken string
	accountID   string
	proxyURL    string
	expiresAt   time.Time
}

// probeRunStart validates the run and launches it in the background. It returns
// nil once the goroutine is on its way, or an error explaining the refusal --
// and a refusal changes nothing at all.
func probeRunStart() error {
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	accounts := append([]string(nil), cfg.ProbeAccounts...)
	models := append([]string(nil), cfg.Models...)
	proxies := append([]string(nil), cfg.ProbeProxies...)

	switch {
	case len(accounts) == 0:
		// No fallback to "all of them": harvesting spends one upstream request per
		// bucket and per renewal, so "nothing selected means everything" is the one
		// mistake that quietly burns quota on credentials the operator did not pick.
		return fmt.Errorf("probe_accounts is empty, so there is nothing to probe; refusing to widen an empty selection to every credential")
	case len(models) == 0:
		return fmt.Errorf("models is empty, so there is no bucket to fill")
	case strings.TrimSpace(cfg.ProbeManagementKey) == "":
		return fmt.Errorf("probe_management_key is not set; it is the Bearer for GET %s and %s, the two read-only calls that fetch the account list and each credential's token", probeRouteAuthFiles, probeRouteAuthDownload)
	case strings.TrimSpace(cfg.StoreDir) == "":
		return fmt.Errorf("store_dir is empty, so a harvested template has nowhere to be written for the business role to read")
	}

	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if probeRunner.run.Running {
		return fmt.Errorf("a probe is already running; stop it before starting another")
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

// probeRunCancel asks the running probe to stop. It returns false when nothing
// was running. Cancellation ends the initial sweep and the renewal loop; there
// is no credential state to restore, because the offline harvest never changed
// any.
func probeRunCancel() bool {
	probeRunner.mu.Lock()
	defer probeRunner.mu.Unlock()
	if !probeRunner.run.Running || probeRunner.cancel == nil {
		return false
	}
	probeRunner.cancel()
	probeRunner.run.Lines = probeAppendLine(probeRunner.run.Lines, "stop requested; the probe will finish the current harvest and exit")
	return true
}

// probeRunSnapshot returns a copy of the run state, Lines included. The copy is
// what makes it safe to hand to a JSON encoder while the run keeps appending.
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
// any proxy URL already, with maskProxyURL, and any account name with
// probeShortAuth; this is the second line of defence, not the first, and it
// exists because Lines is served to a reader who has presented no key.
func probeRunLog(format string, args ...any) {
	line := probeRedact(fmt.Sprintf(format, args...))
	probeRunUpdate(func(run *probeRunState) {
		run.Lines = probeAppendLine(run.Lines, line)
	})
	log.Printf("%sprobe %s", logPrefix, line)
}

// probeRunFail records the reason a run stopped. The first error wins: what went
// wrong first is what the operator needs, and anything after it is a consequence.
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

// probeRunFinish marks the run over. It is the outermost defer in probeSweep and
// runs once the renewal loop has returned on cancel.
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

// probeSweep is the whole run: read credentials, fill every pending bucket once,
// then stay up renewing them. It is the only goroutine this file starts.
func probeSweep(ctx context.Context, cfg pluginConfig, accounts, models, proxies []string) {
	// Registered first, so it runs last: the run is not "finished" until the
	// renewal loop below has returned.
	defer probeRunFinish()
	// A panic in a native plugin takes the whole CPA process with it, so this
	// goroutine catches its own.
	defer func() {
		if recovered := recover(); recovered != nil {
			probeRunFail(fmt.Errorf("probe panicked: %v", recovered))
		}
	}()

	pool := newProbeClientPool()
	defer pool.closeIdle()
	client := newProbeClient(cfg)
	defer client.http.CloseIdleConnections()

	auths, errList := client.listCodexAuths(ctx)
	if errList != nil {
		probeRunFail(fmt.Errorf("could not list Codex credentials: %w", errList))
		return
	}
	// A selected account CPA does not know about would make the run quietly cover
	// less than was asked for, so it stops instead.
	known := make(map[string]bool, len(auths))
	for _, auth := range auths {
		known[auth.Name] = true
	}
	for _, account := range accounts {
		if !known[account] {
			probeRunFail(fmt.Errorf("selected account %q is not among CPA's Codex credentials; fix the selection rather than probing something CPA cannot serve", account))
			return
		}
	}

	now := time.Now()
	creds := probeDownloadCreds(ctx, client, accounts, now)
	if len(creds) == 0 {
		probeRunFail(fmt.Errorf("no usable credentials: every selected account's token was unreadable or already expired"))
		return
	}

	idxOf := probeAccountIndex(accounts)
	targets := probePendingTargets(cfg, accounts, models)
	probeRunUpdate(func(run *probeRunState) { run.Total = len(targets) })
	probeRunLog("offline harvest: %d account(s) x %d model(s) = %d bucket(s) to fill, %d exit(s) in pool", len(accounts), len(models), len(targets), len(proxies))
	if len(targets) > 0 {
		if cooling := probeFireBatch(ctx, cfg, pool, creds, targets, idxOf, proxies, true); cooling > 0 {
			// Said once per pass rather than per bucket per tick: the common case
			// after a recent sweep is that most buckets are still inside the
			// window, and an operator who just pressed the button needs to be told
			// why nothing happened.
			probeRunLog("%d bucket(s) skipped: every exit already tried within the %s cooldown", cooling, probeExitCooldown)
		}
	} else {
		probeRunLog("every selected bucket already holds a live template")
	}

	if ctx.Err() != nil {
		probeRunLog("stopped on request")
		return
	}

	// The run does not end here. Substitution needs live templates for as long as
	// CPA serves traffic, so the goroutine stays up and tops up each bucket a few
	// minutes before its token expires -- the operator's "最后5分钟再获取一遍". It
	// runs until the run is cancelled or the plugin reloads.
	probeRunLog("initial fill done; renewal active — buckets refresh automatically within %s of expiry", probeRenewThreshold)
	probeRunUpdate(func(run *probeRunState) { run.Current = "renewal active" })
	probeRenewLoop(ctx, pool)
}

// probeAccountIndex maps each selected account to its position, which is the
// index probeExits uses to assign the proxy pool in order.
func probeAccountIndex(accounts []string) map[string]int {
	idx := make(map[string]int, len(accounts))
	for i, name := range accounts {
		idx[name] = i
	}
	return idx
}

// probeFireBatch harvests a set of buckets concurrently, bounded by
// probeMaxInFlight. countDone advances the progress bar (the initial fill wants
// it; a renewal tick does not, having no fixed Total). It is the shared fan-out
// for both callers so the concurrency rule lives in one place.
func probeFireBatch(ctx context.Context, cfg pluginConfig, pool *probeClientPool, creds map[string]probeCredential, targets []probeTarget, idxOf map[string]int, proxies []string, countDone bool) int {
	var cooling atomic.Int64
	sem := make(chan struct{}, probeMaxInFlight)
	var wg sync.WaitGroup
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		cred, ok := creds[target.account]
		if !ok {
			// Its credential was unreadable or expired and already logged; count it
			// done so the progress bar reaches Total rather than hanging one short.
			if countDone {
				probeRunUpdate(func(run *probeRunState) { run.Done++ })
			}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target probeTarget, cred probeCredential) {
			defer wg.Done()
			defer func() { <-sem }()
			if !probeHarvestBucket(ctx, cfg, pool, cred, target.model, proxies, idxOf[target.account]) {
				cooling.Add(1)
			}
			if countDone {
				probeRunUpdate(func(run *probeRunState) { run.Done++ })
			}
		}(target, cred)
	}
	wg.Wait()
	return int(cooling.Load())
}

// probeHarvestBucket fills one bucket by walking the account's exit sequence:
// every exit that is out of cooldown gets one try, and the walk stops at the
// first 292. It is the one harvest path; the initial fill and the renewal loop
// both call it, and the claim guard keeps them off each other's buckets.
//
// It reports whether any upstream call was actually made. A bucket whose every
// exit is still inside probeExitCooldown returns false without a word, which is
// what keeps the renewal loop from narrating the same skip once a minute.
func probeHarvestBucket(ctx context.Context, cfg pluginConfig, pool *probeClientPool, cred probeCredential, model string, proxies []string, accountIdx int) bool {
	key := bucketKey(cred.name, model)
	if !probeClaim(key) {
		// Another fire (the other loop, or an overtaking renewal tick) is already
		// on this exact bucket. Firing a second upstream call for it would spend
		// quota to overwrite a value with a near-identical one.
		return false
	}
	defer probeRelease(key)

	short := probeShortAuth(cred.name)
	fired := false
	for _, exit := range probeExits(proxies, accountIdx) {
		if ctx.Err() != nil {
			return fired
		}
		now := time.Now()
		if !probeCooldownReady(exit, cred.name, model, now) {
			// Spent within the window. Silent on purpose: saying so would put one
			// line per bucket per tick into a forty-line transcript.
			continue
		}
		client, errClient := pool.get(exit)
		if errClient != nil {
			probeRunLog("%s %s: exit %s unusable, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errClient.Error()))
			continue
		}

		// Marked before the call rather than after: a request that times out, or
		// whose goroutine dies, still spent an attempt on this triple, and the
		// guarantee being kept is that the upstream sees at most one call per
		// triple per window.
		probeCooldownMark(exit, cred.name, model, now)
		fired = true

		status, value, errFire := probeFireUpstream(ctx, client, cred, model)
		if errFire != nil {
			// A transport failure means this exit did not carry the request at all;
			// the next one might.
			probeRunLog("%s %s: exit %s failed at transport, trying next: %s", short, model, probeShowProxy(exit), probeRedact(errFire.Error()))
			continue
		}
		if probeConsume(cfg, cred.name, short, model, status, value, exit) {
			return true
		}
		// Not stored -- a 312, or a rejection. That is THIS EXIT's IP being
		// throttled for this account and model, not the bucket being unfillable,
		// so the next exit is a different IP and gets its turn. This is the fix
		// for the defect where a 312 ended the attempt outright and the rest of
		// the pool was never dialed at all.
	}
	return fired
}

// probeConsume decides what one upstream response means. Only a 200 carrying a
// template-length turn-state is stored; a degraded length is the throttle this
// plugin exists to route around and is logged, not stored.
// It reports whether a template was stored, which is what tells the caller to
// stop walking the pool: anything else means this exit did not work out and the
// next one deserves a turn.
func probeConsume(cfg pluginConfig, name, short, model string, status int, value, exit string) bool {
	if status != http.StatusOK {
		probeRunLog("%s %s: http=%d via %s, no template (token rejected or upstream error)", short, model, status, probeShowProxy(exit))
		return false
	}
	switch {
	case len(value) == cfg.TemplateLength:
		if errStore := probeStore(cfg, name, model, value); errStore != nil {
			probeRunLog("%s %s: harvested len=%d but store failed: %s", short, model, len(value), probeRedact(errStore.Error()))
			return false
		}
		probeRunLog("%s %s: harvested len=%d via %s, fresh template stored", short, model, len(value), probeShowProxy(exit))
		return true
	case len(value) == cfg.ReplaceLength:
		probeRunLog("%s %s: degraded len=%d via %s (this exit's IP is throttled for this bucket), trying next exit", short, model, len(value), probeShowProxy(exit))
	case value == "":
		probeRunLog("%s %s: http=200 but no turn-state header via %s, nothing to harvest", short, model, probeShowProxy(exit))
	default:
		probeRunLog("%s %s: unexpected turn-state len=%d via %s, not stored", short, model, len(value), probeShowProxy(exit))
	}
	return false
}

// probeStore writes one harvested template to the same store the business role
// reads. AuthID is the credential file name because that is exactly what the
// request hook reads out of selected_auth_id and feeds to bucketKey -- storing
// under anything else would silently break every substitution. Attribution is
// "observed": we held the token, so the account is certain, not inferred.
func probeStore(cfg pluginConfig, name, model, value string) error {
	now := time.Now()
	issued, ok := fernetIssuedAt(value)
	if !ok {
		issued = now
	}
	record := storeRecord{
		AuthID:      name,
		Model:       model,
		Len:         len(value),
		Value:       value,
		IssuedAt:    issued.UTC().Format(time.RFC3339),
		HarvestedAt: now.UTC().Format(time.RFC3339),
		Attribution: attributionObserved,
	}
	if errWrite := writeStoreRecord(cfg.StoreDir, record, cfg.TemplateLength); errWrite != nil {
		return errWrite
	}
	if errIndex := writeStoreIndex(cfg.StoreDir, now, cfg.ttl(), cfg.TemplateLength); errIndex != nil {
		// The bucket file is on disk and is what the business role actually reads;
		// a stale index is a monitoring gap, not a lost harvest. Log and keep it.
		log.Printf("%sprobe index write failed: %v", logPrefix, errIndex)
	}
	state.mu.Lock()
	state.buckets[bucketKey(name, model)] = templateEntry{value: value, issuedAt: issued}
	state.mu.Unlock()
	return nil
}

// probeDownloadCreds reads each selected account's usable state once. An account
// whose token is unreadable or already expired is dropped, with a line saying
// which -- never a stack trace with a token in it.
func probeDownloadCreds(ctx context.Context, client *probeClient, accounts []string, now time.Time) map[string]probeCredential {
	creds := make(map[string]probeCredential, len(accounts))
	for _, name := range accounts {
		if ctx.Err() != nil {
			return creds
		}
		short := probeShortAuth(name)
		blob, errDownload := client.downloadAuth(ctx, name)
		if errDownload != nil {
			probeRunLog("%s: could not read credential: %s", short, probeRedact(errDownload.Error()))
			continue
		}
		cred, errParse := probeParseCredential(name, blob)
		if errParse != nil {
			probeRunLog("%s: credential unusable: %s", short, probeRedact(errParse.Error()))
			continue
		}
		// Never refresh. An expired access token is skipped and left for CPA to
		// refresh in the course of its own business; the next cycle reads the fresh
		// one. Refreshing here could rotate the refresh token and pull the
		// credential out from under live CPA traffic -- the one thing this whole
		// offline design exists to avoid.
		if !cred.expiresAt.IsZero() && !cred.expiresAt.After(now) {
			probeRunLog("%s: access token expired; skipping (not refreshed here — CPA refreshes it, next cycle harvests)", short)
			continue
		}
		creds[name] = cred
	}
	return creds
}

// probeRenewLoop keeps the store warm. Every probeRenewInterval it re-reads the
// live scope (so an edit on the dashboard takes effect without a restart), finds
// the in-scope buckets that are missing or under probeRenewThreshold of life,
// and re-harvests them. It returns on cancel.
func probeRenewLoop(ctx context.Context, pool *probeClientPool) {
	ticker := time.NewTicker(probeRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}

		state.mu.Lock()
		cfg := state.config
		state.mu.Unlock()
		accounts := append([]string(nil), cfg.ProbeAccounts...)
		models := append([]string(nil), cfg.Models...)
		proxies := append([]string(nil), cfg.ProbeProxies...)
		if len(accounts) == 0 || len(models) == 0 {
			probeRunUpdate(func(run *probeRunState) { run.Current = "scope is empty; nothing to keep fresh" })
			continue
		}

		now := time.Now()
		idxOf := probeAccountIndex(accounts)
		var due []probeTarget
		involved := make(map[string]bool)
		for _, account := range accounts {
			for _, model := range models {
				remaining, live := probeBucketRemaining(cfg, account, model, now)
				if live && remaining >= probeRenewThreshold {
					continue
				}
				// Wants a card -- but only queue it if some exit is actually
				// allowed to fire. Without this the loop would download
				// credentials and claim buckets once a minute only to find every
				// triple still cooling, which is the busy-work half of the defect
				// probeExitCooldown exists to end.
				if !probeBucketHasEligibleExit(proxies, idxOf[account], account, model, now) {
					continue
				}
				due = append(due, probeTarget{account: account, model: model})
				involved[account] = true
			}
		}
		if len(due) == 0 {
			probeRunUpdate(func(run *probeRunState) {
				run.Current = fmt.Sprintf("nothing due (fresh, or every exit cooling); next check in %s", probeRenewInterval)
			})
			continue
		}

		probeRunUpdate(func(run *probeRunState) {
			run.Current = fmt.Sprintf("renewing %d bucket(s) near expiry", len(due))
		})
		// Download only the accounts that actually have something due, in scope
		// order so the index still lines up with the proxy assignment.
		var accountList []string
		for _, account := range accounts {
			if involved[account] {
				accountList = append(accountList, account)
			}
		}
		client := newProbeClient(cfg)
		creds := probeDownloadCreds(ctx, client, accountList, now)
		probeFireBatch(ctx, cfg, pool, creds, due, idxOf, proxies, false)
		client.http.CloseIdleConnections()
	}
}

// probeBucketRemaining reports how long the live template for one bucket has
// left, and whether there is one at all. A missing bucket returns (0, false),
// which the renewal loop treats as "due now".
func probeBucketRemaining(cfg pluginConfig, account, model string, now time.Time) (time.Duration, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.refreshStoreLocked(cfg, now)
	tmpl, live := state.freshestTemplateLocked(account, model, now, cfg.ttl())
	if !live {
		return 0, false
	}
	return tmpl.issuedAt.Add(cfg.ttl()).Sub(now), true
}

// probePendingTargets lists the in-scope buckets that do not already hold a live
// template, so the initial fill only spends a request where there is nothing to
// substitute yet.
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

// probeBucketLive reports whether one bucket already holds a live template.
func probeBucketLive(cfg pluginConfig, target probeTarget) bool {
	now := time.Now()
	state.mu.Lock()
	defer state.mu.Unlock()
	state.refreshStoreLocked(cfg, now)
	_, live := state.freshestTemplateLocked(target.account, target.model, now, cfg.ttl())
	return live
}

// probeExits is the order one account tries the pool in: its assigned exit first
// (index i % N), then the rest in order, wrapping once. That satisfies both
// readings of "assign the pool in order" -- account i starts at exit i -- and
// gives every account a full fallback sequence if its first exit is down. An
// empty pool yields a single direct attempt (the empty string), which the client
// pool builds as a no-proxy transport.
func probeExits(proxies []string, accountIdx int) []string {
	if len(proxies) == 0 {
		return []string{""}
	}
	n := len(proxies)
	out := make([]string, 0, n)
	for k := 0; k < n; k++ {
		out = append(out, proxies[(accountIdx+k)%n])
	}
	return out
}

// probeActive prevents two harvests of the same bucket at once -- the initial
// fill and the renewal loop share one harvest path, and a slow upstream call
// could otherwise let a renewal tick fire a bucket a previous one is still on.
// The key is bucketKey, so the guard is per (account, model), never global: two
// different buckets still fire in parallel.
var probeActive = struct {
	mu  sync.Mutex
	set map[string]bool
}{set: map[string]bool{}}

func probeClaim(key string) bool {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	if probeActive.set[key] {
		return false
	}
	probeActive.set[key] = true
	return true
}

func probeRelease(key string) {
	probeActive.mu.Lock()
	defer probeActive.mu.Unlock()
	delete(probeActive.set, key)
}

// probeCooldown records when each (exit, account, model) triple last had an
// upstream call spent on it.
//
// The exit belongs in the key because a 312 is the IP being throttled for that
// account and model, not the bucket being unfillable -- which is the entire
// reason a pool of exits exists. So a 312 on one exit says nothing about the
// next one, and only when every exit has had its turn is the bucket genuinely
// out of options for this window.
//
// Keying on the exit URL has a second, useful property: correcting a typo in a
// proxy changes the string, so the fixed exit is a new triple with no cooldown
// and is retried at once instead of sitting out the window.
var probeCooldown = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

func probeCooldownKey(exit, account, model string) string {
	return exit + "\x00" + account + "\x00" + model
}

// probeCooldownReady reports whether this triple may be fired now. A triple that
// has never been fired is always ready, which is what makes a newly added exit
// eligible the moment it appears in the pool.
func probeCooldownReady(exit, account, model string, now time.Time) bool {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	last, seen := probeCooldown.last[probeCooldownKey(exit, account, model)]
	return !seen || now.Sub(last) >= probeExitCooldown
}

func probeCooldownMark(exit, account, model string, now time.Time) {
	probeCooldown.mu.Lock()
	defer probeCooldown.mu.Unlock()
	probeCooldown.last[probeCooldownKey(exit, account, model)] = now
}

// probeBucketHasEligibleExit reports whether any exit is allowed to fire for this
// bucket. The renewal loop checks this before queueing anything: without it, a
// scope whose every triple is cooling would still download credentials and claim
// buckets once a minute just to discover it may do nothing.
func probeBucketHasEligibleExit(proxies []string, accountIdx int, account, model string, now time.Time) bool {
	for _, exit := range probeExits(proxies, accountIdx) {
		if probeCooldownReady(exit, account, model, now) {
			return true
		}
	}
	return false
}

// probeSleep waits for the given duration and reports whether the run is still
// wanted. It returns false as soon as the run is cancelled.
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

// --- upstream ------------------------------------------------------------

// probeFireUpstream makes one direct call to the upstream as one account and
// returns the HTTP status and the turn-state header. It reads only the headers:
// the turn-state is there, and the SSE body is drained just enough to let the
// socket be reused before being dropped -- generating the completion would spend
// quota this probe has no use for. A transport error is returned as an error so
// the caller can fall through to the next exit; an HTTP status is not.
func probeFireUpstream(ctx context.Context, client *http.Client, cred probeCredential, model string) (int, string, error) {
	payload := map[string]any{
		"model":  model,
		"stream": true,
		"store":  false,
		"input": []map[string]any{{
			"type": "message",
			"role": "user",
			"content": []map[string]any{{
				"type": "input_text",
				"text": "ping",
			}},
		}},
		"reasoning":           map[string]any{"effort": "low"},
		"tool_choice":         "auto",
		"parallel_tool_calls": false,
	}
	raw, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return 0, "", errMarshal
	}

	callCtx, cancel := context.WithTimeout(ctx, probeFireTimeout)
	defer cancel()
	request, errNew := http.NewRequestWithContext(callCtx, http.MethodPost, probeUpstreamURL, bytes.NewReader(raw))
	if errNew != nil {
		return 0, "", errNew
	}
	request.Header.Set("Authorization", "Bearer "+cred.accessToken)
	if cred.accountID != "" {
		request.Header.Set("Chatgpt-Account-Id", cred.accountID)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Originator", "codex-tui")
	request.Header.Set("Session-Id", probeUUID())
	request.Header.Set("User-Agent", probeUserAgent)

	response, errDo := client.Do(request)
	if errDo != nil {
		return 0, "", errDo
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, probeMaxBodyBytes))
	return response.StatusCode, response.Header.Get(turnStateHeader), nil
}

// probeUUID returns a random v4 UUID for the Session-Id header, using the
// crypto/rand source already linked in. A failed read is near-impossible; the
// fallback keeps a probe firing rather than aborting on an unreachable branch.
func probeUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// --- credential parsing --------------------------------------------------

// probeParseCredential pulls the usable state out of a downloaded credential
// file: the access token, the account id (from the token's own claims, which is
// what the upstream expects in Chatgpt-Account-Id), the account's own exit, and
// the token's expiry. Nothing here is logged.
func probeParseCredential(name string, blob map[string]any) (probeCredential, error) {
	token := strings.TrimSpace(stringField(blob, "access_token"))
	if token == "" {
		return probeCredential{}, fmt.Errorf("no access_token in credential file")
	}
	claims := probeJWTClaims(token)
	cred := probeCredential{
		name:        name,
		accessToken: token,
		accountID:   probeAccountID(claims, blob),
		proxyURL:    strings.TrimSpace(stringField(blob, "proxy_url")),
	}
	if exp, ok := probeTokenExpiry(claims); ok {
		cred.expiresAt = exp
	}
	return cred, nil
}

// probeJWTClaims decodes a JWT's middle segment. The claims it reads -- exp and
// the account id -- are not secret; the token as a whole is, and is never logged.
func probeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	data, errDecode := base64.RawURLEncoding.DecodeString(parts[1])
	if errDecode != nil {
		return nil
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(data, &claims); errUnmarshal != nil {
		return nil
	}
	return claims
}

// probeAccountID reads the chatgpt_account_id the upstream expects. It prefers
// the token's own auth claim (authoritative) and falls back to the file's
// top-level account_id.
func probeAccountID(claims, blob map[string]any) string {
	if claims != nil {
		if auth, ok := claims["https://api.openai.com/auth"].(map[string]any); ok {
			if id, ok := auth["chatgpt_account_id"].(string); ok && strings.TrimSpace(id) != "" {
				return strings.TrimSpace(id)
			}
		}
	}
	return strings.TrimSpace(stringField(blob, "account_id"))
}

// probeTokenExpiry reads the token's exp claim. A token with no readable exp
// returns ok=false and is treated as usable -- the upstream is the real arbiter,
// and a 401 there is handled like any other non-200.
func probeTokenExpiry(claims map[string]any) (time.Time, bool) {
	if claims == nil {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0), true
}

// stringField reads a string value from a decoded JSON object, tolerating a
// missing or non-string field by returning "".
func stringField(blob map[string]any, key string) string {
	if value, ok := blob[key].(string); ok {
		return value
	}
	return ""
}

// probeShortAuth renders a credential file name without the customer email that
// sits inside it, for the keyless run transcript.
// codex-<hex>-<email>-<tier>.json becomes "<hex>…<tier>"; the hex and the tier
// are stable and identify the account without publishing whose it is.
//
// The email-bearing segment is dropped BEFORE the first/last pick, not after:
// a name whose email is the last segment (codex-<hex>-<email>.json) would
// otherwise publish the address. This mirrors maskAuthLabel in management.go,
// which the dashboard uses for the same reason; the two are kept in step by
// hand because that file was written concurrently.
func probeShortAuth(name string) string {
	trimmed := strings.TrimSuffix(name, ".json")
	trimmed = strings.TrimPrefix(trimmed, "codex-")
	if trimmed == "" {
		return name
	}
	kept := make([]string, 0, 4)
	for _, part := range strings.Split(trimmed, "-") {
		if !strings.Contains(part, "@") {
			kept = append(kept, part)
		}
	}
	switch len(kept) {
	case 0:
		// Nothing but an email: publish neither half.
		return "…"
	case 1:
		return kept[0]
	default:
		return kept[0] + "…" + kept[len(kept)-1]
	}
}

// --- CPA read client -----------------------------------------------------

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

// probeClient is the harvester's read-only connection to CPA's management API.
// It fetches the account list and each credential's token; it never writes.
type probeClient struct {
	baseURL string
	mgmtKey string
	http    *http.Client
}

func newProbeClient(cfg pluginConfig) *probeClient {
	// configure already fills an empty probe_base_url with defaultProbeBaseURL, so
	// this only catches a config built in-process -- a test, or a future caller
	// that skips configure. It reuses main.go's constant rather than repeating the
	// literal: two defaults that could drift apart is how a probe ends up talking
	// to the wrong port.
	base := strings.TrimRight(strings.TrimSpace(cfg.ProbeBaseURL), "/")
	if base == "" {
		base = defaultProbeBaseURL
	}
	return &probeClient{
		baseURL: base,
		mgmtKey: strings.TrimSpace(cfg.ProbeManagementKey),
		// Proxy is nil on purpose: this client talks to CPA's own loopback
		// listener, and honouring the box's http_proxy/all_proxy would send a
		// loopback call out through an exit that cannot reach it and come back as a
		// bogus 502. The per-exit clients for the upstream calls live in
		// probeClientPool, built the same way for the same reason.
		http: &http.Client{Transport: &http.Transport{Proxy: nil}},
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

	raw, errRead := io.ReadAll(io.LimitReader(response.Body, 64<<10))
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
// The filter is provider when CPA reports one, the naming convention otherwise.
// A .bak file is an operator's backup copy and must never be probed.
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

// downloadAuth fetches one credential file whole. It is the only call that ever
// carries a token back into this process, so its body is never logged; callers
// pull the fields they need through probeParseCredential and drop the rest.
func (c *probeClient) downloadAuth(ctx context.Context, name string) (map[string]any, error) {
	path := probeRouteAuthDownload + "?name=" + url.QueryEscape(name)
	result, errCall := c.call(ctx, http.MethodGet, path, c.mgmtKey, nil, probeMgmtTimeout)
	if errCall != nil {
		return nil, errCall
	}
	if result.status != http.StatusOK {
		return nil, probeExplainStatus(result, "GET "+probeRouteAuthDownload)
	}
	var blob map[string]any
	if errUnmarshal := json.Unmarshal(result.body, &blob); errUnmarshal != nil {
		return nil, fmt.Errorf("GET %s returned a body that is not a JSON object: %w", probeRouteAuthDownload, errUnmarshal)
	}
	return blob, nil
}

// --- per-exit upstream clients -------------------------------------------

// probeClientPool holds one http.Client per exit, built once and shared across
// every fire that uses that exit. A scope of four accounts sharing two exits
// opens two transports, not eight.
type probeClientPool struct {
	mu      sync.Mutex
	clients map[string]*http.Client
}

func newProbeClientPool() *probeClientPool {
	return &probeClientPool{clients: map[string]*http.Client{}}
}

// get returns the client for one exit, building it once. An empty proxyURL is a
// direct connection -- and deliberately does NOT honour the box's
// http_proxy/all_proxy env, for the same reason newProbeClient does not: those
// exits are for the traffic CPA relays, not for a probe reaching out on its own.
func (p *probeClientPool) get(proxyURL string) (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if client, ok := p.clients[proxyURL]; ok {
		return client, nil
	}
	transport := &http.Transport{Proxy: nil}
	if proxyURL != "" {
		parsed, errParse := url.Parse(proxyURL)
		if errParse != nil {
			return nil, fmt.Errorf("exit is not a valid URL: %w", errParse)
		}
		// net/http understands the "socks5" scheme but not the "socks5h" spelling,
		// and an unrecognised scheme is dialed as an HTTP proxy -- which a SOCKS
		// server answers with a protocol error, so the exit would look permanently
		// dead. The two differ only in where the target hostname is resolved, and
		// Go's socks5 dialer already hands the hostname to the proxy (what socks5h
		// asks for), so normalising is exact rather than approximate. The operator's
		// pool contains both spellings.
		if strings.EqualFold(parsed.Scheme, "socks5h") {
			parsed.Scheme = "socks5"
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	client := &http.Client{Transport: transport}
	p.clients[proxyURL] = client
	return client, nil
}

func (p *probeClientPool) closeIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		client.CloseIdleConnections()
	}
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
// run error, or the process log.
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
	return "(direct)"
}

// probeTruncate bounds a quoted body, saying how much was dropped so nobody
// reads a cut-off JSON document as a malformed one.
func probeTruncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + fmt.Sprintf(" ...[+%d chars]", len(text)-limit)
}
