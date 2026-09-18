// Package main implements a CLIProxyAPI native plugin that reuses official
// Codex X-Codex-Turn-State values within a single (account, model) bucket.
//
// The plugin has two roles, and one process is only ever one of them:
//
//   - role: probe    harvests the official template from upstream responses and
//     writes it to the on-disk store. It never rewrites a
//     request, because sending a recycled state upstream would
//     stop a fresh one from being minted, which is exactly what
//     the probe is there to collect.
//   - role: business reads that store and, on a request already carrying a
//     degraded replace_length state for the same bucket, swaps
//     in the stored template. It never writes the store and
//     never harvests from live traffic.
//
// Rules enforced here, per the agreed spec:
//  1. state is never shared across accounts
//  2. state is never shared across models
//  3. reuse within one bucket is allowed regardless of client IP
//  4. a template expires after ttl_seconds (default 3600), measured from the
//     token's own embedded Fernet timestamp rather than from when it was seen
//
// The plugin only ever touches the X-Codex-Turn-State header. It never
// fabricates a value: substitution uses a value previously observed on a
// genuine upstream response belonging to the same bucket.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

// cliproxy_invoke_host calls back into the host. The host owns the response
// buffer, so every non-NULL ptr it hands back must go to cliproxy_release_host.
static int cliproxy_invoke_host(const cliproxy_host_api* host, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (host == NULL || host->call == NULL) {
		return 1;
	}
	return host->call(host->host_ctx, method, request, request_len, response);
}

static void cliproxy_release_host(const cliproxy_host_api* host, void* ptr, size_t len) {
	if (host == NULL || host->free_buffer == NULL || ptr == NULL) {
		return;
	}
	host->free_buffer(ptr, len);
}

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// turnStateHeader is the only header this plugin reads or writes.
const turnStateHeader = "X-Codex-Turn-State"

// selectedAuthMetadataKey mirrors cliproxyexecutor.SelectedAuthMetadataKey.
// It is inlined so the plugin does not depend on the executor package.
const selectedAuthMetadataKey = "selected_auth_id"

const logPrefix = "[codex-turn-state] "

// The two roles. A process is one of them for the whole of a config generation;
// switching is done by editing config.yaml and letting the host reconfigure.
const (
	roleProbe    = "probe"
	roleBusiness = "business"
)

// indexFileName is the store's summary file. It carries no template values, so
// it is safe to read for monitoring, and its mtime is what the business role
// watches to decide when to re-scan.
const indexFileName = "index.json"

// storeIndexVersion tags the on-disk index format.
const storeIndexVersion = 1

var state = pluginState{
	config:   defaultConfig(),
	buckets:  make(map[string]templateEntry),
	countsAt: time.Now(),
}

// hostAPI is the *C.cliproxy_host_api the host passes to cliproxy_plugin_init,
// kept so the management handlers can call back into the host. It is written
// once during init and read from handler goroutines, hence the atomic.
var hostAPI unsafe.Pointer

// hostAPIAvailable reports whether the host handed over a callback table. It is
// worth asking separately from just letting hostCall fail: "the plugin cannot
// make any outbound call" and "the upstream did not answer" are different
// findings, and a diagnostic that reported the first as the second would send
// the operator looking at the network when the problem is the load.
func hostAPIAvailable() bool {
	return atomic.LoadPointer(&hostAPI) != nil
}

// hostCall invokes a host callback and returns its raw RPC envelope. A nil host
// API means the plugin was loaded by something that never handed one over, which
// is a configuration problem rather than a request failure -- the management
// routes that need it say so rather than pretending the call returned nothing.
func hostCall(method string, request []byte) ([]byte, error) {
	raw := atomic.LoadPointer(&hostAPI)
	if raw == nil {
		return nil, fmt.Errorf("host API unavailable: this plugin was initialised without one")
	}
	host := (*C.cliproxy_host_api)(raw)

	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var requestPtr *C.uint8_t
	if len(request) > 0 {
		requestPtr = (*C.uint8_t)(unsafe.Pointer(&request[0]))
	}

	var response C.cliproxy_buffer
	rc := C.cliproxy_invoke_host(host, cMethod, requestPtr, C.size_t(len(request)), &response)
	// request is Go memory handed to C for the duration of the call; the host
	// copies it out before returning, but it must not be collected mid-call.
	runtime.KeepAlive(request)

	if response.ptr != nil {
		defer C.cliproxy_release_host(host, response.ptr, response.len)
	}
	if rc != 0 {
		return nil, fmt.Errorf("host call %s failed with code %d", method, int(rc))
	}
	if response.ptr == nil || response.len == 0 {
		return nil, nil
	}
	return C.GoBytes(response.ptr, C.int(response.len)), nil
}

// decisionCounters tallies what the plugin did, for the management status page.
// Lengths and outcomes only -- never a value.
type decisionCounters struct {
	Harvest    int64 `json:"harvest"`
	Substitute int64 `json:"substitute"`
	Inject     int64 `json:"inject"`
	Pass       int64 `json:"pass"`
	Skip       int64 `json:"skip"`
}

type pluginState struct {
	mu     sync.Mutex
	config pluginConfig
	// buckets is in-process memory. Under role: probe it memoises what was last
	// written to disk, so a repeated identical template does not rewrite the
	// store on every turn. Under role: business it stays empty unless the
	// (currently unreachable) in-band fallback is enabled.
	buckets map[string]templateEntry
	// store is the view of the on-disk store the business role reads. The probe
	// writes the store; the business role only ever reads it. It is re-scanned
	// when index.json changes, throttled to once per second.
	store        map[string]templateEntry
	storeMod     time.Time
	storeChecked time.Time
	// counts and countsAt back the management status page. They are reset when a
	// role change invalidates what the tallies describe.
	counts   decisionCounters
	countsAt time.Time
}

// templateEntry is one harvested template, scoped to a single bucket.
type templateEntry struct {
	value string
	// issuedAt is the token's own issuance time, decoded from the embedded
	// Fernet timestamp, or the harvest time when the value is not a decodable
	// Fernet token. Expiry is keyed on this rather than on when the proxy
	// observed the value: the upstream enforces a server-side validity window
	// from the token's timestamp, so a template harvested late in its life must
	// not be treated as fresh for a further full ttl.
	issuedAt time.Time
}

// templateUsable is the single expiry rule, and every check in this file goes
// through it so the three of them cannot drift apart.
//
// It rejects a future issuedAt outright, which is the non-obvious half. Written
// the natural way -- now.Sub(issuedAt) > ttl, or now.Before(issuedAt.Add(ttl))
// -- a timestamp in the future yields a negative age, or an even later expiry,
// and every such test reads it as "brand new". A clock skew between CPA and the
// upstream, or a hand-edited store file, would then feed a template that cannot
// possibly be valid into live requests: the upstream answers "Encrypted content
// could not be decrypted" while the decision log shows a clean substitute, and
// nothing on our side looks wrong.
//
// No tolerance is allowed. The Fernet timestamp is the upstream's own signing
// moment, so it necessarily precedes the moment we observe the token; a value
// in the future means the clock or the file is wrong, and neither is worth
// trusting for the sake of absorbing drift.
func templateUsable(issuedAt, now time.Time, ttl time.Duration) bool {
	if issuedAt.After(now) {
		return false
	}
	return now.Before(issuedAt.Add(ttl))
}

type pluginConfig struct {
	// Role is "probe" or "business". Empty means "business": that is the role
	// that neither writes the store nor harvests, so a plugin deployed before
	// its config is updated does nothing rather than something surprising.
	Role string `yaml:"role"`
	// StoreDir is the directory holding the template store, laid out as
	// <store_dir>/<auth_id>/<model>.json plus a value-free index.json.
	StoreDir string `yaml:"store_dir"`
	// TemplateLength is the value length treated as a reusable template.
	TemplateLength int `yaml:"template_length"`
	// ReplaceLength is the value length that gets overwritten by a template.
	ReplaceLength int `yaml:"replace_length"`
	// TTLSeconds bounds how long a harvested template stays usable.
	TTLSeconds int `yaml:"ttl_seconds"`
	// HarvestInband lets a non-business role also store a template value seen on
	// a request. It is forced off for role: business, where harvesting from live
	// traffic is prohibited outright -- that is the probe's job.
	HarvestInband bool `yaml:"harvest_inband"`
	// HarvestInBandLegacy accepts the older harvest_in_band spelling so an
	// existing config does not silently change meaning. harvest_inband wins when
	// both appear.
	HarvestInBandLegacy *bool `yaml:"harvest_in_band"`
	// InjectMode selects what the plugin does when it holds a live template for
	// a bucket. "replace-only" (default) restricts rewriting to requests that
	// already carry a replace_length value. "always" makes every outgoing
	// request carry the live template, adding it when absent and replacing
	// anything else -- including on requests that arrived with no state at all,
	// which the spec prohibits, so it is never the default.
	InjectMode string `yaml:"inject_mode"`
	// DryRun logs decisions without rewriting the outgoing header.
	DryRun bool `yaml:"dry_run"`
	// LogDecisions emits one line per harvest/substitute decision.
	LogDecisions bool `yaml:"log_decisions"`
	// Models is the list of official model ids the probe is expected to fill.
	// The plugin does not gate on it; it is carried here so the running config
	// and the probe script cannot drift apart unnoticed.
	Models []string `yaml:"models"`
}

func defaultConfig() pluginConfig {
	return pluginConfig{
		Role:           "",
		StoreDir:       "",
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
		HarvestInband:  false,
		InjectMode:     "replace-only",
		DryRun:         false,
		LogDecisions:   true,
	}
}

// injectAlways reports whether a held template should be forced onto every
// request for its bucket. Any value other than "replace-only" means yes, which
// is only safe because configure rejects every value it does not recognise: a
// typo must not reach this function and quietly become the forcing mode.
func (c pluginConfig) injectAlways() bool {
	return !strings.EqualFold(strings.TrimSpace(c.InjectMode), "replace-only")
}

// isProbe reports whether this process is the harvesting half.
func (c pluginConfig) isProbe() bool {
	return strings.EqualFold(strings.TrimSpace(c.Role), roleProbe)
}

// ttl is the configured template lifetime as a duration.
func (c pluginConfig) ttl() time.Duration {
	return time.Duration(c.TTLSeconds) * time.Second
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type registerRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

// registrationCapability mirrors the host's rpcCapabilities JSON. Note that the
// stream chunk interceptor is advertised as "response_stream_interceptor", not
// the name of its Go interface -- getting that wrong is a silent no-op.
type registrationCapability struct {
	RequestInterceptor        bool `json:"request_interceptor"`
	ResponseInterceptor       bool `json:"response_interceptor"`
	StreamChunkInterceptor    bool `json:"response_stream_interceptor"`
	WebSocketResponseObserver bool `json:"websocket_response_observer"`
	ManagementAPI             bool `json:"management_api"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	// The host API is how the management handlers reach host.auth.list and
	// host.model.execute. It is handed over exactly once, before any other call,
	// and the host owns the allocation for the plugin's lifetime.
	if host != nil {
		atomic.StorePointer(&hostAPI, unsafe.Pointer(host))
	}
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.buckets = make(map[string]templateEntry)
	state.store = nil
	state.storeMod = time.Time{}
	state.storeChecked = time.Time{}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodRequestInterceptBefore:
		// Auth is not selected yet, so no bucket can be derived. Never touch
		// the header here.
		return okEnvelope(pluginapi.RequestInterceptResponse{})
	case pluginabi.MethodRequestInterceptAfter:
		return interceptAfterAuth(request)
	case pluginabi.MethodResponseInterceptAfter:
		return interceptResponse(request)
	case pluginabi.MethodResponseInterceptStreamChunk:
		return interceptStreamChunk(request)
	case pluginabi.MethodWebSocketResponseEvent:
		return observeWebSocketEvent(request)
	case pluginabi.MethodManagementRegister:
		return managementRegister(request)
	case pluginabi.MethodManagementHandle:
		return managementHandle(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func configure(raw []byte) error {
	var req registerRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	if req.SchemaVersion < 2 {
		return fmt.Errorf("codex-turn-state requires host schema version 2 or newer")
	}
	cfg := defaultConfig()
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
		// The alias is resolved by presence, not by value: harvest_inband: false
		// alongside harvest_in_band: true must stay false, and a plain bool
		// cannot tell "absent" from "false".
		var probeKeys struct {
			HarvestInband *bool `yaml:"harvest_inband"`
		}
		if errProbe := yaml.Unmarshal(req.ConfigYAML, &probeKeys); errProbe == nil {
			if probeKeys.HarvestInband == nil && cfg.HarvestInBandLegacy != nil {
				cfg.HarvestInband = *cfg.HarvestInBandLegacy
			}
		}
	}

	// An empty role means business: the half that neither writes nor harvests.
	// The deploy order installs the .so before config.yaml gains a role, and a
	// plugin that refuses to register in that window would look like a broken
	// build rather than an unfinished deploy.
	role := strings.ToLower(strings.TrimSpace(cfg.Role))
	switch role {
	case "":
		role = roleBusiness
	case roleProbe, roleBusiness:
	default:
		return fmt.Errorf("role must be %q or %q, got %q", roleProbe, roleBusiness, cfg.Role)
	}
	cfg.Role = role
	cfg.StoreDir = strings.TrimSpace(cfg.StoreDir)

	if cfg.TemplateLength < 1 {
		return fmt.Errorf("template_length must be greater than zero")
	}
	if cfg.ReplaceLength < 1 {
		return fmt.Errorf("replace_length must be greater than zero")
	}
	if cfg.TemplateLength == cfg.ReplaceLength {
		return fmt.Errorf("template_length and replace_length must differ, both are %d", cfg.TemplateLength)
	}
	if cfg.TTLSeconds < 1 {
		return fmt.Errorf("ttl_seconds must be greater than zero")
	}
	// injectAlways treats anything that is not "replace-only" as "always", so a
	// typo -- replace_only, replaceonly, replace-onlye -- would degrade silently
	// into forcing a template onto requests that carry no state at all. That is
	// the one behaviour the spec prohibits outright, so an unrecognised value
	// has to fail loudly here rather than become the most dangerous mode.
	switch mode := strings.TrimSpace(cfg.InjectMode); {
	case mode == "":
		// An explicitly empty value would fall through injectAlways as "always"
		// too. Pin it to the safe default instead of letting blank mean forcing.
		cfg.InjectMode = "replace-only"
	case strings.EqualFold(mode, "replace-only"), strings.EqualFold(mode, "always"):
		cfg.InjectMode = mode
	default:
		return fmt.Errorf("inject_mode must be %q or %q, got %q", "replace-only", "always", cfg.InjectMode)
	}
	// A probe with nowhere to write is a probe that silently collects nothing,
	// which is worse than failing loudly at configure time.
	if cfg.isProbe() && cfg.StoreDir == "" {
		return fmt.Errorf("role %q requires store_dir", roleProbe)
	}

	// Harvesting from business traffic is prohibited: the business half must not
	// gamble on a template turning up in live traffic. Forcing the flag off (and
	// saying so) keeps a mistaken config running safely instead of refusing to
	// start a production path.
	forcedInband := false
	if cfg.Role == roleBusiness && cfg.HarvestInband {
		cfg.HarvestInband = false
		forcedInband = true
	}

	state.mu.Lock()
	// The host reconfigures far more often than the config actually changes:
	// five times during startup alone, and again every time CPA rewrites
	// config.yaml on its own. Clearing unconditionally would drop every
	// template at unpredictable moments and leave the cache permanently
	// empty, so only a change that invalidates templates clears them.
	cleared := templatesInvalidatedBy(state.config, cfg)
	roleChanged := !strings.EqualFold(state.config.Role, cfg.Role)
	state.config = cfg
	if cleared {
		state.buckets = make(map[string]templateEntry)
		state.store = nil
		state.storeMod = time.Time{}
		state.storeChecked = time.Time{}
	}
	// Tallies describe one role's behaviour. Carrying a probe's harvest count
	// into a business generation would make the status page read as though the
	// business role had been harvesting, which is the one thing it must not do.
	if roleChanged {
		state.counts = decisionCounters{}
		state.countsAt = time.Now()
	}
	state.mu.Unlock()

	if forcedInband {
		log.Printf(logPrefix + "config error: harvest_inband is not allowed for role=business, forced to false")
	}
	templates := "templates kept"
	if cleared {
		templates = "templates cleared"
	}
	log.Printf(logPrefix+"configured role=%s store_dir=%q template_length=%d replace_length=%d ttl_seconds=%d dry_run=%t inject_mode=%s harvest_inband=%t models=%d (%s)",
		cfg.Role, cfg.StoreDir, cfg.TemplateLength, cfg.ReplaceLength, cfg.TTLSeconds, cfg.DryRun, cfg.InjectMode, cfg.HarvestInband, len(cfg.Models), templates)
	return nil
}

// templatesInvalidatedBy reports whether moving from oldCfg to newCfg makes
// already-held templates unusable. A template must never outlive the rules it
// was harvested under, so the two lengths and the TTL force a clear. A role or
// store_dir change forces one too: the memory belongs to the old role's view of
// the old store, and carrying it across would blur exactly the boundary the two
// roles exist to keep. dry_run and log_decisions change what the plugin does
// with a template, not whether the template is still a valid one.
func templatesInvalidatedBy(oldCfg, newCfg pluginConfig) bool {
	return oldCfg.TemplateLength != newCfg.TemplateLength ||
		oldCfg.ReplaceLength != newCfg.ReplaceLength ||
		oldCfg.TTLSeconds != newCfg.TTLSeconds ||
		oldCfg.Role != newCfg.Role ||
		oldCfg.StoreDir != newCfg.StoreDir
}

func pluginRegistration() registration {
	state.mu.Lock()
	probe := state.config.isProbe()
	state.mu.Unlock()

	// The probe advertises the response-side hooks and still advertises the
	// request hook, where it deliberately does nothing: declaring it keeps the
	// two roles on one code path and makes "probe rewrote a request" a thing the
	// logs can rule out rather than a thing the host never offered.
	// The management routes are declared in both roles: the status page is how an
	// operator checks a role switch actually took, so it must survive the switch.
	capabilities := registrationCapability{RequestInterceptor: true, ManagementAPI: true}
	if probe {
		capabilities.ResponseInterceptor = true
		capabilities.StreamChunkInterceptor = true
		capabilities.WebSocketResponseObserver = true
	}

	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "codex-turn-state",
			Version:          "0.1.0",
			Author:           "arden-aaai",
			GitHubRepository: "https://github.com/arden-aaai/cpa-plugin-codex-turn-state",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "role",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{roleProbe, roleBusiness},
					Description: "\"probe\" harvests templates from upstream responses into store_dir; \"business\" only reads the store and substitutes. Empty means business.",
				},
				{
					Name:        "store_dir",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Directory holding the template store, laid out as <store_dir>/<auth_id>/<model>.json plus a value-free index.json. Required for role=probe.",
				},
				{
					Name:        "template_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Value length harvested as a reusable template (default 292).",
				},
				{
					Name:        "replace_length",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "Value length replaced by a template from the same bucket (default 312).",
				},
				{
					Name:        "ttl_seconds",
					Type:        pluginapi.ConfigFieldTypeInteger,
					Description: "How long a template stays usable, measured from its own Fernet timestamp (default 3600).",
				},
				{
					Name:        "harvest_inband",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Off by default and forced off for role=business. Harvesting from live business traffic is prohibited; that is the probe's job.",
				},
				{
					Name:        "inject_mode",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{"replace-only", "always"},
					Description: "\"replace-only\" (default) rewrites only a replace_length value. \"always\" forces the live template onto every request, including ones that carried no state at all. Any other value is rejected at startup rather than silently treated as \"always\".",
				},
				{
					Name:        "dry_run",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Log decisions without rewriting the outgoing header.",
				},
				{
					Name:        "log_decisions",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Emit one log line per harvest or substitution.",
				},
				{
					Name:        "models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Official model ids the probe is expected to fill. Recorded so the running config and the probe script cannot drift apart.",
				},
			},
		},
		Capabilities: capabilities,
	}
}

// interceptAfterAuth runs once the scheduler has picked a credential, so both
// halves of the bucket key are known.
func interceptAfterAuth(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	// The probe must leave requests exactly as it found them. Substituting a
	// stored template here would hand the upstream a state it has already
	// issued, and the fresh 292 the probe exists to collect would never be
	// minted.
	if cfg.isProbe() {
		return noop()
	}

	authID := metadataString(req.Metadata, selectedAuthMetadataKey)
	model := pickModel(req.Model, req.RequestedModel)
	value := headerValue(req.Headers, turnStateHeader)
	attribution := attributionObserved

	// The same metadata gap the collection side has, mirrored here. A minimal
	// request carries no metadata, so selected_auth_id is absent
	// (publishSelectedAuthMetadata early-returns on an empty map,
	// conductor_execution.go:1726). Real Codex traffic sends session metadata and
	// never enters this branch, but a metadata-less request under a single-account
	// deployment would otherwise never be substituted -- a real defect, and it
	// also blocks a minimal-request substitution demo.
	//
	// Inferred under the same invariant harvesting uses: exactly one enabled Codex
	// account (spec §7). With two enabled, a guess would inject one account's 292
	// into another's request -- rule 1 -- so anything but a clean sole account
	// leaves authID empty and the request untouched. The inferred account is used
	// only for the bucket-key lookup; every substitution rule below (replace-only,
	// dry_run, TTL, length) is unchanged.
	//
	// Gated on a present value for two reasons: an empty request has nothing to
	// replace in replace-only mode, so a host lookup would be wasted; and it means
	// that even in always mode this fallback can never supply the account that
	// would inject a template onto a headerless request, which spec §0 forbids.
	if authID == "" && model != "" && value != "" {
		if sole, _, errSole := soleEnabledCodexAuth(); errSole == nil && sole != "" {
			authID = sole
			attribution = attributionInferred
		}
	}

	if authID == "" || model == "" {
		// Without a full key the request cannot be attributed to a bucket, and
		// guessing would break rules 1 and 2. Leave the request untouched.
		if value != "" {
			logDecision("skip", authID, model, len(value), "incomplete bucket key")
		}
		return noop()
	}

	now := time.Now()
	state.mu.Lock()
	ttl := cfg.ttl()

	// In-band harvest, kept behind the flag that role: business forces off. It
	// is unreachable as configured today and deliberately so: it exists only as
	// a single-box fallback for a deployment with no probe at all.
	harvestedOK := false
	if cfg.HarvestInband && len(value) == cfg.TemplateLength {
		state.sweepLocked(now)
		issued, ok := fernetIssuedAt(value)
		if !ok {
			issued = now
		}
		if templateUsable(issued, now, ttl) {
			state.buckets[bucketKey(authID, model)] = templateEntry{value: value, issuedAt: issued}
			harvestedOK = true
		}
	}

	// The probe writes the store; the business role only reads it.
	state.refreshStoreLocked(cfg, now)
	tmpl, haveTmpl := state.freshestTemplateLocked(authID, model, now, ttl)
	state.mu.Unlock()

	decision, reason, replacement := decideHeader(cfg, value, tmpl, haveTmpl, harvestedOK, now)
	// Mark an inferred attribution in the log the same way the harvest side does:
	// "substituted account X's template" and "substituted the sole enabled
	// account's template" are different claims, and a wrong inference here is a
	// cross-account leak, so which one was made must be auditable after the fact.
	if attribution == attributionInferred {
		reason += " (inferred: sole enabled account)"
	}
	logDecision(decision, authID, model, len(value), reason)

	if replacement == "" || cfg.DryRun {
		return noop()
	}
	// Return only the one header. The host preserves every header not named
	// here, so this cannot disturb the rest of the request.
	//
	// ClearHeaders is applied before Headers and sweeps case-insensitively,
	// while the Headers merge is a canonicalizing Del+Add. Clearing first is
	// what guarantees a replacement rather than a second copy alongside a
	// non-canonically spelled original.
	return okEnvelope(pluginapi.RequestInterceptResponse{
		ClearHeaders: []string{turnStateHeader},
		Headers:      http.Header{turnStateHeader: []string{replacement}},
	})
}

// interceptResponse is the probe's harvest point for non-streaming responses.
// It never modifies the response: an empty ResponseInterceptResponse leaves
// every header and the body exactly as the upstream sent them.
func interceptResponse(raw []byte) ([]byte, error) {
	var req pluginapi.ResponseInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cfg.isProbe() {
		harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel))
	}
	return okEnvelope(pluginapi.ResponseInterceptResponse{})
}

// interceptStreamChunk is the probe's harvest point for SSE responses. Response
// headers are only populated on the header-init call, so every payload chunk is
// returned untouched without even looking at it.
func interceptStreamChunk(raw []byte) ([]byte, error) {
	var req pluginapi.StreamChunkInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	if req.ChunkIndex != pluginapi.StreamChunkHeaderInitIndex {
		return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
	}
	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	if cfg.isProbe() {
		harvestFromResponse(cfg, req.ResponseHeaders, req.Metadata, pickModel(req.Model, req.RequestedModel))
	}
	return okEnvelope(pluginapi.StreamChunkInterceptResponse{})
}

// observeWebSocketEvent is diagnostic only. pluginapi.WebSocketResponseEvent
// carries an event type and a payload but no response headers, so this hook
// cannot harvest X-Codex-Turn-State however much we would like it to. If these
// lines ever appear, Codex traffic is taking a path the probe does not cover
// and the harvest design needs revisiting -- which is worth knowing, and is the
// only reason the observer is registered at all.
func observeWebSocketEvent(raw []byte) ([]byte, error) {
	var event pluginapi.WebSocketResponseEvent
	if errUnmarshal := json.Unmarshal(raw, &event); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	authID := strings.TrimSpace(event.AuthID)
	if authID == "" {
		authID = metadataString(event.Metadata, selectedAuthMetadataKey)
	}
	log.Printf(logPrefix+"websocket response event auth=%s model=%s event=%s (no response headers on this hook, nothing harvested)",
		orDash(authID), orDash(pickModel(event.Model, event.RequestedModel)), orDash(event.EventType))
	return okEnvelope(struct{}{})
}

// harvestFromResponse is the one place a template enters the store. Everything
// it rejects, it rejects loudly enough to show up in the decision log, because
// "the probe ran and the bucket stayed empty" is the failure mode that costs a
// whole probing window.
func harvestFromResponse(cfg pluginConfig, headers http.Header, metadata map[string]any, model string) {
	value := headerValue(headers, turnStateHeader)
	if value == "" {
		return
	}
	authID := metadataString(metadata, selectedAuthMetadataKey)
	attribution := attributionObserved

	// The host only publishes selected_auth_id when the request carried some
	// metadata of its own: publishSelectedAuthMetadata returns early on an empty
	// map (sdk/cliproxy/auth/conductor_execution.go:1726). A real Codex client
	// sends session metadata so the name is there, but the probe's minimal
	// request does not, and the account name is simply absent. Relating it back
	// through the request hook does not help either -- the response interceptor
	// is handed the same opts.Metadata (handlers_interceptors.go:590).
	//
	// So fall back to the invariant the spec already imposes: probing enables
	// exactly one Codex account at a time (spec §7 step 2), which makes the
	// account a property of the setup rather than something to read off the
	// request. Every condition is load bearing -- with two accounts enabled this
	// would be a coin toss between them, and a wrong guess feeds one account's
	// token to another.
	//
	// Inference runs for any recognised length, 292 or 312, not only the template
	// length. A 312 is never stored, but attributing it lets the degraded-state
	// log below name the throttled account instead of printing auth=-, which is
	// the difference between "this account is throttled" and "attribution broke".
	//
	// The role check is belt-and-braces: response hooks are only registered for
	// the probe and in-band harvest is forced off for business, so this path is
	// already unreachable there. It is written out anyway so the rule reads
	// completely here instead of resting on a registration elsewhere.
	recognisedLen := len(value) == cfg.TemplateLength || len(value) == cfg.ReplaceLength
	if authID == "" && model != "" && recognisedLen && cfg.isProbe() {
		sole, enabledCount, errSole := soleEnabledCodexAuth()
		switch {
		case errSole != nil:
			// A 292 we cannot attribute is genuinely unharvestable, so it stops
			// here. A 312 falls through to the degraded-state log, still worth
			// emitting with auth=- so the throttling is visible.
			if len(value) == cfg.TemplateLength {
				logDecision("skip", "", model, len(value),
					"incomplete bucket key; cannot infer: credential list unavailable: "+errSole.Error())
				return
			}
		case sole == "":
			if len(value) == cfg.TemplateLength {
				logDecision("skip", "", model, len(value),
					fmt.Sprintf("incomplete bucket key; refusing to infer: %d enabled Codex accounts, need exactly 1", enabledCount))
				return
			}
		default:
			authID = sole
			attribution = attributionInferred
		}
	}

	// A replace_length value is the degraded/throttled state, not a template.
	// This is logged distinctly from an incomplete key because an operator
	// retrying a probe reads exactly this line: "no 292 to harvest because the
	// account is throttled" must not look like "the bucket key is broken", which
	// sends them chasing a metadata bug instead of waiting out the throttle. The
	// attribution above ran only to name the account here; a 312 is never stored.
	if len(value) == cfg.ReplaceLength {
		logDecision("pass", authID, model, len(value),
			"upstream issued degraded state (len=replace_length), no template to harvest — account throttled or honeymoon closed")
		return
	}

	if authID == "" || model == "" {
		logDecision("skip", authID, model, len(value), "incomplete bucket key")
		return
	}
	if len(value) != cfg.TemplateLength {
		// Neither a template nor the known degraded length. Nothing to harvest.
		logDecision("pass", authID, model, len(value), "length not template")
		return
	}

	now := time.Now()
	issued, ok := fernetIssuedAt(value)
	if !ok {
		issued = now
	}
	key := bucketKey(authID, model)

	// Codex mints a fresh token per turn, so an identical value means the host
	// replayed a response we already stored. Skip the write rather than churn
	// the store and its index on every turn.
	state.mu.Lock()
	existing, held := state.buckets[key]
	state.mu.Unlock()
	if held && existing.value == value {
		logDecision("pass", authID, model, len(value), "template already stored")
		return
	}

	record := storeRecord{
		AuthID:      authID,
		Model:       model,
		Len:         len(value),
		Value:       value,
		IssuedAt:    issued.UTC().Format(time.RFC3339),
		HarvestedAt: now.UTC().Format(time.RFC3339),
		Attribution: attribution,
	}
	if errWrite := writeStoreRecord(cfg.StoreDir, record, cfg.TemplateLength); errWrite != nil {
		logDecision("skip", authID, model, len(value), "store write failed: "+errWrite.Error())
		return
	}
	if errIndex := writeStoreIndex(cfg.StoreDir, now, cfg.ttl(), cfg.TemplateLength); errIndex != nil {
		// The bucket file is already on disk and is what the business role
		// actually reads, so a failed index is a monitoring problem, not a
		// harvesting one. Say so and keep the harvest.
		log.Printf(logPrefix+"index write failed: %v", errIndex)
	}

	state.mu.Lock()
	state.buckets[key] = templateEntry{value: value, issuedAt: issued}
	state.mu.Unlock()

	// Inferred attributions are logged differently on purpose. "This bucket
	// belongs to account X" and "this bucket belongs to the only account that
	// was switched on" are different claims, and an operator reading the log
	// afterwards has to be able to tell which one was made.
	if attribution == attributionInferred {
		logDecision("harvest", authID, model, len(value), "template stored (inferred: sole enabled Codex account)")
		return
	}
	logDecision("harvest", authID, model, len(value), "template stored")
}

// soleEnabledCodexAuth returns the name of the only enabled Codex credential.
// It reports the enabled count alongside so a refusal can say why, and returns
// an empty name whenever the count is anything but one -- the caller must not
// guess, so "none" and "several" are the same answer here.
func soleEnabledCodexAuth() (string, int, error) {
	accounts, errList := cachedCodexAuths()
	if errList != nil {
		return "", 0, errList
	}
	name := ""
	count := 0
	for _, account := range accounts {
		if !account.Enabled {
			continue
		}
		count++
		name = account.AuthID
	}
	if count != 1 {
		return "", count, nil
	}
	return name, 1, nil
}

// decideHeader chooses the outgoing X-Codex-Turn-State given the value the
// request arrived with and the freshest live template for its bucket. It
// returns a decision label, a human-readable reason, and the replacement value
// ("" leaves the request untouched). harvestedOK reports whether the caller has
// already stored the in-band value as a template, so logging stays accurate.
func decideHeader(cfg pluginConfig, value string, tmpl templateEntry, haveTmpl, harvestedOK bool, now time.Time) (string, string, string) {
	// Injection first: only when a live template exists and differs from what
	// the request already carries.
	if haveTmpl && value != tmpl.value {
		age := now.Sub(tmpl.issuedAt).Truncate(time.Second)
		if cfg.injectAlways() {
			return "inject", injectReason(value, cfg) + ", template age " + age.String(), tmpl.value
		}
		// replace-only: all three conditions must hold together -- the request
		// carries the header, its length is exactly the degraded one, and the
		// bucket has a live template. A request with no header is left alone.
		if value != "" && len(value) == cfg.ReplaceLength {
			return "substitute", "template age " + age.String(), tmpl.value
		}
	}

	// No rewrite. Report accurately what happened to this request.
	switch {
	case harvestedOK:
		return "harvest", "template stored", ""
	case haveTmpl && value == tmpl.value:
		return "pass", "header already current", ""
	case len(value) == cfg.ReplaceLength && !haveTmpl:
		return "pass", "no live template for bucket", ""
	default:
		return "pass", "nothing to do", ""
	}
}

func injectReason(value string, cfg pluginConfig) string {
	switch len(value) {
	case 0:
		return "added (request carried no state)"
	case cfg.ReplaceLength:
		return "replaced degraded state"
	default:
		return fmt.Sprintf("replaced non-template state (len %d)", len(value))
	}
}

// sweepLocked drops templates that are no longer usable -- expired, or stamped
// in the future, which templateUsable treats the same way. The caller must hold
// state.mu.
func (s *pluginState) sweepLocked(now time.Time) {
	ttl := s.config.ttl()
	for key, entry := range s.buckets {
		if !templateUsable(entry.issuedAt, now, ttl) {
			delete(s.buckets, key)
		}
	}
}

// fernetIssuedAt extracts the issuance time embedded in a Codex
// X-Codex-Turn-State value. These are Fernet tokens: a 0x80 version byte
// followed by an 8-byte big-endian Unix timestamp, base64url-encoded. The
// upstream enforces a validity window measured from this timestamp, so it is
// the correct basis for expiry. The bool is false when the value is not a
// decodable Fernet token, in which case the caller falls back to harvest time.
func fernetIssuedAt(value string) (time.Time, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
	if err != nil || len(raw) < 9 || raw[0] != 0x80 {
		return time.Time{}, false
	}
	secs := binary.BigEndian.Uint64(raw[1:9])
	return time.Unix(int64(secs), 0), true
}

// storeRecord is one bucket file: <store_dir>/<auth_id>/<model>.json. The field
// names are part of the contract with the probe script, which writes the same
// shape when it harvests out of band.
type storeRecord struct {
	AuthID      string `json:"auth_id"`
	Model       string `json:"model"`
	Len         int    `json:"len"`
	Value       string `json:"value"`
	IssuedAt    string `json:"issued_at"`
	HarvestedAt string `json:"harvested_at"`
	// Attribution records how auth_id was determined: "observed" when the host
	// told us, "inferred" when it was deduced from a sole enabled account. A
	// wrong attribution hands one account's token to another, which is the first
	// thing the spec prohibits, so which buckets rest on a deduction has to stay
	// auditable after the fact. Absent on records written before this existed.
	Attribution string `json:"attribution,omitempty"`
}

// How a bucket's account was determined.
const (
	attributionObserved = "observed"
	attributionInferred = "inferred"
)

// indexEntry summarises one bucket without its value, so index.json can be read
// by anything that needs to know whether probing is complete.
type indexEntry struct {
	AuthID    string `json:"auth_id"`
	Model     string `json:"model"`
	Ready     bool   `json:"ready"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type storeIndex struct {
	Version   int          `json:"version"`
	UpdatedAt string       `json:"updated_at"`
	Entries   []indexEntry `json:"entries"`
}

// bucketRelPath maps a bucket key to its path inside the store. Both halves of
// the key come from request metadata, so they are treated as untrusted input: a
// separator or a dot-dot component would let one bucket be written outside its
// own directory, which is the one way this store could cross the account or
// model boundary it exists to enforce.
func bucketRelPath(authID, model string) (string, error) {
	auth := strings.TrimSpace(authID)
	name := strings.TrimSpace(model)
	if auth == "" || name == "" {
		return "", fmt.Errorf("incomplete bucket key: auth=%q model=%q", auth, name)
	}
	for _, part := range []string{auth, name} {
		switch {
		case strings.ContainsAny(part, `/\`):
			return "", fmt.Errorf("unsafe bucket component %q: contains a path separator", part)
		case strings.Contains(part, ".."):
			return "", fmt.Errorf("unsafe bucket component %q: contains %q", part, "..")
		case strings.ContainsRune(part, 0):
			return "", fmt.Errorf("unsafe bucket component: contains NUL")
		case part == ".":
			return "", fmt.Errorf("unsafe bucket component %q", part)
		}
	}
	return filepath.Join(auth, name+".json"), nil
}

// writeStoreRecord atomically writes one bucket file, replacing whatever that
// bucket held before.
func writeStoreRecord(dir string, rec storeRecord, templateLength int) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("store_dir is empty")
	}
	if rec.Len != templateLength {
		return fmt.Errorf("refusing to store len %d: only %d is a template", rec.Len, templateLength)
	}
	if len(rec.Value) != rec.Len {
		return fmt.Errorf("record len %d disagrees with value length %d", rec.Len, len(rec.Value))
	}
	rel, errPath := bucketRelPath(rec.AuthID, rec.Model)
	if errPath != nil {
		return errPath
	}
	full := filepath.Join(dir, rel)
	if errMkdir := os.MkdirAll(filepath.Dir(full), 0o700); errMkdir != nil {
		return errMkdir
	}
	data, errMarshal := json.MarshalIndent(rec, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	return atomicWrite(full, append(data, '\n'))
}

// atomicWrite writes via a temporary file in the same directory and renames, so
// a reader never sees a half-written bucket. os.CreateTemp already creates with
// 0600 and rename preserves the mode, which is the permission the store needs.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, errTemp := os.CreateTemp(dir, ".tmp-*")
	if errTemp != nil {
		return errTemp
	}
	name := tmp.Name()
	// Harmless after a successful rename; the point is to not leave litter
	// behind on any of the failure paths below.
	defer func() { _ = os.Remove(name) }()

	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		return errSync
	}
	if errClose := tmp.Close(); errClose != nil {
		return errClose
	}
	return os.Rename(name, path)
}

// scanStoreRecords reads every bucket file under dir. Records whose contents
// disagree with their own path are dropped: the path is the bucket key, and a
// file claiming a different account or model than the directory it sits in is
// exactly the cross-bucket contamination the store must not propagate. A
// missing directory is not an error -- the probe may simply not have run yet.
func scanStoreRecords(dir string) ([]storeRecord, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	authDirs, errRead := os.ReadDir(dir)
	if errRead != nil {
		if os.IsNotExist(errRead) {
			return nil, nil
		}
		return nil, errRead
	}
	var records []storeRecord
	for _, authDir := range authDirs {
		// index.json lives at the top level and is not a bucket.
		if !authDir.IsDir() {
			continue
		}
		authID := authDir.Name()
		files, errAuth := os.ReadDir(filepath.Join(dir, authID))
		if errAuth != nil {
			log.Printf(logPrefix+"store scan: cannot read bucket dir: %v", errAuth)
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			model := strings.TrimSuffix(file.Name(), ".json")
			data, errFile := os.ReadFile(filepath.Join(dir, authID, file.Name()))
			if errFile != nil {
				log.Printf(logPrefix+"store scan: cannot read bucket file: %v", errFile)
				continue
			}
			var rec storeRecord
			if errUnmarshal := json.Unmarshal(data, &rec); errUnmarshal != nil {
				log.Printf(logPrefix+"store scan: bucket parse error: %v", errUnmarshal)
				continue
			}
			if rec.AuthID != authID || rec.Model != model {
				log.Printf(logPrefix+"store scan: dropping bucket file whose contents disagree with its path (path auth=%s model=%s)", authID, model)
				continue
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].AuthID != records[j].AuthID {
			return records[i].AuthID < records[j].AuthID
		}
		return records[i].Model < records[j].Model
	})
	return records, nil
}

// recordIssuedAt parses a stored bucket's issuance time. It is separate from
// recordUsable because a bucket that is past its window still has a meaningful
// issued_at to display: "probed once, now stale" and "never probed" must not
// look the same to whoever is deciding whether to open business.
func recordIssuedAt(rec storeRecord) (time.Time, bool) {
	issued, errParse := time.Parse(time.RFC3339, rec.IssuedAt)
	if errParse != nil {
		return time.Time{}, false
	}
	return issued, true
}

// recordUsable is the one rule deciding whether a stored bucket may be used.
//
// Three callers need it: the loader that feeds live substitution, the index
// writer, and the management status page. They must not each carry their own
// copy. A status page that judged a bucket ready when the loader would refuse it
// reports a readiness the business role does not have -- and on this deployment
// that page is the only way the host-side probe script can see into a store
// written as root:root 0600, so a disagreement there is not cosmetic: it would
// let the probe declare itself complete against buckets that cannot be used.
func recordUsable(rec storeRecord, issued, now time.Time, ttl time.Duration, templateLength int) bool {
	return rec.Len == templateLength && len(rec.Value) == rec.Len && templateUsable(issued, now, ttl)
}

// loadStore returns every still-live template in the store, keyed by bucketKey.
// Expired records and anything that is not a template length are left out, so a
// caller cannot accidentally substitute one.
func loadStore(dir string, now time.Time, ttl time.Duration, templateLength int) (map[string]templateEntry, error) {
	out := make(map[string]templateEntry)
	records, errScan := scanStoreRecords(dir)
	if errScan != nil {
		return out, errScan
	}
	for _, rec := range records {
		if rec.Len != templateLength || len(rec.Value) != rec.Len {
			continue
		}
		issued, okIssued := recordIssuedAt(rec)
		if !okIssued {
			log.Printf(logPrefix+"store load: unparsable issued_at, skipping bucket auth=%s model=%s", rec.AuthID, rec.Model)
			continue
		}
		// issued_at + ttl <= now is expired, and an issued_at in the future is
		// not trusted either -- see templateUsable. The upstream rejects a
		// replayed token past its window, so either kind of bad timestamp makes
		// the template worse than none.
		if !recordUsable(rec, issued, now, ttl, templateLength) {
			continue
		}
		out[bucketKey(rec.AuthID, rec.Model)] = templateEntry{value: rec.Value, issuedAt: issued}
	}
	return out, nil
}

// writeStoreIndex rebuilds index.json from what is actually on disk. Expired
// buckets stay listed with ready=false: "probed once, now stale" and "never
// probed" need to look different to whoever is deciding to open business.
func writeStoreIndex(dir string, now time.Time, ttl time.Duration, templateLength int) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("store_dir is empty")
	}
	records, errScan := scanStoreRecords(dir)
	if errScan != nil {
		return errScan
	}
	index := storeIndex{
		Version:   storeIndexVersion,
		UpdatedAt: now.UTC().Format(time.RFC3339),
		Entries:   make([]indexEntry, 0, len(records)),
	}
	for _, rec := range records {
		entry := indexEntry{AuthID: rec.AuthID, Model: rec.Model}
		if issued, okIssued := recordIssuedAt(rec); okIssued {
			expires := issued.Add(ttl)
			entry.IssuedAt = issued.UTC().Format(time.RFC3339)
			entry.ExpiresAt = expires.UTC().Format(time.RFC3339)
			// Same usability rule as the loader, so index.json never advertises
			// a bucket as ready that the business role would refuse to load.
			entry.Ready = recordUsable(rec, issued, now, ttl, templateLength)
		}
		index.Entries = append(index.Entries, entry)
	}
	data, errMarshal := json.MarshalIndent(index, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errMkdir
	}
	return atomicWrite(filepath.Join(dir, indexFileName), append(data, '\n'))
}

// refreshStoreLocked keeps the business role's view of the store current. It
// stats index.json at most once per second and re-scans only when that file
// changes, which is the probe's last write for any harvest. Entries that expire
// between scans are filtered at read time by freshestTemplateLocked, so a quiet
// index cannot leave a stale template in play. The caller holds state.mu.
func (s *pluginState) refreshStoreLocked(cfg pluginConfig, now time.Time) {
	dir := strings.TrimSpace(cfg.StoreDir)
	if dir == "" {
		s.store = nil
		s.storeMod = time.Time{}
		return
	}
	if !s.storeChecked.IsZero() && now.Sub(s.storeChecked) < time.Second {
		return
	}
	s.storeChecked = now

	info, errStat := os.Stat(filepath.Join(dir, indexFileName))
	if errStat != nil {
		// No index yet. The probe may have written bucket files without one, so
		// scan directly -- but only while nothing is cached, so a store that
		// never grows an index does not mean a full scan on every request.
		if s.store == nil {
			if loaded, errLoad := loadStore(dir, now, cfg.ttl(), cfg.TemplateLength); errLoad == nil {
				s.store = loaded
			}
		}
		return
	}
	if !s.storeMod.IsZero() && info.ModTime().Equal(s.storeMod) {
		return
	}
	loaded, errLoad := loadStore(dir, now, cfg.ttl(), cfg.TemplateLength)
	if errLoad != nil {
		log.Printf(logPrefix+"store load error: %v", errLoad)
		return
	}
	s.store = loaded
	s.storeMod = info.ModTime()
	log.Printf(logPrefix+"store loaded %d live template(s) from %s", len(loaded), dir)
}

// freshestTemplateLocked returns the newest still-live template for a bucket,
// pooling the in-process memory and the on-disk store. The caller holds
// state.mu.
func (s *pluginState) freshestTemplateLocked(authID, model string, now time.Time, ttl time.Duration) (templateEntry, bool) {
	var best templateEntry
	found := false
	consider := func(e templateEntry, ok bool) {
		// templateUsable, not a bare age comparison: this is the last gate
		// before a value reaches a live request, so a future-stamped template
		// must be rejected here even if it somehow got past loading.
		if !ok || e.value == "" || !templateUsable(e.issuedAt, now, ttl) {
			return
		}
		if !found || e.issuedAt.After(best.issuedAt) {
			best, found = e, true
		}
	}
	key := bucketKey(authID, model)
	inMem, ok := s.buckets[key]
	consider(inMem, ok)
	fromStore, ok := s.store[key]
	consider(fromStore, ok)
	return best, found
}

// bucketKey joins the two halves with a NUL, which cannot appear in either, so
// no pair of distinct (account, model) can collide onto one key.
func bucketKey(authID, model string) string {
	return authID + "\x00" + model
}

// pickModel resolves the model the same way on both sides of the plugin. The
// probe and the business role must agree exactly, or a template harvested under
// one name would never be found under the other.
func pickModel(model, requestedModel string) string {
	if resolved := strings.TrimSpace(model); resolved != "" {
		return resolved
	}
	return strings.TrimSpace(requestedModel)
}

// headerValue finds a header case-insensitively. http.Header.Get would only
// match the canonical spelling, and these headers reach the plugin through a
// JSON round trip that preserves whatever key the host used.
func headerValue(headers http.Header, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, value := range values {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func orDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// logDecision records lengths and bucket identity only. The state value itself
// is a credential-adjacent secret and never reaches the logs.
func logDecision(decision, authID, model string, valueLen int, reason string) {
	if decision == "" {
		return
	}
	state.mu.Lock()
	enabled := state.config.LogDecisions
	// Counted regardless of log_decisions: the status page should still report
	// what the plugin is doing when the operator has quietened the log.
	switch decision {
	case "harvest":
		state.counts.Harvest++
	case "substitute":
		state.counts.Substitute++
	case "inject":
		state.counts.Inject++
	case "pass":
		state.counts.Pass++
	case "skip":
		state.counts.Skip++
	}
	state.mu.Unlock()
	if !enabled {
		return
	}
	log.Printf(logPrefix+"%s auth=%s model=%s len=%d (%s)", decision, orDash(authID), orDash(model), valueLen, reason)
}

func noop() ([]byte, error) {
	return okEnvelope(pluginapi.RequestInterceptResponse{})
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, errMarshal := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	if errMarshal != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"encode error"}}`)
	}
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
