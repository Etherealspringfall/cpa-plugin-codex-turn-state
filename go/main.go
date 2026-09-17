// Package main implements a CLIProxyAPI native plugin that reuses official
// Codex X-Codex-Turn-State values within a single (account, model) bucket.
//
// Rules enforced here, per the agreed spec:
//  1. state is never shared across accounts
//  2. state is never shared across models
//  3. reuse within one bucket is allowed regardless of client IP
//  4. a harvested template expires after ttl_seconds (default 3600)
//
// The plugin only ever touches the X-Codex-Turn-State header. It never
// fabricates a value: substitution uses a value previously observed on a
// genuine request belonging to the same bucket.
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

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
	"strings"
	"sync"
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

var state = pluginState{
	config:  defaultConfig(),
	buckets: make(map[string]templateEntry),
}

type pluginState struct {
	mu      sync.Mutex
	config  pluginConfig
	buckets map[string]templateEntry
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

type pluginConfig struct {
	// TemplateLength is the value length treated as a reusable template.
	TemplateLength int `yaml:"template_length"`
	// ReplaceLength is the value length that gets overwritten by a template.
	ReplaceLength int `yaml:"replace_length"`
	// TTLSeconds bounds how long a harvested template stays usable.
	TTLSeconds int `yaml:"ttl_seconds"`
	// DryRun logs decisions without rewriting the outgoing header.
	DryRun bool `yaml:"dry_run"`
	// LogDecisions emits one line per harvest/substitute decision.
	LogDecisions bool `yaml:"log_decisions"`
}

func defaultConfig() pluginConfig {
	return pluginConfig{
		TemplateLength: 292,
		ReplaceLength:  312,
		TTLSeconds:     3600,
		DryRun:         false,
		LogDecisions:   true,
	}
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

type registrationCapability struct {
	RequestInterceptor bool `json:"request_interceptor"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(_ *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
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
	}
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

	state.mu.Lock()
	// The host reconfigures far more often than the config actually changes:
	// five times during startup alone, and again every time CPA rewrites
	// config.yaml on its own. Clearing unconditionally would drop every
	// template at unpredictable moments and leave the cache permanently
	// empty, so only a change that invalidates templates clears them.
	cleared := templatesInvalidatedBy(state.config, cfg)
	state.config = cfg
	if cleared {
		state.buckets = make(map[string]templateEntry)
	}
	state.mu.Unlock()

	templates := "templates kept"
	if cleared {
		templates = "templates cleared"
	}
	log.Printf(logPrefix+"configured template_length=%d replace_length=%d ttl_seconds=%d dry_run=%t (%s)",
		cfg.TemplateLength, cfg.ReplaceLength, cfg.TTLSeconds, cfg.DryRun, templates)
	return nil
}

// templatesInvalidatedBy reports whether moving from oldCfg to newCfg makes
// already-harvested templates unusable. A template must never outlive the
// rules it was harvested under, so the two lengths and the TTL force a clear.
// dry_run and log_decisions change what the plugin does with a template, not
// whether the template is still a valid one.
func templatesInvalidatedBy(oldCfg, newCfg pluginConfig) bool {
	return oldCfg.TemplateLength != newCfg.TemplateLength ||
		oldCfg.ReplaceLength != newCfg.ReplaceLength ||
		oldCfg.TTLSeconds != newCfg.TTLSeconds
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "codex-turn-state",
			Version:          "0.1.0",
			Author:           "arden-aaai",
			GitHubRepository: "https://github.com/arden-aaai/cpa-plugin-codex-turn-state",
			ConfigFields: []pluginapi.ConfigField{
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
					Description: "How long a harvested template stays usable (default 3600).",
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
			},
		},
		Capabilities: registrationCapability{RequestInterceptor: true},
	}
}

// interceptAfterAuth runs once the scheduler has picked a credential, so both
// halves of the bucket key are known.
func interceptAfterAuth(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
		return nil, errUnmarshal
	}

	value := headerValue(req.Headers, turnStateHeader)
	if value == "" {
		return noop()
	}

	authID := metadataString(req.Metadata, selectedAuthMetadataKey)
	model := strings.TrimSpace(req.Model)
	if authID == "" || model == "" {
		// Without a full key the request cannot be attributed to a bucket, and
		// guessing would break rules 1 and 2. Leave the request untouched.
		logDecision("skip", authID, model, len(value), "incomplete bucket key")
		return noop()
	}
	key := bucketKey(authID, model)

	state.mu.Lock()
	cfg := state.config
	var replacement string
	var decision, reason string

	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	switch len(value) {
	case cfg.TemplateLength:
		now := time.Now()
		state.sweepLocked(now)
		issued, ok := fernetIssuedAt(value)
		if !ok {
			issued = now
		}
		if now.Sub(issued) > ttl {
			// Already past its server-side window on arrival; storing it would
			// only produce a "could not be decrypted" error on reuse.
			decision, reason = "pass", "template already expired on arrival"
		} else {
			state.buckets[key] = templateEntry{value: value, issuedAt: issued}
			remaining := time.Until(issued.Add(ttl)).Truncate(time.Second)
			decision, reason = "harvest", "template stored, expires in "+remaining.String()
		}
	case cfg.ReplaceLength:
		entry, found := state.buckets[key]
		switch {
		case !found:
			decision, reason = "pass", "no template for bucket"
		case time.Since(entry.issuedAt) > ttl:
			delete(state.buckets, key)
			decision, reason = "pass", "template expired"
		default:
			replacement = entry.value
			decision, reason = "substitute", "template age "+time.Since(entry.issuedAt).Truncate(time.Second).String()
		}
	default:
		decision, reason = "pass", "length not configured"
	}
	state.mu.Unlock()

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

// sweepLocked drops expired templates. The caller must hold state.mu.
func (s *pluginState) sweepLocked(now time.Time) {
	ttl := time.Duration(s.config.TTLSeconds) * time.Second
	for key, entry := range s.buckets {
		if now.Sub(entry.issuedAt) > ttl {
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

func bucketKey(authID, model string) string {
	return authID + "\x00" + model
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

// logDecision records lengths and bucket identity only. The state value itself
// is a credential-adjacent secret and never reaches the logs.
func logDecision(decision, authID, model string, valueLen int, reason string) {
	state.mu.Lock()
	enabled := state.config.LogDecisions
	state.mu.Unlock()
	if !enabled || decision == "" {
		return
	}
	if authID == "" {
		authID = "-"
	}
	if model == "" {
		model = "-"
	}
	log.Printf(logPrefix+"%s auth=%s model=%s len=%d (%s)", decision, authID, model, valueLen, reason)
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
