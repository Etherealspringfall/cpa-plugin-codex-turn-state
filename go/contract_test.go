package main

// Contract tests for the shapes this plugin publishes rather than merely uses.
//
// The other test files assert behaviour: given this request, expect that
// decision. These assert *surface*: the exact set of JSON keys the anonymous
// status document can emit, the exact set of paths reachable without a key, and
// the exact set of config fields the host is told about. They are deliberately
// brittle. A behavioural test answers "does it still work"; these answer "did
// the published surface change", and the only correct way to make one fail is
// to change the literal alongside the code and think about what it now exposes.
//
// Why this file exists: statusResponse carries a long comment warning that
// every field on it is anonymously readable, and managementRegister carries
// another warning that anything in Resources is keyless. Both were prose. The
// nearest thing to enforcement was TestAnonymousStatusOmitsTemplateValues,
// which greps the response for the specific tokens it seeded -- a denylist,
// which by construction cannot catch a field nobody thought to seed. A new
// field carrying a proxy password or an unmasked credential path would pass
// every existing test while being served to anything that can reach the port.

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// --- 1. the anonymous status document ------------------------------------

// statusResponsePublicFields is every JSON key path handleStatus can emit, and
// therefore every key path readable without a credential: the same document
// answers /v0/management/codex-turn-state/status and the unauthenticated
// /v0/resource/plugins/codex-turn-state/status, with no per-route filtering.
//
// Nested paths are "parent.child". Slice elements are flattened onto the slice
// key, so a field on statusBucket appears as "buckets.<field>" once rather than
// per element.
//
// Adding a line here is the act of publishing that field. Before you do:
// probe_management_key is the one value on this plugin that is never displayed
// anywhere, masked or otherwise, and proxy URLs carry userinfo.
var statusResponsePublicFields = []string{
	"accounts_error",
	"accounts_source",
	"buckets",
	"buckets.attribution",
	"buckets.auth_id",
	"buckets.enabled",
	"buckets.expires_at",
	"buckets.issued_at",
	"buckets.len",
	"buckets.model",
	"buckets.ready",
	"buckets.seconds_left",
	"config_errors",
	"counters",
	"counters.harvest",
	"counters.inject",
	"counters.pass",
	"counters.skip",
	"counters.substitute",
	"counters_since",
	"dry_run",
	"generated_at",
	"inject_mode",
	"models",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_proxy_count",
	"probe_proxy_rotating_count",
	"probe_run",
	"probe_run.current",
	"probe_run.done",
	"probe_run.error",
	"probe_run.finished_at",
	"probe_run.lines",
	"probe_run.running",
	"probe_run.started_at",
	"probe_run.total",
	"replace_length",
	"role",
	"store_dir",
	"store_error",
	"targets_ready",
	"targets_total",
	"template_length",
	"ttl_seconds",
}

// TestAnonymousStatusFieldSetIsPinned walks the statusResponse type -- not a
// marshalled instance -- so that omitempty fields are counted too. An instance
// only shows what happened to be populated, and "the leak is in a field that is
// empty in the fixture" is exactly the case worth catching.
func TestAnonymousStatusFieldSetIsPinned(t *testing.T) {
	got := jsonFieldPaths(t, reflect.TypeOf(statusResponse{}), "")

	want := make(map[string]bool, len(statusResponsePublicFields))
	for _, field := range statusResponsePublicFields {
		want[field] = true
	}

	for _, field := range got {
		if !want[field] {
			t.Errorf("statusResponse gained the field %q.\n"+
				"That field is now readable without a credential, on the anonymous\n"+
				"resource route. If that is intended, add it to\n"+
				"statusResponsePublicFields; if it can carry a secret, it does not\n"+
				"belong on this struct at all.", field)
		}
		delete(want, field)
	}
	for field := range want {
		t.Errorf("statusResponse lost the field %q, which the dashboard may still be reading; "+
			"remove it from statusResponsePublicFields if the removal is intended", field)
	}
}

// TestStatusFieldPinIsNotVacuous guards the guard: a jsonFieldPaths that
// silently returned nothing would make the test above pass forever.
func TestStatusFieldPinIsNotVacuous(t *testing.T) {
	if len(statusResponsePublicFields) < 40 {
		t.Fatalf("the pinned field list holds %d entries, which is too few to be the real status document", len(statusResponsePublicFields))
	}
	got := jsonFieldPaths(t, reflect.TypeOf(statusResponse{}), "")
	if len(got) != len(statusResponsePublicFields) {
		t.Fatalf("walked %d field paths but pinned %d; the walk and the literal disagree", len(got), len(statusResponsePublicFields))
	}
}

// jsonFieldPaths returns every JSON key path encoding/json can produce for typ,
// recursing through structs, pointers and slice/array elements. It fails the
// test on any shape it does not model (a map, an interface, an embedded
// struct), because silently skipping one would make the pin above under-report
// and the whole file would be theatre.
func jsonFieldPaths(t *testing.T, typ reflect.Type, prefix string) []string {
	t.Helper()

	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("jsonFieldPaths called on %s, which is not a struct", typ)
	}

	var out []string
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Anonymous {
			t.Fatalf("%s embeds %s; encoding/json inlines embedded fields and this walk does not model that", typ, field.Type)
		}
		if field.PkgPath != "" {
			// Unexported: encoding/json never emits it.
			continue
		}

		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			// No tag: encoding/json falls back to the Go field name.
			name = field.Name
		}

		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		out = append(out, path)

		elem := field.Type
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		switch elem.Kind() {
		case reflect.Slice, reflect.Array:
			elem = elem.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			if elem.Kind() == reflect.Struct {
				out = append(out, jsonFieldPaths(t, elem, path)...)
			}
		case reflect.Struct:
			out = append(out, jsonFieldPaths(t, elem, path)...)
		case reflect.Map, reflect.Interface:
			t.Fatalf("%s.%s is a %s, whose keys cannot be pinned by walking the type; "+
				"an open-ended container on an anonymously readable document needs its own assertion",
				typ, field.Name, elem.Kind())
		}
	}
	sort.Strings(out)
	return out
}

// --- 2. the keyless surface ----------------------------------------------

// keylessResourcePaths is every path registered under the resource prefix.
// Registration *is* the grant: the host serves that prefix without
// authentication, so a new entry in managementRegister's Resources list is a
// new keyless endpoint whether or not anyone meant it to be one.
//
// TestManagementRegisterExposesExactlyOneMenuResource already stops a resource
// from acquiring a Menu (which would publish it into the management centre).
// This pins the weaker but wider property: the set itself.
var keylessResourcePaths = []string{
	"/dashboard",
	"/ops/choices",
	"/ops/clear",
	"/ops/dry-run",
	"/ops/probe/cancel",
	"/ops/probe/start",
	"/ops/proxy-check",
	"/ops/role",
	"/ops/scope",
	"/ops/selftest",
	"/status",
}

// authenticatedRoutes is the management surface that stays behind a key.
// routeConfig is the load-bearing one: it returns the configuration verbatim,
// which is where a probe bearer would surface. It must never move to the
// resource list, and it must never acquire a Menu (a GET route with a Menu is
// re-registered under the resource prefix by the host).
var authenticatedRoutes = []string{
	"GET /codex-turn-state/config",
	"GET /codex-turn-state/status",
	"POST /codex-turn-state/buckets/clear",
	"POST /codex-turn-state/selftest",
}

func TestKeylessSurfaceIsPinned(t *testing.T) {
	dir := t.TempDir()
	mustConfigure(t, probeRoleConfig(dir))

	reg := driveManagementRegister(t)

	var gotResources []string
	for _, res := range reg.Resources {
		gotResources = append(gotResources, res.Path)
	}
	assertSetEqual(t, "keyless resource paths", gotResources, keylessResourcePaths,
		"every path here is served without a credential; adding one is a deliberate act")

	var gotRoutes []string
	for _, route := range reg.Routes {
		gotRoutes = append(gotRoutes, route.Method+" "+route.Path)
	}
	assertSetEqual(t, "authenticated management routes", gotRoutes, authenticatedRoutes,
		"moving one of these to the resource list would publish it")
}

// --- 3. the declared configuration ----------------------------------------

// configFieldNames is what the host is told this plugin accepts, in order. The
// host renders these, so a rename is a user-visible change to a YAML key and a
// removal silently stops the field being offered.
var configFieldNames = []string{
	"role",
	"store_dir",
	"template_length",
	"replace_length",
	"ttl_seconds",
	"harvest_inband",
	"inject_mode",
	"dry_run",
	"log_decisions",
	"models",
	"probe_accounts",
	"probe_proxies",
	"probe_proxies_rotating",
	"probe_management_key",
	"probe_base_url",
}

func TestDeclaredConfigFieldsArePinned(t *testing.T) {
	fields := pluginRegistration().Metadata.ConfigFields

	var got []string
	for _, field := range fields {
		got = append(got, field.Name)
	}
	if !reflect.DeepEqual(got, configFieldNames) {
		t.Errorf("declared config fields changed.\n got: %v\nwant: %v\n"+
			"Order matters here because the host renders them in it.", got, configFieldNames)
	}

	// A field declared with no description is one the operator meets with no
	// explanation, and several of these carry warnings about probe scope that
	// are the only place that rule is stated to a reader of the UI.
	for _, field := range fields {
		if strings.TrimSpace(field.Description) == "" {
			t.Errorf("config field %q is declared without a description", field.Name)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func assertSetEqual(t *testing.T, what string, got, want []string, why string) {
	t.Helper()

	if len(got) == 0 {
		t.Fatalf("%s: nothing was declared, so this assertion would pass vacuously", what)
	}

	seen := make(map[string]bool, len(want))
	for _, entry := range want {
		seen[entry] = true
	}
	for _, entry := range got {
		if !seen[entry] {
			t.Errorf("%s gained %q -- %s", what, entry, why)
		}
		delete(seen, entry)
	}
	var missing []string
	for entry := range seen {
		missing = append(missing, entry)
	}
	sort.Strings(missing)
	for _, entry := range missing {
		t.Errorf("%s lost %q; update the literal if the removal is intended", what, entry)
	}
}
