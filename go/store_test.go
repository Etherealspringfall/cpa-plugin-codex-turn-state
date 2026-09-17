package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// storeRecordFor builds a synthetic record for one bucket. The value is a fake
// Fernet token (fakeToken, main_test.go) — no production X-Codex-Turn-State
// value appears anywhere in this repository.
func storeRecordFor(authID, model string, issued time.Time, n int) storeRecord {
	return storeRecord{
		AuthID:      authID,
		Model:       model,
		Len:         n,
		Value:       fakeToken(n, issued),
		IssuedAt:    issued.UTC().Format(time.RFC3339),
		HarvestedAt: issued.UTC().Format(time.RFC3339),
	}
}

// mustWriteRecord writes through the production path and fails on rejection.
func mustWriteRecord(t *testing.T, dir string, rec storeRecord) {
	t.Helper()
	if err := writeStoreRecord(dir, rec, 292); err != nil {
		t.Fatalf("writeStoreRecord(%s/%s): %v", rec.AuthID, rec.Model, err)
	}
}

// writeRawRecord drops a record straight onto disk, bypassing writeStoreRecord.
// The expiry tests need a stale file on disk regardless of whether the writer
// would accept one, so they must not go through the production writer.
func writeRawRecord(t *testing.T, dir string, rec storeRecord) {
	t.Helper()
	rel, err := bucketRelPath(rec.AuthID, rec.Model)
	if err != nil {
		t.Fatalf("bucketRelPath(%q, %q): %v", rec.AuthID, rec.Model, err)
	}
	full := filepath.Join(dir, rel)
	if errMkdir := os.MkdirAll(filepath.Dir(full), 0o700); errMkdir != nil {
		t.Fatalf("mkdir: %v", errMkdir)
	}
	data, errMarshal := json.Marshal(rec)
	if errMarshal != nil {
		t.Fatalf("marshal record: %v", errMarshal)
	}
	if errWrite := os.WriteFile(full, data, 0o600); errWrite != nil {
		t.Fatalf("write record: %v", errWrite)
	}
}

// regularFiles lists every file under dir, slash-separated and relative.
func regularFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return found
}

// snapshotDir records every file path and its contents, so a test can assert
// that a code path left the store completely untouched.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := make(map[string]string)
	for _, rel := range regularFiles(t, dir) {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		snap[rel] = string(data)
	}
	return snap
}

func equalSnapshots(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, valueA := range a {
		valueB, ok := b[key]
		if !ok || valueA != valueB {
			return false
		}
	}
	return true
}

// --- path safety ---------------------------------------------------------

func TestBucketRelPathRejectsTraversal(t *testing.T) {
	// auth_id and model are attacker-adjacent: they arrive as request metadata
	// and are used to build a filesystem path. Anything that could escape the
	// store directory, or name something other than one bucket, must be
	// refused rather than sanitised.
	tests := []struct {
		name    string
		auth    string
		model   string
		wantErr bool
	}{
		{"ordinary bucket", "codex-a.json", "gpt-5.6-sol", false},
		{"dotted model id", "codex-a.json", "gpt-5.5", false},
		{"empty auth", "", "gpt-5.5", true},
		{"empty model", "codex-a.json", "", true},
		{"whitespace auth", "   ", "gpt-5.5", true},
		{"whitespace model", "codex-a.json", "  ", true},
		{"auth is dotdot", "..", "gpt-5.5", true},
		{"model is dotdot", "codex-a.json", "..", true},
		{"auth is dot", ".", "gpt-5.5", true},
		{"model is dot", "codex-a.json", ".", true},
		{"auth escapes upward", "../../etc", "gpt-5.5", true},
		{"model escapes upward", "codex-a.json", "../../etc/passwd", true},
		{"forward slash in auth", "a/b", "gpt-5.5", true},
		{"forward slash in model", "codex-a.json", "a/b", true},
		{"backslash in auth", `a\b`, "gpt-5.5", true},
		{"backslash in model", "codex-a.json", `a\b`, true},
		{"nul byte in auth", "a\x00b", "gpt-5.5", true},
		{"nul byte in model", "codex-a.json", "a\x00b", true},
		{"absolute auth", "/etc/passwd", "gpt-5.5", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bucketRelPath(tc.auth, tc.model)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("bucketRelPath(%q, %q) = %q, want an error", tc.auth, tc.model, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("bucketRelPath(%q, %q): unexpected error %v", tc.auth, tc.model, err)
			}
			want := tc.auth + "/" + tc.model + ".json"
			if filepath.ToSlash(got) != want {
				t.Fatalf("bucketRelPath(%q, %q) = %q, want %q", tc.auth, tc.model, filepath.ToSlash(got), want)
			}
		})
	}
}

// --- §8.5 a 312 must never enter the store -------------------------------

func TestWriteStoreRecordRejectsNonTemplateLength(t *testing.T) {
	issued := testNow.Add(-time.Minute)

	tests := []struct {
		name string
		rec  storeRecord
	}{
		{
			name: "degraded 312 value",
			rec:  storeRecordFor("codex-a.json", "gpt-5.6-sol", issued, 312),
		},
		{
			name: "declared length disagrees with the value",
			rec: func() storeRecord {
				rec := storeRecordFor("codex-a.json", "gpt-5.6-sol", issued, 292)
				rec.Len = 312
				return rec
			}(),
		},
		{
			name: "empty value",
			rec: func() storeRecord {
				rec := storeRecordFor("codex-a.json", "gpt-5.6-sol", issued, 292)
				rec.Value = ""
				rec.Len = 0
				return rec
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeStoreRecord(dir, tc.rec, 292); err == nil {
				t.Fatal("writeStoreRecord accepted a non-template value; only a 292 may be stored")
			}
			if files := regularFiles(t, dir); len(files) != 0 {
				t.Fatalf("a rejected write still left files behind: %v", files)
			}
		})
	}
}

// --- §8.9 write then load round trip -------------------------------------

func TestWriteStoreRecordRoundTripsThroughLoadStore(t *testing.T) {
	dir := t.TempDir()
	issued := testNow.Add(-20 * time.Minute)
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	rec := storeRecordFor(auth, model, issued, 292)
	mustWriteRecord(t, dir, rec)

	if files := regularFiles(t, dir); len(files) != 1 || files[0] != auth+"/"+model+".json" {
		t.Fatalf("unexpected store layout: %v", files)
	}

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	entry, ok := loaded[bucketKey(auth, model)]
	if !ok {
		t.Fatalf("bucket not found after write; keys = %v", bucketNames(loaded))
	}
	if entry.value != rec.Value {
		t.Fatal("loaded value differs from the written one")
	}
	if !entry.issuedAt.Equal(issued) {
		t.Fatalf("issuedAt = %s, want %s (expiry must key on the token's own timestamp)",
			entry.issuedAt.UTC(), issued)
	}
}

func TestLoadStoreOnMissingDirectoryIsNotAnError(t *testing.T) {
	// The business side can start before the probe has written anything.
	loaded, err := loadStore(filepath.Join(t.TempDir(), "not-created-yet"), testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore on a missing directory returned %v; it must degrade to empty", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("expected an empty store, got %d entries", len(loaded))
	}
}

// --- §8.4 expiry at the store layer --------------------------------------

func TestLoadStoreSkipsExpiredRecords(t *testing.T) {
	dir := t.TempDir()
	const auth = "codex-a.json"

	fresh := testNow.Add(-30 * time.Minute)
	stale := testNow.Add(-testTTL - time.Second)

	writeRawRecord(t, dir, storeRecordFor(auth, "gpt-5.6-sol", fresh, 292))
	writeRawRecord(t, dir, storeRecordFor(auth, "gpt-6-astra", stale, 292))

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded[bucketKey(auth, "gpt-5.6-sol")]; !ok {
		t.Fatal("the fresh bucket was dropped")
	}
	if _, ok := loaded[bucketKey(auth, "gpt-6-astra")]; ok {
		t.Fatal("an expired bucket was loaded; replaying it would fail upstream with a decryption error")
	}
}

func TestLoadStoreSkipsRecordsOfTheWrongLength(t *testing.T) {
	dir := t.TempDir()
	const auth = "codex-a.json"
	issued := testNow.Add(-5 * time.Minute)

	// A 312 that somehow reached the disk must not be served as a template.
	writeRawRecord(t, dir, storeRecordFor(auth, "gpt-5.5", issued, 312))

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded[bucketKey(auth, "gpt-5.5")]; ok {
		t.Fatal("loadStore served a 312 as a template")
	}
}

// --- §8.1 / §8.2 isolation at the store layer ----------------------------

func TestLoadStoreKeepsAccountsAndModelsSeparate(t *testing.T) {
	dir := t.TempDir()
	issued := testNow.Add(-5 * time.Minute)

	records := []storeRecord{
		storeRecordFor("codex-a.json", "gpt-5.6-sol", issued, 292),
		storeRecordFor("codex-a.json", "gpt-6-astra", issued, 292),
		storeRecordFor("codex-b.json", "gpt-5.6-sol", issued, 292),
	}
	// Distinct values, so a mix-up is detectable rather than coincidentally
	// equal.
	for i := range records {
		records[i].Value = fakeTokenSeed(292, issued, byte(0x10*(i+1)))
	}
	for _, rec := range records {
		writeRawRecord(t, dir, rec)
	}

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if len(loaded) != len(records) {
		t.Fatalf("loaded %d buckets, want %d: %v", len(loaded), len(records), bucketNames(loaded))
	}
	for _, rec := range records {
		entry, ok := loaded[bucketKey(rec.AuthID, rec.Model)]
		if !ok {
			t.Fatalf("bucket %s/%s missing", rec.AuthID, rec.Model)
		}
		if entry.value != rec.Value {
			t.Fatalf("bucket %s/%s holds another bucket's value", rec.AuthID, rec.Model)
		}
	}
}

// --- overwrite and atomicity ---------------------------------------------

func TestWriteStoreRecordOverwritesSameBucket(t *testing.T) {
	dir := t.TempDir()
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-terra"
	)
	older := testNow.Add(-40 * time.Minute)
	newer := testNow.Add(-2 * time.Minute)

	first := storeRecordFor(auth, model, older, 292)
	second := storeRecordFor(auth, model, newer, 292)
	mustWriteRecord(t, dir, first)
	mustWriteRecord(t, dir, second)

	files := regularFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("re-harvesting one bucket left %d files (temp files must be renamed, not accumulated): %v",
			len(files), files)
	}

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	entry := loaded[bucketKey(auth, model)]
	if entry.value != second.Value {
		t.Fatal("the newer harvest did not replace the older one")
	}
}

func TestWriteStoreRecordLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	issued := testNow.Add(-time.Minute)
	mustWriteRecord(t, dir, storeRecordFor("codex-a.json", "gpt-5.5", issued, 292))

	for _, rel := range regularFiles(t, dir) {
		base := filepath.Base(rel)
		if !strings.HasSuffix(base, ".json") || strings.Contains(base, "tmp") {
			t.Fatalf("found what looks like a leftover temp file: %s", rel)
		}
	}
}

// --- index.json ----------------------------------------------------------

func TestWriteStoreIndexReportsReadinessWithoutValues(t *testing.T) {
	dir := t.TempDir()
	const auth = "codex-a.json"

	fresh := testNow.Add(-15 * time.Minute)
	stale := testNow.Add(-testTTL - time.Minute)

	freshRec := storeRecordFor(auth, "gpt-5.6-sol", fresh, 292)
	staleRec := storeRecordFor(auth, "gpt-6-astra", stale, 292)
	writeRawRecord(t, dir, freshRec)
	writeRawRecord(t, dir, staleRec)

	if err := writeStoreIndex(dir, testNow, testTTL, 292); err != nil {
		t.Fatalf("writeStoreIndex: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}

	// The index is the thing a human reads and pastes into a report. It must
	// never carry a state value.
	for _, rec := range []storeRecord{freshRec, staleRec} {
		if strings.Contains(string(raw), rec.Value) {
			t.Fatal("index.json contains a state value; it must list readiness only")
		}
	}

	var idx storeIndex
	if errUnmarshal := json.Unmarshal(raw, &idx); errUnmarshal != nil {
		t.Fatalf("decode index.json: %v", errUnmarshal)
	}
	if len(idx.Entries) != 2 {
		t.Fatalf("index lists %d entries, want 2", len(idx.Entries))
	}

	byModel := make(map[string]indexEntry, len(idx.Entries))
	for _, entry := range idx.Entries {
		if entry.AuthID != auth {
			t.Fatalf("entry has auth_id %q, want %q", entry.AuthID, auth)
		}
		byModel[entry.Model] = entry
	}

	if got := byModel["gpt-5.6-sol"]; !got.Ready {
		t.Fatal("a fresh bucket is not reported ready")
	}
	if got := byModel["gpt-6-astra"]; got.Ready {
		t.Fatal("an expired bucket is reported ready; --until-complete would declare success on a dead bucket")
	}

	// expires_at must be issued_at + ttl, not harvest time + ttl.
	got := byModel["gpt-5.6-sol"]
	expires, errParse := time.Parse(time.RFC3339, got.ExpiresAt)
	if errParse != nil {
		t.Fatalf("parse expires_at %q: %v", got.ExpiresAt, errParse)
	}
	if !expires.Equal(fresh.Add(testTTL)) {
		t.Fatalf("expires_at = %s, want %s (issued_at + ttl)", expires.UTC(), fresh.Add(testTTL).UTC())
	}
}

// --- future timestamps ---------------------------------------------------

func TestLoadStoreSkipsFutureRecords(t *testing.T) {
	dir := t.TempDir()
	const auth = "codex-a.json"

	fresh := testNow.Add(-10 * time.Minute)
	future := testNow.Add(30 * time.Minute)

	writeRawRecord(t, dir, storeRecordFor(auth, "gpt-5.6-sol", fresh, 292))
	writeRawRecord(t, dir, storeRecordFor(auth, "gpt-6-astra", future, 292))

	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	if _, ok := loaded[bucketKey(auth, "gpt-5.6-sol")]; !ok {
		t.Fatal("the ordinary bucket was dropped")
	}
	if _, ok := loaded[bucketKey(auth, "gpt-6-astra")]; ok {
		t.Fatal("a future-stamped record was loaded; an age comparison reads it as brand new and keeps doing so")
	}
}

// TestWriteStoreIndexDoesNotMarkFutureRecordsReady pins the concrete failure
// this guards against.
//
// index.json is what `probe --until-complete` reads to decide it is done. If a
// future-stamped bucket is advertised as ready while the business loader
// refuses it, the probe stops harvesting on a bucket that business never has a
// template for — and the gap shows up later as unexplained 312s in production
// rather than as a probe failure.
func TestWriteStoreIndexDoesNotMarkFutureRecordsReady(t *testing.T) {
	dir := t.TempDir()
	const (
		auth        = "codex-a.json"
		futureModel = "gpt-6-astra"
		freshModel  = "gpt-5.6-sol"
	)
	future := testNow.Add(30 * time.Minute)
	fresh := testNow.Add(-10 * time.Minute)

	writeRawRecord(t, dir, storeRecordFor(auth, futureModel, future, 292))
	writeRawRecord(t, dir, storeRecordFor(auth, freshModel, fresh, 292))

	if err := writeStoreIndex(dir, testNow, testTTL, 292); err != nil {
		t.Fatalf("writeStoreIndex: %v", err)
	}

	byModel := readIndexByModel(t, dir)

	if entry := byModel[futureModel]; entry.Ready {
		t.Fatal("index.json advertises a future-stamped bucket as ready; --until-complete would declare success on a bucket business cannot load")
	}
	if entry := byModel[freshModel]; !entry.Ready {
		t.Fatal("the ordinary bucket is not reported ready")
	}

	// The index and the loader must agree, which is the whole point.
	loaded, err := loadStore(dir, testNow, testTTL, 292)
	if err != nil {
		t.Fatalf("loadStore: %v", err)
	}
	for model, entry := range byModel {
		_, loadable := loaded[bucketKey(auth, model)]
		if entry.Ready != loadable {
			t.Fatalf("index says ready=%t for %s but the loader %s it", entry.Ready, model,
				map[bool]string{true: "accepts", false: "refuses"}[loadable])
		}
	}
}

// TestStoreExpiryBoundaryAgreesWithSpec drives the boundary through the two
// on-disk paths, so the rule pinned by TestTemplateUsableExpiryBoundary cannot
// be satisfied at the helper while a call site rounds it differently.
func TestStoreExpiryBoundaryAgreesWithSpec(t *testing.T) {
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)

	tests := []struct {
		name   string
		issued time.Time
		want   bool
	}{
		{"one second before expiry", testNow.Add(-testTTL + time.Second), true},
		// Spec §4: issued_at + ttl <= now is expired.
		{"exactly at expiry", testNow.Add(-testTTL), false},
		{"one second past expiry", testNow.Add(-testTTL - time.Second), false},
		{"stamped in the future", testNow.Add(time.Second), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawRecord(t, dir, storeRecordFor(auth, model, tc.issued, 292))

			loaded, err := loadStore(dir, testNow, testTTL, 292)
			if err != nil {
				t.Fatalf("loadStore: %v", err)
			}
			_, gotLoad := loaded[bucketKey(auth, model)]
			if gotLoad != tc.want {
				t.Fatalf("loadStore kept the bucket = %t, want %t", gotLoad, tc.want)
			}

			if err := writeStoreIndex(dir, testNow, testTTL, 292); err != nil {
				t.Fatalf("writeStoreIndex: %v", err)
			}
			if gotReady := readIndexByModel(t, dir)[model].Ready; gotReady != tc.want {
				t.Fatalf("index ready = %t, want %t (it must agree with the loader)", gotReady, tc.want)
			}
		})
	}
}

// readIndexByModel decodes index.json into a lookup keyed by model.
func readIndexByModel(t *testing.T, dir string) map[string]indexEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatalf("read index.json: %v", err)
	}
	var idx storeIndex
	if errUnmarshal := json.Unmarshal(raw, &idx); errUnmarshal != nil {
		t.Fatalf("decode index.json: %v", errUnmarshal)
	}
	byModel := make(map[string]indexEntry, len(idx.Entries))
	for _, entry := range idx.Entries {
		byModel[entry.Model] = entry
	}
	return byModel
}

// --- permissions (spec §3: dir 0700, file 0600) --------------------------

func TestStorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows; CPA runs on Linux")
	}
	dir := t.TempDir()
	const (
		auth  = "codex-a.json"
		model = "gpt-5.6-sol"
	)
	mustWriteRecord(t, dir, storeRecordFor(auth, model, testNow.Add(-time.Minute), 292))

	bucketDir, err := os.Stat(filepath.Join(dir, auth))
	if err != nil {
		t.Fatalf("stat bucket dir: %v", err)
	}
	if perm := bucketDir.Mode().Perm(); perm != 0o700 {
		t.Fatalf("bucket directory mode = %o, want 700", perm)
	}

	bucketFile, err := os.Stat(filepath.Join(dir, auth, model+".json"))
	if err != nil {
		t.Fatalf("stat bucket file: %v", err)
	}
	if perm := bucketFile.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bucket file mode = %o, want 600", perm)
	}
}

// bucketNames renders bucket keys readably: the key separator is a NUL byte.
func bucketNames(store map[string]templateEntry) []string {
	names := make([]string, 0, len(store))
	for key := range store {
		names = append(names, strings.ReplaceAll(key, "\x00", "/"))
	}
	return names
}
