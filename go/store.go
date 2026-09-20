// Store domain: the on-disk template store this plugin owns.
//
// Layout is <store_dir>/<auth_id>/<model>.json plus a value-free index.json,
// and the path IS the bucket key -- a record whose contents disagree with the
// directory it sits in is dropped rather than trusted, because that
// disagreement is exactly the cross-bucket contamination rule 1 forbids.
//
// Everything here takes the directory as a parameter and none of it reads the
// running config, with the two deliberate exceptions at the bottom: the
// pluginState methods, which are the read path the business role uses and must
// be called with state.mu held.
//
// Moved verbatim out of main.go. No behaviour changed in the move.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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
