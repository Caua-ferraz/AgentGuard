package audit

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// logBlob returns an Entry big enough to let a handful of writes cross
// any reasonable rotation threshold without eating megabytes of disk in
// tests.
func logBlob(agent string) Entry {
	return Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   agent,
		Request: policy.ActionRequest{
			Scope:   "shell",
			Command: strings.Repeat("x", 200),
		},
		Result: policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}
}

// TestRotation_SizeTriggered verifies that exceeding MaxSize produces an
// archive file and that the live file carries a fresh schema header.
func TestRotation_SizeTriggered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// Write enough entries to exceed 512 bytes at least twice.
	for i := 0; i < 20; i++ {
		if err := logger.Log(logBlob("bot")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var archives int
	for _, e := range entries {
		if e.Name() == "audit.jsonl" || e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "audit.jsonl.") {
			archives++
		}
	}
	if archives == 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected at least one archive after size-triggered rotation; dir contents: %v", names)
	}
}

// TestRotation_MetaRotatedFromPointsAtArchive checks that the post-rotate
// live file opens with `_meta.rotated_from` set to the archive basename.
func TestRotation_MetaRotatedFromPointsAtArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 256})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = logger.Log(logBlob("bot"))
	}
	logger.Close()

	meta, err := ReadMeta(path)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if meta == nil {
		t.Fatal("live file must have a schema header after rotation")
	}
	if meta.RotatedFrom == "" {
		t.Fatal("post-rotation live file must carry rotated_from")
	}
	// rotated_from must name a file that actually exists in the dir.
	archivePath := filepath.Join(dir, meta.RotatedFrom)
	if _, err := os.Stat(archivePath); err != nil {
		t.Errorf("rotated_from %q does not exist: %v", archivePath, err)
	}
	// It must carry the timestamp suffix.
	if !strings.HasPrefix(meta.RotatedFrom, "audit.jsonl.") {
		t.Errorf("rotated_from should name an archive of audit.jsonl, got %q", meta.RotatedFrom)
	}
}

// TestRotation_Compression verifies archives are gzipped when Compress=true
// and the gzip stream decompresses to valid audit JSONL.
func TestRotation_Compression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{
		MaxSize:  256,
		Compress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		_ = logger.Log(logBlob("bot"))
	}
	logger.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var gzArchive string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "audit.jsonl.") && strings.HasSuffix(e.Name(), ".gz") {
			gzArchive = filepath.Join(dir, e.Name())
			break
		}
	}
	if gzArchive == "" {
		t.Fatal("expected a .gz archive when Compress=true")
	}

	// Ensure no uncompressed archive was left behind.
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit.jsonl.") && !strings.HasSuffix(name, ".gz") && name != "audit.jsonl" {
			t.Errorf("uncompressed archive leaked: %s", name)
		}
	}

	// Decompress and verify JSONL parses.
	f, err := os.Open(gzArchive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("gzipped archive must contain at least a meta + entry, got %d lines", len(lines))
	}
	// First line should be the meta; second line should parse as an Entry.
	if !strings.HasPrefix(lines[0], `{"_meta"`) {
		t.Errorf("first archived line should be _meta, got %q", lines[0])
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[1]), &e); err != nil {
		t.Errorf("entry after meta failed to parse: %v", err)
	}
}

// TestRotation_Pruning keeps only MaxFiles most recent archives and deletes
// the rest.
func TestRotation_Pruning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{
		MaxSize:  256,
		MaxFiles: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Force several rotations with distinct timestamps. rotateLocked uses
	// second-precision UTC so sleeping briefly between bursts guarantees
	// archives get unique suffixes.
	for round := 0; round < 5; round++ {
		for i := 0; i < 10; i++ {
			_ = logger.Log(logBlob("bot"))
		}
		time.Sleep(1100 * time.Millisecond)
	}
	logger.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var archives []string
	for _, e := range entries {
		if e.Name() != "audit.jsonl" && strings.HasPrefix(e.Name(), "audit.jsonl.") {
			archives = append(archives, e.Name())
		}
	}
	if len(archives) > 2 {
		sort.Strings(archives)
		t.Errorf("MaxFiles=2 should keep at most 2 archives, found %d: %v", len(archives), archives)
	}
	if len(archives) == 0 {
		t.Error("expected at least one surviving archive")
	}
}

// TestRotation_ZeroConfigDoesNothing: the zero RotationConfig preserves
// v0.4.0 behaviour — no archive files ever appear.
func TestRotation_ZeroConfigDoesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLogger(path) // no rotation
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	for i := 0; i < 100; i++ {
		_ = logger.Log(logBlob("bot"))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "audit.jsonl" {
			t.Errorf("unexpected auxiliary file with rotation disabled: %s", e.Name())
		}
	}
}

// TestPruneArchives_StandaloneCall lets us exercise the prune logic without
// the time-based sleeps needed to force real rotations.
func TestPruneArchives_StandaloneCall(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")

	// Create 5 fake archives with distinct timestamps.
	timestamps := []string{
		"20260101T000000Z",
		"20260102T000000Z",
		"20260103T000000Z",
		"20260104T000000Z",
		"20260105T000000Z",
	}
	for _, ts := range timestamps {
		p := base + "." + ts
		if err := os.WriteFile(p, []byte("stub"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Also create a .gz to make sure it's counted.
	gzPath := base + ".20260106T000000Z.gz"
	if err := os.WriteFile(gzPath, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := pruneArchives(base, 2); err != nil {
		t.Fatalf("pruneArchives: %v", err)
	}

	remaining, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, e := range remaining {
		kept = append(kept, e.Name())
	}
	sort.Strings(kept)
	// Expected survivors: the two newest by lex order, which is the gz +
	// "20260105T000000Z".
	wantContains := []string{"audit.jsonl.20260105T000000Z", "audit.jsonl.20260106T000000Z.gz"}
	for _, w := range wantContains {
		found := false
		for _, k := range kept {
			if k == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to survive, got %v", w, kept)
		}
	}
	// Oldest four names should be gone.
	for _, removed := range []string{
		"audit.jsonl.20260101T000000Z",
		"audit.jsonl.20260102T000000Z",
		"audit.jsonl.20260103T000000Z",
		"audit.jsonl.20260104T000000Z",
	} {
		for _, k := range kept {
			if k == removed {
				t.Errorf("expected %q to be pruned, still present", removed)
			}
		}
	}
}

// TestPruneArchives_IgnoresUnrelatedFiles: a non-archive file in the same
// directory (e.g. the checkpoint) must never be touched.
func TestPruneArchives_IgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")

	unrelated := []string{
		"audit.jsonl.replay-checkpoint", // not a timestamp suffix
		"other.jsonl",
		"audit.jsonl",
	}
	for _, f := range unrelated {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("stub"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// One real archive.
	archive := base + ".20260101T000000Z"
	if err := os.WriteFile(archive, []byte("stub"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := pruneArchives(base, 0); err != nil {
		t.Fatalf("pruneArchives: %v", err)
	}
	// The archive should be gone (keep=0 means delete them all), the others
	// must survive.
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Errorf("expected archive to be pruned, stat: %v", err)
	}
	for _, f := range unrelated {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("unrelated file %q must not be pruned: %v", f, err)
		}
	}
}
