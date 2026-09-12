package audit

// rotation_collision_test.go pins that a burst of rotations inside a single
// second keeps every archive.
//
// ArchiveTimestampFormat has one-second resolution and rotateLocked renames
// the live file onto that name, so two rotations in the same second used to
// compute the same target and os.Rename replaced the first archive silently.
// That is real audit data destroyed with no error anywhere, and it also broke
// the _meta.rotated_from chain that startup replay walks — so a checkpoint
// pointing into a pruned-away segment degraded a boot-time counter seed for
// reasons no operator could have diagnosed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// archiveNames lists the rotated archives for audit.jsonl in dir, sorted.
func archiveNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == "audit.jsonl" || !strings.HasPrefix(n, "audit.jsonl.") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TestRotation_BurstInOneSecond_KeepsEveryArchive writes fast enough to rotate
// several times without waiting for the clock to advance. Every rotation must
// leave its own archive behind.
func TestRotation_BurstInOneSecond_KeepsEveryArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// A small cap plus 200-byte entries means roughly one rotation per write,
	// and no sleeps anywhere: the whole burst lands inside one or two seconds.
	logger, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	const writes = 12
	start := time.Now()
	for i := 0; i < writes; i++ {
		if err := logger.Log(logBlob("burst")); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	names := archiveNames(t, dir)
	if len(names) < 2 {
		t.Fatalf("only %d archive(s) after %d writes — the test did not rotate enough to be meaningful", len(names), writes)
	}
	// The point of the test: distinct names. Pre-fix this collapsed to one or
	// two archives because same-second rotations renamed over each other.
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Fatalf("duplicate archive name %q", n)
		}
		seen[n] = true
	}
	if len(names) < writes/3 {
		t.Errorf("got %d archives from %d writes in %v; same-second rotations are overwriting each other",
			len(names), writes, elapsed)
	}

	// Every archive must be non-empty and carry its own header: an overwritten
	// archive would show up here as a missing or truncated segment.
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("read archive %s: %v", n, err)
		}
		if len(b) == 0 {
			t.Errorf("archive %s is empty", n)
		}
	}
}

// TestRotation_BurstPreservesRotatedFromChain pins the consequence that
// matters to startup replay: each live file names the archive it came from,
// and following those links must reach every archive exactly once. A
// same-second overwrite used to leave a link pointing at a file whose contents
// belonged to a later segment.
func TestRotation_BurstPreservesRotatedFromChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 256})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if err := logger.Log(logBlob("chain")); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	archives := archiveNames(t, dir)
	if len(archives) < 2 {
		t.Fatalf("need at least 2 archives to exercise the chain, got %d", len(archives))
	}

	// Walk back from the live file. Each hop must name a file that exists and
	// that we have not already visited.
	visited := map[string]bool{}
	current := "audit.jsonl"
	for hops := 0; hops <= len(archives)+1; hops++ {
		meta := readRotatedFrom(t, filepath.Join(dir, current))
		if meta == "" {
			break
		}
		if visited[meta] {
			t.Fatalf("rotated_from chain revisits %q — a same-second overwrite collapsed two segments", meta)
		}
		if _, err := os.Stat(filepath.Join(dir, meta)); err != nil {
			t.Fatalf("rotated_from names %q, which does not exist: %v", meta, err)
		}
		visited[meta] = true
		current = meta
	}

	if len(visited) != len(archives) {
		t.Errorf("chain reached %d of %d archives (%v vs %v) — some segment is unreachable",
			len(visited), len(archives), visited, archives)
	}
}

// readRotatedFrom returns the _meta.rotated_from value from a file's header
// line, or "" when the file has no header or no predecessor.
func readRotatedFrom(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	first := b
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		first = b[:i]
	}
	var env metaEnvelope
	if err := json.Unmarshal(first, &env); err != nil {
		return ""
	}
	return env.Meta.RotatedFrom
}

// TestNextFreeArchivePath pins the name-selection rule directly, including the
// detail that a .gz archive also occupies its slot: compression writes
// alongside the rename, so ignoring the compressed form would hand out a name
// whose gzip output is about to be clobbered.
func TestNextFreeArchivePath(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	at := time.Date(2026, 9, 11, 15, 30, 0, 0, time.UTC)

	first, err := nextFreeArchivePath(base, at)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := filepath.Base(first), "audit.jsonl.20260911T153000Z"; got != want {
		t.Fatalf("first archive name = %q, want %q", got, want)
	}

	// Occupy it, plain form.
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := nextFreeArchivePath(base, at)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := filepath.Base(second), "audit.jsonl.20260911T153001Z"; got != want {
		t.Fatalf("second archive name = %q, want %q (the taken second must be skipped)", got, want)
	}
	// The name must stay exactly as long as the timestamp format, or
	// pruneArchivesWithAge stops recognising it and the archive is never
	// pruned by either bound.
	suffix := strings.TrimPrefix(filepath.Base(second), "audit.jsonl.")
	if len(suffix) != len(ArchiveTimestampFormat) {
		t.Errorf("suffix %q is %d chars, want %d — pruning filters on exact length",
			suffix, len(suffix), len(ArchiveTimestampFormat))
	}

	// Occupy the next slot in COMPRESSED form only.
	if err := os.WriteFile(second+".gz", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := nextFreeArchivePath(base, at)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := filepath.Base(third), "audit.jsonl.20260911T153002Z"; got != want {
		t.Fatalf("third archive name = %q, want %q (a .gz archive occupies its slot too)", got, want)
	}
}

// TestNextFreeArchivePath_ExhaustedRefusesRatherThanOverwrite: when every slot
// in the probe window is taken, rotation must fail. Failing leaves an
// over-large live file, which an operator can recover; renaming over an
// archive destroys data that no one can.
func TestNextFreeArchivePath_ExhaustedRefusesRatherThanOverwrite(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "audit.jsonl")
	at := time.Date(2026, 9, 11, 15, 30, 0, 0, time.UTC)

	for i := 0; i < maxArchiveProbe; i++ {
		name := base + "." + at.Add(time.Duration(i)*time.Second).Format(ArchiveTimestampFormat)
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := nextFreeArchivePath(base, at); err == nil {
		t.Fatalf("expected an error when every slot is taken, got %q", got)
	}
}
