package audit

// Contract tests for the restart-safe startup replay (review finding R3).
//
// The contract: after any sequence of boots, appends, rotations and
// restarts, ReplayWithCheckpoint must (a) deliver every entry written since
// the previous checkpoint to fn exactly once — never an entry that was
// already checkpointed, never a missed one — and (b) return a lifetime
// decision tally equal to everything ever written. These tests assert that
// contract from the outside (unique agent ids per entry, set equality) and
// never inspect how the segments were planned.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func replayTestEntry(agent string, d policy.Decision) Entry {
	return Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   agent,
		Request:   policy.ActionRequest{Scope: "shell", Command: "echo " + agent},
		Result:    policy.CheckResult{Decision: d},
	}
}

// logNamed writes n entries with unique agent ids and returns those ids.
func logNamed(t *testing.T, l Logger, prefix string, n int, d policy.Decision) []string {
	t.Helper()
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%03d", prefix, i)
		if err := l.Log(replayTestEntry(name, d)); err != nil {
			t.Fatalf("Log %s: %v", name, err)
		}
		names = append(names, name)
	}
	return names
}

// replayAgents runs ReplayWithCheckpoint and returns the agent ids fn saw.
func replayAgents(t *testing.T, path string, cp *Checkpoint) ([]string, Checkpoint) {
	t.Helper()
	var seen []string
	next, err := ReplayWithCheckpoint(path, cp, func(e Entry) { seen = append(seen, e.AgentID) })
	if err != nil {
		t.Fatalf("ReplayWithCheckpoint: %v", err)
	}
	return seen, next
}

// persist round-trips a checkpoint through the on-disk JSON so every boot in
// a test sees exactly what a real next boot would read.
func persist(t *testing.T, path string, cp Checkpoint) *Checkpoint {
	t.Helper()
	if err := WriteCheckpoint(path, cp); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	got, err := ReadCheckpoint(path)
	if err != nil || got == nil {
		t.Fatalf("ReadCheckpoint: cp=%v err=%v", got, err)
	}
	return got
}

// assertSameSet fails unless got contains exactly the ids in want, each once.
func assertSameSet(t *testing.T, ctx string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s: replayed set mismatch\n got: %v\nwant: %v", ctx, g, w)
	}
}

func countArchives(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit.jsonl.") &&
			!strings.Contains(name, CheckpointSuffix) &&
			!strings.HasSuffix(name, ".v040-backup") {
			n++
		}
	}
	return n
}

// rotateOnce writes entries until the logger rotates exactly once.
func rotateOnce(t *testing.T, l *FileLogger, dir, prefix string, d policy.Decision) []string {
	t.Helper()
	before := countArchives(t, dir)
	var names []string
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("%s-%03d", prefix, i)
		if err := l.Log(replayTestEntry(name, d)); err != nil {
			t.Fatalf("Log: %v", err)
		}
		names = append(names, name)
		if countArchives(t, dir) > before {
			return names
		}
	}
	t.Fatalf("logger never rotated after %d entries", len(names))
	return nil
}

// --- first boot / resume / no-op boot --------------------------------------

func TestReplayWithCheckpoint_FirstBootCountsEverything(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	want := logNamed(t, l, "allow", 2, policy.Allow)
	want = append(want, logNamed(t, l, "deny", 1, policy.Deny)...)
	want = append(want, logNamed(t, l, "ra", 1, policy.RequireApproval)...)
	if err := l.Log(replayTestEntry("weird", policy.Decision("MAYBE"))); err != nil {
		t.Fatal(err)
	}
	want = append(want, "weird")
	l.Close()

	seen, next := replayAgents(t, path, nil)
	assertSameSet(t, "first boot", seen, want)
	if next.Counts == nil {
		t.Fatal("first boot must produce a tally")
	}
	if got := *next.Counts; got != (DecisionCounts{Total: 5, Allow: 2, Deny: 1, RequireApproval: 1}) {
		t.Errorf("counts = %+v", got)
	}
	if next.Counts.Other() != 1 {
		t.Errorf("Other() = %d, want 1 (the MAYBE decision)", next.Counts.Other())
	}
	if next.FileID == "" {
		t.Error("a schema-v2 file must yield a file identity")
	}
	info, _ := os.Stat(path)
	if next.Offset != info.Size() || next.AuditSize != info.Size() {
		t.Errorf("offset/size = %d/%d, want %d", next.Offset, next.AuditSize, info.Size())
	}
}

func TestReplayWithCheckpoint_ResumeSeesOnlyNewEntriesAndKeepsLifetimeCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	old := logNamed(t, l, "old", 4, policy.Allow)
	l.Close()

	_, cp1 := replayAgents(t, path, nil)

	// Run 1 writes more.
	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	fresh := logNamed(t, l2, "new", 3, policy.Deny)
	l2.Close()

	// Boot 2 resumes from the persisted checkpoint.
	seen2, cp2 := replayAgents(t, path, persist(t, path, cp1))
	assertSameSet(t, "boot 2", seen2, fresh)
	if cp2.Counts == nil || cp2.Counts.Total != uint64(len(old)+len(fresh)) ||
		cp2.Counts.Allow != 4 || cp2.Counts.Deny != 3 {
		t.Fatalf("boot 2 lifetime counts = %+v, want total=7 allow=4 deny=3", cp2.Counts)
	}

	// Boot 3 with nothing new: nothing replayed, tally unchanged (not
	// zeroed, not doubled).
	seen3, cp3 := replayAgents(t, path, persist(t, path, cp2))
	if len(seen3) != 0 {
		t.Errorf("boot 3 replayed %v; want nothing (would double-count on the counters)", seen3)
	}
	if *cp3.Counts != *cp2.Counts {
		t.Errorf("boot 3 counts %+v != boot 2 counts %+v", *cp3.Counts, *cp2.Counts)
	}
	if cp3.FileID != cp2.FileID {
		t.Errorf("file identity drifted between boots without a rotation: %q vs %q", cp3.FileID, cp2.FileID)
	}
}

// --- upgrade path ----------------------------------------------------------

// A checkpoint written by a pre-1.0.1 binary has an offset but no tally.
// Resuming from it would freeze the counters at "since last boot" forever;
// the contract is one full replay to establish the lifetime tally.
func TestReplayWithCheckpoint_LegacyCheckpointWithoutCountsTriggersFullReplay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	all := logNamed(t, l, "e", 6, policy.Allow)
	l.Close()
	info, _ := os.Stat(path)

	legacy := &Checkpoint{Offset: info.Size(), AuditSize: info.Size()}
	seen, next := replayAgents(t, path, persist(t, path, *legacy))
	assertSameSet(t, "legacy checkpoint", seen, all)
	if next.Counts == nil || next.Counts.Total != 6 {
		t.Fatalf("upgrade boot must establish the lifetime tally, got %+v", next.Counts)
	}
	if next.FileID == "" {
		t.Error("upgrade boot must stamp the file identity for the next boot")
	}

	// From here on it resumes normally.
	seen2, _ := replayAgents(t, path, persist(t, path, next))
	if len(seen2) != 0 {
		t.Errorf("second boot after upgrade replayed %v; want nothing", seen2)
	}
}

// --- rotation --------------------------------------------------------------

func TestReplayWithCheckpoint_FollowsRotationChain(t *testing.T) {
	cases := []struct {
		name      string
		compress  bool
		rotations int
	}{
		{"gzip-two-rotations", true, 2},
		{"plain-one-rotation", false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.jsonl")
			cfg := RotationConfig{MaxSize: 400, Compress: tc.compress}
			l, err := NewFileLoggerWithRotation(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			pre := logNamed(t, l, "pre", 1, policy.Allow)

			// Boot 1 checkpoints the first live file.
			_, cp1 := replayAgents(t, path, nil)
			if cp1.FileID == "" {
				t.Fatal("boot 1 must record the live file identity")
			}

			// Run 1 rotates the log tc.rotations times, then writes a tail
			// into the newest live file.
			var post []string
			for i := 0; i < tc.rotations; i++ {
				post = append(post, rotateOnce(t, l, dir, fmt.Sprintf("rot%d", i), policy.Deny)...)
			}
			// The tail may itself push the live file past MaxSize. That is
			// fine: the rotator gives a same-second rotation its own archive
			// name (see rotation_collision_test.go).
			post = append(post, logNamed(t, l, "tail", 2, policy.RequireApproval)...)
			l.Close()
			if got := countArchives(t, dir); got < tc.rotations {
				t.Fatalf("test setup: expected >= %d archives, found %d", tc.rotations, got)
			}
			if tc.compress {
				matches, _ := filepath.Glob(filepath.Join(dir, "audit.jsonl.*.gz"))
				if len(matches) == 0 {
					t.Fatal("test setup: expected gzip archives")
				}
			}

			// Boot 2: the live file is a different segment now. Every entry
			// written after the checkpoint must be replayed exactly once —
			// the ones that landed in the archived segment(s) included.
			seen2, cp2 := replayAgents(t, path, persist(t, path, cp1))
			assertSameSet(t, "boot 2 after rotation", seen2, post)
			wantTotal := uint64(len(pre) + len(post))
			if cp2.Counts == nil || cp2.Counts.Total != wantTotal {
				t.Fatalf("boot 2 lifetime total = %+v, want %d", cp2.Counts, wantTotal)
			}
			if cp2.FileID == cp1.FileID {
				t.Error("boot 2 must re-identify the new live file")
			}

			// Boot 3: nothing new; tally unchanged.
			seen3, cp3 := replayAgents(t, path, persist(t, path, cp2))
			if len(seen3) != 0 {
				t.Errorf("boot 3 replayed %v; want nothing", seen3)
			}
			if *cp3.Counts != *cp2.Counts {
				t.Errorf("boot 3 counts %+v != boot 2 counts %+v", *cp3.Counts, *cp2.Counts)
			}
		})
	}
}

// When the checkpointed segment was pruned, the entries it held after the
// checkpoint are gone for good; the contract is: never double-count the
// entries the checkpoint already tallied, replay every reachable newer
// segment from the start, and keep the carried tally.
func TestReplayWithCheckpoint_PrunedCheckpointSegmentStillCarriesCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 400})
	if err != nil {
		t.Fatal(err)
	}
	pre := logNamed(t, l, "pre", 1, policy.Allow)
	_, cp1 := replayAgents(t, path, nil)

	burst1 := rotateOnce(t, l, dir, "burst1", policy.Deny) // lands in the checkpointed segment
	burst2 := rotateOnce(t, l, dir, "burst2", policy.Deny) // lands in the middle archive
	tail := logNamed(t, l, "tail", 2, policy.Allow)        // newest live file
	l.Close()

	// Prune the archive boot 1 checkpointed (the oldest one).
	archives, _ := filepath.Glob(filepath.Join(dir, "audit.jsonl.*"))
	var names []string
	for _, a := range archives {
		if !strings.Contains(a, CheckpointSuffix) {
			names = append(names, a)
		}
	}
	sort.Strings(names)
	if len(names) < 2 {
		t.Fatalf("test setup: want 2 archives, got %v", names)
	}
	if err := os.Remove(names[0]); err != nil {
		t.Fatal(err)
	}

	seen, cp2 := replayAgents(t, path, persist(t, path, cp1))
	want := append(append([]string(nil), burst2...), tail...)
	assertSameSet(t, "reachable segments", seen, want)
	for _, s := range seen {
		for _, p := range pre {
			if s == p {
				t.Errorf("pre-checkpoint entry %q replayed again (double count)", s)
			}
		}
	}
	_ = burst1 // lost with the pruned archive — by design, documented
	if cp2.Counts == nil || cp2.Counts.Total != cp1.Counts.Total+uint64(len(want)) {
		t.Errorf("counts = %+v, want carried %d + reachable %d", cp2.Counts, cp1.Counts.Total, len(want))
	}
}

// --- legacy headerless live file -------------------------------------------

func writeHeaderlessLines(t *testing.T, path string, names []string, d policy.Decision) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, n := range names {
		if err := enc.Encode(replayTestEntry(n, d)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReplayWithCheckpoint_HeaderlessFileUsesSizeHeuristic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeHeaderlessLines(t, path, []string{"h-0", "h-1"}, policy.Allow)
	info, _ := os.Stat(path)

	// A checkpoint that tallied the two entries; no identity (headerless).
	cp := &Checkpoint{Offset: info.Size(), AuditSize: info.Size(),
		Counts: &DecisionCounts{Total: 2, Allow: 2}}

	writeHeaderlessLines(t, path, []string{"h-2"}, policy.Deny)
	seen, next := replayAgents(t, path, persist(t, path, *cp))
	assertSameSet(t, "grown headerless file", seen, []string{"h-2"})
	if next.Counts.Total != 3 || next.Counts.Deny != 1 {
		t.Errorf("counts = %+v", next.Counts)
	}
	if next.FileID != "" {
		t.Errorf("headerless file must not get an identity, got %q", next.FileID)
	}

	// Truncated below the checkpoint: full replay, carried tally kept.
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	writeHeaderlessLines(t, path, []string{"t-0"}, policy.Allow)
	seen2, next2 := replayAgents(t, path, persist(t, path, next))
	assertSameSet(t, "truncated headerless file", seen2, []string{"t-0"})
	if next2.Counts.Total != next.Counts.Total+1 {
		t.Errorf("truncation must not drop the carried tally: %+v", next2.Counts)
	}
}

// --- robustness ------------------------------------------------------------

func TestReplayWithCheckpoint_CorruptLineIsCountedAndSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(replayTestEntry("ok-0", policy.Allow)); err != nil {
		t.Fatal(err)
	}
	l.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{this is not json\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Log(replayTestEntry("ok-1", policy.Deny)); err != nil {
		t.Fatal(err)
	}
	l2.Close()

	before := metrics.AuditCorruptLinesTotal()
	seen, next := replayAgents(t, path, nil)
	assertSameSet(t, "corrupt line", seen, []string{"ok-0", "ok-1"})
	if got := metrics.AuditCorruptLinesTotal() - before; got != 1 {
		t.Errorf("corrupt-line counter moved by %d, want 1 (a torn line must be visible on /metrics)", got)
	}
	if next.Counts.Total != 2 {
		t.Errorf("counts = %+v, want 2 valid entries", next.Counts)
	}
}

func TestReplayFrom_CorruptLineBumpsMetricToo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte("not json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := metrics.AuditCorruptLinesTotal()
	if _, err := ReplayFrom(path, nil, func(Entry) { t.Error("fn must not see a corrupt line") }); err != nil {
		t.Fatalf("ReplayFrom: %v", err)
	}
	if got := metrics.AuditCorruptLinesTotal() - before; got != 1 {
		t.Errorf("corrupt-line counter moved by %d, want 1", got)
	}
}

func TestReplayWithCheckpoint_MissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	next, err := ReplayWithCheckpoint(filepath.Join(dir, "never.jsonl"), nil, func(Entry) {
		t.Error("fn must not be invoked for a missing file")
	})
	if err != nil {
		t.Errorf("missing file must not error: %v", err)
	}
	if next.Offset != 0 || next.Counts != nil {
		t.Errorf("missing file must yield a zero checkpoint, got %+v", next)
	}
}

// --- on-disk format --------------------------------------------------------

// The checkpoint gained two additive fields. A pre-1.0.1 checkpoint must
// still parse, and a checkpoint without the new fields must serialise to
// the exact bytes the old binary wrote (downgrade safety).
func TestCheckpoint_JSONIsBackwardAndForwardCompatible(t *testing.T) {
	var legacy Checkpoint
	if err := json.Unmarshal([]byte(`{"offset":5,"audit_size":5}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Offset != 5 || legacy.FileID != "" || legacy.Counts != nil {
		t.Errorf("legacy checkpoint parsed as %+v", legacy)
	}

	old, err := json.Marshal(Checkpoint{Offset: 1234, AuditSize: 1234})
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != `{"offset":1234,"audit_size":1234}` {
		t.Errorf("checkpoint without the new fields must keep the old shape, got %s", old)
	}

	full := Checkpoint{Offset: 9, AuditSize: 9, FileID: "2026-09-09T00:00:00.123456789Z",
		Counts: &DecisionCounts{Total: 3, Allow: 1, Deny: 1, RequireApproval: 1}}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var back Checkpoint
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.FileID != full.FileID || back.Counts == nil || *back.Counts != *full.Counts {
		t.Errorf("round trip lost data: %s -> %+v", b, back)
	}
}

// CheckpointPath is the single source of truth every reader and writer
// (server seeder, `agentguard migrate`, the v040 migration) must go
// through. Pin it to what WriteCheckpoint actually creates on disk.
func TestCheckpointPath_IsWhereWriteCheckpointWrites(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	if err := WriteCheckpoint(audit, Checkpoint{Offset: 1, AuditSize: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(CheckpointPath(audit)); err != nil {
		t.Errorf("CheckpointPath(%q) does not name the written file: %v", audit, err)
	}
	if got, want := CheckpointPath(audit), audit+CheckpointSuffix; got != want {
		t.Errorf("CheckpointPath = %q, want %q", got, want)
	}
	if got, stale := CheckpointPath(audit), filepath.Join(dir, ".replay-checkpoint"); got == stale {
		t.Errorf("CheckpointPath must not be the <dir>/.replay-checkpoint form the CLI once used")
	}
}

// --- production wiring -----------------------------------------------------

type replayNopLogger struct{}

func (replayNopLogger) Log(Entry) error                    { return nil }
func (replayNopLogger) Query(QueryFilter) ([]Entry, error) { return nil, nil }
func (replayNopLogger) Close() error                       { return nil }

// The production pipeline wraps the FileLogger in a BufferedAsyncLogger.
// The server keys its checkpoint off Path(); without forwarding, no
// production deployment ever checkpointed.
func TestBufferedAsyncLogger_PathForwardsToFileBackedLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fl, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := NewBufferedAsyncLogger(fl, BufferedAsyncOpts{OverflowPath: filepath.Join(dir, "overflow.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	if got := buf.Path(); got != path {
		t.Errorf("buffered Path() = %q, want %q", got, path)
	}
	_ = buf.Close()
	_ = fl.Close()

	nop, err := NewBufferedAsyncLogger(replayNopLogger{}, BufferedAsyncOpts{OverflowPath: filepath.Join(dir, "overflow2.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	if got := nop.Path(); got != "" {
		t.Errorf("buffered Path() over a non-file logger = %q, want \"\"", got)
	}
	_ = nop.Close()
}
