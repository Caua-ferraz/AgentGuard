package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func entryWith(i int, d policy.Decision) Entry {
	e := sampleEntry(i)
	e.Result.Decision = d
	return e
}

// Rotation with MaxFiles=1 prunes almost every archive. The checkpoint the
// logger writes on each rotation and on Close must still carry the full
// lifetime tally, and a replay from it must reproduce that tally.
func TestFileLogger_CheckpointSurvivesPruning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLoggerWithRotation(path, RotationConfig{MaxSize: 2048, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if !l.EnableCheckpoints(DecisionCounts{}, info.Size()) {
		t.Fatal("EnableCheckpoints returned false")
	}
	want := DecisionCounts{}
	for i := 0; i < 300; i++ {
		d := []policy.Decision{policy.Allow, policy.Deny, policy.RequireApproval}[i%3]
		if err := l.Log(entryWith(i, d)); err != nil {
			t.Fatal(err)
		}
		want.add(d)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	archives, _ := filepath.Glob(path + ".2*")
	if len(archives) > 1 {
		t.Fatalf("expected pruning to keep at most 1 archive, found %d", len(archives))
	}

	cp, err := ReadCheckpoint(path)
	if err != nil || cp == nil || cp.Counts == nil {
		t.Fatalf("ReadCheckpoint = %+v, %v", cp, err)
	}
	if *cp.Counts != want {
		t.Errorf("checkpoint counts = %+v, want %+v", *cp.Counts, want)
	}
	next, err := ReplayWithCheckpoint(path, cp, func(Entry) {})
	if err != nil {
		t.Fatal(err)
	}
	if *next.Counts != want {
		t.Errorf("replayed counts = %+v, want %+v", *next.Counts, want)
	}
}

// Entries appended between the startup replay and EnableCheckpoints (an
// overflow drain, say) are counted from atOffset.
func TestFileLogger_EnableCheckpointsCountsEntriesSinceOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	for i := 0; i < 3; i++ {
		_ = l.Log(entryWith(i, policy.Deny))
	}
	l.EnableCheckpoints(DecisionCounts{Total: 10, Allow: 10}, info.Size())
	_ = l.Log(entryWith(9, policy.Allow))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	cp, err := ReadCheckpoint(path)
	if err != nil || cp == nil || cp.Counts == nil {
		t.Fatalf("ReadCheckpoint = %+v, %v", cp, err)
	}
	if want := (DecisionCounts{Total: 14, Allow: 11, Deny: 3}); *cp.Counts != want {
		t.Errorf("counts = %+v, want %+v", *cp.Counts, want)
	}
}
