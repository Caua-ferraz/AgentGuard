package proxy

// Restart contract for the decision counters (review finding R3).
//
// "Stats survive restarts" means: after a restart the counters equal what a
// never-restarted process would show — every entry ever written, once. The
// counters are process-local, so a restart is simulated with metrics.Reset()
// between NewServer calls; only what is on disk (audit file, archives, the
// replay checkpoint) survives between boots, exactly as in production.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func ccEntry(agent string, d policy.Decision) audit.Entry {
	return audit.Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   agent,
		Request:   policy.ActionRequest{Scope: "shell", Command: "echo"},
		Result:    policy.CheckResult{Decision: d},
	}
}

// appendEntries writes n entries through a fresh FileLogger (append mode).
func appendEntries(t *testing.T, logPath, prefix string, n int, d policy.Decision) {
	t.Helper()
	l, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(ccEntry(fmt.Sprintf("%s-%d", prefix, i), d)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
}

// bootWith simulates one process lifetime: fresh counters, NewServer over
// the given logger, then shutdown.
func bootWith(t *testing.T, logger audit.Logger) {
	t.Helper()
	metrics.Reset()
	srv := NewServer(Config{
		Engine:   policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "x"}),
		Logger:   logger,
		Notifier: notify.NewDispatcher(policy.NotificationCfg{}),
		Version:  "test",
	})
	srv.Shutdown()
}

// bootFile is bootWith over a plain FileLogger on logPath.
func bootFile(t *testing.T, logPath string) {
	t.Helper()
	l, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatal(err)
	}
	bootWith(t, l)
	l.Close()
}

type counterSnapshot struct{ checks, allowed, denied, approval uint64 }

func snapshotCounters() counterSnapshot {
	return counterSnapshot{
		checks:   metrics.ChecksTotal(),
		allowed:  metrics.AllowedTotal(),
		denied:   metrics.DeniedTotal(),
		approval: metrics.ApprovalTotal(),
	}
}

func TestNewServer_CountersSurviveRestart_AppendBetweenBoots(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	appendEntries(t, logPath, "a", 3, policy.Allow)

	bootFile(t, logPath)
	if got := snapshotCounters(); got != (counterSnapshot{3, 3, 0, 0}) {
		t.Fatalf("boot 1 counters = %+v, want 3 allow", got)
	}

	// Run 1 writes more; run 2 must see the lifetime total.
	appendEntries(t, logPath, "d", 2, policy.Deny)
	appendEntries(t, logPath, "r", 1, policy.RequireApproval)
	bootFile(t, logPath)
	want := counterSnapshot{6, 3, 2, 1}
	if got := snapshotCounters(); got != want {
		t.Fatalf("boot 2 counters = %+v, want %+v (previous boot's tally + new entries)", got, want)
	}

	// Run 2 writes nothing; run 3 must neither forget nor double-count.
	bootFile(t, logPath)
	if got := snapshotCounters(); got != want {
		t.Fatalf("boot 3 counters = %+v, want %+v", got, want)
	}
}

func TestNewServer_CountersSurviveRestart_AcrossRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfg := audit.RotationConfig{MaxSize: 400, Compress: true}

	countArchives := func() int {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "audit.jsonl.") && !strings.Contains(e.Name(), audit.CheckpointSuffix) {
				n++
			}
		}
		return n
	}

	// Pre-phase through a plain logger so nothing rotates before boot 1
	// (a fresh install has no archives; that is the state being modelled).
	total := 2
	appendEntries(t, logPath, "pre", total, policy.Allow)
	if got := countArchives(); got != 0 {
		t.Fatalf("test setup: expected no archives before boot 1, found %d", got)
	}

	bootFile(t, logPath)
	if got := metrics.ChecksTotal(); got != uint64(total) {
		t.Fatalf("boot 1: ChecksTotal = %d, want %d", got, total)
	}

	// Run 1: rotate twice (archive names have 1s resolution) then a tail.
	l, err := audit.NewFileLoggerWithRotation(logPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for rot := 0; rot < 2; rot++ {
		time.Sleep(1100 * time.Millisecond)
		before := countArchives()
		for i := 0; i < 50 && countArchives() == before; i++ {
			if err := l.Log(ccEntry(fmt.Sprintf("rot%d-%d", rot, i), policy.Deny)); err != nil {
				t.Fatal(err)
			}
			total++
		}
		if countArchives() == before {
			t.Fatal("test setup: logger never rotated")
		}
	}
	// Archive names carry a one-second timestamp, and a rotation renames the
	// live file onto that name — so a tail that itself rotates inside the
	// same second would silently overwrite the archive just written and
	// break the rotated_from chain. Wait past that second first.
	time.Sleep(1100 * time.Millisecond)
	for i := 0; i < 2; i++ {
		if err := l.Log(ccEntry(fmt.Sprintf("tail-%d", i), policy.RequireApproval)); err != nil {
			t.Fatal(err)
		}
		total++
	}
	l.Close()

	bootFile(t, logPath)
	if got := metrics.ChecksTotal(); got != uint64(total) {
		t.Fatalf("boot 2 after rotation: ChecksTotal = %d, want %d (entries archived between boots must still count)", got, total)
	}
	if got := metrics.ApprovalTotal(); got != 2 {
		t.Errorf("boot 2: ApprovalTotal = %d, want 2", got)
	}

	bootFile(t, logPath)
	if got := metrics.ChecksTotal(); got != uint64(total) {
		t.Fatalf("boot 3: ChecksTotal = %d, want %d", got, total)
	}
}

// The production audit pipeline is a BufferedAsyncLogger over the
// FileLogger. This is the shape that never checkpointed before 1.0.1.
func TestNewServer_BufferedLoggerCheckpointsAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	appendEntries(t, logPath, "seed", 4, policy.Allow)

	bootBuffered := func() *audit.BufferedAsyncLogger {
		fl, err := audit.NewFileLogger(logPath)
		if err != nil {
			t.Fatal(err)
		}
		buf, err := audit.NewBufferedAsyncLogger(fl, audit.BufferedAsyncOpts{
			OverflowPath: filepath.Join(dir, "overflow.jsonl"), QueueSize: 16, Workers: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		bootWith(t, buf)
		t.Cleanup(func() { _ = buf.Close(); _ = fl.Close() })
		return buf
	}

	buf := bootBuffered()
	if got := metrics.ChecksTotal(); got != 4 {
		t.Fatalf("boot 1 (buffered): ChecksTotal = %d, want 4", got)
	}
	cp, err := audit.ReadCheckpoint(logPath)
	if err != nil || cp == nil || cp.Counts == nil {
		t.Fatalf("a buffered file-backed logger must produce a checkpoint with a tally, got cp=%+v err=%v", cp, err)
	}

	// Run 1 logs through the buffered path; Close drains to disk.
	for i := 0; i < 2; i++ {
		if err := buf.Log(ccEntry(fmt.Sprintf("run1-%d", i), policy.Deny)); err != nil {
			t.Fatal(err)
		}
	}
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}

	bootBuffered()
	if got := snapshotCounters(); got != (counterSnapshot{6, 4, 2, 0}) {
		t.Fatalf("boot 2 (buffered): counters = %+v, want 6 checks / 4 allow / 2 deny", got)
	}
}

// A checkpoint written by a pre-1.0.1 binary carries no tally. The first
// boot on the new binary must re-establish the lifetime totals rather than
// resume with zeroed counters.
func TestNewServer_LegacyCheckpointUpgradesToLifetimeCounts(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	appendEntries(t, logPath, "old", 5, policy.Allow)
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	legacy := fmt.Sprintf(`{"offset":%d,"audit_size":%d}`, info.Size(), info.Size())
	if err := os.WriteFile(audit.CheckpointPath(logPath), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	bootFile(t, logPath)
	if got := metrics.AllowedTotal(); got != 5 {
		t.Fatalf("upgrade boot: AllowedTotal = %d, want 5 (a legacy checkpoint must not zero the counters)", got)
	}
	cp, err := audit.ReadCheckpoint(logPath)
	if err != nil || cp == nil || cp.Counts == nil || cp.Counts.Total != 5 {
		t.Fatalf("upgrade boot must rewrite the checkpoint with a tally, got %+v err=%v", cp, err)
	}

	bootFile(t, logPath)
	if got := metrics.AllowedTotal(); got != 5 {
		t.Fatalf("post-upgrade boot: AllowedTotal = %d, want 5", got)
	}
}
