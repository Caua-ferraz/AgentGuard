package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// panicLogger is an underlying Logger that panics on a marker entry
// (AgentID "boom") and records every other entry. It exercises the
// safeUnderlyingLog recover barrier: a store-driver / MarshalJSON / close-race
// panic must be isolated to the entry, not the worker goroutine.
type panicLogger struct {
	mu      sync.Mutex
	entries []Entry
}

func (p *panicLogger) Log(e Entry) error {
	if e.AgentID == "boom" {
		panic("panicLogger: boom")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = append(p.entries, e)
	return nil
}

func (p *panicLogger) Query(QueryFilter) ([]Entry, error) { return nil, nil }
func (p *panicLogger) Close() error                       { return nil }

func (p *panicLogger) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// TestBufferedAsync_WorkerRecoversUnderlyingPanic verifies M1: a panic inside
// underlying.Log is recovered by the worker rather than aborting the whole
// process. The panicking entry must land in the overflow drop accounting
// (durable on disk), not vanish silently, and a subsequent normal entry must
// still be delivered — proving the worker survived.
func TestBufferedAsync_WorkerRecoversUnderlyingPanic(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")
	pl := &panicLogger{}

	b, err := NewBufferedAsyncLogger(pl, BufferedAsyncOpts{
		QueueSize:        16,
		Workers:          2,
		OverflowPath:     overflowPath,
		RecoveryInterval: 24 * time.Hour, // disable recovery so the spill stays on disk
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	// A panicking entry must not take the worker (or the process) down.
	boom := sampleEntry(0)
	boom.AgentID = "boom"
	if err := b.Log(boom); err != nil {
		t.Fatalf("Log(boom): %v", err)
	}

	// The panicking entry is routed to the overflow drop accounting rather
	// than vanishing silently.
	waitFor(t, 2*time.Second, func() bool { return b.DroppedToOverflow() >= 1 },
		"panicking entry lands in overflow drop accounting")

	// A subsequent normal entry is still delivered — the worker survived the
	// panic instead of dying.
	normal := sampleEntry(1) // AgentID "bot-1" (does not panic)
	if err := b.Log(normal); err != nil {
		t.Fatalf("Log(normal): %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return pl.count() >= 1 },
		"normal entry delivered after the panicking one")

	// The panicking entry is durable on disk (overflow), not lost. Read
	// before Close so the close-flush drain does not rename it out from under
	// us (that drain also re-panics on the entry and must not crash — the
	// second safeUnderlyingLog call site covers it).
	data, err := os.ReadFile(overflowPath)
	if err != nil {
		t.Fatalf("ReadFile overflow: %v", err)
	}
	if !strings.Contains(string(data), "boom") {
		t.Errorf("panicking entry not found in overflow file: %q", data)
	}

	// Close must not crash even though the overflow file still contains the
	// panicking entry (flushOverflowOnce re-invokes underlying.Log on it).
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
