package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// --- Test helpers ---

// captureLogger is an in-memory Logger used by the buffered tests. It
// records every entry passed to Log() under a mutex so tests can assert
// on the captured history. CaptureLogger.Log can be made to fail by
// flipping FailNext (single-shot) or AlwaysFail (sticky) — used by the
// "underlying failure → spill to overflow" test.
type captureLogger struct {
	mu          sync.Mutex
	entries     []Entry
	failNext    bool
	alwaysFail  bool
	delayPerLog time.Duration
	closeCalled bool
	queryFunc   func(QueryFilter) ([]Entry, error)
}

func (c *captureLogger) Log(e Entry) error {
	if c.delayPerLog > 0 {
		time.Sleep(c.delayPerLog)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.alwaysFail {
		return errors.New("captureLogger: alwaysFail")
	}
	if c.failNext {
		c.failNext = false
		return errors.New("captureLogger: failNext")
	}
	c.entries = append(c.entries, e)
	return nil
}

func (c *captureLogger) Query(f QueryFilter) ([]Entry, error) {
	if c.queryFunc != nil {
		return c.queryFunc(f)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Entry, len(c.entries))
	copy(cp, c.entries)
	return cp, nil
}

func (c *captureLogger) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCalled = true
	return nil
}

func (c *captureLogger) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// blockingLogger never returns from Log until Release() is called. Used
// by the saturation test to wedge the workers and force overflow.
type blockingLogger struct {
	gate     chan struct{}
	released atomic.Bool
}

func newBlockingLogger() *blockingLogger {
	return &blockingLogger{gate: make(chan struct{})}
}

func (b *blockingLogger) Log(e Entry) error {
	if !b.released.Load() {
		<-b.gate
	}
	return nil
}
func (b *blockingLogger) Query(QueryFilter) ([]Entry, error) { return nil, nil }
func (b *blockingLogger) Close() error                       { return nil }
func (b *blockingLogger) Release() {
	if b.released.CompareAndSwap(false, true) {
		close(b.gate)
	}
}

func sampleEntry(i int) Entry {
	return Entry{
		Timestamp: time.Now().UTC(),
		AgentID:   fmt.Sprintf("bot-%d", i),
		SessionID: fmt.Sprintf("sess-%d", i),
		Request:   policy.ActionRequest{Scope: "shell", Command: fmt.Sprintf("cmd-%d", i)},
		Result:    policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
	}
}

// waitFor polls cond every 10ms up to timeout. Used to assert eventual
// consistency on the worker drain without sleeping long fixed durations.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waitFor timed out (%s): %s", timeout, msg)
}

// --- Tests ---

func TestBufferedAsync_QueueAcceptsBelowCapacity(t *testing.T) {
	dir := t.TempDir()
	cap := &captureLogger{}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        100,
		Workers:          2,
		OverflowPath:     filepath.Join(dir, "overflow.jsonl"),
		RecoveryInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}
	defer b.Close()

	for i := 0; i < 10; i++ {
		if err := b.Log(sampleEntry(i)); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	waitFor(t, 2*time.Second, func() bool { return cap.Count() == 10 }, "all 10 entries reach underlying")

	if got := b.DroppedToOverflow(); got != 0 {
		t.Errorf("expected 0 dropped-to-overflow, got %d", got)
	}
}

func TestBufferedAsync_OverflowOnSaturation(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")
	blocker := newBlockingLogger()
	defer blocker.Release()

	// QueueSize=2, Workers=1; the worker pulls 1 entry and blocks inside
	// underlying.Log forever. The remaining capacity is 2 channel slots,
	// so the next 8 of 10 Log() calls hit the overflow path.
	b, err := NewBufferedAsyncLogger(blocker, BufferedAsyncOpts{
		QueueSize:        2,
		Workers:          1,
		OverflowPath:     overflowPath,
		RecoveryInterval: 24 * time.Hour, // disable recovery for this test
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	// Wait until the worker has actually pulled an entry from the queue
	// before pushing the rest, otherwise the channel may briefly hold all
	// 3 slots and we get a different overflow count than asserted.
	if err := b.Log(sampleEntry(0)); err != nil {
		t.Fatalf("Log(0): %v", err)
	}
	waitFor(t, time.Second, func() bool { return b.QueueDepth() == 0 }, "worker pulls first entry")

	for i := 1; i < 11; i++ {
		if err := b.Log(sampleEntry(i)); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	// Now: queue has 2 (slots 1,2), 8 went to overflow.
	if got := b.DroppedToOverflow(); got != 8 {
		t.Errorf("expected 8 dropped-to-overflow, got %d", got)
	}

	// Verify on disk: 8 lines.
	data, err := os.ReadFile(overflowPath)
	if err != nil {
		t.Fatalf("ReadFile overflow: %v", err)
	}
	lines := strings.Count(strings.TrimRight(string(data), "\n"), "\n") + 1
	if lines != 8 {
		t.Errorf("expected 8 overflow lines on disk, got %d (contents=%q)", lines, data)
	}

	// Release the worker and Close — overflow remains durable on disk.
	blocker.Release()
	_ = b.Close()
}

func TestBufferedAsync_RecoveryLoopDrains(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")

	// Pre-create overflow file with 5 entries.
	f, err := os.OpenFile(overflowPath, os.O_CREATE|os.O_WRONLY, DefaultFilePermissions)
	if err != nil {
		t.Fatalf("create overflow: %v", err)
	}
	enc := json.NewEncoder(f)
	for i := 0; i < 5; i++ {
		if err := enc.Encode(sampleEntry(i)); err != nil {
			t.Fatalf("encode pre-existing overflow: %v", err)
		}
	}
	f.Close()

	cap := &captureLogger{}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        16,
		Workers:          2,
		OverflowPath:     overflowPath,
		RecoveryInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}
	defer b.Close()

	waitFor(t, 5*time.Second, func() bool { return cap.Count() >= 5 }, "5 pre-existing entries reach underlying")

	if got := b.DrainedFromOverflow(); got < 5 {
		t.Errorf("expected DrainedFromOverflow >= 5, got %d", got)
	}

	// Overflow file should be gone after a successful drain (rename then
	// remove of the .draining sibling).
	if _, err := os.Stat(overflowPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected overflow file gone after drain, got stat err=%v", err)
	}
}

func TestBufferedAsync_CloseDoubleCallSafe(t *testing.T) {
	dir := t.TempDir()
	cap := &captureLogger{}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        4,
		Workers:          1,
		OverflowPath:     filepath.Join(dir, "overflow.jsonl"),
		RecoveryInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close MUST NOT panic on the closed channels.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestBufferedAsync_CloseDrainsQueue(t *testing.T) {
	dir := t.TempDir()
	cap := &captureLogger{}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        256,
		Workers:          4,
		OverflowPath:     filepath.Join(dir, "overflow.jsonl"),
		RecoveryInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	for i := 0; i < 100; i++ {
		if err := b.Log(sampleEntry(i)); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// After Close, all enqueued entries must have reached the underlying.
	if got := cap.Count(); got != 100 {
		t.Errorf("expected 100 entries in underlying after Close, got %d", got)
	}
}

func TestBufferedAsync_QueryPassthrough(t *testing.T) {
	dir := t.TempDir()
	called := false
	cap := &captureLogger{
		queryFunc: func(QueryFilter) ([]Entry, error) {
			called = true
			return []Entry{{AgentID: "from-underlying"}}, nil
		},
	}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        4,
		Workers:          1,
		OverflowPath:     filepath.Join(dir, "overflow.jsonl"),
		RecoveryInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}
	defer b.Close()

	got, err := b.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !called {
		t.Fatal("Query was not delegated to underlying.Query")
	}
	if len(got) != 1 || got[0].AgentID != "from-underlying" {
		t.Errorf("unexpected pass-through result: %+v", got)
	}
}

func TestBufferedAsync_ConcurrentLogAndClose(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")
	cap := &captureLogger{}
	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        64,
		Workers:          4,
		OverflowPath:     overflowPath,
		RecoveryInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	var wg sync.WaitGroup
	const writers = 8
	const perWriter = 200

	// We accept that some writes may race past Close into a closed channel.
	// Log must not panic; we recover and account for "lost" entries via the
	// underlying + overflow tally below.
	var raced atomic.Int64
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					raced.Add(1)
				}
			}()
			for i := 0; i < perWriter; i++ {
				if err := b.Log(sampleEntry(w*perWriter + i)); err != nil {
					// Don't fail the test — Log can legitimately error
					// only when both legs fail; record and continue.
					_ = err
				}
			}
		}(w)
	}

	// Trigger Close while writers are still running. Race detector watches
	// every shared field for concurrent writes.
	time.Sleep(5 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	underCount := cap.Count()

	overflowLines := 0
	if data, err := os.ReadFile(overflowPath); err == nil && len(data) > 0 {
		overflowLines = strings.Count(strings.TrimRight(string(data), "\n"), "\n") + 1
	}

	// Surviving entries are in either underlying or overflow. We do not
	// assert a strict total because Log calls that race past channel
	// closure are recovered + dropped — that is the documented Close
	// contract. We DO assert that Close did not crash and that we got
	// at least *some* progress.
	if underCount == 0 && overflowLines == 0 {
		t.Fatalf("expected some entries to survive, got 0 underlying + 0 overflow (raced=%d)", raced.Load())
	}
}

func TestBufferedAsync_AppendOverflowAtomic(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")
	blocker := newBlockingLogger()
	defer blocker.Release()

	// Tiny queue + blocked worker: every Log past the first one hits
	// overflow. Hammer with 8 goroutines × 50 entries each = 400 lines on
	// disk; if the per-line mutex is missing, concurrent json.Encode
	// calls will produce interleaved bytes and json.Unmarshal will fail.
	b, err := NewBufferedAsyncLogger(blocker, BufferedAsyncOpts{
		QueueSize:        1,
		Workers:          1,
		OverflowPath:     overflowPath,
		RecoveryInterval: 24 * time.Hour, // recovery disabled for this test
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	// Prime the worker so the channel is full.
	if err := b.Log(sampleEntry(0)); err != nil {
		t.Fatalf("Log(0): %v", err)
	}
	waitFor(t, time.Second, func() bool { return b.QueueDepth() == 0 }, "worker pulls primer")
	if err := b.Log(sampleEntry(1)); err != nil { // fills the slot
		t.Fatalf("Log(1): %v", err)
	}

	const goroutines = 8
	const perG = 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if err := b.Log(sampleEntry(g*perG + i + 100)); err != nil {
					t.Errorf("Log: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	// Read every overflow line back. Each must be valid JSON. If the
	// mutex is missing this fails immediately on a partially-interleaved
	// line.
	data, err := os.ReadFile(overflowPath)
	if err != nil {
		t.Fatalf("ReadFile overflow: %v", err)
	}
	for i, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if raw == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			t.Errorf("overflow line %d not valid JSON (mutex missing?): %q (err=%v)", i, raw, err)
		}
	}

	blocker.Release()
	_ = b.Close()
}

func TestBufferedAsync_UnderlyingFailureSpillsToOverflow(t *testing.T) {
	dir := t.TempDir()
	overflowPath := filepath.Join(dir, "overflow.jsonl")
	cap := &captureLogger{alwaysFail: true}

	b, err := NewBufferedAsyncLogger(cap, BufferedAsyncOpts{
		QueueSize:        16,
		Workers:          2,
		OverflowPath:     overflowPath,
		RecoveryInterval: 24 * time.Hour, // disable recovery so overflow stays put
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := b.Log(sampleEntry(i)); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}

	waitFor(t, 2*time.Second, func() bool { return b.DroppedToOverflow() >= 5 }, "5 entries spill on underlying failure")

	_ = b.Close()
}

func TestBufferedAsync_RejectsNilUnderlying(t *testing.T) {
	_, err := NewBufferedAsyncLogger(nil, BufferedAsyncOpts{
		OverflowPath: "ignored",
	})
	if err == nil {
		t.Fatal("expected nil-underlying error")
	}
}

func TestBufferedAsync_RejectsEmptyOverflowPath(t *testing.T) {
	_, err := NewBufferedAsyncLogger(&captureLogger{}, BufferedAsyncOpts{})
	if err == nil {
		t.Fatal("expected empty-overflow-path error")
	}
}
