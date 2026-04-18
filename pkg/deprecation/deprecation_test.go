package deprecation

import (
	"bytes"
	"log"
	"sync"
	"testing"
)

func TestWarn_LogsOncePerFeature(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	Warn("test.feature_a", "deprecated in vX, removed in vY")
	Warn("test.feature_a", "deprecated in vX, removed in vY")
	Warn("test.feature_a", "deprecated in vX, removed in vY")

	out := buf.String()
	// First call logs; subsequent calls do not.
	if got := bytes.Count([]byte(out), []byte("deprecation feature=test.feature_a")); got != 1 {
		t.Fatalf("expected exactly 1 log line for feature_a, got %d; output=%q", got, out)
	}
}

func TestWarn_SeparateKeysLogSeparately(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	Warn("test.feature_a", "msg")
	Warn("test.feature_b", "msg")
	Warn("test.feature_a", "msg")

	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("feature=test.feature_a")) {
		t.Errorf("feature_a not logged: %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("feature=test.feature_b")) {
		t.Errorf("feature_b not logged: %q", out)
	}
}

func TestWarn_CountIncrementsEveryCall(t *testing.T) {
	Reset()
	for i := 0; i < 5; i++ {
		Warn("test.counter", "msg")
	}
	if got := Count("test.counter"); got != 5 {
		t.Fatalf("Count = %d, want 5", got)
	}
}

func TestCount_UnknownFeatureReturnsZero(t *testing.T) {
	Reset()
	if got := Count("never.used"); got != 0 {
		t.Fatalf("Count(unknown) = %d, want 0", got)
	}
}

func TestSnapshot_CopiesState(t *testing.T) {
	Reset()
	Warn("test.snap_a", "msg")
	Warn("test.snap_a", "msg")
	Warn("test.snap_b", "msg")

	snap := Snapshot()
	if snap["test.snap_a"] != 2 {
		t.Errorf("snap[snap_a] = %d, want 2", snap["test.snap_a"])
	}
	if snap["test.snap_b"] != 1 {
		t.Errorf("snap[snap_b] = %d, want 1", snap["test.snap_b"])
	}

	// Mutating the returned map must not affect internal state.
	snap["test.snap_a"] = 999
	if Count("test.snap_a") != 2 {
		t.Errorf("internal state leaked through Snapshot copy")
	}
}

func TestWarn_ConcurrentSafe(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const workers = 32
	const perWorker = 1000

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				Warn("test.concurrent", "msg")
			}
		}()
	}
	wg.Wait()

	if got, want := Count("test.concurrent"), uint64(workers*perWorker); got != want {
		t.Fatalf("Count = %d, want %d (lost increments under concurrency)", got, want)
	}
	// Exactly one log line regardless of concurrency.
	if got := bytes.Count(buf.Bytes(), []byte("feature=test.concurrent")); got != 1 {
		t.Fatalf("expected exactly 1 log line under concurrency, got %d", got)
	}
}
