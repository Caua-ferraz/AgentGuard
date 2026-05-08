package policy

// Hammers FilePolicyProvider with concurrent Watch / Get / file-mutation
// for 2 seconds and asserts:
//   - no panics
//   - no goroutine leak (NumGoroutine difference ≤ small constant)
//   - runs cleanly under -race
//
// Failure modes caught: a missing lock, a callback registry leak, or a
// stop function that does not actually unregister.

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// goroutineLeakBudget allows a small headroom for runtime-managed
// goroutines that exist asynchronously across test boundaries (GC,
// periodic preempts on Windows). The threshold is empirically loose; an
// actual goroutine leak from FilePolicyProvider would manifest as 10+
// extra goroutines per Watch call left behind.
const goroutineLeakBudget = 10

// TestATFilePolicyProvider_RaceWatchGetMutate hammers the provider with
// concurrent operations and verifies clean shutdown.
func TestATFilePolicyProvider_RaceWatchGetMutate(t *testing.T) {
	if testing.Short() {
		t.Skip("race scenario takes ~2s")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writeMinimalPolicy(t, path, "race-test-v0")

	prov, err := NewFilePolicyProvider(path)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}

	// Force GC + small settle so the goroutine baseline is meaningful.
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const watchers = 5
	const getters = 5
	const duration = 2 * time.Second

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var panicCount atomic.Int64

	// Watcher goroutines: register a Watch, hold for a bit, then call
	// the stop function. Repeat until the deadline.
	for i := 0; i < watchers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
					t.Errorf("watcher %d panicked: %v", id, r)
				}
			}()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cb := func(*Policy) {}
				stopFn, err := prov.Watch(LocalTenantID, cb)
				if err != nil {
					return // provider may be closed if shutdown ran early
				}
				// Hold the watcher briefly so a concurrent file mutation
				// has a chance to fire it.
				time.Sleep(10 * time.Millisecond)
				stopFn()
				// Calling stop twice must be safe.
				stopFn()
			}
		}(i)
	}

	// Getter goroutines: poll Get(local) and Get(unknown) tightly.
	for i := 0; i < getters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
					t.Errorf("getter %d panicked: %v", id, r)
				}
			}()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := prov.Get(LocalTenantID); err != nil {
					// A close race could surface ErrTenantNotFound; that's
					// the documented behavior, not a panic.
					_ = err
				}
				_, _ = prov.Get("nope") // exercises the unknown-tenant branch
			}
		}(i)
	}

	// Mutator goroutine: rewrite the policy file every 100ms.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				panicCount.Add(1)
				t.Errorf("mutator panicked: %v", r)
			}
		}()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		seq := 0
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				seq++
				body := []byte("version: \"1\"\nname: race-test-v" + itoa(seq) + "\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n")
				tmp := path + ".writing"
				if err := os.WriteFile(tmp, body, 0o600); err != nil {
					return
				}
				_ = os.Rename(tmp, path)
			}
		}
	}()

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	if got := panicCount.Load(); got != 0 {
		t.Fatalf("goroutines panicked: %d", got)
	}

	// Close the provider now that workers are done.
	if err := prov.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Force GC and let the runtime quiesce. The provider's watcher
	// goroutine should be gone after Close.
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	final := runtime.NumGoroutine()
	if delta := final - baseline; delta > goroutineLeakBudget {
		t.Errorf("goroutine leak suspected: baseline=%d final=%d delta=%d (budget=%d)",
			baseline, final, delta, goroutineLeakBudget)
	}
}

// itoa is a tiny stdlib-free helper to keep this test from importing
// strconv just for one call site (the file already pulls in plenty of
// stdlib without it).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
