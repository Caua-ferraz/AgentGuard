// Package audit — BufferedAsyncLogger.
//
// BufferedAsyncLogger wraps any audit.Logger with a bounded channel and a
// pool of N worker goroutines that drain the channel into the underlying
// Log call. The wrapper:
//
//   - Keeps the /v1/check hot path off the audit mutex: workers absorb
//     I/O latency; Log() returns after a channel send or overflow append.
//   - On saturation, persists entries to a JSON-Lines overflow file
//     (mode 0600); a recovery goroutine drains the overflow back into
//     the channel when capacity returns. Entries are durable across the
//     saturation boundary; they are NOT ordered across that boundary.
//   - Runs JSON encode + file write on workers, so the FileLogger.mu
//     hold shrinks to the actual encode+write.
//
// Concurrency contract:
//   - Log MUST NOT block. Path A: non-blocking channel send. Path B: append
//     a JSON line to the overflow file. Either path returns nil to the
//     caller. The only error Log can return is "queue full AND overflow
//     append failed" — both legs of durability gone.
//   - Close is idempotent (sync.Once). It closes the recovery goroutine's
//     stop channel, closes the work queue (workers drain remaining entries),
//     and then runs a one-shot best-effort overflow drain bounded by a
//     short timeout.
//   - The recovery goroutine runs at RecoveryInterval (default 5s). On each
//     tick it atomically renames the overflow file to a `.draining.<ts>`
//     sibling so concurrent Log() callers do not see partially drained
//     state, then reads each line, attempts a non-blocking enqueue, and
//     re-spills any line that would have blocked into a fresh overflow file.
//   - Counters are exposed via getters that return atomic loads. Callers see
//     a value at *some* point in time, not a snapshot across all three.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// Defaults for BufferedAsyncOpts. Tuned for "ten or so RPS sustained, bursts
// of a few hundred". Operators with heavier audit load should override via
// the CLI flags wired in cmd/agentguard/main.go.
const (
	defaultBufferedQueueSize        = 1024
	defaultBufferedWorkers          = 4
	defaultBufferedRecoveryInterval = 5 * time.Second
	// closeFlushTimeout bounds the best-effort final overflow drain run by
	// Close. We do not want shutdown to hang on a recovery cycle.
	closeFlushTimeout = 2 * time.Second
)

// BufferedAsyncOpts configures NewBufferedAsyncLogger.
//
// Zero values for QueueSize, Workers, and RecoveryInterval are replaced
// with documented defaults. OverflowPath is required — the caller picks the
// location (typically `<auditPath>.overflow.jsonl`) so the operator's
// retention/backup tooling sees the spill file alongside the live log.
type BufferedAsyncOpts struct {
	QueueSize        int           // default 1024 if 0
	Workers          int           // default 4   if 0
	OverflowPath     string        // required (caller derives, e.g. "<auditPath>.overflow.jsonl")
	RecoveryInterval time.Duration // default 5s if 0; mainly exposed for tests
}

// BufferedAsyncLogger wraps an underlying Logger with a bounded queue,
// worker pool, and disk-overflow spill path. See package doc for the
// concurrency contract.
type BufferedAsyncLogger struct {
	underlying Logger

	queue            chan Entry
	workers          int
	overflowPath     string
	recoveryInterval time.Duration

	// overflowMu serializes appends to the overflow file. JSON encoding is
	// not atomic across multiple workers writing the same fd — we keep this
	// mutex narrow (single Encode call) so it does not become a hot lock.
	overflowMu sync.Mutex

	closeOnce sync.Once
	closed    chan struct{} // closed by Close to signal recovery goroutine
	wg        sync.WaitGroup

	// metrics (atomic). The counters are observably-consistent — a getter
	// returns a value at some point in time, not a snapshot.
	droppedToOverflow   uint64
	drainedFromOverflow uint64
	queueDepthHint      int64
}

// NewBufferedAsyncLogger constructs a buffered async wrapper around
// underlying. The parent directory of OverflowPath is created if missing
// (mode 0700) so the operator does not have to pre-provision it.
func NewBufferedAsyncLogger(underlying Logger, opts BufferedAsyncOpts) (*BufferedAsyncLogger, error) {
	if underlying == nil {
		return nil, errors.New("audit: underlying logger is nil")
	}
	if opts.OverflowPath == "" {
		return nil, errors.New("audit: overflow path required")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultBufferedQueueSize
	}
	if opts.Workers <= 0 {
		opts.Workers = defaultBufferedWorkers
	}
	if opts.RecoveryInterval <= 0 {
		opts.RecoveryInterval = defaultBufferedRecoveryInterval
	}

	// Ensure the overflow file's parent directory exists. We use 0700
	// because the overflow file itself is 0600 and inherits the same
	// secrecy constraint as the live audit log.
	if dir := filepath.Dir(opts.OverflowPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("audit: mkdir overflow dir %s: %w", dir, err)
		}
	}

	b := &BufferedAsyncLogger{
		underlying:       underlying,
		queue:            make(chan Entry, opts.QueueSize),
		workers:          opts.Workers,
		overflowPath:     opts.OverflowPath,
		recoveryInterval: opts.RecoveryInterval,
		closed:           make(chan struct{}),
	}

	for i := 0; i < b.workers; i++ {
		b.wg.Add(1)
		go b.workerLoop()
	}
	b.wg.Add(1)
	go b.recoveryLoop()

	return b, nil
}

// Log enqueues an entry for async write. Never blocks: on saturation the
// entry is appended to the overflow file and dropToOverflow is incremented.
// Returns an error only when both legs of durability fail (queue full AND
// overflow append failed), which means the entry is lost.
//
// After Close has been called, Log spills directly to the overflow file
// rather than touching the (now-closed) queue. This is the documented
// behavior for the racy "Log called concurrently with Close" path: the
// entry is durable on disk and a future process startup will pick it up
// (once the recovery loop is reinstated, which is the operator's
// restart-the-binary remediation).
func (b *BufferedAsyncLogger) Log(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Guard against the channel being closed between our select-check and
	// the actual send. A send on a closed channel panics; close happens
	// inside Close() under sync.Once. Reading b.closed first means we
	// short-circuit through the overflow path during/after shutdown.
	select {
	case <-b.closed:
		// Closed: the queue is either already closed or about to be.
		// Persist directly to disk so the entry is not lost.
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: closed and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	default:
	}

	select {
	case b.queue <- e:
		b.noteQueueDepth(1)
		return nil
	case <-b.closed:
		// Lost a race with Close after the first guard. Spill to disk.
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: closed and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	default:
		// Saturation. Persist to disk; never block.
		if err := b.appendOverflow(e); err != nil {
			return fmt.Errorf("buffered audit: queue full and overflow append failed: %w", err)
		}
		b.noteDroppedToOverflow()
		return nil
	}
}

// Query passes through to the underlying logger. Entries currently in the
// overflow spill file are NOT yet visible to the index; the recovery
// goroutine closes that gap within RecoveryInterval.
func (b *BufferedAsyncLogger) Query(filter QueryFilter) ([]Entry, error) {
	return b.underlying.Query(filter)
}

// Close drains the queue and stops all goroutines. Safe to call multiple
// times (sync.Once). Close also runs a one-shot best-effort overflow
// drain bounded by closeFlushTimeout so a small backlog at shutdown still
// reaches the underlying logger.
//
// Close does NOT close the underlying logger — the caller owns that
// lifecycle (typically `defer logger.Close()` in cmd/agentguard/main.go,
// after the buffered wrapper's defer fires).
//
// We DO NOT close b.queue: with concurrent Log() callers in flight, a
// `close(channel)` would race a `chansend`. Instead we signal shutdown
// via b.closed and let workers exit on a `select` that picks up either
// a queued entry or the close signal. Log() also reads b.closed first
// and routes to the overflow file once shutdown has begun.
func (b *BufferedAsyncLogger) Close() error {
	b.closeOnce.Do(func() {
		close(b.closed) // tell workers + recoveryLoop to exit after draining
		b.wg.Wait()
		b.flushOverflowOnce(closeFlushTimeout)
	})
	return nil
}

// QueueDepth returns the approximate number of entries sitting in the
// in-memory queue. Returned value is an atomic load of an int64 counter
// maintained by Log() / workerLoop(); it can briefly drift past the
// channel's actual len at a few hundred RPS but converges quickly.
func (b *BufferedAsyncLogger) QueueDepth() int {
	return int(atomic.LoadInt64(&b.queueDepthHint))
}

// DroppedToOverflow returns the lifetime count of entries that were spilled
// to the overflow file because the queue was full or the underlying Log
// call returned an error.
func (b *BufferedAsyncLogger) DroppedToOverflow() uint64 {
	return atomic.LoadUint64(&b.droppedToOverflow)
}

// DrainedFromOverflow returns the lifetime count of entries the recovery
// goroutine successfully pushed back into the queue from the overflow
// file.
func (b *BufferedAsyncLogger) DrainedFromOverflow() uint64 {
	return atomic.LoadUint64(&b.drainedFromOverflow)
}

// noteQueueDepth adjusts the queue-depth hint and mirrors the new value
// to the agentguard_audit_buffered_queue_depth gauge.
func (b *BufferedAsyncLogger) noteQueueDepth(delta int64) {
	metrics.SetAuditBufferedQueueDepth(atomic.AddInt64(&b.queueDepthHint, delta))
}

// noteDroppedToOverflow counts a spill on both the instance counter and
// the agentguard_audit_buffered_dropped_to_overflow_total series.
func (b *BufferedAsyncLogger) noteDroppedToOverflow() {
	atomic.AddUint64(&b.droppedToOverflow, 1)
	metrics.IncAuditBufferedDroppedToOverflow()
}

// workerLoop drains the queue into the underlying logger. On underlying
// failure it falls back to the overflow path so the entry is still
// durable; this is the same recovery guarantee Log() makes for queue
// saturation.
//
// Shutdown semantics: when b.closed is closed, the worker keeps pulling
// any entries already buffered in the queue (drain-on-close), then exits
// once the queue is empty. We never close b.queue itself — that would
// race concurrent Log() sends — so this drain check uses a non-blocking
// receive after observing the closed signal.
func (b *BufferedAsyncLogger) workerLoop() {
	defer b.wg.Done()
	for {
		select {
		case entry := <-b.queue:
			b.noteQueueDepth(-1)
			b.processEntry(entry)
		case <-b.closed:
			// Drain anything still in the channel, then exit.
			for {
				select {
				case entry := <-b.queue:
					b.noteQueueDepth(-1)
					b.processEntry(entry)
				default:
					return
				}
			}
		}
	}
}

// processEntry runs the underlying.Log call and falls back to the overflow
// path on failure. Pulled out of workerLoop so the drain-on-close inner
// loop can call the same code without duplicating the body.
func (b *BufferedAsyncLogger) processEntry(entry Entry) {
	if err := b.safeUnderlyingLog(entry); err != nil {
		log.Printf("WARN audit buffered: underlying log failed: %v (writing to overflow)", err)
		if oerr := b.appendOverflow(entry); oerr != nil {
			log.Printf("ERROR audit buffered: underlying log AND overflow append failed: underlying=%v overflow=%v", err, oerr)
			return
		}
		b.noteDroppedToOverflow()
	}
}

// safeUnderlyingLog invokes b.underlying.Log behind a recover barrier so a
// panic in a store driver, a custom Entry MarshalJSON, or a nil-handle close
// race cannot escape the worker goroutine and abort the whole process.
// CLAUDE.md §2 requires "a flush worker crash must never block or crash the
// proxy loop"; an unrecovered goroutine panic would violate that.
//
// A recovered panic is converted into an error so it flows into the SAME
// overflow-fallback path an ordinary Log error takes at both call sites
// (processEntry and flushOverflowOnce): the entry stays durable and the
// worker keeps draining. This mirrors pkg/notify's workerWithRecover, which
// isolates panics from custom notifiers the same way.
func (b *BufferedAsyncLogger) safeUnderlyingLog(entry Entry) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("PANIC audit buffered: underlying log panicked: %v (routing entry to overflow)", rec)
			err = fmt.Errorf("underlying log panicked: %v", rec)
		}
	}()
	return b.underlying.Log(entry)
}

// appendOverflow writes a single entry as a JSON line to the overflow file
// in O_APPEND mode (mode 0600). Concurrent appends are serialized by
// overflowMu so workers and the saturation path do not produce interleaved
// bytes.
func (b *BufferedAsyncLogger) appendOverflow(e Entry) error {
	b.overflowMu.Lock()
	defer b.overflowMu.Unlock()

	f, err := os.OpenFile(b.overflowPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return fmt.Errorf("open overflow %s: %w", b.overflowPath, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(e); err != nil {
		return fmt.Errorf("encode overflow entry: %w", err)
	}
	return nil
}

// recoveryLoop periodically attempts to drain the overflow file back into
// the in-memory queue. Exits cleanly when b.closed is closed.
func (b *BufferedAsyncLogger) recoveryLoop() {
	defer b.wg.Done()
	t := time.NewTimer(b.recoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-b.closed:
			return
		case <-t.C:
			b.tryDrainOverflow()
			t.Reset(b.recoveryInterval)
		}
	}
}

// tryDrainOverflow renames the overflow file to a `.draining.<ts>` sibling
// (atomic on POSIX), reads each line, and attempts a non-blocking enqueue
// onto the work queue. Lines that would have blocked are re-spilled into a
// fresh overflow file so the next tick can try again.
//
// We rename rather than read-and-truncate so concurrent Log() saturation
// appends always target the live overflow path; a rename leaves the live
// path open for a fresh file (created lazily by appendOverflow) and the
// drain works against an immutable snapshot.
func (b *BufferedAsyncLogger) tryDrainOverflow() {
	// Take overflowMu to serialize against appendOverflow; the rename is
	// fast enough that this does not meaningfully delay saturation writes.
	b.overflowMu.Lock()
	if _, err := os.Stat(b.overflowPath); err != nil {
		b.overflowMu.Unlock()
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("WARN audit buffered: stat overflow %s: %v", b.overflowPath, err)
		}
		return
	}
	drainingPath := fmt.Sprintf("%s.draining.%d", b.overflowPath, time.Now().UTC().UnixNano())
	if err := os.Rename(b.overflowPath, drainingPath); err != nil {
		b.overflowMu.Unlock()
		log.Printf("WARN audit buffered: rename overflow %s -> %s: %v", b.overflowPath, drainingPath, err)
		return
	}
	b.overflowMu.Unlock()

	// Read the snapshot, try to enqueue each entry. Re-spill on full.
	in, err := os.Open(drainingPath)
	if err != nil {
		log.Printf("WARN audit buffered: open draining %s: %v", drainingPath, err)
		return
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var requeued uint64
	var respilled int
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			// Corrupt overflow line. Skip — same posture FileLogger.Query
			// takes for corrupt audit lines.
			log.Printf("WARN audit buffered: skipping corrupt overflow line in %s (%v)", drainingPath, err)
			continue
		}

		select {
		case b.queue <- entry:
			b.noteQueueDepth(1)
			requeued++
		default:
			// Queue full again. Re-spill into a fresh overflow file. We do
			// not block; the next recovery tick will pick it up.
			if err := b.appendOverflow(entry); err != nil {
				log.Printf("ERROR audit buffered: re-spill failed: %v (entry lost)", err)
				continue
			}
			respilled++
		}
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		log.Printf("WARN audit buffered: scan draining %s: %v", drainingPath, scanErr)
	}
	// Close the read handle BEFORE os.Remove so Windows lets the unlink
	// through (Windows refuses to remove a file open in the current
	// process; POSIX is permissive but we close anyway for tidiness).
	if cerr := in.Close(); cerr != nil {
		log.Printf("WARN audit buffered: close draining %s: %v", drainingPath, cerr)
	}

	// On scanner error (e.g. line larger than the 4 MiB buffer, or a
	// truncated read) we MUST NOT remove drainingPath: the unread tail
	// would be silently lost. The rename above already swapped a fresh
	// overflow file in for concurrent appendOverflow callers, so the
	// safe recovery posture is to rename the draining file BACK to
	// b.overflowPath so the next recovery tick (or process startup)
	// picks it up. If a fresh overflow file has appeared in the meantime
	// (concurrent saturation during this drain) we keep the draining
	// file in place under its `.draining.<ts>` name; an operator must
	// inspect / merge it manually, but the entries are durable on disk.
	if scanErr != nil {
		b.overflowMu.Lock()
		_, statErr := os.Stat(b.overflowPath)
		if errors.Is(statErr, os.ErrNotExist) {
			if rerr := os.Rename(drainingPath, b.overflowPath); rerr != nil {
				log.Printf("WARN audit buffered: re-spill rename %s -> %s after scan error: %v (preserving %s)",
					drainingPath, b.overflowPath, rerr, drainingPath)
			} else {
				log.Printf("WARN audit buffered: preserved partial drain by renaming %s -> %s for next tick", drainingPath, b.overflowPath)
			}
		} else {
			// A fresh overflow already exists; leave the draining file
			// in place under its timestamped name. Operator-recoverable.
			log.Printf("WARN audit buffered: leaving %s on disk after scanner error (fresh overflow already exists)", drainingPath)
		}
		b.overflowMu.Unlock()
	} else if err := os.Remove(drainingPath); err != nil {
		log.Printf("WARN audit buffered: remove draining %s: %v", drainingPath, err)
	}

	if requeued > 0 {
		atomic.AddUint64(&b.drainedFromOverflow, requeued)
		metrics.AddAuditBufferedDrainedFromOverflow(requeued)
	}
	if respilled > 0 {
		log.Printf("INFO audit buffered: re-spilled %d entries (queue still saturated)", respilled)
	}
}

// flushOverflowOnce is a one-shot drain attempt run by Close. Bounded by
// timeout so shutdown does not hang on a stuck rename or a slow disk.
//
// We are deliberately conservative here: at this point workers are already
// gone, so enqueueing into b.queue is pointless — instead we forward each
// surviving overflow entry directly to the underlying logger. Any entry
// that the underlying refuses is left in a re-spilled overflow file for
// the next process to pick up on startup.
func (b *BufferedAsyncLogger) flushOverflowOnce(timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	b.overflowMu.Lock()
	if _, err := os.Stat(b.overflowPath); err != nil {
		b.overflowMu.Unlock()
		return
	}
	drainingPath := fmt.Sprintf("%s.draining.close.%d", b.overflowPath, time.Now().UTC().UnixNano())
	if err := os.Rename(b.overflowPath, drainingPath); err != nil {
		b.overflowMu.Unlock()
		log.Printf("WARN audit buffered: close-flush rename: %v", err)
		return
	}
	b.overflowMu.Unlock()

	in, err := os.Open(drainingPath)
	if err != nil {
		log.Printf("WARN audit buffered: close-flush open draining: %v", err)
		return
	}

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	timedOut := false
	for scanner.Scan() {
		if time.Now().After(deadline) {
			timedOut = true
			break
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if err := b.safeUnderlyingLog(entry); err != nil {
			// Best-effort: re-spill into a fresh overflow file. safeUnderlyingLog
			// also absorbs a panicking underlying so the close-flush drain
			// cannot crash on the way out.
			_ = b.appendOverflow(entry)
		}
	}
	// Close the read handle BEFORE rename/remove. On Windows the file
	// cannot be removed or renamed while it is still open in this
	// process, so deferring Close until function exit (the original
	// posture) reliably failed there.
	if cerr := in.Close(); cerr != nil {
		log.Printf("WARN audit buffered: close-flush close draining: %v", cerr)
	}

	if timedOut {
		// Remaining lines stay durable on disk: rename the partially
		// processed draining file back into place so the next process
		// restart picks up where we left off.
		if rerr := os.Rename(drainingPath, b.overflowPath); rerr != nil {
			log.Printf("WARN audit buffered: close-flush re-spill rename: %v", rerr)
		}
		return
	}
	if err := os.Remove(drainingPath); err != nil {
		log.Printf("WARN audit buffered: close-flush remove draining: %v", err)
	}
}

// The notifier-side counterpart of this overflow design lives in
// pkg/notify (DispatcherOptions.SpoolPath / --notify-spool).
