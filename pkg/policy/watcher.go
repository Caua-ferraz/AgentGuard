package policy

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultPollInterval is the fallback poll cadence used when fsnotify cannot
// be initialised (e.g. inotify exhaustion, unsupported filesystem). fsnotify
// is preferred because it reacts immediately to atomic-replace edits; polling
// is bounded-latency but imposes real wall-clock delay between `kubectl
// apply` and the Guard noticing the new policy.
const DefaultPollInterval = 2 * time.Second

// FileWatcher watches a policy file for changes and triggers a callback.
// It prefers event-driven fsnotify; if fsnotify fails to initialise the
// watcher falls back to modtime polling at DefaultPollInterval.
//
// Atomic-replace awareness: editors and `mv` replace a file by unlinking
// and renaming, which invalidates an inotify watch on the path itself.
// The watcher therefore watches the *parent directory* and filters events
// by basename, so `atomic replace` reliably triggers a reload.
type FileWatcher struct {
	path     string
	callback func(*Policy)

	mu      sync.Mutex
	modTime time.Time

	done chan struct{}
	once sync.Once
}

// WatchFile starts watching a policy file for changes. An initial Stat
// failure returns an error up-front so callers can surface misconfiguration
// (missing file) at boot; transient errors inside the watch goroutine are
// logged and do not tear the watcher down.
func WatchFile(path string, callback func(*Policy)) (*FileWatcher, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	w := &FileWatcher{
		path:     path,
		callback: callback,
		modTime:  info.ModTime(),
		done:     make(chan struct{}),
	}

	// Preferred path: event-driven via fsnotify. Watch the parent dir so
	// atomic-replace rewrites (editor save, `mv tmp policy.yaml`) do not
	// silently leave us watching a dangling inode.
	notify, err := fsnotify.NewWatcher()
	if err == nil {
		if addErr := notify.Add(filepath.Dir(path)); addErr == nil {
			go w.watchFS(notify)
			return w, nil
		} else {
			// Adding the directory failed — close the watcher and fall through
			// to polling. Don't leak the fd.
			_ = notify.Close()
			log.Printf("policy watcher: fsnotify Add(%s) failed (%v); falling back to %s polling",
				filepath.Dir(path), addErr, DefaultPollInterval)
		}
	} else {
		log.Printf("policy watcher: fsnotify unavailable (%v); falling back to %s polling",
			err, DefaultPollInterval)
	}

	go w.poll()
	return w, nil
}

// watchFS is the event-driven path. It coalesces adjacent events by
// delegating the decision to `reload`, which is itself a ModTime-guarded
// no-op if nothing actually changed.
func (w *FileWatcher) watchFS(notify *fsnotify.Watcher) {
	defer notify.Close()

	base := filepath.Base(w.path)

	for {
		select {
		case <-w.done:
			return

		case ev, ok := <-notify.Events:
			if !ok {
				return
			}
			// fsnotify delivers every file in the watched directory; filter by
			// basename so unrelated writes do not wake the reload path.
			if filepath.Base(ev.Name) != base {
				continue
			}
			// Write, Create, Rename all mean "policy file may have changed".
			// Chmod/Remove on the old inode after atomic replace is fine —
			// the Create for the new file will follow.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			w.reload()

		case err, ok := <-notify.Errors:
			if !ok {
				return
			}
			// fsnotify's Errors channel is advisory; do not tear the watcher
			// down on transient errors. If errors persist, operators will
			// see them in logs and can investigate.
			log.Printf("policy watcher: fsnotify error: %v", err)
		}
	}
}

// poll is the fallback path used when fsnotify is unavailable.
// Operates by mtime comparison at DefaultPollInterval.
func (w *FileWatcher) poll() {
	ticker := time.NewTicker(DefaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.reload()
		}
	}
}

// reload Stats the file, returns early if ModTime hasn't advanced, and
// otherwise re-parses and invokes the callback. Parse errors are logged
// but do not tear the watcher down — operators who save a malformed file
// can fix it and the next event/tick picks up the good version.
//
// modTime tracks the last *successfully processed* version. It is NOT
// updated on parse failure: doing so used to "consume" the failed
// mtime, so a follow-up good save that happened to be timestamped
// earlier than the failed mtime (e.g. after a test bumped mtime into
// the future to force advancement) was silently skipped. Updating
// only on success means a bad save can be repaired by any subsequent
// write — the next event sees the current mtime is still > the last
// good one and re-attempts parse.
func (w *FileWatcher) reload() {
	info, err := os.Stat(w.path)
	if err != nil {
		// The file may briefly not exist during atomic replace; ignore.
		return
	}
	w.mu.Lock()
	lastGood := w.modTime
	w.mu.Unlock()
	if !info.ModTime().After(lastGood) {
		return
	}

	pol, err := loadWithRetry(w.path)
	if err != nil {
		log.Printf("Policy reload failed: %v", err)
		return
	}
	w.mu.Lock()
	w.modTime = info.ModTime()
	w.mu.Unlock()
	// Wrap the user callback in safeCallback so a panic does not kill
	// the watcher goroutine. In production the callback is
	// FilePolicyProvider.onPolicyChange which fans out to each
	// registered Watch consumer; safeCallback is also used inside
	// onPolicyChange so a single misbehaving consumer cannot starve
	// the rest. Defending here belt-and-braces guards direct
	// WatchFile callers (tests, future providers).
	safeCallback(w.callback, pol)
}

// loadWithRetry re-reads and parses the policy, retrying ONLY transient
// filesystem read errors. The motivating case is an atomic-replace edit
// (write-temp + rename, the pattern every editor and `kubectl apply` uses):
// on Windows the rename's MoveFileEx can leave the destination briefly locked,
// so a reload's open-for-read racing it returns ERROR_SHARING_VIOLATION; on any
// platform the file can momentarily vanish mid-replace (ENOENT). Both surface
// as *fs.PathError. Without a retry the failing read is swallowed and — on the
// event-driven fsnotify path, which has no periodic tick — the change is lost
// until the next unrelated event, which may never come.
//
// Parse and validation errors are deterministic (a malformed file does not fix
// itself in 15ms), so they are returned immediately; only the open/read step is
// retried. The retry budget is tiny, spent solely on the rare failure path, and
// runs on the watcher's background goroutine — it never touches the proxy's
// request path, so it cannot affect the <3ms latency budget.
func loadWithRetry(path string) (*Policy, error) {
	const maxAttempts = 5
	const backoff = 15 * time.Millisecond

	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var pol *Policy
		if pol, err = LoadFromFile(path); err == nil {
			return pol, nil
		}
		// Retry only filesystem-level read failures (open/read), identified by
		// a *fs.PathError anywhere in the chain. A parse/validation error is
		// not a PathError, so it short-circuits out of the loop unchanged.
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			return nil, err
		}
		if attempt < maxAttempts-1 {
			time.Sleep(backoff)
		}
	}
	return nil, err
}

// Close stops the file watcher. Safe to call multiple times.
func (w *FileWatcher) Close() {
	w.once.Do(func() { close(w.done) })
}
