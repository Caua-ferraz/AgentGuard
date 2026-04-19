package policy

import (
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

// poll is the fallback path used when fsnotify is unavailable. It matches
// v0.4.0 behavior so nothing about the user-visible contract changes.
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
func (w *FileWatcher) reload() {
	info, err := os.Stat(w.path)
	if err != nil {
		// The file may briefly not exist during atomic replace; ignore.
		return
	}
	w.mu.Lock()
	if !info.ModTime().After(w.modTime) {
		w.mu.Unlock()
		return
	}
	w.modTime = info.ModTime()
	w.mu.Unlock()

	pol, err := LoadFromFile(w.path)
	if err != nil {
		log.Printf("Policy reload failed: %v", err)
		return
	}
	w.callback(pol)
}

// Close stops the file watcher. Safe to call multiple times.
func (w *FileWatcher) Close() {
	w.once.Do(func() { close(w.done) })
}
