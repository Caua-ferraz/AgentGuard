package policy

import (
	"log"
	"os"
	"time"
)

// FileWatcher watches a policy file for changes and triggers a callback.
type FileWatcher struct {
	path     string
	modTime  time.Time
	done     chan struct{}
	callback func(*Policy)
}

// WatchFile starts watching a policy file for changes.
func WatchFile(path string, callback func(*Policy)) (*FileWatcher, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	w := &FileWatcher{
		path:     path,
		modTime:  info.ModTime(),
		done:     make(chan struct{}),
		callback: callback,
	}

	go w.poll()
	return w, nil
}

func (w *FileWatcher) poll() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			info, err := os.Stat(w.path)
			if err != nil {
				continue
			}
			if info.ModTime().After(w.modTime) {
				w.modTime = info.ModTime()
				pol, err := LoadFromFile(w.path)
				if err != nil {
					log.Printf("Policy reload failed: %v", err)
					continue
				}
				w.callback(pol)
			}
		}
	}
}

// Close stops the file watcher.
func (w *FileWatcher) Close() {
	close(w.done)
}
