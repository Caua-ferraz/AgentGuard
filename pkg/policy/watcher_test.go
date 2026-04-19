package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// minPolicyYAML is a valid policy that LoadFromFile will accept.
const minPolicyYAML = `version: "1"
name: test
rules:
  - scope: shell
    allow:
      - pattern: "ls *"
`

// alternatePolicyYAML differs from minPolicyYAML so callbacks can tell new
// content from old.
const alternatePolicyYAML = `version: "1"
name: test-updated
rules:
  - scope: shell
    allow:
      - pattern: "echo *"
`

// bumpMTime forces a file's mtime forward by 2 seconds. Some filesystems
// record mtime at second precision, so a very fast rewrite + stat may see
// the same mtime and the reload guard would no-op. Explicitly setting
// ModTime removes that flake class.
func bumpMTime(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("os.Chtimes: %v", err)
	}
}

// writePolicyFile writes body to path atomically (write + rename) so an
// in-flight fsnotify watcher sees a single Create event rather than a
// partial write.
func writePolicyFile(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".writing"
	if err := os.WriteFile(tmp, []byte(body), 0600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename tmp: %v", err)
	}
}

// waitForReload waits up to timeout for a callback on ch and fails the test
// if nothing arrives. The timeout has to accommodate the poll fallback
// (DefaultPollInterval = 2s) for environments where fsnotify is unavailable.
func waitForReload(t *testing.T, ch <-chan *Policy, timeout time.Duration) *Policy {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for policy reload callback", timeout)
		return nil
	}
}

// TestWatchFile_ReloadsOnWrite: the primary contract — any write that
// advances mtime must trigger the callback with the new policy.
func TestWatchFile_ReloadsOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan *Policy, 4)
	w, err := WatchFile(path, func(p *Policy) { ch <- p })
	if err != nil {
		t.Fatalf("WatchFile: %v", err)
	}
	defer w.Close()

	if err := os.WriteFile(path, []byte(alternatePolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	bumpMTime(t, path)

	// 5s covers worst-case poll fallback (two poll intervals + slack).
	pol := waitForReload(t, ch, 5*time.Second)
	if pol.Name != "test-updated" {
		t.Errorf("callback received name=%q, want %q", pol.Name, "test-updated")
	}
}

// TestWatchFile_AtomicReplace: editors and `mv tmp target` replace a file
// by swapping inodes. The watcher must notice this — historically, an
// fsnotify.Watcher.Add(path) would silently orphan after such a rename.
func TestWatchFile_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan *Policy, 4)
	w, err := WatchFile(path, func(p *Policy) { ch <- p })
	if err != nil {
		t.Fatalf("WatchFile: %v", err)
	}
	defer w.Close()

	writePolicyFile(t, path, alternatePolicyYAML)
	bumpMTime(t, path)

	pol := waitForReload(t, ch, 5*time.Second)
	if pol.Name != "test-updated" {
		t.Errorf("atomic-replace callback received name=%q, want %q", pol.Name, "test-updated")
	}
}

// TestWatchFile_BadYAMLKeepsWatcherAlive: a malformed save should log but
// leave the watcher running, so the next good save is picked up.
func TestWatchFile_BadYAMLKeepsWatcherAlive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan *Policy, 4)
	w, err := WatchFile(path, func(p *Policy) { ch <- p })
	if err != nil {
		t.Fatalf("WatchFile: %v", err)
	}
	defer w.Close()

	// 1. Save malformed YAML — no callback, no panic.
	if err := os.WriteFile(path, []byte("not: valid: yaml: ["), 0600); err != nil {
		t.Fatal(err)
	}
	bumpMTime(t, path)

	select {
	case p := <-ch:
		t.Fatalf("bad YAML must not produce a callback; got %+v", p)
	case <-time.After(500 * time.Millisecond):
		// Expected: reload fails, callback silent.
	}

	// 2. Save good YAML — callback must fire.
	if err := os.WriteFile(path, []byte(alternatePolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	bumpMTime(t, path)

	pol := waitForReload(t, ch, 5*time.Second)
	if pol.Name != "test-updated" {
		t.Errorf("post-recovery callback name=%q, want %q", pol.Name, "test-updated")
	}
}

// TestFileWatcher_CloseIdempotent: Close must be safe to call more than
// once. A panic here would crash the server on double-shutdown paths.
func TestFileWatcher_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minPolicyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := WatchFile(path, func(*Policy) {})
	if err != nil {
		t.Fatalf("WatchFile: %v", err)
	}
	w.Close()
	w.Close() // second call must not panic (close of closed chan would)
}

// TestWatchFile_MissingFileReturnsError: a boot-time misconfiguration
// (wrong path) must surface immediately rather than silently starting an
// orphaned watcher goroutine.
func TestWatchFile_MissingFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	_, err := WatchFile(filepath.Join(dir, "does-not-exist.yaml"), func(*Policy) {})
	if err == nil {
		t.Fatal("WatchFile on a missing file must return an error")
	}
}
