package policy

// Regression tests for loadWithRetry — the transient-read resilience added to
// FileWatcher.reload so an atomic-replace edit racing the reload (notably a
// Windows ERROR_SHARING_VIOLATION after MoveFileEx) self-heals instead of
// silently dropping the policy change. See watcher.go.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWithRetry(t *testing.T) {
	dir := t.TempDir()

	// Happy path: a valid policy loads on the first attempt.
	good := filepath.Join(dir, "good.yaml")
	writePolicyFile(t, good, "version: \"1\"\nname: good\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"ls *\"\n")
	pol, err := loadWithRetry(good)
	if err != nil || pol == nil || pol.Name != "good" {
		t.Fatalf("loadWithRetry(good) = %v, %v; want name=good, nil err", pol, err)
	}

	// Deterministic validation/parse error is surfaced as-is (proving it is
	// returned immediately rather than retried into a generic timeout). A
	// missing 'version' is a validation error — not a *fs.PathError.
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("name: \"no version field\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWithRetry(bad); err == nil {
		t.Fatal("loadWithRetry(bad) must return the validation error")
	} else if errors.As(err, new(*fs.PathError)) {
		t.Errorf("validation error must not be a *fs.PathError (would be wrongly retried): %v", err)
	}

	// A missing file is the transient *fs.PathError class: retried, then the
	// read error is surfaced after the budget is exhausted.
	_, err = loadWithRetry(filepath.Join(dir, "nope.yaml"))
	if err == nil {
		t.Fatal("loadWithRetry(missing) must return a read error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing-file error should wrap fs.ErrNotExist, got %v", err)
	}
}
