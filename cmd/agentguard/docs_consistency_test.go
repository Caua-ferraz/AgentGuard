package main

// Documentation tripwires for facts the code owns. Each one guards a claim
// that was found stale in the 2026-09-09 review; the test names the doc and
// the line so the fix is a one-file edit.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

func repoRootForDocs(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

func docFiles(t *testing.T) []string {
	t.Helper()
	root := repoRootForDocs(t)
	files, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	return append(files, filepath.Join(root, "README.md"))
}

// The replay checkpoint lives at `<audit-log>` + audit.CheckpointSuffix.
// Three docs described it as `<audit-dir>/.replay-checkpoint` — the path
// the CLI wrongly used (R2). Any doc that names the checkpoint must use
// the real shape.
func TestDocs_CheckpointPathMatchesCode(t *testing.T) {
	const stale = "<audit-dir>/.replay-checkpoint"
	real := "<audit-log>" + audit.CheckpointSuffix
	var bad []string
	mentions := 0
	for _, f := range docFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for i, line := range strings.Split(text, "\n") {
			if strings.Contains(line, stale) {
				bad = append(bad, filepath.Base(f)+":"+itoa(i+1))
			}
		}
		if strings.Contains(text, real) {
			mentions++
		}
	}
	if len(bad) > 0 {
		t.Errorf("docs still describe the checkpoint as %q; the server writes %q: %v", stale, real, bad)
	}
	if mentions == 0 {
		t.Errorf("no doc names the checkpoint as %q — the tripwire would be vacuous", real)
	}
}

// The update check is skipped for `server` (and its `serve` alias). The CLI
// doc must say so, and must not claim the check runs for "every subcommand".
func TestDocs_UpdateCheckSkipsServer(t *testing.T) {
	root := repoRootForDocs(t)
	b, err := os.ReadFile(filepath.Join(root, "docs", "CLI.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "`server` never performs the check (nor does `serve`") {
		t.Errorf("docs/CLI.md must state that `server` (and `serve`) never performs the update check")
	}
	if strings.Contains(text, "Every subcommand kicks off") {
		t.Errorf("docs/CLI.md still claims every subcommand performs the update check")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
