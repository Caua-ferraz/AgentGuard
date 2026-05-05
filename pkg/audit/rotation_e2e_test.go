package audit

// AT-added rotation end-to-end test.
//
// pkg/audit/rotation_test.go already covers the lower-layer rotation
// primitives (size trigger, gzip, prune, age). What's missing is a test
// that drives the rotation through the same write loop a live server
// uses — i.e. many sequential Log() calls in steady state — and verifies
// the post-rotation invariants on disk:
//
//   - At least one archive file is present.
//   - The live audit.jsonl is below the configured threshold (proving
//     rotation actually demoted content to an archive, not just appended
//     a marker).
//
// We use the in-process logger (not the external binary) per the AT
// brief's explicit guidance: "If the in-process route is easier, do that."
// Building the binary in a temp dir, finding a free port, scraping logs
// for the listening port, and pumping HTTP would test the same thing at
// 50x the wall-clock cost without exercising any extra logic.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestATRotationE2E_DrivesRotationThroughLog drives ~5x the rotation
// threshold of audit traffic and asserts the post-state on disk.
func TestATRotationE2E_DrivesRotationThroughLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// 1 KiB threshold: small enough that a few hundred typical entries
	// trip multiple rotations, big enough that the test isn't dominated
	// by header-write overhead.
	const threshold int64 = 1024

	logger, err := NewFileLoggerWithRotation(path, RotationConfig{
		MaxSize:  threshold,
		MaxFiles: 10,
		Compress: true,
	})
	if err != nil {
		t.Fatalf("NewFileLoggerWithRotation: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	// Drive enough writes to exceed the threshold many times over. Each
	// logBlob is ~300 bytes encoded, so 200 entries is ~60 KiB across
	// dozens of rotations.
	for i := 0; i < 200; i++ {
		if err := logger.Log(logBlob("at-bot")); err != nil {
			t.Fatalf("Log %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	// Invariant 1: at least one archive file.
	var archives, gzipped int
	var liveSize int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info %q: %v", e.Name(), err)
		}
		switch e.Name() {
		case "audit.jsonl":
			liveSize = info.Size()
		default:
			if strings.HasPrefix(e.Name(), "audit.jsonl.") {
				archives++
				if strings.HasSuffix(e.Name(), ".gz") {
					gzipped++
				}
			}
		}
	}

	if archives == 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected at least one rotated archive, dir contents: %v", names)
	}

	// Invariant 2: live file is below threshold (modulo a small slack —
	// the live file is allowed to be slightly above threshold momentarily
	// because rotation triggers AFTER a write completes; the next write
	// will rotate. We give 2x slack for that in-flight margin.)
	if liveSize >= 2*threshold {
		t.Errorf("live audit.jsonl size = %d, expected < %d (rotation should have demoted content)",
			liveSize, 2*threshold)
	}

	// Invariant 3: with Compress=true, every archive must be a .gz.
	if gzipped != archives {
		t.Errorf("Compress=true but %d/%d archives were not gzipped",
			archives-gzipped, archives)
	}
}
