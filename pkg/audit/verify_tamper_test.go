package audit

// Regression tests for ways a sealed log could be changed without the key
// and still pass `audit verify`. Each was reproduced against the first
// version of verify before it was fixed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rotatedSealedLog writes a sealed log with several plain archives and
// returns the live path and the archive base names, oldest first.
func rotatedSealedLog(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{MaxSize: 1500})
	writeEntries(t, l, 0, 40)
	_ = l.Close()
	names, err := listArchives(path)
	if err != nil || len(names) < 4 {
		t.Fatalf("test setup: want at least 4 archives, got %v (%v)", names, err)
	}
	if rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}); !rep.OK {
		t.Fatalf("test setup: the untouched log does not verify: %+v", rep.Break)
	}
	return path, names
}

// rewriteHeader changes the first (_meta) line of file.
func rewriteHeader(t *testing.T, file string, change func(*MetaRecord)) {
	t.Helper()
	lines := readLines(t, file)
	var env metaEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatal(err)
	}
	change(&env.Meta)
	b, _ := json.Marshal(env)
	lines[0] = string(b)
	writeLines(t, file, lines)
}

func mustBreak(t *testing.T, path string, opts VerifyOptions, want string) {
	t.Helper()
	rep := verify(t, path, opts)
	if rep.OK || rep.Break == nil || !strings.Contains(rep.Break.Reason, want) {
		t.Fatalf("verify passed or broke for another reason; want a break containing %q\nreport: %+v\nbreak: %+v", want, rep, rep.Break)
	}
}

func TestVerify_DeletedMiddleArchiveIsABreakNotPruning(t *testing.T) {
	path, names := rotatedSealedLog(t)
	if err := os.Remove(filepath.Join(filepath.Dir(path), names[len(names)/2])); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "is missing, but the archive")
}

func TestVerify_RotatedFromRewrittenToAMissingFileIsABreak(t *testing.T) {
	// A missing name newer than every archive, and one older than every
	// archive: either way the archives on disk are left unverified.
	for _, name := range []string{"audit.jsonl.29990101T000000Z", "audit.jsonl.20000101T000000Z"} {
		path, _ := rotatedSealedLog(t)
		rewriteHeader(t, path, func(m *MetaRecord) { m.RotatedFrom = name })
		mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "segment link broken")
	}
}

// TestVerify_PruningInABurstOfRotationsPasses: many rotations inside one
// second with pruning on. Archive names never go backwards, so pruning never
// frees a name a later rotation takes, and the log verifies with only the
// pruned start reported.
func TestVerify_PruningInABurstOfRotationsPasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{MaxSize: 1200, MaxFiles: 2, Compress: true})
	writeEntries(t, l, 0, 60)
	_ = l.Close()
	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
	if !rep.OK || rep.PrunedBefore == 0 || len(rep.Warnings) != 0 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

func TestVerify_RotatedFromRemovedFromALinkedHeaderIsABreak(t *testing.T) {
	path, _ := rotatedSealedLog(t)
	rewriteHeader(t, path, func(m *MetaRecord) { m.RotatedFrom = "" })
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "names no file before it")
}

func TestVerify_ArchiveSkippedByARewrittenLinkIsABreak(t *testing.T) {
	path, names := rotatedSealedLog(t)
	// The newest archive links past its predecessor to the one before.
	newest := filepath.Join(filepath.Dir(path), names[len(names)-1])
	rewriteHeader(t, newest, func(m *MetaRecord) { m.RotatedFrom = names[len(names)-3] })
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "")
}

func TestVerify_PruningOldestArchivesStillPasses(t *testing.T) {
	path, names := rotatedSealedLog(t)
	for _, n := range names[:2] {
		if err := os.Remove(filepath.Join(filepath.Dir(path), n)); err != nil {
			t.Fatal(err)
		}
	}
	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
	if !rep.OK || rep.PrunedBefore == 0 {
		t.Fatalf("pruning the oldest archives must still verify, with the pruned start reported: %+v break %+v", rep, rep.Break)
	}
}

func TestVerify_UnsealedEntryAfterTheSealHeaderIsABreak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	forged, _ := json.Marshal(sampleEntry(99))
	lines := readLines(t, path)
	// After the header (which declares the seal), before seq 1.
	lines = append(lines[:1], append([]string{string(forged)}, lines[1:]...)...)
	writeLines(t, path, lines)
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "no hash")
}

func TestVerify_EveryEntryReplacedByUnsealedOnesIsABreak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	lines := readLines(t, path)
	out := []string{lines[0]}
	for i := 0; i < 3; i++ {
		b, _ := json.Marshal(sampleEntry(100 + i))
		out = append(out, string(b))
	}
	writeLines(t, path, out)
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "no hash")
}

func TestVerify_LogWithEverySealStrippedFailsWithAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	var out []string
	for _, line := range readLines(t, path) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		if meta, ok := m["_meta"].(map[string]any); ok {
			for _, k := range []string{"seal", "chain_prev", "chain_seq"} {
				delete(meta, k)
			}
		}
		for _, k := range []string{"seq", "prev_hash", "hash"} {
			delete(m, k)
		}
		b, _ := json.Marshal(m)
		out = append(out, string(b))
	}
	writeLines(t, path, out)
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "not sealed")
}

func TestVerify_GarbageLineNotFollowedByAResumeLineIsABreak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	lines := readLines(t, path)
	lines = append(lines[:2], append([]string{`{"timestamp":"2026-`}, lines[2:]...)...)
	writeLines(t, path, lines)
	mustBreak(t, path, VerifyOptions{Keys: [][]byte{testSealKey}}, "not valid JSON")
}

// TestSeal_ResumeAfterAWriteThatLostOnlyItsNewline: a crash right before
// the newline leaves a whole entry. The restart completes the line and the
// chain continues from it, with nothing reported cut.
func TestSeal_ResumeAfterAWriteThatLostOnlyItsNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, b[:len(b)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	l = openSealed(t, path, testSealKey, RotationConfig{})
	if a, _ := l.SealHead(); a.Seq != 3 {
		t.Fatalf("head = %d, want 3: the entry that lost only its newline is whole", a.Seq)
	}
	writeEntries(t, l, 3, 2)
	_ = l.Close()
	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
	if !rep.OK || rep.LastSeq != 5 || len(rep.Warnings) != 0 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}
