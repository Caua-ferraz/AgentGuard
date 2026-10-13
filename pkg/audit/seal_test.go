package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

var testSealKey = []byte("0123456789abcdef0123456789abcdef")

func openSealed(t *testing.T, path string, key []byte, rot RotationConfig) *FileLogger {
	t.Helper()
	l, err := NewFileLoggerWithOptions(path, FileLoggerOptions{Rotation: rot, Seal: &SealConfig{Key: key, NodeID: "node-a"}})
	if err != nil {
		t.Fatalf("open sealed logger: %v", err)
	}
	return l
}

func writeEntries(t *testing.T, l Logger, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if err := l.Log(sampleEntry(i)); err != nil {
			t.Fatalf("Log(%d): %v", i, err)
		}
	}
}

func verify(t *testing.T, path string, opts VerifyOptions) *VerifyReport {
	t.Helper()
	rep, err := VerifyChain(path, opts)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	return rep
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The documented rule, implemented from scratch: strip the trailing
// `,"hash":"<hex>"}`, append `}`, hash. Another language can do exactly this.
func TestSeal_LineHashFollowsTheDocumentedRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"plain sha256", nil}, {"hmac key", testSealKey}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l := openSealed(t, path, tc.key, RotationConfig{})
			writeEntries(t, l, 0, 3)
			_ = l.Close()

			prev := ""
			for i, line := range readLines(t, path)[1:] {
				j := strings.LastIndex(line, `,"hash":"`)
				body := line[:j] + "}"
				var got string
				if tc.key == nil {
					s := sha256.Sum256([]byte(body))
					got = hex.EncodeToString(s[:])
				} else {
					m := hmac.New(sha256.New, tc.key)
					m.Write([]byte(body))
					got = hex.EncodeToString(m.Sum(nil))
				}
				var e Entry
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatal(err)
				}
				if e.Hash != got {
					t.Errorf("line %d: hash %s, recomputed %s", i+2, e.Hash, got)
				}
				if e.Seq != uint64(i+1) || e.PrevHash != prev {
					t.Errorf("line %d: seq %d prev_hash %q, want seq %d prev_hash %q", i+2, e.Seq, e.PrevHash, i+1, prev)
				}
				prev = e.Hash
			}
		})
	}
}

// The worked example in docs/FILE_FORMATS.md. If this fails, update the doc.
func TestSeal_DocumentedExample(t *testing.T) {
	s := newSealer(SealConfig{})
	e := Entry{
		Timestamp:  time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		SessionID:  "s1",
		AgentID:    "bot",
		Request:    policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:     policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
		DurationMs: 1,
	}
	line, _, _, err := s.line(e)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"timestamp":"2026-10-01T12:00:00Z","session_id":"s1","agent_id":"bot","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1,"seq":1,"hash":"`
	if !strings.HasPrefix(string(line), want) {
		t.Fatalf("line = %s\nwant prefix %s", line, want)
	}
	body := want[:len(want)-len(`,"hash":"`)] + "}"
	sum := sha256.Sum256([]byte(body))
	if wantLine := want + hex.EncodeToString(sum[:]) + "\"}\n"; string(line) != wantLine {
		t.Fatalf("line = %s\nwant      %s", line, wantLine)
	}
	if got := hex.EncodeToString(sum[:]); got != "278a4467f2999e6ef5146da29743b304f7f309fde7f36676b5a976c5ba434c8d" {
		t.Fatalf("hash = %s; docs/FILE_FORMATS.md shows a different one", got)
	}
}

func TestSeal_RoundTripVerifies(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"plain sha256", nil}, {"hmac key", testSealKey}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l := openSealed(t, path, tc.key, RotationConfig{})
			writeEntries(t, l, 0, 25)
			// Query reads sealed entries like any others, seal fields included.
			got, err := l.Query(QueryFilter{})
			if err != nil || len(got) != 25 || got[24].Seq != 25 || got[24].Hash == "" {
				t.Fatalf("query = %d entries, %v", len(got), err)
			}
			_ = l.Close()

			var keys [][]byte
			if tc.key != nil {
				keys = [][]byte{tc.key}
			}
			rep := verify(t, path, VerifyOptions{Keys: keys})
			if !rep.OK || rep.Entries != 25 || rep.FirstSeq != 1 || rep.LastSeq != 25 {
				t.Fatalf("report = %+v (break %+v)", rep, rep.Break)
			}
		})
	}
}

func TestSeal_HeaderCarriesSealFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	_ = l.Close()
	m, err := ReadMeta(path)
	if err != nil || m == nil {
		t.Fatalf("ReadMeta: %v %v", m, err)
	}
	if m.Seal == nil || m.Seal.Alg != SealAlgHMACSHA256 || m.Seal.KeyID != SealKeyID(testSealKey) || m.NodeID != "node-a" {
		t.Fatalf("header = %+v seal %+v", m, m.Seal)
	}
	if m.SchemaVersion != 2 {
		t.Fatalf("schema_version = %d, want 2", m.SchemaVersion)
	}
}

// Every way of tampering with the file is caught, at the right line.
func TestSeal_VerifyCatchesTampering(t *testing.T) {
	other := filepath.Join(t.TempDir(), "other.jsonl")
	ol := openSealed(t, other, nil, RotationConfig{})
	writeEntries(t, ol, 100, 10)
	_ = ol.Close()
	otherLines := readLines(t, other)

	cases := []struct {
		name   string
		tamper func([]string) []string
		line   int
		reason string
	}{
		{"edit a byte", func(l []string) []string {
			l[4] = strings.Replace(l[4], "cmd-3", "cmd-X", 1)
			return l
		}, 5, "hash mismatch"},
		{"delete a line", func(l []string) []string {
			return append(l[:4], l[5:]...)
		}, 5, "seq gap: expected seq 4, found 5"},
		{"swap two lines", func(l []string) []string {
			l[4], l[5] = l[5], l[4]
			return l
		}, 5, "seq gap: expected seq 4, found 5"},
		{"splice lines from another chain", func(l []string) []string {
			l[4] = otherLines[4] // the other log's seq 4
			return l
		}, 5, "prev_hash mismatch"},
		{"change seq", func(l []string) []string {
			l[4] = strings.Replace(l[4], `"seq":4,`, `"seq":40,`, 1)
			return l
		}, 5, "hash mismatch"},
		{"insert an unsealed line", func(l []string) []string {
			raw, _ := json.Marshal(sampleEntry(99))
			return append(l[:4], append([]string{string(raw)}, l[4:]...)...)
		}, 5, "has no hash"},
		{"drop the hash field", func(l []string) []string {
			i := strings.LastIndex(l[4], `,"hash":"`)
			l[4] = l[4][:i] + "}"
			return l
		}, 5, "has no hash"},
		{"remove the first entries", func(l []string) []string {
			return append(l[:1], l[3:]...)
		}, 2, "seq 3, not 1"},
		{"reset the chain", func(l []string) []string {
			return append(l, otherLines[1:3]...)
		}, 12, "starts over at seq 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			l := openSealed(t, path, nil, RotationConfig{})
			writeEntries(t, l, 0, 10)
			_ = l.Close()
			writeLines(t, path, tc.tamper(readLines(t, path)))

			rep := verify(t, path, VerifyOptions{})
			if rep.OK || rep.Break == nil {
				t.Fatalf("tampering not detected: %+v", rep)
			}
			if rep.Break.Line != tc.line || !strings.Contains(rep.Break.Reason, tc.reason) {
				t.Errorf("break = %s:%d %q, want line %d containing %q", rep.Break.File, rep.Break.Line, rep.Break.Reason, tc.line, tc.reason)
			}
		})
	}
}

func TestSeal_VerifyCatchesTruncationMidLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	writeEntries(t, l, 0, 5)
	_ = l.Close()
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, b[:len(b)-20], 0o600); err != nil {
		t.Fatal(err)
	}
	rep := verify(t, path, VerifyOptions{})
	if rep.OK || rep.Break == nil || rep.Break.Line != 6 || !strings.Contains(rep.Break.Reason, "incomplete") {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

func TestSeal_HMACKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 5)
	_ = l.Close()

	t.Run("the right key verifies", func(t *testing.T) {
		if rep := verify(t, path, VerifyOptions{Keys: [][]byte{[]byte("other"), testSealKey}}); !rep.OK {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
	t.Run("a wrong key fails", func(t *testing.T) {
		rep := verify(t, path, VerifyOptions{Keys: [][]byte{[]byte("not the key")}})
		if rep.OK || rep.Break == nil || !strings.Contains(rep.Break.Reason, "no --key-file has that id") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
	t.Run("no key asks for one", func(t *testing.T) {
		_, err := VerifyChain(path, VerifyOptions{})
		if _, ok := err.(*SealKeyNeededError); !ok {
			t.Fatalf("err = %v, want *SealKeyNeededError", err)
		}
	})
	t.Run("an entry re-hashed without the key fails", func(t *testing.T) {
		lines := readLines(t, path)
		// Recompute line 3 with the right shape but a guessed key: the
		// HMAC can't be forged.
		i := strings.LastIndex(lines[2], `,"hash":"`)
		body := strings.Replace(lines[2][:i]+"}", "cmd-1", "cmd-Z", 1)
		m := hmac.New(sha256.New, []byte("guess"))
		m.Write([]byte(body))
		lines[2] = body[:len(body)-1] + `,"hash":"` + hex.EncodeToString(m.Sum(nil)) + `"}`
		p2 := filepath.Join(t.TempDir(), "audit.jsonl")
		writeLines(t, p2, lines)
		rep := verify(t, p2, VerifyOptions{Keys: [][]byte{testSealKey}})
		if rep.OK || rep.Break == nil || rep.Break.Line != 3 || !strings.Contains(rep.Break.Reason, "hash mismatch") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
	t.Run("a log rewritten with plain sha256 fails when a key is given", func(t *testing.T) {
		p2 := filepath.Join(t.TempDir(), "audit.jsonl")
		l := openSealed(t, p2, nil, RotationConfig{})
		writeEntries(t, l, 0, 5)
		_ = l.Close()
		rep := verify(t, p2, VerifyOptions{Keys: [][]byte{testSealKey}})
		if rep.OK || rep.Break == nil || !strings.Contains(rep.Break.Reason, "no entry is sealed with a key") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
}

// A restart continues the chain where the file ends: seq keeps counting and
// the first new entry links to the last old one.
func TestSeal_ResumeAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, testSealKey, RotationConfig{})
	writeEntries(t, l, 0, 5)
	_ = l.Close()

	l = openSealed(t, path, testSealKey, RotationConfig{})
	if a, ok := l.SealHead(); !ok || a.Seq != 5 {
		t.Fatalf("head after reopen = %+v %v, want seq 5", a, ok)
	}
	writeEntries(t, l, 5, 5)
	_ = l.Close()
	// A restart with nothing written adds no second seal line.
	l = openSealed(t, path, testSealKey, RotationConfig{})
	_ = l.Close()
	l = openSealed(t, path, testSealKey, RotationConfig{})
	_ = l.Close()

	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
	if !rep.OK || rep.Entries != 10 || rep.LastSeq != 10 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
	metaLines := 0
	for _, line := range readLines(t, path) {
		if strings.HasPrefix(line, `{"_meta"`) {
			metaLines++
		}
	}
	if metaLines != 3 { // header, restart, restart (the third restart is a no-op)
		t.Errorf("%d _meta lines, want 3", metaLines)
	}
}

// Sealing turned on for a log that already has entries: those are reported
// as unsealed, and the chain starts at seq 1 after them.
func TestSeal_EnableOnExistingUnsealedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	plain, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	writeEntries(t, plain, 0, 4)
	_ = plain.Close()

	l := openSealed(t, path, nil, RotationConfig{})
	writeEntries(t, l, 4, 3)
	_ = l.Close()

	rep := verify(t, path, VerifyOptions{})
	if !rep.OK || rep.Unsealed != 4 || rep.Entries != 3 || rep.FirstSeq != 1 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

// A crash mid-write leaves a cut last line. The restart ends it and the
// chain continues from the last whole entry; verify points at the cut line.
func TestSeal_ResumeAfterCutLastLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	writeEntries(t, l, 0, 3)
	_ = l.Close()
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, b[:len(b)-30], 0o600); err != nil {
		t.Fatal(err)
	}

	l = openSealed(t, path, nil, RotationConfig{})
	if a, _ := l.SealHead(); a.Seq != 2 {
		t.Fatalf("head = %d, want 2 (the cut entry is lost)", a.Seq)
	}
	writeEntries(t, l, 3, 2)
	_ = l.Close()

	lines := readLines(t, path)
	var last Entry
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("the entry after the cut line is not whole: %v", err)
	}
	rep := verify(t, path, VerifyOptions{})
	if rep.OK || rep.Break == nil || rep.Break.Line != 4 || !strings.Contains(rep.Break.Reason, "not valid JSON") {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

func TestSeal_RotationWithGzipAndPruning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Rotate often without pruning, then restart with pruning on and rotate
	// once more. (Pruning between rotations that fall in the same second
	// can free an archive name older than the newest one; nextFreeArchivePath
	// then reuses it and the newest archive sorts first. Doing the prune in
	// a single rotation keeps the test about sealing, not about that.)
	l := openSealed(t, path, testSealKey, RotationConfig{MaxSize: 2048, Compress: true})
	var anchors []Anchor
	for i := 0; i < 59; i++ {
		writeEntries(t, l, i, 1)
		if i == 2 || i == 58 {
			a, _ := l.SealHead()
			anchors = append(anchors, a)
		}
	}
	_ = l.Close()
	l = openSealed(t, path, testSealKey, RotationConfig{MaxSize: 1, MaxFiles: 2, Compress: true})
	writeEntries(t, l, 59, 1)
	_ = l.Close()

	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}, Anchors: anchors})
	if !rep.OK || rep.LastSeq != 60 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
	if len(rep.Segments) != 3 || !strings.HasSuffix(rep.Segments[0], ".gz") {
		t.Errorf("segments = %v, want two gzip archives and the live file", rep.Segments)
	}
	if rep.PrunedBefore == 0 || rep.FirstSeq != rep.PrunedBefore+1 {
		t.Errorf("pruned_before = %d first_seq = %d: older segments were pruned and the report should say where the chain starts", rep.PrunedBefore, rep.FirstSeq)
	}
	if rep.Anchors[0].Status != AnchorNotCheckable || rep.Anchors[1].Status != AnchorMatch {
		t.Errorf("anchors = %+v, want [not_checkable match]", rep.Anchors)
	}

	t.Run("a changed archive is caught", func(t *testing.T) {
		archive := filepath.Join(dir, rep.Segments[1])
		orig, _ := os.ReadFile(archive)
		defer func() { _ = os.WriteFile(archive, orig, 0o600) }()
		raw := gunzipFile(t, archive)
		raw = bytes.Replace(raw, []byte(`"cmd-`), []byte(`"CMD-`), 1)
		gzipBytes(t, archive, raw)
		rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
		if rep.OK || rep.Break == nil || rep.Break.File != filepath.Base(archive) || !strings.Contains(rep.Break.Reason, "hash mismatch") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
	t.Run("a cut archive is caught, not an I/O error", func(t *testing.T) {
		archive := filepath.Join(dir, rep.Segments[1])
		orig, _ := os.ReadFile(archive)
		defer func() { _ = os.WriteFile(archive, orig, 0o600) }()
		if err := os.WriteFile(archive, orig[:len(orig)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
		if rep.OK || rep.Break == nil || !strings.Contains(rep.Break.Reason, "can't decompress") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
	t.Run("a broken link between files is caught", func(t *testing.T) {
		lines := readLines(t, path)
		var env metaEnvelope
		_ = json.Unmarshal([]byte(lines[0]), &env)
		env.Meta.ChainSeq += 5
		b, _ := json.Marshal(env)
		lines[0] = string(b)
		writeLines(t, path, lines)
		rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
		if rep.OK || rep.Break == nil || !strings.Contains(rep.Break.Reason, "segment link broken") {
			t.Fatalf("report = %+v break %+v", rep, rep.Break)
		}
	})
}

// A restart right after a rotation finds a live file with only a header; the
// chain continues from the header's chain_seq.
func TestSeal_ResumeOnFreshlyRotatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{MaxSize: 1})
	writeEntries(t, l, 0, 3) // every write rotates
	before, _ := l.SealHead()
	_ = l.Close()

	l = openSealed(t, path, nil, RotationConfig{MaxSize: 1})
	after, _ := l.SealHead()
	if after.Seq != 3 || after.Hash != before.Hash || after.SegmentID == "" || after.SegmentID != before.SegmentID {
		t.Fatalf("head after restart = %+v, before = %+v", after, before)
	}
	writeEntries(t, l, 3, 2)
	_ = l.Close()
	if rep := verify(t, path, VerifyOptions{}); !rep.OK || rep.LastSeq != 5 || len(rep.Segments) != 6 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

// The checkpoint records the head; a live file that ends before it gets a
// warning and the metric, and the server still starts.
func TestSeal_CheckpointTailMismatchWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	l.EnableCheckpoints(DecisionCounts{}, 0)
	writeEntries(t, l, 0, 5)
	_ = l.Close()
	cp, err := ReadCheckpoint(path)
	if err != nil || cp == nil || cp.LastSeq != 5 || cp.LastHash == "" {
		t.Fatalf("checkpoint = %+v, %v; want last_seq 5", cp, err)
	}

	before := metrics.AuditSealTailMismatchTotal()
	l = openSealed(t, path, nil, RotationConfig{})
	_ = l.Close()
	if got := metrics.AuditSealTailMismatchTotal() - before; got != 0 {
		t.Fatalf("an intact file raised the tail-mismatch metric (%d)", got)
	}

	lines := readLines(t, path)
	writeLines(t, path, lines[:len(lines)-3]) // drop seq 4, 5 and the restart line
	l = openSealed(t, path, nil, RotationConfig{})
	_ = l.Close()
	if got := metrics.AuditSealTailMismatchTotal() - before; got != 1 {
		t.Fatalf("tail-mismatch metric delta = %d, want 1", got)
	}
}

func TestSeal_ReplayCarriesCheckpointHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	writeEntries(t, l, 0, 2)
	_ = l.Close()
	cp := &Checkpoint{Counts: &DecisionCounts{}, LastSeq: 2, LastHash: "abc"}
	next, err := ReplayWithCheckpoint(path, cp, func(Entry) {})
	if err != nil {
		t.Fatal(err)
	}
	if next.LastSeq != 2 || next.LastHash != "abc" {
		t.Fatalf("next checkpoint = %+v; the seal head must be carried forward", next)
	}
}

// Entries that spill to the overflow file and are drained back later are
// sealed when they reach the file, in file order, so the chain holds.
func TestSeal_OverflowSpillAndDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fl := openSealed(t, path, testSealKey, RotationConfig{})
	gate := &gatedLogger{inner: fl, gate: make(chan struct{})}
	b, err := NewBufferedAsyncLogger(gate, BufferedAsyncOpts{
		QueueSize:        2,
		Workers:          1,
		OverflowPath:     filepath.Join(dir, "overflow.jsonl"),
		RecoveryInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeEntries(t, b, 0, 30)
	if b.DroppedToOverflow() == 0 {
		t.Fatal("nothing spilled to the overflow file; the test does not exercise the drain")
	}
	close(gate.gate)
	waitFor(t, 5*time.Second, func() bool {
		a, _ := b.SealHead()
		return a.Seq == 30
	}, "all 30 entries sealed")
	_ = b.Close()
	_ = fl.Close()

	rep := verify(t, path, VerifyOptions{Keys: [][]byte{testSealKey}})
	if !rep.OK || rep.Entries != 30 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

func TestSeal_ConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{MaxSize: 16 * 1024})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_ = l.Log(sampleEntry(w*1000 + i))
				if i%25 == 0 {
					_, _ = l.SealHead()
				}
			}
		}(w)
	}
	wg.Wait()
	_ = l.Close()
	rep := verify(t, path, VerifyOptions{})
	if !rep.OK || rep.LastSeq != 800 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
}

// With sealing off the line is byte-for-byte what it was before sealing
// existed, even when the caller passes seal fields in.
func TestSeal_OffKeepsOutputByteIdentical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{
		Timestamp:  time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		SessionID:  "s1",
		AgentID:    "bot",
		Request:    policy.ActionRequest{Scope: "shell", Command: "ls"},
		Result:     policy.CheckResult{Decision: policy.Allow, Reason: "ok"},
		DurationMs: 1,
		Seq:        9, PrevHash: "x", Hash: "y",
	}
	if err := l.Log(e); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	lines := readLines(t, path)
	const want = `{"timestamp":"2026-10-01T12:00:00Z","session_id":"s1","agent_id":"bot","request":{"scope":"shell","command":"ls"},"result":{"decision":"ALLOW","reason":"ok"},"duration_ms":1}`
	if lines[1] != want {
		t.Fatalf("entry line = %s\nwant         %s", lines[1], want)
	}
	if strings.Contains(lines[0], "seal") || strings.Contains(lines[0], "chain_") || strings.Contains(lines[0], "node_id") {
		t.Fatalf("header has seal fields with sealing off: %s", lines[0])
	}
}

func TestSeal_Anchors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	writeEntries(t, l, 0, 5)
	a3 := Anchor{Seq: 3}
	head, _ := l.SealHead()
	writeEntries(t, l, 5, 5)
	_ = l.Close()
	for _, line := range readLines(t, path)[1:] {
		var e Entry
		_ = json.Unmarshal([]byte(line), &e)
		if e.Seq == 3 {
			a3.Hash = e.Hash
		}
	}

	rep := verify(t, path, VerifyOptions{Anchors: []Anchor{
		a3,
		{Seq: head.Seq, Hash: head.Hash},
		{Seq: 7, Hash: strings.Repeat("0", 64)},
		{Seq: 12, Hash: strings.Repeat("1", 64)},
	}})
	want := []string{AnchorMatch, AnchorMatch, AnchorMismatch, AnchorMissing}
	for i, r := range rep.Anchors {
		if r.Status != want[i] {
			t.Errorf("anchor %d:%s = %s, want %s", r.Seq, r.Hash, r.Status, want[i])
		}
	}
	if rep.OK {
		t.Error("a mismatched or missing anchor must fail verification")
	}

	// Removing the newest entries leaves a chain that verifies on its own;
	// only an anchor published before the cut can show it.
	lines := readLines(t, path)
	writeLines(t, path, lines[:len(lines)-4])
	rep = verify(t, path, VerifyOptions{Anchors: []Anchor{{Seq: 10, Hash: strings.Repeat("2", 64)}}})
	if rep.OK || rep.Anchors[0].Status != AnchorMissing {
		t.Fatalf("truncated tail not caught by the anchor: %+v", rep)
	}
}

func TestSeal_AnchorPublishing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openSealed(t, path, nil, RotationConfig{})
	stop := l.StartAnchoring(10 * time.Millisecond)
	writeEntries(t, l, 0, 4)
	waitFor(t, 2*time.Second, func() bool { return metrics.AuditSealSeq() == 4 }, "periodic anchor publishes seq 4")
	stop()
	stop() // idempotent
	writeEntries(t, l, 4, 1)
	_ = l.Close()
	if got := metrics.AuditSealSeq(); got != 5 {
		t.Fatalf("anchor gauge after Close = %d, want 5 (Close publishes a last anchor)", got)
	}

	plain, err := NewFileLogger(filepath.Join(t.TempDir(), "plain.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, ok := plain.SealHead(); ok {
		t.Fatal("SealHead reports a head with sealing off")
	}
	plain.StartAnchoring(time.Millisecond)() // no-op without sealing
}

func TestLoadSealKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, []byte("  abcdef\n"), 0o600)
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	open := filepath.Join(dir, "open")
	_ = os.WriteFile(open, []byte("abcdef\n"), 0o600)
	_ = os.Chmod(open, 0o644)

	if k, err := LoadSealKey(good, true); err != nil || string(k) != "abcdef" {
		t.Errorf("good key = %q, %v", k, err)
	}
	if _, err := LoadSealKey(empty, true); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty key: err = %v", err)
	}
	if _, err := LoadSealKey(filepath.Join(dir, "missing"), true); err == nil {
		t.Error("missing key file accepted")
	}
	_, err := LoadSealKey(open, true)
	if isWindows() {
		if err != nil {
			t.Errorf("world-readable check runs on Windows: %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("world-readable key file: err = %v", err)
	}
	if _, err := LoadSealKey(open, false); err != nil {
		t.Errorf("without strictPerms the mode is not checked: %v", err)
	}
}

func BenchmarkFileLoggerLog(b *testing.B) {
	for _, bc := range []struct {
		name string
		seal *SealConfig
	}{
		{"unsealed", nil},
		{"sealed-sha256", &SealConfig{}},
		{"sealed-hmac", &SealConfig{Key: testSealKey}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			l, err := NewFileLoggerWithOptions(filepath.Join(b.TempDir(), "audit.jsonl"), FileLoggerOptions{Seal: bc.seal})
			if err != nil {
				b.Fatal(err)
			}
			defer l.Close()
			e := sampleEntry(1)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := l.Log(e); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// gatedLogger holds every Log until gate is closed, so the buffered queue
// saturates and spills.
type gatedLogger struct {
	inner *FileLogger
	gate  chan struct{}
}

func (g *gatedLogger) Log(e Entry) error {
	<-g.gate
	return g.inner.Log(e)
}
func (g *gatedLogger) Query(f QueryFilter) ([]Entry, error) { return g.inner.Query(f) }
func (g *gatedLogger) Close() error                         { return nil }
func (g *gatedLogger) SealHead() (Anchor, bool)             { return g.inner.SealHead() }

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gzipBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(b)
	_ = gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func isWindows() bool { return filepath.Separator == '\\' }
