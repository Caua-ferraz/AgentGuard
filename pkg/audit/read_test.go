package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// A rotated, compressed log reads back whole and in write order, and a
// line that is not an entry is counted rather than logged.
func TestLogFilesAndReadEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLoggerWithOptions(path, FileLoggerOptions{
		Rotation: RotationConfig{MaxSize: 600, Compress: true},
		Seal:     &SealConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	const n = 12
	for i := 0; i < n; i++ {
		if err := l.Log(Entry{AgentID: "bot", Request: policy.ActionRequest{Scope: "shell", Command: "ls"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not json\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	files, err := LogFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 3 || files[len(files)-1] != path {
		t.Fatalf("files = %v; want archives then the live file", files)
	}

	var seqs []uint64
	bad := 0
	for _, f := range files {
		b, err := ReadEntries(f, func(e Entry) { seqs = append(seqs, e.Seq) })
		if err != nil {
			t.Fatalf("ReadEntries(%s): %v", f, err)
		}
		bad += b
	}
	if len(seqs) != n {
		t.Fatalf("read %d entries, want %d", len(seqs), n)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("entry %d has seq %d: files read out of order (%v)", i, s, seqs)
		}
	}
	if bad != 1 {
		t.Errorf("bad lines = %d, want 1", bad)
	}

	if _, err := LogFiles(filepath.Join(t.TempDir(), "missing.jsonl")); err == nil {
		t.Error("LogFiles of a missing file: no error")
	}
}
