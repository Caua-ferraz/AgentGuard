package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
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

// A line longer than the 4 MiB cap is one bad line, and the entries after
// it are still read. bufio.Scanner used to stop there, dropping them while
// audit verify (no cap) said the log was intact. The startup replay shares
// the reader, so it no longer stops early either.
func TestReadEntries_OverlongLineIsOneBadLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", maxEntryLine+10)
	for _, cmd := range []string{"before", huge, "after", "last"} {
		if err := l.Log(Entry{AgentID: "bot", Request: policy.ActionRequest{Scope: "shell", Command: cmd}}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	var got []string
	bad, err := ReadEntries(path, func(e Entry) { got = append(got, e.Request.Command) })
	if err != nil {
		t.Fatal(err)
	}
	if bad != 1 || strings.Join(got, ",") != "before,after,last" {
		t.Errorf("bad = %d, entries = %v; want 1 bad line and before,after,last", bad, got)
	}

	replayed := 0
	if err := replayFile(path, 0, func(Entry) { replayed++ }); err != nil || replayed != 3 {
		t.Errorf("replay read %d entries (err %v), want 3", replayed, err)
	}
}

func TestReadBoundedLine(t *testing.T) {
	cases := []struct {
		name, in string
		max      int
		want     []string // "!" marks a too-long line
	}{
		{"lines and a last line without a newline", "a\nbb\r\nccc", 10, []string{"a", "bb", "ccc"}},
		{"a line at the cap is kept", "abcd\nx\n", 4, []string{"abcd", "x", ""}},
		{"a line over the cap is dropped whole", "abcde\nx\n", 4, []string{"!", "x", ""}},
		{"blank lines stay blank", "\n\na\n", 4, []string{"", "", "a", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A 16-byte buffer forces long lines across several reads.
			br := bufio.NewReaderSize(strings.NewReader(tc.in), 16)
			var got []string
			for {
				line, tooLong, err := readBoundedLine(br, tc.max)
				if tooLong {
					got = append(got, "!")
				} else {
					got = append(got, string(line))
				}
				if err != nil {
					break
				}
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("lines = %q, want %q", got, tc.want)
			}
		})
	}
}
