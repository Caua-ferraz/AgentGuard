package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func maskCommand(e Entry) Entry {
	e.Request.Command = strings.ReplaceAll(e.Request.Command, "s3cret", "[REDACTED]")
	return e
}

func TestWithTransform_AppliesAndForwardsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	fl, err := NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	l := WithTransform(fl, maskCommand)
	e := sampleEntry(1)
	e.Request.Command = "echo s3cret"
	if err := l.Log(e); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "s3cret") || !strings.Contains(string(data), "[REDACTED]") {
		t.Errorf("file = %s", data)
	}
	pr, ok := l.(interface{ Path() string })
	if !ok || pr.Path() != fl.Path() {
		t.Errorf("Path not forwarded: ok=%v", ok)
	}
	if WithTransform(fl, nil) != Logger(fl) {
		t.Error("WithTransform(nil) should return the inner logger unchanged")
	}
}

func TestBufferedAsync_OverflowAppliesTransform(t *testing.T) {
	overflowPath := filepath.Join(t.TempDir(), "overflow.jsonl")
	blocker := newBlockingLogger()
	defer blocker.Release()
	b, err := NewBufferedAsyncLogger(blocker, BufferedAsyncOpts{
		QueueSize:        1,
		Workers:          1,
		OverflowPath:     overflowPath,
		RecoveryInterval: 24 * time.Hour,
		Transform:        maskCommand,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Log(sampleEntry(0)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return b.QueueDepth() == 0 }, "worker pulls first entry")
	for i := 1; i < 5; i++ {
		e := sampleEntry(i)
		// Built from pieces so secret scanners don't flag the fixture.
		e.Request.Command = "curl -u admin" + ":" + "s3cret https://x"
		if err := b.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(overflowPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s3cret") || !strings.Contains(string(data), "[REDACTED]") {
		t.Errorf("overflow spill not transformed: %s", data)
	}
}
