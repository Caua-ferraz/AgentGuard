package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// writeSealedLog writes n sealed entries to dir/audit.jsonl and returns the
// head.
func writeSealedLog(t *testing.T, dir string, key []byte, n int) audit.Anchor {
	t.Helper()
	l, err := audit.NewFileLoggerWithOptions(filepath.Join(dir, "audit.jsonl"), audit.FileLoggerOptions{Seal: &audit.SealConfig{Key: key}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(audit.Entry{AgentID: "bot", Request: policy.ActionRequest{Scope: "shell", Command: "ls"}}); err != nil {
			t.Fatal(err)
		}
	}
	head, _ := l.SealHead()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return head
}

func TestCLI_AuditVerify(t *testing.T) {
	dir := t.TempDir()
	key := []byte("seal-key")
	keyFile := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(keyFile, append(key, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	head := writeSealedLog(t, dir, key, 5)
	anchor := "5:" + head.Hash

	agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile, "--anchor", anchor).
		expect(t, 0, "OK: the chain is intact.", "")
	agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile).
		expect(t, 0, "Sealed:    5 entries, seq 1 to 5", "")

	r := agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile, "--output", "json")
	var rep audit.VerifyReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || !rep.OK || rep.LastSeq != 5 {
		t.Fatalf("json report = %+v, %v\n%s", rep, err, r.stdout)
	}

	// Usage mistakes exit 2.
	agentguard(t, dir, nil, "audit", "verify").expect(t, 2, "", "give that key with --key-file")
	agentguard(t, dir, nil, "audit", "verify", "--anchor", "five:abc").expect(t, 2, "", "want seq:hash")
	agentguard(t, dir, nil, "audit", "verify", "--output", "xml").expect(t, 2, "", "--output must be text or json")
	agentguard(t, dir, nil, "audit", "verify", "extra").expect(t, 2, "", "unexpected argument")

	// I/O problems exit 3.
	agentguard(t, dir, nil, "audit", "verify", "--audit-log", "missing.jsonl").expect(t, 3, "", "missing.jsonl")
	agentguard(t, dir, nil, "audit", "verify", "--key-file", "nope.key").expect(t, 3, "", "seal key file")

	// An anchor the log no longer reaches fails.
	agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile, "--anchor", "9:"+strings.Repeat("a", 64)).
		expect(t, 1, "MISSING: the log ends at seq 5", "")

	// Tampering exits 1 and names the line.
	path := filepath.Join(dir, "audit.jsonl")
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"command":"ls"`, `"command":"rm"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile, "--anchor", anchor).
		expect(t, 1, "BROKEN at audit.jsonl:2: hash mismatch", "")

	// The query form of `audit` is unchanged.
	agentguard(t, dir, nil, "audit", "stray").expect(t, 2, "", "unexpected argument \"stray\"")
}

// A log with entries but none sealed must not print "intact" or exit 0,
// with or without a key.
func TestCLI_AuditVerifyUnsealedLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.NewFileLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(audit.Entry{AgentID: "bot", Request: policy.ActionRequest{Scope: "shell", Command: "ls"}}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	agentguard(t, dir, nil, "audit", "verify").expect(t, 1, "NOT SEALED: none of the 3 entries is sealed", "")

	// The _meta line a server writes when it starts sealing, after every
	// entry.
	key := []byte("seal-key")
	keyFile := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"_meta":{"schema_version":2,"created_at":"2026-10-01T00:00:00Z","seal":{"alg":"hmac-sha256","key_id":"` + audit.SealKeyID(key) + `"}}}` + "\n")
	_ = f.Close()
	agentguard(t, dir, nil, "audit", "verify", "--key-file", keyFile).expect(t, 1, "BROKEN: no entry is sealed", "")
}
