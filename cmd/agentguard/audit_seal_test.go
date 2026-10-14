package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestAuditSealFromFlags(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "seal.key")
	if err := os.WriteFile(key, []byte("an-hmac-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open.key")
	if err := os.WriteFile(open, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(open, 0o644)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
		wantKey  string
	}{
		{"off by default", nil, 0, "", ""},
		{"on without a key", []string{"--audit-seal"}, 0, "", ""},
		{"on with a key", []string{"--audit-seal", "--audit-seal-key-file", key}, 0, "", "an-hmac-key"},
		{"key file without --audit-seal", []string{"--audit-seal-key-file", key}, exitUsage, "needs --audit-seal", ""},
		{"store backend", []string{"--audit-seal", "--audit-backend", "store"}, exitUsage, "file audit backend only", ""},
		{"negative anchor interval", []string{"--audit-seal", "--audit-anchor-interval", "-1s"}, exitUsage, "negative", ""},
		{"missing key file", []string{"--audit-seal", "--audit-seal-key-file", filepath.Join(dir, "nope")}, 1, "seal key file", ""},
		{"empty key file", []string{"--audit-seal", "--audit-seal-key-file", empty}, 1, "empty", ""},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name     string
			args     []string
			wantCode int
			wantErr  string
			wantKey  string
		}{"world-readable key file", []string{"--audit-seal", "--audit-seal-key-file", open}, 1, "chmod 600", ""})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, f := newServerFlags()
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			o, code, err := auditSealFromFlags(f)
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d (err %v)", code, tc.wantCode, err)
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if string(o.Key) != tc.wantKey {
				t.Errorf("key = %q, want %q", o.Key, tc.wantKey)
			}
		})
	}
}

func waitForCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The full server pipeline (redaction, buffered workers, rotation) writes a
// chain that verifies.
func TestBuildAuditPipeline_Sealed(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	transform := func(e audit.Entry) audit.Entry {
		e.Request.Command = strings.ReplaceAll(e.Request.Command, "secret", "[REDACTED]")
		return e
	}
	p, err := buildAuditPipeline(auditPath, false, nil,
		auditRotationOpts{MaxSizeMB: 1, MaxBackups: 2, Compress: true},
		auditBufferedOpts{Enabled: true, QueueSize: 64, Workers: 4},
		auditSealOpts{Enabled: true, Key: []byte("k"), NodeID: "node-1"}, transform)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		_ = p.Logger.Log(audit.Entry{AgentID: "bot", Request: policy.ActionRequest{Scope: "shell", Command: "echo secret"}})
	}
	// The head is reachable through the buffered and redacting wrappers,
	// which is how GET /v1/audit/head finds it.
	h, ok := p.Logger.(audit.SealHeader)
	if !ok {
		t.Fatal("the pipeline logger does not report a seal head")
	}
	waitForCond(t, func() bool { a, ok := h.SealHead(); return ok && a.Seq == 50 })
	p.Close()

	rep, err := audit.VerifyChain(auditPath, audit.VerifyOptions{Keys: [][]byte{[]byte("k")}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Entries != 50 {
		t.Fatalf("report = %+v break %+v", rep, rep.Break)
	}
	b, _ := os.ReadFile(auditPath)
	if strings.Contains(string(b), "echo secret") || !strings.Contains(string(b), `"node_id":"node-1"`) {
		t.Errorf("the sealed file should hold the redacted command and the node id:\n%s", b)
	}

	if _, err := buildAuditPipeline(auditPath, true, nil, auditRotationOpts{}, auditBufferedOpts{}, auditSealOpts{Enabled: true}, nil); err == nil {
		t.Error("sealing with the store backend was accepted")
	}
}
