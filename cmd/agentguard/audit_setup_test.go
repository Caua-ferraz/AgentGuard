package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

func testEntry(agent string) audit.Entry {
	return audit.Entry{
		Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		AgentID:   agent,
		SessionID: "sess-1",
		Request:   policy.ActionRequest{Scope: "shell", Command: "echo hi"},
		Result:    policy.CheckResult{Decision: policy.Allow, Rule: "allow:test"},
	}
}

func TestBuildAuditPipeline_FileUnbuffered(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")

	p, err := buildAuditPipeline(auditPath, false, nil,
		auditRotationOpts{}, auditBufferedOpts{Enabled: false})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := p.Logger.(*audit.FileLogger); !ok {
		t.Fatalf("unbuffered file backend should expose *audit.FileLogger, got %T", p.Logger)
	}
	if err := p.Logger.Log(testEntry("agent-file")); err != nil {
		t.Fatalf("log: %v", err)
	}
	p.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !bytes.Contains(data, []byte("agent-file")) {
		t.Errorf("audit file missing logged entry; got:\n%s", data)
	}
}

func TestBuildAuditPipeline_FileBuffered_DrainsOnClose(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")

	p, err := buildAuditPipeline(auditPath, false, nil,
		auditRotationOpts{}, auditBufferedOpts{Enabled: true, QueueSize: 64, Workers: 1})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := p.Logger.(*audit.BufferedAsyncLogger); !ok {
		t.Fatalf("buffered backend should expose *audit.BufferedAsyncLogger, got %T", p.Logger)
	}
	if err := p.Logger.Log(testEntry("agent-buffered")); err != nil {
		t.Fatalf("log: %v", err)
	}
	// Close must drain the queue into the file BEFORE closing the file —
	// the explicit cleanup ordering this type exists for.
	p.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !bytes.Contains(data, []byte("agent-buffered")) {
		t.Errorf("buffered entry not drained to file on Close; got:\n%s", data)
	}
}

func TestBuildAuditPipeline_StoreForcesBuffering(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Operator passed --audit-buffered=false; the store backend must
	// force it back on (DB writes never run on the /v1/check path).
	p, err := buildAuditPipeline(filepath.Join(dir, "audit.jsonl"), true, st,
		auditRotationOpts{}, auditBufferedOpts{Enabled: false, QueueSize: 64, Workers: 1})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, ok := p.Logger.(*audit.BufferedAsyncLogger); !ok {
		t.Fatalf("store backend must be wrapped in *audit.BufferedAsyncLogger, got %T", p.Logger)
	}
	if err := p.Logger.Log(testEntry("agent-store")); err != nil {
		t.Fatalf("log: %v", err)
	}
	p.Close() // drains into the still-open store

	got, err := st.QueryAudit(context.Background(), "", audit.QueryFilter{AgentID: "agent-store"})
	if err != nil {
		t.Fatalf("query store: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("store entries = %d, want 1", len(got))
	}
}
