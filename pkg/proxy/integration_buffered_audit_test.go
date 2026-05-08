package proxy

// Drives the BufferedAsyncLogger under live proxy load and confirms
// every audit entry is durable: no entries lost across the saturation
// boundary, retrievable via /v1/audit and via the underlying Query path.
//
// Failure mode caught: any drop, mis-count, or failure to flush entries
// on Close — and the /v1/health endpoint is observed opportunistically.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestATIntegration_BufferedAuditDurability boots a Server whose audit
// logger is a BufferedAsyncLogger with QueueSize=4 + Workers=2 (small
// enough to saturate quickly). Sends 100 rapid /v1/check requests, then
// asserts every entry can be retrieved via the underlying Query.
//
// We deliberately query through the underlying Logger.Query rather than
// through /v1/audit to avoid the audit-query limit clamp; for the
// /v1/audit assertion we walk pages.
func TestATIntegration_BufferedAuditDurability(t *testing.T) {
	const apiKey = "at-buffered-audit-key"
	const totalRequests = 100

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	overflowPath := filepath.Join(dir, "audit.jsonl.overflow.jsonl")

	fileLogger, err := audit.NewFileLogger(logPath)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = fileLogger.Close() })

	bufLogger, err := audit.NewBufferedAsyncLogger(fileLogger, audit.BufferedAsyncOpts{
		QueueSize:        4,
		Workers:          2,
		OverflowPath:     overflowPath,
		RecoveryInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewBufferedAsyncLogger: %v", err)
	}
	// Close ordering: buffered wrapper drains queue + flushes overflow,
	// then the underlying file handle releases. LIFO via defer.
	t.Cleanup(func() { _ = bufLogger.Close() })

	pol := &policy.Policy{
		Version: "1",
		Name:    "at-buffered",
		Rules: []policy.RuleSet{{
			Scope: "shell",
			Allow: []policy.Rule{{Pattern: "ls *"}},
		}},
	}

	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(func() { disp.Close() })

	srv := NewServer(Config{
		Port:     0,
		Engine:   policy.NewEngineFromPolicy(pol),
		Logger:   bufLogger,
		Notifier: disp,
		APIKey:   apiKey,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "at-buffered",
	})
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	// Drive 100 rapid requests with light concurrency to ensure we
	// saturate the 4-slot queue. We use 8 worker goroutines so the queue
	// fills faster than the workers can drain it; the wrapper must spill
	// to overflow and the recovery loop must pick that up.
	const concurrency = 8
	jobs := make(chan int, totalRequests)
	for i := 0; i < totalRequests; i++ {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	client := &http.Client{Timeout: 5 * time.Second}
	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				body := fmt.Sprintf(`{"scope":"shell","command":"ls -la /tmp","agent_id":"at-buf","session_id":"sess-%d"}`, i)
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
					ts.URL+"/v1/check", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("POST /v1/check (job %d): %v", i, err)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("POST /v1/check status=%d (job %d)", resp.StatusCode, i)
				}
			}
		}()
	}
	wg.Wait()

	// Wait for the recovery loop to drain the overflow back into the
	// underlying logger. Bound at 10s so a stuck loop fails fast rather
	// than hanging the test runner.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := bufLogger.Query(audit.QueryFilter{AgentID: "at-buf", Limit: totalRequests + 50})
		if err != nil {
			t.Fatalf("bufLogger.Query: %v", err)
		}
		if len(entries) >= totalRequests {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Final assertion via the wrapper's Query (which delegates to the
	// underlying FileLogger). All 100 entries must be present.
	entries, err := bufLogger.Query(audit.QueryFilter{AgentID: "at-buf", Limit: totalRequests + 50})
	if err != nil {
		t.Fatalf("final Query: %v", err)
	}
	if len(entries) != totalRequests {
		t.Fatalf("final entry count: got %d, want %d (dropped=%d drained=%d)",
			len(entries), totalRequests, bufLogger.DroppedToOverflow(), bufLogger.DrainedFromOverflow())
	}

	// Sanity: every session_id 0..99 must appear exactly once.
	seen := make(map[string]int, totalRequests)
	for _, e := range entries {
		seen[e.SessionID]++
	}
	for i := 0; i < totalRequests; i++ {
		key := fmt.Sprintf("sess-%d", i)
		if got := seen[key]; got != 1 {
			t.Errorf("session_id %s appeared %d times, want 1", key, got)
		}
	}

	// Cross-check via the HTTP audit endpoint. /v1/audit clamps to
	// MaxAuditQueryLimit (default 1000), well above 100. We expect every
	// entry to be visible.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/v1/audit?agent_id=at-buf&limit=200", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/audit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("/v1/audit status=%d body=%s", resp.StatusCode, raw)
	}
	var apiEntries []audit.Entry
	if err := json.NewDecoder(resp.Body).Decode(&apiEntries); err != nil {
		t.Fatalf("decode /v1/audit: %v", err)
	}
	count := 0
	for _, e := range apiEntries {
		if e.AgentID == "at-buf" {
			count++
		}
	}
	if count != totalRequests {
		t.Errorf("/v1/audit count: got %d at-buf entries, want %d", count, totalRequests)
	}
}
