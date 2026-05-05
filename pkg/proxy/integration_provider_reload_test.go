package proxy

// AT (Test Wrangler) integration test — Phase 2.
//
// Exercises three workers' surfaces stitched together:
//   - A5 (FilePolicyProvider + watcher-driven engine refresh)
//   - A7 (legacy /v1/check route)
//   - A10 (last_policy_load_at on /v1/health)
//
// Failure mode this test catches: a worker silently breaks the chain that
// connects "policy file changed on disk" to "engine returns the new
// decision" or "health endpoint reports the new load timestamp". Any of
// these regressions would let v0.6 ship with a stale-policy bug.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// writeReloadablePolicy writes a YAML file with shell rules. cmd is the
// allow pattern; everything else is denied by default-deny. Atomic via
// rename so the FilePolicyProvider's watcher sees a single event.
func writeReloadablePolicy(t *testing.T, path, name, allowPattern string) {
	t.Helper()
	body := []byte("version: \"1\"\nname: \"" + name + "\"\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"" + allowPattern + "\"\n")
	tmp := path + ".writing"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		t.Fatalf("write tmp policy file: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename tmp policy file: %v", err)
	}
}

// TestATIntegration_ProviderReloadE2E spins up a real Server backed by a
// FilePolicyProvider, sends a check that the initial policy ALLOWs,
// modifies the policy file, polls /v1/health for last_policy_load_at to
// advance, and asserts the same check now DENYs.
func TestATIntegration_ProviderReloadE2E(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	writeReloadablePolicy(t, policyPath, "v1-allow-ls", "ls *")

	prov, err := policy.NewFilePolicyProvider(policyPath)
	if err != nil {
		t.Fatalf("NewFilePolicyProvider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })

	eng, err := policy.NewEngine(prov)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(func() { disp.Close() })

	srv := NewServer(Config{
		Port:     0,
		Engine:   eng,
		Logger:   logger,
		Notifier: disp,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "at-reload",
	})
	ts := httptest.NewServer(srv.http.Handler)
	t.Cleanup(ts.Close)

	body := `{"scope":"shell","command":"ls -la","agent_id":"at-bot"}`
	postCheckRaw := func() policy.CheckResult {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /v1/check: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/v1/check status=%d body=%s", resp.StatusCode, raw)
		}
		var res policy.CheckResult
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&res); err != nil {
			t.Fatalf("decode CheckResult: %v body=%s", err, raw)
		}
		return res
	}
	getHealth := func() (string, []byte) {
		t.Helper()
		resp, err := http.Get(ts.URL + "/v1/health")
		if err != nil {
			t.Fatalf("GET /v1/health: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/v1/health status=%d body=%s", resp.StatusCode, raw)
		}
		var h map[string]any
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatalf("decode health: %v body=%s", err, raw)
		}
		ts, _ := h["last_policy_load_at"].(string)
		return ts, raw
	}

	// 1. Initial policy ALLOWs `ls -la`.
	res := postCheckRaw()
	if res.Decision != policy.Allow {
		t.Fatalf("initial decision: want ALLOW, got %s (rule=%s reason=%s)", res.Decision, res.Rule, res.Reason)
	}

	loadAtBefore, healthBefore := getHealth()
	if loadAtBefore == "" {
		t.Fatalf("initial /v1/health missing last_policy_load_at: %s", healthBefore)
	}

	// 2. Modify the policy on disk: drop the allow pattern, add a deny.
	// FilePolicyProvider relies on FileWatcher which uses fsnotify or
	// 2-second polling. mtime granularity on some filesystems is 1s; sleep
	// past it so the watcher observes a newer modtime.
	time.Sleep(1100 * time.Millisecond)
	body2 := []byte("version: \"1\"\nname: v2-deny-ls\nrules:\n  - scope: shell\n    deny:\n      - pattern: \"ls *\"\n        message: \"reloaded policy\"\n")
	tmp := policyPath + ".writing"
	if err := os.WriteFile(tmp, body2, 0o600); err != nil {
		t.Fatalf("rewrite policy: %v", err)
	}
	if err := os.Rename(tmp, policyPath); err != nil {
		t.Fatalf("rename rewrite: %v", err)
	}

	// 3. Poll up to 5s for the watcher to refresh the engine.
	deadline := time.Now().Add(5 * time.Second)
	var finalDecision policy.Decision
	var loadAtAfter string
	for time.Now().Before(deadline) {
		res := postCheckRaw()
		finalDecision = res.Decision
		ts, _ := getHealth()
		loadAtAfter = ts
		if finalDecision == policy.Deny && loadAtAfter != "" && loadAtAfter != loadAtBefore {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if finalDecision != policy.Deny {
		t.Fatalf("post-reload decision: want DENY, got %s after 5s of polling", finalDecision)
	}
	if loadAtAfter == "" {
		t.Fatalf("post-reload /v1/health last_policy_load_at empty")
	}
	if loadAtAfter == loadAtBefore {
		t.Fatalf("last_policy_load_at did not advance: before=%q after=%q", loadAtBefore, loadAtAfter)
	}

	// Sanity: the new timestamp parses and is recent.
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z07:00", loadAtAfter)
	if err != nil {
		t.Errorf("post-reload timestamp does not parse: %q err=%v", loadAtAfter, err)
	} else if time.Since(parsed) > 30*time.Second {
		t.Errorf("post-reload timestamp is older than 30s: %v", parsed)
	}
}
