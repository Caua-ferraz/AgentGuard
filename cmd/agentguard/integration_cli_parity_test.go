package main

// Parity test: `agentguard check` (offline CLI) must return the same
// decision string that POST /v1/check returns when both consult the same
// policy file. Without this test the CLI and server can drift from each
// other since they're two independent implementations of the same
// contract.
//
// Implementation note: we call executeCheck directly rather than
// shelling out to a built binary. Both the CLI and the server consume
// pkg/policy via the same provider abstraction, so this still exercises
// the parity contract end-to-end while staying within `go test`.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

// parityPolicy exercises ALLOW (shell ls), DENY (shell rm -rf), and
// REQUIRE_APPROVAL (cost > alert_threshold) — the three decisions the
// CLI exit-code contract maps to 0/1/2.
const parityPolicy = `version: "1"
name: at-cli-parity-policy

rules:
  - scope: shell
    allow:
      - pattern: "ls *"
    deny:
      - pattern: "rm -rf *"
        message: "destructive"

  - scope: cost
    limits:
      max_per_action: "$5.00"
      max_per_session: "$50.00"
      alert_threshold: "$1.00"
`

func writeParityPolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(parityPolicy), 0o600); err != nil {
		t.Fatalf("write parity policy: %v", err)
	}
	return p
}

func startParityServer(t *testing.T, policyPath string) string {
	t.Helper()
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

	dir := filepath.Dir(policyPath)
	logger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(func() { disp.Close() })

	srv := proxy.NewServer(proxy.Config{
		Port:     0,
		Engine:   eng,
		Logger:   logger,
		Notifier: disp,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "at-cli-parity",
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

// runCLICheck invokes the in-process check subcommand and returns the
// decision string + exit code. We capture stdout to extract the decision
// the CLI rendered; in JSON mode the CLI emits a CheckResult JSON line.
func runCLICheck(t *testing.T, policyPath, body string) (string, int) {
	t.Helper()
	f := &checkCmdFlags{
		PolicyPath: policyPath,
		RequestStr: body,
		OutputFmt:  "json",
	}
	var stdout, stderr bytes.Buffer
	code := executeCheck(f, strings.NewReader(""), &stdout, &stderr)
	if code == exitError {
		t.Fatalf("CLI exited with error: %s\nstderr=%s", stdout.String(), stderr.String())
	}
	// Output is one CheckResult JSON line.
	line := strings.TrimSpace(stdout.String())
	var res policy.CheckResult
	if err := json.NewDecoder(strings.NewReader(line)).Decode(&res); err != nil {
		t.Fatalf("decode CLI JSON output (line=%q): %v\nstderr=%s", line, err, stderr.String())
	}
	return string(res.Decision), code
}

// runServerCheck POSTs the same body to /v1/check and returns the
// decision string from the response.
func runServerCheck(t *testing.T, baseURL, body string) string {
	t.Helper()
	resp, err := http.Post(baseURL+"/v1/check", "application/json",
		strings.NewReader(body))
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
		t.Fatalf("decode server response: %v body=%s", err, raw)
	}
	return string(res.Decision)
}

// TestATIntegration_CLIServerParity walks five representative requests
// covering all three decision outcomes and asserts CLI ↔ server agreement.
func TestATIntegration_CLIServerParity(t *testing.T) {
	policyPath := writeParityPolicy(t)
	baseURL := startParityServer(t, policyPath)

	type fixture struct {
		name         string
		body         string
		wantDecision string
		wantCLIExit  int
	}
	cases := []fixture{
		{
			name:         "shell-allow-ls",
			body:         `{"scope":"shell","command":"ls -la","agent_id":"at-cli"}`,
			wantDecision: string(policy.Allow),
			wantCLIExit:  exitAllow,
		},
		{
			name:         "shell-deny-rmrf",
			body:         `{"scope":"shell","command":"rm -rf /","agent_id":"at-cli"}`,
			wantDecision: string(policy.Deny),
			wantCLIExit:  exitDeny,
		},
		{
			name:         "shell-default-deny-cat",
			body:         `{"scope":"shell","command":"cat /etc/passwd","agent_id":"at-cli"}`,
			wantDecision: string(policy.Deny),
			wantCLIExit:  exitDeny,
		},
		{
			name:         "cost-approval-threshold",
			body:         `{"scope":"cost","est_cost":2.50,"session_id":"s1","agent_id":"at-cli"}`,
			wantDecision: string(policy.RequireApproval),
			wantCLIExit:  exitApproval,
		},
		{
			name:         "cost-allow-under-threshold",
			body:         `{"scope":"cost","est_cost":0.50,"session_id":"s2","agent_id":"at-cli"}`,
			wantDecision: string(policy.Allow),
			wantCLIExit:  exitAllow,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cliDecision, cliExit := runCLICheck(t, policyPath, tc.body)
			serverDecision := runServerCheck(t, baseURL, tc.body)

			if cliDecision != serverDecision {
				t.Errorf("CLI/server decision mismatch: cli=%q server=%q (body=%s)",
					cliDecision, serverDecision, tc.body)
			}
			if cliDecision != tc.wantDecision {
				t.Errorf("decision = %q, want %q (body=%s)", cliDecision, tc.wantDecision, tc.body)
			}
			if cliExit != tc.wantCLIExit {
				t.Errorf("CLI exit = %d, want %d (decision=%q)", cliExit, tc.wantCLIExit, cliDecision)
			}
		})
	}

	// Sanity-print the policy path so a debug rerun is reproducible.
	_ = fmt.Sprintf("policy=%s", policyPath)
}
