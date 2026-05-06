package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalPolicy is the smallest YAML that exercises every decision the
// `check` subcommand can return. ALLOW and DENY come straight from the
// shell rules; REQUIRE_APPROVAL comes from the cost scope's
// alert_threshold (any est_cost > $1.00 over the threshold yields
// approval). It deliberately leaves the default-deny path uncovered for
// scopes other than shell/cost, because exercising it adds no signal:
// every scope falls through to the same default-DENY at the bottom of
// Engine.Check.
const minimalPolicy = `version: "1"
name: test-policy

rules:
  - scope: shell
    allow:
      - pattern: "ls"
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

// writePolicy writes minimalPolicy to a temp file and returns its path.
// Tests get a fresh dir per invocation, so file-level isolation is free.
func writePolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

// runCheckCmd is the thin test harness around executeCheck. Tests pass
// flag values + stdin and read back the captured stdout/stderr. Returning
// the exit code makes the assertion legend match `agentguard check`'s
// documented contract directly.
func runCheckCmd(t *testing.T, f *checkCmdFlags, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	var sout, serr bytes.Buffer
	code = executeCheck(f, strings.NewReader(stdin), &sout, &serr)
	return code, sout.String(), serr.String()
}

func TestCheck_SingleAllowExit0(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Scope:      "shell",
		Command:    "ls",
		AgentID:    "test",
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, "")
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitAllow, stderr)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("stdout missing ALLOW: %q", stdout)
	}
}

func TestCheck_SingleDenyExit1(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Scope:      "shell",
		Command:    "rm -rf /",
		AgentID:    "test",
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, "")
	if code != exitDeny {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitDeny, stderr)
	}
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("stdout missing DENY: %q", stdout)
	}
}

func TestCheck_SingleApprovalExit2(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Scope:      "cost",
		EstCost:    2.50, // > alert_threshold ($1.00), < max_per_action ($5.00)
		SessionID:  "s1",
		AgentID:    "test",
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, "")
	if code != exitApproval {
		t.Fatalf("exit = %d, want %d (stderr=%q stdout=%q)", code, exitApproval, stderr, stdout)
	}
	if !strings.Contains(stdout, "REQUIRE_APPROVAL") {
		t.Errorf("stdout missing REQUIRE_APPROVAL: %q", stdout)
	}
}

func TestCheck_BadPolicyExit3(t *testing.T) {
	f := &checkCmdFlags{
		PolicyPath: filepath.Join(t.TempDir(), "nonexistent.yaml"),
		Scope:      "shell",
		Command:    "ls",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
	if stderr == "" {
		t.Error("expected an error message on stderr")
	}
}

func TestCheck_BatchMixedExitMaxSeverity(t *testing.T) {
	policy := writePolicy(t)
	// Order: allow + approval + deny — exit must be 1 (deny dominates).
	stdin := strings.Join([]string{
		`{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		`{"scope":"cost","est_cost":2.5,"session_id":"s1","agent_id":"bot1"}`,
		`{"scope":"shell","command":"rm -rf /","agent_id":"bot1"}`,
	}, "\n")
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, stdin)
	if code != exitDeny {
		t.Fatalf("exit = %d, want %d (stderr=%q stdout=%q)", code, exitDeny, stderr, stdout)
	}
	for _, want := range []string{"ALLOW", "REQUIRE_APPROVAL", "DENY"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %s: %q", want, stdout)
		}
	}
}

func TestCheck_BatchAllAllowExit0(t *testing.T) {
	policy := writePolicy(t)
	stdin := strings.Join([]string{
		`{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		`{"scope":"shell","command":"ls -la","agent_id":"bot1"}`,
	}, "\n")
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, stdin)
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q stdout=%q)", code, exitAllow, stderr, stdout)
	}
	if strings.Count(stdout, "ALLOW") != 2 {
		t.Errorf("stdout should contain 2 ALLOW lines: %q", stdout)
	}
}

func TestCheck_BatchOneApprovalNoDenyExit2(t *testing.T) {
	policy := writePolicy(t)
	stdin := strings.Join([]string{
		`{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		`{"scope":"cost","est_cost":2.5,"session_id":"s1","agent_id":"bot1"}`,
	}, "\n")
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, stdin)
	if code != exitApproval {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitApproval, stderr)
	}
}

func TestCheck_StdinMode(t *testing.T) {
	policy := writePolicy(t)
	stdin := `{"scope":"shell","command":"ls","agent_id":"bot1"}`
	f := &checkCmdFlags{
		PolicyPath: policy,
		Stdin:      true,
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, stdin)
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitAllow, stderr)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("stdout missing ALLOW: %q", stdout)
	}
}

func TestCheck_RequestStringMode(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		RequestStr: `{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, "")
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitAllow, stderr)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("stdout missing ALLOW: %q", stdout)
	}
}

func TestCheck_FlagBasedSingleCheck(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Scope:      "shell",
		Command:    "ls -la /tmp",
		AgentID:    "bot1",
		Meta:       "team=ml,prio=high",
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, f, "")
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitAllow, stderr)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("stdout missing ALLOW: %q", stdout)
	}
}

func TestCheck_MutuallyExclusiveModesRejected(t *testing.T) {
	policy := writePolicy(t)
	// --request AND --stdin both set
	f := &checkCmdFlags{
		PolicyPath: policy,
		RequestStr: `{"scope":"shell","command":"ls"}`,
		Stdin:      true,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("stderr should mention mutual exclusion: %q", stderr)
	}

	// --stdin AND --batch both set
	f2 := &checkCmdFlags{
		PolicyPath: policy,
		Stdin:      true,
		Batch:      true,
		OutputFmt:  "text",
	}
	code2, _, stderr2 := runCheckCmd(t, f2, "")
	if code2 != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code2, exitError, stderr2)
	}
}

func TestCheck_OutputJSON(t *testing.T) {
	policy := writePolicy(t)
	stdin := strings.Join([]string{
		`{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		`{"scope":"shell","command":"rm -rf /","agent_id":"bot1"}`,
	}, "\n")
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "json",
	}
	code, stdout, stderr := runCheckCmd(t, f, stdin)
	if code != exitDeny {
		t.Fatalf("exit = %d, want %d (stderr=%q stdout=%q)", code, exitDeny, stderr, stdout)
	}
	// Each non-empty stdout line must parse as a CheckResult JSON object.
	for i, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		var got struct {
			SchemaVersion string `json:"schema_version"`
			Decision      string `json:"decision"`
		}
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Errorf("line %d not valid JSON: %v (line=%q)", i, err, line)
			continue
		}
		if got.SchemaVersion != "v1" {
			t.Errorf("line %d schema_version=%q want v1", i, got.SchemaVersion)
		}
		if got.Decision != "ALLOW" && got.Decision != "DENY" {
			t.Errorf("line %d decision=%q unexpected", i, got.Decision)
		}
	}
}

func TestCheck_TenantID(t *testing.T) {
	policy := writePolicy(t)

	// Local tenant — same behavior as default.
	fLocal := &checkCmdFlags{
		PolicyPath: policy,
		TenantID:   "local",
		Scope:      "shell",
		Command:    "ls",
		OutputFmt:  "text",
	}
	code, stdout, stderr := runCheckCmd(t, fLocal, "")
	if code != exitAllow {
		t.Fatalf("local tenant exit = %d, want %d (stderr=%q)", code, exitAllow, stderr)
	}
	if !strings.Contains(stdout, "ALLOW") {
		t.Errorf("local tenant stdout missing ALLOW: %q", stdout)
	}

	// Unknown tenant — engine surfaces deny:tenant:not_found.
	fUnknown := &checkCmdFlags{
		PolicyPath: policy,
		TenantID:   "no-such-tenant",
		Scope:      "shell",
		Command:    "ls",
		OutputFmt:  "text",
	}
	code, stdout, _ = runCheckCmd(t, fUnknown, "")
	if code != exitDeny {
		t.Fatalf("unknown tenant exit = %d, want %d (stdout=%q)", code, exitDeny, stdout)
	}
	if !strings.Contains(stdout, "DENY") {
		t.Errorf("unknown tenant stdout missing DENY: %q", stdout)
	}
	if !strings.Contains(stdout, "tenant:not_found") {
		t.Errorf("unknown tenant rule should be deny:tenant:not_found: %q", stdout)
	}
}

func TestCheck_MissingPolicyFlag(t *testing.T) {
	f := &checkCmdFlags{
		Scope:   "shell",
		Command: "ls",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
	if !strings.Contains(stderr, "--policy") {
		t.Errorf("stderr should mention --policy: %q", stderr)
	}
}

func TestCheck_MalformedRequestJSON(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		RequestStr: `{not json}`,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "not valid JSON") {
		t.Errorf("stderr should call out JSON failure: %q", stderr)
	}
}

func TestCheck_BatchMalformedLineExits3(t *testing.T) {
	policy := writePolicy(t)
	stdin := strings.Join([]string{
		`{"scope":"shell","command":"ls","agent_id":"bot1"}`,
		`{this is not valid json}`,
	}, "\n")
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, stdin)
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
	if !strings.Contains(stderr, "line 2") {
		t.Errorf("stderr should localize the bad line: %q", stderr)
	}
}

func TestCheck_BatchEmptyExits3(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Batch:      true,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
}

func TestCheck_InvalidOutputFormatExits3(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Scope:      "shell",
		Command:    "ls",
		OutputFmt:  "xml",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "--output") {
		t.Errorf("stderr should mention --output: %q", stderr)
	}
}

func TestCheck_FlagBasedRequiresScope(t *testing.T) {
	policy := writePolicy(t)
	f := &checkCmdFlags{
		PolicyPath: policy,
		Command:    "ls",
		// no Scope
		OutputFmt: "text",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "--scope") {
		t.Errorf("stderr should mention --scope: %q", stderr)
	}
}

func TestCheck_DecodeRejectsUnknownField(t *testing.T) {
	policy := writePolicy(t)
	// "actions" instead of "action" — should not silently fall through.
	f := &checkCmdFlags{
		PolicyPath: policy,
		RequestStr: `{"scope":"filesystem","actions":"read","path":"/tmp/x"}`,
		OutputFmt:  "text",
	}
	code, _, stderr := runCheckCmd(t, f, "")
	if code != exitError {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitError, stderr)
	}
}

func TestParseMetaFlag(t *testing.T) {
	tests := []struct {
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"", nil, false},
		{"k=v", map[string]string{"k": "v"}, false},
		{"a=1,b=2", map[string]string{"a": "1", "b": "2"}, false},
		{" a = 1 , b = 2 ", map[string]string{"a": "1", "b": "2"}, false},
		{"a=", map[string]string{"a": ""}, false},
		{"=v", nil, true},
		{"missing-equals", nil, true},
	}
	for _, tc := range tests {
		got, err := parseMetaFlag(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseMetaFlag(%q) = nil err, want err", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMetaFlag(%q) err = %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseMetaFlag(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("parseMetaFlag(%q)[%q] = %q, want %q", tc.in, k, got[k], v)
			}
		}
	}
}

func TestRunCheck_HelpExitsZero(t *testing.T) {
	// `-h` should be treated as a friendly help request, not a usage
	// error. The Go stdlib flag package surfaces this as flag.ErrHelp;
	// runCheck must intercept and exit 0.
	var sout, serr bytes.Buffer
	code := runCheck([]string{"-h"}, strings.NewReader(""), &sout, &serr)
	if code != exitAllow {
		t.Fatalf("exit = %d, want %d (stderr=%q)", code, exitAllow, serr.String())
	}
	if !strings.Contains(serr.String(), "Usage:") {
		t.Errorf("stderr should contain Usage block: %q", serr.String())
	}
}

func TestRunCheck_UnknownFlagExits3(t *testing.T) {
	var sout, serr bytes.Buffer
	code := runCheck([]string{"--no-such-flag"}, strings.NewReader(""), &sout, &serr)
	if code != exitError {
		t.Fatalf("exit = %d, want %d", code, exitError)
	}
}

func TestExitForDecision(t *testing.T) {
	if exitForDecision("ALLOW") != exitAllow {
		t.Error("ALLOW")
	}
	if exitForDecision("DENY") != exitDeny {
		t.Error("DENY")
	}
	if exitForDecision("REQUIRE_APPROVAL") != exitApproval {
		t.Error("REQUIRE_APPROVAL")
	}
	if exitForDecision("UNKNOWN") != exitError {
		t.Error("UNKNOWN should map to error")
	}
}
