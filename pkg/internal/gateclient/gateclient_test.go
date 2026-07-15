package gateclient

import (
	"errors"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

var testRules = FailModeRules{
	Open:        "allow:test:fail_open",
	Closed:      "deny:test:fail_closed",
	ClosedAudit: "deny:test:fail_closed_audit",
	Invalid:     "deny:test:invalid_response",
}

func TestInferFilesystemAction(t *testing.T) {
	cases := map[string]string{
		"read_file":   "read",
		"list_files":  "read",
		"get_file":    "read",
		"stat_file":   "read",
		"cat":         "read",
		"find_files":  "read",
		"glob":        "read",
		"write_file":  "write",
		"edit_file":   "write",
		"create_dir":  "write",
		"append_file": "write",
		"delete_file": "delete",
		"remove_dir":  "delete",
		"unlink":      "delete",
		"unknown":     "",
	}
	for in, want := range cases {
		if got := InferFilesystemAction(in); got != want {
			t.Errorf("InferFilesystemAction(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstStringArg(t *testing.T) {
	args := map[string]interface{}{"cmd": "ls", "empty": "", "n": 1}
	if got := FirstStringArg(args, "command", "cmd"); got != "ls" {
		t.Errorf("FirstStringArg = %q, want ls", got)
	}
	if got := FirstStringArg(args, "empty", "n", "missing"); got != "" {
		t.Errorf("FirstStringArg non-string/empty = %q, want \"\"", got)
	}
	if got := FirstStringArg(nil, "command"); got != "" {
		t.Errorf("FirstStringArg(nil) = %q, want \"\"", got)
	}
}

func TestFailModeDecision(t *testing.T) {
	err := errors.New("boom")
	cases := []struct {
		mode      string
		wantAllow bool
		wantRule  string
	}{
		{"allow", true, testRules.Open},
		{"ALLOW", true, testRules.Open},
		{"fail-closed-with-audit", false, testRules.ClosedAudit},
		{"deny", false, testRules.Closed},
		{"", false, testRules.Closed},
		{"garbage", false, testRules.Closed},
	}
	for _, tc := range cases {
		d := FailModeDecision(tc.mode, err, testRules)
		if d.Allow != tc.wantAllow || d.Rule != tc.wantRule {
			t.Errorf("FailModeDecision(%q) = {Allow:%v Rule:%q}, want {Allow:%v Rule:%q}",
				tc.mode, d.Allow, d.Rule, tc.wantAllow, tc.wantRule)
		}
	}
}

func TestDecisionFromCheckResult_UnknownDecisionDeniesWithInvalidRule(t *testing.T) {
	d := DecisionFromCheckResult(policy.CheckResult{Decision: "GARBAGE"}, testRules)
	if d.Allow {
		t.Fatal("unknown decision must deny")
	}
	if d.Rule != testRules.Invalid {
		t.Errorf("Rule = %q, want %q", d.Rule, testRules.Invalid)
	}
	if d.Reason == "" {
		t.Error("Reason must explain the unknown decision")
	}
}
