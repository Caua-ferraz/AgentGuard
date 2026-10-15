package main

// Unit tests for `agentguard test` (test_cmd.go). The end-to-end runs of
// the real binary are at the bottom, through the re-exec helper in
// cli_exec_test.go.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/configs"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// writeTestFile writes content to dir/name, creating folders on the way, and
// returns the path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// runTestHarness is the harness around executeTest: it returns the exit code
// and what was printed.
func runTestHarness(t *testing.T, f *testCmdFlags) (code int, stdout, stderr string) {
	t.Helper()
	if f.Output == "" {
		f.Output = testOutputText
	}
	var sout, serr bytes.Buffer
	code = executeTest(f, &sout, &serr)
	return code, sout.String(), serr.String()
}

// passingFixture and failingFixture run against minimalPolicy (from
// check_cmd_test.go): ls is allowed, rm -rf is denied.
const passingFixture = `policy: policy.yaml
tests:
  - name: ls is allowed
    request: {scope: shell, command: "ls -la"}
    expect: ALLOW
    expect_rule: "allow:shell:ls *"
  - name: rm -rf is denied
    request: {scope: shell, command: "rm -rf /"}
    expect: DENY
    expect_reason_contains: destructive
`

const failingFixture = `policy: policy.yaml
tests:
  - name: ls is allowed
    request: {scope: shell, command: "ls -la"}
    expect: ALLOW
  - name: rm -rf is wrongly expected to pass
    request: {scope: shell, command: "rm -rf /"}
    expect: ALLOW
    expect_rule: "allow:*"
`

// fixtureDir writes minimalPolicy and the given fixtures into a temp dir.
func fixtureDir(t *testing.T, fixtures map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", minimalPolicy)
	for name, content := range fixtures {
		writeTestFile(t, dir, name, content)
	}
	return dir
}

func TestParseFixture(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // "" means it must parse
	}{
		{"a valid file parses", passingFixture, ""},
		{"prior entries parse", `tests:
  - name: gated
    prior: [{scope: shell, command: "make test", agent_id: dev}]
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: ALLOW
`, ""},
		{"an unknown top-level key is rejected", "polcy: x.yaml\ntests: []\n", `unknown key "polcy"`},
		{"an unknown case key is rejected", `tests:
  - name: x
    request: {scope: shell, command: ls}
    expect: ALLOW
    expect_rul: "allow:*"
`, `unknown key "expect_rul"`},
		{"an unknown request key is rejected", `tests:
  - name: x
    request: {scope: shell, cmd: ls}
    expect: ALLOW
`, `unknown key "cmd"`},
		{"an unknown prior key is rejected", `tests:
  - name: x
    prior: [{scope: shell, comand: ls}]
    request: {scope: shell, command: ls}
    expect: ALLOW
`, `unknown key "comand"`},
		{"the error does not name Go types", "nope: 1\n", "line 1"},
		{"an empty file is rejected", "", "empty"},
		{"a file with no cases is rejected", "policy: p.yaml\n", "no test cases"},
		{"a case needs a name", "tests:\n  - request: {scope: shell, command: ls}\n    expect: ALLOW\n", "tests[0] needs a name"},
		{"case names are unique in a file", `tests:
  - {name: x, request: {scope: shell, command: ls}, expect: ALLOW}
  - {name: x, request: {scope: shell, command: ls}, expect: ALLOW}
`, "same name"},
		{"a case needs a request", "tests:\n  - {name: x, expect: ALLOW}\n", "needs a request"},
		{"a request needs a scope", "tests:\n  - {name: x, request: {command: ls}, expect: ALLOW}\n", "needs a scope"},
		{"a case needs an expectation", "tests:\n  - {name: x, request: {scope: shell, command: ls}}\n", "needs expect"},
		{"expect must be a decision", "tests:\n  - {name: x, request: {scope: shell, command: ls}, expect: allow}\n", `expect is "allow"`},
		{"a second YAML document is rejected, not skipped", `tests:
  - {name: a, request: {scope: shell, command: ls}, expect: ALLOW}
---
tests:
  - {name: b, request: {scope: shell, command: "rm -rf /"}, expect: ALLOW}
`, "line 3: a second YAML document"},
		{"a case that is not a mapping names the shape, not a Go type", "tests:\n  - \"just a string\"\n", "expected a test case"},
		{"tests that are not a list names the shape, not a Go type", "tests: {a: 1}\n", "expected a list of test cases"},
		{"a prior entry needs an action or a command", `tests:
  - name: x
    prior: [{scope: shell}]
    request: {scope: shell, command: ls}
    expect: ALLOW
`, "prior[0] needs a scope and an action or a command"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixture([]byte(tc.yaml))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("parsed; want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "main.") {
				t.Errorf("error names a Go type: %v", err)
			}
		})
	}
}

// TestTest_ExpectRuleIsExact: rule names hold policy patterns with `*` in
// them, so expect_rule compares the whole name. A wildcard reading would let
// "allow:shell:*" pass a case that matched a different, broader rule.
func TestTest_ExpectRuleIsExact(t *testing.T) {
	cases := []struct {
		rule string
		want int
	}{
		{"allow:shell:ls *", testExitPassed},
		{"allow:shell:*", testExitFailed},
		{"allow:shell:ls", testExitFailed},
	}
	for _, tc := range cases {
		dir := fixtureDir(t, map[string]string{"rule_test.yaml": `policy: policy.yaml
tests:
  - name: ls
    request: {scope: shell, command: "ls -la"}
    expect: ALLOW
    expect_rule: "` + tc.rule + `"
`})
		if code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}}); code != tc.want {
			t.Errorf("expect_rule %q: exit %d, want %d\n%s", tc.rule, code, tc.want, stdout)
		}
	}
}

// TestTest_TenantChecksThePolicyAsThatTenant: `tenant:` runs the policy as
// that tenant. It used to find no policy for any tenant but local, so every
// case got deny:tenant:not_found and DENY expectations passed untested.
func TestTest_TenantChecksThePolicyAsThatTenant(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"tenant_test.yaml": `policy: policy.yaml
tenant: acme
tests:
  - name: ls is allowed for acme
    request: {scope: shell, command: "ls -la"}
    expect: ALLOW
  - name: rm -rf is denied by the policy, not by a missing tenant
    request: {scope: shell, command: "rm -rf /"}
    expect: DENY
    expect_rule: "deny:shell:rm -rf *"
`})
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}

// TestTest_FolderFindsYmlFixtures: a folder scan picks up *_test.yml as well
// as *_test.yaml, so a .yml file's cases cannot be skipped without a word.
func TestTest_FolderFindsYmlFixtures(t *testing.T) {
	dir := fixtureDir(t, map[string]string{
		"a_test.yaml": passingFixture,
		"b_test.yml":  failingFixture,
	})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitFailed || !strings.Contains(stdout, "b_test.yml") {
		t.Fatalf("exit %d, want 1 with b_test.yml's failing case reported\n%s", code, stdout)
	}
}

func TestTest_AllPassExits0(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"shell_test.yaml": passingFixture})
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"PASS  ls is allowed", "PASS  rm -rf is denied", "PASS: 2 case(s) passed"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestTest_FailureExits1AndShowsWantAndGot(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"shell_test.yaml": failingFixture})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitFailed {
		t.Fatalf("exit = %d, want 1\n%s", code, stdout)
	}
	for _, want := range []string{
		"PASS  ls is allowed",
		"FAIL  rm -rf is wrongly expected to pass",
		"want ALLOW, got DENY",
		`rule:   "deny:shell:rm -rf *", want "allow:*"`,
		`reason: "destructive"`,
		"FAIL: 1 of 2 case(s) failed",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

func TestTest_ReasonMismatchFails(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"r_test.yaml": `policy: policy.yaml
tests:
  - name: right decision, wrong reason
    request: {scope: shell, command: "rm -rf /"}
    expect: DENY
    expect_reason_contains: "something else"
`})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitFailed || !strings.Contains(stdout, `want it to contain "something else"`) {
		t.Fatalf("exit = %d, want 1 with the reason mismatch shown:\n%s", code, stdout)
	}
}

func TestTest_LoadErrorsExit3AndRunNothing(t *testing.T) {
	cases := []struct {
		name     string
		fixtures map[string]string
		args     func(dir string) []string
		wantErr  string
	}{
		{
			name:     "a fixture with an unknown key",
			fixtures: map[string]string{"a_test.yaml": passingFixture, "b_test.yaml": "policy: policy.yaml\ntests:\n  - {name: x, request: {scope: shell, command: ls}, expect: ALLOW, expct: DENY}\n"},
			args:     func(dir string) []string { return []string{dir} },
			wantErr:  `b_test.yaml: line 3: unknown key "expct"`,
		},
		{
			name:     "a policy file that does not exist",
			fixtures: map[string]string{"a_test.yaml": passingFixture, "b_test.yaml": strings.Replace(passingFixture, "policy.yaml", "missing.yaml", 1)},
			args:     func(dir string) []string { return []string{dir} },
			wantErr:  "missing.yaml",
		},
		{
			name:     "a fixture file that does not exist",
			fixtures: map[string]string{"a_test.yaml": passingFixture},
			args:     func(dir string) []string { return []string{dir, filepath.Join(dir, "nope_test.yaml")} },
			wantErr:  "nope_test.yaml",
		},
		{
			name:     "a folder with no fixtures",
			fixtures: map[string]string{"a_test.yaml": passingFixture, "empty/README": "x"},
			args:     func(dir string) []string { return []string{dir, filepath.Join(dir, "empty")} },
			wantErr:  "has no *_test.yaml or *_test.yml files",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := fixtureDir(t, tc.fixtures)
			code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: tc.args(dir)})
			if code != testExitNoLoad {
				t.Fatalf("exit = %d, want 3\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr lacks %q:\n%s", tc.wantErr, stderr)
			}
			if stdout != "" {
				t.Errorf("cases ran although a fixture did not load:\n%s", stdout)
			}
		})
	}
}

// policy: is relative to the fixture's folder, not the working directory,
// and wins over --policy.
func TestTest_PolicyPathIsRelativeToTheFixture(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "policies/shell.yaml", minimalPolicy)
	writeTestFile(t, dir, "tests/shell_test.yaml", strings.Replace(passingFixture, "policy.yaml", "../policies/shell.yaml", 1))
	// An --policy that would deny everything: it must not be used.
	other := writeTestFile(t, dir, "deny-all.yaml", "version: \"1\"\nname: deny-all\nrules: []\n")

	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{filepath.Join(dir, "tests")}, PolicyPath: other})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if want := filepath.Join(dir, "policies", "shell.yaml"); !strings.Contains(stdout, want) {
		t.Errorf("stdout does not name the policy %s:\n%s", want, stdout)
	}
}

// A fixture without policy: uses --policy.
func TestTest_PolicyFlagForFixturesWithoutOne(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"shell_test.yaml": strings.Replace(passingFixture, "policy: policy.yaml\n", "", 1)})
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, PolicyPath: filepath.Join(dir, "policy.yaml")})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// Only *_test.yaml files are picked up from a folder, and its subfolders
// are not searched.
func TestTest_FolderScan(t *testing.T) {
	dir := fixtureDir(t, map[string]string{
		"a_test.yaml":        passingFixture,
		"notes.yaml":         "not: a fixture\n",
		"nested/b_test.yaml": failingFixture,
	})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0 (only a_test.yaml should run):\n%s", code, stdout)
	}
	if strings.Contains(stdout, "b_test.yaml") || !strings.Contains(stdout, "a_test.yaml") {
		t.Errorf("wrong files ran:\n%s", stdout)
	}
}

func TestTest_RunFilter(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"shell_test.yaml": failingFixture})

	// Filtering the failing case out makes the run pass.
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Run: regexp.MustCompile("^ls")})
	if code != testExitPassed || strings.Contains(stdout, "rm -rf") || !strings.Contains(stdout, "PASS: 1 case(s) passed") {
		t.Fatalf("exit = %d, want 0 with only the ls case:\n%s", code, stdout)
	}

	// A --run that matches nothing must not pass CI silently.
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Run: regexp.MustCompile("no such case")})
	if code != testExitFailed || !strings.Contains(stderr, "no case name matches --run") {
		t.Fatalf("exit = %d, want 1 with a message\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

func TestTest_JUnitOutputIsWellFormed(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"a_test.yaml": passingFixture, "b_test.yaml": failingFixture})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Output: testOutputJUnit})
	if code != testExitFailed {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.HasPrefix(stdout, "<?xml") {
		t.Errorf("no XML declaration:\n%s", stdout)
	}
	var doc junitSuites
	if err := xml.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("output is not valid XML: %v\n%s", err, stdout)
	}
	if doc.Tests != 4 || doc.Failures != 1 || len(doc.Suites) != 2 {
		t.Fatalf("tests=%d failures=%d suites=%d, want 4, 1, 2\n%s", doc.Tests, doc.Failures, len(doc.Suites), stdout)
	}
	b := doc.Suites[1]
	if !strings.HasSuffix(b.Name, "b_test.yaml") || b.Tests != 2 || b.Failures != 1 {
		t.Errorf("second suite = %+v", b)
	}
	failed := b.Cases[1]
	if failed.Failure == nil || !strings.Contains(failed.Failure.Message, "want ALLOW, got DENY") || !strings.Contains(failed.Failure.Text, "destructive") {
		t.Errorf("failed case = %+v", failed)
	}
	if b.Cases[0].Failure != nil {
		t.Errorf("a passing case has a failure: %+v", b.Cases[0])
	}
}

func TestTest_JSONOutput(t *testing.T) {
	dir := fixtureDir(t, map[string]string{"b_test.yaml": failingFixture})
	code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Output: testOutputJSON})
	if code != testExitFailed {
		t.Fatalf("exit = %d, want 1", code)
	}
	var rep testReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if rep.Passed != 1 || rep.Failed != 1 || len(rep.Cases) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	c := rep.Cases[1]
	if c.Passed || c.Decision != "DENY" || c.Rule != "deny:shell:rm -rf *" || len(c.Failures) != 2 {
		t.Errorf("failed case = %+v", c)
	}
}

// requirePriorPolicy allows a deploy only after the tests ran.
const requirePriorPolicy = `version: "1"
name: gated
rules:
  - scope: shell
    allow:
      - pattern: "make test"
      - pattern: "make deploy"
        conditions:
          - require_prior: "make test"
            time_window: "10m"
`

func TestTest_PriorSeedsRequirePriorHistory(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", requirePriorPolicy)
	writeTestFile(t, dir, "gate_test.yaml", `policy: policy.yaml
tests:
  - name: deploy without tests is denied
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: DENY
  - name: deploy after tests is allowed
    prior: [{scope: shell, command: "make test", agent_id: dev}]
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: ALLOW
  - name: another agent's tests do not count
    prior: [{scope: shell, command: "make test", agent_id: someone-else}]
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: DENY
  - name: the earlier case's prior does not leak into this one
    request: {scope: shell, command: "make deploy", agent_id: dev}
    expect: DENY
`)
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// Each case gets its own engine, so cost reserved in one case does not
// count against the next. With a shared engine the second case would be
// denied for going over max_per_session.
func TestTest_CasesDoNotShareCost(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", `version: "1"
name: cost
rules:
  - scope: cost
    limits:
      max_per_action: "$1.00"
      max_per_session: "$1.00"
`)
	writeTestFile(t, dir, "cost_test.yaml", `policy: policy.yaml
tests:
  - name: first spend
    request: {scope: cost, est_cost: 0.75, session_id: s1}
    expect: ALLOW
  - name: same spend on the same session
    request: {scope: cost, est_cost: 0.75, session_id: s1}
    expect: ALLOW
`)
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0 (cost leaked between cases)\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

func TestTest_StrictFailsOnPolicyWarnings(t *testing.T) {
	dir := t.TempDir()
	// "shel" is one edit from "shell": it loads, with a warning.
	writeTestFile(t, dir, "policy.yaml", strings.Replace(minimalPolicy, "scope: shell", "scope: shel", 1))
	writeTestFile(t, dir, "x_test.yaml", `policy: policy.yaml
tests:
  - name: the misspelled scope matches nothing
    request: {scope: shell, command: "ls -la"}
    expect: DENY
`)
	code, _, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed || !strings.Contains(stderr, "WARN:") {
		t.Fatalf("without --strict: exit = %d, want 0 with a warning\nstderr: %s", code, stderr)
	}
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Strict: true})
	if code != testExitNoLoad || !strings.Contains(stderr, "--strict") || stdout != "" {
		t.Fatalf("with --strict: exit = %d, want 3\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

func TestTest_ShippedFixturesPass(t *testing.T) {
	dir := filepath.Join(repoRootForDocs(t), "configs", "tests")
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Strict: true})
	if code != testExitPassed {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, f := range []string{
		"default_test.yaml", "research-agent_test.yaml", "trading-bot_test.yaml",
		"claude-code_test.yaml", "cursor_test.yaml", "gemini-cli_test.yaml", "codex_test.yaml",
	} {
		if !strings.Contains(stdout, f) {
			t.Errorf("%s did not run:\n%s", f, stdout)
		}
	}
}

// codingAgentsPolicyHeader opens configs/tests/coding-agents.yaml.
const codingAgentsPolicyHeader = `# The starter policy (configs/default.yaml) with every coding agent's block
# under agents:, as 'agentguard setup' leaves it once Claude Code, Cursor,
# Gemini CLI and Codex CLI are all connected. The cursor, gemini-cli and
# codex fixtures in this folder run against it, because those blocks
# (configs/cursor.yaml and the others) are fragments that only load inside
# a policy. Don't edit it by hand: TestTest_CodingAgentsPolicyIsCurrent in
# cmd/agentguard/test_cmd_test.go checks it, and rewrites it with
#
#   AGENTGUARD_WRITE_TEST_POLICY=1 go test ./cmd/agentguard -run TestTest_CodingAgentsPolicyIsCurrent
#
`

// TestTest_CodingAgentsPolicyIsCurrent: configs/tests/coding-agents.yaml is
// a copy of the starter policy and the agent blocks, so a change to either
// that isn't copied there would leave the shipped hook cases testing old
// rules. The test builds the policy the way setup does and compares.
func TestTest_CodingAgentsPolicyIsCurrent(t *testing.T) {
	lf := func(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
	path := filepath.Join(t.TempDir(), "coding-agents.yaml")
	writeTestFile(t, filepath.Dir(path), filepath.Base(path), codingAgentsPolicyHeader+lf(configs.Default))
	for _, a := range agentIntegrations {
		if has, err := policyHasAgentRules(path, a.agentID); err != nil {
			t.Fatal(err)
		} else if !has {
			if err := addAgentRules(path, a.agentID, a.name, a.block); err != nil {
				t.Fatalf("adding the %s rules: %v", a.name, err)
			}
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	shipped := filepath.Join(repoRootForDocs(t), "configs", "tests", "coding-agents.yaml")
	if os.Getenv("AGENTGUARD_WRITE_TEST_POLICY") == "1" {
		if err := os.WriteFile(shipped, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(shipped)
	if err != nil {
		t.Fatal(err)
	}
	if lf(got) != lf(want) {
		t.Errorf("%s is not configs/default.yaml with every agent's block; rewrite it with\n  AGENTGUARD_WRITE_TEST_POLICY=1 go test ./cmd/agentguard -run TestTest_CodingAgentsPolicyIsCurrent", shipped)
	}
	pol, err := policy.LoadFromFile(shipped)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range hookAgents {
		if _, ok := pol.Agents[a.agentID]; !ok {
			t.Errorf("%s has no block for agent %q", shipped, a.agentID)
		}
	}
}

// ── Hook cases ───────────────────────────────────────────────────────────

// hookPolicy is a small policy for hook cases: the shell is open but sudo
// needs approval, files are open but /etc is denied and .env needs approval,
// the metadata endpoint is denied, and MCP tools have one rule of each kind.
const hookPolicy = `version: "1"
name: hooks
rules:
  - scope: shell
    require_approval:
      - pattern: "sudo *"
    allow:
      - pattern: "*"
  - scope: filesystem
    deny:
      - action: write
        paths: ["/etc/**"]
        message: "no system files"
    require_approval:
      - action: write
        paths: ["**/.env"]
    allow:
      - action: read
        paths: ["**"]
      - action: write
        paths: ["**"]
  - scope: network
    deny:
      - domain: "169.254.169.254"
        message: "no metadata"
    allow:
      - domain: "*"
  - scope: mcp_tool
    deny:
      - pattern: "*:write_file"
    require_approval:
      - pattern: "github:*"
    allow:
      - pattern: "*:read_*"
`

// A patch that touches two files, for the Codex cases. %s and %s are the
// files.
const twoFilePatch = `"*** Begin Patch\n*** Update File: %s\n@@\n-a\n+b\n*** Add File: %s\n+x\n*** End Patch\n"`

func TestParseFixture_HookCases(t *testing.T) {
	const names = "claude-code, cursor, gemini-cli, codex"
	cases := []struct {
		name    string
		yaml    string
		wantErr string // "" means it must parse
	}{
		{"a hook case parses", `tests:
  - name: x
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: ls}}
    expect: ALLOW
`, ""},
		{"the agent's own keys in input are not fixture keys", `tests:
  - name: x
    hook: gemini-cli
    input: {tool_name: mcp_x_y, mcp_context: {server_name: x, tool_name: y}, anything: [1, 2]}
    expect: ALLOW
`, ""},
		{"a case with both a request and a hook is rejected", `tests:
  - name: x
    request: {scope: shell, command: ls}
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: ls}}
    expect: ALLOW
`, "has both request: and hook:/input:; a case checks one action"},
		{"a hook without input is rejected and names the hooks", `tests:
  - {name: x, hook: codex, expect: ALLOW}
`, "has hook: codex but no input:; add input: with the tool call as the agent sends it to the hook, such as {tool_name: Bash, tool_input: {command: ls}} (hook is one of " + names + ")"},
		{"an input without a hook is rejected and names the hooks", `tests:
  - {name: x, input: {tool_name: Bash}, expect: ALLOW}
`, "has input: but no hook:; add hook: with the agent that sends this input, one of " + names},
		{"an unknown hook is rejected and names the hooks", `tests:
  - {name: x, hook: claude, input: {tool_name: Bash}, expect: ALLOW}
`, `hook is "claude"; use one of ` + names},
		{"a request alongside an input without a hook is rejected", `tests:
  - {name: x, request: {scope: shell, command: ls}, input: {tool_name: Bash}, expect: ALLOW}
`, "has both request: and hook:/input:"},
		{"an input that is not a mapping is rejected", `tests:
  - {name: x, hook: claude-code, input: "sudo ls", expect: ALLOW}
`, "input must be a mapping"},
		{"a case with neither a request nor a hook names both ways", "tests:\n  - {name: x, expect: ALLOW}\n",
			"needs a request: (or hook: and input:, a coding agent's tool call; hook is one of " + names + ")"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFixture([]byte(tc.yaml))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("parsed; want an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// A fixture error in a hook case is a load error: exit 3, nothing runs.
func TestTest_HookFixtureErrorsExit3(t *testing.T) {
	dir := fixtureDir(t, map[string]string{
		"a_test.yaml": passingFixture,
		"b_test.yaml": "policy: policy.yaml\ntests:\n  - {name: x, hook: copilot, input: {tool_name: Bash}, expect: ALLOW}\n",
	})
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitNoLoad || stdout != "" || !strings.Contains(stderr, `b_test.yaml: tests[0] "x": hook is "copilot"; use one of claude-code, cursor, gemini-cli, codex`) {
		t.Fatalf("exit %d, want 3 with the hook named\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// Each agent's input goes through that agent's own parse. When it maps to
// several requests, each is checked and the most severe verdict counts,
// along with its rule and reason.
func TestTest_HookCases(t *testing.T) {
	cases := []struct {
		name  string
		hook  string
		input string // YAML
		// expect, and optionally the rule and reason text the winning
		// verdict must have; the case must pass.
		expect, rule, reason string
	}{
		{"Claude Code sudo needs approval", "claude-code",
			`{tool_name: Bash, tool_input: {command: "sudo ls"}}`, "REQUIRE_APPROVAL", "require_approval:shell:sudo *", ""},
		{"Claude Code may not write to /etc", "claude-code",
			`{tool_name: Write, tool_input: {file_path: /etc/hosts, content: x}}`, "DENY", "", "no system files"},
		{"a Claude Code MCP tool is checked as server:tool", "claude-code",
			`{tool_name: mcp__github__create_issue, tool_input: {title: x}}`, "REQUIRE_APPROVAL", "require_approval:mcp_tool:github:*", ""},
		{"Claude Code may fetch a site", "claude-code",
			`{tool_name: WebFetch, tool_input: {url: "https://example.com/x"}}`, "ALLOW", "", ""},
		{"Cursor sudo needs approval", "cursor",
			`{hook_event_name: beforeShellExecution, command: "sudo ls", cwd: /home/a/p}`, "REQUIRE_APPROVAL", "", ""},
		{"Cursor may not write to /etc", "cursor",
			`{hook_event_name: preToolUse, tool_name: Write, tool_input: {file_path: /etc/hosts}}`, "DENY", "", "no system files"},
		{"a Cursor MCP call is checked as server:tool", "cursor",
			`{hook_event_name: beforeMCPExecution, tool_name: write_file, mcp_server_name: fs, tool_input: "{}"}`, "DENY", "deny:mcp_tool:*:write_file", ""},
		{"Gemini CLI may run ls", "gemini-cli",
			`{hook_event_name: BeforeTool, tool_name: run_shell_command, tool_input: {command: "ls -la"}}`, "ALLOW", "allow:shell:*", ""},
		{"Gemini CLI .env writes need approval", "gemini-cli",
			`{tool_name: write_file, tool_input: {file_path: /home/a/p/.env}}`, "REQUIRE_APPROVAL", "", ""},
		{"Gemini CLI MCP read tool is allowed", "gemini-cli",
			`{tool_name: mcp_notes_read_note, tool_input: {}}`, "ALLOW", "allow:mcp_tool:*:read_*", ""},
		{"a Gemini web_fetch is denied when one of its URLs is", "gemini-cli",
			`{tool_name: web_fetch, tool_input: {prompt: "compare https://example.com and http://169.254.169.254/latest"}}`, "DENY", "", "no metadata"},
		{"Codex sudo needs approval", "codex",
			`{hook_event_name: PreToolUse, tool_name: Bash, tool_input: {command: ["sudo", "ls"]}}`, "REQUIRE_APPROVAL", "", ""},
		{"a Codex patch is denied when one of its files is", "codex",
			fmt.Sprintf(`{tool_name: apply_patch, tool_input: {command: `+twoFilePatch+`}}`, "/home/a/p/main.go", "/etc/cron.d/x"), "DENY", "", "no system files"},
		{"a Codex patch needs approval when one file does and none is denied", "codex",
			fmt.Sprintf(`{tool_name: apply_patch, tool_input: {command: `+twoFilePatch+`}}`, "/home/a/p/main.go", "/home/a/p/.env"), "REQUIRE_APPROVAL", "", ""},
		{"a deny beats an approval in the same patch", "codex",
			fmt.Sprintf(`{tool_name: apply_patch, tool_input: {command: `+twoFilePatch+`}}`, "/home/a/p/.env", "/etc/hosts"), "DENY", "", "no system files"},
		{"a Codex patch is allowed when every file is", "codex",
			fmt.Sprintf(`{tool_name: apply_patch, tool_input: {command: `+twoFilePatch+`}}`, "/home/a/p/main.go", "/home/a/p/util.go"), "ALLOW", "", ""},
		{"a Codex MCP write tool is denied", "codex",
			`{tool_name: mcp__fs__write_file, tool_input: {}}`, "DENY", "deny:mcp_tool:*:write_file", ""},
	}
	var sb strings.Builder
	sb.WriteString("policy: policy.yaml\ntests:\n")
	for _, tc := range cases {
		fmt.Fprintf(&sb, "  - name: %q\n    hook: %s\n    input: %s\n    expect: %s\n", tc.name, tc.hook, tc.input, tc.expect)
		if tc.rule != "" {
			fmt.Fprintf(&sb, "    expect_rule: %q\n", tc.rule)
		}
		if tc.reason != "" {
			fmt.Fprintf(&sb, "    expect_reason_contains: %q\n", tc.reason)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", hookPolicy)
	writeTestFile(t, dir, "hooks_test.yaml", sb.String())
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Output: testOutputJSON})
	var rep testReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("exit %d, output is not JSON: %v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}
	if len(rep.Cases) != len(cases) {
		t.Fatalf("%d results for %d cases\n%s", len(rep.Cases), len(cases), stdout)
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := rep.Cases[i]
			if !r.Passed {
				t.Errorf("failed: %v (decision %s, rule %q, reason %q)", r.Failures, r.Decision, r.Rule, r.Reason)
			}
			if r.Hook != tc.hook {
				t.Errorf("hook = %q, want %q", r.Hook, tc.hook)
			}
		})
	}
	if code != testExitPassed {
		t.Errorf("exit %d, want 0", code)
	}
}

// A hook input that maps to no request, or that the hook can't read, fails
// its case with the reason. It is not a crash, and not a pass: such a case
// would test nothing.
func TestTest_HookInputThatChecksNothingFails(t *testing.T) {
	cases := []struct {
		name, hook, input, want string
	}{
		{"a Claude Code tool the hook does not check", "claude-code",
			`{tool_name: TodoWrite, tool_input: {}}`, `the claude-code hook doesn't check this input (hook_event_name "", tool "TodoWrite"), so the case tests nothing`},
		{"a Claude Code event other than PreToolUse", "claude-code",
			`{hook_event_name: PostToolUse, tool_name: Bash, tool_input: {command: ls}}`, `the claude-code hook doesn't check this input (hook_event_name "PostToolUse", tool "Bash")`},
		{"a Cursor input without its event", "cursor",
			`{command: "sudo ls"}`, `the cursor hook doesn't check this input (hook_event_name "", tool "")`},
		{"a Codex patch that names no files", "codex",
			`{tool_name: apply_patch, tool_input: {command: "*** Begin Patch\n*** End Patch\n"}}`, "the codex hook can't read this input (the patch names no files)"},
		{"a Gemini web_fetch with no URL", "gemini-cli",
			`{tool_name: web_fetch, tool_input: {prompt: "summarize the news"}}`, "the gemini-cli hook can't read this input (web_fetch has no http(s) URL the hook can read)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "policy.yaml", hookPolicy)
			writeTestFile(t, dir, "x_test.yaml", fmt.Sprintf("policy: policy.yaml\ntests:\n  - name: x\n    hook: %s\n    input: %s\n    expect: ALLOW\n", tc.hook, tc.input))
			code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
			if code != testExitFailed {
				t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			if !strings.Contains(stdout, "FAIL  x\n        hook: "+tc.want) {
				t.Errorf("stdout lacks %q:\n%s", tc.want, stdout)
			}
		})
	}
}

// prior: seeds history for a hook case too. The agent's requests carry its
// own agent_id, so the prior entries name it.
func TestTest_HookCaseWithPrior(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", requirePriorPolicy)
	writeTestFile(t, dir, "gate_test.yaml", `policy: policy.yaml
tests:
  - name: Claude Code may deploy once the tests ran
    prior: [{scope: shell, command: "make test", agent_id: claude-code}]
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: "make deploy"}}
    expect: ALLOW
  - name: Claude Code may not deploy before the tests ran
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: "make deploy"}}
    expect: DENY
`)
	code, stdout, stderr := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
	if code != testExitPassed {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
}

// hookOutputFixture has a request case and two hook cases, one of which
// fails: a patch expected to pass that touches /etc.
const hookOutputFixture = `policy: policy.yaml
tests:
  - name: a request case
    request: {scope: shell, command: "ls"}
    expect: ALLOW
  - name: a passing hook case
    hook: claude-code
    input: {tool_name: Bash, tool_input: {command: "sudo ls"}}
    expect: REQUIRE_APPROVAL
  - name: a failing hook case
    hook: codex
    input: {tool_name: apply_patch, tool_input: {command: "*** Begin Patch\n*** Update File: /home/a/main.go\n*** Add File: /etc/x\n+x\n*** End Patch\n"}}
    expect: ALLOW
`

// The JSON, JUnit and text results name a hook case's hook.
func TestTest_OutputNamesTheHook(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "policy.yaml", hookPolicy)
	writeTestFile(t, dir, "h_test.yaml", hookOutputFixture)

	t.Run("json", func(t *testing.T) {
		code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Output: testOutputJSON})
		if code != testExitFailed {
			t.Fatalf("exit %d, want 1", code)
		}
		var raw struct {
			Cases []map[string]any `json:"cases"`
		}
		if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, stdout)
		}
		if _, ok := raw.Cases[0]["hook"]; ok {
			t.Errorf("the request case has a hook key: %v", raw.Cases[0])
		}
		if raw.Cases[1]["hook"] != "claude-code" || raw.Cases[2]["hook"] != "codex" {
			t.Errorf("hooks = %v, %v; want claude-code, codex", raw.Cases[1]["hook"], raw.Cases[2]["hook"])
		}
		if raw.Cases[2]["decision"] != "DENY" || raw.Cases[2]["passed"] != false {
			t.Errorf("failing hook case = %v", raw.Cases[2])
		}
	})

	t.Run("junit", func(t *testing.T) {
		code, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}, Output: testOutputJUnit})
		if code != testExitFailed {
			t.Fatalf("exit %d, want 1", code)
		}
		var doc junitSuites
		if err := xml.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatalf("not XML: %v\n%s", err, stdout)
		}
		cs := doc.Suites[0].Cases
		if cs[0].Properties != nil {
			t.Errorf("the request case has properties: %+v", cs[0].Properties)
		}
		for i, want := range map[int]string{1: "claude-code", 2: "codex"} {
			p := cs[i].Properties
			if p == nil || len(p.Items) != 1 || p.Items[0] != (junitProperty{Name: "hook", Value: want}) {
				t.Errorf("case %d properties = %+v, want hook=%s", i, p, want)
			}
		}
		if f := cs[2].Failure; f == nil || !strings.Contains(f.Text, "hook: codex\n") {
			t.Errorf("failure does not name the hook: %+v", f)
		}
	})

	t.Run("text", func(t *testing.T) {
		_, stdout, _ := runTestHarness(t, &testCmdFlags{Paths: []string{dir}})
		if !strings.Contains(stdout, "FAIL  a failing hook case\n        want ALLOW, got DENY\n        hook:   codex\n") {
			t.Errorf("text output does not name the hook:\n%s", stdout)
		}
	})
}

func TestMostSevere(t *testing.T) {
	v := func(ds ...policy.Decision) []policy.CheckResult {
		out := make([]policy.CheckResult, len(ds))
		for i, d := range ds {
			out[i] = policy.CheckResult{Decision: d}
		}
		return out
	}
	cases := []struct {
		name    string
		results []policy.CheckResult
		want    int
	}{
		{"one verdict is the verdict", v(policy.Allow), 0},
		{"all allowed: the first allow", v(policy.Allow, policy.Allow), 0},
		{"an approval beats allows", v(policy.Allow, policy.RequireApproval, policy.RequireApproval), 1},
		{"a deny beats approvals and allows", v(policy.RequireApproval, policy.Allow, policy.Deny), 2},
		{"the first deny wins", v(policy.Deny, policy.Deny), 0},
		{"an unknown decision counts as a deny", v(policy.RequireApproval, "LATER"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mostSevere(tc.results); got != tc.want {
				t.Errorf("mostSevere = %d, want %d", got, tc.want)
			}
		})
	}
}

// ── The real binary ──────────────────────────────────────────────────────

func TestCLI_Test(t *testing.T) {
	root := repoRootForDocs(t)
	dir := fixtureDir(t, map[string]string{"bad_test.yaml": failingFixture})

	agentguard(t, root, nil, "test", "configs/tests").expect(t, 0, "PASS: ", "")
	agentguard(t, root, nil, "test", "configs/tests", "--run", "claude-code", "--output", "junit").expect(t, 0, "<testsuites", "")
	agentguard(t, dir, nil, "test", ".").expect(t, 1, "FAIL  rm -rf is wrongly expected to pass", "")

	agentguard(t, dir, nil, "test").expect(t, 2, "", "missing the fixture files or folders")
	agentguard(t, dir, nil, "test", ".", "--output", "xml").expect(t, 2, "", `--output is "xml"`)
	agentguard(t, dir, nil, "test", ".", "--run", "(").expect(t, 2, "", "not a valid regular expression")
	agentguard(t, dir, nil, "test", ".", "--rn", "x").expect(t, 2, "", "unknown flag --rn (did you mean --run?)")
	agentguard(t, dir, nil, "test", "missing").expect(t, 3, "", "missing")

	// A fixture without policy: finds one the way the server would.
	noPolicy := t.TempDir()
	writeTestFile(t, noPolicy, "x_test.yaml", strings.Replace(passingFixture, "policy: policy.yaml\n", "", 1))
	policyFile := filepath.Join(dir, "policy.yaml")
	agentguard(t, noPolicy, []string{"AGENTGUARD_POLICY=" + policyFile}, "test", ".").
		expect(t, 0, "PASS: 2 case(s) passed", "(from AGENTGUARD_POLICY)")
}
