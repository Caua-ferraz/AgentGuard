package main

// Unit tests for `agentguard test` (test_cmd.go). The end-to-end runs of
// the real binary are at the bottom, through the re-exec helper in
// cli_exec_test.go.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	for _, f := range []string{"default_test.yaml", "research-agent_test.yaml", "trading-bot_test.yaml"} {
		if !strings.Contains(stdout, f) {
			t.Errorf("%s did not run:\n%s", f, stdout)
		}
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
