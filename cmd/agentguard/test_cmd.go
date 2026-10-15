package main

// test_cmd.go is `agentguard test`: it runs a policy against fixture files
// of example actions and their expected verdicts, so a policy change that
// allows or blocks the wrong thing fails CI the way a code change with a
// broken unit test does.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	schemav1 "github.com/Caua-ferraz/AgentGuard/pkg/proxy/schema/v1"
)

// Exit codes for `agentguard test`. 2 is exitUsage, shared with the other
// commands.
const (
	testExitPassed = 0
	testExitFailed = 1
	testExitNoLoad = 3
)

// fixtureSuffixes name the files a folder argument is searched for.
var fixtureSuffixes = []string{"_test.yaml", "_test.yml"}

const (
	testOutputText  = "text"
	testOutputJSON  = "json"
	testOutputJUnit = "junit"
)

// ── Fixture format ───────────────────────────────────────────────────────

// fixtureFile is one *_test.yaml file. Unknown keys are rejected at every
// level: a misspelled `expect_rul:` that silently checked nothing would
// make a CI gate pass without testing what its author meant.
type fixtureFile struct {
	// Policy is the policy file these cases run against, relative to the
	// fixture's folder. Empty: --policy, else the file the server would load.
	Policy string        `yaml:"policy"`
	Tenant string        `yaml:"tenant"`
	Tests  []fixtureCase `yaml:"tests"`
}

// fixtureCase is one test case: an action and the verdict it must get.
//
// The action is either a Request, or a coding agent's tool call: Hook names
// the agent and Input is the call as that agent sends it to `agentguard
// hook`. A hook case goes through the agent's own adapter, so it tests the
// mapping from tool call to requests as well as the policy.
type fixtureCase struct {
	Name    string           `yaml:"name"`
	Prior   []fixtureRequest `yaml:"prior"`
	Request *fixtureRequest  `yaml:"request"`
	Hook    string           `yaml:"hook"`
	// Input is any YAML value, so the agent's own keys (tool_name,
	// tool_input, ...) aren't held to the fixture's known keys: the agent
	// decides what they mean. caseHook checks that it is a mapping.
	Input                any    `yaml:"input"`
	Expect               string `yaml:"expect"`
	ExpectRule           string `yaml:"expect_rule"`
	ExpectReasonContains string `yaml:"expect_reason_contains"`
}

// fixtureRequest is policy.ActionRequest with YAML keys. ActionRequest only
// has JSON tags, and yaml.v3 would otherwise expect `agentid`. It leaves out
// schema_version (always v1) and approval_id, which Engine.Check never reads.
type fixtureRequest struct {
	Scope     string            `yaml:"scope"`
	Action    string            `yaml:"action"`
	Command   string            `yaml:"command"`
	Path      string            `yaml:"path"`
	Domain    string            `yaml:"domain"`
	URL       string            `yaml:"url"`
	AgentID   string            `yaml:"agent_id"`
	SessionID string            `yaml:"session_id"`
	EstCost   float64           `yaml:"est_cost"`
	Meta      map[string]string `yaml:"meta"`
}

func (r fixtureRequest) actionRequest() policy.ActionRequest {
	return policy.ActionRequest{
		SchemaVersion: schemav1.Version,
		Scope:         r.Scope,
		Action:        r.Action,
		Command:       r.Command,
		Path:          r.Path,
		Domain:        r.Domain,
		URL:           r.URL,
		AgentID:       r.AgentID,
		SessionID:     r.SessionID,
		EstCost:       r.EstCost,
		Meta:          r.Meta,
	}
}

// checkCaseAction checks that a case gives its action one way, in full: a
// request with a scope, or a hook and its input. Its errors are fixture
// errors.
func checkCaseAction(c fixtureCase) error {
	if c.Hook == "" && c.Input == nil {
		switch {
		case c.Request == nil:
			return fmt.Errorf("needs a request: (or hook: and input:, a coding agent's tool call; hook is one of %s)", strings.Join(hookAgentNames(), ", "))
		case c.Request.Scope == "":
			return errors.New("its request needs a scope")
		}
		return nil
	}
	_, _, err := caseHook(c)
	return err
}

// caseHook returns the agent a hook case's input goes to, and the input as
// the JSON that agent would send. Its errors are fixture errors.
func caseHook(c fixtureCase) (*hookAgent, []byte, error) {
	supported := strings.Join(hookAgentNames(), ", ")
	switch {
	case c.Request != nil:
		return nil, nil, errors.New("has both request: and hook:/input:; a case checks one action, so keep request: for a policy action, or hook: and input: for a coding agent's tool call")
	case c.Hook == "":
		return nil, nil, fmt.Errorf("has input: but no hook:; add hook: with the agent that sends this input, one of %s", supported)
	case c.Input == nil:
		return nil, nil, fmt.Errorf("has hook: %s but no input:; add input: with the tool call as the agent sends it to the hook, such as {tool_name: Bash, tool_input: {command: ls}} (hook is one of %s)", c.Hook, supported)
	}
	agent := hookAgentByName(c.Hook)
	if agent == nil {
		return nil, nil, fmt.Errorf("hook is %q; use one of %s", c.Hook, supported)
	}
	// Every agent sends its tool call as one JSON object.
	if _, ok := c.Input.(map[string]any); !ok {
		return nil, nil, errors.New("input must be a mapping: the JSON object the agent sends, written as YAML")
	}
	raw, err := json.Marshal(c.Input)
	if err != nil {
		return nil, nil, fmt.Errorf("input can't be written as JSON (%v); every key in it must be text", err)
	}
	return agent, raw, nil
}

// caseRequests returns the requests a case checks. A hook case's input goes
// through the agent's own parse, as `agentguard hook` reads it. An input
// the hook doesn't check, or can't read, is an error the case fails with:
// such a case would test nothing, which is almost certainly a mistake.
func caseRequests(c fixtureCase) ([]policy.ActionRequest, error) {
	if c.Hook == "" {
		return []policy.ActionRequest{c.Request.actionRequest()}, nil
	}
	agent, raw, err := caseHook(c)
	if err != nil {
		return nil, err // unreachable: parseFixture rejected the case
	}
	call, checked, err := agent.parse(raw)
	switch {
	case err != nil:
		return nil, fmt.Errorf("the %s hook can't read this input (%v); the real hook would let the call through unchecked, or block it with --fail-closed", agent.name, err)
	case !checked || len(call.reqs) == 0:
		return nil, fmt.Errorf("the %s hook doesn't check this input (hook_event_name %q, tool %q), so the case tests nothing; give it a tool call the hook checks (see docs/CODING_AGENTS.md § What gets checked)", agent.name, call.event, call.tool)
	}
	return call.reqs, nil
}

// unknownKey rewrites yaml.v3's "field x not found in type main.fixtureCase"
// into words that don't name Go types.
var unknownKey = regexp.MustCompile(`field (\S+) not found in type \S+`)

// wrongShape rewrites yaml.v3's "cannot unmarshal !!str `x` into
// main.fixtureCase" the same way.
var wrongShape = regexp.MustCompile("cannot unmarshal (!!\\w+)(?: `[^`]*`)? into (\\S+)")

// yamlKinds and fixtureShapes name YAML tags and fixture types in words.
var (
	yamlKinds = map[string]string{
		"!!str": "text", "!!seq": "a list", "!!map": "a mapping",
		"!!int": "a number", "!!float": "a number", "!!bool": "true/false", "!!null": "nothing",
	}
	fixtureShapes = map[string]string{
		"main.fixtureFile":      "a mapping with a tests: list",
		"[]main.fixtureCase":    "a list of test cases",
		"main.fixtureCase":      "a test case (a mapping with name:, request: or hook: and input:, and expect:)",
		"*main.fixtureRequest":  "a request (a mapping with scope: and the action's fields)",
		"main.fixtureRequest":   "an action (a mapping with scope: and the action's fields)",
		"[]main.fixtureRequest": "a list of actions",
		"map[string]string":     "a mapping of text values",
		"string":                "text",
		"float64":               "a number",
	}
)

// fixtureError turns a yaml.v3 decode error into a message about the file,
// not about Go types.
func fixtureError(err error) error {
	msg := strings.TrimPrefix(err.Error(), "yaml: unmarshal errors:\n  ")
	msg = strings.ReplaceAll(msg, "\n  ", "; ")
	msg = unknownKey.ReplaceAllString(msg, `unknown key "$1"`)
	msg = wrongShape.ReplaceAllStringFunc(msg, func(m string) string {
		sub := wrongShape.FindStringSubmatch(m)
		got, ok := yamlKinds[sub[1]]
		if !ok {
			got = sub[1]
		}
		want, ok := fixtureShapes[sub[2]]
		if !ok {
			want = "something else"
		}
		return fmt.Sprintf("expected %s, got %s", want, got)
	})
	return errors.New(msg)
}

// parseFixture decodes and checks one fixture file's contents.
func parseFixture(data []byte) (*fixtureFile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f fixtureFile
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the file is empty; it needs a tests: list")
		}
		return nil, fixtureError(err)
	}
	// One document per file. A second one after `---` would otherwise never
	// be read, and its cases would look like they passed.
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("line %d: a second YAML document (after ---); a test file holds one document, so put these cases in the first one or in another file", extra.Line)
	} else if !errors.Is(err, io.EOF) {
		return nil, fixtureError(err)
	}
	if len(f.Tests) == 0 {
		return nil, errors.New("no test cases; add a tests: list")
	}
	seen := map[string]bool{}
	for i, c := range f.Tests {
		where := fmt.Sprintf("tests[%d]", i)
		if c.Name == "" {
			return nil, fmt.Errorf("%s needs a name", where)
		}
		where = fmt.Sprintf("%s %q", where, c.Name)
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: another case in this file has the same name", where)
		}
		seen[c.Name] = true
		if err := checkCaseAction(c); err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
		}
		switch policy.Decision(c.Expect) {
		case policy.Allow, policy.Deny, policy.RequireApproval:
		case "":
			return nil, fmt.Errorf("%s: needs expect: ALLOW, DENY or REQUIRE_APPROVAL", where)
		default:
			return nil, fmt.Errorf("%s: expect is %q; use ALLOW, DENY or REQUIRE_APPROVAL", where, c.Expect)
		}
		for j, p := range c.Prior {
			// PriorActionIndex.Record keeps nothing without an action or a
			// command, so such an entry would seed no history at all.
			if p.Scope == "" || (p.Action == "" && p.Command == "") {
				return nil, fmt.Errorf("%s: prior[%d] needs a scope and an action or a command", where, j)
			}
		}
	}
	return &f, nil
}

// ── Running ──────────────────────────────────────────────────────────────

// testCmdFlags carries the flags of `agentguard test`, so executeTest can
// be unit-tested without os.Args.
type testCmdFlags struct {
	Paths      []string // fixture files and folders, as given
	PolicyPath string   // --policy; "" means look for one when a fixture needs it
	Strict     bool
	Run        *regexp.Regexp // --run; nil runs every case
	Output     string
}

// loadedFixture is one fixture file ready to run.
type loadedFixture struct {
	path       string
	policyPath string
	pol        *policy.Policy
	file       *fixtureFile
}

// caseResult is the outcome of one case. It is also the JSON output.
type caseResult struct {
	File                 string `json:"file"`
	Policy               string `json:"policy"`
	Name                 string `json:"name"`
	Hook                 string `json:"hook,omitempty"` // a hook case's agent; "" for a request
	Passed               bool   `json:"passed"`
	Expect               string `json:"expect"`
	ExpectRule           string `json:"expect_rule,omitempty"`
	ExpectReasonContains string `json:"expect_reason_contains,omitempty"`
	Decision             string `json:"decision"`
	Rule                 string `json:"matched_rule,omitempty"`
	Reason               string `json:"reason"`
	// Failures lists what did not match, one item per expectation.
	Failures []string `json:"failures,omitempty"`
}

// executeTest loads every fixture and policy, runs the cases and prints the
// results. Nothing runs unless everything loads: a CI log that shows some
// passes above a load error is easy to misread as a pass.
func executeTest(f *testCmdFlags, stdout, stderr io.Writer) int {
	fixtures, ok := loadFixtures(f, stderr)
	if !ok {
		return testExitNoLoad
	}
	var results []caseResult
	for _, fx := range fixtures {
		for _, c := range fx.file.Tests {
			if f.Run != nil && !f.Run.MatchString(c.Name) {
				continue
			}
			results = append(results, runCase(fx, c))
		}
	}
	if len(results) == 0 {
		// Exiting 0 would let a mistyped --run pass CI without running
		// anything. (A fixture with no cases already failed to load.)
		if f.Run != nil {
			fmt.Fprintf(stderr, "agentguard test: no case name matches --run %q\n", f.Run.String())
		} else {
			fmt.Fprintln(stderr, "agentguard test: no test cases to run")
		}
		return testExitFailed
	}

	var err error
	switch f.Output {
	case testOutputJSON:
		err = writeTestJSON(stdout, results)
	case testOutputJUnit:
		err = writeTestJUnit(stdout, results)
	default:
		err = writeTestText(stdout, results)
	}
	if err != nil {
		fmt.Fprintf(stderr, "agentguard test: writing results: %v\n", err)
		return testExitFailed
	}
	for _, r := range results {
		if !r.Passed {
			return testExitFailed
		}
	}
	return testExitPassed
}

// loadFixtures expands folders, parses every fixture and loads each policy
// once. It reports every problem it finds, not just the first, so one CI
// run shows them all.
func loadFixtures(f *testCmdFlags, stderr io.Writer) ([]loadedFixture, bool) {
	var paths []string
	ok := true
	fail := func(format string, a ...any) {
		fmt.Fprintf(stderr, "agentguard test: "+format+"\n", a...)
		ok = false
	}
	for _, arg := range f.Paths {
		info, err := os.Stat(arg)
		if err != nil {
			fail("%v", err)
			continue
		}
		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}
		found, err := fixturesIn(arg)
		switch {
		case err != nil:
			fail("%v", err)
		case len(found) == 0:
			fail("%s has no *_test.yaml or *_test.yml files (subfolders are not searched)", arg)
		}
		paths = append(paths, found...)
	}

	type loadedPolicy struct {
		pol *policy.Policy
		err error
	}
	policies := map[string]loadedPolicy{}
	defaultPolicy := f.PolicyPath
	var defaultErr error // findPolicy's error, reported once
	var fixtures []loadedFixture
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			fail("%v", err)
			continue
		}
		file, err := parseFixture(data)
		if err != nil {
			fail("%s: %v", p, err)
			continue
		}
		policyPath := file.Policy
		switch {
		case policyPath != "" && !filepath.IsAbs(policyPath):
			policyPath = filepath.Join(filepath.Dir(p), policyPath)
		case policyPath == "":
			if defaultPolicy == "" {
				if defaultErr != nil {
					continue
				}
				found, note, err := findPolicy("", false)
				if err != nil {
					defaultErr = err
					fail("%s has no policy: line, and %v", p, err)
					continue
				}
				fmt.Fprintf(stderr, "Using policy file %s (%s) for fixtures with no policy: line.\n", found, note)
				defaultPolicy = found
			}
			policyPath = defaultPolicy
		}
		lp, seen := policies[policyPath]
		if !seen {
			lp.pol, lp.err = loadTestPolicy(policyPath, f.Strict, stderr)
			policies[policyPath] = lp
			if lp.err != nil {
				fail("%v", lp.err)
			}
		}
		if lp.err != nil {
			continue
		}
		fixtures = append(fixtures, loadedFixture{path: p, policyPath: policyPath, pol: lp.pol, file: file})
	}
	return fixtures, ok
}

// fixturesIn lists dir's *_test.yaml and *_test.yml files, sorted.
// Subfolders are not searched, so a folder of work-in-progress fixtures can
// sit next to the real ones.
func fixturesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && isFixtureName(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

func isFixtureName(name string) bool {
	for _, suffix := range fixtureSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// loadTestPolicy loads a policy the way `agentguard validate` does: load
// warnings go to stderr, and with strict they fail the load.
func loadTestPolicy(path string, strict bool, stderr io.Writer) (*policy.Policy, error) {
	pol, warnings, err := policy.LoadFromFileWithWarnings(path)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %v", path, err)
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "WARN: %s: %s\n", path, w)
	}
	if strict && len(warnings) > 0 {
		return nil, fmt.Errorf("policy %s loads, but with %d warning(s) (--strict)", path, len(warnings))
	}
	return pol, nil
}

// runCase checks one case. A hook input that maps to several requests (a
// patch that touches several files) gets the verdict the hook acts on: each
// request is checked, and the most severe verdict wins.
func runCase(fx loadedFixture, c fixtureCase) caseResult {
	r := caseResult{
		File:                 fx.path,
		Policy:               fx.policyPath,
		Name:                 c.Name,
		Hook:                 c.Hook,
		Expect:               c.Expect,
		ExpectRule:           c.ExpectRule,
		ExpectReasonContains: c.ExpectReasonContains,
	}
	reqs, err := caseRequests(c)
	if err != nil {
		r.Failures = []string{"hook: " + err.Error()}
		return r
	}
	results := make([]policy.CheckResult, len(reqs))
	for i, req := range reqs {
		results[i] = checkCaseRequest(fx, c, req)
	}
	res := results[mostSevere(results)]
	r.Decision, r.Rule, r.Reason = string(res.Decision), res.Rule, res.Reason
	if string(res.Decision) != c.Expect {
		r.Failures = append(r.Failures, fmt.Sprintf("decision: want %s, got %s", c.Expect, res.Decision))
	}
	if c.ExpectRule != "" && c.ExpectRule != res.Rule {
		r.Failures = append(r.Failures, fmt.Sprintf("rule: want %q, got %q", c.ExpectRule, res.Rule))
	}
	if c.ExpectReasonContains != "" && !strings.Contains(res.Reason, c.ExpectReasonContains) {
		r.Failures = append(r.Failures, fmt.Sprintf("reason: want it to contain %q, got %q", c.ExpectReasonContains, res.Reason))
	}
	r.Passed = len(r.Failures) == 0
	return r
}

// checkCaseRequest checks one of a case's requests on an engine of its own.
// Engines keep state between checks (cost reserved per session), so sharing
// one would let an earlier case change a later case's verdict, and
// reordering the file would change the results.
func checkCaseRequest(fx loadedFixture, c fixtureCase, req policy.ActionRequest) policy.CheckResult {
	tenant := fx.file.Tenant
	if tenant == "" {
		tenant = policy.LocalTenantID
	}

	// A provider over the already-loaded policy: no file watcher per case,
	// and every case sees the same policy even if the file changes mid-run.
	// It serves the policy to the fixture's tenant, so `tenant:` checks the
	// policy as that tenant instead of finding no policy for it.
	engine, err := policy.NewEngine(fixtureProvider{policy.NewStaticPolicyProvider(fx.pol), tenant})
	var res policy.CheckResult
	if err != nil {
		// Unreachable with a non-nil policy; reported as a failure rather
		// than a pass.
		res = policy.CheckResult{Decision: "ERROR", Reason: err.Error()}
	} else {
		// The server records each ALLOW into an index like this one and
		// answers require_prior from it. Here it holds only the case's
		// prior: actions, so the history a case sees is the one it states.
		idx := policy.NewPriorActionIndex(0)
		now := time.Now()
		for _, p := range c.Prior {
			idx.Record(tenant, p.AgentID, p.Scope, p.Action, p.Command, now)
		}
		engine.SetPriorActionQuerier(idx)
		res = engine.Check(req, tenant)
		_ = engine.Close()
	}
	return res
}

// fixtureProvider serves one loaded policy to one tenant. The static
// provider it wraps only knows the local tenant.
type fixtureProvider struct {
	*policy.StaticPolicyProvider
	tenant string
}

func (p fixtureProvider) Get(tenantID string) (*policy.Policy, error) {
	if tenantID == p.tenant {
		tenantID = policy.LocalTenantID
	}
	return p.StaticPolicyProvider.Get(tenantID)
}

func (p fixtureProvider) Watch(tenantID string, cb func(*policy.Policy)) (func(), error) {
	if tenantID == p.tenant {
		tenantID = policy.LocalTenantID
	}
	return p.StaticPolicyProvider.Watch(tenantID, cb)
}

// ── Output ───────────────────────────────────────────────────────────────

// writeTestText prints one PASS/FAIL line per case under its file, the
// details of each failure, and a summary.
func writeTestText(w io.Writer, results []caseResult) error {
	var sb strings.Builder
	passed, file := 0, ""
	for _, r := range results {
		if r.File != file {
			file = r.File
			fmt.Fprintf(&sb, "%s (policy %s)\n", r.File, r.Policy)
		}
		if r.Passed {
			passed++
			fmt.Fprintf(&sb, "  PASS  %s\n", r.Name)
			continue
		}
		fmt.Fprintf(&sb, "  FAIL  %s\n", r.Name)
		if r.Decision == "" {
			// The hook input mapped to no request, so there is no verdict
			// to show: only why.
			fmt.Fprintf(&sb, "        %s\n", r.Failures[0])
			continue
		}
		fmt.Fprintf(&sb, "        want %s, got %s\n", r.Expect, r.Decision)
		if r.Hook != "" {
			fmt.Fprintf(&sb, "        hook:   %s\n", r.Hook)
		}
		rule := fmt.Sprintf("%q", r.Rule)
		if r.Rule == "" {
			rule = "(none: no rule matched)"
		}
		if r.ExpectRule != "" {
			rule += fmt.Sprintf(", want %q", r.ExpectRule)
		}
		fmt.Fprintf(&sb, "        rule:   %s\n", rule)
		reason := fmt.Sprintf("%q", r.Reason)
		if r.ExpectReasonContains != "" {
			reason += fmt.Sprintf(", want it to contain %q", r.ExpectReasonContains)
		}
		fmt.Fprintf(&sb, "        reason: %s\n", reason)
	}
	failed := len(results) - passed
	if failed == 0 {
		fmt.Fprintf(&sb, "PASS: %d case(s) passed\n", passed)
	} else {
		fmt.Fprintf(&sb, "FAIL: %d of %d case(s) failed\n", failed, len(results))
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// testReport is the --output json document.
type testReport struct {
	Passed int          `json:"passed"`
	Failed int          `json:"failed"`
	Cases  []caseResult `json:"cases"`
}

func writeTestJSON(w io.Writer, results []caseResult) error {
	rep := testReport{Cases: results}
	for _, r := range results {
		if r.Passed {
			rep.Passed++
		} else {
			rep.Failed++
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// JUnit XML, the subset CI test-report viewers read: one <testsuite> per
// fixture file, one <testcase> per case, a <failure> on each failed one.
type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string `xml:"name,attr"`
	ClassName string `xml:"classname,attr"`
	// Properties names a hook case's hook, in the <properties> element that
	// test-report viewers show with a case.
	Properties *junitProperties `xml:"properties,omitempty"`
	Failure    *junitFailure    `xml:"failure,omitempty"`
}

type junitProperties struct {
	Items []junitProperty `xml:"property"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func writeTestJUnit(w io.Writer, results []caseResult) error {
	doc := junitSuites{Name: "agentguard test"}
	for _, r := range results {
		if len(doc.Suites) == 0 || doc.Suites[len(doc.Suites)-1].Name != r.File {
			doc.Suites = append(doc.Suites, junitSuite{Name: r.File})
		}
		s := &doc.Suites[len(doc.Suites)-1]
		jc := junitCase{Name: r.Name, ClassName: r.File}
		hook := ""
		if r.Hook != "" {
			jc.Properties = &junitProperties{Items: []junitProperty{{Name: "hook", Value: r.Hook}}}
			hook = "hook: " + r.Hook + "\n"
		}
		if !r.Passed {
			jc.Failure = &junitFailure{
				Message: r.Failures[0],
				Text: fmt.Sprintf("%s\npolicy: %s\n%sdecision: %s\nrule: %s\nreason: %s\n",
					strings.Join(r.Failures, "\n"), r.Policy, hook, r.Decision, r.Rule, r.Reason),
			}
			s.Failures++
			doc.Failures++
		}
		s.Tests++
		doc.Tests++
		s.Cases = append(s.Cases, jc)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// ── Command line ─────────────────────────────────────────────────────────

var testFlagGroups = []clihelp.Group{
	{Title: "Policy", Names: []string{"policy", "strict"}},
	{Title: "Cases and output", Names: []string{"run", "output"}},
}

func testUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage: agentguard test [flags] <fixture.yaml | folder>...

Run a policy against test cases, each an action and the verdict it must
get, and report which pass. Use it in CI so a policy change that allows or
blocks the wrong thing fails the build. No server needed.

A folder is searched for *_test.yaml and *_test.yml files (not its
subfolders). A fixture file holds one YAML document and looks like this:

  policy: ../default.yaml    # optional, relative to this file
  tests:
    - name: plain ls is allowed
      request: {scope: shell, command: "ls -la", agent_id: dev}
      expect: ALLOW            # ALLOW, DENY or REQUIRE_APPROVAL
      expect_rule: "allow:shell:ls *"      # optional; the exact rule
      expect_reason_contains: "shell"      # optional
    - name: deploy once the tests ran
      prior: [{scope: shell, command: "make test", agent_id: dev}]
      request: {scope: shell, command: "make deploy", agent_id: dev}
      expect: ALLOW
    - name: Claude Code sudo needs approval
      hook: claude-code        # claude-code, cursor, gemini-cli or codex
      input: {tool_name: Bash, tool_input: {command: "sudo ls"}}
      expect: REQUIRE_APPROVAL

The actions under prior: count as allowed just now, so require_prior rules
can be tested. A case with hook: and input: gives a coding agent's tool
call instead of a request; it is read the way 'agentguard hook' reads it,
and when it maps to several checks the most severe verdict counts. Each case gets a fresh engine: cost spent in one case does
not carry over to the next. Rate limits are not checked; the server
applies them, not the policy engine.

`)
	clihelp.WriteGroups(w, fs, testFlagGroups, policyHelp)
	fmt.Fprint(w, `
A fixture with no policy: line uses --policy, else the file 'agentguard
server' would load: AGENTGUARD_POLICY, then configs/default.yaml, then the
installer's starter policy.

Examples:
  agentguard test configs/tests
  agentguard test --run deploy policy_test.yaml
  agentguard test --output junit configs/tests > policy-tests.xml

Exit codes:
  0  every case passed
  1  a case failed, or --run matched no case
  2  command-line mistake
  3  a fixture or policy could not be loaded
`)
}

func runTestCmd(args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := &testCmdFlags{}
	fs.StringVar(&f.PolicyPath, "policy", "", "Policy for fixtures without a policy: line (found automatically when not given; see below)")
	fs.BoolVar(&f.Strict, "strict", false, "Treat policy load warnings as a load failure (exit 3), as 'validate --strict' does")
	run := fs.String("run", "", "Only run cases whose name matches this regular expression")
	fs.StringVar(&f.Output, "output", testOutputText, "Output format: text, json, or junit (JUnit XML, for CI test reports)")
	positional, code, ok := parseCommand(fs, func(w io.Writer) { testUsage(w, fs) }, args)
	if !ok {
		return code
	}
	if len(positional) == 0 {
		return usageError("test", "missing the fixture files or folders to run")
	}
	switch f.Output {
	case testOutputText, testOutputJSON, testOutputJUnit:
	default:
		return usageError("test", "--output is %q; use text, json or junit", f.Output)
	}
	if *run != "" {
		re, err := regexp.Compile(*run)
		if err != nil {
			return usageError("test", "--run is not a valid regular expression: %v", err)
		}
		f.Run = re
	}
	f.Paths = positional
	return executeTest(f, os.Stdout, os.Stderr)
}
