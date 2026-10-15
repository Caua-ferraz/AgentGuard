package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

var (
	t0     = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	period = Period{Since: t0, Until: t0.Add(7 * 24 * time.Hour)}
)

// at is t0 plus d.
func at(d time.Duration) time.Time { return t0.Add(d) }

func entry(ts time.Time, agent, session string, d policy.Decision, rule, approvalID string, req policy.ActionRequest) audit.Entry {
	req.AgentID = agent
	return audit.Entry{
		Timestamp: ts, AgentID: agent, SessionID: session, Request: req,
		Result: policy.CheckResult{Decision: d, Rule: rule, ApprovalID: approvalID},
	}
}

func shell(cmd string) policy.ActionRequest {
	return policy.ActionRequest{Scope: "shell", Command: cmd}
}

// fixtureEntries is the fixed log the golden files are made from. It covers
// the period edges, every approval stage, the default deny, masked and
// unmasked secrets, and values that need escaping.
func fixtureEntries() []audit.Entry {
	net := policy.ActionRequest{Scope: "network", Domain: "api.github.com", Meta: map[string]string{"transport": "mcp_gateway"}}
	evil := entry(at(3*time.Hour), "<script>alert(1)</script>", "s2|x", policy.Deny, "", "",
		policy.ActionRequest{Scope: "network", Domain: "evil.example"})
	evil.TenantID = "acme"
	mcp := entry(at(2*time.Hour), "dev-bot", "s1", policy.Allow, "allow:network:api.github.com", "", net)
	mcp.Transport = audit.TransportMCPGateway
	deploy := func(ts time.Duration, d policy.Decision, rule, id string) audit.Entry {
		e := entry(at(ts), "ci-bot", "s3", d, rule, id, shell("make deploy"))
		e.Transport = audit.TransportClaudeCode
		return e
	}
	return []audit.Entry{
		entry(t0.Add(-time.Second), "early-bot", "s0", policy.Allow, "allow:shell:ls", "", shell("ls")),
		entry(t0, "dev-bot", "s1", policy.Allow, "allow:shell:ls", "", shell("ls -la")),
		mcp,
		entry(at(150*time.Minute), "dev-bot", "s1", policy.Deny, "deny:shell:rm -rf *", "", shell("rm -rf /")),
		evil,
		deploy(4*time.Hour, policy.RequireApproval, "require_approval:shell:make deploy", "ap_1"),
		deploy(4*time.Hour+time.Minute, policy.RequireApproval, "require_approval:pending", "ap_1"),
		deploy(4*time.Hour+2*time.Minute, policy.Allow, "allow:approved", "ap_1"),
		deploy(5*time.Hour, policy.RequireApproval, "require_approval:shell:make deploy", "ap_2"),
		deploy(5*time.Hour+time.Minute, policy.Deny, "deny:approved", "ap_2"),
		deploy(6*time.Hour, policy.RequireApproval, "require_approval:shell:make deploy", "ap_3"),
		entry(at(24*time.Hour), "dev-bot", "s4", policy.Allow, "allow:shell:export *", "", shell("export TOKEN=[REDACTED]")),
		entry(at(25*time.Hour), "dev-bot", "", policy.Allow, "allow:shell:export *", "", shell("export API_KEY=sk-abcdefghijklmnopqrstuvwx")),
		entry(period.Until, "late-bot", "s9", policy.Deny, "deny:shell:rm -rf *", "", shell("rm -rf /")),
	}
}

// fixtureReport is the report the golden files hold: file mode, a log
// sealed with a key that verified.
func fixtureReport() *Report {
	r := &Report{
		GeneratedAt:       at(7*24*time.Hour + time.Hour),
		AgentGuardVersion: "1.4.0 (test)",
		Period:            period,
		Source: Source{
			Mode:     SourceFile,
			AuditLog: "/var/lib/agentguard/audit.jsonl",
			Files:    []string{"audit.jsonl.20260930T120000Z.gz", "audit.jsonl"},
		},
		Policy: &PolicyFile{Path: "configs/default.yaml", SHA256: strings.Repeat("ab", 32), Found: "--policy"},
		Integrity: FromVerify(&audit.VerifyReport{
			OK: true, Segments: []string{"audit.jsonl.20260930T120000Z.gz", "audit.jsonl"},
			Entries: 14, FirstSeq: 1, LastSeq: 14, LastHash: strings.Repeat("cd", 32),
			Seals: []string{"hmac-sha256 key 0123456789abcdef"},
		}),
	}
	r.Activity, r.Approvals = Aggregate(slices.Values(fixtureEntries()), r.Period)
	Finish(r)
	return r
}

func TestGolden(t *testing.T) {
	r := fixtureReport()
	for _, format := range Formats {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, r, format); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "report."+format)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run 'go test ./pkg/report -update' to create it)", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Errorf("%s differs from %s; if the change is intended, run 'go test ./pkg/report -update' and review the diff\n%s", format, path, buf.String())
			}
		})
	}
}

// A value from the log can't break out of its place: no raw HTML in the
// HTML or Markdown form, no extra table cell in Markdown.
func TestRender_EscapesLogValues(t *testing.T) {
	r := fixtureReport()
	for _, format := range []string{FormatMarkdown, FormatHTML} {
		var buf bytes.Buffer
		if err := Write(&buf, r, format); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "<script>") {
			t.Errorf("%s output holds a raw <script> tag from an agent id", format)
		}
	}
	if got := md("a|b\nc"); got != `a\|b c` {
		t.Errorf("md(%q) = %q", "a|b\nc", got)
	}
}

func TestMd(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"table and emphasis characters", "a|b *c* _d_", `a\|b \*c\* \_d\_`},
		{"raw HTML", "<script>", "&lt;script&gt;"},
		{"a URL is not an autolink", "see https://evil.example/x", `see https\://evil.example/x`},
		{"a www. host is not an autolink", "go to WWW.evil.example", `go to WWW\.evil.example`},
		{"an address is not an autolink", "mail a@evil.example", `mail a\@evil.example`},
		{"a terminal escape is defused", "red\x1b[31mtext", "red�\\[31mtext"},
		{"backspace and C1 CSI", "ok\b\b\u009b2J", "ok���2J"},
		{"bidi overrides", "abc‮evil⁦x⁩", "abc�evil�x�"},
		{"tab stays, newline folds", "a\tb\nc", "a\tb c"},
		{"invalid UTF-8", "a\xffb", "a�b"},
	}
	for _, tc := range cases {
		if got := md(tc.in); got != tc.want {
			t.Errorf("%s: md(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// Control and bidi characters from the log never reach the HTML page.
func TestHTML_ReplacesControlCharacters(t *testing.T) {
	r := fixtureReport()
	r.Activity.AgentsSeen.Names = append(r.Activity.AgentsSeen.Names, "evil\x1b]0;title\x07‮gnp.exe")
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"\x1b", "\x07", "‮"} {
		if strings.Contains(buf.String(), bad) {
			t.Errorf("the page holds %q", bad)
		}
	}
	if !strings.Contains(buf.String(), "evil�]0;title��gnp.exe") {
		t.Error("the agent id is not shown with U+FFFD in place of the controls")
	}
}

func TestWrite_UnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, fixtureReport(), "pdf"); err == nil || !strings.Contains(err.Error(), "md, json, html") {
		t.Errorf("err = %v, want one naming the formats", err)
	}
}

// The JSON shape is documented in docs/COMPLIANCE.md; these keys must stay.
func TestJSON_TopLevelKeys(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, fixtureReport()); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"format_version", "generated_at", "agentguard_version", "period", "source", "policy",
		"integrity", "activity", "approvals", "posture", "controls", "limits"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
}
