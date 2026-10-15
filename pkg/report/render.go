package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Output formats.
const (
	FormatMarkdown = "md"
	FormatJSON     = "json"
	FormatHTML     = "html"
)

// Formats lists the output formats Write accepts.
var Formats = []string{FormatMarkdown, FormatJSON, FormatHTML}

// Write renders r in format to w.
func Write(w io.Writer, r *Report, format string) error {
	switch format {
	case FormatMarkdown:
		return WriteMarkdown(w, r)
	case FormatJSON:
		return WriteJSON(w, r)
	case FormatHTML:
		return WriteHTML(w, r)
	}
	return fmt.Errorf("unknown report format %q (want %s)", format, strings.Join(Formats, ", "))
}

// WriteJSON writes r as indented JSON: the documented, stable shape.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ── Text shared by the Markdown and HTML forms ───────────────────────────

const title = "AgentGuard compliance evidence report"

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func periodText(p Period) string {
	return stamp(p.Since) + " (inclusive) to " + stamp(p.Until) + " (exclusive)"
}

func sourceText(s Source) string {
	if s.Mode == SourceServer {
		out := fmt.Sprintf("server %s, tenant %s, entries fetched: %d", s.Server, s.Tenant, s.Fetched)
		if s.OutsidePeriod > 0 {
			out += fmt.Sprintf(" (outside the period and dropped: %d)", s.OutsidePeriod)
		}
		return out
	}
	return fmt.Sprintf("audit log files: %s (%s, unreadable lines: %d)", s.AuditLog, plural(len(s.Files), "file", "files"), s.BadLines)
}

func policyText(p *PolicyFile) string {
	if p == nil {
		return "none given or found"
	}
	return fmt.Sprintf("%s (%s), SHA-256 %s", p.Path, p.Found, p.SHA256)
}

func decisionsText(a Activity) string {
	parts := make([]string, 0, len(a.Decisions))
	for _, d := range a.Decisions {
		parts = append(parts, fmt.Sprintf("%s %d", d.Name, d.Count))
	}
	return fmt.Sprintf("%d (%s)", a.Entries, strings.Join(parts, ", "))
}

func methodText(m string) string {
	if m == MethodSealHead {
		return "the server's seal head (GET /v1/audit/head); the chain was not checked"
	}
	return "agentguard audit verify, over the log files"
}

func headText(h *Head) string {
	if h == nil {
		return ""
	}
	out := fmt.Sprintf("seq %d, hash %s", h.Seq, h.Hash)
	if h.SegmentID != "" {
		out += ", segment " + h.SegmentID
	}
	if h.At != nil {
		out += ", read at " + stamp(*h.At)
	}
	return out
}

func spanText(a Activity) string {
	switch a.Entries {
	case 0:
		return "No audit entries in the period."
	case 1:
		return "1 entry, at " + stamp(*a.FirstEntry) + "."
	}
	return fmt.Sprintf("%d entries, the first at %s and the last at %s.", a.Entries, stamp(*a.FirstEntry), stamp(*a.LastEntry))
}

// tallyHeading is a breakdown's heading: "Agents (top 10 of 42)" when the
// list is cut.
func tallyHeading(name string, t Tally) string {
	if len(t.Top) < t.Distinct {
		return fmt.Sprintf("%s (top %d of %d)", name, len(t.Top), t.Distinct)
	}
	return name
}

func namesText(l NameList) string {
	if l.Count == 0 {
		return "none"
	}
	out := strings.Join(l.Names, ", ")
	if l.Truncated {
		out += fmt.Sprintf(" (the first %d of %d, by name)", len(l.Names), l.Count)
	}
	return out
}

const approvalsNote = "The audit log has an entry when an action is sent for approval, and another when the agent comes back with the approval id after a person decided. \"No outcome on record\" covers requests that timed out, were decided but not retried, were decided after the period, or are still pending."

// ── Markdown ─────────────────────────────────────────────────────────────

// WriteMarkdown writes r as a Markdown document. Every value that comes
// from the log or the command line is escaped, so an agent id can't add
// table columns, links or HTML.
func WriteMarkdown(w io.Writer, r *Report) error {
	m := &mdWriter{w: w}
	m.p("# %s\n", title)
	m.para(Disclaimer)

	m.h2(SectionSummary)
	m.table([]string{"Item", "Value"}, [][]string{
		{"Period", periodText(r.Period)},
		{"Generated", stamp(r.GeneratedAt)},
		{"AgentGuard", r.AgentGuardVersion},
		{"Source", sourceText(r.Source)},
		{"Policy", policyText(r.Policy)},
		{"Decisions", decisionsText(r.Activity)},
		{"Audit log", r.Integrity.Status},
	})

	in := r.Integrity
	m.h2(SectionIntegrity)
	m.p("\n**Status: %s.** %s\n", md(in.Status), md(in.Summary))
	items := []string{"Checked with: " + methodText(in.Method)}
	if len(in.Seals) > 0 {
		items = append(items, "Sealed with: "+strings.Join(in.Seals, ", then "))
	}
	if in.Head != nil {
		items = append(items, "Latest seal anchor: "+headText(in.Head))
	}
	if len(r.Source.Files) > 0 {
		items = append(items, "Files, oldest first: "+strings.Join(r.Source.Files, ", "))
	}
	if in.Verify != nil {
		for _, warn := range in.Verify.Warnings {
			items = append(items, "Warning: "+warn)
		}
	}
	for _, e := range r.Source.ReadErrors {
		items = append(items, "Read error: "+e)
	}
	m.list(items)

	a := r.Activity
	m.h2(SectionActivity)
	m.para(spanText(a))
	m.h3("Decisions")
	m.counts("Decision", a.Decisions)
	m.h3(tallyHeading("Scopes", a.Scopes))
	m.counts("Scope", a.Scopes.Top)
	m.h3(tallyHeading("Transports", a.Transports))
	m.counts("Transport", a.Transports.Top)
	m.h3(tallyHeading("Tenants", a.Tenants))
	m.counts("Tenant", a.Tenants.Top)
	m.h3(tallyHeading("Agents", a.Agents))
	m.counts("Agent", a.Agents.Top)

	m.h2(SectionRules)
	m.h3(tallyHeading("DENY", a.DenyRules))
	m.counts("Rule", a.DenyRules.Top)
	m.h3(tallyHeading("REQUIRE_APPROVAL", a.ApprovalRules))
	m.counts("Rule", a.ApprovalRules.Top)

	ap := r.Approvals
	m.h2(SectionApprovals)
	m.table([]string{"Stage", "Approval ids"}, [][]string{
		{"Sent for approval", fmt.Sprint(ap.Requested)},
		{"Approved by a person", fmt.Sprint(ap.Approved)},
		{"Denied by a person", fmt.Sprint(ap.Denied)},
		{"Timed out", "unknown (not recorded in the audit log)"},
		{"No outcome on record", fmt.Sprint(ap.NoOutcome)},
	})
	m.para(approvalsNote)

	m.h2(SectionSeen)
	m.list([]string{
		fmt.Sprintf("Agents (%d): %s", a.AgentsSeen.Count, namesText(a.AgentsSeen)),
		fmt.Sprintf("Sessions (%d): %s", a.SessionsSeen.Count, namesText(a.SessionsSeen)),
	})

	m.h2(SectionPosture)
	rows := make([][]string, 0, len(r.Posture))
	for _, c := range r.Posture {
		rows = append(rows, []string{c.Name, c.Status, c.Detail})
	}
	m.table([]string{"Check", "Status", "Detail"}, rows)

	m.h2(SectionControls + " (SOC 2)")
	m.p("\n> %s\n", md(Disclaimer))
	rows = rows[:0]
	for _, c := range r.Controls {
		rows = append(rows, []string{c.Criterion + " " + c.Title, c.Shows, strings.Join(c.Where, ", ")})
	}
	m.table([]string{"Criterion", "What this report shows", "Where"}, rows)

	m.h2(SectionLimits)
	m.list(r.Limits)
	return m.err
}

// mdWriter writes Markdown and keeps the first write error. Each block
// starts with the blank line that separates it from the one before.
type mdWriter struct {
	w   io.Writer
	err error
}

func (m *mdWriter) p(format string, a ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format, a...)
	}
}

func (m *mdWriter) h2(s string)   { m.p("\n## %s\n", md(s)) }
func (m *mdWriter) h3(s string)   { m.p("\n### %s\n", md(s)) }
func (m *mdWriter) para(s string) { m.p("\n%s\n", md(s)) }

func (m *mdWriter) list(items []string) {
	m.p("\n")
	for _, it := range items {
		m.p("- %s\n", md(it))
	}
}

// table writes a table whose cells are all escaped, or "None." when there
// are no rows.
func (m *mdWriter) table(head []string, rows [][]string) {
	if len(rows) == 0 {
		m.para("None.")
		return
	}
	m.p("\n| %s |\n|%s\n", strings.Join(head, " | "), strings.Repeat(" --- |", len(head)))
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = md(c)
		}
		m.p("| %s |\n", strings.Join(cells, " | "))
	}
}

func (m *mdWriter) counts(name string, cs []Count) {
	rows := make([][]string, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, []string{c.Name, fmt.Sprint(c.Count)})
	}
	m.table([]string{name, "Count"}, rows)
}

// mdEscaper backslash-escapes Markdown punctuation, turns < > & into
// entities (Markdown passes raw HTML through) and folds line breaks into
// spaces so a value stays in its table cell.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"|", `\|`, "#", `\#`, "~", `\~`, "!", `\!`,
	"<", "&lt;", ">", "&gt;", "&", "&amp;",
	"\r\n", " ", "\n", " ", "\r", " ",
)

func md(s string) string { return mdEscaper.Replace(s) }
