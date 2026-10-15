package report

import (
	"bytes"
	"html/template"
	"io"
	"strings"
)

// WriteHTML writes r as one self-contained HTML page: inline CSS, no
// scripts, nothing loaded from elsewhere, so it can be mailed or archived
// as is. html/template escapes every value; it leaves control and bidi
// characters alone, so the page goes through visible as well (the
// template's own text has none).
func WriteHTML(w io.Writer, r *Report) error {
	var buf bytes.Buffer
	if err := htmlPage.Execute(&buf, r); err != nil {
		return err
	}
	_, err := io.WriteString(w, visible(buf.String()))
	return err
}

// countTable is one breakdown table: its first column's heading and rows.
type countTable struct {
	Head string
	Rows []Count
}

var htmlPage = template.Must(template.New("report").Funcs(template.FuncMap{
	"title":         func() string { return title },
	"disclaimer":    func() string { return Disclaimer },
	"stamp":         stamp,
	"period":        periodText,
	"source":        sourceText,
	"policy":        policyText,
	"decisions":     decisionsText,
	"method":        methodText,
	"head":          headText,
	"span":          spanText,
	"heading":       tallyHeading,
	"names":         namesText,
	"join":          strings.Join,
	"approvalsNote": func() string { return approvalsNote },
	"counts": func(head string, rows []Count) countTable {
		return countTable{Head: head, Rows: rows}
	},
	"section": func(name string) string {
		return map[string]string{
			"summary": SectionSummary, "integrity": SectionIntegrity, "activity": SectionActivity,
			"rules": SectionRules, "approvals": SectionApprovals, "seen": SectionSeen,
			"posture": SectionPosture, "controls": SectionControls, "limits": SectionLimits,
		}[name]
	},
}).Parse(htmlTemplate))

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{title}}</title>
<style>
:root { --fg: #1d1d1f; --muted: #5f6368; --bg: #fff; --line: #d9d9de; --head: #f4f4f6;
  --pass: #1e7b34; --warn: #9a6200; --fail: #b3261e; --unknown: #5f6368; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e8e8ea; --muted: #a0a0a8; --bg: #161618; --line: #3a3a40; --head: #222226;
    --pass: #6fcf87; --warn: #e3b341; --fail: #f28b82; --unknown: #a0a0a8; }
}
body { margin: 0 auto; max-width: 960px; padding: 24px 16px 48px; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
h1 { font-size: 1.6em; margin: 0 0 8px; }
h2 { font-size: 1.25em; margin: 32px 0 8px; padding-bottom: 4px; border-bottom: 1px solid var(--line); }
h3 { font-size: 1em; margin: 20px 0 6px; }
.note { color: var(--muted); }
.disclaimer { border-left: 4px solid var(--warn); padding: 8px 12px; background: var(--head); }
table { border-collapse: collapse; width: 100%; margin: 6px 0; }
th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: var(--head); font-weight: 600; }
td.num { text-align: right; white-space: nowrap; width: 8em; }
.status { font-weight: 600; text-transform: uppercase; font-size: 0.85em; white-space: nowrap; }
.pass, .intact { color: var(--pass); }
.warn, .not_sealed, .not_verified { color: var(--warn); }
.fail, .broken { color: var(--fail); }
.unknown { color: var(--unknown); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9em; overflow-wrap: anywhere; }
@media print { body { max-width: none; } h2 { break-after: avoid; } table { break-inside: avoid; } }
</style>
</head>
<body>
<h1>{{title}}</h1>
<p class="disclaimer">{{disclaimer}}</p>

<h2>{{section "summary"}}</h2>
<table>
<tr><th>Period</th><td>{{period .Period}}</td></tr>
<tr><th>Generated</th><td>{{stamp .GeneratedAt}}</td></tr>
<tr><th>AgentGuard</th><td>{{.AgentGuardVersion}}</td></tr>
<tr><th>Source</th><td>{{source .Source}}</td></tr>
<tr><th>Policy</th><td>{{policy .Policy}}</td></tr>
<tr><th>Decisions</th><td>{{decisions .Activity}}</td></tr>
<tr><th>Audit log</th><td><span class="status {{.Integrity.Status}}">{{.Integrity.Status}}</span></td></tr>
</table>

<h2>{{section "integrity"}}</h2>
{{with .Integrity}}<p><span class="status {{.Status}}">{{.Status}}</span> {{.Summary}}</p>
<ul>
<li>Checked with: {{method .Method}}</li>
{{- if .Seals}}
<li>Sealed with: {{join .Seals ", then "}}</li>
{{- end}}
{{- with .Head}}
<li>Latest seal anchor: <code>{{head .}}</code></li>
{{- end}}
{{- end}}
{{- with .Source.Files}}
<li>Files, oldest first: {{join . ", "}}</li>
{{- end}}
{{- with .Integrity.Verify}}{{range .Warnings}}
<li>Warning: {{.}}</li>
{{- end}}{{end}}
{{- range .Source.ReadErrors}}
<li>Read error: {{.}}</li>
{{- end}}
{{- range .Source.Warnings}}
<li>Warning: {{.}}</li>
{{- end}}
</ul>

{{with .Activity}}
<h2>{{section "activity"}}</h2>
<p>{{span .}}</p>
<h3>Decisions</h3>
{{template "counts" (counts "Decision" .Decisions)}}
<h3>{{heading "Scopes" .Scopes}}</h3>
{{template "counts" (counts "Scope" .Scopes.Top)}}
<h3>{{heading "Transports" .Transports}}</h3>
{{template "counts" (counts "Transport" .Transports.Top)}}
<h3>{{heading "Tenants" .Tenants}}</h3>
{{template "counts" (counts "Tenant" .Tenants.Top)}}
<h3>{{heading "Agents" .Agents}}</h3>
{{template "counts" (counts "Agent" .Agents.Top)}}

<h2>{{section "rules"}}</h2>
<h3>{{heading "DENY" .DenyRules}}</h3>
{{template "counts" (counts "Rule" .DenyRules.Top)}}
<h3>{{heading "REQUIRE_APPROVAL" .ApprovalRules}}</h3>
{{template "counts" (counts "Rule" .ApprovalRules.Top)}}
{{end}}

<h2>{{section "approvals"}}</h2>
{{with .Approvals}}<table>
<tr><th>Stage</th><th>Approval ids</th></tr>
<tr><td>Sent for approval</td><td class="num">{{.Requested}}</td></tr>
<tr><td>Approved by a person</td><td class="num">{{.Approved}}</td></tr>
<tr><td>Denied by a person</td><td class="num">{{.Denied}}</td></tr>
<tr><td>Timed out</td><td class="num">unknown</td></tr>
<tr><td>No outcome on record</td><td class="num">{{.NoOutcome}}</td></tr>
</table>{{end}}
<p class="note">{{approvalsNote}}</p>

<h2>{{section "seen"}}</h2>
<ul>
<li>Agents ({{.Activity.AgentsSeen.Count}}): {{names .Activity.AgentsSeen}}</li>
<li>Sessions ({{.Activity.SessionsSeen.Count}}): {{names .Activity.SessionsSeen}}</li>
</ul>

<h2>{{section "posture"}}</h2>
<table>
<tr><th>Check</th><th>Status</th><th>Detail</th></tr>
{{- range .Posture}}
<tr><td>{{.Name}}</td><td><span class="status {{.Status}}">{{.Status}}</span></td><td>{{.Detail}}</td></tr>
{{- end}}
</table>

<h2>{{section "controls"}} (SOC 2)</h2>
<p class="disclaimer">{{disclaimer}}</p>
<table>
<tr><th>Criterion</th><th>What this report shows</th><th>Where</th></tr>
{{- range .Controls}}
<tr><td><strong>{{.Criterion}}</strong> {{.Title}}</td><td>{{.Shows}}</td><td>{{join .Where ", "}}</td></tr>
{{- end}}
</table>

<h2>{{section "limits"}}</h2>
<ul>
{{- range .Limits}}
<li>{{.}}</li>
{{- end}}
</ul>
</body>
</html>
{{define "counts"}}{{if .Rows}}<table>
<tr><th>{{.Head}}</th><th>Count</th></tr>
{{- range .Rows}}
<tr><td>{{.Name}}</td><td class="num">{{.Count}}</td></tr>
{{- end}}
</table>{{else}}<p class="note">None.</p>{{end}}{{end}}`
