package report

import (
	"fmt"
	"strings"
)

// Section names, as the renderers title them. Control.Where refers to them.
const (
	SectionSummary   = "Summary"
	SectionIntegrity = "Audit log integrity"
	SectionActivity  = "Activity"
	SectionRules     = "Top rules"
	SectionApprovals = "Approvals"
	SectionSeen      = "Agents and sessions"
	SectionPosture   = "Posture checks"
	SectionControls  = "Control mapping"
	SectionLimits    = "Limits"
)

// Disclaimer heads the control mapping in every format.
const Disclaimer = "Supporting evidence only. This report is not a SOC 2 report, a certification or an audit opinion; an auditor decides what it shows and whether it is enough."

// Finish fills the parts of r that follow from the rest: the posture
// checks, the control mapping and the limits. Call it once everything else
// is set.
func Finish(r *Report) {
	r.FormatVersion = FormatVersion
	r.Posture = Assess(r)
	r.Controls = MapControls(r)
	r.Limits = Limits(r)
}

// Assess runs the posture checks that can be decided from what the report
// read. A check that can't is "unknown", never a guess.
func Assess(r *Report) []Check {
	in := r.Integrity
	file := r.Source.Mode == SourceFile
	var checks []Check

	sealed := Check{Name: "Audit log sealed"}
	switch in.Status {
	case IntegrityNotSealed:
		sealed.Status, sealed.Detail = CheckWarn, "No: edits to the log can't be detected. Start the server with --audit-seal."
	case IntegrityUnknown:
		sealed.Status, sealed.Detail = CheckUnknown, in.Summary
	default:
		sealed.Status, sealed.Detail = CheckPass, "Yes: every entry carries seq, prev_hash and hash."
	}
	checks = append(checks, sealed)

	key := Check{Name: "Seal uses a secret key"}
	switch {
	case in.KeyBased != nil && *in.KeyBased:
		key.Status, key.Detail = CheckPass, "HMAC-SHA256: only a holder of the key can write a chain that verifies."
	case in.KeyBased != nil:
		key.Status, key.Detail = CheckWarn, "Plain SHA-256: anyone who can write the file can recompute the chain. Set --audit-seal-key-file."
	case in.Status == IntegrityNotSealed:
		key.Status, key.Detail = CheckWarn, "Not sealed."
	default:
		key.Status, key.Detail = CheckUnknown, "The server's head does not say how the chain is sealed."
	}
	checks = append(checks, key)

	chain := Check{Name: "Seal chain verified"}
	switch in.Status {
	case IntegrityIntact:
		chain.Status, chain.Detail = CheckPass, in.Summary
	case IntegrityBroken:
		chain.Status, chain.Detail = CheckFail, in.Summary
	case IntegrityNotSealed:
		chain.Status, chain.Detail = CheckWarn, "Not sealed: nothing to verify."
	default:
		chain.Status, chain.Detail = CheckUnknown, in.Summary
	}
	checks = append(checks, chain)

	unsealed := Check{Name: "Entries outside the seal chain"}
	switch {
	case in.Verify == nil:
		unsealed.Status, unsealed.Detail = CheckUnknown, "Known only when the report verifies the log files."
	case in.Status == IntegrityNotSealed:
		unsealed.Status, unsealed.Detail = CheckWarn, fmt.Sprintf("All of them: the files hold %s and no seal.", plural(int(in.Verify.Unsealed), "entry", "entries"))
	case in.Verify.Unsealed > 0:
		unsealed.Status, unsealed.Detail = CheckWarn, fmt.Sprintf("Written before sealing began, and not protected: %s.", plural(int(in.Verify.Unsealed), "entry", "entries"))
	default:
		unsealed.Status, unsealed.Detail = CheckPass, "None."
	}
	if in.Verify != nil && in.Verify.PrunedBefore > 0 {
		unsealed.Detail += fmt.Sprintf(" Older files were pruned; the chain starts at seq %d.", in.Verify.PrunedBefore+1)
	}
	checks = append(checks, unsealed)

	lines := Check{Name: "Unreadable lines"}
	switch {
	case !file:
		lines.Status, lines.Detail = CheckUnknown, "The server skips them; known only when the report reads the log files."
	case len(r.Source.ReadErrors) > 0:
		lines.Status, lines.Detail = CheckFail, fmt.Sprintf("Some files could not be read to the end (%s); lines that are not entries: %d.", strings.Join(r.Source.ReadErrors, "; "), r.Source.BadLines)
	case r.Source.BadLines > 0:
		lines.Status, lines.Detail = CheckWarn, fmt.Sprintf("Lines in the log files that are not audit entries (damaged, or cut short by a crash): %d.", r.Source.BadLines)
	default:
		lines.Status, lines.Detail = CheckPass, "Every line of the log files is an audit entry."
	}
	checks = append(checks, lines)

	act := r.Activity
	secrets := Check{Name: "Secrets masked in the log"}
	switch {
	case act.UnmaskedSecretEntries > 0:
		secrets.Status, secrets.Detail = CheckFail, fmt.Sprintf("Entries holding text that looks like a secret (an API key, token or password): %d. Is the server running with --audit-redact=false?", act.UnmaskedSecretEntries)
	case act.RedactedEntries > 0:
		secrets.Status, secrets.Detail = CheckPass, fmt.Sprintf("Entries with masked secrets: %d. None holds an unmasked one.", act.RedactedEntries)
	default:
		secrets.Status, secrets.Detail = CheckUnknown, "No entry holds a secret, masked or not, so the log can't show whether masking (--audit-redact) is on."
	}
	checks = append(checks, secrets)

	auth := Check{Name: "Audit API requires an API key"}
	switch {
	case file:
		auth.Status, auth.Detail = CheckUnknown, "Not checked: the report read the log files, not a server."
	case r.Source.AuthRequired == nil:
		auth.Status, auth.Detail = CheckUnknown, "Not checked."
	case *r.Source.AuthRequired:
		auth.Status, auth.Detail = CheckPass, "The server refused an audit query without the API key (HTTP 401)."
	default:
		auth.Status, auth.Detail = CheckFail, "The server answered an audit query that had no API key. Start it with --api-key or --api-key-file."
	}
	checks = append(checks, auth)
	return checks
}

// MapControls maps the report's evidence to the SOC 2 criteria it bears
// on. The wording says what the report shows, never that a criterion is
// met.
func MapControls(r *Report) []Control {
	a := r.Activity
	deny := countOf(a.Decisions, "DENY")
	approval := countOf(a.Decisions, "REQUIRE_APPROVAL")
	policy := "no policy file was named"
	if r.Policy != nil {
		policy = "the policy file's SHA-256 " + shortHash(r.Policy.SHA256)
	}
	return []Control{
		{
			Criterion: "CC6.1",
			Title:     "Logical access to protected assets is restricted",
			Shows:     fmt.Sprintf("Agent actions that reached AgentGuard were checked against a policy (%s): %s, %d denied, broken down by scope and agent.", policy, plural(a.Entries, "decision", "decisions"), deny),
			Where:     []string{SectionSummary, SectionActivity, SectionRules, SectionPosture},
		},
		{
			Criterion: "CC6.6",
			Title:     "Access from outside the system boundary is controlled",
			Shows:     fmt.Sprintf("Actions reaching outside the agent (network, browser, MCP tools, LLM tool calls) went through AgentGuard; the scope and transport breakdowns and the deny rules show what was let through and what was blocked (%s, %s).", plural(a.Scopes.Distinct, "scope", "scopes"), plural(a.Transports.Distinct, "transport", "transports")),
			Where:     []string{SectionActivity, SectionRules},
		},
		{
			Criterion: "CC7.2",
			Title:     "System components are monitored for anomalies",
			Shows:     fmt.Sprintf("Every decision is recorded in the audit log; its seal status is %q, and the posture checks cover unreadable lines and unmasked secrets.", r.Integrity.Status),
			Where:     []string{SectionIntegrity, SectionActivity, SectionPosture},
		},
		{
			Criterion: "CC7.3",
			Title:     "Security events are evaluated",
			Shows:     fmt.Sprintf("Entries sending an action to a person for approval: %d (%s). On record as approved by a person: %d; denied by a person: %d. The top deny rules show which risky actions were stopped.", approval, plural(r.Approvals.Requested, "approval id", "approval ids"), r.Approvals.Approved, r.Approvals.Denied),
			Where:     []string{SectionApprovals, SectionRules},
		},
		{
			Criterion: "CC8.1",
			Title:     "Changes are authorized",
			Shows:     fmt.Sprintf("The report names %s, so a reviewer can match it to an approved change. Actions the policy sends for approval (deploys, writes) needed a person's yes: see Approvals.", policy),
			Where:     []string{SectionSummary, SectionApprovals},
		},
	}
}

// Limits lists what the report can't show, for the reader to weigh the
// numbers against.
func Limits(r *Report) []string {
	l := []string{
		"The report counts what the audit log recorded. An action that never reached AgentGuard is not in it.",
		"Approval outcomes show only when the agent came back with the approval id after a person decided. The log does not record the decision itself, who made it, or a request that timed out.",
	}
	if r.Policy != nil {
		l = append(l, "The policy SHA-256 is of the file as it was when the report was made. The audit log does not record which version of the policy made each decision.")
	}
	l = append(l, "The secret check uses the built-in patterns only, not a policy's notifications.redaction.extra_patterns.")
	if r.Source.Mode == SourceServer {
		l = append(l,
			"A server using the file audit backend answers from its live file only: entries in rotated archives are not included. Run the report with --audit-log on the server's files to cover them.",
			fmt.Sprintf("Only tenant %q is covered: the audit API answers for one tenant at a time.", r.Source.Tenant),
		)
	} else {
		l = append(l,
			"Archives that no file links to, and archives already pruned by --audit-max-backups or --audit-max-age-days, are not read.",
			"Entries a running server still holds in its buffer or its overflow file (<audit-log>.overflow.jsonl) are not in the log yet, so they are not counted.",
		)
	}
	return l
}

// plural is "1 entry" or "3 entries".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func countOf(cs []Count, name string) int {
	for _, c := range cs {
		if c.Name == name {
			return c.Count
		}
	}
	return 0
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}
