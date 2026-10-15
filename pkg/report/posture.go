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
	file := r.Source.Mode == SourceFile
	var checks []Check

	checks = append(checks, sealedCheck(r), keyCheck(r), chainCheck(r), outsideChainCheck(r))

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

// sealedCheck passes only for a chain that verified. A seal the report
// could not verify is only a claim: a _meta header anyone can write, or a
// server's word.
func sealedCheck(r *Report) Check {
	in := r.Integrity
	c := Check{Name: "Audit log sealed"}
	switch in.Status {
	case IntegrityIntact:
		c.Status, c.Detail = CheckPass, "Yes, and the chain verified: every sealed entry carries seq, prev_hash and hash."
	case IntegrityBroken:
		c.Status, c.Detail = CheckFail, "The seal does not hold: "+in.Summary
	case IntegrityNotSealed:
		c.Status, c.Detail = CheckWarn, "No: edits to the log can't be detected. Start the server with --audit-seal."
	case IntegrityNotVerified:
		if r.Source.Mode == SourceFile {
			c.Status, c.Detail = CheckWarn, "The log says so and its structure holds, but its hashes were not checked: give --key-file to verify it."
		} else {
			c.Status, c.Detail = CheckUnknown, "The server reports a seal head, but the report did not check the chain. Run it on the log files to verify."
		}
	default:
		c.Status, c.Detail = CheckUnknown, in.Summary
	}
	return c
}

// keyCheck reports how the chain is sealed. The algorithm is read from the
// log's header, so unless the chain verified with the key it is a claim.
func keyCheck(r *Report) Check {
	in := r.Integrity
	c := Check{Name: "Seal uses a secret key"}
	unverified := ""
	switch in.Status {
	case IntegrityBroken:
		unverified = " (the header says so, but the chain is broken)"
	case IntegrityNotVerified:
		unverified = " (the header says so; without --key-file that is not verified, and anyone who can write the file can write a header)"
	}
	switch {
	case in.Status == IntegrityNotSealed:
		c.Status, c.Detail = CheckWarn, "Not sealed."
	case in.KeyBased != nil && *in.KeyBased && unverified == "":
		c.Status, c.Detail = CheckPass, "HMAC-SHA256, verified with the key: only a holder of the key can write a chain that verifies."
	case in.KeyBased != nil && *in.KeyBased:
		c.Status, c.Detail = CheckUnknown, "HMAC-SHA256"+unverified+"."
	case in.KeyBased != nil:
		c.Status, c.Detail = CheckWarn, "Plain SHA-256"+unverified+": anyone who can write the file can recompute the chain. Set --audit-seal-key-file."
	case r.Source.Mode == SourceFile:
		c.Status, c.Detail = CheckWarn, "No seal is declared in the log files."
	default:
		c.Status, c.Detail = CheckUnknown, "The server's head does not say how the chain is sealed."
	}
	return c
}

func chainCheck(r *Report) Check {
	in := r.Integrity
	c := Check{Name: "Seal chain verified"}
	switch in.Status {
	case IntegrityIntact:
		c.Status, c.Detail = CheckPass, in.Summary
	case IntegrityBroken:
		c.Status, c.Detail = CheckFail, in.Summary
	case IntegrityNotSealed:
		c.Status, c.Detail = CheckWarn, "Not sealed: nothing to verify."
	default:
		c.Status, c.Detail = CheckUnknown, in.Summary
	}
	return c
}

// outsideChainCheck counts the entries no seal protects. Reading files,
// audit verify counts them (up to a break); from a server, the report
// counts entries in the period that came without seq or hash.
func outsideChainCheck(r *Report) Check {
	in := r.Integrity
	c := Check{Name: "Entries outside the seal chain"}
	if v := in.Verify; v != nil {
		switch {
		case in.Status == IntegrityBroken:
			c.Status, c.Detail = CheckFail, "Unknown past the break, and nothing after it is protected: "+in.Summary
		case in.Status == IntegrityNotSealed:
			c.Status, c.Detail = CheckWarn, fmt.Sprintf("All of them: the files hold %s and none is sealed.", plural(int(v.Unsealed), "entry", "entries"))
		case v.Unsealed > 0:
			c.Status, c.Detail = CheckWarn, fmt.Sprintf("Written before sealing began, and not protected: %s.", plural(int(v.Unsealed), "entry", "entries"))
		default:
			c.Status, c.Detail = CheckPass, "None."
		}
		if v.PrunedBefore > 0 {
			c.Detail += fmt.Sprintf(" Older files were pruned; the chain starts at seq %d.", v.PrunedBefore+1)
		}
		return c
	}
	n, total := r.Activity.UnsealedEntries, r.Activity.Entries
	switch {
	case in.Status == IntegrityNotSealed:
		c.Status, c.Detail = CheckWarn, "All of them: the server's log is not sealed."
	case n > 0:
		c.Status, c.Detail = CheckWarn, fmt.Sprintf("Entries in the period that came without seq or hash: %d of %d.", n, total)
	case in.Status == IntegrityNotVerified:
		c.Status, c.Detail = CheckPass, "Every entry in the period carries seq and hash (the chain itself was not checked)."
	default:
		c.Status, c.Detail = CheckUnknown, "Unknown whether the server seals its log."
	}
	return c
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
	for _, w := range r.Source.Warnings {
		l = append(l, "The entries may be incomplete: "+w+".")
	}
	if r.Source.Mode == SourceServer {
		l = append(l,
			"A server using the file audit backend answers from its live file only: entries in rotated archives are not included, and entries that rotate out while the report reads are lost. The report notices a rotation only on a sealed server (its seal head names the live file). Run the report with --audit-log on the server's files to cover archives.",
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
