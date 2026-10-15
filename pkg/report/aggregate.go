package report

import (
	"iter"
	"sort"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// How much of each breakdown the report lists. The counts behind them are
// always complete; only the lists are cut, so a log with a million agents
// still makes a readable report.
const (
	topN    = 10  // agents, tenants and rules, by count
	allN    = 50  // decisions, scopes and transports: small sets, listed whole
	namesN  = 100 // agents and sessions seen, by name
	noValue = "(none)"
)

// defaultDenyRule names the rule of a DENY that no rule matched: the engine
// leaves matched_rule empty for the default deny.
const defaultDenyRule = "(default deny)"

// Rules the server stamps on the entry it writes when an agent comes back
// with an approval id (pkg/proxy resolvedApprovalToResult).
const (
	ruleApproved       = "allow:approved"
	ruleDeniedByHuman  = "deny:approved" // a prefix: also deny:approved:invalid_resolution
	rulePendingApprove = "require_approval:pending"
)

// redactedMarker is what the server's --audit-redact puts in place of a
// secret (pkg/notify Redactor).
const redactedMarker = "[REDACTED]"

// Activity is what was decided in the period.
type Activity struct {
	// Entries is the number of audit entries in the period.
	Entries int `json:"entries"`
	// FirstEntry and LastEntry are the earliest and latest timestamps among
	// them; omitted when there are none.
	FirstEntry *time.Time `json:"first_entry,omitempty"`
	LastEntry  *time.Time `json:"last_entry,omitempty"`
	// Decisions always lists ALLOW, DENY and REQUIRE_APPROVAL, in that
	// order, then any other value found.
	Decisions  []Count `json:"decisions"`
	Scopes     Tally   `json:"scopes"`
	Transports Tally   `json:"transports"`
	Tenants    Tally   `json:"tenants"`
	Agents     Tally   `json:"agents"`
	// DenyRules and ApprovalRules are the matched rules of DENY and
	// REQUIRE_APPROVAL entries. A DENY no rule matched counts as
	// "(default deny)".
	DenyRules     Tally `json:"deny_rules"`
	ApprovalRules Tally `json:"approval_rules"`
	// AgentsSeen and SessionsSeen list the agent and session ids (entries
	// without a session id are not counted as a session).
	AgentsSeen   NameList `json:"agents_seen"`
	SessionsSeen NameList `json:"sessions_seen"`
	// RedactedEntries counts entries holding "[REDACTED]", the mask the
	// server's --audit-redact writes. UnmaskedSecretEntries counts entries
	// whose request or reason still matches one of the built-in secret
	// patterns.
	RedactedEntries       int `json:"redacted_entries"`
	UnmaskedSecretEntries int `json:"unmasked_secret_entries"`
	// UnsealedEntries counts entries in the period without a seal (no hash
	// or no seq). In server mode it is the only seal evidence per entry.
	UnsealedEntries int `json:"unsealed_entries"`
}

// Approvals is the approval lifecycle as the audit log records it. The log
// has an entry when an action is sent for approval, and another when the
// agent comes back with the approval id after a human resolved it. It has
// none for the resolution itself or for a request that timed out.
type Approvals struct {
	// Requested counts approval ids first sent for approval in the period.
	Requested int `json:"requested"`
	// Approved and Denied count approval ids whose human decision shows in
	// the period (allow:approved or deny:approved entries).
	Approved int `json:"approved"`
	Denied   int `json:"denied"`
	// NoOutcome counts ids requested in the period with no approved or
	// denied entry in it: timed out, resolved but never retried, resolved
	// after the period, or still pending.
	NoOutcome int `json:"no_outcome"`
	// TimedOut is always null: the audit log does not record time-outs.
	// They are among NoOutcome.
	TimedOut *int `json:"timed_out"`
}

// Aggregate tallies the entries that fall in p. Entries outside it are
// skipped, so the caller can pass a whole log.
func Aggregate(entries iter.Seq[audit.Entry], p Period) (Activity, Approvals) {
	var (
		a          Activity
		decisions  = map[string]int{}
		scopes     = map[string]int{}
		transports = map[string]int{}
		tenants    = map[string]int{}
		agents     = map[string]int{}
		denyRules  = map[string]int{}
		apprRules  = map[string]int{}
		sessions   = map[string]bool{}
		requested  = map[string]bool{}
		approved   = map[string]bool{}
		denied     = map[string]bool{}
		redactor   = notify.DefaultRedactor()
	)
	for e := range entries {
		if !p.Contains(e.Timestamp) {
			continue
		}
		a.Entries++
		ts := e.Timestamp.UTC()
		if a.FirstEntry == nil || ts.Before(*a.FirstEntry) {
			a.FirstEntry = &ts
		}
		if a.LastEntry == nil || ts.After(*a.LastEntry) {
			a.LastEntry = &ts
		}

		decision := string(e.Result.Decision)
		decisions[orNone(decision)]++
		scopes[orNone(e.Request.Scope)]++
		transports[e.EffectiveTransport()]++
		tenants[e.EffectiveTenant()]++
		agents[orNone(e.AgentID)]++
		if e.SessionID != "" {
			sessions[e.SessionID] = true
		}

		rule, id := e.Result.Rule, e.Result.ApprovalID
		switch e.Result.Decision {
		case policy.Deny:
			if rule == "" {
				rule = defaultDenyRule
			}
			denyRules[rule]++
			if id != "" && strings.HasPrefix(rule, ruleDeniedByHuman) {
				denied[id] = true
			}
		case policy.RequireApproval:
			apprRules[orNone(rule)]++
			// A retry while the approval is still pending repeats the id
			// with its own rule; the first entry for an id is the request.
			if id != "" && rule != rulePendingApprove {
				requested[id] = true
			}
		case policy.Allow:
			if id != "" && rule == ruleApproved {
				approved[id] = true
			}
		}

		if e.Hash == "" || e.Seq == 0 {
			a.UnsealedEntries++
		}
		if mentionsRedaction(e) {
			a.RedactedEntries++
		}
		if holdsSecret(redactor, e) {
			a.UnmaskedSecretEntries++
		}
	}

	a.Decisions = decisionCounts(decisions)
	a.Scopes = tally(scopes, allN)
	a.Transports = tally(transports, allN)
	a.Tenants = tally(tenants, topN)
	a.Agents = tally(agents, topN)
	a.DenyRules = tally(denyRules, topN)
	a.ApprovalRules = tally(apprRules, topN)
	a.AgentsSeen = nameList(agents, namesN)
	a.SessionsSeen = nameList(sessions, namesN)

	ap := Approvals{Requested: len(requested), Approved: len(approved), Denied: len(denied)}
	for id := range requested {
		if !approved[id] && !denied[id] {
			ap.NoOutcome++
		}
	}
	return a, ap
}

func orNone(s string) string {
	if s == "" {
		return noValue
	}
	return s
}

// decisionCounts lists the three decisions first, in their usual order, so
// a report with no denials still says DENY 0.
func decisionCounts(m map[string]int) []Count {
	known := []string{string(policy.Allow), string(policy.Deny), string(policy.RequireApproval)}
	out := make([]Count, 0, len(known))
	for _, d := range known {
		out = append(out, Count{Name: d, Count: m[d]})
		delete(m, d)
	}
	return append(out, tally(m, allN).Top...)
}

// tally sorts m by count, most first, ties by name, and keeps the first n.
func tally(m map[string]int, n int) Tally {
	top := make([]Count, 0, len(m))
	for k, v := range m {
		top = append(top, Count{Name: k, Count: v})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].Name < top[j].Name
	})
	if len(top) > n {
		top = top[:n]
	}
	return Tally{Distinct: len(m), Top: top}
}

// nameList returns the first n keys of m in sorted order.
func nameList[V any](m map[string]V, n int) NameList {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	l := NameList{Count: len(names), Names: names}
	if len(names) > n {
		l.Names, l.Truncated = names[:n], true
	}
	return l
}

// requestTexts are the fields the server's --audit-redact masks
// (cmd/agentguard: RedactRequest plus the reason).
func requestTexts(e audit.Entry) []string {
	r := e.Request
	texts := []string{r.Command, r.Path, r.Domain, r.Action, r.URL, e.Result.Reason}
	for _, v := range r.Meta {
		texts = append(texts, v)
	}
	return texts
}

func mentionsRedaction(e audit.Entry) bool {
	for _, s := range requestTexts(e) {
		if strings.Contains(s, redactedMarker) {
			return true
		}
	}
	return false
}

// holdsSecret reports whether masking would still change the entry: a
// value the built-in patterns take for a secret was written verbatim. The
// masks already there are taken out first, so "TOKEN=[REDACTED]" (an
// operator's extra pattern can leave that) is not counted as a secret.
func holdsSecret(r *notify.Redactor, e audit.Entry) bool {
	for _, s := range requestTexts(e) {
		s = strings.ReplaceAll(s, redactedMarker, "")
		if s != "" && r.RedactString(s) != s {
			return true
		}
	}
	return false
}
