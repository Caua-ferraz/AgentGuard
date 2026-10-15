package report

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func TestAggregate_Fixture(t *testing.T) {
	a, ap := Aggregate(slices.Values(fixtureEntries()), period)

	if a.Entries != 12 {
		t.Errorf("entries = %d, want 12 (since is inclusive, until exclusive)", a.Entries)
	}
	if !a.FirstEntry.Equal(t0) || !a.LastEntry.Equal(at(25*time.Hour)) {
		t.Errorf("first/last = %v/%v", a.FirstEntry, a.LastEntry)
	}
	wantDecisions := []Count{{"ALLOW", 5}, {"DENY", 3}, {"REQUIRE_APPROVAL", 4}}
	if !slices.Equal(a.Decisions, wantDecisions) {
		t.Errorf("decisions = %v, want %v", a.Decisions, wantDecisions)
	}
	if got := countOf(a.DenyRules.Top, "(default deny)"); got != 1 {
		t.Errorf("default deny counted %d times, want 1", got)
	}
	if got := countOf(a.ApprovalRules.Top, "require_approval:shell:make deploy"); got != 3 {
		t.Errorf("approval rule counted %d times, want 3", got)
	}
	if got := countOf(a.Transports.Top, "sdk"); got != 5 {
		t.Errorf("sdk transport = %d, want 5 (entries without a transport are sdk)", got)
	}
	if got := countOf(a.Tenants.Top, "local"); got != 11 {
		t.Errorf("local tenant = %d, want 11 (entries without a tenant are local)", got)
	}
	if a.AgentsSeen.Count != 3 || a.SessionsSeen.Count != 4 {
		t.Errorf("seen = %d agents, %d sessions; want 3, 4 (an entry without a session is not one)", a.AgentsSeen.Count, a.SessionsSeen.Count)
	}
	if a.RedactedEntries != 1 || a.UnmaskedSecretEntries != 1 {
		t.Errorf("redacted/unmasked = %d/%d, want 1/1", a.RedactedEntries, a.UnmaskedSecretEntries)
	}
	want := Approvals{Requested: 3, Approved: 1, Denied: 1, NoOutcome: 1}
	if ap != want {
		t.Errorf("approvals = %+v, want %+v", ap, want)
	}
}

func TestAggregate_Cases(t *testing.T) {
	ls := policy.ActionRequest{Scope: "shell", Command: "ls"}
	cases := []struct {
		name    string
		entries []audit.Entry
		check   func(t *testing.T, a Activity, ap Approvals)
	}{
		{
			name: "an empty period still lists the three decisions",
			check: func(t *testing.T, a Activity, ap Approvals) {
				if a.Entries != 0 || a.FirstEntry != nil || len(a.Decisions) != 3 {
					t.Errorf("activity = %+v", a)
				}
			},
		},
		{
			name: "an unknown decision is listed after the three",
			entries: []audit.Entry{
				entry(t0, "a", "", "MAYBE", "", "", ls),
			},
			check: func(t *testing.T, a Activity, _ Approvals) {
				if len(a.Decisions) != 4 || a.Decisions[3] != (Count{"MAYBE", 1}) {
					t.Errorf("decisions = %v", a.Decisions)
				}
			},
		},
		{
			name: "a resolution of an approval requested before the period counts, the request does not",
			entries: []audit.Entry{
				entry(t0.Add(-time.Hour), "a", "", policy.RequireApproval, "r", "ap_old", ls),
				entry(t0, "a", "", policy.Allow, "allow:approved", "ap_old", ls),
			},
			check: func(t *testing.T, _ Activity, ap Approvals) {
				if ap != (Approvals{Approved: 1}) {
					t.Errorf("approvals = %+v", ap)
				}
			},
		},
		{
			name: "an invalid resolution counts as denied by a person",
			entries: []audit.Entry{
				entry(t0, "a", "", policy.RequireApproval, "r", "ap_1", ls),
				entry(t0, "a", "", policy.Deny, "deny:approved:invalid_resolution", "ap_1", ls),
			},
			check: func(t *testing.T, _ Activity, ap Approvals) {
				if ap != (Approvals{Requested: 1, Denied: 1}) {
					t.Errorf("approvals = %+v", ap)
				}
			},
		},
		{
			name: "an empty agent id shows as (none)",
			entries: []audit.Entry{
				entry(t0, "", "", policy.Allow, "", "", ls),
			},
			check: func(t *testing.T, a Activity, _ Approvals) {
				if a.Agents.Top[0].Name != "(none)" {
					t.Errorf("agents = %+v", a.Agents)
				}
			},
		},
		{
			name:    "long lists are cut but the counts stay whole",
			entries: manyAgents(150),
			check: func(t *testing.T, a Activity, _ Approvals) {
				if a.Agents.Distinct != 150 || len(a.Agents.Top) != topN {
					t.Errorf("agents tally = %d distinct, %d listed", a.Agents.Distinct, len(a.Agents.Top))
				}
				if a.AgentsSeen.Count != 150 || len(a.AgentsSeen.Names) != namesN || !a.AgentsSeen.Truncated {
					t.Errorf("agents seen = %d, %d names, truncated %v", a.AgentsSeen.Count, len(a.AgentsSeen.Names), a.AgentsSeen.Truncated)
				}
				if a.AgentsSeen.Names[0] != "agent-000" {
					t.Errorf("names not sorted: %v", a.AgentsSeen.Names[:3])
				}
			},
		},
		{
			name: "ties are broken by name",
			entries: []audit.Entry{
				entry(t0, "b", "", policy.Allow, "", "", ls),
				entry(t0, "a", "", policy.Allow, "", "", ls),
			},
			check: func(t *testing.T, a Activity, _ Approvals) {
				if a.Agents.Top[0].Name != "a" {
					t.Errorf("agents = %v", a.Agents.Top)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, ap := Aggregate(slices.Values(tc.entries), period)
			tc.check(t, a, ap)
		})
	}
}

func manyAgents(n int) []audit.Entry {
	var es []audit.Entry
	for i := n - 1; i >= 0; i-- {
		es = append(es, entry(t0, fmt.Sprintf("agent-%03d", i), "", policy.Allow, "", "", policy.ActionRequest{Scope: "shell"}))
	}
	return es
}

func TestPeriodContains(t *testing.T) {
	cases := []struct {
		name string
		ts   time.Time
		want bool
	}{
		{"the start is in", period.Since, true},
		{"just before the start is out", period.Since.Add(-time.Nanosecond), false},
		{"just before the end is in", period.Until.Add(-time.Nanosecond), true},
		{"the end is out", period.Until, false},
		{"another time zone is compared as an instant", period.Since.In(time.FixedZone("x", 3600)), true},
	}
	for _, tc := range cases {
		if got := period.Contains(tc.ts); got != tc.want {
			t.Errorf("%s: Contains(%v) = %v", tc.name, tc.ts, got)
		}
	}
}
