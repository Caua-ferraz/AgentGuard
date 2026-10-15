package audit

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

var sessT0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

// sessionEntries is an orchestrator session with two sub-agent sessions,
// a session in another tenant, and an entry with no session.
func sessionEntries() []Entry {
	return []Entry{
		{Timestamp: sessT0, SessionID: "orch", AgentID: "claude",
			Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
			Result:  policy.CheckResult{Decision: policy.Allow}, Transport: TransportClaudeCode},
		{Timestamp: sessT0.Add(time.Second), SessionID: "sub-1", AgentID: "claude",
			Request: policy.ActionRequest{Scope: "shell", Command: "cat x", ParentSessionID: "orch",
				Meta: map[string]string{"subagent": "Explore"}},
			Result: policy.CheckResult{Decision: policy.Deny}, Transport: TransportClaudeCode},
		{Timestamp: sessT0.Add(1500 * time.Millisecond), SessionID: "sub-1", AgentID: "helper",
			Request: policy.ActionRequest{Scope: "network", Domain: "x.test", ParentSessionID: "orch"},
			Result:  policy.CheckResult{Decision: policy.RequireApproval}},
		{Timestamp: sessT0.Add(2 * time.Second), SessionID: "sub-2", AgentID: "claude",
			Request: policy.ActionRequest{Scope: "shell", Command: "pwd", ParentSessionID: "orch"},
			Result:  policy.CheckResult{Decision: policy.Allow}, Transport: TransportClaudeCode},
		{Timestamp: sessT0.Add(3 * time.Second), SessionID: "orch", AgentID: "claude",
			Request: policy.ActionRequest{Scope: "shell", Command: "git status"},
			Result:  policy.CheckResult{Decision: policy.Allow}, Transport: TransportClaudeCode},
		{Timestamp: sessT0.Add(4 * time.Second), SessionID: "orch", AgentID: "other", TenantID: "acme",
			Request: policy.ActionRequest{Scope: "shell", Command: "id"},
			Result:  policy.CheckResult{Decision: policy.Deny}},
		{Timestamp: sessT0.Add(5 * time.Second), AgentID: "loner",
			Request: policy.ActionRequest{Scope: "shell", Command: "date"},
			Result:  policy.CheckResult{Decision: policy.Allow}},
	}
}

func newSessionLogger(t *testing.T) *FileLogger {
	t.Helper()
	l, err := NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for _, e := range sessionEntries() {
		if err := l.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	return l
}

func sessionIDs(list []SessionSummary) []string {
	ids := []string{}
	for _, s := range list {
		ids = append(ids, s.SessionID)
	}
	return ids
}

func TestFileLogger_SessionsSummarisesEachSession(t *testing.T) {
	l := newSessionLogger(t)
	got, err := l.Sessions(SessionFilter{TenantID: "local"})
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	// Newest first; the acme session and the entry without a session are
	// not in the local tenant's list.
	if ids := sessionIDs(got); !reflect.DeepEqual(ids, []string{"orch", "sub-2", "sub-1"}) {
		t.Fatalf("sessions = %v", ids)
	}
	sub1 := got[2]
	want := SessionSummary{
		SessionID:       "sub-1",
		ParentSessionID: "orch",
		Agents:          []SessionAgent{{AgentID: "claude", Subagent: "Explore"}, {AgentID: "helper"}},
		Transports:      []string{TransportClaudeCode, TransportSDK},
		FirstSeen:       sessT0.Add(time.Second),
		LastSeen:        sessT0.Add(1500 * time.Millisecond),
		Counts:          DecisionCounts{Total: 2, Deny: 1, RequireApproval: 1},
	}
	if !reflect.DeepEqual(sub1, want) {
		t.Errorf("sub-1 summary:\n got %+v\nwant %+v", sub1, want)
	}
	if orch := got[0]; orch.Counts.Total != 2 || orch.ParentSessionID != "" || !orch.FirstSeen.Equal(sessT0) {
		t.Errorf("orch summary = %+v", orch)
	}
}

func TestFileLogger_SessionsFilters(t *testing.T) {
	l := newSessionLogger(t)
	since := sessT0.Add(1500 * time.Millisecond)
	until := sessT0.Add(3 * time.Second)
	cases := []struct {
		name string
		f    SessionFilter
		want []string
	}{
		{"children of a parent", SessionFilter{TenantID: "local", ParentSessionID: "orch"}, []string{"sub-2", "sub-1"}},
		{"sessions an agent took part in", SessionFilter{TenantID: "local", AgentID: "helper"}, []string{"sub-1"}},
		{"one session", SessionFilter{TenantID: "local", SessionID: "sub-2"}, []string{"sub-2"}},
		{"limit keeps the newest", SessionFilter{TenantID: "local", Limit: 1}, []string{"orch"}},
		{"since is inclusive and until exclusive", SessionFilter{TenantID: "local", Since: &since, Until: &until}, []string{"sub-2", "sub-1"}},
		{"another tenant sees only its own", SessionFilter{TenantID: "acme"}, []string{"orch"}},
		{"no tenant is every tenant", SessionFilter{}, []string{"orch", "sub-2", "sub-1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := l.Sessions(tc.f)
			if err != nil {
				t.Fatalf("Sessions: %v", err)
			}
			if ids := sessionIDs(got); !reflect.DeepEqual(ids, tc.want) {
				t.Errorf("sessions = %v, want %v", ids, tc.want)
			}
		})
	}

	// A window counts only the entries inside it.
	got, _ := l.Sessions(SessionFilter{TenantID: "local", SessionID: "sub-1", Since: &since})
	if len(got) != 1 || got[0].Counts.Total != 1 || got[0].Agents[0].AgentID != "helper" {
		t.Errorf("windowed sub-1 = %+v", got)
	}
}

// A logger that can only Query (no Sessions of its own) gets the same
// answer through QuerySessions.
func TestQuerySessions_FallsBackToQuery(t *testing.T) {
	l := newSessionLogger(t)
	for _, f := range []SessionFilter{
		{TenantID: "local"},
		{TenantID: "local", ParentSessionID: "orch"},
		{TenantID: "local", AgentID: "helper"},
		{TenantID: "acme"},
	} {
		native, err := QuerySessions(l, f)
		if err != nil {
			t.Fatal(err)
		}
		viaQuery, err := QuerySessions(struct{ Logger }{l}, f)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(native, viaQuery) {
			t.Errorf("filter %+v:\nnative %+v\nquery  %+v", f, native, viaQuery)
		}
	}
}

func TestFileLogger_QueryUntilAndParent(t *testing.T) {
	l := newSessionLogger(t)
	at := func(d time.Duration) *time.Time { v := sessT0.Add(d); return &v }
	cases := []struct {
		name string
		f    QueryFilter
		want int
	}{
		{"until is exclusive", QueryFilter{Until: at(time.Second)}, 1},
		{"until inside a second", QueryFilter{Until: at(1500 * time.Millisecond)}, 2},
		{"since is inclusive", QueryFilter{Since: at(1500 * time.Millisecond)}, 5},
		{"since equal to until is empty", QueryFilter{Since: at(time.Second), Until: at(time.Second)}, 0},
		{"parent session", QueryFilter{ParentSessionID: "orch"}, 3},
		{"parent session and window", QueryFilter{ParentSessionID: "orch", Until: at(2 * time.Second)}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := l.Query(tc.f)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("got %d entries, want %d", len(got), tc.want)
			}
		})
	}
}
