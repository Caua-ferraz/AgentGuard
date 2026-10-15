package audit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// manySessions is one entry per session for n sessions, plus a session
// "kept" whose first entry is the first line and whose second is the last:
// it is dropped from the scan's memory early and has to come back with
// both entries counted.
func manySessions(n int) []Entry {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	entry := func(i int, session, agent, parent string) Entry {
		return Entry{Timestamp: t0.Add(time.Duration(i) * time.Millisecond), SessionID: session, AgentID: agent,
			Request: policy.ActionRequest{Scope: "shell", Command: "ls", ParentSessionID: parent},
			Result:  policy.CheckResult{Decision: policy.Allow}}
	}
	out := []Entry{entry(0, "kept", "bot", "")}
	for i := 1; i <= n; i++ {
		parent := ""
		if i%10 == 0 {
			parent = "orch"
		}
		out = append(out, entry(i, fmt.Sprintf("s%06d", i), "bot", parent))
	}
	return append(out, entry(n+1, "kept", "bot", ""))
}

func TestSessions_ScanMemoryIsBounded(t *testing.T) {
	entries := manySessions(2000)
	cases := []struct {
		name      string
		f         SessionFilter
		wantFirst []string
		truncated bool
	}{
		{"a small page of many sessions", SessionFilter{Limit: 3, MaxTracked: 50},
			[]string{"kept", "s002000", "s001999"}, true},
		{"more matches than the cap", SessionFilter{ParentSessionID: "orch", Limit: 3, MaxTracked: 50},
			nil, true}, // which children survive the cap is not pinned
		{"under the cap nothing is cut", SessionFilter{Limit: 3, MaxTracked: 5000},
			[]string{"kept", "s002000", "s001999"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stats scanStats
			page, err := summarize(sliceSource(entries), tc.f, &stats)
			if err != nil {
				t.Fatal(err)
			}
			if page.Truncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", page.Truncated, tc.truncated)
			}
			if stats.maxTracked > tc.f.MaxTracked {
				t.Errorf("held %d sessions at once, cap %d", stats.maxTracked, tc.f.MaxTracked)
			}
			if len(page.Sessions) != tc.f.Limit {
				t.Fatalf("got %d sessions, want %d", len(page.Sessions), tc.f.Limit)
			}
			if tc.wantFirst != nil {
				if ids := sessionIDs(page.Sessions); fmt.Sprint(ids) != fmt.Sprint(tc.wantFirst) {
					t.Errorf("sessions = %v, want %v", ids, tc.wantFirst)
				}
				// Dropped and seen again, "kept" is still counted in full.
				if kept := page.Sessions[0]; kept.Counts.Total != 2 || !kept.FirstSeen.Equal(entries[0].Timestamp) {
					t.Errorf("kept = %+v, want both entries", kept)
				}
			}
			for _, s := range page.Sessions {
				if tc.f.ParentSessionID != "" && s.ParentSessionID != tc.f.ParentSessionID {
					t.Errorf("%s is not a child of %s", s.SessionID, tc.f.ParentSessionID)
				}
			}
		})
	}

	// The default cap follows the limit and never drops below the floor.
	if got := (SessionFilter{Limit: 100}).maxTracked(); got != DefaultMaxTrackedSessions {
		t.Errorf("default cap = %d", got)
	}
	if got := (SessionFilter{Limit: 10000}).maxTracked(); got != 100000 {
		t.Errorf("cap for limit 10000 = %d", got)
	}
}

// The file backend goes through the same bounded scan.
func TestFileLogger_SessionsTruncatesPastTheCap(t *testing.T) {
	l, err := NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for _, e := range manySessions(300) {
		if err := l.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	page, err := l.Sessions(SessionFilter{Limit: 2, MaxTracked: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Sessions) != 2 || page.Sessions[0].SessionID != "kept" || page.Sessions[0].Counts.Total != 2 {
		t.Errorf("page = %+v", page)
	}
}

func TestSessionSummary_ListsAreCapped(t *testing.T) {
	var entries []Entry
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < MaxSessionAgents+8; i++ {
		entries = append(entries, Entry{Timestamp: t0, SessionID: "busy", AgentID: fmt.Sprintf("a%02d", i),
			Request: policy.ActionRequest{Meta: map[string]string{"transport": "x"}}, Transport: fmt.Sprintf("t%02d", i)})
	}
	page, _ := summarize(sliceSource(entries), SessionFilter{}, nil)
	s := page.Sessions[0]
	if len(s.Agents) != MaxSessionAgents || len(s.Transports) != MaxSessionTransports || !s.ListsTruncated {
		t.Errorf("agents %d transports %d truncated %v", len(s.Agents), len(s.Transports), s.ListsTruncated)
	}
	if s.Counts.Total != uint64(len(entries)) {
		t.Errorf("counts cover %d entries, want %d", s.Counts.Total, len(entries))
	}
	// The first ones seen are kept.
	if s.Agents[0].AgentID != "a00" || s.Agents[MaxSessionAgents-1].AgentID != fmt.Sprintf("a%02d", MaxSessionAgents-1) {
		t.Errorf("agents = %v", s.Agents)
	}
}

// The file backend's two-pass SessionDetail gives what the three-query
// path gives.
func TestFileLogger_SessionDetailMatchesTheQueries(t *testing.T) {
	l := newSessionLogger(t)
	since := sessT0.Add(1500 * time.Millisecond)
	for _, f := range []SessionDetailFilter{
		{TenantID: "local", SessionID: "orch", EntryLimit: 10, ChildLimit: 10},
		{TenantID: "local", SessionID: "orch", EntryLimit: 1, ChildLimit: 1},
		{TenantID: "local", SessionID: "sub-1", EntryLimit: 10, ChildLimit: 10},
		{TenantID: "local", SessionID: "orch", Since: &since, EntryLimit: 10, ChildLimit: 10},
		{TenantID: "acme", SessionID: "orch", EntryLimit: 10, ChildLimit: 10},
		{TenantID: "acme", SessionID: "sub-1", EntryLimit: 10, ChildLimit: 10},
	} {
		native, err := l.SessionDetail(f)
		if err != nil {
			t.Fatal(err)
		}
		composed, err := QuerySessionDetail(struct{ Logger }{l}, f)
		if err != nil {
			t.Fatal(err)
		}
		nj, _ := json.Marshal(native)
		cj, _ := json.Marshal(composed)
		if string(nj) != string(cj) {
			t.Errorf("filter %+v:\nfile    %s\nqueries %s", f, nj, cj)
		}
	}
	d, _ := l.SessionDetail(SessionDetailFilter{TenantID: "local", SessionID: "orch", EntryLimit: 1, ChildLimit: 1})
	if !d.Found || !d.Truncated || !d.ChildrenTruncated || len(d.Entries) != 1 || len(d.Children) != 1 {
		t.Errorf("limited detail = %+v", d)
	}
}
