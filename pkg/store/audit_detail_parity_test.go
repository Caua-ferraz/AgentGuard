package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// checkDetailParity pins GET /v1/sessions/{id}'s data: the file backend's
// two-pass SessionDetail and the store's three queries agree.
func checkDetailParity(t *testing.T, fileLogger, storeLogger audit.Logger) {
	t.Helper()
	for name, f := range map[string]audit.SessionDetailFilter{
		"parent":          {TenantID: "local", SessionID: "s1", EntryLimit: 10, ChildLimit: 10},
		"parent, limited": {TenantID: "local", SessionID: "s1", EntryLimit: 1, ChildLimit: 1},
		"child":           {TenantID: "local", SessionID: "c2", EntryLimit: 10, ChildLimit: 10},
		"other tenant":    {TenantID: "acme", SessionID: "s1", EntryLimit: 10, ChildLimit: 10},
		"windowed":        {TenantID: "local", SessionID: "s1", Since: parityTime(4*time.Minute + time.Second), EntryLimit: 10, ChildLimit: 10},
		"missing":         {TenantID: "local", SessionID: "nope", EntryLimit: 10, ChildLimit: 10},
	} {
		t.Run(name, func(t *testing.T) {
			fd, err := audit.QuerySessionDetail(fileLogger, f)
			if err != nil {
				t.Fatal(err)
			}
			sd, err := audit.QuerySessionDetail(storeLogger, f)
			if err != nil {
				t.Fatal(err)
			}
			if a, b := flatDetail(fd), flatDetail(sd); a != b {
				t.Errorf("detail differs:\nfile : %s\nstore: %s", a, b)
			}
		})
	}
}

// flatDetail renders a detail for comparison. The store keeps only some
// request fields, so entries are compared by time and command, in order;
// the summaries in full.
func flatDetail(d audit.SessionDetail) string {
	type shape struct {
		Found, Truncated, ChildrenTruncated bool
		Session                             audit.SessionSummary
		Children                            []audit.SessionSummary
		Entries                             []string
	}
	sh := shape{Found: d.Found, Truncated: d.Truncated, ChildrenTruncated: d.ChildrenTruncated, Session: d.Session, Children: d.Children}
	for _, e := range d.Entries {
		sh.Entries = append(sh.Entries, e.Timestamp.UTC().Format(time.RFC3339Nano)+" "+e.Request.Command)
	}
	b, _ := json.Marshal(sh)
	return string(b)
}

func TestAuditSessionDetail_FileAndStoreBackendsAgree(t *testing.T) {
	fileLogger, storeLogger := newParityLoggers(t)
	checkDetailParity(t, fileLogger, storeLogger)
}

// A session with more agents and transports than a summary lists keeps the
// first ones seen, on both backends.
func TestAuditSessions_ListCapsAgree(t *testing.T) {
	dir := t.TempDir()
	fileLogger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fileLogger.Close() })
	st, err := NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	storeLogger := NewAuditLogger(st)
	n := audit.MaxSessionAgents + 5
	for i := 0; i < n; i++ {
		// Names whose sorted order differs from the order they are seen.
		name := string(rune('z'-i%26)) + string(rune('A'+i))
		e := audit.Entry{Timestamp: parityBase.Add(time.Duration(i) * time.Second), SessionID: "crowd",
			AgentID: name, Transport: "t-" + name,
			Request: policy.ActionRequest{Scope: "shell"}, Result: policy.CheckResult{Decision: policy.Allow}}
		for _, l := range []audit.Logger{fileLogger, storeLogger} {
			if err := l.Log(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	fp, _ := audit.QuerySessions(fileLogger, audit.SessionFilter{})
	sp, _ := audit.QuerySessions(storeLogger, audit.SessionFilter{})
	fj, _ := json.Marshal(fp)
	sj, _ := json.Marshal(sp)
	if string(fj) != string(sj) {
		t.Errorf("capped lists differ:\nfile : %s\nstore: %s", fj, sj)
	}
	if len(sp.Sessions) != 1 {
		t.Fatalf("sessions = %+v", sp.Sessions)
	}
	if s := sp.Sessions[0]; !s.ListsTruncated || len(s.Agents) != audit.MaxSessionAgents ||
		len(s.Transports) != audit.MaxSessionTransports || s.Counts.Total != uint64(n) {
		t.Errorf("crowd = %+v", s)
	}
}
