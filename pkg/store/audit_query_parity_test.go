package store

// audit_query_parity_test.go pins the QueryFilter CONTRACT across the two
// live audit backends: the JSONL FileLogger (Go-side matchesFilter scan)
// and the store-backed logger (SQL WHERE on audit_entries). The two
// implementations are deliberately different — the file scan can't use
// indexes, the SQL path must — so the dedup is this parity test, not a
// shared predicate: any semantic drift (a filter field one backend
// ignores, different Since/Until/limit/offset behaviour) fails here. The
// session summaries (SessionFilter) are pinned the same way.

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

var parityBase = time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)

func parityEntries() []audit.Entry {
	base := parityBase
	return []audit.Entry{
		{
			Timestamp: base,
			AgentID:   "agent-a", SessionID: "s1", TenantID: "local",
			Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
			Result:  policy.CheckResult{Decision: policy.Allow, Rule: "allow:1"},
		},
		{
			Timestamp: base.Add(1 * time.Minute),
			AgentID:   "agent-a", SessionID: "s2", TenantID: "acme",
			Request:   policy.ActionRequest{Scope: "network", URL: "https://x.test", Domain: "x.test"},
			Result:    policy.CheckResult{Decision: policy.Deny, Rule: "deny:1"},
			Transport: "mcp_gateway",
		},
		{
			Timestamp: base.Add(2 * time.Minute),
			AgentID:   "agent-b", SessionID: "s1", TenantID: "acme",
			Request:   policy.ActionRequest{Scope: "shell", Command: "rm -rf /"},
			Result:    policy.CheckResult{Decision: policy.Deny, Rule: "deny:2"},
			Transport: "llm_api_proxy",
		},
		{
			Timestamp: base.Add(3 * time.Minute),
			AgentID:   "agent-b", SessionID: "s3", // TenantID empty → effective "local"
			Request: policy.ActionRequest{Scope: "filesystem", Path: "/tmp/x", Action: "write"},
			Result:  policy.CheckResult{Decision: policy.RequireApproval, Rule: "approve:1"},
		},
		// Sub-agent sessions under s1, with timestamps inside one second:
		// RFC3339Nano drops trailing zeros, so text order and time order of
		// "…:00Z" and "…:00.5Z" differ — the since/until edges below bite.
		{
			Timestamp: base.Add(4 * time.Minute),
			AgentID:   "claude", SessionID: "c1",
			Request: policy.ActionRequest{Scope: "shell", Command: "pwd", ParentSessionID: "s1",
				Meta: map[string]string{audit.SubagentMetaKey: "Explore"}},
			Result:    policy.CheckResult{Decision: policy.Allow, Rule: "allow:2"},
			Transport: "claude_code",
		},
		{
			Timestamp: base.Add(4*time.Minute + 500*time.Millisecond),
			AgentID:   "helper", SessionID: "c1",
			Request: policy.ActionRequest{Scope: "shell", Command: "id", ParentSessionID: "s1"},
			Result:  policy.CheckResult{Decision: policy.Deny, Rule: "deny:3"},
		},
		{
			Timestamp: base.Add(4*time.Minute + time.Second),
			AgentID:   "claude", SessionID: "c2",
			Request: policy.ActionRequest{Scope: "shell", Command: "date", ParentSessionID: "s1",
				Meta: map[string]string{audit.SubagentMetaKey: "Plan"}},
			Result:    policy.CheckResult{Decision: policy.RequireApproval, Rule: "approve:2"},
			Transport: "claude_code",
		},
		{
			Timestamp: base.Add(4*time.Minute + 1999*time.Millisecond),
			AgentID:   "claude", SessionID: "c2",
			Request:   policy.ActionRequest{Scope: "shell", Command: "uname", ParentSessionID: "s1"},
			Result:    policy.CheckResult{Decision: policy.Allow, Rule: "allow:3"},
			Transport: "claude_code",
		},
		// No session: never part of a session summary.
		{
			Timestamp: base.Add(5 * time.Minute),
			AgentID:   "loner",
			Request:   policy.ActionRequest{Scope: "shell", Command: "true"},
			Result:    policy.CheckResult{Decision: policy.Allow, Rule: "allow:4"},
		},
	}
}

// newParityLoggers returns a FileLogger and a SQLite-backed logger holding
// parityEntries.
func newParityLoggers(t *testing.T) (file, store audit.Logger) {
	t.Helper()
	dir := t.TempDir()
	fileLogger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("file logger: %v", err)
	}
	t.Cleanup(func() { _ = fileLogger.Close() })

	st, err := NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	storeLogger := NewAuditLogger(st)

	for _, l := range []audit.Logger{fileLogger, storeLogger} {
		for _, e := range parityEntries() {
			if err := l.Log(e); err != nil {
				t.Fatalf("log: %v", err)
			}
		}
	}
	return fileLogger, storeLogger
}

func TestAuditQuery_FileAndStoreBackendsAgree(t *testing.T) {
	fileLogger, storeLogger := newParityLoggers(t)
	checkQueryParity(t, fileLogger, storeLogger)
}

func TestAuditSessions_FileAndStoreBackendsAgree(t *testing.T) {
	fileLogger, storeLogger := newParityLoggers(t)
	checkSessionParity(t, fileLogger, storeLogger)
}

func parityTime(d time.Duration) *time.Time {
	t := parityBase.Add(d)
	return &t
}

func checkQueryParity(t *testing.T, fileLogger, storeLogger audit.Logger) {
	t.Helper()
	since := parityTime(2 * time.Minute) // >= third entry
	sub := 4 * time.Minute

	filters := map[string]audit.QueryFilter{
		"all":                 {},
		"tenant local":        {TenantID: "local"},
		"tenant acme":         {TenantID: "acme"},
		"agent":               {AgentID: "agent-b"},
		"session":             {SessionID: "s1"},
		"decision deny":       {Decision: "DENY"},
		"scope shell":         {Scope: "shell"},
		"transport gateway":   {Transport: "mcp_gateway"},
		"transport sdk":       {Transport: "sdk"}, // empty Transport defaults to sdk on both sides
		"since":               {Since: since},
		"limit":               {Limit: 2},
		"limit+offset":        {Limit: 2, Offset: 1},
		"offset only":         {Offset: 1},
		"tenant+decision":     {TenantID: "acme", Decision: "DENY"},
		"agent+scope+session": {AgentID: "agent-a", Scope: "shell", SessionID: "s1"},
		"desc":                {Desc: true},
		"desc+limit":          {Desc: true, Limit: 2},
		"desc+limit+offset":   {Desc: true, Limit: 2, Offset: 1},
		"desc offset only":    {Desc: true, Offset: 1},
		"desc+decision+limit": {Desc: true, Decision: "DENY", Limit: 1},
		"parent session":      {ParentSessionID: "s1"},
		"parent+agent":        {ParentSessionID: "s1", AgentID: "claude"},
		// since is inclusive, until exclusive, also inside one second.
		"until":                     {Until: since},
		"since+until":               {Since: parityTime(time.Minute), Until: since},
		"since on a whole second":   {Since: parityTime(sub)},
		"since inside a second":     {Since: parityTime(sub + 500*time.Millisecond)},
		"since just after an entry": {Since: parityTime(sub + 500*time.Millisecond + time.Nanosecond)},
		"until inside a second":     {Until: parityTime(sub + 500*time.Millisecond)},
		"until on a whole second":   {Until: parityTime(sub + time.Second)},
		"until just after an entry": {Until: parityTime(sub + time.Second + time.Nanosecond)},
		"until in the last ms":      {Until: parityTime(sub + 1999*time.Millisecond)},
		"since equals until":        {Since: parityTime(sub), Until: parityTime(sub)},
		"window+desc+limit":         {Since: parityTime(sub), Until: parityTime(5 * time.Minute), Desc: true, Limit: 2},
	}

	for name, f := range filters {
		t.Run(name, func(t *testing.T) {
			fromFile, err := fileLogger.Query(f)
			if err != nil {
				t.Fatalf("file query: %v", err)
			}
			fromStore, err := storeLogger.Query(f)
			if err != nil {
				t.Fatalf("store query: %v", err)
			}

			if len(fromFile) != len(fromStore) {
				t.Fatalf("result count differs: file=%d store=%d (filter %+v)",
					len(fromFile), len(fromStore), f)
			}
			for i := range fromFile {
				fe, se := fromFile[i], fromStore[i]
				// Compare through the Effective* accessors: the store
				// materialises defaults ("local"/"sdk") at insert time,
				// the file keeps the raw entry — same contract either way.
				if fe.EffectiveTenant() != se.EffectiveTenant() ||
					fe.AgentID != se.AgentID ||
					fe.SessionID != se.SessionID ||
					fe.EffectiveTransport() != se.EffectiveTransport() ||
					fe.Request.Scope != se.Request.Scope ||
					fe.Request.Command != se.Request.Command ||
					fe.Request.ParentSessionID != se.Request.ParentSessionID ||
					fe.Request.Meta[audit.SubagentMetaKey] != se.Request.Meta[audit.SubagentMetaKey] ||
					fe.Result.Decision != se.Result.Decision ||
					fe.Result.Rule != se.Result.Rule ||
					!fe.Timestamp.Equal(se.Timestamp) {
					t.Errorf("entry %d differs:\nfile : %+v\nstore: %+v", i, fe, se)
				}
			}
		})
	}

	// The edges are pinned to known counts too, so both backends agreeing
	// on a wrong answer still fails.
	sinceInside, _ := storeLogger.Query(audit.QueryFilter{Since: parityTime(sub + 500*time.Millisecond)})
	if len(sinceInside) != 4 { // the 4:00.5, 4:01, 4:01.999 and 5:00 entries
		t.Errorf("since inside a second: got %d entries, want 4", len(sinceInside))
	}
	untilInside, _ := storeLogger.Query(audit.QueryFilter{Since: parityTime(sub), Until: parityTime(sub + time.Second)})
	if len(untilInside) != 2 { // 4:00 and 4:00.5; 4:01 is the exclusive bound
		t.Errorf("until on a whole second: got %d entries, want 2", len(untilInside))
	}
}

func checkSessionParity(t *testing.T, fileLogger, storeLogger audit.Logger) {
	t.Helper()
	sub := 4 * time.Minute
	filters := map[string]audit.SessionFilter{
		"local":                  {TenantID: "local"},
		"acme":                   {TenantID: "acme"},
		"every tenant":           {},
		"limit":                  {TenantID: "local", Limit: 2},
		"one session":            {TenantID: "local", SessionID: "c1"},
		"children":               {TenantID: "local", ParentSessionID: "s1"},
		"agent":                  {TenantID: "local", AgentID: "helper"},
		"agent in another":       {TenantID: "acme", AgentID: "agent-b"},
		"since inside a second":  {TenantID: "local", Since: parityTime(sub + 500*time.Millisecond)},
		"until inside a second":  {TenantID: "local", Until: parityTime(sub + 1500*time.Millisecond)},
		"window":                 {TenantID: "local", Since: parityTime(time.Minute), Until: parityTime(sub + time.Second)},
		"children in a window":   {TenantID: "local", ParentSessionID: "s1", Until: parityTime(sub + time.Second)},
		"no session in a window": {TenantID: "local", Since: parityTime(5 * time.Minute)},
	}
	for name, f := range filters {
		t.Run(name, func(t *testing.T) {
			fromFile, err := audit.QuerySessions(fileLogger, f)
			if err != nil {
				t.Fatalf("file sessions: %v", err)
			}
			fromStore, err := audit.QuerySessions(storeLogger, f)
			if err != nil {
				t.Fatalf("store sessions: %v", err)
			}
			// JSON is what the API returns, and it compares times by
			// instant rather than by location pointer.
			fj, _ := json.Marshal(fromFile)
			sj, _ := json.Marshal(fromStore)
			if string(fj) != string(sj) {
				t.Errorf("sessions differ (filter %+v):\nfile : %s\nstore: %s", f, fj, sj)
			}
		})
	}

	// And a known answer: c2 is the newest local session, c1 lists both
	// of its agents, and both name s1 as their parent.
	page, err := audit.QuerySessions(storeLogger, audit.SessionFilter{TenantID: "local", ParentSessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	got := page.Sessions
	if len(got) != 2 || got[0].SessionID != "c2" || got[1].SessionID != "c1" {
		t.Fatalf("children of s1 = %+v", got)
	}
	c1 := got[1]
	if c1.ParentSessionID != "s1" || len(c1.Agents) != 2 || c1.Agents[0] != (audit.SessionAgent{AgentID: "claude", Subagent: "Explore"}) ||
		c1.Counts.Total != 2 || c1.Counts.Deny != 1 || !c1.LastSeen.Equal(parityBase.Add(sub+500*time.Millisecond)) {
		t.Errorf("c1 summary = %+v", c1)
	}
}
