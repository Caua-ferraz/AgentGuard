package store

// audit_query_parity_test.go pins the QueryFilter CONTRACT across the two
// live audit backends: the JSONL FileLogger (Go-side matchesFilter scan)
// and the store-backed logger (SQL WHERE on audit_entries). The two
// implementations are deliberately different — the file scan can't use
// indexes, the SQL path must — so the dedup is this parity test, not a
// shared predicate: any semantic drift (a filter field one backend
// ignores, different Since/limit/offset behaviour) fails here.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

func parityEntries() []audit.Entry {
	base := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
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
	}
}

func TestAuditQuery_FileAndStoreBackendsAgree(t *testing.T) {
	dir := t.TempDir()

	fileLogger, err := audit.NewFileLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("file logger: %v", err)
	}
	defer fileLogger.Close()

	st, err := NewSQLiteStore(filepath.Join(dir, "agentguard.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	storeLogger := NewAuditLogger(st)

	for _, e := range parityEntries() {
		if err := fileLogger.Log(e); err != nil {
			t.Fatalf("file log: %v", err)
		}
		if err := storeLogger.Log(e); err != nil {
			t.Fatalf("store log: %v", err)
		}
	}

	since := time.Date(2026, 6, 10, 10, 2, 0, 0, time.UTC) // >= third entry

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
		"since":               {Since: &since},
		"limit":               {Limit: 2},
		"limit+offset":        {Limit: 2, Offset: 1},
		"offset only":         {Offset: 1},
		"tenant+decision":     {TenantID: "acme", Decision: "DENY"},
		"agent+scope+session": {AgentID: "agent-a", Scope: "shell", SessionID: "s1"},
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
					fe.Result.Decision != se.Result.Decision ||
					fe.Result.Rule != se.Result.Rule ||
					!fe.Timestamp.Equal(se.Timestamp) {
					t.Errorf("entry %d differs:\nfile : %+v\nstore: %+v", i, fe, se)
				}
			}
		})
	}
}
