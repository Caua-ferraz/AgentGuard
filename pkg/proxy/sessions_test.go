package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

// sessionBackends runs a test against the file audit backend and the
// SQLite store backend, so the routes behave the same on both.
func sessionBackends(t *testing.T, fn func(t *testing.T, logger audit.Logger)) {
	t.Run("file", func(t *testing.T) {
		l, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		fn(t, l)
	})
	t.Run("store", func(t *testing.T) {
		st, err := store.NewSQLiteStore(filepath.Join(t.TempDir(), "agentguard.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		fn(t, store.NewAuditLogger(st))
	})
}

// getJSON sends an authenticated GET through the full handler chain and
// decodes a 200 body into out.
func getJSON(t *testing.T, srv *Server, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusOK && out != nil {
		if err := json.NewDecoder(w.Body).Decode(out); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
	}
	return w.Code
}

func postSessionCheck(t *testing.T, srv *Server, path, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s: status %d: %s", path, w.Code, w.Body)
	}
}

func TestSessions_ListAndDetail(t *testing.T) {
	sessionBackends(t, func(t *testing.T, logger audit.Logger) {
		srv := newTestServer(t, func(c *Config) { c.Logger = logger })
		for _, body := range []string{
			`{"scope":"shell","command":"ls -la","agent_id":"orchestrator","session_id":"orch"}`,
			`{"scope":"shell","command":"rm -rf /","agent_id":"worker","session_id":"orch/sub 1","parent_session_id":"orch","meta":{"subagent":"Explore"}}`,
			`{"scope":"shell","command":"sudo reboot","agent_id":"worker","session_id":"orch/sub 1","parent_session_id":"orch"}`,
			`{"scope":"shell","command":"echo hi","agent_id":"tester","session_id":"sub-2","parent_session_id":"orch"}`,
			`{"scope":"shell","command":"echo no session","agent_id":"loner"}`,
		} {
			postSessionCheck(t, srv, "/v1/check", body)
		}

		var list sessionList
		if code := getJSON(t, srv, "/v1/sessions", &list); code != http.StatusOK {
			t.Fatalf("GET /v1/sessions: %d", code)
		}
		if len(list.Sessions) != 3 {
			t.Fatalf("sessions = %+v, want 3 (the entry without a session is not one)", list.Sessions)
		}
		if time.Since(list.Since) < DefaultSessionWindow-time.Minute || time.Since(list.Since) > DefaultSessionWindow+time.Minute {
			t.Errorf("default since = %v, want about 24h ago", list.Since)
		}

		var byAgent sessionList
		getJSON(t, srv, "/v1/sessions?agent_id=tester", &byAgent)
		if len(byAgent.Sessions) != 1 || byAgent.Sessions[0].SessionID != "sub-2" {
			t.Errorf("agent_id=tester: %+v", byAgent.Sessions)
		}
		var limited sessionList
		getJSON(t, srv, "/v1/sessions?limit=1", &limited)
		if len(limited.Sessions) != 1 {
			t.Errorf("limit=1 returned %d sessions", len(limited.Sessions))
		}

		var d sessionDetail
		if code := getJSON(t, srv, "/v1/sessions/orch", &d); code != http.StatusOK {
			t.Fatalf("GET /v1/sessions/orch: %d", code)
		}
		if d.Session.SessionID != "orch" || d.Session.Counts.Total != 1 || len(d.Entries) != 1 || d.Truncated {
			t.Errorf("orch detail = %+v", d)
		}
		if list.Truncated || d.ChildrenTruncated {
			t.Errorf("small log reported truncated: list %v children %v", list.Truncated, d.ChildrenTruncated)
		}
		if len(d.Children) != 2 {
			t.Fatalf("orch children = %+v, want 2", d.Children)
		}

		// The child's id has a '/' and a space: it is sent escaped.
		var child sessionDetail
		path := "/v1/sessions/" + url.PathEscape("orch/sub 1")
		if code := getJSON(t, srv, path, &child); code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, code)
		}
		if child.Session.ParentSessionID != "orch" || len(child.Entries) != 2 ||
			child.Entries[0].Result.Decision != policy.Deny || child.Entries[1].Result.Decision != policy.RequireApproval {
			t.Errorf("child detail = %+v", child)
		}
		// Only the first call named the sub-agent, so the agent shows twice:
		// as itself and as the sub-agent.
		wantAgents := []audit.SessionAgent{{AgentID: "worker"}, {AgentID: "worker", Subagent: "Explore"}}
		if len(child.Session.Agents) != 2 || child.Session.Agents[0] != wantAgents[0] || child.Session.Agents[1] != wantAgents[1] {
			t.Errorf("child agents = %+v, want %+v", child.Session.Agents, wantAgents)
		}

		var cut sessionDetail
		getJSON(t, srv, path+"?limit=1", &cut)
		if len(cut.Entries) != 1 || !cut.Truncated || cut.Session.Counts.Total != 2 {
			t.Errorf("limit=1 detail: entries %d truncated %v total %d", len(cut.Entries), cut.Truncated, cut.Session.Counts.Total)
		}

		if code := getJSON(t, srv, "/v1/sessions/nope", nil); code != http.StatusNotFound {
			t.Errorf("unknown session: %d, want 404", code)
		}
	})
}

func TestSessions_RejectBadInput(t *testing.T) {
	srv := newTestServer(t)
	for _, path := range []string{
		"/v1/sessions?since=yesterday",
		"/v1/sessions?until=2026-13-01T00:00:00Z",
		"/v1/sessions?since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
		"/v1/sessions?limit=0",
		"/v1/sessions/x?limit=abc",
		"/v1/sessions/",
		"/v1/audit?since=1h",
		"/v1/audit?since=2026-10-01%2010:00:00Z", // a space that can't be a lost '+'
		"/v1/audit?since=2026-10-02T00:00:00Z&until=2026-10-01T00:00:00Z",
	} {
		if code := getJSON(t, srv, path, nil); code != http.StatusBadRequest {
			t.Errorf("GET %s: %d, want 400", path, code)
		}
	}
}

func TestSessions_NeedTheAPIKey(t *testing.T) {
	srv := newTestServer(t)
	for _, path := range []string{"/v1/sessions", "/v1/sessions/x", "/v1/t/local/sessions", "/v1/t/local/sessions/x"} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a key: %d, want 401", path, w.Code)
		}
	}
}

func TestAuditQuery_SinceUntilAndParent(t *testing.T) {
	sessionBackends(t, func(t *testing.T, logger audit.Logger) {
		srv := newTestServer(t, func(c *Config) { c.Logger = logger })
		t0 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
		for i, d := range []time.Duration{0, 500 * time.Millisecond, time.Second, time.Hour} {
			e := audit.Entry{Timestamp: t0.Add(d), SessionID: "s", AgentID: "bot",
				Request: policy.ActionRequest{Scope: "shell", Command: "ls"},
				Result:  policy.CheckResult{Decision: policy.Allow}}
			if i%2 == 1 {
				e.Request.ParentSessionID = "p"
			}
			if err := logger.Log(e); err != nil {
				t.Fatal(err)
			}
		}
		cases := []struct {
			query string
			want  int
		}{
			{"since=2026-10-01T08:00:00.5Z", 3},
			{"until=2026-10-01T08:00:00.5Z", 1},
			{"since=2026-10-01T08:00:00Z&until=2026-10-01T08:00:01Z", 2},
			{"since=2026-10-01T10:00:00%2B02:00", 4}, // an offset is the same instant in UTC
			{"since=2026-10-01T10:00:00+02:00", 4},   // an unencoded '+' arrives as a space
			{"since=2026-10-01T10:00:00.5+02:00", 3},
			{"since=2026-10-01T06:00:00-02:00", 4},
			{"until=2026-10-01T08:00:00Z", 0},
			{"parent_session_id=p", 2},
			{"parent_session_id=p&since=2026-10-01T08:00:01Z", 1},
		}
		for _, tc := range cases {
			var got []audit.Entry
			if code := getJSON(t, srv, "/v1/audit?"+tc.query, &got); code != http.StatusOK {
				t.Fatalf("GET /v1/audit?%s: %d", tc.query, code)
			}
			if len(got) != tc.want {
				t.Errorf("/v1/audit?%s: %d entries, want %d", tc.query, len(got), tc.want)
			}
		}
	})
}

// tenantSource serves fixed policies for the acme and globex tenants.
type tenantSource struct{}

func (tenantSource) GetPolicyYAML(_ context.Context, tenant string) ([]byte, bool, error) {
	switch tenant {
	case "acme", "globex":
		return []byte("version: \"1\"\nname: \"" + tenant + "\"\nrules:\n  - scope: shell\n    allow:\n      - pattern: \"*\"\n"), true, nil
	}
	return nil, false, nil
}

func (tenantSource) ListPolicyTenants(context.Context) ([]string, error) {
	return []string{"acme", "globex"}, nil
}

// One tenant never sees another's sessions: not in the list, not by id,
// not as a child, even when the session ids are the same.
func TestSessions_TenantIsolation(t *testing.T) {
	sessionBackends(t, func(t *testing.T, logger audit.Logger) {
		prov, err := policy.NewMultiTenantProvider(policy.NewStaticPolicyProvider(&policy.Policy{Version: "1", Name: "local"}), tenantSource{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = prov.Close() })
		eng, err := policy.NewEngine(prov)
		if err != nil {
			t.Fatal(err)
		}
		srv := newTestServer(t, func(c *Config) { c.Logger = logger; c.Engine = eng })

		postSessionCheck(t, srv, "/v1/t/acme/check", `{"scope":"shell","command":"ls","agent_id":"acme-bot","session_id":"shared"}`)
		postSessionCheck(t, srv, "/v1/t/globex/check", `{"scope":"shell","command":"ls","agent_id":"globex-bot","session_id":"shared"}`)
		postSessionCheck(t, srv, "/v1/t/globex/check", `{"scope":"shell","command":"ls","agent_id":"globex-bot","session_id":"globex-child","parent_session_id":"shared"}`)

		var acme sessionList
		getJSON(t, srv, "/v1/t/acme/sessions", &acme)
		if len(acme.Sessions) != 1 || acme.Sessions[0].SessionID != "shared" ||
			acme.Sessions[0].Agents[0].AgentID != "acme-bot" || acme.Sessions[0].Counts.Total != 1 {
			t.Errorf("acme list = %+v", acme.Sessions)
		}
		var d sessionDetail
		getJSON(t, srv, "/v1/t/acme/sessions/shared", &d)
		if len(d.Children) != 0 || len(d.Entries) != 1 || d.Entries[0].AgentID != "acme-bot" {
			t.Errorf("acme detail leaks globex: %+v", d)
		}
		if code := getJSON(t, srv, "/v1/t/acme/sessions/globex-child", nil); code != http.StatusNotFound {
			t.Errorf("acme reading globex's session: %d, want 404", code)
		}
		var acmeChildren sessionList
		getJSON(t, srv, "/v1/t/acme/sessions?parent_session_id=shared", &acmeChildren)
		if len(acmeChildren.Sessions) != 0 {
			t.Errorf("acme sees globex's child: %+v", acmeChildren.Sessions)
		}

		var globex sessionDetail
		getJSON(t, srv, "/v1/t/globex/sessions/shared", &globex)
		if len(globex.Children) != 1 || globex.Children[0].SessionID != "globex-child" {
			t.Errorf("globex children = %+v", globex.Children)
		}

		// The legacy routes are the local tenant, which has no sessions.
		var local sessionList
		getJSON(t, srv, "/v1/sessions", &local)
		if len(local.Sessions) != 0 {
			t.Errorf("local list = %+v", local.Sessions)
		}
		if code := getJSON(t, srv, "/v1/t/nobody/sessions", nil); code != http.StatusNotFound {
			t.Errorf("unknown tenant: %d, want 404", code)
		}
	})
}
