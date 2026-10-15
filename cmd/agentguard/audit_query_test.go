package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

func TestParseAuditTime(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, raw, want, wantErr string
	}{
		{"empty means no bound", "", "", ""},
		{"a duration counts back from now", "2h", "2026-10-14T10:00:00Z", ""},
		{"minutes", "90m", "2026-10-14T10:30:00Z", ""},
		{"an RFC 3339 time is kept", "2026-10-01T08:30:00Z", "2026-10-01T08:30:00Z", ""},
		{"an offset is turned into UTC", "2026-10-01T10:30:00+02:00", "2026-10-01T08:30:00Z", ""},
		{"fractions are kept", "2026-10-01T08:30:00.25Z", "2026-10-01T08:30:00.25Z", ""},
		{"a negative duration is refused", "-2h", "", "negative"},
		{"anything else is refused", "yesterday", "", "neither a duration"},
		{"a date alone is refused", "2026-10-01", "", "RFC 3339"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAuditTime(tc.raw, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestRunAuditQuery_SendsSessionAndTimeFilters(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("since") == "probe" { // a 1.4 server reads since
			http.Error(w, "invalid since", http.StatusBadRequest)
			return
		}
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	q := auditQuery{Limit: 10, Order: "asc", Session: "sess 1", ParentSession: "orch",
		Since: "2026-10-14T10:00:00Z", Until: "2026-10-14T11:00:00Z"}
	var out, errOut bytes.Buffer
	if code := runAuditQuery(&out, &errOut, srv.URL, q, ""); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for k, v := range map[string]string{
		"session_id": "sess 1", "parent_session_id": "orch",
		"since": "2026-10-14T10:00:00Z", "until": "2026-10-14T11:00:00Z", "order": "asc",
	} {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}

	// Unset filters stay off the URL.
	if code := runAuditQuery(&out, &errOut, srv.URL, auditQuery{Limit: 5}, ""); code != 0 {
		t.Fatal(code)
	}
	for _, k := range []string{"session_id", "parent_session_id", "since", "until"} {
		if got.Has(k) {
			t.Errorf("%s sent without its flag", k)
		}
	}
}

// A server before 1.4 ignores since/until/parent_session_id and returns
// everything, so the CLI refuses rather than print that as an answer. It
// asks the server (an invalid since: 400 from 1.4, 200 before), so a dev
// build or an unbumped version string doesn't matter.
func TestRunAuditQuery_RefusesNewFiltersOnAnOlderServer(t *testing.T) {
	cases := []struct {
		name        string
		readsSince  bool // the server is 1.4 or later
		auditStatus int  // what /v1/audit answers otherwise
		q           auditQuery
		wantCode    int
		wantQueried bool
	}{
		{"older server with --since", false, 200, auditQuery{Limit: 5, Since: "2026-10-14T10:00:00Z"}, 1, false},
		{"older server with --until", false, 200, auditQuery{Limit: 5, Until: "2026-10-14T10:00:00Z"}, 1, false},
		{"older server with --parent-session", false, 200, auditQuery{Limit: 5, ParentSession: "orch"}, 1, false},
		{"older server with only --session", false, 200, auditQuery{Limit: 5, Session: "s"}, 0, true},
		{"1.4 server", true, 200, auditQuery{Limit: 5, Since: "2026-10-14T10:00:00Z"}, 0, true},
		{"wrong key: the query reports it", false, 401, auditQuery{Limit: 5, Since: "2026-10-14T10:00:00Z"}, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queried := false
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"status":"ok","version":"1.3.2"}`))
			})
			mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
				if tc.auditStatus != 200 {
					queried = true
					w.WriteHeader(tc.auditStatus)
					return
				}
				if r.URL.Query().Get("since") == "probe" {
					if tc.readsSince {
						http.Error(w, "invalid since", http.StatusBadRequest)
						return
					}
					_, _ = w.Write([]byte(`[]`))
					return
				}
				queried = true
				_, _ = w.Write([]byte(`[]`))
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)
			var out, errOut bytes.Buffer
			code := runAuditQuery(&out, &errOut, srv.URL, tc.q, "")
			if code != tc.wantCode || queried != tc.wantQueried {
				t.Fatalf("exit %d queried %v, want %d %v (stderr %q)", code, queried, tc.wantCode, tc.wantQueried, errOut.String())
			}
			if !tc.wantQueried && !strings.Contains(errOut.String(), "runs AgentGuard 1.3.2, which ignores --since, --until and --parent-session (added in 1.4)") {
				t.Errorf("stderr = %q", errOut.String())
			}
		})
	}
}

// Against this tree's own server the new flags work, whatever its version
// string says.
func TestRunAuditQuery_TimeFiltersAgainstTheRealServer(t *testing.T) {
	logger, err := audit.NewFileLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	t0 := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	for i, parent := range []string{"", "orch", "orch"} {
		if err := logger.Log(audit.Entry{Timestamp: t0.Add(time.Duration(i) * time.Hour), SessionID: "s", AgentID: "bot",
			Request: policy.ActionRequest{Scope: "shell", Command: "ls", ParentSessionID: parent},
			Result:  policy.CheckResult{Decision: policy.Allow}}); err != nil {
			t.Fatal(err)
		}
	}
	disp := notify.NewDispatcher(policy.NotificationCfg{})
	t.Cleanup(func() { disp.Close() })
	srv := proxy.NewServer(proxy.Config{
		Engine:   policy.NewEngineFromPolicy(&policy.Policy{Version: "1", Name: "t"}),
		Logger:   logger,
		Notifier: disp,
		BaseURL:  "http://127.0.0.1:0",
		Version:  "1.3.0", // the version string before the release bump
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	var out, errOut bytes.Buffer
	q := auditQuery{Limit: 50, Order: "asc", ParentSession: "orch", Since: "2026-10-14T11:00:00Z", Until: "2026-10-14T12:00:00Z"}
	if code := runAuditQuery(&out, &errOut, ts.URL, q, ""); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Showing 1 audit entries") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestAuditCmd_BadTimeIsAUsageMistake(t *testing.T) {
	dir := t.TempDir()
	agentguard(t, dir, nil, "audit", "--since", "yesterday").expect(t, 2, "", "--since: \"yesterday\" is neither a duration")
	agentguard(t, dir, nil, "audit", "--until", "-1h").expect(t, 2, "", "--until: \"-1h\" is negative")
}
