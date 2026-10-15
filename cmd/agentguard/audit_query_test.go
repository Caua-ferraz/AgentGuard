package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestAuditCmd_BadTimeIsAUsageMistake(t *testing.T) {
	dir := t.TempDir()
	agentguard(t, dir, nil, "audit", "--since", "yesterday").expect(t, 2, "", "--since: \"yesterday\" is neither a duration")
	agentguard(t, dir, nil, "audit", "--until", "-1h").expect(t, 2, "", "--until: \"-1h\" is negative")
}
