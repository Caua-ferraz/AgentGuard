package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// statusServer serves /health and answers /api/pending with the given status
// and body (status 0 = don't register /api/pending, like a server started
// without --dashboard).
func statusServer(t *testing.T, pendingStatus int, pendingBody string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	if pendingStatus != 0 {
		mux.HandleFunc("/api/pending", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(pendingStatus)
			_, _ = w.Write([]byte(pendingBody))
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestStatusReport(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantStdout string
		wantStderr string
	}{
		{"server without --dashboard", 0, "", "Pending approvals: unavailable (the server was started without --dashboard)", ""},
		{"unauthorized", http.StatusUnauthorized, "Unauthorized", "Pending approvals: unauthorized", ""},
		{"other error status", http.StatusInternalServerError, "boom", "Pending approvals: unavailable (HTTP 500)", ""},
		{"empty queue", http.StatusOK, `[]`, "Pending approvals: none", ""},
		{"one pending", http.StatusOK, `[{"id":"ap_1","request":{"scope":"shell","command":"sudo ls","agent_id":"bot"}}]`,
			`[ap_1] scope=shell action="sudo ls" agent=bot`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url := statusServer(t, c.status, c.body)
			var out, errOut bytes.Buffer
			if code := statusReport(&out, &errOut, url, ""); code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errOut.String())
			}
			if !strings.Contains(out.String(), "AgentGuard server: OK") {
				t.Errorf("stdout missing health line: %q", out.String())
			}
			if !strings.Contains(out.String(), c.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), c.wantStdout)
			}
			if errOut.Len() != 0 {
				t.Errorf("unexpected stderr: %q", errOut.String())
			}
		})
	}
}

func TestStatusReport_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens there any more
	var out, errOut bytes.Buffer
	if code := statusReport(&out, &errOut, url, ""); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "Cannot connect to AgentGuard") {
		t.Errorf("stderr = %q", errOut.String())
	}
}
