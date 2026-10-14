package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

func TestHandleAuditHead(t *testing.T) {
	sealedLogger := func(t *testing.T) audit.Logger {
		t.Helper()
		l, err := audit.NewFileLoggerWithOptions(filepath.Join(t.TempDir(), "audit.jsonl"),
			audit.FileLoggerOptions{Seal: &audit.SealConfig{}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}

	cases := []struct {
		name     string
		sealed   bool
		path     string
		auth     bool
		wantCode int
	}{
		{"sealed log returns the head", true, "/v1/audit/head", true, http.StatusOK},
		{"tenant mirror returns the same head", true, "/v1/t/local/audit/head", true, http.StatusOK},
		{"needs the API key like GET /v1/audit", true, "/v1/audit/head", false, http.StatusUnauthorized},
		{"sealing off is 404", false, "/v1/audit/head", true, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, func(c *Config) {
				if tc.sealed {
					c.Logger = sealedLogger(t)
				}
			})
			for _, body := range []string{
				`{"scope":"shell","command":"ls -la","agent_id":"bot-1"}`,
				`{"scope":"shell","command":"echo hi","agent_id":"bot-1"}`,
			} {
				srv.handleCheck(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/check", strings.NewReader(body)))
			}

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.auth {
				req.Header.Set("Authorization", "Bearer test-secret")
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.wantCode, w.Body)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			var head audit.Anchor
			if err := json.NewDecoder(w.Body).Decode(&head); err != nil {
				t.Fatal(err)
			}
			if head.Seq != 2 || len(head.Hash) != 64 || head.SegmentID == "" || head.At.IsZero() {
				t.Fatalf("head = %+v, want seq 2 with a hash, segment and time", head)
			}
		})
	}
}
