package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The dashboard ships a Sessions view: a tab, the list and replay panes,
// the calls to the session routes, and the replay controls.
func TestDashboard_HasTheSessionsView(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.APIKey = "" })
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /dashboard: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-view="sessions"`,
		`id="sessions-view"`,
		`id="session-list"`,
		`id="replay"`,
		`agFetch('/v1/sessions?limit=200&since='`,
		`agFetch('/v1/sessions/' + encodeURIComponent(id))`,
		`const cell = renderEntry(e);`,
		`controlButton('Play'`,
		`controlButton('Step'`,
		`controlButton('Back'`,
		`'Replay speed'`,
		`'lane-label'`,
		`'approval-note'`,
		`#session=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}

	// Audit values are attacker-influenced: the sessions code builds the
	// DOM with textContent only, and the page loads nothing from elsewhere.
	start := strings.Index(body, "// ---- Sessions view ----")
	if start < 0 {
		t.Fatal("sessions script not found")
	}
	script := body[start:]
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if strings.Contains(script, bad) {
			t.Errorf("sessions script uses %s", bad)
		}
	}
	for _, bad := range []string{"<script src", "<link ", "http://", "https://"} {
		if strings.Contains(body, bad) {
			t.Errorf("dashboard references an external asset: %q", bad)
		}
	}
}
