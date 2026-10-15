package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
)

const (
	// DefaultSessionWindow is how far back GET /v1/sessions looks when the
	// client gives no ?since=.
	DefaultSessionWindow = 24 * time.Hour
	// DefaultSessionListLimit and MaxSessionListLimit bound ?limit= on
	// GET /v1/sessions, and MaxSessionListLimit also caps the child
	// sessions GET /v1/sessions/{id} returns.
	DefaultSessionListLimit = 100
	MaxSessionListLimit     = 1000
	// DefaultSessionEntryLimit and MaxSessionEntryLimit bound ?limit= on
	// GET /v1/sessions/{id}: the entries of one session, oldest first.
	DefaultSessionEntryLimit = 1000
	MaxSessionEntryLimit     = 5000
)

// sessionList is the body of GET /v1/sessions. Since and Until echo the
// window that was searched, so a client that left since out can see the
// default it got. Truncated is audit.SessionPage's: the window held more
// sessions than the file backend tracks, so the list may miss some.
type sessionList struct {
	Since     time.Time              `json:"since"`
	Until     *time.Time             `json:"until,omitempty"`
	Sessions  []audit.SessionSummary `json:"sessions"`
	Truncated bool                   `json:"truncated"`
}

// sessionDetail is the body of GET /v1/sessions/{id}. Truncated is true when
// the session has more entries than ?limit= let through; page on with
// ?since= set to the last entry's timestamp plus a nanosecond.
// ChildrenTruncated is true when not every child session is listed.
type sessionDetail struct {
	Session           audit.SessionSummary   `json:"session"`
	Children          []audit.SessionSummary `json:"children"`
	ChildrenTruncated bool                   `json:"children_truncated"`
	Entries           []audit.Entry          `json:"entries"`
	Truncated         bool                   `json:"truncated"`
}

// parseTimeParam parses an optional RFC 3339 query parameter. Empty
// returns nil.
func parseTimeParam(q url.Values, name string) (*time.Time, error) {
	raw := q.Get(name)
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: want an RFC 3339 time such as 2026-10-14T09:00:00Z", name, raw)
	}
	t = t.UTC()
	return &t, nil
}

// parseWindow reads ?since= (inclusive) and ?until= (exclusive).
func parseWindow(q url.Values) (since, until *time.Time, err error) {
	if since, err = parseTimeParam(q, "since"); err != nil {
		return nil, nil, err
	}
	if until, err = parseTimeParam(q, "until"); err != nil {
		return nil, nil, err
	}
	if since != nil && until != nil && until.Before(*since) {
		return nil, nil, fmt.Errorf("until (%s) is before since (%s)", until.Format(time.RFC3339Nano), since.Format(time.RFC3339Nano))
	}
	return since, until, nil
}

// handleSessionList returns the tenant's sessions in a time window, newest
// first (GET /v1/sessions).
//
// Query-string contract:
//   - ?since=, ?until= — RFC 3339; since is inclusive, until exclusive.
//     since defaults to DefaultSessionWindow ago; until defaults to open.
//   - ?agent_id= — sessions in which this agent made a call.
//   - ?parent_session_id= — sessions started by this session.
//   - ?limit=N — [1, MaxSessionListLimit], clamped above; default
//     DefaultSessionListLimit.
//
// The store backend aggregates in SQL. The file backend scans the live
// audit file (one to three passes) holding at most
// audit.DefaultMaxTrackedSessions sessions, and says truncated when the
// window held more. Neither runs on the /v1/check path.
func (s *Server) handleSessionList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, err := parseBoundedInt(q.Get("limit"), DefaultSessionListLimit, 1, MaxSessionListLimit)
	if err != nil {
		http.Error(w, "invalid limit: "+err.Error(), http.StatusBadRequest)
		return
	}
	since, until, err := parseWindow(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if since == nil {
		d := time.Now().UTC().Add(-DefaultSessionWindow)
		since = &d
	}
	page, err := audit.QuerySessions(s.cfg.Logger, audit.SessionFilter{
		TenantID:        TenantIDFromContext(r.Context()),
		AgentID:         q.Get("agent_id"),
		ParentSessionID: q.Get("parent_session_id"),
		Since:           since,
		Until:           until,
		Limit:           limit,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
		return
	}
	if page.Sessions == nil {
		page.Sessions = []audit.SessionSummary{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sessionList{Since: *since, Until: until, Sessions: page.Sessions, Truncated: page.Truncated})
}

// handleSessionGet returns one session: its summary, the sessions it
// started, and its entries oldest first (GET /v1/sessions/{id}).
//
// ?since= and ?until= narrow all three to a window (no default: the whole
// session). ?limit=N bounds the entries, [1, MaxSessionEntryLimit],
// default DefaultSessionEntryLimit. 404 when the tenant has no entry for
// the session in the window.
func (s *Server) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing session id: use /v1/sessions/{id}, or /v1/sessions to list them", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	limit, err := parseBoundedInt(q.Get("limit"), DefaultSessionEntryLimit, 1, MaxSessionEntryLimit)
	if err != nil {
		http.Error(w, "invalid limit: "+err.Error(), http.StatusBadRequest)
		return
	}
	since, until, err := parseWindow(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d, err := audit.QuerySessionDetail(s.cfg.Logger, audit.SessionDetailFilter{
		TenantID:   TenantIDFromContext(r.Context()),
		SessionID:  id,
		Since:      since,
		Until:      until,
		EntryLimit: limit,
		ChildLimit: MaxSessionListLimit,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Query error: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !d.Found {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no audit entries for this session; check the id, or widen since/until"})
		return
	}
	_ = json.NewEncoder(w).Encode(sessionDetail{
		Session:           d.Session,
		Children:          d.Children,
		ChildrenTruncated: d.ChildrenTruncated,
		Entries:           d.Entries,
		Truncated:         d.Truncated,
	})
}
