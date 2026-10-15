package audit

import (
	"container/list"
	"errors"
	"log"
	"sort"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// SubagentMetaKey is the request meta key that names a sub-agent. The
// Claude Code hook sets it to the sub-agent's type, so the calls a
// sub-agent makes inside its parent's session can be told apart.
const SubagentMetaKey = "subagent"

const (
	// DefaultMaxTrackedSessions is the fewest sessions a scan of the file
	// backend keeps in memory at once (see SessionFilter.MaxTracked).
	// session_id comes from the unauthenticated /v1/check, so a client can
	// write a new one on every call; without a cap, summarising a window
	// would hold one record per line.
	DefaultMaxTrackedSessions = 50000
	// MaxSessionAgents and MaxSessionTransports cap a summary's lists, for
	// the same reason: agent_id and meta values are caller-chosen. The
	// first ones seen are kept and ListsTruncated is set.
	MaxSessionAgents     = 32
	MaxSessionTransports = 16
)

// SessionAgent is one agent seen in a session: an agent_id, and the
// sub-agent (meta["subagent"]) when the calls came from one.
type SessionAgent struct {
	AgentID  string `json:"agent_id"`
	Subagent string `json:"subagent,omitempty"`
}

// SessionSummary describes one session over a time window: who took part,
// through which transports, when, and how its checks were decided.
//
// ParentSessionID is the parent named by the session's first entry that
// names one. A session that names several parents is still listed under
// each of them by a ParentSessionID filter.
//
// ListsTruncated is true when the session had more than MaxSessionAgents
// agents or MaxSessionTransports transports; the lists hold the first ones
// seen. The counts always cover every entry.
type SessionSummary struct {
	SessionID       string         `json:"session_id"`
	ParentSessionID string         `json:"parent_session_id,omitempty"`
	Agents          []SessionAgent `json:"agents"`
	Transports      []string       `json:"transports"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	Counts          DecisionCounts `json:"counts"`
	ListsTruncated  bool           `json:"lists_truncated,omitempty"`
}

// SessionFilter selects the sessions SessionQuerier.Sessions returns.
//
// Since (inclusive) and Until (exclusive) bound the entries that are
// counted, as in QueryFilter; nil leaves that side open. Entries with an
// empty session_id belong to no session and are never counted.
//
// AgentID keeps sessions in which that agent made a call in the window;
// ParentSessionID keeps sessions with an entry naming that parent. Both
// select sessions, they do not trim them: the summary still covers every
// entry of the session in the window. Limit 0 means no cap.
//
// MaxTracked bounds how many sessions a scan holds in memory (file
// backend); 0 means max(10*Limit, DefaultMaxTrackedSessions). Past it the
// result is marked Truncated (see SessionPage).
type SessionFilter struct {
	TenantID        string
	SessionID       string
	ParentSessionID string
	AgentID         string
	Since           *time.Time
	Until           *time.Time
	Limit           int
	MaxTracked      int
}

func (f SessionFilter) maxTracked() int {
	if f.MaxTracked > 0 {
		return f.MaxTracked
	}
	if n := 10 * f.Limit; n > DefaultMaxTrackedSessions {
		return n
	}
	return DefaultMaxTrackedSessions
}

// SessionPage is the result of a session query.
//
// Truncated is true when the window held more sessions than the scan
// tracks (SessionFilter.MaxTracked). The sessions returned are then the
// ones most recently written to the log, with exact summaries; older
// sessions, and with an AgentID or ParentSessionID filter some matching
// ones, may be missing. A narrower since/until avoids it. The SQL store
// backend never truncates.
type SessionPage struct {
	Sessions  []SessionSummary
	Truncated bool
}

// SessionQuerier is implemented by loggers that summarise sessions
// themselves: the FileLogger in a bounded scan of the file, the
// store-backed logger in SQL, and the wrappers that forward to either.
// Sessions are returned newest first (by last_seen, then session_id).
type SessionQuerier interface {
	Sessions(f SessionFilter) (SessionPage, error)
}

// QuerySessions summarises sessions through l: natively when l is a
// SessionQuerier, otherwise from the entries l.Query returns.
func QuerySessions(l Logger, f SessionFilter) (SessionPage, error) {
	if q, ok := l.(SessionQuerier); ok {
		return q.Sessions(f)
	}
	// The agent and parent filters select whole sessions, so they can't be
	// pushed into the entry query: a session's other entries still count.
	entries, err := l.Query(QueryFilter{TenantID: f.TenantID, SessionID: f.SessionID, Since: f.Since, Until: f.Until})
	page, _ := summarize(sliceSource(entries), f, nil)
	return page, err
}

// entrySource feeds entries in log order to fn until fn returns false. It
// can be read more than once: the summaries below take up to three passes
// so their memory stays bounded.
type entrySource func(fn func(Entry) bool) error

func sliceSource(entries []Entry) entrySource {
	return func(fn func(Entry) bool) error {
		for _, e := range entries {
			if !fn(e) {
				break
			}
		}
		return nil
	}
}

// inWindow reports whether e is counted by f, ignoring the agent and
// parent filters (which select whole sessions).
func (f SessionFilter) inWindow(e Entry) bool {
	return e.SessionID != "" &&
		(f.TenantID == "" || e.EffectiveTenant() == f.TenantID) &&
		(f.SessionID == "" || e.SessionID == f.SessionID) &&
		(f.Since == nil || !e.Timestamp.Before(*f.Since)) &&
		(f.Until == nil || e.Timestamp.Before(*f.Until))
}

// scanStats records what a summary held in memory; tests pin the bound.
type scanStats struct {
	passes     int
	maxTracked int // most sessions held at once
}

// summarize builds f's sessions from src in at most three passes, holding
// at most f.maxTracked() sessions:
//
//  1. With an agent or parent filter, find the sessions that match it.
//  2. Summarise the selected sessions. When there are more than the cap,
//     the session seen longest ago is dropped for each new one, so the
//     ones kept are exactly those with the latest last entry.
//  3. Only if a session was dropped: a dropped session that came back has
//     lost its earlier entries, so the page to return is summarised again
//     from scratch.
func summarize(src entrySource, f SessionFilter, stats *scanStats) (SessionPage, error) {
	if stats == nil {
		stats = &scanStats{}
	}
	limit := f.maxTracked()
	var page SessionPage

	var selected map[string]bool
	if f.AgentID != "" || f.ParentSessionID != "" {
		ids, held, truncated, err := matchingSessions(src, f, limit)
		stats.passes++
		stats.maxTracked = held
		if err != nil {
			return page, err
		}
		page.Truncated = truncated
		selected = ids
		if len(selected) == 0 {
			page.Sessions = []SessionSummary{}
			return page, nil
		}
	}

	lru := newSessionLRU(limit)
	err := src(func(e Entry) bool {
		if f.inWindow(e) && (selected == nil || selected[e.SessionID]) {
			lru.add(e)
		}
		return true
	})
	stats.passes++
	if lru.peak > stats.maxTracked {
		stats.maxTracked = lru.peak
	}
	if err != nil {
		return page, err
	}
	page.Sessions = lru.summaries()
	SortSessions(page.Sessions)
	if f.Limit > 0 && len(page.Sessions) > f.Limit {
		page.Sessions = page.Sessions[:f.Limit]
	}
	if !lru.evicted {
		return page, nil
	}

	page.Truncated = true
	keep := make(map[string]bool, len(page.Sessions))
	for _, s := range page.Sessions {
		keep[s.SessionID] = true
	}
	exact := newSessionLRU(len(keep) + 1)
	err = src(func(e Entry) bool {
		if f.inWindow(e) && keep[e.SessionID] {
			exact.add(e)
		}
		return true
	})
	stats.passes++
	if exact.peak > stats.maxTracked {
		stats.maxTracked = exact.peak
	}
	page.Sessions = exact.summaries()
	SortSessions(page.Sessions)
	return page, err
}

// matchingSessions returns the sessions with an entry in the window that
// satisfies f's agent and parent filters (both, when both are set),
// tracking at most limit candidates.
func matchingSessions(src entrySource, f SessionFilter, limit int) (map[string]bool, int, bool, error) {
	const agentBit, parentBit = 1, 2
	want := uint8(0)
	if f.AgentID != "" {
		want |= agentBit
	}
	if f.ParentSessionID != "" {
		want |= parentBit
	}
	seen := map[string]uint8{}
	truncated := false
	err := src(func(e Entry) bool {
		if !f.inWindow(e) {
			return true
		}
		var bits uint8
		if f.AgentID != "" && e.AgentID == f.AgentID {
			bits |= agentBit
		}
		if f.ParentSessionID != "" && e.Request.ParentSessionID == f.ParentSessionID {
			bits |= parentBit
		}
		if bits == 0 {
			return true
		}
		if _, ok := seen[e.SessionID]; !ok && len(seen) >= limit {
			truncated = true
			return true
		}
		seen[e.SessionID] |= bits
		return true
	})
	ids := make(map[string]bool, len(seen))
	for id, bits := range seen {
		if bits == want {
			ids[id] = true
		}
	}
	return ids, len(seen), truncated, err
}

// sessionLRU holds at most cap session summaries, dropping the one whose
// latest entry is oldest when a new session arrives at the cap.
type sessionLRU struct {
	cap     int
	byID    map[string]*list.Element
	order   *list.List // of *SessionSummary, least recently seen first
	peak    int
	evicted bool
}

func newSessionLRU(capacity int) *sessionLRU {
	return &sessionLRU{cap: capacity, byID: map[string]*list.Element{}, order: list.New()}
}

func (c *sessionLRU) add(e Entry) {
	el, ok := c.byID[e.SessionID]
	if ok {
		c.order.MoveToBack(el)
	} else {
		if c.order.Len() >= c.cap {
			oldest := c.order.Front()
			delete(c.byID, oldest.Value.(*SessionSummary).SessionID)
			c.order.Remove(oldest)
			c.evicted = true
		}
		s := &SessionSummary{SessionID: e.SessionID, FirstSeen: e.Timestamp, LastSeen: e.Timestamp,
			Agents: []SessionAgent{}, Transports: []string{}}
		el = c.order.PushBack(s)
		c.byID[e.SessionID] = el
		if n := c.order.Len(); n > c.peak {
			c.peak = n
		}
	}
	el.Value.(*SessionSummary).add(e.Timestamp, e.Result.Decision, e.AgentID,
		e.Request.Meta[SubagentMetaKey], e.EffectiveTransport(), e.Request.ParentSessionID)
}

func (c *sessionLRU) summaries() []SessionSummary {
	out := make([]SessionSummary, 0, c.order.Len())
	for el := c.order.Front(); el != nil; el = el.Next() {
		s := *el.Value.(*SessionSummary)
		s.SortLists()
		out = append(out, s)
	}
	return out
}

// add counts one entry of the session, in log order. The SQL store builds
// its lists through AddAgent and AddTransport, so both backends cap them
// the same way.
func (s *SessionSummary) add(ts time.Time, d policy.Decision, agentID, subagent, transport, parent string) {
	if ts.Before(s.FirstSeen) {
		s.FirstSeen = ts
	}
	if ts.After(s.LastSeen) {
		s.LastSeen = ts
	}
	s.Counts.add(d)
	s.AddAgent(agentID, subagent)
	s.AddTransport(transport)
	if s.ParentSessionID == "" {
		s.ParentSessionID = parent
	}
}

// AddAgent records an agent in the summary, up to MaxSessionAgents
// distinct ones. An entry with neither an agent nor a sub-agent adds none.
func (s *SessionSummary) AddAgent(agentID, subagent string) {
	ag := SessionAgent{AgentID: agentID, Subagent: subagent}
	if ag == (SessionAgent{}) {
		return
	}
	for _, have := range s.Agents {
		if have == ag {
			return
		}
	}
	if len(s.Agents) >= MaxSessionAgents {
		s.ListsTruncated = true
		return
	}
	s.Agents = append(s.Agents, ag)
}

// AddTransport records a transport in the summary, up to
// MaxSessionTransports distinct ones.
func (s *SessionSummary) AddTransport(t string) {
	for _, have := range s.Transports {
		if have == t {
			return
		}
	}
	if len(s.Transports) >= MaxSessionTransports {
		s.ListsTruncated = true
		return
	}
	s.Transports = append(s.Transports, t)
}

// SortLists puts Agents (by agent_id, then subagent) and Transports in a
// stable order, so every backend returns the same JSON for the same data.
func (s *SessionSummary) SortLists() {
	sort.Slice(s.Agents, func(i, j int) bool {
		if s.Agents[i].AgentID != s.Agents[j].AgentID {
			return s.Agents[i].AgentID < s.Agents[j].AgentID
		}
		return s.Agents[i].Subagent < s.Agents[j].Subagent
	})
	sort.Strings(s.Transports)
}

// SortSessions orders sessions newest first: by LastSeen descending, then
// by SessionID so sessions that ended at the same instant keep one order.
func SortSessions(list []SessionSummary) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].LastSeen.Equal(list[j].LastSeen) {
			return list[i].LastSeen.After(list[j].LastSeen)
		}
		return list[i].SessionID < list[j].SessionID
	})
}

// SessionDetailFilter selects one session for QuerySessionDetail.
// EntryLimit and ChildLimit bound the entries and child sessions returned.
type SessionDetailFilter struct {
	TenantID   string
	SessionID  string
	Since      *time.Time
	Until      *time.Time
	EntryLimit int
	ChildLimit int
}

// SessionDetail is one session: its summary (Found is false when it has
// no entry in the window), the sessions it started, and its entries in
// log order. Truncated says the session had more than EntryLimit entries;
// ChildrenTruncated, that not every child session is listed.
type SessionDetail struct {
	Found             bool
	Session           SessionSummary
	Children          []SessionSummary
	ChildrenTruncated bool
	Entries           []Entry
	Truncated         bool
}

// SessionDetailer is implemented by loggers that read a session's detail
// in fewer passes than QuerySessionDetail's three queries.
type SessionDetailer interface {
	SessionDetail(f SessionDetailFilter) (SessionDetail, error)
}

// QuerySessionDetail returns one session's detail through l. Without a
// SessionDetailer it runs three queries: the summary, the children and the
// entries (on the SQL store each is an indexed query).
func QuerySessionDetail(l Logger, f SessionDetailFilter) (SessionDetail, error) {
	if d, ok := l.(SessionDetailer); ok {
		return d.SessionDetail(f)
	}
	var d SessionDetail
	own, err := QuerySessions(l, SessionFilter{TenantID: f.TenantID, SessionID: f.SessionID, Since: f.Since, Until: f.Until})
	if err != nil || len(own.Sessions) == 0 {
		return d, err
	}
	d.Found, d.Session = true, own.Sessions[0]
	// One more than the limit tells a full page from a cut-off one.
	kids, err := QuerySessions(l, SessionFilter{
		TenantID: f.TenantID, ParentSessionID: f.SessionID, Since: f.Since, Until: f.Until, Limit: f.ChildLimit + 1,
	})
	if err != nil {
		return d, err
	}
	d.Children, d.ChildrenTruncated = trimChildren(kids, f.ChildLimit)
	d.Entries, err = l.Query(QueryFilter{
		TenantID: f.TenantID, SessionID: f.SessionID, Since: f.Since, Until: f.Until, Limit: f.EntryLimit + 1,
	})
	d.Entries, d.Truncated = trimEntries(d.Entries, f.EntryLimit)
	return d, err
}

func trimChildren(p SessionPage, limit int) ([]SessionSummary, bool) {
	kids := p.Sessions
	truncated := p.Truncated
	if len(kids) > limit {
		kids, truncated = kids[:limit], true
	}
	if kids == nil {
		kids = []SessionSummary{}
	}
	return kids, truncated
}

func trimEntries(entries []Entry, limit int) ([]Entry, bool) {
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}
	if entries == nil {
		entries = []Entry{}
	}
	return entries, truncated
}

// fileSource reads the live audit file. Like Query, it reads only the live
// file, not rotated archives.
func (l *FileLogger) fileSource() entrySource {
	l.mu.Lock()
	path := l.file.Name()
	l.mu.Unlock()
	return func(fn func(Entry) bool) error {
		err := scanEntries(path, fn)
		if errors.Is(err, errScan) {
			log.Printf("WARN audit: scanner error reading %s for sessions (%v)", path, err)
		}
		return err
	}
}

// Sessions summarises the live file's sessions in a bounded scan (see
// summarize and SessionPage).
func (l *FileLogger) Sessions(f SessionFilter) (SessionPage, error) {
	return summarize(l.fileSource(), f, nil)
}

// SessionDetail reads one session in at most two passes over the file: the
// first collects the session's summary, its entries and the ids of the
// sessions that name it as parent; the second, only when there are such
// sessions, summarises them.
func (l *FileLogger) SessionDetail(f SessionDetailFilter) (SessionDetail, error) {
	src := l.fileSource()
	win := SessionFilter{TenantID: f.TenantID, Since: f.Since, Until: f.Until}
	childFilter := SessionFilter{TenantID: f.TenantID, Since: f.Since, Until: f.Until, Limit: f.ChildLimit + 1}
	maxKids := childFilter.maxTracked()

	var d SessionDetail
	own := newSessionLRU(1)
	kids := map[string]bool{}
	kidsCut := false
	err := src(func(e Entry) bool {
		if !win.inWindow(e) {
			return true
		}
		if e.SessionID == f.SessionID {
			own.add(e)
			if len(d.Entries) <= f.EntryLimit {
				d.Entries = append(d.Entries, e)
			}
		}
		if e.Request.ParentSessionID == f.SessionID {
			if !kids[e.SessionID] && len(kids) >= maxKids {
				kidsCut = true
			} else {
				kids[e.SessionID] = true
			}
		}
		return true
	})
	if err != nil {
		return d, err
	}
	sums := own.summaries()
	if len(sums) == 0 {
		return d, nil
	}
	d.Found, d.Session = true, sums[0]
	d.Entries, d.Truncated = trimEntries(d.Entries, f.EntryLimit)

	var page SessionPage
	if len(kids) > 0 {
		page, err = summarize(func(fn func(Entry) bool) error {
			return src(func(e Entry) bool {
				if !kids[e.SessionID] {
					return true
				}
				return fn(e)
			})
		}, childFilter, nil)
	}
	page.Truncated = page.Truncated || kidsCut
	d.Children, d.ChildrenTruncated = trimChildren(page, f.ChildLimit)
	return d, err
}

// Sessions forwards to the wrapped logger.
func (l *transformLogger) Sessions(f SessionFilter) (SessionPage, error) {
	return QuerySessions(l.inner, f)
}

// SessionDetail forwards to the wrapped logger.
func (l *transformLogger) SessionDetail(f SessionDetailFilter) (SessionDetail, error) {
	return QuerySessionDetail(l.inner, f)
}

// Sessions forwards to the underlying logger. Like Query, it does not see
// entries still in the queue or the overflow file.
func (b *BufferedAsyncLogger) Sessions(f SessionFilter) (SessionPage, error) {
	return QuerySessions(b.underlying, f)
}

// SessionDetail forwards to the underlying logger.
func (b *BufferedAsyncLogger) SessionDetail(f SessionDetailFilter) (SessionDetail, error) {
	return QuerySessionDetail(b.underlying, f)
}
