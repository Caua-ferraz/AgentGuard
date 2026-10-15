package audit

import (
	"sort"
	"time"
)

// SubagentMetaKey is the request meta key that names a sub-agent. The
// Claude Code hook sets it to the sub-agent's type, so the calls a
// sub-agent makes inside its parent's session can be told apart.
const SubagentMetaKey = "subagent"

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
type SessionSummary struct {
	SessionID       string         `json:"session_id"`
	ParentSessionID string         `json:"parent_session_id,omitempty"`
	Agents          []SessionAgent `json:"agents"`
	Transports      []string       `json:"transports"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	Counts          DecisionCounts `json:"counts"`
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
type SessionFilter struct {
	TenantID        string
	SessionID       string
	ParentSessionID string
	AgentID         string
	Since           *time.Time
	Until           *time.Time
	Limit           int
}

// SessionQuerier is implemented by loggers that summarise sessions
// themselves: the FileLogger in one pass over the file, the store-backed
// logger in SQL, and the wrappers that forward to either. Sessions returns
// the newest sessions first (by last_seen, then session_id).
type SessionQuerier interface {
	Sessions(f SessionFilter) ([]SessionSummary, error)
}

// QuerySessions summarises sessions through l: natively when l is a
// SessionQuerier, otherwise from the entries l.Query returns.
func QuerySessions(l Logger, f SessionFilter) ([]SessionSummary, error) {
	if q, ok := l.(SessionQuerier); ok {
		return q.Sessions(f)
	}
	// The agent and parent filters select whole sessions, so they can't be
	// pushed into the entry query: a session's other entries still count.
	entries, err := l.Query(QueryFilter{TenantID: f.TenantID, SessionID: f.SessionID, Since: f.Since, Until: f.Until})
	agg := NewSessionAggregator(f)
	for _, e := range entries {
		agg.Add(e)
	}
	return agg.Result(), err
}

// SessionAggregator builds session summaries from entries fed to it in log
// order. It is how backends without SQL implement SessionQuerier.
type SessionAggregator struct {
	f    SessionFilter
	byID map[string]*sessionAcc
}

type sessionAcc struct {
	sum        SessionSummary
	agents     map[SessionAgent]bool
	transports map[string]bool
	parents    map[string]bool
	agentSeen  bool
}

// NewSessionAggregator returns an empty aggregator for f.
func NewSessionAggregator(f SessionFilter) *SessionAggregator {
	return &SessionAggregator{f: f, byID: map[string]*sessionAcc{}}
}

// Add counts e if it falls inside the filter's tenant, session and window.
func (a *SessionAggregator) Add(e Entry) {
	f := a.f
	if e.SessionID == "" ||
		(f.TenantID != "" && e.EffectiveTenant() != f.TenantID) ||
		(f.SessionID != "" && e.SessionID != f.SessionID) ||
		(f.Since != nil && e.Timestamp.Before(*f.Since)) ||
		(f.Until != nil && !e.Timestamp.Before(*f.Until)) {
		return
	}
	acc := a.byID[e.SessionID]
	if acc == nil {
		acc = &sessionAcc{
			sum:        SessionSummary{SessionID: e.SessionID, FirstSeen: e.Timestamp, LastSeen: e.Timestamp},
			agents:     map[SessionAgent]bool{},
			transports: map[string]bool{},
			parents:    map[string]bool{},
		}
		a.byID[e.SessionID] = acc
	}
	if e.Timestamp.Before(acc.sum.FirstSeen) {
		acc.sum.FirstSeen = e.Timestamp
	}
	if e.Timestamp.After(acc.sum.LastSeen) {
		acc.sum.LastSeen = e.Timestamp
	}
	acc.sum.Counts.add(e.Result.Decision)
	if ag := (SessionAgent{AgentID: e.AgentID, Subagent: e.Request.Meta[SubagentMetaKey]}); ag != (SessionAgent{}) {
		acc.agents[ag] = true
	}
	acc.transports[e.EffectiveTransport()] = true
	if p := e.Request.ParentSessionID; p != "" {
		if acc.sum.ParentSessionID == "" {
			acc.sum.ParentSessionID = p
		}
		acc.parents[p] = true
	}
	if f.AgentID != "" && e.AgentID == f.AgentID {
		acc.agentSeen = true
	}
}

// Result returns the matching sessions, newest first, capped at the
// filter's Limit.
func (a *SessionAggregator) Result() []SessionSummary {
	out := make([]SessionSummary, 0, len(a.byID))
	for _, acc := range a.byID {
		if a.f.AgentID != "" && !acc.agentSeen {
			continue
		}
		if a.f.ParentSessionID != "" && !acc.parents[a.f.ParentSessionID] {
			continue
		}
		s := acc.sum
		s.Agents = make([]SessionAgent, 0, len(acc.agents))
		for ag := range acc.agents {
			s.Agents = append(s.Agents, ag)
		}
		s.Transports = make([]string, 0, len(acc.transports))
		for t := range acc.transports {
			s.Transports = append(s.Transports, t)
		}
		s.SortLists()
		out = append(out, s)
	}
	SortSessions(out)
	if a.f.Limit > 0 && len(out) > a.f.Limit {
		out = out[:a.f.Limit]
	}
	return out
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

// Sessions forwards to the wrapped logger.
func (l *transformLogger) Sessions(f SessionFilter) ([]SessionSummary, error) {
	return QuerySessions(l.inner, f)
}

// Sessions forwards to the underlying logger. Like Query, it does not see
// entries still in the queue or the overflow file.
func (b *BufferedAsyncLogger) Sessions(f SessionFilter) ([]SessionSummary, error) {
	return QuerySessions(b.underlying, f)
}
