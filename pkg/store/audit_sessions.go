package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// SessionSink is implemented by stores that summarise audit sessions in SQL
// (SQLiteStore and PostgresStore). It is separate from AuditSink so a Store
// written outside this package keeps compiling; the store-backed logger
// falls back to summarising QueryAudit's entries for one that lacks it.
type SessionSink interface {
	QuerySessions(ctx context.Context, tenantID string, f audit.SessionFilter) ([]audit.SessionSummary, error)
}

// Timestamps are stored as RFC3339Nano text, which drops trailing zeros
// from the fraction: "…:05Z" and "…:05.5Z". Compared as text these sort
// wrong ('.' < 'Z'), so an entry at 10:00:05.5 sorted before one at
// 10:00:05 and a since/until bound inside a second could keep or drop the
// wrong entries. tsNormSQL rewrites the stored value to a fixed-width form
// (always nine fraction digits, no zone: every row is written in UTC) that
// sorts as time does; bounds are formatted with tsNormLayout to match.
const (
	tsNormSQL = `substr("timestamp", 1, 19) || substr(CASE WHEN length("timestamp") > 20 ` +
		`THEN substr("timestamp", 20, length("timestamp") - 20) ELSE '.' END || '000000000', 1, 10)`
	tsNormLayout = "2006-01-02T15:04:05.000000000"
	// tsSecondLayout is the stored value's whole-second prefix. Comparing
	// the raw column against it is correct to the second and can use the
	// (tenant_id, timestamp) index; the exact tsNormSQL test then runs on
	// the rows it leaves.
	tsSecondLayout = "2006-01-02T15:04:05"
)

// sqlDialect is what differs between the two SQL backends here.
type sqlDialect struct {
	// numbered placeholders ($1, $2, …) instead of ?.
	numbered bool
	// collate is appended to text comparisons and orderings that must
	// compare bytes. Postgres otherwise uses the database's collation, which
	// may ignore punctuation; SQLite already compares bytes.
	collate string
}

var (
	sqliteDialect   = sqlDialect{}
	postgresDialect = sqlDialect{numbered: true, collate: ` COLLATE "C"`}
)

// sqlArgs collects query arguments and hands out their placeholders in the
// order the SQL text is built.
type sqlArgs struct {
	d    sqlDialect
	args []any
}

func (a *sqlArgs) add(v any) string {
	a.args = append(a.args, v)
	if a.d.numbered {
		return "$" + strconv.Itoa(len(a.args))
	}
	return "?"
}

// windowConds returns the WHERE conditions for since (inclusive) and until
// (exclusive) on audit_entries.timestamp.
func windowConds(a *sqlArgs, since, until *time.Time) []string {
	var conds []string
	if since != nil {
		s := since.UTC()
		conds = append(conds,
			`"timestamp" >= `+a.add(s.Format(tsSecondLayout)),
			"("+tsNormSQL+")"+a.d.collate+" >= "+a.add(s.Format(tsNormLayout)))
	}
	if until != nil {
		u := until.UTC()
		// Every row before until is in a second before the one after
		// until's, so this whole-second bound never drops one.
		next := u.Truncate(time.Second).Add(time.Second)
		conds = append(conds,
			`"timestamp" < `+a.add(next.Format(tsSecondLayout)),
			"("+tsNormSQL+")"+a.d.collate+" < "+a.add(u.Format(tsNormLayout)))
	}
	return conds
}

// sessionBaseConds is the tenant + window part shared by every session
// query. tenantID wins over f.TenantID; empty means all tenants.
func sessionBaseConds(a *sqlArgs, tenantID string, f audit.SessionFilter) []string {
	t := tenantID
	if t == "" {
		t = f.TenantID
	}
	conds := []string{"session_id != ''"}
	if t != "" {
		conds = append(conds, "tenant_id = "+a.add(EffectiveTenant(t)))
	}
	return append(conds, windowConds(a, f.Since, f.Until)...)
}

// querySessions summarises sessions with two queries: one groups the
// window by session for the counts and times, newest first and limited;
// the other lists the distinct agents, transports and parents of just the
// sessions on that page. Semantics match audit.SessionAggregator, pinned
// by the parity test.
func querySessions(ctx context.Context, db *sql.DB, d sqlDialect, tenantID string, f audit.SessionFilter) ([]audit.SessionSummary, error) {
	a := &sqlArgs{d: d}
	conds := sessionBaseConds(a, tenantID, f)
	if f.SessionID != "" {
		conds = append(conds, "session_id = "+a.add(f.SessionID))
	}
	// The agent and parent filters pick sessions; the summary still counts
	// all of the session's entries in the window, so they are subqueries.
	if f.AgentID != "" {
		sub := sessionBaseConds(a, tenantID, f)
		sub = append(sub, "agent_id = "+a.add(f.AgentID))
		conds = append(conds, "session_id IN (SELECT session_id FROM audit_entries WHERE "+strings.Join(sub, " AND ")+")")
	}
	if f.ParentSessionID != "" {
		sub := sessionBaseConds(a, tenantID, f)
		sub = append(sub, "parent_session_id = "+a.add(f.ParentSessionID))
		conds = append(conds, "session_id IN (SELECT session_id FROM audit_entries WHERE "+strings.Join(sub, " AND ")+")")
	}

	q := `SELECT session_id, MIN(tsn), MAX(tsn), COUNT(*),
	        SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END),
	        SUM(CASE WHEN decision = 'DENY' THEN 1 ELSE 0 END),
	        SUM(CASE WHEN decision = 'REQUIRE_APPROVAL' THEN 1 ELSE 0 END)
	      FROM (SELECT session_id, decision, (` + tsNormSQL + `)` + d.collate + ` AS tsn
	            FROM audit_entries WHERE ` + strings.Join(conds, " AND ") + `) w
	      GROUP BY session_id
	      ORDER BY MAX(tsn) DESC, session_id` + d.collate + ` ASC`
	if f.Limit > 0 {
		q += " LIMIT " + a.add(f.Limit)
	}
	rows, err := db.QueryContext(ctx, q, a.args...)
	if err != nil {
		return nil, fmt.Errorf("store: query sessions: %w", err)
	}
	out := []audit.SessionSummary{}
	index := map[string]int{}
	for rows.Next() {
		var (
			s                             audit.SessionSummary
			first, last                   string
			total, allow, deny, approvals int64
		)
		if err := rows.Scan(&s.SessionID, &first, &last, &total, &allow, &deny, &approvals); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scan session: %w", err)
		}
		s.FirstSeen = parseNormTime(first)
		s.LastSeen = parseNormTime(last)
		s.Counts = audit.DecisionCounts{Total: uint64(total), Allow: uint64(allow), Deny: uint64(deny), RequireApproval: uint64(approvals)}
		s.Agents = []audit.SessionAgent{}
		s.Transports = []string{}
		index[s.SessionID] = len(out)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store: query sessions: %w", err)
	}
	_ = rows.Close()
	if len(out) == 0 {
		return out, nil
	}

	// Second query: who and how, for the sessions on this page only.
	a = &sqlArgs{d: d}
	conds = sessionBaseConds(a, tenantID, f)
	ids := make([]string, len(out))
	for i, s := range out {
		ids[i] = a.add(s.SessionID)
	}
	conds = append(conds, "session_id IN ("+strings.Join(ids, ", ")+")")
	q = `SELECT session_id, agent_id, subagent, transport, parent_session_id, MIN(id)
	     FROM audit_entries WHERE ` + strings.Join(conds, " AND ") + `
	     GROUP BY session_id, agent_id, subagent, transport, parent_session_id`
	rows, err = db.QueryContext(ctx, q, a.args...)
	if err != nil {
		return nil, fmt.Errorf("store: query session agents: %w", err)
	}
	defer rows.Close()

	type tuple struct {
		agentID, subagent, transport, parent string
		firstID                              int64 // MIN(id): when the tuple first appears
	}
	tuples := make([][]tuple, len(out))
	for rows.Next() {
		var (
			sessionID string
			tp        tuple
		)
		if err := rows.Scan(&sessionID, &tp.agentID, &tp.subagent, &tp.transport, &tp.parent, &tp.firstID); err != nil {
			return nil, fmt.Errorf("store: scan session agents: %w", err)
		}
		if i, ok := index[sessionID]; ok {
			tuples[i] = append(tuples[i], tp)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query session agents: %w", err)
	}
	// Replay the tuples in the order they first appear, so the lists keep
	// the first agents and transports seen when they hit their caps, and
	// the parent is the one named by the session's first entry that names
	// one: the same rules as the file backend's scan.
	for i := range out {
		sort.Slice(tuples[i], func(a, b int) bool { return tuples[i][a].firstID < tuples[i][b].firstID })
		for _, tp := range tuples[i] {
			out[i].AddAgent(tp.agentID, tp.subagent)
			out[i].AddTransport(tp.transport)
			if out[i].ParentSessionID == "" {
				out[i].ParentSessionID = tp.parent
			}
		}
		out[i].SortLists()
	}
	return out, nil
}

// scanAuditRows reads the rows of QueryAudit's SELECT (both backends).
//
// The store keeps only some request fields. Of the session fields it keeps
// parent_session_id and the meta.subagent value; the latter comes back as
// the request's only meta key, so readers see the sub-agent the same way
// for both backends.
func scanAuditRows(rows *sql.Rows) ([]audit.Entry, error) {
	defer rows.Close()
	var out []audit.Entry
	for rows.Next() {
		var (
			e                  audit.Entry
			tsStr, decision    string
			parent, subagentID string
		)
		if err := rows.Scan(
			&e.TenantID, &tsStr, &e.SessionID, &e.AgentID, &e.Request.Scope, &e.Request.Action,
			&e.Request.Command, &e.Request.Path, &e.Request.Domain, &e.Request.URL,
			&decision, &e.Result.Reason, &e.Result.Rule, &e.DurationMs, &e.Transport,
			&parent, &subagentID,
		); err != nil {
			return out, fmt.Errorf("store: scan audit: %w", err)
		}
		e.Timestamp = parseTime(tsStr)
		e.Result.Decision = policy.Decision(decision)
		e.Request.ParentSessionID = parent
		if subagentID != "" {
			e.Request.Meta = map[string]string{audit.SubagentMetaKey: subagentID}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// parseNormTime reads a tsNormSQL value back as a UTC time.
func parseNormTime(s string) time.Time {
	t, err := time.ParseInLocation(tsNormLayout, s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return t
}

// QuerySessions summarises the tenant's audit sessions (see SessionSink).
func (s *SQLiteStore) QuerySessions(ctx context.Context, tenantID string, f audit.SessionFilter) ([]audit.SessionSummary, error) {
	return querySessions(ctx, s.db, sqliteDialect, tenantID, f)
}

// QuerySessions summarises the tenant's audit sessions (see SessionSink).
func (s *PostgresStore) QuerySessions(ctx context.Context, tenantID string, f audit.SessionFilter) ([]audit.SessionSummary, error) {
	return querySessions(ctx, s.db, postgresDialect, tenantID, f)
}

// Sessions implements audit.SessionQuerier for the store-backed logger. SQL
// aggregation holds no per-session state in this process, so the page is
// never Truncated.
func (a auditLoggerAdapter) Sessions(f audit.SessionFilter) (audit.SessionPage, error) {
	if ss, ok := a.s.(SessionSink); ok {
		list, err := ss.QuerySessions(context.Background(), f.TenantID, f)
		return audit.SessionPage{Sessions: list}, err
	}
	// Hide this adapter's own Sessions so QuerySessions aggregates the
	// entries Query returns instead of calling back here.
	return audit.QuerySessions(struct{ audit.Logger }{a}, f)
}
