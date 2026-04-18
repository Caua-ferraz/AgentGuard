package audit

// SQLiteLogger is a database-backed audit logger that replaces the full-file-scan
// approach of FileLogger with indexed SQL queries. It implements the Logger interface.
//
// To activate, add a pure-Go SQLite driver dependency:
//
//	go get modernc.org/sqlite
//
// Then wire SQLiteLogger into cmd/agentguard/main.go in place of (or alongside) FileLogger.
//
// Schema:
//
//	CREATE TABLE IF NOT EXISTS audit_entries (
//	    id         INTEGER PRIMARY KEY AUTOINCREMENT,
//	    timestamp  TEXT    NOT NULL,
//	    session_id TEXT    NOT NULL DEFAULT '',
//	    agent_id   TEXT    NOT NULL DEFAULT '',
//	    scope      TEXT    NOT NULL DEFAULT '',
//	    action     TEXT    NOT NULL DEFAULT '',
//	    command    TEXT    NOT NULL DEFAULT '',
//	    path       TEXT    NOT NULL DEFAULT '',
//	    domain     TEXT    NOT NULL DEFAULT '',
//	    url        TEXT    NOT NULL DEFAULT '',
//	    decision   TEXT    NOT NULL DEFAULT '',
//	    reason     TEXT    NOT NULL DEFAULT '',
//	    rule       TEXT    NOT NULL DEFAULT '',
//	    duration_ms INTEGER NOT NULL DEFAULT 0
//	);
//
//	CREATE INDEX idx_audit_agent    ON audit_entries(agent_id);
//	CREATE INDEX idx_audit_decision ON audit_entries(decision);
//	CREATE INDEX idx_audit_scope    ON audit_entries(scope);
//	CREATE INDEX idx_audit_ts       ON audit_entries(timestamp);

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS audit_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    session_id  TEXT    NOT NULL DEFAULT '',
    agent_id    TEXT    NOT NULL DEFAULT '',
    scope       TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL DEFAULT '',
    command     TEXT    NOT NULL DEFAULT '',
    path        TEXT    NOT NULL DEFAULT '',
    domain      TEXT    NOT NULL DEFAULT '',
    url         TEXT    NOT NULL DEFAULT '',
    decision    TEXT    NOT NULL DEFAULT '',
    reason      TEXT    NOT NULL DEFAULT '',
    rule        TEXT    NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0
);`

const createIndexesSQL = `
CREATE INDEX IF NOT EXISTS idx_audit_agent    ON audit_entries(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_entries(decision);
CREATE INDEX IF NOT EXISTS idx_audit_scope    ON audit_entries(scope);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_entries(timestamp);`

const insertSQL = `
INSERT INTO audit_entries (
    timestamp, session_id, agent_id,
    scope, action, command, path, domain, url,
    decision, reason, rule, duration_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// SQLiteLogger stores audit entries in a SQLite database for efficient querying.
// Requires a "database/sql" driver for SQLite to be registered (e.g., modernc.org/sqlite).
type SQLiteLogger struct {
	mu sync.Mutex
	db *sql.DB
}

// NewSQLiteLogger opens (or creates) a SQLite database at the given path and
// initializes the audit_entries table and indexes.
//
// Before calling this, register a SQLite driver. For example:
//
//	import _ "modernc.org/sqlite"
//
// Then call:
//
//	logger, err := audit.NewSQLiteLogger("audit.db")
func NewSQLiteLogger(dbPath string) (*SQLiteLogger, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening audit database: %w", err)
	}

	// Enable WAL mode for better concurrent read/write performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating audit table: %w", err)
	}

	if _, err := db.Exec(createIndexesSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating indexes: %w", err)
	}

	return &SQLiteLogger{db: db}, nil
}

// Log writes an audit entry to the database.
func (l *SQLiteLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	_, err := l.db.Exec(insertSQL,
		entry.Timestamp.Format(time.RFC3339Nano),
		entry.SessionID,
		entry.AgentID,
		entry.Request.Scope,
		entry.Request.Action,
		entry.Request.Command,
		entry.Request.Path,
		entry.Request.Domain,
		entry.Request.URL,
		string(entry.Result.Decision),
		entry.Result.Reason,
		entry.Result.Rule,
		entry.DurationMs,
	)
	return err
}

// Query returns audit entries matching the given filter. Unlike FileLogger.Query,
// this uses indexed SQL queries instead of a full file scan — O(log n) per query.
func (l *SQLiteLogger) Query(filter QueryFilter) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var conditions []string
	var args []interface{}

	if filter.AgentID != "" {
		conditions = append(conditions, "agent_id = ?")
		args = append(args, filter.AgentID)
	}
	if filter.SessionID != "" {
		conditions = append(conditions, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.Decision != "" {
		conditions = append(conditions, "decision = ?")
		args = append(args, filter.Decision)
	}
	if filter.Scope != "" {
		conditions = append(conditions, "scope = ?")
		args = append(args, filter.Scope)
	}
	if filter.Since != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.Format(time.RFC3339Nano))
	}

	query := "SELECT timestamp, session_id, agent_id, scope, action, command, path, domain, url, decision, reason, rule, duration_ms FROM audit_entries"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id ASC"

	// LIMIT/OFFSET are parameterized to avoid SQL injection even though the
	// caller is currently trusted. Treat Limit <= 0 as "no limit". SQLite
	// requires a LIMIT to accept an OFFSET, so when the caller asks for an
	// offset without a limit we fall back to LIMIT -1 (SQLite convention for
	// "no limit with offset").
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	} else if filter.Offset > 0 {
		query += " LIMIT -1 OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit entries: %w", err)
	}
	defer rows.Close()

	var results []Entry
	for rows.Next() {
		var (
			tsStr    string
			e        Entry
			decision string
		)
		err := rows.Scan(
			&tsStr,
			&e.SessionID,
			&e.AgentID,
			&e.Request.Scope,
			&e.Request.Action,
			&e.Request.Command,
			&e.Request.Path,
			&e.Request.Domain,
			&e.Request.URL,
			&decision,
			&e.Result.Reason,
			&e.Result.Rule,
			&e.DurationMs,
		)
		if err != nil {
			return results, fmt.Errorf("scanning audit row: %w", err)
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		e.Result.Decision = policy.Decision(decision)
		results = append(results, e)
	}

	return results, rows.Err()
}

// Close closes the underlying database connection.
func (l *SQLiteLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.db.Close()
}
