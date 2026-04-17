package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// Entry represents a single audit log record.
type Entry struct {
	Timestamp  time.Time           `json:"timestamp"`
	SessionID  string              `json:"session_id"`
	AgentID    string              `json:"agent_id"`
	Request    policy.ActionRequest `json:"request"`
	Result     policy.CheckResult  `json:"result"`
	DurationMs int64               `json:"duration_ms"`
}

// Logger is the interface for audit logging.
type Logger interface {
	Log(entry Entry) error
	Query(filter QueryFilter) ([]Entry, error)
	Close() error
}

// QueryFilter specifies criteria for querying audit logs.
type QueryFilter struct {
	AgentID   string     `json:"agent_id,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	Decision  string     `json:"decision,omitempty"`
	Scope     string     `json:"scope,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Limit     int        `json:"limit,omitempty"`
}

// DefaultFilePermissions is the Unix file mode for newly created audit log files.
// Restricted to owner-only since audit logs may contain sensitive operational data.
const DefaultFilePermissions = 0600

// FileLogger writes audit entries as JSON lines to a file.
type FileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewFileLogger creates a new file-based audit logger.
func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	return &FileLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// Log writes an audit entry to the log file.
func (l *FileLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	return l.enc.Encode(entry)
}

// Query reads the log file and filters entries.
//
// Lock scope: we hold l.mu only long enough to capture the current file path
// (effectively immutable, but we still snapshot it under the lock for safety)
// and open a read handle. The actual scan runs WITHOUT the lock so concurrent
// Log() writes are not blocked by long queries.
//
// This is safe because:
//   - FileLogger.file is opened in O_APPEND mode, so writes go to EOF
//     atomically (on POSIX, append writes of ≤PIPE_BUF are atomic).
//   - Our read handle captures a consistent size at open; extra bytes written
//     after we open are simply not seen by this query.
//   - Scanner discards partial lines implicitly (each line terminated by \n).
//
// TODO(perf): Query scans the full file linearly. For production workloads
// with large audit logs, replace with a database-backed implementation
// (SQLite or PostgreSQL).
func (l *FileLogger) Query(filter QueryFilter) ([]Entry, error) {
	l.mu.Lock()
	path := l.file.Name()
	l.mu.Unlock()

	readFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer readFile.Close()

	var results []Entry
	scanner := bufio.NewScanner(readFile)
	// Default Scanner buffer is 64KB; bump so large entries don't break the
	// scan. Audit entries normally well under 4KB.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip corrupt lines
		}

		if matchesFilter(entry, filter) {
			results = append(results, entry)
		}

		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}

	return results, nil
}

func matchesFilter(entry Entry, filter QueryFilter) bool {
	if filter.AgentID != "" && entry.AgentID != filter.AgentID {
		return false
	}
	if filter.SessionID != "" && entry.SessionID != filter.SessionID {
		return false
	}
	if filter.Decision != "" && string(entry.Result.Decision) != filter.Decision {
		return false
	}
	if filter.Scope != "" && entry.Request.Scope != filter.Scope {
		return false
	}
	if filter.Since != nil && entry.Timestamp.Before(*filter.Since) {
		return false
	}
	return true
}

// Close flushes and closes the log file.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}
