package audit

import (
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

// FileLogger writes audit entries as JSON lines to a file.
type FileLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewFileLogger creates a new file-based audit logger.
func NewFileLogger(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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
// For production use, this should be replaced with a database-backed implementation.
func (l *FileLogger) Query(filter QueryFilter) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Read from beginning
	readFile, err := os.Open(l.file.Name())
	if err != nil {
		return nil, err
	}
	defer readFile.Close()

	var results []Entry
	dec := json.NewDecoder(readFile)

	for dec.More() {
		var entry Entry
		if err := dec.Decode(&entry); err != nil {
			continue
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
