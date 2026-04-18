package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// CurrentSchemaVersion is the schema version produced by this binary.
// Readers accept N-1 (headerless v1 files written by v0.4.0) transparently
// and refuse N+1 with a clear error.
const CurrentSchemaVersion = 2

// metaLinePrefix identifies the schema-header line on disk. Any JSON line
// whose first non-space byte sequence begins with this prefix is treated as
// metadata and skipped by Query().
var metaLinePrefix = []byte(`{"_meta"`)

// MetaRecord is the shape of the first line of a schema-v2 audit file.
// Optional RotatedFrom is set when the file is the successor in a rotation
// chain — the replay walker follows it to stitch history back together.
type MetaRecord struct {
	SchemaVersion int       `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	RotatedFrom   string    `json:"rotated_from,omitempty"`
}

// metaEnvelope is the on-disk wrapper: the v2 meta line is literally
// {"_meta": {...}} so readers can identify it with a cheap prefix check
// before JSON parsing.
type metaEnvelope struct {
	Meta MetaRecord `json:"_meta"`
}

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
//
// Offset is applied after filtering but before the Limit is reached: the first
// Offset matching records are discarded, then up to Limit records are
// collected. A Limit of 0 means "no cap" (compat with v0.4.0).
type QueryFilter struct {
	AgentID   string     `json:"agent_id,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	Decision  string     `json:"decision,omitempty"`
	Scope     string     `json:"scope,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// DefaultFilePermissions is the Unix file mode for newly created audit log files.
// Restricted to owner-only since audit logs may contain sensitive operational data.
const DefaultFilePermissions = 0600

// FileLogger writes audit entries as JSON lines to a file.
//
// Rotation: when rotCfg.MaxSize > 0, every Log() call stats the underlying
// file after the write and hands off to rotateLocked() once the live file
// meets or exceeds the threshold. Rotation is opt-in at v0.4.1 (wired via
// NewFileLoggerWithRotation); callers using the zero-rotation NewFileLogger
// keep v0.4.0's unbounded-growth behaviour.
type FileLogger struct {
	mu     sync.Mutex
	file   *os.File
	enc    *json.Encoder
	rotCfg RotationConfig
}

// NewFileLogger creates a new file-based audit logger.
//
// Schema v2: if the target file does not exist or is empty, the logger
// writes a single {"_meta":{"schema_version":2,...}} header line before any
// entries. Existing non-empty files are left alone — the v0.4.0_to_v0.4.1
// migration is responsible for rewriting legacy (headerless, v1) files.
// Query() tolerates both cases transparently.
func NewFileLogger(path string) (*FileLogger, error) {
	// Determine if the file pre-exists and has content BEFORE opening in
	// append mode. os.Stat returns ENOENT for missing files, which is fine.
	needsHeader := false
	if info, err := os.Stat(path); os.IsNotExist(err) {
		needsHeader = true
	} else if err != nil {
		return nil, fmt.Errorf("stat audit log: %w", err)
	} else if info.Size() == 0 {
		needsHeader = true
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	l := &FileLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}

	if needsHeader {
		env := metaEnvelope{Meta: MetaRecord{
			SchemaVersion: CurrentSchemaVersion,
			CreatedAt:     time.Now().UTC(),
		}}
		// Write the meta line directly (not through l.enc) so a failure here
		// surfaces immediately rather than being buffered.
		if err := l.enc.Encode(env); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("write schema header: %w", err)
		}
	}

	return l, nil
}

// Log writes an audit entry to the log file.
//
// When RotationConfig.MaxSize is non-zero, the underlying file is stat'd
// after a successful encode and rotateLocked() fires if the live file has
// reached the size threshold. Rotation errors are returned to the caller
// because the entry that triggered rotation has already been persisted —
// a rotation failure here is a signal the operator needs to act on, not a
// write that silently dropped data.
func (l *FileLogger) Log(entry Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	if err := l.enc.Encode(entry); err != nil {
		return err
	}

	if l.rotCfg.MaxSize > 0 {
		if info, err := l.file.Stat(); err == nil && info.Size() >= l.rotCfg.MaxSize {
			if err := l.rotateLocked(); err != nil {
				return fmt.Errorf("audit rotation: %w", err)
			}
		}
	}
	return nil
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

	// skip counts remaining matches to discard before results are collected.
	// A negative Offset is treated as zero (defensive: handler should clamp).
	skip := filter.Offset
	if skip < 0 {
		skip = 0
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		// Skip schema-v2 meta header lines — they are not audit entries.
		// Cheap prefix check avoids paying the JSON-parse cost on every line.
		if bytes.HasPrefix(bytes.TrimLeft(line, " \t"), metaLinePrefix) {
			continue
		}

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip corrupt lines
		}

		if !matchesFilter(entry, filter) {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		results = append(results, entry)

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

// ReadMeta returns the schema-v2 meta record from the first line of path.
// Returns (nil, nil) if the file is headerless (v0.4.0 legacy format) or
// empty, so callers can distinguish "no header" from "read error".
//
// Refuses files whose schema_version is newer than CurrentSchemaVersion —
// running an old binary against a newer file is an obvious operator error.
func ReadMeta(path string) (*MetaRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	br := bufio.NewReader(f)
	line, err := br.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read first line: %w", err)
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if !bytes.HasPrefix(trimmed, metaLinePrefix) {
		// Legacy headerless file — not an error, just no meta.
		return nil, nil
	}

	var env metaEnvelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, fmt.Errorf("parse meta header: %w", err)
	}
	if env.Meta.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("audit file %s has schema_version=%d; this binary understands up to %d — upgrade the binary or downgrade the file",
			path, env.Meta.SchemaVersion, CurrentSchemaVersion)
	}
	return &env.Meta, nil
}
