package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// CheckpointSuffix is appended to an audit log path to produce the companion
// checkpoint file written by the startup replay seeder.
const CheckpointSuffix = ".replay-checkpoint"

// Checkpoint records how far the startup seeder scanned into the audit log,
// so the next boot can resume from the stored offset instead of re-reading
// gigabytes of history.
//
// AuditSize is the file size when the checkpoint was written. If the current
// audit file is smaller at the next boot, the log was truncated or rotated
// and the offset must be discarded — we fall back to scanning from zero.
type Checkpoint struct {
	Offset    int64 `json:"offset"`
	AuditSize int64 `json:"audit_size"`
}

// checkpointPath returns the companion checkpoint file path for an audit log.
func checkpointPath(auditPath string) string {
	return auditPath + CheckpointSuffix
}

// ReadCheckpoint loads the checkpoint for auditPath. Returns (nil, nil) when
// the checkpoint file is missing — this is the expected first-boot state and
// must not be treated as an error. A corrupt checkpoint is also downgraded
// to (nil, nil) so an unreadable marker simply triggers a full rescan rather
// than aborting startup.
func ReadCheckpoint(auditPath string) (*Checkpoint, error) {
	b, err := os.ReadFile(checkpointPath(auditPath))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		return nil, nil
	}
	return &cp, nil
}

// WriteCheckpoint persists cp atomically via write-then-rename. A partial
// write crash therefore leaves either the old checkpoint or no change —
// never a half-written file.
func WriteCheckpoint(auditPath string, cp Checkpoint) error {
	path := checkpointPath(auditPath)
	tmp := path + ".tmp"
	b, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReplayFrom scans auditPath starting at cp.Offset (or 0 if cp is nil or
// stale) and invokes fn for every valid entry. Returns the end-of-file
// offset reached during the scan — the caller should persist this back as
// the next checkpoint so subsequent boots skip work already done.
//
// Staleness detection: if cp.AuditSize exceeds the current file size, the
// file has been truncated or rotated; we discard the checkpoint and rescan
// from the beginning so counters stay accurate.
//
// Missing audit file: returns (0, nil) — a fresh install has nothing to
// replay, and that is not an error.
func ReplayFrom(auditPath string, cp *Checkpoint, fn func(Entry)) (int64, error) {
	info, err := os.Stat(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	start := int64(0)
	if cp != nil && cp.AuditSize <= info.Size() && cp.Offset <= info.Size() && cp.Offset >= 0 {
		start = cp.Offset
	}

	f, err := os.Open(auditPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return 0, err
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(bytes.TrimLeft(line, " \t"), metaLinePrefix) {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		fn(entry)
	}

	return info.Size(), nil
}

// Path returns the filesystem path of the underlying audit log, or "" if
// the FileLogger has no open file. Used by callers that need to co-locate
// auxiliary files (checkpoint, rotation markers) next to the log.
func (l *FileLogger) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return ""
	}
	return l.file.Name()
}
