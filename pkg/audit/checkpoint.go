package audit

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// CheckpointSuffix is appended to an audit log path to produce the companion
// checkpoint file written by the startup replay seeder.
const CheckpointSuffix = ".replay-checkpoint"

// maxRotationChainDepth bounds the rotated_from walk so a corrupt or
// self-referential header chain can never spin the startup replay forever.
// Archive names are timestamped and unique, so a real chain is never cyclic;
// the bound is purely defensive.
const maxRotationChainDepth = 10000

// DecisionCounts is the cumulative decision tally recorded in a Checkpoint.
// It is what lets the decision counters on /metrics and /api/stats survive a
// restart: the next boot seeds the counters from these values and then
// replays only the entries written after Offset.
//
// Total counts every replayed entry; the three named fields count the
// well-known decisions. Total - (Allow+Deny+RequireApproval) is the number of
// entries carrying an unknown decision string (see Other).
type DecisionCounts struct {
	Total           uint64 `json:"total"`
	Allow           uint64 `json:"allow"`
	Deny            uint64 `json:"deny"`
	RequireApproval uint64 `json:"require_approval"`
}

// add tallies one replayed entry.
func (c *DecisionCounts) add(d policy.Decision) {
	c.Total++
	switch d {
	case policy.Allow:
		c.Allow++
	case policy.Deny:
		c.Deny++
	case policy.RequireApproval:
		c.RequireApproval++
	}
}

// Other returns the number of counted entries whose decision was none of the
// three well-known values.
func (c DecisionCounts) Other() uint64 {
	known := c.Allow + c.Deny + c.RequireApproval
	if known > c.Total {
		return 0
	}
	return c.Total - known
}

// Checkpoint records how far the startup seeder scanned into the audit log,
// so the next boot can resume from the stored offset instead of re-reading
// gigabytes of history.
//
// Offset and AuditSize describe the live audit file at the time the
// checkpoint was written. FileID identifies WHICH file they describe: it is
// the live file's schema-v2 `_meta.created_at`, which rotation rewrites for
// every new live file. A boot whose live file carries a different FileID
// knows the log rotated in between and follows the `_meta.rotated_from`
// chain back to the checkpointed segment rather than trusting a byte offset
// into an unrelated file. FileID is empty for legacy headerless files, in
// which case the older size heuristic applies (see ReplayWithCheckpoint).
//
// Counts is the cumulative decision tally as of Offset. It is what makes the
// counters restart-safe. A checkpoint without Counts (written by a pre-1.0.1
// binary) triggers one full replay so the lifetime totals are re-established
// before the next checkpoint is written.
//
// Both new fields are additive and omitted when empty, so an older binary
// reading a newer checkpoint sees exactly the shape it always did.
type Checkpoint struct {
	Offset    int64           `json:"offset"`
	AuditSize int64           `json:"audit_size"`
	FileID    string          `json:"file_id,omitempty"`
	Counts    *DecisionCounts `json:"counts,omitempty"`
}

// CheckpointPath returns the companion checkpoint file path for an audit
// log: `<audit-log-path>` + CheckpointSuffix. Every reader and writer of the
// checkpoint — the server's startup seeder, the `agentguard migrate`
// subcommand, and the startup migration that invalidates it — MUST derive
// the path through this function so they can never disagree about where the
// file lives.
func CheckpointPath(auditPath string) string {
	return auditPath + CheckpointSuffix
}

// checkpointPath is the package-internal alias kept for existing callers.
func checkpointPath(auditPath string) string {
	return CheckpointPath(auditPath)
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
//
// ReplayFrom is the pre-1.0.1 primitive and is kept unchanged for embedders.
// It knows nothing about rotation or persisted counts; the server uses
// ReplayWithCheckpoint.
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

	if err := replayFile(auditPath, start, fn); err != nil {
		// Replay is best-effort at startup — counters being off after a
		// truncated replay is preferable to refusing to start. We surface
		// the error so the caller (NewServer) can log it.
		return info.Size(), err
	}
	return info.Size(), nil
}

// ReplayWithCheckpoint is the restart-safe startup replay. It scans every
// audit entry written after cp (or every entry, when cp is nil or predates
// persisted counts), invokes fn for each, and returns the Checkpoint the
// caller should persist for the next boot.
//
// The returned Checkpoint.Counts is the LIFETIME decision tally: cp.Counts
// carried forward plus every entry replayed in this call. Seeding the
// decision counters from it — rather than incrementing per replayed entry —
// is what makes `agentguard_checks_total` and `/api/stats` survive restarts
// with the same totals a never-restarted process would show.
//
// Resume rules, in order:
//
//  1. cp nil, or cp without Counts (legacy checkpoint): full replay of the
//     live file from byte 0. The one-time cost re-establishes the lifetime
//     tally; every later boot resumes.
//  2. cp.FileID set and equal to the live file's `_meta.created_at`: same
//     file, resume at cp.Offset.
//  3. cp.FileID set but different: the log rotated since the checkpoint.
//     Walk `_meta.rotated_from` from the live file back through the
//     archives (gzip or plain). The archive whose header matches cp.FileID
//     is replayed from cp.Offset; every newer archive and the live file are
//     replayed from 0, oldest first. If the chain ends before a match (the
//     checkpointed segment was pruned), everything reachable is replayed
//     from 0 and cp.Counts is still carried forward — the pruned entries
//     were counted before they were pruned.
//  4. cp.FileID empty (headerless legacy live file): the size heuristic —
//     resume at cp.Offset when the file has only grown, else full replay.
//
// Missing audit file: returns a zero Checkpoint and nil — a fresh install
// has nothing to replay. A scan error on any segment is logged, the
// remaining segments are still replayed, and the first error is returned
// alongside the (partial) checkpoint so the caller can decide whether to
// persist it.
func ReplayWithCheckpoint(auditPath string, cp *Checkpoint, fn func(Entry)) (Checkpoint, error) {
	info, err := os.Stat(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Checkpoint{}, nil
		}
		return Checkpoint{}, err
	}

	liveMeta, metaErr := ReadMeta(auditPath)
	if metaErr != nil {
		// A header we cannot parse is treated as "no identity": the size
		// heuristic still applies and startup is not blocked by the replay.
		log.Printf("WARN audit: replay could not read %s header (%v); resuming without file identity", auditPath, metaErr)
		liveMeta = nil
	}

	segs := planReplaySegments(auditPath, info.Size(), liveMeta, cp)

	var counts DecisionCounts
	if cp != nil && cp.Counts != nil {
		counts = *cp.Counts
	}
	wrapped := func(e Entry) {
		counts.add(e.Result.Decision)
		fn(e)
	}

	var firstErr error
	for _, seg := range segs {
		if err := replayFile(seg.path, seg.start, wrapped); err != nil {
			log.Printf("WARN audit: replay of %s from offset %d failed (%v) — counters may be under-seeded", seg.path, seg.start, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	next := Checkpoint{
		Offset:    info.Size(),
		AuditSize: info.Size(),
		FileID:    fileIDOf(liveMeta),
		Counts:    &counts,
	}
	return next, firstErr
}

// replaySegment is one file to scan and the byte offset (in the uncompressed
// stream) to start from.
type replaySegment struct {
	path  string
	start int64
}

// planReplaySegments decides which files to scan and from where, per the
// resume rules documented on ReplayWithCheckpoint. The result is ordered
// oldest-first so counts and the require_prior index see entries in write
// order.
func planReplaySegments(livePath string, liveSize int64, liveMeta *MetaRecord, cp *Checkpoint) []replaySegment {
	full := []replaySegment{{path: livePath, start: 0}}
	if cp == nil || cp.Counts == nil {
		// Rule 1: nothing, or a legacy checkpoint with no tally to carry.
		return full
	}

	if cp.FileID != "" {
		if fileIDOf(liveMeta) == cp.FileID {
			// Rule 2: same file.
			if cp.Offset >= 0 && cp.Offset <= liveSize {
				return []replaySegment{{path: livePath, start: cp.Offset}}
			}
			return full
		}
		// Rule 3: rotated since the checkpoint — walk the chain.
		segs := []replaySegment{{path: livePath, start: 0}}
		seen := map[string]bool{livePath: true}
		dir := filepath.Dir(livePath)
		cur := liveMeta
		for depth := 0; cur != nil && cur.RotatedFrom != "" && depth < maxRotationChainDepth; depth++ {
			// Base() guards against a header that names a path outside the
			// audit directory; archives always live next to the live file.
			p := filepath.Join(dir, filepath.Base(cur.RotatedFrom))
			if seen[p] {
				break
			}
			seen[p] = true
			m, err := readMetaAny(p)
			if err != nil {
				log.Printf("WARN audit: rotation chain ends at %s (%v); replaying everything reachable", p, err)
				break
			}
			if fileIDOf(m) == cp.FileID {
				segs = append(segs, replaySegment{path: p, start: cp.Offset})
				reverseSegments(segs)
				return segs
			}
			segs = append(segs, replaySegment{path: p, start: 0})
			cur = m
		}
		reverseSegments(segs)
		return segs
	}

	// Rule 4: legacy headerless live file — size heuristic.
	if cp.AuditSize <= liveSize && cp.Offset <= liveSize && cp.Offset >= 0 {
		return []replaySegment{{path: livePath, start: cp.Offset}}
	}
	return full
}

func reverseSegments(s []replaySegment) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// fileIDOf derives the checkpoint identity of a segment from its header.
// Empty for headerless (legacy) files.
func fileIDOf(m *MetaRecord) string {
	if m == nil || m.CreatedAt.IsZero() {
		return ""
	}
	return m.CreatedAt.UTC().Format(time.RFC3339Nano)
}

// readMetaAny reads the schema header of a live file or a rotated archive,
// transparently decompressing `.gz` archives.
func readMetaAny(path string) (*MetaRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", path, err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	return readMetaFrom(r, path)
}

// replayFile scans one segment from start, decompressing `.gz` archives. For
// a gzip archive the offset is in the uncompressed stream, so the reader
// discards that many bytes before scanning.
func replayFile(path string, start int64, fn func(Entry)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gunzip %s: %w", path, err)
		}
		defer func() { _ = gz.Close() }()
		if start > 0 {
			if _, err := io.CopyN(io.Discard, gz, start); err != nil {
				if err == io.EOF {
					return nil // checkpoint sits at or past the end: nothing new
				}
				return err
			}
		}
		r = gz
	} else if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return err
		}
	}
	return replayReader(r, path, fn)
}

// replayReader is the shared line scanner: skips blank and `_meta` lines,
// counts and skips unparseable lines (they are visible on /metrics as
// agentguard_audit_corrupt_lines_total, exactly as Query reports them), and
// invokes fn for every well-formed entry.
func replayReader(r io.Reader, name string, fn func(Entry)) error {
	scanner := bufio.NewScanner(r)
	// 4 MiB max line — match Query()'s headroom so a single oversize entry
	// does not silently abort the replay (bufio.ErrTooLong otherwise stops
	// the scan with no signal to the caller).
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	corruptLogged := false
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
			metrics.IncAuditCorruptLine()
			if !corruptLogged {
				log.Printf("WARN audit: replay skipping corrupt line in %s (%v)", name, err)
				corruptLogged = true
			}
			continue
		}
		fn(entry)
	}

	if err := scanner.Err(); err != nil {
		// Replay is best-effort at startup — counters being off after a
		// truncated replay is preferable to refusing to start. Bump the
		// corrupt-lines counter so /metrics shows the degradation.
		metrics.IncAuditCorruptLine()
		log.Printf("WARN audit: replay scanner error on %s (%v) — counters may be under-seeded", name, err)
		return fmt.Errorf("replay scan: %w", err)
	}
	return nil
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
