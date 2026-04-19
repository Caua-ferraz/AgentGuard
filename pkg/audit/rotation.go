package audit

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/metrics"
)

// ArchiveTimestampFormat is the format used to suffix archived audit files.
// Lexicographic order matches chronological order, which lets prune walk
// os.ReadDir without parsing each name back to a time.Time.
const ArchiveTimestampFormat = "20060102T150405Z"

// RotationConfig configures size-triggered rotation for FileLogger.
//
// The zero value disables rotation entirely — v0.4.0 behaviour.
//
// When MaxSize > 0, after every successful Log() the current file size is
// checked and rotateLocked() fires if the file meets or exceeds MaxSize.
// Rotation is synchronous; the caller's Log() blocks until the rename +
// new-file + header write is done. Expected cost: one stat + one rename +
// one file open + ~80 bytes encode. At default 100 MB thresholds this is
// milliseconds every few hundred thousand entries.
type RotationConfig struct {
	// MaxSize is the live-file size threshold in bytes. 0 disables rotation.
	MaxSize int64
	// MaxFiles caps the number of archived files kept after pruning. Older
	// archives (by timestamp suffix) are deleted first. 0 means keep all.
	MaxFiles int
	// Compress, when true, gzips the archive file after rename and removes
	// the uncompressed copy. A gzip failure leaves the uncompressed archive
	// in place — pruning still counts it.
	Compress bool
}

// NewFileLoggerWithRotation is NewFileLogger + rotation policy. The
// configuration is captured at construction; mutating it after the fact has
// no effect.
func NewFileLoggerWithRotation(path string, cfg RotationConfig) (*FileLogger, error) {
	l, err := NewFileLogger(path)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.rotCfg = cfg
	l.mu.Unlock()
	return l, nil
}

// rotateLocked closes the live file, renames it to a timestamped archive,
// optionally compresses that archive, opens a fresh live file, and writes a
// schema-v2 meta header whose RotatedFrom field names the archive's basename.
//
// Must be called with l.mu held.
//
// Failure modes:
//   - If close/rename fails, the logger is left in a usable state only if the
//     rename did not run. Any partial step returns an error so the caller
//     knows an entry may not have flushed.
//   - Gzip failure is logged but not surfaced — the uncompressed archive is
//     still a valid audit record.
//   - Prune failure is logged but not surfaced — too many archives is an
//     operational concern, not a data-loss one.
func (l *FileLogger) rotateLocked() error {
	path := l.file.Name()
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close pre-rotate: %w", err)
	}

	ts := time.Now().UTC().Format(ArchiveTimestampFormat)
	archivePath := fmt.Sprintf("%s.%s", path, ts)

	if err := os.Rename(path, archivePath); err != nil {
		// Rename failed — try to reopen the original so the logger is not
		// permanently broken. If that also fails we're in real trouble.
		if f, reopenErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions); reopenErr == nil {
			l.file = f
			l.enc = json.NewEncoder(f)
		}
		return fmt.Errorf("rename to archive: %w", err)
	}

	finalArchive := archivePath
	if l.rotCfg.Compress {
		gzPath := archivePath + ".gz"
		if err := gzipFile(archivePath, gzPath); err != nil {
			log.Printf("WARN: gzip rotated audit file %s: %v (leaving uncompressed)", archivePath, err)
		} else {
			if err := os.Remove(archivePath); err != nil {
				log.Printf("WARN: remove uncompressed archive %s: %v", archivePath, err)
			} else {
				finalArchive = gzPath
			}
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, DefaultFilePermissions)
	if err != nil {
		return fmt.Errorf("reopen live file after rotate: %w", err)
	}
	l.file = f
	l.enc = json.NewEncoder(f)

	env := metaEnvelope{Meta: MetaRecord{
		SchemaVersion: CurrentSchemaVersion,
		CreatedAt:     time.Now().UTC(),
		RotatedFrom:   filepath.Base(finalArchive),
	}}
	if err := l.enc.Encode(env); err != nil {
		return fmt.Errorf("write post-rotate header: %w", err)
	}

	if l.rotCfg.MaxFiles > 0 {
		if err := pruneArchives(path, l.rotCfg.MaxFiles); err != nil {
			log.Printf("WARN: audit archive prune failed: %v", err)
		}
	}

	// Count only successful rotations: a half-completed rotate returns above
	// before we reach here, and observability would otherwise be misleading
	// (a stuck rotation doesn't "count" as a rotation operators should see).
	metrics.IncAuditRotation()
	return nil
}

// gzipFile streams src into dst.gz. dst is created with mode 0600 since
// archived audit logs carry the same secrecy constraint as the live file.
func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, DefaultFilePermissions)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)

	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// pruneArchives removes the oldest archive files for basePath until no more
// than keep remain. "Oldest" is defined by timestamp suffix — since
// ArchiveTimestampFormat is lex-sorted, sort.Strings(asc) yields oldest-first.
//
// Both `<basePath>.<ts>` and `<basePath>.<ts>.gz` are considered archives.
// The live `<basePath>` itself is never deleted.
func pruneArchives(basePath string, keep int) error {
	dir := filepath.Dir(basePath)
	base := filepath.Base(basePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	var archives []string
	prefix := base + "."
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".gz")
		// Accept only names that look like our timestamp (14 chars + Z).
		if len(suffix) != len(ArchiveTimestampFormat) {
			continue
		}
		archives = append(archives, filepath.Join(dir, name))
	}

	if len(archives) <= keep {
		return nil
	}

	sort.Strings(archives) // ascending → oldest first
	excess := len(archives) - keep
	for _, p := range archives[:excess] {
		if err := os.Remove(p); err != nil {
			// Surface the error but keep pruning the rest.
			log.Printf("WARN: remove archive %s: %v", p, err)
		}
	}
	return nil
}
