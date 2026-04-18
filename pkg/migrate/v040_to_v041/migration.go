// Package v040_to_v041 adds the schema-v2 `_meta` header to a pre-existing
// v0.4.0 audit log. It is the first real migration shipped by AgentGuard and
// exists primarily to de-risk a rollback: the pre-migration bytes are
// preserved at `<audit-log>.v040-backup` so an operator who downgrades to
// v0.4.0 can mv the backup back over the live file and resume.
//
// Detect condition: audit file exists, is non-empty, and its first line is
// NOT a meta envelope (i.e. the file is a legacy headerless JSONL written by
// v0.4.0). Fresh installs and already-migrated v2 files both return false.
//
// Safety model:
//   - Migration streams the original bytes into a temp file prefixed by a
//     newly-minted `_meta` line, then atomically renames the temp file over
//     the original. A crash at any point leaves either the original bytes
//     intact or the fully-written v2 file intact; no half-written state.
//   - Before the rename, the original is copied to `.v040-backup` in the
//     same directory. The backup is only written once — if it already exists
//     (e.g. a previous partial run) it is left untouched so the earliest
//     pre-migration state wins.
//   - Verify() re-parses the meta line and refuses to call the migration
//     successful unless SchemaVersion matches CurrentSchemaVersion.
package v040_to_v041

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/migrate"
)

// logOrDefault is the local analogue of env.logger() — the framework keeps
// that helper unexported so each migration duplicates this two-line shim.
func logOrDefault(env migrate.Env) *log.Logger {
	if env.Logger != nil {
		return env.Logger
	}
	return log.Default()
}

// BackupSuffix is appended to the audit log basename to form the rollback
// copy written by this migration. Downgrading to v0.4.0 is a matter of
// renaming the backup back over the live file.
const BackupSuffix = ".v040-backup"

// MigrationID is the stable identifier used in logs and the --id CLI flag.
const MigrationID = "v040_to_v041"

func init() {
	migrate.Register(&Migration{})
}

// Migration implements migrate.Migration for the v0.4.0 → v0.4.1 audit file
// upgrade.
type Migration struct{}

// ID returns the stable migration identifier.
func (*Migration) ID() string { return MigrationID }

// FromVersion is the on-disk version this migration accepts as input.
// v0.4.0 audit files are headerless — we report this as "1" in the framework's
// schema_version space, consistent with FILE_FORMATS.md.
func (*Migration) FromVersion() string { return "1" }

// ToVersion is the on-disk version produced by a successful run.
func (*Migration) ToVersion() string { return fmt.Sprintf("%d", audit.CurrentSchemaVersion) }

// Description is the one-line summary shown in `agentguard migrate --list`.
func (*Migration) Description() string {
	return "Add schema-v2 _meta header to an existing audit log (preserves a .v040-backup rollback copy)"
}

// Detect returns true when the audit file exists, is non-empty, and has no
// `_meta` line — i.e. it is a legacy v0.4.0 file.
func (*Migration) Detect(ctx context.Context, env migrate.Env) (bool, error) {
	if env.AuditLogPath == "" {
		return false, nil
	}
	info, err := os.Stat(env.AuditLogPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat audit log: %w", err)
	}
	if info.Size() == 0 {
		return false, nil
	}
	meta, err := audit.ReadMeta(env.AuditLogPath)
	if err != nil {
		return false, fmt.Errorf("read meta: %w", err)
	}
	// ReadMeta returns (nil, nil) for a headerless legacy file; that is
	// exactly the state this migration fixes.
	return meta == nil, nil
}

// Migrate rewrites the audit file in place with a `_meta` header at the top,
// preserving a `.v040-backup` copy for rollback.
//
// Work is staged in `<path>.v041-migrate.tmp`. On success, the original is
// copied to the backup path, then the temp file is renamed over the original.
// Rename is atomic on POSIX, so readers never see a half-written file.
func (m *Migration) Migrate(ctx context.Context, env migrate.Env, dryRun bool) (migrate.Result, error) {
	res := migrate.Result{
		MigrationID: m.ID(),
		From:        m.FromVersion(),
		To:          m.ToVersion(),
		DryRun:      dryRun,
		Stats:       map[string]int64{},
	}

	if env.AuditLogPath == "" {
		return res, fmt.Errorf("AuditLogPath is empty")
	}

	backupPath := backupPathFor(env)
	info, err := os.Stat(env.AuditLogPath)
	if err != nil {
		return res, fmt.Errorf("stat audit log: %w", err)
	}
	res.Stats["original_bytes"] = info.Size()

	if dryRun {
		logOrDefault(env).Printf("migrate %s: would prepend _meta and write backup to %s (%d bytes)",
			m.ID(), backupPath, info.Size())
		res.Notes = append(res.Notes, "dry-run: no files written")
		return res, nil
	}

	// 1. Stage the rewritten file in a sibling temp file.
	tmpPath := env.AuditLogPath + ".v041-migrate.tmp"
	if err := writeRewritten(env.AuditLogPath, tmpPath); err != nil {
		// Best-effort cleanup; ignore errors.
		_ = os.Remove(tmpPath)
		return res, fmt.Errorf("stage rewritten file: %w", err)
	}

	// 2. Write the rollback backup — but only if we do not already have one.
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		if err := copyFile(env.AuditLogPath, backupPath); err != nil {
			_ = os.Remove(tmpPath)
			return res, fmt.Errorf("write backup %s: %w", backupPath, err)
		}
		res.Notes = append(res.Notes, fmt.Sprintf("backup written: %s", backupPath))
		res.Stats["backup_bytes"] = info.Size()
	} else if err == nil {
		res.Notes = append(res.Notes, fmt.Sprintf("backup already present, not overwritten: %s", backupPath))
	} else {
		_ = os.Remove(tmpPath)
		return res, fmt.Errorf("stat backup: %w", err)
	}

	// 3. Atomic swap.
	if err := os.Rename(tmpPath, env.AuditLogPath); err != nil {
		_ = os.Remove(tmpPath)
		return res, fmt.Errorf("rename temp over audit log: %w", err)
	}

	// 4. The replay checkpoint (if any) is keyed off byte offsets in the old
	// file; after the in-place rewrite those offsets are meaningless. Delete
	// it so the next startup does a fresh scan.
	if env.CheckpointPath != "" {
		if err := os.Remove(env.CheckpointPath); err != nil && !os.IsNotExist(err) {
			res.Notes = append(res.Notes, fmt.Sprintf("WARN: could not remove stale checkpoint %s: %v", env.CheckpointPath, err))
		} else if err == nil {
			res.Notes = append(res.Notes, "removed stale replay checkpoint (offsets invalid after rewrite)")
		}
	}

	postInfo, err := os.Stat(env.AuditLogPath)
	if err == nil {
		res.Stats["final_bytes"] = postInfo.Size()
	}
	return res, nil
}

// Verify ensures the audit log now carries a schema-v2 meta record.
func (m *Migration) Verify(ctx context.Context, env migrate.Env) error {
	if env.AuditLogPath == "" {
		return fmt.Errorf("AuditLogPath is empty")
	}
	meta, err := audit.ReadMeta(env.AuditLogPath)
	if err != nil {
		return fmt.Errorf("post-migration ReadMeta: %w", err)
	}
	if meta == nil {
		return fmt.Errorf("post-migration audit file is still headerless")
	}
	if meta.SchemaVersion != audit.CurrentSchemaVersion {
		return fmt.Errorf("post-migration schema_version=%d, want %d",
			meta.SchemaVersion, audit.CurrentSchemaVersion)
	}
	return nil
}

// backupPathFor places the backup either next to the audit log or under
// env.BackupDir when set. Keeping the live file and its backup in separate
// directories is useful for operators who mount an ephemeral audit volume
// and want the backup on durable storage.
func backupPathFor(env migrate.Env) string {
	base := filepath.Base(env.AuditLogPath) + BackupSuffix
	if env.BackupDir != "" {
		return filepath.Join(env.BackupDir, base)
	}
	return env.AuditLogPath + BackupSuffix
}

// writeRewritten streams `src` into `dst` with a freshly-minted schema-v2
// `_meta` line prepended. `dst` is created with 0600 to match the live
// file's permission.
func writeRewritten(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, audit.DefaultFilePermissions)
	if err != nil {
		return err
	}

	// Write the meta line. MarshalIndent would pretty-print; Marshal gives a
	// compact single-line object which is what the JSONL reader expects.
	metaLine := struct {
		Meta audit.MetaRecord `json:"_meta"`
	}{
		Meta: audit.MetaRecord{
			SchemaVersion: audit.CurrentSchemaVersion,
			CreatedAt:     time.Now().UTC(),
		},
	}
	b, err := json.Marshal(metaLine)
	if err != nil {
		_ = out.Close()
		return err
	}
	if _, err := out.Write(append(b, '\n')); err != nil {
		_ = out.Close()
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// copyFile is a small helper because os.Rename can't cross filesystems and
// env.BackupDir may point at a different mount.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, audit.DefaultFilePermissions)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
