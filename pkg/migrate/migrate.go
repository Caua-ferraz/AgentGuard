// Package migrate coordinates on-disk schema migrations for AgentGuard.
//
// Migrations are versioned transitions of persistent state (audit log,
// checkpoint files, rotated archives). Each migration lives under its own
// subpackage (pkg/migrate/vNNN_to_vMMM/), implements the Migration interface,
// and registers itself at init() time via Register().
//
// There are two entry points:
//
//   - RunStartup(ctx, env): called from main.go before the server binds. Every
//     registered migration whose Detect() returns true runs in registration
//     order. Any error aborts startup — we never proceed past a failed
//     migration, because half-migrated state is worse than not upgrading.
//
//   - RunCLI(ctx, env, args): backs the `agentguard migrate` subcommand.
//     Supports --dry-run (log intended actions without touching disk),
//     --id=<migration-id> (run a specific migration out of startup order, for
//     operators who need to re-run one explicitly), and a few convenience
//     flags documented in the subcommand help text.
//
// The framework is deliberately stdlib-only: no external deps, no global
// state that survives Reset(), and every migration receives its paths and
// logger through the Env struct rather than reading from package-level
// variables. That keeps migrations testable without touching the real disk.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
)

// Migration is the contract every on-disk migration implements. Implementations
// live in pkg/migrate/vNNN_to_vMMM/ and register themselves via Register().
type Migration interface {
	// ID is a stable identifier used in logs, metrics, and the CLI flag.
	// Convention: "vNNN_to_vMMM", e.g. "v040_to_v041".
	ID() string

	// FromVersion is the schema version this migration accepts as input.
	// Detect() must fail if observed input is anything else.
	FromVersion() string

	// ToVersion is the schema version this migration produces.
	ToVersion() string

	// Description is a one-line human-readable summary for CLI help and log
	// output. No trailing period, no newlines.
	Description() string

	// Detect reports whether the migration should run against the current
	// on-disk state. Returns (true, nil) if Migrate() should execute,
	// (false, nil) if state is already at ToVersion (or otherwise not this
	// migration's concern), and (_, err) on read/parse failure. Read-only —
	// must not modify disk.
	Detect(ctx context.Context, env Env) (bool, error)

	// Migrate performs the transition. When dryRun is true it must log the
	// intended actions without touching disk. On error the on-disk state
	// must be left unchanged — implementations typically stage output in a
	// temp file and atomically rename on success.
	Migrate(ctx context.Context, env Env, dryRun bool) (Result, error)

	// Verify checks post-migration invariants. Called after a successful
	// Migrate() and again on startup when resuming after a crash, to ensure
	// previous output is still intact. Must be idempotent.
	Verify(ctx context.Context, env Env) error
}

// Env carries everything a migration may need from the host process. Paths
// are passed explicitly rather than via package-level globals so migrations
// stay testable in isolation.
type Env struct {
	// AuditLogPath is the path to the live audit.jsonl file.
	AuditLogPath string

	// CheckpointPath is the path to the .replay-checkpoint file.
	CheckpointPath string

	// BackupDir is the directory under which rollback artifacts
	// (e.g. audit.jsonl.v040-backup) are written. Empty => same dir as
	// AuditLogPath.
	BackupDir string

	// Logger is where migrations emit progress. nil => stdlib log package.
	Logger *log.Logger

	// Stdout is where CLI output is written. nil => os.Stdout. Primarily
	// used by RunCLI; migrations themselves should log via Logger.
	Stdout io.Writer
}

// Result is the summary a migration returns. Stats keys are free-form and
// documented per migration; common keys include "records_migrated",
// "bytes_written", and "backup_path" (stored as a stat for convenience
// although it is not a count — operators tend to look for it there).
type Result struct {
	MigrationID string
	From        string
	To          string
	DryRun      bool
	Stats       map[string]int64
	Notes       []string
}

// registry holds every migration registered at init() time. It is not reset
// between RunStartup calls because migrations are immutable and the CLI
// and startup paths share the same registered set.
var (
	regMu      sync.RWMutex
	registered []Migration
)

// Register adds a Migration to the registry. Typically called from an init()
// in the migration's subpackage. Duplicate IDs cause a panic — the registry
// is tiny and duplication indicates a programming error, not something to
// silently tolerate.
func Register(m Migration) {
	if m == nil {
		panic("migrate: Register called with nil Migration")
	}
	regMu.Lock()
	defer regMu.Unlock()
	for _, existing := range registered {
		if existing.ID() == m.ID() {
			panic(fmt.Sprintf("migrate: duplicate Migration ID %q", m.ID()))
		}
	}
	registered = append(registered, m)
}

// Registered returns a copy of the registry. Test-only helper; production
// code should call RunStartup or RunCLI instead.
func Registered() []Migration {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Migration, len(registered))
	copy(out, registered)
	return out
}

// resetRegistry clears the registry. Exported only for tests via testing.go.
func resetRegistry() {
	regMu.Lock()
	registered = nil
	regMu.Unlock()
}

// logger returns env.Logger or the stdlib default.
func (e Env) logger() *log.Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return log.Default()
}

// RunStartup runs every registered migration whose Detect() returns true, in
// registration order. If any migration errors, startup aborts — the caller
// (main.go) should log the error and exit non-zero.
//
// RunStartup is safe to call when no migrations are registered (a fresh
// install) or when all migrations report Detect=false (an already-upgraded
// install). In both cases it returns nil after logging a single summary
// line.
func RunStartup(ctx context.Context, env Env) error {
	lg := env.logger()
	migs := Registered()
	ran := 0
	for _, m := range migs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("migrate: startup cancelled before %s: %w", m.ID(), err)
		}
		need, err := m.Detect(ctx, env)
		if err != nil {
			return fmt.Errorf("migrate: detect %s: %w", m.ID(), err)
		}
		if !need {
			continue
		}
		lg.Printf("migrate: running %s (%s -> %s): %s", m.ID(), m.FromVersion(), m.ToVersion(), m.Description())
		res, err := m.Migrate(ctx, env, false)
		if err != nil {
			return fmt.Errorf("migrate: %s failed: %w", m.ID(), err)
		}
		if err := m.Verify(ctx, env); err != nil {
			return fmt.Errorf("migrate: %s post-verify failed: %w", m.ID(), err)
		}
		lg.Printf("migrate: %s complete (%s)", m.ID(), summarizeStats(res))
		ran++
	}
	if ran == 0 && len(migs) > 0 {
		lg.Printf("migrate: no migrations needed (%d registered, all Detect=false)", len(migs))
	}
	return nil
}

// CLIOptions is the parsed form of the `agentguard migrate` subcommand flags.
type CLIOptions struct {
	DryRun           bool
	ID               string // run only this migration, skip others
	List             bool   // list registered migrations and exit
	ResetCheckpoint  bool   // delete the replay checkpoint before running
	AuditLogPath     string
	CheckpointPath   string
	BackupDir        string
}

// ErrMigrationNotFound is returned by RunCLI when --id names a migration that
// is not in the registry.
var ErrMigrationNotFound = errors.New("migration not found in registry")

// RunCLI executes the `agentguard migrate` subcommand semantics:
//   - --list: print the registry and return.
//   - --id=X: run only migration X (even if Detect=false — operator override).
//   - default: run every migration whose Detect() is true, like RunStartup
//     does, but honoring --dry-run.
//
// Errors are returned rather than Fatal'd so main.go controls the exit code
// and the tests can drive the same code path without os.Exit.
func RunCLI(ctx context.Context, env Env, opts CLIOptions) error {
	out := env.Stdout
	if out == nil {
		out = discardIfNilStdout()
	}
	migs := Registered()

	if opts.List {
		return listMigrations(out, migs)
	}

	if opts.ID != "" {
		for _, m := range migs {
			if m.ID() == opts.ID {
				return runOne(ctx, env, m, opts.DryRun)
			}
		}
		return fmt.Errorf("%w: %s", ErrMigrationNotFound, opts.ID)
	}

	// Default: run every migration whose Detect() reports true.
	lg := env.logger()
	ran := 0
	for _, m := range migs {
		if err := ctx.Err(); err != nil {
			return err
		}
		need, err := m.Detect(ctx, env)
		if err != nil {
			return fmt.Errorf("detect %s: %w", m.ID(), err)
		}
		if !need {
			continue
		}
		if err := runOne(ctx, env, m, opts.DryRun); err != nil {
			return err
		}
		lg.Printf("migrate: %s done", m.ID())
		ran++
	}
	fmt.Fprintf(out, "migrate: %d migration(s) processed\n", ran)
	return nil
}

func runOne(ctx context.Context, env Env, m Migration, dryRun bool) error {
	lg := env.logger()
	lg.Printf("migrate: running %s (%s -> %s)%s", m.ID(), m.FromVersion(), m.ToVersion(),
		dryRunSuffix(dryRun))
	res, err := m.Migrate(ctx, env, dryRun)
	if err != nil {
		return fmt.Errorf("%s: %w", m.ID(), err)
	}
	if !dryRun {
		if err := m.Verify(ctx, env); err != nil {
			return fmt.Errorf("%s post-verify: %w", m.ID(), err)
		}
	}
	lg.Printf("migrate: %s result: %s", m.ID(), summarizeStats(res))
	for _, n := range res.Notes {
		lg.Printf("migrate: %s note: %s", m.ID(), n)
	}
	return nil
}

func listMigrations(out io.Writer, migs []Migration) error {
	if len(migs) == 0 {
		fmt.Fprintln(out, "No migrations registered.")
		return nil
	}
	// Sort by ID so list output is stable even if registration order varies.
	sorted := make([]Migration, len(migs))
	copy(sorted, migs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })
	fmt.Fprintln(out, "Registered migrations:")
	for _, m := range sorted {
		fmt.Fprintf(out, "  %s  %s -> %s  %s\n", m.ID(), m.FromVersion(), m.ToVersion(), m.Description())
	}
	return nil
}

func summarizeStats(r Result) string {
	parts := make([]string, 0, len(r.Stats)+1)
	if r.DryRun {
		parts = append(parts, "dry-run")
	}
	// Sort keys for stable log output.
	keys := make([]string, 0, len(r.Stats))
	for k := range r.Stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, r.Stats[k]))
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, " ")
}

func dryRunSuffix(dryRun bool) string {
	if dryRun {
		return " [dry-run]"
	}
	return ""
}

// discardIfNilStdout returns an io.Writer that drops writes. Used when a
// caller passed env.Stdout = nil — we avoid nil-pointer panics without
// forcing callers to import io.Discard themselves.
func discardIfNilStdout() io.Writer { return io.Discard }
