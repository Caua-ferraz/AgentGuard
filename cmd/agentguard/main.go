package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // pprof handlers register on http.DefaultServeMux when --debug-pprof is set
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
	"github.com/Caua-ferraz/AgentGuard/pkg/migrate"
	_ "github.com/Caua-ferraz/AgentGuard/pkg/migrate/v040_to_v041" // register the v0.4.0 → v0.4.1 audit schema migration
	"github.com/Caua-ferraz/AgentGuard/pkg/notify"
	"github.com/Caua-ferraz/AgentGuard/pkg/persist"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
	"github.com/Caua-ferraz/AgentGuard/pkg/store"
)

var (
	version = "0.6.0"
	commit  = "dev"
)

func main() {
	// Best-effort update check: kick off a background goroutine that asks
	// GitHub for the latest release. It prints one line to stderr if the
	// running binary is older. Disabled on dev builds and via
	// AGENTGUARD_NO_UPDATE_CHECK=1. See update_check.go.
	updateDone := startUpdateCheck(version)

	// Subcommands
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	policyFile := serveCmd.String("policy", "configs/default.yaml", "Path to policy file")
	port := serveCmd.Int("port", 8080, "Port to listen on")
	dashboard := serveCmd.Bool("dashboard", false, "Enable web dashboard")
	watch := serveCmd.Bool("watch", false, "Watch policy file for changes")
	auditPath := serveCmd.String("audit-log", "audit.jsonl", "Path to audit log file")
	apiKey := serveCmd.String("api-key", "", "Bearer token for approve/deny endpoints")
	baseURL := serveCmd.String("base-url", "", "External base URL for approval links (default: http://localhost:<port>)")
	allowedOrigin := serveCmd.String("allowed-origin", "", "Exact CORS origin to accept (e.g. https://app.example). Empty means permissive-localhost (any http://localhost:* or http://127.0.0.1:*) for backward compat.")
	tlsTerminated := serveCmd.Bool("tls-terminated-upstream", false, "Issue session cookies with Secure regardless of r.TLS — set when behind a TLS-terminating reverse proxy that does not forward X-Forwarded-Proto")
	sessionCostTTL := serveCmd.Duration("session-cost-ttl", 0, "If > 0, evict session-cost accumulator entries idle longer than this duration (e.g. 24h). Zero disables eviction (entries never expire).")
	sessionCostSweep := serveCmd.Duration("session-cost-sweep-interval", 0, "How often to run the session-cost sweeper. Defaults to max(session-cost-ttl/4, 1m).")
	// Audit log rotation. Defaults aim at production-friendly bounds:
	// 100 MiB live-file ceiling, 30-day retention, 5 archives kept (older
	// archives pruned by oldest-first lex order on the timestamp suffix),
	// gzip on. Set --audit-max-size-mb=0 to disable rotation entirely.
	// See pkg/audit/rotation.go for the rotation contract.
	auditMaxSizeMB := serveCmd.Int("audit-max-size-mb", 100, "Maximum size of the live audit log in MiB before rotation. 0 disables rotation.")
	auditMaxBackups := serveCmd.Int("audit-max-backups", 5, "Maximum number of rotated archives to keep. 0 keeps all archives indefinitely.")
	auditMaxAgeDays := serveCmd.Int("audit-max-age-days", 30, "Maximum age (in days) of archived audit files. Archives older than this are pruned at rotation time. 0 disables age-based pruning.")
	auditCompress := serveCmd.Bool("audit-compress", true, "Gzip rotated archives. Disable to keep them as plain JSONL for grep tooling.")
	// Buffered async audit logger: bounded queue + worker pool + disk-
	// overflow durability so the /v1/check hot path does not wait on the
	// audit mutex. See pkg/audit/buffered.go for the contract.
	auditBuffered := serveCmd.Bool("audit-buffered", true, "Wrap the audit logger in a bounded async queue with disk-overflow durability. Disable to write straight to FileLogger.")
	auditQueueSize := serveCmd.Int("audit-queue-size", 1024, "Bounded queue size for the buffered async logger. Ignored unless --audit-buffered is set.")
	auditWorkers := serveCmd.Int("audit-workers", 4, "Worker goroutines draining the buffered audit queue. Ignored unless --audit-buffered is set.")
	auditOverflowPath := serveCmd.String("audit-overflow-path", "", "Path to the disk-overflow spill file used when the buffered queue saturates. Defaults to <audit-log>.overflow.jsonl. Ignored unless --audit-buffered is set.")
	// Debug pprof. Off by default; when on, the runtime profiler endpoints
	// register under http.DefaultServeMux via the blank import above and we
	// expose them on a second listener bound to 127.0.0.1 only. Operators
	// who want pprof reachable beyond localhost MUST tunnel it explicitly
	// (e.g. `kubectl port-forward`, `ssh -L`) — this is a security floor we
	// will not lower behind a flag.
	debugPprof := serveCmd.Bool("debug-pprof", false, "Expose Go pprof handlers on a separate localhost-only listener (--debug-pprof-port). Off by default; enable for performance investigations only.")
	debugPprofPort := serveCmd.Int("debug-pprof-port", 6060, "Port for the localhost-only pprof listener. Ignored unless --debug-pprof is set.")
	// Durable persistence (v0.6). Zero-config by default: runtime state
	// (approvals, rate-limit buckets, cost accumulators) is written behind to a
	// SQLite database so it survives restarts. The store is NEVER on the
	// /v1/check hot path — a background syncer flushes snapshots on a ≥1s tick
	// and hydrates the in-memory maps on boot. See docs/v0.6-ARCHITECTURE-PLAN.md.
	persistEnabled := serveCmd.Bool("persist", true, "Persist runtime state (approvals, rate-limit buckets, cost accumulators) to a durable store so it survives restarts. Set false for pure in-memory (pre-v0.6 behavior).")
	storeDSN := serveCmd.String("store-dsn", "", "Durable store DSN. Empty => zero-config SQLite at <data-dir>/agentguard.db; a sqlite file path is also accepted. (Postgres is future work.)")
	dataDir := serveCmd.String("data-dir", ".", "Directory for the zero-config SQLite database (agentguard.db). Ignored when --store-dsn is set or --persist=false.")
	auditBackend := serveCmd.String("audit-backend", "file", `Audit storage: "file" (JSONL, default) or "store" (the SQLite store — unifies state+audit in one DB with indexed queries). "store" requires --persist.`)

	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
	validateFile := validateCmd.String("policy", "configs/default.yaml", "Policy file to validate")

	approveCmd := flag.NewFlagSet("approve", flag.ExitOnError)
	approveURL := approveCmd.String("url", "http://localhost:8080", "AgentGuard server URL")
	approveKey := approveCmd.String("api-key", "", "Bearer token (overrides AGENTGUARD_API_KEY)")

	denyCmd := flag.NewFlagSet("deny", flag.ExitOnError)
	denyURL := denyCmd.String("url", "http://localhost:8080", "AgentGuard server URL")
	denyKey := denyCmd.String("api-key", "", "Bearer token (overrides AGENTGUARD_API_KEY)")

	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)
	statusURL := statusCmd.String("url", "http://localhost:8080", "AgentGuard server URL")
	statusKey := statusCmd.String("api-key", "", "Bearer token (overrides AGENTGUARD_API_KEY)")

	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	auditQueryURL := auditCmd.String("url", "http://localhost:8080", "AgentGuard server URL")
	auditAgent := auditCmd.String("agent", "", "Filter by agent ID")
	auditDecision := auditCmd.String("decision", "", "Filter by decision (ALLOW, DENY, REQUIRE_APPROVAL)")
	auditScope := auditCmd.String("scope", "", "Filter by scope")
	auditTransport := auditCmd.String("transport", "", "Filter by integration path (sdk|mcp_gateway|llm_api_proxy)")
	auditLimit := auditCmd.Int("limit", 50, "Max entries to return")
	auditKey := auditCmd.String("api-key", "", "Bearer token (overrides AGENTGUARD_API_KEY)")

	migrateCmd := flag.NewFlagSet("migrate", flag.ExitOnError)
	migrateAuditPath := migrateCmd.String("audit-log", "audit.jsonl", "Path to audit log file")
	migrateCheckpoint := migrateCmd.String("checkpoint", "", "Path to replay checkpoint (default: <audit-dir>/.replay-checkpoint)")
	migrateBackupDir := migrateCmd.String("backup-dir", "", "Directory for rollback backups (default: same dir as --audit-log)")
	migrateDryRun := migrateCmd.Bool("dry-run", false, "Log intended actions without touching disk")
	migrateList := migrateCmd.Bool("list", false, "List registered migrations and exit")
	migrateID := migrateCmd.String("id", "", "Run only the named migration (operator override; runs even if Detect=false)")
	migrateReset := migrateCmd.Bool("reset-checkpoint", false, "Delete the replay checkpoint before running (forces full replay on next start)")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Give the background update check up to 800ms to finish so any
	// deprecation notice lands before subcommand output starts. If the
	// check is still running after the deadline we just move on — the
	// goroutine continues silently and a late print is harmless.
	waitForUpdateCheck(updateDone, 800*time.Millisecond)

	switch os.Args[1] {
	case "serve":
		_ = serveCmd.Parse(os.Args[2:]) // flag.ExitOnError handles errors
		// Fall back to AGENTGUARD_API_KEY env if --api-key not supplied.
		runServe(*policyFile, *port, *dashboard, *watch, *auditPath, resolveAPIKey(*apiKey), *baseURL, *allowedOrigin, *tlsTerminated, *sessionCostTTL, *sessionCostSweep, auditRotationOpts{
			MaxSizeMB:  *auditMaxSizeMB,
			MaxBackups: *auditMaxBackups,
			MaxAgeDays: *auditMaxAgeDays,
			Compress:   *auditCompress,
		}, auditBufferedOpts{
			Enabled:      *auditBuffered,
			QueueSize:    *auditQueueSize,
			Workers:      *auditWorkers,
			OverflowPath: *auditOverflowPath,
		}, pprofOpts{
			Enabled: *debugPprof,
			Port:    *debugPprofPort,
		}, persistOpts{
			Enabled:      *persistEnabled,
			DSN:          *storeDSN,
			DataDir:      *dataDir,
			AuditBackend: *auditBackend,
		})

	case "validate":
		_ = validateCmd.Parse(os.Args[2:])
		runValidate(*validateFile)

	case "approve":
		_ = approveCmd.Parse(os.Args[2:])
		args := approveCmd.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: agentguard approve [flags] <approval-id>")
			os.Exit(1)
		}
		runResolve(*approveURL, args[0], "approve", resolveAPIKey(*approveKey))

	case "deny":
		_ = denyCmd.Parse(os.Args[2:])
		args := denyCmd.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: agentguard deny [flags] <approval-id>")
			os.Exit(1)
		}
		runResolve(*denyURL, args[0], "deny", resolveAPIKey(*denyKey))

	case "status":
		_ = statusCmd.Parse(os.Args[2:])
		runStatus(*statusURL, resolveAPIKey(*statusKey))

	case "audit":
		_ = auditCmd.Parse(os.Args[2:])
		runAuditQuery(*auditQueryURL, *auditAgent, *auditDecision, *auditScope, *auditTransport, *auditLimit, resolveAPIKey(*auditKey))

	case "migrate":
		_ = migrateCmd.Parse(os.Args[2:])
		runMigrate(*migrateAuditPath, *migrateCheckpoint, *migrateBackupDir, *migrateDryRun, *migrateList, *migrateID, *migrateReset)

	case "check":
		// runCheck owns its own flag.FlagSet (with ContinueOnError so
		// usage errors map to exit code 3 rather than the default
		// ExitOnError = 2). Stdin/stdout/stderr are passed explicitly so
		// the function is unit-testable from check_cmd_test.go.
		os.Exit(runCheck(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))

	case "tenant":
		runTenant(os.Args[2:])

	case "version":
		fmt.Printf("agentguard %s (%s)\n", version, commit)

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `AgentGuard — The firewall for AI agents.

Usage:
  agentguard <command> [flags]

Commands:
  serve       Start the AgentGuard server (policy engine, audit log, approval queue, dashboard)
  validate    Validate a policy file
  check       Run a one-shot policy check against a local policy file
  approve     Approve a pending action by ID
  deny        Deny a pending action by ID
  status      Show connected agents and pending actions
  audit       Query the audit log
  tenant      Manage per-tenant policies in the store (put|list|rm)
  migrate     Run on-disk schema migrations (see docs/FILE_FORMATS.md)
  version     Print version information

Run 'agentguard <command> -h' for details on each command.
`)
}

// auditRotationOpts mirrors the --audit-* CLI flags. Held in a struct so
// runServe's signature does not balloon further; the struct itself is
// translated into a pkg/audit RotationConfig inside runServe.
type auditRotationOpts struct {
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

// auditBufferedOpts mirrors the --audit-buffered* CLI flags. Held in a
// struct so runServe's signature stays bounded; the struct is translated
// into a pkg/audit BufferedAsyncOpts inside runServe.
//
// Enabled=false makes writes go straight to the FileLogger and /v1/check
// waits on the audit mutex. Enabled=true (the default) decouples the
// request path from audit I/O via a bounded queue + worker pool + disk-
// overflow durability.
type auditBufferedOpts struct {
	Enabled      bool
	QueueSize    int
	Workers      int
	OverflowPath string
}

// pprofOpts mirrors the --debug-pprof* CLI flags. Held in a struct so
// runServe's signature stays bounded; the listener is started in runServe
// only when Enabled is true and is always bound to 127.0.0.1 (no flag to
// loosen this — operators who need pprof reachable beyond localhost must
// tunnel through SSH or a kube port-forward).
type pprofOpts struct {
	Enabled bool
	Port    int
}

// persistOpts mirrors the v0.6 persistence CLI flags. Held in a struct so
// runServe's signature stays bounded.
type persistOpts struct {
	Enabled      bool
	DSN          string
	DataDir      string
	AuditBackend string // "file" | "store"
}

// openStore opens the durable store described by cfg. An empty DSN selects the
// zero-config embedded SQLite database at <data-dir>/agentguard.db; a non-empty
// DSN is treated as a SQLite path (Postgres is rejected for now). Returns the
// concrete *SQLiteStore (which satisfies both store.Store for the syncer/audit
// AND policy.PolicySource for the multi-tenant provider) plus the resolved
// path for logging.
func openStore(cfg persistOpts) (*store.SQLiteStore, string, error) {
	if strings.HasPrefix(cfg.DSN, "postgres") || strings.HasPrefix(cfg.DSN, "postgresql") {
		return nil, "", fmt.Errorf("--store-dsn %q: external Postgres DSNs are not supported yet; leave empty for zero-config SQLite", cfg.DSN)
	}
	path := cfg.DSN
	if path == "" {
		dir := cfg.DataDir
		if dir == "" {
			dir = "."
		}
		path = filepath.Join(dir, "agentguard.db")
	}
	s, err := store.NewSQLiteStore(path)
	return s, path, err
}

func runServe(policyFile string, port int, dashboardEnabled bool, watch bool, auditPath string, apiKey string, baseURL string, allowedOrigin string, tlsTerminatedUpstream bool, sessionCostTTL time.Duration, sessionCostSweep time.Duration, rotOpts auditRotationOpts, bufOpts auditBufferedOpts, pprofCfg pprofOpts, persistCfg persistOpts) {
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	// Warn the operator when session-cost TTL is disabled. The engine
	// accumulator grows one entry per distinct session_id forever when
	// the sweeper is off, and operators who never set --session-cost-ttl
	// usually do not realise it.
	if sessionCostTTL <= 0 {
		log.Println("WARNING: --session-cost-ttl is 0; session-cost accumulator will grow unbounded. Set e.g. --session-cost-ttl 24h to bound memory.")
	}

	// Optional pprof debug listener. Bound to 127.0.0.1 only — never
	// 0.0.0.0 — because pprof exposes goroutine stacks and live memory
	// shapes that should not leak to the network. Operators who want to
	// reach it remotely must tunnel (`ssh -L`, `kubectl port-forward`).
	pprofSrv := startPprofServer(pprofCfg)
	if pprofSrv != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = pprofSrv.Shutdown(ctx)
		}()
	}
	// Load policy through the provider abstraction. FilePolicyProvider
	// wraps the single-file load + watch pattern; a database-backed
	// provider can swap in without changing engine or server code.
	provider, err := policy.NewFilePolicyProvider(policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy %s: %v", policyFile, err)
	}
	defer provider.Close()
	pol, err := provider.Get(policy.LocalTenantID)
	if err != nil {
		// NewFilePolicyProvider already validated that the local policy
		// loaded; this is a defensive read for the rule-count log line.
		log.Fatalf("Failed to read policy from provider: %v", err)
	}
	log.Printf("Loaded policy: %s (%d rules across %d scopes)", pol.Name, pol.RuleCount(), pol.ScopeCount())

	// Open the durable store (v0.6). Zero-config by default: a SQLite database
	// at <data-dir>/agentguard.db. Deferred Close is registered HERE (early) so
	// — via Go's LIFO defer order — the store is the LAST thing torn down, after
	// the syncer's final flush and the buffered audit logger's drain (both
	// registered later) have written through it.
	var st *store.SQLiteStore
	var storePath string
	storeAudit := persistCfg.Enabled && persistCfg.AuditBackend == "store"
	if persistCfg.Enabled {
		st, storePath, err = openStore(persistCfg)
		if err != nil {
			log.Fatalf("Failed to open store: %v", err)
		}
		defer func() { _ = st.Close() }()
	} else if persistCfg.AuditBackend == "store" {
		log.Fatalf("--audit-backend=store requires --persist (the store is disabled)")
	}

	// Contract rule #1 (Latency is God): a store-backed audit logger writes to
	// SQLite, which MUST NOT happen synchronously on the /v1/check path. Force
	// async buffering for the store backend even if the operator passed
	// --audit-buffered=false (which is fine for the cheap file append, but a DB
	// write per request would blow the <3ms budget).
	if storeAudit && !bufOpts.Enabled {
		log.Printf("WARNING: --audit-backend=store requires async buffering to keep DB writes off the /v1/check hot path; forcing --audit-buffered=true.")
		bufOpts.Enabled = true
	}

	// Audit logger selection. The default "file" backend is the JSONL
	// FileLogger (rotation + startup migration); "store" routes the audit
	// trail into the SQLite store's indexed audit_entries table (unified
	// single-file deployment, §2.4). Either way the BufferedAsyncLogger keeps
	// the /v1/check hot path off the audit write — it only enqueues.
	var auditLogger audit.Logger
	if storeAudit {
		base := store.NewAuditLogger(st)
		auditLogger = base
		if bufOpts.Enabled {
			overflowPath := bufOpts.OverflowPath
			if overflowPath == "" {
				overflowPath = auditPath + ".overflow.jsonl"
			}
			bufLogger, err := audit.NewBufferedAsyncLogger(base, audit.BufferedAsyncOpts{
				QueueSize:    bufOpts.QueueSize,
				Workers:      bufOpts.Workers,
				OverflowPath: overflowPath,
			})
			if err != nil {
				log.Fatalf("Failed to initialize buffered audit logger: %v", err)
			}
			// Drains into the still-open store on shutdown — store.Close was
			// deferred earlier, so by LIFO it runs after this drain.
			defer bufLogger.Close()
			auditLogger = bufLogger
		}
		log.Printf("Audit backend: store (%s)", storePath)
	} else {
		// Run startup migrations BEFORE opening the file audit logger. An
		// in-place rewrite (e.g. v040_to_v041 prepending a _meta header) has to
		// happen before we start appending new entries — otherwise the next
		// write would land in a file the migration is about to rename.
		migEnv := migrate.Env{
			AuditLogPath:   auditPath,
			CheckpointPath: auditPath + audit.CheckpointSuffix,
		}
		if err := migrate.RunStartup(context.Background(), migEnv); err != nil {
			log.Fatalf("Startup migration failed: %v", err)
		}

		// Rotation is on by default (100 MiB live cap, 30-day retention,
		// 5 archives, gzip). Setting --audit-max-size-mb=0 disables rotation
		// entirely (unbounded growth).
		rotCfg := audit.RotationConfig{
			MaxFiles: rotOpts.MaxBackups,
			Compress: rotOpts.Compress,
		}
		if rotOpts.MaxSizeMB > 0 {
			rotCfg.MaxSize = int64(rotOpts.MaxSizeMB) * 1024 * 1024
		}
		if rotOpts.MaxAgeDays > 0 {
			rotCfg.MaxAge = time.Duration(rotOpts.MaxAgeDays) * 24 * time.Hour
		}
		var fileLogger *audit.FileLogger
		if rotCfg.MaxSize > 0 || rotCfg.MaxFiles > 0 || rotCfg.MaxAge > 0 {
			fileLogger, err = audit.NewFileLoggerWithRotation(auditPath, rotCfg)
		} else {
			fileLogger, err = audit.NewFileLogger(auditPath)
		}
		if err != nil {
			log.Fatalf("Failed to initialize audit log: %v", err)
		}
		auditLogger = fileLogger
		if bufOpts.Enabled {
			overflowPath := bufOpts.OverflowPath
			if overflowPath == "" {
				overflowPath = auditPath + ".overflow.jsonl"
			}
			bufLogger, err := audit.NewBufferedAsyncLogger(fileLogger, audit.BufferedAsyncOpts{
				QueueSize:    bufOpts.QueueSize,
				Workers:      bufOpts.Workers,
				OverflowPath: overflowPath,
			})
			if err != nil {
				log.Fatalf("Failed to initialize buffered audit logger: %v", err)
			}
			// LIFO: bufLogger.Close (drains) runs before fileLogger.Close.
			defer fileLogger.Close()
			defer bufLogger.Close()
			auditLogger = bufLogger
		} else {
			defer fileLogger.Close()
		}
	}

	// In persistence mode, wrap the file provider (which serves the local
	// tenant) with a MultiTenantProvider that serves OTHER tenants' policies
	// from the store (registered via `agentguard tenant put`). Non-local
	// policies are parsed once and cached in memory, so per-tenant evaluation
	// never hits the DB on the /v1/check hot path. The file provider's own
	// Close (deferred above) still owns the watcher lifecycle.
	var engineProvider policy.PolicyProvider = provider
	if persistCfg.Enabled {
		mtp, mtErr := policy.NewMultiTenantProvider(provider, st)
		if mtErr != nil {
			log.Fatalf("Failed to initialize multi-tenant policy provider: %v", mtErr)
		}
		engineProvider = mtp
	}

	// Initialize policy engine. The engine subscribes to the provider's
	// Watch stream so hot-reloads land automatically — no second watcher.
	engine, err := policy.NewEngine(engineProvider)
	if err != nil {
		log.Fatalf("Failed to initialize policy engine: %v", err)
	}
	defer engine.Close()

	// Initialize notifier from policy config. The dispatcher owns background
	// worker goroutines and MUST be Close()'d on shutdown to stop them.
	notifier := notify.NewDispatcher(pol.Notifications)
	defer notifier.Close()

	// Hot-reload: log every successful provider update. The engine's own
	// Watch subscription already swaps the cached policy; this callback
	// is for operator visibility (`Policy reloaded: ...`). The --watch
	// flag is preserved for back-compat — the file watcher is always on
	// inside the FilePolicyProvider, so the flag now only gates the log
	// line, not the underlying behavior.
	if watch {
		stop, err := provider.Watch(policy.LocalTenantID, func(updated *policy.Policy) {
			log.Printf("Policy reloaded: %s (%d rules)", updated.Name, updated.RuleCount())
		})
		if err != nil {
			log.Fatalf("Failed to subscribe to policy reloads: %v", err)
		}
		defer stop()
	}

	// Build and start proxy server. Policy-driven tunables (session TTL,
	// request body cap, audit query bounds) are resolved through Policy
	// accessors so an operator gets the documented defaults when the
	// relevant YAML key is absent.
	srv := proxy.NewServer(proxy.Config{
		Port:                     port,
		Engine:                   engine,
		Logger:                   auditLogger,
		DashboardEnabled:         dashboardEnabled,
		Notifier:                 notifier,
		APIKey:                   apiKey,
		BaseURL:                  baseURL,
		AllowedOrigin:            allowedOrigin,
		Version:                  version,
		TLSTerminatedUpstream:    tlsTerminatedUpstream,
		SessionCostTTL:           sessionCostTTL,
		SessionCostSweepInterval: sessionCostSweep,
		SessionTTL:               pol.SessionTTL(),
		MaxRequestBodyBytes:      pol.MaxRequestBodyBytes(),
		AuditDefaultLimit:        pol.AuditDefaultLimit(),
		AuditMaxLimit:            pol.AuditMaxLimit(),
	})

	// Wire the write-behind persistence syncer (v0.6). It hydrates the
	// in-memory state from the store on boot, then flushes snapshots on a ≥1s
	// background tick. It NEVER runs on the request path. The deferred Close
	// performs a final flush; registered AFTER store.Close (defer LIFO) so the
	// final flush writes through a still-open store.
	if persistCfg.Enabled {
		syncer := persist.New(persist.Config{
			Store:       st,
			Engine:      engine,
			Limiter:     srv.Limiter(),
			Approvals:   srv.ApprovalQueue(),
			CostTTL:     sessionCostTTL, // matches in-memory sweeper (0 = keep)
			ApprovalTTL: 24 * time.Hour, // resolved approvals retained 24h
			BucketTTL:   time.Hour,      // fully-refilled buckets reaped after 1h
		})
		hctx, hcancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := syncer.Hydrate(hctx); err != nil {
			log.Printf("WARNING: state hydration failed (%v); starting with empty in-memory state", err)
		}
		hcancel()
		syncer.Start()
		defer syncer.Close()
		log.Printf("Persistence: enabled (store=%s, audit-backend=%s)", storePath, persistCfg.AuditBackend)
	} else {
		log.Printf("Persistence: disabled (--persist=false); runtime state is in-memory only")
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("AgentGuard v%s listening on :%d", version, port)
		if dashboardEnabled {
			log.Printf("Dashboard: http://localhost:%d/dashboard", port)
		}
		log.Printf("Health:    http://localhost:%d/health", port)
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down...")
	srv.Shutdown()
}

// startPprofServer boots a localhost-bound HTTP listener that serves the
// pprof handlers registered by the blank import of net/http/pprof at the
// top of this file. Returns the server (so callers can Shutdown it) when
// enabled; returns nil when --debug-pprof is unset.
//
// Security: addr is hard-coded to 127.0.0.1 — there is no flag to widen
// the bind. Pprof leaks goroutine stacks, heap shapes, and CPU samples
// that an attacker can use to fingerprint the binary or extract secrets
// from in-flight strings, so the only correct default is "loopback only,
// no override". Operators who need remote access must tunnel.
func startPprofServer(opts pprofOpts) *http.Server {
	if !opts.Enabled {
		return nil
	}
	addr := fmt.Sprintf("127.0.0.1:%d", opts.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux, // pprof handlers register here via net/http/pprof init()
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("pprof debug server listening on http://%s/debug/pprof/", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pprof server error: %v", err)
		}
	}()
	return srv
}

func runValidate(policyFile string) {
	pol, err := policy.LoadFromFile(policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID: %s — %d rules across %d scopes\n", pol.Name, pol.RuleCount(), pol.ScopeCount())
}

// resolveAPIKey returns the first non-empty of: explicit flag, env var.
func resolveAPIKey(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("AGENTGUARD_API_KEY")
}

// attachAuth adds a Bearer header when the key is non-empty.
func attachAuth(req *http.Request, key string) {
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
}

func runResolve(baseURL, approvalID, action, apiKey string) {
	url := fmt.Sprintf("%s/v1/%s/%s", strings.TrimRight(baseURL, "/"), action, approvalID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	attachAuth(req, apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Action %s: %s\n", action, body["status"])
	} else {
		fmt.Fprintf(os.Stderr, "Failed (%d): %s\n", resp.StatusCode, body["error"])
		os.Exit(1)
	}
}

func runStatus(baseURL, apiKey string) {
	url := strings.TrimRight(baseURL, "/")

	// Health check (unauthenticated)
	resp, err := http.Get(url + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to AgentGuard at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Printf("AgentGuard server: OK (%s)\n", baseURL)

	// Pending approvals (requires auth when server has --api-key)
	pendingReq, err := http.NewRequest(http.MethodGet, url+"/api/pending", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	attachAuth(pendingReq, apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err = client.Do(pendingReq)
	if err != nil {
		fmt.Println("Pending approvals: unavailable (dashboard not enabled?)")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Println("Pending approvals: unauthorized (set --api-key or AGENTGUARD_API_KEY)")
		return
	}

	var pending []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding pending list: %v\n", err)
		return
	}

	if len(pending) == 0 {
		fmt.Println("Pending approvals: none")
	} else {
		fmt.Printf("Pending approvals: %d\n", len(pending))
		for _, p := range pending {
			id, _ := p["id"].(string)
			req, ok := p["request"].(map[string]interface{})
			if !ok {
				fmt.Printf("  [%s] (unable to parse request)\n", id)
				continue
			}
			scope, _ := req["scope"].(string)
			cmd, _ := req["command"].(string)
			agent, _ := req["agent_id"].(string)
			if cmd == "" {
				cmd, _ = req["domain"].(string)
			}
			if cmd == "" {
				cmd, _ = req["path"].(string)
			}
			fmt.Printf("  [%s] scope=%s action=%q agent=%s\n", id, scope, cmd, agent)
		}
	}
}

func runAuditQuery(baseURL, agent, decision, scope, transport string, limit int, apiKey string) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	if agent != "" {
		params.Set("agent_id", agent)
	}
	if decision != "" {
		params.Set("decision", decision)
	}
	if scope != "" {
		params.Set("scope", scope)
	}
	if transport != "" {
		params.Set("transport", transport)
	}
	queryURL := fmt.Sprintf("%s/v1/audit?%s", strings.TrimRight(baseURL, "/"), params.Encode())

	req, err := http.NewRequest(http.MethodGet, queryURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	attachAuth(req, apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		fmt.Fprintln(os.Stderr, "audit: unauthorized (set --api-key or AGENTGUARD_API_KEY)")
		os.Exit(1)
	}

	var entries []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding audit entries: %v\n", err)
		return
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return
	}

	fmt.Printf("Showing %d audit entries:\n\n", len(entries))
	for _, e := range entries {
		ts, _ := e["timestamp"].(string)
		agentID, _ := e["agent_id"].(string)
		req, _ := e["request"].(map[string]interface{})
		result, _ := e["result"].(map[string]interface{})
		reqScope, _ := req["scope"].(string)
		dec, _ := result["decision"].(string)
		reason, _ := result["reason"].(string)
		// Transport is omitempty on the wire — older entries lack the
		// field. Fall back to "sdk" so columns stay aligned.
		tport, _ := e["transport"].(string)
		if tport == "" {
			tport = "sdk"
		}
		cmd, _ := req["command"].(string)
		if cmd == "" {
			cmd, _ = req["domain"].(string)
		}
		if cmd == "" {
			cmd, _ = req["path"].(string)
		}
		fmt.Printf("  %s  %-18s  transport=%-12s  scope=%-12s  agent=%-15s  %s\n", ts, dec, tport, reqScope, agentID, cmd)
		if reason != "" {
			fmt.Printf("    reason: %s\n", reason)
		}
	}
}

// runMigrate implements the `agentguard migrate` subcommand. It is a thin
// wrapper that wires the CLI flags into migrate.RunCLI — the framework
// handles registry lookup, dry-run semantics, and logging.
//
// The --reset-checkpoint flag deletes the replay checkpoint before running
// any migration, forcing the next server start to do a full replay. This is
// the escape hatch for operators who suspect the checkpoint is corrupt or
// was written by an incompatible build.
func runMigrate(auditPath, checkpointPath, backupDir string, dryRun, list bool, id string, resetCheckpoint bool) {
	if checkpointPath == "" {
		// Default to <audit-dir>/.replay-checkpoint.
		dir := filepathDir(auditPath)
		checkpointPath = filepathJoin(dir, ".replay-checkpoint")
	}
	if backupDir == "" {
		backupDir = filepathDir(auditPath)
	}

	if resetCheckpoint {
		if err := os.Remove(checkpointPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "migrate: could not remove checkpoint %s: %v\n", checkpointPath, err)
			os.Exit(1)
		}
		fmt.Printf("migrate: checkpoint removed (%s)\n", checkpointPath)
	}

	env := migrate.Env{
		AuditLogPath:   auditPath,
		CheckpointPath: checkpointPath,
		BackupDir:      backupDir,
		Stdout:         os.Stdout,
	}
	opts := migrate.CLIOptions{
		DryRun: dryRun,
		ID:     id,
		List:   list,
	}
	if err := migrate.RunCLI(context.Background(), env, opts); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

// runTenant implements `agentguard tenant <put|list|rm>` — the operator
// interface for registering per-tenant policies in the durable store (v0.6
// multi-tenancy). It opens the store directly (the server need not be running;
// SQLite WAL permits a concurrent writer, and a running server picks up a new
// tenant on its next lookup).
func runTenant(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentguard tenant <put|list|rm> [flags]")
		os.Exit(1)
	}
	sub := args[0]
	rest := args[1:]
	// Pull a leading positional tenant id so `tenant put acme --policy x` works
	// despite Go's flag package halting at the first non-flag token; also accept
	// it trailing (`tenant put --policy x acme`).
	var tenant string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		tenant = rest[0]
		rest = rest[1:]
	}
	fs := flag.NewFlagSet("tenant "+sub, flag.ExitOnError)
	storeDSN := fs.String("store-dsn", "", "Store DSN (empty => <data-dir>/agentguard.db)")
	dataDir := fs.String("data-dir", ".", "Directory holding agentguard.db")
	policyPath := fs.String("policy", "", "Policy YAML file to register (put only)")
	_ = fs.Parse(rest)
	if tenant == "" && len(fs.Args()) > 0 {
		tenant = fs.Args()[0]
	}

	st, path, err := openStore(persistOpts{DSN: *storeDSN, DataDir: *dataDir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tenant: cannot open store: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()

	switch sub {
	case "put":
		if tenant == "" || *policyPath == "" {
			fmt.Fprintln(os.Stderr, "Usage: agentguard tenant put <tenant-id> --policy <file.yaml>")
			os.Exit(1)
		}
		// Validate before storing so a malformed policy is never registered.
		pol, err := policy.LoadFromFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tenant put: INVALID policy %s: %v\n", *policyPath, err)
			os.Exit(1)
		}
		raw, err := os.ReadFile(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tenant put: read %s: %v\n", *policyPath, err)
			os.Exit(1)
		}
		if err := st.PutPolicy(ctx, tenant, raw); err != nil {
			fmt.Fprintf(os.Stderr, "tenant put: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Registered tenant %q: %s (%d rules across %d scopes) in %s\n",
			tenant, pol.Name, pol.RuleCount(), pol.ScopeCount(), path)

	case "list":
		tenants, err := st.ListPolicyTenants(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tenant list: %v\n", err)
			os.Exit(1)
		}
		if len(tenants) == 0 {
			fmt.Println("No tenant policies registered. (The 'local' tenant is served from --policy.)")
			return
		}
		fmt.Printf("Registered tenants (%d):\n", len(tenants))
		for _, t := range tenants {
			fmt.Printf("  %s\n", t)
		}

	case "rm":
		if tenant == "" {
			fmt.Fprintln(os.Stderr, "Usage: agentguard tenant rm <tenant-id>")
			os.Exit(1)
		}
		ok, err := st.DeletePolicy(ctx, tenant)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tenant rm: %v\n", err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("Removed tenant %q\n", tenant)
		} else {
			fmt.Printf("Tenant %q not found\n", tenant)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown tenant subcommand %q (want put|list|rm)\n", sub)
		os.Exit(1)
	}
}

// filepathDir and filepathJoin wrap path/filepath so runMigrate stays
// readable without adding another top-level import block rewrite. They are
// here (rather than in a helpers file) because they are the only uses in
// main.go today — pulling them into a shared file would be premature.
func filepathDir(p string) string     { return filepath.Dir(p) }
func filepathJoin(a, b string) string { return filepath.Join(a, b) }
