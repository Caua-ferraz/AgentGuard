package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
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
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	"github.com/Caua-ferraz/AgentGuard/pkg/proxy"
)

var (
	version = "0.4.0"
	commit  = "dev"
)

func main() {
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
	sessionCostTTL := serveCmd.Duration("session-cost-ttl", 0, "If > 0, evict session-cost accumulator entries idle longer than this duration (e.g. 24h). Zero preserves v0.4.0 behavior (entries never expire).")
	sessionCostSweep := serveCmd.Duration("session-cost-sweep-interval", 0, "How often to run the session-cost sweeper. Defaults to max(session-cost-ttl/4, 1m).")

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

	switch os.Args[1] {
	case "serve":
		_ = serveCmd.Parse(os.Args[2:]) // flag.ExitOnError handles errors
		// Fall back to AGENTGUARD_API_KEY env if --api-key not supplied.
		runServe(*policyFile, *port, *dashboard, *watch, *auditPath, resolveAPIKey(*apiKey), *baseURL, *allowedOrigin, *tlsTerminated, *sessionCostTTL, *sessionCostSweep)

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
		runAuditQuery(*auditQueryURL, *auditAgent, *auditDecision, *auditScope, *auditLimit, resolveAPIKey(*auditKey))

	case "migrate":
		_ = migrateCmd.Parse(os.Args[2:])
		runMigrate(*migrateAuditPath, *migrateCheckpoint, *migrateBackupDir, *migrateDryRun, *migrateList, *migrateID, *migrateReset)

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
  serve       Start the AgentGuard proxy server
  validate    Validate a policy file
  approve     Approve a pending action by ID
  deny        Deny a pending action by ID
  status      Show connected agents and pending actions
  audit       Query the audit log
  migrate     Run on-disk schema migrations (see docs/FILE_FORMATS.md)
  version     Print version information

Run 'agentguard <command> -h' for details on each command.
`)
}

func runServe(policyFile string, port int, dashboardEnabled bool, watch bool, auditPath string, apiKey string, baseURL string, allowedOrigin string, tlsTerminatedUpstream bool, sessionCostTTL time.Duration, sessionCostSweep time.Duration) {
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}
	// Load policy
	pol, err := policy.LoadFromFile(policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy %s: %v", policyFile, err)
	}
	log.Printf("Loaded policy: %s (%d rules across %d scopes)", pol.Name, pol.RuleCount(), pol.ScopeCount())

	// Run startup migrations BEFORE opening the audit logger. An in-place
	// rewrite (e.g. v040_to_v041 prepending a _meta header) has to happen
	// before we start appending new entries — otherwise the next write
	// would land in a file the migration is about to rename.
	migEnv := migrate.Env{
		AuditLogPath:   auditPath,
		CheckpointPath: auditPath + audit.CheckpointSuffix,
	}
	if err := migrate.RunStartup(context.Background(), migEnv); err != nil {
		log.Fatalf("Startup migration failed: %v", err)
	}

	// Initialize audit logger
	logger, err := audit.NewFileLogger(auditPath)
	if err != nil {
		log.Fatalf("Failed to initialize audit log: %v", err)
	}
	defer logger.Close()

	// Initialize policy engine
	engine := policy.NewEngine(pol)

	// Initialize notifier from policy config. The dispatcher owns background
	// worker goroutines and MUST be Close()'d on shutdown to stop them.
	notifier := notify.NewDispatcher(pol.Notifications)
	defer notifier.Close()

	// Enable file watching for hot reload
	if watch {
		watcher, err := policy.WatchFile(policyFile, func(updated *policy.Policy) {
			engine.UpdatePolicy(updated)
			log.Printf("Policy reloaded: %s (%d rules)", updated.Name, updated.RuleCount())
		})
		if err != nil {
			log.Fatalf("Failed to watch policy file: %v", err)
		}
		defer watcher.Close()
	}

	// Build and start proxy server. Policy-driven tunables (session TTL,
	// request body cap, audit query bounds) are resolved through Policy
	// accessors so an operator gets the documented defaults when the
	// relevant YAML key is absent.
	srv := proxy.NewServer(proxy.Config{
		Port:                     port,
		Engine:                   engine,
		Logger:                   logger,
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

func runAuditQuery(baseURL, agent, decision, scope string, limit int, apiKey string) {
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
		cmd, _ := req["command"].(string)
		if cmd == "" {
			cmd, _ = req["domain"].(string)
		}
		if cmd == "" {
			cmd, _ = req["path"].(string)
		}
		fmt.Printf("  %s  %-18s  scope=%-12s  agent=%-15s  %s\n", ts, dec, reqScope, agentID, cmd)
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

// filepathDir and filepathJoin wrap path/filepath so runMigrate stays
// readable without adding another top-level import block rewrite. They are
// here (rather than in a helpers file) because they are the only uses in
// main.go today — pulling them into a shared file would be premature.
func filepathDir(p string) string  { return filepath.Dir(p) }
func filepathJoin(a, b string) string { return filepath.Join(a, b) }
