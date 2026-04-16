package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/audit"
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

	validateCmd := flag.NewFlagSet("validate", flag.ExitOnError)
	validateFile := validateCmd.String("policy", "configs/default.yaml", "Policy file to validate")

	approveCmd := flag.NewFlagSet("approve", flag.ExitOnError)
	approveURL := approveCmd.String("url", "http://localhost:8080", "AgentGuard server URL")

	denyCmd := flag.NewFlagSet("deny", flag.ExitOnError)
	denyURL := denyCmd.String("url", "http://localhost:8080", "AgentGuard server URL")

	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)
	statusURL := statusCmd.String("url", "http://localhost:8080", "AgentGuard server URL")

	auditCmd := flag.NewFlagSet("audit", flag.ExitOnError)
	auditQueryURL := auditCmd.String("url", "http://localhost:8080", "AgentGuard server URL")
	auditAgent := auditCmd.String("agent", "", "Filter by agent ID")
	auditDecision := auditCmd.String("decision", "", "Filter by decision (ALLOW, DENY, REQUIRE_APPROVAL)")
	auditScope := auditCmd.String("scope", "", "Filter by scope")
	auditLimit := auditCmd.Int("limit", 50, "Max entries to return")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		_ = serveCmd.Parse(os.Args[2:]) // flag.ExitOnError handles errors
		runServe(*policyFile, *port, *dashboard, *watch, *auditPath, *apiKey, *baseURL)

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
		runResolve(*approveURL, args[0], "approve")

	case "deny":
		_ = denyCmd.Parse(os.Args[2:])
		args := denyCmd.Args()
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: agentguard deny [flags] <approval-id>")
			os.Exit(1)
		}
		runResolve(*denyURL, args[0], "deny")

	case "status":
		_ = statusCmd.Parse(os.Args[2:])
		runStatus(*statusURL)

	case "audit":
		_ = auditCmd.Parse(os.Args[2:])
		runAuditQuery(*auditQueryURL, *auditAgent, *auditDecision, *auditScope, *auditLimit)

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
  version     Print version information

Run 'agentguard <command> -h' for details on each command.
`)
}

func runServe(policyFile string, port int, dashboardEnabled bool, watch bool, auditPath string, apiKey string, baseURL string) {
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}
	// Load policy
	pol, err := policy.LoadFromFile(policyFile)
	if err != nil {
		log.Fatalf("Failed to load policy %s: %v", policyFile, err)
	}
	log.Printf("Loaded policy: %s (%d rules across %d scopes)", pol.Name, pol.RuleCount(), pol.ScopeCount())

	// Initialize audit logger
	logger, err := audit.NewFileLogger(auditPath)
	if err != nil {
		log.Fatalf("Failed to initialize audit log: %v", err)
	}
	defer logger.Close()

	// Initialize policy engine
	engine := policy.NewEngine(pol)

	// Initialize notifier from policy config
	notifier := notify.NewDispatcher(pol.Notifications)

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

	// Build and start proxy server
	srv := proxy.NewServer(proxy.Config{
		Port:             port,
		Engine:           engine,
		Logger:           logger,
		DashboardEnabled: dashboardEnabled,
		Notifier:         notifier,
		APIKey:           apiKey,
		BaseURL:          baseURL,
		Version:          version,
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

func runResolve(baseURL, approvalID, action string) {
	url := fmt.Sprintf("%s/v1/%s/%s", strings.TrimRight(baseURL, "/"), action, approvalID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

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

func runStatus(baseURL string) {
	url := strings.TrimRight(baseURL, "/")

	// Health check
	resp, err := http.Get(url + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to AgentGuard at %s: %v\n", baseURL, err)
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Printf("AgentGuard server: OK (%s)\n", baseURL)

	// Pending approvals
	resp, err = http.Get(url + "/api/pending")
	if err != nil {
		fmt.Println("Pending approvals: unavailable (dashboard not enabled?)")
		return
	}
	defer resp.Body.Close()

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

func runAuditQuery(baseURL, agent, decision, scope string, limit int) {
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

	resp, err := http.Get(queryURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

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
