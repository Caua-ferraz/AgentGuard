package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
	schemav1 "github.com/Caua-ferraz/AgentGuard/pkg/proxy/schema/v1"
)

// defaultWatchPoll is how often --watch re-polls the followed file for
// appended bytes once it has caught up to EOF.
const defaultWatchPoll = 200 * time.Millisecond

// Exit codes for `agentguard check`. Stable contract — scripts pin on these.
//
//	0 = ALLOW (single) or every entry ALLOW (batch)
//	1 = DENY (single) or any entry DENY (batch)
//	2 = REQUIRE_APPROVAL (single) or any entry REQUIRE_APPROVAL with no DENY
//	3 = error (file missing, malformed JSON, invalid policy, flag misuse)
//
// Precedence in batch mode: error > deny > approval > allow.
//
// The `error` legend is deliberately distinct from "policy denies the
// action". A bash pipeline like `agentguard check ... && deploy.sh` should
// treat exit 1 as "policy fired correctly and rejected"; exit 3 means
// AgentGuard itself could not produce a verdict. Conflating them would
// silently let infrastructure bugs masquerade as policy denials.
const (
	exitAllow    = 0
	exitDeny     = 1
	exitApproval = 2
	exitError    = 3
)

// checkCmdFlags carries every flag accepted by `agentguard check`. Held in
// a struct so executeCheck can be unit-tested without touching package
// globals or os.Args.
type checkCmdFlags struct {
	PolicyPath string
	TenantID   string
	RequestStr string
	Stdin      bool
	Batch      bool
	Watch      string
	OutputFmt  string

	// watchStop ends a --watch loop (tests close it; production wires
	// SIGINT in runCheck). nil means "run until interrupted".
	watchStop <-chan struct{}
	// watchPoll is the tail-poll interval; tests shrink it. Zero means
	// defaultWatchPoll.
	watchPoll time.Duration

	// Per-field flags. These build a single ActionRequest when the caller
	// chooses the flag-based input mode (no --request, --stdin, or --batch).
	Scope     string
	Command   string
	Action    string
	Path      string
	Domain    string
	URL       string
	AgentID   string
	SessionID string
	EstCost   float64
	// Meta is parsed as comma-separated `k=v` pairs. Operators who need
	// embedded commas or quotes should fall through to --request '{"meta":{}}'
	// which parses as JSON unambiguously.
	Meta string
}

// runCheck is the entry point invoked by main.go's subcommand dispatch.
// It owns flag parsing and forwards execution to executeCheck, which is
// pure (no os.Stdin / os.Stdout reads) so tests can inject buffers.
func runCheck(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `Usage: agentguard check [flags]

Run a single policy check (or a batch from stdin) against a local policy
file without going through the HTTP server. Useful in CI pipelines and
one-shot scripts.

Input modes (mutually exclusive):
  --request <json>     Single check from a JSON string
  --stdin              Single check from one JSON object on stdin
  --batch              Batch check from JSONL (one JSON object per line) on stdin
  --watch <file>       Follow a JSONL file (tail -f) and verdict each appended
                       request with ONE policy load for the whole stream; the
                       policy file hot-reloads on edit. Runs until interrupted.
  (default)            Single check built from per-field flags

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, `
Exit codes:
  0  ALLOW (or every entry ALLOW in batch mode)
  1  DENY  (or any entry DENY in batch mode)
  2  REQUIRE_APPROVAL (or any approval and no deny in batch mode)
  3  Error (missing/invalid policy, malformed JSON, flag misuse)
`)
	}

	f := &checkCmdFlags{}
	fs.StringVar(&f.PolicyPath, "policy", "", "Policy file path (required)")
	fs.StringVar(&f.TenantID, "tenant-id", "", "Tenant ID (default \"local\")")
	fs.StringVar(&f.RequestStr, "request", "", "JSON request string for single check")
	fs.BoolVar(&f.Stdin, "stdin", false, "Read a single JSON request object from stdin")
	fs.BoolVar(&f.Batch, "batch", false, "Read JSONL (one request per line) from stdin")
	fs.StringVar(&f.Watch, "watch", "", "Follow a JSONL file (tail -f) and verdict each appended request")
	fs.StringVar(&f.OutputFmt, "output", "text", "Output format: text | json")

	fs.StringVar(&f.Scope, "scope", "", "Request scope (shell, filesystem, network, ...)")
	fs.StringVar(&f.Command, "command", "", "Shell command to evaluate")
	fs.StringVar(&f.Action, "action", "", "Action name (read|write|delete|...)")
	fs.StringVar(&f.Path, "path", "", "Filesystem path")
	fs.StringVar(&f.Domain, "domain", "", "Network domain")
	fs.StringVar(&f.URL, "url", "", "Request URL")
	fs.StringVar(&f.AgentID, "agent-id", "", "Agent identifier (for per-agent overrides)")
	fs.StringVar(&f.SessionID, "session-id", "", "Session identifier (for cost accumulators)")
	fs.Float64Var(&f.EstCost, "est-cost", 0, "Estimated cost (cost scope)")
	fs.StringVar(&f.Meta, "meta", "", "Comma-separated k=v pairs (e.g. \"team=ml,prio=high\")")

	// --watch runs until interrupted; wire SIGINT/SIGTERM so Ctrl-C
	// returns the aggregate exit code instead of killing the process
	// mid-verdict.
	if i := indexOfWatchFlag(args); i >= 0 {
		stop := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			signal.Stop(sigCh)
			close(stop)
		}()
		f.watchStop = stop
	}

	if err := fs.Parse(args); err != nil {
		// `-h` / `-help` returns flag.ErrHelp; the FlagSet has already
		// printed the usage block via fs.Usage. Exit 0 in that case so
		// `agentguard check -h` is a friendly help, not a usage error.
		if errors.Is(err, flag.ErrHelp) {
			return exitAllow
		}
		// All other parse errors (unknown flag, bad numeric value, etc.)
		// already wrote to stderr. Map to the documented "usage error"
		// exit code so scripts can distinguish flag misuse from policy
		// denials.
		return exitError
	}
	return executeCheck(f, stdin, stdout, stderr)
}

// executeCheck is the pure half of the check subcommand. Accepts io.Reader
// for stdin and io.Writers for output so tests can supply bytes.Buffer.
func executeCheck(f *checkCmdFlags, stdin io.Reader, stdout, stderr io.Writer) int {
	if f.PolicyPath == "" {
		fmt.Fprintln(stderr, "check: --policy is required")
		return exitError
	}
	if f.OutputFmt != "" && f.OutputFmt != "text" && f.OutputFmt != "json" {
		fmt.Fprintf(stderr, "check: invalid --output value %q (want \"text\" or \"json\")\n", f.OutputFmt)
		return exitError
	}

	mode, err := selectInputMode(f)
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return exitError
	}

	// Build the engine via the same provider abstraction the server uses.
	// FilePolicyProvider validates the policy at construction time, so a
	// missing or malformed file surfaces as exitError before we touch any
	// requests.
	provider, err := policy.NewFilePolicyProvider(f.PolicyPath)
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return exitError
	}
	defer provider.Close()

	engine, err := policy.NewEngine(provider)
	if err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return exitError
	}
	defer engine.Close()

	tenantID := f.TenantID
	if tenantID == "" {
		tenantID = policy.LocalTenantID
	}

	switch mode {
	case inputModeFlags:
		req, err := buildRequestFromFlags(f)
		if err != nil {
			fmt.Fprintf(stderr, "check: %v\n", err)
			return exitError
		}
		return runSingle(engine, req, tenantID, f.OutputFmt, stdout)
	case inputModeRequest:
		req, err := decodeRequest([]byte(f.RequestStr))
		if err != nil {
			fmt.Fprintf(stderr, "check: --request is not valid JSON: %v\n", err)
			return exitError
		}
		return runSingle(engine, req, tenantID, f.OutputFmt, stdout)
	case inputModeStdin:
		data, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "check: reading stdin: %v\n", err)
			return exitError
		}
		req, err := decodeRequest(data)
		if err != nil {
			fmt.Fprintf(stderr, "check: stdin is not valid JSON: %v\n", err)
			return exitError
		}
		return runSingle(engine, req, tenantID, f.OutputFmt, stdout)
	case inputModeBatch:
		return runBatch(engine, stdin, tenantID, f.OutputFmt, stdout, stderr)
	case inputModeWatch:
		return runWatch(engine, f, tenantID, stdout, stderr)
	default:
		// Unreachable — selectInputMode either returns a known mode or an
		// error. Defensive default-deny so a future enum addition can't
		// silently exit 0.
		fmt.Fprintln(stderr, "check: internal error: unknown input mode")
		return exitError
	}
}

type inputMode int

const (
	inputModeFlags inputMode = iota
	inputModeRequest
	inputModeStdin
	inputModeBatch
	inputModeWatch
)

// selectInputMode enforces the documented mutual-exclusion contract:
// at most one of --request, --stdin, --batch, --watch may be set; the
// per-field flags are only consulted when none of those is set.
func selectInputMode(f *checkCmdFlags) (inputMode, error) {
	chosen := 0
	if f.RequestStr != "" {
		chosen++
	}
	if f.Stdin {
		chosen++
	}
	if f.Batch {
		chosen++
	}
	if f.Watch != "" {
		chosen++
	}
	if chosen > 1 {
		return 0, errors.New("--request, --stdin, --batch, and --watch are mutually exclusive")
	}
	if f.RequestStr != "" {
		return inputModeRequest, nil
	}
	if f.Stdin {
		return inputModeStdin, nil
	}
	if f.Batch {
		return inputModeBatch, nil
	}
	if f.Watch != "" {
		return inputModeWatch, nil
	}
	return inputModeFlags, nil
}

// buildRequestFromFlags turns the per-field --scope/--command/... flags
// into a policy.ActionRequest. Returns an error if --scope is empty,
// because every other code path requires it.
func buildRequestFromFlags(f *checkCmdFlags) (policy.ActionRequest, error) {
	if f.Scope == "" {
		return policy.ActionRequest{}, errors.New("--scope is required when no --request/--stdin/--batch is given")
	}
	meta, err := parseMetaFlag(f.Meta)
	if err != nil {
		return policy.ActionRequest{}, err
	}
	return policy.ActionRequest{
		SchemaVersion: schemav1.Version,
		Scope:         f.Scope,
		Action:        f.Action,
		Command:       f.Command,
		Path:          f.Path,
		Domain:        f.Domain,
		URL:           f.URL,
		AgentID:       f.AgentID,
		SessionID:     f.SessionID,
		EstCost:       f.EstCost,
		Meta:          meta,
	}, nil
}

// parseMetaFlag accepts comma-separated `k=v` pairs. Returns nil for an
// empty string (so the caller's resulting ActionRequest has no Meta map
// at all, matching the omitempty wire shape).
func parseMetaFlag(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("invalid --meta entry %q: expected key=value", pair)
		}
		key := strings.TrimSpace(pair[:eq])
		val := strings.TrimSpace(pair[eq+1:])
		if key == "" {
			return nil, fmt.Errorf("invalid --meta entry %q: empty key", pair)
		}
		out[key] = val
	}
	return out, nil
}

// decodeRequest parses a JSON ActionRequest with strict field handling so
// that typos (e.g. `"actions"` vs `"action"`) surface as errors rather
// than silently producing a default-deny verdict on an empty request.
func decodeRequest(data []byte) (policy.ActionRequest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var req policy.ActionRequest
	if err := dec.Decode(&req); err != nil {
		return policy.ActionRequest{}, err
	}
	if req.Scope == "" {
		return policy.ActionRequest{}, errors.New("request missing required field \"scope\"")
	}
	return req, nil
}

// runSingle evaluates one request and prints the result in the requested
// format. Returns the appropriate exit code per the decision.
func runSingle(engine *policy.Engine, req policy.ActionRequest, tenantID, outputFmt string, stdout io.Writer) int {
	res := engine.Check(req, tenantID)
	res.SchemaVersion = schemav1.Version
	if err := writeResult(stdout, req, res, outputFmt); err != nil {
		// A stdout write error is rare (closed pipe, full disk). We've
		// already evaluated policy, so the *decision* is valid; mapping
		// the I/O failure to exitError matches the contract — the caller
		// never received the verdict.
		fmt.Fprintf(stdout, "check: write error: %v\n", err)
		return exitError
	}
	return exitForDecision(res.Decision)
}

// runBatch reads JSONL from stdin, evaluates each line, and emits one
// output line per request. The exit code reflects the most-severe result
// across the batch (error > deny > approval > allow).
//
// A single malformed line aborts the batch with exitError after emitting
// any results already produced — the alternative ("skip and continue")
// would silently mask half a CI plan.
//
// Note: severity ordering is NOT the numeric exit-code ordering. The
// numeric codes are 0/1/2/3 (allow/deny/approval/error) by external
// contract, but operationally we treat deny as MORE severe than approval
// (a deny is a hard refusal; an approval is a "human, please look").
// severityRank maps each exit code to its severity for the max-severity
// reduction below.
func runBatch(engine *policy.Engine, stdin io.Reader, tenantID, outputFmt string, stdout, stderr io.Writer) int {
	scanner := bufio.NewScanner(stdin)
	// Lift the default 64 KiB line cap to 1 MiB so a long shell command
	// or domain list does not silently truncate. Matches the audit
	// logger's scanner buffer in pkg/audit/logger.go.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	worst := exitAllow
	processed := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		processed++
		req, err := decodeRequest([]byte(line))
		if err != nil {
			fmt.Fprintf(stderr, "check: line %d: %v\n", processed, err)
			return exitError
		}
		res := engine.Check(req, tenantID)
		res.SchemaVersion = schemav1.Version
		if err := writeResult(stdout, req, res, outputFmt); err != nil {
			fmt.Fprintf(stderr, "check: write error: %v\n", err)
			return exitError
		}
		code := exitForDecision(res.Decision)
		if severityRank(code) > severityRank(worst) {
			worst = code
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(stderr, "check: scanner: %v\n", err)
		return exitError
	}
	if processed == 0 {
		fmt.Fprintln(stderr, "check: --batch input was empty")
		return exitError
	}
	return worst
}

// severityRank ranks an exit code by operational severity, NOT by its
// numeric value. Contract: allow < approval < deny < error. The exit
// codes themselves are fixed by the documented CLI contract (0/1/2/3),
// but the numeric ordering is wrong for "max severity" reductions —
// deny (1) numerically precedes approval (2) but operationally a deny
// is more severe. Used by runBatch to fold per-line outcomes.
func severityRank(code int) int {
	switch code {
	case exitAllow:
		return 0
	case exitApproval:
		return 1
	case exitDeny:
		return 2
	case exitError:
		return 3
	default:
		return 3
	}
}

// exitForDecision maps a policy decision to the documented exit code.
// Unknown decisions default to exitError so a hypothetical future
// "Decision" string can't silently exit 0.
func exitForDecision(d policy.Decision) int {
	switch d {
	case policy.Allow:
		return exitAllow
	case policy.Deny:
		return exitDeny
	case policy.RequireApproval:
		return exitApproval
	default:
		return exitError
	}
}

// writeResult emits one line per evaluated request in the chosen format.
// JSON output mirrors the wire response shape (CheckResult) so downstream
// tools can consume the same JSON they'd receive from /v1/check.
//
// Text output is human-friendly and includes the originating request
// scope/command/path so a batch line by itself is interpretable.
func writeResult(w io.Writer, req policy.ActionRequest, res policy.CheckResult, outputFmt string) error {
	if outputFmt == "json" {
		return writeResultJSON(w, res)
	}
	return writeResultText(w, req, res)
}

func writeResultJSON(w io.Writer, res policy.CheckResult) error {
	// Marshal then write+newline so each batch entry is its own JSONL
	// record. json.Encoder.Encode would also work and append \n, but
	// Marshal lets us preserve the SchemaVersion ordering documented in
	// pkg/proxy/schema/v1/schema.json without surprise.
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

func writeResultText(w io.Writer, req policy.ActionRequest, res policy.CheckResult) error {
	var sb strings.Builder
	sb.WriteString(string(res.Decision))
	sb.WriteString("\tscope=")
	sb.WriteString(req.Scope)
	if req.Command != "" {
		fmt.Fprintf(&sb, " command=%q", req.Command)
	}
	if req.Action != "" {
		sb.WriteString(" action=")
		sb.WriteString(req.Action)
	}
	if req.Path != "" {
		fmt.Fprintf(&sb, " path=%q", req.Path)
	}
	if req.Domain != "" {
		sb.WriteString(" domain=")
		sb.WriteString(req.Domain)
	}
	if req.URL != "" {
		fmt.Fprintf(&sb, " url=%q", req.URL)
	}
	if req.EstCost != 0 {
		fmt.Fprintf(&sb, " est_cost=%.2f", req.EstCost)
	}
	if res.Rule != "" {
		fmt.Fprintf(&sb, " rule=%q", res.Rule)
	}
	if res.Reason != "" {
		fmt.Fprintf(&sb, " reason=%q", res.Reason)
	}
	if res.ApprovalID != "" {
		sb.WriteString(" approval_id=")
		sb.WriteString(res.ApprovalID)
	}
	sb.WriteByte('\n')
	_, err := io.WriteString(w, sb.String())
	return err
}

// indexOfWatchFlag reports whether args select --watch (so runCheck can
// wire signal handling before parsing). Handles the four spellings the
// flag package accepts: -watch v, --watch v, -watch=v, --watch=v.
func indexOfWatchFlag(args []string) int {
	for i, a := range args {
		if a == "-watch" || a == "--watch" ||
			strings.HasPrefix(a, "-watch=") || strings.HasPrefix(a, "--watch=") {
			return i
		}
	}
	return -1
}

// runWatch follows a JSONL file (tail -f semantics): existing lines are
// verdicted immediately, then the file is polled for appended requests.
// One policy load serves the whole stream, and the FilePolicyProvider's
// watcher keeps the engine hot-reloaded on policy edits — the original
// motivation: a CI plan or local agent harness gating N actions should
// not pay N policy loads.
//
// Only newline-terminated lines are processed; a partial line at EOF is
// buffered until the writer finishes it, so a torn mid-append read can't
// produce a bogus parse error. Malformed lines abort with exitError
// (same posture as --batch — skipping would silently mask requests).
// The loop ends when f.watchStop closes (SIGINT/SIGTERM in production,
// the test harness otherwise) and returns the worst exit code seen.
func runWatch(engine *policy.Engine, f *checkCmdFlags, tenantID string, stdout, stderr io.Writer) int {
	file, err := os.Open(f.Watch)
	if err != nil {
		fmt.Fprintf(stderr, "check: --watch: %v\n", err)
		return exitError
	}
	defer file.Close()

	poll := f.watchPoll
	if poll <= 0 {
		poll = defaultWatchPoll
	}

	reader := bufio.NewReader(file)
	var partial []byte
	worst := exitAllow
	processed := 0

	for {
		chunk, err := reader.ReadBytes('\n')
		partial = append(partial, chunk...)

		if err == nil {
			line := strings.TrimSpace(string(partial))
			partial = partial[:0]
			if line == "" {
				continue
			}
			processed++
			req, derr := decodeRequest([]byte(line))
			if derr != nil {
				fmt.Fprintf(stderr, "check: watch line %d: %v\n", processed, derr)
				return exitError
			}
			res := engine.Check(req, tenantID)
			res.SchemaVersion = schemav1.Version
			if werr := writeResult(stdout, req, res, f.OutputFmt); werr != nil {
				fmt.Fprintf(stderr, "check: write error: %v\n", werr)
				return exitError
			}
			if code := exitForDecision(res.Decision); severityRank(code) > severityRank(worst) {
				worst = code
			}
			continue
		}

		if !errors.Is(err, io.EOF) {
			fmt.Fprintf(stderr, "check: --watch read: %v\n", err)
			return exitError
		}

		// Caught up. Wait for more bytes or the stop signal.
		select {
		case <-f.watchStop:
			return worst
		case <-time.After(poll):
		}
	}
}
