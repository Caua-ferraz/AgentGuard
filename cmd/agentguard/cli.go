package main

// cli.go is the command-line plumbing every agentguard subcommand shares:
// the command table and "did you mean" suggestions, flag parsing that
// accepts flags after positional arguments, policy-file discovery, the
// server-URL fallback and the "can't reach the server" message. The flag
// section of each --help is printed by internal/clihelp.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
)

// exitUsage is the exit status for a malformed command line (unknown
// command or flag, missing or extra argument). It matches what Go's flag
// package has always used for a bad flag. `check` keeps its own documented
// code (3) for the same situation.
const exitUsage = 2

// command is one agentguard subcommand as listed by `agentguard help`.
type command struct {
	Name    string
	Aliases []string // older or alternative names that run the same command
	Group   string
	Summary string
}

// commandGroups is the order the help lists the groups in.
var commandGroups = []string{"Run the server", "Policies", "Work with a running server", "Other"}

// commands is every subcommand. "serve" stays an alias of "server" for the
// whole 1.x line (docs/COMPATIBILITY.md, frozen surface 4).
var commands = []command{
	{Name: "server", Aliases: []string{"serve"}, Group: "Run the server", Summary: "Start AgentGuard: policy engine, approvals, audit log, dashboard"},
	{Name: "validate", Group: "Policies", Summary: "Check that a policy file loads"},
	{Name: "check", Group: "Policies", Summary: "Evaluate one action against a policy file (no server needed)"},
	{Name: "tenant", Group: "Policies", Summary: "Manage per-tenant policies in the store (put|list|rm)"},
	{Name: "status", Group: "Work with a running server", Summary: "Show server health and pending approvals"},
	{Name: "approve", Group: "Work with a running server", Summary: "Approve a pending action by ID"},
	{Name: "deny", Group: "Work with a running server", Summary: "Deny a pending action by ID"},
	{Name: "audit", Group: "Work with a running server", Summary: "Query the audit log"},
	{Name: "migrate", Group: "Other", Summary: "Upgrade the audit log's format (the server does this at startup)"},
	{Name: "version", Group: "Other", Summary: "Print version information (also: --version)"},
	{Name: "help", Group: "Other", Summary: "Show help for a command"},
}

// lookupCommand maps a command-line token to its command name, following
// aliases and the flag spellings of help and version.
func lookupCommand(token string) (string, bool) {
	switch token {
	case "-h", "-help", "--help":
		return "help", true
	case "-version", "--version":
		return "version", true
	}
	for _, c := range commands {
		if c.Name == token {
			return c.Name, true
		}
		for _, a := range c.Aliases {
			if a == token {
				return c.Name, true
			}
		}
	}
	return "", false
}

// suggestCommand returns the command a mistyped token most likely meant
// ("--serve" → "server", "stauts" → "status"), or "" when nothing is close.
func suggestCommand(token string) string {
	bare := strings.ToLower(strings.TrimLeft(token, "-"))
	if name, ok := lookupCommand(bare); ok {
		return name
	}
	var names []string
	canonical := map[string]string{}
	for _, c := range commands {
		for _, n := range append([]string{c.Name}, c.Aliases...) {
			names = append(names, n)
			canonical[n] = c.Name
		}
	}
	if match := closest(bare, names); match != "" {
		return canonical[match]
	}
	return ""
}

// closest returns the candidate nearest to word: within one edit for short
// words, two for longer ones, or the only candidate word is a prefix of.
func closest(word string, candidates []string) string {
	if word == "" {
		return ""
	}
	limit := 1
	if len(word) > 4 {
		limit = 2
	}
	best, bestDist := "", limit+1
	for _, c := range candidates {
		if d := editDistance(word, c); d < bestDist {
			best, bestDist = c, d
		}
	}
	if best != "" {
		return best
	}
	if len(word) >= 3 {
		var prefixed []string
		for _, c := range candidates {
			if strings.HasPrefix(c, word) {
				prefixed = append(prefixed, c)
			}
		}
		if len(prefixed) == 1 {
			return prefixed[0]
		}
	}
	return ""
}

// editDistance is the optimal-string-alignment distance between a and b:
// insertions, deletions, substitutions and swaps of two adjacent letters.
func editDistance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}

// unknownCommand reports a token that is not a command and returns the
// usage exit code.
func unknownCommand(token string) int {
	fmt.Fprintf(os.Stderr, "agentguard: unknown command %q.", token)
	if s := suggestCommand(token); s != "" {
		fmt.Fprintf(os.Stderr, " Did you mean 'agentguard %s'?", s)
	}
	fmt.Fprintln(os.Stderr, "\nRun 'agentguard help' for the list of commands.")
	return exitUsage
}

// usageError reports a command-line mistake for cmd ("approve",
// "tenant put", …) and returns the usage exit code.
func usageError(cmd, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "agentguard %s: %s\nRun 'agentguard %s -h' for help.\n", cmd, fmt.Sprintf(format, a...), cmd)
	return exitUsage
}

// parseArgs parses args with fs and returns the positional arguments. Flags
// may come before, between or after them: Go's flag package on its own stops
// at the first positional and silently ignores every flag after it, so
// `approve ap_1 --url X` would have gone to the default server. A "--" ends
// flag parsing; everything after it is positional.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		if used := len(args) - len(rest); used > 0 && args[used-1] == "--" {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// parseCommand parses a subcommand's arguments. It silences the flag
// package's own output: -h prints usage to stdout (exit 0) and a bad flag
// prints one line and a pointer to -h (exit 2) instead of the whole flag
// list. ok is false when the caller should return code.
func parseCommand(fs *flag.FlagSet, usage func(io.Writer), args []string) (positional []string, code int, ok bool) {
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	positional, err := parseArgs(fs, args)
	switch {
	case err == nil:
		return positional, 0, true
	case errors.Is(err, flag.ErrHelp):
		usage(os.Stdout)
		return nil, 0, false
	default:
		return nil, usageError(fs.Name(), "%s", flagError(fs, err)), false
	}
}

// flagError rewords the flag package's parse errors in the --flag spelling
// the docs use, with a suggestion for a mistyped flag name.
func flagError(fs *flag.FlagSet, err error) string {
	msg := err.Error()
	if name, found := strings.CutPrefix(msg, "flag provided but not defined: "); found {
		name = strings.TrimLeft(name, "-")
		out := fmt.Sprintf("unknown flag --%s", name)
		var names []string
		fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
		if s := closest(name, names); s != "" {
			out += fmt.Sprintf(" (did you mean --%s?)", s)
		}
		return out
	}
	if name, found := strings.CutPrefix(msg, "flag needs an argument: "); found {
		return fmt.Sprintf("--%s needs a value", strings.TrimLeft(name, "-"))
	}
	return msg
}

// flagWasSet reports whether any of names was given on the command line.
func flagWasSet(fs *flag.FlagSet, names ...string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		for _, n := range names {
			if f.Name == n {
				set = true
			}
		}
	})
	return set
}

// ── Help layout ──────────────────────────────────────────────────────────

// urlAlias prints --guard-url on --url's line in the client commands' help.
var urlAlias = clihelp.Options{Aliases: map[string]string{"guard-url": "url"}}

// policyHelp hides --policy's "(default configs/default.yaml)": the default
// is a search order, which the command's help spells out.
var policyHelp = clihelp.Options{HideDefault: map[string]bool{"policy": true}}

// serverHelp also hides --node-id's default: it is this machine's hostname,
// which the flag's description already names, and printing it would make
// the help differ from host to host (and overflow on long hostnames).
var serverHelp = clihelp.Options{HideDefault: map[string]bool{"policy": true, "node-id": true}}

// ── Policy file discovery ────────────────────────────────────────────────

const defaultPolicyPath = "configs/default.yaml"

// systemPolicyPath is where a root install of AgentGuard (and the container
// image) keeps the starter policy. A variable only so tests can move it.
var systemPolicyPath = "/etc/agentguard/default.yaml"

// installedPolicyPaths are the files the installer writes the starter policy
// to, most specific first: the user's config folder, then the system one.
// They match scripts/install.sh and scripts/install.ps1, which use ~/.config
// on macOS as well (not ~/Library).
func installedPolicyPaths() []string {
	if goos == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return []string{filepath.Join(d, "agentguard", "default.yaml")}
		}
		return nil
	}
	var paths []string
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		paths = append(paths, filepath.Join(d, "agentguard", "default.yaml"))
	} else if h, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(h, ".config", "agentguard", "default.yaml"))
	}
	return append(paths, systemPolicyPath)
}

// findPolicy picks the policy file for server, validate and check. An
// explicit --policy always wins. Otherwise: AGENTGUARD_POLICY, then
// ./configs/default.yaml (the --policy default, so running from a checkout
// behaves as it always has), then the installer's starter policy. note says
// where an implicit choice came from, for the "Using policy" line; it is ""
// when the operator named the file with --policy.
func findPolicy(flagValue string, explicit bool) (path, note string, err error) {
	if explicit {
		return flagValue, "", nil
	}
	if env := os.Getenv("AGENTGUARD_POLICY"); env != "" {
		return env, "from AGENTGUARD_POLICY", nil
	}
	tried := []string{defaultPolicyPath}
	if fileExists(defaultPolicyPath) {
		return defaultPolicyPath, "the default", nil
	}
	for _, p := range installedPolicyPaths() {
		if fileExists(p) {
			return p, "found automatically", nil
		}
		tried = append(tried, p)
	}
	return "", "", fmt.Errorf("no policy file found (looked for %s); pass --policy <file> or set AGENTGUARD_POLICY", strings.Join(tried, ", "))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ── Talking to a running server ──────────────────────────────────────────

const defaultServerURL = "http://localhost:8080"

// addServerURLFlags registers --url and its --guard-url alias (the name the
// MCP gateway and LLM proxy use for the same thing) on fs.
func addServerURLFlags(fs *flag.FlagSet) *string {
	u := fs.String("url", defaultServerURL, "AgentGuard server URL. Env: AGENTGUARD_URL")
	fs.StringVar(u, "guard-url", defaultServerURL, "Same as --url")
	return u
}

// serverURL returns the server to talk to: --url or --guard-url when given,
// else AGENTGUARD_URL, else the flag default. It rejects a value that isn't
// an http(s) URL, which would otherwise fail later with a cryptic
// "unsupported protocol scheme".
func serverURL(fs *flag.FlagSet, value string) (string, error) {
	if !flagWasSet(fs, "url", "guard-url") {
		if env := os.Getenv("AGENTGUARD_URL"); env != "" {
			value = env
		}
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%q is not a server URL; include the scheme, e.g. http://localhost:8080", value)
	}
	return strings.TrimRight(value, "/"), nil
}

// cannotConnect is the message for a server that can't be reached.
func cannotConnect(w io.Writer, baseURL string, err error) {
	fmt.Fprintf(w, "Cannot connect to AgentGuard at %s (%s).\n", baseURL, connectFailure(err))
	fmt.Fprintln(w, "Is 'agentguard server' running there? Use --url or AGENTGUARD_URL to point at another server.")
}

// connectFailure names why a request didn't reach the server, in words.
func connectFailure(err error) string {
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return "unknown host " + dnsErr.Name
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	case strings.Contains(strings.ToLower(err.Error()), "refused"):
		return "connection refused"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err.Error()
	}
	return err.Error()
}
