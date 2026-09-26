package main

// End-to-end tests of the agentguard command line: each case runs the real
// main() in a child process (this test binary, re-executed) and checks the
// exit status and output a user would see.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
)

// runMainEnv tells the re-executed test binary to run main() with the
// JSON-encoded argument list it holds instead of the tests.
const runMainEnv = "AGENTGUARD_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(runMainEnv); ok {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			panic(err)
		}
		os.Args = append([]string{"agentguard"}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type cliResult struct {
	code           int
	stdout, stderr string
}

// agentguard runs `agentguard args...` in dir with env added to a clean
// environment (no update check, no AGENTGUARD_* leaking in from the host).
func agentguard(t *testing.T, dir string, env []string, args ...string) cliResult {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AGENTGUARD_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, runMainEnv+"="+string(raw), "AGENTGUARD_NO_UPDATE_CHECK=1")
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	code := 0
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("running agentguard %q: %v", args, err)
	}
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func (r cliResult) expect(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, stdout) {
		t.Errorf("stdout lacks %q:\n%s", stdout, r.stdout)
	}
	if !strings.Contains(r.stderr, stderr) {
		t.Errorf("stderr lacks %q:\n%s", stderr, r.stderr)
	}
}

func TestCLI_Help(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		agentguard(t, dir, nil, args...).expect(t, 0, "server      Start AgentGuard", "")
	}
	agentguard(t, dir, nil).expect(t, 2, "", "Usage:")

	// `help <command>`, `<command> -h` and the old `serve` name all print the
	// same help, on stdout, exit 0.
	want := agentguard(t, dir, nil, "server", "-h")
	want.expect(t, 0, "Usage: agentguard server", "")
	for _, args := range [][]string{{"help", "server"}, {"help", "serve"}, {"serve", "--help"}} {
		if got := agentguard(t, dir, nil, args...); got.code != 0 || got.stdout != want.stdout {
			t.Errorf("agentguard %q: exit %d, help differs from 'server -h'", args, got.code)
		}
	}
	agentguard(t, dir, nil, "help", "tenant", "put").expect(t, 0, "Usage: agentguard tenant put", "")
	agentguard(t, dir, nil, "check", "--help").expect(t, 0, "Usage: agentguard check", "")
}

// Every help page: exits 0, fits 80 columns, has an example, and leaves no
// flag out of its groups.
func TestCLI_HelpPages(t *testing.T) {
	dir := t.TempDir()
	pages := [][]string{
		{"setup", "-h"}, {"server", "-h"}, {"validate", "-h"}, {"check", "-h"}, {"approve", "-h"}, {"deny", "-h"},
		{"status", "-h"}, {"audit", "-h"}, {"tenant", "-h"}, {"tenant", "put", "-h"},
		{"tenant", "list", "-h"}, {"tenant", "rm", "-h"}, {"migrate", "-h"}, {"help", "help"},
	}
	for _, args := range pages {
		r := agentguard(t, dir, nil, args...)
		if r.code != 0 {
			t.Errorf("agentguard %q: exit %d", args, r.code)
		}
		if !strings.Contains(r.stdout, "Example") {
			t.Errorf("agentguard %q: no example", args)
		}
		if strings.Contains(r.stdout, clihelp.Ungrouped+":") {
			t.Errorf("agentguard %q: a flag is missing from the help groups", args)
		}
		for _, line := range strings.Split(r.stdout, "\n") {
			if utf8.RuneCountInString(line) > clihelp.Width {
				t.Errorf("agentguard %q: line wider than %d: %q", args, clihelp.Width, line)
			}
		}
	}
}

func TestCLI_TopLevelHelpGetsYouStarted(t *testing.T) {
	r := agentguard(t, t.TempDir(), nil, "help")
	for _, want := range []string{
		"Get started:", "agentguard server --dashboard", "http://localhost:8080/dashboard",
		"agentguard-mcp-gateway", "agentguard-llm-proxy",
		"https://github.com/Caua-ferraz/AgentGuard/blob/v" + version + "/docs/CLI.md",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("top-level help lacks %q", want)
		}
	}
	for _, line := range strings.Split(r.stdout, "\n") {
		if utf8.RuneCountInString(line) > clihelp.Width {
			t.Errorf("line wider than %d: %q", clihelp.Width, line)
		}
	}
}

func TestCLI_ClientHelpShowsAliasOnce(t *testing.T) {
	r := agentguard(t, t.TempDir(), nil, "approve", "-h")
	if !strings.Contains(r.stdout, "--url, --guard-url string") {
		t.Errorf("approve help doesn't show --guard-url on --url's line:\n%s", r.stdout)
	}
	if strings.Contains(r.stdout, "\n  --guard-url") {
		t.Errorf("approve help lists --guard-url on its own line:\n%s", r.stdout)
	}
}

// `version -h` failed with "unexpected argument" and `help version` printed
// the whole command list.
func TestCLI_VersionAndHelpHaveTheirOwnHelp(t *testing.T) {
	dir := t.TempDir()
	agentguard(t, dir, nil, "version", "-h").expect(t, 0, "Usage: agentguard version", "")
	agentguard(t, dir, nil, "help", "version").expect(t, 0, "Usage: agentguard version", "")
	agentguard(t, dir, nil, "help", "help").expect(t, 0, "Usage: agentguard help [<command>", "")
}

func TestCLI_TenantPutNamesTheStore(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(repoRootForDocs(t), "configs", "default.yaml")
	agentguard(t, dir, nil, "tenant", "put", "acme", "--policy", policy, "--data-dir", dir).
		expect(t, 0, "A server sees it only if it uses this same store", "")
}

// Without a terminal (a script, CI) setup can't show its menu: it prints
// the status and points to the installers, and exits 2.
func TestCLI_SetupNeedsATerminal(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("setup refuses to run as root")
	}
	dir := t.TempDir()
	env := []string{"XDG_CONFIG_HOME=" + dir, "XDG_DATA_HOME=" + dir, "APPDATA=" + dir, "LOCALAPPDATA=" + dir, "AGENTGUARD_DISTRIBUTION="}
	agentguard(t, dir, env, "setup").expect(t, 2, "not set up yet", "")
	agentguard(t, dir, env, "setup").expect(t, 2, "setup is interactive", "")
	agentguard(t, dir, env, "setup", "--yes").expect(t, 2, "", "unknown flag --yes")
	agentguard(t, dir, []string{"AGENTGUARD_DISTRIBUTION=container"}, "setup").expect(t, 1, "", "docker pull")
}

func TestCLI_UnknownCommand(t *testing.T) {
	dir := t.TempDir()
	agentguard(t, dir, nil, "--serve").expect(t, 2, "", "Did you mean 'agentguard server'?")
	agentguard(t, dir, nil, "stauts").expect(t, 2, "", "Did you mean 'agentguard status'?")
	agentguard(t, dir, nil, "help", "sever").expect(t, 2, "", "Did you mean 'agentguard server'?")
	agentguard(t, dir, nil, "frobnicate").expect(t, 2, "", "Run 'agentguard help'")
}

func TestCLI_VersionSpellings(t *testing.T) {
	dir := t.TempDir()
	for _, arg := range []string{"version", "--version", "-version"} {
		agentguard(t, dir, nil, arg).expect(t, 0, "agentguard "+version, "")
	}
}

// A flag after the approval ID used to be dropped without a word, so this
// approved on http://localhost:8080 instead of the named server.
func TestCLI_ApproveFlagsAfterID(t *testing.T) {
	srv := newFakeServer(t, http.StatusOK, `{"status":"approved","id":"ap_1"}`)
	agentguard(t, t.TempDir(), nil, "approve", "ap_1", "--url", srv.URL, "--api-key", "k").expect(t, 0, "Approved ap_1", "")
	if path, auth, _ := srv.last(); path != "/v1/approve/ap_1" || auth != "Bearer k" {
		t.Errorf("server saw %s with Authorization %q", path, auth)
	}
}

func TestCLI_ServerURLFromEnv(t *testing.T) {
	srv := newFakeServer(t, http.StatusOK, `[]`)
	agentguard(t, t.TempDir(), []string{"AGENTGUARD_URL=" + srv.URL}, "status").expect(t, 0, "AgentGuard server: OK ("+srv.URL+")", "")
	if _, _, hits := srv.last(); hits == 0 {
		t.Error("status did not use AGENTGUARD_URL")
	}
	agentguard(t, t.TempDir(), []string{"AGENTGUARD_URL=http://127.0.0.1:1"}, "deny", "ap_1").expect(t, 1, "", "Cannot connect to AgentGuard at http://127.0.0.1:1")
}

func TestCLI_ArgumentMistakes(t *testing.T) {
	dir := t.TempDir()
	agentguard(t, dir, nil, "approve").expect(t, 2, "", "missing the approval ID")
	agentguard(t, dir, nil, "deny", "a", "b").expect(t, 2, "", `unexpected argument "b"`)
	agentguard(t, dir, nil, "status", "extra").expect(t, 2, "", `unexpected argument "extra"`)
	agentguard(t, dir, nil, "server", "--prot", "1").expect(t, 2, "", "unknown flag --prot (did you mean --port?)")
	agentguard(t, dir, nil, "audit", "--url", "localhost:8080").expect(t, 2, "", "include the scheme")
	agentguard(t, dir, nil, "check", "extra").expect(t, 3, "", `unexpected argument "extra"`)

	// A mistyped tenant subcommand is caught before the store is opened, so
	// it no longer leaves an empty agentguard.db behind.
	agentguard(t, dir, nil, "tenant", "lst").expect(t, 2, "", "Did you mean 'agentguard tenant list'?")
	if _, err := os.Stat(filepath.Join(dir, "agentguard.db")); err == nil {
		t.Error("tenant typo created agentguard.db")
	}
}

func TestCLI_ValidateFileArgument(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte("rules: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The file argument used to be ignored and the default policy validated
	// instead, printing VALID for a broken file.
	agentguard(t, dir, nil, "validate", broken).expect(t, 1, "", "INVALID")
	agentguard(t, dir, nil, "validate", "a.yaml", "--policy", "b.yaml").expect(t, 2, "", "not both")

	good := filepath.Join(repoRootForDocs(t), "configs", "default.yaml")
	agentguard(t, dir, nil, "validate", good, "--strict").expect(t, 0, "VALID", "")
	agentguard(t, dir, []string{"AGENTGUARD_POLICY=" + good}, "validate").expect(t, 0, "VALID", "(from AGENTGUARD_POLICY)")
}
