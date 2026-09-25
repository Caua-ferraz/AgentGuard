package main

// Unit tests for the shared command-line plumbing in cli.go. The
// end-to-end behaviour of the real binary is in cli_exec_test.go.

import (
	"bytes"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeServer answers every request with status and body, and records the
// last request's path and Authorization header for the test to check.
type fakeServer struct {
	*httptest.Server
	mu         sync.Mutex
	path, auth string
	hits       int
}

func newFakeServer(t *testing.T, status int, body string) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.path, f.auth = r.URL.Path, r.Header.Get("Authorization")
		f.hits++
		f.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.Close)
	return f
}

// last returns the recorded path, Authorization header and request count.
func (f *fakeServer) last() (path, auth string, hits int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.path, f.auth, f.hits
}

func TestLookupCommand(t *testing.T) {
	cases := map[string]string{
		"server":    "server",
		"serve":     "server", // frozen 1.x alias
		"validate":  "validate",
		"help":      "help",
		"-h":        "help",
		"--help":    "help",
		"-help":     "help",
		"version":   "version",
		"--version": "version",
		"-version":  "version",
	}
	for token, want := range cases {
		if got, ok := lookupCommand(token); !ok || got != want {
			t.Errorf("lookupCommand(%q) = %q, %v; want %q", token, got, ok, want)
		}
	}
	for _, token := range []string{"", "--serve", "sever", "Server"} {
		if got, ok := lookupCommand(token); ok {
			t.Errorf("lookupCommand(%q) = %q; want not found", token, got)
		}
	}
}

// Every command in the frozen 1.x list must still dispatch
// (docs/COMPATIBILITY.md, frozen surface 4).
func TestLookupCommand_FrozenSubcommandsStillExist(t *testing.T) {
	for _, name := range []string{"serve", "validate", "check", "approve", "deny", "status", "audit", "tenant", "migrate", "version"} {
		if _, ok := lookupCommand(name); !ok {
			t.Errorf("frozen subcommand %q no longer dispatches", name)
		}
	}
}

func TestSuggestCommand(t *testing.T) {
	cases := map[string]string{
		"--serve":    "server",
		"--server":   "server",
		"-status":    "status",
		"sever":      "server",
		"servr":      "server",
		"stauts":     "status",
		"aprove":     "approve",
		"valdiate":   "validate",
		"tennat":     "tenant",
		"migarte":    "migrate",
		"vers":       "version",
		"frobnicate": "",
		"x":          "",
		"":           "",
	}
	for token, want := range cases {
		if got := suggestCommand(token); got != want {
			t.Errorf("suggestCommand(%q) = %q, want %q", token, got, want)
		}
	}
}

func TestParseArgs_FlagsAnywhere(t *testing.T) {
	cases := []struct {
		args    []string
		wantURL string
		wantPos []string
	}{
		{[]string{"--url", "http://a", "ap_1"}, "http://a", []string{"ap_1"}},
		{[]string{"ap_1", "--url", "http://a"}, "http://a", []string{"ap_1"}},
		{[]string{"ap_1", "--url=http://a", "ap_2"}, "http://a", []string{"ap_1", "ap_2"}},
		{[]string{"ap_1", "--", "--url", "http://a"}, "http://default", []string{"ap_1", "--url", "http://a"}},
		{nil, "http://default", nil},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		u := fs.String("url", "http://default", "")
		pos, err := parseArgs(fs, c.args)
		if err != nil {
			t.Fatalf("parseArgs(%q): %v", c.args, err)
		}
		if *u != c.wantURL || strings.Join(pos, " ") != strings.Join(c.wantPos, " ") {
			t.Errorf("parseArgs(%q) = url %q, positional %q; want %q, %q", c.args, *u, pos, c.wantURL, c.wantPos)
		}
	}
}

func TestFlagError_SuggestsTheFlag(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	fs.String("policy", "", "")
	_, err := parseArgs(fs, []string{"--polcy", "x"})
	if got := flagError(fs, err); got != "unknown flag --polcy (did you mean --policy?)" {
		t.Errorf("flagError = %q", got)
	}
	_, err = parseArgs(fs, []string{"--policy"})
	if got := flagError(fs, err); got != "--policy needs a value" {
		t.Errorf("flagError = %q", got)
	}
}

// isolatePolicySearch points every place findPolicy looks at an empty temp
// folder, so a policy on the machine running the tests can't leak in.
func isolatePolicySearch(t *testing.T, platform string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("AGENTGUARD_POLICY", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg"))
	t.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	prevGOOS, prevSystem := goos, systemPolicyPath
	goos, systemPolicyPath = platform, filepath.Join(dir, "etc", "agentguard", "default.yaml")
	t.Cleanup(func() { goos, systemPolicyPath = prevGOOS, prevSystem })
	return dir
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("name: t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFindPolicy_Order(t *testing.T) {
	dir := isolatePolicySearch(t, "linux")
	xdg := filepath.Join(dir, "xdg", "agentguard", "default.yaml")
	system := systemPolicyPath

	if _, _, err := findPolicy(defaultPolicyPath, false); err == nil || !strings.Contains(err.Error(), "no policy file found") {
		t.Fatalf("nothing on disk: err = %v", err)
	}

	writeFile(t, system)
	if p, _, _ := findPolicy(defaultPolicyPath, false); p != system {
		t.Errorf("root install: got %q, want %q", p, system)
	}
	writeFile(t, xdg)
	if p, _, _ := findPolicy(defaultPolicyPath, false); p != xdg {
		t.Errorf("user config beats system: got %q, want %q", p, xdg)
	}
	writeFile(t, filepath.Join(dir, "configs", "default.yaml"))
	if p, _, _ := findPolicy(defaultPolicyPath, false); p != defaultPolicyPath {
		t.Errorf("./configs/default.yaml keeps its old precedence: got %q", p)
	}
	t.Setenv("AGENTGUARD_POLICY", "from-env.yaml")
	if p, note, _ := findPolicy(defaultPolicyPath, false); p != "from-env.yaml" || !strings.Contains(note, "AGENTGUARD_POLICY") {
		t.Errorf("env: got %q (%q)", p, note)
	}
	if p, note, _ := findPolicy("explicit.yaml", true); p != "explicit.yaml" || note != "" {
		t.Errorf("--policy must win: got %q (%q)", p, note)
	}
}

func TestFindPolicy_Windows(t *testing.T) {
	dir := isolatePolicySearch(t, "windows")
	appdata := filepath.Join(dir, "appdata", "agentguard", "default.yaml")
	writeFile(t, appdata)
	if p, note, err := findPolicy(defaultPolicyPath, false); err != nil || p != appdata || note != "found automatically" {
		t.Errorf("got %q (%q, %v), want %q", p, note, err, appdata)
	}
}

func TestServerURL(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(&bytes.Buffer{})
		return fs, addServerURLFlags(fs)
	}
	cases := []struct {
		name, env string
		args      []string
		want      string
		wantErr   bool
	}{
		{name: "default", want: defaultServerURL},
		{name: "env", env: "http://env:1/", want: "http://env:1"},
		{name: "flag beats env", env: "http://env:1", args: []string{"--url", "http://flag:2"}, want: "http://flag:2"},
		{name: "guard-url alias", env: "http://env:1", args: []string{"--guard-url", "https://g:3"}, want: "https://g:3"},
		{name: "no scheme", args: []string{"--url", "localhost:8080"}, wantErr: true},
		{name: "bad env", env: "agentguard:8080", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AGENTGUARD_URL", c.env)
			fs, u := newFS()
			if err := fs.Parse(c.args); err != nil {
				t.Fatal(err)
			}
			got, err := serverURL(fs, *u)
			if (err != nil) != c.wantErr || got != c.want {
				t.Errorf("serverURL = %q, %v; want %q (error %v)", got, err, c.want, c.wantErr)
			}
		})
	}
}

// A server flag missing from serverFlagGroups would land under "Other" in
// `agentguard server -h`; a name in a group with no flag behind it would
// be a typo that hides the flag it meant.
func TestServerHelp_GroupsEveryFlag(t *testing.T) {
	fs, _ := newServerFlags()
	seen := map[string]int{}
	for _, g := range serverFlagGroups {
		for _, n := range g.Names {
			seen[n]++
			if fs.Lookup(n) == nil {
				t.Errorf("group %q lists %q, which is not a server flag", g.Title, n)
			}
		}
	}
	fs.VisitAll(func(f *flag.Flag) {
		if seen[f.Name] != 1 {
			t.Errorf("server flag --%s is in %d help groups, want exactly 1", f.Name, seen[f.Name])
		}
	})
	var help bytes.Buffer
	serverUsage(&help, fs)
	for _, want := range []string{"Usage: agentguard server", "'agentguard serve'", "--audit-compress", "--audit-compress=false turns it off", "(default 8080)"} {
		if !strings.Contains(help.String(), want) {
			t.Errorf("server help lacks %q", want)
		}
	}
	for _, bad := range []string{"\nOther:", "  -port"} {
		if strings.Contains(help.String(), bad) {
			t.Errorf("server help contains %q", bad)
		}
	}
}

func TestCannotConnect_NamesTheFixes(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, err := http.Get(url)
	if err == nil {
		t.Fatal("expected a connection error")
	}
	var out bytes.Buffer
	cannotConnect(&out, url, err)
	for _, want := range []string{"Cannot connect to AgentGuard at " + url, "connection refused", "agentguard server", "AGENTGUARD_URL"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("message lacks %q: %q", want, out.String())
		}
	}
}

func TestRunResolve(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		key      string
		wantCode int
		wantOut  string
	}{
		{"approved", 200, `{"status":"approved","id":"ap_1"}`, "k", 0, "Approved ap_1"},
		{"already resolved", 409, `{"error":"already resolved","id":"ap_1","status":"denied"}`, "k", 1, "ap_1 was already denied"},
		{"not found (plain text)", 404, "pending action ap_1 not found\n", "k", 1, "no pending approval ap_1"},
		{"no key", 401, "Unauthorized\n", "", 1, "requires an API key"},
		{"wrong key", 401, "invalid api key\n", "bad", 1, "rejected the API key"},
		{"html page", 502, "<html><body>Bad gateway</body></html>", "k", 1, "is this an AgentGuard server?"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newFakeServer(t, c.status, c.body)
			var out, errOut bytes.Buffer
			code := runResolve(&out, &errOut, srv.URL, "ap_1", "approve", c.key)
			gotPath, gotAuth, _ := srv.last()
			if code != c.wantCode {
				t.Errorf("exit = %d, want %d", code, c.wantCode)
			}
			if !strings.Contains(out.String()+errOut.String(), c.wantOut) {
				t.Errorf("output %q lacks %q", out.String()+errOut.String(), c.wantOut)
			}
			if gotPath != "/v1/approve/ap_1" {
				t.Errorf("path = %q", gotPath)
			}
			if c.key != "" && gotAuth != "Bearer "+c.key {
				t.Errorf("Authorization = %q", gotAuth)
			}
		})
	}
}
