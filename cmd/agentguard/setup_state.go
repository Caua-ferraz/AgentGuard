package main

// setup_state.go: what `agentguard setup` knows about this computer — how
// this copy was installed, where its files live, what setup set up before
// (setup.json), and whether the server answers.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Caua-ferraz/AgentGuard/cmd/internal/buildinfo"
	"github.com/Caua-ferraz/AgentGuard/internal/localconfig"
)

// tools are the three binaries a release installs, side by side.
var tools = []string{"agentguard", "agentguard-mcp-gateway", "agentguard-llm-proxy"}

// How this copy of agentguard was installed; it decides how it updates.
const (
	channelRelease   = "release"    // installer or release archive: setup updates it
	channelGoInstall = "go-install" // `go install …@version`: go install updates it
	channelSource    = "source"     // built from a checkout: nothing to update to
	channelContainer = "container"  // the container image: docker pull updates it
)

// machine is this computer as setup sees it.
type machine struct {
	goos, goarch string
	exe          string // this binary, symlinks resolved
	binDir       string // the folder it lives in, with the other two
	configDir    string // policy, API key, setup.json
	dataDir      string // audit log, state database, server log
	channel      string
}

func detectMachine() (machine, error) {
	m := machine{goos: goos, goarch: runtime.GOARCH}
	exe, err := os.Executable()
	if err != nil {
		return m, fmt.Errorf("can't find this program's own path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	m.exe, m.binDir = exe, filepath.Dir(exe)
	m.configDir = localconfig.ConfigDir(goos)
	m.dataDir = localconfig.DataDir(goos)
	if m.configDir == "" || m.dataDir == "" {
		return m, errors.New("can't find your home folder (HOME / APPDATA / LOCALAPPDATA is not set)")
	}
	m.channel = installChannel(commit)
	return m, nil
}

// installChannel tells the ways of installing apart with the signals
// updateCommand already uses.
func installChannel(currentCommit string) string {
	switch {
	case os.Getenv("AGENTGUARD_DISTRIBUTION") == "container":
		return channelContainer
	case strings.Contains(version, "dev"):
		return channelSource
	case currentCommit == "dev" && buildinfo.ReleaseVersion() != "":
		return channelGoInstall
	case currentCommit == "dev":
		return channelSource
	default:
		return channelRelease
	}
}

func (m machine) exeName(tool string) string {
	if m.goos == "windows" {
		return tool + ".exe"
	}
	return tool
}

func (m machine) policyPath() string { return filepath.Join(m.configDir, localconfig.PolicyFile) }
func (m machine) keyPath() string    { return filepath.Join(m.configDir, localconfig.APIKeyFile) }
func (m machine) statePath() string  { return filepath.Join(m.configDir, localconfig.SetupFile) }
func (m machine) logPath() string    { return filepath.Join(m.dataDir, "server.log") }

// setupState is what setup set up, kept in <config>/setup.json so later
// runs, the status line and uninstall know it. Internal to setup: not a
// documented file format.
type setupState struct {
	Port       int    `json:"port"`
	Policy     string `json:"policy"`
	DataDir    string `json:"data_dir"`
	APIKey     bool   `json:"api_key"`     // the server runs with --api-key-file
	LoginStart bool   `json:"login_start"` // a login service runs it
}

func loadState(m machine) (*setupState, error) {
	b, err := os.ReadFile(m.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s setupState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", m.statePath(), err)
	}
	if s.Port == 0 {
		s.Port = 8080
	}
	return &s, nil
}

func saveState(m machine, s *setupState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath(), append(b, '\n'), 0o600)
}

// serverArgs is the command line the login service runs.
func serverArgs(m machine, s *setupState) []string {
	args := []string{
		"server",
		"--policy", s.Policy,
		"--data-dir", s.DataDir,
		"--audit-log", filepath.Join(s.DataDir, "audit.jsonl"),
		"--port", fmt.Sprint(s.Port),
		"--bind", "127.0.0.1",
		"--dashboard",
	}
	if s.APIKey {
		args = append(args, "--api-key-file", m.keyPath())
	}
	return args
}

func baseURL(port int) string { return fmt.Sprintf("http://127.0.0.1:%d", port) }

// serverHealth asks the server on port for /health and returns the version
// it reports, or "" when nothing answers as AgentGuard. A variable so tests
// can stand in for a server.
var serverHealth = func(port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL(port)+"/health", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&body) != nil || body.Status != "ok" {
		return ""
	}
	if body.Version == "" {
		return "?"
	}
	return body.Version
}

// waitForHealth polls /health until the server answers or timeout passes.
func waitForHealth(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if serverHealth(port) != "" {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// freePort returns want when nothing listens on it, else the next free
// port up to want+19.
func freePort(want int) (int, error) {
	for p := want; p < want+20; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			_ = l.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("ports %d-%d are all in use", want, want+19)
}
