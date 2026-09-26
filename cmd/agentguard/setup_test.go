package main

// Tests for `agentguard setup`: the service definitions it writes, the
// release download and binary swap, and the set-up and uninstall flows,
// driven through a scripted terminal and a fake login service.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/cmd/internal/buildinfo"
	"github.com/Caua-ferraz/AgentGuard/configs"
	"github.com/Caua-ferraz/AgentGuard/internal/tui"
)

// ── Service definitions ─────────────────────────────────────────────────

// testSpec is a Linux-style service spec, written out so the test reads the
// same on every OS (serverArgs joins paths with the OS's separator).
func testSpec() serviceSpec {
	data := "/home/u/.local/share/agentguard"
	return serviceSpec{
		Exe: "/home/u/.local/bin/agentguard",
		Args: []string{"server", "--policy", "/home/u/my policies/100% safe.yaml", "--data-dir", data,
			"--port", "8080", "--bind", "127.0.0.1", "--dashboard", "--api-key-file", "/home/u/.config/agentguard/api-key"},
		WorkDir: data,
		LogFile: data + "/server.log",
	}
}

func TestServerArgs(t *testing.T) {
	m := machine{goos: "linux", configDir: "/c"}
	args := strings.Join(serverArgs(m, &setupState{Port: 9000, Policy: "/p.yaml", DataDir: "/d", APIKey: true}), " ")
	for _, want := range []string{"server ", "--policy /p.yaml", "--data-dir /d", "--audit-log " + filepath.Join("/d", "audit.jsonl"), "--port 9000", "--bind 127.0.0.1", "--dashboard", "--api-key-file " + filepath.Join("/c", "api-key")} {
		if !strings.Contains(args, want) {
			t.Errorf("server args lack %q: %s", want, args)
		}
	}
	if args := strings.Join(serverArgs(m, &setupState{Port: 1, Policy: "/p", DataDir: "/d"}), " "); strings.Contains(args, "api-key") {
		t.Errorf("no key chosen, but the args name one: %s", args)
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	unit := renderSystemdUnit(testSpec())
	for _, want := range []string{
		`ExecStart="/home/u/.local/bin/agentguard" "server"`,
		`"/home/u/my policies/100%% safe.yaml"`, // space kept inside quotes, % doubled
		`"--api-key-file" "/home/u/.config/agentguard/api-key"`,
		"Restart=on-failure",
		"WantedBy=default.target",
		// Only command lines take quotes; a quoted path here is "a bad unit
		// file setting" (found by the real-service CI job).
		"\nWorkingDirectory=/home/u/.local/share/agentguard\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
}

func TestRenderLaunchdPlist(t *testing.T) {
	spec := testSpec()
	spec.Exe = "/Users/u/bin/a&b/agentguard"
	plist := renderLaunchdPlist(spec)
	for _, want := range []string{
		"<string>" + launchdLabel + "</string>",
		"<string>/Users/u/bin/a&amp;b/agentguard</string>",
		"<string>--api-key-file</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>StandardErrorPath</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
}

func TestRenderTaskScript(t *testing.T) {
	spec := serviceSpec{
		Exe:     `C:\Users\O'Neil\AppData\Local\Programs\AgentGuard\bin\agentguard.exe`,
		Args:    []string{"server", "--policy", `C:\Users\O'Neil\AppData\Roaming\agentguard\default.yaml`, "--dashboard"},
		WorkDir: `C:\Users\O'Neil\AppData\Local\AgentGuard\data`,
		LogFile: `C:\Users\O'Neil\AppData\Local\AgentGuard\data\server.log`,
	}
	script := renderTaskScript(spec)
	for _, want := range []string{
		`-Execute 'conhost.exe'`,
		`--headless cmd.exe /d /s /c "`,
		`O''Neil`, // a quote in the path is doubled for PowerShell
		`>> C:\Users\O''Neil\AppData\Local\AgentGuard\data\server.log 2>&1"`,
		"New-ScheduledTaskTrigger -AtLogOn -User $user",
		"-RunLevel Limited",
		"Register-ScheduledTask -TaskName 'AgentGuard'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("task script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "O'Neil") {
		t.Errorf("an undoubled quote would end the PowerShell string early:\n%s", script)
	}
}

// ── Release download and swap ───────────────────────────────────────────

func fakeArchive(t *testing.T, m machine, v string) []byte {
	t.Helper()
	dir := fmt.Sprintf("agentguard_%s_%s_%s/", v, m.goos, m.goarch)
	var buf bytes.Buffer
	if m.goos == "windows" {
		// Backslashes, as Windows PowerShell's Compress-Archive writes them.
		zw := zip.NewWriter(&buf)
		for _, tool := range tools {
			w, _ := zw.Create(strings.TrimSuffix(dir, "/") + `\` + m.exeName(tool))
			fmt.Fprintf(w, "%s %s", tool, v)
		}
		_ = zw.Close()
		return buf.Bytes()
	}
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, tool := range append([]string{"README.md"}, tools...) {
		body := fmt.Sprintf("%s %s", tool, v)
		_ = tw.WriteHeader(&tar.Header{Name: dir + tool, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// releaseServer serves one version's archive and checksums.txt, the way a
// mirror behind AGENTGUARD_DOWNLOAD_URL would.
func releaseServer(t *testing.T, m machine, v string, tamper bool) {
	t.Helper()
	archive := fakeArchive(t, m, v)
	sum := sha256.Sum256(archive)
	if tamper {
		archive = append(archive, 0)
	}
	name := releaseArchive(v, m.goos, m.goarch)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt":
			fmt.Fprintf(w, "%s  other.tar.gz\n%s *%s\n", strings.Repeat("0", 64), hex.EncodeToString(sum[:]), name)
		case "/" + name:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AGENTGUARD_DOWNLOAD_URL", srv.URL)
}

func TestDownloadAndReplace(t *testing.T) {
	for _, osName := range []string{"linux", "windows"} {
		t.Run(osName, func(t *testing.T) {
			m := machine{goos: osName, goarch: "amd64", binDir: t.TempDir()}
			for _, tool := range tools {
				_ = os.WriteFile(filepath.Join(m.binDir, m.exeName(tool)), []byte("old"), 0o755)
			}
			releaseServer(t, m, "9.9.9", false)
			bins, err := downloadRelease(t.Context(), m, "9.9.9")
			if err != nil {
				t.Fatal(err)
			}
			if err := replaceTools(m, bins); err != nil {
				t.Fatal(err)
			}
			for _, tool := range tools {
				got, _ := os.ReadFile(filepath.Join(m.binDir, m.exeName(tool)))
				if string(got) != tool+" 9.9.9" {
					t.Errorf("%s = %q after the update", tool, got)
				}
			}
			entries, _ := os.ReadDir(m.binDir)
			if len(entries) != len(tools) {
				t.Errorf("leftover files after the update: %v", entries)
			}
		})
	}
}

func TestDownloadRefusesATamperedArchive(t *testing.T) {
	m := machine{goos: "linux", goarch: "arm64"}
	releaseServer(t, m, "9.9.9", true)
	if _, err := downloadRelease(t.Context(), m, "9.9.9"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum mismatch", err)
	}
	if _, err := downloadRelease(t.Context(), machine{goos: "linux", goarch: "riscv64"}, "9.9.9"); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("an archive missing from checksums.txt: err = %v", err)
	}
}

func TestInstallChannel(t *testing.T) {
	cases := []struct {
		name, distribution, commit, module, want string
	}{
		{"container", "container", "abc1234", "", channelContainer},
		{"release build", "", "abc1234", "", channelRelease},
		{"go install", "", "dev", "v1.2.0", channelGoInstall},
		{"source build", "", "dev", "(devel)", channelSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AGENTGUARD_DISTRIBUTION", c.distribution)
			prev := buildinfo.Read
			buildinfo.Read = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: c.module}}, true
			}
			t.Cleanup(func() { buildinfo.Read = prev })
			if got := installChannel(c.commit); got != c.want {
				t.Errorf("installChannel = %q, want %q", got, c.want)
			}
		})
	}
}

// ── The flows, through a scripted terminal ─────────────────────────────

// scriptedUI answers each menu with the next scripted choice and records
// what setup printed.
type scriptedUI struct {
	t       *testing.T
	choices []int
	titles  []string
	out     bytes.Buffer
}

func (u *scriptedUI) Select(title string, opts []tui.Option, def int) (int, error) {
	u.titles = append(u.titles, title)
	if len(u.choices) == 0 {
		u.t.Fatalf("setup asked %q but the script has no answer left", title)
	}
	c := u.choices[0]
	u.choices = u.choices[1:]
	return c, nil
}
func (u *scriptedUI) Printf(format string, a ...any) { fmt.Fprintf(&u.out, format, a...) }
func (u *scriptedUI) Style() tui.Style               { return tui.Style{} }

// fakeService is a login service that only records what it was asked.
type fakeService struct {
	installed bool
	spec      serviceSpec
	calls     []string
}

func (f *fakeService) Describe() string { return "fake service" }
func (f *fakeService) Available() error { return nil }
func (f *fakeService) Installed() bool  { return f.installed }
func (f *fakeService) Install(s serviceSpec) error {
	f.installed, f.spec = true, s
	f.calls = append(f.calls, "install")
	return nil
}
func (f *fakeService) Start() error   { f.calls = append(f.calls, "start"); return nil }
func (f *fakeService) Restart() error { f.calls = append(f.calls, "restart"); return nil }
func (f *fakeService) Remove() error {
	f.installed = false
	f.calls = append(f.calls, "remove")
	return nil
}
func (f *fakeService) LogHint() string { return "the log" }

// testMachine lays out a computer in a temp folder: an install folder with
// the three binaries, and empty config and data folders.
func testMachine(t *testing.T) machine {
	t.Helper()
	root := t.TempDir()
	m := machine{
		goos: goos, goarch: "amd64", channel: channelRelease,
		binDir:    filepath.Join(root, "bin"),
		configDir: filepath.Join(root, "config", "agentguard"),
		dataDir:   filepath.Join(root, "share", "agentguard"),
	}
	m.exe = filepath.Join(m.binDir, m.exeName("agentguard"))
	_ = os.MkdirAll(m.binDir, 0o755)
	for _, tool := range tools {
		_ = os.WriteFile(filepath.Join(m.binDir, m.exeName(tool)), []byte("bin"), 0o755)
	}
	return m
}

// serverUp makes every health check succeed, as if the server started.
func serverUp(t *testing.T) {
	prev := serverHealth
	serverHealth = func(int) string { return version }
	t.Cleanup(func() { serverHealth = prev })
}

func TestSetupFlow(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	ui := &scriptedUI{t: t, choices: []int{0, 0, 1}} // start at login: yes; API key: yes; then "Back to the menu"
	svc := &fakeService{}
	s := &setup{m: m, ui: ui, svc: svc}

	if done, _ := s.doSetup(); done {
		t.Fatal("set up should return to the menu")
	}

	if got, _ := os.ReadFile(m.policyPath()); !bytes.Equal(got, configs.Default) {
		t.Errorf("the starter policy wasn't written to %s", m.policyPath())
	}
	key, err := os.ReadFile(m.keyPath())
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}\n$`).Match(key) {
		t.Fatalf("API key file = %q, %v; want 64 hex characters", key, err)
	}
	if info, _ := os.Stat(m.keyPath()); goos != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("API key file mode = %v, want 0600", info.Mode().Perm())
	}
	state, err := loadState(m)
	if err != nil || state == nil || !state.LoginStart || !state.APIKey || state.DataDir != m.dataDir {
		t.Fatalf("setup.json = %+v, %v", state, err)
	}
	args := strings.Join(svc.spec.Args, " ")
	if !strings.Contains(args, "--api-key-file "+m.keyPath()) || strings.Contains(args, strings.TrimSpace(string(key))) {
		t.Errorf("the service must get the key file, never the key itself: %s", args)
	}
	if svc.spec.Exe != m.exe {
		t.Errorf("service runs %q, want %q", svc.spec.Exe, m.exe)
	}

	// Running it again ("Change settings") keeps the policy and key, and
	// turning login start off removes the service.
	_ = os.WriteFile(m.policyPath(), []byte("# edited\n"), 0o644)
	ui.choices = []int{1, 0} // start at login: no; API key: yes
	s.doSetup()
	if got, _ := os.ReadFile(m.policyPath()); string(got) != "# edited\n" {
		t.Error("setting up again overwrote the operator's policy")
	}
	if again, _ := os.ReadFile(m.keyPath()); !bytes.Equal(again, key) {
		t.Error("setting up again replaced the API key")
	}
	if svc.installed || svc.calls[len(svc.calls)-1] != "remove" {
		t.Errorf("login start off should remove the service: %v", svc.calls)
	}
}

func TestUninstallKeepsDataUnlessAskedTo(t *testing.T) {
	serverUp(t)
	for _, c := range []struct {
		name       string
		choice     int // with a service installed: 0 stop only, 1 keep data, 2 everything
		binsGone   bool
		configGone bool
	}{
		{"stop only", 0, false, false},
		{"keep my policy and data", 1, true, false},
		{"everything", 2, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := testMachine(t)
			ui := &scriptedUI{t: t, choices: []int{0, 0, 1}}
			svc := &fakeService{}
			s := &setup{m: m, ui: ui, svc: svc}
			s.doSetup()

			ui.choices = []int{c.choice}
			done, code := s.doUninstall()
			if svc.installed {
				t.Error("the login service is still installed")
			}
			if done != c.binsGone || code != 0 {
				t.Errorf("doUninstall = %v, %d", done, code)
			}
			for _, tool := range tools {
				_, err := os.Stat(filepath.Join(m.binDir, m.exeName(tool)))
				if gone := os.IsNotExist(err); gone != c.binsGone {
					t.Errorf("%s removed = %v, want %v", tool, gone, c.binsGone)
				}
			}
			_, err := os.Stat(m.policyPath())
			if gone := os.IsNotExist(err); gone != c.configGone {
				t.Errorf("policy deleted = %v, want %v", gone, c.configGone)
			}
			_, err = os.Stat(m.dataDir)
			if gone := os.IsNotExist(err); gone != c.configGone {
				t.Errorf("data folder deleted = %v, want %v", gone, c.configGone)
			}
			if c.binsGone && !strings.Contains(ui.out.String(), feedbackURL) {
				t.Error("uninstall didn't ask why")
			}
		})
	}
}

func TestUpdateTarget(t *testing.T) {
	s := &setup{m: machine{channel: channelRelease}}
	t.Setenv("AGENTGUARD_VERSION", "")
	if got := s.updateTarget(); got != "" {
		t.Errorf("nothing known yet: %q", got)
	}
	s.latest = "99.0.0"
	if got := s.updateTarget(); got != "99.0.0" {
		t.Errorf("newer release: %q", got)
	}
	s.latest = version
	if got := s.updateTarget(); got != "" {
		t.Errorf("already current: %q", got)
	}
	t.Setenv("AGENTGUARD_VERSION", "v1.0.0")
	if got := s.updateTarget(); got != "1.0.0" {
		t.Errorf("a pinned version wins, like with the installers: %q", got)
	}
	s.m.channel = channelSource
	if got := s.updateTarget(); got != "" {
		t.Errorf("a source build has nothing to update to: %q", got)
	}
}

func TestSafeToDelete(t *testing.T) {
	for dir, want := range map[string]bool{
		filepath.Join("home", "u", ".config", "agentguard"):           true,
		filepath.Join("C:", "Users", "u", "AgentGuard", "data"):       true,
		filepath.Join("home", "u"):                                    false,
		filepath.Join("home", "u", ".local", "share"):                 false,
		filepath.Join("C:", "Users", "u", "AppData", "Local", "data"): false,
	} {
		if got := safeToDelete(dir); got != want {
			t.Errorf("safeToDelete(%s) = %v, want %v", dir, got, want)
		}
	}
}

// ── Keys ────────────────────────────────────────────────────────────────

func TestServerAPIKey(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "from-env")
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	_ = os.WriteFile(file, []byte("from-file\r\nsecond line\n"), 0o600)
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)

	for _, c := range []struct {
		flag, file, want string
		wantErr          bool
	}{
		{"from-flag", file, "from-flag", false},
		{"", file, "from-file", false},
		{"", "", "from-env", false},
		{"", filepath.Join(dir, "missing"), "", true},
		{"", empty, "", true},
	} {
		got, err := serverAPIKey(c.flag, c.file)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("serverAPIKey(%q, %q) = %q, %v; want %q (error %v)", c.flag, c.file, got, err, c.want, c.wantErr)
		}
	}
}

func TestClientsFallBackToTheSavedKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("AGENTGUARD_API_KEY", "")
	_ = os.MkdirAll(filepath.Join(dir, "agentguard"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "agentguard", "api-key"), []byte("saved\n"), 0o600)
	if got := resolveClientAPIKey(""); got != "saved" {
		t.Errorf("client key = %q, want the saved one", got)
	}
	if got := resolveAPIKey(""); got != "" {
		t.Errorf("the server must not pick up the saved key by itself: %q", got)
	}
}

// A starter policy that can't be written stops setup with the reason; it
// used to be lost, and setup carried on as if it had worked.
func TestSetupStopsWhenThePolicyCantBeWritten(t *testing.T) {
	serverUp(t)
	m := testMachine(t)
	// A file where the config folder should be: nothing can be created in it.
	if err := os.MkdirAll(filepath.Dir(m.configDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.configDir, []byte("not a folder"), 0o644); err != nil {
		t.Fatal(err)
	}
	ui := &scriptedUI{t: t, choices: []int{0, 0}}
	svc := &fakeService{}
	s := &setup{m: m, ui: ui, svc: svc}
	s.doSetup()
	if !strings.Contains(ui.out.String(), "✗ Starter policy") {
		t.Errorf("no failure reported:\n%s", ui.out.String())
	}
	if svc.installed || s.state != nil {
		t.Error("setup went on after the policy failed")
	}
}
