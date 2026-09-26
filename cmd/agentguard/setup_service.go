package main

// setup_service.go: starting the server at login, per OS — a systemd user
// service on Linux, a LaunchAgent on macOS, a per-user Task Scheduler task
// on Windows. None needs admin rights. Each renders its definition as text
// (tested on every OS) and runs the OS's own tool to load it; runCommand is
// swapped out in tests.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// serviceSpec is what the login service runs.
type serviceSpec struct {
	Exe     string   // the agentguard binary
	Args    []string // its arguments (serverArgs)
	WorkDir string   // the data folder
	LogFile string   // where the server's output goes (launchd, Windows)
}

// loginService starts the server at login and controls it.
type loginService interface {
	Describe() string // e.g. "systemd user service"
	Available() error // nil when this computer can run one
	Installed() bool
	Install(spec serviceSpec) error // write it, enable it, (re)start the server
	Start() error
	Restart() error
	Remove() error // stop the server, disable and delete the service
	LogHint() string
}

// runCommand runs a program and returns its combined output. A variable so
// tests can record the commands instead of running them.
var runCommand = func(stdin, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func newLoginService(m machine) loginService {
	switch m.goos {
	case "linux":
		return &systemdService{m: m}
	case "darwin":
		return &launchdService{m: m}
	case "windows":
		return &taskService{m: m}
	default:
		return unsupportedService{goos: m.goos}
	}
}

// ── Linux: systemd user service ─────────────────────────────────────────

type systemdService struct{ m machine }

const systemdUnit = "agentguard.service"

func (s *systemdService) Describe() string { return "systemd user service" }

func (s *systemdService) path() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Dir(s.m.configDir) // ~/.config
	}
	return filepath.Join(base, "systemd", "user", systemdUnit)
}

func (s *systemdService) Available() error {
	if _, err := runCommand("", "systemctl", "--user", "show-environment"); err != nil {
		return errors.New("systemd user services aren't available here (containers and WSL often don't have them)")
	}
	return nil
}

func (s *systemdService) Installed() bool { return fileExists(s.path()) }

func (s *systemdService) Install(spec serviceSpec) error {
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.path(), []byte(renderSystemdUnit(spec)), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", systemdUnit}, {"restart", systemdUnit}} {
		if _, err := runCommand("", "systemctl", append([]string{"--user"}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

func (s *systemdService) Start() error {
	_, err := runCommand("", "systemctl", "--user", "start", systemdUnit)
	return err
}

func (s *systemdService) Restart() error {
	_, err := runCommand("", "systemctl", "--user", "restart", systemdUnit)
	return err
}

func (s *systemdService) Remove() error {
	_, _ = runCommand("", "systemctl", "--user", "disable", "--now", systemdUnit)
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, _ = runCommand("", "systemctl", "--user", "daemon-reload")
	return nil
}

func (s *systemdService) LogHint() string { return "journalctl --user -u agentguard" }

func renderSystemdUnit(spec serviceSpec) string {
	words := []string{systemdQuote(spec.Exe)}
	for _, a := range spec.Args {
		words = append(words, systemdQuote(a))
	}
	return `# Written by 'agentguard setup'. Run 'agentguard setup' again to change it.
[Unit]
Description=AgentGuard server
After=network.target

[Service]
ExecStart=` + strings.Join(words, " ") + `
WorkingDirectory=` + strings.ReplaceAll(spec.WorkDir, "%", "%%") + `
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`
}

// systemdQuote quotes one word of a unit file command line: backslashes and
// quotes escaped, and % and $ doubled so systemd doesn't expand them.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

// ── macOS: LaunchAgent ──────────────────────────────────────────────────

type launchdService struct{ m machine }

const launchdLabel = "com.lictorate.agentguard"

func (s *launchdService) Describe() string { return "LaunchAgent" }

func (s *launchdService) path() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

func (s *launchdService) target() string { return fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel) }

func (s *launchdService) Available() error { return nil }

func (s *launchdService) Installed() bool { return fileExists(s.path()) }

func (s *launchdService) Install(spec serviceSpec) error {
	if err := os.MkdirAll(filepath.Dir(s.path()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.path(), []byte(renderLaunchdPlist(spec)), 0o644); err != nil {
		return err
	}
	_, _ = runCommand("", "launchctl", "bootout", s.target()) // an older copy, if loaded
	_, err := runCommand("", "launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), s.path())
	return err
}

func (s *launchdService) Start() error {
	_, err := runCommand("", "launchctl", "kickstart", s.target())
	return err
}

func (s *launchdService) Restart() error {
	_, err := runCommand("", "launchctl", "kickstart", "-k", s.target())
	return err
}

func (s *launchdService) Remove() error {
	_, _ = runCommand("", "launchctl", "bootout", s.target())
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *launchdService) LogHint() string { return s.m.logPath() }

func renderLaunchdPlist(spec serviceSpec) string {
	var args strings.Builder
	for _, a := range append([]string{spec.Exe}, spec.Args...) {
		args.WriteString("\n\t\t<string>" + xmlEscape(a) + "</string>")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by 'agentguard setup'. Run 'agentguard setup' again to change it. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>` + args.String() + `
	</array>
	<key>WorkingDirectory</key>
	<string>` + xmlEscape(spec.WorkDir) + `</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(spec.LogFile) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(spec.LogFile) + `</string>
</dict>
</plist>
`
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// ── Windows: per-user Task Scheduler task ───────────────────────────────

type taskService struct{ m machine }

const taskName = "AgentGuard"

func (s *taskService) Describe() string { return "Task Scheduler task at logon" }

func (s *taskService) Available() error { return nil }

// Installed asks schtasks, which answers in milliseconds; the menu checks
// on every redraw, and PowerShell takes a second to start.
func (s *taskService) Installed() bool {
	_, err := runCommand("", "schtasks.exe", "/Query", "/TN", taskName)
	return err == nil
}

func (s *taskService) Install(spec serviceSpec) error {
	if _, err := powershell(renderTaskScript(spec)); err != nil {
		return err
	}
	return s.Restart()
}

func (s *taskService) Start() error {
	_, err := powershell(`Start-ScheduledTask -TaskName '` + taskName + `'`)
	return err
}

func (s *taskService) Restart() error {
	if err := s.stop(); err != nil {
		return err
	}
	return s.Start()
}

// stop ends the task and the server it started. The server runs under
// conhost and cmd, so it is found by its --data-dir, which only the server
// setup runs has.
func (s *taskService) stop() error {
	_, err := powershell(`Stop-ScheduledTask -TaskName '` + taskName + `' -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='agentguard.exe'" |
  Where-Object { $_.CommandLine -like ` + psQuote("*--data-dir*"+s.m.dataDir+"*") + ` } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }`)
	return err
}

func (s *taskService) Remove() error {
	if err := s.stop(); err != nil {
		return err
	}
	_, err := powershell(`Unregister-ScheduledTask -TaskName '` + taskName + `' -Confirm:$false -ErrorAction SilentlyContinue`)
	return err
}

func (s *taskService) LogHint() string { return s.m.logPath() }

// renderTaskScript registers the logon task. The action runs the server
// through `conhost --headless` so no console window opens at logon, and
// through cmd so its output goes to the log file.
func renderTaskScript(spec serviceSpec) string {
	cmdline := winQuote(spec.Exe)
	for _, a := range spec.Args {
		cmdline += " " + winQuote(a)
	}
	action := `--headless cmd.exe /d /s /c "` + cmdline + ` >> ` + winQuote(spec.LogFile) + ` 2>&1"`
	return `$ErrorActionPreference = 'Stop'
$user = "$env:USERDOMAIN\$env:USERNAME"
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument ` + psQuote(action) + ` -WorkingDirectory ` + psQuote(spec.WorkDir) + `
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName '` + taskName + `' -Description 'Starts the AgentGuard server at logon. Written by agentguard setup.' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
`
}

// winQuote quotes one argument for a Windows command line. Paths and flags
// setup passes never contain quotes, so wrapping in quotes is enough.
func winQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t&()^|<>") {
		return s
	}
	return `"` + s + `"`
}

// psQuote is a PowerShell single-quoted string literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// powershell runs a script with Windows PowerShell, passed encoded so no
// quoting survives the trip, and fails when the script throws.
func powershell(script string) (string, error) {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return runCommand("", "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
}

// ── Other systems ───────────────────────────────────────────────────────

type unsupportedService struct{ goos string }

func (u unsupportedService) Describe() string { return "login service" }
func (u unsupportedService) Available() error {
	return fmt.Errorf("setup can't start AgentGuard at login on %s", u.goos)
}
func (u unsupportedService) Installed() bool           { return false }
func (u unsupportedService) Install(serviceSpec) error { return u.Available() }
func (u unsupportedService) Start() error              { return u.Available() }
func (u unsupportedService) Restart() error            { return u.Available() }
func (u unsupportedService) Remove() error             { return nil }
func (u unsupportedService) LogHint() string           { return "" }
