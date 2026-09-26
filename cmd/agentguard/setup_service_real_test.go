package main

// An opt-in test of the real login service on this OS: it installs the
// systemd user service, LaunchAgent or Task Scheduler task setup would,
// running a freshly built agentguard, and checks the server answers,
// restarts and goes away. It changes the machine it runs on, so it only
// runs with AGENTGUARD_TEST_REAL_SERVICE=1 — in CI, on throwaway runners
// (the setup-service job in .github/workflows/ci.yml).

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginService_Real(t *testing.T) {
	if os.Getenv("AGENTGUARD_TEST_REAL_SERVICE") != "1" {
		t.Skip("installs a real login service; set AGENTGUARD_TEST_REAL_SERVICE=1 on a throwaway machine")
	}
	dir := t.TempDir()
	m := machine{goos: goos, binDir: filepath.Join(dir, "bin"), configDir: filepath.Join(dir, "config", "agentguard"), dataDir: filepath.Join(dir, "data")}
	m.exe = filepath.Join(m.binDir, m.exeName("agentguard"))
	for _, d := range []string{m.binDir, m.configDir, m.dataDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command("go", "build", "-o", m.exe, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	policy := filepath.Join(repoRootForDocs(t), "configs", "default.yaml")
	if err := writeNewKey(m.keyPath()); err != nil {
		t.Fatal(err)
	}
	port, err := freePort(18480)
	if err != nil {
		t.Fatal(err)
	}
	st := &setupState{Port: port, Policy: policy, DataDir: m.dataDir, APIKey: true, LoginStart: true}
	spec := serviceSpec{Exe: m.exe, Args: serverArgs(m, st), WorkDir: m.dataDir, LogFile: m.logPath()}

	svc := newLoginService(m)
	if err := svc.Available(); err != nil {
		t.Skipf("no login service on this machine: %v", err)
	}
	t.Cleanup(func() { _ = svc.Remove() })
	logs := func() string {
		b, _ := os.ReadFile(m.logPath())
		return string(b)
	}

	if err := svc.Install(spec); err != nil {
		t.Fatalf("install %s: %v", svc.Describe(), err)
	}
	if !svc.Installed() {
		t.Fatalf("%s not installed after Install", svc.Describe())
	}
	if !waitForHealth(port, 30*time.Second) {
		t.Fatalf("the server the %s started never answered on port %d\nlog:\n%s", svc.Describe(), port, logs())
	}
	if err := svc.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !waitForHealth(port, 30*time.Second) {
		t.Fatalf("no answer after the restart\nlog:\n%s", logs())
	}
	if err := svc.Remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if svc.Installed() {
		t.Fatalf("%s still installed after Remove", svc.Describe())
	}
	deadline := time.Now().Add(15 * time.Second)
	for serverHealth(port) != "" {
		if time.Now().After(deadline) {
			t.Fatal("the server still answers after the service was removed")
		}
		time.Sleep(300 * time.Millisecond)
	}
}
