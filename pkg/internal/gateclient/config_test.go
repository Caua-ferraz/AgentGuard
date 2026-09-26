package gateclient

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestFlagSet() (*flag.FlagSet, *GateFlags) {
	fs := flag.NewFlagSet("test-gate", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	return fs, RegisterGateFlags(fs, "Path to policy YAML")
}

func TestGateFlags_DefaultsAndOverrides(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	t.Setenv("AGENTGUARD_URL", "")

	fs, gf := newTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := gf.Resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if *gf.GuardURL != DefaultGuardURL || *gf.TenantID != DefaultTenantID ||
		*gf.FailMode != DefaultFailMode || *gf.LogLevel != DefaultLogLevel {
		t.Errorf("defaults wrong: %q %q %q %q", *gf.GuardURL, *gf.TenantID, *gf.FailMode, *gf.LogLevel)
	}

	fs, gf = newTestFlagSet()
	if err := fs.Parse([]string{
		"--guard-url", "https://guard.example:9090",
		"--tenant-id", "acme",
		"--fail-mode", "allow",
		"--log-level", "debug",
		"--policy", "p.yaml",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := gf.Resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if *gf.GuardURL != "https://guard.example:9090" || *gf.TenantID != "acme" ||
		*gf.FailMode != "allow" || *gf.LogLevel != "debug" || *gf.PolicyPath != "p.yaml" {
		t.Errorf("overrides wrong: %q %q %q %q %q",
			*gf.GuardURL, *gf.TenantID, *gf.FailMode, *gf.LogLevel, *gf.PolicyPath)
	}
}

// AGENTGUARD_URL (read by the SDKs and the agentguard client commands)
// fills --guard-url when the flag isn't given; the flag always wins.
func TestGateFlags_GuardURLFromEnv(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	t.Setenv("AGENTGUARD_URL", "http://env-guard:9000")

	fs, gf := newTestFlagSet()
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := gf.Resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if *gf.GuardURL != "http://env-guard:9000" {
		t.Errorf("env fallback: GuardURL = %q", *gf.GuardURL)
	}

	fs, gf = newTestFlagSet()
	if err := fs.Parse([]string{"--guard-url", DefaultGuardURL}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := gf.Resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if *gf.GuardURL != DefaultGuardURL {
		t.Errorf("an explicit --guard-url (even the default value) must win: got %q", *gf.GuardURL)
	}
}

func TestRejectArgs(t *testing.T) {
	if err := RejectArgs(nil, ""); err != nil {
		t.Errorf("no args: %v", err)
	}
	cases := map[string]string{
		"version": "did you mean --version?",
		"help":    "did you mean --help?",
		"/tmp":    "takes flags only",
	}
	for arg, want := range cases {
		err := RejectArgs([]string{arg, "more"}, "")
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), `"`+arg+`"`) {
			t.Errorf("RejectArgs(%q) = %v, want it to name the argument and say %q", arg, err, want)
		}
	}
	if err := RejectArgs([]string{"x"}, "a hint"); err == nil || !strings.Contains(err.Error(), "a hint") {
		t.Errorf("custom hint: %v", err)
	}
}

// noSavedKey points the config folder at an empty temp folder, so a key
// `agentguard setup` saved on the test machine can't leak in.
func noSavedKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	return dir
}

func TestResolveAPIKey_FlagWinsOverEnv(t *testing.T) {
	noSavedKey(t)
	t.Setenv("AGENTGUARD_API_KEY", "env-token")
	if got := ResolveAPIKey("flag-token"); got != "flag-token" {
		t.Errorf("flag must win: got %q", got)
	}
	if got := ResolveAPIKey(""); got != "env-token" {
		t.Errorf("env fallback: got %q", got)
	}
	t.Setenv("AGENTGUARD_API_KEY", "")
	if got := ResolveAPIKey(""); got != "" {
		t.Errorf("no flag no env: got %q", got)
	}
}

func TestValidateGateConfig(t *testing.T) {
	cases := []struct {
		name                                   string
		guardURL, tenantID, failMode, logLevel string
		wantErr                                string // substring; "" = ok
	}{
		{"ok defaults", DefaultGuardURL, "local", "deny", "info", ""},
		{"ok all enums", "https://g", "t", "fail-closed-with-audit", "debug", ""},
		{"empty guard url", "", "t", "deny", "info", "must not be empty"},
		{"no scheme", "not-a-url", "t", "deny", "info", "not a valid URL"},
		{"bad scheme", "ftp://x", "t", "deny", "info", "http or https"},
		{"empty tenant", "http://g", "", "deny", "info", "tenant-id"},
		{"bad fail mode", "http://g", "t", "yolo", "info", "fail-mode"},
		{"bad log level", "http://g", "t", "deny", "trace", "log-level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGateConfig(tc.guardURL, tc.tenantID, tc.failMode, tc.logLevel)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// The key `agentguard setup` saves is the last fallback, after the flag and
// AGENTGUARD_API_KEY.
func TestResolveAPIKey_SavedKeyIsLastFallback(t *testing.T) {
	dir := noSavedKey(t)
	if err := os.MkdirAll(filepath.Join(dir, "agentguard"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agentguard", "api-key"), []byte("saved-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTGUARD_API_KEY", "")
	if got := ResolveAPIKey(""); got != "saved-key" {
		t.Errorf("saved key fallback: got %q", got)
	}
	t.Setenv("AGENTGUARD_API_KEY", "env-token")
	if got := ResolveAPIKey(""); got != "env-token" {
		t.Errorf("env must win over the saved key: got %q", got)
	}
	if got := ResolveAPIKey("flag-token"); got != "flag-token" {
		t.Errorf("flag must win: got %q", got)
	}
}
