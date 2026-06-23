package gateclient

import (
	"bytes"
	"flag"
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

func TestResolveAPIKey_FlagWinsOverEnv(t *testing.T) {
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
