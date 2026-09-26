package llmproxy

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Caua-ferraz/AgentGuard/internal/clihelp"
)

func TestConfig_Defaults(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	t.Setenv("AGENTGUARD_URL", "")
	cfg, err := ParseConfigWithOutput(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("Listen = %q, want %q", cfg.Listen, DefaultListen)
	}
	if cfg.UpstreamOpenAI != DefaultUpstreamOpenAI {
		t.Errorf("UpstreamOpenAI = %q, want %q", cfg.UpstreamOpenAI, DefaultUpstreamOpenAI)
	}
	if cfg.UpstreamAnthropic != DefaultUpstreamAnthropic {
		t.Errorf("UpstreamAnthropic = %q, want %q", cfg.UpstreamAnthropic, DefaultUpstreamAnthropic)
	}
	if cfg.GuardURL != DefaultGuardURL {
		t.Errorf("GuardURL = %q, want %q", cfg.GuardURL, DefaultGuardURL)
	}
	if cfg.MaxBufferBytes != DefaultMaxBufferBytes {
		t.Errorf("MaxBufferBytes = %d, want %d", cfg.MaxBufferBytes, DefaultMaxBufferBytes)
	}
	if cfg.FailMode != "deny" {
		t.Errorf("FailMode = %q, want deny", cfg.FailMode)
	}
}

func TestConfig_APIKeyEnvFallback(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "env-token")
	cfg, err := ParseConfigWithOutput(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.APIKey != "env-token" {
		t.Errorf("APIKey = %q, want env-token", cfg.APIKey)
	}
	// Explicit flag wins.
	cfg, err = ParseConfigWithOutput([]string{"--api-key", "flag-token"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.APIKey != "flag-token" {
		t.Errorf("APIKey = %q, want flag-token", cfg.APIKey)
	}
}

func TestConfig_GuardURLEnvFallback(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	t.Setenv("AGENTGUARD_URL", "http://guard.internal:8080")
	cfg, err := ParseConfigWithOutput(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.GuardURL != "http://guard.internal:8080" {
		t.Errorf("GuardURL = %q, want the AGENTGUARD_URL value", cfg.GuardURL)
	}
	cfg, err = ParseConfigWithOutput([]string{"--guard-url", "http://flag:1"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.GuardURL != "http://flag:1" {
		t.Errorf("GuardURL = %q, the flag must win", cfg.GuardURL)
	}
}

// A positional argument used to be ignored: `agentguard-llm-proxy version`
// started the proxy.
func TestConfig_RejectsPositionalArgs(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	for _, args := range [][]string{{"version"}, {"--listen", "127.0.0.1:9", "extra"}} {
		if _, err := ParseConfigWithOutput(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
			t.Errorf("ParseConfig(%q) err = %v, want unexpected argument", args, err)
		}
	}
}

func TestConfig_ValidationErrors(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	cases := []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"bad-listen", []string{"--listen", "no-port"}, "valid host:port"},
		{"bad-fail-mode", []string{"--fail-mode", "yolo"}, "fail-mode"},
		{"bad-log-level", []string{"--log-level", "trace"}, "log-level"},
		{"zero-buffer", []string{"--max-buffer-bytes", "0"}, "max-buffer-bytes"},
		{"giant-buffer", []string{"--max-buffer-bytes", "999999999999"}, "exceeds maximum"},
		{"bad-upstream", []string{"--upstream-openai", "not-a-url"}, "upstream-openai"},
		{"bad-guard-url", []string{"--guard-url", "ftp://x"}, "http or https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfigWithOutput(tc.args, &bytes.Buffer{})
			if err == nil {
				t.Fatalf("want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %v, want contains %q", err, tc.wantSub)
			}
		})
	}
}

// Non-loopback bind without --proxy-api-key is refused per
// docs/LLM_API_PROXY.md § 8.1 (avoid accidental internet-exposed
// proxies).
func TestConfig_NonLoopbackBindRequiresProxyAuth(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	_, err := ParseConfigWithOutput([]string{"--listen", "0.0.0.0:8081"}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("want error refusing non-loopback bind without proxy-api-key")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("err = %v, want contains non-loopback", err)
	}
	// With --proxy-api-key it should pass.
	_, err = ParseConfigWithOutput([]string{"--listen", "0.0.0.0:8081", "--proxy-api-key", "k"}, &bytes.Buffer{})
	if err != nil {
		t.Errorf("non-loopback with proxy-api-key should succeed; got %v", err)
	}
}

// An empty host (":8081") makes net/http listen on every interface, so it
// must be treated like 0.0.0.0: refused without --proxy-api-key. It used to
// pass validation as "loopback" and start an unauthenticated proxy on all
// interfaces.
func TestConfig_EmptyHostBindRequiresProxyAuth(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	for _, l := range []string{":8081", "[::]:8081"} {
		t.Run(l, func(t *testing.T) {
			_, err := ParseConfigWithOutput([]string{"--listen", l}, &bytes.Buffer{})
			if err == nil {
				t.Fatalf("--listen %q without --proxy-api-key: want refusal, got nil", l)
			}
			if !strings.Contains(err.Error(), "non-loopback") {
				t.Errorf("err = %v, want contains non-loopback", err)
			}
			if _, err := ParseConfigWithOutput([]string{"--listen", l, "--proxy-api-key", "k"}, &bytes.Buffer{}); err != nil {
				t.Errorf("--listen %q with --proxy-api-key should succeed; got %v", l, err)
			}
		})
	}
	if _, err := ParseConfigWithOutput([]string{"--listen", ":8081"}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "every interface") {
		t.Errorf("empty-host refusal should explain it binds every interface; got %v", err)
	}
}

func TestConfig_LoopbackVariants(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
	loopbacks := []string{"127.0.0.1:8081", "[::1]:8081", "localhost:8081"}
	for _, l := range loopbacks {
		t.Run(l, func(t *testing.T) {
			_, err := ParseConfigWithOutput([]string{"--listen", l}, &bytes.Buffer{})
			if err != nil {
				t.Errorf("loopback %q rejected: %v", l, err)
			}
		})
	}
}

func TestConfig_HelpDoesNotPanic(t *testing.T) {
	// flag.ContinueOnError returns ErrHelp for --help; we just want
	// to make sure ParseConfigWithOutput surfaces that without
	// crashing.
	t.Setenv("AGENTGUARD_API_KEY", "")
	var buf bytes.Buffer
	_, err := ParseConfigWithOutput([]string{"--help"}, &buf)
	if err == nil {
		t.Fatalf("want non-nil error from --help (flag.ErrHelp)")
	}
	// Output should at least mention some flag we registered.
	if !strings.Contains(buf.String(), "upstream-openai") {
		t.Errorf("usage output missing flag names; got: %s", buf.String())
	}
}

func TestConfig_DirectValidate(t *testing.T) {
	cfg := &Config{
		Listen:            "127.0.0.1:8081",
		UpstreamOpenAI:    "https://api.openai.com",
		UpstreamAnthropic: "https://api.anthropic.com",
		GuardURL:          "http://127.0.0.1:8080",
		TenantID:          "local",
		FailMode:          "deny",
		LogLevel:          "info",
		MaxBufferBytes:    DefaultMaxBufferBytes,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	cfg.TenantID = ""
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected validation error for empty tenant")
	}
}

// Ensure the package compiles cleanly with no environment leakage.
func TestConfig_OSEnvIsolation(t *testing.T) {
	// Save and restore the env var to keep this test reentrant.
	const env = "AGENTGUARD_API_KEY"
	prev, hadPrev := os.LookupEnv(env)
	defer func() {
		if hadPrev {
			os.Setenv(env, prev)
		} else {
			os.Unsetenv(env)
		}
	}()
	os.Setenv(env, "isolated")
	cfg, err := ParseConfigWithOutput(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.APIKey != "isolated" {
		t.Errorf("APIKey = %q, want isolated", cfg.APIKey)
	}
}

// agentguard-llm-proxy -h prints every flag in a group, as --flag, within 80 columns.
func TestConfig_HelpGroupsEveryFlag(t *testing.T) {
	var out bytes.Buffer
	_, err := ParseConfigWithOutput([]string{"-h"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	help := out.String()
	if strings.Contains(help, clihelp.Ungrouped+":") {
		t.Errorf("a flag is missing from the help groups:\n%s", help)
	}
	for _, want := range []string{"--listen string", "--guard-url string", "--version", "AGENTGUARD_URL"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	for _, line := range strings.Split(help, "\n") {
		if utf8.RuneCountInString(line) > clihelp.Width {
			t.Errorf("line wider than %d: %q", clihelp.Width, line)
		}
		if strings.HasPrefix(line, "  -") && !strings.HasPrefix(line, "  --") {
			t.Errorf("flag written with one dash: %q", line)
		}
	}
}
