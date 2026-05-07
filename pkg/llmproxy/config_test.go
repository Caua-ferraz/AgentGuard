package llmproxy

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestConfig_Defaults(t *testing.T) {
	t.Setenv("AGENTGUARD_API_KEY", "")
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
