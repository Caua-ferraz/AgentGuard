package mcpgw

import (
	"strings"
	"testing"
)

// --upstream-http and --upstream-header: what parses, what is refused, and
// that a refusal never echoes a header value (it may be a token).
func TestParseConfig_HTTPUpstreams(t *testing.T) {
	t.Setenv("AGENTGUARD_URL", "")
	t.Setenv("MCPGW_TEST_TOKEN", "s3cret-token")
	base := []string{"--policy-mode", "fast"}

	cases := []struct {
		name    string
		args    []string
		wantErr string // substring; "" means the args must parse
		check   func(t *testing.T, c *Config)
	}{
		{
			name: "an https upstream on its own is enough",
			args: []string{"--upstream-http", "docs:https://mcp.example.com/mcp"},
			check: func(t *testing.T, c *Config) {
				if len(c.Upstreams) != 1 {
					t.Fatalf("upstreams = %+v", c.Upstreams)
				}
				got := c.Upstreams[0]
				want := UpstreamSpec{Namespace: "docs", Transport: TransportHTTP, URL: "https://mcp.example.com/mcp"}
				if got != want {
					t.Errorf("spec = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "stdio and http upstreams mix, stdio first",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream", "fs:npx server-fs /tmp",
			},
			check: func(t *testing.T, c *Config) {
				if len(c.Upstreams) != 2 || c.Upstreams[0].Transport != TransportStdio || c.Upstreams[1].Transport != TransportHTTP {
					t.Errorf("upstreams = %+v", c.Upstreams)
				}
			},
		},
		{
			name: "plain http is fine for localhost, 127.0.0.1 and [::1]",
			args: []string{
				"--upstream-http", "a:http://localhost:3000/mcp",
				"--upstream-http", "b:http://127.0.0.1:3000/mcp",
				"--upstream-http", "c:http://[::1]:3000/mcp",
			},
		},
		{
			name:    "plain http to another host is refused",
			args:    []string{"--upstream-http", "docs:http://mcp.example.com/mcp"},
			wantErr: "use https",
		},
		{
			name:    "a non-http scheme is refused",
			args:    []string{"--upstream-http", "docs:ftp://mcp.example.com/mcp"},
			wantErr: "must start with https://",
		},
		{
			name:    "a bare URL needs a namespace",
			args:    []string{"--upstream-http", "https://mcp.example.com/mcp"},
			wantErr: "needs a namespace",
		},
		{
			name:    "a URL without a host is refused",
			args:    []string{"--upstream-http", "docs:/mcp"},
			wantErr: "has no host",
		},
		{
			name:    "credentials in the URL are refused",
			args:    []string{"--upstream-http", "docs:https://user:pw@mcp.example.com/mcp"},
			wantErr: "must not contain credentials",
		},
		{
			name:    "a namespace with whitespace is refused",
			args:    []string{"--upstream-http", "my docs:https://mcp.example.com/mcp"},
			wantErr: "must not contain colon or whitespace",
		},
		{
			name: "the same namespace twice is refused",
			args: []string{
				"--upstream-http", "docs:https://a.example.com/mcp",
				"--upstream-http", "docs:https://b.example.com/mcp",
			},
			wantErr: "declared more than once",
		},
		{
			name: "a namespace shared with a stdio upstream is refused",
			args: []string{
				"--upstream", "docs:npx server-docs",
				"--upstream-http", "docs:https://mcp.example.com/mcp",
			},
			wantErr: "used by both --upstream and --upstream-http",
		},
		{
			name: "headers expand ${VAR} from the environment",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:Authorization=Bearer ${MCPGW_TEST_TOKEN}",
				"--upstream-header", "docs:x-team=platform",
			},
			check: func(t *testing.T, c *Config) {
				h := c.UpstreamHeaders["docs"]
				if got := h.Get("Authorization"); got != "Bearer s3cret-token" {
					t.Errorf("Authorization = %q", got)
				}
				if got := h.Get("X-Team"); got != "platform" {
					t.Errorf("X-Team = %q", got)
				}
			},
		},
		{
			name: "a lone $ in a value is kept as is",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:X-Key=pa$$word",
			},
			check: func(t *testing.T, c *Config) {
				if got := c.UpstreamHeaders["docs"].Get("X-Key"); got != "pa$$word" {
					t.Errorf("X-Key = %q", got)
				}
			},
		},
		{
			name: "an unset variable is an error naming the variable",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:Authorization=Bearer ${MCPGW_TEST_UNSET_VAR}",
			},
			wantErr: "MCPGW_TEST_UNSET_VAR is not set",
		},
		{
			name: "a malformed ${ reference is refused",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:Authorization=Bearer ${MCPGW_TEST_TOKEN",
			},
			wantErr: "malformed",
		},
		{
			name: "a header for an unknown namespace is refused",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "dcos:X-Team=platform",
			},
			wantErr: `namespace "dcos", but no --upstream-http declares it`,
		},
		{
			name: "a header for a stdio upstream is refused",
			args: []string{
				"--upstream", "fs:npx server-fs /tmp",
				"--upstream-header", "fs:X-Team=platform",
			},
			wantErr: "headers apply to --upstream-http servers only",
		},
		{
			name: "a header the gateway manages is refused",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:mcp-session-id=abc",
			},
			wantErr: "the gateway sets Mcp-Session-Id itself",
		},
		{
			name: "a header without = is refused",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:Authorization",
			},
			wantErr: "<ns>:<Name>=<Value>",
		},
		{
			name: "an invalid header name is refused",
			args: []string{
				"--upstream-http", "docs:https://mcp.example.com/mcp",
				"--upstream-header", "docs:Bad Name=x",
			},
			wantErr: "not a valid HTTP header name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(append(append([]string{}, tc.args...), base...))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got none", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %q, want it to contain %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "s3cret-token") {
					t.Errorf("error leaks a header value: %q", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}
