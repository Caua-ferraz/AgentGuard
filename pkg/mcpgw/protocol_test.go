package mcpgw

import (
	"encoding/json"
	"testing"
)

// TestNegotiateProtocolVersion covers the matrix from
// docs/MCP_GATEWAY.md § 3.2.
func TestNegotiateProtocolVersion(t *testing.T) {
	supported := []string{"2024-11-05", "2025-03-26", "2025-11-25"}

	cases := []struct {
		name      string
		requested string
		supported []string
		want      string
	}{
		{
			name:      "exact match newest",
			requested: "2025-11-25",
			supported: supported,
			want:      "2025-11-25",
		},
		{
			name:      "exact match middle",
			requested: "2025-03-26",
			supported: supported,
			want:      "2025-03-26",
		},
		{
			name:      "exact match oldest",
			requested: "2024-11-05",
			supported: supported,
			want:      "2024-11-05",
		},
		{
			name:      "client newer than gateway -> highest",
			requested: "2026-12-31",
			supported: supported,
			want:      "2025-11-25",
		},
		{
			name:      "client between supported entries -> highest <= client",
			requested: "2025-06-15",
			supported: supported,
			want:      "2025-03-26",
		},
		{
			name:      "client older than gateway -> empty (negotiation fail)",
			requested: "1999-01-01",
			supported: supported,
			want:      "",
		},
		{
			name:      "empty client request -> highest",
			requested: "",
			supported: supported,
			want:      "2025-11-25",
		},
		{
			name:      "empty supported set -> empty",
			requested: "2025-11-25",
			supported: nil,
			want:      "",
		},
		{
			name:      "single supported, exact match",
			requested: "2024-11-05",
			supported: []string{"2024-11-05"},
			want:      "2024-11-05",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NegotiateProtocolVersion(tc.requested, tc.supported)
			if got != tc.want {
				t.Errorf("NegotiateProtocolVersion(%q, %v) = %q, want %q",
					tc.requested, tc.supported, got, tc.want)
			}
		})
	}
}

// TestErrorCodes asserts the constants are stable. Changing one of
// these is a wire-format break and should fail the test loudly.
func TestErrorCodes(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"ParseError", ErrCodeParseError, -32700},
		{"InvalidRequest", ErrCodeInvalidRequest, -32600},
		{"MethodNotFound", ErrCodeMethodNotFound, -32601},
		{"InvalidParams", ErrCodeInvalidParams, -32602},
		{"InternalError", ErrCodeInternalError, -32603},
		{"PolicyDeny", ErrCodePolicyDeny, -32000},
		{"PolicyApproval", ErrCodePolicyApproval, -32001},
		{"UpstreamUnavail", ErrCodeUpstreamUnavail, -32002},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (wire-format break!)", tc.name, tc.got, tc.want)
		}
	}
}

// TestRequestRoundTrip ensures every JSON-RPC envelope round-trips
// without losing fields.
func TestRequestRoundTrip(t *testing.T) {
	req := Request{
		JSONRPC: JSONRPCVersion,
		ID:      float64(42), // json decode produces float64 for numeric ids
		Method:  MethodToolsCall,
		Params:  json.RawMessage(`{"name":"fs:read_file","arguments":{"path":"/tmp/x"}}`),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Request
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.JSONRPC != req.JSONRPC || got.Method != req.Method {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
}

func TestResponseRoundTrip(t *testing.T) {
	resp := NewResponseError("abc", ErrCodePolicyDeny, "blocked", json.RawMessage(`{"rule":"deny:test"}`))
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Response
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Error == nil || got.Error.Code != ErrCodePolicyDeny {
		t.Errorf("expected error code %d, got %+v", ErrCodePolicyDeny, got.Error)
	}
	idStr, ok := got.ID.(string)
	if !ok || idStr != "abc" {
		t.Errorf("expected id \"abc\", got %v (%T)", got.ID, got.ID)
	}
}

func TestToolDescriptorPreservesUnknownFields(t *testing.T) {
	// Upstream advertises a non-standard "annotations" field; we
	// must round-trip it so re-emitting the descriptor with a
	// prefixed Name doesn't lose data.
	raw := []byte(`{"name":"read_file","description":"Read a file","inputSchema":{"type":"object"},"annotations":{"readOnly":true}}`)
	var t1 ToolDescriptor
	if err := json.Unmarshal(raw, &t1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if t1.Name != "read_file" {
		t.Errorf("Name: got %q", t1.Name)
	}
	if t1.Description != "Read a file" {
		t.Errorf("Description: got %q", t1.Description)
	}
	if _, ok := t1.Extra["annotations"]; !ok {
		t.Errorf("Extra missing annotations")
	}
	t1.Name = "fs:" + t1.Name

	out, err := json.Marshal(t1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Re-parse and confirm the annotations field survived.
	var raw2 map[string]json.RawMessage
	if err := json.Unmarshal(out, &raw2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, ok := raw2["annotations"]; !ok {
		t.Errorf("annotations dropped on re-marshal: %s", string(out))
	}
	var name string
	if err := json.Unmarshal(raw2["name"], &name); err != nil || name != "fs:read_file" {
		t.Errorf("Name didn't survive: got %q", name)
	}
}

func TestContentBlockPreservesUnknownFields(t *testing.T) {
	// Upstream sends an image content block; the bridge must
	// round-trip it untouched.
	raw := []byte(`{"type":"image","data":"base64stuff","mimeType":"image/png"}`)
	var b ContentBlock
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if b.Type != "image" {
		t.Errorf("type: got %q", b.Type)
	}
	if _, ok := b.Extra["data"]; !ok {
		t.Errorf("extra missing data")
	}

	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt map[string]json.RawMessage
	if err := json.Unmarshal(out, &rt); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, ok := rt["data"]; !ok {
		t.Errorf("data field dropped on re-marshal: %s", string(out))
	}
}

func TestMergeCapabilities(t *testing.T) {
	// MergeCapabilities masks `resources` and `prompts` regardless of
	// what upstreams advertise (see MergeCapabilities doc-comment).
	// These cases assert that masking holds across upstream shapes.
	cases := []struct {
		name        string
		upstream    []map[string]interface{}
		wantTools   bool
		wantRes     bool
		wantPrompts bool
	}{
		{
			name:      "no upstreams -> tools+logging only",
			upstream:  nil,
			wantTools: true,
		},
		{
			name: "one upstream with resources -> resources masked",
			upstream: []map[string]interface{}{
				{"resources": map[string]interface{}{}},
			},
			wantTools: true,
			wantRes:   false,
		},
		{
			name: "one upstream with prompts -> prompts masked",
			upstream: []map[string]interface{}{
				{"prompts": map[string]interface{}{}},
			},
			wantTools:   true,
			wantPrompts: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := MergeCapabilities(tc.upstream)
			if _, ok := merged["tools"]; ok != tc.wantTools {
				t.Errorf("tools: got %v, want %v", ok, tc.wantTools)
			}
			if _, ok := merged["resources"]; ok != tc.wantRes {
				t.Errorf("resources: got %v, want %v", ok, tc.wantRes)
			}
			if _, ok := merged["prompts"]; ok != tc.wantPrompts {
				t.Errorf("prompts: got %v, want %v", ok, tc.wantPrompts)
			}
			// Logging is always advertised.
			if _, ok := merged["logging"]; !ok {
				t.Errorf("logging missing")
			}
		})
	}
}

// TestMergeCapabilities_MasksResourcesAndPrompts is the regression test
// for the masking invariant: even when multiple upstreams advertise
// `resources` / `prompts`, the gateway must NOT expose those
// capabilities to the client because resources/* and prompts/* method
// routing is not yet implemented. Advertising them would mislead the
// client into showing resources that every read would reject with
// MethodNotFound.
func TestMergeCapabilities_MasksResourcesAndPrompts(t *testing.T) {
	upstreams := []map[string]interface{}{
		{
			"tools":     map[string]interface{}{"listChanged": false},
			"resources": map[string]interface{}{"subscribe": true, "listChanged": true},
			"prompts":   map[string]interface{}{"listChanged": true},
		},
		{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
			"prompts":   map[string]interface{}{},
		},
	}

	merged := MergeCapabilities(upstreams)

	if _, ok := merged["tools"]; !ok {
		t.Errorf("tools must always be advertised; got merged=%v", merged)
	}
	if _, ok := merged["logging"]; !ok {
		t.Errorf("logging must always be advertised; got merged=%v", merged)
	}
	if _, ok := merged["resources"]; ok {
		t.Errorf("resources must be masked; got merged=%v", merged)
	}
	if _, ok := merged["prompts"]; ok {
		t.Errorf("prompts must be masked; got merged=%v", merged)
	}
}

// TestParseConfig exercises ParseConfig's flag-parsing + validation.
func TestParseConfig(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		check   func(t *testing.T, c *Config)
	}{
		{
			name:    "no upstreams -> error",
			args:    []string{},
			wantErr: true,
		},
		{
			name: "single upstream labeled",
			// Use --policy-mode fast so the strict-mode --policy
			// requirement (added by A18) doesn't fire — this case
			// exercises namespace + default propagation, not the
			// strict-mode requirement.
			args: []string{"--upstream", "fs:npx -y server-fs /tmp", "--policy-mode", "fast"},
			check: func(t *testing.T, c *Config) {
				if len(c.Upstreams) != 1 {
					t.Fatalf("upstreams: got %d", len(c.Upstreams))
				}
				if c.Upstreams[0].Namespace != "fs" {
					t.Errorf("namespace: got %q", c.Upstreams[0].Namespace)
				}
				if c.Upstreams[0].Command != "npx -y server-fs /tmp" {
					t.Errorf("command: got %q", c.Upstreams[0].Command)
				}
				if c.FailMode != "deny" {
					t.Errorf("FailMode default: got %q", c.FailMode)
				}
				if c.PolicyMode != "fast" {
					t.Errorf("PolicyMode override: got %q", c.PolicyMode)
				}
			},
		},
		{
			name: "single upstream unlabeled -> ns from first word",
			args: []string{"--upstream", "echo hi", "--policy-mode", "fast"},
			check: func(t *testing.T, c *Config) {
				if c.Upstreams[0].Namespace != "echo" {
					t.Errorf("namespace: got %q", c.Upstreams[0].Namespace)
				}
				if c.Upstreams[0].Command != "echo hi" {
					t.Errorf("command: got %q", c.Upstreams[0].Command)
				}
			},
		},
		{
			name: "duplicate namespace -> error",
			args: []string{
				"--upstream", "fs:cmd1",
				"--upstream", "fs:cmd2",
			},
			wantErr: true,
		},
		{
			name:    "empty namespace before colon -> error",
			args:    []string{"--upstream", ":cmd"},
			wantErr: true,
		},
		{
			name:    "invalid fail-mode -> error",
			args:    []string{"--upstream", "fs:cmd", "--fail-mode", "lol"},
			wantErr: true,
		},
		{
			name:    "invalid policy-mode -> error",
			args:    []string{"--upstream", "fs:cmd", "--policy-mode", "lol"},
			wantErr: true,
		},
		{
			name:    "invalid guard-url -> error",
			args:    []string{"--upstream", "fs:cmd", "--guard-url", "not-a-url"},
			wantErr: true,
		},
		{
			name: "two upstreams unique ns -> ok",
			args: []string{
				"--upstream", "fs:cmd1",
				"--upstream", "github:cmd2",
				"--policy-mode", "fast",
			},
			check: func(t *testing.T, c *Config) {
				if len(c.Upstreams) != 2 {
					t.Fatalf("upstreams: got %d", len(c.Upstreams))
				}
				if c.Upstreams[0].Namespace != "fs" || c.Upstreams[1].Namespace != "github" {
					t.Errorf("namespaces: %+v", c.Upstreams)
				}
			},
		},
		{
			// A18 added --policy-mode strict + missing --policy as a
			// hard error so the dual-check pattern can never silently
			// degrade to single-check (the gateway needs the
			// tool_scope_map to know which secondary scope to fire).
			name:    "strict mode without --policy -> error",
			args:    []string{"--upstream", "fs:cmd1"},
			wantErr: true,
		},
		{
			name: "strict mode with --policy -> ok",
			args: []string{
				"--upstream", "fs:cmd1",
				"--policy", "configs/default.yaml",
			},
			check: func(t *testing.T, c *Config) {
				if c.PolicyPath != "configs/default.yaml" {
					t.Errorf("PolicyPath: got %q", c.PolicyPath)
				}
				if c.PolicyMode != "strict" {
					t.Errorf("PolicyMode default: got %q", c.PolicyMode)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfig(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (cfg=%+v)", cfg)
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

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{name: "simple", in: "echo hi", want: []string{"echo", "hi"}},
		{name: "tabs", in: "echo\thi", want: []string{"echo", "hi"}},
		{name: "quoted", in: `echo "hello world"`, want: []string{"echo", "hello world"}},
		{name: "escape inside quote", in: `echo "say \"hi\""`, want: []string{"echo", `say "hi"`}},
		{name: "unterminated quote", in: `echo "oops`, wantErr: true},
		{name: "trailing backslash inside quote", in: `echo "x\`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SplitCommandLine(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tokens %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slicesEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
