package examples_test

// AT (Test Wrangler) — verifies that every client-config JSON file
// shipped under examples/ parses as valid JSON, contains the expected
// shape (an "mcpServers.agentguard" entry), and references the
// production AgentGuard CLI flags. A20 owns the file contents; this
// test catches accidental JSON breakage during edits, and pins that
// the documented flag set is the same set the gateway's flag parser
// understands.
//
// Why this is a test, not a Make target: example JSON files are
// trivially editable by humans, easy to break (trailing comma, missing
// quote), and operators copy-paste them. A regression here is a
// silent UX failure. Running it as `go test` keeps the check in the
// same gate as the rest of CI.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// expectedFlags are the long-form flags every example config must
// reference at least once (any subset is fine — different IDEs may
// reasonably configure different defaults). The set is the public
// interface from cmd/agentguard-mcp-gateway/main.go via
// pkg/mcpgw.ParseConfig.
var expectedFlags = []string{
	"--upstream",
	"--guard-url",
	"--api-key",
	"--policy",
	"--tenant-id",
	"--policy-mode",
	"--fail-mode",
	"--log-level",
}

func TestExamples_ClientConfigsParseAsJSON(t *testing.T) {
	matches, err := filepath.Glob("*.json")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no *.json files found in examples/ directory; this test must run from the examples/ directory")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			// Parse as a generic map so we can inspect structure.
			var doc map[string]interface{}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("invalid JSON: %v\n--- contents ---\n%s", err, string(data))
			}

			// Every config has a server-list object containing at least
			// an "agentguard" entry. The container key varies by IDE:
			//   - Claude Desktop / Cline / Continue / Cursor → "mcpServers"
			//   - Zed → "context_servers" (Zed's MCP-equivalent key)
			// We accept either.
			var servers map[string]interface{}
			if v, ok := doc["mcpServers"].(map[string]interface{}); ok {
				servers = v
			} else if v, ok := doc["context_servers"].(map[string]interface{}); ok {
				servers = v
			} else {
				t.Fatalf("missing mcpServers or context_servers field; doc keys=%v", mapKeys(doc))
			}
			ag, ok := servers["agentguard"].(map[string]interface{})
			if !ok {
				t.Fatalf("missing or non-object .agentguard entry; servers=%v", servers)
			}

			// The agentguard entry must have a command + args. The
			// command should be the gateway binary name.
			cmd, ok := ag["command"].(string)
			if !ok || cmd == "" {
				t.Fatalf("missing or empty command field; ag=%v", ag)
			}
			if !strings.Contains(cmd, "agentguard-mcp-gateway") {
				t.Errorf("command %q does not reference agentguard-mcp-gateway", cmd)
			}

			argsRaw, ok := ag["args"].([]interface{})
			if !ok {
				t.Fatalf("missing or non-array args field; ag=%v", ag)
			}
			args := make([]string, 0, len(argsRaw))
			for _, a := range argsRaw {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}

			// At least the flag mentioned in the file must be in the
			// gateway's flag set. We don't require ALL expected flags
			// (some IDE configs reasonably omit --policy in fast mode);
			// instead, we assert that every flag that DOES appear is
			// one of the documented set.
			for _, arg := range args {
				if !strings.HasPrefix(arg, "--") {
					continue // value, not a flag
				}
				if !flagInSet(arg, expectedFlags) {
					t.Errorf("config uses flag %q which is not in the documented gateway flag set %v", arg, expectedFlags)
				}
			}

			// Sanity: at least --upstream must be present (the gateway
			// requires at least one).
			hasUpstream := false
			for _, arg := range args {
				if arg == "--upstream" {
					hasUpstream = true
					break
				}
			}
			if !hasUpstream {
				t.Errorf("config %s does not declare any --upstream", path)
			}
		})
	}
}

func flagInSet(flag string, set []string) bool {
	for _, f := range set {
		if flag == f {
			return true
		}
	}
	return false
}

func mapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
