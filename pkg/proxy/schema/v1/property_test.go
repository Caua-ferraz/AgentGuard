// AT (Test Wrangler) property + golden test — Phase 2.
//
// Catches silent wire-format drift on the v1 ActionRequest/CheckResult
// types. We cannot reasonably shell out to a Python interpreter from a
// Go test on Windows CI runners, so the property side is Go-only:
// generate random valid ActionRequests, marshal+unmarshal, and assert
// reflexive equality. The cross-language anchor is the golden-fixture
// check below: the Python and TypeScript SDK test files load the SAME
// fixture file from disk and assert structurally identical decode
// results. If the Go re-encode here differs from the on-disk fixture,
// that signals drift well before the SDKs notice.
//
// Closes the "no silent wire-format drift" guarantee for R1 F4 / F7.

package v1

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// scopes / decisions that are valid in v1. The property generator
// chooses from these so we don't waste cycles on rejected inputs.
var validScopes = []string{
	"shell", "filesystem", "network", "browser", "data", "cost",
}

// generateActionRequest returns a randomly-populated ActionRequest with
// every field within ASCII printable range. Used by the testing/quick
// driver below.
//
// We intentionally always include the schema_version field so the
// round-trip preserves byte-for-byte (omitempty drops the field from
// the JSON body otherwise — which is the documented behavior, but it
// makes the reflexive-equality check below noisier than it needs to be).
func generateActionRequest(rnd *rand.Rand) ActionRequest {
	return ActionRequest{
		SchemaVersion: Version,
		Scope:         validScopes[rnd.Intn(len(validScopes))],
		Action:        randomASCII(rnd, rnd.Intn(20)),
		Command:       randomASCII(rnd, rnd.Intn(40)),
		Path:          randomASCII(rnd, rnd.Intn(40)),
		Domain:        randomASCII(rnd, rnd.Intn(30)),
		URL:           randomASCII(rnd, rnd.Intn(50)),
		AgentID:       randomASCII(rnd, rnd.Intn(20)),
		SessionID:     randomASCII(rnd, rnd.Intn(20)),
		EstCost:       float64(rnd.Intn(10000)) / 100.0, // two-decimal "$" range
		// Meta omitted — map ordering is non-deterministic and the
		// round-trip already exercises the type's JSON shape.
	}
}

// randomASCII returns a string of printable ASCII chars (0x20-0x7E)
// excluding double-quote and backslash to keep the JSON encoder honest
// without requiring escape-sequence diff. n=0 returns "".
func randomASCII(rnd *rand.Rand, n int) string {
	if n == 0 {
		return ""
	}
	buf := make([]byte, n)
	for i := range buf {
		c := byte(0x20 + rnd.Intn(0x7F-0x20))
		// Excise the two characters that complicate JSON byte-equality.
		if c == '"' || c == '\\' {
			c = ' '
		}
		buf[i] = c
	}
	return string(buf)
}

// TestActionRequest_RoundTripProperty drives 100+ random ActionRequest
// values through json.Marshal → json.Unmarshal and asserts the decoded
// value is reflect.DeepEqual to the input. The property: the v1 wire
// format is lossless on every populated field.
func TestActionRequest_RoundTripProperty(t *testing.T) {
	prop := func(seed int64) bool {
		rnd := rand.New(rand.NewSource(seed))
		original := generateActionRequest(rnd)

		data, err := json.Marshal(original)
		if err != nil {
			t.Logf("marshal err: %v", err)
			return false
		}

		var decoded ActionRequest
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Logf("unmarshal err: %v on bytes %q", err, data)
			return false
		}

		if !reflect.DeepEqual(original, decoded) {
			t.Logf("round-trip drift:\n original=%+v\n decoded=%+v\n bytes=%s",
				original, decoded, data)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 200}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("property failed: %v", err)
	}
}

// TestCheckResult_RoundTripProperty mirrors the request side for
// CheckResult — every populated field round-trips losslessly.
func TestCheckResult_RoundTripProperty(t *testing.T) {
	decisions := []policy.Decision{policy.Allow, policy.Deny, policy.RequireApproval}

	prop := func(seed int64) bool {
		rnd := rand.New(rand.NewSource(seed))
		original := CheckResult{
			SchemaVersion: Version,
			Decision:      decisions[rnd.Intn(len(decisions))],
			Reason:        randomASCII(rnd, rnd.Intn(60)),
			Rule:          randomASCII(rnd, rnd.Intn(40)),
			ApprovalID:    randomASCII(rnd, rnd.Intn(40)),
			ApprovalURL:   randomASCII(rnd, rnd.Intn(80)),
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Logf("marshal err: %v", err)
			return false
		}

		var decoded CheckResult
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Logf("unmarshal err: %v on bytes %q", err, data)
			return false
		}

		if !reflect.DeepEqual(original, decoded) {
			t.Logf("round-trip drift:\n original=%+v\n decoded=%+v\n bytes=%s",
				original, decoded, data)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 200}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatalf("property failed: %v", err)
	}
}

// TestFixture_GoldenCrossCheck loads the on-disk Python/TypeScript-shared
// fixture, decodes it through Go's standard json package, re-encodes,
// and compares the resulting key-set to the original on-disk shape.
// This is the Go side of the cross-language anchor: if Python/TS see a
// different decode than this test asserts, drift is in the SDK; if this
// test fails after a Go change, drift is in pkg/policy or pkg/proxy/schema/v1.
func TestFixture_GoldenCrossCheck(t *testing.T) {
	path := filepath.Join("testdata", "sample_request.json")
	rawIn, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Step 1: decode into a typed ActionRequest.
	var req ActionRequest
	if err := json.Unmarshal(rawIn, &req); err != nil {
		t.Fatalf("decode typed: %v", err)
	}

	// Step 2: re-encode and decode back into a generic map. Compare to
	// the same generic-map decode of the original fixture. Any silent
	// field drop or rename surfaces here.
	rawOut, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	var decodedOriginal, decodedRoundTrip map[string]any
	if err := json.Unmarshal(rawIn, &decodedOriginal); err != nil {
		t.Fatalf("generic decode original: %v", err)
	}
	if err := json.Unmarshal(rawOut, &decodedRoundTrip); err != nil {
		t.Fatalf("generic decode round-trip: %v", err)
	}

	if !reflect.DeepEqual(decodedOriginal, decodedRoundTrip) {
		t.Fatalf("cross-check drift between fixture and Go round-trip:\n original=%v\n round-trip=%v",
			decodedOriginal, decodedRoundTrip)
	}

	// Step 3: confirm the documented field set is present (regression
	// coupon for "field silently disappeared"). The same key list is
	// asserted in plugins/python/tests/test_wire_format.py.
	for _, key := range []string{"schema_version", "agent_id", "session_id", "scope", "command", "meta"} {
		if _, ok := decodedOriginal[key]; !ok {
			t.Errorf("fixture missing expected key %q", key)
		}
	}
}
