// Tests for the v1 wire-protocol schema package. These tests are the
// Go side of the cross-language contract test (R1 F7 in the audit). The
// Python equivalent lives at plugins/python/tests/test_wire_format.py
// and the TypeScript equivalent at
// plugins/typescript/src/__tests__/wire_format.test.ts. All three load
// the same fixtures from this package's testdata/ directory.
package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// TestActionRequest_RoundTrip asserts that an ActionRequest with every
// field populated survives a json.Marshal/json.Unmarshal cycle without
// loss. Closes R1 F4 (no schema_version field) and R1 F7 (Go side of
// the cross-language contract).
func TestActionRequest_RoundTrip(t *testing.T) {
	original := ActionRequest{
		SchemaVersion: Version,
		Scope:         "shell",
		Action:        "exec",
		Command:       "ls -la",
		Path:          "/tmp/x",
		Domain:        "api.example.com",
		URL:           "https://api.example.com/v1/foo",
		AgentID:       "agent-a",
		SessionID:     "sess-1",
		EstCost:       0.25,
		Meta:          map[string]string{"k": "v", "k2": "v2"},
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got ActionRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(original, got) {
		t.Fatalf("round-trip mismatch:\n want: %+v\n got:  %+v", original, got)
	}
}

// TestCheckResult_RoundTrip asserts that a CheckResult survives a
// marshal/unmarshal cycle, including the schema_version field added
// for v0.5.
func TestCheckResult_RoundTrip(t *testing.T) {
	original := CheckResult{
		SchemaVersion: Version,
		Decision:      DecisionRequireApproval,
		Reason:        "needs human review",
		Rule:          "require_approval:shell:rm",
		ApprovalID:    "ap_0123456789abcdef0123456789abcdef",
		ApprovalURL:   "https://example/v1/approve/ap_0123456789abcdef0123456789abcdef",
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got CheckResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(original, got) {
		t.Fatalf("round-trip mismatch:\n want: %+v\n got:  %+v", original, got)
	}
}

// TestActionRequest_DefaultsSchemaVersion asserts the documented
// behavior: a request with schema_version omitted decodes to an empty
// SchemaVersion field, and the proxy is responsible for defaulting it
// to "v1" before further processing. This locks in the contract that
// v0.4.x clients (which do not emit schema_version) keep working.
func TestActionRequest_DefaultsSchemaVersion(t *testing.T) {
	body := []byte(`{"scope":"shell","command":"ls"}`)

	var req ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.SchemaVersion != "" {
		t.Fatalf("expected empty SchemaVersion on legacy request, got %q", req.SchemaVersion)
	}

	// Mirror the proxy-side default: empty becomes Version.
	if req.SchemaVersion == "" {
		req.SchemaVersion = Version
	}
	if req.SchemaVersion != "v1" {
		t.Fatalf("expected default %q, got %q", Version, req.SchemaVersion)
	}
}

// TestActionRequest_RejectsUnknownSchemaVersion asserts that the wire
// format successfully decodes an explicit non-v1 value (so the server
// can read it and reject it with a structured 400) — the rejection
// itself is exercised by the proxy server tests; this test asserts
// the schema-package contract that "v2" decodes cleanly into the
// SchemaVersion field rather than being silently accepted as v1.
func TestActionRequest_RejectsUnknownSchemaVersion(t *testing.T) {
	body := []byte(`{"schema_version":"v2","scope":"shell","command":"ls"}`)

	var req ActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.SchemaVersion != "v2" {
		t.Fatalf("expected SchemaVersion=v2, got %q", req.SchemaVersion)
	}
	if req.SchemaVersion == Version {
		t.Fatal("v2 must not collide with the v1 constant — package version drift")
	}
}

// TestSchemaJSON_Parseable asserts that schema.json is valid JSON and
// that the top-level shape matches what we expect — the file is
// hand-written and we don't carry a draft-07 validator dependency, so
// this test is a structural sanity check rather than a full validation.
func TestSchemaJSON_Parseable(t *testing.T) {
	path := filepath.Join("schema.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema.json: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse schema.json: %v", err)
	}

	for _, key := range []string{"$schema", "$id", "title", "$defs"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("schema.json missing top-level key %q", key)
		}
	}

	defs, ok := doc["$defs"].(map[string]interface{})
	if !ok {
		t.Fatalf("schema.json $defs is not an object")
	}
	for _, def := range []string{"schemaVersion", "decision", "scope", "actionRequest", "checkResult"} {
		if _, ok := defs[def]; !ok {
			t.Errorf("schema.json $defs missing %q", def)
		}
	}
}

// TestFixture_SampleRequest asserts the on-disk request fixture decodes
// into an ActionRequest with the documented field values. This is the
// Go anchor of the cross-language contract: any drift between this
// expectation and what plugins/python and plugins/typescript assert
// will fail in CI.
func TestFixture_SampleRequest(t *testing.T) {
	path := filepath.Join("testdata", "sample_request.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var req ActionRequest
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want := ActionRequest{
		SchemaVersion: "v1",
		AgentID:       "test-agent-001",
		SessionID:     "sess-abc",
		Scope:         "shell",
		Command:       "ls -la",
		Meta:          map[string]string{"source": "ci-fixture"},
	}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("fixture mismatch:\n want: %+v\n got:  %+v", want, req)
	}

	// Also verify byte-level shape: re-encoding the decoded value must
	// land on the same set of keys (modulo whitespace) as the original
	// fixture, so a code change that silently drops a field is caught.
	reencoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	var rt map[string]interface{}
	if err := json.Unmarshal(reencoded, &rt); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	var orig map[string]interface{}
	if err := json.Unmarshal(b, &orig); err != nil {
		t.Fatalf("re-decode original: %v", err)
	}
	if !reflect.DeepEqual(rt, orig) {
		t.Fatalf("key-set drift:\n original: %v\n round-trip: %v", orig, rt)
	}
}

// TestFixture_SampleResult asserts the on-disk result fixture decodes
// into a CheckResult with the documented field values.
func TestFixture_SampleResult(t *testing.T) {
	path := filepath.Join("testdata", "sample_result.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var res CheckResult
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want := CheckResult{
		SchemaVersion: "v1",
		Decision:      policy.Allow,
		Reason:        "matched allow rule",
		Rule:          "allow:shell:ls",
	}
	if !reflect.DeepEqual(res, want) {
		t.Fatalf("fixture mismatch:\n want: %+v\n got:  %+v", want, res)
	}
}

// TestVersionConstant guards the literal "v1" — if anyone changes the
// constant without simultaneously introducing a v2 package and
// negotiating with clients, this test catches it.
func TestVersionConstant(t *testing.T) {
	if Version != "v1" {
		t.Fatalf("schema package Version drifted: got %q want %q", Version, "v1")
	}
}

// TestFixturesAreCanonicalJSON asserts the fixture files use a stable,
// compact representation suitable for byte-equality comparisons
// across language test runners. This avoids flake from CRLF vs LF or
// trailing-newline drift on Windows checkouts.
func TestFixturesAreCanonicalJSON(t *testing.T) {
	for _, name := range []string{"sample_request.json", "sample_result.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Reject CR — fixtures must be LF-only.
		if bytes.Contains(b, []byte{'\r'}) {
			t.Errorf("%s contains CR byte; fixtures must be LF-only", name)
		}
		// Must end with a single newline.
		if len(b) == 0 || b[len(b)-1] != '\n' {
			t.Errorf("%s missing trailing LF", name)
		}
	}
}
