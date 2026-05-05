// Package v1 documents and re-exports the v1 wire-protocol types for the
// AgentGuard /v1/check endpoint.
//
// Canonical types live in github.com/Caua-ferraz/AgentGuard/pkg/policy
// (ActionRequest, CheckResult). This package exists for two reasons:
//
//  1. Versioning — when v2 of the wire protocol is introduced, a new
//     pkg/proxy/schema/v2 package will appear alongside v1, and the
//     proxy can dispatch on the request's schema_version field. The v1
//     types stay frozen.
//
//  2. Discoverability — operators and SDK authors looking for "the
//     wire format" find a single self-contained directory containing
//     the Go types, the JSON-Schema document (schema.json), and the
//     cross-language fixtures (testdata/) that are exercised by the
//     contract tests in plugins/python and plugins/typescript.
//
// Why re-export rather than redefine: making this package canonical
// would force pkg/policy (which is imported by every part of the system,
// including pkg/proxy/schema/v1 itself) to depend on it, creating an
// import cycle. The decision is recorded in .audit/v05_decisions.md
// under "Wire-schema canonical-type location".
//
// Backward-compatibility contract for v1:
//   - No field is ever removed.
//   - No field's JSON type or name ever changes.
//   - New optional fields may be added to ActionRequest/CheckResult.
//     Strict clients that reject unknown fields are responsible for
//     coordinating their upgrade window with the server.
//
// See docs/WIRE_PROTOCOL.md for the operator-facing description.
package v1

import "github.com/Caua-ferraz/AgentGuard/pkg/policy"

// Version is the wire-protocol version emitted by this package.
// Requests with an empty schema_version default to this value;
// requests with any other value are rejected with HTTP 400.
const Version = "v1"

// ActionRequest is the v1 request body for POST /v1/check. The
// canonical definition lives on policy.ActionRequest; this alias keeps
// existing imports stable while making the wire-protocol identity
// explicit for callers that import the schema package directly.
type ActionRequest = policy.ActionRequest

// CheckResult is the v1 response body for POST /v1/check. As above, an
// alias for policy.CheckResult.
type CheckResult = policy.CheckResult

// Decision is the v1 decision enum. Possible values:
//   - "ALLOW"
//   - "DENY"
//   - "REQUIRE_APPROVAL"
type Decision = policy.Decision

// Decision constants re-exported for symmetry with the schema package.
const (
	DecisionAllow           = policy.Allow
	DecisionDeny            = policy.Deny
	DecisionRequireApproval = policy.RequireApproval
)
