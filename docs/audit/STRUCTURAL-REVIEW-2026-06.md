# AgentGuard Structural & Architectural Review — 2026-06

**Scope:** maintainability, cohesion, duplication, dead code — explicitly *not*
a security review (see `2026-06-INTERNAL-AUDIT.md` for that).
**Method:** full-source review (~32K non-test LOC: 3 Go binaries, 12 `pkg/`
packages, Python + TypeScript SDKs), followed by remediation of the
mechanical findings in the same change set.
**Commit baseline:** `security/v0.6-audit-hardening` @ `51e7b76`.

---

## Verdict

**Structurally sound enough to move forward — no refactor-first blocker.**

The package dependency graph is clean and acyclic (`policy` is a pure root
imported by nine packages; no cycles anywhere). Interfaces exist at the right
seams (`PolicyProvider`, `audit.Logger`, the store interfaces). Tenant IDs
thread explicitly as parameters, not hidden globals. Docs match the code
(`PROXY_ARCHITECTURE.md` correctly describes the three-binary topology).

The debt that existed was *contained and named*: one deliberate duplication
cluster (the mirrored llmproxy/mcpgw gates — fixed in this change set), three
god files, and a globals-based metrics registry (deferred — see below). None
of the deferred items blocks feature work; they raise the cost of specific
kinds of change and should be scheduled, not firefought.

---

## Fixed in this change set

| # | Finding | Fix |
|---|---------|-----|
| 1 | **Mirrored gate clients.** `pkg/llmproxy/gate.go` and `pkg/mcpgw/gate.go` were deliberate near-copies (`callV1Check` ~95% identical, `truncateForError`/`firstStringArg` byte-identical, `failModeDecision`/`decisionFromCheckResult` logic-identical) and had already diverged: llmproxy recognised `cat`/`find`/`glob` as filesystem read verbs, mcpgw did not; llmproxy hard-denied unknown `/v1/check` decisions, mcpgw passed them through bare. | New shared internal package **`pkg/internal/gateclient`** owns the `/v1/check` wire contract, fail-mode translation, and the shared helpers. Both gates are now thin delegates; the diverged behaviours are unified to the superset (mcpgw gains the extra read verbs and the defensive unknown-decision deny with new `mcpgw.InvalidResponseRule`). |
| 2 | **Duplicate `Decision` struct** in `pkg/llmproxy/server.go` and `pkg/mcpgw/bridge.go`. | Single `gateclient.Decision`; both packages re-export it via type alias, so their public APIs are unchanged. |
| 3 | **Version skew.** Both gates stamped a hard-coded `User-Agent: …/1.0` on `/v1/check` while the same binaries reported `BuildVersion`/`GatewayBuildVersion` elsewhere. | `/v1/check` User-Agent now uses the build-version variables. |
| 4 | **Dead code.** `ErrPolicyNotLoaded` declared in both gate packages, referenced by neither (self-documented as "currently unused"). | Deleted from both. |
| 5 | **Python adapter copy-paste.** `langchain._infer_check_params` / `crewai._extract_check_params` were ~95% identical and had diverged (CrewAI silently lacked the filesystem `action` inference); the URL→domain block was pasted a third time in `mcp.py`, whose verb table also lacked `create`. | New **`agentguard/adapters/_common.py`** (`extract_check_params`, `infer_path_action`, `domain_from_url`); all three adapters delegate. CrewAI gains action inference; MCP gains the `create`→write verb. MCP keeps its redaction + shell-fallback specifics locally. |
| 6 | **No `__all__`** in the Python SDK's 635-line `__init__.py` — no explicit public-API boundary. | `__all__` added. |

Net: −409 lines across the touched files before counting the two new shared
modules. Verified: `go build ./...`, `go vet`, full `go test ./...` green
(one known-flaky concurrency test, `TestServer_MaxConcurrentStreams_
DecrementsOnRequestEnd`, fails only under full-suite parallel load and passes
3/3 in isolation — pre-existing); Python suite 334 passed / 1 skipped.

## Deferred (recorded, deliberately not done here)

These are real but are hot-path or API-shape refactors that deserve their own
approval per the engineering contract (no behaviour change was acceptable
collateral in a review pass):

1. **`pkg/metrics` globals.** ~30 package-level vars + ~60 free functions; every
   caller hard-codes `metrics.Inc*()`. No injection seam → tests share global
   state, backend unswappable. Fix: a `Metrics` interface injected via config,
   bound to the global registry in `main.go`.
2. **God files.** `pkg/proxy/server.go` (1,999 lines: routing + approval queue +
   SSE hub + cost sweeper + Prometheus serialisation + dashboard + audit query)
   and `pkg/policy/engine.go` (1,799 lines; the glob/pattern matchers are a
   separable internal package). Mechanical splits, but they churn the two most
   change-sensitive files in the repo — schedule alongside a quiet cycle.
3. **Parallel `Config` structs** in llmproxy/mcpgw (shared GuardURL/APIKey/
   TenantID/FailMode/PolicyPath fields + separate flag parsing). A shared
   embedded base struct breaks keyed `Config{…}` literals across the test
   suite, so it needs a deliberate API decision rather than a drive-by.
4. **Audit backend bifurcation.** `FileLogger` and `SQLiteLogger` re-implement
   `Query()` filtering separately; backend selection + forced buffering logic
   lives inline in `cmd/agentguard/main.go:~346–451`.
5. **`pkg/persist` tier-bridging.** The syncer imports concrete types from
   `policy`, `proxy`, `ratelimit`, and `store` at once; narrow snapshotter
   interfaces would decouple it. Off the hot path, so cosmetic for now.
6. **Python `__init__.py` monolith.** Guard client, exceptions, and decorator
   in one 635-line module; a `core.py`/`decorators.py` split with re-exports
   would not break imports.
7. **`bin/sim/*.py`** mock servers are referenced by no test, doc, Makefile, or
   CI job — confirm whether they are still used for manual testing; delete or
   document.
