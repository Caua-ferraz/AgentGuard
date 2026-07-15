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

## Follow-up hardening (post-0.6.1 patch, second pass)

Resolved in the follow-up debt-reduction pass:

1. **`pkg/metrics` globals → Registry seam.** All series state now lives in
   `metrics.Registry`; the package-level functions delegate to `Default`.
   The exported raw counter vars became same-named accessor functions, the
   exported histograms became `Observe*Duration` functions, and `Reset()`
   gives tests isolation. Prometheus output is byte-identical (pinned by
   `TestRegistry_ResetMatchesFresh`). Five copy-pasted labeled-counter
   emitters collapsed into one generic `writeLabeledCounter`.
2. **Parallel `Config` structs → shared `gateclient` config.** The shared
   gate flags (guard-url, api-key, tenant-id, fail-mode, log-level, policy),
   the AGENTGUARD_API_KEY env fallback, and the shared validation now live
   in `pkg/internal/gateclient/config.go`; both proxies register/resolve
   through it. Side fix: the MCP gateway now validates tenant-id non-empty
   and rejects non-http(s) guard URLs, matching the LLM proxy.
3. **Audit wiring + backend parity.** Backend selection, startup migration,
   rotation, and forced-buffering rules moved from `runServe` into
   `cmd/agentguard/audit_setup.go` (`buildAuditPipeline`), with the
   shutdown order explicit in `auditPipeline.Close` instead of defer LIFO.
   The never-wired `audit.SQLiteLogger` (267 lines, predates v0.5
   transport tagging; superseded by `store.NewAuditLogger`) was deleted.
   The two live backends keep their deliberately different mechanisms
   (Go-side scan vs indexed SQL); their QueryFilter semantics are pinned
   by `pkg/store/audit_query_parity_test.go`.
4. **Python `__init__.py` monolith** split into `core.py` (client,
   exceptions, constants) + `decorators.py` (`@guarded`); the package root
   re-exports everything, so imports are unchanged.
5. **Tooling/test health.** `.gitattributes` now forces LF for `*.go`
   (gofmt is meaningful on Windows again; 20 genuinely misformatted files
   surfaced and fixed). The streaming-cap tests' poll deadlines are sized
   for full-suite parallel load (the `MaxConcurrentStreams` flake).

## Still deferred

1. **God files.** `pkg/proxy/server.go` (~2,000 lines: routing + approval
   queue + SSE hub + cost sweeper + Prometheus serialisation + dashboard +
   audit query) and `pkg/policy/engine.go` (~1,800 lines; the glob/pattern
   matchers are a separable internal package). Mechanical splits, but they
   churn the two most change-sensitive files in the repo — schedule
   alongside a quiet cycle (0.7+).
2. **`pkg/persist` tier-bridging.** The syncer imports concrete types from
   `policy`, `proxy`, `ratelimit`, and `store` at once; narrow snapshotter
   interfaces would decouple it. Off the hot path, cosmetic.
3. **`bin/sim/*.py`** — resolved as a non-issue: the directory is inside the
   gitignored `/bin/`, i.e. untracked local dev tooling, not shipped code.
