# Dependency safety registry (`advisories.json`)

This registry drives `TestDependencyAudit_Gate` in `pkg/depaudit`. It is the
one place AgentGuard records **known** security vulnerabilities and performance
regressions that affect a version the project ships.

## The contract the gate enforces

A dependency is **SAFE** (passes) when it is on the latest version, **or** it is
behind the latest version but the gap carries no known security vulnerability
and no known performance regression. Being merely behind is fine — we do not
fail the build for routine upstream releases.

A dependency is **UNSAFE** (fails) only when its current version is inside an
advisory's affected range **and** a fixed release exists, i.e. an upgrade would
actually resolve a real security or performance problem.

## How security is actually verified (not assumed)

The gate does **not** trust the registry alone for security. When run online
(`DEPAUDIT_ONLINE=1`, which CI sets), it queries the live **OSV.dev** database
for each *exact pinned version* across Go, PyPI, and npm and fails if that
version has a known vulnerability with an available fix. This is what makes
"behind latest but safe to defer" a *verified* statement about the gap rather
than an assumption: OSV is asked whether the current pin is vulnerable.

Coverage and its honest limits (the report states the split every run):

- **Exact pins (Go module versions, npm lockfile-resolved)** — verified live
  against OSV.dev. Go is additionally covered by the blocking, reachability-based
  `govulncheck` job.
- **Python extras (version *ranges*, no lockfile) and Go pseudo-versions** —
  not a clean point query, so they are **registry-only** for security. Surface
  Python advisories with `pip-audit` and triage real ones into this registry.
- **Performance regressions** — have no automated database anywhere. Upstream
  release notes and our own benchmarks are the only source, so this registry is
  the source of truth for them. It is how "an upgrade fixes a perf regression"
  becomes a build-breaking fact instead of tribal knowledge.

## Adding an entry

```json
{
  "id": "GHSA-xxxx-xxxx-xxxx (CVE-2026-12345)",
  "ecosystem": "go | python | npm",
  "package": "exact/module/or/package/name",
  "kind": "security | performance",
  "summary": "One sentence: what goes wrong.",
  "reference": "https://link-to-advisory-or-release-notes",
  "affected": [{ "introduced": "1.2.0", "fixed": "1.2.7" }]
}
```

- `package` must match the manifest name exactly: the Go module path
  (`gopkg.in/yaml.v3`), the PyPI name (`langchain-core`), or the npm name
  (`@types/node`).
- `introduced` `"0"` means "from the beginning". `fixed` `""` (or omitted) means
  no fix exists yet — it is reported as a note and does **not** fail the gate,
  because an upgrade cannot resolve it.
- For Python extras (version *ranges*, not pins) the gate fails only when the
  allowed range overlaps the affected interval **and** the constraint cannot
  reach the fix — i.e. the ceiling locks the project below a security/perf fix.
  An old floor whose range still permits a safe version is intentionally not
  flagged.

## Removing an entry

Delete it once every manifest has moved past `fixed`. Keeping resolved entries
is harmless (they no longer match), but pruning keeps the registry readable.

## Running it

```
go test -run '^TestDependencyAudit_Gate$'   -v ./pkg/depaudit   # blocking gate
DEPAUDIT_ONLINE=1 \
go test -run '^TestDependencyAudit_Report$' -v ./pkg/depaudit   # full report
make dep-audit                                                  # both, locally
```
