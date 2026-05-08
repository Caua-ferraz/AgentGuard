/**
 * AgentGuard TypeScript SDK
 *
 * Lightweight client for checking actions against AgentGuard policies.
 *
 * @example
 * ```ts
 * import { AgentGuard } from '@agentguard/sdk';
 *
 * const guard = new AgentGuard('http://localhost:8080');
 * const result = await guard.check('shell', { command: 'rm -rf ./data' });
 *
 * if (result.allowed) {
 *   execute(command);
 * } else if (result.needsApproval) {
 *   console.log(`Approve at: ${result.approvalUrl}`);
 * } else {
 *   console.log(`Blocked: ${result.reason}`);
 * }
 * ```
 */

export interface CheckOptions {
  action?: string;
  command?: string;
  path?: string;
  domain?: string;
  url?: string;
  /** Session identifier for session-level cost tracking. */
  sessionId?: string;
  /** Estimated cost of this action in USD (for cost scope). */
  estCost?: number;
  meta?: Record<string, string>;
}

export interface CheckResult {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matchedRule?: string;
  approvalId?: string;
  approvalUrl?: string;

  /** Convenience: true if decision is ALLOW */
  readonly allowed: boolean;
  /** Convenience: true if decision is DENY */
  readonly denied: boolean;
  /** Convenience: true if decision is REQUIRE_APPROVAL */
  readonly needsApproval: boolean;
}

/**
 * Wire-format of the /v1/check response as emitted by the Go server. Kept
 * internal: callers see the normalized `CheckResult` shape above.
 */
interface CheckResponseJSON {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matched_rule?: string;
  approval_id?: string;
  approval_url?: string;
}

/** Wire-format of the /v1/status/{id} response. */
interface StatusResponseJSON {
  id: string;
  status: "pending" | "resolved";
  decision?: "ALLOW" | "DENY";
  reason?: string;
}

export interface AgentGuardOptions {
  /** Base URL of the AgentGuard proxy (default: http://localhost:8080) */
  baseUrl?: string;
  /** Agent identifier sent with every check */
  agentId?: string;
  /** API key for authenticated endpoints (approve/deny) */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Behavior when AgentGuard is unreachable: 'deny' (default) or 'allow' */
  failMode?: "deny" | "allow";
  /**
   * Optional tenant identifier.
   *
   * When set to a non-empty value other than `"local"`, every HTTP call
   * is routed through the tenant-aware `/v1/t/{tenantId}/...` URL family
   * instead of the legacy `/v1/...` path. Empty string, `undefined`, or
   * `"local"` selects the legacy URLs. Falls back to the
   * `AGENTGUARD_TENANT_ID` env var when available (Node only).
   *
   * The bundled FilePolicyProvider only recognises `"local"`;
   * multi-tenant providers can register others.
   */
  tenantId?: string;
}

/**
 * Sentinel tenant value treated as an alias for the legacy URL family.
 * Exported so callers can build the same comparison the SDK does without
 * hardcoding the string literal in user code.
 */
export const LOCAL_TENANT_ID = "local";

/**
 * Read a process.env variable without assuming Node. Returns undefined if
 * the runtime has no `process` (browsers, Deno without --compat, etc.) or
 * if the variable is unset/empty. Keeps the SDK usable in non-Node
 * contexts while still honoring env fallback when it is available — this
 * matches the Python SDK's `base_url or os.environ.get(...)` pattern.
 */
function readEnv(name: string): string | undefined {
  try {
    const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    const v = p && p.env ? p.env[name] : undefined;
    return v && v.length > 0 ? v : undefined;
  } catch {
    return undefined;
  }
}

class CheckResultImpl implements CheckResult {
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  reason: string;
  matchedRule?: string;
  approvalId?: string;
  approvalUrl?: string;

  constructor(data: Partial<CheckResult>) {
    this.decision = data.decision ?? "DENY";
    this.reason = data.reason ?? "";
    this.matchedRule = data.matchedRule;
    this.approvalId = data.approvalId;
    this.approvalUrl = data.approvalUrl;
  }

  get allowed(): boolean {
    return this.decision === "ALLOW";
  }
  get denied(): boolean {
    return this.decision === "DENY";
  }
  get needsApproval(): boolean {
    return this.decision === "REQUIRE_APPROVAL";
  }
}

/**
 * Base class for AgentGuard policy-failure errors thrown by {@link guarded}.
 *
 * Callers can `catch (e) { if (e instanceof AgentGuardDeniedError) ... }`
 * and read structured fields (`result`, `approvalId`, `approvalUrl`). Every
 * subclass extends the standard `Error`, so generic `catch { ... }`
 * handlers are unaffected.
 */
export class AgentGuardError extends Error {
  readonly result?: CheckResult;

  constructor(message: string, result?: CheckResult) {
    super(message);
    this.name = "AgentGuardError";
    this.result = result;
    // Fix instanceof across downstream transpile targets (ES5).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when the policy decision was DENY. */
export class AgentGuardDeniedError extends AgentGuardError {
  constructor(message: string, result?: CheckResult) {
    super(message, result);
    this.name = "AgentGuardDeniedError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the policy decision was REQUIRE_APPROVAL and the
 * decorator/HOF was not configured to wait for resolution.
 */
export class AgentGuardApprovalRequiredError extends AgentGuardError {
  readonly approvalId: string;
  readonly approvalUrl: string;

  constructor(
    message: string,
    result?: CheckResult,
    approvalId = "",
    approvalUrl = ""
  ) {
    super(message, result);
    this.name = "AgentGuardApprovalRequiredError";
    this.approvalId = approvalId;
    this.approvalUrl = approvalUrl;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when `waitForApproval` was requested but the action did not resolve
 * before the deadline. `result` carries the synthetic DENY/"Approval timed
 * out" produced by {@link AgentGuard.waitForApproval}.
 */
export class AgentGuardApprovalTimeoutError extends AgentGuardError {
  readonly approvalId: string;

  constructor(message: string, result?: CheckResult, approvalId = "") {
    super(message, result);
    this.name = "AgentGuardApprovalTimeoutError";
    this.approvalId = approvalId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an auth-gated AgentGuard endpoint (`/v1/approve`,
 * `/v1/deny`, `/v1/status`, `/v1/audit`) returns 401 or 403.
 *
 * Lets callers tell apart "API key wrong / expired" from "approval poll
 * timed out" so the operator-facing error surfaces the right cause.
 */
export class AgentGuardAuthError extends AgentGuardError {
  readonly status: number;

  constructor(message: string, status: number, result?: CheckResult) {
    super(message, result);
    this.name = "AgentGuardAuthError";
    this.status = status;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Valid values for the `failMode` SDK option. Exported so callers can
 * use the same allowlist when validating their own configuration.
 */
const VALID_FAIL_MODES = ["deny", "allow"] as const;

/**
 * Allowed keys on `AgentGuardOptions`. Used to reject unknown options at
 * construction time instead of silently ignoring them — typos like
 * `agnetId: "x"` should fail loudly, not silently default to `agentId=""`.
 */
const VALID_AGENTGUARD_OPTION_KEYS: ReadonlySet<string> = new Set([
  "baseUrl",
  "agentId",
  "apiKey",
  "timeout",
  "failMode",
  "tenantId",
]);

/**
 * Allowed keys on the {@link guarded} options object.
 */
const VALID_GUARDED_OPTION_KEYS: ReadonlySet<string> = new Set([
  "getCheckOptions",
  "waitForApproval",
  "approvalTimeoutMs",
  "approvalPollIntervalMs",
]);

export class AgentGuard {
  private baseUrl: string;
  private agentId: string;
  private apiKey: string;
  private timeout: number;
  private failMode: "deny" | "allow";
  private tenantId: string;

  constructor(baseUrlOrOptions?: string | AgentGuardOptions) {
    // Environment fallbacks mirror the Python SDK: AGENTGUARD_URL supplies
    // baseUrl when the caller did not pass one; AGENTGUARD_API_KEY supplies
    // apiKey; AGENTGUARD_TENANT_ID supplies tenantId. Explicit values in
    // the options object override the env var so callers that genuinely
    // want to disable a setting can pass an empty string.
    const envBaseUrl = readEnv("AGENTGUARD_URL");
    const envApiKey = readEnv("AGENTGUARD_API_KEY") ?? "";
    const envTenantId = readEnv("AGENTGUARD_TENANT_ID") ?? "";

    if (typeof baseUrlOrOptions === "string") {
      this.baseUrl = baseUrlOrOptions.replace(/\/$/, "");
      this.agentId = "";
      this.apiKey = envApiKey;
      this.timeout = 5000;
      this.failMode = "deny";
      this.tenantId = envTenantId;
    } else {
      const opts = baseUrlOrOptions ?? {};

      // Reject unknown options so a typo like `agnetId: "x"` raises
      // at construction instead of silently running with
      // `agentId = ""` and surfacing as a confusing policy-decision
      // mystery later.
      const unknown = Object.keys(opts).filter(
        (k) => !VALID_AGENTGUARD_OPTION_KEYS.has(k)
      );
      if (unknown.length > 0) {
        throw new TypeError(
          `AgentGuard: unknown options ${JSON.stringify(unknown)}. ` +
            `Valid options: ${JSON.stringify(
              Array.from(VALID_AGENTGUARD_OPTION_KEYS).sort()
            )}.`
        );
      }

      this.baseUrl = (opts.baseUrl ?? envBaseUrl ?? "http://localhost:8080").replace(
        /\/$/,
        ""
      );
      this.agentId = opts.agentId ?? "";
      this.apiKey = opts.apiKey ?? envApiKey;
      this.timeout = opts.timeout ?? 5000;
      this.failMode = opts.failMode ?? "deny";
      // tenantId precedence: an explicit options field — including the
      // empty string — wins over the env var. Passing tenantId: "" is
      // the supported way to suppress an env-var-leaked tenant in a
      // scoped test or a sub-process that should hit the legacy URLs.
      this.tenantId = opts.tenantId !== undefined ? opts.tenantId : envTenantId;
    }

    // Validate failMode. "deny" and "allow" are the only meaningful
    // values; anything else (typo, accidental boolean, user passing the
    // Python convention "DENY") is a programming bug and must surface
    // at startup, not at the first request.
    if (
      !(VALID_FAIL_MODES as readonly string[]).includes(this.failMode)
    ) {
      throw new TypeError(
        `AgentGuard: invalid failMode ${JSON.stringify(this.failMode)}. ` +
          `Expected one of ${JSON.stringify(VALID_FAIL_MODES)}.`
      );
    }
  }

  /**
   * Build the absolute URL for the given /v1 suffix.
   *
   * `suffix` is the path *after* `/v1`, e.g. `"/check"`,
   * `"/approve/ap_abc"`, `"/audit"`. When `tenantId` is set and not
   * `"local"`, the URL becomes `{baseUrl}/v1/t/{tenantId}{suffix}` with
   * `tenantId` URL-encoded via `encodeURIComponent` so reserved chars
   * (`/`, spaces) cannot break the path layout.
   */
  private url(suffix: string): string {
    if (this.tenantId && this.tenantId !== LOCAL_TENANT_ID) {
      return `${this.baseUrl}/v1/t/${encodeURIComponent(this.tenantId)}${suffix}`;
    }
    return `${this.baseUrl}/v1${suffix}`;
  }

  private authHeaders(): Record<string, string> {
    if (this.apiKey) {
      return { Authorization: `Bearer ${this.apiKey}` };
    }
    return {};
  }

  /**
   * Check an action against the AgentGuard policy.
   */
  async check(scope: string, options: CheckOptions = {}): Promise<CheckResult> {
    const payload: Record<string, unknown> = {
      scope,
      agent_id: this.agentId,
    };

    if (options.action) payload.action = options.action;
    if (options.command) payload.command = options.command;
    if (options.path) payload.path = options.path;
    if (options.domain) payload.domain = options.domain;
    if (options.url) payload.url = options.url;
    if (options.sessionId) payload.session_id = options.sessionId;
    if (options.estCost !== undefined && options.estCost !== 0) payload.est_cost = options.estCost;
    if (options.meta) payload.meta = options.meta;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(this.url("/check"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);

      // Honest response validation. A misconfigured reverse proxy
      // returning HTML or a chunked text body would either explode or
      // — worse — successfully decode a malformed JSON payload missing
      // `decision`, masking the actual issue. We positively assert each
      // layer.
      if (!response.ok) {
        return this.failModeResult(
          `AgentGuard returned status ${response.status}`
        );
      }

      const ctype = (response.headers.get("Content-Type") ?? "").toLowerCase();
      if (!ctype.startsWith("application/json")) {
        return this.failModeResult(
          `AgentGuard returned unexpected content-type ${JSON.stringify(ctype)}`
        );
      }

      let raw: unknown;
      try {
        raw = await response.json();
      } catch (e) {
        return this.failModeResult(
          `AgentGuard returned non-JSON body: ${
            e instanceof Error ? e.message : String(e)
          }`
        );
      }

      if (
        raw === null ||
        typeof raw !== "object" ||
        typeof (raw as { decision?: unknown }).decision !== "string"
      ) {
        return this.failModeResult(
          `AgentGuard returned malformed response body (missing 'decision')`
        );
      }

      const data = raw as CheckResponseJSON;
      return new CheckResultImpl({
        decision: data.decision,
        reason: data.reason,
        matchedRule: data.matched_rule,
        approvalId: data.approval_id,
        approvalUrl: data.approval_url,
      });
    } catch (err) {
      // Fail closed (deny) by default when AgentGuard is unreachable.
      return this.failModeResult(
        `AgentGuard unreachable: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Build a CheckResult honoring the configured `failMode`.
   *
   * Centralizes the fail-mode dispatch so transport failures and HTTP
   * contract violations (bad status, wrong content-type, malformed
   * body) all flow through one decision point. Without this a 200-OK
   * with the wrong Content-Type would surface as an opaque "AgentGuard
   * unreachable" instead of a clean "wrong content-type" reason.
   */
  private failModeResult(reason: string): CheckResult {
    const fallbackDecision = this.failMode === "allow" ? "ALLOW" : "DENY";
    return new CheckResultImpl({
      decision: fallbackDecision,
      reason,
    });
  }

  /**
   * Approve a pending action.
   */
  async approve(approvalId: string): Promise<boolean> {
    try {
      const res = await fetch(this.url(`/approve/${approvalId}`), {
        method: "POST",
        headers: this.authHeaders(),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Deny a pending action.
   */
  async deny(approvalId: string): Promise<boolean> {
    try {
      const res = await fetch(this.url(`/deny/${approvalId}`), {
        method: "POST",
        headers: this.authHeaders(),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Wait for a pending action to be resolved (blocks).
   *
   * Sends the API key on every poll since /v1/status is auth-gated on
   * servers configured with --api-key.
   */
  async waitForApproval(
    approvalId: string,
    timeoutMs: number = 300_000,
    pollIntervalMs: number = 2_000
  ): Promise<CheckResult> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      try {
        const res = await fetch(
          this.url(`/status/${approvalId}`),
          { headers: this.authHeaders() }
        );
        // 401/403 means the API key is broken. Continuing to poll
        // would just spin until the deadline elapses and return a
        // synthetic "Approval timed out" DENY, hiding the real cause.
        if (res.status === 401 || res.status === 403) {
          throw new AgentGuardAuthError(
            `AgentGuard rejected status poll for ${approvalId} ` +
              `with HTTP ${res.status} (check apiKey)`,
            res.status
          );
        }
        if (res.ok) {
          const data = (await res.json()) as StatusResponseJSON;
          if (data.status === "resolved" && (data.decision === "ALLOW" || data.decision === "DENY")) {
            return new CheckResultImpl({
              decision: data.decision,
              reason: data.reason ?? "resolved",
            });
          }
        }
      } catch (e) {
        // AgentGuardAuthError must propagate so the caller sees the auth
        // failure immediately. Other transport errors (DNS, ECONNREFUSED,
        // 5xx surfaced above) are swallowed and retried until deadline.
        if (e instanceof AgentGuardAuthError) throw e;
      }

      // Jittered sleep — 80%..120% of pollIntervalMs. Avoids a
      // thundering-herd when many SDK clients wait on the same approval
      // and would otherwise poll on identical period boundaries.
      const jitter = pollIntervalMs * (0.8 + 0.4 * Math.random());
      await new Promise((resolve) => setTimeout(resolve, jitter));
    }

    return new CheckResultImpl({
      decision: "DENY",
      reason: "Approval timed out",
    });
  }
}

/**
 * Optional configuration for {@link guarded}.
 *
 * `waitForApproval: true` dispatches on the resolved decision instead of
 * throwing immediately on REQUIRE_APPROVAL — mirrors the Python SDK's
 * `wait_for_approval=True`.
 */
export interface GuardedOptions<T extends (...args: unknown[]) => Promise<unknown>> {
  /** Custom extractor for the `CheckOptions` payload from the wrapped function's args. */
  getCheckOptions?: (...args: Parameters<T>) => CheckOptions;
  /** Block until a human approves/denies when the decision is REQUIRE_APPROVAL. Default false. */
  waitForApproval?: boolean;
  /** Total time to wait for a resolution, in ms. Default 300_000. */
  approvalTimeoutMs?: number;
  /** Poll interval while waiting, in ms. Default 2_000. */
  approvalPollIntervalMs?: number;
}

/**
 * Higher-order function that wraps an async function with an AgentGuard check.
 *
 * Two overloads: callers can pass a fourth positional `getCheckOptions`
 * callback, or a typed options object that adds `waitForApproval`,
 * `approvalTimeoutMs`, `approvalPollIntervalMs`.
 *
 * @example
 * ```ts
 * const guard = new AgentGuard('http://localhost:8080');
 * const safeExec = guarded(guard, 'shell', (cmd: string) => exec(cmd));
 *
 * await safeExec('ls -la');        // Allowed → runs
 * await safeExec('rm -rf /');      // DENY → throws AgentGuardDeniedError
 *
 * // Opt-in: block until a human approves.
 * const reviewed = guarded(guard, 'shell', (cmd: string) => exec(cmd), {
 *   waitForApproval: true,
 *   approvalTimeoutMs: 60_000,
 * });
 * ```
 */
export function guarded<T extends (...args: unknown[]) => Promise<unknown>>(
  guard: AgentGuard,
  scope: string,
  fn: T,
  getCheckOptions?: (...args: Parameters<T>) => CheckOptions
): T;
export function guarded<T extends (...args: unknown[]) => Promise<unknown>>(
  guard: AgentGuard,
  scope: string,
  fn: T,
  options: GuardedOptions<T>
): T;
export function guarded<T extends (...args: unknown[]) => Promise<unknown>>(
  guard: AgentGuard,
  scope: string,
  fn: T,
  optionsOrGetCheckOptions?:
    | ((...args: Parameters<T>) => CheckOptions)
    | GuardedOptions<T>
): T {
  // Normalize the overload — a bare callback is the simple shape.
  const opts: GuardedOptions<T> =
    typeof optionsOrGetCheckOptions === "function"
      ? { getCheckOptions: optionsOrGetCheckOptions }
      : optionsOrGetCheckOptions ?? {};

  // Reject unknown option keys at decoration time. A typo such as
  // `waitForApprovel: true` would otherwise be silently ignored and
  // the wrapper would throw on REQUIRE_APPROVAL instead of waiting.
  const unknownGuardedKeys = Object.keys(opts).filter(
    (k) => !VALID_GUARDED_OPTION_KEYS.has(k)
  );
  if (unknownGuardedKeys.length > 0) {
    throw new TypeError(
      `guarded(): unknown option ${JSON.stringify(unknownGuardedKeys)}. ` +
        `Valid options: ${JSON.stringify(
          Array.from(VALID_GUARDED_OPTION_KEYS).sort()
        )}.`
    );
  }

  const waitForApproval = opts.waitForApproval ?? false;
  const approvalTimeoutMs = opts.approvalTimeoutMs ?? 300_000;
  const approvalPollIntervalMs = opts.approvalPollIntervalMs ?? 2_000;
  const getCheckOptions = opts.getCheckOptions;

  return (async (...args: Parameters<T>) => {
    const options = getCheckOptions
      ? getCheckOptions(...args)
      : { command: String(args[0] ?? "") };

    const result = await guard.check(scope, options);

    if (result.allowed) {
      return fn(...args);
    }

    if (result.needsApproval) {
      if (waitForApproval) {
        const resolved = await guard.waitForApproval(
          result.approvalId ?? "",
          approvalTimeoutMs,
          approvalPollIntervalMs
        );
        if (resolved.allowed) {
          return fn(...args);
        }
        if (resolved.denied && resolved.reason === "Approval timed out") {
          throw new AgentGuardApprovalTimeoutError(
            `Approval for ${result.approvalId ?? ""} timed out after ${approvalTimeoutMs}ms`,
            resolved,
            result.approvalId ?? ""
          );
        }
        throw new AgentGuardDeniedError(
          `Action denied by AgentGuard: ${resolved.reason}`,
          resolved
        );
      }
      // Stable message text — text-matchers in caller code depend on it.
      throw new AgentGuardApprovalRequiredError(
        `Action requires approval. Approve at: ${result.approvalUrl}`,
        result,
        result.approvalId ?? "",
        result.approvalUrl ?? ""
      );
    }

    throw new AgentGuardDeniedError(
      `Action denied by AgentGuard: ${result.reason}`,
      result
    );
  }) as T;
}

export default AgentGuard;
