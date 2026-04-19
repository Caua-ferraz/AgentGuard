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
}

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
 * Backward-compatibility note
 * ---------------------------
 * Prior to v0.5.0 the {@link guarded} HOF threw plain `Error` instances with
 * human-readable messages. v0.5.0 introduces these typed subclasses so
 * callers can `catch (e) { if (e instanceof AgentGuardDeniedError) ... }`
 * and read structured fields (`result`, `approvalId`, `approvalUrl`). The
 * message text is preserved exactly — existing string/regex matchers keep
 * working — and every subclass extends the standard `Error`, so generic
 * `catch { ... }` handlers are unaffected.
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

export class AgentGuard {
  private baseUrl: string;
  private agentId: string;
  private apiKey: string;
  private timeout: number;
  private failMode: "deny" | "allow";

  constructor(baseUrlOrOptions?: string | AgentGuardOptions) {
    // Environment fallbacks mirror the Python SDK: AGENTGUARD_URL supplies
    // baseUrl when the caller did not pass one; AGENTGUARD_API_KEY supplies
    // apiKey. Explicit values in the options object override the env var
    // so callers that genuinely want to disable auth can pass apiKey: "".
    const envBaseUrl = readEnv("AGENTGUARD_URL");
    const envApiKey = readEnv("AGENTGUARD_API_KEY") ?? "";

    if (typeof baseUrlOrOptions === "string") {
      this.baseUrl = baseUrlOrOptions.replace(/\/$/, "");
      this.agentId = "";
      this.apiKey = envApiKey;
      this.timeout = 5000;
      this.failMode = "deny";
    } else {
      const opts = baseUrlOrOptions ?? {};
      this.baseUrl = (opts.baseUrl ?? envBaseUrl ?? "http://localhost:8080").replace(
        /\/$/,
        ""
      );
      this.agentId = opts.agentId ?? "";
      this.apiKey = opts.apiKey ?? envApiKey;
      this.timeout = opts.timeout ?? 5000;
      this.failMode = opts.failMode ?? "deny";
    }
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

      const response = await fetch(`${this.baseUrl}/v1/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`AgentGuard returned ${response.status}`);
      }

      const data = (await response.json()) as CheckResponseJSON;
      return new CheckResultImpl({
        decision: data.decision,
        reason: data.reason,
        matchedRule: data.matched_rule,
        approvalId: data.approval_id,
        approvalUrl: data.approval_url,
      });
    } catch (err) {
      // Fail closed (deny) by default when AgentGuard is unreachable
      const fallbackDecision = this.failMode === "allow" ? "ALLOW" : "DENY";
      return new CheckResultImpl({
        decision: fallbackDecision,
        reason: `AgentGuard unreachable: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  /**
   * Approve a pending action.
   */
  async approve(approvalId: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/v1/approve/${approvalId}`, {
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
      const res = await fetch(`${this.baseUrl}/v1/deny/${approvalId}`, {
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
          `${this.baseUrl}/v1/status/${approvalId}`,
          { headers: this.authHeaders() }
        );
        if (res.ok) {
          const data = (await res.json()) as StatusResponseJSON;
          if (data.status === "resolved" && (data.decision === "ALLOW" || data.decision === "DENY")) {
            return new CheckResultImpl({
              decision: data.decision,
              reason: data.reason ?? "resolved",
            });
          }
        }
      } catch {
        // Continue polling
      }

      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
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
 * `wait_for_approval=True`. Defaults preserve v0.4.x behavior exactly.
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
 * Overloads preserve v0.4.x ergonomics — callers can still pass a fourth
 * positional `getCheckOptions` callback — while adding a typed options
 * object for v0.5.0 callers that want `waitForApproval`.
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
  // Normalize the overload — treat a bare callback as the v0.4.x shape.
  const opts: GuardedOptions<T> =
    typeof optionsOrGetCheckOptions === "function"
      ? { getCheckOptions: optionsOrGetCheckOptions }
      : optionsOrGetCheckOptions ?? {};

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
      // Default v0.4.x behavior — message text preserved.
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
