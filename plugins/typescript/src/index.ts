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

export class AgentGuard {
  private baseUrl: string;
  private agentId: string;
  private apiKey: string;
  private timeout: number;
  private failMode: "deny" | "allow";

  constructor(baseUrlOrOptions?: string | AgentGuardOptions) {
    if (typeof baseUrlOrOptions === "string") {
      this.baseUrl = baseUrlOrOptions.replace(/\/$/, "");
      this.agentId = "";
      this.apiKey = "";
      this.timeout = 5000;
      this.failMode = "deny";
    } else {
      const opts = baseUrlOrOptions ?? {};
      this.baseUrl = (opts.baseUrl ?? "http://localhost:8080").replace(
        /\/$/,
        ""
      );
      this.agentId = opts.agentId ?? "";
      this.apiKey = opts.apiKey ?? "";
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

      const data = await response.json();
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
          `${this.baseUrl}/v1/status/${approvalId}`
        );
        if (res.ok) {
          const data = await res.json();
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
 * Higher-order function that wraps an async function with an AgentGuard check.
 *
 * @example
 * ```ts
 * const guard = new AgentGuard('http://localhost:8080');
 * const safeExec = guarded(guard, 'shell', (cmd: string) => exec(cmd));
 *
 * await safeExec('ls -la');        // ✅ Allowed
 * await safeExec('rm -rf /');      // ❌ Throws PermissionError
 * ```
 */
export function guarded<T extends (...args: unknown[]) => Promise<unknown>>(
  guard: AgentGuard,
  scope: string,
  fn: T,
  getCheckOptions?: (...args: Parameters<T>) => CheckOptions
): T {
  return (async (...args: Parameters<T>) => {
    const options = getCheckOptions
      ? getCheckOptions(...args)
      : { command: String(args[0] ?? "") };

    const result = await guard.check(scope, options);

    if (result.allowed) {
      return fn(...args);
    } else if (result.needsApproval) {
      throw new Error(
        `Action requires approval. Approve at: ${result.approvalUrl}`
      );
    } else {
      throw new Error(`Action denied by AgentGuard: ${result.reason}`);
    }
  }) as T;
}

export default AgentGuard;
