# AgentGuard compliance evidence report

Supporting evidence only. This report is not a SOC 2 report, a certification or an audit opinion; an auditor decides what it shows and whether it is enough.

## Summary

| Item | Value |
| --- | --- |
| Period | 2026-10-01T00:00:00Z (inclusive) to 2026-10-08T00:00:00Z (exclusive) |
| Generated | 2026-10-08T01:00:00Z |
| AgentGuard | 1.4.0 (test) |
| Source | audit log files: /var/lib/agentguard/audit.jsonl (2 files, unreadable lines: 0) |
| Policy | configs/default.yaml (--policy), SHA-256 abababababababababababababababababababababababababababababababab |
| Decisions | 12 (ALLOW 5, DENY 3, REQUIRE\_APPROVAL 4) |
| Audit log | intact |

## Audit log integrity

**Status: intact.** agentguard audit verify checked 14 sealed entries (seq 1 to 14): the chain is intact.

- Checked with: agentguard audit verify, over the log files
- Sealed with: hmac-sha256 key 0123456789abcdef
- Latest seal anchor: seq 14, hash cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
- Files, oldest first: audit.jsonl.20260930T120000Z.gz, audit.jsonl

## Activity

12 entries, the first at 2026-10-01T00:00:00Z and the last at 2026-10-02T01:00:00Z.

### Decisions

| Decision | Count |
| --- | --- |
| ALLOW | 5 |
| DENY | 3 |
| REQUIRE\_APPROVAL | 4 |

### Scopes

| Scope | Count |
| --- | --- |
| shell | 10 |
| network | 2 |

### Transports

| Transport | Count |
| --- | --- |
| claude\_code | 6 |
| sdk | 5 |
| mcp\_gateway | 1 |

### Tenants

| Tenant | Count |
| --- | --- |
| local | 11 |
| acme | 1 |

### Agents

| Agent | Count |
| --- | --- |
| ci-bot | 6 |
| dev-bot | 5 |
| &lt;script&gt;alert(1)&lt;/script&gt; | 1 |

## Top rules

### DENY

| Rule | Count |
| --- | --- |
| (default deny) | 1 |
| deny:approved | 1 |
| deny:shell:rm -rf \* | 1 |

### REQUIRE\_APPROVAL

| Rule | Count |
| --- | --- |
| require\_approval:shell:make deploy | 3 |
| require\_approval:pending | 1 |

## Approvals

| Stage | Approval ids |
| --- | --- |
| Sent for approval | 3 |
| Approved by a person | 1 |
| Denied by a person | 1 |
| Timed out | unknown (not recorded in the audit log) |
| No outcome on record | 1 |

The audit log has an entry when an action is sent for approval, and another when the agent comes back with the approval id after a person decided. "No outcome on record" covers requests that timed out, were decided but not retried, were decided after the period, or are still pending.

## Agents and sessions

- Agents (3): &lt;script&gt;alert(1)&lt;/script&gt;, ci-bot, dev-bot
- Sessions (4): s1, s2\|x, s3, s4

## Posture checks

| Check | Status | Detail |
| --- | --- | --- |
| Audit log sealed | pass | Yes: every entry carries seq, prev\_hash and hash. |
| Seal uses a secret key | pass | HMAC-SHA256: only a holder of the key can write a chain that verifies. |
| Seal chain verified | pass | agentguard audit verify checked 14 sealed entries (seq 1 to 14): the chain is intact. |
| Entries outside the seal chain | pass | None. |
| Unreadable lines | pass | Every line of the log files is an audit entry. |
| Secrets masked in the log | fail | Entries holding text that looks like a secret (an API key, token or password): 1. Is the server running with --audit-redact=false? |
| Audit API requires an API key | unknown | Not checked: the report read the log files, not a server. |

## Control mapping (SOC 2)

> Supporting evidence only. This report is not a SOC 2 report, a certification or an audit opinion; an auditor decides what it shows and whether it is enough.

| Criterion | What this report shows | Where |
| --- | --- | --- |
| CC6.1 Logical access to protected assets is restricted | Agent actions that reached AgentGuard were checked against a policy (the policy file's SHA-256 abababababab…): 12 decisions, 3 denied, broken down by scope and agent. | Summary, Activity, Top rules, Posture checks |
| CC6.6 Access from outside the system boundary is controlled | Actions reaching outside the agent (network, browser, MCP tools, LLM tool calls) went through AgentGuard; the scope and transport breakdowns and the deny rules show what was let through and what was blocked (2 scopes, 3 transports). | Activity, Top rules |
| CC7.2 System components are monitored for anomalies | Every decision is recorded in the audit log; its seal status is "intact", and the posture checks cover unreadable lines and unmasked secrets. | Audit log integrity, Activity, Posture checks |
| CC7.3 Security events are evaluated | Entries sending an action to a person for approval: 4 (3 approval ids). On record as approved by a person: 1; denied by a person: 1. The top deny rules show which risky actions were stopped. | Approvals, Top rules |
| CC8.1 Changes are authorized | The report names the policy file's SHA-256 abababababab…, so a reviewer can match it to an approved change. Actions the policy sends for approval (deploys, writes) needed a person's yes: see Approvals. | Summary, Approvals |

## Limits

- The report counts what the audit log recorded. An action that never reached AgentGuard is not in it.
- Approval outcomes show only when the agent came back with the approval id after a person decided. The log does not record the decision itself, who made it, or a request that timed out.
- The policy SHA-256 is of the file as it was when the report was made. The audit log does not record which version of the policy made each decision.
- The secret check uses the built-in patterns only, not a policy's notifications.redaction.extra\_patterns.
- Archives that no file links to, and archives already pruned by --audit-max-backups or --audit-max-age-days, are not read.
- Entries a running server still holds in its buffer or its overflow file (&lt;audit-log&gt;.overflow.jsonl) are not in the log yet, so they are not counted.
