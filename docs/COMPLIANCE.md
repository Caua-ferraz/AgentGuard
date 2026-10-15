# Compliance evidence report

`agentguard report` (v1.4) turns the audit log into a report you can hand
to an auditor: what AgentGuard decided over a period, whether the log that
recorded it was changed, and which SOC 2 criteria that evidence bears on.

**The report is supporting evidence. It is not a SOC 2 report, a
certification or an audit opinion.** It shows what the audit log
recorded. An auditor decides what that proves and whether it is enough.

## Generate it

From the audit log files (the default). This also verifies the seal chain,
as `agentguard audit verify` does. Without `--key-file`, a log sealed with
a key still gets every check but its hashes (every entry after the seal is
sealed, `seq` has no gaps, each `prev_hash` links up), and the report says
the hashes were not checked:

```bash
agentguard report --since 2026-09-01 --until 2026-10-01 \
  --audit-log /var/lib/agentguard/audit.jsonl \
  --key-file /var/lib/agentguard/audit-seal.key \
  --policy /etc/agentguard/default.yaml \
  --output html --out-file september.html
```

From a running server, when you can't read its files:

```bash
agentguard report --url https://guard.internal --api-key "$KEY" \
  --since 7d --output json > week.json
```

Without `--since` and `--until` the report covers the 24 hours before now.
`--since` is inclusive and `--until` exclusive, so back-to-back reports
(`--since 2026-09-01 --until 2026-10-01`, then `--since 2026-10-01 …`)
never count an entry twice or miss one. Times are RFC 3339, a date
(midnight UTC), or a duration back in time: `90m`, `24h`, `7d` (`d` is 24
hours; Go durations have no day unit, so the report adds it). All flags:
[CLI.md § agentguard report](CLI.md#agentguard-report).

Formats: `md` (Markdown, the default), `json` (the stable shape below) and
`html` (one page with inline CSS and no scripts, so it can be mailed or
archived as is). Every value taken from the log is escaped in Markdown and
HTML, so an agent id can't add markup to the report, and a URL or an
address in it does not become a link. In both, control characters (but
tab and newline) and the bidi controls that reorder text are replaced
with U+FFFD, so a value can't move a terminal's cursor or read as
something else. JSON keeps every value exactly as logged; its encoder
escapes the C0 controls.

Exit status: `0` written; `1` written, but the audit log failed
verification; `2` command-line mistake; `3` the log, a key file, the
policy file or the server can't be read.

### Files or server

| | Files (`--audit-log`) | Server (`--url`) |
|---|---|---|
| Entries read | The live file and every rotated archive linked to it (gzip or plain) | `GET /v1/audit`, oldest first, paged. A server with the file backend answers from its live file only, not its archives |
| Tenants | All of them | One: `local`, or `--tenant-id` |
| Seal chain | Verified (`--key-file` for a log sealed with a key) | Not verified. The head comes from `GET /v1/audit/head` |
| Unreadable lines | Counted | Unknown (the server skips them) |
| API key check | Unknown | Checked: the report asks for one entry without the key, without following redirects. 401 or 403 means required; a JSON list of entries means open; anything else is unknown |
| Policy file | `--policy`, else the file `agentguard server` would load | `--policy` only |

The server is asked for the period with `since` and `until`, which
`GET /v1/audit` takes from 1.4 (they came with the sessions work). A server
that predates them ignores them; the report drops entries outside the
period itself, so the numbers are the same, and `source.outside_period`
says how many were dropped. A server older than 1.4 also has no
`GET /v1/audit/head`, so the seal status is then "unknown".

The report pages by time, not by offset: each page starts a moment before
the last entry of the one before, and an entry seen twice is counted once.
An offset into the server's live file stops meaning anything when the file
rotates. Rotation still loses the entries left in the old file, which the
server no longer serves; on a sealed server the report notices (the seal
head names a new file afterwards) and adds a warning to the report. The
report stops with exit 3 if a server sends the same page over and over, or
after 50,000 pages, 10 million entries or 30 minutes: report on that much
from the files.

`--url` must not hold a user name or password (`http://user:pass@host`):
it would be written into the report. Give the key with `--api-key`.

## What the report holds

- **Summary.** The period, when the report was made, the AgentGuard
  version, where the entries came from, and the policy file with its
  SHA-256.
- **Audit log integrity.** `intact`, `broken`, `not_sealed`,
  `not_verified` (the log says it is sealed, but the hashes were not
  checked: server mode, or no `--key-file`) or `unknown`. With the seal type (HMAC key or plain
  SHA-256), the latest seal anchor (seq and hash), the files read, and
  audit verify's warnings.
- **Activity.** Entries by decision (ALLOW, DENY and REQUIRE_APPROVAL are
  always listed), scope, transport, tenant and agent. Entries written
  without a transport count as `sdk`, and without a tenant as `local`, as
  everywhere else.
- **Top rules.** The rules behind DENY and REQUIRE_APPROVAL decisions, by
  count. A DENY that no rule matched shows as `(default deny)`.
- **Approvals.** Approval ids sent for approval in the period, approved by
  a person, denied by a person, and with no outcome on record (see Limits).
  "Timed out" is always unknown.
- **Agents and sessions.** How many were seen, and their ids (the first
  100 by name).
- **Posture checks.** Each is `pass`, `warn`, `fail` or `unknown`:

  | Check | How it is decided |
  |---|---|
  | Audit log sealed | Passes only when the chain verified. Fails when it is broken. A seal the report could not verify is a claim: a `_meta` header anyone who can write the file can forge (warn, files read without `--key-file`), or the server's word (unknown) |
  | Seal uses a secret key | HMAC-SHA256 passes only when it verified with `--key-file`; read from an unverified header it is unknown. Plain SHA-256 warns (anyone who can write the file can recompute it) |
  | Seal chain verified | audit verify's result; unknown in server mode |
  | Entries outside the seal chain | Files: entries written before sealing began, or fail when the chain breaks (nothing after the break is protected). Server: entries in the period that came without `seq` or `hash` |
  | Unreadable lines | Lines of the files that are not entries, or files that end early |
  | Secrets masked in the log | Fails when a request or reason still matches the built-in secret patterns of `--audit-redact`. Otherwise unknown: masked values (`[REDACTED]`) with no unmasked secret are consistent with masking being on, but not proof, since an agent's own text can contain the marker; with neither, the log can't show it |
  | Audit API requires an API key | Server mode: whether `GET /v1/audit` answers without the key |

- **Control mapping.** See below.
- **Limits.** What the report can't show, in the report itself.

## Control mapping

The report maps its evidence to five SOC 2 Trust Services Criteria. Each
row says what the report shows and in which sections. It never says a
criterion is met.

| Criterion | What the report shows | Sections |
|---|---|---|
| CC6.1 Logical access to protected assets is restricted | Agent actions were checked against a named policy (SHA-256); how many were allowed and denied, by scope and agent | Summary, Activity, Top rules, Posture checks |
| CC6.6 Access from outside the system boundary is controlled | Network, browser, MCP tool and LLM tool-call actions went through AgentGuard; what was let through and blocked, by scope and transport | Activity, Top rules |
| CC7.2 System components are monitored for anomalies | Every decision is in the audit log; whether the log is sealed and intact; unreadable lines; unmasked secrets | Audit log integrity, Activity, Posture checks |
| CC7.3 Security events are evaluated | Actions sent to a person for approval and the decisions on record; the rules that stopped risky actions | Approvals, Top rules |
| CC8.1 Changes are authorized | The policy file's SHA-256, to match against an approved change; actions the policy sends for approval (deploys, writes) needed a person's yes | Summary, Approvals |

## Limits

- The report counts what the audit log recorded. An action that never
  reached AgentGuard (an agent not wired to it, a tool outside the
  gateway) is not in it.
- The audit log has an entry when an action is sent for approval, and
  another only when the agent comes back with the approval id after a
  person decided. It does not record the decision itself, who made it, or
  a request that timed out. "No outcome on record" covers requests that
  timed out, were decided but not retried, were decided after the period,
  or are still pending.
- The policy SHA-256 is of the file when the report is made. The log does
  not record which version of the policy made each decision; keep the
  policy in version control and match the hash to a commit.
- The secret check uses the built-in patterns only, not a policy's
  `notifications.redaction.extra_patterns`.
- Reading files: archives that no file links to, and archives already
  pruned (`--audit-max-backups`, `--audit-max-age-days`), are not read.
  Entries a running server still holds in its buffer or overflow file are
  not in the log yet. Keep archives for as long as your audit period
  needs.
- Server mode: the chain is not verified, rotated archives of a file
  backend are not included, and only one tenant is covered.
- A passing verify shows the log was not changed by anyone without the
  key; it does not rule out the newest entries being cut off. Check
  published anchors with `agentguard audit verify --anchor` for that
  ([OPERATIONS § Sealing and anchoring](OPERATIONS.md#sealing-and-anchoring)).

## JSON shape

`--output json` prints one object. Its shape is stable for 1.x: fields are
only added, never renamed or removed. `format_version` (now `1`) changes
only if that ever stops being true. Times are RFC 3339 UTC.

| Field | Meaning |
|---|---|
| `format_version` | `1` |
| `generated_at` | When the report was made |
| `agentguard_version` | e.g. `"1.4.0 (abc1234)"` |
| `period.since`, `period.until` | The period; `since` inclusive, `until` exclusive |
| `source.mode` | `"file"` or `"server"` |
| `source.audit_log`, `source.files`, `source.bad_lines`, `source.read_errors` | Files mode: the live file, the files read (oldest first), lines that are not entries, files that end early |
| `source.server`, `source.tenant`, `source.fetched`, `source.outside_period`, `source.auth_required` | Server mode: the URL, the tenant, different entries fetched, entries dropped as outside the period, whether the audit API needs the key (absent when unknown) |
| `source.warnings` | Why the entries may be incomplete, e.g. the server's live file rotated while the report read it |
| `policy` | `{path, sha256, found}` or `null`. `found` is `--policy`, `AGENTGUARD_POLICY`, `the default` or `found automatically` |
| `integrity.method` | `"verify"` or `"seal_head"` |
| `integrity.status` | `intact`, `broken`, `not_sealed`, `not_verified` or `unknown` |
| `integrity.summary` | One sentence |
| `integrity.seals`, `integrity.key_based` | How the entries are sealed, as the log's `_meta` headers say; `key_based` is `null` when unknown. Confirmed only when `status` is `intact` |
| `integrity.head` | `{seq, hash, segment_id?, at?}`: the latest seal anchor |
| `integrity.verify` | audit verify's full report, as `audit verify --output json` prints it (files mode) |
| `activity.entries`, `activity.first_entry`, `activity.last_entry` | Entries in the period and their time span |
| `activity.decisions` | `[{name, count}]`, ALLOW, DENY, REQUIRE_APPROVAL first |
| `activity.scopes`, `.transports`, `.tenants`, `.agents`, `.deny_rules`, `.approval_rules` | `{distinct, top: [{name, count}]}`: how many values, and the most frequent (all scopes and transports, the top 10 of the others) |
| `activity.agents_seen`, `activity.sessions_seen` | `{count, names, truncated}`: the first 100 ids by name |
| `activity.redacted_entries`, `activity.unmasked_secret_entries` | Entries with masked secrets, and with text that looks like an unmasked one |
| `activity.unsealed_entries` | Entries in the period without `seq` or `hash` |
| `approvals` | `{requested, approved, denied, no_outcome, timed_out}`; `timed_out` is always `null` |
| `posture` | `[{name, status, detail}]` |
| `controls` | `[{criterion, title, shows, where}]` |
| `limits` | `[string]` |

The renderers and the numbers live in `pkg/report`, with golden files in
`pkg/report/testdata/` for each format.
