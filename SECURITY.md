# Security Policy

AgentGuard is a defensive-security tool, so we take vulnerabilities in the
proxy, SDKs, and adapters seriously. This document explains which versions
receive security fixes and how to report a vulnerability privately.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | Yes                |
| < 0.5   | No                 |

Older versions do not receive backports. If you are running a release line
that is no longer supported, please upgrade to the latest 0.5.x release.

## Reporting a Vulnerability

Please report suspected vulnerabilities by email to **cauaferraz@lictorate.com**.

Do **not** open a public GitHub issue, pull request, or discussion thread for
security reports. Public reports give attackers a head start before a fix is
available.

When reporting, include as much of the following as you can:

- A description of the issue and its impact.
- Reproduction steps, including a minimal policy / request / configuration.
- The AgentGuard version (`agentguard version`) and SDK version, if relevant.
- Any proof-of-concept code or logs.
- Whether you have already disclosed the issue elsewhere.

## Response SLA

- **Initial acknowledgement:** within **48 hours** of receipt.
- **Triage and severity assessment:** within **7 days**.
- **Coordinated disclosure window:** up to **90 days** from the initial
  report, unless the issue requires a longer fix window and you agree in
  writing to extend it.

We will keep you informed throughout the process and credit you in the
release notes (or the `SECURITY.md` advisories section) unless you request
otherwise.

## Out of Scope

The following are generally not treated as vulnerabilities in AgentGuard:

- Running AgentGuard without `--api-key` and exposing the dashboard
  publicly. Without an API key the server intentionally binds to
  `127.0.0.1` only; remote exposure requires an explicit reverse-proxy
  setup, which is the operator's responsibility.
- Self-XSS, social-engineering, and other attacks that require a victim
  to paste attacker-controlled text into their own browser console.
- Volumetric / denial-of-service issues that require a network-level
  rate limiter, in deployments without one configured.
