# Security policy

Orbis runs on the machines it protects and parses output from external
tools, so the project holds itself to a high security bar.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Report a vulnerability in the Security tab). Do not open a public issue.

Include what you found, reproduction steps, and affected versions or
commits. We aim to respond within 72 hours.

## Scope

- The Orbis codebase and its collector parsers (they process output
  produced by third-party tools on machines you may not control)
- The local state file and anything that could leak secrets from it

## Design commitments

- Findings, secrets, and evidence never leave the machine unless the user
  explicitly configures it. There is no telemetry.
- Secrets discovered by collectors are redacted in every output path
  before display or storage.
- Evidence from scanner output is treated as untrusted data, never as
  instructions.
- Automated remediation (when it lands) is preview-first, approval-gated,
  and rollback-capable.

## Supported versions

Pre-1.0, only the latest release line receives security fixes.
