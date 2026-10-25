# The Orbis Finding Model

Every collector, no matter what tool it wraps, normalizes its output into one
`Finding` struct (see `crates/orbis-core/src/lib.rs`). Everything downstream
(dedup, risk, explain, report, the future correlation engine) speaks only
this language.

## Field contract

| Field | Type | Contract |
|---|---|---|
| `id` | string | `ORB-XXXX`, derived from the fingerprint. Stable across scans. Human-quotable. |
| `fingerprint` | u64 | Hash of (source, asset, kind, component, normalized title). The real dedup key. |
| `source` | string | Collector that produced the finding: `nmap`, `lynis`, `trivy`, `gitleaks`, ... |
| `asset` | string | Host, image, or repository the finding belongs to. |
| `kind` | enum | `open_port`, `vulnerability`, `misconfiguration`, `secret`, `other`. |
| `severity` | enum | Raw severity as the source tool reported it. Context does not modify this; the risk engine does that. |
| `confidence` | 0.0-1.0 | How sure the source tool is. Multiplies into risk. |
| `title` | string | One line, written for a human. Drives fingerprints, so wording changes create new findings. |
| `description` | string | A few sentences of plain-language context. |
| `evidence` | list | Verified proof lines with the tool that produced each. Explain output is built only from this. |
| `cve` | list | CVE identifiers, when known. |
| `component` | string | Affected software or service (`openssl`, `sshd`, a file path for secrets). |
| `affected_version` / `fixed_version` | optional | When the source tool knows versions. |
| `exposure` | enum | `internet`, `local_network`, `localhost`, `unknown`. Who can reach it. |
| `exploitability` | enum | `high`, `medium`, `low`, `unknown`. How practical exploitation is. |
| `criticality` | enum | `production`, `staging`, `development`, `unknown`. How much the asset matters. |
| `first_seen` / `last_seen` | unix seconds | Preserved across scans by fingerprint. |
| `status` | enum | `open` or `resolved`. |
| `recommended_fix` | string | One concrete action, always populated in v0.1. |

## Rules collectors must follow

1. Never invent evidence. If the tool did not say it, the finding does not
   contain it.
2. Never render full secrets. Redact to a recognizable prefix.
3. Report raw severity as the tool gave it; heuristics only fill context
   fields (exposure, exploitability) with defensible defaults.
4. Parsing is a pure function over captured output, so fixtures are tests.
