<p align="center">
  <img src="site/assets/logo.svg" width="110" alt="Orbis logo: an orbit ring around a core">
</p>

<h1 align="center">Orbis</h1>

<p align="center">
  <strong>Security noise in. Actions out.</strong><br>
  Open-source security visibility and remediation. Local-first. No cloud required.
</p>

<p align="center">
  <a href="#license" alt="License"><img src="https://img.shields.io/badge/license-Apache--2.0-269B79"></a>
  <a href="https://www.rust-lang.org/" alt="Rust"><img src="https://img.shields.io/badge/built%20with-Rust-444?logo=rust&logoColor=white"></a>
  <a href="#quickstart" alt="Platforms"><img src="https://img.shields.io/badge/platform-linux%20%C2%B7%20windows%20%C2%B7%20macos-444"></a>
  <a href="CONTRIBUTING.md" alt="Contributing"><img src="https://img.shields.io/badge/PRs-welcome-269B79"></a>
</p>

---

You already run the best scanners: nmap, lynis, trivy, gitleaks. The problem
was never detection, it is the pile of disconnected output nobody has time to
triage. Orbis orchestrates those tools, normalizes everything into one model,
correlates fragments into attack paths, and explains each risk in context,
with the fix attached.

It is not another scanner, and it is not a cloud dashboard. It is the layer
between your tools and your next action.

## What it looks like

Real output from `orbis scan --demo` (bundled fixtures, runs offline with no
scanners installed):

```text
$ orbis scan --demo

  -  nmap        4 findings
  -  lynis       8 findings
  -  trivy       9 findings
  -  gitleaks    2 findings

ORBIS SECURITY OVERVIEW

Score  65 / 100

  1 critical  1 high  6 medium  15 low

Biggest risks
  1  ORB-1A21  [critical]  AWS Access Key ID
  2  ORB-49AC  [high]  Port 22/tcp open (ssh)
  3  ORB-F2BD  [medium]  Generic API Key

Recommended first action
-> Rotate the credential immediately, then remove it from history in deploy/.env.
```

Every finding answers "why does this matter?" on demand, evidence included,
secrets always redacted:

```text
$ orbis explain ORB-1A21

ORB-1A21  AWS Access Key ID

WHY THIS MATTERS
A credential was found in deploy/.env on server-01. Treat committed secrets
as compromised: anyone with repository access or a copy of the history may
hold it, and automated crawlers scan public repositories continuously.

RISK
Orbis risk: critical (score 0.66)
severity critical | exposure internet | exploitability high | confidence 0.95

EVIDENCE
  -  deploy/.env:4 aws-access-token [AKIAQVZE********] 9f31c0a (gitleaks)

RECOMMENDED FIX
-> Rotate the credential immediately, then remove it from history in deploy/.env.
```

## What Orbis does

|   | Capability | Status |
| :- | :--- | :--- |
| <img src="docs/images/icon-orchestrate.svg" width="22" alt=""> | **Orchestrates, never replaces.** Runs the scanners you already trust; missing tools are skipped, never fatal. | ✅ v0.1 |
| <img src="docs/images/icon-normalize.svg" width="22" alt=""> | **One finding model.** Every tool normalizes into a single schema with stable IDs that survive rescans. | ✅ v0.1 |
| <img src="docs/images/icon-risk.svg" width="22" alt=""> | **Risk in context.** Severity x exposure x exploitability x criticality x confidence, not raw severity noise. | ✅ v0.1 |
| <img src="docs/images/icon-terminal.svg" width="22" alt=""> | **Explains itself.** Every risk carries its evidence, its reasoning, and a recommended fix. | ✅ v0.1 |
| <img src="docs/images/icon-local.svg" width="22" alt=""> | **Local-first.** Plain JSON state on your machine. Secrets redacted in output. No cloud, no telemetry. | ✅ v0.1 |
| <img src="docs/images/icon-correlate.svg" width="22" alt=""> | **Attack paths.** Fragments from different scanners joined into one story with one merged risk score. | 🚧 v0.2 |
| <img src="docs/images/icon-remediate.svg" width="22" alt=""> | **Safe remediation.** Preview, approve, rollback. Orbis never changes a system without consent. | 🗓️ v0.3 |

## How it works

```text
nmap XML ─┐                       ┌─> dedupe      same finding keeps its ID across scans
lynis log ─┼─> orbis-collect ─┬─> ├─> risk        context score, security grade 0-100
trivy JSON ┤    (Finding)     │  └─> correlate    fragments -> attack paths   (v0.2)
gitleaks  ─┘                  └─> explain/report  why + evidence + fix, in your terminal
```

- The finding model is the contract: [docs/finding-model.md](docs/finding-model.md)
- How risk is scored and why: [docs/risk.md](docs/risk.md)
- Visual identity and UI language: [BRAND.md](BRAND.md)

## Quickstart

Prerequisites: a Rust toolchain ([rustup](https://rustup.rs/)); the scanners
themselves are optional and detected automatically.

```bash
cargo install --path crates/orbis-cli

orbis scan --demo                 # try everything offline, no scanners needed
orbis scan --target localhost     # a real scan; runs whichever tools you have
orbis findings --severity critical
orbis explain ORB-1A21
orbis report --json               # machine-readable, pipe it anywhere
```

Or straight from a checkout:

```bash
cargo build --release             # binary at target/release/orbis
cargo test                        # unit tests + end-to-end demo pipeline
```

## Design choices

- **Rust, one static binary.** Installs with `cargo install`, runs over SSH on
  hardened servers, no runtime to ship. The same core will power the desktop
  app (Tauri) later.
- **Memory safety is a security feature.** Collectors parse XML and JSON
  produced by external tools on machines you do not control.
- **Pure-Rust dependencies only** (serde, clap, roxmltree, colored). Builds on
  any machine with just a Rust toolchain, no C compiler required.
- **Small, honest releases.** Every version does its scope completely: v0.1
  scans and explains; nothing ships half-done.

## Roadmap

| Milestone | Scope |
| :--- | :--- |
| v0.1 ✅ | Scan, normalize, dedupe, contextual risk, explain, report |
| v0.2 🚧 | Correlation engine: attack paths, declarative rules, SQLite state |
| v0.3 | Remediation: preview, approve, rollback with automatic backups |
| v0.4 | Repository scanning and CI mode |
| v0.5 | Desktop app (Tauri) |
| v1.0 | Plugin API and long-term support |

## Contributing

Issues and pull requests are welcome, from typo fixes to new collectors. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup; the gates are the same
as CI: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` on
Linux, Windows, and macOS. Good first contributions: a collector for a tool
you use, fixture files, and docs improvements.

See also [SECURITY.md](SECURITY.md) for responsible disclosure, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for the community standard.

## Acknowledgments

Orbis stands on nmap, Lynis, Trivy, and Gitleaks, and on serde, clap,
roxmltree, and the Rust ecosystem. We conduct the orchestra; they are the
musicians.

## License

Apache-2.0. See [LICENSE](LICENSE). The license grants code and patents, not
the "Orbis" name (currently a working codename while naming and trademark
clearance is pending).
