# Orbis

**Open-source security visibility and remediation, local-first.**

Orbis is not another scanner. It orchestrates the excellent tools you already
run (nmap, lynis, trivy, gitleaks, and more), normalizes their findings into
one model, explains what actually matters in context, and helps you fix it
safely.

```bash
orbis scan
```

```text
ORBIS SECURITY OVERVIEW

Score  44 / 100

  1 critical   3 high   17 medium   7 low

Biggest risks
  1  ORB-8F42  [critical]  AWS Access Key ID
  2  ORB-2C91  [critical]  Port 22/tcp open (ssh)
  3  ORB-A117  [high]  Root login is permitted via SSH

Recommended first action
  -> Rotate the credential immediately, then remove it from history in deploy/.env.
```

Then ask why:

```bash
orbis explain ORB-8F42
```

## Status: v0.1 (scanner)

Scope discipline matters more than feature count. v0.1 does exactly this:

- Run nmap, lynis, trivy, and gitleaks (missing tools are skipped, never fatal)
- Normalize everything into the [Orbis Finding Model](docs/finding-model.md)
- Deduplicate findings across scans with stable IDs
- Score risk with context, not raw severity: [risk model](docs/risk.md)
- Commands: `scan`, `findings`, `show`, `explain`, `report` (terminal + JSON)

Try it offline right now, no scanners installed:

```bash
orbis scan --demo
orbis findings --severity critical
orbis explain ORB-8F42
orbis report --json
```

Roadmap: v0.2 correlation and attack paths, v0.3 preview/approve/rollback
remediation, v0.4 repository scanning and CI, v0.5 desktop.

## Why Rust

- **One static binary.** `curl | sh` installs a single executable. No runtime
  to ship, no dependency hell on hardened servers.
- **It runs where you scan.** The same core compiles to Linux, Windows, and
  macOS, as CLI today and as the v0.5 desktop agent later.
- **Parsing untrusted output.** Collectors consume XML and JSON produced by
  external tools on machines you do not control. Memory safety is a security
  feature, not a nicety, for a product in this position.
- **Low system footprint.** An agent that watches production hosts must be
  quiet: no garbage collector pauses, tens of megabytes, not hundreds.
- **One language across surfaces.** The desktop app (v0.5) is Tauri, whose
  backend is Rust. The core built now is the same core that powers it.

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Core + CLI | Rust, cargo workspace | See above |
| Finding model | serde with tagged enums | One schema, JSON-native, versionable |
| nmap XML parsing | roxmltree | Pure Rust, no C toolchain needed to build |
| CLI framework | clap 4 (derive) | Subcommands that feel like git |
| Terminal color | colored | Matches the [brand palette](BRAND.md) |
| Storage v0.1 | JSON at `~/.orbis/state.json` | Local-first, inspectable, zero deps; SQLite lands in v0.2 |
| Collectors | External tools, orchestrated | Orbis never replaces nmap or trivy; it conducts them |
| Desktop v0.5 | Tauri (Rust + React/TypeScript) | Same core, native speed, small bundles |
| Site | Static HTML/CSS/vanilla JS (`site/`) | Nothing to ship but files |

Dependencies are deliberately all pure Rust: the project builds on any
machine with just a Rust toolchain, no C compiler required.

## Layout

```text
crates/
  orbis-core/       Finding model, severity, fingerprinting, dedup
  orbis-scanner/    Collector trait + nmap, lynis, trivy, gitleaks adapters
  orbis-risk/       Context-aware risk engine and security score
  orbis-cli/        The orbis binary: scan, findings, show, explain, report
docs/               finding-model.md, risk.md
rules/              Declarative rules land here in v0.2
site/               The landing page (open site/index.html)
```

## Building

```bash
cargo build --release
# the binary is target/release/orbis
```

```bash
cargo test          # unit tests + the end-to-end demo pipeline
```

### Build environment on this machine

Rust stable with the `x86_64-pc-windows-gnu` toolchain (no MSVC installed).
Linking `windows-sys` needs GNU binutils, provided by the portable MinGW-w64 at
`C:\mingw64`. In Git Bash, build with:

```bash
export PATH="/c/mingw64/bin:/c/Users/HP/.cargo/bin:$PATH"
cargo test
```

## Notes

- Orbis is a working codename; naming and trademark clearance is pending.
- Demo fixtures use fictional CVEs and documentation IP ranges (RFC 5737).
- No secrets, source, or findings leave the machine. There is no cloud to
  leave to.
