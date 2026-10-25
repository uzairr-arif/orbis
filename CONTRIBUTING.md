# Contributing to Orbis

Thanks for helping build Orbis. This document gets you productive fast.

## Dev setup

```bash
# Rust stable is the only requirement
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone <repository url>
cd orbis
cargo test            # everything must pass
cargo run -- scan --demo   # try the product offline, no scanners needed
```

The `--demo` flag runs collectors against bundled fixtures in
`crates/orbis-scanner/fixtures/`, so the whole product works on any machine.

## Architecture

```text
crates/
  orbis-core/       The Finding model: severity, fingerprinting, dedup.
                    Every collector normalizes into this. Docs: docs/finding-model.md
  orbis-scanner/    Collector adapters (nmap, lynis, trivy, gitleaks).
                    Missing tools are skipped, never fatal.
  orbis-risk/       Context-aware risk engine. Docs: docs/risk.md
  orbis-cli/        The orbis binary and local state (~/.orbis/state.json)
```

Data flows one way: collectors produce `Finding`s, the risk engine scores
them, the CLI renders them. Read `docs/finding-model.md` first; it is the
contract everything else depends on.

## Adding a collector

1. Create `crates/orbis-scanner/src/<tool>.rs` implementing `Collector`
   (`name`, `is_available`, `scan`).
2. Put the parsing in a pure function over captured output
   (`parse_xml`, `parse_json`, `parse_report`). Never parse inside the
   process runner; tests depend on this separation.
3. Add a realistic fixture to `crates/orbis-scanner/fixtures/` and a unit
   test asserting the parsed findings (counts, severities, key fields).
4. Register the collector in `registry()` in `crates/orbis-scanner/src/lib.rs`.
5. Follow the collector rules in `docs/finding-model.md`: no invented
   evidence, secrets always redacted, raw severity passed through as
   reported.

## Ground rules

- `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`, and
  `cargo test --workspace` must all pass. CI enforces this on three OSes.
- Parsers are pure functions with fixture-backed tests. A collector that
  only works when the real tool is installed is not done.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
  `feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `chore: ...`.
- Findings and evidence come from tools, never from imagination. If the
  tool did not say it, the finding does not contain it.
- No telemetry, no cloud calls, no secrets in logs. Orbis is local-first;
  keep it that way.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Do not open public issues for
vulnerabilities.
