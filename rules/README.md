# rules/

Home of the declarative rule files arriving in v0.2:

- severity and context heuristics per service (today hardcoded in
  `crates/orbis-scanner/src/nmap.rs` `classify`)
- risk weights and thresholds (today in `crates/orbis-risk/src/lib.rs`)
- correlation rules: which finding combinations become attack paths
- remediation playbooks per rule

Until then, the weights live in code and are documented in `docs/risk.md`.
