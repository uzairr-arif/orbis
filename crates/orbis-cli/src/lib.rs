//! orbis-cli library surface: everything the binary does except argument
//! parsing, so the full pipeline is testable without touching ~/.orbis.

pub mod explain;
pub mod report;
pub mod store;

use orbis_core::{dedupe, Finding};
use orbis_risk::security_score;
use orbis_scanner::{run as run_collectors, CollectorReport, ScanOptions};

/// The result of one scan, before anything is written to disk.
pub struct ScanOutcome {
    pub target: String,
    pub reports: Vec<CollectorReport>,
    pub findings: Vec<Finding>,
    pub score: u8,
}

/// Run all collectors, normalize, dedupe, and score. Pure with respect to
/// persistent state: the caller decides whether to persist.
pub fn scan(target: &str, demo: bool) -> ScanOutcome {
    // The demo fixtures tell one machine's story; name it accordingly.
    let target = if demo && target == "localhost" {
        "server-01"
    } else {
        target
    };
    let opts = ScanOptions {
        target: target.to_string(),
        demo,
    };
    let (reports, raw) = run_collectors(&opts);
    let findings = dedupe(raw);
    let score = security_score(&findings);
    ScanOutcome {
        target: target.to_string(),
        reports,
        findings,
        score,
    }
}
