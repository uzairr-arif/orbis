//! End-to-end pipeline test: the bundled demo fixtures flow through every
//! collector, normalization, dedup, and the risk engine. No disk access.

use orbis_cli::scan;
use orbis_core::Severity;
use orbis_risk::{assess, top_risks, RiskLevel};

#[test]
fn demo_pipeline_matches_the_spec() {
    let outcome = scan("server-01", true);

    // All four collectors ran clean in demo mode.
    assert_eq!(outcome.reports.len(), 4);
    assert!(outcome
        .reports
        .iter()
        .all(|r| matches!(r.status, orbis_scanner::RunStatus::Ok)));

    // Raw severity counts across collectors: 2 critical, 5 high, 11 medium.
    assert_eq!(
        count(
            outcome.findings.iter().map(|f| f.severity),
            Severity::Critical
        ),
        2
    );
    assert_eq!(
        count(outcome.findings.iter().map(|f| f.severity), Severity::High),
        5
    );
    assert_eq!(
        count(
            outcome.findings.iter().map(|f| f.severity),
            Severity::Medium
        ),
        11
    );

    // Every finding has a stable ID and a non-empty recommended fix.
    assert!(outcome
        .findings
        .iter()
        .all(|f| f.id.starts_with("ORB-") && !f.recommended_fix.is_empty()));

    // Fingerprints are unique after dedup.
    let mut fps: Vec<_> = outcome.findings.iter().map(|f| f.fingerprint).collect();
    fps.sort_unstable();
    fps.dedup();
    assert_eq!(fps.len(), outcome.findings.len());

    // The committed AWS key is the single most dangerous finding.
    let top = top_risks(&outcome.findings, 1);
    assert!(top[0].title.contains("AWS"));
    assert_eq!(assess(top[0]).level, RiskLevel::Critical);

    // Score reflects a machine with real problems, and is in range.
    assert!(outcome.score < 100, "score was {}", outcome.score);
    assert!(outcome.score > 0, "score was {}", outcome.score);
}

fn count<I: Iterator<Item = Severity>>(iter: I, want: Severity) -> usize {
    iter.filter(|s| *s == want).count()
}
