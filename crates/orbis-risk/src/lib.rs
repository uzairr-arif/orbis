//! Risk engine.
//!
//! Raw severity treats every finding as equally urgent. Orbis instead scores
//! context:
//!
//! ```text
//! risk = severity x exposure x exploitability x criticality x confidence
//! ```
//!
//! The same CVSS 8.2 on an internet-facing production host is critical; on a
//! localhost-only dev box it is medium at best. Weights live here until the
//! rules engine (v0.2) moves them into rules/.

use orbis_core::{Criticality, Exploitability, Exposure, Finding};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "critical",
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
            RiskLevel::Info => "info",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskAssessment {
    /// 0.0 to 1.0 composite score.
    pub score: f32,
    pub level: RiskLevel,
    /// The context factors that produced this score, for explain output.
    pub factors: Vec<(&'static str, String)>,
}

fn exposure_weight(e: Exposure) -> f32 {
    match e {
        Exposure::Internet => 1.0,
        Exposure::LocalNetwork => 0.6,
        Exposure::Localhost => 0.5,
        Exposure::Unknown => 0.5,
    }
}

fn exploitability_weight(x: Exploitability) -> f32 {
    match x {
        Exploitability::High => 1.0,
        Exploitability::Medium => 0.7,
        Exploitability::Low => 0.6,
        Exploitability::Unknown => 0.6,
    }
}

fn criticality_weight(c: Criticality) -> f32 {
    match c {
        Criticality::Production => 1.0,
        Criticality::Staging => 0.7,
        Criticality::Development => 0.7,
        Criticality::Unknown => 0.7,
    }
}

/// Score a finding in context. Deterministic and cheap: no I/O, no network.
pub fn assess(f: &Finding) -> RiskAssessment {
    let score = f.severity.base_weight()
        * exposure_weight(f.exposure)
        * exploitability_weight(f.exploitability)
        * criticality_weight(f.criticality)
        * f.confidence.clamp(0.0, 1.0);

    RiskAssessment {
        score,
        level: level_for(score),
        factors: vec![
            ("severity", f.severity.label().to_string()),
            ("exposure", exposure_label(f.exposure).to_string()),
            (
                "exploitability",
                exploitability_label(f.exploitability).to_string(),
            ),
            ("criticality", criticality_label(f.criticality).to_string()),
            ("confidence", format!("{:.2}", f.confidence.clamp(0.0, 1.0))),
        ],
    }
}

fn level_for(score: f32) -> RiskLevel {
    if score >= 0.60 {
        RiskLevel::Critical
    } else if score >= 0.35 {
        RiskLevel::High
    } else if score >= 0.12 {
        RiskLevel::Medium
    } else if score >= 0.05 {
        RiskLevel::Low
    } else {
        RiskLevel::Info
    }
}

fn exposure_label(e: Exposure) -> &'static str {
    match e {
        Exposure::Internet => "internet",
        Exposure::LocalNetwork => "local network",
        Exposure::Localhost => "localhost",
        Exposure::Unknown => "unknown",
    }
}

fn exploitability_label(x: Exploitability) -> &'static str {
    match x {
        Exploitability::High => "high",
        Exploitability::Medium => "medium",
        Exploitability::Low => "low",
        Exploitability::Unknown => "unknown",
    }
}

fn criticality_label(c: Criticality) -> &'static str {
    match c {
        Criticality::Production => "production",
        Criticality::Staging => "staging",
        Criticality::Development => "development",
        Criticality::Unknown => "unknown",
    }
}

/// Overall security score, 0 (compromised posture) to 100 (clean).
/// Penalties are counted by Orbis risk level, not raw severity, so context
/// downgrades are reflected here too.
pub fn security_score(findings: &[Finding]) -> u8 {
    let penalty: f32 = findings
        .iter()
        .map(|f| match assess(f).level {
            RiskLevel::Critical => 12.0,
            RiskLevel::High => 5.0,
            RiskLevel::Medium => 2.0,
            RiskLevel::Low => 0.5,
            RiskLevel::Info => 0.0,
        })
        .sum();

    (100.0 - penalty).clamp(0.0, 100.0) as u8
}

/// The n highest-risk findings, most dangerous first.
pub fn top_risks(findings: &[Finding], n: usize) -> Vec<&Finding> {
    let mut ranked: Vec<&Finding> = findings.iter().collect();
    ranked.sort_by(|a, b| {
        assess(b)
            .score
            .partial_cmp(&assess(a).score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked.truncate(n);
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbis_core::{Evidence, FindingKind, Severity};

    fn context_finding(
        sev: Severity,
        exp: Exposure,
        x: Exploitability,
        crit: Criticality,
    ) -> Finding {
        let mut f = Finding::new(
            "trivy",
            "image",
            FindingKind::Vulnerability,
            sev,
            "Vulnerable package",
        );
        f.exposure = exp;
        f.exploitability = x;
        f.criticality = crit;
        f.confidence = 0.98;
        f.cve = vec!["CVE-2026-XXXX".into()];
        f.evidence.push(Evidence {
            source: "trivy".into(),
            detail: "fixture".into(),
        });
        f
    }

    #[test]
    fn same_cve_different_context_gives_different_risk() {
        let internet = context_finding(
            Severity::High,
            Exposure::Internet,
            Exploitability::High,
            Criticality::Production,
        );
        let local = context_finding(
            Severity::High,
            Exposure::Localhost,
            Exploitability::Low,
            Criticality::Development,
        );

        assert_eq!(assess(&internet).level, RiskLevel::Critical);
        assert_eq!(assess(&local).level, RiskLevel::Medium);
    }

    #[test]
    fn committed_cloud_credentials_are_critical() {
        let mut f = Finding::new(
            "gitleaks",
            "repo",
            FindingKind::Secret,
            Severity::Critical,
            "AWS Access Key ID",
        );
        f.exposure = Exposure::Internet;
        f.exploitability = Exploitability::High;
        f.confidence = 0.95;

        assert_eq!(assess(&f).level, RiskLevel::Critical);
    }

    #[test]
    fn score_drops_with_findings_and_never_goes_negative() {
        let clean = security_score(&[]);
        assert_eq!(clean, 100);

        let mut noisy = Vec::new();
        for _ in 0..30 {
            noisy.push(context_finding(
                Severity::Critical,
                Exposure::Internet,
                Exploitability::High,
                Criticality::Production,
            ));
        }
        assert_eq!(security_score(&noisy), 0);
    }

    #[test]
    fn top_risks_orders_most_dangerous_first() {
        let mut low = context_finding(
            Severity::Low,
            Exposure::Localhost,
            Exploitability::Low,
            Criticality::Development,
        );
        low.title = "low".into();
        let mut high = context_finding(
            Severity::Critical,
            Exposure::Internet,
            Exploitability::High,
            Criticality::Production,
        );
        high.title = "high".into();

        let all = [low, high];
        let ranked = top_risks(&all, 1);
        assert_eq!(ranked[0].title, "high");
    }
}
