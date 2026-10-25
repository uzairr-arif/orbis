//! Orbis Finding Model.
//!
//! Every collector, no matter what tool it wraps, normalizes its output into
//! [`Finding`]. Everything downstream (dedup, risk, explain, report) speaks
//! only this language. See docs/finding-model.md for the field contract.

use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

/// Raw severity as reported by the source tool.
///
/// Ord convention: more severe sorts FIRST (Critical is "smallest"). So
/// "at least Medium" is `sev <= Severity::Medium`, and ascending sort puts
/// the most dangerous findings on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// Base weight used by the risk engine before context multipliers.
    pub fn base_weight(&self) -> f32 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.7,
            Severity::Medium => 0.4,
            Severity::Low => 0.2,
            Severity::Info => 0.1,
        }
    }

    /// Parse a scanner-reported severity string (trivy, CVE databases).
    pub fn parse(raw: &str) -> Severity {
        match raw.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" | "MODERATE" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What kind of problem the finding represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum FindingKind {
    OpenPort,
    Vulnerability,
    Misconfiguration,
    Secret,
    Other(String),
}

impl FindingKind {
    pub fn label(&self) -> &str {
        match self {
            FindingKind::OpenPort => "open port",
            FindingKind::Vulnerability => "vulnerability",
            FindingKind::Misconfiguration => "misconfiguration",
            FindingKind::Secret => "exposed secret",
            FindingKind::Other(_) => "finding",
        }
    }
}

/// Who can reach the affected component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Internet,
    LocalNetwork,
    Localhost,
    Unknown,
}

/// How practical exploitation is, when the source tool says anything about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    High,
    Medium,
    Low,
    Unknown,
}

/// How much the affected asset matters to the organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Production,
    Staging,
    Development,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Resolved,
}

/// One piece of verified proof for a finding, with the tool that produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub detail: String,
}

/// The universal Orbis finding. Collectors build these; everything else
/// consumes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Human-readable ID, stable across scans for the same fingerprint.
    pub id: String,
    /// Hash over (source, asset, kind, component, title). Drives dedup.
    pub fingerprint: u64,
    /// Collector that produced the finding, e.g. "trivy".
    pub source: String,
    /// Host, image, repository, or project the finding belongs to.
    pub asset: String,
    pub kind: FindingKind,
    pub severity: Severity,
    /// 0.0 to 1.0. How sure the source tool is.
    pub confidence: f32,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    pub cve: Vec<String>,
    /// Affected software or service, e.g. "openssl" or "sshd".
    pub component: String,
    pub affected_version: Option<String>,
    pub fixed_version: Option<String>,
    pub exposure: Exposure,
    pub exploitability: Exploitability,
    pub criticality: Criticality,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    pub status: Status,
    pub recommended_fix: String,
}

impl Finding {
    /// Start a finding with defaults; collectors fill in what they know.
    pub fn new(
        source: &str,
        asset: &str,
        kind: FindingKind,
        severity: Severity,
        title: impl Into<String>,
    ) -> Self {
        let now = unix_now();
        Finding {
            id: String::new(),
            fingerprint: 0,
            source: source.to_string(),
            asset: asset.to_string(),
            kind,
            severity,
            confidence: 0.8,
            title: title.into(),
            description: String::new(),
            evidence: Vec::new(),
            cve: Vec::new(),
            component: String::new(),
            affected_version: None,
            fixed_version: None,
            exposure: Exposure::Unknown,
            exploitability: Exploitability::Unknown,
            criticality: Criticality::Unknown,
            first_seen: now,
            last_seen: now,
            status: Status::Open,
            recommended_fix: String::new(),
        }
    }

    /// Compute the dedup fingerprint and the stable display ID.
    /// Two findings from the same tool about the same component on the same
    /// asset with the same title are the same finding.
    pub fn finalize(&mut self) {
        let mut hasher = DefaultHasher::new();
        self.source.hash(&mut hasher);
        self.asset.hash(&mut hasher);
        format!("{:?}", self.kind).hash(&mut hasher);
        self.component.hash(&mut hasher);
        self.title.to_ascii_lowercase().hash(&mut hasher);
        self.fingerprint = hasher.finish();
        self.id = stable_id(self.fingerprint);
    }
}

/// Short, stable, human-quotable ID derived from the fingerprint.
/// Collisions are acceptable at this scale; the fingerprint is the real key.
pub fn stable_id(fingerprint: u64) -> String {
    format!("ORB-{:04X}", (fingerprint as u16) as u32)
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Merge a re-observed finding into a stored one: keep the ID and first_seen,
/// refresh last_seen, and merge evidence lists. Severity keeps the more
/// severe value: with the Ord convention (Critical sorts first), that is
/// `.min()`, not `.max()`.
pub fn merge(stored: &mut Finding, fresh: &Finding) {
    stored.last_seen = fresh.last_seen;
    stored.severity = stored.severity.min(fresh.severity);
    stored.confidence = stored.confidence.max(fresh.confidence);
    for ev in &fresh.evidence {
        if !stored.evidence.iter().any(|e| e.detail == ev.detail) {
            stored.evidence.push(ev.clone());
        }
    }
}

/// Deduplicate a batch of findings within one scan by fingerprint.
pub fn dedupe(findings: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    for mut f in findings {
        f.finalize();
        match out.iter_mut().find(|e| e.fingerprint == f.fingerprint) {
            Some(stored) => merge(stored, &f),
            None => out.push(f),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(title: &str, component: &str) -> Finding {
        let mut f = Finding::new(
            "trivy",
            "server-01",
            FindingKind::Vulnerability,
            Severity::High,
            title,
        );
        f.component = component.to_string();
        f.finalize();
        f
    }

    #[test]
    fn fingerprints_are_stable_and_case_insensitive_on_title() {
        let a = sample("Vulnerable OpenSSL version", "openssl");
        let b = sample("vulnerable openssl version", "openssl");
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn different_components_do_not_collide() {
        let a = sample("Vulnerable OpenSSL version", "openssl");
        let b = sample("Vulnerable OpenSSL version", "nginx");
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn dedupe_merges_repeats_into_one() {
        let mut base = sample("Vulnerable OpenSSL version", "openssl");
        base.evidence.push(Evidence {
            source: "trivy".into(),
            detail: "CVE-2026-1337 in openssl 3.0.11".into(),
        });
        let mut repeat = sample("Vulnerable OpenSSL version", "openssl");
        repeat.evidence.push(Evidence {
            source: "trivy".into(),
            detail: "seen again on rescan".into(),
        });

        let merged = dedupe(vec![base, repeat]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].evidence.len(), 2);
    }

    #[test]
    fn merge_keeps_the_worst_severity() {
        let mut stored = sample("Vulnerable OpenSSL version", "openssl");
        let mut escalated = sample("Vulnerable OpenSSL version", "openssl");
        escalated.severity = Severity::Critical;
        merge(&mut stored, &escalated);
        assert_eq!(stored.severity, Severity::Critical);

        let mut milder = sample("Vulnerable OpenSSL version", "openssl");
        milder.severity = Severity::Low;
        merge(&mut stored, &milder);
        assert_eq!(stored.severity, Severity::Critical);
    }

    #[test]
    fn severity_parse_handles_scanner_dialects() {
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::parse("Moderate"), Severity::Medium);
        assert_eq!(Severity::parse("weird"), Severity::Info);
    }
}
