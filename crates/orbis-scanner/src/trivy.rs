//! trivy adapter. Runs `trivy image --format json <target>` and parses the
//! vulnerability list. Container images scanned locally are localhost-only
//! exposure until correlation learns otherwise.

use crate::util::tool_exists;
use crate::{Collector, ScanOptions};
use anyhow::{Context, Result};
use orbis_core::{Evidence, Exposure, Finding, FindingKind, Severity};
use serde::Deserialize;
use std::process::Command;

pub struct Trivy;

const DEMO: &str = include_str!("../fixtures/trivy.json");

#[derive(Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName")]
    pkg: String,
    #[serde(rename = "InstalledVersion")]
    installed: Option<String>,
    #[serde(rename = "FixedVersion")]
    fixed: Option<String>,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Title", default)]
    title: Option<String>,
    #[serde(rename = "Confidence", default)]
    confidence: Option<f32>,
}

impl Collector for Trivy {
    fn name(&self) -> &'static str {
        "trivy"
    }

    fn is_available(&self) -> bool {
        tool_exists("trivy")
    }

    fn scan(&self, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let json = if opts.demo {
            DEMO.to_string()
        } else {
            let output = Command::new("trivy")
                .arg("image")
                .arg("--format")
                .arg("json")
                .arg("--quiet")
                .arg(&opts.target)
                .output()
                .context("failed to start trivy")?;
            if !output.status.success() {
                anyhow::bail!(
                    "trivy exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        parse_json(&json, &opts.target)
    }
}

pub fn parse_json(json: &str, default_asset: &str) -> Result<Vec<Finding>> {
    let report: TrivyReport = serde_json::from_str(json).context("could not parse trivy JSON")?;
    let mut findings = Vec::new();

    for result in &report.results {
        for v in &result.vulnerabilities {
            let mut f = Finding::new(
                "trivy",
                &result.target,
                FindingKind::Vulnerability,
                Severity::parse(&v.severity),
                v.title
                    .clone()
                    .unwrap_or_else(|| format!("{} in {}", v.id, v.pkg)),
            );
            f.component = v.pkg.clone();
            f.affected_version = v.installed.clone();
            f.fixed_version = v.fixed.clone();
            f.cve = vec![v.id.clone()];
            f.exposure = Exposure::Localhost;
            f.confidence = v.confidence.unwrap_or(0.85).clamp(0.0, 1.0);
            f.description = format!(
                "{} reports {} in {} {} on {}.",
                "trivy",
                v.id,
                v.pkg,
                v.installed.as_deref().unwrap_or("?"),
                result.target
            );
            f.evidence.push(Evidence {
                source: "trivy".into(),
                detail: format!(
                    "{} {} {} (fixed in {})",
                    v.id,
                    v.pkg,
                    v.installed.as_deref().unwrap_or("?"),
                    v.fixed.as_deref().unwrap_or("no fix available")
                ),
            });
            f.recommended_fix = match &v.fixed {
                Some(fv) => format!("Upgrade {} to {} or later.", v.pkg, fv),
                None => format!(
                    "No fixed version published yet. Monitor {} and mitigate exposure.",
                    v.id
                ),
            };
            findings.push(f);
        }
    }

    let _ = default_asset;
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_fixture_yields_nine_vulnerabilities() {
        let findings = parse_json(DEMO, "nginx:1.25").unwrap();
        assert_eq!(findings.len(), 9);

        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Critical)
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::High)
                .count(),
            2
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.severity == Severity::Medium)
                .count(),
            6
        );

        let crit = findings
            .iter()
            .find(|f| f.cve.contains(&"CVE-2026-1337".to_string()))
            .unwrap();
        assert_eq!(crit.component, "openssl");
        assert_eq!(crit.fixed_version.as_deref(), Some("3.0.12"));
        assert!(crit.recommended_fix.contains("Upgrade openssl to 3.0.12"));
    }
}
