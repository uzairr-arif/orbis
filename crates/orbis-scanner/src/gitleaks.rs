//! gitleaks adapter. Runs `gitleaks detect` over a repository and parses the
//! JSON report. Committed secrets are treated as internet exposure: assume any
//! clone or push may have already leaked them.

use crate::util::tool_exists;
use crate::{Collector, ScanOptions};
use anyhow::{Context, Result};
use orbis_core::{Evidence, Exploitability, Exposure, Finding, FindingKind, Severity};
use serde::Deserialize;
use std::process::Command;

pub struct Gitleaks;

const DEMO: &str = include_str!("../fixtures/gitleaks.json");

#[derive(Deserialize)]
struct Leak {
    #[serde(rename = "RuleID")]
    rule: String,
    #[serde(rename = "Description", default)]
    description: Option<String>,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "StartLine")]
    line: i64,
    #[serde(rename = "Secret")]
    secret: String,
    #[serde(rename = "Commit", default)]
    commit: Option<String>,
}

impl Collector for Gitleaks {
    fn name(&self) -> &'static str {
        "gitleaks"
    }

    fn is_available(&self) -> bool {
        tool_exists("gitleaks")
    }

    fn scan(&self, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let json = if opts.demo {
            DEMO.to_string()
        } else {
            let report_path =
                std::env::temp_dir().join(format!("orbis-gitleaks-{}.json", std::process::id()));
            let output = Command::new("gitleaks")
                .arg("detect")
                .arg("--source")
                .arg(&opts.target)
                .arg("--report-format")
                .arg("json")
                .arg("--report-path")
                .arg(&report_path)
                .output()
                .context("failed to start gitleaks")?;

            // gitleaks exits 1 when leaks are found; that is a successful scan.
            if !output.status.success() && output.status.code() != Some(1) {
                anyhow::bail!(
                    "gitleaks exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }

            let report = std::fs::read_to_string(&report_path)
                .with_context(|| "could not read gitleaks report")?;
            let _ = std::fs::remove_file(&report_path);
            report
        };

        parse_json(&json, &opts.target)
    }
}

fn classify(rule: &str) -> (Severity, Exploitability) {
    // Cloud credentials are immediately usable and billable.
    if rule.starts_with("aws-") || rule.starts_with("gcp") || rule.starts_with("azure") {
        (Severity::Critical, Exploitability::High)
    } else {
        (Severity::High, Exploitability::Medium)
    }
}

pub fn parse_json(json: &str, asset: &str) -> Result<Vec<Finding>> {
    let leaks: Vec<Leak> = serde_json::from_str(json).context("could not parse gitleaks JSON")?;
    let mut findings = Vec::new();

    for leak in &leaks {
        let (severity, exploitability) = classify(&leak.rule);
        let redacted = redact(&leak.secret);

        let mut f = Finding::new(
            "gitleaks",
            asset,
            FindingKind::Secret,
            severity,
            leak.description
                .clone()
                .unwrap_or_else(|| format!("{} pattern matched", leak.rule)),
        );
        f.component = leak.file.clone();
        f.exposure = Exposure::Internet;
        f.exploitability = exploitability;
        f.confidence = 0.95;
        f.description = format!(
            "A secret matching rule {} was committed at {}:{}.",
            leak.rule, leak.file, leak.line
        );
        f.evidence.push(Evidence {
            source: "gitleaks".into(),
            detail: format!(
                "{}:{} {} [{}] {}",
                leak.file,
                leak.line,
                leak.rule,
                redacted,
                leak.commit.as_deref().unwrap_or("no commit")
            ),
        });
        f.recommended_fix = format!(
            "Rotate the credential immediately, then remove it from history in {}.",
            leak.file
        );
        findings.push(f);
    }

    Ok(findings)
}

/// Never render a full secret. First 8 characters are enough to recognize.
fn redact(secret: &str) -> String {
    let prefix: String = secret.chars().take(8).collect();
    format!("{prefix}{}", "*".repeat(8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_fixture_yields_two_secrets() {
        let findings = parse_json(DEMO, "/srv/app").unwrap();
        assert_eq!(findings.len(), 2);

        let aws = findings
            .iter()
            .find(|f| f.component == "deploy/.env")
            .unwrap();
        assert_eq!(aws.severity, Severity::Critical);
        assert_eq!(aws.exposure, Exposure::Internet);
        assert!(aws.recommended_fix.contains("Rotate"));

        // Secrets must never be printed in full, even in evidence.
        assert!(!format!("{:?}", aws.evidence).contains("AKIAQVZEXAMPLEKEY1"));
        assert!(format!("{:?}", aws.evidence).contains("AKIAQVZE********"));
    }
}
