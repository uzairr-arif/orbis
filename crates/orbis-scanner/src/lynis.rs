//! lynis adapter. Reads the report lynis writes to /var/log/lynis-report.dat
//! after a system audit. The parser is a pure function over that file.

use crate::util::tool_exists;
use crate::{Collector, ScanOptions};
use anyhow::{Context, Result};
use orbis_core::{Evidence, Finding, FindingKind, Severity};
use std::path::PathBuf;
use std::process::Command;

pub struct Lynis;

const DEMO: &str = include_str!("../fixtures/lynis-report.dat");
const REPORT_PATH: &str = "/var/log/lynis-report.dat";

impl Collector for Lynis {
    fn name(&self) -> &'static str {
        "lynis"
    }

    fn is_available(&self) -> bool {
        tool_exists("lynis")
    }

    fn scan(&self, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let report = if opts.demo {
            DEMO.to_string()
        } else {
            let status = Command::new("lynis")
                .arg("audit")
                .arg("system")
                .arg("--quick")
                .status()
                .context("failed to start lynis")?;
            if !status.success() {
                anyhow::bail!("lynis audit system exited with {status}");
            }
            std::fs::read_to_string(PathBuf::from(REPORT_PATH))
                .with_context(|| format!("could not read {REPORT_PATH}"))?
        };

        parse_report(&report, &opts.target)
    }
}

/// lynis test IDs that map to more than the default warning severity.
fn warning_severity(test_id: &str) -> Severity {
    match test_id {
        // SSH root login is the classic pre-exploit condition.
        "SSH-7408" => Severity::High,
        _ => Severity::Medium,
    }
}

pub fn parse_report(report: &str, asset: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for line in report.lines() {
        let (is_warning, rest) = if let Some(r) = line.strip_prefix("warning[]=") {
            (true, r)
        } else if let Some(r) = line.strip_prefix("suggestion[]=") {
            (false, r)
        } else {
            continue;
        };

        let mut parts = rest.splitn(2, '|');
        let test_id = parts.next().unwrap_or_default().to_string();
        let payload = parts.next().unwrap_or_default();

        let mut text = String::new();
        let mut details = String::new();
        for field in payload.split('|') {
            if let Some(t) = field.strip_prefix("text=") {
                text = t.to_string();
            } else if let Some(d) = field.strip_prefix("details=") {
                details = d.to_string();
            }
        }
        if text.is_empty() {
            continue;
        }

        let severity = if is_warning {
            warning_severity(&test_id)
        } else {
            Severity::Low
        };

        let mut f = Finding::new(
            "lynis",
            asset,
            FindingKind::Misconfiguration,
            severity,
            text.clone(),
        );
        f.component = test_id.clone();
        f.confidence = if is_warning { 0.9 } else { 0.7 };
        f.description = format!("lynis test {test_id} flagged: {text}");
        f.evidence.push(Evidence {
            source: "lynis".into(),
            detail: if details.is_empty() {
                format!("{test_id}: {text}")
            } else {
                format!("{test_id}: {text} ({details})")
            },
        });
        f.recommended_fix = if details.is_empty() {
            format!("Resolve lynis {test_id}: {text}")
        } else {
            details.clone()
        };
        findings.push(f);
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_fixture_parses_warnings_and_suggestions() {
        let findings = parse_report(DEMO, "server-01").unwrap();
        assert_eq!(findings.len(), 8);

        // Ord convention: more severe sorts first (Critical is "smallest"),
        // so "at least Medium severity" is `<= Medium`.
        let warnings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity <= Severity::Medium)
            .collect();
        assert_eq!(warnings.len(), 5);

        let root = findings
            .iter()
            .find(|f| f.component == "SSH-7408")
            .expect("root login finding");
        assert_eq!(root.severity, Severity::High);

        let cipher = findings
            .iter()
            .find(|f| f.component == "SSH-7404")
            .expect("cipher suggestion");
        assert_eq!(cipher.severity, Severity::Low);
        assert_eq!(cipher.recommended_fix, "Remove 3des-cbc from Ciphers");
    }
}
