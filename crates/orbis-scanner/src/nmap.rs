//! nmap adapter. Runs `nmap -oX - -sV <target>` and parses the XML stream.
//! The parser is a pure function so the bundled fixture doubles as a test.

use crate::util::tool_exists;
use crate::{Collector, ScanOptions};
use anyhow::{Context, Result};
use orbis_core::{Evidence, Exploitability, Exposure, Finding, FindingKind, Severity};
use std::process::Command;

pub struct Nmap;

const DEMO: &str = include_str!("../fixtures/nmap.xml");

impl Collector for Nmap {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn is_available(&self) -> bool {
        tool_exists("nmap")
    }

    fn scan(&self, opts: &ScanOptions) -> Result<Vec<Finding>> {
        let xml = if opts.demo {
            DEMO.to_string()
        } else {
            let output = Command::new("nmap")
                .arg("-oX")
                .arg("-")
                .arg("-sV")
                .arg(&opts.target)
                .output()
                .context("failed to start nmap")?;
            if !output.status.success() {
                anyhow::bail!(
                    "nmap exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        parse_xml(&xml, &opts.target)
    }
}

/// Severity and context heuristics per service. v0.2 replaces this with the
/// rules engine and correlation, so SSH + weak auth becomes one path.
fn classify(port: u16, service: &str) -> (Severity, &'static str) {
    match (port, service) {
        (23, _) => (Severity::Critical, "telnet"),
        (22, _) => (Severity::High, "sshd"),
        (80, "http") | (443, "https") => (Severity::Low, "web service"),
        _ => (Severity::Medium, "network service"),
    }
}

pub fn parse_xml(xml: &str, asset: &str) -> Result<Vec<Finding>> {
    let doc = roxmltree::Document::parse(xml).context("could not parse nmap XML")?;
    let mut findings = Vec::new();

    for port in doc.descendants().filter(|n| n.has_tag_name("port")) {
        let portid = match port.attribute("portid").and_then(|p| p.parse::<u16>().ok()) {
            Some(p) => p,
            None => continue,
        };
        let protocol = port.attribute("protocol").unwrap_or("tcp");

        let state_open = port
            .children()
            .any(|c| c.has_tag_name("state") && c.attribute("state") == Some("open"));
        if !state_open {
            continue;
        }

        let service = port
            .children()
            .find(|c| c.has_tag_name("service"))
            .and_then(|s| s.attribute("name"))
            .unwrap_or("unknown")
            .to_string();
        let product = port
            .children()
            .find(|c| c.has_tag_name("service"))
            .and_then(|s| s.attribute("product"))
            .unwrap_or("")
            .to_string();
        let version = port
            .children()
            .find(|c| c.has_tag_name("service"))
            .and_then(|s| s.attribute("version"))
            .unwrap_or("")
            .to_string();

        let banner = [product.as_str(), version.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");

        let (severity, component) = classify(portid, &service);
        let mut f = Finding::new(
            "nmap",
            asset,
            FindingKind::OpenPort,
            severity,
            format!("Port {portid}/{} open ({service})", protocol),
        );
        f.component = component.to_string();
        f.affected_version = if banner.is_empty() {
            None
        } else {
            Some(banner.clone())
        };
        f.exposure = Exposure::Internet;
        f.exploitability = match component {
            "sshd" | "telnet" => Exploitability::High,
            _ => Exploitability::Medium,
        };
        f.confidence = 0.95;
        f.description = format!(
            "{}/{}/{} on {asset} accepts connections.",
            protocol, portid, service
        );
        f.evidence.push(Evidence {
            source: "nmap".into(),
            detail: format!("{portid}/{} open {service} {banner}", protocol),
        });
        f.recommended_fix = match component {
            "sshd" => {
                "Restrict SSH access to trusted networks and disable password authentication."
                    .into()
            }
            "telnet" => "Disable telnet and use SSH instead.".into(),
            _ => "Close the port if the service is unused, or restrict it with a firewall rule."
                .into(),
        };
        findings.push(f);
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_fixture_yields_four_open_ports() {
        let findings = parse_xml(super::DEMO, "server-01").unwrap();
        assert_eq!(findings.len(), 4);

        let ssh = findings
            .iter()
            .find(|f| f.title.contains("22/tcp"))
            .expect("ssh port finding");
        assert_eq!(ssh.severity, Severity::High);
        assert_eq!(ssh.exposure, Exposure::Internet);
        assert_eq!(ssh.component, "sshd");
        assert!(ssh.recommended_fix.contains("Restrict SSH"));

        let web = findings
            .iter()
            .find(|f| f.title.contains("80/tcp"))
            .unwrap();
        assert_eq!(web.severity, Severity::Low);
    }
}
