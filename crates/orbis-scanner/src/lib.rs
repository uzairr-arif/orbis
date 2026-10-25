//! Collector adapters.
//!
//! Orbis does not reinvent security research; it orchestrates excellent
//! existing tools. Every adapter implements [`Collector`], runs its tool (or
//! the bundled demo fixture), and returns normalized [`Finding`]s. Parsers are
//! pure functions over captured output, so they are testable anywhere.

mod gitleaks;
mod lynis;
mod nmap;
mod trivy;
mod util;

use anyhow::Result;
use orbis_core::Finding;
use std::time::Instant;

pub use gitleaks::Gitleaks;
pub use lynis::Lynis;
pub use nmap::Nmap;
pub use trivy::Trivy;

/// Options for one scan run.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Host, CIDR, image, or repository path to scan.
    pub target: String,
    /// Parse bundled fixtures instead of running real tools. Works offline
    /// on any machine, for demos and development.
    pub demo: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            target: "localhost".to_string(),
            demo: false,
        }
    }
}

/// What happened when one collector ran.
#[derive(Debug)]
pub enum RunStatus {
    Ok,
    /// Tool not found on PATH.
    Unavailable,
    /// Tool ran but failed.
    Failed(String),
}

#[derive(Debug)]
pub struct CollectorReport {
    pub name: &'static str,
    pub status: RunStatus,
    pub findings: usize,
    pub elapsed_ms: u128,
}

/// A wrapped external scanner. Implementations must be cheap to construct.
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    /// Is the wrapped tool installed and callable?
    fn is_available(&self) -> bool;

    /// Run the tool and return normalized findings.
    fn scan(&self, opts: &ScanOptions) -> Result<Vec<Finding>>;
}

/// The v0.1 collector set, in the order the report lists them.
pub fn registry() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(Nmap),
        Box::new(Lynis),
        Box::new(Trivy),
        Box::new(Gitleaks),
    ]
}

/// Run every collector, collecting per-tool reports. A tool that is missing or
/// failing never aborts the scan; it is reported and skipped.
pub fn run(opts: &ScanOptions) -> (Vec<CollectorReport>, Vec<Finding>) {
    let mut reports = Vec::new();
    let mut findings = Vec::new();

    for collector in registry() {
        let name = collector.name();
        let started = Instant::now();

        let (status, produced) = if opts.demo || collector.is_available() {
            match collector.scan(opts) {
                Ok(list) => (RunStatus::Ok, list),
                Err(e) => (RunStatus::Failed(e.to_string()), Vec::new()),
            }
        } else {
            (RunStatus::Unavailable, Vec::new())
        };

        reports.push(CollectorReport {
            name,
            findings: produced.len(),
            status,
            elapsed_ms: started.elapsed().as_millis(),
        });
        findings.extend(produced);
    }

    (reports, findings)
}
