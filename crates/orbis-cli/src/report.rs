//! Terminal rendering. Colors follow BRAND.md's terminal palette; severity
//! hues are semantic and appear only on real findings data.

use crate::store::State;
use colored::{ColoredString, Colorize};
use orbis_core::{Finding, Severity};
use orbis_risk::{assess, security_score, top_risks, RiskLevel};

fn crit() -> ColoredString {
    "critical".truecolor(237, 106, 77).bold()
}
fn high() -> ColoredString {
    "high".truecolor(225, 145, 60).bold()
}
fn medium() -> ColoredString {
    "medium".truecolor(203, 179, 90).bold()
}
fn low() -> ColoredString {
    "low".truecolor(160, 170, 165).bold()
}
pub fn accent(text: &str) -> ColoredString {
    text.truecolor(82, 207, 162).bold()
}
fn dim(text: &str) -> ColoredString {
    text.truecolor(124, 138, 133)
}

pub fn severity_label(sev: Severity) -> ColoredString {
    match sev {
        Severity::Critical => crit(),
        Severity::High => high(),
        Severity::Medium => medium(),
        Severity::Low | Severity::Info => low(),
    }
}

fn risk_label(level: RiskLevel) -> ColoredString {
    match level {
        RiskLevel::Critical => crit(),
        RiskLevel::High => high(),
        RiskLevel::Medium => medium(),
        RiskLevel::Low | RiskLevel::Info => low(),
    }
}

/// The summary shown after `orbis scan` and by `orbis report`.
pub fn overview(state: &State) {
    let findings = &state.findings;

    println!("{}", "ORBIS SECURITY OVERVIEW".bold());
    println!();

    let score = security_score(findings);
    let score_colored = match score {
        0..=39 => format!("{score} / 100").truecolor(237, 106, 77).bold(),
        40..=69 => format!("{score} / 100").truecolor(225, 145, 60).bold(),
        _ => format!("{score} / 100").truecolor(82, 207, 162).bold(),
    };
    println!("{}  {}", "Score".bold(), score_colored);
    println!();

    let (c, h, m, l) = count_by_risk(findings);
    if c + h + m + l == 0 {
        println!("{}", accent("No open findings."));
        return;
    }
    let crit_line = format!("{c} {}", crit());
    let high_line = format!("{h} {}", high());
    let med_line = format!("{m} {}", medium());
    let low_line = format!("{l} {}", low());
    println!("  {crit_line}  {high_line}  {med_line}  {low_line}");
    println!();

    let top = top_risks(findings, 3);
    if !top.is_empty() {
        println!("{}", "Biggest risks".bold());
        for (i, f) in top.iter().enumerate() {
            let level = assess(f).level;
            println!(
                "  {}  {}  [{}]  {}",
                dim(&format!("{}", i + 1)),
                f.id,
                risk_label(level),
                f.title
            );
        }
        println!();

        println!("{}", "Recommended first action".bold());
        println!("{} {}", accent("->"), top[0].recommended_fix);
    }
}

fn count_by_risk(findings: &[Finding]) -> (usize, usize, usize, usize) {
    let mut c = 0;
    let mut h = 0;
    let mut m = 0;
    let mut l = 0;
    for f in findings {
        match assess(f).level {
            RiskLevel::Critical => c += 1,
            RiskLevel::High => h += 1,
            RiskLevel::Medium => m += 1,
            RiskLevel::Low | RiskLevel::Info => l += 1,
        }
    }
    (c, h, m, l)
}

/// `orbis findings` listing.
pub fn findings_table(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", dim("No findings match."));
        return;
    }
    for f in findings {
        println!(
            "{}  [{}]  {:<10}  {}",
            f.id,
            severity_label(f.severity),
            dim(f.source.as_str()),
            f.title
        );
    }
    println!();
    println!("{}", dim(&format!("{} findings", findings.len())));
}

/// `orbis show <ID>` detail view.
pub fn show(f: &Finding) {
    println!(
        "{}  [{}]  {}",
        f.id.bold(),
        severity_label(f.severity),
        f.title.bold()
    );
    println!(
        "{} {}   {} {}   {} {}",
        dim("source:"),
        f.source,
        dim("asset:"),
        f.asset,
        dim("kind:"),
        f.kind.label()
    );
    if !f.cve.is_empty() {
        println!("{} {}", dim("cve:"), f.cve.join(", "));
    }
    if let (Some(installed), Some(fixed)) = (&f.affected_version, &f.fixed_version) {
        let version_line = format!("{installed} -> {fixed}");
        println!(
            "{} {} {} {}",
            dim("component:"),
            f.component,
            dim("version:"),
            version_line
        );
    }
    println!();

    if !f.description.is_empty() {
        println!("{}", f.description);
        println!();
    }

    if !f.evidence.is_empty() {
        println!("{}", "Evidence".bold());
        for ev in &f.evidence {
            println!("  {}  {}", dim(&ev.source), ev.detail);
        }
        println!();
    }

    println!("{}", "Recommended fix".bold());
    println!("{} {}", accent("->"), f.recommended_fix);
}
