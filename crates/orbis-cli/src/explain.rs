//! `orbis explain <ID>`: plain-language risk narrative built strictly from
//! verified evidence. The AI layer (later versions) answers questions on top
//! of this same data; it never invents evidence.

use crate::report::accent;
use colored::Colorize;
use orbis_core::{Evidence, Exposure, Finding, FindingKind};
use orbis_risk::{RiskAssessment, RiskLevel};

pub fn explain(f: &Finding, risk: &RiskAssessment) {
    println!("{}  {}", f.id.bold(), f.title.bold());
    println!();

    println!("{}", "WHY THIS MATTERS".bold());
    println!("{}", why(f));
    println!();

    println!("{}", "RISK".bold());
    let level = match risk.level {
        RiskLevel::Critical => "critical".truecolor(237, 106, 77).bold(),
        RiskLevel::High => "high".truecolor(225, 145, 60).bold(),
        RiskLevel::Medium => "medium".truecolor(203, 179, 90).bold(),
        RiskLevel::Low | RiskLevel::Info => "low".truecolor(160, 170, 165).bold(),
    };
    println!("Orbis risk: {} (score {:.2})", level, risk.score);
    let factors: Vec<String> = risk
        .factors
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    println!("{}", factors.join(" | "));
    println!();

    if !f.evidence.is_empty() {
        println!("{}", "EVIDENCE".bold());
        for ev in &f.evidence {
            println!("  {}  {}", "-".truecolor(124, 138, 133), evidence_line(ev));
        }
        println!();
    }

    println!("{}", "RECOMMENDED FIX".bold());
    println!("{} {}", accent("->"), f.recommended_fix);
}

fn evidence_line(ev: &Evidence) -> String {
    // Evidence comes from untrusted tool output; keep it on one line.
    let clean: String = ev
        .detail
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .take(200)
        .collect();
    format!("{clean} ({})", ev.source)
}

/// Build the narrative from finding facts. Templates per kind; no invented
/// detail, only what the collectors verified.
fn why(f: &Finding) -> String {
    let exposure = match f.exposure {
        Exposure::Internet => "is reachable from the public internet",
        Exposure::LocalNetwork => "is reachable from the local network",
        Exposure::Localhost => "is reachable only from this machine",
        Exposure::Unknown => "has unknown reachability",
    };

    match &f.kind {
        FindingKind::OpenPort => format!(
            "The {} service on {} {}. Open ports are attack surface; anything \
             internet-facing that does not need to be is a standing risk.",
            f.component, f.asset, exposure
        ),
        FindingKind::Vulnerability => {
            let cve = if f.cve.is_empty() {
                String::new()
            } else {
                format!(" ({})", f.cve.join(", "))
            };
            let fix = match &f.fixed_version {
                Some(v) => format!(" A fixed version, {v}, is available."),
                None => String::new(),
            };
            format!(
                "{} reports a known vulnerability{cve} in {} on {}, which {}. {}{}",
                capitalize(&f.source),
                f.component,
                f.asset,
                exposure,
                f.description.trim_end_matches('.'),
                fix
            )
        }
        FindingKind::Misconfiguration => format!(
            "A configuration weakness was verified on {}: {}. Hardening gaps like \
             this are how attackers move from access to control.",
            f.asset,
            f.title.to_lowercase()
        ),
        FindingKind::Secret => format!(
            "A credential was found in {} on {}. Treat committed secrets as \
             compromised: anyone with repository access or a copy of the \
             history may hold it, and automated crawlers scan public \
             repositories continuously.",
            f.component, f.asset
        ),
        FindingKind::Other(_) => f.description.clone(),
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
