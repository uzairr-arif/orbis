//! orbis: security visibility and remediation, local-first.
//!
//! v0.1 commands: scan, findings, show, explain, report.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use orbis_cli::store;
use orbis_cli::{explain, report};
use orbis_core::Severity;

#[derive(Parser)]
#[command(
    name = "orbis",
    version,
    about = "Security visibility and remediation, local-first",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run every available collector and store the normalized findings
    Scan {
        /// Host, image, or repository path to scan
        #[arg(short, long, default_value = "localhost")]
        target: String,
        /// Use bundled fixtures instead of real tools (works offline)
        #[arg(long)]
        demo: bool,
    },
    /// List stored findings
    Findings {
        /// Only show findings at this severity or above
        #[arg(short, long)]
        severity: Option<SeverityArg>,
    },
    /// Show full detail for one finding
    Show { id: String },
    /// Explain one finding in plain language
    Explain { id: String },
    /// Print the security overview again
    Report {
        /// Machine-readable JSON state
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
}

impl SeverityArg {
    fn as_severity(self) -> Severity {
        match self {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli.command) {
        eprintln!("{} {e:#}", "error:".truecolor(237, 106, 77).bold());
        std::process::exit(1);
    }
}

fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Scan { target, demo } => scan(&target, demo),
        Command::Findings { severity } => findings(severity),
        Command::Show { id } => with_finding(&id, report::show),
        Command::Explain { id } => with_finding(&id, |f| {
            let risk = orbis_risk::assess(f);
            explain::explain(f, &risk);
        }),
        Command::Report { json } => report_cmd(json),
    }
}

fn scan(target: &str, demo: bool) -> Result<()> {
    println!("{}", "orbis scan".bold());
    println!();

    let outcome = orbis_cli::scan(target, demo);

    for cr in &outcome.reports {
        use orbis_scanner::RunStatus;
        match &cr.status {
            RunStatus::Ok => println!(
                "  {}  {:<10}  {} findings",
                "-".truecolor(82, 207, 162),
                cr.name,
                cr.findings
            ),
            RunStatus::Unavailable => println!(
                "  {}  {:<10}  not installed, skipped",
                "-".truecolor(124, 138, 133),
                cr.name
            ),
            RunStatus::Failed(e) => {
                println!("  {}  {:<10}  {}", "!".truecolor(237, 106, 77), cr.name, e)
            }
        }
    }
    println!();

    let state = store::persist_scan(outcome.findings, &outcome.target, demo, outcome.score);

    println!(
        "{} {}",
        "state:".truecolor(124, 138, 133),
        store::state_path().display()
    );
    println!();
    report::overview(&state);
    Ok(())
}

fn findings(severity: Option<SeverityArg>) -> Result<()> {
    let state = require_state()?;
    let mut list: Vec<_> = state.findings.clone();

    if let Some(min) = severity {
        let floor = min.as_severity();
        list.retain(|f| f.severity <= floor);
    }

    // Most severe first.
    list.sort_by_key(|f| f.severity);
    report::findings_table(&list);
    Ok(())
}

fn report_cmd(json: bool) -> Result<()> {
    let state = require_state()?;
    if json {
        let out = serde_json::to_string_pretty(&state).context("could not serialize state")?;
        println!("{out}");
    } else {
        report::overview(&state);
    }
    Ok(())
}

fn require_state() -> Result<store::State> {
    store::load().ok_or_else(|| {
        anyhow::anyhow!(
            "no state yet. Run `orbis scan` first (or `orbis scan --demo` to try it offline)."
        )
    })
}

fn with_finding<F>(id: &str, render: F) -> Result<()>
where
    F: FnOnce(&orbis_core::Finding),
{
    let state = require_state()?;
    let wanted = id.to_ascii_uppercase();
    let finding = state
        .findings
        .iter()
        .find(|f| f.id.to_ascii_uppercase() == wanted)
        .with_context(|| format!("no finding named {id}. Try `orbis findings`"))?;
    render(finding);
    Ok(())
}
