//! Local state: ~/.orbis/state.json. The whole product is local-first, so
//! v0.1 keeps everything in one small JSON file. SQLite lands with the
//! history features in v0.2.

use anyhow::{Context, Result};
use orbis_core::{merge, unix_now, Finding};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct State {
    pub saved_at: u64,
    pub demo: bool,
    pub target: String,
    pub score: u8,
    pub findings: Vec<Finding>,
}

/// ~/.orbis without external crates: USERPROFILE on Windows, HOME elsewhere.
fn orbis_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".orbis")
}

pub fn state_path() -> PathBuf {
    orbis_dir().join("state.json")
}

pub fn load() -> Option<State> {
    let path = state_path();
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save(state: &State) -> Result<()> {
    let dir = orbis_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    let path = state_path();
    let json = serde_json::to_string_pretty(state).with_context(|| "could not serialize state")?;
    std::fs::write(&path, json).with_context(|| format!("could not write {}", path.display()))
}

/// Fold a fresh scan into any existing state: IDs stay stable per fingerprint,
/// first_seen is preserved, evidence accumulates, severity ratchets up.
pub fn persist_scan(mut fresh: Vec<Finding>, target: &str, demo: bool, score: u8) -> State {
    let previous = load();
    let now = unix_now();

    if let Some(prev) = &previous {
        for f in fresh.iter_mut() {
            if let Some(stored) = prev
                .findings
                .iter()
                .find(|p| p.fingerprint == f.fingerprint)
            {
                let mut merged = stored.clone();
                merge(&mut merged, f);
                f.first_seen = merged.first_seen;
                f.evidence = merged.evidence;
                f.severity = merged.severity;
                f.confidence = merged.confidence;
            }
        }
    }

    let state = State {
        saved_at: now,
        demo,
        target: target.to_string(),
        score,
        findings: fresh,
    };
    let _ = save(&state);
    state
}
