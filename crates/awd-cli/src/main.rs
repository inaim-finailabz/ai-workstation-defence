//! awd -- AI Workstation Defence.
//!
//!   sudo awd watch --agents config/agents.toml        live, from macOS Endpoint Security
//!   awd watch --source replay --input examples/sample-session.jsonl --data-dir ./awd-data
//!   awd report --data-dir ./awd-data                   "did my agents touch private data?"
//!   awd verify --data-dir ./awd-data                   check the log was not edited or cut short
//!   awd anchor --data-dir ./awd-data                   print a fingerprint to keep off this machine

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use awd_collector::{eslogger, netpoll::NetPoller, replay};
use awd_core::{AgentSpec, AgentTag, Attributor, EventKind, RawEvent};
use awd_log::{check_anchor, check_head, load_or_create_key, read_entries, verify, Anchor, AnchorCheck, AuditLog, LogError};
use awd_policy::{explain, Decision, Policy, Severity, Verdict};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
const DEFAULT_DATA_DIR: &str = "/Library/Application Support/AIWorkstationDefence";
#[cfg(target_os = "linux")]
const DEFAULT_DATA_DIR: &str = "/var/lib/ai-workstation-defence";
#[cfg(windows)]
const DEFAULT_DATA_DIR: &str = r"C:\ProgramData\AIWorkstationDefence";
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
const DEFAULT_DATA_DIR: &str = "awd-data";

#[derive(Parser)]
#[command(name = "awd", version, about = "Record and explain what AI agents do on this machine, as the operating system reports it")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Source {
    /// Live events from macOS Endpoint Security (root required).
    Eslogger,
    /// A recorded JSON-lines file of events.
    Replay,
}

#[derive(Subcommand)]
enum Cmd {
    /// Record agent activity to the tamper-evident log and print it in plain language.
    Watch {
        #[arg(long, value_enum, default_value = "eslogger")]
        source: Source,
        #[arg(long, required_if_eq("source", "replay"))]
        input: Option<PathBuf>,
        #[arg(long, default_value = "config/agents.toml")]
        agents: PathBuf,
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        /// Home directory of the person being protected (default: the invoking user's).
        #[arg(long)]
        home: Option<String>,
        /// One-time upgrade for a log written before head records existed:
        /// accept the log as it stands and give it its first head record.
        #[arg(long)]
        adopt_existing_log: bool,
    },
    /// Plain-language summary: what each agent did and what private data it touched.
    Report {
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        #[arg(long)]
        agent: Option<String>,
        /// Print every recorded action, not only the summary and alerts.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        home: Option<String>,
    },
    /// Check that no entry was edited, removed, reordered or cut off the end.
    Verify {
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        /// An anchor printed earlier by `awd anchor` and kept off this machine.
        /// Catches a log that was rolled back or rewritten together with its head record.
        #[arg(long, value_name = "ENTRIES:MAC")]
        anchor: Option<Anchor>,
    },
    /// Print the log's current anchor (entry count and last MAC). Keep it
    /// somewhere agents on this machine cannot write, and pass it to `verify` later.
    Anchor {
        #[arg(long, default_value = DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
    },
}

#[derive(Deserialize)]
struct AgentsFile {
    agent: Vec<AgentSpec>,
}

/// One log entry's body.
#[derive(Serialize, Deserialize)]
struct Record {
    event: RawEvent,
    agent: AgentTag,
    verdict: Verdict,
}

/// Under sudo, protect the person who ran the command, not root.
fn invoking_home(explicit: Option<String>) -> String {
    if let Some(h) = explicit {
        return h;
    }
    if let Ok(user) = std::env::var("SUDO_USER") {
        let base = if cfg!(target_os = "macos") { "/Users" } else { "/home" };
        return format!("{base}/{user}");
    }
    std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_default()
}

/// The activity log, its MAC key and its head record.
fn paths(data_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (data_dir.join("activity.log"), data_dir.join("log.key"), data_dir.join("log.head"))
}

/// The result of checking the chain, the head record and, if given, an outside anchor.
struct Integrity {
    entries: u64,
    last_mac: String,
    /// Plain-language description of the first thing that failed.
    problem: Option<String>,
}

fn integrity(data_dir: &Path, anchor: Option<&Anchor>) -> Result<Integrity> {
    let (log_path, key_path, head_path) = paths(data_dir);
    let key = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let (entries, last_mac, mut problem) = if log_path.exists() {
        let r = verify(&log_path, &key)?;
        let broken = r.first_bad.map(|bad| {
            format!("ALTERED: the chain breaks at entry {bad} ({} entries before it are intact)", r.entries)
        });
        (r.entries, r.last_mac, broken)
    } else {
        (0, String::new(), None)
    };
    if problem.is_none() {
        problem = match check_head(&log_path, &head_path, &key) {
            Ok(AnchorCheck::Holds) => None,
            Ok(AnchorCheck::Truncated { found }) => Some(format!(
                "CUT SHORT: the log holds {found} entries, fewer than its head record counts. The newest entries were removed."
            )),
            Ok(AnchorCheck::Rewritten) => {
                Some("ALTERED: the log no longer contains the entry its head record points to.".into())
            }
            Err(LogError::HeadMissing) => Some(
                "NO HEAD RECORD: the log has entries but its head record is gone, so cut-off entries cannot be ruled out. \
                 If this log was written by an older awd, run `awd watch --adopt-existing-log` once."
                    .into(),
            ),
            Err(LogError::HeadInvalid) => {
                Some("ALTERED: the head record is damaged or was not written with this log's key.".into())
            }
            Err(e) => return Err(e.into()),
        };
    }
    if let (None, Some(anchor)) = (&problem, anchor) {
        problem = match check_anchor(&log_path, anchor)? {
            AnchorCheck::Holds => None,
            AnchorCheck::Truncated { found } => Some(format!(
                "CUT SHORT: your anchor counts {} entries but the log holds {found}. The log was rolled back.",
                anchor.entries
            )),
            AnchorCheck::Rewritten => Some(format!(
                "REWRITTEN: entry {} is not the one your anchor recorded. The log was replaced.",
                anchor.entries - 1
            )),
        };
    }
    Ok(Integrity { entries, last_mac, problem })
}

fn watch(
    source: Source,
    input: Option<PathBuf>,
    agents: &Path,
    data_dir: &Path,
    home: String,
    adopt_existing_log: bool,
) -> Result<()> {
    let specs: AgentsFile = toml::from_str(
        &std::fs::read_to_string(agents).with_context(|| format!("reading {}", agents.display()))?,
    )?;
    let (log_path, key_path, head_path) = paths(data_dir);
    let key = load_or_create_key(&key_path)?;
    if adopt_existing_log && log_path.exists() && !head_path.exists() {
        let anchor = AuditLog::adopt(&log_path, &head_path, &key)?;
        eprintln!("awd: accepted the existing log as it stands ({} entries) and wrote its first head record", anchor.entries);
    }
    let mut log = AuditLog::open(&log_path, &head_path, key)?;
    let mut attributor = Attributor::new(specs.agent);
    let mut policy = Policy::new(home.clone(), data_dir.to_string_lossy());

    let (tx, rx) = mpsc::channel::<RawEvent>();
    let tracked: Arc<Mutex<Vec<u32>>> = Arc::default();
    match source {
        Source::Replay => {
            let events = replay::read(input.as_deref().context("--input is required")?)?;
            thread::spawn(move || events.into_iter().for_each(|e| drop(tx.send(e))));
        }
        Source::Eslogger => {
            if !cfg!(target_os = "macos") {
                bail!("the eslogger source is macOS only; Linux (eBPF) and Windows (ETW) sources are on the roadmap");
            }
            let es_tx = tx.clone();
            thread::spawn(move || {
                if let Err(e) = eslogger::run(es_tx) {
                    eprintln!("awd: {e:#}");
                    std::process::exit(1);
                }
            });
            let pids = Arc::clone(&tracked);
            thread::spawn(move || {
                let mut poller = NetPoller::default();
                loop {
                    thread::sleep(Duration::from_secs(3));
                    let current = pids.lock().map(|p| p.clone()).unwrap_or_default();
                    for ev in poller.poll(&current) {
                        if tx.send(ev).is_err() {
                            return;
                        }
                    }
                }
            });
            eprintln!("awd: watching AI agents (Ctrl+C to stop). Log: {}", log_path.display());
            eprintln!("awd: this version records and alerts only. It does not block anything.");
        }
    }

    for ev in rx {
        let attribution = attributor.observe(&ev);
        if matches!(ev.kind, EventKind::Exec { .. } | EventKind::Fork { .. } | EventKind::Exit) {
            if let Ok(mut p) = tracked.lock() {
                *p = attributor.tracked_pids();
            }
        }
        let Some(tag) = attribution.tag.clone() else { continue };
        let verdict = policy.evaluate(&ev, &attribution);
        if !matches!(ev.kind, EventKind::Fork { .. } | EventKind::Exit) {
            println!("{}", explain(&ev, &tag, &verdict, &home));
        }
        log.append(&Record { event: ev, agent: tag, verdict })?;
    }
    Ok(())
}

fn report(data_dir: &Path, agent: Option<String>, all: bool, home: String) -> Result<()> {
    let (log_path, _, _) = paths(data_dir);
    let check = integrity(data_dir, None)?;
    if let Some(problem) = &check.problem {
        println!("WARNING: the log failed its integrity check. What follows cannot be trusted as complete.\n  {problem}\n");
    }
    if !log_path.exists() {
        println!("No AI agent activity recorded yet.");
        return Ok(());
    }

    #[derive(Default)]
    struct Summary {
        actions: usize,
        files_read: BTreeSet<String>,
        files_changed: BTreeSet<String>,
        programs: BTreeSet<String>,
        destinations: BTreeSet<String>,
        private: BTreeMap<&'static str, usize>,
        blocked: usize,
        alerts: BTreeMap<Severity, usize>,
    }
    let mut by_agent: BTreeMap<String, Summary> = BTreeMap::new();
    let mut lines = Vec::new();

    for entry in read_entries(&log_path)? {
        let Ok(rec) = serde_json::from_value::<Record>(entry.body) else { continue };
        if agent.as_deref().is_some_and(|a| a != rec.agent.agent_id) {
            continue;
        }
        let s = by_agent.entry(rec.agent.agent_name.clone()).or_default();
        match &rec.event.kind {
            EventKind::Fork { .. } | EventKind::Exit => continue,
            EventKind::FileRead { path } => {
                s.files_read.insert(path.clone());
            }
            EventKind::FileWrite { path } | EventKind::FileCreate { path } | EventKind::FileDelete { path } => {
                s.files_changed.insert(path.clone());
            }
            EventKind::FileRename { to, .. } => {
                s.files_changed.insert(to.clone());
            }
            EventKind::Exec { path, .. } => {
                s.programs.insert(path.rsplit('/').next().unwrap_or(path).to_string());
            }
            EventKind::NetConnect { remote, port } => {
                s.destinations.insert(format!("{remote}:{port}"));
            }
            _ => {}
        }
        s.actions += 1;
        if let Some(cat) = rec.verdict.category.filter(|c| c.is_crown_jewel()) {
            *s.private.entry(cat.describe()).or_default() += 1;
        }
        if rec.verdict.decision == Decision::Block {
            s.blocked += 1;
        }
        for a in &rec.verdict.alerts {
            *s.alerts.entry(a.severity).or_default() += 1;
        }
        if all || !rec.verdict.alerts.is_empty() {
            lines.push(explain(&rec.event, &rec.agent, &rec.verdict, &home));
        }
    }

    if by_agent.is_empty() {
        println!("No AI agent activity recorded yet.");
        return Ok(());
    }
    for (name, s) in &by_agent {
        println!("{name}");
        println!(
            "  {} actions: read {} files, changed {} files, ran {} programs, contacted {} destinations",
            s.actions,
            s.files_read.len(),
            s.files_changed.len(),
            s.programs.len(),
            s.destinations.len()
        );
        if s.private.is_empty() {
            println!("  Private data: none of the protected stores were touched.");
        } else {
            for (what, n) in &s.private {
                println!("  Private data: touched {what} ({n} times)");
            }
        }
        if s.blocked > 0 {
            println!("  Not blocked: {} actions the policy marks for blocking went ahead (this version only records).", s.blocked);
        }
        let count = |sev| s.alerts.get(&sev).copied().unwrap_or(0);
        println!(
            "  Alerts: {} critical, {} high, {} notices",
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium)
        );
        println!();
    }
    if !lines.is_empty() {
        println!("{}", if all { "Everything recorded:" } else { "What needs your attention:" });
        for l in lines {
            println!("  {l}");
        }
    }
    let state = if check.problem.is_none() { "chain and head record intact" } else { "FAILED (see the warning above)" };
    println!("\nLog integrity: {} entries, {state}", check.entries);
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Watch { source, input, agents, data_dir, home, adopt_existing_log } => {
            watch(source, input, &agents, &data_dir, invoking_home(home), adopt_existing_log)
        }
        Cmd::Report { data_dir, agent, all, home } => report(&data_dir, agent, all, invoking_home(home)),
        Cmd::Verify { data_dir, anchor } => {
            let check = integrity(&data_dir, anchor.as_ref())?;
            if let Some(problem) = check.problem {
                println!("{problem}");
                std::process::exit(2);
            }
            let anchored = if anchor.is_some() { ", anchor holds" } else { "" };
            println!("OK: {} entries, chain intact, head record matches{anchored}", check.entries);
            Ok(())
        }
        Cmd::Anchor { data_dir } => {
            let check = integrity(&data_dir, None)?;
            if let Some(problem) = check.problem {
                bail!("not printing an anchor for a log that fails its check. {problem}");
            }
            println!("{}", Anchor { entries: check.entries, last_mac: check.last_mac });
            Ok(())
        }
    }
}
