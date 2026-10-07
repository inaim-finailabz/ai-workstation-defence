//! awd -- AI Workstation Defence.
//!
//!   sudo awd watch --agents config/agents.toml        live, from macOS Endpoint Security
//!   awd watch --source replay --input examples/sample-session.jsonl --data-dir ./awd-data
//!   awd report --data-dir ./awd-data                   "did my agents touch private data?"
//!   awd verify --data-dir ./awd-data                   prove the log was not edited

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use awd_collector::{eslogger, netpoll::NetPoller, replay};
use awd_core::{AgentSpec, AgentTag, Attributor, EventKind, RawEvent};
use awd_log::{load_or_create_key, read_entries, verify, AuditLog};
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
#[command(name = "awd", version, about = "See exactly what AI agents do on this machine")]
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
    /// Check that no entry was edited, removed or reordered.
    Verify {
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

fn paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (data_dir.join("activity.log"), data_dir.join("log.key"))
}

fn watch(source: Source, input: Option<PathBuf>, agents: &Path, data_dir: &Path, home: String) -> Result<()> {
    let specs: AgentsFile = toml::from_str(
        &std::fs::read_to_string(agents).with_context(|| format!("reading {}", agents.display()))?,
    )?;
    let (log_path, key_path) = paths(data_dir);
    let key = load_or_create_key(&key_path)?;
    let mut log = AuditLog::open(&log_path, key)?;
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
    let (log_path, key_path) = paths(data_dir);
    let key = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let check = verify(&log_path, &key)?;
    if let Some(bad) = check.first_bad {
        println!("WARNING: the log was altered at entry {bad}. Entries from there on cannot be trusted.\n");
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
            println!("  Policy would have blocked {} actions.", s.blocked);
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
    println!("\nLog integrity: {} entries, {}", check.entries, if check.first_bad.is_none() { "unaltered" } else { "ALTERED" });
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Watch { source, input, agents, data_dir, home } => {
            watch(source, input, &agents, &data_dir, invoking_home(home))
        }
        Cmd::Report { data_dir, agent, all, home } => report(&data_dir, agent, all, invoking_home(home)),
        Cmd::Verify { data_dir } => {
            let (log_path, key_path) = paths(&data_dir);
            let key = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
            let r = verify(&log_path, &key)?;
            match r.first_bad {
                None => println!("OK: {} entries, chain intact", r.entries),
                Some(bad) => {
                    println!("ALTERED: the chain breaks at entry {bad} ({} entries before it are intact)", r.entries);
                    std::process::exit(2);
                }
            }
            Ok(())
        }
    }
}
