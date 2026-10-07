//! Turns a recorded event into one plain-language sentence a non-expert can read.

use awd_core::{AgentTag, EventKind, RawEvent};

use crate::rules::{Decision, Severity, Verdict};

fn short(path: &str, home: &str) -> String {
    match path.strip_prefix(home) {
        Some(rest) => format!("~{rest}"),
        None => path.to_string(),
    }
}

fn program(exe: &str) -> &str {
    exe.rsplit('/').next().unwrap_or(exe)
}

pub fn explain(ev: &RawEvent, tag: &AgentTag, verdict: &Verdict, home: &str) -> String {
    let who = if tag.depth == 0 {
        tag.agent_name.clone()
    } else {
        format!("{} (via {})", tag.agent_name, program(&ev.exe))
    };
    let what = match &ev.kind {
        EventKind::Exec { path, args } => {
            let shown: Vec<&str> = args.iter().skip(1).take(4).map(String::as_str).collect();
            if shown.is_empty() {
                format!("ran {}", program(path))
            } else {
                format!("ran {} {}", program(path), shown.join(" "))
            }
        }
        EventKind::Fork { .. } => "started a child process".into(),
        EventKind::Exit => "finished".into(),
        EventKind::FileRead { path } => format!("read {}", short(path, home)),
        EventKind::FileWrite { path } => format!("wrote {}", short(path, home)),
        EventKind::FileCreate { path } => format!("created {}", short(path, home)),
        EventKind::FileRename { from, to } => format!("moved {} to {}", short(from, home), short(to, home)),
        EventKind::FileDelete { path } => format!("deleted {}", short(path, home)),
        EventKind::PersistenceAdded { item } => format!("registered a start-up item {item}"),
        EventKind::NetConnect { remote, port } => format!("connected to {remote}:{port}"),
        EventKind::PrivacyPermissionChanged { service } => format!("changed privacy permission {service}"),
    };

    let mut line = format!("[{}] {who} {what}", ev.ts.format("%H:%M:%S"));
    if let Some(top) = verdict.alerts.iter().max_by_key(|a| a.severity) {
        let level = match top.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "NOTICE",
            Severity::Info => "INFO",
        };
        line.push_str(&format!(" -- {level}: {}", top.message));
    }
    if verdict.decision == Decision::Block {
        line.push_str(" [policy: BLOCK -- recorded; enforcement arrives in v1]");
    }
    line
}
