//! Agent attribution through the process tree.
//!
//! An agent rarely acts directly: it starts a shell, which starts python,
//! which starts curl. Every descendant of an agent process inherits the
//! agent's tag, so `agent -> bash -> python -> curl` is still the agent.
//! Tags are only ever assigned from OS events (exec and fork), so an agent
//! cannot shed its tag by spawning helpers.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::event::{EventKind, RawEvent};

/// How to recognise an agent's root process.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentSpec {
    pub id: String,
    pub name: String,
    /// Executable or script base names (case-insensitive prefix match), e.g. "claude".
    pub match_any: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTag {
    pub agent_id: String,
    pub agent_name: String,
    pub root_pid: u32,
    /// 0 for the agent itself, 1 for its children, and so on.
    pub depth: u32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attribution {
    pub tag: Option<AgentTag>,
    /// Set when an agent process started another known AI agent.
    pub started_sub_agent: Option<String>,
}

pub struct Attributor {
    specs: Vec<AgentSpec>,
    tags: HashMap<u32, AgentTag>,
}

fn base_name(s: &str) -> String {
    Path::new(s)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

impl Attributor {
    pub fn new(specs: Vec<AgentSpec>) -> Self {
        Self { specs, tags: HashMap::new() }
    }

    /// Matches the executable and the first few arguments, because many
    /// agents run as `node /path/to/claude` or `python -m aider`.
    fn match_spec(&self, exe: &str, args: &[String]) -> Option<&AgentSpec> {
        let mut names = vec![base_name(exe)];
        names.extend(args.iter().take(3).map(|a| base_name(a)));
        self.specs.iter().find(|spec| {
            spec.match_any.iter().any(|m| {
                let m = m.to_lowercase();
                names.iter().any(|n| !n.is_empty() && n.starts_with(&m))
            })
        })
    }

    pub fn observe(&mut self, ev: &RawEvent) -> Attribution {
        // A process seen for the first time inherits its parent's tag.
        if !self.tags.contains_key(&ev.pid) {
            if let Some(parent) = self.tags.get(&ev.ppid).cloned() {
                self.tags.insert(ev.pid, AgentTag { depth: parent.depth + 1, ..parent });
            }
        }

        let mut started_sub_agent = None;
        match &ev.kind {
            EventKind::Exec { path, args } => {
                if let Some(spec) = self.match_spec(path, args).cloned() {
                    match self.tags.get(&ev.pid) {
                        // Already inside an agent: keep the root agent, flag the sub-agent.
                        Some(tag) if tag.agent_id != spec.id => started_sub_agent = Some(spec.name),
                        Some(_) => {}
                        None => {
                            self.tags.insert(
                                ev.pid,
                                AgentTag {
                                    agent_id: spec.id,
                                    agent_name: spec.name,
                                    root_pid: ev.pid,
                                    depth: 0,
                                },
                            );
                        }
                    }
                }
            }
            EventKind::Fork { child_pid } => {
                if let Some(tag) = self.tags.get(&ev.pid).cloned() {
                    self.tags.insert(*child_pid, AgentTag { depth: tag.depth + 1, ..tag });
                }
            }
            _ => {}
        }

        let tag = self.tags.get(&ev.pid).cloned();
        if ev.kind == EventKind::Exit {
            self.tags.remove(&ev.pid);
        }
        Attribution { tag, started_sub_agent }
    }

    /// PIDs currently attributed to an agent (used by the network poller).
    pub fn tracked_pids(&self) -> Vec<u32> {
        self.tags.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn spec(id: &str, m: &str) -> AgentSpec {
        AgentSpec { id: id.into(), name: id.into(), match_any: vec![m.into()] }
    }

    fn ev(pid: u32, ppid: u32, kind: EventKind) -> RawEvent {
        RawEvent { ts: Utc::now(), pid, ppid, exe: "/bin/x".into(), kind }
    }

    #[test]
    fn descendants_inherit_the_agent_tag() {
        let mut a = Attributor::new(vec![spec("claude", "claude")]);
        let root = a.observe(&ev(100, 1, EventKind::Exec { path: "/usr/local/bin/claude".into(), args: vec![] }));
        assert_eq!(root.tag.as_ref().unwrap().depth, 0);

        a.observe(&ev(100, 1, EventKind::Fork { child_pid: 101 }));
        a.observe(&ev(101, 100, EventKind::Exec { path: "/bin/zsh".into(), args: vec![] }));
        // Grandchild seen first through its own event, never through a fork.
        let curl = a.observe(&ev(102, 101, EventKind::FileRead { path: "/etc/hosts".into() }));
        let tag = curl.tag.unwrap();
        assert_eq!(tag.agent_id, "claude");
        assert_eq!(tag.root_pid, 100);
        assert_eq!(tag.depth, 2);
    }

    #[test]
    fn script_run_by_an_interpreter_is_recognised() {
        let mut a = Attributor::new(vec![spec("aider", "aider")]);
        let at = a.observe(&ev(
            200,
            1,
            EventKind::Exec { path: "/usr/bin/python3".into(), args: vec!["python3".into(), "/opt/bin/aider".into()] },
        ));
        assert_eq!(at.tag.unwrap().agent_id, "aider");
    }

    #[test]
    fn unrelated_processes_are_not_tagged() {
        let mut a = Attributor::new(vec![spec("claude", "claude")]);
        let at = a.observe(&ev(300, 1, EventKind::FileRead { path: "/tmp/x".into() }));
        assert!(at.tag.is_none());
    }

    #[test]
    fn agent_starting_another_agent_is_flagged_and_keeps_root() {
        let mut a = Attributor::new(vec![spec("claude", "claude"), spec("codex", "codex")]);
        a.observe(&ev(100, 1, EventKind::Exec { path: "/bin/claude".into(), args: vec![] }));
        a.observe(&ev(100, 1, EventKind::Fork { child_pid: 101 }));
        let sub = a.observe(&ev(101, 100, EventKind::Exec { path: "/bin/codex".into(), args: vec![] }));
        assert_eq!(sub.started_sub_agent.as_deref(), Some("codex"));
        assert_eq!(sub.tag.unwrap().agent_id, "claude");
    }

    #[test]
    fn exit_clears_the_tag() {
        let mut a = Attributor::new(vec![spec("claude", "claude")]);
        a.observe(&ev(100, 1, EventKind::Exec { path: "/bin/claude".into(), args: vec![] }));
        a.observe(&ev(100, 1, EventKind::Exit));
        assert!(a.tracked_pids().is_empty());
    }
}
