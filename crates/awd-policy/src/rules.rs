//! Red-line rules. Fixed and deterministic on purpose: no model sits in the
//! decision path, so nothing an agent writes can talk a rule out of firing.

use std::collections::{HashMap, HashSet};

use awd_core::{Attribution, EventKind, RawEvent};
use serde::{Deserialize, Serialize};

use crate::classify::{classify, Category};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub rule: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    /// The policy says block. In v0 this is recorded, not yet enforced
    /// (enforcement needs Endpoint Security AUTH events on macOS).
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub category: Option<Category>,
    pub alerts: Vec<Alert>,
    pub decision: Decision,
}

pub struct Policy {
    home: String,
    defence_dir: String,
    seen_destinations: HashMap<String, HashSet<String>>,
}

fn alert(rule: &str, severity: Severity, message: String) -> Alert {
    Alert { rule: rule.into(), severity, message }
}

impl Policy {
    pub fn new(home: impl Into<String>, defence_dir: impl Into<String>) -> Self {
        Self { home: home.into(), defence_dir: defence_dir.into(), seen_destinations: HashMap::new() }
    }

    pub fn evaluate(&mut self, ev: &RawEvent, attr: &Attribution) -> Verdict {
        let mut alerts = Vec::new();
        let mut decision = Decision::Allow;
        let mut category = None;
        let agent = attr.tag.as_ref().map(|t| t.agent_name.as_str()).unwrap_or("A process");

        for path in ev.kind.paths() {
            let Some(cat) = classify(path, &self.home, &self.defence_dir) else { continue };
            category = Some(cat);
            if cat.is_crown_jewel() {
                decision = Decision::Block;
                alerts.push(alert("crown-jewel-access", Severity::Critical, format!("{agent} touched {}", cat.describe())));
            } else {
                match cat {
                    Category::DefenceItself => {
                        decision = Decision::Block;
                        alerts.push(alert("defence-tamper", Severity::Critical, format!("{agent} touched {}", cat.describe())));
                    }
                    Category::ShellHistory | Category::EnvSecrets => {
                        alerts.push(alert("secret-adjacent", Severity::High, format!("{agent} touched {}", cat.describe())));
                    }
                    Category::AgentConfig if ev.kind.is_modification() => {
                        alerts.push(alert("self-modification", Severity::High, format!("{agent} changed {}", cat.describe())));
                    }
                    Category::PersistenceLocation if ev.kind.is_modification() => {
                        alerts.push(alert("persistence", Severity::Critical, format!("{agent} changed {}", cat.describe())));
                    }
                    _ => {}
                }
            }
        }

        match &ev.kind {
            EventKind::PersistenceAdded { item } => {
                alerts.push(alert("persistence", Severity::Critical, format!("{agent} registered a start-up item: {item}")));
            }
            EventKind::PrivacyPermissionChanged { service } => {
                alerts.push(alert("privacy-permission", Severity::Critical, format!("A privacy permission changed: {service}")));
            }
            EventKind::NetConnect { remote, port } => {
                let key = attr.tag.as_ref().map(|t| t.agent_id.clone()).unwrap_or_default();
                if self.seen_destinations.entry(key).or_default().insert(format!("{remote}:{port}")) {
                    alerts.push(alert("new-destination", Severity::Medium, format!("{agent} connected to a new destination: {remote}:{port}")));
                }
            }
            _ => {}
        }

        if let Some(sub) = &attr.started_sub_agent {
            alerts.push(alert("sub-agent", Severity::High, format!("{agent} started another AI agent: {sub}")));
        }

        Verdict { category, alerts, decision }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use awd_core::AgentTag;
    use chrono::Utc;

    fn tagged() -> Attribution {
        Attribution {
            tag: Some(AgentTag { agent_id: "claude".into(), agent_name: "Claude Code".into(), root_pid: 1, depth: 1 }),
            started_sub_agent: None,
        }
    }

    fn ev(kind: EventKind) -> RawEvent {
        RawEvent { ts: Utc::now(), pid: 2, ppid: 1, exe: "/bin/cat".into(), kind }
    }

    #[test]
    fn crown_jewel_read_is_critical_and_blocked() {
        let mut p = Policy::new("/Users/ana", "/var/awd");
        let v = p.evaluate(&ev(EventKind::FileRead { path: "/Users/ana/.ssh/id_rsa".into() }), &tagged());
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn project_file_read_is_quiet() {
        let mut p = Policy::new("/Users/ana", "/var/awd");
        let v = p.evaluate(&ev(EventKind::FileRead { path: "/Users/ana/code/a.rs".into() }), &tagged());
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.alerts.is_empty());
    }

    #[test]
    fn reading_own_config_is_fine_but_editing_it_alerts() {
        let mut p = Policy::new("/Users/ana", "/var/awd");
        let read = p.evaluate(&ev(EventKind::FileRead { path: "/Users/ana/.claude/settings.json".into() }), &tagged());
        assert!(read.alerts.is_empty());
        let write = p.evaluate(&ev(EventKind::FileWrite { path: "/Users/ana/.claude/settings.json".into() }), &tagged());
        assert_eq!(write.alerts[0].rule, "self-modification");
    }

    #[test]
    fn new_destination_alerts_once() {
        let mut p = Policy::new("/Users/ana", "/var/awd");
        let e = ev(EventKind::NetConnect { remote: "203.0.113.9".into(), port: 443 });
        assert_eq!(p.evaluate(&e, &tagged()).alerts.len(), 1);
        assert!(p.evaluate(&e, &tagged()).alerts.is_empty());
    }

    #[test]
    fn touching_the_defence_is_blocked() {
        let mut p = Policy::new("/Users/ana", "/var/awd");
        let v = p.evaluate(&ev(EventKind::FileDelete { path: "/var/awd/activity.log".into() }), &tagged());
        assert_eq!(v.decision, Decision::Block);
        assert_eq!(v.alerts[0].rule, "defence-tamper");
    }
}
