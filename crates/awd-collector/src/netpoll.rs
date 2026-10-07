//! Outbound connections of agent processes.
//!
//! Endpoint Security has no TCP connect event, so v0 polls `lsof` for the
//! PIDs currently attributed to agents. Short connections between polls can
//! be missed; v1 uses a Network Extension content filter (macOS) or eBPF
//! (Linux) to see every connection.

use std::collections::HashSet;
use std::process::Command;

use awd_core::{EventKind, RawEvent};
use chrono::Utc;

/// Parses `lsof -F pcn` output into (pid, command, remote host, remote port).
pub fn parse_lsof(output: &str) -> Vec<(u32, String, String, u16)> {
    let mut out = Vec::new();
    let mut pid = 0u32;
    let mut cmd = String::new();
    for line in output.lines() {
        let (tag, rest) = line.split_at(line.len().min(1));
        match tag {
            "p" => pid = rest.parse().unwrap_or(0),
            "c" => cmd = rest.to_string(),
            "n" => {
                // "10.0.0.2:51234->140.82.112.3:443"
                if let Some((_, remote)) = rest.split_once("->") {
                    if let Some((host, port)) = remote.rsplit_once(':') {
                        if let Ok(port) = port.parse() {
                            out.push((pid, cmd.clone(), host.trim_matches(['[', ']']).to_string(), port));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Remembers which connections were already reported.
#[derive(Default)]
pub struct NetPoller {
    seen: HashSet<(u32, String, u16)>,
}

impl NetPoller {
    pub fn poll(&mut self, pids: &[u32]) -> Vec<RawEvent> {
        if pids.is_empty() {
            return Vec::new();
        }
        let list: Vec<String> = pids.iter().map(u32::to_string).collect();
        let Ok(out) = Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a", "-p", &list.join(","), "-F", "pcn"])
            .output()
        else {
            return Vec::new();
        };
        parse_lsof(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .filter(|(pid, _, host, port)| self.seen.insert((*pid, host.clone(), *port)))
            .map(|(pid, cmd, remote, port)| RawEvent {
                ts: Utc::now(),
                pid,
                ppid: 0,
                exe: cmd,
                kind: EventKind::NetConnect { remote, port },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_established_connections() {
        let out = "p501\nccurl\nn10.0.0.2:51234->140.82.112.3:443\np502\ncnode\nn[::1]:5000->[2606:4700::1]:443\n";
        let r = parse_lsof(out);
        assert_eq!(r[0], (501, "curl".into(), "140.82.112.3".into(), 443));
        assert_eq!(r[1].2, "2606:4700::1");
    }
}
