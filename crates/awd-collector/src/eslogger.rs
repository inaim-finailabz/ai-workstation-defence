//! macOS source: Apple's `eslogger` (macOS 13+), which streams Endpoint
//! Security events as JSON. It needs root and Full Disk Access for the
//! terminal, but no Apple entitlement -- so v0 gets real, per-process,
//! kernel-sourced events today. v1 replaces it with a native Endpoint
//! Security client, which adds AUTH events and therefore real blocking.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

use anyhow::{Context, Result};
use awd_core::{EventKind, RawEvent};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// Endpoint Security events we subscribe to.
pub const EVENTS: &[&str] = &[
    "exec",
    "fork",
    "exit",
    "open",
    "create",
    "rename",
    "unlink",
    "btm_launch_item_add",
    "tcc_modify",
];

const FWRITE: i64 = 0x2;

fn s(v: &Value, ptr: &str) -> Option<String> {
    v.pointer(ptr).and_then(Value::as_str).map(String::from)
}

fn u(v: &Value, ptr: &str) -> Option<u32> {
    v.pointer(ptr).and_then(Value::as_u64).map(|n| n as u32)
}

/// Destination of create/rename: either an existing file or dir + filename.
fn destination(ev: &Value) -> Option<String> {
    s(ev, "/destination/existing_file/path").or_else(|| {
        let dir = s(ev, "/destination/new_path/dir/path")?;
        let name = s(ev, "/destination/new_path/filename")?;
        Some(format!("{}/{}", dir.trim_end_matches('/'), name))
    })
}

/// Parses one line of `eslogger --format json` output. Unknown or
/// malformed events return `None` rather than failing the stream.
pub fn parse_line(line: &str) -> Option<RawEvent> {
    let v: Value = serde_json::from_str(line).ok()?;
    let pid = u(&v, "/process/audit_token/pid")?;
    let ppid = u(&v, "/process/ppid").unwrap_or(0);
    let exe = s(&v, "/process/executable/path").unwrap_or_default();
    let ts = s(&v, "/time")
        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    let event = v.get("event")?.as_object()?;
    let (name, ev) = event.iter().next()?;
    let kind = match name.as_str() {
        "exec" => EventKind::Exec {
            path: s(ev, "/target/executable/path")?,
            args: ev
                .get("args")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
        },
        "fork" => EventKind::Fork { child_pid: u(ev, "/child/audit_token/pid")? },
        "exit" => EventKind::Exit,
        "open" => {
            let path = s(ev, "/file/path")?;
            let flags = ev.get("fflag").and_then(Value::as_i64).unwrap_or(0);
            if flags & FWRITE != 0 {
                EventKind::FileWrite { path }
            } else {
                EventKind::FileRead { path }
            }
        }
        "create" => EventKind::FileCreate { path: destination(ev)? },
        "rename" => EventKind::FileRename { from: s(ev, "/source/path")?, to: destination(ev)? },
        "unlink" => EventKind::FileDelete { path: s(ev, "/target/path")? },
        "btm_launch_item_add" => EventKind::PersistenceAdded {
            item: s(ev, "/item/item_url")
                .or_else(|| s(ev, "/executable_path"))
                .unwrap_or_else(|| "unknown item".into()),
        },
        "tcc_modify" => EventKind::PrivacyPermissionChanged {
            service: s(ev, "/service").unwrap_or_else(|| "unknown".into()),
        },
        _ => return None,
    };
    Some(RawEvent { ts, pid, ppid, exe, kind })
}

/// Runs `eslogger` and forwards parsed events until it exits.
pub fn run(tx: Sender<RawEvent>) -> Result<()> {
    let mut child = Command::new("eslogger")
        .args(EVENTS)
        .args(["--format", "json"])
        .stdout(Stdio::piped())
        .spawn()
        .context("could not start eslogger (needs macOS 13+, root, and Full Disk Access for this terminal)")?;
    let stdout = child.stdout.take().context("eslogger has no stdout")?;
    for line in BufReader::new(stdout).lines() {
        if let Some(ev) = parse_line(&line?) {
            if tx.send(ev).is_err() {
                break;
            }
        }
    }
    let _ = child.kill();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_with_args() {
        let line = r#"{"time":"2026-10-07T10:00:00.000000Z","process":{"audit_token":{"pid":42},"ppid":1,"executable":{"path":"/bin/zsh"}},"event":{"exec":{"target":{"executable":{"path":"/usr/bin/curl"}},"args":["curl","https://example.com"]}}}"#;
        let ev = parse_line(line).unwrap();
        assert_eq!(ev.pid, 42);
        assert_eq!(
            ev.kind,
            EventKind::Exec { path: "/usr/bin/curl".into(), args: vec!["curl".into(), "https://example.com".into()] }
        );
    }

    #[test]
    fn open_with_write_flag_is_a_write() {
        let line = r#"{"process":{"audit_token":{"pid":7},"ppid":1,"executable":{"path":"/bin/cat"}},"event":{"open":{"file":{"path":"/tmp/a"},"fflag":3}}}"#;
        assert_eq!(parse_line(line).unwrap().kind, EventKind::FileWrite { path: "/tmp/a".into() });
    }

    #[test]
    fn create_with_new_path() {
        let line = r#"{"process":{"audit_token":{"pid":7},"ppid":1,"executable":{"path":"/bin/cp"}},"event":{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/a/Library/LaunchAgents"},"filename":"x.plist"}}}}}"#;
        assert_eq!(
            parse_line(line).unwrap().kind,
            EventKind::FileCreate { path: "/Users/a/Library/LaunchAgents/x.plist".into() }
        );
    }

    #[test]
    fn fork_child_pid() {
        let line = r#"{"process":{"audit_token":{"pid":7},"ppid":1,"executable":{"path":"/bin/zsh"}},"event":{"fork":{"child":{"audit_token":{"pid":8}}}}}"#;
        assert_eq!(parse_line(line).unwrap().kind, EventKind::Fork { child_pid: 8 });
    }

    #[test]
    fn unknown_or_malformed_lines_are_skipped() {
        assert!(parse_line("not json").is_none());
        let line = r#"{"process":{"audit_token":{"pid":7},"ppid":1,"executable":{"path":"/bin/x"}},"event":{"mmap":{}}}"#;
        assert!(parse_line(line).is_none());
    }
}
