//! End-to-end tests: run the real `awd` binary and check it does what the
//! README says -- no more, no less.
//!
//!     cargo test --test end_to_end

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("awd-e2e-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn awd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_awd"))
        .args(args)
        .current_dir(workspace_root())
        .env_remove("SUDO_USER")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)
}

/// Replays `events` into a fresh data directory and returns it.
fn record(name: &str, events: &Path) -> PathBuf {
    let data = scratch(name).join("data");
    let out = awd(&[
        "watch", "--source", "replay", "--input", events.to_str().unwrap(),
        "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana",
    ]);
    assert!(out.status.success(), "watch failed: {}", text(&out));
    data
}

fn sample() -> PathBuf {
    workspace_root().join("examples/sample-session.jsonl")
}

#[test]
fn sample_session_reports_what_the_readme_promises() {
    let data = record("sample", &sample());
    let out = awd(&["report", "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana"]);
    let report = text(&out);
    assert!(out.status.success(), "{report}");
    for expected in [
        "Claude Code",
        "Private data: touched SSH keys (1 times)",
        "Policy would have blocked 1 actions.",
        "Alerts: 2 critical, 2 high, 1 notices",
        "(via python3) read ~/.ssh/id_ed25519",
        "changed an AI agent's own configuration",
        "changed a start-up or scheduled-task location",
        "Log integrity: 13 entries, unaltered",
    ] {
        assert!(report.contains(expected), "report is missing {expected:?}:\n{report}");
    }
}

#[test]
fn processes_that_are_not_ai_agents_are_not_recorded() {
    // The sample ends with Notes.app reading the same SSH key. It is not an
    // agent, so it must not appear: this tool watches agents, not people.
    let data = record("not-agent", &sample());
    let log = fs::read_to_string(data.join("activity.log")).unwrap();
    assert!(!log.contains("Notes.app"));
    assert_eq!(log.lines().count(), 13);
}

#[test]
fn file_contents_never_reach_the_log() {
    let dir = scratch("contents");
    let secret = dir.join("secret.txt");
    let marker = format!("TOP-SECRET-CONTENT-{}", std::process::id());
    fs::write(&secret, &marker).unwrap();

    let events = dir.join("events.jsonl");
    // JSON-quoted, so Windows back-slashes are escaped the same way the log stores them.
    let quoted = serde_json::to_string(secret.to_str().unwrap()).unwrap();
    let path = quoted.trim_matches('"');
    fs::write(
        &events,
        format!(
            "{{\"ts\":\"2026-10-07T09:00:00Z\",\"pid\":10,\"ppid\":1,\"exe\":\"/bin/zsh\",\"kind\":\"exec\",\"path\":\"/usr/local/bin/claude\",\"args\":[\"claude\"]}}\n\
             {{\"ts\":\"2026-10-07T09:00:01Z\",\"pid\":10,\"ppid\":1,\"exe\":\"/usr/local/bin/claude\",\"kind\":\"file_read\",\"path\":\"{path}\"}}\n\
             {{\"ts\":\"2026-10-07T09:00:02Z\",\"pid\":10,\"ppid\":1,\"exe\":\"/usr/local/bin/claude\",\"kind\":\"file_write\",\"path\":\"{path}\"}}\n"
        ),
    )
    .unwrap();

    let data = record("contents-data", &events);
    let log = fs::read_to_string(data.join("activity.log")).unwrap();
    assert!(log.contains(path), "the path should be recorded");
    assert!(!log.contains(&marker), "file contents leaked into the log");
}

#[cfg(unix)]
#[test]
fn log_and_key_are_private_to_their_owner() {
    use std::os::unix::fs::PermissionsExt;
    let data = record("perms", &sample());
    let mode = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(data.clone()), 0o700, "data directory");
    assert_eq!(mode(data.join("log.key")), 0o600, "log key");
    assert_eq!(mode(data.join("activity.log")), 0o600, "activity log");
}

#[test]
fn an_unaltered_log_verifies() {
    let data = record("verify-ok", &sample());
    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(text(&out).contains("OK: 13 entries, chain intact"));
}

#[test]
fn editing_one_character_is_detected() {
    let data = record("verify-edit", &sample());
    let log = data.join("activity.log");
    let edited = fs::read_to_string(&log).unwrap().replacen("cart.ts", "cart.js", 1);
    fs::write(&log, edited).unwrap();

    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out).contains("ALTERED"));

    let report = awd(&["report", "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana"]);
    assert!(text(&report).contains("WARNING: the log was altered"));
}

#[test]
fn deleting_a_line_is_detected() {
    let data = record("verify-delete", &sample());
    let log = data.join("activity.log");
    let kept: Vec<String> = fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
    // Remove the line that recorded reading the SSH key.
    let without: Vec<&String> = kept.iter().filter(|l| !l.contains("id_ed25519\"")).collect();
    assert!(without.len() < kept.len());
    fs::write(&log, without.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();

    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

#[test]
fn a_log_forged_without_the_key_is_detected() {
    let data = record("verify-forge", &sample());
    // Replace the key with a different one: every existing entry now fails.
    fs::write(data.join("log.key"), b"a-key-an-attacker-guessed-0000000").unwrap();
    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out).contains("breaks at entry 0"));
}
