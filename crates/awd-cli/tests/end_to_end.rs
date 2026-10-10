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
        "Not blocked: 1 actions the policy marks for blocking went ahead (this version only records).",
        "[policy: WOULD BLOCK -- not enforced in this version, the action went ahead]",
        "Alerts: 2 critical, 2 high, 1 notices",
        "(via python3) read ~/.ssh/id_ed25519",
        "changed an AI agent's own configuration",
        "changed a start-up or scheduled-task location",
        "Log integrity: 13 entries, chain and head record intact",
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
    assert_eq!(mode(data.join("log.head")), 0o600, "head record");
}

#[test]
fn an_unaltered_log_verifies() {
    let data = record("verify-ok", &sample());
    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(text(&out).contains("OK: 13 entries, chain intact, head record matches"));
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
    assert!(text(&report).contains("WARNING: the log failed its integrity check"));
    assert!(text(&report).contains("FAILED (see the warning above)"));
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

/// Keeps only the first `n` lines of the log.
fn cut_log(data: &Path, n: usize) {
    let log = data.join("activity.log");
    let kept: String = fs::read_to_string(&log).unwrap().lines().take(n).map(|l| format!("{l}\n")).collect();
    fs::write(&log, kept).unwrap();
}

#[test]
fn cutting_off_the_newest_entries_is_detected() {
    // The first 5 lines are still a valid chain. Everything after them,
    // including the SSH-key read, is gone.
    let data = record("verify-cut", &sample());
    cut_log(&data, 5);

    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("CUT SHORT"), "{}", text(&out));

    let report = awd(&["report", "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana"]);
    assert!(text(&report).contains("WARNING: the log failed its integrity check"));

    // Recording must not carry on over the gap as if nothing happened.
    let again = awd(&[
        "watch", "--source", "replay", "--input", sample().to_str().unwrap(),
        "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana",
    ]);
    assert!(!again.status.success());
    assert!(text(&again).contains("cut short"), "{}", text(&again));
}

#[test]
fn deleting_the_head_record_does_not_hide_a_cut() {
    let data = record("verify-no-head", &sample());
    cut_log(&data, 5);
    fs::remove_file(data.join("log.head")).unwrap();
    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("NO HEAD RECORD"), "{}", text(&out));
}

#[test]
fn deleting_the_whole_log_is_detected() {
    let data = record("verify-wipe", &sample());
    fs::remove_file(data.join("activity.log")).unwrap();
    let out = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("CUT SHORT"), "{}", text(&out));
}

#[test]
fn an_anchor_kept_elsewhere_catches_a_rollback_of_log_and_head_together() {
    let dir = scratch("verify-anchor");
    let data = dir.join("data");
    let half = dir.join("half.jsonl");
    let lines: Vec<String> = fs::read_to_string(sample()).unwrap().lines().map(String::from).collect();
    fs::write(&half, lines[..6].join("\n") + "\n").unwrap();
    let watch = |input: &Path| {
        let out = awd(&[
            "watch", "--source", "replay", "--input", input.to_str().unwrap(),
            "--data-dir", data.to_str().unwrap(), "--home", "/Users/ana",
        ]);
        assert!(out.status.success(), "{}", text(&out));
    };

    // Record part of a session and save the whole data directory, as someone
    // who can write there could.
    watch(&half);
    let early = dir.join("early");
    fs::create_dir_all(&early).unwrap();
    for f in ["activity.log", "log.head"] {
        fs::copy(data.join(f), early.join(f)).unwrap();
    }

    // Record more, and take an anchor off the machine.
    watch(&sample());
    let anchor = text(&awd(&["anchor", "--data-dir", data.to_str().unwrap()])).trim().to_string();
    let verify = |anchor: &str| awd(&["verify", "--data-dir", data.to_str().unwrap(), "--anchor", anchor]);
    assert!(text(&verify(&anchor)).contains("anchor holds"), "{anchor}");

    // Put the early log and its matching head record back.
    for f in ["activity.log", "log.head"] {
        fs::copy(early.join(f), data.join(f)).unwrap();
    }
    let plain = awd(&["verify", "--data-dir", data.to_str().unwrap()]);
    assert!(plain.status.success(), "without an anchor, a matched rollback passes: {}", text(&plain));
    let out = verify(&anchor);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("rolled back"), "{}", text(&out));
}
