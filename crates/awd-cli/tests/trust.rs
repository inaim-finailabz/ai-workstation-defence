//! Trust tests: checks anyone can run to confirm this tool is not a trojan horse.
//!
//!     cargo test --test trust
//!
//! They read the project's own source code and dependency lock file and fail
//! if the tool gains any way to reach the network, runs any program other
//! than the two it documents, reads environment secrets, uses `unsafe`, or
//! touches files anywhere other than the reviewed call sites listed below.
//!
//! If one of these tests fails after a change, that change must be reviewed
//! and the expectation here updated *in the same commit*, where every reader
//! can see it. That is the point: nothing sensitive can be added quietly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Every `.rs` file under `crates/*/src`, as (relative path, full text).
fn source_files() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with("._") || name == "target" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if name.ends_with(".rs") && path.components().any(|c| c.as_os_str() == "src") {
                let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    out.sort();
    assert!(out.len() >= 10, "expected to find the project's source files, found {}", out.len());
    out
}

/// The shipped code only: everything before the first `#[cfg(test)]`.
fn shipped(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap()
}

#[test]
fn no_network_code_in_the_source() {
    let forbidden = [
        "std::net", "TcpStream", "TcpListener", "UdpSocket", "UnixStream", "UnixListener",
        "UnixDatagram", "ToSocketAddrs", "socket2", "reqwest", "hyper", "ureq", "isahc", "curl::",
    ];
    for (file, text) in source_files() {
        for word in forbidden {
            assert!(!text.contains(word), "{file} mentions `{word}`: this tool must never open network connections");
        }
    }
}

#[test]
fn no_network_libraries_in_the_dependency_tree() {
    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    let packages: BTreeSet<&str> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .map(|l| l.trim_end_matches('"'))
        .collect();
    let forbidden = [
        // HTTP clients and servers
        "reqwest", "hyper", "ureq", "curl", "isahc", "surf", "attohttpc", "h2", "h3", "quinn", "axum", "warp", "actix-web",
        // async networking runtimes and socket crates
        "tokio", "async-std", "smol", "mio", "socket2",
        // TLS stacks (only needed to talk to servers)
        "rustls", "native-tls", "openssl", "openssl-sys",
        // websockets, telemetry and crash reporters
        "tungstenite", "opentelemetry", "sentry", "segment",
    ];
    for name in forbidden {
        assert!(!packages.contains(name), "dependency `{name}` can talk to the network; it must not be in Cargo.lock");
    }
}

#[test]
fn runs_only_the_two_documented_programs() {
    // eslogger: Apple's Endpoint Security event stream (macOS).
    // lsof: lists the network connections of agent processes.
    let mut programs = BTreeSet::new();
    for (file, text) in source_files() {
        for part in shipped(&text).split("Command::new(").skip(1) {
            let literal = part.trim_start().strip_prefix('"').and_then(|p| p.split('"').next());
            let program = literal.unwrap_or_else(|| panic!("{file}: Command::new must take a literal program name"));
            programs.insert(program.to_string());
        }
    }
    let expected: BTreeSet<String> = ["eslogger", "lsof"].iter().map(|s| s.to_string()).collect();
    assert_eq!(programs, expected, "the set of external programs changed; review it and update this test");
}

#[test]
fn reads_no_environment_variables_except_the_home_directory() {
    let mut names = BTreeSet::new();
    for (file, text) in source_files() {
        let code = shipped(&text);
        for marker in ["env::var(\"", "env::var_os(\""] {
            for part in code.split(marker).skip(1) {
                names.insert(part.split('"').next().unwrap().to_string());
            }
        }
        assert!(!code.contains("env::vars("), "{file} enumerates all environment variables");
    }
    // HOME / USERPROFILE: whose home to protect. SUDO_USER: the person who ran sudo.
    let allowed: BTreeSet<String> = ["HOME", "USERPROFILE", "SUDO_USER"].iter().map(|s| s.to_string()).collect();
    assert!(names.is_subset(&allowed), "unexpected environment variables read: {names:?}");
}

#[test]
fn contains_no_unsafe_code() {
    for (file, text) in source_files() {
        assert!(!text.contains("unsafe"), "{file} contains `unsafe` code");
    }
}

/// Every place the shipped code opens, reads, writes or deletes a file.
/// Each one was reviewed:
///   awd-log     -- the activity log and its key, in the data directory only
///   awd-collector/replay -- the replay file the user names on the command line
///   awd-cli     -- the agents config file and the log key
/// No code reads the files agents touch: the log records paths reported by
/// the operating system, never contents.
#[test]
fn file_access_happens_only_at_reviewed_call_sites() {
    let patterns = [
        "File::open(", "File::create(", "fs::read(", "fs::read_to_string(", "fs::write(", "OpenOptions::new()",
        "create_dir_all(", "set_permissions(", "remove_file(", "remove_dir", "fs::copy(", "fs::rename(", "read_dir(",
    ];
    let mut actual: BTreeMap<(String, &str), usize> = BTreeMap::new();
    for (file, text) in source_files() {
        let code = shipped(&text);
        for p in patterns {
            let n = code.matches(p).count();
            if n > 0 {
                actual.insert((file.clone(), p), n);
            }
        }
    }
    let expected: BTreeMap<(String, &str), usize> = [
        ("crates/awd-log/src/lib.rs", "fs::read(", 1),            // load the log key
        ("crates/awd-log/src/lib.rs", "create_dir_all(", 1),      // create the data directory
        ("crates/awd-log/src/lib.rs", "set_permissions(", 1),     // ...and make it owner-only (0700, Unix)
        ("crates/awd-log/src/lib.rs", "File::open(", 2),          // read the log (verify, read entries)
        ("crates/awd-log/src/lib.rs", "OpenOptions::new()", 2),   // write a new key (0600); append to the log (0600)
        ("crates/awd-collector/src/replay.rs", "File::open(", 1), // the replay file named on the command line
        ("crates/awd-cli/src/main.rs", "fs::read_to_string(", 1), // config/agents.toml
        ("crates/awd-cli/src/main.rs", "fs::read(", 2),           // the log key, for report and verify
    ]
    .into_iter()
    .map(|(f, p, n)| ((f.to_string(), p), n))
    .collect();
    assert_eq!(actual, expected, "file-access call sites changed; review the change and update this list");
}
