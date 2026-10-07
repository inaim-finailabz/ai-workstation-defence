//! Append-only, hash-chained, HMAC-authenticated activity log (JSON lines).
//!
//! Each entry carries the MAC of the entry before it, so removing, editing
//! or reordering any line breaks the chain from that point on. The MAC key
//! lives beside the log in a directory only the daemon's account can read;
//! an agent that cannot read the key cannot forge a valid replacement.
//!
//! This makes tampering *detectable*. Keeping the log out of the agent's
//! reach in the first place is the job of file permissions: the daemon runs
//! as root and the log directory is 0700.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const GENESIS: &str = "genesis";

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("log chain broken at entry {0}")]
    Broken(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub prev: String,
    pub body: serde_json::Value,
    pub mac: String,
}

fn compute_mac(key: &[u8], seq: u64, ts: &DateTime<Utc>, prev: &str, body: &serde_json::Value) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(format!("{seq}|{}|{prev}|{body}", ts.to_rfc3339()).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Loads the MAC key, creating a random 32-byte key (mode 0600) if missing.
pub fn load_or_create_key(path: &Path) -> Result<Vec<u8>, LogError> {
    if path.exists() {
        return Ok(fs::read(path)?);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let mut key = vec![0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut key)?;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(&key)?;
    Ok(key)
}

pub struct AuditLog {
    file: File,
    key: Vec<u8>,
    last_mac: String,
    next_seq: u64,
}

impl AuditLog {
    /// Opens (or creates) the log, verifying the existing chain first.
    pub fn open(path: &Path, key: Vec<u8>) -> Result<Self, LogError> {
        let (last_mac, next_seq) = if path.exists() {
            let report = verify(path, &key)?;
            if let Some(bad) = report.first_bad {
                return Err(LogError::Broken(bad));
            }
            (report.last_mac, report.entries)
        } else {
            (GENESIS.to_string(), 0)
        };
        let file = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        Ok(Self { file, key, last_mac, next_seq })
    }

    pub fn append<T: Serialize>(&mut self, body: &T) -> Result<u64, LogError> {
        let body = serde_json::to_value(body)?;
        let ts = Utc::now();
        let seq = self.next_seq;
        let mac = compute_mac(&self.key, seq, &ts, &self.last_mac, &body);
        let entry = LogEntry { seq, ts, prev: self.last_mac.clone(), body, mac: mac.clone() };
        writeln!(self.file, "{}", serde_json::to_string(&entry)?)?;
        self.file.flush()?;
        self.last_mac = mac;
        self.next_seq += 1;
        Ok(seq)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub entries: u64,
    pub first_bad: Option<u64>,
    pub last_mac: String,
}

/// Walks the whole chain. `first_bad` is the first entry that fails.
pub fn verify(path: &Path, key: &[u8]) -> Result<VerifyReport, LogError> {
    let reader = BufReader::new(File::open(path)?);
    let mut prev = GENESIS.to_string();
    let mut count = 0u64;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ok = match serde_json::from_str::<LogEntry>(&line) {
            Ok(e) => e.seq == count && e.prev == prev && compute_mac(key, e.seq, &e.ts, &e.prev, &e.body) == e.mac,
            Err(_) => false,
        };
        if !ok {
            return Ok(VerifyReport { entries: count, first_bad: Some(count), last_mac: prev });
        }
        let entry: LogEntry = serde_json::from_str(&line)?;
        prev = entry.mac;
        count += 1;
    }
    Ok(VerifyReport { entries: count, first_bad: None, last_mac: prev })
}

/// Reads all entries without verifying (use `verify` first when it matters).
pub fn read_entries(path: &Path) -> Result<Vec<LogEntry>, LogError> {
    let reader = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            out.push(serde_json::from_str(&line)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("awd-log-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn chain_verifies_and_reopens() {
        let d = temp_dir("ok");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let path = d.join("activity.log");
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        log.append(&json!({"n": 1})).unwrap();
        log.append(&json!({"n": 2})).unwrap();
        drop(log);
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        assert_eq!(log.append(&json!({"n": 3})).unwrap(), 2);
        let r = verify(&path, &key).unwrap();
        assert_eq!(r.entries, 3);
        assert_eq!(r.first_bad, None);
    }

    #[test]
    fn edited_line_is_detected() {
        let d = temp_dir("edit");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let path = d.join("activity.log");
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        for n in 0..3 {
            log.append(&json!({"path": format!("/file/{n}")})).unwrap();
        }
        let text = fs::read_to_string(&path).unwrap().replace("/file/1", "/file/harmless");
        fs::write(&path, text).unwrap();
        assert_eq!(verify(&path, &key).unwrap().first_bad, Some(1));
        assert!(matches!(AuditLog::open(&path, key), Err(LogError::Broken(1))));
    }

    #[test]
    fn deleted_line_is_detected() {
        let d = temp_dir("delete");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let path = d.join("activity.log");
        let mut log = AuditLog::open(&path, key.clone()).unwrap();
        for n in 0..3 {
            log.append(&json!({ "n": n })).unwrap();
        }
        let lines: Vec<String> = fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert_eq!(verify(&path, &key).unwrap().first_bad, Some(1));
    }

    #[test]
    fn wrong_key_cannot_forge() {
        let d = temp_dir("forge");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let path = d.join("activity.log");
        let mut forged = AuditLog::open(&path, b"attacker-guess".to_vec()).unwrap();
        forged.append(&json!({"n": 0})).unwrap();
        assert_eq!(verify(&path, &key).unwrap().first_bad, Some(0));
    }
}
