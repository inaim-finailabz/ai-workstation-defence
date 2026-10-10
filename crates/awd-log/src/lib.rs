//! Append-only, hash-chained, HMAC-authenticated activity log (JSON lines).
//!
//! Each entry carries the MAC of the entry before it, so removing, editing
//! or reordering any line breaks the chain from that point on. The MAC key
//! lives beside the log in a directory only the daemon's account can read;
//! an agent that cannot read the key cannot forge a valid replacement.
//!
//! The chain alone cannot show that the *newest* entries were cut off: a
//! shorter log is still a valid chain. So every append also overwrites a small
//! head record (entry count and last MAC, itself MAC'd with the key).
//! Checking the log against it catches truncation by anyone without the key.
//!
//! The head record sits in the same directory as the log, so someone who
//! can write there can put back an older log *and* its older head, and
//! someone who also holds the key can rewrite everything. An [`Anchor`]
//! kept off the machine catches both: see [`check_anchor`].
//!
//! This makes tampering *detectable*. Keeping the log out of the agent's
//! reach in the first place is the job of file permissions: the daemon runs
//! as root and the log directory is 0700 (on Windows, place the data
//! directory under C:\ProgramData, which standard users cannot modify).

use std::fs::{self, File, OpenOptions};
use std::fmt;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::str::FromStr;

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
    #[error("no secure random source: {0}")]
    Random(String),
    #[error("the log was cut short: the head record counts {recorded} entries, the log holds {found}")]
    Truncated { recorded: u64, found: u64 },
    #[error("the log no longer contains the entry the head record points to")]
    Rewritten,
    #[error("the log has entries but no head record, so cut-off entries cannot be ruled out")]
    HeadMissing,
    #[error("the head record is damaged or was not written with this key")]
    HeadInvalid,
    #[error("not an anchor (expected <entries>:<mac>): {0}")]
    BadAnchor(String),
}

/// Owner-only file (0600) on Unix; inherits the directory's ACL on Windows.
fn private_file(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    opts.mode(0o600);
    opts
}

/// Owner-only directory (0700) on Unix.
fn make_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
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
        make_private_dir(dir)?;
    }
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).map_err(|e| LogError::Random(e.to_string()))?;
    let mut f = private_file(OpenOptions::new().write(true).create_new(true)).open(path)?;
    f.write_all(&key)?;
    Ok(key)
}

/// A point in the chain: how many entries there were, and the MAC of the
/// last one. Written as `<entries>:<mac>`, short enough to copy by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub entries: u64,
    pub last_mac: String,
}

impl fmt::Display for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.entries, self.last_mac)
    }
}

impl FromStr for Anchor {
    type Err = LogError;

    fn from_str(s: &str) -> Result<Self, LogError> {
        let bad = || LogError::BadAnchor(s.to_string());
        let (entries, last_mac) = s.trim().split_once(':').ok_or_else(bad)?;
        Ok(Self { entries: entries.parse().map_err(|_| bad())?, last_mac: last_mac.to_string() })
    }
}

fn head_mac(key: &[u8], anchor: &Anchor) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(format!("head|{anchor}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Reads the head record. `None` if there is none; an error if it is
/// damaged or was not written with `key`.
pub fn read_head(path: &Path, key: &[u8]) -> Result<Option<Anchor>, LogError> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    // One line: <anchor>:<mac of the anchor>.
    let (anchor, mac) = text.lines().next().and_then(|l| l.rsplit_once(':')).ok_or(LogError::HeadInvalid)?;
    let anchor: Anchor = anchor.parse().map_err(|_| LogError::HeadInvalid)?;
    if head_mac(key, &anchor) != mac {
        return Err(LogError::HeadInvalid);
    }
    Ok(Some(anchor))
}

/// Overwrites the head record in place with one small write. The count is
/// zero-padded so the record never gets shorter. If power is lost mid-write
/// the record fails its MAC, and the next check fails rather than passes.
fn put_head(file: &mut File, key: &[u8], anchor: &Anchor) -> Result<(), LogError> {
    let line = format!("{:020}:{}:{}\n", anchor.entries, anchor.last_mac, head_mac(key, anchor));
    file.seek(SeekFrom::Start(0))?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn write_head(path: &Path, key: &[u8], anchor: &Anchor) -> Result<File, LogError> {
    let mut file = private_file(OpenOptions::new().write(true).create(true).truncate(false)).open(path)?;
    put_head(&mut file, key, anchor)?;
    Ok(file)
}

pub struct AuditLog {
    file: File,
    head: File,
    key: Vec<u8>,
    last_mac: String,
    next_seq: u64,
}

impl AuditLog {
    /// Opens (or creates) the log, verifying the existing chain and its
    /// head record first.
    pub fn open(path: &Path, head_path: &Path, key: Vec<u8>) -> Result<Self, LogError> {
        let (last_mac, next_seq) = if path.exists() {
            let report = verify(path, &key)?;
            if let Some(bad) = report.first_bad {
                return Err(LogError::Broken(bad));
            }
            (report.last_mac, report.entries)
        } else {
            (GENESIS.to_string(), 0)
        };
        match check_head(path, head_path, &key)? {
            // The log may be ahead of its head after a crash between the two writes.
            AnchorCheck::Holds => {}
            AnchorCheck::Truncated { found } => {
                let recorded = read_head(head_path, &key)?.map_or(0, |h| h.entries);
                return Err(LogError::Truncated { recorded, found });
            }
            AnchorCheck::Rewritten => return Err(LogError::Rewritten),
        }
        let file = private_file(OpenOptions::new().create(true).append(true)).open(path)?;
        let head = write_head(head_path, &key, &Anchor { entries: next_seq, last_mac: last_mac.clone() })?;
        Ok(Self { file, head, key, last_mac, next_seq })
    }

    /// Gives a log written before head records existed its first one.
    /// Only for that one-time upgrade: it vouches for the log as it stands.
    pub fn adopt(path: &Path, head_path: &Path, key: &[u8]) -> Result<Anchor, LogError> {
        let report = verify(path, key)?;
        if let Some(bad) = report.first_bad {
            return Err(LogError::Broken(bad));
        }
        let anchor = Anchor { entries: report.entries, last_mac: report.last_mac };
        write_head(head_path, key, &anchor)?;
        Ok(anchor)
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
        put_head(&mut self.head, &self.key, &Anchor { entries: self.next_seq, last_mac: self.last_mac.clone() })?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorCheck {
    /// The log still contains the chain the anchor recorded.
    Holds,
    /// The log holds fewer entries than the anchor recorded.
    Truncated { found: u64 },
    /// The log is long enough, but the anchored entry is not the one in it.
    Rewritten,
}

/// Does the log still contain the chain `anchor` recorded? Run [`verify`]
/// first: this trusts the MACs it reads.
///
/// An anchor copied off the machine keeps working when everything on the
/// machine has been replaced, key included: a rewritten log cannot reproduce
/// the anchored MAC.
pub fn check_anchor(path: &Path, anchor: &Anchor) -> Result<AnchorCheck, LogError> {
    if anchor.entries == 0 {
        return Ok(AnchorCheck::Holds);
    }
    let mut found = 0u64;
    if path.exists() {
        for line in BufReader::new(File::open(path)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            found += 1;
            if found == anchor.entries {
                let same = serde_json::from_str::<LogEntry>(&line).is_ok_and(|e| e.mac == anchor.last_mac);
                return Ok(if same { AnchorCheck::Holds } else { AnchorCheck::Rewritten });
            }
        }
    }
    Ok(AnchorCheck::Truncated { found })
}

/// Checks the log against its head record. A log with entries and no head
/// record is an error ([`LogError::HeadMissing`]): otherwise deleting the
/// record would hide a truncation.
pub fn check_head(path: &Path, head_path: &Path, key: &[u8]) -> Result<AnchorCheck, LogError> {
    match read_head(head_path, key)? {
        Some(head) => check_anchor(path, &head),
        None if path.exists() && verify(path, key)?.entries > 0 => Err(LogError::HeadMissing),
        None => Ok(AnchorCheck::Holds),
    }
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
        let (path, head) = (d.join("activity.log"), d.join("log.head"));
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
        log.append(&json!({"n": 1})).unwrap();
        log.append(&json!({"n": 2})).unwrap();
        drop(log);
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
        assert_eq!(log.append(&json!({"n": 3})).unwrap(), 2);
        let r = verify(&path, &key).unwrap();
        assert_eq!(r.entries, 3);
        assert_eq!(r.first_bad, None);
    }

    #[test]
    fn edited_line_is_detected() {
        let d = temp_dir("edit");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let (path, head) = (d.join("activity.log"), d.join("log.head"));
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
        for n in 0..3 {
            log.append(&json!({"path": format!("/file/{n}")})).unwrap();
        }
        let text = fs::read_to_string(&path).unwrap().replace("/file/1", "/file/harmless");
        fs::write(&path, text).unwrap();
        assert_eq!(verify(&path, &key).unwrap().first_bad, Some(1));
        assert!(matches!(AuditLog::open(&path, &head, key), Err(LogError::Broken(1))));
    }

    #[test]
    fn deleted_line_is_detected() {
        let d = temp_dir("delete");
        let key = load_or_create_key(&d.join("key")).unwrap();
        let (path, head) = (d.join("activity.log"), d.join("log.head"));
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
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
        let (path, head) = (d.join("activity.log"), d.join("log.head"));
        let mut forged = AuditLog::open(&path, &head, b"attacker-guess".to_vec()).unwrap();
        forged.append(&json!({"n": 0})).unwrap();
        assert_eq!(verify(&path, &key).unwrap().first_bad, Some(0));
        assert!(matches!(read_head(&head, &key), Err(LogError::HeadInvalid)));
    }

    /// Writes `n` entries and returns (log path, head path, key).
    fn filled(name: &str, n: u64) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
        let d = temp_dir(name);
        let key = load_or_create_key(&d.join("key")).unwrap();
        let (path, head) = (d.join("activity.log"), d.join("log.head"));
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
        for i in 0..n {
            log.append(&json!({ "n": i })).unwrap();
        }
        (path, head, key)
    }

    fn keep_first(path: &Path, n: usize) {
        let text = fs::read_to_string(path).unwrap();
        fs::write(path, text.lines().take(n).map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    }

    #[test]
    fn cut_off_tail_is_detected() {
        let (path, head, key) = filled("truncate", 5);
        keep_first(&path, 2);
        // The shorter log is still a valid chain; only the head record shows the loss.
        assert_eq!(verify(&path, &key).unwrap().first_bad, None);
        assert_eq!(check_head(&path, &head, &key).unwrap(), AnchorCheck::Truncated { found: 2 });
        assert!(matches!(AuditLog::open(&path, &head, key), Err(LogError::Truncated { recorded: 5, found: 2 })));
    }

    #[test]
    fn deleting_the_whole_log_is_detected() {
        let (path, head, key) = filled("wipe", 3);
        fs::remove_file(&path).unwrap();
        assert_eq!(check_head(&path, &head, &key).unwrap(), AnchorCheck::Truncated { found: 0 });
        assert!(matches!(AuditLog::open(&path, &head, key), Err(LogError::Truncated { recorded: 3, found: 0 })));
    }

    #[test]
    fn deleting_the_head_record_does_not_hide_a_cut() {
        let (path, head, key) = filled("no-head", 4);
        keep_first(&path, 1);
        fs::remove_file(&head).unwrap();
        assert!(matches!(check_head(&path, &head, &key), Err(LogError::HeadMissing)));
        assert!(matches!(AuditLog::open(&path, &head, key), Err(LogError::HeadMissing)));
    }

    #[test]
    fn a_head_record_cannot_be_forged_without_the_key() {
        let (path, head, key) = filled("head-forge", 4);
        keep_first(&path, 2);
        let last = read_entries(&path).unwrap().pop().unwrap().mac;
        let fake = Anchor { entries: 2, last_mac: last };
        write_head(&head, b"attacker-guess", &fake).unwrap();
        assert!(matches!(check_head(&path, &head, &key), Err(LogError::HeadInvalid)));
    }

    #[test]
    fn a_log_ahead_of_its_head_reopens() {
        // A crash between writing an entry and its head record leaves the log one ahead.
        let (path, head, key) = filled("ahead", 3);
        let older = Anchor { entries: 2, last_mac: read_entries(&path).unwrap()[1].mac.clone() };
        write_head(&head, &key, &older).unwrap();
        assert_eq!(check_head(&path, &head, &key).unwrap(), AnchorCheck::Holds);
        drop(AuditLog::open(&path, &head, key.clone()).unwrap());
        assert_eq!(read_head(&head, &key).unwrap().unwrap().entries, 3);
    }

    #[test]
    fn an_outside_anchor_catches_what_the_head_record_cannot() {
        let (path, head, key) = filled("anchor", 5);
        let anchor: Anchor = read_head(&head, &key).unwrap().unwrap().to_string().parse().unwrap();
        assert_eq!(check_anchor(&path, &anchor).unwrap(), AnchorCheck::Holds);

        // Roll back: an older log with a head record that matches it.
        keep_first(&path, 2);
        AuditLog::adopt(&path, &head, &key).unwrap();
        assert_eq!(check_head(&path, &head, &key).unwrap(), AnchorCheck::Holds);
        assert_eq!(check_anchor(&path, &anchor).unwrap(), AnchorCheck::Truncated { found: 2 });

        // Rewrite: someone holding the key writes a whole new log of the same length.
        fs::remove_file(&path).unwrap();
        fs::remove_file(&head).unwrap();
        let mut log = AuditLog::open(&path, &head, key.clone()).unwrap();
        for i in 0..5 {
            log.append(&json!({ "harmless": i })).unwrap();
        }
        assert_eq!(verify(&path, &key).unwrap().first_bad, None);
        assert_eq!(check_head(&path, &head, &key).unwrap(), AnchorCheck::Holds);
        assert_eq!(check_anchor(&path, &anchor).unwrap(), AnchorCheck::Rewritten);
    }
}
