//! The event schema. Every event comes from the operating system, never from
//! the agent's own reporting, and records *what* and *who* -- never contents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A process replaced its image with a new program.
    Exec {
        path: String,
        #[serde(default)]
        args: Vec<String>,
    },
    /// A process created a child.
    Fork { child_pid: u32 },
    Exit,
    FileRead { path: String },
    FileWrite { path: String },
    FileCreate { path: String },
    FileRename { from: String, to: String },
    FileDelete { path: String },
    /// A login item, launch agent or daemon was registered.
    PersistenceAdded { item: String },
    /// An outbound network connection was observed.
    NetConnect { remote: String, port: u16 },
    /// A privacy permission (camera, microphone, full disk access...) changed.
    PrivacyPermissionChanged { service: String },
}

impl EventKind {
    /// File paths this event touches, for classification.
    pub fn paths(&self) -> Vec<&str> {
        match self {
            EventKind::FileRead { path }
            | EventKind::FileWrite { path }
            | EventKind::FileCreate { path }
            | EventKind::FileDelete { path } => vec![path.as_str()],
            EventKind::FileRename { from, to } => vec![from.as_str(), to.as_str()],
            _ => vec![],
        }
    }

    /// True when the event changes the file system rather than only reading it.
    pub fn is_modification(&self) -> bool {
        matches!(
            self,
            EventKind::FileWrite { .. }
                | EventKind::FileCreate { .. }
                | EventKind::FileRename { .. }
                | EventKind::FileDelete { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawEvent {
    pub ts: DateTime<Utc>,
    pub pid: u32,
    pub ppid: u32,
    /// Executable of the acting process.
    pub exe: String,
    #[serde(flatten)]
    pub kind: EventKind,
}
