//! AI Workstation Defence -- core types.

pub mod attribution;
pub mod event;

pub use attribution::{AgentSpec, AgentTag, Attribution, Attributor};
pub use event::{EventKind, RawEvent};
