//! AI Workstation Defence -- what is sensitive, what crosses a red line,
//! and how to say it in plain language.

pub mod classify;
pub mod explain;
pub mod rules;

pub use classify::{classify, Category};
pub use explain::explain;
pub use rules::{Alert, Decision, Policy, Severity, Verdict};
