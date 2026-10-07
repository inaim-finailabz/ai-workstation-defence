//! Classifies file paths by how sensitive they are.
//!
//! "Crown jewels" are stores no legitimate coding or summarising agent
//! needs to touch. They are blocked in v1; everything else is logged.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    // Crown jewels.
    SshKeys,
    Keychain,
    BrowserSecrets,
    PasswordManager,
    CloudCredentials,
    // Sensitive but not blocked.
    ShellHistory,
    EnvSecrets,
    AgentConfig,
    PersistenceLocation,
    // The defence itself.
    DefenceItself,
}

impl Category {
    pub fn is_crown_jewel(self) -> bool {
        matches!(
            self,
            Category::SshKeys
                | Category::Keychain
                | Category::BrowserSecrets
                | Category::PasswordManager
                | Category::CloudCredentials
        )
    }

    pub fn describe(self) -> &'static str {
        match self {
            Category::SshKeys => "SSH keys",
            Category::Keychain => "the system keychain",
            Category::BrowserSecrets => "saved browser passwords or cookies",
            Category::PasswordManager => "a password manager's data",
            Category::CloudCredentials => "cloud or developer credentials",
            Category::ShellHistory => "shell command history",
            Category::EnvSecrets => "an environment secrets file",
            Category::AgentConfig => "an AI agent's own configuration",
            Category::PersistenceLocation => "a start-up or scheduled-task location",
            Category::DefenceItself => "this defence's own log or keys",
        }
    }
}

/// Path fragments, relative to the home directory unless they start with '/'.
const RULES: &[(Category, &[&str])] = &[
    (Category::SshKeys, &[".ssh/"]),
    (Category::Keychain, &["Library/Keychains/", "/Library/Keychains/"]),
    (
        Category::BrowserSecrets,
        &[
            "Library/Application Support/Google/Chrome/Default/Login Data",
            "Library/Application Support/Google/Chrome/Default/Cookies",
            "Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
            "Library/Application Support/Microsoft Edge/Default/Login Data",
            "Library/Cookies/",
            "Library/Containers/com.apple.Safari/Data/Library/Cookies/",
            "logins.json",
            "key4.db",
            "cookies.sqlite",
            ".config/google-chrome/Default/Login Data",
            ".config/google-chrome/Default/Cookies",
        ],
    ),
    (
        Category::PasswordManager,
        &[
            "Library/Group Containers/2BUA8C4S2C.com.1password",
            "Library/Application Support/1Password",
            "Library/Application Support/Bitwarden",
            ".config/Bitwarden",
            ".password-store/",
            ".kdbx",
        ],
    ),
    (
        Category::CloudCredentials,
        &[
            ".aws/credentials",
            ".aws/config",
            ".config/gcloud/",
            ".azure/",
            ".kube/config",
            ".docker/config.json",
            ".netrc",
            ".git-credentials",
            ".npmrc",
            ".pypirc",
            ".config/gh/hosts.yml",
        ],
    ),
    (Category::ShellHistory, &[".zsh_history", ".bash_history", ".local/share/fish/fish_history", ".python_history"]),
    (Category::EnvSecrets, &[".env"]),
    (
        Category::AgentConfig,
        &[".claude/", ".claude.json", ".codex/", ".cursor/", ".aider", ".continue/", ".config/goose/", ".gemini/"],
    ),
    (
        Category::PersistenceLocation,
        &[
            "Library/LaunchAgents/",
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            "/etc/cron",
            "/var/at/tabs/",
            "/etc/systemd/",
            ".config/systemd/user/",
            ".config/autostart/",
            ".zshrc",
            ".bashrc",
            ".bash_profile",
            ".zprofile",
            ".profile",
        ],
    ),
];

/// Classifies `path`. `defence_dir` is where this product keeps its log and key.
pub fn classify(path: &str, home: &str, defence_dir: &str) -> Option<Category> {
    if !defence_dir.is_empty() && path.starts_with(defence_dir) {
        return Some(Category::DefenceItself);
    }
    let rel = path
        .strip_prefix(home)
        .map(|r| r.trim_start_matches('/'))
        .unwrap_or(path);
    let file_name = path.rsplit('/').next().unwrap_or(path);

    for (cat, fragments) in RULES {
        for frag in *fragments {
            let hit = if frag.starts_with('/') {
                path.starts_with(frag)
            } else if *frag == ".env" {
                // .env, .env.local, .env.production -- but not .envrc
                file_name == ".env" || file_name.starts_with(".env.")
            } else if frag.starts_with('.') && !frag.contains('/') && !frag.ends_with('/') && *frag != ".netrc" {
                // Extension or dotfile name anywhere (".kdbx", ".zshrc", ".aider.conf.yml").
                file_name.ends_with(frag) || file_name.starts_with(&format!("{frag}."))
            } else {
                rel.starts_with(frag) || path.contains(&format!("/{frag}"))
            };
            if hit {
                return Some(*cat);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/Users/ana";
    const DEF: &str = "/Library/Application Support/AIWorkstationDefence";

    fn c(p: &str) -> Option<Category> {
        classify(p, HOME, DEF)
    }

    #[test]
    fn crown_jewels() {
        assert_eq!(c("/Users/ana/.ssh/id_ed25519"), Some(Category::SshKeys));
        assert_eq!(c("/Users/ana/Library/Keychains/login.keychain-db"), Some(Category::Keychain));
        assert_eq!(
            c("/Users/ana/Library/Application Support/Google/Chrome/Default/Login Data"),
            Some(Category::BrowserSecrets)
        );
        assert_eq!(c("/Users/ana/.aws/credentials"), Some(Category::CloudCredentials));
        assert_eq!(c("/Users/ana/vault/personal.kdbx"), Some(Category::PasswordManager));
        assert!(c("/Users/ana/.ssh/id_ed25519").unwrap().is_crown_jewel());
    }

    #[test]
    fn sensitive_but_not_blocked() {
        assert_eq!(c("/Users/ana/.zsh_history"), Some(Category::ShellHistory));
        assert_eq!(c("/Users/ana/code/app/.env.local"), Some(Category::EnvSecrets));
        assert_eq!(c("/Users/ana/code/app/.envrc"), None);
        assert_eq!(c("/Users/ana/.claude/settings.json"), Some(Category::AgentConfig));
        assert_eq!(c("/Users/ana/Library/LaunchAgents/com.x.plist"), Some(Category::PersistenceLocation));
        assert!(!c("/Users/ana/.zsh_history").unwrap().is_crown_jewel());
    }

    #[test]
    fn ordinary_project_files_are_unclassified() {
        assert_eq!(c("/Users/ana/code/app/src/main.rs"), None);
        assert_eq!(c("/Users/ana/Documents/notes.md"), None);
    }

    #[test]
    fn the_defence_itself() {
        assert_eq!(c(&format!("{DEF}/activity.log")), Some(Category::DefenceItself));
    }
}
