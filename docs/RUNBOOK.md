# Runbook: build, verify and run on macOS, Linux and Windows

**What works where today:**

| | macOS 13+ | Linux | Windows 10/11 |
| --- | --- | --- | --- |
| Build and run all tests | yes | yes | yes |
| Verify a log, read reports, replay sessions | yes | yes | yes |
| **Live watching of AI agents** | **yes** | not yet (eBPF source planned) | not yet (ETW source planned) |

We publish no prebuilt binaries. You build from source you can read.

`awd` records and alerts. It does not block anything in this version.

---

## macOS

### 1. Install the tools (once)

```bash
xcode-select --install                                           # Apple's compiler tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust, from rust-lang.org
source "$HOME/.cargo/env"
```

### 2. Get the code and verify it

```bash
git clone https://github.com/inaim-finailabz/ai-workstation-defence.git
cd ai-workstation-defence
./scripts/verify.sh
```

Every step should print `PASS`. See [TESTING.md](TESTING.md) for what each step checks, and what it does not.

### 3. Watch your AI agents live

1. Open **System Settings → Privacy & Security → Full Disk Access** and turn it on for your terminal app (Terminal, iTerm…). Apple's Endpoint Security event stream requires it.
2. Start watching. Root is required to read the event stream. The log is stored in `/Library/Application Support/AIWorkstationDefence`, where only root can write.

   ```bash
   sudo ./target/release/awd watch --agents config/agents.toml
   ```

3. Use your AI agents as normal. Each action appears as one plain sentence.
4. Any time, in another terminal:

   ```bash
   sudo ./target/release/awd report          # summary + what needs your attention
   sudo ./target/release/awd report --all    # every recorded action
   sudo ./target/release/awd verify          # check the log was not edited or cut short
   sudo ./target/release/awd anchor          # print <entries>:<mac> to keep off this machine
   ```

   Keep the anchor somewhere no agent on this machine can write (another device, your phone, paper). Later, `sudo ./target/release/awd verify --anchor <entries>:<mac>` fails if the log was rolled back or rewritten, which the local check alone cannot catch.

5. Upgrading from an older `awd`? A log written before head records existed fails to open. Run `sudo ./target/release/awd watch --adopt-existing-log --agents config/agents.toml` once: it accepts the log as it stands and writes its first head record.

**Add an agent:** add an `[[agent]]` entry to `config/agents.toml` with its program name.

**Stop:** `Ctrl+C`. The log stays and can be verified at any time.

---

## Linux (Ubuntu, Debian, Fedora…)

### 1. Install the tools (once)

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y build-essential git curl strace
# Fedora
sudo dnf install -y gcc git curl strace

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 2. Get the code and verify it

```bash
git clone https://github.com/inaim-finailabz/ai-workstation-defence.git
cd ai-workstation-defence
./scripts/verify.sh
```

On Linux the script also traces every network system call with `strace` and runs the tool inside a network namespace with no network. If your distribution restricts unprivileged namespaces (Ubuntu 24.04 does), that step shows `SKIP`. The `strace` check still runs.

### 3. Use it

Live watching on Linux is not available yet. You can already verify logs and read reports, including logs copied from a Mac:

```bash
./target/release/awd verify --data-dir /path/to/data
./target/release/awd report --data-dir /path/to/data
```

---

## Windows 10 / 11

### 1. Install the tools (once)

1. Install **Visual Studio Build Tools** from visualstudio.microsoft.com and select **Desktop development with C++**. Rust needs its linker.
2. Install Rust: download and run `rustup-init.exe` from [rustup.rs](https://rustup.rs) and accept the defaults.
3. Install **Git for Windows** from git-scm.com.

Open a new **PowerShell** window afterwards so the tools are on your `PATH`.

### 2. Get the code and verify it

```powershell
git clone https://github.com/inaim-finailabz/ai-workstation-defence.git
cd ai-workstation-defence
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
```

Run PowerShell **as Administrator** to also run the tool with Windows Firewall blocking all its outbound traffic. The script adds a temporary firewall rule and removes it afterwards. Without Administrator, that step shows `SKIP`.

### 3. Use it

Live watching on Windows is not available yet. You can verify logs and read reports:

```powershell
.\target\release\awd.exe verify --data-dir C:\path\to\data
.\target\release\awd.exe report --data-dir C:\path\to\data
```

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `could not start eslogger` | macOS 13 or newer is required; run with `sudo`; give your terminal Full Disk Access |
| `error: linker 'cc' not found` (Linux) | install `build-essential` (Debian/Ubuntu) or `gcc` (Fedora) |
| `link.exe not found` (Windows) | install Visual Studio Build Tools with **Desktop development with C++** |
| `failed to select a version` / lock-file errors | run `rustup update`. Rust 1.80 or newer is needed. |
| `ALTERED: the chain breaks at entry N` | entries from N onward were edited, removed or reordered after recording; treat them as untrustworthy |
| Too much output while watching | expected for busy agents; read `awd report` instead, which shows only what needs attention |
