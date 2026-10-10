# AI Workstation Defence

[![verify](https://github.com/inaim-finailabz/ai-workstation-defence/actions/workflows/ci.yml/badge.svg)](https://github.com/inaim-finailabz/ai-workstation-defence/actions/workflows/ci.yml)

**See what AI agents do on your computer, as the operating system reports it.**

`awd` is an open-source visibility and alerting tool. It records and explains; it does not block anything yet, and it does not see everything. The [limits](#status-v0-an-honest-list) are listed below.

AI agents now run on our own laptops and workstations: coding assistants, summarisers, and tool-using agents with shell, file, browser and email access. They are useful, and they get more capable and more persistent with every release. Persistent means that when one path is blocked, they try another.

The question every owner should be able to answer is simple: **did my AI agents touch my private data?** Today, most people can't answer it. This project is a first step toward making that answer easy. It is not yet a complete answer: a quiet report means nothing was recorded, not that nothing happened.

> Part of the white paper **[AI Defence in Depth: Distrust Every Agent](docs/whitepaper/)**, a practical guide to defending homes, labs and small teams against AI agents, including the ones you deploy yourself.

## What it does

`awd` records what AI agents do, from the operating system's point of view, not from the agent's own reporting. It then explains it in plain language.

```
$ awd report
Claude Code
  10 actions: read 3 files, changed 3 files, ran 3 programs, contacted 1 destinations
  Private data: touched SSH keys (1 times)
  Not blocked: 1 actions the policy marks for blocking went ahead (this version only records).
  Alerts: 2 critical, 2 high, 1 notices

What needs your attention:
  [09:01:00] Claude Code read ~/code/shop/.env.production -- HIGH: Claude Code touched an environment secrets file
  [09:01:05] Claude Code (via python3) read ~/.ssh/id_ed25519 -- CRITICAL: Claude Code touched SSH keys [policy: WOULD BLOCK -- not enforced in this version, the action went ahead]
  [09:01:06] Claude Code (via python3) connected to 203.0.113.50:443 -- NOTICE: Claude Code connected to a new destination: 203.0.113.50:443
  [09:01:30] Claude Code wrote ~/.claude/settings.json -- HIGH: Claude Code changed an AI agent's own configuration
  [09:02:00] Claude Code created ~/Library/LaunchAgents/com.helper.sync.plist -- CRITICAL: Claude Code changed a start-up or scheduled-task location

Log integrity: 13 entries, chain and head record intact
```

The output above comes from the simulated session in [`examples/sample-session.jsonl`](examples/sample-session.jsonl). The agent edits a file and runs tests, which stay quiet. Then it reads a secrets file, starts Python to read an SSH key and connect out, edits its own configuration, and installs a start-up item.

## Can I trust it?

A tool that watches your computer needs deep access, so **don't take our word for it. Check it yourself:**

```bash
./scripts/verify.sh                                              # macOS / Linux
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1      # Windows
```

This builds the tool from source and runs every test. It replays a sample session, edits the log and cuts off its end to show both are caught, and runs the same session with the network cut off.

Automated **trust tests** are safeguards, not proof. They search the source and the dependency list for the usual routes: network code, network libraries, unexpected programs, new file access, environment secrets and `unsafe` code. A change that adds one fails the build and shows up in a public diff. They do not show that the software cannot communicate or misbehave; code written to avoid those patterns would pass. The same checks run publicly on every commit, on Linux, macOS and Windows.

The tests run on replayed sessions. They do not establish that live capture is complete, how it performs under load, or that it resists evasion. No live-workload results are published yet.

- **[TESTING.md](docs/TESTING.md):** what every test checks, and what it does not, in plain words
- **[RUNBOOK.md](docs/RUNBOOK.md):** how to build, verify and run on macOS, Linux and Windows

## How it works

| Principle | How |
| --- | --- |
| **The OS is the witness, not the agent** | File and process events come from macOS Endpoint Security (via Apple's `eslogger`), not from the agent's own reporting. Network connections are sampled, so short ones can be missed. |
| **Every child counts** | `agent → zsh → python3 → curl` is still the agent. Attribution follows exec and fork through the whole process tree, and flags an agent that starts another AI agent. It starts from the program's name, so a renamed agent is not attributed. |
| **What and who, never contents** | The log records which file, program or destination, never file contents, clipboard text or network payloads. The log must not become the biggest privacy leak on the machine. |
| **Tamper-evident log** | Append-only JSON lines, each entry HMAC-chained to the previous one, so editing, deleting or reordering a line is detected (`awd verify`). A separate head record holds the entry count and last MAC, so cutting entries off the end is detected too. The log, key and head record live in a root-only directory. For protection that does not depend on that directory, keep an anchor elsewhere (below). |
| **Rules decide, no AI in the path** | Red lines are fixed, deterministic rules. Nothing an agent writes can talk a rule out of firing. |
| **Crown jewels** | SSH keys, keychains, browser passwords and cookies, password managers and cloud credentials are marked "would block" and raise a critical alert. No legitimate coding agent needs them. In v0 the access still goes ahead. |

**Red-line alerts in v0:**
- touching a crown jewel
- reading shell history or `.env` files
- an agent editing its own configuration
- creating start-up or scheduled-task items
- privacy permission changes
- a new network destination
- an agent starting another AI agent
- any attempt to touch the defence's own log or key

**Keeping an anchor off the machine.** The head record sits beside the log, so it stops anyone who cannot write that directory or does not hold the key. Someone who can write there could put back an older log together with its older head record, and someone who also reads the key could rewrite everything. An anchor kept elsewhere catches both:

```bash
awd anchor                      # prints <entries>:<mac>, e.g. 13:a02126fc…
awd verify --anchor 13:a02126fc…   # later: fails if the log no longer contains that entry
```

Store the anchor where no agent on this machine can write: another device, a note on your phone, a printed page. `awd` never sends it anywhere itself.

## Try it

Full step-by-step instructions for each system are in the **[runbook](docs/RUNBOOK.md)**. The short version (Rust 1.80+):

```bash
cargo build --release --locked

# Replay the simulated session (no special permissions needed)
./target/release/awd watch --source replay --input examples/sample-session.jsonl --data-dir ./awd-data --home /Users/ana
./target/release/awd report --data-dir ./awd-data --home /Users/ana
./target/release/awd verify --data-dir ./awd-data
```

**Live on macOS 13+:** give your terminal Full Disk Access (System Settings → Privacy & Security), then:

```bash
sudo ./target/release/awd watch --agents config/agents.toml
# in another terminal, later:
sudo ./target/release/awd report
```

Agents are recognised by the names in [`config/agents.toml`](config/agents.toml): Claude Code, Codex CLI, Gemini CLI, Cursor, Windsurf, Aider, Goose and opencode. Add your own.

## Status: v0, an honest list

This is an early, working prototype. Know its limits:

- **macOS only** for live capture. Linux (eBPF) and Windows (ETW) sources are planned.
- **It monitors. It does not block.** Nothing is prevented in v0. Where the policy says block, the report says "would block" and the action still goes ahead: an agent that reads your SSH key has read it. Real blocking on macOS needs Endpoint Security *AUTH* events, which require an Apple entitlement.
- **It does not see everything.** Network capture is polled every 3 seconds with `lsof`, so a connection that opens and closes between polls is not recorded. v1 uses a Network Extension (macOS) or eBPF (Linux).
- **Agent recognition is by name.** A renamed binary is not recognised as an agent, so nothing it does is recorded or alerted. This is the simplest way to escape the tool today. Stronger identification (code signature, path and hash) is not built yet.
- **Root is the root of trust.** An agent running as root, or a user who approves it, can defeat any local monitor. Run agents as a normal user.
- **Not validated on live workloads.** The tests replay recorded sessions. Capture completeness, performance under real event volume (`open` events can be very frequent) and resistance to evasion have not been measured or published.
- **The log's own protection has limits.** Edits, deletions and a cut-off end are detected. A rollback of the log together with its head record, or a full rewrite by someone who can read the key, is only caught if you keep an anchor off the machine and check it. `awd` does not ship anchors anywhere for you.
- **`.env.example` raises a HIGH alert.** Every `.env.*` file is classed as secrets, although coding agents read `.env.example` routinely.
- **"New destination" alerts repeat after a restart.** The seen-destinations list is held in memory and is not rebuilt from the log when `watch` starts.

## Roadmap

1. **v0 (this release):** transparent, tamper-evident, plain-language log + red-line alerts + crown-jewel policy (recorded, not enforced).
2. **v1:**
   - native Endpoint Security client with real crown-jewel blocking
   - agent identification by code signature, path and hash, not name alone
   - published live-workload tests: capture completeness, performance and evasion attempts
   - Network Extension for every connection
   - desktop app (Tauri)
   - signed updates
   - honeytoken paths: bait files listed in the config, where any touch by an agent is critical
   - strike counter: red-line alerts counted per agent, with `narrow-recommended` raised at a threshold and a stricter rule set applied after it
   - snapshot before write: the file is cloned before a write, delete or rename is allowed, and only the snapshot ID is logged
3. **Next: per-agent sandboxes (paper Layer 4).** Agents may touch only their project folder and listed destinations, enforced by the OS.
4. **Later: anomaly detection (paper Layer 5)** against each agent's normal behaviour, plus Linux and Windows.

The plan and the v1 scope were reviewed by **[Assembly of Elders](docs/decisions/0001-v1-scope.md)**, a multi-model review board with Claude, GPT and DeepSeek in expert roles. The board split between "logging first" and "sandbox first", and the owner chose logging plus a crown-jewel block.

## Layout

```
crates/awd-core       event schema, process-tree agent attribution
crates/awd-policy     crown-jewel classification, red-line rules, plain-language explanations
crates/awd-log        append-only HMAC-chained log + verifier
crates/awd-collector  eslogger (macOS), lsof network poller, replay files
crates/awd-cli        the `awd` command
crates/awd-cli/tests  end-to-end and trust tests
scripts/              verify.sh (macOS/Linux), verify.ps1 (Windows)
docs/                 testing, runbook, decisions, white paper
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

© 2026 AI Labz Ltd. AI Labz Ltd is the legal owner of all intellectual property developed under the FinAI Labz brand, including open-source and proprietary technology. This project is open source under the licenses above.
