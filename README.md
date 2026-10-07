# AI Workstation Defence

[![verify](https://github.com/inaim-finailabz/ai-workstation-defence/actions/workflows/ci.yml/badge.svg)](https://github.com/inaim-finailabz/ai-workstation-defence/actions/workflows/ci.yml)

**See exactly what AI agents do on your computer.**

AI agents now run on our own laptops and workstations: coding assistants, summarisers, and tool-using agents with shell, file, browser and email access. They are useful, and they get more capable and more persistent with every release. Persistent means that when one path is blocked, they try another.

The question every owner should be able to answer is simple: **did my AI agents touch my private data?** Today, most people can't answer it. This project is a first step toward making that answer easy.

> Part of the white paper **[AI Defence in Depth: Distrust Every Agent](docs/whitepaper/)**, a practical guide to defending homes, labs and small teams against AI agents, including the ones you deploy yourself.

## What it does

`awd` records what AI agents do, from the operating system's point of view, not from the agent's own reporting. It then explains it in plain language.

```
$ awd report
Claude Code
  10 actions: read 3 files, changed 3 files, ran 3 programs, contacted 1 destinations
  Private data: touched SSH keys (1 times)
  Policy would have blocked 1 actions.
  Alerts: 2 critical, 2 high, 1 notices

What needs your attention:
  [09:01:00] Claude Code read ~/code/shop/.env.production -- HIGH: Claude Code touched an environment secrets file
  [09:01:05] Claude Code (via python3) read ~/.ssh/id_ed25519 -- CRITICAL: Claude Code touched SSH keys [policy: BLOCK -- recorded; enforcement arrives in v1]
  [09:01:06] Claude Code (via python3) connected to 203.0.113.50:443 -- NOTICE: Claude Code connected to a new destination: 203.0.113.50:443
  [09:01:30] Claude Code wrote ~/.claude/settings.json -- HIGH: Claude Code changed an AI agent's own configuration
  [09:02:00] Claude Code created ~/Library/LaunchAgents/com.helper.sync.plist -- CRITICAL: Claude Code changed a start-up or scheduled-task location

Log integrity: 13 entries, unaltered
```

The output above comes from the simulated session in [`examples/sample-session.jsonl`](examples/sample-session.jsonl). The agent edits a file and runs tests, which stay quiet. Then it reads a secrets file, starts Python to read an SSH key and connect out, edits its own configuration, and installs a start-up item.

## Can I trust it?

A tool that watches your computer needs deep access, so **don't take our word for it. Check it yourself:**

```bash
./scripts/verify.sh                                              # macOS / Linux
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1      # Windows
```

This builds the tool from source and runs every test. It replays a sample session, tampers with the log to show the tampering is caught, and runs the tool with the network cut off to show it needs none. Automated **trust tests** fail if anyone adds network code, network libraries, unexpected programs, new file access, environment secrets or `unsafe` code. The same checks run publicly on every commit, on Linux, macOS and Windows.

- **[TESTING.md](docs/TESTING.md):** what every test proves, in plain words
- **[RUNBOOK.md](docs/RUNBOOK.md):** how to build, verify and run on macOS, Linux and Windows

## How it works

| Principle | How |
| --- | --- |
| **The OS is the witness, not the agent** | Events come from macOS Endpoint Security (via Apple's `eslogger`). An agent cannot under-report what the kernel saw. |
| **Every child counts** | `agent → zsh → python3 → curl` is still the agent. Attribution follows exec and fork through the whole process tree, and flags an agent that starts another AI agent. |
| **What and who, never contents** | The log records which file, program or destination, never file contents, clipboard text or network payloads. The log must not become the biggest privacy leak on the machine. |
| **Tamper-evident log** | Append-only JSON lines, each entry HMAC-chained to the previous one. Editing, deleting or reordering any line is detected (`awd verify`). The log and key live in a root-only directory. |
| **Rules decide, no AI in the path** | Red lines are fixed, deterministic rules. Nothing an agent writes can talk a rule out of firing. |
| **Crown jewels** | SSH keys, keychains, browser passwords and cookies, password managers and cloud credentials are marked for blocking. No legitimate coding agent needs them. |

**Red-line alerts in v0:**
- touching a crown jewel
- reading shell history or `.env` files
- an agent editing its own configuration
- creating start-up or scheduled-task items
- privacy permission changes
- a new network destination
- an agent starting another AI agent
- any attempt to touch the defence's own log or key

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
- **Blocking is recorded, not enforced.** Real blocking on macOS needs Endpoint Security *AUTH* events, which require an Apple entitlement. Until then, `BLOCK` means "the policy says block", and it's logged and alerted.
- **Network capture is polled** every 3 seconds with `lsof`, so very short connections can be missed. v1 uses a Network Extension (macOS) or eBPF (Linux).
- **Root is the trust anchor.** An agent running as root, or a user who approves it, can defeat any local monitor. Run agents as a normal user.
- **Agent recognition is by name.** A renamed binary is not recognised as an agent (its actions are still visible to the OS, just not attributed).
- Not yet tested on large live workloads. Event volume from `open` can be high.

## Roadmap

1. **v0 (this release):** transparent, tamper-evident, plain-language log + red-line alerts + crown-jewel policy.
2. **v1:**
   - native Endpoint Security client with real crown-jewel blocking
   - Network Extension for every connection
   - desktop app (Tauri)
   - signed updates
3. **Layer 2:** per-agent sandboxes. Agents may touch only their project folder and listed destinations, enforced by the OS.
4. **Layer 3:** anomaly detection against each agent's normal behaviour, plus Linux and Windows.

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
