# Testing: what each test proves

This tool watches AI agents on your computer, so it needs deep access itself. You should not have to take our word that it is safe. Every claim below is checked by a test you can run on your own machine, from source you can read.

**Run everything with one command** (see the [runbook](RUNBOOK.md)):

| System | Command |
| --- | --- |
| macOS / Linux | `./scripts/verify.sh` |
| Windows | `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1` |

The same checks run publicly on every commit, on Linux, macOS and Windows, in the repository's **Actions** tab.

## 1. Is it a trojan horse? — trust tests

`cargo test --test trust` · [`crates/awd-cli/tests/trust.rs`](../crates/awd-cli/tests/trust.rs)

These tests read the project's own source code and dependency list. They fail if anyone adds a dangerous capability, so it cannot be slipped in quietly. Any change to them shows up in a public diff.

| Test | What it proves | Fails if someone… |
| --- | --- | --- |
| `no_network_code_in_the_source` | The code contains no networking at all | adds `std::net`, sockets or an HTTP client to any file |
| `no_network_libraries_in_the_dependency_tree` | None of the 50+ libraries it uses can talk to the network | adds a library such as `reqwest`, `hyper`, `tokio`, a TLS stack or a telemetry or crash reporter |
| `runs_only_the_two_documented_programs` | It starts exactly two programs: `eslogger` (Apple's event stream) and `lsof` (lists connections) | makes it run `curl`, a shell or anything else |
| `reads_no_environment_variables_except_the_home_directory` | It reads only `HOME`, `USERPROFILE` and `SUDO_USER`, to know whose home folder to protect | makes it read API keys or tokens from the environment |
| `contains_no_unsafe_code` | No `unsafe` Rust, so the compiler checks memory safety everywhere | adds `unsafe` code |
| `file_access_happens_only_at_reviewed_call_sites` | It opens files in exactly 8 reviewed places: its own log, its key, its config, and a replay file you name | adds any new place that reads, writes or deletes a file |

**We checked that these tests catch real problems.** We planted code that opened a network connection, ran `curl`, read an SSH key and read an `OPENAI_API_KEY` variable. Four of the six tests failed at once, each naming the exact problem.

## 2. Does it do what it says? — end-to-end tests

`cargo test --test end_to_end` · [`crates/awd-cli/tests/end_to_end.rs`](../crates/awd-cli/tests/end_to_end.rs)

These run the real `awd` program on a recorded session.

| Test | What it proves |
| --- | --- |
| `sample_session_reports_what_the_readme_promises` | The report finds the SSH-key access through a child process, the edit to the agent's own settings and the new start-up item, with the counts shown in the README |
| `processes_that_are_not_ai_agents_are_not_recorded` | It watches agents, not you: Notes.app reading the same SSH key is not logged |
| `file_contents_never_reach_the_log` | A file holding a unique secret marker is read and written by an agent; the log records the path but never the contents |
| `log_and_key_are_private_to_their_owner` | The data folder is `0700` and the log and key are `0600`: other users cannot read them (macOS and Linux) |
| `an_unaltered_log_verifies` | An untouched log passes `awd verify` |
| `editing_one_character_is_detected` | Changing one character in the log is caught, and the report warns about it |
| `deleting_a_line_is_detected` | Removing the line that recorded the SSH-key read is caught |
| `a_log_forged_without_the_key_is_detected` | A log written with a guessed key fails verification from the first entry |

## 3. Do the parts work? — unit tests

`cargo test --workspace` runs these with everything else.

| Area | Tests | What they prove |
| --- | --- | --- |
| Agent attribution (`awd-core`) | 5 | Children and grandchildren of an agent are attributed to it. Agents started via `python script` are recognised. Other processes are not tagged. An agent starting another agent is flagged. Exiting clears the tag. |
| Sensitivity rules (`awd-policy`) | 9 | SSH keys, keychains, browser secrets, password managers and cloud credentials are crown jewels. `.env` and shell history are sensitive. `.envrc` and ordinary project files are not. Editing an agent's own config alerts, reading it does not. A new destination alerts once. Touching the defence itself is blocked. |
| Tamper-evident log (`awd-log`) | 4 | The chain survives reopening. Edits, deletions and forged entries are all detected. |
| Event sources (`awd-collector`) | 6 | `eslogger` events (exec, write, create, fork) and `lsof` network output are parsed correctly. Malformed lines are skipped, not trusted. |

## 4. Does it need the network at runtime? — run with the network cut off

The scripts run a full record → report → verify cycle with networking removed:

| System | How the network is cut off | Proof |
| --- | --- | --- |
| macOS | `sandbox-exec` profile that denies all network access | the full run succeeds (the same sandbox stops `curl` from resolving any host) |
| Linux | `strace -e trace=network`, then a network namespace with no interfaces (`unshare -rn`) | the trace contains no internet socket (`AF_INET`/`AF_INET6`), and the run succeeds with no network at all |
| Windows (Administrator) | Windows Firewall rule blocking all outbound traffic from `awd.exe` | the full run succeeds |

## 5. Are its dependencies safe? — vulnerability audit

The CI runs `cargo audit` on every commit against the RustSec advisory database of known vulnerabilities in Rust libraries. Builds use `--locked`, so everyone compiles exactly the dependency versions in `Cargo.lock`.

## What the tests do not prove

- **Live capture** of a real agent needs root on macOS and can't run in public CI. It is tested by parsing real `eslogger` event formats, not by running `eslogger` itself.
- **A prebuilt binary you downloaded** is not covered: these tests prove the *source*. We publish no binaries; build from source as the runbook shows.
- **Root is the trust anchor.** An agent running as root, or one you grant administrator rights, can defeat any local monitor, including this one.
