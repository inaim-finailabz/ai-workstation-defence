# Testing: what each test checks, and what it does not

This tool watches AI agents on your computer, so it needs deep access itself. You should not have to take our word that it is safe. Every check below is a test you can run on your own machine, from source you can read.

Read the results for what they are. The trust tests are safeguards that make sensitive changes visible; they do not prove the software cannot communicate or misbehave. The other tests run on replayed sessions; they do not establish that live capture is complete, fast enough or hard to evade. [The last section](#what-the-tests-do-not-show) lists the gaps.

**Run everything with one command** (see the [runbook](RUNBOOK.md)):

| System | Command |
| --- | --- |
| macOS / Linux | `./scripts/verify.sh` |
| Windows | `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1` |

The same checks run publicly on every commit, on Linux, macOS and Windows, in the repository's **Actions** tab.

## 1. Would a sensitive change be noticed? — trust tests

`cargo test --test trust` · [`crates/awd-cli/tests/trust.rs`](../crates/awd-cli/tests/trust.rs)

These tests search the project's own source code and dependency list for known patterns. They fail if someone adds a dangerous capability by one of the usual routes, so that route cannot be used quietly. Any change to the tests themselves shows up in a public diff.

They are text searches, so they catch what they look for and nothing else. Passing them does not prove the tool has no way to reach the network or to misbehave.

| Test | What it checks | Fails if someone… | What it would miss |
| --- | --- | --- | --- |
| `no_network_code_in_the_source` | The project's own source does not mention the standard networking types or common HTTP clients | adds `std::net`, sockets or an HTTP client to any file | Networking reached another way: through a dependency, a raw system call, or a program it starts |
| `no_network_libraries_in_the_dependency_tree` | None of a list of well-known networking, TLS and telemetry libraries is in `Cargo.lock` | adds a library such as `reqwest`, `hyper`, `tokio`, a TLS stack or a telemetry or crash reporter | A library that is not on the list, or one that opens sockets through the standard library |
| `runs_only_the_two_documented_programs` | The source starts two programs by name: `eslogger` (Apple's event stream) and `lsof` (lists connections) | makes it run `curl`, a shell or anything else with `Command::new` | A program started by a dependency, or a different `eslogger` or `lsof` earlier on the `PATH` |
| `reads_no_environment_variables_except_the_home_directory` | The source reads only `HOME`, `USERPROFILE` and `SUDO_USER`, to know whose home folder to protect | makes it read API keys or tokens with `env::var` | Environment reads inside dependencies |
| `contains_no_unsafe_code` | The project's own source has no `unsafe` Rust | adds `unsafe` code to this project | `unsafe` code inside the dependencies, which is common and not checked here |
| `file_access_happens_only_at_reviewed_call_sites` | The source opens files at 8 reviewed kinds of call site: its own log, key and head record, its config, and a replay file you name | adds a new place that reads, writes or deletes a file with the standard calls | File access through a dependency or a call pattern not on the list |

**We checked that these tests catch the obvious cases.** We planted code that opened a network connection, ran `curl`, read an SSH key and read an `OPENAI_API_KEY` variable. Four of the six tests failed at once, each naming the exact problem. We have not tested them against code written to get past them.

## 2. Does it do what it says? — end-to-end tests

`cargo test --test end_to_end` · [`crates/awd-cli/tests/end_to_end.rs`](../crates/awd-cli/tests/end_to_end.rs)

These run the real `awd` program on a recorded session, not on a live agent.

| Test | What it checks |
| --- | --- |
| `sample_session_reports_what_the_readme_promises` | The report finds the SSH-key access through a child process, the edit to the agent's own settings and the new start-up item, with the counts shown in the README. It also says the action marked for blocking went ahead |
| `processes_that_are_not_ai_agents_are_not_recorded` | It watches agents, not you: Notes.app reading the same SSH key is not logged |
| `file_contents_never_reach_the_log` | A file holding a unique secret marker is read and written by an agent; the log records the path but never the contents |
| `log_and_key_are_private_to_their_owner` | The data folder is `0700` and the log, key and head record are `0600`: other users cannot read them (macOS and Linux) |
| `an_unaltered_log_verifies` | An untouched log passes `awd verify` |
| `editing_one_character_is_detected` | Changing one character in the log is caught, and the report warns about it |
| `deleting_a_line_is_detected` | Removing the line that recorded the SSH-key read is caught |
| `a_log_forged_without_the_key_is_detected` | A log written with a guessed key fails verification from the first entry |
| `cutting_off_the_newest_entries_is_detected` | A log cut back to its first 5 entries fails `awd verify`, the report warns, and `awd watch` refuses to carry on recording over the gap |
| `deleting_the_head_record_does_not_hide_a_cut` | Removing the head record as well does not make the cut log pass |
| `deleting_the_whole_log_is_detected` | Removing the log while its head record remains fails verification |
| `an_anchor_kept_elsewhere_catches_a_rollback_of_log_and_head_together` | Putting back an older log with its matching older head record passes the local check, and fails as soon as `awd verify --anchor` is given an anchor taken earlier. This is the case the head record alone cannot catch |

## 3. Do the parts work? — unit tests

`cargo test --workspace` runs these with everything else.

| Area | Tests | What they check |
| --- | --- | --- |
| Agent attribution (`awd-core`) | 5 | Children and grandchildren of an agent are attributed to it. Agents started via `python script` are recognised. Other processes are not tagged. An agent starting another agent is flagged. Exiting clears the tag. |
| Sensitivity rules (`awd-policy`) | 9 | SSH keys, keychains, browser secrets, password managers and cloud credentials are crown jewels. `.env` and shell history are sensitive. `.envrc` and ordinary project files are not. Editing an agent's own config alerts, reading it does not. A new destination alerts once. Touching the defence itself is blocked. |
| Tamper-evident log (`awd-log`) | 10 | The chain survives reopening. Edits, deletions and forged entries are detected. A cut-off end, a deleted log and a deleted head record are detected. A head record cannot be forged without the key. A log one entry ahead of its head record (a crash between the two writes) reopens. An outside anchor catches a rollback and a full rewrite with the real key. |
| Event sources (`awd-collector`) | 6 | `eslogger` events (exec, write, create, fork) and `lsof` network output are parsed correctly. Malformed lines are skipped, not trusted. |

## 4. Does the replayed session need the network? — run with the network cut off

The scripts run a record → report → verify cycle on the sample session with networking removed. This shows that this run completes without the network. It does not show that no other code path ever tries to use it.

| System | How the network is cut off | What was observed |
| --- | --- | --- |
| macOS | `sandbox-exec` profile that denies all network access | the full run succeeds (the same sandbox stops `curl` from resolving any host) |
| Linux | `strace -e trace=network`, then a network namespace with no interfaces (`unshare -rn`) | the trace contains no internet socket (`AF_INET`/`AF_INET6`), and the run succeeds with no network at all |
| Windows (Administrator) | Windows Firewall rule blocking all outbound traffic from `awd.exe` | the full run succeeds |

## 5. Are its dependencies safe? — vulnerability audit

The CI runs `cargo audit` on every commit against the RustSec advisory database of known vulnerabilities in Rust libraries. Builds use `--locked`, so everyone compiles exactly the dependency versions in `Cargo.lock`.

## What the tests do not show

- **Live capture is not validated.** Capturing a real agent needs root on macOS and can't run in public CI. It is tested by parsing real `eslogger` event formats, not by running `eslogger` itself. Nothing here measures whether every action of a live agent is recorded.
- **Performance under real workloads is not measured.** Replays are small. `open` events from a busy agent can be very frequent, and no published result shows how many events per second the tool keeps up with, what it costs in CPU, or whether events are dropped under load.
- **Resistance to evasion is not tested.** No test tries to escape the tool. Known gaps: an agent binary that is renamed or copied is not attributed, and a connection shorter than the 3-second poll can be missed.
- **Blocking is not tested, because there is none.** v0 records a "would block" decision. The tests confirm it is recorded and reported as not enforced.
- **The trust tests are safeguards, not proof.** They are pattern searches over this project's source and its dependency list. They do not audit what the 50+ dependencies do, and they would not catch code written to avoid the patterns.
- **The log's local protection has a limit.** The tests show the head record catches a cut-off end. They also show it does not catch a rollback of log and head record together; only an anchor you keep elsewhere does.
- **A prebuilt binary you downloaded** is not covered: these tests check the *source*. We publish no binaries; build from source as the runbook shows.
- **Root is the root of trust.** An agent running as root, or one you grant administrator rights, can defeat any local monitor, including this one.

**What live validation needs before the tool is relied on for protection:** a real agent session compared against an independent record of what it did, event rates and CPU cost under a heavy build, and a set of deliberate evasion attempts with the results published, including the ones that succeed.
