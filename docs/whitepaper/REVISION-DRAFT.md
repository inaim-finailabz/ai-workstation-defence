# AI Defence in Depth: revision 2 notes

*10 October 2026. These changes are applied to the white paper as Revision 2: the PDF, both diagrams and the READMEs in this repository. The "What this means for awd" section at the end is still open work on the tool.*

Three things differ from the wording below. The 3 a.m. rule uses the main proposal (contain the source); the high-confidence-detector alternative was not taken. The week 3 gate was shortened to fit the diagram: "every honeytoken alerts when you trigger it, and an out-of-range argument is refused". The Appendix C threshold note lists all three starting values in one sentence.

## What changes and why

Six changes close the gaps the four recommended improvements pointed at, and four corrections fix places where the paper disagrees with itself. The text in each section below is written in the paper's voice, ready to paste.

| # | Change | Where | The one-line version |
| --- | --- | --- | --- |
| 1 | Check the arguments, not just the tool | Layer 4 | List what is allowed. A blocked pattern comes back slightly changed. |
| 2 | Watch what leaves | Layer 4, Appendix C | Bait that turns up in an outgoing message is proof, not suspicion. |
| 3 | Approve on another device | Layer 4 | An agent that can use your screen can click your Approve button. |
| 4 | Narrow before you kill | Layers 4 and 6 | Suspicion costs the agent its power, not its task. |
| 5 | Snapshot before writing | Layer 4 | Every allowed change can be undone. What cannot be undone needs approval. |
| 6 | One 3 a.m. rule, not two | Layer 6 | One alarm contains its source. Two detectors contain everything. |

Two of the four recommendations are not adopted as written. A trust score built from the model's own confidence breaks principle 4, "Rules act; AI only advises", so narrowing runs on fixed counters instead. Regex deny-lists and credential stripping are weaker than what the paper already does: it keeps real keys out of the sandbox, and its own threat table says exact-pattern rules miss the next variant.

The corrections: the executive summary points the tool at the wrong layer and says "tamper-proof"; Appendix A's text and rules disagree; Appendix B's allow-list includes a way out; Appendix C does not parse as intended.

## Executive summary

Two sentences change, and one gains a clause.

| Current | Replace with |
| --- | --- |
| 4. Agent containment. Agents you deploy run in sandboxes with short-lived, narrow permissions they cannot widen. | 4. Agent containment. Agents you deploy run in sandboxes with short-lived, narrow permissions they cannot widen, and that shrink on suspicion. |
| 5. Detection and deception. Tamper-proof logs, rules tuned to AI behaviour, and bait that only an intruder would touch. | 5. Detection and deception. Tamper-evident logs, rules tuned to AI behaviour, and bait that only an intruder would touch. |
| Start with the first layer today. An open-source tool for it, a transparent, tamper-evident log of what AI agents do on your own workstation, is published at github.com/inaim-finailabz/ai-workstation-defence. | Start with Layer 1 today: put your machines on a private mesh. Then find out what your agents already do. An open-source tool for that, the first piece of Layer 5, keeps a transparent, tamper-evident log of what AI agents do on your own workstation: github.com/inaim-finailabz/ai-workstation-defence. |

The log is tamper-evident, not tamper-proof: changes are detected, not prevented. The rest of the paper and the repository already say it that way.

## Layer 4: containing the agents you deploy

Seven components join the list, after "Approve the effect, not the story". Nothing existing is removed.

- **Check the arguments, not just the tool.** Every tool has a fixed schema: the type, range and allowed values of each argument. The proxy rejects any call that does not fit. File paths are resolved to their real location first, following links and `..`, and must land inside the workspace. Destinations and recipients must be on the task's list. No tool that crosses the boundary accepts a free-form command. List what is allowed, never what is bad: a blocked pattern comes back slightly changed.
- **Watch what leaves.** The proxy compares everything outbound (request bodies, email text, commit contents) with the honeytoken values planted in the sandbox. A match means the agent read bait and is now sending it out. That is a Tier 1 trigger with almost no false positives.
- **Unknown means ask.** The proxy holds a fixed table that puts every tool in one of three classes: allowed, needs approval, never. A tool that is not in the table needs approval.
- **Approve on another device.** Approval happens on a device the agent cannot operate, such as your phone, confirmed with a passkey. An agent that can use your screen and keyboard can click an Approve button on the same machine. A request nobody answers expires as denied (for example after 30 minutes). Silence never approves.
- **Narrow on suspicion.** The token service counts fixed signals per agent: repeated denials, a call that failed its argument check, a request to change its own configuration. Past a threshold, the agent's next token is narrower: read-only, no outward-facing tools, no sub-agents. Narrowing is automatic. Widening is yours, in the morning. No score comes from the model, because an agent's confidence is the agent's own report.
- **Outside content narrows too.** Once an agent has read content from outside your control (a web page, an inbound email, a document from a stranger), every outward-facing tool needs approval for the rest of the task. This does not depend on spotting the hidden instruction. It assumes one is there.
- **Snapshot before writing.** Before the proxy carries out any write outside the sandbox, it records the state it is about to change: a commit for a repository, a filesystem snapshot (APFS, ZFS, Btrfs) for other folders. Snapshots live on the proxy's side, out of the agent's reach. The log entry holds the snapshot's ID, never its contents. Undoing a bad action is then a restore, not an investigation. Snapshots cover only what can be undone. A sent email cannot, which is why it needs approval.

In the persistence table, one existing row gains a clause and five rows are added.

| Persistent behaviour | What catches it |
| --- | --- |
| Retrying a denied action in smaller pieces or another tool (existing row) | Proxy logs repeated denials followed by a variant; alert on the pattern and narrow the token |
| Hiding a blocked value inside an allowed argument | Fixed argument schemas; paths resolved before they are checked |
| Sending out a secret it found | No real keys in the sandbox; honeytoken match on outbound content |
| Clicking its own approval | Approval on a separate device, confirmed with a passkey |
| Following instructions hidden in a page or email | Outward-facing tools need approval once outside content is read |
| Waiting for the approver to give up | Unanswered requests expire as denied |

## Layer 6: response while you sleep

The tier table gains a row above Tier 1, and the 3 a.m. rule is rewritten so it no longer overrides Tier 2. Tiers 1 to 3 keep their numbers, so the roadmap and Appendix C stay valid.

| Tier | Actions | Runs | Safeguard |
| --- | --- | --- | --- |
| 0: Narrow (new) | Re-issue one agent's token with less scope: read-only, no outward-facing tools, no sub-agents | Automatically, on fixed counters or once outside content is read | One agent only; the task continues; only a human restores scope |
| 1: Instant | Kill a session, revoke a token, tarpit or block a source, reset an agent sandbox, isolate whatever touched a honeytoken | Automatically, in under a second, on one detector | Narrow and reversible |
| 2: Contain | Lock an account, cut a host off the mesh, suspend all agent workflows | Automatically, only when 2 independent detectors agree | Expires on its own unless a human confirms |
| 3: Human | Wipe and rebuild, delete accounts, contact police, notify others | Only with a human decision | Waits safely, because Tier 2 already contained the threat |

Replace the 3 a.m. paragraph with:

**The 3 a.m. rule: contain the source first.** If a critical alert gets no acknowledgement within 15 minutes, the system contains the source of that alert: the one agent, account or host that raised it. Its workflows are suspended, its tokens are revoked and its host leaves the mesh. Everything else keeps running. Containing everything still needs two independent detectors, whether you are awake or asleep. Containment lifts after a set window (for example 4 hours) unless someone reviews it. Logs and the incident record stay. A false alarm costs one agent a few hours; a real one is stopped.

As published, Tier 2 needs two detectors but the 3 a.m. rule applies it after one unanswered alert. One alert an attacker can trigger, plus 15 minutes of sleep, suspends everything. That is the shield turned against you, which this section promises cannot happen.

An alternative, if the original reach is preferred: keep full containment on one unanswered alert, but only for detectors listed as high-confidence, such as a touched honeytoken. Pick one and state it.

Add two items under "The shield cannot be turned against you":

- **Narrowing only goes one way.** No signal widens a token. An attacker who trips the counters gets an agent with less power, never more. The worst they can do is make your agent ask you more often.
- **Silence never approves.** The 3 a.m. rule contains threats. It never grants a pending request. Unanswered approvals expire as denied.

## What this cannot stop

The new controls have limits of their own, so two gaps join the list.

- **An allowed action with the wrong meaning.** Argument checks confirm that a recipient is on the list and a path is inside the workspace. They cannot tell whether the message should be sent or the change is correct. That judgement stays with the approval screen, and with you.
- **What cannot be undone.** Snapshots restore files. They do not recall an email, a payment or a secret that has already been read.

## Appendix A: default-deny mesh access rules

The published text says agent hosts reach "the model proxy and code host", but the rules grant the model proxy only. The tag is also renamed to match Layer 4, which calls it the tool proxy. Replace the introduction and the policy with:

**A. Default-deny mesh access rules** (Tailscale policy format; Headscale reads the same format). Anything not listed is denied. Note what is missing: no rule lets servers reach workstations, and agent hosts reach only the tool proxy and the outbound proxy. The mesh decides who may connect to the backup host. The backup store itself, through object lock and a write-only credential, decides that nothing there can be changed or deleted.

```jsonc
{
  "tagOwners": {
    "tag:server":       ["autogroup:admin"],
    "tag:agent-host":   ["autogroup:admin"],
    "tag:tool-proxy":   ["autogroup:admin"],
    "tag:egress-proxy": ["autogroup:admin"],
    "tag:backup":       ["autogroup:admin"]
  },
  "acls": [
    // Your own devices may reach servers on SSH and HTTPS only
    {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22,443"]},
    // Agent hosts may reach the tool proxy; model APIs and the code host sit behind it
    {"action": "accept", "src": ["tag:agent-host"], "dst": ["tag:tool-proxy:443"]},
    // Agent hosts may reach the outbound proxy for package mirrors (Appendix B)
    {"action": "accept", "src": ["tag:agent-host"], "dst": ["tag:egress-proxy:3128"]},
    // Servers may connect to the backup host; write-once is enforced there, not here
    {"action": "accept", "src": ["tag:server"], "dst": ["tag:backup:443"]}
  ]
}
```

The old comment, "nothing may read or delete from it over the mesh", claimed something a port rule cannot do. A rule that opens port 443 allows reads, writes and deletes alike.

## Appendix B: outbound allow-list for agent hosts

The code host comes off the list. An agent that can reach all of github.com can push to any account's repository or gist, so the published list contains a way out. Replace the introduction and the configuration with:

**B. Outbound allow-list for agent hosts** (Squid forward proxy, running outside the agent's machine). Pair it with a firewall rule that lets the agent network reach only this proxy and the tool proxy. The code host is deliberately absent: it is reached through the tool proxy, limited to the repositories the task names. A public registry is still a place where anyone can publish. The allow-list limits where the agent can go; pinned lockfiles and a local mirror limit what comes back.

```
acl agent_net src 10.50.0.0/24
acl pkg_mirrors dstdomain .pypi.org .files.pythonhosted.org .npmjs.org
acl tls_port port 443

http_access deny !agent_net
http_access deny !tls_port
http_access allow pkg_mirrors
http_access deny all
# Every denied request is logged; repeated denials feed the "retry with variation" rule
```

## Appendix C: response policy

The published template has two faults a YAML parser exposes, and it gains the new rules. `do: apply_tier: 2` is a syntax error. `[tarpit(source, 30m)]` reads as two actions, `tarpit(source` and `30m)`, because the comma splits the list; any action with arguments needs quotes. Replace the policy with:

```yaml
rules:
  - name: honeytoken-touched
    when: { detector: canary, any: true }
    tier: 1
    actions: ["revoke_tokens(source)", "isolate_host(source)", page_owner]
  - name: honeytoken-in-outbound
    when: { detector: tool_proxy, outbound_matches: honeytoken_values }
    tier: 1
    actions: [block_call, "revoke_tokens(source)", page_owner]
  - name: recon-burst
    when: { detector: proxy_logs, distinct_denied: ">=50", window: 5m }
    tier: 1
    actions: ["tarpit(source, 30m)"]
  - name: repeated-denials
    when: { detector: tool_proxy, denied_calls: ">=5", window: 10m, per: agent }
    tier: 0
    actions: ["narrow_token(agent, read_only)"]
    restore: human
  - name: outside-content-read
    when: { detector: tool_proxy, read_source: untrusted }
    tier: 0
    actions: ["require_approval(agent, outward_tools)"]
    restore: end_of_task
  - name: confirmed-intrusion
    when: { agree: [edr, rule_engine], min_sources: 2 }
    tier: 2
    actions: [lock_account, "remove_from_mesh(host)", suspend_agents]
    expires: 4h
limits:
  max_accounts_locked: { count: 3, window: 10m, then: escalate_only }
approvals:
  device: separate
  unanswered: { after: 30m, do: deny }
unacknowledged_critical:
  after: 15m
  do: { contain: source, expires: 4h }
```

The thresholds (5 denials in 10 minutes, 30 minutes for an approval) are starting values, in the same spirit as the paper's 50 requests in 5 minutes. Tune them to your own traffic.

## Knock-on edits

Six smaller edits keep the rest of the paper and the repository consistent with the changes above.

| Where | Edit |
| --- | --- |
| Layer 5 detection table, "Prompt injection" row | Trigger becomes: "Agent input containing override or exfiltration instructions. A hint only: Layer 4 assumes every outside input carries one." |
| Containment diagram, tool proxy box | "Checks every call" becomes "Checks every call and its arguments". Add a line: "Snapshots before it writes". |
| Roadmap diagram, week 3 gate | "Every honeytoken raises an alert when you trigger it, and a call with an out-of-range argument is refused." |
| Roadmap diagram, week 4 exercise | Add two checks: an unanswered approval expires as denied, and a narrowed agent cannot widen itself. |
| Quarterly numbers after week 4 | Add a fourth: time to undo, from spotting a bad agent write to the restored state. |
| Repository README roadmap | Items 3 and 4 call sandboxes "Layer 2" and anomaly detection "Layer 3". In the paper they are Layers 4 and 5. Rename to "Next: per-agent sandboxes (paper Layer 4)" and "Later: anomaly detection (paper Layer 5)". |

Decision record 0001 uses the old numbering too. It is a dated record, so leave its text and add a one-line note pointing to the paper's numbering.

## What this means for awd

Three faults come first, then three features that carry the paper's changes into the tool. The faults were confirmed by building `awd` at commit 8642b63 and running it with the replay source.

| # | Item | Observed or proposed | Fix |
| --- | --- | --- | --- |
| 1 | Deleting the newest log entries is not detected | A 26-entry log cut to its first 5 lines still passes: `awd verify` reports "OK: 5 entries, chain intact". The README says deleting any line is detected. | Record the head of the chain (entry count and last MAC) where the agent cannot write, and have `verify` compare against it. An `awd anchor` command can print it for shipping off the machine. |
| 2 | `.env.example` raises a HIGH alert | Every `.env.*` file is classed as secrets. Coding agents read `.env.example` routinely, and the paper plants bait in that same file. | Exempt `.example`, `.sample` and `.template`, or treat the file as a honeytoken when it is listed as one (item 5). |
| 3 | "New destination" alerts repeat after a restart | The seen-destinations list is held in memory. Replaying the sample session twice into one log alerts twice for the same address. | Rebuild the list from the log when `watch` starts. |
| 4 | Strike counter (Tier 0 signal) | `Policy` already keeps per-agent state. Count red-line alerts per agent and emit `narrow-recommended` at a threshold. | An alert in v0. In v1 the same counter switches that agent to a stricter rule set. |
| 5 | Honeytoken paths | Let the owner list bait files in the config. Any touch by an agent is critical. | A new category beside the crown jewels. It works on paths, since `awd` never reads contents. |
| 6 | Snapshot before write (v1 only) | v0 cannot do this: `eslogger` reports events after they happen. The native Endpoint Security client sees a write, delete or rename before it is allowed. | Clone the file first (an APFS clone is fast), keep it outside the log, and log only the snapshot ID. The client must still answer inside Apple's deadline. |

Item 1 also covers a second weakness: the key sits beside the log, so anyone who can read both can rewrite the whole chain. An anchor kept elsewhere catches that too.

The Tailscale and Squid templates have not been tested against live software; the YAML and the access-rule JSON were parsed locally.
