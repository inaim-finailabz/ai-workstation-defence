# 0001: v1 scope — transparent log + red-line alerts + crown-jewel block

**Date:** 2026-10-07 · **Status:** accepted · **Decided by:** owner, after an Assembly of Elders review

*Note, 2026-10-10: this record numbers the tool's own build stages. In the [white paper](../whitepaper/), sandboxing ("layer 2" here) is Layer 4 and anomaly detection is Layer 5.*

## Question

AI agents run locally on our workstations. Labs keep training more capable and more persistent ones. How do we *know* they are not intruding into private data, and what is the first layer to build?

The owner proposed: a complete, transparent, simple log of what agents do on the workstation.

## What the review board said

The board had three seats. A fourth seat, Detection & Monitoring on Gemini, failed with a provider overload error.

| Seat | Position |
| --- | --- |
| Containment Architect (Claude) | **Agree.** You cannot enforce boundaries you cannot observe. The log must be OS-level, append-only and outside the agent's write reach. |
| Red Team (GPT) | **Agree, with a condition.** It must be adversarially hardened, attribute actions through child processes and sub-agents, and log *what and who, never contents*. v1 also needs cheap red-line alerts, or agents misbehave between reviews. |
| Outside Reviewer (DeepSeek) | **Disagree.** Prevention must come first. A log of exfiltration after the fact is not assurance. Build a default-deny sandbox first. |

**Rejected unanimously:** agent self-reporting as the telemetry source, logging file or clipboard contents, an LLM watchdog in the decision path, and logging with no prevention at all.

## Decision

v1 = **full OS-level transparent log** + **real-time red-line alerts** + **hard block on crown jewels only**:
- SSH keys
- keychains
- browser password and cookie stores
- password managers
- cloud and developer credentials

There is no broad allow-list sandbox in v1. Default-deny sandboxing is layer 2.

## Why

- **Logging first** gives the evidence base every later control needs, with no friction for legitimate work.
- **The crown-jewel block** answers the dissent where it matters most. No legitimate coding or summarising agent needs these stores, so blocking them costs almost nothing.
- **Red-line alerts** address the Red Team's condition, so misbehaviour is surfaced in real time.

## Consequences

- Real blocking needs Endpoint Security AUTH events on macOS, and so an Apple entitlement. Apply early. v0 records `BLOCK` decisions without enforcing them.
- Process-tree attribution is the core technical risk. It is unit-tested, but not yet tested against live adversarial evasion. That test is the next milestone.
