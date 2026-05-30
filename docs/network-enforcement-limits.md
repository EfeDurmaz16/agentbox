# Network Enforcement Limits

Agentbox has network policy fields and network boundary evidence, but network
control is not equally strong on every runtime backend. This document separates
what is classified, what is observed, and what is actually enforced.

## Enforcement Vocabulary

| Term | Meaning |
|------|---------|
| Classified | The daemon can recognize a command or URL-like destination and decide allow, approve, or block. |
| Observed | A provider or OS hook can record that traffic happened. |
| Provider mode | The runtime backend can place the task in a coarse network mode, such as none, restricted, or host. |
| Packet/domain enforced | The OS or runtime blocks traffic at the network layer. |

Only packet/domain-enforced behavior should be marketed as network enforcement.
Classification and observation are still useful, but they are governance and
evidence layers.

## Current Platform Matrix

| Runtime | Current strength | Limit |
|---------|------------------|-------|
| Direct host shims | Command classification and audit evidence | Only commands that pass through shims are governed. Direct sockets from binaries, browsers, SDKs, or interpreters are not fully mediated. |
| Podman compatibility | Coarse provider network mode plus daemon policy/evidence | Domain allow/deny is not proven as packet-level enforcement. macOS Podman also runs behind a VM boundary. |
| macOS AgentPod | Gated VM boot prototype plus descriptors | Network Extension is planned, but no shipped entitlement-backed provider exists. The Apple Virtualization boot prototype does not mediate egress. |
| Linux AgentPod | Prototype primitives | Session-cgroup-scoped nftables output-hook packet rules can deny IP/CIDR destinations behind `AGENTBOX_LINUX_NFTABLES=1`. Domain policy is explicit but still resolver/ipset-gated. eBPF remains observed-only. |
| Windows AgentPod | Prototype primitives | WFP/ETW are planned for network governance/evidence, but provider execution remains unavailable. |

## Direct Host

Direct-host mode can classify obvious network commands such as `curl` and
`wget`, including allowlists, denylists, localhost policy, and approval on first
contact.

It does not catch:

- direct socket calls inside arbitrary binaries
- browser network access
- SDK traffic inside long-running processes
- DNS and HTTP requests made without a shimmed command
- traffic from another process running under the same user account

Use this mode for operator approval and evidence around common agent command
lines, not for complete egress control.

## Podman Compatibility

Podman gives Agentbox a useful compatibility minipod, but the current shipped
adapter should be treated as coarse network mode orchestration plus Agentbox
policy evidence.

Limits:

- network mode mapping is not the same as per-domain enforcement
- sidecars and daemon socket bridges can create intended local paths
- macOS Podman behavior depends on its Linux VM
- live proof for socket/shim/network behavior is still required on each host

Podman can remain a backend, but it is not the final network architecture.

## macOS Native Direction

Network Extension is the likely enforcement path for macOS AgentPod egress
governance. Until the entitlement, system extension lifecycle, and live
allow/deny tests exist, macOS native network support is planned only.

The minimum live proof should include:

- allowlisted destination succeeds
- denied destination fails
- unrelated host traffic is not affected
- evidence links the decision to the Agentbox session id
- uninstall/disable cleans up the network hook

## Linux Native Direction

Linux has multiple possible surfaces:

- namespace-level network isolation for coarse boundary
- nftables or cgroup-attached hooks for enforcement
- eBPF for observability and possibly enforcement after live denial tests

The current Linux AgentPod code models kernel primitives and benchmark plans.
It also has a gated nftables path behind `AGENTBOX_LINUX_NFTABLES=1`: the
native plan builds an Agentbox-owned inet table, an output hook, and rules
matched to the AgentPod session cgroup with `socket cgroupv2`. The live smoke
creates a delegated cgroup, installs a loopback TCP packet-deny rule, observes
the denied connect, removes the table, and verifies cleanup. Domain selectors
remain resolver/ipset-gated until A/AAAA snapshots, TTL refresh, CNAME behavior,
wildcards, split-horizon DNS, and DNS-over-HTTPS bypasses are handled in live
evidence. eBPF design is evidence-first unless a live hook proves blocking.

The minimum live proof should include:

- session-scoped process/cgroup correlation
- denied destination fails from inside the AgentPod
- allowed destination succeeds
- DNS behavior is explicitly handled or documented as out of scope
- evidence records observed and blocked traffic separately

## Windows Native Direction

Windows Filtering Platform is the likely enforcement path. ETW is the likely
evidence path.

WFP enforcement should not be claimed until a live test proves that a denied
flow from the AgentPod process is blocked and unrelated host traffic is not
affected. ETW by itself is observation only.

## Product Rule

When presenting Agentbox network behavior:

- say `classified` for daemon command decisions
- say `observed` for eBPF/ETW telemetry
- say `provider network mode` for coarse container/runtime modes
- say `enforced` only when a live provider test proves denial behavior

Skipped live tests are not evidence of enforcement.
