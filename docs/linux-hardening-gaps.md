# Linux AgentPod Hardening Gaps

`agentpod-linux` is a gated prototype primitive. It can exercise native Linux
runner phases on suitable hosts, and portable CI checks that the native-plan
contract stays honest. It is not a complete sandbox, a production-safe boundary
for arbitrary untrusted code, or a kernel-grade isolation claim yet.

This document maps the remaining Linux hardening gaps to explicit follow-up
issues so public docs, demos, and release notes do not overclaim the current
implementation.

## Gap Map

| Gap | Current proof | Follow-up issue | Claim boundary |
| --- | --- | --- | --- |
| Complete syscall policy | Generated seccomp deny rules, imported OCI/libseccomp subset profiles, and a coarse connect-deny bridge for deny-all network modes. The importer validates schema, action semantics, architectures, and syscall names before compiling supported unconditional deny rules into the prototype BPF loader. | #261 | Do not claim complete libseccomp profile compatibility, default-deny profile support, conditional argument rules, notify/listener support, arbitrary profile enforcement, or syscall coverage beyond the supported prototype loader set. |
| Complete filesystem policy | ABI-aware Landlock path-beneath rules, workspace bindings, read-only mount descriptors, guest aliases, optional runtime support paths, and supported ABI v2 `REFER` / ABI v3 `TRUNCATE` rights when the host exposes them. | #262 | Do not claim complete Landlock ABI coverage, complete filesystem mediation, file-type creation rights beyond the modeled directory/regular-file subset, device `ioctl` mediation, network/scoped Landlock features, or full protection against every path escape class. |
| Packet/domain network policy | Network mode descriptors, legacy coarse deny-all connect denial through seccomp, session-cgroup-scoped nftables output-hook packet rules for IP/CIDR policy, lifecycle cleanup descriptors, and a gated nftables packet-denial smoke. | #263 | Packet firewall denial may be claimed only for the gated IP/CIDR nftables subset when the live smoke passes on that host. Do not claim live domain allowlist enforcement, DNS semantic completeness, resolver TTL refresh, wildcard support, DNS-over-HTTPS mediation, or complete network isolation. |
| Kernel event evidence | eBPF observability receipt schemas in the native plan, including provider, session, cgroup path, event identity, pid/tgid fallback fields, and observed-only semantics. | #264 | Do not claim live eBPF probe loading, live event capture, enforcement, or observed events as denial proof. |
| Mount/rootfs/proc/device boundary | Native plans now describe the real mount boundary: host-root inside a private mount namespace, no `pivot_root`, PID-namespace procfs via `unshare --mount-proc`, host `/tmp` visibility subject to Landlock policy, and host `/dev` path access mediated by Landlock/host permissions. The live smoke proves `/proc` and `/workspace` are mounted in the runner namespace, `/etc/shadow`, `/root/.ssh`, `/dev/kmsg`, and `/dev/mem` are unavailable or mediated, and the run does not leak a stale `/workspace` mount into the host namespace. | #265 | Do not claim hardened rootfs isolation, complete `/proc` isolation, private tmpfs, a private/safe device namespace, device `ioctl` mediation, or complete host path invisibility. |
| Fail-closed lifecycle cleanup | Native plans expose fail-closed lifecycle gates, setup-failure cleanup order, timeout process-tree kill policy, request-file/cgroup/nftables cleanup evidence events, partial cgroup cleanup tests, and live smoke checks for repeated request/cgroup cleanup plus timeout cleanup. | #266 | Do not claim complete failure injection for every mount/rootfs/proc/device path or cleanup behavior outside Agentbox-owned runner request files, session cgroups, and Agentbox-owned nftables tables. |

## Safe Release Language

Use these phrases for the current Linux surface:

- `gated prototype primitive`
- `portable native-plan conformance`
- `descriptor-only`
- `observed-only`
- `coarse connect-deny bridge`
- `optional live Linux smoke`
- `supported OCI/libseccomp import subset`
- `ABI-aware Landlock supported subset`
- `host-supported Landlock REFER/TRUNCATE`
- `session-cgroup-scoped nftables packet subset`
- `domain resolver/ipset semantics are explicit but not live-enforced`

Avoid these phrases until the mapped issues are complete and verified by live
tests:

- `complete sandbox`
- `kernel-grade isolation`
- `production-safe arbitrary untrusted code execution`
- `complete libseccomp support`
- `complete Landlock coverage`
- `domain allowlist enforcement`
- `complete packet firewall enforcement`

## Verification Surface

Portable CI runs the conformance wrapper:

```sh
bash scripts/smoke-linux-agentpod-conformance.sh
```

Live Linux proof remains optional and host-dependent:

```sh
AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh
AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh
```

A skipped live smoke is not a pass. It records that the current host cannot
prove the stronger Linux boundary.
