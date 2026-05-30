# AgentPod QA Matrix

This matrix is the release QA checklist for provider and platform coverage. It
uses the support vocabulary from the [provider truth contract](provider-truth.md)
and should not be read as a sandbox claim. A skipped host-dependent smoke is
not a pass; it means that provider was not proven on that host.

## Gate Labels

| Gate | Meaning |
|------|---------|
| Required | Must pass for every release candidate unless the candidate is explicitly marked blocked. |
| Optional/live | Run on hosts or endpoints that can exercise the provider. Results are additive proof. |
| Skipped by host dependency | The repo has a smoke or check, but the current host lacks the OS, tool, entitlement, service, or env gate. Record the skip. |
| Future | Required before stronger product or paid-provider claims, but not wired as a current release gate. |

## Provider Platform Matrix

| Platform/provider surface | Provider truth | Gate | Verification commands | Pass, skip, and claim rule |
|---------------------------|----------------|------|-----------------------|----------------------------|
| macOS direct-host | `direct-host` is `shipped` command mediation. It is useful for local policy, approvals, explicit credential grants, audit, and evidence; it is not an OS sandbox. | Required for a macOS/direct-host release candidate. | `cargo run --locked -q -p agentbox-cli -- setup --dry-run --provider direct-host --json`<br>`cargo run --locked -q -p agentbox-cli -- bridge-health --provider direct-host --json`<br>`cargo run --locked -q -p agentbox-cli -- run --provider direct-host --risk low --json -- echo ok`<br>`bash scripts/release-readiness.sh` | Pass only when direct-host commands run and provider truth still reports active command mediation. Do not claim filesystem, browser, wallet, keychain, process, or packet isolation. |
| Podman compatibility | `podman` is `experimental` compatibility support. It is not the AgentPod-native product center and does not prove domain or packet enforcement. | Optional/live; skipped by host dependency when Podman, a running Podman machine, or a Linux guest shim is unavailable. | `bash scripts/smoke-podman-bridge.sh`<br>`bash scripts/smoke-macos-minipod.sh`<br>`AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh` | Pass only when the live smoke proves daemon socket visibility and shim execution inside a Podman minipod. Exit 77 or missing Podman is a recorded skip, not a compatibility pass. |
| Linux native AgentPod | `agentpod-linux` is a gated `prototype primitive`. It can exercise native runner phases on suitable Linux hosts, but it is not a complete sandbox claim. Remaining gaps are mapped in [Linux hardening gaps](linux-hardening-gaps.md). | Portable CI for the conformance wrapper; optional/live for the gated native smoke. Live smoke is skipped by host dependency on non-Linux hosts or when `unshare`, `jq`, Landlock, writable/delegated cgroups v2, overlayfs, or the runner gate is missing. | `bash scripts/smoke-linux-agentpod-conformance.sh`<br>`AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh`<br>`AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh` | Portable CI proves the clean-checkout native-plan contract and prints the exact live command. Live pass only for the specific prototype behavior exercised: namespace runner, ABI-aware Landlock read/write/create/remove/execute plus host-supported `REFER`/`TRUNCATE` allow/deny fixtures, cgroup attachment, generated seccomp-deny rules, imported OCI/libseccomp subset deny rules, coarse connect-deny fixture for deny-all network modes, overlay-review proof, eBPF observability receipt shape in the native plan, and nftables table lifecycle when separately gated. Do not claim eBPF probe loading/live capture, complete Landlock ABI coverage beyond modeled path-beneath rules, file-type creation or device `ioctl` mediation, complete libseccomp compatibility beyond the supported import subset, domain allowlist enforcement, or packet firewall denial. |
| Remote descriptor and worker | `remote-agentpod` is `experimental`. The descriptor and worker contract can be proven locally; production trust still depends on endpoint identity, capability reporting, and returned evidence. | Required for the local contract smoke in the release gate; optional/live for endpoint-specific HTTPS workers. Loopback HTTP is a dev-only gate. | `bash scripts/smoke-remote-worker.sh`<br>`cargo run --locked -q -p agentbox-cli -- remote-descriptor --endpoint https://worker.example.com/agentpod --auth signed-challenge --evidence bundle-upload`<br>`cargo run --locked -q -p agentbox-cli -- setup --dry-run --provider remote-agentpod --endpoint https://agentpod.example.com/run --json`<br>`bash scripts/release-readiness.sh` | Pass only when the local worker smoke proves handshake, provider create/exec/destroy, policy rejection, evidence upload/stream/status, approval grant flow, workspace export/apply, restart, and kill behavior. A real remote endpoint needs its own live record; the loopback smoke is not a managed sandbox-service claim. |
| Windows descriptor | `agentpod-windows` is a descriptor/prototype surface. Job Object, AppContainer, WFP, ETW, Windows Sandbox, and Hyper-V plans exist, but provider execution remains unavailable until live Windows proof exists. | Required for descriptor truth through CLI contract checks; optional/live for the gated Job Object create/close smoke on Windows; skipped by host dependency elsewhere. | `cargo run --locked -q -p agentbox-cli -- native-plan --provider agentpod-windows -- codex exec`<br>`AGENTBOX_WINDOWS_JOB_OBJECT=1 bash scripts/smoke-windows-job-object.sh`<br>`bash scripts/smoke-cli-contracts.sh` | Pass for descriptor truth only, or for Job Object create/close when the gated Windows smoke runs. Do not claim process assignment, kill-on-close cleanup, filesystem or credential constraints, WFP denial, ETW evidence export, or VM lifecycle proof. |

## Release Use

Run the required release gate first:

```sh
bash scripts/release-readiness.sh
```

When a candidate host can exercise live providers, run the optional/live smoke
bundle:

```sh
AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh
```

For provider-specific investigation, use the scoped setup and readiness
commands before trying a live run:

```sh
cargo run --locked -q -p agentbox-cli -- provider-readiness --json
cargo run --locked -q -p agentbox-cli -- provider-readiness --provider direct-host --json
cargo run --locked -q -p agentbox-cli -- provider-readiness --provider remote-agentpod --json
cargo run --locked -q -p agentbox-cli -- setup-plan --provider podman-compat --json
cargo run --locked -q -p agentbox-cli -- setup-plan --provider agentpod-linux --json
cargo run --locked -q -p agentbox-cli -- setup-plan --provider agentpod-windows --json
```

Release notes and support artifacts should report each matrix row as passed,
failed, skipped by host dependency, or future. They should not collapse skipped
live smoke into a passed provider claim.
