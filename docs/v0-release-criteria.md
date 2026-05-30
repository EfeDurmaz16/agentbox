# AgentPod v0 Release Criteria

This is the public v0 release bar for Agentbox AgentPods. It is written for an
operator deciding whether a build is usable, supportable, and honestly
described. It is not a pricing page and it is not a roadmap claim.

The v0 release can be OSS-proud before it is paid-product ready. Those bars are
different:

- **OSS-proud** means a technical operator can build from source, run the
  shipped paths, inspect provider truth, verify evidence, and understand every
  major limitation without private services.
- **paid-product** means install, recovery, support collection, provider
  claims, and evidence verification are dependable enough that a customer can
  pay for the packaged product and get clear answers when it fails.

## Claim Vocabulary

Every release surface must use the same support vocabulary as
`agentbox providers`, `agentbox provider-readiness`, and
`docs/release-readiness.md`:

- `shipped`: runnable in the release path and covered by normal verification.
- `experimental`: runnable or contract-backed, but not a stable support promise.
- `prototype`: gated implementation proof with explicit host requirements.
- `descriptor-only`: metadata, plan, or contract surface without live
  enforcement.
- `planned`: design direction only.

Provider metadata is not proof. A provider moves up only when lifecycle,
enforcement, and evidence behavior have live verification for the claimed host.

## Current Provider Truth For v0

| Provider | v0 claim allowed | v0 claim not allowed | Required proof |
|----------|------------------|----------------------|----------------|
| `direct-host` | Fallback/dev path for low-risk command governance, approvals, explicit environment/credential grants, and hash-chained evidence. | Full filesystem, process, browser, wallet, keychain, or packet isolation. It is weak isolation and must not be sold as the paid-product sandbox for arbitrary agent work. | `cargo run --locked -q -p agentbox-cli -- run --provider direct-host --risk low --json -- echo ok`, `cargo run --locked -q -p agentbox-cli -- bridge-health --provider direct-host --json`, and the release gate. |
| `podman` | Compatibility provider when Podman is installed and live smoke passes on the target host. | Agentbox-owned native isolation, uniform cross-platform behavior, or packet/domain enforcement. | `bash scripts/smoke-podman-bridge.sh` or `AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh` on a host with Podman. A skip is not a pass. |
| `agentpod-linux` | Gated native prototype on Linux hosts that satisfy namespace, cgroup v2, Landlock, seccomp, overlayfs, and runner prerequisites. | Default paid-product backend, complete sandbox, live eBPF probe loading/capture, complete Landlock ABI coverage beyond modeled path-beneath rules, complete libseccomp import, domain allowlist enforcement, or packet firewall denial. | `bash scripts/smoke-linux-agentpod-conformance.sh` runs in CI and verifies the clean-checkout native-plan contract. `AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh` is the live Linux gate. The portable native-plan contract proves descriptor-only eBPF receipts identify session/process fields without claiming enforcement; the Linux-only unit fixture proves coarse `connect(2)` denial for deny-all network modes; `AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh` proves table lifecycle only, not egress enforcement. |
| `agentpod-macos` | Descriptor and gated runner contract until live VM lifecycle, signed system extension, Network Extension, and denial tests exist. | Native macOS AgentPod execution or enforcement. | Current release gates may verify provider truth and compatibility smoke, but they do not prove native macOS execution. A future paid claim needs a live macOS native smoke that boots, mediates, denies, records evidence, and cleans up. |
| `agentpod-windows` | Descriptor/prototype primitives for Job Objects, AppContainer, WFP, ETW, Windows Sandbox, and Hyper-V planning. | Native Windows AgentPod execution or enforcement. | `AGENTBOX_WINDOWS_JOB_OBJECT=1 bash scripts/smoke-windows-job-object.sh` proves only Job Object create/close. A paid claim needs process assignment, cleanup, filesystem/credential constraints, network evidence or denial, and evidence export. |
| `remote-agentpod` | Experimental remote worker path when an HTTPS endpoint, or explicitly gated loopback dev endpoint, is configured. | General managed sandbox service, durable paid remote runtime, or secret-safe production worker fleet. | `bash scripts/smoke-remote-worker.sh` plus endpoint-specific provider readiness, evidence upload/status, restart, destroy, and support artifacts. |

## OSS-Proud v0 Bar

An OSS-proud v0 release is acceptable when all of the following are true:

- A fresh checkout can build and test without private services.
- The README explains AgentPod, direct-host, Podman compatibility, native
  descriptors, and evidence without overclaiming isolation.
- Provider truth is inspectable through CLI JSON, including primitive status,
  active flags, gates, and enforcement scope.
- Direct-host examples run as command-governance examples, not sandbox claims.
- Podman examples either pass live smoke or clearly skip with a documented
  reason.
- Linux native, macOS native, Windows native, and remote AgentPod claims match
  their current gates.
- Evidence export and verification are documented as part of normal operation.
- Skipped live tests are recorded as skipped, not counted as passing proof.
- Release notes separate shipped, experimental, prototype, descriptor-only, and
  planned surfaces.

Minimum OSS verification:

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
bash scripts/smoke-cli-contracts.sh
bash scripts/release-readiness.sh
```

If `doctor` fails because the host is not set up, do not hide the failure. Set
`AGENTBOX_RELEASE_ALLOW_DOCTOR_FAILURE=1` only to produce artifacts for a
blocked release candidate, not to turn the candidate green.

## Paid-Product v0 Bar

A paid-product v0 release requires the OSS-proud bar plus operational proof:

- A clean-host install path exists for each claimed paid platform.
- Upgrade, rollback, uninstall, daemon recovery, shim recovery, and failed setup
  recovery are documented and tested on each claimed platform.
- The installer preserves provider truth. It must not make direct-host,
  Podman, descriptor-only native providers, or gated prototypes look stronger
  than the CLI reports.
- Support collection can gather doctor output, setup plan, provider gaps,
  provider readiness, bridge health, release artifacts, logs, and evidence
  references without exposing secrets.
- Evidence verification is required before support trusts a session bundle,
  native receipt, or remote worker receipt.
- Paid claims name the exact provider and platform that passed live gates.
  "AgentPod support" by itself is too vague.
- Direct-host can be included as fallback/dev command governance, but it cannot
  be the paid isolation story for high-risk autonomous work.
- Podman can be included as compatibility support, but not as the architecture
  or as native Agentbox isolation.
- Linux native can be sold only as a gated prototype unless the release includes
  repeatable live enforcement proof on the supported Linux target.
- macOS and Windows remain unavailable/descriptor/prototype unless live gates
  prove execution, denial, evidence, cleanup, and recovery on those platforms.

Minimum paid verification for each claimed platform:

```sh
cargo build --locked --release
cargo run --locked -q -p agentbox-cli -- setup --dry-run --wizard --json
cargo run --locked -q -p agentbox-cli -- setup-plan --json
cargo run --locked -q -p agentbox-cli -- doctor --json
cargo run --locked -q -p agentbox-cli -- providers --json
cargo run --locked -q -p agentbox-cli -- provider-gaps --json
cargo run --locked -q -p agentbox-cli -- provider-readiness --json
cargo run --locked -q -p agentbox-cli -- bridge-health --json
bash scripts/release-readiness.sh
```

Run live provider smoke only on hosts that can actually exercise that provider:

```sh
AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh
bash scripts/smoke-podman-bridge.sh
AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh
AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh
AGENTBOX_WINDOWS_JOB_OBJECT=1 bash scripts/smoke-windows-job-object.sh
```

The macOS compatibility smoke is Podman compatibility proof, not native macOS
AgentPod proof:

```sh
bash scripts/smoke-macos-minipod.sh
```

## Category Gates

### Provider Truth

The release blocks if public docs, README, CLI output, or release notes disagree
with provider JSON:

```sh
cargo run --locked -q -p agentbox-cli -- providers --json
cargo run --locked -q -p agentbox-cli -- provider-gaps --json
cargo run --locked -q -p agentbox-cli -- provider-readiness --json
cargo run --locked -q -p agentbox-cli -- bridge-health --json
```

Operators must be able to answer:

- Which provider is selected?
- Which primitives are active, prototype, descriptor-only, missing, or gated?
- Which env gate or host prerequisite is required?
- What enforcement scope is actually claimed?
- Which verification command proves the claim?

### Installer

For OSS v0, source build plus explicit shim installation can be enough. For
paid-product v0, an installer or package must preserve all current truth
boundaries:

```sh
cargo build --locked --release
cargo run --locked -q -p agentbox-cli -- setup --dry-run --wizard --json
cargo run --locked -q -p agentbox-cli -- setup --dry-run --provider direct-host --json
cargo run --locked -q -p agentbox-cli -- setup-plan --json
```

Do not ship a paid installer that mutates PATH, shell files, services, network
rules, privileged helpers, or native provider state without an explicit operator
step and a rollback path.

### QA

The normal v0 QA floor is:

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
bash scripts/smoke-cli-contracts.sh
bash scripts/demo-v0.2.sh
bash scripts/demo-autonomous-agent.sh
bash scripts/release-readiness.sh
```

Live-provider QA is additive and host-specific. A skipped live smoke must be
called out in release notes and paid support materials.

### Docs

Docs are release-blocking when they affect operator trust. Before v0, verify:

- `README.md` says Agentbox runs AgentPods and names the current provider
  boundaries.
- `docs/status-matrix.md` matches `agentbox providers --json` and
  `agentbox provider-readiness --json`.
- `docs/limitations.md` explains direct-host, Podman, native provider, and
  credential boundaries.
- `docs/installer-packaging.md` matches the actual installer/package state.
- `docs/release-readiness.md` links to this v0 release criteria document.
- Release notes include the exact verification commands and artifact location.

### Support

Until a dedicated support bundle command ships, the support baseline is a
manual collection path:

```sh
cargo run --locked -q -p agentbox-cli -- doctor --json
cargo run --locked -q -p agentbox-cli -- setup-plan --json
cargo run --locked -q -p agentbox-cli -- provider-gaps --json
cargo run --locked -q -p agentbox-cli -- provider-readiness --json
cargo run --locked -q -p agentbox-cli -- bridge-health --json
bash scripts/release-readiness.sh
```

Support must ask for evidence references or a verified evidence bundle before
trusting claims about what happened in a session. Support materials must also
state which files may contain local paths or logs and must avoid collecting raw
secrets, tokens, private keys, or credential payloads.

### Evidence Verification

Evidence is part of the release bar, not a demo extra. Operators must be able to
export and verify an AgentPod session bundle:

```sh
cargo run --locked -q -p agentbox-cli -- evidence --session <session-id> --bundle ./agentbox-evidence
cargo run --locked -q -p agentbox-cli -- evidence --verify --bundle ./agentbox-evidence
```

Local audit verification remains useful when a local audit database exists:

```sh
cargo run --locked -q -p agentbox-cli -- evidence --verify
```

A release blocks if evidence verification accepts a tampered bundle, if public
docs imply replay can safely rerun side-effecting commands, or if descriptor
integrations such as FIDES, AGIT, or OAPS are described as live integrations
without configured external adapters.

## Release Decision

Use this decision table when cutting v0:

| Decision | Allowed when | Public wording |
|----------|--------------|----------------|
| Ship OSS v0 | OSS-proud bar passes, limitations are current, and release-readiness artifacts exist. | "Agentbox v0 ships governed AgentPod command execution, provider truth reporting, and evidence verification. Native provider work remains prototype or descriptor-only unless stated otherwise." |
| Ship paid preview | OSS-proud bar passes, clean-host install/recovery/support are proven for the named platform, and paid materials clearly limit provider claims. | "Paid preview for named platform and provider scope." |
| Ship paid v0 | Paid-product bar passes for each claimed platform and provider. | "Paid AgentPod support for the verified platform/provider matrix." |
| Block release | Required doctor checks fail, provider truth is inconsistent, evidence verification is missing, docs overclaim isolation, or installer/support paths are unproven. | "Release candidate blocked by listed gates." |

When in doubt, downgrade the claim. An incomplete release is acceptable. A
misleading release is not.
