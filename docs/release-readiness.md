# Release Readiness Checklist

This checklist defines what must be true before tagging an Agentbox release.
It is intentionally stricter than "the repo builds" because Agentbox is a local
runtime boundary for autonomous agents.

## Release Contract

Before a release, state the support level for each surface:

- shipped
- experimental
- prototype primitive
- descriptor only
- planned

Do not promote a runtime provider because its metadata exists. Provider support
requires runnable lifecycle behavior and live proof.

## Required Gates

Run these before every release candidate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p agentbox-cli -- doctor
cargo run -p agentbox-cli -- providers
cargo run -p agentbox-cli -- evidence --verify
```

`doctor` and `evidence --verify` may require local state. If they cannot run in
CI, run them manually and record the reason.

## Install And CLI

- [ ] `cargo build --release` succeeds.
- [ ] Any installer or package follows
      [installer packaging](installer-packaging.md) and was tested on a clean
      host for that platform.
- [ ] `agentbox install` creates shims in `~/.agentbox/shims`.
- [ ] `agentbox doctor` reports daemon, socket, PATH, shims, audit, and provider
      readiness clearly.
- [ ] `agentbox start`, `status`, and `stop` work on the release host.
- [ ] `agentbox policy`, `policy-simulate`, and `policy-explain` work without a
      daemon.
- [ ] `agentbox providers` separates shipped, experimental, unavailable, and
      planned surfaces.

## Daemon And Shims

- [ ] Shims are first on `PATH` in the documented setup.
- [ ] Safe commands pass quickly.
- [ ] Approval-bucket commands request approval or deny on timeout.
- [ ] Block-bucket commands deny without notification.
- [ ] Absolute-path and direct-syscall bypass limits are documented.
- [ ] ntfy config is generated and documented.
- [ ] Failure modes are clear when the daemon is unavailable.

## Minipods And Providers

- [ ] `agentbox minipod-spec hermes --workspace .` emits valid JSON.
- [ ] `scripts/demo-autonomous-agent.sh` passes.
- [ ] Native AgentPod providers remain unavailable until live enforcement lands.
- [ ] Podman compatibility is marked experimental or unavailable honestly.
- [ ] Podman live smoke is run only on hosts where Podman is installed.
- [ ] Linux benchmark and native primitive scripts skip honestly on non-Linux
      hosts.
- [ ] Windows and macOS native provider docs match provider status.

## Policy Boundaries

- [ ] Host environment inheritance is rejected.
- [ ] Host network mode is rejected.
- [ ] Protected paths require explicit file grants.
- [ ] Denied domains win before allowlists or approval grants.
- [ ] Approval grants cannot bypass block-bucket decisions.
- [ ] Expired grants are ignored.
- [ ] Once grants are consumed.

## Evidence

- [ ] SQLite audit rows are hash-chained.
- [ ] `agentbox evidence --verify` passes on a local audit DB.
- [ ] Credential-like values are redacted from audit and transcript output.
- [ ] Session evidence bundles include approvals, boundary events, transcripts,
      replay metadata, and workspace diff references where available.
- [ ] FIDES and agit integrations are labeled skeletons unless external
      authority/adapters are configured.

## Docs

- [ ] README quickstart works from a fresh checkout.
- [ ] `docs/status-matrix.md` matches current code.
- [ ] `docs/limitations.md` names known bypass classes.
- [ ] `docs/network-enforcement-limits.md` separates classification,
      observation, provider mode, and enforcement.
- [ ] `docs/safe-credential-patterns.md` explains credential grants and
      redaction limits.
- [ ] `docs/glossary.md` defines public vocabulary.
- [ ] `docs/installer-packaging.md` matches the actual package state.
- [ ] Release notes say what is shipped, experimental, prototype, and planned.

## Public Claim Check

Reject the release if any public surface claims:

- bypass-proof isolation
- full browser, keychain, wallet, or credential isolation
- native macOS, Linux, or Windows provider execution without live proof
- eBPF, WFP, or Network Extension enforcement without denial tests
- FIDES signing or AGIT commit publication without an external adapter

## Release Notes Shape

Each release note should include:

- summary
- shipped
- experimental
- prototype primitives
- descriptor-only providers
- verification run
- known limitations
- next release focus

## Current v0.2 Bar

The next credible release should demonstrate:

1. Direct-host governance is stable.
2. Minipod manifests are deny-by-default and task-scoped.
3. Provider status reporting is honest.
4. Evidence export is useful after a session.
5. Demo scripts run without requiring proprietary agent installs.
6. Native provider work is visible as prototypes, not overclaimed as shipped.
