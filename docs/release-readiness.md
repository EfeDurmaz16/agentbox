# Release Readiness Checklist

This checklist defines what must be true before tagging an Agentbox release.
It is intentionally stricter than "the repo builds" because Agentbox is a local
runtime boundary for autonomous agents.

For the public v0 paid-product and OSS-proud release bar, including provider
truth, installer, QA, docs, support, and evidence verification criteria, see
[AgentPod v0 release criteria](v0-release-criteria.md).

## Release Contract

Before a release, state the support level for each surface:

- shipped
- experimental
- prototype primitive
- descriptor only
- planned
- unavailable

These terms are defined in the
[provider truth contract](provider-truth.md). Do not promote a runtime provider
because its metadata exists. Provider support requires runnable lifecycle
behavior and live proof.

## Required Gates

Run these before every release candidate:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
cargo run -p agentbox-cli -- doctor --json
cargo run -p agentbox-cli -- providers --json
cargo run -p agentbox-cli -- bridge-health --json
cargo run -p agentbox-cli -- evidence --verify
```

`doctor` and `evidence --verify` may require local state. If they cannot run in
CI, run them manually and record the reason.

The consolidated release gate is:

```sh
scripts/release-readiness.sh
```

It writes `doctor.json`, `setup-plan.json`, `providers.json`,
`bridge-health.json`, `signing.json`, logs, and `manifest.json` under
`target/agentbox-release-readiness` by default.
`doctor.json` separates `required_failed` from `advisory_failed`; required
failures block the release, while advisory failures track planned or prototype
provider prerequisites. `providers.json` is checked for primitive-level
status/gate/scope metadata and `bridge-health.json` is checked for readiness
verdicts and claim boundaries, so release artifacts cannot silently drop the
provider truth contract. `signing.json` is an explicit unsigned placeholder; it
prevents release notes or packaging jobs from implying signed artifacts before
real signing/attestation exists. `setup-plan.json` records the next operator
action to surface in installer or package UX. If local required doctor checks
are expected to fail on a candidate host, set
`AGENTBOX_RELEASE_ALLOW_DOCTOR_FAILURE=1` and treat the generated `doctor.json`
as an explicit release blocker rather than a pass. Optional platform/live smoke
scripts run only with `AGENTBOX_RELEASE_LIVE_SMOKE=1`.

For interactive setup debugging, run `agentbox setup-plan` or
`agentbox setup-plan --json`. It derives the next operator action from the same
doctor report without mutating host state.

## Install And CLI

- [ ] `cargo build --release` succeeds.
- [ ] Any installer or package follows
      [installer packaging](installer-packaging.md) and was tested on a clean
      host for that platform.
- [ ] Installer output clearly reports which providers are shipped,
      experimental, prototype-gated, descriptor-only, or unavailable on that
      host.
- [ ] `signing.json` says `signed: false` unless real artifact signing and
      verification are configured for the release.
- [ ] `agentbox install` creates shims in `~/.agentbox/shims`.
- [ ] `agentbox doctor` reports daemon, socket, PATH, shims, audit, and provider
      readiness clearly.
- [ ] `agentbox start`, `status`, and `stop` work on the release host.
- [ ] `agentbox policy`, `policy-simulate`, and `policy-explain` work without a
      daemon.
- [ ] `agentbox providers` separates shipped, experimental, unavailable, and
      planned surfaces, including primitive-level active/gate/scope metadata in
      JSON output.
- [ ] `agentbox bridge-health --json` records each provider's active,
      supported, gated, or metadata-only host-bridge readiness without implying
      provider execution proof.

## Daemon And Shims

- [ ] Shims are first on `PATH` in the documented setup.
- [ ] Safe commands pass quickly.
- [ ] Approval-bucket commands request approval or deny on timeout.
- [ ] Block-bucket commands deny without notification.
- [ ] Absolute-path and direct-syscall bypass limits are documented.
- [ ] Direct-host execution is documented as clearing the ambient daemon
      environment and injecting only explicit `ExecCommand.env` entries plus
      approved credential environment grants.
- [ ] ntfy config is generated and documented.
- [ ] Failure modes are clear when the daemon is unavailable.

## Minipods And Providers

- [x] `agentbox minipod-spec hermes --workspace .` emits valid JSON.
- [x] `scripts/demo-v0.2.sh` passes.
- [x] `scripts/demo-autonomous-agent.sh` passes.
- [x] macOS native plan compiler output is tested without claiming execution.
- [x] `agentbox doctor` reports macOS native plan, Apple Virtualization, and
      future ES/NE entitlement readiness honestly.
- [x] Native AgentPod providers remain unavailable until live enforcement lands,
      except explicitly gated Linux prototype runs.
- [x] Podman compatibility is marked experimental or unavailable honestly.
- [x] Podman live smoke is run only on hosts where Podman is installed.
- [x] `scripts/smoke-podman-bridge.sh` proves daemon socket visibility and shim
      execution inside a Podman minipod, or skips with code 77 when Podman is
      absent.
- [x] Linux benchmark and native primitive scripts skip honestly on non-Linux
      hosts.
- [x] Windows and macOS native provider docs match provider status.

## Policy Boundaries

- [x] Host environment inheritance is rejected.
- [x] Direct-host child processes do not inherit the daemon's ambient
      environment by default.
- [x] Host network mode is rejected.
- [x] Protected paths require explicit file grants.
- [x] Denied domains win before allowlists or approval grants.
- [x] Approval grants cannot bypass block-bucket decisions.
- [x] Expired grants are ignored.
- [x] Once grants are consumed.

## Evidence

- [x] SQLite audit rows are hash-chained.
- [x] `agentbox evidence --verify` passes on a local audit DB.
- [x] Credential-like values are redacted from audit and transcript output.
- [x] Session evidence bundles include approvals, boundary events, transcripts,
      replay metadata, and workspace diff references where available.
- [x] FIDES and agit integrations are labeled skeletons unless external
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

## Paid Product Credibility

- [ ] Clean install, upgrade, uninstall, and recovery flows are tested on each
      claimed platform.
- [ ] Support artifacts are actionable: doctor output, setup plan, provider
      gaps, bridge health, logs, and evidence bundle paths can be collected
      without exposing secrets.
- [ ] Evidence verification is part of the support playbook before trusting a
      session bundle or receipt.
- [ ] Rollback is documented for daemon state, shims, config, and failed
      provider setup.
- [ ] Platform and provider limits are shown in product UI, CLI output, README,
      and release notes without implying native support that is not live-tested.

## OSS-Proud Credibility

- [ ] Fresh checkout setup is reproducible with documented commands and no
      private services.
- [ ] Unit tests, contract tests, and relevant smoke scripts are documented with
      skip conditions that do not count as passes.
- [ ] Examples exercise shipped or explicitly experimental behavior, not
      roadmap-only provider claims.
- [ ] Contribution docs, issue templates or labels, and maintainer expectations
      help contributors find real work.
- [ ] Provider status is honest in docs and CLI output: shipped, experimental,
      prototype-gated, descriptor-only, unavailable, or planned.

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
