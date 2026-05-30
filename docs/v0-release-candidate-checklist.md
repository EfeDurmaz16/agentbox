# AgentPod v0 Release Candidate Checklist

This is the cut checklist for an Agentbox AgentPod v0 release candidate. It
does not create a release by itself and it does not upgrade any provider claim.
It decides whether a candidate is:

- `ship-oss-v0`
- `ship-paid-preview`
- `blocked`

The default v0 target is OSS-proud AgentPod command governance with honest
provider truth, evidence verification, reproducible local install, upgrade,
rollback, uninstall, support bundle export, and release artifacts. Paid preview
or native/remote production claims require extra live evidence.

## Candidate Scope

| Surface | Candidate decision |
|---------|--------------------|
| OSS source build and local command governance | In scope when required gates pass. |
| Direct-host provider | In scope as weak-isolation command mediation only. |
| Podman compatibility | In scope only when live smoke passes on the target host; otherwise host-gated and not a passed claim. |
| Linux native AgentPod | Prototype-gated. Portable conformance is in scope; paid/native sandbox claim is deferred. |
| macOS native AgentPod | Descriptor plus gated Apple Virtualization boot prototype. Runnable native provider claim is deferred. |
| Windows native AgentPod | Descriptor/prototype surfaces. Runnable Windows provider claim is deferred. |
| Remote AgentPod | Experimental local/endpoint contract. Managed hosted worker claim is deferred. |
| FIDES, AGIT, OAPS integrations | Descriptor/local evidence boundaries only. Live external authority/lineage claims are deferred. |
| Paid packaging/support | Paid preview only for named platform/provider pairs with clean-host install, support bundle, evidence, rollback, and provider proof. |

## Evidence Packet

Attach or link these artifacts before tagging an RC:

| Evidence | Required for | Command or artifact |
|----------|--------------|---------------------|
| Clean worktree and commit | Every candidate | `git status --short --branch`, `git rev-parse HEAD` |
| CI run | Every candidate | GitHub Actions `CI` run for the candidate commit on Ubuntu and macOS |
| Release readiness artifacts | Every candidate, unless explicitly blocked | `bash scripts/release-readiness.sh` |
| Provider truth JSON | Every candidate | `target/agentbox-release-readiness/providers.json` |
| Bridge health JSON | Every candidate | `target/agentbox-release-readiness/bridge-health.json` |
| Doctor JSON | Every candidate; required failures block unless recorded as blocked | `target/agentbox-release-readiness/doctor.json` |
| Setup plan JSON | Every candidate | `target/agentbox-release-readiness/setup-plan.json` |
| Signing placeholder or real signing status | Every candidate | `target/agentbox-release-readiness/signing.json`, `SIGNING_STATUS.json` in release archives |
| CLI contract smoke | Every candidate | `bash scripts/smoke-cli-contracts.sh` |
| Release smoke suite | Every candidate | `bash scripts/smoke-agentpod-release-suite.sh` |
| Install upgrade rollback smoke | Every candidate | `bash scripts/smoke-install-upgrade-rollback.sh` |
| Support bundle sample | Every supportable candidate | `agentbox support-bundle --output ./agentbox-support-bundle --json` |
| Release archives and checksums | Binary/archive candidate | `.github/workflows/release.yml`, `scripts/package-release-artifacts.sh`, `SHA256SUMS` |
| Optional live provider smokes | Only for the claimed host/provider | `AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh` plus provider-specific smoke logs |

If a required command fails, the candidate is `blocked` unless the checklist
explicitly says the surface is deferred and not part of the release claim.

## P0/P1 Gate Map

Every P0/P1 gate from `docs/agentpod-productization-100-issues.md` must be
covered by passing evidence or explicit deferred status before an RC can be cut.

| Issues | Gate area | RC status | Evidence or deferred status |
|--------|-----------|-----------|-----------------------------|
| 1-6 | Product contract, provider truth, stale naming, direct-host and Podman boundaries, fake-provider cleanup | Required | `README.md`, `docs/provider-truth.md`, `docs/product-direction.md`, `docs/limitations.md`, `docs/status-matrix.md`, `docs/pricing-packaging-boundary.md`; verify with `rg "AgentPod" docs README.md`, provider JSON, and release docs review. |
| 7-9 | Paid-product bar, OSS-proud bar, public limitation taxonomy | Required | `docs/v0-release-criteria.md`, `docs/pricing-packaging-boundary.md`, `docs/limitations.md`; paid claims remain limited to named provider/platform proof. |
| 11-15 | AgentPod CLI lifecycle naming, status/explain/doctor surfaces, actionable unavailable provider errors | Required | `scripts/smoke-cli-contracts.sh` covers grouped `agentpod status`, `agentpod explain`, `agentpod doctor`, setup/provider readiness, unavailable native provider truth, and CLI help. |
| 16-19 | Machine-readable JSON, session selection, evidence path surfacing, risk labels | Required | `scripts/smoke-cli-contracts.sh`, `docs/status-matrix.md`, and `README.md` cover JSON contract checks, `pods`/`sessions`, evidence commands, risk/provider output, and run plan JSON. |
| 21-24 | Direct-host weak isolation, no silent native fallback, high-risk direct-host guardrails, bypass limitation tests | Required for direct-host claim | `bash scripts/smoke-agentpod-release-suite.sh` proves low-risk allow and high-risk deny; `docs/limitations.md` and `docs/status-matrix.md` keep direct-host weak-isolation boundaries explicit. |
| 25-27 | Direct-host env/credential handling, sensitive-path defaults, audit parity | Required for direct-host claim | `scripts/smoke-cli-contracts.sh`, `docs/safe-credential-patterns.md`, `docs/status-matrix.md`, and evidence bundle verification prove explicit grants, redaction, audit/evidence export, and non-claims. |
| 31-34 | Podman renamed as compatibility provider, doctor checks, lifecycle smoke, host bridge | Host-gated | `podman-compat` provider truth and deprecated `podman` alias are required in CLI smoke. Live compatibility support requires `bash scripts/smoke-podman-bridge.sh` or `AGENTBOX_RELEASE_LIVE_SMOKE=1 bash scripts/release-readiness.sh` on a supported host; otherwise record a skip, not a pass. |
| 35-38 | Podman mount, credential, network, image provenance | Deferred unless live compatibility support is claimed | `docs/provider-truth.md`, `docs/qa-matrix.md`, and provider JSON must keep Podman `experimental`. Do not claim native isolation, domain/packet enforcement, or image provenance beyond attached evidence. |
| 41-43 | Remote trust model, descriptor schema, signed worker identity | Required for experimental remote contract | `docs/remote-agentpod.md`, `scripts/smoke-remote-worker.sh`, and CLI contract remote descriptor/handshake checks. |
| 44-47 | Remote attestation placeholder, workspace packaging, evidence return, secret grants | Required for experimental remote contract; managed service deferred | Local worker/descriptor evidence can pass. Production HTTPS worker, hosted fleet, attestation service, and managed sandbox claims require endpoint-specific live logs and are deferred by default. |
| 51-54 | Linux native status, user namespaces, workspace mounts, cgroups | Prototype-gated | Portable CI must run `bash scripts/smoke-linux-agentpod-conformance.sh`. Live native support requires `AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh` on a supported Linux host. Paid/native sandbox claim is deferred. |
| 55-57 | Linux seccomp, Landlock, network enforcement | Prototype-gated | `docs/linux-hardening-gaps.md`, CLI contract native-plan checks, and optional `AGENTBOX_LINUX_NFTABLES=1 bash scripts/smoke-linux-nftables.sh`. Complete syscall, filesystem, domain, and packet enforcement remains deferred unless live evidence is attached. |
| 61-63 | macOS provider unavailable, VM storage layout, VM runner request validation | Required as descriptor/prototype truth | `docs/macos-virtualization-boot.md`, `docs/macos-endpoint-security.md`, CLI contract macOS native-plan checks, and provider JSON must keep runtime execution unavailable. |
| 64-66 | macOS boot prototype, workspace mount contract, credential channel | Host-gated prototype | `AGENTBOX_MACOS_VM_BOOT_PROTOTYPE=1` evidence can be attached when run. Native macOS AgentPod execution, ES/NE enforcement, and paid macOS sandbox claims are deferred. |
| 71-72 | Windows descriptor-only status and architecture | Required as descriptor truth | `docs/windows-native-provider.md`, CLI contract Windows native-plan checks, and provider JSON must keep execution unavailable. |
| 73-75 | Windows capability descriptor, Job Object prototype, restricted token flow | Host-gated prototype | `AGENTBOX_WINDOWS_JOB_OBJECT=1 bash scripts/smoke-windows-job-object.sh` can prove create/close only on Windows. Process assignment, WFP denial, ETW export, token enforcement, and Windows paid support are deferred. |
| 81-83 | Evidence bundle schema, hash chain, evidence verify command | Required | `bash scripts/smoke-agentpod-release-suite.sh`, `bash scripts/smoke-cli-contracts.sh`, and `docs/evidence-bundle-schema.md` prove clean verify and tamper rejection. |
| 84-87 | FIDES boundary, signed approval receipt, AGIT diff boundary, transcript redaction | Required as local/descriptor evidence; live integrations deferred | `README.md`, `docs/status-matrix.md`, session evidence bundle schemas, and support bundle redaction checks must keep FIDES/AGIT/OAPS `live_support=false` unless real adapters are configured. |
| 91-93 | v0 criteria, reproducible local install, release artifacts | Required for RC | `docs/v0-release-criteria.md`, `docs/local-install.md`, `docs/installer-packaging.md`, `.github/workflows/release.yml`, `scripts/package-release-artifacts.sh`, release archive `SHA256SUMS`, and signing/provenance status. Platform code signing remains explicit unsigned/deferred unless configured. |
| 94-97 | Upgrade/rollback, uninstall, QA matrix, release smoke suite | Required for RC | `bash scripts/smoke-install-upgrade-rollback.sh`, `agentbox uninstall --dry-run --json`, `docs/qa-matrix.md`, `bash scripts/smoke-agentpod-release-suite.sh`, and `bash scripts/smoke-cli-contracts.sh`. |

## Cut Procedure

1. Pick the candidate commit and verify the worktree is clean.
2. Run the full local evidence packet.
3. Run optional live-provider smoke only for providers included in the public
   claim.
4. Record every P0/P1 row above as `passed`, `host-gated skip`, or `deferred`.
5. Reject the candidate if any required row is `failed`.
6. Generate release archives only after required rows pass or the candidate is
   explicitly marked blocked.
7. Write release notes with separate sections for shipped, experimental,
   prototype, descriptor-only, planned, unavailable, skipped live gates, and
   deferred paid/native claims.

## RC Decision Table

| Decision | Required condition | Public wording |
|----------|--------------------|----------------|
| `ship-oss-v0` | All required rows pass; host-gated rows are recorded as skips; deferred rows are not claimed as shipped. | "Agentbox v0 ships governed AgentPod command execution, provider truth reporting, support bundle export, and evidence verification. Native provider work remains prototype or descriptor-only unless stated otherwise." |
| `ship-paid-preview` | OSS row passes plus clean-host install, support bundle, evidence verification, rollback/uninstall, and live provider proof for a named platform/provider. | "Paid preview for the named platform/provider matrix only." |
| `blocked` | Any required row fails, doctor has unresolved required failures, docs overclaim provider support, evidence verification fails, or release artifacts lack checksums/provenance status. | "Release candidate blocked by listed gates." |

## Verification

For this checklist change:

```sh
rg -n "P0/P1 Gate Map|1-6|94-97|ship-oss-v0|blocked" docs/v0-release-candidate-checklist.md
rg -n "v0-release-candidate-checklist|Release Candidate Checklist" README.md docs/release-readiness.md docs/v0-release-criteria.md
git diff --check
```
