# AgentPod Productization 100-Issue Plan

## Thesis

AgentPod is the primary product. Agentbox is the CLI, daemon, policy engine,
evidence layer, and control plane around AgentPods.

The product goal is a credible governed execution runtime for local and remote
agents: honest provider status, clear boundaries, useful default UX, real
platform isolation work, reviewable evidence, and a release path that can stand
as either a paid product foundation or serious OSS.

## Execution Rules

- AgentPod is the main product surface; Agentbox commands should orbit the
  AgentPod lifecycle, policy, evidence, and provider truth.
- `direct-host` is a fallback and development mode only. It must stay useful,
  guarded, audited, and plainly weaker than native or VM-backed providers.
- Podman is compatibility only. Do not position Podman as the product center,
  and do not imply Docker-provider parity unless it exists.
- No fake provider support. A provider is shipped only when lifecycle behavior
  is implemented, tested, and truthfully reported.
- Keep PRs atomic. One issue should normally map to one PR; split only when the
  verification gate would become unclear.

## Issue Plan

### Epic 1: Product Contract and Stale Surface Cleanup

1. **Make AgentPod the canonical docs entrypoint** | Priority: P0 | Area: docs/product | PR boundary: add/adjust docs index references without rewriting unrelated docs | Verification gate: `rg "AgentPod" docs README.md` shows product-first wording and no new Podman-first claims.
2. **Freeze provider truth terminology** | Priority: P0 | Area: docs/runtime | PR boundary: define provider status terms in one canonical doc | Verification gate: provider statuses match `shipped`, `experimental`, `prototype primitive`, `descriptor only`, or `planned`.
3. **Audit stale minipod naming in public surfaces** | Priority: P0 | Area: docs/cli | PR boundary: replace user-facing stale names where safe; leave historical references scoped | Verification gate: `rg "minipod|sb-pods|sb-" docs README.md` has intentional results only.
4. **Document direct-host as fallback/dev mode** | Priority: P0 | Area: docs/security | PR boundary: update limitations and contract docs only | Verification gate: direct-host page states what is enforced, what is bypassable, and when to use it.
5. **Document Podman compatibility boundary** | Priority: P0 | Area: docs/runtime | PR boundary: add compatibility wording and unsupported-provider refusal language | Verification gate: docs state Podman compatibility only and no Docker parity claim.
6. **Remove fake-provider phrasing from roadmap surfaces** | Priority: P0 | Area: docs/release | PR boundary: edit roadmap/status docs to separate plans from runnable behavior | Verification gate: every provider claim has a status and evidence/verification reference.
7. **Add paid-product credibility checklist** | Priority: P1 | Area: docs/product | PR boundary: one checklist doc section, no code | Verification gate: checklist covers installer, supportability, evidence, rollback, and platform limits.
8. **Add OSS-proud credibility checklist** | Priority: P1 | Area: docs/product | PR boundary: one checklist doc section, no code | Verification gate: checklist covers reproducible setup, tests, examples, contribution path, and issue labels.
9. **Create public limitation taxonomy** | Priority: P1 | Area: docs/security | PR boundary: classify limitations by provider and risk | Verification gate: each limitation has mitigation or explicit non-goal.
10. **Add canonical product glossary cleanup** | Priority: P2 | Area: docs/glossary | PR boundary: update glossary only | Verification gate: glossary defines AgentPod, provider, direct-host, podman-compat, evidence bundle, and host bridge.

### Epic 2: CLI UX and Operator Workflows

11. **Rename CLI help around AgentPod lifecycle** | Priority: P0 | Area: cli/ux | PR boundary: help text and command aliases only | Verification gate: `agentbox --help` and relevant subcommands show AgentPod-first language.
12. **Add `agentbox pod status` operator view** | Priority: P0 | Area: cli/runtime | PR boundary: read-only status command | Verification gate: command returns provider, session state, policy mode, evidence path, and honest availability.
13. **Add `agentbox pod explain` command** | Priority: P0 | Area: cli/policy | PR boundary: explain command for a proposed argv without execution | Verification gate: command shows provider choice, policy decisions, approvals, and denial reasons.
14. **Add `agentbox pod doctor` command** | Priority: P0 | Area: cli/diagnostics | PR boundary: diagnostics command only | Verification gate: command reports daemon, shim, database, provider prerequisites, and platform limitations.
15. **Make provider unavailable errors actionable** | Priority: P0 | Area: cli/errors | PR boundary: error taxonomy and display text | Verification gate: unavailable provider output includes reason, required gate, and next command.
16. **Add machine-readable CLI output mode** | Priority: P1 | Area: cli/integration | PR boundary: JSON output for status/explain/doctor | Verification gate: JSON schema fixtures pass and stdout contains no human-only prose in JSON mode.
17. **Add session selection UX** | Priority: P1 | Area: cli/runtime | PR boundary: list/select/inspect current sessions | Verification gate: operator can identify the latest AgentPod session without reading SQLite manually.
18. **Add evidence path surfacing to every run** | Priority: P1 | Area: cli/evidence | PR boundary: CLI output and tests | Verification gate: successful, denied, and failed runs print or emit evidence bundle location.
19. **Add concise command risk labels** | Priority: P1 | Area: cli/policy | PR boundary: display policy risk summary only | Verification gate: deploy, credential, network, filesystem, and benign commands render stable labels.
20. **Add shell completion coverage for AgentPod commands** | Priority: P2 | Area: cli/ux | PR boundary: completion generator updates | Verification gate: completion tests include pod/status/explain/doctor/session flags.

### Epic 3: Direct-Host Honesty and Dev-Mode Guardrails

21. **Mark direct-host sessions as weak isolation** | Priority: P0 | Area: runtime/direct-host | PR boundary: session metadata and display only | Verification gate: evidence and status output include `isolation_strength=weak`.
22. **Deny silent native fallback to direct-host** | Priority: P0 | Area: runtime/provider | PR boundary: provider selection behavior | Verification gate: requesting unavailable native provider fails unless explicit fallback flag is set.
23. **Require explicit dev-mode flag for risky direct-host runs** | Priority: P0 | Area: policy/direct-host | PR boundary: policy gate for high-risk command classes | Verification gate: high-risk direct-host command denies without explicit dev-mode or approval.
24. **Add direct-host bypass limitation tests** | Priority: P0 | Area: tests/security | PR boundary: regression tests only | Verification gate: tests prove shell builtins, absolute paths, and env inheritance are documented or blocked.
25. **Make direct-host env inheritance explicit** | Priority: P1 | Area: runtime/credentials | PR boundary: env handling and docs | Verification gate: default env set is listed, redacted, and covered by tests.
26. **Add direct-host sensitive-path deny defaults** | Priority: P1 | Area: policy/filesystem | PR boundary: default policy fixtures | Verification gate: home secrets, browser profiles, cloud configs, and SSH paths deny or require approval.
27. **Add direct-host audit parity with AgentPod runs** | Priority: P1 | Area: evidence/direct-host | PR boundary: audit event normalization | Verification gate: direct-host and provider-backed runs emit comparable start/decision/end events.
28. **Add direct-host warning suppression rules** | Priority: P2 | Area: cli/ux | PR boundary: UX preference only | Verification gate: warnings can be acknowledged per workspace without hiding evidence status.
29. **Add direct-host smoke fixtures** | Priority: P2 | Area: tests/runtime | PR boundary: smoke script and fixtures | Verification gate: smoke covers allowed command, denied command, approval-required command, and evidence export.
30. **Document direct-host support policy** | Priority: P2 | Area: docs/support | PR boundary: docs only | Verification gate: support table states it is for development, fallback, and low-risk guarded local work.

### Epic 4: Podman Compatibility Cleanup

31. **Rename Podman provider to `podman-compat`** | Priority: P0 | Area: runtime/provider | PR boundary: provider ID migration and compatibility alias | Verification gate: old ID warns, new ID works, status says compatibility.
32. **Add Podman prerequisite doctor checks** | Priority: P0 | Area: cli/diagnostics | PR boundary: doctor checks only | Verification gate: missing machine, socket, image, and mount issues produce actionable output.
33. **Add Podman lifecycle conformance smoke** | Priority: P0 | Area: tests/provider | PR boundary: smoke script and CI gating where feasible | Verification gate: create/run/inspect/logs/stop/remove flow passes on supported host.
34. **Verify host bridge inside Podman AgentPod** | Priority: P0 | Area: runtime/bridge | PR boundary: bridge mount and smoke only | Verification gate: command inside pod can reach daemon only through the intended bridge.
35. **Add explicit mount policy for Podman** | Priority: P1 | Area: policy/filesystem | PR boundary: mount mapping implementation | Verification gate: read-only, workspace-write, and denied path fixtures pass.
36. **Add Podman credential isolation checks** | Priority: P1 | Area: policy/credentials | PR boundary: env/mount restrictions and tests | Verification gate: common host credentials are absent unless granted.
37. **Add Podman network mode reporting** | Priority: P1 | Area: policy/network | PR boundary: capability/status reporting | Verification gate: status says what network enforcement is real, partial, or unavailable.
38. **Add Podman image provenance pinning** | Priority: P1 | Area: release/security | PR boundary: image reference and verification docs | Verification gate: image digest or build recipe is recorded in release evidence.
39. **Add Podman cleanup reliability tests** | Priority: P2 | Area: tests/provider | PR boundary: cleanup tests only | Verification gate: interrupted session leaves no untracked containers/volumes beyond documented artifacts.
40. **Document Podman escape and bypass boundaries** | Priority: P2 | Area: docs/security | PR boundary: limitations doc only | Verification gate: docs state Podman is not the paid-product isolation center.

### Epic 5: Remote Worker Trust

41. **Define remote AgentPod trust model** | Priority: P0 | Area: docs/remote | PR boundary: trust model doc section | Verification gate: covers identity, transport, workspace transfer, secret grants, evidence, and revocation.
42. **Add remote provider descriptor schema** | Priority: P0 | Area: runtime/remote | PR boundary: schema/types only | Verification gate: fixture validates endpoint, identity, capabilities, and status.
43. **Require signed remote worker identity** | Priority: P0 | Area: security/remote | PR boundary: identity verification interface | Verification gate: unsigned or mismatched worker descriptor is rejected.
44. **Add remote capability attestation placeholder** | Priority: P1 | Area: security/remote | PR boundary: typed receipt model, no fake enforcement | Verification gate: status distinguishes attested, self-reported, and unknown capabilities.
45. **Add remote workspace packaging plan** | Priority: P1 | Area: runtime/remote | PR boundary: package manifest and docs | Verification gate: package includes explicit include/exclude rules and hash manifest.
46. **Add remote evidence return contract** | Priority: P1 | Area: evidence/remote | PR boundary: evidence schema extension | Verification gate: remote run must return signed receipt or fail closed.
47. **Add remote secret grant contract** | Priority: P1 | Area: credentials/remote | PR boundary: grant schema only | Verification gate: grant has scope, expiry, recipient identity, and redaction rules.
48. **Add remote worker revocation flow** | Priority: P2 | Area: security/remote | PR boundary: revocation state and docs | Verification gate: revoked worker cannot start new sessions in local tests.
49. **Add remote transport failure semantics** | Priority: P2 | Area: runtime/remote | PR boundary: error handling and retry policy | Verification gate: network loss, partial evidence, and timeout cases produce deterministic session states.
50. **Document remote worker non-goals** | Priority: P2 | Area: docs/remote | PR boundary: docs only | Verification gate: docs do not claim remote isolation without attestation and operator trust boundaries.

### Epic 6: Linux Native Sandbox

51. **Promote Linux native status from plan to gated prototype only where true** | Priority: P0 | Area: runtime/linux | PR boundary: status reporting and docs | Verification gate: provider refuses unless gate and host prerequisites are satisfied.
52. **Add Linux user namespace lifecycle tests** | Priority: P0 | Area: runtime/linux | PR boundary: namespace test harness | Verification gate: test proves rootless UID/GID mapping or reports unsupported host clearly.
53. **Wire Linux mount namespace workspace modes** | Priority: P0 | Area: runtime/linux | PR boundary: workspace mount implementation | Verification gate: direct, read-only, overlay-review, and ephemeral fixtures pass on Linux.
54. **Wire Linux cgroups v2 limits** | Priority: P0 | Area: runtime/linux | PR boundary: CPU/memory/process limit implementation | Verification gate: resource limit smoke proves enforcement or explicit unsupported state.
55. **Wire Linux seccomp profile loading** | Priority: P1 | Area: security/linux | PR boundary: seccomp loader and tests | Verification gate: denied syscall fixture fails with expected evidence.
56. **Expand Linux Landlock rules beyond write-only prototype** | Priority: P1 | Area: security/linux | PR boundary: Landlock ruleset implementation | Verification gate: read/write/execute path fixtures match policy without breaking launcher.
57. **Add Linux network enforcement plan-to-live bridge** | Priority: P1 | Area: policy/network | PR boundary: nftables or equivalent prototype behind gate | Verification gate: denied destination fixture cannot connect and evidence records denial.
58. **Add Linux eBPF observability receipt** | Priority: P2 | Area: observability/linux | PR boundary: observability receipt only | Verification gate: events identify process/session without claiming enforcement.
59. **Add Linux provider conformance CI target** | Priority: P2 | Area: ci/linux | PR boundary: CI job or documented manual gate | Verification gate: Linux-native smoke command is reproducible from clean checkout.
60. **Document Linux hardening gaps** | Priority: P2 | Area: docs/linux | PR boundary: docs only | Verification gate: gaps map to explicit future issues and no shipped-sandbox overclaim remains.

### Epic 7: macOS VM Path

61. **Keep macOS native provider unavailable until VM lifecycle exists** | Priority: P0 | Area: runtime/macos | PR boundary: provider refusal/status only | Verification gate: `agentpod-macos` returns unavailable with exact missing prerequisites.
62. **Define macOS VM cell storage layout** | Priority: P0 | Area: runtime/macos | PR boundary: storage layout code/docs | Verification gate: plan command renders deterministic paths and cleanup policy.
63. **Implement macOS VM runner request validation** | Priority: P0 | Area: runtime/macos | PR boundary: runner request parser/validator | Verification gate: invalid request fixtures fail before any VM side effect.
64. **Add macOS VM boot prototype behind gate** | Priority: P1 | Area: runtime/macos | PR boundary: gated boot/stop only | Verification gate: VM boots a minimal image or fails with typed host prerequisite reason.
65. **Add macOS workspace mount contract** | Priority: P1 | Area: runtime/macos | PR boundary: mount/share plan and tests | Verification gate: direct and overlay-review plans render host/guest paths and evidence refs.
66. **Add macOS credential channel contract** | Priority: P1 | Area: credentials/macos | PR boundary: channel schema only | Verification gate: credential grant has scope, expiry, recipient cell, and audit entry.
67. **Add macOS Network Extension design-to-gate path** | Priority: P2 | Area: policy/network | PR boundary: entitlement/prereq/status work | Verification gate: status distinguishes design, entitlement missing, installed, and enforcing.
68. **Add macOS Endpoint Security design-to-gate path** | Priority: P2 | Area: security/macos | PR boundary: entitlement/prereq/status work | Verification gate: status distinguishes design, entitlement missing, installed, and enforcing.
69. **Add macOS VM cleanup smoke** | Priority: P2 | Area: tests/macos | PR boundary: cleanup script/tests | Verification gate: interrupted gated VM run removes transient artifacts or records retained paths.
70. **Document macOS paid-product support boundary** | Priority: P2 | Area: docs/macos | PR boundary: docs only | Verification gate: docs state what works on Apple Silicon, what needs entitlements, and what is unsupported.

### Epic 8: Windows Native Path

71. **Keep Windows provider descriptor-only until runnable** | Priority: P0 | Area: runtime/windows | PR boundary: provider status and refusal | Verification gate: Windows provider cannot be selected as shipped until lifecycle exists.
72. **Define Windows native provider architecture** | Priority: P0 | Area: docs/windows | PR boundary: architecture doc only | Verification gate: covers Job Objects, AppContainer, restricted tokens, WFP, ETW, and optional Hyper-V.
73. **Add Windows capability descriptor schema** | Priority: P1 | Area: runtime/windows | PR boundary: schema/types only | Verification gate: descriptor records filesystem, process, network, credential, and evidence capabilities.
74. **Prototype Windows Job Object launcher** | Priority: P1 | Area: runtime/windows | PR boundary: gated launcher prototype | Verification gate: process tree termination and CPU/memory limit smoke passes on Windows.
75. **Prototype Windows restricted token flow** | Priority: P1 | Area: security/windows | PR boundary: gated token prototype | Verification gate: denied privilege fixture cannot access protected operation.
76. **Prototype Windows AppContainer workspace mode** | Priority: P2 | Area: security/windows | PR boundary: gated AppContainer prototype | Verification gate: workspace access follows explicit allowlist fixture.
77. **Define Windows network enforcement path** | Priority: P2 | Area: policy/network | PR boundary: WFP design/status only | Verification gate: docs and status do not claim enforcement until WFP path exists.
78. **Define Windows evidence via ETW path** | Priority: P2 | Area: evidence/windows | PR boundary: ETW receipt design only | Verification gate: evidence model can reference ETW events without requiring live ETW ingestion.
79. **Add Windows installer prerequisite checks** | Priority: P2 | Area: installer/windows | PR boundary: diagnostic checks | Verification gate: doctor reports OS version, privileges, Hyper-V availability, and missing components.
80. **Document Windows non-goals for first paid/OSS release** | Priority: P2 | Area: docs/windows | PR boundary: docs only | Verification gate: release docs clearly mark Windows as planned/prototype unless gates pass.

### Epic 9: Evidence, FIDES, and AGIT

81. **Define canonical AgentPod evidence bundle schema** | Priority: P0 | Area: evidence/schema | PR boundary: schema and fixtures | Verification gate: bundle includes manifest, provider receipt, policy decisions, approvals, commands, artifacts, and hashes.
82. **Hash-chain session evidence events** | Priority: P0 | Area: evidence/integrity | PR boundary: event hash chain implementation | Verification gate: tamper fixture fails verification and clean fixture passes.
83. **Add `agentbox evidence verify` command** | Priority: P0 | Area: cli/evidence | PR boundary: verification command only | Verification gate: command verifies schema, hashes, signatures when present, and missing references.
84. **Add FIDES authority adapter boundary** | Priority: P1 | Area: integration/fides | PR boundary: adapter interface and no-op implementation | Verification gate: docs and tests show no fake live FIDES claim.
85. **Add signed approval receipt shape** | Priority: P1 | Area: evidence/fides | PR boundary: receipt schema and fixtures | Verification gate: approval receipt includes signer, scope, expiry, decision, and evidence hash.
86. **Add AGIT workspace diff evidence boundary** | Priority: P1 | Area: integration/agit | PR boundary: adapter interface and local diff fixture | Verification gate: evidence can reference diff snapshot without requiring AGIT service.
87. **Add command transcript redaction rules** | Priority: P1 | Area: evidence/privacy | PR boundary: redaction implementation and tests | Verification gate: secrets in env, args, and output fixtures are redacted deterministically.
88. **Add evidence export formats** | Priority: P2 | Area: evidence/export | PR boundary: JSONL and bundle archive export | Verification gate: exported bundle round-trips through verify command.
89. **Add evidence retention policy controls** | Priority: P2 | Area: evidence/storage | PR boundary: config and cleanup behavior | Verification gate: retention dry-run lists deletions and never removes unverified active session data.
90. **Document evidence trust boundaries** | Priority: P2 | Area: docs/evidence | PR boundary: docs only | Verification gate: docs distinguish local audit, tamper-evident bundle, FIDES-signed approval, and AGIT lineage.

### Epic 10: Release, Installer, QA, and Monetizable Packaging

91. **Define v0 paid/OSS release criteria** | Priority: P0 | Area: release | PR boundary: release checklist only | Verification gate: criteria map to provider truth, installer, QA, docs, support, and evidence verification.
92. **Add reproducible local install path** | Priority: P0 | Area: installer | PR boundary: install script or package recipe | Verification gate: clean machine instructions install CLI, daemon, shim, and doctor passes.
93. **Add signed release artifact workflow** | Priority: P0 | Area: release/security | PR boundary: CI workflow and signing docs | Verification gate: release artifact has checksum, signature, provenance, and verification instructions.
94. **Add upgrade and rollback path** | Priority: P1 | Area: installer | PR boundary: installer behavior/docs | Verification gate: upgrade preserves config/evidence and rollback restores previous working binary.
95. **Add uninstall path** | Priority: P1 | Area: installer | PR boundary: uninstall command/script | Verification gate: uninstall removes shim/daemon artifacts and preserves or explicitly prompts for evidence data.
96. **Add QA matrix for providers and platforms** | Priority: P1 | Area: qa | PR boundary: matrix doc and scripts | Verification gate: matrix covers macOS direct-host, Podman compat, Linux native, remote descriptor, and Windows descriptor.
97. **Add release smoke suite** | Priority: P1 | Area: qa | PR boundary: smoke script only | Verification gate: one command validates doctor, direct-host deny/allow, evidence verify, and provider status.
98. **Add support bundle export** | Priority: P2 | Area: support | PR boundary: diagnostic bundle command | Verification gate: bundle includes logs/status/config/evidence refs and redacts secrets.
99. **Add pricing/packaging boundary doc** | Priority: P2 | Area: product | PR boundary: docs only | Verification gate: doc separates OSS core, paid packaging/support, remote workers, and enterprise controls.
100. **Cut v0 release candidate checklist** | Priority: P2 | Area: release | PR boundary: release-candidate checklist only | Verification gate: every P0/P1 gate is linked to passing evidence or explicit deferred status.

## First-Wave Execution Order

- Wave A: product contract cleanup, provider truth terminology, direct-host
  honesty, and Podman compatibility boundary. This prevents future work from
  building on false public claims.
- Wave B: CLI operator UX: `pod status`, `pod explain`, `pod doctor`,
  actionable provider errors, and evidence path surfacing.
- Wave C: evidence bundle schema, hash-chain verification, FIDES/AGIT adapter
  boundaries, and redaction fixtures.
- Wave D: Linux native enforcement hardening because it is the nearest path to
  real local sandbox credibility.
- Wave E: macOS VM lifecycle path, installer/release smoke, and support bundle.
- Wave F: remote worker trust and Windows native path after the local truth
  surface is stable.

## Parallel Ownership Guidance

- Docs/product owner: Epics 1 and release-facing parts of Epic 10. Owns public
  language, provider truth, limitations, and product definition.
- CLI/runtime owner: Epic 2, direct-host runtime work in Epic 3, and provider
  status plumbing across all epics.
- Security/provider owner: Epics 4, 6, 7, and 8. Owns real enforcement gates and
  refuses fake provider status.
- Evidence/integration owner: Epic 9 plus evidence surfacing in Epic 2. Owns
  schema stability, verification, redaction, FIDES boundary, and AGIT boundary.
- QA/release owner: Epic 10. Owns installer, smoke suite, support bundle,
  release artifacts, and platform matrix.
- Avoid parallel edits in the same provider files. Parallel agents can inspect
  and design independently, but implementation PRs should keep provider,
  evidence, CLI, and docs changes separated unless a verification gate requires
  crossing the boundary.

## Definition of Done

Agentbox is credible as a paid product or serious OSS when an operator can
install it, run an AgentPod, understand the provider strength, see direct-host
or compatibility limitations, verify evidence, and recover from failures
without reading source code.

The minimum bar:

- Provider status is honest and enforced by code, not just docs.
- Direct-host is useful but clearly marked as weaker fallback/dev mode.
- Podman compatibility works where claimed and is not the product center.
- Linux native has real sandbox gates before any shipped claim.
- macOS VM path has a real lifecycle gate before any shipped claim.
- Windows is descriptor/prototype only until runnable and verified.
- Evidence bundles can be exported and verified.
- FIDES and AGIT integrations have clear adapter boundaries without fake live
  support.
- Installer, upgrade, rollback, uninstall, doctor, and support bundle paths are
  tested.
- Release notes state exact capabilities, limitations, and verification results.
