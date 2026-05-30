# Agentbox 100-Issue Runtime Sprint

> Historical/superseded planning note. This backlog captured the first product
> reset wave before AgentPod became the primary product contract. Keep it for
> context only; use `docs/roadmap-250-commits.md`,
> `docs/product-checkpoint-audit.md`, and the status matrix for current claims.

This was the initial issue backlog for turning Agentbox into a usable
cross-platform governed runtime for autonomous agents. Older "minipod" and
Podman-centered wording below is historical, not the current product framing.

The target shape is 100 issues grouped into 10 epics. Most issues should become
one pull request or one atomic commit. Larger issues should split into 2-6
commits with clear boundaries.

## Labels

- `moat`
- `priority:p0`, `priority:p1`, `priority:p2`
- `size:s`, `size:m`, `size:l`
- `epic:<name>`
- `area:<name>`
- `type:feature`, `type:test`, `type:docs`, `type:infra`
- `platform:macos`, `platform:linux`, `platform:windows`
- `integration:fides`, `integration:agit`, `integration:aspendos`

## Issue Template

```md
## Objective

What should be true when this issue is complete.

## Why This Matters

How this deepens the Agentbox moat or removes execution risk.

## Scope

- In scope
- Out of scope

## Acceptance Criteria

- [ ] Behavior or doc exists
- [ ] Tests cover it where practical
- [ ] Verification command passes
- [ ] No fake provider support

## Verification

Commands to run.

## Suggested Commit Boundary

Expected atomic commit message(s).
```

## Epic 1: Product Reset and Public Contract

1. Rewrite README around governed minipods for autonomous agents.
2. Add a public status matrix for direct mode, Podman mode, Linux native, macOS
   Endpoint Security, Windows native, FIDES, and agit support.
3. Add a threat model for local autonomous agents.
4. Add a platform isolation strategy doc.
5. Add a glossary for minipod, boundary, authority, evidence, policy, and
   host bridge.
6. Replace coding-only language with autonomous-agent language across docs.
7. Document the Mac mini replacement wedge without overclaiming security.
8. Add public limitations and bypass boundaries.
9. Add a demo success script for OpenClaw/Hermes-style agents.
10. Add a release-readiness checklist.

## Epic 2: Runtime Core

11. Introduce `MinipodSpec` as the product-level runtime manifest.
12. Introduce `RuntimeProvider` as the OS/backend abstraction.
13. Introduce `RuntimeSession` with lifecycle state.
14. Persist runtime sessions across CLI process restarts.
15. Add session labels for agent, task, workspace, and provider.
16. Add provider capability declarations.
17. Add runtime error taxonomy.
18. Add minipod manifest serialization tests.
19. Add provider conformance test scaffolding.
20. Rename user-facing pod language from `sb-*` to `agentbox-*`.

## Epic 3: macOS Local Minipods

21. Harden the current Podman provider behind `RuntimeProvider`.
22. Add Podman machine readiness checks to `agentbox doctor`.
23. Prove daemon socket mount from macOS host into Linux minipod.
24. Prove shim execution inside a minipod.
25. Add minipod lifecycle smoke script for macOS.
26. Add workspace overlay policy for macOS minipods.
27. Add sidecar service readiness checks.
28. Add minipod logs command.
29. Add minipod inspect command.
30. Document macOS VM-backed limitations.

## Epic 4: Filesystem Boundary

31. Add explicit host mount policy types.
32. Deny sensitive host paths by default.
33. Add read-only mount support.
34. Add writable workspace overlay support.
35. Canonicalize paths before policy decisions.
36. Detect symlink escapes from workspace.
37. Add protected-path tests for `.ssh`, `.aws`, `.config`, browser profiles,
   keychains, and env files.
38. Add file access approval scopes.
39. Add filesystem event audit records.
40. Add docs for safe file sharing into minipods.

## Epic 5: Network Boundary

41. Add network policy types to minipod manifests.
42. Default new minipods to governed egress.
43. Add domain allowlist support for minipods.
44. Add approval-on-first-contact network mode.
45. Add localhost/service access policy.
46. Add denylist support for high-risk destinations.
47. Add network event audit records.
48. Add tests for URL/domain parsing edge cases.
49. Add provider capability flags for network enforcement strength.
50. Document network limitations per platform.

## Epic 6: Credential Boundary

51. Stop inheriting host env by default in minipods.
52. Add explicit credential grant manifest entries.
53. Add one-time credential mount support.
54. Add credential redaction in logs and audit output.
55. Add approval for credential reads.
56. Add FIDES authority hook for credential grants.
57. Add credential revocation event model.
58. Add credential leak regression fixtures.
59. Add cloud CLI credential boundary tests.
60. Document safe credential patterns for agents.

## Epic 7: Policy and Approval

61. Add task-scoped policy bundles.
62. Add per-agent policy profiles.
63. Add session-scoped approvals.
64. Add approval expiry.
65. Add approval scope types: once, command, path, domain, session.
66. Add signed approval model.
67. Add policy simulation command.
68. Add policy explain command for arbitrary commands.
69. Add fail-open/fail-closed mode selection.
70. Add high-risk policy fixtures for deploy, payment, database, messaging, and
   browser actions.

## Epic 8: Evidence and Audit

71. Add audit schema migrations.
72. Add hash-chained audit entries.
73. Add session evidence model.
74. Add JSONL evidence export.
75. Add agit evidence adapter skeleton.
76. Add FIDES signed action adapter skeleton.
77. Add workspace diff snapshot hooks.
78. Add command transcript export.
79. Add tamper verification command.
80. Add session replay metadata.

## Epic 9: Linux Native Runtime

81. Add Linux native provider scaffold.
82. Add user namespace launcher prototype.
83. Add mount namespace launcher prototype.
84. Add PID namespace process tree control.
85. Add cgroups v2 resource limits.
86. Add seccomp profile support.
87. Add Landlock filesystem rules.
88. Add rootless execution tests.
89. Add Linux provider conformance tests.
90. Add Linux isolation benchmark.

## Epic 10: Native Enforcement, Windows, and Release

91. Add macOS Endpoint Security design doc.
92. Add macOS System Extension scaffold plan.
93. Add Linux eBPF observability design doc.
94. Add Windows native provider design doc.
95. Add Windows Job Objects prototype issue.
96. Add Windows AppContainer prototype issue.
97. Add Windows Sandbox provider issue.
98. Add Homebrew formula.
99. Add signed release artifact workflow.
100. Add public v0.2 release notes and demo checklist.

## First Sprint Cut

The first execution wave should prioritize:

1. Product reset docs and README.
2. Runtime abstraction types.
3. `agentbox doctor`.
4. macOS Podman smoke proof.
5. filesystem/credential/network boundary types.
6. FIDES/agit evidence skeletons without claiming live integration.

That wave creates the product spine without pretending the kernel-grade work is
already complete.
