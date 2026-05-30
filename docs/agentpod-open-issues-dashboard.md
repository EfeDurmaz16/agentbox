# AgentPod Productization Execution Dashboard
Generated: 2026-05-30T21:23:13.909791+00:00
Open issues: 54

## Coverage
- Mapped into 100-issue AgentPod plan: 36
- Outside mapped plan (legacy/epic-level tasks): 18

## Open Issue Surface (sorted by priority, then plan id)

| GH # | Title | Priority | Size | Area | Type | Epic | Platform | 100-Plan Match |
|---|---|---|---|---|---|---|---|---|
| #1 | Epic 1: Product reset and public contract | p0 | m | docs | docs | n/a | n/a | no |
| #2 | Epic 2: Runtime core and provider abstraction | p0 | l | runtime | feature | n/a | n/a | no |
| #3 | Epic 3: macOS local minipods | p0 | l | runtime | feature | n/a | macos | no |
| #4 | Epic 4: Filesystem boundary | p0 | l | runtime | feature | n/a | n/a | no |
| #5 | Epic 5: Network boundary | p0 | l | policy | feature | n/a | n/a | no |
| #6 | Epic 6: Credential boundary | p0 | l | policy | feature | n/a | n/a | no |
| #7 | Epic 7: Policy and approval | p0 | l | policy | feature | n/a | n/a | no |
| #8 | Epic 8: Evidence and audit | p0 | l | evidence | feature | n/a | n/a | no |
| #176 | AgentPod 017: Add session selection UX | p1 | m | runtime | feature | cli-ux | n/a | yes |
| #177 | AgentPod 018: Add evidence path surfacing to every run | p1 | m | evidence | infra | cli-ux | n/a | yes |
| #178 | AgentPod 019: Add concise command risk labels | p1 | m | policy | infra | cli-ux | n/a | yes |
| #185 | AgentPod 026: Add direct-host sensitive-path deny defaults | p1 | m | policy | feature | direct-host | n/a | yes |
| #186 | AgentPod 027: Add direct-host audit parity with AgentPod runs | p1 | m | evidence | feature | direct-host | n/a | yes |
| #194 | AgentPod 035: Add explicit mount policy for Podman | p1 | m | policy | infra | podman-compat | n/a | yes |
| #195 | AgentPod 036: Add Podman credential isolation checks | p1 | m | policy | feature | podman-compat | n/a | yes |
| #196 | AgentPod 037: Add Podman network mode reporting | p1 | m | policy | feature | podman-compat | n/a | yes |
| #197 | AgentPod 038: Add Podman image provenance pinning | p1 | m | security | infra | podman-compat | n/a | yes |
| #203 | AgentPod 044: Add remote capability attestation placeholder | p1 | m | remote | test | remote-worker | n/a | yes |
| #204 | AgentPod 045: Add remote workspace packaging plan | p1 | m | runtime | feature | remote-worker | n/a | yes |
| #205 | AgentPod 046: Add remote evidence return contract | p1 | m | evidence | feature | remote-worker | n/a | yes |
| #232 | AgentPod 073: Add Windows capability descriptor schema | p1 | m | runtime | feature | windows-native | windows | yes |
| #233 | AgentPod 074: Prototype Windows Job Object launcher | p1 | m | runtime | feature | windows-native | windows | yes |
| #234 | AgentPod 075: Prototype Windows restricted token flow | p1 | m | security | security | windows-native | windows | yes |
| #9 | Epic 9: Linux native runtime | p1 | l | runtime | feature | n/a | linux | no |
| #10 | Epic 10: Native enforcement, Windows, and release | p1 | l | runtime | infra | n/a | macos | no |
| #118 | Arc 8: Podman compatibility provider | p1 | l | runtime | test | n/a | n/a | no |
| #119 | Arc 9: Native and VM-backed providers | p1 | l | runtime | feature | n/a | macos | no |
| #120 | Arc 10: Product UX, install, release, and remote AgentPods | p1 | l | docs | feature | n/a | n/a | no |
| #155 | Task 155: Add native provider verification matrix command | p1 | m | runtime | feature | n/a | n/a | no |
| #156 | Task 156: Add macOS VM cell receipt plan | p1 | m | runtime | feature | n/a | macos | no |
| #157 | Task 157: Add Linux namespace live gate skeleton | p1 | m | runtime | infra | n/a | linux | no |
| #158 | Task 158: Add Windows token restriction descriptor | p1 | m | runtime | feature | n/a | windows | no |
| #169 | AgentPod 010: Add canonical product glossary cleanup | p2 | s | docs | docs | product-contract | n/a | yes |
| #179 | AgentPod 020: Add shell completion coverage for AgentPod commands | p2 | m | cli | feature | cli-ux | n/a | yes |
| #187 | AgentPod 028: Add direct-host warning suppression rules | p2 | m | cli | feature | direct-host | n/a | yes |
| #188 | AgentPod 029: Add direct-host smoke fixtures | p2 | m | runtime | test | direct-host | n/a | yes |
| #189 | AgentPod 030: Document direct-host support policy | p2 | s | docs | docs | direct-host | n/a | yes |
| #198 | AgentPod 039: Add Podman cleanup reliability tests | p2 | m | n/a | test | podman-compat | n/a | yes |
| #199 | AgentPod 040: Document Podman escape and bypass boundaries | p2 | s | docs | docs | podman-compat | n/a | yes |
| #207 | AgentPod 048: Add remote worker revocation flow | p2 | m | remote | security | remote-worker | n/a | yes |
| #208 | AgentPod 049: Add remote transport failure semantics | p2 | m | runtime | feature | remote-worker | n/a | yes |
| #209 | AgentPod 050: Document remote worker non-goals | p2 | s | docs | docs | remote-worker | n/a | yes |
| #226 | AgentPod 067: Add macOS Network Extension design-to-gate path | p2 | m | policy | feature | macos-vm | n/a | yes |
| #227 | AgentPod 068: Add macOS Endpoint Security design-to-gate path | p2 | m | security | security | macos-vm | macos | yes |
| #228 | AgentPod 069: Add macOS VM cleanup smoke | p2 | m | n/a | test | macos-vm | macos | yes |
| #229 | AgentPod 070: Document macOS paid-product support boundary | p2 | s | docs | docs | macos-vm | macos | yes |
| #235 | AgentPod 076: Prototype Windows AppContainer workspace mode | p2 | m | security | security | windows-native | windows | yes |
| #236 | AgentPod 077: Define Windows network enforcement path | p2 | m | policy | feature | windows-native | n/a | yes |
| #237 | AgentPod 078: Define Windows evidence via ETW path | p2 | m | evidence | feature | windows-native | windows | yes |
| #238 | AgentPod 079: Add Windows installer prerequisite checks | p2 | m | install | infra | windows-native | windows | yes |
| #239 | AgentPod 080: Document Windows non-goals for first paid/OSS release | p2 | s | docs | docs | windows-native | windows | yes |
| #248 | AgentPod 089: Add evidence retention policy controls | p2 | m | evidence | feature | evidence-integrations | n/a | yes |
| #249 | AgentPod 090: Document evidence trust boundaries | p2 | s | evidence | docs | evidence-integrations | n/a | yes |
| #159 | Task 159: Add product status checkpoint for tasks 139-149 | p2 | s | docs | docs | n/a | n/a | no |

## Priority and area buckets (open issues)

- p0=8 | p1=24 | p2=22 | n/a=0

```text
runtime                      17
policy                       10
docs                         9
evidence                     7
security                     4
cli                          2
n/a                          2
remote                       2
install                      1
```

## Recommended next 12 execution items (p0/p1 first)

1. #176: AgentPod 017: Add session selection UX
2. #177: AgentPod 018: Add evidence path surfacing to every run
3. #178: AgentPod 019: Add concise command risk labels
4. #185: AgentPod 026: Add direct-host sensitive-path deny defaults
5. #186: AgentPod 027: Add direct-host audit parity with AgentPod runs
6. #194: AgentPod 035: Add explicit mount policy for Podman
7. #195: AgentPod 036: Add Podman credential isolation checks
8. #196: AgentPod 037: Add Podman network mode reporting
9. #197: AgentPod 038: Add Podman image provenance pinning
10. #203: AgentPod 044: Add remote capability attestation placeholder
11. #204: AgentPod 045: Add remote workspace packaging plan
12. #205: AgentPod 046: Add remote evidence return contract
