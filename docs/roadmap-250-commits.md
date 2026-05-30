# Agentbox 250+ Commit Product Sprint

This is the execution queue for turning Agentbox into a complete AgentPod
product: governed execution cells for autonomous agents across direct-host,
native sandbox, VM-backed, and remote-compatible providers.

The target is not "Podman but smaller". The stable product is the AgentPod
contract. Podman remains a compatibility provider and smoke backend.

## Finished Product Shape

```text
agent intent
  -> agentbox run
  -> AgentPod manifest
  -> provider selection
  -> guarded execution cell
  -> host bridge
  -> policy / approval / credential / network enforcement
  -> evidence bundle
  -> review / apply / commit / discard
```

The finished CLI path should feel like:

```sh
agentbox setup
agentbox doctor
agentbox run codex --repo ~/repo --risk medium --workspace-mode overlay-review
agentbox review <session>
agentbox evidence --session <session> --bundle ./agentbox-evidence
```

## Product Rules

- Agent type is not the main axis. Risk and host access are the main axes.
- `direct-host` is a useful low-risk provider, not the final isolation story.
- `podman-compat` is useful for compatibility and Linux guest smoke tests, not
  the product center.
- Native providers must report truthfully: descriptor, prototype primitive,
  experimental, or shipped.
- The default autonomous-agent workspace posture should become
  `overlay-review`, with direct writes kept for explicit low-risk use.
- Credentials are explicit grants. No ambient host credential inheritance by
  default.
- Network policy should be usable: `open-with-guardrails` for normal work,
  stronger modes when risk rises.
- Evidence is a product feature, not just logs.

## Commit Arcs

Each arc is intentionally sized around 25 atomic commits. Some commits will
split during implementation if a diff crosses a boundary. That is expected.

## Current Sprint Checkpoint

The sprint has moved past pure planning. The current working spine is:

- Linux AgentPod has a gated prototype execution path through
  `agentbox-linux-runner`, `unshare`, workspace bind mounting, cgroup v2 attach,
  ABI-aware Landlock path-beneath policy for the supported subset, supported
  seccomp deny filters, timeout handling, stdout/stderr collection, and
  request/cgroup cleanup. It is still not a
  complete sandbox claim; the remaining Linux boundary is mapped in
  [Linux hardening gaps](linux-hardening-gaps.md).
- Linux runner request files are owned lifecycle artifacts: they are cleaned on
  early returns and use path-safe, collision-resistant filenames for parallel
  exec attempts.
- macOS AgentPod remains unavailable for execution, but the native plan now
  exposes prerequisite checks and ordered runner phases for the future Apple
  Virtualization VM runner, Endpoint Security system extension, Network
  Extension, host bridge, and evidence flow. The daemon also has a typed VM
  runner request schema, a Linux `VZLinuxBootLoader` artifact contract, and a
  gated `agentbox-macos-vm-runner` boot prototype that either reports typed
  missing prerequisites or attempts Apple Virtualization only when kernel/initrd
  and entitlement prerequisites are present.
- `agentbox doctor --json` and setup-plan filtering now surface macOS VM runner
  and extension readiness gaps as advisory checks instead of hiding them in
  prose.
- Remote AgentPod has a broad experimental contract worker surface, but richer
  worker-side approvals, socket/provider-token credentials, full event
  streaming, and automatic remote supervision remain open.

Current proof queue:

1. macOS: boot a minimal Apple Virtualization VM cell, mount a workspace, and
   prove create/exec/destroy lifecycle with evidence before claiming execution.
2. Linux: strengthen seccomp/Landlock coverage, prove read/execute path policy,
   and keep live native execution gated behind `AGENTBOX_LINUX_NATIVE=1`.
3. Windows: extend Job Object contract work into process assignment,
   kill-on-close cleanup, and resource limit proof before claiming execution.
4. Remote: add worker-side approval UX, full event streaming, and supervision
   without weakening the current credential restrictions.
5. Installer UX: turn provider gap reports and bridge health into guided
   first-run setup output.

### Arc 1: Product Contract In Code

Outcome: code names and manifests express AgentPod, provider kind, risk, and
workspace/network intent without hiding the existing Minipod compatibility.

1. `docs(product): replace 100-issue queue with AgentPod product queue`
2. `feat(runtime): add AgentPodSpec compatibility wrapper`
3. `feat(runtime): add AgentPod risk level model`
4. `feat(runtime): add workspace mode enum matching product contract`
5. `feat(runtime): add open-with-guardrails network mode`
6. `feat(runtime): add provider family metadata`
7. `feat(runtime): add provider status metadata`
8. `feat(runtime): add provider selection request type`
9. `feat(runtime): add provider selection explanation type`
10. `feat(runtime): select direct host for low-risk tasks`
11. `feat(runtime): select native provider candidates for medium-risk tasks`
12. `feat(runtime): select VM-backed candidates for high-risk tasks`
13. `feat(runtime): expose unavailable provider reasons`
14. `test(runtime): cover risk to provider selection`
15. `test(runtime): cover provider truth metadata`
16. `feat(cli): add --risk to manifest generation`
17. `feat(cli): add --workspace-mode to manifest generation`
18. `feat(cli): add --provider selection hint`
19. `feat(cli): add provider recommendation output`
20. `docs(contract): document code-level AgentPod fields`
21. `docs(status): align provider status taxonomy`
22. `test(cli): cover AgentPod manifest flags`
23. `refactor(runtime): preserve MinipodSpec serialization compatibility`
24. `docs(migration): document minipod to agentpod naming`
25. `chore(product): add sprint tracker for remaining arcs`

### Arc 2: Usable Mac Direct-Host Provider

Outcome: the currently runnable macOS path is reliable enough to use while
native and VM providers are built.

26. `fix(cli): clean stale daemon pid during start`
27. `fix(cli): report stale socket separately in doctor`
28. `fix(cli): add doctor --fix-path-hint`
29. `feat(cli): add setup command for local shims and config`
30. `feat(cli): add run --direct-host explicit mode`
31. `feat(runtime): model direct-host provider capabilities`
32. `feat(runtime): persist direct-host sessions`
33. `feat(runtime): record direct-host transcripts`
34. `feat(runtime): attach policy decisions to sessions`
35. `test(cli): cover daemon stale pid cleanup`
36. `test(cli): cover shim path priority diagnostic`
37. `test(runtime): cover direct-host session evidence`
38. `docs(mac): add direct-host quickstart`
39. `docs(mac): document what direct-host does not isolate`
40. `feat(cli): add run dry-run plan output`
41. `feat(cli): add review command skeleton`
42. `feat(cli): add apply/discard command skeleton`
43. `feat(runtime): add workspace diff capture hook`
44. `test(runtime): cover workspace diff hook metadata`
45. `feat(cli): add session list filters`
46. `feat(cli): add session inspect risk/provider fields`
47. `feat(cli): add evidence bundle directory export`
48. `test(cli): cover evidence bundle shape`
49. `docs(demo): update mac autonomous-agent demo`
50. `chore(release): mark direct-host as experimental usable`

### Arc 3: Overlay Review Workspace

Outcome: autonomous agents can write into a reviewable workspace layer instead
of mutating the host tree directly.

51. `feat(workspace): add overlay-review workspace mode`
52. `feat(workspace): add ephemeral workspace mode`
53. `feat(workspace): add commit-gated workspace mode`
54. `feat(workspace): allocate session overlay directories`
55. `feat(workspace): canonicalize overlay roots`
56. `feat(workspace): reject overlay paths under protected roots`
57. `feat(workspace): snapshot lower workspace metadata`
58. `feat(workspace): generate overlay diff`
59. `feat(workspace): export overlay diff as patch`
60. `feat(workspace): discard overlay session output`
61. `feat(workspace): apply overlay diff with review`
62. `feat(workspace): detect symlink escape attempts`
63. `feat(workspace): detect hardlink escape attempts`
64. `feat(workspace): protect home-level config paths`
65. `feat(cli): add agentbox review diff`
66. `feat(cli): add agentbox review apply`
67. `feat(cli): add agentbox review discard`
68. `test(workspace): cover overlay allocation`
69. `test(workspace): cover diff export`
70. `test(workspace): cover symlink escapes`
71. `test(workspace): cover protected path rejects`
72. `docs(workspace): document review workflow`
73. `docs(workspace): document commit-gated mode`
74. `docs(demo): add overlay-review demo`
75. `chore(status): mark overlay-review capability honestly`

### Arc 4: Governed Host Bridge

Outcome: every provider talks to the host through one bridge contract for
commands, approvals, files, credentials, network events, kill, and evidence.

76. `feat(bridge): define host bridge protocol schema`
77. `feat(bridge): add unix socket bridge server`
78. `feat(bridge): add command mediation request`
79. `feat(bridge): add file grant request`
80. `feat(bridge): add credential grant request`
81. `feat(bridge): add network first-contact request`
82. `feat(bridge): add approval response envelope`
83. `feat(bridge): add evidence append request`
84. `feat(bridge): add kill switch request`
85. `feat(bridge): add bridge client crate module`
86. `feat(bridge): add provider bridge capability checks`
87. `feat(bridge): add redaction helpers`
88. `test(bridge): cover schema compatibility`
89. `test(bridge): cover command mediation`
90. `test(bridge): cover credential redaction`
91. `test(bridge): cover kill switch`
92. `docs(bridge): document host bridge contract`
93. `docs(bridge): document provider transport variants`
94. `feat(cli): add bridge diagnostics`
95. `feat(cli): add bridge event tail`
96. `feat(runtime): attach bridge id to sessions`
97. `feat(runtime): record bridge transport metadata`
98. `test(runtime): cover bridge metadata persistence`
99. `docs(security): describe bridge attack surface`
100. `chore(status): add bridge readiness status`

### Arc 5: Credential Broker

Outcome: agents receive explicit, scoped, auditable credential grants instead
of inherited host secrets.

101. `feat(credentials): add grant source model`
102. `feat(credentials): add env grant resolver`
103. `feat(credentials): add file grant resolver`
104. `feat(credentials): add keychain grant descriptor`
105. `feat(credentials): add one-time grant state`
106. `feat(credentials): add grant expiry`
107. `feat(credentials): add approval-required grant reads`
108. `feat(credentials): add redacted audit rendering`
109. `feat(credentials): add revocation evidence`
110. `feat(credentials): block ambient env inheritance by default`
111. `feat(cli): add credential grant flags`
112. `feat(cli): add credential list`
113. `feat(cli): add credential revoke`
114. `test(credentials): cover env grant resolution`
115. `test(credentials): cover file grant path checks`
116. `test(credentials): cover redaction fixtures`
117. `test(credentials): cover one-time grant consumption`
118. `docs(credentials): document safe grant patterns`
119. `docs(credentials): document cloud CLI risks`
120. `feat(integration): add FIDES authority hook descriptor`
121. `feat(integration): add FIDES grant evidence adapter skeleton`
122. `test(integration): cover disabled FIDES adapter honesty`
123. `docs(integration): document FIDES boundary`
124. `docs(status): mark credential broker stage`
125. `chore(security): add secret scanning checklist`

### Arc 6: Network Guardrails

Outcome: normal internet use works while dangerous destinations and high-risk
actions are mediated and recorded.

126. `feat(network): add open-with-guardrails mode`
127. `feat(network): add metadata endpoint denylist`
128. `feat(network): add localhost policy model`
129. `feat(network): add high-risk destination classes`
130. `feat(network): add first-contact event model`
131. `feat(network): add domain normalization`
132. `feat(network): add IP/CIDR normalization`
133. `feat(network): add URL parser tests`
134. `feat(network): add provider enforcement strength enum`
135. `feat(network): add observe-only network event mode`
136. `feat(network): add deny-by-default rendering`
137. `feat(cli): add network explain command`
138. `feat(cli): add network allow/deny session commands`
139. `test(network): cover metadata endpoint blocking`
140. `test(network): cover localhost policy`
141. `test(network): cover first-contact decisions`
142. `docs(network): document open-with-guardrails`
143. `docs(network): document enforcement vs observation`
144. `feat(provider): expose packet enforcement capability`
145. `feat(provider): expose domain enforcement capability`
146. `feat(evidence): add network events JSONL`
147. `test(evidence): cover network event export`
148. `docs(demo): add network approval demo`
149. `docs(status): align network claims`
150. `chore(security): add network bypass checklist`

### Arc 7: Evidence, Replay, And AGIT/FIDES Fit

Outcome: every meaningful session can produce a useful evidence bundle and
attach lineage/signature integrations without fake support claims.

151. `feat(evidence): define bundle manifest schema`
152. `feat(evidence): export manifest json`
153. `feat(evidence): export policy json`
154. `feat(evidence): export approvals jsonl`
155. `feat(evidence): export commands jsonl`
156. `feat(evidence): export filesystem jsonl`
157. `feat(evidence): export credentials jsonl`
158. `feat(evidence): export network jsonl`
159. `feat(evidence): export workspace diff`
160. `feat(evidence): export hashes json`
161. `feat(evidence): verify evidence bundle hashes`
162. `feat(evidence): add replay metadata`
163. `feat(evidence): add transcript redaction`
164. `test(evidence): cover bundle verification`
165. `test(evidence): cover transcript redaction`
166. `test(evidence): cover tamper detection`
167. `feat(integration): add AGIT lineage descriptor`
168. `feat(integration): add AGIT patch output adapter`
169. `feat(integration): add FIDES signed action descriptor`
170. `feat(integration): add OAPS evidence profile descriptor`
171. `test(integration): cover disabled adapter status`
172. `docs(evidence): document bundle format`
173. `docs(integration): document AGIT/FIDES/OAPS fit`
174. `docs(demo): add evidence replay demo`
175. `chore(status): mark evidence bundle maturity`

### Arc 8: Podman Compatibility Provider

Outcome: compatibility mode is genuinely useful and honestly labeled, with a
Linux guest shim artifact story instead of macOS binaries inside Linux guests.

176. `feat(podman): add linux guest shim artifact lookup`
177. `feat(podman): add shim target triple validation`
178. `feat(podman): add bridge socket smoke fixture`
179. `feat(podman): add container lifecycle labels`
180. `feat(podman): add sidecar network wiring`
181. `feat(podman): add overlay mount wiring`
182. `feat(podman): add service readiness timeout reporting`
183. `feat(podman): add pod logs aggregation`
184. `feat(podman): add pod inspect metadata`
185. `feat(podman): add provider conformance runner`
186. `test(podman): cover linux shim rejection`
187. `test(podman): cover command construction`
188. `test(podman): cover sidecar readiness`
189. `test(podman): cover overlay mount args`
190. `test(podman): add live bridge smoke skip semantics`
191. `docs(podman): document compatibility status`
192. `docs(podman): document macOS Linux guest boundary`
193. `ci(podman): add optional Linux smoke job`
194. `ci(podman): add artifact build matrix`
195. `chore(status): close Podman proof issues only after live pass`
196. `feat(cli): add podman doctor details`
197. `feat(cli): add podman bridge smoke command`
198. `docs(demo): add podman compatibility demo`
199. `test(runtime): cover provider fallback when podman missing`
200. `chore(release): mark podman-compat experimental`

### Arc 9: Native And VM-Backed Providers

Outcome: kernel-grade work begins as real primitives with explicit boundaries
on macOS, Linux, and Windows.

201. `feat(macos): add Apple Virtualization provider crate scaffold`
202. `feat(macos): add VM image descriptor model`
203. `feat(macos): add VM bridge transport descriptor`
204. `feat(macos): add Endpoint Security event schema`
205. `feat(macos): add Network Extension policy schema`
206. `feat(macos): add system extension install diagnostics`
207. `test(macos): cover descriptor status honesty`
208. `docs(macos): document VM-backed AgentPod path`
209. `feat(linux): add namespace launcher scaffold`
210. `feat(linux): add cgroups v2 resource config`
211. `feat(linux): add overlayfs workspace config`
212. `feat(linux): add seccomp profile renderer`
213. `feat(linux): add Landlock ruleset model`
214. `feat(linux): add nftables policy descriptor`
215. `feat(linux): add eBPF observability descriptor`
216. `test(linux): cover namespace config validation`
217. `test(linux): cover seccomp profile rendering`
218. `test(linux): cover Landlock rule validation`
219. `docs(linux): document native provider lifecycle`
220. `feat(windows): add Job Object provider scaffold`
221. `feat(windows): add AppContainer descriptor`
222. `feat(windows): add WFP policy descriptor`
223. `feat(windows): add ETW event schema`
224. `docs(windows): document native provider lifecycle`
225. `chore(status): mark native primitives as prototype only`

### Arc 10: Product UX, Install, Release, Remote

Outcome: Agentbox becomes a product people can try, inspect, install, and later
run against remote AgentPod workers.

226. `feat(cli): add agentbox setup wizard`
227. `feat(cli): add agentbox run plan preview`
228. `feat(cli): add agentbox run --json`
229. `feat(cli): add agentbox review TUI skeleton`
230. `feat(cli): add agentbox sessions watch`
231. `feat(remote): define remote AgentPod transport`
232. `feat(remote): add remote provider descriptor`
233. `feat(remote): add remote bridge auth descriptor`
234. `feat(remote): add remote evidence upload descriptor`
235. `test(remote): cover remote descriptor honesty`
236. `docs(remote): document attached remote machine model`
237. `docs(remote): document cloud execution boundary`
238. `docs(install): add Homebrew path`
239. `docs(install): add Linux install path`
240. `docs(install): add Windows install path`
241. `ci: add fmt clippy test release gate`
242. `ci: add optional live test matrix`
243. `ci: add artifact signing placeholder without claiming signing`
244. `docs(release): add v0.2 demo checklist`
245. `docs(release): add public limitations page`
246. `docs(readme): rewrite quickstart around AgentPod`
247. `docs(readme): add status table`
248. `docs(readme): add examples for Codex, OpenClaw, Hermes`
249. `docs(readme): add contribution guide`
250. `chore(release): cut v0.2 product-ready tag candidate`

## First Execution Wave

Historical note: this wave has been absorbed into the current AgentPod spine.
The remaining work is provider proof, installer UX, and release hardening, not
another broad naming pass.

## Verification Gates

Use the strongest gate practical for each commit:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
git diff --check
```

Provider/live gates must skip honestly when prerequisites are missing. A skipped
live test is not a pass and must not close live-proof issues.
