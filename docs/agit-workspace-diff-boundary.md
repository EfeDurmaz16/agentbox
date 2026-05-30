# AGIT Workspace Diff Boundary

Agentbox can reference workspace diff snapshots as evidence for future AGIT
lineage, but it does not require or ship an AGIT service.

The current implementation is an adapter boundary:

- Rust interface: `crates/agentbox-daemon/src/runtime/agit.rs`
- lineage record: `AgitEvidenceLineageRecord`
- workspace diff ref: `AgitWorkspaceDiffEvidenceRef`
- publisher trait: `AgitEvidencePublisher`
- default implementation: `NoopAgitEvidencePublisher`
- descriptor: `AgitEvidenceAdapterDescriptor`
- fixture: `crates/agentbox-daemon/fixtures/agit-workspace-diff-ref.json`

The default publisher always returns `RequiresExternalAdapter`. That keeps the
lineage boundary honest: Agentbox may produce local refs, but it does not claim
that an AGIT repository, commit, or lineage graph was updated.

## Diff Reference Shape

`AgitWorkspaceDiffEvidenceRef` binds a local diff snapshot to:

- Agentbox session id
- workspace path
- snapshot id
- patch reference path
- patch SHA-256
- patch byte count
- evidence hash
- `live_support=false`
- `requires_external_adapter=true`

The patch bytes do not need to be embedded in the AGIT ref. A support bundle or
evidence bundle can carry a patch file separately while the AGIT boundary keeps
a stable hash pointer.

## Non-Claims

This boundary does not provide:

- AGIT repository initialization
- AGIT commit publication
- remote AGIT service calls
- merge decisions
- workspace apply/discard semantics
- signed AGIT lineage

Those belong behind an external AGIT adapter. Until that exists, AGIT refs are
local evidence pointers only.

## Verification

```sh
cargo test --locked -p agentbox-daemon agit
rg -n "AgitWorkspaceDiffEvidenceRef|NoopAgitEvidencePublisher|external-adapter-required|live_support=false|agit-workspace-diff-ref" crates/agentbox-daemon/src/runtime/agit.rs crates/agentbox-daemon/fixtures/agit-workspace-diff-ref.json docs/agit-workspace-diff-boundary.md docs/status-matrix.md
git diff --check
```
