# FIDES Authority Boundary

Agentbox can emit FIDES-compatible authority requests and signed-action drafts,
but it does not ship a live FIDES authority runtime, signing service,
revocation registry, or verifier.

The current implementation is an adapter boundary:

- Rust interface: `crates/agentbox-daemon/src/runtime/fides.rs`
- request type: `FidesCredentialAuthorityRequest`
- decision type: `FidesCredentialAuthorityDecision`
- hook trait: `FidesCredentialAuthorityHook`
- default implementation: `NoopFidesCredentialAuthorityHook`
- descriptor: `FidesAuthorityAdapterDescriptor`

The default hook always returns `RequiresExternalAuthority`. That is deliberate:
Agentbox must not turn a FIDES-shaped request into a fake signed approval.

## Ownership Split

| Layer | Owner | Current status |
|-------|-------|----------------|
| Runtime policy, local approval, credential grants, evidence references | Agentbox | Shipped local governance. |
| Authority identity, signed policies, signed approvals, delegation tokens, revocation, verification | FIDES or another external authority system | External adapter required. |
| Mapping Agentbox evidence into FIDES-style action drafts | Agentbox | Descriptor/draft support only; no signature. |
| Publishing or verifying FIDES authority records | External adapter | Not shipped by Agentbox. |

## Request Shape

`FidesCredentialAuthorityRequest` binds a credential decision to:

- Agentbox session id
- agent name
- provider and platform
- grant name, kind, target, one-time flag, and approval requirement
- evidence references, usually audit hashes or bundle refs

The request is useful because an external FIDES runtime can decide whether a
grant is allowed without needing raw secret values. It is not proof that the
external authority approved the grant.

## Default No-Op Behavior

`NoopFidesCredentialAuthorityHook` must remain fail-closed:

```text
credential grant request
  -> NoopFidesCredentialAuthorityHook
  -> RequiresExternalAuthority("FIDES runtime is not configured")
```

Acceptable default states:

- `external-authority-required`
- `live_support=false`
- `requires_external_adapter=true`

Unacceptable default states:

- returning `Allow`
- fabricating a signer
- marking `live_support=true`
- implying FIDES revocation or verification exists without an adapter

## Signed-Action Drafts

`FidesSignedActionDraft` maps local audit events into FIDES-style action drafts.
Drafts can carry evidence refs, but `signature` remains `None` until an external
signer is configured.

A draft with `signature=None` is not a signed FIDES approval. It is a portable
object that can be handed to a future adapter.

## Verification

Use this gate for issue #243:

```sh
cargo test --locked -p agentbox-daemon fides
rg -n "NoopFidesCredentialAuthorityHook|external-authority-required|live_support=false|requires_external_adapter=true|signature=None" docs/fides-authority-boundary.md crates/agentbox-daemon/src/runtime/fides.rs docs/status-matrix.md docs/safe-credential-patterns.md
git diff --check
```

Provider/support level remains honest only if tests and docs continue to show
that no live FIDES authority claim is shipped by default.
