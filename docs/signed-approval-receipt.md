# Signed Approval Receipt

Agentbox approval evidence can be represented as a signed approval receipt
without claiming that Agentbox ships a live FIDES signer. The receipt shape is
local schema and fixture support; a signature is meaningful only when an
external authority signs it.

Rust schema:

- `ApprovalSignature`
- `ApprovalReceiptDecision`
- `SignedApprovalRecord`

Fixture:

- `crates/agentbox-daemon/fixtures/signed-approval-receipt.json`

## Required Fields

| Field | Purpose |
|-------|---------|
| `grant_id` | Stable approval grant id. |
| `session_id` | AgentPod or runtime session the grant applies to. |
| `scope` | The approved boundary: once, command, path, domain, or session. |
| `expires_at` | Expiry deadline for the approval grant. |
| `decision` | `granted`, `denied`, `expired`, or `cancelled`. |
| `evidence_hash` | Hash over the approval evidence or bundle root being signed. |
| `evidence_refs` | Audit ids, event hashes, bundle refs, or receipt refs. |
| `signature.signer` | FIDES DID or external authority id when signed. |
| `signature.algorithm` | Signature algorithm. |
| `signature.signature` | Detached signature payload. |
| `signature.signed_at` | Signing timestamp. |

Unsigned local approvals remain valid Agentbox v0 evidence when labeled as
unsigned. They are not FIDES approvals.

## Non-Claims

This schema does not provide:

- a bundled FIDES signer
- signer key management
- signature verification policy
- revocation
- delegation-token verification
- live publication to FIDES

Those belong behind the FIDES authority adapter boundary.

## Verification

```sh
cargo test --locked -p agentbox-daemon signed_approval_record
rg -n "SignedApprovalRecord|ApprovalReceiptDecision|evidence_hash|signature.signer|signed-approval-receipt" crates/agentbox-daemon/src/runtime/types.rs crates/agentbox-daemon/fixtures/signed-approval-receipt.json docs/evidence-bundle-schema.md docs/signed-approval-receipt.md docs/status-matrix.md
git diff --check
```
