# AgentPod Evidence Bundle Schema

AgentPod evidence bundles are the reproducible session record for governed
agent execution. A bundle lets an operator, remote worker, verifier, FIDES
adapter, or AGIT lineage adapter answer four questions after a run:

- what execution boundary was requested
- what provider actually ran and what it claims to enforce
- which commands, policy decisions, approvals, artifacts, and redactions were
  observed
- whether the exported record is internally hash-consistent

This document defines the canonical `agentpod-evidence-bundle/v0` shape. It is
a contract for emitters and verifiers. Current Agentbox support is not yet a
complete canonical exporter: the CLI can export and verify a session bundle
directory with `index.json`, `bundle.json`, `manifest.json`, `replay.json`,
`transcripts.json`, and `integrations.json`. Future code should converge on the
canonical layout below without presenting descriptor-only or prototype provider
surfaces as shipped.

## Bundle Layout

Canonical bundles are directories. Paths are relative to the bundle root and
must not contain `..`, absolute paths, symlinks, or platform-specific path
separators.

```text
agentpod-evidence/
  index.json
  session.json
  manifest.json
  provider.json
  policy-decisions.jsonl
  approvals.jsonl
  commands.jsonl
  artifacts.json
  hashes.json
  redactions.json
  replay.json
  integrations.json
  transcripts/
    command-0001.json
```

Required v0 files:

| Path | Purpose |
| --- | --- |
| `index.json` | Bundle manifest, schema id, file inventory, root hash, and compatibility metadata. |
| `session.json` | Session identity, timestamps, status, platform, risk, workspace mode, and agent metadata. |
| `manifest.json` | AgentPod manifest captured before execution. |
| `provider.json` | Provider descriptor and provider receipt for the observed run. |
| `policy-decisions.jsonl` | Ordered policy decisions for commands, files, credentials, network events, and host bridge actions. |
| `approvals.jsonl` | Approval requests, responses, receipt references, and expiry/scope metadata. Empty file is valid when no approval was requested. |
| `commands.jsonl` | Ordered command lifecycle events and exit summaries. |
| `artifacts.json` | Workspace diffs, output artifacts, uploaded bundles, transcript references, and external artifact references. |
| `hashes.json` | Per-file hashes, event chain metadata, root hash algorithm, and optional external attestations. |
| `redactions.json` | Redaction policy, redaction boundaries, and fields that were intentionally omitted or tokenized. |

Optional v0 files:

| Path | Purpose |
| --- | --- |
| `replay.json` | Metadata-only replay plan and replay limitations. |
| `integrations.json` | Descriptor-only or live integration metadata for FIDES, AGIT, OAPS, remote workers, or other sinks. |
| `transcripts/*.json` | Redacted command transcript payloads referenced by `commands.jsonl` or `artifacts.json`. |
| `network.jsonl` | Detailed network observations when separated from `policy-decisions.jsonl`. |
| `filesystem.jsonl` | Detailed filesystem observations when separated from `policy-decisions.jsonl`. |
| `credentials.jsonl` | Detailed credential grant/read/revocation observations when separated from `policy-decisions.jsonl`. |

## `index.json`

`index.json` is the entrypoint for validators. It records the canonical schema,
bundle identity, file inventory, compatibility rules, and root hash.

Required fields:

- `schema`: literal `agentpod-evidence-bundle`
- `schema_version`: integer `0`
- `bundle_id`: stable bundle id, preferably ULID or UUID
- `session_id`: AgentPod session id
- `created_at`: RFC 3339 timestamp for bundle creation
- `producer`: object with `name`, `version`, and optional `git_commit`
- `compatibility`: object with `min_reader_version`, `forward_compatible`,
  and optional `extensions`
- `required_file_kinds`: array containing every required v0 file kind
- `files`: array of file descriptors
- `root_hash`: object with `algorithm`, `encoding`, `value`, and `covers`

Each file descriptor contains:

- `path`: bundle-relative path
- `kind`: stable file kind such as `manifest`, `provider_receipt`, or
  `commands`
- `media_type`: `application/json` or `application/jsonl`
- `required`: boolean
- `bytes`: byte count of the serialized file
- `sha256`: lowercase SHA-256 hex digest of the serialized file
- `redaction_boundary`: one of `none`, `redacted`, `tokenized`,
  `descriptor-only`, or `omitted`

The root hash is computed over the sorted `files` descriptors, not over
`index.json` itself. Sort by `path`, concatenate:

```text
<path>\n<sha256>\n<bytes>\n
```

Then SHA-256 the UTF-8 bytes of that stream. `root_hash.covers` must say
`files[] descriptors excluding index.json`.

## `session.json`

Required fields:

- `schema_version`: integer `0`
- `session_id`
- `session_name`
- `agent`: object with `name`, optional `version`, and optional `pid`
- `provider`: provider id requested or selected for the session
- `platform`: host platform string
- `status`: `created`, `running`, `stopped`, `failed`, or `destroyed`
- `risk`: risk classification used for provider selection
- `workspace_mode`: `direct`, `overlay-review`, `ephemeral`, or
  `commit-gated`
- `started_at`, `stopped_at`
- `provider_selection_reason`

`session.json` must not include raw secrets, full unredacted environment
snapshots, private key material, bearer tokens, or unredacted transcript text.

## `manifest.json`

`manifest.json` is the AgentPod manifest captured before execution. It records
the boundary that was requested, not what was actually enforced. It should
include:

- workspace root and workspace write mode
- read-only mounts, writable mounts, credential mounts, and protected host paths
- credential grants with scope, expiry, one-time flag, approval requirement,
  and redaction policy
- network policy mode and allow/deny/first-contact rules
- approval policy and pre-granted approval scopes
- sidecar and host bridge requirements
- provider constraints and risk hints

## `provider.json`

`provider.json` contains both a descriptor and a receipt.

Required descriptor fields:

- `provider_id`
- `implementation_status`: `shipped`, `experimental`,
  `prototype primitive`, `descriptor only`, `planned`, or `unavailable`
- `platform`
- `capabilities`: array of supported boundary capabilities
- `claim_boundary`: plain-language statement of what is and is not claimed

Required receipt fields:

- `receipt_id`
- `session_id`
- `provider_id`
- `observed_status`
- `enforcement_status`
- `started_at`, `stopped_at`
- `runner_phases`: array of phase receipts with `phase`, `event_name`,
  `status`, `active`, optional `requires_gate`, `enforcement_scope`, and
  optional `evidence_ref`
- `enforced_phases`
- `skipped_planned_primitives`
- `evidence_refs`

The receipt must stay honest. Descriptor-only plans, unavailable providers, and
prototype primitive phases are valid evidence, but they are not shipped
enforcement claims.

## Events

All JSONL files contain one JSON object per line. Lines are ordered by
`sequence`. Every event must include:

- `schema_version`: integer `0`
- `event_id`
- `session_id`
- `sequence`: monotonically increasing integer within the file
- `timestamp`: RFC 3339 timestamp
- `event_type`
- `source`: `daemon`, `cli`, `provider`, `worker`, `host-bridge`,
  `policy`, or `integration`
- `redaction_boundary`
- `prev_event_hash`: previous event hash in the same JSONL file, or `null` for
  the first line
- `event_hash`: SHA-256 of the canonical serialized event with
  `event_hash` omitted

The current CLI bundle exporter also writes a `hash_chain` object into
`bundle.json`. This is a session-local chain over `replay.steps`, separate from
the global audit database chain. Each entry records `sequence`,
`audit_event_id`, `audit_previous_event_hash`, `audit_event_hash`,
`bundle_previous_event_hash`, and `bundle_event_hash`.

`agentbox evidence verify --bundle <dir>` verifies file checksums first, then
recomputes this session-local chain when `hash_chain` is present. A clean bundle
passes; changing replay or grouped evidence event content without regenerating a
coherent bundle fails verification.

### Policy Decisions

`policy-decisions.jsonl` events record the decision trace before execution or
access:

- `subject_type`: `command`, `file`, `network`, `credential`, `host-action`,
  or `provider-phase`
- `subject_ref`
- `bucket`: `allow`, `approve`, or `block`
- `decision`
- `rule_ids`
- `inputs_redacted`: boolean
- `approval_request_ref`: event id when `bucket` is `approve`
- `command_ref`: command event id when applicable
- `provider_receipt_ref`: provider receipt or runner phase when applicable

Policy decisions must be emitted before the controlled command, access, or host
bridge action is executed.

### Approvals

`approvals.jsonl` events record operator or external authority decisions:

- `approval_id`
- `request_ref`: policy decision or pending remote approval id
- `scope`: `once`, `command`, `path`, `domain`, `credential`, or `session`
- `requested_at`
- `resolved_at`
- `outcome`: `granted`, `denied`, `expired`, or `cancelled`
- `reason`
- `expires_at`
- `receipt_refs`: references to local audit rows, remote worker receipts,
  FIDES signatures, or other approval receipts
- `signature`: optional detached signature descriptor; absent means unsigned

Unsigned local approvals are valid v0 evidence when labeled as unsigned.

### Commands

`commands.jsonl` events record command lifecycle without leaking secrets:

- `command_id`
- `argv_redacted`
- `cwd`
- `env_policy`: descriptor of inherited, denied, or brokered env handling
- `policy_decision_ref`
- `approval_refs`
- `started_at`
- `finished_at`
- `exit_code`
- `stdout_ref`, `stderr_ref`: transcript or artifact refs
- `provider_phase_refs`

Raw argv, environment variables, stdout, and stderr must be redacted or moved
to transcript files with explicit redaction boundaries when they may contain
secrets.

## Artifacts

`artifacts.json` is a JSON object with `schema_version`, `artifacts`, and
optional `external_refs`. Artifact descriptors include:

- `artifact_id`
- `kind`: `workspace-diff`, `patch`, `transcript`, `file`, `upload`,
  `remote-bundle`, or `attestation`
- `path` or `uri`
- `media_type`
- `sha256`
- `bytes`
- `produced_by`: command id, provider phase, or integration id
- `redaction_boundary`

## Redaction Boundaries

Redaction is part of the evidence contract, not a display option.

- `none`: file is expected to contain no sensitive fields
- `redacted`: sensitive substrings were replaced with stable placeholders
- `tokenized`: sensitive values were replaced with deterministic references
- `descriptor-only`: only metadata is present; raw payload was never exported
- `omitted`: payload exists conceptually but is intentionally absent

Bundles must never include raw private keys, bearer tokens, session cookies,
unredacted cloud credentials, or unredacted payment credentials. Redaction
metadata should identify field paths and categories, not the secret values.

## Compatibility

This v0 schema uses integer `schema_version: 0` for canonical bundle artifacts.
Readers must reject unknown required file kinds. Readers may ignore unknown
optional file kinds and unknown object fields when `compatibility.forward_compatible`
is `true`.

Breaking changes require a new major schema version. Additive file kinds or
fields may be introduced as optional extensions when they are listed in
`compatibility.extensions` and each new file descriptor sets `required: false`.

Provider support must use the provider truth language from
`docs/provider-truth.md`; schema compatibility does not upgrade provider
implementation status.

## Minimal `index.json` Example

```json
{
  "schema": "agentpod-evidence-bundle",
  "schema_version": 0,
  "bundle_id": "01HY8XRK8M7Z7VYH9D4FJ9E3Q4",
  "session_id": "agentpod-session-01",
  "created_at": "2026-05-30T12:00:00Z",
  "producer": {
    "name": "agentbox",
    "version": "0.2.0",
    "git_commit": "unknown"
  },
  "compatibility": {
    "min_reader_version": "0.2.0",
    "forward_compatible": true,
    "extensions": []
  },
  "required_file_kinds": [
    "session",
    "manifest",
    "provider_receipt",
    "policy_decisions",
    "approvals",
    "commands",
    "artifacts",
    "hashes",
    "redactions"
  ],
  "files": [
    {
      "path": "session.json",
      "kind": "session",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "none"
    },
    {
      "path": "manifest.json",
      "kind": "manifest",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "none"
    },
    {
      "path": "provider.json",
      "kind": "provider_receipt",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "descriptor-only"
    },
    {
      "path": "policy-decisions.jsonl",
      "kind": "policy_decisions",
      "media_type": "application/jsonl",
      "required": true,
      "bytes": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "redaction_boundary": "redacted"
    },
    {
      "path": "approvals.jsonl",
      "kind": "approvals",
      "media_type": "application/jsonl",
      "required": true,
      "bytes": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "redaction_boundary": "redacted"
    },
    {
      "path": "commands.jsonl",
      "kind": "commands",
      "media_type": "application/jsonl",
      "required": true,
      "bytes": 0,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "redaction_boundary": "redacted"
    },
    {
      "path": "artifacts.json",
      "kind": "artifacts",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "redacted"
    },
    {
      "path": "hashes.json",
      "kind": "hashes",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "none"
    },
    {
      "path": "redactions.json",
      "kind": "redactions",
      "media_type": "application/json",
      "required": true,
      "bytes": 2,
      "sha256": "44136fa355b3678a1146ad16f7e8649e94fb4f87af1a3be66a900c65db8a25a8",
      "redaction_boundary": "none"
    }
  ],
  "root_hash": {
    "algorithm": "sha256",
    "encoding": "hex",
    "value": "c3d86cb702706122160719ed0ba8088ed88f235b8b3f5d7bfc33f2d0bc1a1890",
    "covers": "files[] descriptors excluding index.json"
  }
}
```

## Verification

Current CLI verification for emitted bundle directories:

```sh
agentbox evidence --session <session-id> --bundle ./agentpod-evidence
agentbox evidence verify --bundle ./agentpod-evidence
```

Schema artifact parse verification:

```sh
python3 -m json.tool schemas/agentpod-evidence-bundle.schema.json >/dev/null
```

Canonical v0 verifier work should:

1. parse `index.json` against `schemas/agentpod-evidence-bundle.schema.json`
2. reject missing required file kinds
3. verify every file descriptor byte count and SHA-256
4. recompute `root_hash`
5. verify JSONL event hash chains independently per event file
6. confirm approval refs, policy decision refs, command refs, provider receipt
   refs, and artifact refs point to existing bundle records
7. report descriptor-only and prototype provider support as evidence, not as
   shipped enforcement
