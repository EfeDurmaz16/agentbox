# Safe Credential Patterns

Autonomous agents should not receive the operator's ambient credential surface.
Agentbox should make credentials task-scoped, explicit, auditable, and
revocable where the provider can support it.

## Default Rule

Do not inherit host credentials by default.

Unsafe:

```text
agent task
  -> full host environment
  -> ~/.ssh, ~/.aws, browser profile, keychain, cloud caches
```

Preferred:

```text
agent task
  -> minipod manifest
  -> exact credential grant
  -> approval / authority check
  -> redacted evidence
  -> revocation event
```

Agentbox manifest validation rejects host environment inheritance. Sensitive
path mounts require explicit file grants.

## Recommended Grant Shapes

| Need | Pattern | Avoid |
|------|---------|-------|
| Read one token file | `--credential-file name=host:guest` | Mounting a whole config directory. |
| Use cloud CLI briefly | short-lived task credential file | Passing the user's normal shell environment. |
| Push to GitHub | session-scoped approval plus exact credential path | Mounting `~/.ssh` broadly. |
| Query a database | task-specific connection file with expiration | Long-lived `.env` from the host project root. |
| Browser automation | separate browser profile created for the task | Operator's real browser profile. |
| Payment or deploy action | explicit approval and evidence bundle | Silent ambient credentials. |

## One-Time Credential Files

`--credential-file name=host:guest` should be used for exact file grants:

```sh
agentbox minipod-spec deploy-agent \
  --workspace ./release-work \
  --credential-file vercel=./secrets/vercel-token:/run/agentbox/secrets/vercel
```

This records a credential grant in the minipod manifest and distinguishes the
mount from ordinary read-only reference data. One-time grants should produce
revocation evidence when the session is destroyed.

## FIDES Authority Boundary

Agentbox has a FIDES-compatible credential authority request shape. The default
hook does not fake approval; it reports that no external FIDES runtime is
configured.

Target flow:

```text
credential grant request
  -> FIDES authority policy
  -> signed allow / deny / reason
  -> Agentbox session grant
  -> evidence bundle
```

Until a real FIDES authority is wired, treat credential grants as local
Agentbox policy objects rather than cryptographic authorization.

## Redaction Is Not Isolation

Agentbox redacts credential-like material in audit output, command transcripts,
and evidence bundles. This reduces accidental leakage, but it is not a complete
secret management system.

Redaction can miss:

- unusual token formats
- binary output
- secrets transformed by tools
- secrets logged outside Agentbox
- credentials copied into generated files

The primary control should be least-privilege credential exposure, not cleanup
after exposure.

## Platform Notes

| Runtime | Credential boundary today |
|---------|---------------------------|
| Direct host shims | Approves/audits common credential path access, but cannot stop all process-local reads. |
| Podman compatibility | Can carry credential mount metadata; live socket/shim behavior still needs host proof. |
| macOS AgentPod | Needs Endpoint Security, keychain mediation, or VM-backed profile separation before broad claims. |
| Linux AgentPod | Needs namespace/Landlock/seccomp/provider wiring before file grants become kernel-backed. |
| Windows AgentPod | Needs Job Objects plus AppContainer/ACL/profile strategy before credential isolation is credible. |

## Operator Checklist

Before giving an agent credentials:

- use a task-specific token
- prefer a file grant over environment inheritance
- keep the grant path exact
- set an expiration or one-time lifecycle when possible
- require approval for credential reads or downstream mutation
- verify the evidence bundle after the task
- rotate the credential if the agent handled a powerful secret

Do not grant:

- full home directory access
- real browser profiles
- full SSH directories
- cloud provider root/admin credentials
- package registry publish tokens without explicit publish approval
- payment or deploy credentials without evidence expectations

## Verification

Useful checks:

```sh
agentbox minipod-spec deploy-agent \
  --workspace ./release-work \
  --credential-file vercel=./secrets/vercel-token:/run/agentbox/secrets/vercel

agentbox evidence --limit 20
```

Provider live tests must prove actual denial behavior before claiming native
credential isolation.
