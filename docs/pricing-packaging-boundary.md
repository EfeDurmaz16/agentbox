# Pricing And Packaging Boundary

This document defines what Agentbox can package, support, or sell without
weakening the open AgentPod product contract. It is not a price sheet. It is the
claim boundary for OSS distribution, paid packaging/support, remote workers, and
enterprise controls.

Agentbox can be monetized around packaging, reliability, support, verified
provider operation, and fleet controls. It must not monetize by hiding provider
truth, downgrading the OSS safety model, or presenting descriptor-only surfaces
as shipped enforcement.

## Product Split

| Surface | Belongs in OSS core | Can be paid packaging/support | Must not be claimed without proof |
|---------|---------------------|-------------------------------|-----------------------------------|
| AgentPod contract | Manifest schema, provider ids, provider truth vocabulary, workspace modes, credential grants, policy hooks, evidence receipts. | Stable release builds, compatibility testing, migration support, and long-term support branches. | That every provider enforces every primitive on every OS. |
| Local command governance | CLI, daemon, shims, policy classification, approvals, audit, evidence export, evidence verification. | Clean-host installers, signed/notarized binaries, rollback support, daemon/service setup, and support playbooks. | Full OS sandboxing for direct-host mode. |
| Provider metadata | `agentbox providers`, `provider-gaps`, `provider-readiness`, `bridge-health`, and docs that expose shipped, experimental, prototype, descriptor-only, planned, and unavailable states. | Verified platform matrices and paid support for named provider/host combinations. | Native macOS, Linux, Windows, or remote isolation when only descriptors or prototypes exist. |
| Evidence and support | Evidence bundle export/verify, AgentPod receipts, redacted support bundle export, public schemas, and local troubleshooting docs. | Support SLAs, triage tooling, artifact retention workflows, managed evidence review, and customer-specific incident support. | That support can trust raw logs, unverified bundles, or incomplete remote receipts. |
| Remote AgentPod | Secret-free descriptors, gated loopback smoke, HTTPS endpoint contract, identity/evidence model, and honest experimental status. | Managed or customer-attached workers after endpoint identity, lifecycle, evidence, restart, destroy, and support gates pass. | A generic hosted sandbox, confidential compute, or production remote fleet before live proof exists. |
| Enterprise controls | Public policy/evidence primitives and integration descriptors for FIDES, AGIT, and OAPS. | Admin policy bundles, org templates, identity/SSO hooks, SIEM export, approval routing, fleet rollout, and compliance reports after implementation. | Live enterprise governance, signed authority, or external revocation when descriptors are metadata-only. |

## OSS Core

The OSS core should remain useful without private services:

- build from source with Cargo
- run the CLI, daemon, shims, direct-host command governance, and current
  provider inspection commands
- generate AgentPod manifests and run through provider selection
- inspect support levels for every provider and primitive
- export and verify evidence bundles
- export a redacted support bundle for bug reports
- read docs that explain every major limitation and verification gate

The OSS version may include experimental and prototype code, but those surfaces
must keep their gates visible. An OSS user should never need a paid service to
learn that a provider is descriptor-only or unavailable.

## Paid Packaging And Support

Paid packaging is allowed when it adds operational value around the same truth
surface:

- reproducible release binaries and archives
- Homebrew, tarball, package, MSI, or managed installer distribution
- signing, notarization, checksums, attestations, and SBOMs
- clean-host setup, daemon/service lifecycle, upgrade, rollback, uninstall, and
  recovery support
- named provider/platform support matrices
- support bundle triage and evidence verification workflows
- long-term support releases and customer-specific compatibility testing

Paid support must name the exact platform and provider scope. "Paid AgentPod"
by itself is too broad. Acceptable wording is closer to:

```text
Paid preview support for macOS source/install packaging and direct-host command
governance, with Podman compatibility only when live smoke passes on the target
host. Native macOS AgentPod execution remains descriptor/prototype-gated.
```

Packaging must not silently install privileged helpers, mutate shell startup
files, install firewall rules, or enable native providers without explicit
operator action and rollback.

## Remote Workers

Remote AgentPod can become a paid surface, but only after the worker is a real
governed execution target rather than a generic remote shell.

Paid remote worker support requires:

- HTTPS or stronger authenticated transport
- worker identity and challenge binding
- capability reporting with attested, self-reported, or unknown status
- verified workspace bundle upload and export
- explicit credential grant handling without ambient host credential forwarding
- lifecycle receipts for create, exec, stop, destroy, and restart behavior
- evidence return that can be checked against the local session
- support bundle and incident artifacts that redact secrets

Until those gates pass, remote AgentPod remains experimental. It can be
documented, tested against loopback, and used by advanced operators with the
gate enabled, but it should not be sold as a production hosted sandbox service.

## Enterprise Controls

Enterprise controls should build on Agentbox primitives instead of replacing
them:

- organization policy bundles
- role-based approval routing
- SSO or identity provider binding
- signed authority and delegation through FIDES once live adapters exist
- AGIT-linked workspace/action lineage once live adapters exist
- OAPS profiles for interoperable policy/evidence exchange
- audit export to SIEM or data warehouse targets
- admin-managed provider allowlists, kill switches, and retention policy

These are paid-capable surfaces because they require deployment, integration,
and operational support. They are not v0 shipped claims unless the repo contains
the implementation, tests, and public verification commands.

## Claim Rules

Use the same vocabulary as `docs/provider-truth.md` and CLI provider JSON:

- `shipped`
- `experimental`
- `prototype primitive`
- `descriptor only`
- `planned`
- `unavailable`

Do not use pricing or packaging language to upgrade a claim. If a provider is
descriptor-only in `agentbox providers --json`, it stays descriptor-only in the
README, package page, release notes, support docs, and sales material.

Before claiming a paid surface:

1. The OSS truth surface must already show the boundary.
2. A clean-host install or setup path must exist for the named platform.
3. The claimed provider must have a live verification command for that host.
4. Support artifacts must be collectable without secrets.
5. Evidence verification must be part of the support workflow.
6. Release notes must name shipped, experimental, prototype, descriptor-only,
   planned, and unavailable surfaces separately.

## Allowed And Disallowed Wording

| Avoid | Use instead |
|-------|-------------|
| "Agentbox ships native macOS sandboxes." | "Agentbox ships macOS native descriptors and a gated Apple Virtualization boot prototype; provider execution remains unavailable until live gates pass." |
| "Paid AgentPod gives every agent a secure container." | "Paid packaging/support covers named provider/platform combinations that passed the release gates." |
| "Remote AgentPod is a hosted sandbox." | "Remote AgentPod is an experimental worker contract until identity, lifecycle, evidence, and support gates pass." |
| "Enterprise governance is supported." | "Enterprise control primitives are planned or descriptor-backed until the specific adapter is implemented and verified." |
| "Podman is the Agentbox runtime." | "Podman is a compatibility provider; Agentbox owns the AgentPod contract." |

## Release Gate

For issue #258, verify that this boundary stays visible:

```sh
rg -n "OSS core|Paid Packaging And Support|Remote Workers|Enterprise Controls|descriptor-only|experimental" docs/pricing-packaging-boundary.md
rg -n "pricing-packaging-boundary|Pricing And Packaging Boundary" README.md docs/v0-release-criteria.md
git diff --check
```

This doc should be updated whenever a provider moves up or down in
`agentbox providers --json`, whenever packaging gains a new clean-host path, or
whenever paid support materials add a new claim.
