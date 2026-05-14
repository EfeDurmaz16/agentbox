# macOS System Extension Scaffold Plan

Agentbox should use a macOS system extension only when it can honestly install,
run, and report its enforcement state. Until then, `agentpod-macos` remains a
descriptor and the CLI must not claim host-level enforcement.

## Package Shape

The likely package is:

```text
Agentbox.app
  -> AgentboxEndpointExtension.systemextension
  -> agentbox-daemon
  -> agentbox-cli
```

The app owns installation, upgrade, approval UX, and uninstall. The extension
owns Endpoint Security subscription and authorization responses. The Rust daemon
owns policy, approvals, sessions, and evidence.

## Required Apple Pieces

- Apple Developer Program membership.
- `com.apple.developer.endpoint-security.client` entitlement approval.
- System Extension install entitlement and provisioning profile.
- Hardened runtime signing.
- Notarization.
- User approval in System Settings, or MDM profile for managed installs.

Normal open-source CI should not require these pieces. CI can validate schemas,
FFI bindings, and docs, but privileged smoke tests need a separate macOS runner
with the required entitlement and install flow.

## Extension Responsibilities

The extension should be deliberately small:

- subscribe to selected Endpoint Security events;
- normalize event metadata;
- map process events to an AgentPod session when possible;
- call the daemon through a narrow local policy channel;
- apply the daemon decision before the ES response deadline;
- emit minimal local diagnostics without secrets.

The extension should not:

- own product policy;
- store approval state;
- export network content;
- parse broad configuration files;
- silently downgrade to “enforced” when the daemon is unavailable.

## IPC Boundary

The extension-to-daemon protocol should be separate from the current shim socket.
It needs bounded latency and a small schema:

```text
MacOsAuthEvent {
  event_id,
  event_kind,
  deadline,
  pid,
  parent_pid,
  executable_path,
  argv_digest,
  signing_team_id,
  target_path,
  requested_access,
  session_id,
  workspace_root
}
```

The daemon response should be:

```text
MacOsAuthDecision {
  event_id,
  decision,
  policy_hash,
  approval_id,
  reason,
  cache_ttl_ms
}
```

## Development Stages

1. **Doc and schema scaffold**
   - Add event and decision schemas.
   - Add `agentbox doctor` readiness rows.
   - Keep runtime execution unavailable.

2. **Xcode sample target**
   - Build a minimal system extension target.
   - Subscribe to notify-only events first.
   - No production policy enforcement.

3. **Auth exec smoke**
   - Subscribe to `AUTH_EXEC`.
   - Allow system binaries by default.
   - Deny one controlled test binary in an isolated test session.

4. **Daemon policy bridge**
   - Connect extension to daemon.
   - Add response deadline handling.
   - Record evidence for every decision.

5. **File-event enforcement**
   - Gate writes, deletes, renames, and selected reads outside workspace.
   - Keep protected credential paths deny-by-default.

6. **Packaging and release**
   - Host app install flow.
   - Notarized build.
   - Upgrade/uninstall path.
   - MDM notes for managed machines.

## Doctor States

`agentbox doctor` should eventually distinguish:

| State | Meaning |
|-------|---------|
| `descriptor-only` | AgentPod provider exists but no extension build is installed. |
| `missing-entitlement` | Extension binary exists but lacks Endpoint Security entitlement. |
| `installed-disabled` | System extension is installed but not active. |
| `active-observe` | Extension is active in notify-only mode. |
| `active-enforce` | Extension is active and authorizing scoped events. |

Anything below `active-enforce` must not be reported as kernel-grade
enforcement.

## External References

- Apple Endpoint Security framework: https://developer.apple.com/documentation/endpointsecurity
- Endpoint Security entitlement: https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client
- System Extensions overview: https://developer.apple.com/system-extensions/
- Network Extension filtering: https://developer.apple.com/documentation/networkextension/filtering-network-traffic
