#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run -q -p agentbox-cli --)
AGENT_NAME="${AGENTBOX_DEMO_AGENT:-hermes}"
WORKSPACE="${AGENTBOX_DEMO_WORKSPACE:-}"

log() {
  printf '\n==> %s\n' "$*"
}

if [[ -z "$WORKSPACE" ]]; then
  WORKSPACE="$(mktemp -d "${TMPDIR:-/tmp}/agentbox-agent-demo.XXXXXX")"
  cleanup_workspace=1
else
  cleanup_workspace=0
  mkdir -p "$WORKSPACE"
fi

cleanup() {
  if [[ "$cleanup_workspace" -eq 1 ]]; then
    rm -rf "$WORKSPACE"
  fi
}
trap cleanup EXIT

POLICY_BUNDLE="$WORKSPACE/agentbox.task-policy.json"
mkdir -p "$WORKSPACE/docs" "$WORKSPACE/secrets"
printf 'demo task notes\n' > "$WORKSPACE/docs/task.md"
printf 'placeholder-demo-token\n' > "$WORKSPACE/secrets/demo-token"

cat > "$POLICY_BUNDLE" <<'JSON'
{
  "schema_version": 1,
  "id": "demo-autonomous-agent",
  "description": "Demo policy bundle for OpenClaw/Hermes-style local agent work",
  "labels": {
    "demo": "autonomous-agent"
  },
  "allowed_domains": ["api.openai.com"],
  "denied_domains": ["metadata.google.internal"],
  "read_only_mounts": [],
  "credential_grants": [],
  "approval_grants": [],
  "protected_paths": []
}
JSON

log "Agentbox autonomous agent demo"
printf 'agent:     %s\n' "$AGENT_NAME"
printf 'workspace: %s\n' "$WORKSPACE"

log "generating governed minipod manifest"
"${CLI[@]}" minipod-spec "$AGENT_NAME" \
  --workspace "$WORKSPACE" \
  --agent-profile research \
  --network-mode first-contact \
  --allow-domain api.openai.com \
  --deny-domain metadata.google.internal \
  --deny-localhost \
  --mount-ro "$WORKSPACE/docs:/mnt/task-docs" \
  --credential-file "demo-token=$WORKSPACE/secrets/demo-token:/run/agentbox/secrets/demo-token" \
  --policy-bundle "$POLICY_BUNDLE"

log "showing provider honesty"
"${CLI[@]}" providers

cat <<'TEXT'

Demo interpretation:
- This does not require OpenClaw or Hermes to be installed.
- The manifest shape is the contract those agents should run under.
- Credential access is explicit, not inherited from the host environment.
- Unknown network contact requires approval; one high-risk metadata endpoint is denied.
- Native AgentPod providers still report unavailable until enforcement is proven.
TEXT
