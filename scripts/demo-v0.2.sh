#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARTIFACT_DIR="${AGENTBOX_DEMO_ARTIFACT_DIR:-target/agentbox-v02-demo}"
mkdir -p "$ARTIFACT_DIR"

CLI=(${AGENTBOX_DEMO_CLI:-cargo run -q -p agentbox-cli --})

log() {
  printf '\n==> %s\n' "$*"
}

validate_json() {
  local path="$1"
  local expression="$2"
  python3 - "$path" "$expression" <<'PY'
import json
import sys

path, expression = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

safe_globals = {"__builtins__": {}, "all": all, "any": any, "len": len}
if not eval(expression, safe_globals, {"data": data}):
    raise SystemExit(f"JSON contract failed for {path}: {expression}")
PY
}

log "provider support levels"
"${CLI[@]}" providers --json >"$ARTIFACT_DIR/providers.json"
validate_json "$ARTIFACT_DIR/providers.json" \
  "any(p.get('provider') == 'direct-host' and p.get('status') == 'shipped' for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('status') == 'experimental' for p in data) and any(p.get('provider') == 'agentpod-macos' and p.get('status') == 'descriptor-only' for p in data)"

log "provider bridge readiness"
"${CLI[@]}" bridge-health --json >"$ARTIFACT_DIR/bridge-health.json"
validate_json "$ARTIFACT_DIR/bridge-health.json" \
  "any(p.get('provider') == 'direct-host' and p.get('readiness', {}).get('verdict') == 'active-command-mediation' for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('readiness', {}).get('verdict') == 'endpoint-gated' for p in data) and any(p.get('provider') == 'agentpod-macos' and p.get('readiness', {}).get('verdict') == 'metadata-only' for p in data)"

log "guided setup without mutation"
"${CLI[@]}" setup --dry-run --wizard --json >"$ARTIFACT_DIR/setup-wizard.json"
validate_json "$ARTIFACT_DIR/setup-wizard.json" \
  "data.get('schema_version') == 1 and data.get('dry_run') == True and data.get('wizard') == True and any(step.get('title') == 'Verify readiness' for step in data.get('wizard_steps', []))"

log "AgentPod high-risk plan without execution"
"${CLI[@]}" run --plan --risk high --workspace-mode overlay-review --json -- echo demo >"$ARTIFACT_DIR/run-plan.json"
validate_json "$ARTIFACT_DIR/run-plan.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name', '').startswith('agentpod-') and data.get('manifest', {}).get('workspace_mode') == 'OverlayReview' and any('not generally runnable' in warning for warning in data.get('warnings', []))"

log "general-agent manifest"
"${CLI[@]}" minipod-spec hermes \
  --workspace . \
  --agent-profile research \
  --network-mode first-contact \
  --allow-domain api.openai.com \
  --workspace-mode overlay-review >"$ARTIFACT_DIR/manifest.json"
validate_json "$ARTIFACT_DIR/manifest.json" \
  "data.get('kind') == 'AgentPod' and data.get('agent', {}).get('name') == 'hermes' and data.get('workspace_mode') == 'OverlayReview' and data.get('network', {}).get('mode') == 'ApprovalOnFirstContact'"

log "session listing UX"
"${CLI[@]}" sessions --json >"$ARTIFACT_DIR/sessions.json"
validate_json "$ARTIFACT_DIR/sessions.json" \
  "data == [] or all(item.get('id') and item.get('provider') for item in data)"

log "release signing placeholder when artifacts exist"
SIGNING_JSON="${AGENTBOX_RELEASE_ARTIFACT_DIR:-target/agentbox-release-readiness}/signing.json"
if [[ -f "$SIGNING_JSON" ]]; then
  validate_json "$SIGNING_JSON" \
    "data.get('schema_version') == 1 and data.get('signed') == False and data.get('status') == 'unsigned-placeholder'"
else
  printf 'signing artifact not found at %s; run scripts/release-readiness.sh before public demo.\n' "$SIGNING_JSON"
fi

log "v0.2 demo contract passed"
printf 'artifacts: %s\n' "$ARTIFACT_DIR"
