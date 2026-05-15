#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CLI=(cargo run --locked -q -p agentbox-cli --)
REMOTE_WORKER=(cargo run --locked -q -p agentbox-remote-worker --)
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() {
  printf '\n==> %s\n' "$*"
}

validate_json() {
  local file="$1"
  local expression="$2"
  python3 - "$file" "$expression" <<'PY'
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

log "checking provider truth JSON"
"${CLI[@]}" providers --json >"$TMPDIR/providers.json"
validate_json "$TMPDIR/providers.json" \
  "any(p.get('provider') == 'direct-host' and p.get('status') == 'shipped' and p.get('doctor_check') == 'daemon socket' and 'path-shim' in p.get('boundary_primitives', []) and p.get('network') == 'command-mediation' and any(s.get('primitive') == 'path-shim' and s.get('status') == 'shipped' and s.get('active') == True for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'podman' and p.get('setup_command') and p.get('verification_command') and any(s.get('primitive') == 'guest-shim' and s.get('requires_gate') for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('status') == 'experimental' and p.get('setup_command') and p.get('doctor_check') == 'remote-agentpod endpoint' for p in data) and any(p.get('provider') == 'agentpod-windows' and 'job-objects' in p.get('boundary_primitives', []) and 'wfp' in p.get('boundary_primitives', []) and 'windows-sandbox' in p.get('boundary_primitives', []) and 'hyper-v' in p.get('boundary_primitives', []) and any(s.get('primitive') == 'job-objects' and s.get('status') == 'descriptor-only' and s.get('active') == False and s.get('requires_gate') == 'AGENTBOX_WINDOWS_NATIVE=1' for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'agentpod-linux' and 'user-namespaces' in p.get('boundary_primitives', []) and 'seccomp' in p.get('boundary_primitives', []) and p.get('verification_command') and any(s.get('primitive') == 'seccomp' and s.get('status') == 'prototype' and s.get('active') == False and s.get('requires_gate') == 'AGENTBOX_LINUX_NATIVE=1' for s in p.get('boundary_primitive_statuses', [])) for p in data) and any(p.get('provider') == 'agentpod-macos' and any(s.get('primitive') == 'apple-virtualization' and s.get('status') == 'descriptor-only' and s.get('active') == False and s.get('requires_gate') == 'AGENTBOX_MACOS_NATIVE=1' for s in p.get('boundary_primitive_statuses', [])) for p in data)"

log "checking bridge health readiness JSON"
"${CLI[@]}" bridge-health --json >"$TMPDIR/bridge-health.json"
validate_json "$TMPDIR/bridge-health.json" \
  "all(p.get('bridge_health') and p.get('readiness') for p in data) and any(p.get('provider') == 'direct-host' and p.get('readiness', {}).get('verdict') == 'active-command-mediation' and p.get('bridge_health', {}).get('policy', {}).get('active') == True for p in data) and any(p.get('provider') == 'remote-agentpod' and p.get('readiness', {}).get('verdict') == 'endpoint-gated' and p.get('bridge_health', {}).get('approval', {}).get('supported') == True for p in data)"
"${CLI[@]}" bridge-health --provider agentpod-macos --json >"$TMPDIR/bridge-health-macos.json"
validate_json "$TMPDIR/bridge-health-macos.json" \
  "len(data) == 1 and data[0].get('provider') == 'agentpod-macos' and data[0].get('readiness', {}).get('verdict') == 'metadata-only' and 'execution is not wired' in data[0].get('readiness', {}).get('claim_boundary', '')"

log "checking daemon cleanup command surface"
"${CLI[@]}" clean --help >"$TMPDIR/clean-help.txt"
grep -F "Remove stale daemon pid and socket files" "$TMPDIR/clean-help.txt" >/dev/null

log "checking network explain guardrails"
"${CLI[@]}" network-explain \
  http://169.254.169.254/latest/meta-data/ \
  --mode open-with-guardrails >"$TMPDIR/network-explain-metadata.txt"
grep -F "bucket:   block" "$TMPDIR/network-explain-metadata.txt" >/dev/null
grep -F "metadata endpoint" "$TMPDIR/network-explain-metadata.txt" >/dev/null
"${CLI[@]}" network-explain \
  http://192.168.1.20/admin \
  --mode open-with-guardrails >"$TMPDIR/network-explain-private.txt"
grep -F "bucket:   approve" "$TMPDIR/network-explain-private.txt" >/dev/null
grep -F "private network destination" "$TMPDIR/network-explain-private.txt" >/dev/null

log "checking credential broker command surface"
"${CLI[@]}" credentials --help >"$TMPDIR/credentials-help.txt"
grep -F "List credential grants for an AgentPod session" \
  "$TMPDIR/credentials-help.txt" >/dev/null
grep -F "Emit JSON" "$TMPDIR/credentials-help.txt" >/dev/null
"${CLI[@]}" credential-revoke --help >"$TMPDIR/credential-revoke-help.txt"
grep -F "Revoke a credential grant from an AgentPod session" \
  "$TMPDIR/credential-revoke-help.txt" >/dev/null
"${CLI[@]}" evidence --help >"$TMPDIR/evidence-help.txt"
grep -F "Export only session credential grants/events as JSONL" \
  "$TMPDIR/evidence-help.txt" >/dev/null

log "checking doctor JSON truth"
set +e
"${CLI[@]}" doctor --json >"$TMPDIR/doctor.json"
doctor_status=$?
set -e
validate_json "$TMPDIR/doctor.json" \
  "data.get('schema_version') == 1 and data.get('checks') is not None and data.get('ok', 0) + data.get('failed', 0) == len(data.get('checks', [])) and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and any(c.get('name') == 'agentbox-shim binary' and c.get('severity') == 'required' and c.get('release_blocker') == (not c.get('ok')) for c in data.get('checks', [])) and any(c.get('name') == 'remote-agentpod endpoint' and c.get('severity') == 'advisory' for c in data.get('checks', []))"
if [ "$doctor_status" -ne 0 ]; then
  validate_json "$TMPDIR/doctor.json" "data.get('required_failed', 0) > 0"
fi

log "checking setup plan JSON truth"
"${CLI[@]}" setup-plan --json >"$TMPDIR/setup-plan.json"
validate_json "$TMPDIR/setup-plan.json" \
  "data.get('schema_version') == 1 and data.get('required_failed', 0) + data.get('advisory_failed', 0) == data.get('failed', 0) and data.get('steps') is not None and all(step.get('severity') in ['required', 'advisory'] for step in data.get('steps', []))"
"${CLI[@]}" setup-plan --provider remote-agentpod --json >"$TMPDIR/setup-plan-remote.json"
validate_json "$TMPDIR/setup-plan-remote.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'remote-agentpod' and all(step.get('check') == 'remote-agentpod endpoint' for step in data.get('steps', []))"
"${CLI[@]}" setup-plan --provider direct-host --json >"$TMPDIR/setup-plan-direct-host.json"
validate_json "$TMPDIR/setup-plan-direct-host.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'direct-host' and all(step.get('check') in ['agentbox directory', 'config file', 'daemon process', 'daemon socket', 'agentbox-daemon binary', 'agentbox-shim binary', 'installed shims', 'shim PATH priority', 'audit database'] for step in data.get('steps', []))"
"${CLI[@]}" setup --dry-run --provider remote-agentpod --json >"$TMPDIR/setup-dry-run-remote.json"
validate_json "$TMPDIR/setup-dry-run-remote.json" \
  "data.get('schema_version') == 1 and data.get('dry_run') == True and data.get('provider') == 'remote-agentpod' and data.get('shims') is None and data.get('setup_plan', {}).get('provider') == 'remote-agentpod' and 'agentbox bridge-health --provider remote-agentpod' in data.get('operator_commands', []) and 'export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://worker.example.com/agentpod' in data.get('operator_commands', [])"
"${CLI[@]}" setup --dry-run --provider remote-agentpod --endpoint https://agentpod.example.com/run --json >"$TMPDIR/setup-dry-run-remote-endpoint.json"
validate_json "$TMPDIR/setup-dry-run-remote-endpoint.json" \
  "data.get('remote_endpoint') == 'https://agentpod.example.com/run' and 'export AGENTBOX_REMOTE_AGENTPOD_ENDPOINT=https://agentpod.example.com/run' in data.get('operator_commands', []) and 'agentbox remote-handshake --endpoint https://agentpod.example.com/run' in data.get('operator_commands', [])"
"${CLI[@]}" setup --dry-run --provider direct-host --json >"$TMPDIR/setup-dry-run-direct-host.json"
validate_json "$TMPDIR/setup-dry-run-direct-host.json" \
  "data.get('schema_version') == 1 and data.get('dry_run') == True and data.get('provider') == 'direct-host' and data.get('remote_endpoint') is None and data.get('setup_plan', {}).get('provider') == 'direct-host' and 'agentbox bridge-health --provider direct-host' in data.get('operator_commands', []) and any('agentbox start' in command for command in data.get('operator_commands', []))"
"${CLI[@]}" setup --dry-run --wizard --provider direct-host --json >"$TMPDIR/setup-wizard-direct-host.json"
validate_json "$TMPDIR/setup-wizard-direct-host.json" \
  "data.get('schema_version') == 1 and data.get('wizard') == True and data.get('dry_run') == True and any(step.get('title') == 'Install local command shims' and step.get('command') == 'agentbox setup --provider direct-host' for step in data.get('wizard_steps', [])) and any(step.get('title') == 'Inspect provider bridge readiness' and step.get('command') == 'agentbox bridge-health --provider direct-host' for step in data.get('wizard_steps', [])) and any(step.get('title') == 'Verify readiness' and step.get('command') == 'agentbox doctor' for step in data.get('wizard_steps', []))"

log "checking pods JSON truth"
"${CLI[@]}" pods --json >"$TMPDIR/pods.json"
validate_json "$TMPDIR/pods.json" \
  "data == [] or all(item.get('id') and item.get('provider') for item in data)"
"${CLI[@]}" sessions --json >"$TMPDIR/sessions.json"
validate_json "$TMPDIR/sessions.json" \
  "data == [] or all(item.get('id') and item.get('provider') for item in data)"
"${CLI[@]}" sessions --help >"$TMPDIR/sessions-help.txt"
grep -F "List persisted AgentPod sessions" "$TMPDIR/sessions-help.txt" >/dev/null

log "checking AgentPod run plan JSON"
"${CLI[@]}" run --plan --json -- echo agentbox-contract >"$TMPDIR/run-plan.json"
validate_json "$TMPDIR/run-plan.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('availability_check') == 'not performed by --plan' and data.get('manifest', {}).get('kind') == 'AgentPod' and len(data.get('backend_actions', [])) >= 3"
"${CLI[@]}" run --plan --risk low --json -- echo agentbox-contract >"$TMPDIR/run-plan-low.json"
validate_json "$TMPDIR/run-plan-low.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name') == 'direct-host' and all('not generally runnable' not in warning for warning in data.get('warnings', []))"
"${CLI[@]}" run --provider direct-host --risk low --json -- echo agentbox-contract >"$TMPDIR/run-direct-host.json"
validate_json "$TMPDIR/run-direct-host.json" \
  "data.get('schema_version') == 1 and data.get('session', {}).get('provider') == 'direct-host' and data.get('command_result', {}).get('stdout') == 'agentbox-contract\n' and data.get('destroyed') == True"
DIRECT_OVERLAY_WORKSPACE="$TMPDIR/direct-host-overlay-workspace"
mkdir -p "$DIRECT_OVERLAY_WORKSPACE"
printf 'lower\n' >"$DIRECT_OVERLAY_WORKSPACE/README.md"
(
  cd "$DIRECT_OVERLAY_WORKSPACE"
  cargo run --locked --manifest-path "$ROOT/Cargo.toml" -q -p agentbox-cli -- run --provider direct-host --risk medium --workspace-mode overlay-review --json -- sh -c 'printf overlay > created.txt' >"$TMPDIR/run-direct-host-overlay.json"
)
validate_json "$TMPDIR/run-direct-host-overlay.json" \
  "data.get('schema_version') == 1 and data.get('session', {}).get('provider') == 'direct-host' and data.get('session', {}).get('spec', {}).get('workspace_mode') == 'OverlayReview' and data.get('command_result', {}).get('exit_code') == 0 and data.get('destroyed') == True and any('review-discard' in command for command in data.get('review_commands', []))"
test ! -e "$DIRECT_OVERLAY_WORKSPACE/created.txt"
DIRECT_OVERLAY_SESSION="$(python3 - "$TMPDIR/run-direct-host-overlay.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    print(json.load(fh)["session"]["id"])
PY
)"
"${CLI[@]}" review-discard "$DIRECT_OVERLAY_SESSION" >"$TMPDIR/direct-host-overlay-discard.txt"
grep -F "Discarded projected workspace output." "$TMPDIR/direct-host-overlay-discard.txt" >/dev/null

log "checking workspace review mode manifests"
"${CLI[@]}" minipod-spec codex \
  --workspace "$TMPDIR" \
  --workspace-mode overlay-review >"$TMPDIR/minipod-overlay-review.json"
validate_json "$TMPDIR/minipod-overlay-review.json" \
  "data.get('kind') == 'AgentPod' and data.get('workspace_mode') == 'OverlayReview' and data.get('filesystem', {}).get('workspace_write_policy') == 'WritableOverlay' and data.get('filesystem', {}).get('workspace_overlay', {}).get('mode') == 'ReviewRequired' and data.get('filesystem', {}).get('workspace_overlay', {}).get('upper_host_path') and data.get('filesystem', {}).get('workspace_overlay', {}).get('work_host_path')"
"${CLI[@]}" minipod-spec codex \
  --workspace "$TMPDIR" \
  --workspace-mode ephemeral >"$TMPDIR/minipod-ephemeral.json"
validate_json "$TMPDIR/minipod-ephemeral.json" \
  "data.get('workspace_mode') == 'Ephemeral' and data.get('filesystem', {}).get('workspace_write_policy') == 'WritableOverlay' and data.get('filesystem', {}).get('workspace_overlay', {}).get('mode') == 'DiscardOnDestroy'"
"${CLI[@]}" minipod-spec codex \
  --workspace "$TMPDIR" \
  --workspace-mode commit-gated >"$TMPDIR/minipod-commit-gated.json"
validate_json "$TMPDIR/minipod-commit-gated.json" \
  "data.get('workspace_mode') == 'CommitGated' and data.get('filesystem', {}).get('workspace_write_policy') == 'WritableOverlay' and data.get('filesystem', {}).get('workspace_overlay', {}).get('mode') == 'ReviewRequired'"

log "checking native plan auto provider truth"
"${CLI[@]}" native-plan \
  --workspace "$TMPDIR" \
  -- /bin/true >"$TMPDIR/native-plan-auto.json"
validate_json "$TMPDIR/native-plan-auto.json" \
  "data.get('schema_version') == 1 and data.get('provider') in ['agentpod-linux', 'agentpod-macos', 'agentpod-windows'] and data.get('live_execution_enabled') == False and data.get('security_claim')"

log "checking high-risk provider recommendation truth"
"${CLI[@]}" run --plan --risk high --json -- echo agentbox-contract >"$TMPDIR/run-plan-high.json"
validate_json "$TMPDIR/run-plan-high.json" \
  "data.get('schema_version') == 1 and data.get('selected_provider', {}).get('name', '').startswith('agentpod-') and len(data.get('selected_provider', {}).get('boundary_primitives', [])) >= 1 and any(s.get('active') == False and s.get('requires_gate') and s.get('enforcement_scope') for s in data.get('selected_provider', {}).get('boundary_primitive_statuses', [])) and any('not generally runnable' in warning for warning in data.get('warnings', []))"

log "checking macOS native plan compiler truth"
AGENTBOX_MACOS_NATIVE= "${CLI[@]}" native-plan \
  --provider agentpod-macos \
  --workspace "$TMPDIR" \
  -- /bin/true >"$TMPDIR/native-plan-macos.json"
validate_json "$TMPDIR/native-plan-macos.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'agentpod-macos' and data.get('virtualization', {}).get('requires_apple_virtualization') == True and data.get('endpoint_security', {}).get('requires_system_extension') == True and data.get('network_extension', {}).get('requires_network_extension') == True and data.get('live_env_var') == 'AGENTBOX_MACOS_NATIVE' and data.get('live_execution_enabled') == False and 'execution is not wired' in data.get('security_claim', '')"

log "checking Windows native plan compiler truth"
AGENTBOX_WINDOWS_NATIVE= "${CLI[@]}" native-plan \
  --provider agentpod-windows \
  --workspace "$TMPDIR" \
  -- codex exec >"$TMPDIR/native-plan-windows.json"
validate_json "$TMPDIR/native-plan-windows.json" \
  "data.get('schema_version') == 1 and data.get('provider') == 'agentpod-windows' and data.get('job_object', {}).get('kill_on_close') == True and data.get('job_object', {}).get('process_limit', 0) > 0 and 'live Win32 apply proof' in data.get('job_object', {}).get('resource_claim', '') and data.get('app_container', {}).get('requires_profile_creation') == True and data.get('app_container', {}).get('workspace_mode') == 'overlay-review' and data.get('app_container', {}).get('workspace_boundary', {}).get('review_required') == True and 'live ACL proof is not wired' in data.get('app_container', {}).get('workspace_boundary', {}).get('enforcement_claim', '') and data.get('wfp', {}).get('requires_wfp') == True and any('private-lan' in rule.get('selector', '') for rule in data.get('wfp', {}).get('planned_rules', [])) and 'windows.wfp.flow.block' in data.get('wfp', {}).get('evidence_events', []) and 'no packet/domain denial proof' in data.get('wfp', {}).get('enforcement_claim', '') and data.get('etw', {}).get('requires_etw') == True and 'windows-etw-events.jsonl' in data.get('etw', {}).get('evidence_export', {}).get('bundle_files', []) and 'live ETW capture/export is not wired' in data.get('etw', {}).get('evidence_export', {}).get('export_claim', '') and 'windows-sandbox' in data.get('vm_boundary', {}).get('candidate_backends', []) and data.get('vm_boundary', {}).get('cell_config', {}).get('workspace_mount', {}).get('review_required') == True and data.get('vm_boundary', {}).get('cell_config', {}).get('host_bridge', {}).get('policy_endpoint') == 'agentbox.policy.v1.Decide' and data.get('live_env_var') == 'AGENTBOX_WINDOWS_NATIVE' and data.get('live_execution_enabled') == False and 'execution is not wired' in data.get('security_claim', '')"

log "checking remote descriptor JSON"
"${CLI[@]}" remote-descriptor \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --evidence bundle-upload >"$TMPDIR/remote-descriptor.json"
validate_json "$TMPDIR/remote-descriptor.json" \
  "data.get('provider') == 'remote-agentpod' and data.get('endpoint') == 'https://worker.example.com/agentpod' and data.get('auth_kind') == 'SignedChallenge' and data.get('evidence_mode') == 'BundleUpload' and data.get('secret_material_included') == False and data.get('lifecycle', {}).get('heartbeat_interval_seconds') == 30 and data.get('lifecycle', {}).get('restart_policy', {}).get('strategy') == 'OnFailure'"

log "checking remote handshake JSON"
"${CLI[@]}" remote-handshake \
  --endpoint https://worker.example.com/agentpod \
  --auth signed-challenge \
  --ttl-seconds 120 >"$TMPDIR/remote-handshake.json"
validate_json "$TMPDIR/remote-handshake.json" \
  "data.get('provider') == 'remote-agentpod' and data.get('auth_kind') == 'SignedChallenge' and data.get('challenge_id') and data.get('challenge_nonce_sha256') and data.get('secret_material_included') == False"

log "checking remote evidence metadata JSON"
"${CLI[@]}" remote-evidence \
  --session abx-session-1 \
  --worker-session worker-session-1 \
  --evidence bundle-upload \
  --bundle-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --event-count 3 >"$TMPDIR/remote-evidence.json"
validate_json "$TMPDIR/remote-evidence.json" \
  "data.get('session_id') == 'abx-session-1' and data.get('worker_session_id') == 'worker-session-1' and data.get('event_count') == 3 and data.get('bundle_sha256', '').startswith('012345')"

log "checking remote evidence status command surface"
"${CLI[@]}" remote-evidence-status --help >"$TMPDIR/remote-evidence-status-help.txt"
grep -F "Query a remote AgentPod worker for accepted evidence state" \
  "$TMPDIR/remote-evidence-status-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-evidence-status-help.txt" >/dev/null
"${CLI[@]}" remote-restart --help >"$TMPDIR/remote-restart-help.txt"
grep -F "Restart a stopped or failed remote AgentPod worker session" \
  "$TMPDIR/remote-restart-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-restart-help.txt" >/dev/null
grep -F "Operator-visible restart reason" \
  "$TMPDIR/remote-restart-help.txt" >/dev/null
"${CLI[@]}" remote-worker-status --help >"$TMPDIR/remote-worker-status-help.txt"
grep -F "Query remote AgentPod worker supervision status" \
  "$TMPDIR/remote-worker-status-help.txt" >/dev/null
grep -F "omitted values can be read from --session" \
  "$TMPDIR/remote-worker-status-help.txt" >/dev/null
"${CLI[@]}" remote-approval-grant --help >"$TMPDIR/remote-approval-grant-help.txt"
grep -F "Grant a pending remote AgentPod command approval" \
  "$TMPDIR/remote-approval-grant-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-approval-grant-help.txt" >/dev/null
"${CLI[@]}" remote-evidence-upload --help >"$TMPDIR/remote-evidence-upload-help.txt"
grep -F "Upload a verified evidence bundle directory to a remote AgentPod worker" \
  "$TMPDIR/remote-evidence-upload-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-evidence-upload-help.txt" >/dev/null
"${CLI[@]}" remote-evidence-stream --help >"$TMPDIR/remote-evidence-stream-help.txt"
grep -F "Upload UTF-8 evidence stream chunks to a remote AgentPod worker" \
  "$TMPDIR/remote-evidence-stream-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-evidence-stream-help.txt" >/dev/null
"${CLI[@]}" remote-workspace-export --help >"$TMPDIR/remote-workspace-export-help.txt"
grep -F "Export a remote AgentPod worker workspace into a local review directory" \
  "$TMPDIR/remote-workspace-export-help.txt" >/dev/null
grep -F "omitted values are read from the local session when possible" \
  "$TMPDIR/remote-workspace-export-help.txt" >/dev/null
"${CLI[@]}" remote-workspace-apply --help >"$TMPDIR/remote-workspace-apply-help.txt"
grep -F "Apply a pulled remote AgentPod workspace export to a local workspace" \
  "$TMPDIR/remote-workspace-apply-help.txt" >/dev/null

log "checking workspace review command surface"
"${CLI[@]}" review --help >"$TMPDIR/review-help.txt"
grep -F "Review workspace output for an AgentPod session" \
  "$TMPDIR/review-help.txt" >/dev/null
grep -F "Emit only the workspace patch" "$TMPDIR/review-help.txt" >/dev/null
grep -F "Print a keyboard-style review command menu" \
  "$TMPDIR/review-help.txt" >/dev/null
"${CLI[@]}" review-apply --help >"$TMPDIR/review-apply-help.txt"
grep -F "Apply projected workspace output to the lower workspace" \
  "$TMPDIR/review-apply-help.txt" >/dev/null
"${CLI[@]}" review-discard --help >"$TMPDIR/review-discard-help.txt"
grep -F "Discard projected workspace output for an AgentPod session" \
  "$TMPDIR/review-discard-help.txt" >/dev/null
"${CLI[@]}" review-commit --help >"$TMPDIR/review-commit-help.txt"
grep -F "Apply projected workspace output and commit it in the lower workspace" \
  "$TMPDIR/review-commit-help.txt" >/dev/null
grep -F "Commit message for the lower workspace" \
  "$TMPDIR/review-commit-help.txt" >/dev/null

log "checking evidence bundle verification"
BUNDLE_DIR="$TMPDIR/evidence-bundle"
mkdir -p "$BUNDLE_DIR"
printf '{"schema_version":1,"kind":"AgentPod"}\n' >"$BUNDLE_DIR/manifest.json"
printf '{"schema_version":1,"commands":[{"audit_event_id":"evt_1"}],"approvals":[],"lifecycle_events":[],"boundary_events":[],"credential_events":[]}\n' >"$BUNDLE_DIR/bundle.json"
python3 - "$BUNDLE_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

bundle = pathlib.Path(sys.argv[1])
files = []
for path, description in [
    ("bundle.json", "smoke bundle"),
    ("manifest.json", "smoke manifest"),
]:
    data = (bundle / path).read_bytes()
    files.append(
        {
            "path": path,
            "media_type": "application/json",
            "description": description,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        }
    )
root_entries = [
    f"{entry['path']}\0{entry['sha256']}\0{entry['bytes']}\0{entry['media_type']}"
    for entry in sorted(files, key=lambda value: value["path"])
]
root_payload = ("agentbox-evidence-root-v1\n" + "\n".join(root_entries)).encode()
index = {
    "schema_version": 1,
    "bundle_id": "smoke-bundle",
    "session_id": "smoke-session",
    "provider": "direct-host",
    "status": "Stopped",
    "root_sha256": hashlib.sha256(root_payload).hexdigest(),
    "generated_at": "2026-05-14T00:00:00Z",
    "files": files,
}
(bundle / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
PY
"${CLI[@]}" evidence --verify --bundle "$BUNDLE_DIR"
"${CLI[@]}" remote-evidence \
  --session smoke-session \
  --worker-session smoke-worker-session \
  --bundle-dir "$BUNDLE_DIR" >"$TMPDIR/remote-evidence-from-bundle.json"
validate_json "$TMPDIR/remote-evidence-from-bundle.json" \
  "data.get('session_id') == 'smoke-session' and data.get('worker_session_id') == 'smoke-worker-session' and data.get('event_count') == 1 and len(data.get('bundle_sha256', '')) == 64 and data.get('derived_from_bundle') == True and data.get('bundle_id') == 'smoke-bundle' and data.get('bundle_root_sha256') == data.get('bundle_sha256')"
printf '{"tampered":true}\n' >"$BUNDLE_DIR/manifest.json"
if "${CLI[@]}" evidence --verify --bundle "$BUNDLE_DIR" >/tmp/agentbox-invalid-evidence-bundle.out 2>/tmp/agentbox-invalid-evidence-bundle.err; then
  echo "evidence bundle verification accepted tampered bundle" >&2
  exit 1
fi

log "checking remote evidence rejects invalid bundle digests"
if "${CLI[@]}" remote-evidence \
  --session abx-session-1 \
  --worker-session worker-session-1 \
  --evidence bundle-upload \
  --bundle-sha256 not-a-sha256 \
  --event-count 3 >/tmp/agentbox-invalid-remote-evidence.out 2>/tmp/agentbox-invalid-remote-evidence.err; then
  echo "remote-evidence accepted an invalid bundle digest" >&2
  exit 1
fi

log "checking remote worker binary contract"
"${REMOTE_WORKER[@]}" --help >/tmp/agentbox-remote-worker-help.out 2>/tmp/agentbox-remote-worker-help.err
if "${REMOTE_WORKER[@]}" >/tmp/agentbox-remote-worker-missing-key.out 2>/tmp/agentbox-remote-worker-missing-key.err; then
  echo "remote worker started without an explicit signing key" >&2
  exit 1
fi

log "CLI contract smoke passed"
