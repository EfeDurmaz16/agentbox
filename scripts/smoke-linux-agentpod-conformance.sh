#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() {
  printf '\n==> %s\n' "$*"
}

cleanup_workspace=""
plan_json="$(mktemp)"
workspace="${AGENTBOX_LINUX_CONFORMANCE_WORKSPACE:-}"
if [[ -z "$workspace" ]]; then
  workspace="$(mktemp -d)"
  cleanup_workspace="$workspace"
fi
trap 'rm -rf "$cleanup_workspace" "$plan_json"' EXIT

command_string="${AGENTBOX_LINUX_CONFORMANCE_COMMAND:-/bin/true}"

log "checking Linux AgentPod native-plan conformance"
cargo run --locked -q -p agentbox-cli -- native-plan \
  --provider agentpod-linux \
  --workspace "$workspace" \
  -- $command_string >"$plan_json"

python3 - "$plan_json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    plan = json.load(fh)

assert plan["provider"] == "agentpod-linux"
assert plan["live_env_var"] == "AGENTBOX_LINUX_NATIVE"
assert plan["live_execution_enabled"] is False
assert plan["mount_namespace"]["workspace_bind_mount_wired"] is True
assert plan["landlock"]["handled_access_mask"] == 447
assert plan["network_enforcement"]["env_var"] == "AGENTBOX_LINUX_NETWORK_GUARD"
assert plan["nftables"]["live_gate"]["env_var"] == "AGENTBOX_LINUX_NFTABLES"
assert any(
    phase["name"] == "bind-workspace"
    and phase["status"] == "prototype"
    and phase["evidence_event"] == "agentpod.linux.runner.workspace.mounted"
    for phase in plan["runner_phases"]
)
assert any(
    phase["name"] == "apply-landlock"
    and phase["status"] == "prototype"
    for phase in plan["runner_phases"]
)
assert any(
    receipt["event_type"] == "linux.process.exec"
    and receipt["status"] == "descriptor-only-or-unobserved"
    and receipt["enforcement"] == "observed-only"
    for receipt in plan["ebpf"]["receipts"]
)
PY

log "checking Linux native smoke syntax"
bash -n scripts/smoke-linux-native.sh

log "Linux AgentPod live smoke command"
printf '%s\n' 'AGENTBOX_LINUX_NATIVE=1 bash scripts/smoke-linux-native.sh'

if [[ "${AGENTBOX_LINUX_NATIVE_CONFORMANCE_LIVE:-0}" == "1" ]]; then
  log "running gated Linux native smoke"
  AGENTBOX_LINUX_NATIVE=1 \
    AGENTBOX_LINUX_NATIVE_WORKSPACE="$workspace" \
    AGENTBOX_LINUX_NATIVE_COMMAND="$command_string" \
    bash scripts/smoke-linux-native.sh
else
  log "skipping live Linux native smoke"
  printf '%s\n' \
    "set AGENTBOX_LINUX_NATIVE_CONFORMANCE_LIVE=1 to run the live gate on a Linux host with unshare, Landlock, delegated cgroups v2, and overlayfs"
fi

log "Linux AgentPod conformance target passed"
