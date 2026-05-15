#!/usr/bin/env bash
set -euo pipefail

skip() {
  printf 'SKIP: %s\n' "$*" >&2
  exit 77
}

if [[ "$(uname -s)" != "Linux" ]]; then
  skip "Linux native AgentPod smoke must run on Linux"
fi

if ! command -v unshare >/dev/null 2>&1; then
  skip "unshare is required for the Linux native AgentPod smoke"
fi

if ! command -v jq >/dev/null 2>&1; then
  skip "jq is required for the Linux native AgentPod smoke"
fi

if ! cargo run -q -p agentbox-cli -- doctor --json |
  jq -e '.checks[] | select(.name == "Linux Landlock ABI" and .ok == true)' >/dev/null; then
  skip "Linux Landlock ABI is required for the Linux native AgentPod smoke"
fi

if ! cargo run -q -p agentbox-cli -- doctor --json |
  jq -e '.checks[] | select(.name == "Linux cgroups v2" and .ok == true)' >/dev/null; then
  skip "writable/delegated Linux cgroups v2 root is required for the Linux native AgentPod smoke"
fi

workspace="${AGENTBOX_LINUX_NATIVE_WORKSPACE:-$(mktemp -d)}"
command_string="${AGENTBOX_LINUX_NATIVE_COMMAND:-/bin/true}"
timeout_seconds="${AGENTBOX_LINUX_NATIVE_TIMEOUT_SECONDS:-30}"

echo "workspace=$workspace"
echo "command=$command_string"
echo "timeout_seconds=$timeout_seconds"

cargo run -q -p agentbox-cli -- native-plan \
  --provider agentpod-linux \
  --workspace "$workspace" \
  -- $command_string |
  jq -e '
    .provider == "agentpod-linux"
    and .live_env_var == "AGENTBOX_LINUX_NATIVE"
    and .landlock.handled_access_mask == 434
    and .security_claim == "prototype namespace/resource execution with cgroup v2 process attach; not a complete sandbox"
  ' >/dev/null

(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --timeout-seconds "$timeout_seconds" \
    -- $command_string
)

proof_outside="$(mktemp -d)"
trap 'rm -rf "$proof_outside"' EXIT
proof_allowed="$workspace/agentbox-landlock-allowed"
proof_denied="$proof_outside/agentbox-landlock-denied"
rm -f "$proof_allowed" "$proof_denied"

set +e
proof_output="$(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --timeout-seconds "$timeout_seconds" \
    -- /bin/sh -c 'printf ok > "$1"; printf no > "$2"' sh "$proof_allowed" "$proof_denied" 2>&1
)"
proof_status=$?
set -e

if [[ "$proof_status" -eq 0 ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to fail on outside-workspace write" >&2
  exit 1
fi
if [[ "$(cat "$proof_allowed")" != "ok" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to write inside workspace" >&2
  exit 1
fi
if [[ -e "$proof_denied" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to deny outside-workspace write" >&2
  exit 1
fi

echo "linux native AgentPod smoke passed"
