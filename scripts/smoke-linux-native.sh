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

workspace="${AGENTBOX_LINUX_NATIVE_WORKSPACE:-$(mktemp -d)}"
command_string="${AGENTBOX_LINUX_NATIVE_COMMAND:-/bin/true}"

echo "workspace=$workspace"
echo "command=$command_string"

cargo run -q -p agentbox-cli -- native-plan \
  --provider agentpod-linux \
  --workspace "$workspace" \
  -- $command_string |
  jq -e '
    .provider == "agentpod-linux"
    and .live_env_var == "AGENTBOX_LINUX_NATIVE"
    and .security_claim == "prototype namespace/resource execution plan; not a complete sandbox"
  ' >/dev/null

(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    -- $command_string
)

echo "linux native AgentPod smoke passed"
