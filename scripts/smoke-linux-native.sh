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

if ! grep -qw overlay /proc/filesystems; then
  skip "overlayfs support is required for the Linux native AgentPod overlay-review smoke"
fi

workspace="${AGENTBOX_LINUX_NATIVE_WORKSPACE:-$(mktemp -d)}"
command_string="${AGENTBOX_LINUX_NATIVE_COMMAND:-/bin/true}"
timeout_seconds="${AGENTBOX_LINUX_NATIVE_TIMEOUT_SECONDS:-30}"
runner_binary="${AGENTBOX_LINUX_RUNNER:-$(pwd)/target/debug/agentbox-linux-runner}"

cargo build -q -p agentbox-daemon --bin agentbox-linux-runner
export AGENTBOX_LINUX_RUNNER="$runner_binary"

echo "workspace=$workspace"
echo "command=$command_string"
echo "timeout_seconds=$timeout_seconds"
echo "runner=$AGENTBOX_LINUX_RUNNER"

cargo run -q -p agentbox-cli -- native-plan \
  --provider agentpod-linux \
  --workspace "$workspace" \
  -- $command_string |
  jq -e '
    .provider == "agentpod-linux"
    and .live_env_var == "AGENTBOX_LINUX_NATIVE"
    and .landlock.handled_access_mask == 434
    and .mount_namespace.workspace_bind_mount_wired == true
    and (.mount_namespace.workspace_mount_claim | contains("agentbox-linux-runner"))
    and any(.runner_phases[]; .name == "bind-workspace" and .status == "prototype")
    and any(.runner_phases[]; .name == "apply-landlock" and .status == "prototype")
    and (.security_claim | contains("runner-managed workspace mount"))
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
parallel_root=""
trap 'rm -rf "$proof_outside" "$parallel_root"' EXIT
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

set +e
cgroup_output="$(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --max-processes 16 \
    --timeout-seconds "$timeout_seconds" \
    -- /bin/sh -c '
      printf "self_cgroup:%s\n" "$(cat /proc/self/cgroup)"
      spawned=0
      while [ "$spawned" -lt 64 ]; do
        sleep 30 &
        child=$!
        if ! kill -0 "$child" 2>/dev/null; then
          break
        fi
        spawned=$((spawned + 1))
      done
      printf "spawned:%s\n" "$spawned"
      jobs -p | while read -r pid; do
        kill "$pid" 2>/dev/null || true
      done
      [ "$spawned" -lt 64 ]
    ' 2>&1
)"
cgroup_status=$?
set -e

if [[ "$cgroup_status" -ne 0 ]]; then
  printf '%s\n' "$cgroup_output" >&2
  echo "expected Linux cgroups v2 pids.max smoke to prove process limit enforcement" >&2
  exit 1
fi
if ! grep -q 'self_cgroup:.*agentbox-' <<<"$cgroup_output"; then
  printf '%s\n' "$cgroup_output" >&2
  echo "expected Linux cgroups v2 smoke to run inside an agentbox cgroup" >&2
  exit 1
fi
spawned_count="$(sed -n 's/^spawned://p' <<<"$cgroup_output" | tail -n 1)"
if [[ -z "$spawned_count" || "$spawned_count" -ge 64 ]]; then
  printf '%s\n' "$cgroup_output" >&2
  echo "expected Linux cgroups v2 pids.max to prevent spawning all probe processes" >&2
  exit 1
fi

overlay_workspace="$(mktemp -d)"
overlay_base="$(mktemp -d)"
trap 'rm -rf "$proof_outside" "$parallel_root" "$overlay_workspace" "$overlay_base"' EXIT
printf 'base\n' >"$overlay_workspace/base.txt"

set +e
overlay_output="$(
  cd "$overlay_workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode overlay-review \
    --workspace-overlay-dir "$overlay_base" \
    --timeout-seconds "$timeout_seconds" \
    -- /bin/sh -c 'printf overlay > created.txt; printf changed > base.txt' 2>&1
)"
overlay_status=$?
set -e

if [[ "$overlay_status" -ne 0 ]]; then
  printf '%s\n' "$overlay_output" >&2
  echo "expected Linux overlay-review AgentPod command to complete" >&2
  exit 1
fi
if [[ "$(cat "$overlay_workspace/base.txt")" != "base" ]]; then
  printf '%s\n' "$overlay_output" >&2
  echo "expected overlay-review run to leave lower workspace file unchanged" >&2
  exit 1
fi
if [[ -e "$overlay_workspace/created.txt" ]]; then
  printf '%s\n' "$overlay_output" >&2
  echo "expected overlay-review run not to write created file into lower workspace" >&2
  exit 1
fi
if [[ "$(cat "$overlay_base/upper/base.txt")" != "changed" ]]; then
  printf '%s\n' "$overlay_output" >&2
  find "$overlay_base" -maxdepth 3 -type f -print >&2
  echo "expected overlay upper layer to capture modified workspace file" >&2
  exit 1
fi
if [[ "$(cat "$overlay_base/upper/created.txt")" != "overlay" ]]; then
  printf '%s\n' "$overlay_output" >&2
  find "$overlay_base" -maxdepth 3 -type f -print >&2
  echo "expected overlay upper layer to capture created workspace file" >&2
  exit 1
fi

parallel_root="$(mktemp -d)"
parallel_left="$parallel_root/left"
parallel_right="$parallel_root/right"
request_dir="${TMPDIR:-/tmp}/agentbox-linux-runner"
mkdir -p "$parallel_left" "$parallel_right" "$request_dir"
request_count_before="$(find "$request_dir" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"

run_parallel_agentpod() {
  local label="$1"
  local dir="$2"
  (
    cd "$dir"
    printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
      --provider agentpod-linux \
      --workspace-mode direct \
      --timeout-seconds "$timeout_seconds" \
      -- /bin/sh -c 'printf "%s\n" "$1" > "$2"; sleep 1' sh "$label" "$dir/agentbox-parallel-proof"
  ) >"$dir/run.log" 2>&1
}

run_parallel_agentpod left "$parallel_left" &
left_pid=$!
run_parallel_agentpod right "$parallel_right" &
right_pid=$!

left_status=0
right_status=0
wait "$left_pid" || left_status=$?
wait "$right_pid" || right_status=$?

if [[ "$left_status" -ne 0 || "$right_status" -ne 0 ]]; then
  cat "$parallel_left/run.log" "$parallel_right/run.log" >&2
  echo "expected parallel Linux native AgentPod commands to both complete" >&2
  exit 1
fi
if [[ "$(cat "$parallel_left/agentbox-parallel-proof")" != "left" ]]; then
  cat "$parallel_left/run.log" >&2
  echo "expected left parallel AgentPod command to write its own workspace proof" >&2
  exit 1
fi
if [[ "$(cat "$parallel_right/agentbox-parallel-proof")" != "right" ]]; then
  cat "$parallel_right/run.log" >&2
  echo "expected right parallel AgentPod command to write its own workspace proof" >&2
  exit 1
fi

request_count_after="$(find "$request_dir" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"
if [[ "$request_count_after" != "$request_count_before" ]]; then
  find "$request_dir" -maxdepth 1 -type f -name '*.json' -print >&2
  echo "expected Linux runner request files to be cleaned after parallel exec" >&2
  exit 1
fi

echo "linux native AgentPod smoke passed"
