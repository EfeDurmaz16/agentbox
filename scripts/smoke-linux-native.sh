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
seccomp_profile="$(mktemp)"
plan_json="$(mktemp)"
trap 'rm -f "$seccomp_profile" "$plan_json"' EXIT

case "$(uname -m)" in
  x86_64 | amd64)
    seccomp_arch="SCMP_ARCH_X86_64"
    ;;
  arm64 | aarch64)
    seccomp_arch="SCMP_ARCH_AARCH64"
    ;;
  arm | armv7l)
    seccomp_arch="SCMP_ARCH_ARM"
    ;;
  i386 | i686)
    seccomp_arch="SCMP_ARCH_X86"
    ;;
  *)
    seccomp_arch="SCMP_ARCH_NATIVE"
    ;;
esac

cat >"$seccomp_profile" <<EOF
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["$seccomp_arch"],
  "syscalls": [
    {
      "names": ["kill"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "comment": "block signal fanout from imported OCI/libseccomp profile"
    }
  ]
}
EOF

cargo build -q -p agentbox-daemon --bin agentbox-linux-runner
export AGENTBOX_LINUX_RUNNER="$runner_binary"

echo "workspace=$workspace"
echo "command=$command_string"
echo "timeout_seconds=$timeout_seconds"
echo "runner=$AGENTBOX_LINUX_RUNNER"

cargo run -q -p agentbox-cli -- native-plan \
  --provider agentpod-linux \
  --workspace "$workspace" \
  -- $command_string >"$plan_json"

jq -e '
    .provider == "agentpod-linux"
    and .live_env_var == "AGENTBOX_LINUX_NATIVE"
    and .landlock.handled_access_mask == .landlock.abi.supported_access_mask
    and (.landlock.abi.effective_abi_version >= 1)
    and (.landlock.abi.supported_access | index("ReadFile") != null)
    and (.landlock.abi.supported_access | index("WriteFile") != null)
    and (.landlock.abi.supported_access | index("Execute") != null)
    and (.landlock.abi.unsupported_access | index("IoctlDev") != null)
    and (if .landlock.abi.effective_abi_version >= 2 then
      (.landlock.abi.supported_access | index("Refer") != null)
    else
      (.landlock.abi.supported_access | index("Refer") == null)
    end)
    and (if .landlock.abi.effective_abi_version >= 3 then
      (.landlock.abi.supported_access | index("Truncate") != null)
    else
      (.landlock.abi.supported_access | index("Truncate") == null)
    end)
    and .mount_namespace.workspace_bind_mount_wired == true
    and (.mount_namespace.workspace_mount_claim | contains("agentbox-linux-runner"))
    and any(.runner_phases[]; .name == "bind-workspace" and .status == "prototype")
    and any(.runner_phases[]; .name == "apply-landlock" and .status == "prototype")
    and (.security_claim | contains("runner-managed workspace mount"))
  ' "$plan_json" >/dev/null

landlock_effective_abi="$(jq -r '.landlock.abi.effective_abi_version' "$plan_json")"

(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --timeout-seconds "$timeout_seconds" \
    -- $command_string
  )

set +e
seccomp_output="$(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --seccomp-profile "$seccomp_profile" \
    --timeout-seconds "$timeout_seconds" \
    -- /bin/sh -c 'kill -0 $$; printf "kill_status:%s\n" "$?"' 2>&1
)"
seccomp_status=$?
set -e

if [[ "$seccomp_status" -ne 0 ]]; then
  printf '%s\n' "$seccomp_output" >&2
  echo "expected imported OCI/libseccomp profile AgentPod command to exit after observing seccomp denial" >&2
  exit 1
fi
if [[ "$seccomp_output" != *"kill_status:1"* || "$seccomp_output" != *"Operation not permitted"* ]]; then
  printf '%s\n' "$seccomp_output" >&2
  echo "expected imported OCI/libseccomp profile to deny kill(2) with EPERM evidence" >&2
  exit 1
fi

proof_outside="$(mktemp -d)"
parallel_root=""
trap 'rm -rf "$proof_outside" "$parallel_root"; rm -f "$seccomp_profile" "$plan_json"' EXIT
proof_policy_dir="$workspace/agentbox-landlock-policy"
mkdir -p "$proof_policy_dir"
proof_read_allowed="$proof_policy_dir/allowed-read"
proof_read_denied="$proof_outside/denied-read"
proof_exec_allowed="$proof_policy_dir/allowed-exec"
proof_exec_denied="$proof_outside/denied-exec"
proof_write_allowed="$proof_policy_dir/allowed-write"
proof_write_denied="$proof_outside/denied-write"
proof_rename_src="$proof_policy_dir/rename-src"
proof_rename_dir="$proof_policy_dir/rename-dst"
proof_truncate_allowed="$proof_policy_dir/truncate-allowed"
printf 'read-ok' >"$proof_read_allowed"
printf 'read-no' >"$proof_read_denied"
printf 'rename-ok' >"$proof_rename_src"
mkdir -p "$proof_rename_dir"
printf 'truncate-before' >"$proof_truncate_allowed"
cat >"$proof_exec_allowed" <<'EOF'
#!/bin/sh
printf allowed-exec
EOF
cat >"$proof_exec_denied" <<'EOF'
#!/bin/sh
printf denied-exec
EOF
chmod +x "$proof_exec_allowed" "$proof_exec_denied"
rm -f "$proof_write_allowed" "$proof_write_denied"

set +e
proof_output="$(
  cd "$workspace"
  printf 'y\n' | AGENTBOX_LINUX_NATIVE=1 cargo run -q -p agentbox-cli -- run \
    --provider agentpod-linux \
    --workspace-mode direct \
    --timeout-seconds "$timeout_seconds" \
    -- /bin/sh -c '
      set -u
      cat "$1" || exit 10
      if cat "$2"; then
        echo "read denial failed"
        exit 11
      fi
      "$3" > "$7/exec-allowed-output" || exit 12
      if "$4"; then
        echo "execute denial failed"
        exit 13
      fi
      printf ok > "$5" || exit 14
      if printf no > "$6"; then
        echo "write denial failed"
        exit 15
      fi
      abi="$8"
      rename_src="$9"
      rename_dir="${10}"
      truncate_allowed="${11}"
      if [ "$abi" -ge 2 ]; then
        mv "$rename_src" "$rename_dir/moved" || exit 16
        if mv "$2" "$7/denied-move"; then
          echo "rename denial failed"
          exit 17
        fi
      fi
      if [ "$abi" -ge 3 ]; then
        printf truncated > "$truncate_allowed" || exit 18
      fi
      printf "landlock-policy-ok\n"
    ' sh "$proof_read_allowed" "$proof_read_denied" "$proof_exec_allowed" "$proof_exec_denied" "$proof_write_allowed" "$proof_write_denied" "$proof_policy_dir" "$landlock_effective_abi" "$proof_rename_src" "$proof_rename_dir" "$proof_truncate_allowed" 2>&1
)"
proof_status=$?
set -e

if [[ "$proof_status" -ne 0 ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock ABI-aware proof command to succeed after observing denials" >&2
  exit 1
fi
if [[ "$proof_output" != *"read-ok"* || "$proof_output" != *"landlock-policy-ok"* ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to read allowed workspace file" >&2
  exit 1
fi
if [[ "$(cat "$proof_policy_dir/exec-allowed-output")" != "allowed-exec" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to execute allowed workspace file" >&2
  exit 1
fi
if [[ "$(cat "$proof_write_allowed")" != "ok" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to write inside workspace" >&2
  exit 1
fi
if [[ -e "$proof_write_denied" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to deny outside-workspace write" >&2
  exit 1
fi
if [[ "$landlock_effective_abi" -ge 2 ]]; then
  if [[ "$(cat "$proof_rename_dir/moved")" != "rename-ok" ]]; then
    printf '%s\n' "$proof_output" >&2
    echo "expected Linux Landlock proof command to allow ABI v2 same-workspace rename" >&2
    exit 1
  fi
  if [[ -e "$proof_policy_dir/denied-move" ]]; then
    printf '%s\n' "$proof_output" >&2
    echo "expected Linux Landlock proof command to deny outside-to-workspace rename" >&2
    exit 1
  fi
fi
if [[ "$landlock_effective_abi" -ge 3 && "$(cat "$proof_truncate_allowed")" != "truncated" ]]; then
  printf '%s\n' "$proof_output" >&2
  echo "expected Linux Landlock proof command to allow ABI v3 workspace truncate" >&2
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
trap 'rm -rf "$proof_outside" "$parallel_root" "$overlay_workspace" "$overlay_base"; rm -f "$seccomp_profile" "$plan_json"' EXIT
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
