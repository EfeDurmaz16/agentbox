#!/usr/bin/env bash
set -u

iterations="${AGENTBOX_LINUX_BENCH_ITERS:-25}"
command_string="${AGENTBOX_LINUX_BENCH_COMMAND:-/bin/true}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: Linux isolation benchmark requires Linux"
  exit 77
fi

if ! [[ "$iterations" =~ ^[0-9]+$ ]] || [[ "$iterations" -eq 0 ]]; then
  echo "error: AGENTBOX_LINUX_BENCH_ITERS must be a positive integer" >&2
  exit 2
fi

read -r -a command_argv <<< "$command_string"
if [[ "${#command_argv[@]}" -eq 0 ]]; then
  echo "error: AGENTBOX_LINUX_BENCH_COMMAND cannot be empty" >&2
  exit 2
fi

have_unshare=0
if command -v unshare >/dev/null 2>&1; then
  have_unshare=1
fi

now_ns() {
  date +%s%N
}

run_layer() {
  local layer="$1"
  shift

  local i start end elapsed_ms status
  for ((i = 1; i <= iterations; i++)); do
    start="$(now_ns)"
    if "$@" >/dev/null 2>&1; then
      status="ok"
    else
      status="fail"
    fi
    end="$(now_ns)"
    elapsed_ms=$(( (end - start) / 1000000 ))
    printf '%s,%d,%d,%s\n' "$layer" "$i" "$elapsed_ms" "$status"
  done
}

echo "layer,iteration,elapsed_ms,status"
run_layer "direct" "${command_argv[@]}"

if [[ "$have_unshare" -eq 0 ]]; then
  echo "SKIP: unshare command not found" >&2
  exit 77
fi

run_layer "userns" unshare --user --map-root-user --setgroups=deny -- "${command_argv[@]}"
run_layer "mntns" unshare --mount --propagation private -- "${command_argv[@]}"
run_layer "pidns" unshare --pid --fork --mount-proc -- "${command_argv[@]}"
run_layer "user-mount-pid" unshare \
  --user --map-root-user --setgroups=deny \
  --mount --propagation private \
  --pid --fork --mount-proc -- "${command_argv[@]}"
