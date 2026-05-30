#!/usr/bin/env bash
set -euo pipefail

skip() {
  echo "SKIP: $*"
  exit 77
}

if [ "$(uname -s)" != "Linux" ]; then
  skip "Linux nftables smoke must run on Linux"
fi

if [ "${AGENTBOX_LINUX_NFTABLES:-0}" != "1" ]; then
  skip "set AGENTBOX_LINUX_NFTABLES=1 to run nftables live gate smoke"
fi

if ! command -v nft >/dev/null 2>&1; then
  skip "nft command is not installed"
fi

if ! command -v python3 >/dev/null 2>&1; then
  skip "python3 is required for the nftables packet denial fixture"
fi

probe_table="agentbox_probe_$$"
if ! nft add table inet "$probe_table" >/dev/null 2>&1; then
  skip "nft command lacks permission to manage inet tables"
fi
nft delete table inet "$probe_table" >/dev/null 2>&1 || true

cgroup_root="${AGENTBOX_LINUX_CGROUP_ROOT:-/sys/fs/cgroup}"
session="agentbox-nft-smoke-$$"
session_cgroup="$cgroup_root/$session"
original_cgroup_rel="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
original_cgroup="$cgroup_root$original_cgroup_rel"
if ! mkdir "$session_cgroup" >/dev/null 2>&1; then
  skip "writable/delegated cgroup v2 root is required for session-scoped nftables smoke"
fi
if ! printf '%s\n' "$$" >"$session_cgroup/cgroup.procs" 2>/dev/null; then
  rmdir "$session_cgroup" >/dev/null 2>&1 || true
  skip "failed to attach smoke process to delegated cgroup $session"
fi

table="agentbox_smoke_$$"
chain="agentpod_egress"
port_file="$(mktemp)"
listener_pid=""

cleanup() {
  nft delete table inet "$table" >/dev/null 2>&1 || true
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
    wait "$listener_pid" >/dev/null 2>&1 || true
  fi
  if [ -w "$original_cgroup/cgroup.procs" ]; then
    printf '%s\n' "$$" >"$original_cgroup/cgroup.procs" 2>/dev/null || true
  fi
  rmdir "$session_cgroup" >/dev/null 2>&1 || true
  rm -f "$port_file"
}
trap cleanup EXIT

python3 - "$port_file" <<'PY' &
import pathlib
import socket
import sys
import time

port_file = pathlib.Path(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 0))
sock.listen(8)
sock.settimeout(0.5)
port_file.write_text(str(sock.getsockname()[1]), encoding="utf-8")
deadline = time.time() + 60
while time.time() < deadline:
    try:
        conn, _addr = sock.accept()
    except TimeoutError:
        continue
    except OSError:
        break
    else:
        conn.close()
PY
listener_pid=$!

for _ in $(seq 1 50); do
  if [ -s "$port_file" ]; then
    break
  fi
  sleep 0.1
done
if [ ! -s "$port_file" ]; then
  echo "expected listener to publish an ephemeral port" >&2
  exit 1
fi
port="$(cat "$port_file")"

python3 - "$port" <<'PY'
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
sock.close()
PY

nft add table inet "$table"
nft add chain inet "$table" "$chain" '{ type filter hook output priority filter; policy accept; }'
nft add rule inet "$table" "$chain" socket cgroupv2 level 1 "$session" ip daddr 127.0.0.1 tcp dport "$port" reject with tcp reset
nft list table inet "$table" >/dev/null

set +e
denial_output="$(python3 - "$port" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
try:
    sock.connect(("127.0.0.1", int(sys.argv[1])))
except OSError as exc:
    print(f"denied_error:{exc.errno}:{exc.strerror}")
    sys.exit(0)
print("unexpected_success")
sys.exit(2)
PY
)"
denial_status=$?
set -e
if [ "$denial_status" -ne 0 ] || [[ "$denial_output" != denied_error:* ]]; then
  printf '%s\n' "$denial_output" >&2
  echo "expected nftables cgroup-scoped rule to deny packet-level loopback connect" >&2
  exit 1
fi

nft delete table inet "$table"
if nft list table inet "$table" >/dev/null 2>&1; then
  echo "expected nftables smoke cleanup to remove table $table" >&2
  exit 1
fi
trap - EXIT
cleanup

echo "Linux nftables live gate smoke passed for session cgroup $session and inet table $table"
