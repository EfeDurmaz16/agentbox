#!/bin/bash
# Test the Agentbox approve flow with a real phone notification.
#
# Prerequisites:
#   1. Install ntfy app on your phone (iOS/Android)
#   2. Subscribe to your topic: cat ~/.agentbox/config.toml | grep ntfy_topic
#   3. Start the daemon: cargo run -p agentbox-daemon
#
# Usage:
#   ./scripts/test-approve.sh              # Test git push (approve)
#   ./scripts/test-approve.sh block        # Test rm -rf / (block)
#   ./scripts/test-approve.sh allow        # Test ls -la (allow)

SOCKET="$HOME/.agentbox/agentbox.sock"

if [ ! -S "$SOCKET" ]; then
    echo "Error: Daemon not running. Start it first:"
    echo "  cargo run -p agentbox-daemon"
    exit 1
fi

MODE="${1:-approve}"

case "$MODE" in
    approve)
        echo "Sending: git push origin main (APPROVE — check your phone)"
        PAYLOAD='{"binary":"git","args":["push","origin","main"],"cwd":"'"$(pwd)"'","parent_process":"test-script","pid":9999}'
        ;;
    block)
        echo "Sending: rm -rf / (BLOCK — instant deny, no notification)"
        PAYLOAD='{"binary":"rm","args":["-rf","/"],"cwd":"'"$(pwd)"'","parent_process":"test-script","pid":9999}'
        ;;
    allow)
        echo "Sending: ls -la (ALLOW — instant pass-through)"
        PAYLOAD='{"binary":"ls","args":["-la"],"cwd":"'"$(pwd)"'","parent_process":"test-script","pid":9999}'
        ;;
    *)
        echo "Unknown mode: $MODE (use approve, block, or allow)"
        exit 1
        ;;
esac

python3 -c "
import socket, json, sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(130)
sock.connect('$SOCKET')
sock.sendall(('$PAYLOAD' + '\n').encode())

print('Waiting for response...')
resp = sock.recv(4096).decode().strip()
sock.close()

data = json.loads(resp)
decision = data.get('decision', 'unknown')
reason = data.get('reason', '')

if decision in ('allowed', 'approved'):
    print(f'\033[32m{decision.upper()}\033[0m — {reason}')
elif decision in ('denied', 'timed_out'):
    print(f'\033[33m{decision.upper()}\033[0m — {reason}')
elif decision == 'blocked':
    print(f'\033[31m{decision.upper()}\033[0m — {reason}')
else:
    print(f'{decision} — {reason}')
"
