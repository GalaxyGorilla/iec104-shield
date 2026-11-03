#!/bin/sh
# Real-binary SIGHUP smoke test.
#
# Starts the proxy from a YAML file, proves a command is denied, rewrites the
# file to allow it, sends SIGHUP, and proves the same command now passes. Then
# writes a broken file and proves SIGHUP keeps the running configuration.
#
# Exit 77 when the independent peer cannot be built and SMOKE_REQUIRED is not
# set.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PEER_DIR="$ROOT/test/peers/iec104peer"
TMP=$(mktemp -d)
SERVER_PID=""
PROXY_PID=""

cleanup() {
	[ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	[ -n "$PROXY_PID" ] && wait "$PROXY_PID" 2>/dev/null || true
	[ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

freeport() {
	python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

fail() {
	echo "reload smoke FAILED: $1"
	echo "--- client"
	cat "$TMP/client.log" 2>/dev/null || true
	echo "--- outstation"
	cat "$TMP/server.log" 2>/dev/null || true
	echo "--- proxy"
	cat "$TMP/proxy.log" 2>/dev/null || true
	exit 1
}

wait_for() {
	file=$1
	pattern=$2
	i=0
	while [ "$i" -lt 50 ]; do
		grep -q "$pattern" "$file" 2>/dev/null && return 0
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

command -v go >/dev/null 2>&1 || { echo "go not installed"; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 77; }

echo "== building independent peer"
if ! (cd "$PEER_DIR" && go build -o "$TMP/iec104peer" .) >"$TMP/build.log" 2>&1; then
	if [ "${SMOKE_REQUIRED:-0}" = "1" ]; then
		echo "peer build failed:"
		cat "$TMP/build.log"
		exit 1
	fi
	echo "peer build failed (run 'make peers' with network access); exit 77"
	cat "$TMP/build.log"
	exit 77
fi

echo "== building iec104-shield"
(cd "$ROOT" && go build -o bin/iec104-shield ./cmd/iec104-shield)

DEV_PORT=$(freeport)
PROXY_PORT=$(freeport)

echo "== outstation on 127.0.0.1:$DEV_PORT"
"$TMP/iec104peer" -mode server -host 127.0.0.1 -port "$DEV_PORT" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
wait_for "$TMP/server.log" READY || fail "outstation did not become ready"

write_config() {
	action=$1
	cat >"$TMP/gateway.yaml" <<EOF
devices:
  - name: reload-test
    listen_addr: "127.0.0.1:$PROXY_PORT"
    device_addr: "127.0.0.1:$DEV_PORT"
    command_policy:
      default: deny
      rules:
        - types: [45]
          common_address: 1
          ioa: "1000-1500"
          select: execute
          action: $action
log:
  level: info
  format: console
EOF
}

write_config deny
echo "== proxy from config, command denied"
"$ROOT/bin/iec104-shield" gateway --config "$TMP/gateway.yaml" >"$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
wait_for "$TMP/proxy.log" "ready" || fail "proxy did not become ready"

"$TMP/iec104peer" -mode client -host 127.0.0.1 -port "$PROXY_PORT" >"$TMP/client.log" 2>&1 || true
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 negative=true' "$TMP/client.log" ||
	fail "command was not denied before the reload"

echo "== rewriting the policy and sending SIGHUP"
write_config allow
kill -HUP "$PROXY_PID"
wait_for "$TMP/proxy.log" "configuration reloaded" || fail "proxy did not log a successful reload"

"$TMP/iec104peer" -mode client -host 127.0.0.1 -port "$PROXY_PORT" >"$TMP/client.log" 2>&1 || true
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 negative=false' "$TMP/client.log" ||
	fail "command was still denied after the reload"
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=2000 negative=true' "$TMP/client.log" ||
	fail "denied command was allowed after the reload"

echo "== a broken config keeps the running configuration"
printf 'devices: [\n' >"$TMP/gateway.yaml"
kill -HUP "$PROXY_PID"
wait_for "$TMP/proxy.log" "keeping the running configuration" || fail "proxy did not reject the broken config"

"$TMP/iec104peer" -mode client -host 127.0.0.1 -port "$PROXY_PORT" >"$TMP/client.log" 2>&1 || true
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 negative=false' "$TMP/client.log" ||
	fail "broken reload changed the running policy"

echo "== stopping the proxy"
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
if python3 - "$PROXY_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", port))
except OSError:
    sys.exit(0)
sys.exit(1)
PY
then
	echo "PASS: original address refused after the proxy stopped"
else
	fail "original address still accepted a connection after the proxy stopped"
fi

echo "== SIGHUP reload (IEC-104, real binary): PASS"
