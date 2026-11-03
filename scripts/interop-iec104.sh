#!/bin/sh
# Independent IEC-104 interop:
#
#   wendy512/iec104 master -> iec104-shield -> wendy512/iec104 outstation
#
# The outstation and master are both a third-party implementation. The proxy
# forwards an interrogation and an allowed command, and answers a disallowed
# command with a negative activation confirmation without forwarding it.
#
# Exit 77 when the peer cannot be built and INTEROP_REQUIRED is not set.
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
	echo "interop FAILED: $1"
	echo "--- client"
	cat "$TMP/client.log" 2>/dev/null || true
	echo "--- outstation"
	cat "$TMP/server.log" 2>/dev/null || true
	echo "--- proxy"
	cat "$TMP/proxy.log" 2>/dev/null || true
	exit 1
}

command -v go >/dev/null 2>&1 || { echo "go not installed"; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 77; }

echo "== building independent peer"
if ! (cd "$PEER_DIR" && go build -o "$TMP/iec104peer" .) >"$TMP/build.log" 2>&1; then
	if [ "${INTEROP_REQUIRED:-0}" = "1" ]; then
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
i=0
while [ "$i" -lt 50 ]; do
	grep -q READY "$TMP/server.log" 2>/dev/null && break
	sleep 0.1
	i=$((i + 1))
done
grep -q READY "$TMP/server.log" || fail "outstation did not become ready"

echo "== proxy owns 127.0.0.1:$PROXY_PORT, outstation moved to 127.0.0.1:$DEV_PORT"
"$ROOT/bin/iec104-shield" gateway \
	--listen "127.0.0.1:$PROXY_PORT" \
	--device "127.0.0.1:$DEV_PORT" \
	--command-default deny \
	--command-rule 'allow:45:1:1000-1500:execute' \
	--log-level info >"$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
i=0
while [ "$i" -lt 50 ]; do
	grep -q "ready" "$TMP/proxy.log" 2>/dev/null && break
	sleep 0.1
	i=$((i + 1))
done
grep -q "ready" "$TMP/proxy.log" || fail "proxy did not become ready"

echo "== independent master through the original address"
"$TMP/iec104peer" -mode client -host 127.0.0.1 -port "$PROXY_PORT" >"$TMP/client.log" 2>&1 || true
sleep 0.3

grep -q 'SINGLE_POINT ioa=100 value=true' "$TMP/client.log" || fail "interrogation data did not cross the proxy"
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 negative=false' "$TMP/client.log" || fail "allowed command did not get a positive confirmation"
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=2000 negative=true' "$TMP/client.log" || fail "denied command did not get a negative confirmation"
grep -q 'COMMAND type=45 ca=1 ioa=1000' "$TMP/server.log" || fail "allowed command did not reach the outstation"
if grep -q 'COMMAND type=45 ca=1 ioa=2000' "$TMP/server.log"; then
	fail "denied command reached the outstation"
fi

echo "== stopping the proxy: the original address must disappear"
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
sleep 0.2
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

echo "== the outstation still answers at its moved address"
if "$ROOT/bin/iec104-shield" selftest --listen 127.0.0.1:1 --device "127.0.0.1:$DEV_PORT" >/dev/null 2>&1; then
	echo "PASS: outstation still answers at 127.0.0.1:$DEV_PORT"
else
	fail "outstation stopped answering at its moved address"
fi

echo "== address takeover (IEC-104, independent peer): PASS"
