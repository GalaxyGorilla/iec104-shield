#!/bin/sh
# Independent IEC-104 interop, run against TWO separate peer stacks:
#
#   master -> iec104-shield -> outstation
#
# The first peer is wendy512/iec104; the second is otfabric/go-iec104. Neither
# end uses the proxy's parser. Each scenario forwards an interrogation,
# spontaneous data, an allowed command and a select-before-operate pair, and
# answers a disallowed command with a negative activation confirmation without
# forwarding it.
#
# Exit 77 when a peer cannot be built and INTEROP_REQUIRED is not set.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
SERVER_PID=""
PROXY_PID=""
CLIENT_LOG=""
SERVER_LOG=""
PROXY_LOG=""
SBO_LOG=""

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
	cat "$CLIENT_LOG" 2>/dev/null || true
	echo "--- sbo client"
	cat "$SBO_LOG" 2>/dev/null || true
	echo "--- outstation"
	cat "$SERVER_LOG" 2>/dev/null || true
	echo "--- proxy"
	cat "$PROXY_LOG" 2>/dev/null || true
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

build_peer() {
	dir=$1
	out=$2
	if ! (cd "$dir" && go build -o "$out" .) >"$TMP/build.log" 2>&1; then
		if [ "${INTEROP_REQUIRED:-0}" = "1" ]; then
			echo "peer build failed ($dir):"
			cat "$TMP/build.log"
			exit 1
		fi
		echo "peer build failed ($dir); exit 77"
		cat "$TMP/build.log"
		exit 77
	fi
}

command -v go >/dev/null 2>&1 || { echo "go not installed"; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not installed"; exit 77; }

echo "== building independent peers"
build_peer "$ROOT/test/peers/iec104peer" "$TMP/iec104peer"
build_peer "$ROOT/test/peers/iec104peer2" "$TMP/iec104peer2"

echo "== building iec104-shield"
(cd "$ROOT" && go build -o bin/iec104-shield ./cmd/iec104-shield)

HAVE_TLS=0
if command -v openssl >/dev/null 2>&1; then
	if openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$TMP/tls.key" -out "$TMP/tls.crt" -days 1 \
		-subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
		>/dev/null 2>&1; then
		HAVE_TLS=1
	fi
fi

run_scenario() {
	PEER=$1
	LABEL=$2
	DEV_PORT=$(freeport)
	PROXY_PORT=$(freeport)
	CLIENT_LOG="$TMP/$LABEL-client.log"
	SERVER_LOG="$TMP/$LABEL-server.log"
	PROXY_LOG="$TMP/$LABEL-proxy.log"
	SBO_LOG="$TMP/$LABEL-sbo.log"

	echo "== [$LABEL] outstation on 127.0.0.1:$DEV_PORT"
	"$PEER" -mode server -host 127.0.0.1 -port "$DEV_PORT" >"$SERVER_LOG" 2>&1 &
	SERVER_PID=$!
	wait_for "$SERVER_LOG" READY || fail "[$LABEL] outstation did not become ready"

	echo "== [$LABEL] proxy owns 127.0.0.1:$PROXY_PORT, outstation moved to 127.0.0.1:$DEV_PORT"
	"$ROOT/bin/iec104-shield" gateway \
		--listen "127.0.0.1:$PROXY_PORT" \
		--device "127.0.0.1:$DEV_PORT" \
		--command-default deny \
		--command-rule 'allow:45:1:1000-1500:any' \
		--log-level info >"$PROXY_LOG" 2>&1 &
	PROXY_PID=$!
	wait_for "$PROXY_LOG" "ready" || fail "[$LABEL] proxy did not become ready"

	echo "== [$LABEL] independent master through the original address"
	"$PEER" -mode client -host 127.0.0.1 -port "$PROXY_PORT" >"$CLIENT_LOG" 2>&1 || true
	sleep 0.3

	grep -q 'SINGLE_POINT ioa=100 value=true' "$CLIENT_LOG" || fail "[$LABEL] interrogation data did not cross the proxy"
	grep -q 'SINGLE_POINT ioa=100 value=true cause=3' "$CLIENT_LOG" || fail "[$LABEL] spontaneous data did not cross the proxy"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 .*negative=false' "$CLIENT_LOG" || fail "[$LABEL] allowed command did not get a positive confirmation"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=2000 .*negative=true' "$CLIENT_LOG" || fail "[$LABEL] denied command did not get a negative confirmation"
	grep -q 'COMMAND type=45 ca=1 ioa=1000' "$SERVER_LOG" || fail "[$LABEL] allowed command did not reach the outstation"
	if grep -q 'COMMAND type=45 ca=1 ioa=2000' "$SERVER_LOG"; then
		fail "[$LABEL] denied command reached the outstation"
	fi

	echo "== [$LABEL] select-before-operate through the original address"
	"$PEER" -mode sbo-client -host 127.0.0.1 -port "$PROXY_PORT" >"$SBO_LOG" 2>&1 || true
	sleep 0.3

	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 select=true negative=false' "$SBO_LOG" || fail "[$LABEL] SBO select was not confirmed"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 select=false negative=false' "$SBO_LOG" || fail "[$LABEL] SBO execute was not confirmed"
	grep -q 'SINGLE_POINT ioa=100 value=true cause=3' "$SBO_LOG" || fail "[$LABEL] spontaneous data did not cross the proxy during SBO"
	grep -q 'COMMAND type=45 ca=1 ioa=1000 select=true' "$SERVER_LOG" || fail "[$LABEL] SBO select did not reach the outstation"
	grep -q 'COMMAND type=45 ca=1 ioa=1000 select=false' "$SERVER_LOG" || fail "[$LABEL] SBO execute did not reach the outstation"

	echo "== [$LABEL] stopping the proxy: the original address must disappear"
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
		echo "PASS: [$LABEL] original address refused after the proxy stopped"
	else
		fail "[$LABEL] original address still accepted a connection after the proxy stopped"
	fi

	echo "== [$LABEL] the outstation still answers at its moved address"
	if "$ROOT/bin/iec104-shield" selftest --listen 127.0.0.1:1 --device "127.0.0.1:$DEV_PORT" >/dev/null 2>&1; then
		echo "PASS: [$LABEL] outstation still answers at 127.0.0.1:$DEV_PORT"
	else
		fail "[$LABEL] outstation stopped answering at its moved address"
	fi

	kill "$SERVER_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
	SERVER_PID=""
}

run_tls_scenario() {
	PEER=$1
	LABEL=$2
	UPSTREAM_TLS=$3
	DEV_PORT=$(freeport)
	PROXY_PORT=$(freeport)
	CLIENT_LOG="$TMP/$LABEL-client.log"
	SERVER_LOG="$TMP/$LABEL-server.log"
	PROXY_LOG="$TMP/$LABEL-proxy.log"
	SBO_LOG="$TMP/$LABEL-sbo.log"

	echo "== [$LABEL] outstation on 127.0.0.1:$DEV_PORT"
	if [ "$UPSTREAM_TLS" = "1" ]; then
		"$PEER" -mode server -tls -tls-cert "$TMP/tls.crt" -tls-key "$TMP/tls.key" \
			-host 127.0.0.1 -port "$DEV_PORT" >"$SERVER_LOG" 2>&1 &
	else
		"$PEER" -mode server -host 127.0.0.1 -port "$DEV_PORT" >"$SERVER_LOG" 2>&1 &
	fi
	SERVER_PID=$!
	wait_for "$SERVER_LOG" READY || fail "[$LABEL] outstation did not become ready"

	echo "== [$LABEL] TLS proxy owns 127.0.0.1:$PROXY_PORT"
	if [ "$UPSTREAM_TLS" = "1" ]; then
		"$ROOT/bin/iec104-shield" gateway \
			--listen "127.0.0.1:$PROXY_PORT" \
			--device "127.0.0.1:$DEV_PORT" \
			--tls-cert "$TMP/tls.crt" \
			--tls-key "$TMP/tls.key" \
			--device-tls-ca "$TMP/tls.crt" \
			--command-default deny \
			--command-rule 'allow:45:1:1000-1500:any' \
			--log-level info >"$PROXY_LOG" 2>&1 &
	else
		"$ROOT/bin/iec104-shield" gateway \
			--listen "127.0.0.1:$PROXY_PORT" \
			--device "127.0.0.1:$DEV_PORT" \
			--tls-cert "$TMP/tls.crt" \
			--tls-key "$TMP/tls.key" \
			--command-default deny \
			--command-rule 'allow:45:1:1000-1500:any' \
			--log-level info >"$PROXY_LOG" 2>&1 &
	fi
	PROXY_PID=$!
	wait_for "$PROXY_LOG" "ready" || fail "[$LABEL] TLS proxy did not become ready"

	echo "== [$LABEL] TLS master through the original address"
	"$PEER" -mode client -tls -tls-ca "$TMP/tls.crt" \
		-host 127.0.0.1 -port "$PROXY_PORT" >"$CLIENT_LOG" 2>&1 || true
	sleep 0.3
	grep -q 'SINGLE_POINT ioa=100 value=true' "$CLIENT_LOG" || fail "[$LABEL] TLS interrogation data did not cross"
	grep -q 'SINGLE_POINT ioa=100 value=true cause=3' "$CLIENT_LOG" || fail "[$LABEL] TLS spontaneous data did not cross"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 .*negative=false' "$CLIENT_LOG" || fail "[$LABEL] TLS allowed command was not confirmed"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=2000 .*negative=true' "$CLIENT_LOG" || fail "[$LABEL] TLS denied command was not refused"
	grep -q 'COMMAND type=45 ca=1 ioa=1000' "$SERVER_LOG" || fail "[$LABEL] TLS allowed command did not reach the outstation"
	if grep -q 'COMMAND type=45 ca=1 ioa=2000' "$SERVER_LOG"; then
		fail "[$LABEL] TLS denied command reached the outstation"
	fi

	echo "== [$LABEL] TLS select-before-operate"
	"$PEER" -mode sbo-client -tls -tls-ca "$TMP/tls.crt" \
		-host 127.0.0.1 -port "$PROXY_PORT" >"$SBO_LOG" 2>&1 || true
	sleep 0.3
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 select=true negative=false' "$SBO_LOG" || fail "[$LABEL] TLS SBO select was not confirmed"
	grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=1000 select=false negative=false' "$SBO_LOG" || fail "[$LABEL] TLS SBO execute was not confirmed"

	echo "== [$LABEL] a plain client is refused"
	if python3 - "$PROXY_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(2.0)
s.connect(("127.0.0.1", port))
s.sendall(bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00]))
try:
    data = s.recv(1)
except OSError:
    sys.exit(0)
sys.exit(0 if data == b"" else 1)
PY
	then
		echo "PASS: [$LABEL] plain client refused by the TLS listener"
	else
		fail "[$LABEL] plain client was not refused by the TLS listener"
	fi

	echo "== [$LABEL] stopping the TLS proxy"
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
		echo "PASS: [$LABEL] TLS address refused after the proxy stopped"
	else
		fail "[$LABEL] TLS address still accepted a connection after the proxy stopped"
	fi

	kill "$SERVER_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
	SERVER_PID=""
}

run_scenario "$TMP/iec104peer" wendy512
run_scenario "$TMP/iec104peer2" otfabric
if [ "$HAVE_TLS" = "1" ]; then
	run_tls_scenario "$TMP/iec104peer2" otfabric-tls 0
	run_tls_scenario "$TMP/iec104peer2" otfabric-tls-both 1
else
	echo "== TLS scenarios skipped: openssl not available"
fi

echo "== address takeover, SBO and TLS (IEC-104, two independent peers): PASS"
