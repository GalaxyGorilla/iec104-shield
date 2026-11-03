#!/bin/sh
# Third interop peer: MZ Automation lib60870-C as the outstation.
#
#   lib60870 outstation <- iec104-shield <- otfabric master
#
# lib60870 is the widely deployed C reference implementation. It is used as a
# separate test process, never linked into the proxy, so the proxy stays pure
# Go and the MIT/GPL boundary stays clean.
#
# The script clones lib60870 when LIB60870_DIR is not set, builds only the
# library target, and compiles the cs104_server example with a small patch:
# an argv port and unbuffered stdout. Exit 77 when the toolchain or network is
# unavailable and LIB60870_REQUIRED is not set.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
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
	echo "lib60870 interop FAILED: $1"
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
	while [ "$i" -lt 100 ]; do
		grep -q "$pattern" "$file" 2>/dev/null && return 0
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || {
		if [ "${LIB60870_REQUIRED:-0}" = "1" ]; then
			echo "missing required tool: $1"
			exit 1
		fi
		echo "skip: missing $1 (set LIB60870_DIR or install the C toolchain); exit 77"
		exit 77
	}
}

need go
need python3
need cc
need cmake
if [ -z "${LIB60870_DIR:-}" ]; then
	need git
fi

if [ -n "${LIB60870_DIR:-}" ]; then
	if [ -d "$LIB60870_DIR/lib60870-C" ]; then
		SRC="$LIB60870_DIR/lib60870-C"
	elif [ -d "$LIB60870_DIR/src" ]; then
		SRC="$LIB60870_DIR"
	else
		echo "LIB60870_DIR=$LIB60870_DIR does not contain lib60870-C" >&2
		exit 1
	fi
else
	echo "== cloning lib60870"
	git clone --depth 1 https://github.com/mz-automation/lib60870.git "$TMP/lib60870" >/dev/null 2>&1 || {
		if [ "${LIB60870_REQUIRED:-0}" = "1" ]; then
			echo "lib60870 clone failed"
			exit 1
		fi
		echo "lib60870 clone failed (network); exit 77"
		exit 77
	}
	SRC="$TMP/lib60870/lib60870-C"
fi

echo "== building lib60870 library"
cmake -S "$SRC" -B "$TMP/build" >/dev/null 2>&1 || fail "cmake configure"
cmake --build "$TMP/build" --target lib60870 -j 4 >/dev/null 2>&1 || fail "lib60870 build"

echo "== building the patched cs104_server"
cp "$SRC/examples/cs104_server/simple_server.c" "$TMP/server.c"
python3 - "$TMP/server.c" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace(
    "CS104_Slave slave = CS104_Slave_create(10, 10);",
    "setvbuf(stdout, NULL, _IONBF, 0);\n"
    "    CS104_Slave slave = CS104_Slave_create(10, 10);\n"
    "    if (argc > 1) CS104_Slave_setLocalPort(slave, atoi(argv[1]));",
)
open(p, "w").write(s)
PY
cc \
	-I"$SRC/config" \
	-I"$SRC/src/file-service" \
	-I"$SRC/src/inc/api" \
	-I"$SRC/src/inc/internal" \
	-I"$SRC/src/common/inc" \
	-I"$SRC/src/hal/inc" \
	"$TMP/server.c" -o "$TMP/cs104_server" \
	"$TMP/build/src/liblib60870.a" -lpthread -lm || fail "compile cs104_server"

echo "== building the otfabric master"
(cd "$ROOT/test/peers/iec104peer2" && go build -o "$TMP/iec104peer2" .) || fail "build peer2"
(cd "$ROOT" && go build -o bin/iec104-shield ./cmd/iec104-shield) || fail "build proxy"

DEV_PORT=$(freeport)
PROXY_PORT=$(freeport)

echo "== lib60870 outstation on 127.0.0.1:$DEV_PORT"
"$TMP/cs104_server" "$DEV_PORT" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
wait_for "$TMP/server.log" "APCI parameters" || fail "lib60870 outstation did not start"

echo "== proxy owns 127.0.0.1:$PROXY_PORT"
"$ROOT/bin/iec104-shield" gateway \
	--listen "127.0.0.1:$PROXY_PORT" \
	--device "127.0.0.1:$DEV_PORT" \
	--command-default deny \
	--command-rule 'allow:45:1:5000-5000:any' \
	--log-level info >"$TMP/proxy.log" 2>&1 &
PROXY_PID=$!
wait_for "$TMP/proxy.log" "ready" || fail "proxy did not become ready"

echo "== otfabric master through the original address"
"$TMP/iec104peer2" -mode client \
	-host 127.0.0.1 -port "$PROXY_PORT" \
	-allow-ioa 5000 -deny-ioa 2000 >"$TMP/client.log" 2>&1 || true
sleep 0.3

grep -q 'SINGLE_POINT ioa=104 value=true cause=20' "$TMP/client.log" ||
	fail "lib60870 interrogation data did not cross the proxy"
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=5000 .*negative=false' "$TMP/client.log" ||
	fail "allowed command did not get a positive confirmation"
grep -q 'COMMAND_RESPONSE type=45 ca=1 ioa=2000 .*negative=true' "$TMP/client.log" ||
	fail "denied command did not get a negative confirmation"
grep -q 'IOA: 5000 switch to 1' "$TMP/server.log" ||
	fail "allowed command did not reach lib60870"
if grep -q 'IOA: 2000' "$TMP/server.log"; then
	fail "denied command reached lib60870"
fi

echo "== stopping the proxy"
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

echo "== lib60870 interop: PASS"
