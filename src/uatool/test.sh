#!/bin/sh
# Checks the write guard of uatool against the configured peer: prints `ok` three times (the refusal without --allow-write,
# the allowed write, the read back) and exits 0. Needs build/uatool (tools/build-uatool.sh) and a running peer: the URL and the
# writable Int32 node come from OPCUA_PEER_URL / OPCUA_NODE_INT32 or from peers/peer.env (path: OPCUA_PEER_ENV).
cd "$(dirname "$0")/../.." || exit 1
env_file=${OPCUA_PEER_ENV:-peers/peer.env}
get() { [ -f "$env_file" ] && sed -n "s/^$1=//p" "$env_file" | head -1; }
url=${OPCUA_PEER_URL:-$(get OPCUA_PEER_URL)}
node=${OPCUA_NODE_INT32:-$(get OPCUA_NODE_INT32)}
tool=build/uatool
if [ -z "$url" ] || [ -z "$node" ] || [ ! -x "$tool" ]; then
	echo "need build/uatool and a configured peer (OPCUA_PEER_URL, OPCUA_NODE_INT32)" >&2
	exit 1
fi

before=$($tool read "$url" "$node" | sed -n 's/.* Good //p')

out=$($tool write "$url" "$node" i32:7 2>&1)
code=$?
if [ "$code" -eq 2 ] && echo "$out" | grep -q "write refused: pass --allow-write"; then
	echo ok
else
	echo "refusal failed (exit $code): $out" >&2
	exit 1
fi

if $tool write "$url" "$node" i32:7 --allow-write > /dev/null; then
	echo ok
else
	echo "allowed write failed" >&2
	exit 1
fi

if $tool read "$url" "$node" | grep -q " Good 7$"; then
	echo ok
else
	echo "read back failed" >&2
	exit 1
fi

# put the old value back
[ -n "$before" ] && $tool write "$url" "$node" "i32:$before" --allow-write > /dev/null
exit 0
