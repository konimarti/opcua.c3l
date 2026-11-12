#!/bin/sh
# Builds the static library and fails when it exports `main` or any uagen symbol (the tool must not leak into the archive).
set -eu
cd "$(dirname "$0")/.."
c3c build opcua >/dev/null
bad=$(nm build/opcua.a 2>/dev/null | grep -E ' [TtDdBbRr] (main$|.*uagen)' || true)
if [ -n "$bad" ]; then
	echo "build/opcua.a contains tool symbols:"
	echo "$bad"
	exit 1
fi
echo "build/opcua.a is clean"
