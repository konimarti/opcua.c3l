#!/bin/bash
# Runs the whole test suite against one peer: peers/run-peer-suite.sh open62541|asyncua
# For a plain shell and for CI: it calls the compiler's own test command. Inside the agent box use peers/peer.sh start <peer>
# and the c3_test tool instead (the box hook forbids calling the compiler by hand).
set -u
cd "$(dirname "$0")/.."
peer=$1
peers/peer.sh start "$peer"
trap 'peers/peer.sh stop "$peer"' EXIT
c3c test
