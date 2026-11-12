#!/bin/bash
# Runs the whole test suite against one peer: peers/run-peer-suite.sh open62541|asyncua
set -u
cd "$(dirname "$0")/.."
peer=$1
peers/peer.sh start "$peer"
trap 'peers/peer.sh stop "$peer"' EXIT
c3c test
