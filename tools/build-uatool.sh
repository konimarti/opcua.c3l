#!/bin/sh
# Builds the uatool binary into build/ (a binary build is the one step that needs the compiler directly).
set -eu
cd "$(dirname "$0")/.."
c3c build uatool
