#!/bin/sh
# Analyse raw app images with Ghidra headless and export decompiled C to decomp/.
# usage: GHIDRA=/opt/ghidra_11.4.2_PUBLIC ghidra/run.sh firmware/FA_127_01_07.bin ...
set -eu
GHIDRA=${GHIDRA:-/opt/ghidra_11.4.2_PUBLIC}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROJ=${PROJ:-$(mktemp -d)}
mkdir -p "$PROJ"
for bin in "$@"; do
	"$GHIDRA/support/analyzeHeadless" "$PROJ" G502 -import "$bin" -overwrite \
		-processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr 0x08004000 \
		-scriptPath "$ROOT/ghidra" -preScript STM32L1Setup.java \
		-postScript ExportDecomp.java "$ROOT/decomp"
done
