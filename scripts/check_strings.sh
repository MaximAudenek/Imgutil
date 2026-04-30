#!/bin/bash
# Verify the release binary contains no forbidden substrings per SPEC.md.
# Exits non-zero if any match is found.
set -euo pipefail

BIN="${1:-target/release/imgutil}"

if [[ ! -f "$BIN" ]]; then
    echo "error: binary not found at $BIN" >&2
    exit 2
fi

PATTERN='stego|encod|crypto|cipher|argon|chacha|secret'

if matches=$(strings "$BIN" | grep -iE "$PATTERN"); then
    echo "FAIL: forbidden strings present in $BIN" >&2
    echo "$matches" | sed 's/^/  /' >&2
    exit 1
fi

echo "PASS: no forbidden strings in $BIN"
