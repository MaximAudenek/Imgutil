#!/bin/bash
# Build a release binary, sanitize it of forbidden substrings, smoke-test the
# CLI, then run the strings check. Print the binary's sha256 sum on success.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=target/release/imgutil

echo "==> cargo build --release"
cargo build --release

echo "==> sanitizing release binary"
python3 scripts/sanitize_binary.py "$BIN"

# On macOS, the linker-signed adhoc signature is invalidated by the rewrite.
# Re-applying an adhoc signature recomputes the hash over the modified bytes
# so Gatekeeper / kernel will not SIGKILL the process at exec.
if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "==> re-signing (adhoc) after rewrite"
    codesign -f -s - "$BIN"
fi

echo "==> smoke test: encode → decode round-trip"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "release-smoke-test-$(date +%s)" > "$TMP/in.bin"
mkdir -p "$TMP/out"
printf "smoke_test_password\n" | "$BIN" generate --in "$TMP/in.bin" --out-dir "$TMP/out" >/dev/null
printf "smoke_test_password\n" | "$BIN" extract --in-dir "$TMP/out" --out "$TMP/decoded.bin" >/dev/null
if ! cmp -s "$TMP/in.bin" "$TMP/decoded.bin"; then
    echo "FAIL: round-trip mismatch after sanitization" >&2
    exit 1
fi

echo "==> strings check"
scripts/check_strings.sh "$BIN"

echo "==> sha256"
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$BIN"
elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$BIN"
else
    echo "warning: no sha256 tool found" >&2
fi
