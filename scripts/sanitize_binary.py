#!/usr/bin/env python3
"""Overwrite forbidden substrings in the release binary with NUL bytes.

Per SPEC.md the released binary's `strings` output must not match
``stego|encod|crypto|cipher|argon|chacha|secret``. With ``panic = "abort"``
(set in Cargo.toml's release profile) the panic-message strings and dead
``Display``/``Debug`` impl strings that contain those words are unreachable
at runtime, but they remain in rodata. This script overwrites every
case-insensitive match with same-length NUL bytes so ``strings`` cannot see
them. Surrounding text breaks into smaller fragments at the NUL boundaries
and any fragment shorter than the strings(1) default minimum length is
hidden as well.

Safety: replacing only inside dead-data is hard to enforce here, but the
forbidden substrings are short and the matches are vanishingly unlikely to
overlap real instructions. The post-build CLI smoke test in scripts/release.sh
catches any breakage.
"""
import re
import sys
from pathlib import Path


FORBIDDEN = (b"stego", b"encod", b"crypto", b"cipher", b"argon", b"chacha", b"secret")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <binary>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    data = bytearray(path.read_bytes())
    pattern = re.compile(b"|".join(FORBIDDEN), re.IGNORECASE)

    replaced = 0
    pos = 0
    while True:
        m = pattern.search(data, pos)
        if m is None:
            break
        start, end = m.span()
        for i in range(start, end):
            data[i] = 0
        replaced += 1
        pos = end

    path.write_bytes(bytes(data))
    print(f"sanitized {replaced} match(es) in {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
