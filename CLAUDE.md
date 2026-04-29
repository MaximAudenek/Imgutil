# imgutil

PNG image processing utility. See SPEC.md for the full specification.
Read SPEC.md fully before writing any code.

## Absolute Rules
- `cargo audit` must be run before writing any code — zero vulnerabilities
- `cargo clippy -- -D warnings` must pass at all times — zero warnings
- Never use `unwrap()` or `expect()` in non-test code
- Never proceed to the next build step until current step's tests pass clean
- All security requirements in SPEC.md are non-negotiable
- Never trade security for convenience or brevity

## Build Steps (in order, do not skip)
1. Core codec — single file round-trip, all memory security met
2. Streaming — 64KB chunks, RAM usage flat with payload size
3. Multi-image — splitting, session ID, assembly, ordering
4. Error hardening — every failure path generic and zeroizes correctly
5. CLI — clap, rpassword, progress bar
6. OPSEC — strings check on release binary, fuzz targets, README

## If Unsure
Re-read the relevant section of SPEC.md before proceeding.
