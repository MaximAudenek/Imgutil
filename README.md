# imgutil

PNG image processing utility.

## Usage

```
imgutil generate --in <FILE> --out-dir <DIRECTORY>
imgutil extract  --in-dir <DIRECTORY> --out <FILE>
imgutil extract  --in <FILE>          --out <FILE>
```

The password is always read from stdin. The prompt is the literal
string `Password: ` written to stderr.

## Building

The release binary is produced by a wrapper script that performs three
post-build steps required by the project's operational requirements:

1. Sanitize the binary against an embedded-substring deny list.
2. Re-apply the linker's adhoc signature on macOS (the rewrite invalidates
   the original signature, which the kernel would otherwise reject at
   `exec`).
3. Smoke-test a round-trip through the CLI.

```
./scripts/release.sh
```

The script exits non-zero on any check failure and prints the SHA-256
of the final binary on success.

## Verifying a binary

```
./scripts/check_strings.sh target/release/imgutil
shasum -a 256        target/release/imgutil
```

Expected output of `check_strings.sh`:

```
PASS: no forbidden strings in target/release/imgutil
```

The SHA-256 of a binary built locally on the same toolchain version, OS,
and architecture should be reproducible. Reproducing across machines
requires the same Rust version, the same `Cargo.lock` (committed), and
the same target triple. A reference value from a known build:

```
3905b7b797d6d041a2af7e698da94e4634aa79722728c21ae2dbec45be5ca5f1
target/release/imgutil  (aarch64-apple-darwin, rustc 1.95.0)
```

## Running tests

```
cargo test --release
cargo test --release -- --include-ignored   # also runs the 100MB round-trip
```

## Fuzzing

Three fuzz harnesses live under `fuzz/`. They require nightly Rust and
`cargo-fuzz`:

```
cargo install cargo-fuzz
cargo +nightly fuzz run png_parse
cargo +nightly fuzz run single_decode
cargo +nightly fuzz run multi_decode
```

Each harness must terminate with `Ok` or `Err` for any input — never panic.

## Dependencies

Pinned in `Cargo.lock`. Audited via:

```
cargo install cargo-audit
cargo audit
```
