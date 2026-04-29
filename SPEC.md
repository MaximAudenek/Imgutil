# imgutil — Full Specification

You are implementing a steganographic encoder/decoder in Rust.
Security is the highest priority — never trade security for
convenience or brevity. The algorithm's security relies entirely
on the key — assume the algorithm itself is fully public
(Kerckhoffs's principle).

## What you are building
A CLI tool (binary name: `imgutil`) that encodes arbitrary binary
payloads into PNG images appearing as random noise, and decodes
them back. Output must be statistically indistinguishable from
genuine random noise images. The tool must never reveal its
steganographic purpose through any user-facing interface,
including help text, error messages, or binary strings.

## CLI Interface

    imgutil generate --in <file> --out-dir <directory>
    imgutil extract --in-dir <directory> --out <file>
    imgutil extract --in <single.png> --out <file>

--help text must describe this as a "PNG image processing
utility". No steganographic, cryptographic, or encoding
terminology in any user-facing string including help text,
error messages, or prompts. All crypto-related strings in
source code that could be embedded in the binary must use
indirection or be stripped by the release profile.

Password is always read via rpassword from stdin.
The prompt shown to user must always be exactly "Password: "
— never include filenames, operation type, or any other
context in the prompt string.
Never accept passwords as CLI arguments — they appear in
shell history and /proc/<pid>/cmdline.

Progress reporting goes to stderr only, never stdout, so it
does not pollute piped output. Show a progress bar or
percentage for operations taking more than 2 seconds.

On successful encode: print only chunk count and output
directory path to stderr.
On successful decode: print only output file path to stderr.
Nothing else.

## Algorithm

### Key Derivation (per image, not per session)
Each PNG image carries its own 32-byte nonce. Key derivation
is performed independently per image using that image's nonce:

    key = Argon2id(password_bytes, salt=nonce, m=65536, t=3, p=1)
    → 32-byte key

Password is read from stdin exactly once. For multi-image
operations, re-derive the key for each image using that
image's stored nonce — do not reuse the key across images.
Zeroize password immediately after first key derivation.
Store password bytes in a Zeroize-protected buffer only.

ChaCha20-Poly1305 uses:
  - cipher key: the 32-byte derived key
  - cipher nonce: first 12 bytes of the 32-byte nonce

Argon2id uses:
  - salt: full 32-byte nonce

These overlap intentionally — both derived from same entropy source.

### Encoding
1. Read password → zeroize after first key derivation
2. Generate 128-bit session ID via rand::thread_rng()
3. Calculate total payload size, determine chunk boundaries
   based on chosen image resolutions
4. For each chunk:
   a. Generate fresh 32-byte nonce via rand::thread_rng()
      (each chunk gets its own unique nonce)
   b. Derive key = Argon2id(password, this_chunk_nonce)
   c. Construct plaintext blob:
        [16 bytes: session ID]
        [4 bytes:  chunk index, little-endian]
        [4 bytes:  total chunk count, little-endian]
        [8 bytes:  total payload byte length, little-endian]
                   (meaningful in chunk 0; zero-filled in others)
        [N bytes:  payload chunk bytes]
   d. Encrypt blob with ChaCha20-Poly1305 → ciphertext + MAC
   e. Choose smallest standard resolution whose pixel capacity
      fits the ciphertext:
        1280×720, 1920×1080, 2560×1440, 3840×2160, 7680×4320
      If payload chunk exceeds 7680×4320 capacity, split further.
   f. Pad ciphertext to exactly image pixel capacity with
      rand::thread_rng() random bytes
   g. Store 32-byte nonce: pixels 0–31, R channel only,
      1 byte per pixel; G and B channels of these pixels
      filled with rand::thread_rng()
   h. Store padded ciphertext in remaining pixels sequentially:
      R then G then B per pixel, left to right, top to bottom
   i. Write PNG with ONLY IHDR + IDAT + IEND chunks.
      No tEXt, no tIME, no bKGD, no metadata chunks whatsoever.
   j. Output filename: chunk_0001.png, chunk_0002.png, etc.
   k. Zeroize key and ALL intermediate buffers before next chunk
5. Before writing any output file: if chunk_XXXX.png already
   exists in output directory, abort with error — never
   silently overwrite

### Decoding
1. Collect all .png files from input directory or single file
   (max 9999 files — reject and error if exceeded)
2. Read password from stdin once into Zeroize-protected buffer
3. For each PNG found:
   a. Validate file: reject if contains any chunk other than
      IHDR, IDAT, IEND
   b. Validate dimensions: reject if not one of our five
      standard resolutions
   c. Read 32-byte nonce from pixels 0–31, R channel only
   d. Derive key = Argon2id(password, this_image's_nonce)
   e. Read remaining pixel data sequentially into ciphertext buffer
   f. Attempt ChaCha20-Poly1305 decrypt + MAC verify
   g. On MAC failure: zeroize key and ciphertext buffer,
      skip this file silently
   h. On success: extract (session_id, chunk_index,
      total_chunks, payload_length if chunk 0, data)
   i. Zeroize key and ciphertext buffer before next image
4. Zeroize password buffer
5. Group successfully decrypted chunks by session_id
6. If zero chunks decrypted → "Authentication failed."
7. If multiple distinct session IDs found → "Authentication failed."
8. Verify chunk count: number of chunks must equal total_chunks
   value → else "Authentication failed."
9. Sort chunks by chunk_index (0-based)
10. Verify no gaps in chunk_index sequence → else error
11. Read total payload length from chunk 0 header
12. Validate payload_length is plausible given chunk count
    and image sizes → else "Authentication failed."
13. Assemble chunks in order, write exactly payload_length
    bytes to output file
14. On ANY failure after output file is created: overwrite
    entire partial output file with rand::thread_rng() bytes,
    then delete it. Verify deletion succeeded.
15. Zeroize all assembled data buffers

## Security Requirements (non-negotiable)

### Memory
- zeroize crate on ALL sensitive types using Zeroize derive
  macro: password buffer, key buffer, plaintext blob,
  ciphertext buffer, assembled payload, all intermediate
  structs holding any of the above
- secrecy crate Secret<> wrapper for key material
- subtle crate ConstantTimeEq for any comparison involving
  key material, MAC tags, or session IDs
- #[inline(never)] on ALL functions that touch key material
- Never load full payload into RAM — process in 64KB chunks.
  At no point should more than one 64KB chunk of plaintext
  exist in RAM simultaneously
- Attempt mlock() on Linux/macOS for key buffer pages to
  prevent swap. Use VirtualLock() on Windows.
  If neither succeeds, print to stderr:
  "Warning: memory could not be locked. Ensure swap is encrypted."
  Then continue.

### Input Validation
- Validate PNG dimensions before any allocation
- Reject any PNG with dimensions not exactly matching one
  of our five standard resolutions
- Reject any PNG containing chunks other than IHDR, IDAT, IEND
- Cap PNG file count in directory decode to 9999
- Validate all length fields in decrypted blob before using:
  chunk_index < total_chunks, payload_length plausible given
  chunk count and image sizes

### Error Messages
All user-facing error messages must be generic and
information-neutral. Never distinguish between:
  - wrong password
  - corrupted image
  - not a stego image
  - wrong chunk count
  - missing chunks
  - tampered image

Authentication/integrity failures → "Authentication failed."
File read errors                  → "Could not read file."
File write errors                 → "Could not write file."
Invalid arguments                 → "Invalid arguments." + usage
All other errors                  → "An error occurred."

Internal error types may be descriptive for developer use
but must NEVER reach user-facing output in release builds.

### OPSEC
- Binary name: imgutil
- All user-facing strings: no crypto, encoding, or
  steganography terminology
- --help describes: "PNG image processing utility"
- strip = true in release profile eliminates debug strings
- Verify: `strings imgutil | grep -iE "stego|encod|crypto|cipher|argon|chacha|secret"`
  must return nothing in release build
- Make this grep check part of the build verification step

### Build Hardening
```toml
[profile.release]
strip = true
opt-level = "s"
lto = true
codegen-units = 1
panic = "abort"
```

- Commit Cargo.lock to repository — pins exact dependency
  versions for reproducible builds
- Document in README: sha256sum of release binary, how to
  verify, how to reproduce the build exactly
- Add cargo-fuzz targets covering:
    - PNG parsing path with malformed inputs
    - Decoder path with corrupted ciphertext
    - Blob assembly with mismatched chunk counts
- Run `cargo audit` before any code is written
- Run `cargo clippy -- -D warnings` — zero warnings policy

## Crates (exact versions)
```toml
chacha20poly1305 = "0.10"
argon2           = "0.5"
zeroize          = { version = "1.7", features = ["derive"] }
secrecy          = "0.8"
subtle           = "2.5"
rand             = "0.8"
png              = "0.17"
rpassword        = "7.3"
clap             = { version = "4.4", features = ["derive"] }
indicatif        = "0.17"
```

Run `cargo audit` before writing any code. If any crate has
a known vulnerability, stop and report it — do not proceed.

## Build Order
Build in this exact order. Do not skip steps. Do not proceed
to the next step until the current step's tests pass and
clippy is clean.

### Step 1 — Core Codec
Encode and decode a single small file end-to-end.
All memory security requirements met from the start.
Round-trip test: encode file → decode → verify byte-for-byte identical.
`cargo clippy -- -D warnings`: zero warnings.
`cargo audit`: zero vulnerabilities.

### Step 2 — Streaming
64KB chunk processing throughout encode and decode paths.
Verify via test that RAM usage does not scale with payload size.
Round-trip test with 100MB file.

### Step 3 — Multi-Image
Splitting, per-chunk nonces, session ID, assembly, ordering,
chunk validation.
Round-trip test with file requiring exactly 3 chunks.
Test: shuffled chunk order still assembles correctly.

### Step 4 — Error Hardening
Every error path zeroizes correctly and produces generic message.
Tests:
  - Wrong password → "Authentication failed."
  - Single bit flipped in image → "Authentication failed."
  - Missing chunk → "Authentication failed."
  - Extra unrelated PNG in directory → handled gracefully
  - Partial output file on failure → overwritten and deleted

### Step 5 — CLI
clap subcommands, rpassword integration, indicatif progress bar,
output directory collision detection (abort if chunk file exists).

### Step 6 — OPSEC Verification
- strings check on release binary (grep must return nothing)
- cargo-fuzz targets written and run
- README with reproducible build instructions and binary sha256sum
