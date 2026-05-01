# imgutil

A fast, minimal PNG image processing utility for macOS and Linux.

## Features

- Generates high-quality noise images at standard resolutions
- Processes files of any size — from a few bytes to multiple gigabytes
- Splits large inputs across multiple output images automatically
- Streams data in fixed chunks — RAM usage stays flat regardless of input size
- Outputs clean PNG files with no embedded metadata
- Supports standard Unix piping

## Installation

### Build from source

Requires Rust 1.70+.

```bash
git clone https://github.com/MaximAudenek/Imgutil.git
cd Imgutil
./scripts/release.sh
cp target/release/imgutil /usr/local/bin/imgutil
```

### Verify binary integrity

```bash
sha256sum target/release/imgutil
```

Expected hash (aarch64-apple-darwin, Cargo.lock pinned):
```
3905b7b797d6d041a2af7e698da94e4634aa79722728c21ae2dbec45be5ca5f1
```

## Usage

### Generate images from a file

```bash
imgutil generate --in <file> --out-dir <directory>
```

Output images are named `chunk_0001.png`, `chunk_0002.png`, and so on.
The smallest standard resolution that fits the input is chosen automatically.

Supported output resolutions:
- 1280×720
- 1920×1080
- 2560×1440
- 3840×2160
- 7680×4320

### Extract file from images

```bash
# From a directory of chunks:
imgutil extract --in-dir <directory> --out <file>

# From a single image:
imgutil extract --in <file.png> --out <file>
```

### Pipe support

Read from stdin:
```bash
cat input.wav | imgutil generate --out-dir ./output/
curl https://example.com/file | imgutil generate --out-dir ./output/
```

Write to stdout:
```bash
imgutil extract --in-dir ./output/ --out -
imgutil extract --in-dir ./output/ --out - | mpv -
imgutil extract --in-dir ./output/ --out - | nc 192.168.1.5 4444
```

Full pipe chain:
```bash
cat input.txt | imgutil generate --out-dir ./output/
imgutil extract --in-dir ./output/ --out - | cat
```

## Notes

- Output directory must not already contain chunk files — imgutil never overwrites
- Input files of any format are supported (binary, text, audio, video, archives)
- When decoding, unrelated files in the input directory are silently ignored
- The output file type is not preserved — the recipient should know the expected format,
  or wrap the input in a zip before processing

## Security

- Inputs and outputs are processed in 64 KB chunks — the full payload is never loaded into RAM
- Sensitive material is zeroed from memory immediately after use
- Memory pages are locked via `mlock()` on Linux/macOS and `VirtualLock()` on Windows
  where available, to prevent sensitive data from being written to swap
- If memory locking is unavailable, a warning is printed to stderr
- All output PNG files contain only `IHDR`, `IDAT`, and `IEND` chunks — no metadata

## Building and testing

```bash
# Run all tests
cargo test --release

# Check for dependency vulnerabilities
cargo audit

# Full release pipeline (build, verify, smoke test)
./scripts/release.sh
```

## Requirements

- Rust 1.70+
- macOS or Linux (Windows supported with reduced memory-locking guarantees)

## License

MIT
