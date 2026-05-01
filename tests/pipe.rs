//! Tests for the pipe-support addition: encode from a Read source and
//! decode to a Write sink. These exercise the library functions directly
//! since stdin / stdout testing at the CLI level is constrained by the
//! password-prompt path. CLI tests for the --out - flag live in tests/cli.rs.

use std::io::{Cursor, Write};
use std::process::{Command, Stdio};

use imgutil::{
    Zeroizing, decode_dir_to_file, decode_dir_to_writer_with_progress, decode_single,
    encode_file_to_dir, encode_reader_to_dir_with_progress,
};

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_imgutil")
}

#[test]
fn pipe_encode_from_reader_decode_to_file_roundtrip() {
    // stdin → file equivalent: encode_reader_to_dir_with_progress emulates
    // the path the CLI takes when --in is omitted.
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    let decoded = dir.path().join("decoded.bin");

    let payload: Vec<u8> = (0u32..120_000).map(|i| (i & 0xff) as u8).collect();
    let cursor = Cursor::new(payload.clone());
    let count = encode_reader_to_dir_with_progress(
        cursor,
        payload.len() as u64,
        &out_dir,
        pw("pipe-roundtrip"),
        |_, _| {},
    )
    .unwrap();
    assert_eq!(count, 1);

    decode_dir_to_file(&out_dir, &decoded, pw("pipe-roundtrip")).unwrap();
    let recovered = std::fs::read(&decoded).unwrap();
    assert_eq!(payload, recovered, "stdin→file round-trip mismatch");
}

#[test]
fn pipe_encode_from_file_decode_to_writer_roundtrip() {
    // file → stdout equivalent: decode_dir_to_writer_with_progress writes
    // to any Write sink (tests use a Vec<u8>).
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    let payload: Vec<u8> = b"file -> writer round-trip pipe payload".to_vec();
    std::fs::write(&in_path, &payload).unwrap();

    encode_file_to_dir(&in_path, &out_dir, pw("k")).unwrap();

    let mut sink: Vec<u8> = Vec::new();
    decode_dir_to_writer_with_progress(&out_dir, &mut sink, pw("k"), |_, _| {}).unwrap();
    assert_eq!(payload, sink, "file→writer round-trip mismatch");
}

#[test]
fn pipe_encode_from_reader_decode_to_writer_roundtrip() {
    // stdin → stdout equivalent: both ends are non-file streams.
    let dir = tempfile::tempdir().unwrap();
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();

    let payload: Vec<u8> = (0u32..40_000).map(|i| (i.wrapping_mul(7) & 0xff) as u8).collect();
    let cursor = Cursor::new(payload.clone());
    encode_reader_to_dir_with_progress(
        cursor,
        payload.len() as u64,
        &out_dir,
        pw("k"),
        |_, _| {},
    )
    .unwrap();

    let mut sink: Vec<u8> = Vec::new();
    decode_dir_to_writer_with_progress(&out_dir, &mut sink, pw("k"), |_, _| {}).unwrap();
    assert_eq!(payload, sink, "stdin→stdout round-trip mismatch");
}

#[test]
fn pipe_decode_to_writer_wrong_password_yields_no_output() {
    // MAC verification (phase 1 of decode_multi_streaming) runs to completion
    // before phase 3 begins writing, so an auth failure must not leak any
    // partial plaintext to the writer.
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, b"sensitive plaintext").unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw("right")).unwrap();

    let mut sink: Vec<u8> = Vec::new();
    let result = decode_dir_to_writer_with_progress(&out_dir, &mut sink, pw("wrong"), |_, _| {});
    assert!(matches!(result, Err(imgutil::Error::Verification)));
    assert!(sink.is_empty(), "wrong password leaked plaintext to writer");
}

// ---- CLI-level tests ----

fn encode_dir_for_cli(payload: &[u8], password: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, payload).unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw(password)).unwrap();
    dir
}

#[test]
fn cli_extract_to_stdout_emits_payload_bytes_and_silent_stderr() {
    // Encode via library so the CLI invocation only exercises the new
    // --out - path. Pipe the password via stdin and capture stdout +
    // stderr separately. On success: stdout = exact payload bytes, stderr
    // contains only the "Password: " prompt — no progress, no path
    // message.
    let payload = b"binary\x00stream\xffwith-non-utf8\x01bytes";
    let dir = encode_dir_for_cli(payload, "stdoutpw");
    let out_dir = dir.path().join("encoded");

    let mut child = Command::new(binary())
        .args([
            "extract",
            "--in-dir",
            out_dir.to_str().unwrap(),
            "--out",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"stdoutpw\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success(), "extract --out - exited non-zero");
    assert_eq!(out.stdout, payload, "stdout payload mismatch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The only thing on stderr should be the password prompt.
    assert_eq!(
        stderr.as_ref(),
        "Password: ",
        "stderr must contain only the password prompt; got: {stderr:?}"
    );
}

#[test]
fn cli_extract_to_stdout_via_single_png_variant() {
    let payload = b"single PNG to stdout";
    let dir = encode_dir_for_cli(payload, "single");
    let out_dir = dir.path().join("encoded");
    let chunk_path = out_dir.join("chunk_0001.png");

    let mut child = Command::new(binary())
        .args([
            "extract",
            "--in",
            chunk_path.to_str().unwrap(),
            "--out",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"single\n").unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    assert_eq!(out.stdout, payload);
}

#[test]
fn cli_extract_to_stdout_wrong_password_fails_with_empty_stdout() {
    let payload = b"plaintext-must-not-appear";
    let dir = encode_dir_for_cli(payload, "right");
    let out_dir = dir.path().join("encoded");

    let mut child = Command::new(binary())
        .args([
            "extract",
            "--in-dir",
            out_dir.to_str().unwrap(),
            "--out",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"wrong\n").unwrap();
    let out = child.wait_with_output().unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty on auth failure; got {} bytes",
        out.stdout.len(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Authentication failed."),
        "expected auth-failed message; got: {stderr:?}"
    );
}

#[test]
fn cli_decode_to_stdout_then_decode_via_decode_single_match() {
    // Belt-and-braces: roundtrip the payload by piping through cat (via Vec
    // capture) and confirm a separate library decode produces the same
    // bytes. Catches any accidental stdout munging (newlines, encoding).
    let payload: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
    let dir = encode_dir_for_cli(&payload, "k");
    let out_dir = dir.path().join("encoded");
    let chunk_path = out_dir.join("chunk_0001.png");

    let mut child = Command::new(binary())
        .args([
            "extract",
            "--in",
            chunk_path.to_str().unwrap(),
            "--out",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"k\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, payload);

    // Independent library decode must yield the same bytes.
    let png = std::fs::read(&chunk_path).unwrap();
    let lib_decoded = decode_single(&png, pw("k")).unwrap();
    assert_eq!(out.stdout, lib_decoded[..]);
}
