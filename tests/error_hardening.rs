use std::path::PathBuf;

use imgutil::{
    Error, Zeroizing, decode_dir_to_file, decode_file_to_file, decode_single, encode_file_to_dir,
    encode_single,
};

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

#[test]
fn user_message_wrong_password() {
    let png = encode_single(b"sensitive data", pw("right")).unwrap();
    let err = decode_single(&png, pw("wrong")).unwrap_err();
    assert_eq!(err.user_message(), "Authentication failed.");
}

#[test]
fn user_message_bit_flip() {
    let mut png = encode_single(b"some payload here for tampering", pw("p")).unwrap();
    let target = 200.min(png.len() - 1);
    png[target] ^= 0x01;
    let err = decode_single(&png, pw("p")).unwrap_err();
    // Either Format (PNG CRC/inflate) or Verification (AEAD) — both map to
    // "Authentication failed.", which is the security-critical guarantee.
    assert_eq!(err.user_message(), "Authentication failed.");
}

#[test]
fn user_message_non_png_input() {
    let bogus = vec![0u8; 100];
    let err = decode_single(&bogus, pw("p")).unwrap_err();
    assert_eq!(err.user_message(), "Authentication failed.");
}

#[test]
fn user_message_invalid_args() {
    let err = Error::InvalidArgs;
    assert_eq!(err.user_message(), "Invalid arguments.");
}

#[test]
fn user_message_capacity() {
    let err = Error::Capacity;
    assert_eq!(err.user_message(), "An error occurred.");
}

#[test]
fn user_message_internal() {
    let err = Error::Internal;
    assert_eq!(err.user_message(), "An error occurred.");
}

#[test]
fn user_message_read_io() {
    let err = Error::ReadIo(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
    assert_eq!(err.user_message(), "Could not read file.");
}

#[test]
fn user_message_write_io() {
    let err = Error::WriteIo(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test"));
    assert_eq!(err.user_message(), "Could not write file.");
}

#[test]
fn display_uses_user_message() {
    // Display impl must NOT leak descriptive internal messages — release
    // builds rely on this for OPSEC.
    let err = Error::Verification;
    assert_eq!(format!("{err}"), "Authentication failed.");
}

#[test]
fn file_encode_decode_roundtrip_via_filesystem() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    let decoded_path = dir.path().join("decoded.bin");
    std::fs::create_dir_all(&out_dir).unwrap();

    let payload: Vec<u8> = (0u32..50_000).map(|i| (i & 0xff) as u8).collect();
    std::fs::write(&in_path, &payload).unwrap();

    let n = encode_file_to_dir(&in_path, &out_dir, pw("filepass")).unwrap();
    assert_eq!(n, 1);
    assert!(out_dir.join("chunk_0001.png").exists());

    decode_dir_to_file(&out_dir, &decoded_path, pw("filepass")).unwrap();
    let recovered = std::fs::read(&decoded_path).unwrap();
    assert_eq!(payload, recovered);
}

#[test]
fn file_encode_refuses_to_overwrite_existing_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, b"hello").unwrap();
    // Plant a colliding file.
    std::fs::write(out_dir.join("chunk_0001.png"), b"existing").unwrap();

    let result = encode_file_to_dir(&in_path, &out_dir, pw("k"));
    assert!(matches!(result, Err(Error::InvalidArgs)));
    assert_eq!(result.unwrap_err().user_message(), "Invalid arguments.");
}

#[test]
fn file_decode_refuses_to_overwrite_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    let decoded_path = dir.path().join("decoded.bin");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, b"hello").unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw("k")).unwrap();
    // Pre-create the output file.
    std::fs::write(&decoded_path, b"existing").unwrap();

    let result = decode_dir_to_file(&out_dir, &decoded_path, pw("k"));
    assert!(matches!(result, Err(Error::InvalidArgs)));
    // Pre-existing file was not touched.
    let kept = std::fs::read(&decoded_path).unwrap();
    assert_eq!(kept, b"existing");
}

#[test]
fn file_decode_failure_shreds_and_deletes_output() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    let decoded_path = dir.path().join("decoded.bin");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, b"sensitive plaintext for this test").unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw("right_password")).unwrap();

    // Decode with the wrong password — must fail and clean up.
    let result = decode_dir_to_file(&out_dir, &decoded_path, pw("wrong_password"));
    assert!(matches!(result, Err(Error::Verification)));
    assert_eq!(result.unwrap_err().user_message(), "Authentication failed.");
    assert!(
        !decoded_path.exists(),
        "output file must be deleted after decode failure",
    );
}

#[test]
fn file_decode_single_png_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    let decoded_path = dir.path().join("decoded.bin");
    std::fs::create_dir_all(&out_dir).unwrap();
    let payload: Vec<u8> = b"single chunk file API test payload".to_vec();
    std::fs::write(&in_path, &payload).unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw("k")).unwrap();

    // Use the single-PNG decode entry point.
    let chunk_path: PathBuf = out_dir.join("chunk_0001.png");
    decode_file_to_file(&chunk_path, &decoded_path, pw("k")).unwrap();
    let recovered = std::fs::read(&decoded_path).unwrap();
    assert_eq!(payload, recovered);
}

#[test]
fn file_decode_dir_with_unrelated_png_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let in_path = dir.path().join("input.bin");
    let out_dir = dir.path().join("encoded");
    let decoded_path = dir.path().join("decoded.bin");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&in_path, b"primary data").unwrap();
    encode_file_to_dir(&in_path, &out_dir, pw("primary")).unwrap();

    // Plant an unrelated PNG (encrypted with a different password) in the
    // same directory. decode_dir_to_file must silently skip it.
    let stranger = encode_single(b"different secret", pw("other")).unwrap();
    std::fs::write(out_dir.join("zzz_unrelated.png"), &stranger).unwrap();

    decode_dir_to_file(&out_dir, &decoded_path, pw("primary")).unwrap();
    let recovered = std::fs::read(&decoded_path).unwrap();
    assert_eq!(recovered, b"primary data");
}

#[test]
fn file_decode_missing_input_dir() {
    let dir = tempfile::tempdir().unwrap();
    let nonexistent = dir.path().join("nope");
    let out_path = dir.path().join("decoded.bin");
    let result = decode_dir_to_file(&nonexistent, &out_path, pw("k"));
    assert!(matches!(result, Err(Error::InvalidArgs)));
}

#[test]
fn file_encode_missing_input_file() {
    let dir = tempfile::tempdir().unwrap();
    let nonexistent = dir.path().join("nope.bin");
    let out_dir = dir.path().join("encoded");
    std::fs::create_dir_all(&out_dir).unwrap();
    let result = encode_file_to_dir(&nonexistent, &out_dir, pw("k"));
    assert!(matches!(result, Err(Error::ReadIo(_))));
    assert_eq!(result.unwrap_err().user_message(), "Could not read file.");
}
