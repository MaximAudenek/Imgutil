use std::io::Cursor;

use imgutil::{Zeroizing, decode_single, decode_stream, encode_single, encode_stream};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

fn deterministic_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

#[test]
fn stream_roundtrip_at_chunk_boundary() {
    for len in [0usize, 1, 32, 64 * 1024 - 1, 64 * 1024, 64 * 1024 + 1] {
        let payload = deterministic_payload(len, len as u64);
        let png = encode_stream(Cursor::new(&payload), len as u64, pw("pw")).unwrap();

        let mut out: Vec<u8> = Vec::new();
        decode_stream(&png, pw("pw"), &mut out).unwrap();
        assert_eq!(payload, out, "round-trip failed at len={len}");
    }
}

#[test]
fn stream_and_single_apis_interoperate() {
    let payload = deterministic_payload(200_000, 7);
    // encode via stream, decode via single
    let png = encode_stream(Cursor::new(&payload), payload.len() as u64, pw("k")).unwrap();
    let decoded = decode_single(&png, pw("k")).unwrap();
    assert_eq!(payload, decoded[..]);

    // encode via single, decode via stream
    let png2 = encode_single(&payload, pw("k")).unwrap();
    let mut out2: Vec<u8> = Vec::new();
    decode_stream(&png2, pw("k"), &mut out2).unwrap();
    assert_eq!(payload, out2);
}

#[test]
fn stream_roundtrip_8mb() {
    let payload = deterministic_payload(8 * 1024 * 1024, 42);
    let png = encode_stream(Cursor::new(&payload), payload.len() as u64, pw("hunter2")).unwrap();

    let mut out: Vec<u8> = Vec::new();
    decode_stream(&png, pw("hunter2"), &mut out).unwrap();
    assert_eq!(payload.len(), out.len());
    assert_eq!(payload, out);
}

#[test]
fn stream_wrong_password_fails() {
    let payload = deterministic_payload(200_000, 1);
    let png = encode_stream(Cursor::new(&payload), payload.len() as u64, pw("right")).unwrap();
    let mut out: Vec<u8> = Vec::new();
    let result = decode_stream(&png, pw("wrong"), &mut out);
    assert!(matches!(result, Err(imgutil::Error::Verification)));
    // On verification failure, no plaintext should have been written to the sink.
    assert!(out.is_empty(), "decode_stream wrote plaintext before MAC verify");
}

#[test]
fn stream_tampered_ciphertext_rejected_before_any_output() {
    let payload = deterministic_payload(50_000, 9);
    let mut png = encode_stream(Cursor::new(&payload), payload.len() as u64, pw("p")).unwrap();
    // Flip a byte deep in the file (likely lands in IDAT data).
    let target = 5000.min(png.len() - 1);
    png[target] ^= 0x01;

    let mut out: Vec<u8> = Vec::new();
    let result = decode_stream(&png, pw("p"), &mut out);
    assert!(matches!(
        result,
        Err(imgutil::Error::Format) | Err(imgutil::Error::Verification)
    ));
    assert!(out.is_empty(), "tampered input must not yield partial plaintext");
}
