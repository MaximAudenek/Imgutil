use imgutil::{Zeroizing, decode_single, encode_single};

fn pw(s: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.as_bytes().to_vec())
}

#[test]
fn roundtrip_small_payload() {
    let payload: &[u8] =
        b"The quick brown fox jumps over the lazy dog. 0123456789 !@#$%^&*()";
    let png = encode_single(payload, pw("correct horse battery staple")).unwrap();

    // Sanity: PNG must start with PNG signature.
    assert_eq!(&png[..8], &[137, 80, 78, 71, 13, 10, 26, 10]);

    let decoded = decode_single(&png, pw("correct horse battery staple")).unwrap();
    assert_eq!(payload, &decoded[..]);
}

#[test]
fn roundtrip_empty_payload() {
    let payload: &[u8] = b"";
    let png = encode_single(payload, pw("p")).unwrap();
    let decoded = decode_single(&png, pw("p")).unwrap();
    assert_eq!(payload, &decoded[..]);
}

#[test]
fn wrong_password_fails_with_verification() {
    let payload: &[u8] = b"sensitive data";
    let png = encode_single(payload, pw("right password")).unwrap();
    let result = decode_single(&png, pw("wrong password"));
    assert!(matches!(result, Err(imgutil::Error::Verification)));
}

#[test]
fn single_bit_flip_fails() {
    let payload: &[u8] = b"some bytes here for tampering";
    let mut png = encode_single(payload, pw("pw")).unwrap();
    // Flip a bit somewhere deep in the IDAT region (after the header bytes).
    // The PNG signature is 8 bytes, then IHDR chunk = 4+4+13+4 = 25 bytes.
    // Flip a byte at offset 200 which lands inside an IDAT chunk.
    let target = 200.min(png.len() - 1);
    png[target] ^= 0x01;
    let result = decode_single(&png, pw("pw"));
    // Either the PNG decoder rejects (Format) due to CRC/inflate error,
    // or the AEAD rejects (Verification). Both are acceptable failure modes;
    // both produce a generic outcome to the caller.
    assert!(matches!(
        result,
        Err(imgutil::Error::Format) | Err(imgutil::Error::Verification)
    ));
}

#[test]
fn non_png_input_rejected() {
    let bogus = vec![0u8; 100];
    let result = decode_single(&bogus, pw("pw"));
    assert!(matches!(result, Err(imgutil::Error::Format)));
}
