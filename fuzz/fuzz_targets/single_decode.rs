#![no_main]

// Single-image decode fuzz target: feed arbitrary bytes as a candidate PNG
// to decode_single. Must always return Err and never panic — Argon2id is
// invoked once per iteration so this target is slower than png_parse, but
// it covers the full ciphertext path including AEAD verify.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let pw = imgutil::Zeroizing::new(b"fuzz_password".to_vec());
    let _ = imgutil::decode_single(data, pw);
});
