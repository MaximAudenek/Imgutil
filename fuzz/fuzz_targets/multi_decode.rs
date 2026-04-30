#![no_main]

// Multi-image assembly fuzz target: split the input into 1..=8 pseudo-PNG
// chunks and feed them to decode_multi. Exercises the silent-skip path,
// session-id grouping, chunk-count / index validation, and the partial-
// payload computation. Must always return Err and never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let chunk_count = (usize::from(data[0]) % 8) + 1;
    let body = &data[1..];
    let chunk_size = body.len() / chunk_count;
    if chunk_size == 0 {
        return;
    }
    let mut chunks: Vec<&[u8]> = Vec::with_capacity(chunk_count);
    for i in 0..chunk_count {
        let start = i * chunk_size;
        let end = start + chunk_size;
        chunks.push(&body[start..end]);
    }
    let pw = imgutil::Zeroizing::new(b"fuzz_password".to_vec());
    let mut out: Vec<u8> = Vec::new();
    let _ = imgutil::decode_multi(&chunks, pw, &mut out);
});
