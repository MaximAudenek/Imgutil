#![no_main]

// PNG parsing fuzz target: exercise the chunk-validating PNG reader on
// arbitrary bytes. Must never panic — only return Ok or Err.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = imgutil::__fuzz::read_pixels(data);
});
