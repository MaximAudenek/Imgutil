#![deny(clippy::unwrap_used, clippy::expect_used)]

mod codec;
mod crypto;
mod error;
mod fs_ops;
mod memory;
mod png_io;
mod resolution;

pub use codec::{
    decode_multi, decode_multi_streaming, decode_single, decode_stream, encode_multi,
    encode_multi_streaming, encode_single, encode_stream,
};
pub use error::Error;
pub use fs_ops::{
    decode_dir_to_file, decode_dir_to_file_with_progress, decode_file_to_file,
    decode_file_to_file_with_progress, encode_file_to_dir, encode_file_to_dir_with_progress,
};

pub use zeroize::Zeroizing;
