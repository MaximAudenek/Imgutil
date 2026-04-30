#![deny(clippy::unwrap_used, clippy::expect_used)]

mod codec;
mod crypto;
mod error;
mod fs_ops;
mod memory;
mod png_io;
mod resolution;

pub use codec::{
    decode_multi, decode_single, decode_stream, encode_multi, encode_single, encode_stream,
};
pub use error::Error;
pub use fs_ops::{decode_dir_to_file, decode_file_to_file, encode_file_to_dir};

pub use zeroize::Zeroizing;
