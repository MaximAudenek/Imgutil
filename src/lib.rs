#![deny(clippy::unwrap_used, clippy::expect_used)]

mod aead;
mod codec;
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

#[doc(hidden)]
#[cfg(feature = "__fuzz")]
pub mod __fuzz {
    //! Direct access to internal entry points for the fuzz harnesses in
    //! `fuzz/`. Gated behind the `__fuzz` feature; not part of the public
    //! API.
    pub use crate::png_io::read_pixels;
}
