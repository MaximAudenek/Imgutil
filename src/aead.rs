use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use poly1305::universal_hash::{KeyInit as _, UniversalHash};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::memory;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;
pub const POLY_KEY_LEN: usize = 32;
pub const POLY_BLOCK_LEN: usize = 16;

const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

#[inline(never)]
pub fn derive_key(password: &[u8], salt: &[u8; NONCE_LEN]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut key = Zeroizing::new(vec![0u8; KEY_LEN]);
    memory::try_lock(&key);
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
        .map_err(|_| Error::Internal)?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    kdf.hash_password_into(password, salt, &mut key)
        .map_err(|_| Error::Internal)?;
    Ok(key)
}

pub struct Cipher {
    inner: ChaCha20,
}

impl Cipher {
    #[inline(never)]
    pub fn new(
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(Self, Zeroizing<[u8; POLY_KEY_LEN]>), Error> {
        if key.len() != KEY_LEN {
            return Err(Error::Internal);
        }
        let mut inner =
            ChaCha20::new_from_slices(key, &nonce[..12]).map_err(|_| Error::Internal)?;
        let mut block0 = Zeroizing::new([0u8; 64]);
        // Use the fallible variant — `apply_keystream` calls `unwrap()` on
        // the result, which embeds a Display string in the binary that
        // matches the OPSEC strings check. The fallible call is dead-code
        // friendly.
        inner
            .try_apply_keystream(&mut *block0)
            .map_err(|_| Error::Internal)?;
        let mut otk = Zeroizing::new([0u8; POLY_KEY_LEN]);
        otk.copy_from_slice(&block0[..POLY_KEY_LEN]);
        Ok((Self { inner }, otk))
    }

    #[inline(never)]
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.inner
            .try_apply_keystream(buf)
            .map_err(|_| Error::Internal)
    }
}

pub struct Mac {
    poly: Poly1305,
    residual: [u8; POLY_BLOCK_LEN],
    residual_len: usize,
    total: u64,
}

impl Mac {
    #[inline(never)]
    pub fn new(otk: &[u8; POLY_KEY_LEN]) -> Self {
        Self {
            poly: Poly1305::new(otk.into()),
            residual: [0u8; POLY_BLOCK_LEN],
            residual_len: 0,
            total: 0,
        }
    }

    #[inline(never)]
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.saturating_add(data.len() as u64);

        if self.residual_len > 0 {
            let need = POLY_BLOCK_LEN - self.residual_len;
            let take = need.min(data.len());
            self.residual[self.residual_len..self.residual_len + take]
                .copy_from_slice(&data[..take]);
            self.residual_len += take;
            data = &data[take..];
            if self.residual_len == POLY_BLOCK_LEN {
                let block_arr = self.residual;
                self.poly.update(&[block_arr.into()]);
                self.residual.zeroize();
                self.residual_len = 0;
            }
        }

        let mut block = [0u8; POLY_BLOCK_LEN];
        let mut chunks = data.chunks_exact(POLY_BLOCK_LEN);
        for chunk in &mut chunks {
            block.copy_from_slice(chunk);
            self.poly.update(&[block.into()]);
        }
        block.zeroize();

        let tail = chunks.remainder();
        if !tail.is_empty() {
            self.residual[..tail.len()].copy_from_slice(tail);
            self.residual_len = tail.len();
        }
    }

    #[inline(never)]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.residual_len > 0 {
            for i in self.residual_len..POLY_BLOCK_LEN {
                self.residual[i] = 0;
            }
            let block_arr = self.residual;
            self.poly.update(&[block_arr.into()]);
            self.residual.zeroize();
            self.residual_len = 0;
        }
        let mut len_block = [0u8; POLY_BLOCK_LEN];
        len_block[8..16].copy_from_slice(&self.total.to_le_bytes());
        self.poly.update(&[len_block.into()]);

        let tag = self.poly.finalize();
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        out
    }

    #[inline(never)]
    pub fn verify(self, expected: &[u8; TAG_LEN]) -> Result<(), Error> {
        let actual = self.finalize();
        let eq: bool = actual.ct_eq(expected).into();
        if eq { Ok(()) } else { Err(Error::Verification) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::{AeadInPlace, KeyInit as RefKeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce as RefNonce};

    /// Verify the streaming construction is byte-for-byte identical to the
    /// chacha20poly1305 crate's all-at-once AEAD over the same key/nonce/AAD.
    /// This is the integrity check on our manual RFC 8439 implementation.
    #[test]
    fn streaming_matches_reference_aead() {
        for &len in &[0usize, 1, 15, 16, 17, 31, 32, 4095, 4096, 4097, 200_000] {
            let key = [7u8; KEY_LEN];
            let mut nonce = [0u8; NONCE_LEN];
            for (i, b) in nonce.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13);
            }
            let mut plaintext = vec![0u8; len];
            for (i, b) in plaintext.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17).wrapping_add(3);
            }

            let mut ours = plaintext.clone();
            let (mut cipher, otk) = Cipher::new(&key, &nonce).unwrap();
            let mut mac = Mac::new(&otk);
            cipher.apply(&mut ours).unwrap();
            mac.update(&ours);
            let our_tag = mac.finalize();

            let ref_cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            let mut reference = plaintext.clone();
            let ref_tag = ref_cipher
                .encrypt_in_place_detached(RefNonce::from_slice(&nonce[..12]), b"", &mut reference)
                .unwrap();

            assert_eq!(ours, reference, "ciphertext mismatch at len={len}");
            assert_eq!(&our_tag[..], ref_tag.as_slice(), "tag mismatch at len={len}");
        }
    }

    #[test]
    fn mac_residual_buffering_matches_one_shot() {
        // Update fed in many small slices must produce the same MAC as one
        // single update call with the same total content.
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let (_c, otk) = Cipher::new(&key, &nonce).unwrap();

        let data: Vec<u8> = (0..7000u32).map(|i| (i & 0xff) as u8).collect();

        let mut mac_chunked = Mac::new(&otk);
        let mut i = 0;
        let chunk_sizes = [1usize, 2, 5, 13, 16, 17, 31, 64, 4096, 12345];
        let mut ci = 0;
        while i < data.len() {
            let n = chunk_sizes[ci % chunk_sizes.len()].min(data.len() - i);
            mac_chunked.update(&data[i..i + n]);
            i += n;
            ci += 1;
        }
        let tag_chunked = mac_chunked.finalize();

        let mut mac_oneshot = Mac::new(&otk);
        mac_oneshot.update(&data);
        let tag_oneshot = mac_oneshot.finalize();

        assert_eq!(tag_chunked, tag_oneshot);
    }
}

