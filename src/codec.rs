use std::io::{Read, Write};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN, TAG_LEN};
use crate::error::Error;
use crate::memory;
use crate::png_io;
use crate::resolution::{self, NONCE_PIXELS};

const SESSION_ID_LEN: usize = 16;
pub const HEADER_LEN: usize = 32;
const CHUNK_BYTES: usize = 64 * 1024;

#[inline(never)]
pub fn encode_stream<R: Read>(
    mut reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let payload_len_usize: usize =
        payload_len.try_into().map_err(|_| Error::Capacity)?;
    let needed_ciphertext = HEADER_LEN
        .checked_add(payload_len_usize)
        .and_then(|x| x.checked_add(TAG_LEN))
        .ok_or(Error::Capacity)?;
    let (width, height) =
        resolution::smallest_fit(needed_ciphertext).ok_or(Error::Capacity)?;
    let cap = resolution::capacity_bytes(width, height);
    let plaintext_total = cap.checked_sub(TAG_LEN).ok_or(Error::Internal)?;
    let pad_len = plaintext_total
        .checked_sub(HEADER_LEN)
        .and_then(|x| x.checked_sub(payload_len_usize))
        .ok_or(Error::Internal)?;

    let mut rng = rand::thread_rng();
    let mut session_id = [0u8; SESSION_ID_LEN];
    rng.fill_bytes(&mut session_id);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let total_pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(Error::Internal)?;
    let pixel_byte_count = total_pixels.checked_mul(3).ok_or(Error::Internal)?;
    let mut pixels: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; pixel_byte_count]);

    for i in 0..NONCE_PIXELS {
        pixels[i * 3] = nonce[i];
        let mut gb = [0u8; 2];
        rng.fill_bytes(&mut gb);
        pixels[i * 3 + 1] = gb[0];
        pixels[i * 3 + 2] = gb[1];
    }

    let key = crypto::derive_key(&password, &nonce)?;
    drop(password);

    let (mut cipher, otk) = crypto::Cipher::new(&key, &nonce)?;
    drop(key);
    let mut mac = crypto::Mac::new(&otk);
    drop(otk);

    let header_off = NONCE_PIXELS * 3;

    {
        let region = pixels
            .get_mut(header_off..header_off + HEADER_LEN)
            .ok_or(Error::Internal)?;
        region[0..16].copy_from_slice(&session_id);
        region[16..20].copy_from_slice(&0u32.to_le_bytes());
        region[20..24].copy_from_slice(&1u32.to_le_bytes());
        region[24..32].copy_from_slice(&payload_len.to_le_bytes());
        cipher.apply(region);
        mac.update(region);
    }
    let mut written = HEADER_LEN;

    let mut remaining = payload_len_usize;
    while remaining > 0 {
        let n = remaining.min(CHUNK_BYTES);
        let start = header_off + written;
        let region = pixels
            .get_mut(start..start + n)
            .ok_or(Error::Internal)?;
        reader.read_exact(region)?;
        cipher.apply(region);
        mac.update(region);
        written += n;
        remaining -= n;
    }

    let mut pad_remaining = pad_len;
    while pad_remaining > 0 {
        let n = pad_remaining.min(CHUNK_BYTES);
        let start = header_off + written;
        let region = pixels
            .get_mut(start..start + n)
            .ok_or(Error::Internal)?;
        rng.fill_bytes(region);
        cipher.apply(region);
        mac.update(region);
        written += n;
        pad_remaining -= n;
    }

    let tag = mac.finalize();
    drop(cipher);
    let tag_off = header_off + written;
    pixels
        .get_mut(tag_off..tag_off + TAG_LEN)
        .ok_or(Error::Internal)?
        .copy_from_slice(&tag);

    let png_bytes = png_io::write_minimal_png(width, height, &pixels)?;
    Ok(png_bytes)
}

#[inline(never)]
pub fn encode_single(
    payload: &[u8],
    password: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    encode_stream(payload, payload.len() as u64, password)
}

#[inline(never)]
pub fn decode_stream<W: Write>(
    png_bytes: &[u8],
    password: Zeroizing<Vec<u8>>,
    mut out: W,
) -> Result<(), Error> {
    let (width, height, raw_pixels) = png_io::read_pixels(png_bytes)?;
    let pixels: Zeroizing<Vec<u8>> = Zeroizing::new(raw_pixels);
    let total_pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(Error::Format)?;
    let expected_bytes = total_pixels.checked_mul(3).ok_or(Error::Format)?;
    if pixels.len() != expected_bytes {
        return Err(Error::Format);
    }

    let mut nonce = [0u8; NONCE_LEN];
    for i in 0..NONCE_LEN {
        nonce[i] = pixels[i * 3];
    }

    let cap = resolution::capacity_bytes(width, height);
    let plaintext_total = cap.checked_sub(TAG_LEN).ok_or(Error::Format)?;

    let header_off = NONCE_PIXELS * 3;
    let tag_off = header_off
        .checked_add(plaintext_total)
        .ok_or(Error::Format)?;
    let tag_end = tag_off.checked_add(TAG_LEN).ok_or(Error::Format)?;
    if tag_end > pixels.len() {
        return Err(Error::Format);
    }

    let key = crypto::derive_key(&password, &nonce)?;
    drop(password);

    {
        let (cipher_pass1, otk) = crypto::Cipher::new(&key, &nonce)?;
        drop(cipher_pass1);
        let mut mac = crypto::Mac::new(&otk);
        drop(otk);
        let ct_slice = pixels
            .get(header_off..tag_off)
            .ok_or(Error::Format)?;
        let mut off = 0usize;
        while off < ct_slice.len() {
            let n = (ct_slice.len() - off).min(CHUNK_BYTES);
            mac.update(&ct_slice[off..off + n]);
            off += n;
        }
        let mut tag_buf = [0u8; TAG_LEN];
        tag_buf.copy_from_slice(
            pixels
                .get(tag_off..tag_end)
                .ok_or(Error::Format)?,
        );
        mac.verify(&tag_buf)?;
    }

    let (mut cipher, otk2) = crypto::Cipher::new(&key, &nonce)?;
    drop(key);
    drop(otk2);

    let mut header_buf: Zeroizing<[u8; HEADER_LEN]> = Zeroizing::new([0u8; HEADER_LEN]);
    header_buf.copy_from_slice(
        pixels
            .get(header_off..header_off + HEADER_LEN)
            .ok_or(Error::Format)?,
    );
    cipher.apply(&mut *header_buf);

    let chunk_idx_bytes: [u8; 4] =
        header_buf[16..20].try_into().map_err(|_| Error::Internal)?;
    let total_chunks_bytes: [u8; 4] =
        header_buf[20..24].try_into().map_err(|_| Error::Internal)?;
    let total_len_bytes: [u8; 8] =
        header_buf[24..32].try_into().map_err(|_| Error::Internal)?;
    let chunk_idx = u32::from_le_bytes(chunk_idx_bytes);
    let total_chunks = u32::from_le_bytes(total_chunks_bytes);
    let total_len = u64::from_le_bytes(total_len_bytes);
    drop(header_buf);

    if total_chunks != 1 || chunk_idx != 0 {
        return Err(Error::Verification);
    }
    let max_payload = plaintext_total
        .checked_sub(HEADER_LEN)
        .ok_or(Error::Verification)?;
    let total_len_usize: usize =
        total_len.try_into().map_err(|_| Error::Verification)?;
    if total_len_usize > max_payload {
        return Err(Error::Verification);
    }

    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
    memory::try_lock(&scratch);
    let payload_start = header_off + HEADER_LEN;
    let mut written = 0usize;
    while written < total_len_usize {
        let n = (total_len_usize - written).min(CHUNK_BYTES);
        let src = pixels
            .get(payload_start + written..payload_start + written + n)
            .ok_or(Error::Format)?;
        scratch[..n].copy_from_slice(src);
        cipher.apply(&mut scratch[..n]);
        out.write_all(&scratch[..n])?;
        written += n;
    }

    Ok(())
}

#[inline(never)]
pub fn decode_single(
    png_bytes: &[u8],
    password: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    decode_stream(png_bytes, password, &mut buf)?;
    Ok(Zeroizing::new(buf))
}
