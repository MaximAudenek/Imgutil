use std::io::{Read, Write};

use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::{self, NONCE_LEN, TAG_LEN};
use crate::error::Error;
use crate::memory;
use crate::png_io;
use crate::resolution::{self, NONCE_PIXELS};

const SESSION_ID_LEN: usize = 16;
pub const HEADER_LEN: usize = 32;
const CHUNK_BYTES: usize = 64 * 1024;
const MAX_CHUNKS: u32 = 9999;
const DEFAULT_CHUNK_RES: (u32, u32) = (7680, 4320);

fn encode_chunk<R: Read>(
    reader: &mut R,
    payload_len: u64,
    password: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    chunk_idx: u32,
    total_chunks: u32,
    total_len_for_chunk0: u64,
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

    let key = crypto::derive_key(password, &nonce)?;
    let (mut cipher, otk) = crypto::Cipher::new(&key, &nonce)?;
    drop(key);
    let mut mac = crypto::Mac::new(&otk);
    drop(otk);

    let header_off = NONCE_PIXELS * 3;
    let total_len_field = if chunk_idx == 0 { total_len_for_chunk0 } else { 0 };

    {
        let region = pixels
            .get_mut(header_off..header_off + HEADER_LEN)
            .ok_or(Error::Internal)?;
        region[0..16].copy_from_slice(session_id);
        region[16..20].copy_from_slice(&chunk_idx.to_le_bytes());
        region[20..24].copy_from_slice(&total_chunks.to_le_bytes());
        region[24..32].copy_from_slice(&total_len_field.to_le_bytes());
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
        reader.read_exact(region).map_err(Error::ReadIo)?;
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
pub fn encode_stream<R: Read>(
    reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);
    let mut reader = reader;
    encode_chunk(
        &mut reader,
        payload_len,
        &password,
        &session_id,
        0,
        1,
        payload_len,
    )
}

#[inline(never)]
pub fn encode_single(
    payload: &[u8],
    password: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    encode_stream(payload, payload.len() as u64, password)
}

#[inline(never)]
pub fn encode_multi<R: Read>(
    reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, Error> {
    encode_multi_with_res(reader, payload_len, password, DEFAULT_CHUNK_RES)
}

#[inline(never)]
pub fn encode_multi_streaming<R, F>(
    reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
    emit: F,
) -> Result<u32, Error>
where
    R: Read,
    F: FnMut(u32, u32, &[u8]) -> Result<(), Error>,
{
    encode_multi_streaming_with_res(reader, payload_len, password, DEFAULT_CHUNK_RES, emit)
}

/// Returns total number of chunks the payload will produce at the given
/// resolution, or an error if it would exceed MAX_CHUNKS.
pub(crate) fn compute_total_chunks(
    payload_len: u64,
    chunk_res: (u32, u32),
) -> Result<u32, Error> {
    let payload_len_usize: usize =
        payload_len.try_into().map_err(|_| Error::Capacity)?;
    if !resolution::is_standard(chunk_res.0, chunk_res.1) {
        return Err(Error::Internal);
    }
    let chunk_cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
    let chunk_payload_max = chunk_cap
        .checked_sub(HEADER_LEN + TAG_LEN)
        .ok_or(Error::Internal)?;
    if chunk_payload_max == 0 {
        return Err(Error::Internal);
    }
    let n = if payload_len_usize == 0 {
        1usize
    } else {
        payload_len_usize.div_ceil(chunk_payload_max)
    };
    if n > MAX_CHUNKS as usize {
        return Err(Error::Capacity);
    }
    n.try_into().map_err(|_| Error::Capacity)
}

#[inline(never)]
pub(crate) fn encode_multi_streaming_with_res<R, F>(
    mut reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
    chunk_res: (u32, u32),
    mut emit: F,
) -> Result<u32, Error>
where
    R: Read,
    F: FnMut(u32, u32, &[u8]) -> Result<(), Error>,
{
    let payload_len_usize: usize =
        payload_len.try_into().map_err(|_| Error::Capacity)?;
    let total_chunks = compute_total_chunks(payload_len, chunk_res)?;
    let chunk_cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
    let chunk_payload_max = chunk_cap
        .checked_sub(HEADER_LEN + TAG_LEN)
        .ok_or(Error::Internal)?;

    let mut session_id = [0u8; SESSION_ID_LEN];
    rand::thread_rng().fill_bytes(&mut session_id);

    let mut remaining = payload_len_usize;
    for chunk_idx in 0..total_chunks {
        let is_last = chunk_idx as usize == total_chunks as usize - 1;
        let this_payload = if is_last { remaining } else { chunk_payload_max };
        let png = encode_chunk(
            &mut reader,
            this_payload as u64,
            &password,
            &session_id,
            chunk_idx,
            total_chunks,
            payload_len,
        )?;
        emit(chunk_idx, total_chunks, &png)?;
        remaining = remaining
            .checked_sub(this_payload)
            .ok_or(Error::Internal)?;
    }
    Ok(total_chunks)
}

#[inline(never)]
pub(crate) fn encode_multi_with_res<R: Read>(
    reader: R,
    payload_len: u64,
    password: Zeroizing<Vec<u8>>,
    chunk_res: (u32, u32),
) -> Result<Vec<Vec<u8>>, Error> {
    let mut pngs: Vec<Vec<u8>> = Vec::new();
    encode_multi_streaming_with_res(
        reader,
        payload_len,
        password,
        chunk_res,
        |_idx, _total, png| {
            pngs.push(png.to_vec());
            Ok(())
        },
    )?;
    Ok(pngs)
}

struct ChunkMeta {
    png_idx: usize,
    session_id: [u8; SESSION_ID_LEN],
    chunk_idx: u32,
    total_chunks: u32,
    total_len_field: u64,
    nonce: [u8; NONCE_LEN],
    key: Zeroizing<Vec<u8>>,
    cap_bytes: usize,
}

#[inline(never)]
fn open_chunk_meta(png: &[u8], password: &[u8]) -> Result<ChunkMeta, Error> {
    let (width, height, raw_pixels) = png_io::read_pixels(png)?;
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

    let key = crypto::derive_key(password, &nonce)?;

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

    let (mut cipher, _otk2) = crypto::Cipher::new(&key, &nonce)?;
    let mut hbuf: Zeroizing<[u8; HEADER_LEN]> = Zeroizing::new([0u8; HEADER_LEN]);
    hbuf.copy_from_slice(
        pixels
            .get(header_off..header_off + HEADER_LEN)
            .ok_or(Error::Format)?,
    );
    cipher.apply(&mut *hbuf);

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&hbuf[0..SESSION_ID_LEN]);
    let chunk_idx_bytes: [u8; 4] =
        hbuf[16..20].try_into().map_err(|_| Error::Internal)?;
    let total_chunks_bytes: [u8; 4] =
        hbuf[20..24].try_into().map_err(|_| Error::Internal)?;
    let total_len_bytes: [u8; 8] =
        hbuf[24..32].try_into().map_err(|_| Error::Internal)?;
    let chunk_idx = u32::from_le_bytes(chunk_idx_bytes);
    let total_chunks = u32::from_le_bytes(total_chunks_bytes);
    let total_len_field = u64::from_le_bytes(total_len_bytes);

    Ok(ChunkMeta {
        png_idx: 0,
        session_id,
        chunk_idx,
        total_chunks,
        total_len_field,
        nonce,
        key,
        cap_bytes: cap,
    })
}

#[inline(never)]
fn decrypt_chunk_payload<W: Write>(
    png: &[u8],
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    payload_len: usize,
    out: &mut W,
) -> Result<(), Error> {
    let (width, height, raw_pixels) = png_io::read_pixels(png)?;
    let pixels: Zeroizing<Vec<u8>> = Zeroizing::new(raw_pixels);
    let total_pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or(Error::Format)?;
    let expected = total_pixels.checked_mul(3).ok_or(Error::Format)?;
    if pixels.len() != expected {
        return Err(Error::Format);
    }
    let cap = resolution::capacity_bytes(width, height);
    let max_payload = cap
        .checked_sub(HEADER_LEN + TAG_LEN)
        .ok_or(Error::Format)?;
    if payload_len > max_payload {
        return Err(Error::Verification);
    }
    let header_off = NONCE_PIXELS * 3;

    let (mut cipher, _otk) = crypto::Cipher::new(key, nonce)?;
    let mut throwaway: Zeroizing<[u8; HEADER_LEN]> = Zeroizing::new([0u8; HEADER_LEN]);
    cipher.apply(&mut *throwaway);
    drop(throwaway);

    let mut scratch: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
    memory::try_lock(&scratch);
    let payload_start = header_off + HEADER_LEN;
    let mut written = 0usize;
    while written < payload_len {
        let n = (payload_len - written).min(CHUNK_BYTES);
        let src = pixels
            .get(payload_start + written..payload_start + written + n)
            .ok_or(Error::Format)?;
        scratch[..n].copy_from_slice(src);
        cipher.apply(&mut scratch[..n]);
        out.write_all(&scratch[..n]).map_err(Error::WriteIo)?;
        written += n;
    }
    Ok(())
}

#[inline(never)]
pub fn decode_stream<W: Write>(
    png_bytes: &[u8],
    password: Zeroizing<Vec<u8>>,
    mut out: W,
) -> Result<(), Error> {
    let meta = open_chunk_meta(png_bytes, &password)?;
    drop(password);

    if meta.total_chunks != 1 || meta.chunk_idx != 0 {
        return Err(Error::Verification);
    }
    let total_len_usize: usize = meta
        .total_len_field
        .try_into()
        .map_err(|_| Error::Verification)?;
    let max_payload = meta
        .cap_bytes
        .checked_sub(HEADER_LEN + TAG_LEN)
        .ok_or(Error::Verification)?;
    if total_len_usize > max_payload {
        return Err(Error::Verification);
    }
    decrypt_chunk_payload(png_bytes, &meta.key, &meta.nonce, total_len_usize, &mut out)
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

#[inline(never)]
pub fn decode_multi<W: Write>(
    pngs: &[&[u8]],
    password: Zeroizing<Vec<u8>>,
    out: W,
) -> Result<(), Error> {
    decode_multi_streaming(pngs, password, out, |_, _| {})
}

#[inline(never)]
pub fn decode_multi_streaming<W, F>(
    pngs: &[&[u8]],
    password: Zeroizing<Vec<u8>>,
    mut out: W,
    mut on_chunk_written: F,
) -> Result<(), Error>
where
    W: Write,
    F: FnMut(u32, u32),
{
    if pngs.len() > MAX_CHUNKS as usize {
        return Err(Error::Verification);
    }

    let mut chunks: Vec<ChunkMeta> = Vec::new();
    for (i, png) in pngs.iter().enumerate() {
        match open_chunk_meta(png, &password) {
            Ok(mut m) => {
                m.png_idx = i;
                chunks.push(m);
            }
            Err(_) => {
                // Silent skip per spec: MAC failure / format failure on any
                // single PNG must not surface to the caller.
                continue;
            }
        }
    }
    drop(password);

    if chunks.is_empty() {
        return Err(Error::Verification);
    }

    let session_id = chunks[0].session_id;
    for c in &chunks {
        let eq: bool = c.session_id[..].ct_eq(&session_id[..]).into();
        if !eq {
            return Err(Error::Verification);
        }
    }

    let total_chunks = chunks[0].total_chunks;
    if total_chunks == 0 || total_chunks > MAX_CHUNKS {
        return Err(Error::Verification);
    }
    if !chunks.iter().all(|c| c.total_chunks == total_chunks) {
        return Err(Error::Verification);
    }
    if chunks.len() != total_chunks as usize {
        return Err(Error::Verification);
    }

    chunks.sort_by_key(|c| c.chunk_idx);
    for (i, c) in chunks.iter().enumerate() {
        if c.chunk_idx as usize != i {
            return Err(Error::Verification);
        }
    }

    let total_len = chunks[0].total_len_field;
    let total_len_usize: usize =
        total_len.try_into().map_err(|_| Error::Verification)?;

    let n = chunks.len();
    let mut per_chunk_payload: Vec<usize> = Vec::with_capacity(n);
    let mut sum_non_last: usize = 0;
    for (i, c) in chunks.iter().enumerate() {
        let chunk_max_payload = c
            .cap_bytes
            .checked_sub(HEADER_LEN + TAG_LEN)
            .ok_or(Error::Verification)?;
        if i + 1 < n {
            per_chunk_payload.push(chunk_max_payload);
            sum_non_last = sum_non_last
                .checked_add(chunk_max_payload)
                .ok_or(Error::Verification)?;
        } else {
            if total_len_usize < sum_non_last {
                return Err(Error::Verification);
            }
            let last_payload = total_len_usize - sum_non_last;
            if last_payload > chunk_max_payload {
                return Err(Error::Verification);
            }
            if total_chunks > 1 && last_payload == 0 {
                return Err(Error::Verification);
            }
            per_chunk_payload.push(last_payload);
        }
    }

    let total_chunks_u32 = total_chunks;
    for (i, c) in chunks.iter().enumerate() {
        decrypt_chunk_payload(
            pngs[c.png_idx],
            &c.key,
            &c.nonce,
            per_chunk_payload[i],
            &mut out,
        )?;
        let done: u32 = (i + 1).try_into().map_err(|_| Error::Internal)?;
        on_chunk_written(done, total_chunks_u32);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn pw(s: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(seed.wrapping_add(13))).collect()
    }

    /// 3-chunk round-trip using the smallest standard resolution as the
    /// chunk-sizing unit. Per-chunk payload at 1280×720 is ~2.76 MB; ~6 MB
    /// payload forces exactly 3 chunks (2 full + small remainder).
    #[test]
    fn multi_three_chunk_roundtrip() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 1024;
        let p = payload(total, 5);

        let pngs = encode_multi_with_res(Cursor::new(&p), p.len() as u64, pw("k"), chunk_res)
            .unwrap();
        assert_eq!(pngs.len(), 3, "expected exactly 3 chunks");

        let png_refs: Vec<&[u8]> = pngs.iter().map(|v| v.as_slice()).collect();
        let mut out: Vec<u8> = Vec::new();
        decode_multi(&png_refs, pw("k"), &mut out).unwrap();
        assert_eq!(p, out);
    }

    #[test]
    fn multi_shuffled_order_assembles_correctly() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 4096;
        let p = payload(total, 11);

        let pngs = encode_multi_with_res(Cursor::new(&p), p.len() as u64, pw("k"), chunk_res)
            .unwrap();
        assert_eq!(pngs.len(), 3);

        // Reverse the order.
        let png_refs_reversed: Vec<&[u8]> =
            pngs.iter().rev().map(|v| v.as_slice()).collect();
        let mut out: Vec<u8> = Vec::new();
        decode_multi(&png_refs_reversed, pw("k"), &mut out).unwrap();
        assert_eq!(p, out, "shuffled order must reassemble identically");

        // Arbitrary permutation: [1, 2, 0].
        let perm: Vec<&[u8]> = vec![pngs[1].as_slice(), pngs[2].as_slice(), pngs[0].as_slice()];
        let mut out2: Vec<u8> = Vec::new();
        decode_multi(&perm, pw("k"), &mut out2).unwrap();
        assert_eq!(p, out2);
    }

    #[test]
    fn multi_missing_chunk_rejected() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 1000;
        let p = payload(total, 17);

        let pngs = encode_multi_with_res(Cursor::new(&p), p.len() as u64, pw("k"), chunk_res)
            .unwrap();
        assert_eq!(pngs.len(), 3);

        // Drop the middle chunk.
        let png_refs: Vec<&[u8]> = vec![pngs[0].as_slice(), pngs[2].as_slice()];
        let mut out: Vec<u8> = Vec::new();
        let result = decode_multi(&png_refs, pw("k"), &mut out);
        assert!(matches!(result, Err(Error::Verification)));
        assert_eq!(result.unwrap_err().user_message(), "Authentication failed.");
    }

    #[test]
    fn multi_duplicate_chunk_rejected() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 500;
        let p = payload(total, 23);

        let pngs = encode_multi_with_res(Cursor::new(&p), p.len() as u64, pw("k"), chunk_res)
            .unwrap();
        assert_eq!(pngs.len(), 3);

        // Submit chunks [0, 0, 1] — wrong total but len matches total_chunks=3.
        // This should fail the "no gaps in chunk_idx sequence" check.
        let png_refs: Vec<&[u8]> =
            vec![pngs[0].as_slice(), pngs[0].as_slice(), pngs[1].as_slice()];
        let mut out: Vec<u8> = Vec::new();
        let result = decode_multi(&png_refs, pw("k"), &mut out);
        assert!(matches!(result, Err(Error::Verification)));
    }

    #[test]
    fn multi_mixed_sessions_rejected() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 100;
        let p1 = payload(total, 31);
        let p2 = payload(total, 32);

        let pngs1 =
            encode_multi_with_res(Cursor::new(&p1), p1.len() as u64, pw("k"), chunk_res).unwrap();
        let pngs2 =
            encode_multi_with_res(Cursor::new(&p2), p2.len() as u64, pw("k"), chunk_res).unwrap();
        assert_eq!(pngs1.len(), 3);
        assert_eq!(pngs2.len(), 3);

        // Mix one PNG from each session — both decrypt successfully (same
        // password) but session_id mismatch must trigger Verification.
        let png_refs: Vec<&[u8]> = vec![
            pngs1[0].as_slice(),
            pngs1[1].as_slice(),
            pngs2[2].as_slice(),
        ];
        let mut out: Vec<u8> = Vec::new();
        let result = decode_multi(&png_refs, pw("k"), &mut out);
        assert!(matches!(result, Err(Error::Verification)));
    }

    #[test]
    fn multi_unrelated_png_silently_skipped() {
        let chunk_res = (1280u32, 720u32);
        let cap = resolution::capacity_bytes(chunk_res.0, chunk_res.1);
        let chunk_payload = cap - HEADER_LEN - TAG_LEN;
        let total = 2 * chunk_payload + 200;
        let p = payload(total, 41);

        let pngs = encode_multi_with_res(Cursor::new(&p), p.len() as u64, pw("k"), chunk_res)
            .unwrap();
        assert_eq!(pngs.len(), 3);

        // A PNG encrypted with a DIFFERENT password — its MAC will fail under
        // password "k", so it must be silently skipped, leaving the original
        // 3 chunks to decode normally.
        let stranger = encode_single(b"unrelated", pw("other_password")).unwrap();

        let png_refs: Vec<&[u8]> = vec![
            pngs[0].as_slice(),
            stranger.as_slice(),
            pngs[1].as_slice(),
            pngs[2].as_slice(),
        ];
        let mut out: Vec<u8> = Vec::new();
        decode_multi(&png_refs, pw("k"), &mut out).unwrap();
        assert_eq!(p, out);
    }

    #[test]
    fn multi_single_chunk_roundtrip() {
        // encode_multi with a payload that fits in one chunk produces 1 PNG
        // and decode_multi handles it identically to decode_single.
        let p = payload(50_000, 7);
        let pngs = encode_multi(Cursor::new(&p), p.len() as u64, pw("k")).unwrap();
        assert_eq!(pngs.len(), 1);
        let refs: Vec<&[u8]> = pngs.iter().map(|v| v.as_slice()).collect();
        let mut out: Vec<u8> = Vec::new();
        decode_multi(&refs, pw("k"), &mut out).unwrap();
        assert_eq!(p, out);
    }

    #[test]
    fn multi_empty_input_rejected() {
        let result: Result<(), Error> =
            decode_multi(&[], pw("k"), &mut Vec::<u8>::new());
        assert!(matches!(result, Err(Error::Verification)));
    }
}
