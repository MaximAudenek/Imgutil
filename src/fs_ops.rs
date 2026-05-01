use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::codec;
use crate::error::Error;

const SHRED_CHUNK: usize = 64 * 1024;
const MAX_CHUNK_FILES: usize = 9999;
const DEFAULT_CHUNK_RES: (u32, u32) = (7680, 4320);

fn chunk_filename(idx: u32) -> String {
    format!("chunk_{:04}.png", idx + 1)
}

#[inline(never)]
pub fn encode_file_to_dir(
    in_path: &Path,
    out_dir: &Path,
    password: Zeroizing<Vec<u8>>,
) -> Result<u32, Error> {
    encode_file_to_dir_with_progress(in_path, out_dir, password, |_, _| {})
}

#[inline(never)]
pub fn encode_file_to_dir_with_progress<F>(
    in_path: &Path,
    out_dir: &Path,
    password: Zeroizing<Vec<u8>>,
    on_chunk_written: F,
) -> Result<u32, Error>
where
    F: FnMut(u32, u32),
{
    let metadata = std::fs::metadata(in_path).map_err(Error::ReadIo)?;
    if !metadata.is_file() {
        return Err(Error::InvalidArgs);
    }
    let file_len = metadata.len();
    let in_file = File::open(in_path).map_err(Error::ReadIo)?;
    encode_reader_to_dir_with_progress(in_file, file_len, out_dir, password, on_chunk_written)
}

#[inline(never)]
pub fn encode_reader_to_dir_with_progress<R, F>(
    reader: R,
    payload_len: u64,
    out_dir: &Path,
    password: Zeroizing<Vec<u8>>,
    mut on_chunk_written: F,
) -> Result<u32, Error>
where
    R: Read,
    F: FnMut(u32, u32),
{
    if !out_dir.is_dir() {
        return Err(Error::InvalidArgs);
    }

    // Pre-compute the chunk count and refuse if any target file already
    // exists. Per SPEC.md: never silently overwrite.
    let total_chunks = codec::compute_total_chunks(payload_len, DEFAULT_CHUNK_RES)?;
    for i in 0..total_chunks {
        let p = out_dir.join(chunk_filename(i));
        if p.exists() {
            return Err(Error::InvalidArgs);
        }
    }

    let written = codec::encode_multi_streaming(reader, payload_len, password, |idx, total, png| {
        let p = out_dir.join(chunk_filename(idx));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(Error::WriteIo)?;
        f.write_all(png).map_err(Error::WriteIo)?;
        f.sync_all().map_err(Error::WriteIo)?;
        on_chunk_written(idx + 1, total);
        Ok(())
    })?;

    Ok(written)
}

fn read_pngs_from_dir(dir: &Path) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(Error::ReadIo)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
        })
        .collect();
    if entries.len() > MAX_CHUNK_FILES {
        return Err(Error::InvalidArgs);
    }
    entries.sort();

    let mut data: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(entries.len());
    for p in entries {
        let mut buf: Vec<u8> = Vec::new();
        let mut f = File::open(&p).map_err(Error::ReadIo)?;
        f.read_to_end(&mut buf).map_err(Error::ReadIo)?;
        data.push(Zeroizing::new(buf));
    }
    Ok(data)
}

#[inline(never)]
pub fn decode_dir_to_file(
    in_dir: &Path,
    out_path: &Path,
    password: Zeroizing<Vec<u8>>,
) -> Result<(), Error> {
    decode_dir_to_file_with_progress(in_dir, out_path, password, |_, _| {})
}

#[inline(never)]
pub fn decode_dir_to_file_with_progress<F>(
    in_dir: &Path,
    out_path: &Path,
    password: Zeroizing<Vec<u8>>,
    on_chunk_written: F,
) -> Result<(), Error>
where
    F: FnMut(u32, u32),
{
    if !in_dir.is_dir() {
        return Err(Error::InvalidArgs);
    }
    if out_path.exists() {
        return Err(Error::InvalidArgs);
    }

    let pngs_data = read_pngs_from_dir(in_dir)?;
    if pngs_data.is_empty() {
        return Err(Error::Verification);
    }
    let png_refs: Vec<&[u8]> = pngs_data.iter().map(|v| v.as_slice()).collect();

    decode_into_new_file(out_path, |f| {
        codec::decode_multi_streaming(&png_refs, password, f, on_chunk_written)
    })
}

#[inline(never)]
pub fn decode_dir_to_writer_with_progress<W, F>(
    in_dir: &Path,
    out: W,
    password: Zeroizing<Vec<u8>>,
    on_chunk_written: F,
) -> Result<(), Error>
where
    W: Write,
    F: FnMut(u32, u32),
{
    if !in_dir.is_dir() {
        return Err(Error::InvalidArgs);
    }

    let pngs_data = read_pngs_from_dir(in_dir)?;
    if pngs_data.is_empty() {
        return Err(Error::Verification);
    }
    let png_refs: Vec<&[u8]> = pngs_data.iter().map(|v| v.as_slice()).collect();

    // No create_new + shred wrapper here: the writer is owned by the caller
    // (e.g. stdout). MAC verification still happens before any plaintext is
    // emitted — phase 1 of decode_multi_streaming runs to completion before
    // phase 3 begins writing — so a verification failure cannot leak partial
    // plaintext to the writer.
    codec::decode_multi_streaming(&png_refs, password, out, on_chunk_written)
}

#[inline(never)]
pub fn decode_file_to_file(
    in_png: &Path,
    out_path: &Path,
    password: Zeroizing<Vec<u8>>,
) -> Result<(), Error> {
    decode_file_to_file_with_progress(in_png, out_path, password, |_, _| {})
}

#[inline(never)]
pub fn decode_file_to_writer_with_progress<W, F>(
    in_png: &Path,
    out: W,
    password: Zeroizing<Vec<u8>>,
    on_chunk_written: F,
) -> Result<(), Error>
where
    W: Write,
    F: FnMut(u32, u32),
{
    if !in_png.is_file() {
        return Err(Error::InvalidArgs);
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut f = File::open(in_png).map_err(Error::ReadIo)?;
    f.read_to_end(&mut buf).map_err(Error::ReadIo)?;
    let png_data = Zeroizing::new(buf);
    let pngs: [&[u8]; 1] = [png_data.as_slice()];

    codec::decode_multi_streaming(&pngs[..], password, out, on_chunk_written)
}

#[inline(never)]
pub fn decode_file_to_file_with_progress<F>(
    in_png: &Path,
    out_path: &Path,
    password: Zeroizing<Vec<u8>>,
    on_chunk_written: F,
) -> Result<(), Error>
where
    F: FnMut(u32, u32),
{
    if !in_png.is_file() {
        return Err(Error::InvalidArgs);
    }
    if out_path.exists() {
        return Err(Error::InvalidArgs);
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut f = File::open(in_png).map_err(Error::ReadIo)?;
    f.read_to_end(&mut buf).map_err(Error::ReadIo)?;
    let png_data = Zeroizing::new(buf);
    let pngs: [&[u8]; 1] = [png_data.as_slice()];

    decode_into_new_file(out_path, |out_f| {
        codec::decode_multi_streaming(&pngs[..], password, out_f, on_chunk_written)
    })
}

/// Open `out_path` exclusively (`create_new`), invoke `body`, then on success
/// fsync; on error shred-and-delete the partial output before propagating the
/// original error. The cleanup result is intentionally swallowed — surfacing
/// it would create an information channel about whether the underlying
/// filesystem was healthy at the moment of failure.
fn decode_into_new_file<G>(out_path: &Path, body: G) -> Result<(), Error>
where
    G: FnOnce(&mut File) -> Result<(), Error>,
{
    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .map_err(Error::WriteIo)?;

    match body(&mut out_file) {
        Ok(()) => {
            out_file.sync_all().map_err(Error::WriteIo)?;
            Ok(())
        }
        Err(e) => {
            drop(out_file);
            let _ = shred_and_delete(out_path);
            Err(e)
        }
    }
}

/// Overwrite a file with random bytes equal to its current length, sync to
/// disk, remove it, and verify removal succeeded. Used on any decode failure
/// after the output file has been created so partial plaintext does not
/// linger on disk.
#[inline(never)]
pub(crate) fn shred_and_delete(path: &Path) -> Result<(), Error> {
    let metadata = std::fs::metadata(path).map_err(Error::WriteIo)?;
    let len = metadata.len();
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(Error::WriteIo)?;
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; SHRED_CHUNK]);
        let mut rng = rand::thread_rng();
        let mut written: u64 = 0;
        while written < len {
            let remaining = len - written;
            let n = remaining.min(buf.len() as u64) as usize;
            rng.fill_bytes(&mut buf[..n]);
            f.write_all(&buf[..n]).map_err(Error::WriteIo)?;
            written += n as u64;
        }
        full_sync(&f).map_err(Error::WriteIo)?;
    }
    std::fs::remove_file(path).map_err(Error::WriteIo)?;
    if path.exists() {
        return Err(Error::Internal);
    }
    Ok(())
}

/// Best-effort durable flush. On macOS uses fcntl(F_FULLFSYNC) to push data
/// past the disk's write cache to physical media — plain fsync(2) on APFS
/// returns once data has reached the drive's volatile cache. Other platforms
/// fall back to sync_all (fsync). For our purposes the difference matters
/// only in the shred path: we want the random overwrite on durable storage
/// before deleting the file.
#[cfg(target_os = "macos")]
fn full_sync(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    // F_FULLFSYNC = 51 on Darwin; libc exports it as a constant.
    let ret = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
    if ret < 0 {
        // Fall back to fsync if F_FULLFSYNC is rejected (e.g. on filesystems
        // that don't support it).
        return file.sync_all();
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn full_sync(file: &File) -> std::io::Result<()> {
    file.sync_all()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn shred_overwrites_then_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("victim.bin");
        let original = b"plaintext that must not survive";
        std::fs::write(&path, original).unwrap();
        assert!(path.exists());

        shred_and_delete(&path).unwrap();

        assert!(!path.exists(), "file must be removed");
    }

    #[test]
    fn shred_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();
        assert!(path.exists());

        shred_and_delete(&path).unwrap();

        assert!(!path.exists());
    }

    #[test]
    fn shred_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("does_not_exist.bin");
        let result = shred_and_delete(&nonexistent);
        assert!(matches!(result, Err(Error::WriteIo(_))));
    }
}
