use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use zeroize::Zeroizing;

use crate::codec;
use crate::error::Error;

const SHRED_CHUNK: usize = 64 * 1024;
const MAX_CHUNK_FILES: usize = 9999;

fn chunk_filename(idx: u32) -> String {
    format!("chunk_{:04}.png", idx + 1)
}

#[inline(never)]
pub fn encode_file_to_dir(
    in_path: &Path,
    out_dir: &Path,
    password: Zeroizing<Vec<u8>>,
) -> Result<u32, Error> {
    if !out_dir.is_dir() {
        return Err(Error::InvalidArgs);
    }
    let metadata = std::fs::metadata(in_path).map_err(Error::ReadIo)?;
    if !metadata.is_file() {
        return Err(Error::InvalidArgs);
    }
    let file_len = metadata.len();
    let in_file = File::open(in_path).map_err(Error::ReadIo)?;

    let pngs = codec::encode_multi(in_file, file_len, password)?;

    for (i, _) in pngs.iter().enumerate() {
        let p = out_dir.join(chunk_filename(i as u32));
        if p.exists() {
            return Err(Error::InvalidArgs);
        }
    }

    for (i, png) in pngs.iter().enumerate() {
        let p = out_dir.join(chunk_filename(i as u32));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(Error::WriteIo)?;
        f.write_all(png).map_err(Error::WriteIo)?;
        f.sync_all().map_err(Error::WriteIo)?;
    }

    let count: u32 = pngs.len().try_into().map_err(|_| Error::Internal)?;
    Ok(count)
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

    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .map_err(Error::WriteIo)?;

    match codec::decode_multi(&png_refs, password, &mut out_file) {
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

#[inline(never)]
pub fn decode_file_to_file(
    in_png: &Path,
    out_path: &Path,
    password: Zeroizing<Vec<u8>>,
) -> Result<(), Error> {
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

    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_path)
        .map_err(Error::WriteIo)?;

    match codec::decode_multi(&pngs[..], password, &mut out_file) {
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
        f.sync_all().map_err(Error::WriteIo)?;
    }
    std::fs::remove_file(path).map_err(Error::WriteIo)?;
    if path.exists() {
        return Err(Error::Internal);
    }
    Ok(())
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

