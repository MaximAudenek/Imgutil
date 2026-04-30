use std::io::Cursor;

use crate::error::Error;
use crate::resolution;

const PNG_MAGIC: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

fn validate_chunks_only(data: &[u8]) -> Result<(), Error> {
    if data.len() < 8 || data[..8] != PNG_MAGIC {
        return Err(Error::Format);
    }
    let mut i = 8usize;
    let mut saw_ihdr = false;
    let mut saw_iend = false;
    while i < data.len() {
        if i.checked_add(8).is_none_or(|x| x > data.len()) {
            return Err(Error::Format);
        }
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype = [data[i + 4], data[i + 5], data[i + 6], data[i + 7]];
        let end = i
            .checked_add(8)
            .and_then(|x| x.checked_add(len))
            .and_then(|x| x.checked_add(4))
            .filter(|&e| e <= data.len())
            .ok_or(Error::Format)?;
        match &ctype {
            b"IHDR" => {
                if saw_ihdr {
                    return Err(Error::Format);
                }
                saw_ihdr = true;
            }
            b"IDAT" => {
                if !saw_ihdr {
                    return Err(Error::Format);
                }
            }
            b"IEND" => {
                if saw_iend {
                    return Err(Error::Format);
                }
                saw_iend = true;
            }
            _ => return Err(Error::Format),
        }
        i = end;
    }
    if !saw_ihdr || !saw_iend {
        return Err(Error::Format);
    }
    Ok(())
}

pub fn write_minimal_png(width: u32, height: u32, rgb: &[u8]) -> Result<Vec<u8>, Error> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(3))
        .ok_or(Error::Internal)?;
    if rgb.len() != expected {
        return Err(Error::Internal);
    }
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| Error::Internal)?;
        writer
            .write_image_data(rgb)
            .map_err(|_| Error::Internal)?;
    }
    validate_chunks_only(&out)?;
    Ok(out)
}

pub fn read_pixels(data: &[u8]) -> Result<(u32, u32, Vec<u8>), Error> {
    validate_chunks_only(data)?;
    let decoder = png::Decoder::new(Cursor::new(data));
    let mut reader = decoder.read_info().map_err(|_| Error::Format)?;
    let info = reader.info();
    let width = info.width;
    let height = info.height;
    if !resolution::is_standard(width, height) {
        return Err(Error::Format);
    }
    if info.color_type != png::ColorType::Rgb {
        return Err(Error::Format);
    }
    if info.bit_depth != png::BitDepth::Eight {
        return Err(Error::Format);
    }
    let buf_size = reader.output_buffer_size();
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(3))
        .ok_or(Error::Format)?;
    if buf_size != expected {
        return Err(Error::Format);
    }
    let mut buf = vec![0u8; buf_size];
    reader
        .next_frame(&mut buf)
        .map_err(|_| Error::Format)?;
    Ok((width, height, buf))
}
