pub const RESOLUTIONS: [(u32, u32); 5] = [
    (1280, 720),
    (1920, 1080),
    (2560, 1440),
    (3840, 2160),
    (7680, 4320),
];

pub const NONCE_PIXELS: usize = 32;

pub fn capacity_bytes(width: u32, height: u32) -> usize {
    let pixels = (width as usize).saturating_mul(height as usize);
    pixels.saturating_sub(NONCE_PIXELS).saturating_mul(3)
}

pub fn smallest_fit(needed: usize) -> Option<(u32, u32)> {
    RESOLUTIONS
        .iter()
        .copied()
        .find(|&(w, h)| capacity_bytes(w, h) >= needed)
}

pub fn is_standard(width: u32, height: u32) -> bool {
    RESOLUTIONS.iter().any(|&(w, h)| w == width && h == height)
}
