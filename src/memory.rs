use std::sync::atomic::{AtomicBool, Ordering};

static WARNED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn lock_pages(addr: *const u8, len: usize) -> bool {
    // SAFETY: addr/len describe a valid byte range owned by the caller for the lifetime of the call.
    unsafe { libc::mlock(addr as *const libc::c_void, len) == 0 }
}

#[cfg(windows)]
fn lock_pages(addr: *const u8, len: usize) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    // SAFETY: addr/len describe a valid byte range owned by the caller for the lifetime of the call.
    unsafe { VirtualLock(addr as _, len) != 0 }
}

#[cfg(not(any(unix, windows)))]
fn lock_pages(_addr: *const u8, _len: usize) -> bool {
    false
}

pub fn try_lock(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    let ok = lock_pages(buf.as_ptr(), buf.len());
    if !ok && !WARNED.swap(true, Ordering::SeqCst) {
        eprintln!("Warning: memory could not be locked. Ensure swap is encrypted.");
    }
}
