// extern "C" exports for C++ bootimg.cpp
//
// Upstream Magisk uses CXX bridge to call these Rust functions from C++.
// For standalone build, we export them directly as extern "C" so C++ can
// link against them. This is the primary P4 adaptation layer.

use crate::compress::{get_decoder, get_encoder};
use crate::ffi::FileFormat;
use crate::sign;

use std::io::Cursor;
use std::mem::ManuallyDrop;
use std::ops::DerefMut;

#[cfg(unix)]
use std::os::fd::FromRawFd;

// ---------------------------------------------------------------------------
// File descriptor → Write adapter (cross-platform)
// ---------------------------------------------------------------------------

#[cfg(unix)]
unsafe fn fd_to_file(fd: i32) -> ManuallyDrop<std::fs::File> {
    unsafe { ManuallyDrop::new(std::fs::File::from_raw_fd(fd)) }
}

#[cfg(windows)]
unsafe fn fd_to_file(fd: i32) -> ManuallyDrop<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    let handle = unsafe { libc_msvcrt::get_osfhandle(fd) };
    unsafe { ManuallyDrop::new(std::fs::File::from_raw_handle(handle as *mut _)) }
}

/// Platform-specific MSVCRT FFI for _get_osfhandle on Windows
#[cfg(windows)]
mod libc_msvcrt {
    unsafe extern "C" {
        #[link_name = "_get_osfhandle"]
        pub fn get_osfhandle(fd: i32) -> isize;
    }
}

// ---------------------------------------------------------------------------
// Compression/Decompression callbacks for C++
// ---------------------------------------------------------------------------

/// Decompress data from `in_bytes` (pointer+len) and write to file descriptor `out_fd`.
/// Called by bootimg.cpp's `decompress()` function during unpack.
#[unsafe(no_mangle)]
pub extern "C" fn rust_decompress_bytes(fmt: i32, in_ptr: *const u8, in_len: usize, out_fd: i32) {
    let format = int_to_format(fmt);
    if !format.is_compressed() {
        return;
    }
    let in_bytes = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    let mut out_file = unsafe { fd_to_file(out_fd) };

    let _ = (|| -> std::io::Result<()> {
        let mut decoder = get_decoder(format, in_bytes)?;
        std::io::copy(decoder.as_mut(), out_file.deref_mut())?;
        Ok(())
    })();
}

/// Compress data from `in_bytes` and write to file descriptor `out_fd`.
/// Called by bootimg.cpp's `compress_len()` function during repack.
#[unsafe(no_mangle)]
pub extern "C" fn rust_compress_bytes(fmt: i32, in_ptr: *const u8, in_len: usize, out_fd: i32) {
    let format = int_to_format(fmt);
    if !format.is_compressed() {
        return;
    }
    let in_bytes = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    let mut out_file = unsafe { fd_to_file(out_fd) };

    let _ = (|| -> std::io::Result<()> {
        let mut encoder = get_encoder(format, out_file.deref_mut())?;
        std::io::copy(&mut Cursor::new(in_bytes), encoder.deref_mut())?;
        encoder.finish()?;
        Ok(())
    })();
}

// ---------------------------------------------------------------------------
// SHA callbacks for C++
// ---------------------------------------------------------------------------

/// Opaque SHA context handle for C++
pub struct ShaContext {
    inner: sign::SHA,
}

/// Create a new SHA context. Returns opaque pointer.
/// use_sha1: true=SHA1, false=SHA256
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha_new(use_sha1: bool) -> *mut ShaContext {
    let inner = if use_sha1 {
        sign::SHA::SHA1(sha1::Sha1::default())
    } else {
        sign::SHA::SHA256(sha2::Sha256::default())
    };
    Box::into_raw(Box::new(ShaContext { inner }))
}

/// Update SHA context with data.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha_update(ctx: *mut ShaContext, data: *const u8, len: usize) {
    let ctx = unsafe { &mut *ctx };
    let data = unsafe { std::slice::from_raw_parts(data, len) };
    ctx.inner.update(data);
}

/// Finalize SHA and write digest to `out`. Returns digest size.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha_finalize(ctx: *mut ShaContext, out: *mut u8, out_len: usize) -> usize {
    let ctx = unsafe { &mut *ctx };
    let size = ctx.inner.output_size();
    if out_len >= size {
        let out = unsafe { std::slice::from_raw_parts_mut(out, size) };
        ctx.inner.finalize_into(out);
    }
    size
}

/// Get output size of SHA context.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha_output_size(ctx: *const ShaContext) -> usize {
    let ctx = unsafe { &*ctx };
    ctx.inner.output_size()
}

/// Free SHA context.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha_free(ctx: *mut ShaContext) {
    if !ctx.is_null() {
        unsafe { drop(Box::from_raw(ctx)) };
    }
}

/// Compute SHA256 hash of data directly.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sha256_hash(data: *const u8, data_len: usize, out: *mut u8, out_len: usize) {
    if out_len < 32 {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    let out = unsafe { std::slice::from_raw_parts_mut(out, 32) };
    sign::sha256_hash(data, out);
}

// ---------------------------------------------------------------------------
// sign_payload callback for C++
// ---------------------------------------------------------------------------

/// Sign payload with embedded AOSP verity key. Returns DER-encoded signature.
/// Caller must free the returned buffer with rust_free_vec.
#[unsafe(no_mangle)]
pub extern "C" fn rust_sign_payload(
    payload: *const u8,
    payload_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let result = sign::sign_payload_for_cxx(payload);
    if result.is_empty() {
        unsafe { *out_len = 0 };
        return std::ptr::null_mut();
    }
    unsafe { *out_len = result.len() };
    let mut boxed = result.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

/// Free a buffer allocated by rust_sign_payload.
#[unsafe(no_mangle)]
pub extern "C" fn rust_free_vec(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }
}

// ---------------------------------------------------------------------------
// Format check callback for C++
// ---------------------------------------------------------------------------

/// check_fmt: detect file format from magic bytes.
/// Called from C++ bootimg.cpp
#[unsafe(no_mangle)]
pub extern "C" fn rust_check_fmt(buf: *const u8, len: usize) -> i32 {
    let buf = unsafe { std::slice::from_raw_parts(buf, len) };
    crate::ffi::check_fmt(buf) as i32
}

// ---------------------------------------------------------------------------
// Helper: i32 → FileFormat
// ---------------------------------------------------------------------------

fn int_to_format(v: i32) -> FileFormat {
    match v {
        0 => FileFormat::UNKNOWN,
        1 => FileFormat::CHROMEOS,
        2 => FileFormat::AOSP,
        3 => FileFormat::AOSP_VENDOR,
        4 => FileFormat::DHTB,
        5 => FileFormat::BLOB,
        6 => FileFormat::GZIP,
        7 => FileFormat::ZOPFLI,
        8 => FileFormat::XZ,
        9 => FileFormat::LZMA,
        10 => FileFormat::BZIP2,
        11 => FileFormat::LZ4,
        12 => FileFormat::LZ4_LEGACY,
        13 => FileFormat::LZ4_LG,
        14 => FileFormat::LZOP,
        15 => FileFormat::MTK,
        16 => FileFormat::DTB,
        17 => FileFormat::ZIMAGE,
        _ => FileFormat::UNKNOWN,
    }
}
