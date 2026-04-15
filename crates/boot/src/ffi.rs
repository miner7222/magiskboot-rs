// Standalone FFI shim — replaces CXX bridge from upstream lib.rs
//
// Upstream: lib.rs defines `#[cxx::bridge] pub mod ffi { ... }` with FileFormat enum
// and C++ extern functions. This module provides the same types and function signatures
// so that other .rs files can `use crate::ffi::*` unchanged.
//
// C++ functions (unpack, repack, cleanup, split_image_dtb, check_fmt) are stubbed
// here and will be wired to actual C++ via CXX in Phase 3.

/// File format enum — matches upstream CXX bridge definition exactly.
/// Kept as a plain Rust enum instead of CXX-generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum FileFormat {
    UNKNOWN = 0,
    /* Boot formats */
    CHROMEOS = 1,
    AOSP = 2,
    AOSP_VENDOR = 3,
    DHTB = 4,
    BLOB = 5,
    /* Compression formats */
    GZIP = 6,
    ZOPFLI = 7,
    XZ = 8,
    LZMA = 9,
    BZIP2 = 10,
    LZ4 = 11,
    LZ4_LEGACY = 12,
    LZ4_LG = 13,
    /* Unsupported compression */
    LZOP = 14,
    /* Misc */
    MTK = 15,
    DTB = 16,
    ZIMAGE = 17,
}

// ---------------------------------------------------------------------------
// C++ function stubs — will be replaced with actual CXX bridge in Phase 3
// ---------------------------------------------------------------------------

/// Format detection from magic bytes.
/// Stub: reimplemented in Rust based on upstream bootimg.cpp check_fmt().
pub fn check_fmt(buf: &[u8]) -> FileFormat {
    if buf.len() < 4 {
        return FileFormat::UNKNOWN;
    }

    // GZIP magic
    if buf.len() >= 4 && buf[0] == 0x1f && buf[1] == 0x8b && buf[2] == 0x08 {
        return FileFormat::GZIP;
    }

    // XZ magic
    if buf.len() >= 6 && buf[..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] {
        return FileFormat::XZ;
    }

    // LZMA magic (heuristic)
    if buf.len() >= 13 && buf[0] == 0x5d && buf[1] == 0x00 && buf[2] == 0x00 {
        return FileFormat::LZMA;
    }

    // BZIP2 magic
    if buf.len() >= 4 && buf[..2] == *b"BZ" && buf[2] == b'h' {
        return FileFormat::BZIP2;
    }

    // LZ4 frame magic
    if buf.len() >= 4 {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic == 0x184D2204 {
            return FileFormat::LZ4;
        }
        // LZ4 legacy magic
        if magic == 0x184C2102 {
            return FileFormat::LZ4_LEGACY;
        }
    }

    // LZOP magic
    if buf.len() >= 9 && buf[..9] == [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a] {
        return FileFormat::LZOP;
    }

    // ChromeOS
    if buf.len() >= 8 && &buf[..8] == b"CHROMEOS" {
        return FileFormat::CHROMEOS;
    }

    // AOSP boot image
    if buf.len() >= 8 && &buf[..8] == b"ANDROID!" {
        return FileFormat::AOSP;
    }

    // AOSP vendor boot
    if buf.len() >= 12 && buf[..12] == b"VNDRBOOT\x00\x00\x00\x03"[..12] {
        return FileFormat::AOSP_VENDOR;
    }

    // DTB magic (big-endian)
    if buf.len() >= 4 {
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic == 0xd00dfeed {
            return FileFormat::DTB;
        }
    }

    // DHTB magic
    if buf.len() >= 8 && &buf[..4] == b"DHTB" {
        return FileFormat::DHTB;
    }

    // BLOB (Tegra)
    if buf.len() >= 16 && buf[..4] == [0x00, 0x00, 0x00, 0x00]
        && &buf[4..12] == b"\x00\x00\x00\x00\x00\x00\x00\x00"
    {
        // Heuristic: BLOB detection is complex, skip for now
    }

    // MTK magic
    if buf.len() >= 4 && buf[..4] == [0x88, 0x16, 0x88, 0x58] {
        return FileFormat::MTK;
    }

    FileFormat::UNKNOWN
}

// ---------------------------------------------------------------------------
// C++ wrapper functions — linked via extern "C" from cpp/wrapper.cpp
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn magiskboot_unpack(image: *const std::ffi::c_char, skip_decomp: i32, hdr: i32) -> i32;
    fn magiskboot_repack(src_img: *const std::ffi::c_char, out_img: *const std::ffi::c_char, skip_comp: i32);
    fn magiskboot_split_image_dtb(filename: *const std::ffi::c_char, skip_decomp: i32) -> i32;
    fn magiskboot_cleanup();
}

/// Clean up temporary files in current directory.
pub fn cleanup() {
    unsafe { magiskboot_cleanup(); }
}

/// Unpack boot image.
pub fn unpack(image: &str, skip_decomp: bool, hdr: bool) -> i32 {
    let c_image = std::ffi::CString::new(image).unwrap();
    unsafe { magiskboot_unpack(c_image.as_ptr(), skip_decomp as i32, hdr as i32) }
}

/// Repack boot image.
pub fn repack(src_img: &str, out_img: &str, skip_comp: bool) {
    let c_src = std::ffi::CString::new(src_img).unwrap();
    let c_out = std::ffi::CString::new(out_img).unwrap();
    unsafe { magiskboot_repack(c_src.as_ptr(), c_out.as_ptr(), skip_comp as i32); }
}

/// Split image DTB.
pub fn split_image_dtb(filename: &str, skip_decomp: bool) -> i32 {
    let c_filename = std::ffi::CString::new(filename).unwrap();
    unsafe { magiskboot_split_image_dtb(c_filename.as_ptr(), skip_decomp as i32) }
}

// ---------------------------------------------------------------------------
// BootImage stub — will be replaced with CXX UniquePtr<boot_img> in Phase 3
// ---------------------------------------------------------------------------

/// Placeholder for C++ boot_img class.
pub struct BootImage {
    payload_data: Vec<u8>,
    tail_data: Vec<u8>,
    signed: bool,
    tail_offset: u64,
}

impl BootImage {
    pub fn new(_img: &str) -> Box<BootImage> {
        eprintln!("Warning: BootImage C++ integration not yet available");
        Box::new(BootImage {
            payload_data: Vec::new(),
            tail_data: Vec::new(),
            signed: false,
            tail_offset: 0,
        })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload_data
    }

    pub fn tail(&self) -> &[u8] {
        &self.tail_data
    }

    pub fn is_signed(&self) -> bool {
        self.signed
    }

    pub fn tail_off(&self) -> u64 {
        self.tail_offset
    }
}
