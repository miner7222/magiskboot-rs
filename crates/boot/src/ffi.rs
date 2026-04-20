// Crate-internal boot-image entry points.
//
// Upstream Magisk v30.7 exposed these through a CXX bridge into
// `cpp/bootimg.cpp`; this module is the Rust-native replacement so
// every other file under `crates/boot/src/` can still `use
// crate::ffi::*` with no signature churn. The actual parse /
// unpack / repack / split logic lives in `bootimg/`. What stays
// here:
//
// - `FileFormat` enum (matches upstream numbering for any caller
//   that still round-trips it as `i32`).
// - `check_fmt` magic-byte sniffer.
// - Thin forwarders `unpack` / `repack` / `cleanup` /
//   `split_image_dtb` that the CLI dispatches into.
// - `BootImage` — a parsed view of a boot image on disk, backing
//   the `sign.rs` verify path.

/// File format enum — numbering matches upstream Magisk's CXX
/// bridge definition so any caller round-tripping through `i32`
/// stays compatible.
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
// Format detection — pure Rust port of bootimg.cpp::check_fmt.
// ---------------------------------------------------------------------------

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
// Pure-Rust entry points — replace the previous CXX bridge to
// `cpp/bootimg.cpp`. Each one forwards into the `bootimg::*` module,
// using the current working directory as the work dir so the CLI
// contract stays identical: drop sections into `./kernel`,
// `./ramdisk.cpio`, ...
//
// Errors are folded into the upstream integer return shape — 0 on
// success, 1 on failure for split, and the flag bitmask for unpack.
// ---------------------------------------------------------------------------

/// Clean up temporary files in the current directory that `unpack`
/// may have written. Silently ignores missing files.
pub fn cleanup() {
    for name in [
        "header",
        "kernel",
        "ramdisk.cpio",
        "second",
        "kernel_dtb",
        "extra",
        "recovery_dtbo",
        "dtb",
        "bootconfig",
        "signature",
    ] {
        let _ = std::fs::remove_file(name);
    }
    let _ = std::fs::remove_dir_all("vendor_ramdisk");
}

/// Unpack a boot image into the current working directory.
/// Returns the upstream-compatible flag bitmask on success, or `-1`
/// on failure — callers pass this to `std::process::exit`.
pub fn unpack(image: &str, skip_decomp: bool, hdr: bool) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::bootimg::unpack(std::path::Path::new(image), &cwd, skip_decomp, hdr) {
        Ok(report) => report.flags as i32,
        Err(e) => {
            eprintln!("! unpack failed: {e}");
            -1
        }
    }
}

/// Repack a boot image using sections from the current working
/// directory.
pub fn repack(src_img: &str, out_img: &str, skip_comp: bool) {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    if let Err(e) = crate::bootimg::repack(
        std::path::Path::new(src_img),
        &cwd,
        std::path::Path::new(out_img),
        skip_comp,
    ) {
        eprintln!("! repack failed: {e}");
    }
}

/// Split an appended-DTB kernel image into `./kernel` + `./kernel_dtb`.
/// Returns `0` on success, `1` when no DTB was found — matches the
/// upstream exit-code contract.
pub fn split_image_dtb(filename: &str, skip_decomp: bool) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::bootimg::split_image_dtb(std::path::Path::new(filename), &cwd, skip_decomp) {
        Ok(rc) => rc,
        Err(e) => {
            eprintln!("! split failed: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// BootImage — pure-Rust parse of an AOSP boot image. Mirrors
// `cpp/bootimg.cpp::boot_img` for the fields downstream callers +
// the `verify` / `sign` CLI paths actually consume: `payload`,
// `tail`, `is_signed`, `tail_off`.
//
// Coverage matches `bootimg::unpack`: AOSP v3 / v4, with outer
// wrapper strip for ChromeOS / DHTB / Tegra Blob. Legacy v0..v2 +
// vendor_boot are stubbed to empty payload/tail so callers see a
// well-defined "unsupported" state rather than a panic.
// ---------------------------------------------------------------------------

use crate::bootimg::hdr::{
    BootImgHdrV3, BootImgHdrV4, AVB1_SIGNATURE_MAGIC, BOOT_MAGIC,
};
use crate::bootimg::unpack::sniff_outer_for_repack;

/// Parsed view of a boot image held in memory.
pub struct BootImage {
    /// Owned backing buffer — the file's entire contents. `payload`
    /// and `tail` reference slices into this.
    buf: Vec<u8>,
    /// `[start, end)` of the AOSP payload (header + all sections)
    /// within `buf`. Zero-length for unsupported images.
    payload_range: (usize, usize),
    /// `[start, end)` of the trailing bytes past the AOSP payload.
    tail_range: (usize, usize),
    /// True iff the tail starts with the AVB1 `AVB\0` magic.
    signed: bool,
}

impl BootImage {
    /// Parse the boot image at `img`. Unsupported headers (v0..v2,
    /// vendor_boot, broken files) collapse to empty ranges; callers
    /// observe that via a zero-length `payload()` / `tail()`.
    pub fn new(img: &str) -> Box<BootImage> {
        let buf = match std::fs::read(img) {
            Ok(b) => b,
            Err(_) => {
                return Box::new(BootImage {
                    buf: Vec::new(),
                    payload_range: (0, 0),
                    tail_range: (0, 0),
                    signed: false,
                });
            }
        };

        let (_flags, hdr_off) = sniff_outer_for_repack(&buf);
        let (payload_end, tail_end) = compute_ranges(&buf, hdr_off);
        let tail_range = (payload_end, tail_end);
        let signed = tail_slice(&buf, tail_range)
            .get(..AVB1_SIGNATURE_MAGIC.len())
            .is_some_and(|m| m == AVB1_SIGNATURE_MAGIC);

        Box::new(BootImage {
            buf,
            payload_range: (hdr_off, payload_end),
            tail_range,
            signed,
        })
    }

    pub fn payload(&self) -> &[u8] {
        payload_slice(&self.buf, self.payload_range)
    }

    pub fn tail(&self) -> &[u8] {
        tail_slice(&self.buf, self.tail_range)
    }

    pub fn is_signed(&self) -> bool {
        self.signed
    }

    pub fn tail_off(&self) -> u64 {
        self.tail_range.0 as u64
    }
}

fn payload_slice(buf: &[u8], range: (usize, usize)) -> &[u8] {
    if range.1 <= buf.len() && range.0 <= range.1 {
        &buf[range.0..range.1]
    } else {
        &[]
    }
}

fn tail_slice(buf: &[u8], range: (usize, usize)) -> &[u8] {
    if range.1 <= buf.len() && range.0 <= range.1 {
        &buf[range.0..range.1]
    } else {
        &[]
    }
}

/// Return `(payload_end, tail_end)` indices for the AOSP image
/// starting at `hdr_off` in `buf`. Unsupported headers return
/// `(hdr_off, hdr_off)` so the caller sees empty ranges.
fn compute_ranges(buf: &[u8], hdr_off: usize) -> (usize, usize) {
    if hdr_off >= buf.len() {
        return (hdr_off, hdr_off);
    }
    let payload = &buf[hdr_off..];
    if payload.len() < BOOT_MAGIC.len() || &payload[..BOOT_MAGIC.len()] != BOOT_MAGIC {
        return (hdr_off, hdr_off);
    }
    const HEADER_VERSION_OFFSET: usize = 40;
    if payload.len() < HEADER_VERSION_OFFSET + 4 {
        return (hdr_off, hdr_off);
    }
    let ver = u32::from_le_bytes(
        payload[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    const PAGE: usize = 4096;
    fn align_up(v: usize, a: usize) -> usize {
        v.div_ceil(a) * a
    }
    let payload_end_rel = match ver {
        3 => {
            if payload.len() < std::mem::size_of::<BootImgHdrV3>() {
                return (hdr_off, hdr_off);
            }
            let h: &BootImgHdrV3 =
                bytemuck::from_bytes(&payload[..std::mem::size_of::<BootImgHdrV3>()]);
            let k = h.kernel_size as usize;
            let r = h.ramdisk_size as usize;
            let kernel_off = PAGE;
            let ramdisk_off = align_up(kernel_off + k, PAGE);
            align_up(ramdisk_off + r, PAGE)
        }
        4 => {
            if payload.len() < std::mem::size_of::<BootImgHdrV4>() {
                return (hdr_off, hdr_off);
            }
            let h: &BootImgHdrV4 =
                bytemuck::from_bytes(&payload[..std::mem::size_of::<BootImgHdrV4>()]);
            let k = h.v3.kernel_size as usize;
            let r = h.v3.ramdisk_size as usize;
            let s = h.signature_size as usize;
            let kernel_off = PAGE;
            let ramdisk_off = align_up(kernel_off + k, PAGE);
            let signature_off = align_up(ramdisk_off + r, PAGE);
            if s > 0 {
                align_up(signature_off + s, PAGE)
            } else {
                signature_off
            }
        }
        _ => {
            // Unsupported versions: no payload/tail decode.
            return (hdr_off, hdr_off);
        }
    };
    let payload_end = hdr_off + payload_end_rel;
    let tail_end = buf.len().min(align_up(buf.len(), PAGE));
    if payload_end > buf.len() {
        return (hdr_off, hdr_off);
    }
    (payload_end, tail_end.max(payload_end))
}

#[cfg(test)]
mod bootimage_tests {
    use super::*;
    use crate::bootimg::hdr::BOOT_MAGIC;
    use std::mem::size_of;

    fn build_v3(kernel: &[u8], ramdisk: &[u8], tail: &[u8]) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        hdr[40..44].copy_from_slice(&3u32.to_le_bytes());
        let mut out = hdr;
        while out.len() < PAGE {
            out.push(0);
        }
        out.extend_from_slice(kernel);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.extend_from_slice(tail);
        out
    }

    #[test]
    fn parses_payload_and_tail_ranges() {
        let tmp = tempfile::tempdir().unwrap();
        let img_bytes = build_v3(&b"K".repeat(10), &b"R".repeat(10), b"TAILBYTES");
        let img_path = tmp.path().join("boot.img");
        std::fs::write(&img_path, &img_bytes).unwrap();
        let bi = BootImage::new(img_path.to_str().unwrap());
        // Payload ends at 8192 (page 0 header + page 1 kernel + page 2 ramdisk).
        assert_eq!(bi.payload().len(), 12288);
        assert_eq!(bi.tail_off(), 12288);
        // Tail contains our TAILBYTES marker.
        assert!(bi.tail().starts_with(b"TAILBYTES"));
        assert!(!bi.is_signed());
    }

    #[test]
    fn flags_avb1_signed_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let img_bytes = build_v3(&b"K".repeat(5), &b"R".repeat(5), b"AVB\x00rest");
        let img_path = tmp.path().join("signed.img");
        std::fs::write(&img_path, &img_bytes).unwrap();
        let bi = BootImage::new(img_path.to_str().unwrap());
        assert!(bi.is_signed());
    }

    #[test]
    fn missing_file_yields_empty_ranges() {
        let bi = BootImage::new("this/path/does/not/exist.img");
        assert!(bi.payload().is_empty());
        assert!(bi.tail().is_empty());
        assert!(!bi.is_signed());
        assert_eq!(bi.tail_off(), 0);
    }

    #[test]
    fn non_aosp_bytes_yield_empty_ranges() {
        let tmp = tempfile::tempdir().unwrap();
        let img_path = tmp.path().join("junk.img");
        std::fs::write(&img_path, vec![0xffu8; 4096]).unwrap();
        let bi = BootImage::new(img_path.to_str().unwrap());
        assert!(bi.payload().is_empty());
        assert!(bi.tail().is_empty());
    }
}
