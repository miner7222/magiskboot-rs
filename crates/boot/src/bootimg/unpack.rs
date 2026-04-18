//! Boot image unpack — pure-Rust port of the C++ `boot_img`
//! constructor + `parse_image` + `parse_hdr` + `dump` path.
//!
//! This turn seeds the AOSP v3 / v4 boot_img path (no vendor_boot,
//! no v0 / v1 / v2 / PXA, no MTK, no zImage kernel carve). That
//! covers every image the Phase-7 user-facing target ships — Lenovo
//! TB320 / TB322FC firmware uses AOSP v4 for both `boot.img` and
//! `init_boot.img`. Follow-up commits add vendor_boot + legacy
//! versions + the exotic wrappers.
//!
//! The exit-code bitmask returned by [`unpack`] stays
//! binary-compatible with the upstream C++ build — LTBox reads
//! individual bits to drive downstream logic (e.g. whether AVB
//! re-signing is required).

use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;

use bytemuck::Pod;

use crate::bootimg::hdr::{
    align_to, BootFlag, BootImgHdrV3, BootImgHdrV4, BOOT_FLAGS_MAX, BOOT_MAGIC,
    CHROMEOS_MAGIC, DHTB_MAGIC, BLOB_MAGIC,
};

/// Exit-code bit for a specific [`BootFlag`] — mirrors the C++
/// `std::bitset<BOOT_FLAGS_MAX>` layout + the CLI's `exit(flags.to_ulong())`.
fn flag_bit(f: BootFlag) -> u32 {
    1u32 << (f as u32)
}

/// Outcome of a successful unpack: the detected flag bitmask plus
/// the decoded header (for sanity / downstream tooling).
#[derive(Clone, Copy, Debug)]
pub struct UnpackReport {
    /// Bit-OR of [`BootFlag`] values — passed to `std::process::exit`
    /// by the CLI entry point and binary-compatible with v30.7.
    pub flags: u32,
    /// Header version (3 or 4 in this module's scope).
    pub header_version: u32,
    /// Byte offset of the AOSP header inside the mmap'd file — 0
    /// for unwrapped images, >0 when one of the outer wrappers was
    /// stripped.
    pub payload_offset: usize,
}

impl UnpackReport {
    /// True iff the corresponding flag bit is set.
    pub fn has(&self, f: BootFlag) -> bool {
        self.flags & flag_bit(f) != 0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("file does not contain an AOSP boot image magic")]
    NotAnAospBootImage,
    #[error("unsupported header version {0} — this module only covers v3/v4")]
    UnsupportedVersion(u32),
    #[error("header field overflow — image truncated before section {section}")]
    Truncated { section: &'static str },
}

/// Unpack `image_path` into `out_dir`, writing `kernel`, `ramdisk.cpio`,
/// and (when present) `signature` sibling files. Compressed sections
/// are decompressed transparently unless `skip_decompress` is `true`.
///
/// `write_header_txt` controls whether a `header` text file with
/// `key=value` lines lands next to the sections — LTBox does not
/// rely on this today but upstream CLI exposes it via `--header-file`.
///
/// Returns an [`UnpackReport`] whose `flags` field is the
/// `exit(...)` bitmask the CLI should return.
pub fn unpack(
    image_path: &Path,
    out_dir: &Path,
    skip_decompress: bool,
    write_header_txt: bool,
) -> Result<UnpackReport, UnpackError> {
    let buf = std::fs::read(image_path)?;
    let (outer_flags, header_offset) = sniff_outer(&buf);

    // Slice from the detected AOSP header onward; headers + section
    // offsets are relative to this cursor.
    let payload = buf
        .get(header_offset..)
        .ok_or(UnpackError::NotAnAospBootImage)?;

    // Must start with AOSP magic — otherwise the outer sniff picked
    // a wrapper that carried us past the real header (or there is no
    // boot image here at all).
    if payload.len() < BOOT_MAGIC.len() || &payload[..BOOT_MAGIC.len()] != BOOT_MAGIC {
        return Err(UnpackError::NotAnAospBootImage);
    }

    // The header_version field sits at the same byte offset for v3
    // and v4 (after magic + 4 u32s + reserved[4] = 8 + 16 + 16 = 40).
    const HEADER_VERSION_OFFSET: usize = 40;
    let header_version = {
        let slice = payload
            .get(HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + 4)
            .ok_or(UnpackError::Truncated { section: "header_version" })?;
        u32::from_le_bytes(slice.try_into().unwrap())
    };

    let mut report = UnpackReport {
        flags: outer_flags,
        header_version,
        payload_offset: header_offset,
    };

    std::fs::create_dir_all(out_dir)?;

    match header_version {
        3 => {
            let hdr: &BootImgHdrV3 = pod_ref(payload)?;
            unpack_v3_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
            if write_header_txt {
                write_header_file(hdr, out_dir)?;
            }
        }
        4 => {
            let hdr: &BootImgHdrV4 = pod_ref(payload)?;
            unpack_v4_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
            if write_header_txt {
                write_header_file(&hdr.v3, out_dir)?;
            }
        }
        other => return Err(UnpackError::UnsupportedVersion(other)),
    }

    Ok(report)
}

/// Return a `&T` view into the start of `buf`. Safe because every
/// header type we use is `Pod`; errors if `buf` is too short.
fn pod_ref<T: Pod>(buf: &[u8]) -> Result<&T, UnpackError> {
    let need = std::mem::size_of::<T>();
    if buf.len() < need {
        return Err(UnpackError::Truncated { section: "header" });
    }
    Ok(bytemuck::from_bytes(&buf[..need]))
}

/// Port of the C++ constructor's outer-wrapper scan. Walks the mmap
/// byte-by-byte looking for one of the recognised wrappers; on a hit
/// sets the corresponding flag + skips over the wrapper. Stops at
/// the first AOSP magic and returns the byte offset of that magic.
///
/// Current coverage: ChromeOS, DHTB, Tegra Blob, and direct AOSP.
/// Follow-up commits will add Nook HD, Acclaim, Amonet, Z4, MTK,
/// zImage + vendor_boot detection, matching the C++ loop's other
/// cases one-by-one with their own tests.
fn sniff_outer(buf: &[u8]) -> (u32, usize) {
    let mut flags: u32 = 0;
    let mut i = 0usize;
    while i < buf.len() {
        let rem = &buf[i..];
        if rem.starts_with(CHROMEOS_MAGIC) {
            flags |= flag_bit(BootFlag::ChromeOs);
            // C++: addr += 65535
            i += 65535;
            continue;
        }
        if rem.starts_with(DHTB_MAGIC) {
            flags |= flag_bit(BootFlag::Dhtb);
            flags |= flag_bit(BootFlag::SeAndroid);
            // DHTB wrapper is 512 bytes.
            i += 512;
            continue;
        }
        if rem.starts_with(BLOB_MAGIC) {
            flags |= flag_bit(BootFlag::Blob);
            // BlobHdr is 104 bytes; skip past it.
            i += 104;
            continue;
        }
        if rem.starts_with(BOOT_MAGIC) {
            return (flags, i);
        }
        i += 1;
    }
    (flags, buf.len())
}

/// Boot v3: layout is fixed — header (4096 B) → kernel → ramdisk,
/// each section padded up to the next 4 KiB boundary.
fn unpack_v3_sections(
    hdr: &BootImgHdrV3,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    _report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    const PAGE: u64 = 4096;
    let kernel_size = hdr.kernel_size as u64;
    let ramdisk_size = hdr.ramdisk_size as u64;

    let mut off = PAGE; // header is always one 4 KiB page in v3+
    dump_section(
        payload,
        off as usize,
        kernel_size as usize,
        out_dir,
        "kernel",
        skip_decompress,
    )?;
    off = align_to(off + kernel_size, PAGE);

    dump_section(
        payload,
        off as usize,
        ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
    )?;
    Ok(())
}

/// Boot v4 = v3 + an extra `signature` section after the ramdisk.
fn unpack_v4_sections(
    hdr: &BootImgHdrV4,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    const PAGE: u64 = 4096;
    let kernel_size = hdr.v3.kernel_size as u64;
    let ramdisk_size = hdr.v3.ramdisk_size as u64;
    let signature_size = hdr.signature_size as u64;

    let mut off = PAGE;
    dump_section(
        payload,
        off as usize,
        kernel_size as usize,
        out_dir,
        "kernel",
        skip_decompress,
    )?;
    off = align_to(off + kernel_size, PAGE);

    dump_section(
        payload,
        off as usize,
        ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
    )?;
    off = align_to(off + ramdisk_size, PAGE);

    if signature_size > 0 {
        dump_section(
            payload,
            off as usize,
            signature_size as usize,
            out_dir,
            "signature",
            true, // signatures are raw blobs; never decompress
        )?;
        report.flags |= flag_bit(BootFlag::Avb);
    }
    Ok(())
}

/// Write `len` bytes starting at `off` to `<out_dir>/<name>`. Zero-
/// sized sections are skipped. When `skip_decompress` is false and
/// the bytes look compressed, they are piped through the matching
/// decoder first — same behaviour as the C++ `dump()` helper.
fn dump_section(
    payload: &[u8],
    off: usize,
    len: usize,
    out_dir: &Path,
    name: &str,
    skip_decompress: bool,
) -> Result<(), UnpackError> {
    if len == 0 {
        return Ok(());
    }
    let end = off.checked_add(len).ok_or(UnpackError::Truncated { section: "section" })?;
    if end > payload.len() {
        return Err(UnpackError::Truncated { section: "section" });
    }
    let slice = &payload[off..end];

    // Compression detection — mirrors the C++ `check_fmt` path, but
    // only decompresses when we recognise a `is_compressed()` format
    // so raw kernel / dtb blobs are written straight.
    let decoded_path = out_dir.join(name);
    if !skip_decompress {
        let fmt = crate::ffi::check_fmt(slice);
        if fmt.is_compressed() {
            let mut out = File::create(&decoded_path)?;
            let mut reader =
                crate::compress::get_decoder(fmt, Box::new(std::io::Cursor::new(slice)))
                    .map_err(|e| UnpackError::Io(io::Error::other(format!("{e}"))))?;
            std::io::copy(&mut reader, &mut out)?;
            return Ok(());
        }
    }

    let mut f = File::create(&decoded_path)?;
    f.write_all(slice)?;
    Ok(())
}

/// Write a minimal `<out_dir>/header` file the v3 / v4 path uses to
/// round-trip human-editable fields (cmdline + os_version). Same
/// `key=value` shape the upstream C++ `dump_hdr_file()` wrote.
fn write_header_file(hdr: &BootImgHdrV3, out_dir: &Path) -> Result<(), UnpackError> {
    let mut f = File::create(out_dir.join("header"))?;
    // cmdline: cmdline[0..512] + extra cmdline[512..1536].
    let cmdline_bytes = &hdr.cmdline[..];
    let end = cmdline_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(cmdline_bytes.len());
    let cmdline = std::str::from_utf8(&cmdline_bytes[..end]).unwrap_or("");
    writeln!(f, "cmdline={cmdline}")?;

    let os_version = hdr.os_version;
    if os_version != 0 {
        let version = (os_version >> 11) & 0x7f_ffff;
        let patch_level = os_version & 0x7ff;
        let a = (version >> 14) & 0x7f;
        let b = (version >> 7) & 0x7f;
        let c = version & 0x7f;
        writeln!(f, "os_version={a}.{b}.{c}")?;
        let y = (patch_level >> 4) + 2000;
        let m = patch_level & 0xf;
        writeln!(f, "os_patch_level={y}-{m:02}")?;
    }
    let _ = BOOT_FLAGS_MAX; // silence warning if not referenced elsewhere
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    fn build_hdr_v3(kernel_size: u32, ramdisk_size: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&kernel_size.to_le_bytes());
        hdr[12..16].copy_from_slice(&ramdisk_size.to_le_bytes());
        // header_version at offset 40
        hdr[40..44].copy_from_slice(&3u32.to_le_bytes());
        hdr
    }

    fn build_hdr_v4(kernel_size: u32, ramdisk_size: u32, signature_size: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; size_of::<BootImgHdrV4>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&kernel_size.to_le_bytes());
        hdr[12..16].copy_from_slice(&ramdisk_size.to_le_bytes());
        hdr[40..44].copy_from_slice(&4u32.to_le_bytes());
        // signature_size sits right after the v3 block
        let sig_off = size_of::<BootImgHdrV3>();
        hdr[sig_off..sig_off + 4].copy_from_slice(&signature_size.to_le_bytes());
        hdr
    }

    fn assemble_v3_image(kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut out = build_hdr_v3(kernel.len() as u32, ramdisk.len() as u32);
        out.resize(PAGE, 0);
        out.extend_from_slice(kernel);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out
    }

    fn assemble_v4_image(kernel: &[u8], ramdisk: &[u8], signature: &[u8]) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut out = build_hdr_v4(
            kernel.len() as u32,
            ramdisk.len() as u32,
            signature.len() as u32,
        );
        out.resize(PAGE, 0);
        out.extend_from_slice(kernel);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        if !signature.is_empty() {
            out.extend_from_slice(signature);
            while out.len() % PAGE != 0 {
                out.push(0);
            }
        }
        out
    }

    #[test]
    fn sniff_outer_detects_direct_aosp() {
        let mut img = vec![0u8; 4096];
        img[..8].copy_from_slice(BOOT_MAGIC);
        let (flags, off) = sniff_outer(&img);
        assert_eq!(flags, 0);
        assert_eq!(off, 0);
    }

    #[test]
    fn sniff_outer_strips_dhtb_wrapper() {
        let mut img = vec![0u8; 8192];
        img[..DHTB_MAGIC.len()].copy_from_slice(DHTB_MAGIC);
        // AOSP magic lands at the 512-byte boundary.
        img[512..520].copy_from_slice(BOOT_MAGIC);
        let (flags, off) = sniff_outer(&img);
        assert!(flags & flag_bit(BootFlag::Dhtb) != 0);
        assert!(flags & flag_bit(BootFlag::SeAndroid) != 0);
        assert_eq!(off, 512);
    }

    #[test]
    fn sniff_outer_strips_blob_wrapper() {
        let mut img = vec![0u8; 8192];
        img[..BLOB_MAGIC.len()].copy_from_slice(BLOB_MAGIC);
        img[104..112].copy_from_slice(BOOT_MAGIC);
        let (flags, off) = sniff_outer(&img);
        assert!(flags & flag_bit(BootFlag::Blob) != 0);
        assert_eq!(off, 104);
    }

    #[test]
    fn unpack_v3_writes_kernel_and_ramdisk() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"--KERNEL-BLOB--".to_vec();
        let ramdisk = b"0707010000000 fake cpio".to_vec();
        let img = assemble_v3_image(&kernel, &ramdisk);
        let img_path = tmp.path().join("boot.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert_eq!(report.header_version, 3);
        assert_eq!(report.flags, 0);

        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn unpack_v4_writes_signature_and_flags_avb() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"k".repeat(123);
        let ramdisk = b"r".repeat(456);
        let signature = b"s".repeat(64);
        let img = assemble_v4_image(&kernel, &ramdisk, &signature);
        let img_path = tmp.path().join("boot.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert_eq!(report.header_version, 4);
        assert!(report.has(BootFlag::Avb));

        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(out.join("signature")).unwrap(), signature);
    }

    #[test]
    fn unpack_rejects_non_aosp_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let junk = vec![0xffu8; 4096];
        let img_path = tmp.path().join("junk.img");
        std::fs::write(&img_path, &junk).unwrap();
        let out = tmp.path().join("out");
        let err = unpack(&img_path, &out, true, false).unwrap_err();
        assert!(matches!(err, UnpackError::NotAnAospBootImage));
    }

    #[test]
    fn unpack_rejects_unsupported_version() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[40..44].copy_from_slice(&2u32.to_le_bytes());
        hdr.resize(4096, 0);
        let img_path = tmp.path().join("v2.img");
        std::fs::write(&img_path, &hdr).unwrap();
        let out = tmp.path().join("out");
        let err = unpack(&img_path, &out, true, false).unwrap_err();
        assert!(matches!(err, UnpackError::UnsupportedVersion(2)));
    }

    /// Hardware-in-the-loop smoke test — runs only when the
    /// `LTBOX_TB322_IMAGES` env var points at a firmware directory
    /// with TB322FC's `init_boot.img` and `boot.img`. Skipped
    /// otherwise so the default `cargo test` stays hermetic.
    ///
    /// We assert just layout-level invariants:
    ///
    /// - Header version is 4 (both Lenovo images).
    /// - Every non-empty section the header advertises actually
    ///   lands on disk with the declared byte count.
    ///
    /// AVB signature-block checks are deliberately absent — some
    /// Lenovo v4 images leave `signature_size = 0` and carry their
    /// AVB2 footer as an appended tail instead. Tail detection is
    /// added in the next sub-phase.
    #[test]
    fn unpack_tb322fc_samples() {
        let Ok(dir) = std::env::var("LTBOX_TB322_IMAGES") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        for img_name in ["init_boot.img", "boot.img"] {
            let img = dir.join(img_name);
            if !img.exists() {
                continue;
            }
            let tmp = tempfile::tempdir().unwrap();
            let out = tmp.path().join("out");
            let report = unpack(&img, &out, true, true)
                .unwrap_or_else(|e| panic!("{img_name} unpack: {e}"));
            assert_eq!(report.header_version, 4, "{img_name} version");

            // Re-read the header to confirm the on-disk section
            // sizes match what unpack wrote.
            let bytes = std::fs::read(&img).unwrap();
            let v4: &BootImgHdrV4 =
                bytemuck::from_bytes(&bytes[..size_of::<BootImgHdrV4>()]);
            let ksz = v4.v3.kernel_size as u64;
            let rsz = v4.v3.ramdisk_size as u64;
            if ksz > 0 {
                let k = std::fs::read(out.join("kernel")).unwrap();
                assert_eq!(k.len() as u64, ksz, "{img_name} kernel size");
            }
            if rsz > 0 {
                let r = std::fs::read(out.join("ramdisk.cpio")).unwrap();
                assert_eq!(r.len() as u64, rsz, "{img_name} ramdisk size");
            }
        }
    }

    /// Byte-for-byte parity against the C++ `magiskboot unpack`
    /// output. Runs only when `LTBOX_PARITY_CPP` points at a
    /// directory that already contains the reference outputs a
    /// previous `magiskboot.exe` run produced in an otherwise-empty
    /// folder (the original `init_boot.img` must sit next to the
    /// reference `ramdisk.cpio`).
    ///
    /// This closes the loop on 7B: an unnoticed byte-drift in
    /// either the header carve or the downstream decompression
    /// trips here before it trips LTBox's Magisk patch.
    #[test]
    fn unpack_byte_matches_cpp_reference() {
        let Ok(ref_dir) = std::env::var("LTBOX_PARITY_CPP") else {
            return;
        };
        let ref_dir = std::path::PathBuf::from(ref_dir);
        // Accept whichever boot image the user dropped in the
        // reference dir — init_boot.img, boot.img, or vendor_boot.img.
        for img_name in ["init_boot.img", "boot.img", "vendor_boot.img"] {
            let src = ref_dir.join(img_name);
            if !src.exists() {
                continue;
            }
            let tmp = tempfile::tempdir().unwrap();
            let out = tmp.path();
            unpack(&src, out, /* skip_decompress = */ false, true)
                .unwrap_or_else(|e| panic!("{img_name} unpack: {e}"));

            // Every section the C++ binary produced must exist with
            // identical bytes. Extra sections (header, kernel when
            // present) are also diffed when the reference has them.
            for name in ["kernel", "ramdisk.cpio", "dtb", "second", "signature", "header"] {
                let ref_p = ref_dir.join(name);
                if !ref_p.exists() {
                    continue;
                }
                let ours = out.join(name);
                assert!(ours.exists(), "{img_name}: missing {name} in Rust output");
                let a = std::fs::read(&ref_p).unwrap();
                let b = std::fs::read(&ours).unwrap();
                assert_eq!(
                    a,
                    b,
                    "{img_name}: {name} bytes differ (cpp {} vs rust {})",
                    a.len(),
                    b.len()
                );
            }
        }
    }
}
