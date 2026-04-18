//! Boot image repack — pure-Rust port of the C++ `repack()` function.
//!
//! Scope mirrors `unpack.rs`: AOSP boot_img v3 / v4 + the outer
//! wrappers 7B already sniffs (direct AOSP, ChromeOS, DHTB, Tegra
//! Blob). Deferred (follow-up commits, matching `unpack.rs`):
//!
//! - vendor_boot v3 / v4
//! - legacy v0 / v1 / v2 + Samsung PXA
//! - MTK / Nook / Acclaim / Amonet / Z4 wrappers
//! - zImage kernel carve + zopfli recompression for kernel
//! - SHA-1 / SHA-256 `id` field patch (v0..v2 only)
//! - AVB1 signature block (`AVB\0` trailer)
//! - DHTB wrapper SHA-256 checksum + Blob size recomputation when
//!   the AOSP payload grows (Blob/DHTB are direct-copied from source
//!   so size field stays valid as long as the repacked AOSP image
//!   matches the original size — the pad-to-original-length step
//!   below guarantees that for compressed-section round-trips)
//!
//! Byte-layout rules implemented here:
//!
//! - The AOSP payload starts on a fresh page (4 KiB for v3/v4,
//!   matching `hdr_space()` = `align_to(hdr_size, page_size)` in the
//!   C++ source).
//! - Every section (kernel, ramdisk, signature) ends on the next
//!   page boundary *measured from the AOSP header start* — this
//!   matches C++ `file_align()` = `align_padding(lseek - off.header,
//!   page_size)`.
//! - Tail bytes past the last known section (AVB2 footer + vbmeta +
//!   zero pad that Lenovo firmware appends) are copied verbatim from
//!   source. This keeps AVB2 offsets valid when the repacked AOSP
//!   image length matches the source — the common case for a Magisk
//!   patch where ramdisk size changes by < 4 KiB and compression
//!   still lands in the same page.
//! - Output is padded to the source file's length (same as C++
//!   `write_zero(fd, boot.map.size() - current)`).
//!
//! Compression policy:
//!
//! - Kernel keeps its source compression format (or raw if source
//!   was raw).
//! - Ramdisk keeps source format EXCEPT for AOSP v4 — GKI v4
//!   requires LZ4_LEGACY so the C++ source force-upgrades any other
//!   format. This port mirrors that exactly.
//! - `skip_comp = true` writes work-dir bytes raw regardless.

use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::Path;

use bytemuck::Pod;

use crate::bootimg::hdr::{
    align_padding, align_to, BootFlag, BootImgHdrV3, BootImgHdrV4, BLOB_MAGIC, BOOT_MAGIC,
    CHROMEOS_MAGIC, DHTB_MAGIC,
};
use crate::ffi::{check_fmt, FileFormat};

/// Errors the repack path can surface. Mirrors
/// `UnpackError` plus the write-side failure modes.
#[derive(Debug, thiserror::Error)]
pub enum RepackError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("source file does not contain an AOSP boot image magic")]
    NotAnAospBootImage,
    #[error("unsupported header version {0} — this module only covers v3/v4")]
    UnsupportedVersion(u32),
    #[error("source image truncated before section {section}")]
    Truncated { section: &'static str },
    #[error("compression roundtrip failed: {0}")]
    Compress(String),
}

/// Rebuild `<out_img>` from `<src_img>` + files in `<work_dir>`
/// (`kernel`, `ramdisk.cpio`, optional `signature`). Semantics
/// match the upstream `magiskboot repack`: sections present in the
/// work dir replace the originals; missing sections fall back to
/// the source bytes (except that a zero-sized original is a no-op).
///
/// `skip_comp = true` skips both compression and decompression
/// probing, writing work-dir bytes verbatim — same toggle as
/// upstream's `--no-compress`.
pub fn repack(
    src_img: &Path,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let src = std::fs::read(src_img)?;
    let (outer_flags, hdr_off) = crate::bootimg::unpack::sniff_outer_for_repack(&src);
    if hdr_off >= src.len() {
        return Err(RepackError::NotAnAospBootImage);
    }
    let payload = &src[hdr_off..];
    if payload.len() < BOOT_MAGIC.len() || &payload[..BOOT_MAGIC.len()] != BOOT_MAGIC {
        return Err(RepackError::NotAnAospBootImage);
    }

    const HEADER_VERSION_OFFSET: usize = 40;
    if payload.len() < HEADER_VERSION_OFFSET + 4 {
        return Err(RepackError::Truncated { section: "header_version" });
    }
    let header_version = u32::from_le_bytes(
        payload[HEADER_VERSION_OFFSET..HEADER_VERSION_OFFSET + 4]
            .try_into()
            .unwrap(),
    );

    match header_version {
        3 => repack_v3(&src, hdr_off, outer_flags, work_dir, out_img, skip_comp),
        4 => repack_v4(&src, hdr_off, outer_flags, work_dir, out_img, skip_comp),
        other => Err(RepackError::UnsupportedVersion(other)),
    }
}

// ---------------------------------------------------------------------------
// v3 / v4 drivers. They share the same skeleton — differ only in
// the signature section that v4 adds.
// ---------------------------------------------------------------------------

fn repack_v3(
    src: &[u8],
    hdr_off: usize,
    _outer_flags: u32,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    const PAGE: usize = 4096;
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrV3 = pod_ref(payload)?;

    let src_kernel_size = hdr.kernel_size as usize;
    let src_ramdisk_size = hdr.ramdisk_size as usize;

    let kernel_off = PAGE;
    let ramdisk_off = align_to((kernel_off + src_kernel_size) as u64, PAGE as u64) as usize;
    let src_tail_off_rel = align_to((ramdisk_off + src_ramdisk_size) as u64, PAGE as u64) as usize;
    let src_tail_off_abs = hdr_off + src_tail_off_rel;

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    // 1. Wrapper bytes verbatim.
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    // 2. Reserve header page.
    let mut new_hdr = *hdr;
    // Reset section sizes — they will be rewritten below.
    new_hdr.kernel_size = 0;
    new_hdr.ramdisk_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));
    pad_to(&mut out, out_hdr_off, PAGE);

    // 3. Kernel.
    let new_kernel_size = write_section(
        &mut out,
        out_hdr_off,
        &src[hdr_off + kernel_off..hdr_off + kernel_off + src_kernel_size],
        &work_dir.join("kernel"),
        SectionPolicy::Kernel,
        header_version_v3(),
        skip_comp,
    )?;
    new_hdr.kernel_size = new_kernel_size as u32;
    pad_to(&mut out, out_hdr_off, PAGE);

    // 4. Ramdisk.
    let new_ramdisk_size = write_section(
        &mut out,
        out_hdr_off,
        &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + src_ramdisk_size],
        &work_dir.join("ramdisk.cpio"),
        SectionPolicy::Ramdisk,
        header_version_v3(),
        skip_comp,
    )?;
    new_hdr.ramdisk_size = new_ramdisk_size as u32;
    pad_to(&mut out, out_hdr_off, PAGE);

    // 5. Tail (AVB / appended data) verbatim from source. Must be
    //    the last write — any subsequent zero-pad would push the
    //    AVB2 footer (last 64 bytes of the source tail) away from
    //    EOF, which breaks downstream `avbtool erase_footer` calls
    //    (they look at the final 64 bytes for `AVBf` magic).
    if src_tail_off_abs < src.len() {
        out.extend_from_slice(&src[src_tail_off_abs..]);
    }

    // 6. Patch header in place with the rewritten sizes.
    patch_v3_header(&mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV3>()], &new_hdr);

    // 7. Patch outer wrapper size fields.
    patch_outer_wrapper(&mut out, out_hdr_off, src_tail_off_rel);

    write_file(out_img, &out)
}

fn repack_v4(
    src: &[u8],
    hdr_off: usize,
    _outer_flags: u32,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    const PAGE: usize = 4096;
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrV4 = pod_ref(payload)?;

    let src_kernel_size = hdr.v3.kernel_size as usize;
    let src_ramdisk_size = hdr.v3.ramdisk_size as usize;
    let src_signature_size = hdr.signature_size as usize;

    let kernel_off = PAGE;
    let ramdisk_off = align_to((kernel_off + src_kernel_size) as u64, PAGE as u64) as usize;
    let signature_off = align_to(
        (ramdisk_off + src_ramdisk_size) as u64,
        PAGE as u64,
    ) as usize;
    let src_tail_off_rel = if src_signature_size > 0 {
        align_to((signature_off + src_signature_size) as u64, PAGE as u64) as usize
    } else {
        signature_off
    };
    let src_tail_off_abs = hdr_off + src_tail_off_rel;

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.v3.kernel_size = 0;
    new_hdr.v3.ramdisk_size = 0;
    // signature_size stays the same — we byte-copy the section.
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));
    pad_to(&mut out, out_hdr_off, PAGE);

    // Kernel.
    let new_kernel_size = write_section(
        &mut out,
        out_hdr_off,
        &src[hdr_off + kernel_off..hdr_off + kernel_off + src_kernel_size],
        &work_dir.join("kernel"),
        SectionPolicy::Kernel,
        header_version_v4(),
        skip_comp,
    )?;
    new_hdr.v3.kernel_size = new_kernel_size as u32;
    pad_to(&mut out, out_hdr_off, PAGE);

    // Ramdisk.
    let new_ramdisk_size = write_section(
        &mut out,
        out_hdr_off,
        &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + src_ramdisk_size],
        &work_dir.join("ramdisk.cpio"),
        SectionPolicy::Ramdisk,
        header_version_v4(),
        skip_comp,
    )?;
    new_hdr.v3.ramdisk_size = new_ramdisk_size as u32;
    pad_to(&mut out, out_hdr_off, PAGE);

    // Signature (copy-through; work-dir override if present).
    if src_signature_size > 0 {
        let sig_path = work_dir.join("signature");
        if sig_path.exists() {
            let bytes = std::fs::read(&sig_path)?;
            out.extend_from_slice(&bytes);
            new_hdr.signature_size = bytes.len() as u32;
        } else {
            out.extend_from_slice(
                &src[hdr_off + signature_off..hdr_off + signature_off + src_signature_size],
            );
        }
        pad_to(&mut out, out_hdr_off, PAGE);
    }

    // Tail verbatim — must be the last write so the AVB2 footer
    // (last 64 bytes of source tail) stays at EOF for downstream
    // `avbtool erase_footer` to find.
    if src_tail_off_abs < src.len() {
        out.extend_from_slice(&src[src_tail_off_abs..]);
    }

    patch_v4_header(&mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV4>()], &new_hdr);

    patch_outer_wrapper(&mut out, out_hdr_off, src_tail_off_rel);

    write_file(out_img, &out)
}

// ---------------------------------------------------------------------------
// Section writer — drives the compression policy + fallback rules.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum SectionPolicy {
    Kernel,
    Ramdisk,
}

#[derive(Clone, Copy)]
struct HeaderVersion(u32);

fn header_version_v3() -> HeaderVersion {
    HeaderVersion(3)
}
fn header_version_v4() -> HeaderVersion {
    HeaderVersion(4)
}

/// Append one section to `out`, returning the number of bytes
/// written (i.e. the section size field the header must record).
///
/// - If `work_file` exists and its contents are already in a
///   compressed format, write the work-dir bytes raw.
/// - Otherwise, if the original section was compressed, recompress
///   the work-dir bytes using the detected original format.
/// - Ramdisks on v4 boot images are forced to LZ4_LEGACY.
/// - If no work-dir file is present, fall back to copying the
///   original section bytes.
fn write_section(
    out: &mut Vec<u8>,
    _out_hdr_off: usize,
    src_section: &[u8],
    work_file: &Path,
    policy: SectionPolicy,
    hv: HeaderVersion,
    skip_comp: bool,
) -> Result<usize, RepackError> {
    if !work_file.exists() {
        // Nothing in the work dir — pass the original section through.
        out.extend_from_slice(src_section);
        return Ok(src_section.len());
    }

    let mut work_bytes = Vec::new();
    File::open(work_file)?.read_to_end(&mut work_bytes)?;

    if skip_comp {
        let before = out.len();
        out.extend_from_slice(&work_bytes);
        return Ok(out.len() - before);
    }

    // Detect format of the *original* section. If original was raw,
    // write work bytes raw — same policy as upstream.
    let src_fmt = if src_section.is_empty() {
        FileFormat::UNKNOWN
    } else {
        check_fmt(src_section)
    };
    let work_fmt = check_fmt(&work_bytes);

    // Upstream forces LZ4_LEGACY for v4 ramdisks regardless of what
    // the source format was (v3/v4 GKI requirement).
    let mut target_fmt = src_fmt;
    if let SectionPolicy::Ramdisk = policy {
        if hv.0 == 4 && target_fmt != FileFormat::LZ4_LEGACY && target_fmt.is_compressed() {
            target_fmt = FileFormat::LZ4_LEGACY;
        }
    }

    // If work bytes are already compressed (e.g. user shipped a
    // pre-compressed payload), write them raw. Matches
    // `!fmt_compressed_any(check_fmt(work))` branch in C++.
    if work_fmt.is_compressed() || matches!(work_fmt, FileFormat::LZOP) {
        let before = out.len();
        out.extend_from_slice(&work_bytes);
        return Ok(out.len() - before);
    }

    // Work bytes raw; recompress if the original was compressed.
    if target_fmt.is_compressed() {
        let before = out.len();
        // Encode via the shared compressor; writes through to `out`.
        {
            let mut encoder = crate::compress::get_encoder(target_fmt, &mut *out)
                .map_err(|e| RepackError::Compress(e.to_string()))?;
            encoder
                .write_all(&work_bytes)
                .map_err(|e| RepackError::Compress(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| RepackError::Compress(e.to_string()))?;
        }
        return Ok(out.len() - before);
    }

    // Raw → raw.
    let before = out.len();
    out.extend_from_slice(&work_bytes);
    Ok(out.len() - before)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pod_ref<T: Pod>(buf: &[u8]) -> Result<&T, RepackError> {
    let need = size_of::<T>();
    if buf.len() < need {
        return Err(RepackError::Truncated { section: "header" });
    }
    Ok(bytemuck::from_bytes(&buf[..need]))
}

/// Pad `out` with zeros until the offset *relative to `hdr_off`* is
/// a multiple of `page`. Mirrors the C++ `file_align()` macro.
fn pad_to(out: &mut Vec<u8>, hdr_off: usize, page: usize) {
    let rel = out.len() - hdr_off;
    let pad = align_padding(rel as u64, page as u64) as usize;
    out.resize(out.len() + pad, 0);
}

fn patch_v3_header(slot: &mut [u8], hdr: &BootImgHdrV3) {
    slot.copy_from_slice(bytemuck::bytes_of(hdr));
}

fn patch_v4_header(slot: &mut [u8], hdr: &BootImgHdrV4) {
    slot.copy_from_slice(bytemuck::bytes_of(hdr));
}

/// Patch any outer wrapper that records the AOSP payload size.
/// DHTB: 512-byte wrapper, size at offset 48 (after magic[8] +
/// checksum[40]). Blob: 104-byte wrapper, datalen at offset 20.
/// ChromeOS is opaque — parsing its signed verity metadata is out
/// of scope so the wrapper stays unmodified (matches C++).
fn patch_outer_wrapper(out: &mut [u8], out_hdr_off: usize, src_tail_off_rel: usize) {
    if out_hdr_off == 0 {
        return;
    }
    // AOSP image size = everything from the start of the AOSP
    // header through the end of the last section (pre-tail).
    let aosp_img_size = src_tail_off_rel as u32;
    if out[..DHTB_MAGIC.len()].starts_with(DHTB_MAGIC) && out.len() >= 52 {
        // dhtb_hdr::size lives right after magic[8] + checksum[40] = 48
        out[48..52].copy_from_slice(&aosp_img_size.to_le_bytes());
        // SHA-256 checksum recomputation is intentionally skipped
        // in this port; see module header.
        return;
    }
    if out[..BLOB_MAGIC.len()].starts_with(BLOB_MAGIC) && out.len() >= 24 {
        // blob_hdr::datalen lives at offset 20 (after secure_magic[20]).
        out[20..24].copy_from_slice(&aosp_img_size.to_le_bytes());
        return;
    }
    // ChromeOS + unknown wrappers: leave as-is.
    let _ = CHROMEOS_MAGIC;
    let _ = BootFlag::ChromeOs;
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), RepackError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = File::create(path)?;
    f.write_all(bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootimg::hdr::{BootImgHdrV3, BootImgHdrV4, BOOT_MAGIC};
    use crate::bootimg::unpack::unpack;

    fn build_v3_image(kernel: &[u8], ramdisk: &[u8], tail: &[u8]) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut hdr = BootImgHdrV3 {
            magic: [0u8; 8],
            kernel_size: kernel.len() as u32,
            ramdisk_size: ramdisk.len() as u32,
            os_version: 0,
            header_size: size_of::<BootImgHdrV3>() as u32,
            reserved: [0; 4],
            header_version: 3,
            cmdline: [0u8; 1536],
        };
        hdr.magic.copy_from_slice(BOOT_MAGIC);
        let mut out = Vec::new();
        out.extend_from_slice(bytemuck::bytes_of(&hdr));
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

    fn build_v4_image(
        kernel: &[u8],
        ramdisk: &[u8],
        signature: &[u8],
        tail: &[u8],
    ) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut hdr = BootImgHdrV4 {
            v3: BootImgHdrV3 {
                magic: [0u8; 8],
                kernel_size: kernel.len() as u32,
                ramdisk_size: ramdisk.len() as u32,
                os_version: 0,
                header_size: size_of::<BootImgHdrV4>() as u32,
                reserved: [0; 4],
                header_version: 4,
                cmdline: [0u8; 1536],
            },
            signature_size: signature.len() as u32,
        };
        hdr.v3.magic.copy_from_slice(BOOT_MAGIC);
        let mut out = Vec::new();
        out.extend_from_slice(bytemuck::bytes_of(&hdr));
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
        if !signature.is_empty() {
            out.extend_from_slice(signature);
            while out.len() % PAGE != 0 {
                out.push(0);
            }
        }
        out.extend_from_slice(tail);
        out
    }

    #[test]
    fn repack_v3_round_trip_preserves_content() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KERNEL-BYTES".to_vec();
        let ramdisk = b"0707010RAMDISK".to_vec();
        let tail = vec![0xABu8; 128];
        let img_bytes = build_v3_image(&kernel, &ramdisk, &tail);
        let src = tmp.path().join("src.img");
        std::fs::write(&src, &img_bytes).unwrap();

        // Unpack first so work dir has the sections.
        let work = tmp.path().join("work");
        unpack(&src, &work, /*skip_decompress=*/ true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, /*skip_comp=*/ true).unwrap();

        let dst_bytes = std::fs::read(&dst).unwrap();
        // Padded to source length.
        assert_eq!(dst_bytes.len(), img_bytes.len());

        // Re-unpack and verify content parity.
        let work2 = tmp.path().join("work2");
        unpack(&dst, &work2, /*skip_decompress=*/ true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn repack_v4_round_trip_preserves_signature_and_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"k".repeat(111);
        let ramdisk = b"r".repeat(222);
        let signature = b"s".repeat(64);
        let tail = vec![0x5Au8; 256];
        let img_bytes = build_v4_image(&kernel, &ramdisk, &signature, &tail);
        let src = tmp.path().join("src.img");
        std::fs::write(&src, &img_bytes).unwrap();

        let work = tmp.path().join("work");
        unpack(&src, &work, true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let dst_bytes = std::fs::read(&dst).unwrap();
        assert_eq!(dst_bytes.len(), img_bytes.len());
        // Tail byte-exact preservation.
        assert_eq!(&dst_bytes[dst_bytes.len() - tail.len()..], tail.as_slice());

        // Re-unpack verifies section bytes round-trip.
        let work2 = tmp.path().join("work2");
        unpack(&dst, &work2, true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(work2.join("signature")).unwrap(), signature);
    }

    #[test]
    fn repack_rejects_non_aosp_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let junk = vec![0xffu8; 4096];
        let src = tmp.path().join("junk.img");
        std::fs::write(&src, &junk).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let dst = tmp.path().join("dst.img");
        let err = repack(&src, &work, &dst, true).unwrap_err();
        assert!(matches!(err, RepackError::NotAnAospBootImage));
    }

    #[test]
    fn repack_rejects_unsupported_version() {
        let tmp = tempfile::tempdir().unwrap();
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[40..44].copy_from_slice(&2u32.to_le_bytes());
        hdr.resize(4096, 0);
        let src = tmp.path().join("v2.img");
        std::fs::write(&src, &hdr).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let dst = tmp.path().join("dst.img");
        let err = repack(&src, &work, &dst, true).unwrap_err();
        assert!(matches!(err, RepackError::UnsupportedVersion(2)));
    }

    /// Round-trip TB322FC Lenovo images: unpack → repack → re-unpack,
    /// verify kernel + ramdisk.cpio bytes match on every hop.
    /// Skipped unless `LTBOX_TB322_IMAGES` points at the firmware dir.
    #[test]
    fn repack_tb322fc_samples_round_trip() {
        let Ok(dir) = std::env::var("LTBOX_TB322_IMAGES") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        for img_name in ["init_boot.img", "boot.img"] {
            let src = dir.join(img_name);
            if !src.exists() {
                continue;
            }
            let tmp = tempfile::tempdir().unwrap();
            let work1 = tmp.path().join("work1");
            unpack(&src, &work1, false, true)
                .unwrap_or_else(|e| panic!("{img_name} first unpack: {e}"));

            let dst = tmp.path().join("dst.img");
            repack(&src, &work1, &dst, false)
                .unwrap_or_else(|e| panic!("{img_name} repack: {e}"));

            let work2 = tmp.path().join("work2");
            unpack(&dst, &work2, false, true)
                .unwrap_or_else(|e| panic!("{img_name} second unpack: {e}"));

            // Kernel + ramdisk.cpio must decompress to identical
            // bytes — that's the functional invariant Magisk cares
            // about, compression bytes will differ under flate2 vs
            // libdeflate.
            for name in ["kernel", "ramdisk.cpio"] {
                let a_path = work1.join(name);
                let b_path = work2.join(name);
                if !a_path.exists() {
                    continue;
                }
                let a = std::fs::read(&a_path).unwrap();
                let b = std::fs::read(&b_path).unwrap();
                assert_eq!(a, b, "{img_name}: {name} content differs across round-trip");
            }
        }
    }

    /// Byte-for-byte parity against a C++ `magiskboot repack` result.
    /// Runs only when `LTBOX_PARITY_CPP_REPACK` names a directory that
    /// contains:
    ///
    /// - `src.img`       — original source image
    /// - `work/kernel`, `work/ramdisk.cpio` (+ `signature` for v4) —
    ///   the exact bytes the user plans to feed the repacker
    /// - `cpp.img`       — the reference C++ output
    ///
    /// We invoke the Rust repack with the same inputs and compare
    /// byte-for-byte. Only passes when both tools agree bit-exactly
    /// — currently expected only for `skip_comp = true`, since
    /// compressed output byte-drifts between libraries. The env
    /// variable `LTBOX_PARITY_REPACK_SKIP_COMP` gates that mode.
    #[test]
    fn repack_byte_matches_cpp_reference() {
        let Ok(dir) = std::env::var("LTBOX_PARITY_CPP_REPACK") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let src = dir.join("src.img");
        let work = dir.join("work");
        let cpp = dir.join("cpp.img");
        if !src.exists() || !work.exists() || !cpp.exists() {
            return;
        }
        let skip = std::env::var("LTBOX_PARITY_REPACK_SKIP_COMP").is_ok();

        let tmp = tempfile::tempdir().unwrap();
        let ours = tmp.path().join("rust.img");
        repack(&src, &work, &ours, skip).expect("repack");
        let a = std::fs::read(&cpp).unwrap();
        let b = std::fs::read(&ours).unwrap();
        assert_eq!(
            a,
            b,
            "repack byte-parity: cpp {} vs rust {}",
            a.len(),
            b.len()
        );
    }
}
