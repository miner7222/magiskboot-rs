//! Boot image repack — pure-Rust port of the C++ `repack()` function.
//!
//! Scope mirrors `unpack.rs`: AOSP boot v0–v4, Samsung PXA, vendor_boot
//! v3 / v4, and the wrappers `unpack` recognises. The Z4 wrapper is not
//! implemented, and ChromeOS images are not re-signed (see `ffi::unpack`).
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
//! - Everything after the last section follows upstream v31.1 (see
//!   [`finish_tail`]): Samsung / LG trailers, the AVB2 vbmeta blob copied
//!   verbatim on a 4 KiB boundary, zero padding to the source length, the
//!   footer's `original_image_size` / `vbmeta_offset`, DHTB / blob size
//!   fields, and AVB1 re-signing.
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
    AVB_FOOTER_MAGIC, AVB_MAGIC, AvbFooter, AvbVBMetaImageHeader, BLOB_MAGIC, BOOT_ID_SIZE,
    BOOT_MAGIC, BootFlag, BootImgHdrPxa, BootImgHdrV0, BootImgHdrV1, BootImgHdrV2, BootImgHdrV3,
    BootImgHdrV4, BootImgHdrVndV3, BootImgHdrVndV4, DHTB_MAGIC, LG_BUMP_MAGIC, MTK_MAGIC, MtkHdr,
    SEANDROID_MAGIC, SHA_DIGEST_SIZE, SHA256_DIGEST_SIZE, VENDOR_BOOT_MAGIC,
    VendorRamdiskTableEntryV4, align_padding, align_to, id_uses_sha1,
};
use crate::bootimg::unpack::{VND_RAMDISK_DIR, VND_RAMDISK_TABLE_FILE};
use crate::ffi::FileFormat;
use crate::format::check_fmt;
use crate::zimage::ZImage;
use digest::Digest;
use sha1::Sha1;
use sha2::Sha256;

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
    #[error("invalid output layout: {0}")]
    Layout(&'static str),
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
    if payload.len() < BOOT_MAGIC.len() {
        return Err(RepackError::NotAnAospBootImage);
    }
    let is_vendor = payload.starts_with(VENDOR_BOOT_MAGIC);
    let is_boot = payload.starts_with(BOOT_MAGIC);
    if !is_vendor && !is_boot {
        return Err(RepackError::NotAnAospBootImage);
    }

    let header_version_offset = if is_vendor { 8 } else { 40 };
    if payload.len() < header_version_offset + 4 {
        return Err(RepackError::Truncated {
            section: "header_version",
        });
    }
    let header_version = u32::from_le_bytes(
        payload[header_version_offset..header_version_offset + 4]
            .try_into()
            .unwrap(),
    );

    // PXA detection: page_size @ offset 36 >= 0x02000000.
    let is_pxa = !is_vendor && {
        let page_size_slice = payload.get(36..40).ok_or(RepackError::Truncated {
            section: "page_size",
        })?;
        let page_size = u32::from_le_bytes(page_size_slice.try_into().unwrap());
        page_size >= 0x0200_0000
    };

    if is_vendor {
        match header_version {
            3 => repack_vendor_v3(&src, hdr_off, work_dir, out_img, skip_comp),
            4 => repack_vendor_v4(&src, hdr_off, work_dir, out_img, skip_comp),
            other => Err(RepackError::UnsupportedVersion(other)),
        }
    } else if is_pxa {
        repack_pxa(&src, hdr_off, work_dir, out_img, skip_comp)
    } else {
        match header_version {
            1 => repack_v1(&src, hdr_off, work_dir, out_img, skip_comp),
            2 => repack_v2(&src, hdr_off, work_dir, out_img, skip_comp),
            3 => repack_v3(&src, hdr_off, outer_flags, work_dir, out_img, skip_comp),
            4 => repack_v4(&src, hdr_off, outer_flags, work_dir, out_img, skip_comp),
            // header_version not in {1..4} → legacy v0 (field carries extra_size).
            _ => repack_v0(&src, hdr_off, work_dir, out_img, skip_comp),
        }
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

    // 5. Patch header in place with the rewritten sizes.
    patch_v3_header(
        &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV3>()],
        &new_hdr,
    );

    // 6. Trailers, AVB2 vbmeta + footer, wrapper fields, AVB1 re-sign.
    finish_tail(src, hdr_off, src_tail_off_rel, &mut out, out_hdr_off)?;

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
    let signature_off = align_to((ramdisk_off + src_ramdisk_size) as u64, PAGE as u64) as usize;
    let src_tail_off_rel = if src_signature_size > 0 {
        align_to((signature_off + src_signature_size) as u64, PAGE as u64) as usize
    } else {
        signature_off
    };

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

    patch_v4_header(
        &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV4>()],
        &new_hdr,
    );

    finish_tail(src, hdr_off, src_tail_off_rel, &mut out, out_hdr_off)?;

    write_file(out_img, &out)
}

// ---------------------------------------------------------------------------
// Legacy v0/v1/v2 + PXA repack drivers.
//
// Shared skeleton — only header struct and section list vary per
// version. The `LegacyRepackLayout` struct below captures the fields
// the shared walker needs to emit the sections in the correct order
// with the correct page alignment.
// ---------------------------------------------------------------------------

struct LegacyRepackLayout<'a> {
    page: usize,
    hdr_size: usize,
    kernel_src: &'a [u8],
    ramdisk_src: &'a [u8],
    second_src: &'a [u8],
    extra_src: &'a [u8],
    recovery_dtbo_src: &'a [u8],
    dtb_src: &'a [u8],
}

#[derive(Default)]
struct LegacyRepackSizes {
    kernel: u32,
    ramdisk: u32,
    second: u32,
    extra: u32,
    recovery_dtbo: u32,
    dtb: u32,
}

fn emit_legacy_sections(
    out: &mut Vec<u8>,
    out_hdr_off: usize,
    lay: &LegacyRepackLayout,
    work_dir: &Path,
    skip_comp: bool,
) -> Result<LegacyRepackSizes, RepackError> {
    let page = lay.page;
    pad_to(out, out_hdr_off, page);

    let kernel = write_section(
        out,
        out_hdr_off,
        lay.kernel_src,
        &work_dir.join("kernel"),
        SectionPolicy::Kernel,
        header_version_v3(),
        skip_comp,
    )? as u32;
    pad_to(out, out_hdr_off, page);

    let ramdisk = write_section(
        out,
        out_hdr_off,
        lay.ramdisk_src,
        &work_dir.join("ramdisk.cpio"),
        SectionPolicy::Ramdisk,
        header_version_v3(),
        skip_comp,
    )? as u32;
    pad_to(out, out_hdr_off, page);

    let second = write_section(
        out,
        out_hdr_off,
        lay.second_src,
        &work_dir.join("second"),
        SectionPolicy::Kernel,
        header_version_v3(),
        skip_comp,
    )? as u32;
    pad_to(out, out_hdr_off, page);

    let extra = write_section(
        out,
        out_hdr_off,
        lay.extra_src,
        &work_dir.join("extra"),
        SectionPolicy::Kernel,
        header_version_v3(),
        skip_comp,
    )? as u32;
    pad_to(out, out_hdr_off, page);

    let recovery_dtbo =
        write_raw_section(out, lay.recovery_dtbo_src, &work_dir.join("recovery_dtbo"))? as u32;
    pad_to(out, out_hdr_off, page);

    let dtb = write_raw_section(out, lay.dtb_src, &work_dir.join("dtb"))? as u32;
    pad_to(out, out_hdr_off, page);

    let _ = lay.hdr_size;
    Ok(LegacyRepackSizes {
        kernel,
        ramdisk,
        second,
        extra,
        recovery_dtbo,
        dtb,
    })
}

fn legacy_offsets(lay: &LegacyRepackLayout) -> (usize, usize, usize, usize, usize, usize) {
    let page = lay.page as u64;
    let mut off = align_to(lay.hdr_size as u64, page);
    let kernel_off = off as usize;
    off = align_to(off + lay.kernel_src.len() as u64, page);
    let ramdisk_off = off as usize;
    off = align_to(off + lay.ramdisk_src.len() as u64, page);
    let second_off = off as usize;
    off = align_to(off + lay.second_src.len() as u64, page);
    let extra_off = off as usize;
    off = align_to(off + lay.extra_src.len() as u64, page);
    let recovery_dtbo_off = off as usize;
    off = align_to(off + lay.recovery_dtbo_src.len() as u64, page);
    let dtb_off = off as usize;
    (
        kernel_off,
        ramdisk_off,
        second_off,
        extra_off,
        recovery_dtbo_off,
        dtb_off,
    )
}

/// Source offset (relative to the header) where the tail starts: the page
/// boundary after the last legacy section, as upstream `get_block` computes.
fn legacy_tail_rel(lay: &LegacyRepackLayout) -> usize {
    let (.., dtb_off) = legacy_offsets(lay);
    align_to((dtb_off + lay.dtb_src.len()) as u64, lay.page as u64) as usize
}

fn repack_v0(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrV0 = pod_ref(payload)?;
    let page = hdr.page_size as usize;
    let extra_size = hdr.header_version as usize;
    let hdr_size = size_of::<BootImgHdrV0>();
    let kernel_size = hdr.kernel_size as usize;
    let ramdisk_size = hdr.ramdisk_size as usize;
    let second_size = hdr.second_size as usize;

    let off_base = align_to(hdr_size as u64, page as u64) as usize;
    let kernel_off = off_base;
    let ramdisk_off = align_to((kernel_off + kernel_size) as u64, page as u64) as usize;
    let second_off = align_to((ramdisk_off + ramdisk_size) as u64, page as u64) as usize;
    let extra_off = align_to((second_off + second_size) as u64, page as u64) as usize;

    let lay = LegacyRepackLayout {
        page,
        hdr_size,
        kernel_src: &src[hdr_off + kernel_off..hdr_off + kernel_off + kernel_size],
        ramdisk_src: &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + ramdisk_size],
        second_src: &src[hdr_off + second_off..hdr_off + second_off + second_size],
        extra_src: &src[hdr_off + extra_off..hdr_off + extra_off + extra_size],
        recovery_dtbo_src: &[],
        dtb_src: &[],
    };

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.kernel_size = 0;
    new_hdr.ramdisk_size = 0;
    new_hdr.second_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));

    let sizes = emit_legacy_sections(&mut out, out_hdr_off, &lay, work_dir, skip_comp)?;
    new_hdr.kernel_size = sizes.kernel;
    new_hdr.ramdisk_size = sizes.ramdisk;
    new_hdr.second_size = sizes.second;
    // extra_size lives in the union field `header_version`.
    new_hdr.header_version = sizes.extra;

    let use_sha1 = id_uses_sha1(&hdr.id);
    new_hdr.id = compute_legacy_id(
        &out,
        out_hdr_off,
        page,
        hdr_size,
        &sizes,
        LegacyIdVersion::V0,
        use_sha1,
    );

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV0>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));
    finish_tail(src, hdr_off, legacy_tail_rel(&lay), &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

fn repack_v1(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrV1 = pod_ref(payload)?;
    let page = hdr.v0.page_size as usize;
    let hdr_size = hdr.header_size as usize;
    let kernel_size = hdr.v0.kernel_size as usize;
    let ramdisk_size = hdr.v0.ramdisk_size as usize;
    let second_size = hdr.v0.second_size as usize;
    let recovery_dtbo_size = hdr.recovery_dtbo_size as usize;

    let off_base = align_to(hdr_size as u64, page as u64) as usize;
    let kernel_off = off_base;
    let ramdisk_off = align_to((kernel_off + kernel_size) as u64, page as u64) as usize;
    let second_off = align_to((ramdisk_off + ramdisk_size) as u64, page as u64) as usize;
    let extra_off = align_to((second_off + second_size) as u64, page as u64) as usize;
    let recovery_dtbo_off = extra_off;

    let lay = LegacyRepackLayout {
        page,
        hdr_size,
        kernel_src: &src[hdr_off + kernel_off..hdr_off + kernel_off + kernel_size],
        ramdisk_src: &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + ramdisk_size],
        second_src: &src[hdr_off + second_off..hdr_off + second_off + second_size],
        extra_src: &[],
        recovery_dtbo_src: &src
            [hdr_off + recovery_dtbo_off..hdr_off + recovery_dtbo_off + recovery_dtbo_size],
        dtb_src: &[],
    };

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.v0.kernel_size = 0;
    new_hdr.v0.ramdisk_size = 0;
    new_hdr.v0.second_size = 0;
    new_hdr.recovery_dtbo_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));

    let sizes = emit_legacy_sections(&mut out, out_hdr_off, &lay, work_dir, skip_comp)?;
    new_hdr.v0.kernel_size = sizes.kernel;
    new_hdr.v0.ramdisk_size = sizes.ramdisk;
    new_hdr.v0.second_size = sizes.second;
    new_hdr.recovery_dtbo_size = sizes.recovery_dtbo;

    let use_sha1 = id_uses_sha1(&hdr.v0.id);
    new_hdr.v0.id = compute_legacy_id(
        &out,
        out_hdr_off,
        page,
        hdr_size,
        &sizes,
        LegacyIdVersion::V1,
        use_sha1,
    );

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV1>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));
    finish_tail(src, hdr_off, legacy_tail_rel(&lay), &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

fn repack_v2(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrV2 = pod_ref(payload)?;
    let page = hdr.v1.v0.page_size as usize;
    let hdr_size = hdr.v1.header_size as usize;
    let kernel_size = hdr.v1.v0.kernel_size as usize;
    let ramdisk_size = hdr.v1.v0.ramdisk_size as usize;
    let second_size = hdr.v1.v0.second_size as usize;
    let recovery_dtbo_size = hdr.v1.recovery_dtbo_size as usize;
    let dtb_size = hdr.dtb_size as usize;

    let off_base = align_to(hdr_size as u64, page as u64) as usize;
    let kernel_off = off_base;
    let ramdisk_off = align_to((kernel_off + kernel_size) as u64, page as u64) as usize;
    let second_off = align_to((ramdisk_off + ramdisk_size) as u64, page as u64) as usize;
    let extra_off = align_to((second_off + second_size) as u64, page as u64) as usize;
    let recovery_dtbo_off = extra_off;
    let dtb_off = align_to((recovery_dtbo_off + recovery_dtbo_size) as u64, page as u64) as usize;

    let lay = LegacyRepackLayout {
        page,
        hdr_size,
        kernel_src: &src[hdr_off + kernel_off..hdr_off + kernel_off + kernel_size],
        ramdisk_src: &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + ramdisk_size],
        second_src: &src[hdr_off + second_off..hdr_off + second_off + second_size],
        extra_src: &[],
        recovery_dtbo_src: &src
            [hdr_off + recovery_dtbo_off..hdr_off + recovery_dtbo_off + recovery_dtbo_size],
        dtb_src: &src[hdr_off + dtb_off..hdr_off + dtb_off + dtb_size],
    };

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.v1.v0.kernel_size = 0;
    new_hdr.v1.v0.ramdisk_size = 0;
    new_hdr.v1.v0.second_size = 0;
    new_hdr.v1.recovery_dtbo_size = 0;
    new_hdr.dtb_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));

    let sizes = emit_legacy_sections(&mut out, out_hdr_off, &lay, work_dir, skip_comp)?;
    new_hdr.v1.v0.kernel_size = sizes.kernel;
    new_hdr.v1.v0.ramdisk_size = sizes.ramdisk;
    new_hdr.v1.v0.second_size = sizes.second;
    new_hdr.v1.recovery_dtbo_size = sizes.recovery_dtbo;
    new_hdr.dtb_size = sizes.dtb;

    let use_sha1 = id_uses_sha1(&hdr.v1.v0.id);
    new_hdr.v1.v0.id = compute_legacy_id(
        &out,
        out_hdr_off,
        page,
        hdr_size,
        &sizes,
        LegacyIdVersion::V2,
        use_sha1,
    );

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrV2>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));
    finish_tail(src, hdr_off, legacy_tail_rel(&lay), &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

fn repack_pxa(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrPxa = pod_ref(payload)?;
    let page = hdr.page_size as usize;
    let hdr_size = size_of::<BootImgHdrPxa>();
    let kernel_size = hdr.kernel_size as usize;
    let ramdisk_size = hdr.ramdisk_size as usize;
    let second_size = hdr.second_size as usize;
    let extra_size = hdr.extra_size as usize;

    let off_base = align_to(hdr_size as u64, page as u64) as usize;
    let kernel_off = off_base;
    let ramdisk_off = align_to((kernel_off + kernel_size) as u64, page as u64) as usize;
    let second_off = align_to((ramdisk_off + ramdisk_size) as u64, page as u64) as usize;
    let extra_off = align_to((second_off + second_size) as u64, page as u64) as usize;

    let lay = LegacyRepackLayout {
        page,
        hdr_size,
        kernel_src: &src[hdr_off + kernel_off..hdr_off + kernel_off + kernel_size],
        ramdisk_src: &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + ramdisk_size],
        second_src: &src[hdr_off + second_off..hdr_off + second_off + second_size],
        extra_src: &src[hdr_off + extra_off..hdr_off + extra_off + extra_size],
        recovery_dtbo_src: &[],
        dtb_src: &[],
    };

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.kernel_size = 0;
    new_hdr.ramdisk_size = 0;
    new_hdr.second_size = 0;
    new_hdr.extra_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));

    let sizes = emit_legacy_sections(&mut out, out_hdr_off, &lay, work_dir, skip_comp)?;
    new_hdr.kernel_size = sizes.kernel;
    new_hdr.ramdisk_size = sizes.ramdisk;
    new_hdr.second_size = sizes.second;
    new_hdr.extra_size = sizes.extra;

    let use_sha1 = id_uses_sha1(&hdr.id);
    new_hdr.id = compute_legacy_id(
        &out,
        out_hdr_off,
        page,
        hdr_size,
        &sizes,
        LegacyIdVersion::Pxa,
        use_sha1,
    );

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrPxa>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));
    finish_tail(src, hdr_off, legacy_tail_rel(&lay), &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

// ---------------------------------------------------------------------------
// Vendor_boot v3 / v4 repack drivers.
//
// Layout (page = `hdr.page_size`):
//   header   : align_to(hdr_size, page)
//   ramdisk  : hdr.ramdisk_size
//   dtb      : hdr.dtb_size
//   v4 only:
//     vendor_ramdisk_table : hdr.vendor_ramdisk_table_size
//     bootconfig           : hdr.bootconfig_size
//
// Every section ends on the next `page` boundary measured from the
// vendor_boot header start — matches the C++ `file_align()` macro.
// Multi-ramdisk v4 images pull per-entry cpios from
// `<work_dir>/vendor_ramdisk/<name>.cpio` and rewrite the table
// offsets/sizes accordingly. The `vendor_ramdisk_table` dump file
// carries board_id + type fields verbatim so they round-trip
// unchanged.
// ---------------------------------------------------------------------------

fn repack_vendor_v3(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrVndV3 = pod_ref(payload)?;
    let page = hdr.page_size as usize;
    if page == 0 {
        return Err(RepackError::Truncated {
            section: "vendor page_size",
        });
    }
    let hdr_size = size_of::<BootImgHdrVndV3>();
    let src_ramdisk_size = hdr.ramdisk_size as usize;
    let src_dtb_size = hdr.dtb_size as usize;

    let ramdisk_off = align_to(hdr_size as u64, page as u64) as usize;
    let dtb_off = align_to((ramdisk_off + src_ramdisk_size) as u64, page as u64) as usize;

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.ramdisk_size = 0;
    new_hdr.dtb_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));
    pad_to(&mut out, out_hdr_off, page);

    let new_ramdisk_size = write_section(
        &mut out,
        out_hdr_off,
        &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + src_ramdisk_size],
        &work_dir.join("ramdisk.cpio"),
        SectionPolicy::Ramdisk,
        header_version_vnd_v3(),
        skip_comp,
    )?;
    new_hdr.ramdisk_size = new_ramdisk_size as u32;
    pad_to(&mut out, out_hdr_off, page);

    let new_dtb_size = write_raw_section(
        &mut out,
        &src[hdr_off + dtb_off..hdr_off + dtb_off + src_dtb_size],
        &work_dir.join("dtb"),
    )?;
    new_hdr.dtb_size = new_dtb_size as u32;
    pad_to(&mut out, out_hdr_off, page);

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrVndV3>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));

    let src_tail_rel = align_to((dtb_off + src_dtb_size) as u64, page as u64) as usize;
    finish_tail(src, hdr_off, src_tail_rel, &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

fn repack_vendor_v4(
    src: &[u8],
    hdr_off: usize,
    work_dir: &Path,
    out_img: &Path,
    skip_comp: bool,
) -> Result<(), RepackError> {
    let payload = &src[hdr_off..];
    let hdr: &BootImgHdrVndV4 = pod_ref(payload)?;
    let page = hdr.vnd_v3.page_size as usize;
    if page == 0 {
        return Err(RepackError::Truncated {
            section: "vendor page_size",
        });
    }
    let hdr_size = size_of::<BootImgHdrVndV4>();
    let src_ramdisk_size = hdr.vnd_v3.ramdisk_size as usize;
    let src_dtb_size = hdr.vnd_v3.dtb_size as usize;
    let src_table_size = hdr.vendor_ramdisk_table_size as usize;
    let src_table_entry_num = hdr.vendor_ramdisk_table_entry_num as usize;
    let src_table_entry_size = hdr.vendor_ramdisk_table_entry_size as usize;

    let ramdisk_off = align_to(hdr_size as u64, page as u64) as usize;
    let dtb_off = align_to((ramdisk_off + src_ramdisk_size) as u64, page as u64) as usize;
    let table_off = align_to((dtb_off + src_dtb_size) as u64, page as u64) as usize;
    let bootconfig_off = align_to((table_off + src_table_size) as u64, page as u64) as usize;

    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    out.extend_from_slice(&src[..hdr_off]);
    let out_hdr_off = out.len();
    let mut new_hdr = *hdr;
    new_hdr.vnd_v3.ramdisk_size = 0;
    new_hdr.vnd_v3.dtb_size = 0;
    new_hdr.bootconfig_size = 0;
    out.extend_from_slice(bytemuck::bytes_of(&new_hdr));
    pad_to(&mut out, out_hdr_off, page);

    // Ramdisk section — multi-entry (table-driven) or single.
    let (new_ramdisk_size, new_table_bytes) = if src_table_size > 0 {
        if src_table_entry_size != size_of::<VendorRamdiskTableEntryV4>() {
            return Err(RepackError::Truncated {
                section: "vendor_ramdisk_table_entry_size mismatch",
            });
        }
        let src_table_start = hdr_off + table_off;
        let src_table_end =
            src_table_start
                .checked_add(src_table_size)
                .ok_or(RepackError::Truncated {
                    section: "vendor_ramdisk_table",
                })?;
        if src_table_end > src.len() {
            return Err(RepackError::Truncated {
                section: "vendor_ramdisk_table",
            });
        }
        let src_table_bytes = &src[src_table_start..src_table_end];

        let mut new_table_bytes = src_table_bytes.to_vec();
        // If the work dir has a persisted table file, prefer it
        // (carries user edits to board_id / ramdisk_type).
        let table_file = work_dir.join(VND_RAMDISK_TABLE_FILE);
        if table_file.exists() {
            let bytes = std::fs::read(&table_file)?;
            if bytes.len() == src_table_size {
                new_table_bytes = bytes;
            }
        }

        let section_start_in_out = out.len();
        let mut cursor_in_section: u32 = 0;
        for idx in 0..src_table_entry_num {
            let e_off = idx * src_table_entry_size;
            let entry_slot = &mut new_table_bytes[e_off..e_off + src_table_entry_size];
            let entry: &mut VendorRamdiskTableEntryV4 = bytemuck::from_bytes_mut(entry_slot);
            let entry_src_offset = entry.ramdisk_offset as usize;
            let entry_src_size = entry.ramdisk_size as usize;
            let name_bytes = &entry.ramdisk_name[..];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            let name = std::str::from_utf8(&name_bytes[..end]).unwrap_or("");
            let file_name = if name.is_empty() {
                "ramdisk.cpio".to_string()
            } else {
                format!("{name}.cpio")
            };
            let work_file = work_dir.join(VND_RAMDISK_DIR).join(&file_name);
            let src_section = &src[hdr_off + ramdisk_off + entry_src_offset
                ..hdr_off + ramdisk_off + entry_src_offset + entry_src_size];
            let written = write_section(
                &mut out,
                out_hdr_off,
                src_section,
                &work_file,
                SectionPolicy::Ramdisk,
                // Per-entry ramdisks don't force LZ4_LEGACY — upstream
                // only forces it for the top-level boot v4 ramdisk path.
                header_version_vnd_v3(),
                skip_comp,
            )?;
            entry.ramdisk_offset = cursor_in_section;
            entry.ramdisk_size = written as u32;
            cursor_in_section =
                cursor_in_section
                    .checked_add(written as u32)
                    .ok_or(RepackError::Truncated {
                        section: "ramdisk offset overflow",
                    })?;
        }
        let total = out.len() - section_start_in_out;
        (total, Some(new_table_bytes))
    } else {
        let n = write_section(
            &mut out,
            out_hdr_off,
            &src[hdr_off + ramdisk_off..hdr_off + ramdisk_off + src_ramdisk_size],
            &work_dir.join("ramdisk.cpio"),
            SectionPolicy::Ramdisk,
            header_version_vnd_v3(),
            skip_comp,
        )?;
        (n, None)
    };
    new_hdr.vnd_v3.ramdisk_size = new_ramdisk_size as u32;
    pad_to(&mut out, out_hdr_off, page);

    // DTB — raw bytes.
    let new_dtb_size = write_raw_section(
        &mut out,
        &src[hdr_off + dtb_off..hdr_off + dtb_off + src_dtb_size],
        &work_dir.join("dtb"),
    )?;
    new_hdr.vnd_v3.dtb_size = new_dtb_size as u32;
    pad_to(&mut out, out_hdr_off, page);

    // Vendor ramdisk table (if present).
    if let Some(table_bytes) = new_table_bytes {
        out.extend_from_slice(&table_bytes);
        pad_to(&mut out, out_hdr_off, page);
    }

    // Bootconfig.
    let bootconfig_file = work_dir.join("bootconfig");
    if bootconfig_file.exists() {
        let bytes = std::fs::read(&bootconfig_file)?;
        new_hdr.bootconfig_size = bytes.len() as u32;
        out.extend_from_slice(&bytes);
        pad_to(&mut out, out_hdr_off, page);
    } else {
        let src_bootconfig_size = hdr.bootconfig_size as usize;
        if src_bootconfig_size > 0 {
            let section =
                &src[hdr_off + bootconfig_off..hdr_off + bootconfig_off + src_bootconfig_size];
            out.extend_from_slice(section);
            new_hdr.bootconfig_size = src_bootconfig_size as u32;
            pad_to(&mut out, out_hdr_off, page);
        }
    }

    let hdr_slot = &mut out[out_hdr_off..out_hdr_off + size_of::<BootImgHdrVndV4>()];
    hdr_slot.copy_from_slice(bytemuck::bytes_of(&new_hdr));

    let src_tail_rel = align_to(
        (bootconfig_off + hdr.bootconfig_size as usize) as u64,
        page as u64,
    ) as usize;
    finish_tail(src, hdr_off, src_tail_rel, &mut out, out_hdr_off)?;
    write_file(out_img, &out)
}

/// Copy `src_section` into `out`, or the contents of `work_file` when
/// it exists. Intended for raw blobs (dtb / bootconfig) where neither
/// compression nor any size-padding rule applies.
fn write_raw_section(
    out: &mut Vec<u8>,
    src_section: &[u8],
    work_file: &Path,
) -> Result<usize, RepackError> {
    if work_file.exists() {
        let bytes = std::fs::read(work_file)?;
        let n = bytes.len();
        out.extend_from_slice(&bytes);
        return Ok(n);
    }
    out.extend_from_slice(src_section);
    Ok(src_section.len())
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
fn header_version_vnd_v3() -> HeaderVersion {
    HeaderVersion(3)
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
    // MTK wrapper: some MTK SoCs prepend a 512-byte MtkHdr before the
    // kernel / ramdisk payload. If the source section starts with the
    // MTK magic, copy the source MTK header verbatim, then write the
    // new payload, then patch the MtkHdr.size field to match the new
    // payload size — same logic as the upstream C++ `boot_img` path.
    let (src_mtk_hdr, src_inner) = split_mtk(src_section);
    let is_primary_kernel = matches!(policy, SectionPolicy::Kernel)
        && work_file.file_name().is_some_and(|name| name == "kernel");
    let (src_payload, src_kernel_dtb) = if is_primary_kernel {
        if let Some(offset) = crate::dtb::find_dtb_offset(src_inner) {
            (&src_inner[..offset], Some(&src_inner[offset..]))
        } else {
            (src_inner, None)
        }
    } else {
        (src_inner, None)
    };

    let zimage = if is_primary_kernel {
        ZImage::parse(src_payload)
    } else {
        None
    };

    let section_start = out.len();
    if let Some(mtk_header) = src_mtk_hdr {
        out.extend_from_slice(mtk_header);
    }
    let payload_size = if let Some(zimage) = zimage {
        write_zimage(out, &zimage, work_file, policy, hv, skip_comp)?
    } else {
        write_section_payload(out, src_payload, work_file, policy, hv, skip_comp)?
    };
    let dtb_file = work_file
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join("kernel_dtb");
    let dtb_size = if is_primary_kernel && dtb_file.exists() {
        write_raw_section(out, src_kernel_dtb.unwrap_or_default(), &dtb_file)?
    } else if let Some(src_dtb) = src_kernel_dtb {
        write_raw_section(out, src_dtb, &dtb_file)?
    } else {
        0
    };
    let inner_size = payload_size + dtb_size;

    if src_mtk_hdr.is_some() {
        // Patch MtkHdr.size (bytes 4..8 LE) to cover the kernel payload and
        // its appended DTB, but not the MTK header itself.
        let size_off = section_start + 4;
        out[size_off..size_off + 4].copy_from_slice(&(inner_size as u32).to_le_bytes());
    }
    Ok(out.len() - section_start)
}

/// Emit a parsed zImage wrapper around the work-dir kernel. The original head
/// is used as a same-sized placeholder until the new piggy size is known, then
/// replaced with its relocated form.
fn write_zimage(
    out: &mut Vec<u8>,
    zimage: &ZImage<'_>,
    work_file: &Path,
    policy: SectionPolicy,
    hv: HeaderVersion,
    skip_comp: bool,
) -> Result<usize, RepackError> {
    let section_start = out.len();
    if !work_file.exists() {
        out.extend_from_slice(zimage.head);
        out.extend_from_slice(zimage.piggy);
        out.extend_from_slice(zimage.tail);
        return Ok(out.len() - section_start);
    }

    out.extend_from_slice(zimage.head);
    let piggy_start = out.len();
    let original_payload = if zimage.fmt == FileFormat::GZIP {
        zimage.piggy
    } else {
        &zimage.piggy[..zimage.piggy.len() - size_of::<u32>()]
    };

    let work_bytes = std::fs::read(work_file)?;
    let work_fmt = check_fmt(&work_bytes);
    let recompresses_raw = !skip_comp
        && !work_fmt.is_compressed()
        && !matches!(work_fmt, FileFormat::LZOP)
        && zimage.fmt.is_compressed();

    write_section_payload(out, original_payload, work_file, policy, hv, skip_comp)?;
    if recompresses_raw && zimage.fmt != FileFormat::GZIP {
        let uncompressed_size = u32::try_from(work_bytes.len())
            .map_err(|_| RepackError::Compress("zImage kernel exceeds u32 size".into()))?;
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
    }

    let piggy_size = out.len() - piggy_start;
    let tail = zimage.new_tail(piggy_size);
    out.extend_from_slice(&tail);
    let head = zimage.new_head(piggy_size);
    out[section_start..section_start + head.len()].copy_from_slice(&head);
    Ok(out.len() - section_start)
}

/// Split off a leading MTK wrapper header from a section if present.
/// Returns `(Some(512-byte header slice), rest)` on match, else
/// `(None, section)`.
fn split_mtk(src: &[u8]) -> (Option<&[u8]>, &[u8]) {
    if src.len() >= size_of::<MtkHdr>() {
        let magic = u32::from_le_bytes(src[..4].try_into().unwrap());
        if magic == MTK_MAGIC {
            return (
                Some(&src[..size_of::<MtkHdr>()]),
                &src[size_of::<MtkHdr>()..],
            );
        }
    }
    (None, src)
}

/// Original `write_section` body — writes the inner payload only.
/// Split out so the MTK path can frame it with header + size patch.
fn write_section_payload(
    out: &mut Vec<u8>,
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
            let mut encoder =
                crate::compress::get_encoder_bcj_detection(target_fmt, &mut *out, &work_bytes)
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
// Legacy id-field checksum — mirrors the C++ `hdr->id()` patch path.
//
// SHA-1 or SHA-256 (selected from the source `id` field — if bytes
// \[24..32) are all zero it's SHA-1, otherwise SHA-256) is fed the
// following sequence, per AOSP `mkbootimg.py`:
//
//   kernel  bytes, kernel_size  (LE u32)
//   ramdisk bytes, ramdisk_size (LE u32)
//   second  bytes, second_size  (LE u32)
//   if has_extra && extra_size > 0:
//       extra bytes, extra_size (LE u32)
//   if v1 or v2:
//       recovery_dtbo bytes, recovery_dtbo_size (LE u32)
//   if v2:
//       dtb bytes, dtb_size (LE u32)
//
// Section bytes come from the already-written output buffer so any
// compression / MTK header re-prepend done upstream is included in
// the digest (C++ computes the hash on the post-emit buffer, so we
// must too for byte parity).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyIdVersion {
    V0,
    V1,
    V2,
    Pxa,
}

fn compute_legacy_id(
    out: &[u8],
    out_hdr_off: usize,
    page: usize,
    hdr_size: usize,
    sizes: &LegacyRepackSizes,
    version: LegacyIdVersion,
    use_sha1: bool,
) -> [u8; BOOT_ID_SIZE] {
    let page_u64 = page as u64;
    let mut off = align_to(hdr_size as u64, page_u64);
    let kernel_off = off as usize;
    off = align_to(off + sizes.kernel as u64, page_u64);
    let ramdisk_off = off as usize;
    off = align_to(off + sizes.ramdisk as u64, page_u64);
    let second_off = off as usize;
    off = align_to(off + sizes.second as u64, page_u64);
    let extra_off = off as usize;
    off = align_to(off + sizes.extra as u64, page_u64);
    let recovery_dtbo_off = off as usize;
    off = align_to(off + sizes.recovery_dtbo as u64, page_u64);
    let dtb_off = off as usize;

    let hdr_slice = &out[out_hdr_off..];

    // Feed sequence — identical across SHA-1 and SHA-256, captured in
    // a closure so the two digest paths stay symmetric.
    let run_feeds = |mut push: Box<dyn FnMut(&[u8])>| {
        let feed_section = |push: &mut dyn FnMut(&[u8]), offset: usize, size: u32| {
            push(&hdr_slice[offset..offset + size as usize]);
            push(&size.to_le_bytes());
        };
        feed_section(&mut *push, kernel_off, sizes.kernel);
        feed_section(&mut *push, ramdisk_off, sizes.ramdisk);
        feed_section(&mut *push, second_off, sizes.second);
        if matches!(version, LegacyIdVersion::V0 | LegacyIdVersion::Pxa) && sizes.extra > 0 {
            feed_section(&mut *push, extra_off, sizes.extra);
        }
        if matches!(version, LegacyIdVersion::V1 | LegacyIdVersion::V2) {
            feed_section(&mut *push, recovery_dtbo_off, sizes.recovery_dtbo);
        }
        if matches!(version, LegacyIdVersion::V2) {
            feed_section(&mut *push, dtb_off, sizes.dtb);
        }
    };

    let mut id = [0u8; BOOT_ID_SIZE];
    if use_sha1 {
        let mut ctx = Sha1::new();
        run_feeds(Box::new(|bytes: &[u8]| ctx.update(bytes)));
        let digest = ctx.finalize();
        id[..SHA_DIGEST_SIZE].copy_from_slice(&digest);
    } else {
        let mut ctx = Sha256::new();
        run_feeds(Box::new(|bytes: &[u8]| ctx.update(bytes)));
        let digest = ctx.finalize();
        id[..SHA256_DIGEST_SIZE].copy_from_slice(&digest);
    };
    id
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

fn read_be_u64(buf: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        buf.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Samsung `SignerVer02` block that follows `SEANDROIDENFORCE` in the tail.
const SIGNER_VER02_MAGIC: &[u8] = b"SignerVer02";
const SIGNER_VER02_SZ: usize = 512;
/// DHTB wrapper: magic[8] + checksum[40] + size(u32) + padding → 512 bytes.
const DHTB_HDR_SZ: usize = 512;
const DHTB_CHECKSUM_OFF: usize = 8;
const DHTB_SIZE_OFF: usize = 48;
/// Tegra blob wrapper: `blob_hdr::size` sits after secure_magic[20],
/// datalen, signature, magic[16], hdr_version, hdr_size, part_offset,
/// num_parts, unknown[7], name[4], offset.
const BLOB_HDR_SZ: usize = 104;
const BLOB_SIZE_OFF: usize = 96;
/// avbtool's block size for non-sparse images.
const AVB_BLOCK_SIZE: usize = 4096;
/// `AvbVBMetaImageHeader::flags` (big endian u32).
const VBMETA_FLAGS_OFF: usize = 120;

fn has_flag(flags: u32, f: BootFlag) -> bool {
    flags & (1u32 << (f as u32)) != 0
}

/// The source image's AVB2 footer and the vbmeta blob it points to, when both
/// are well formed. Offsets are absolute in the source file.
fn source_avb(src: &[u8]) -> Option<(&[u8], &[u8])> {
    let footer_size = size_of::<AvbFooter>();
    let footer_off = src.len().checked_sub(footer_size)?;
    let footer = &src[footer_off..];
    if !footer.starts_with(AVB_FOOTER_MAGIC) {
        return None;
    }
    let vbmeta_off = read_be_u64(footer, 20).and_then(|v| usize::try_from(v).ok())?;
    let vbmeta_size = read_be_u64(footer, 28).and_then(|v| usize::try_from(v).ok())?;
    let vbmeta_end = vbmeta_off.checked_add(vbmeta_size)?;
    if vbmeta_end > footer_off || vbmeta_size < size_of::<AvbVBMetaImageHeader>() {
        return None;
    }
    let vbmeta = &src[vbmeta_off..vbmeta_end];
    vbmeta.starts_with(AVB_MAGIC).then_some((footer, vbmeta))
}

/// Everything upstream v31.1 `repack()` does after the last section, shared by
/// every header version:
///
/// 1. proprietary trailers: `SEANDROIDENFORCE` (+ `0xFFFFFFFF` for DHTB,
///    + Samsung `SignerVer02` block), or the LG bump magic;
/// 2. the AVB2 vbmeta blob on a 4 KiB boundary (relative to the header);
/// 3. zero padding to the source length (skipped for ChromeOS, whose
///    re-signing this port leaves to the caller, as upstream v31.0 did);
/// 4. the AVB2 footer: `original_image_size` covers the trailers,
///    `vbmeta_offset` points at the new blob. Hash descriptors are left alone
///    (upstream reverted the `image_size` sync in 07390a786);
/// 5. DHTB / Tegra blob size and checksum fields;
/// 6. AVB1 re-signing with the bundled verity key when the source tail held a
///    BootSignature that verified.
///
/// `out` must end on the page boundary after the last section.
fn finish_tail(
    src: &[u8],
    src_hdr_off: usize,
    src_tail_rel: usize,
    out: &mut Vec<u8>,
    out_hdr_off: usize,
) -> Result<(), RepackError> {
    let (outer_flags, _) = crate::bootimg::unpack::sniff_outer_for_repack(src);
    let dhtb = has_flag(outer_flags, BootFlag::Dhtb);
    let blob = has_flag(outer_flags, BootFlag::Blob);
    let chromeos = has_flag(outer_flags, BootFlag::ChromeOs);

    let src_payload_end = src_hdr_off.saturating_add(src_tail_rel).min(src.len());
    let src_tail = &src[src_payload_end..];
    let tail_seandroid = src_tail.starts_with(SEANDROID_MAGIC);
    let signer_ver02 = tail_seandroid
        && src_tail.len() >= SEANDROID_MAGIC.len() + SIGNER_VER02_SZ
        && src_tail[SEANDROID_MAGIC.len()..].starts_with(SIGNER_VER02_MAGIC);
    let lg_bump = !tail_seandroid && src_tail.starts_with(LG_BUMP_MAGIC);
    let avb1_signed = !tail_seandroid
        && !lg_bump
        && crate::sign::verify_boot_signature(&src[src_hdr_off..src_payload_end], src_tail);

    // 1. Proprietary trailers.
    let tail_off = out.len();
    if dhtb || tail_seandroid {
        out.extend_from_slice(SEANDROID_MAGIC);
        if dhtb {
            out.extend_from_slice(&[0xFF; 4]);
        }
        if signer_ver02 {
            let start = SEANDROID_MAGIC.len();
            out.extend_from_slice(&src_tail[start..start + SIGNER_VER02_SZ]);
        }
    } else if lg_bump {
        out.extend_from_slice(LG_BUMP_MAGIC);
    }
    let eof_off = out.len();
    let aosp_img_size = tail_off - out_hdr_off;
    let orig_img_size = eof_off - out_hdr_off;

    // 2. AVB2 vbmeta.
    let avb = source_avb(src);
    let mut vbmeta_off = None;
    if let Some((_, vbmeta)) = avb {
        pad_to(out, out_hdr_off, AVB_BLOCK_SIZE);
        vbmeta_off = Some(out.len());
        out.extend_from_slice(vbmeta);
    }

    // 3. Pad to the source length.
    if !chromeos && out.len() < src.len() {
        out.resize(src.len(), 0);
    }

    // 4. AVB2 footer, kept at the very end; grow the image if the new
    //    vbmeta would otherwise run into it.
    if let (Some((footer, _)), Some(vbmeta_off)) = (avb, vbmeta_off) {
        let footer_size = footer.len();
        let vbmeta_end = vbmeta_off + avb.map_or(0, |(_, v)| v.len());
        if out.len() < vbmeta_end + footer_size {
            out.resize(vbmeta_end + footer_size, 0);
        }
        let footer_off = out.len() - footer_size;
        out[footer_off..].copy_from_slice(footer);
        out[footer_off + 12..footer_off + 20]
            .copy_from_slice(&(orig_img_size as u64).to_be_bytes());
        out[footer_off + 20..footer_off + 28].copy_from_slice(&(vbmeta_off as u64).to_be_bytes());
        if crate::check_env("PATCHVBMETAFLAG") {
            out[vbmeta_off + VBMETA_FLAGS_OFF..vbmeta_off + VBMETA_FLAGS_OFF + 4]
                .copy_from_slice(&3u32.to_be_bytes());
        }
    }

    // 5. Wrapper size / checksum fields. A wrapper the sniff reported but that
    //    is not where it is patched would be left with stale fields: refuse.
    if dhtb && !(out_hdr_off >= DHTB_HDR_SZ && out.starts_with(DHTB_MAGIC)) {
        return Err(RepackError::Layout(
            "DHTB wrapper is not at the image start",
        ));
    }
    if blob && !dhtb && !(out_hdr_off >= BLOB_HDR_SZ && out.starts_with(BLOB_MAGIC)) {
        return Err(RepackError::Layout(
            "Tegra blob wrapper is not at the image start",
        ));
    }
    if dhtb {
        out[DHTB_SIZE_OFF..DHTB_SIZE_OFF + 4]
            .copy_from_slice(&(orig_img_size as u32).to_le_bytes());
        let digest = Sha256::digest(&out[out_hdr_off..out_hdr_off + orig_img_size]);
        // Upstream writes SHA256_DIGEST_SIZE bytes into the 40-byte slot and
        // keeps the remaining source bytes.
        out[DHTB_CHECKSUM_OFF..DHTB_CHECKSUM_OFF + SHA256_DIGEST_SIZE].copy_from_slice(&digest);
    } else if blob {
        out[BLOB_SIZE_OFF..BLOB_SIZE_OFF + 4]
            .copy_from_slice(&(aosp_img_size as u32).to_le_bytes());
    }

    // 6. AVB1 re-sign over the new payload. Upstream skips silently when
    //    signing fails and writes over vbmeta when the two collide; both would
    //    ship a broken image, so this port refuses instead.
    if avb1_signed {
        let sig = crate::sign::sign_payload_for_cxx(&out[out_hdr_off..tail_off]);
        if sig.is_empty() {
            return Err(RepackError::Layout("failed to re-sign the AVB1 signature"));
        }
        let sig_end = tail_off + sig.len();
        let limit = vbmeta_off.unwrap_or(usize::MAX);
        if sig_end > limit {
            return Err(RepackError::Layout(
                "AVB1 signature would overlap the AVB2 vbmeta block",
            ));
        }
        if out.len() < sig_end {
            out.resize(sig_end, 0);
        }
        out[tail_off..sig_end].copy_from_slice(&sig);
    }
    Ok(())
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
    use crate::bootimg::hdr::{AVB_DESCRIPTOR_TAG_HASH, AvbDescriptor};
    use crate::bootimg::hdr::{BOOT_MAGIC, BootImgHdrV3, BootImgHdrV4};
    use crate::bootimg::unpack::unpack;

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_zimage(fmt: FileFormat) -> Vec<u8> {
        const START: u32 = 0x8000;
        const HEAD: usize = 0x100;
        const PIGGY: usize = 0x20;
        const PIGGY_END: usize = HEAD + PIGGY;
        const TOTAL: usize = 0x140;
        const TABLE: usize = 0x60;

        let mut image = vec![0u8; TOTAL];
        put_u32(&mut image, 0x24, 0x016f_2818);
        put_u32(&mut image, 0x28, START);
        put_u32(&mut image, 0x2c, START + TOTAL as u32);
        put_u32(&mut image, 0x34, 0x4545_4545);
        put_u32(&mut image, 0x38, TABLE as u32);
        put_u32(&mut image, TABLE, 3);
        put_u32(&mut image, TABLE + 4, 0x5a53_4c4b);
        put_u32(&mut image, TABLE + 8, START + PIGGY_END as u32 - 4);
        match fmt {
            FileFormat::GZIP => {
                image[HEAD..HEAD + 10].copy_from_slice(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03")
            }
            FileFormat::XZ => {
                image[HEAD..HEAD + 12].copy_from_slice(b"\xfd7zXZ\x00\x00\x01\x69\x22\xde\x36");
                put_u32(&mut image, PIGGY_END - 4, 0x1122_3344);
            }
            _ => panic!("unsupported synthetic format"),
        }
        image[PIGGY_END..].fill(0x5a);
        image
    }

    fn compress_for_test(fmt: FileFormat, raw: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let mut encoder = crate::compress::get_encoder(fmt, &mut compressed).unwrap();
            encoder.write_all(raw).unwrap();
            encoder.finish().unwrap();
        }
        compressed
    }

    #[test]
    fn zimage_repack_restores_non_gzip_size_word() {
        let source = synthetic_zimage(FileFormat::XZ);
        let zimage = ZImage::parse(&source).expect("synthetic zImage");
        let raw = b"synthetic uncompressed ARM kernel payload";
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("kernel");
        std::fs::write(&kernel, raw).unwrap();

        let mut out = Vec::new();
        write_zimage(
            &mut out,
            &zimage,
            &kernel,
            SectionPolicy::Kernel,
            header_version_v3(),
            false,
        )
        .unwrap();

        let compressed = compress_for_test(FileFormat::XZ, raw);
        let payload_start = zimage.head.len();
        assert_eq!(
            &out[payload_start..payload_start + compressed.len()],
            compressed
        );
        assert_eq!(
            &out[payload_start + compressed.len()..payload_start + compressed.len() + 4],
            &(raw.len() as u32).to_le_bytes()
        );
    }

    #[test]
    fn zimage_repack_does_not_append_size_word_to_gzip() {
        let source = synthetic_zimage(FileFormat::GZIP);
        let zimage = ZImage::parse(&source).expect("synthetic zImage");
        let raw = b"synthetic uncompressed ARM kernel payload";
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("kernel");
        std::fs::write(&kernel, raw).unwrap();

        let mut out = Vec::new();
        write_zimage(
            &mut out,
            &zimage,
            &kernel,
            SectionPolicy::Kernel,
            header_version_v3(),
            false,
        )
        .unwrap();

        let compressed = compress_for_test(FileFormat::GZIP, raw);
        let payload_len = compressed.len();
        let expected_tail = zimage.new_tail(payload_len);
        let payload_start = zimage.head.len();
        assert_eq!(&out[payload_start..payload_start + payload_len], compressed);
        assert_eq!(&out[payload_start + payload_len..], expected_tail);
    }

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

    fn build_v4_image(kernel: &[u8], ramdisk: &[u8], signature: &[u8], tail: &[u8]) -> Vec<u8> {
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

    fn build_avb_image(aosp_size: usize, partition_size: usize) -> Vec<u8> {
        const VBMETA_SIZE: usize = 256 + 136;
        let mut out = vec![0u8; partition_size];
        let vbmeta_offset = aosp_size;
        out[vbmeta_offset..vbmeta_offset + 4].copy_from_slice(AVB_MAGIC);
        out[vbmeta_offset + 20..vbmeta_offset + 28].copy_from_slice(&136u64.to_be_bytes());
        out[vbmeta_offset + 104..vbmeta_offset + 112].copy_from_slice(&136u64.to_be_bytes());

        let descriptor = vbmeta_offset + size_of::<AvbVBMetaImageHeader>();
        out[descriptor..descriptor + 8].copy_from_slice(&AVB_DESCRIPTOR_TAG_HASH.to_be_bytes());
        out[descriptor + 8..descriptor + 16].copy_from_slice(&120u64.to_be_bytes());
        out[descriptor + 16..descriptor + 24].copy_from_slice(&(aosp_size as u64).to_be_bytes());

        let footer = partition_size - size_of::<AvbFooter>();
        out[footer..footer + 4].copy_from_slice(AVB_FOOTER_MAGIC);
        out[footer + 12..footer + 20].copy_from_slice(&(aosp_size as u64).to_be_bytes());
        out[footer + 20..footer + 28].copy_from_slice(&(vbmeta_offset as u64).to_be_bytes());
        out[footer + 28..footer + 36].copy_from_slice(&(VBMETA_SIZE as u64).to_be_bytes());
        out
    }

    #[test]
    fn avb_tail_round_trip_is_byte_exact_when_payload_size_is_unchanged() {
        let src = build_avb_image(4096, 8192);
        let mut out = src[..4096].to_vec();
        finish_tail(&src, 0, 4096, &mut out, 0).unwrap();
        assert_eq!(out, src);
    }

    #[test]
    fn avb_tail_updates_footer_but_not_hash_descriptor() {
        let src = build_avb_image(4096, 8192);
        let new_aosp_size = 5000usize;
        let mut out = vec![0u8; new_aosp_size];
        finish_tail(&src, 0, 4096, &mut out, 0).unwrap();

        let footer = out.len() - size_of::<AvbFooter>();
        assert_eq!(read_be_u64(&out, footer + 12), Some(new_aosp_size as u64));
        assert_eq!(read_be_u64(&out, footer + 20), Some(8192));
        // Upstream 07390a786 reverted the hash descriptor image_size sync.
        let descriptor = 8192 + size_of::<AvbVBMetaImageHeader>();
        assert_eq!(
            read_be_u64(&out, descriptor + size_of::<AvbDescriptor>()),
            Some(4096)
        );
    }

    #[test]
    fn tail_pads_non_avb_image_to_source_length() {
        let src = vec![0u8; 16384];
        let mut out = vec![0x11u8; 4096];
        finish_tail(&src, 0, 4096, &mut out, 0).unwrap();
        assert_eq!(out.len(), src.len());
        assert!(out[4096..].iter().all(|&b| b == 0));
    }

    #[test]
    fn tail_re_emits_seandroid_signer_ver02_block() {
        let mut src = vec![0u8; 4096];
        src.extend_from_slice(SEANDROID_MAGIC);
        let mut signer = vec![0x5Au8; SIGNER_VER02_SZ];
        signer[..SIGNER_VER02_MAGIC.len()].copy_from_slice(SIGNER_VER02_MAGIC);
        src.extend_from_slice(&signer);
        src.resize(12288, 0);

        // New payload is one page longer than the source.
        let mut out = vec![0u8; 8192];
        finish_tail(&src, 0, 4096, &mut out, 0).unwrap();
        assert_eq!(&out[8192..8192 + 16], SEANDROID_MAGIC);
        assert_eq!(&out[8192 + 16..8192 + 16 + SIGNER_VER02_SZ], &signer[..]);
        assert_eq!(out.len(), src.len());
    }

    #[test]
    fn tail_re_emits_full_lg_bump_magic() {
        let mut src = vec![0u8; 4096];
        src.extend_from_slice(LG_BUMP_MAGIC);
        src.resize(8192, 0);
        let mut out = vec![0u8; 4096];
        finish_tail(&src, 0, 4096, &mut out, 0).unwrap();
        assert_eq!(LG_BUMP_MAGIC.len(), 16);
        assert_eq!(&out[4096..4112], LG_BUMP_MAGIC);
    }

    #[test]
    fn tail_patches_blob_size_field_not_datalen() {
        let mut src = vec![0u8; BLOB_HDR_SZ];
        src[..BLOB_MAGIC.len()].copy_from_slice(BLOB_MAGIC);
        src[20..24].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        src.extend_from_slice(&[0u8; 4096]);
        let mut out = src[..BLOB_HDR_SZ].to_vec();
        out.extend_from_slice(&[0u8; 8192]);
        finish_tail(&src, BLOB_HDR_SZ, 4096, &mut out, BLOB_HDR_SZ).unwrap();
        assert_eq!(&out[20..24], &0xAABB_CCDDu32.to_le_bytes());
        assert_eq!(
            &out[BLOB_SIZE_OFF..BLOB_SIZE_OFF + 4],
            &8192u32.to_le_bytes()
        );
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

        // Re-unpack and verify section content parity. The source
        // tail is intentionally dropped by repack — the downstream
        // root pipeline rebuilds AVB via avbtool afterwards, so tail
        // verbatim is not kept.
        let work2 = tmp.path().join("work2");
        unpack(&dst, &work2, /*skip_decompress=*/ true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn repack_v4_round_trip_preserves_signature() {
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

        // Re-unpack verifies section bytes round-trip. Signature
        // section (which lives inside the AOSP payload, not the
        // tail) is preserved via the normal repack path.
        let work2 = tmp.path().join("work2");
        unpack(&dst, &work2, true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(work2.join("signature")).unwrap(), signature);
    }

    fn build_vendor_v3_image(page: usize, ramdisk: &[u8], dtb: &[u8]) -> Vec<u8> {
        use crate::bootimg::hdr::{BootImgHdrVndV3, VENDOR_BOOT_MAGIC};
        let mut hdr_bytes = vec![0u8; size_of::<BootImgHdrVndV3>()];
        hdr_bytes[..8].copy_from_slice(VENDOR_BOOT_MAGIC);
        hdr_bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
        hdr_bytes[12..16].copy_from_slice(&(page as u32).to_le_bytes());
        hdr_bytes[24..28].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        let cmdline_end = 28 + 2048;
        let name_off = cmdline_end + 4;
        let hsize_off = name_off + 16;
        hdr_bytes[hsize_off..hsize_off + 4]
            .copy_from_slice(&(size_of::<BootImgHdrVndV3>() as u32).to_le_bytes());
        let dtb_off = hsize_off + 4;
        hdr_bytes[dtb_off..dtb_off + 4].copy_from_slice(&(dtb.len() as u32).to_le_bytes());

        let mut out = hdr_bytes;
        while out.len() % page != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % page != 0 {
            out.push(0);
        }
        out.extend_from_slice(dtb);
        while out.len() % page != 0 {
            out.push(0);
        }
        out
    }

    fn build_v1_image_for_repack(page: usize, kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
        use crate::bootimg::hdr::{BootImgHdrV0, BootImgHdrV1};
        let hdr_size = size_of::<BootImgHdrV1>() as u32;
        let mut hdr = vec![0u8; size_of::<BootImgHdrV1>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        hdr[36..40].copy_from_slice(&(page as u32).to_le_bytes());
        hdr[40..44].copy_from_slice(&1u32.to_le_bytes());
        let v1_off = size_of::<BootImgHdrV0>();
        hdr[v1_off + 12..v1_off + 16].copy_from_slice(&hdr_size.to_le_bytes());

        let mut out = hdr;
        while out.len() % page != 0 {
            out.push(0);
        }
        out.extend_from_slice(kernel);
        while out.len() % page != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % page != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn repack_v1_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KERNEL-v1".to_vec();
        let ramdisk = b"RAMDISK-v1".to_vec();
        let img = build_v1_image_for_repack(2048, &kernel, &ramdisk);
        let src = tmp.path().join("v1.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let work2 = tmp.path().join("work2");
        crate::bootimg::unpack::unpack(&dst, &work2, true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn repack_vendor_v3_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let ramdisk = b"0707010VENDOR".to_vec();
        let dtb = b"DTBRAWBYTES".to_vec();
        let img = build_vendor_v3_image(4096, &ramdisk, &dtb);
        let src = tmp.path().join("vendor.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        unpack(&src, &work, true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let work2 = tmp.path().join("work2");
        unpack(&dst, &work2, true, false).unwrap();
        assert_eq!(std::fs::read(work2.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(work2.join("dtb")).unwrap(), dtb);
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
        // vendor_boot only supports v3/v4 — v5 should error.
        let tmp = tempfile::tempdir().unwrap();
        let mut hdr = vec![0u8; 4096];
        hdr[..8].copy_from_slice(crate::bootimg::hdr::VENDOR_BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&5u32.to_le_bytes());
        let src = tmp.path().join("vnd_v5.img");
        std::fs::write(&src, &hdr).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let dst = tmp.path().join("dst.img");
        let err = repack(&src, &work, &dst, true).unwrap_err();
        assert!(matches!(err, RepackError::UnsupportedVersion(5)));
    }

    // ---------- Wrapper round-trips (MTK / NookHD / Acclaim / Amonet) ----------

    fn build_mtk_wrapper(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; size_of::<MtkHdr>()];
        v[..4].copy_from_slice(&MTK_MAGIC.to_le_bytes());
        v[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        v[8..14].copy_from_slice(b"KERNEL");
        v.extend_from_slice(payload);
        v
    }

    /// Build a minimal v3 image matching the unpack test helper,
    /// duplicated here because it lives in the unpack test module.
    fn build_v3_image_raw(kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        hdr[40..44].copy_from_slice(&3u32.to_le_bytes());
        let mut out = hdr;
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

    #[test]
    fn repack_v3_mtk_kernel_round_trip_patches_size() {
        let tmp = tempfile::tempdir().unwrap();
        let orig_payload = b"--orig-mtk-kernel--".to_vec();
        let wrapped = build_mtk_wrapper(&orig_payload);
        let ramdisk = b"r".repeat(64);
        let img = build_v3_image_raw(&wrapped, &ramdisk);
        let src = tmp.path().join("src.img");
        std::fs::write(&src, &img).unwrap();

        // Unpack, then substitute a new kernel payload of a *different*
        // length in the work dir. Repack should re-prepend the MTK
        // header and patch its size field to the new length.
        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();
        let new_payload = b"--NEW-larger-mtk-kernel-payload-bytes--".to_vec();
        std::fs::write(work.join("kernel"), &new_payload).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        // Inspect the output: kernel section at page offset contains
        // MTK header (magic + patched size) followed by the new payload.
        let out_bytes = std::fs::read(&dst).unwrap();
        let k_off = 4096usize;
        let magic = u32::from_le_bytes(out_bytes[k_off..k_off + 4].try_into().unwrap());
        let size = u32::from_le_bytes(out_bytes[k_off + 4..k_off + 8].try_into().unwrap());
        assert_eq!(magic, MTK_MAGIC);
        assert_eq!(size as usize, new_payload.len());
        let hdr_len = size_of::<MtkHdr>();
        let payload_slice = &out_bytes[k_off + hdr_len..k_off + hdr_len + new_payload.len()];
        assert_eq!(payload_slice, new_payload.as_slice());

        // Re-unpack parity: MTK strips back off, kernel file = new payload.
        let work2 = tmp.path().join("work2");
        let report = crate::bootimg::unpack::unpack(&dst, &work2, true, false).unwrap();
        assert!(report.has(BootFlag::MtkKernel));
        assert_eq!(std::fs::read(work2.join("kernel")).unwrap(), new_payload);
    }

    #[test]
    fn repack_v3_nookhd_preserves_pre_header_bytes() {
        use crate::bootimg::hdr::{NOOKHD_PRE_HEADER_SZ, NOOKHD_RL_MAGIC};
        let tmp = tempfile::tempdir().unwrap();
        let mut pre = vec![0u8; NOOKHD_PRE_HEADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre[64..64 + NOOKHD_RL_MAGIC.len()].copy_from_slice(NOOKHD_RL_MAGIC);
        // Spread a recognisable byte pattern across the pre-header so
        // any byte-drift on repack would be detectable.
        for (i, b) in pre.iter_mut().enumerate().skip(128).take(256) {
            *b = (i & 0xff) as u8;
        }
        let kernel = b"KN-nk".to_vec();
        let ramdisk = b"RN-nk".to_vec();
        let mut img = pre.clone();
        img.extend_from_slice(&build_v3_image_raw(&kernel, &ramdisk));
        let src = tmp.path().join("nook.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();
        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        // Verify pre-header bytes survive byte-for-byte.
        let out_bytes = std::fs::read(&dst).unwrap();
        assert_eq!(&out_bytes[..NOOKHD_PRE_HEADER_SZ], pre.as_slice());
    }

    #[test]
    fn repack_dhtb_patches_size_and_checksum() {
        use sha2::Digest;
        const DHTB_HDR_SIZE: usize = 512;
        const TRAILER_LEN: usize = 16 + 4;
        let tmp = tempfile::tempdir().unwrap();

        let kernel = b"DHTB-KERNEL".to_vec();
        let ramdisk = b"DHTB-RAMDISK".to_vec();
        let aosp = build_v3_image_raw(&kernel, &ramdisk);
        let aosp_size = aosp.len() as u32;

        // Assemble: DHTB hdr (magic only, size/checksum stale) + AOSP +
        // SEANDROIDENFORCE + 0xFFFFFFFF trailer.
        let mut img = vec![0u8; DHTB_HDR_SIZE];
        img[..DHTB_MAGIC.len()].copy_from_slice(DHTB_MAGIC);
        // Stale size + checksum so we can prove the repacker overwrote them.
        img[48..52].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        img[8..8 + 32].copy_from_slice(&[0xCDu8; 32]);
        img.extend_from_slice(&aosp);
        img.extend_from_slice(b"SEANDROIDENFORCE");
        img.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        let src = tmp.path().join("dhtb.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();
        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let out = std::fs::read(&dst).unwrap();
        assert!(out.starts_with(DHTB_MAGIC), "DHTB magic survives repack");

        // Size field = AOSP size + 20 (SEANDROIDENFORCE + 0xFFFFFFFF).
        let dhtb_size = u32::from_le_bytes(out[48..52].try_into().unwrap());
        assert_eq!(
            dhtb_size,
            aosp_size + TRAILER_LEN as u32,
            "DHTB size must cover AOSP payload + 20-byte trailer"
        );

        // Checksum = SHA-256 over the 20-byte-padded payload.
        let hash_end = DHTB_HDR_SIZE + dhtb_size as usize;
        let expected = Sha256::digest(&out[DHTB_HDR_SIZE..hash_end]);
        assert_eq!(
            &out[8..8 + 32],
            expected.as_slice(),
            "DHTB SHA-256 checksum must match upstream formula"
        );
        // Last 8 bytes of the 40-byte checksum slot must be zero.
        assert!(
            out[8 + 32..48].iter().all(|&b| b == 0),
            "DHTB checksum slot tail must be zero-padded"
        );
    }

    /// Round-trip real vendor images: unpack → repack → re-unpack,
    /// verify kernel + ramdisk.cpio bytes match on every hop.
    /// Skipped unless the env var (see body) points at a firmware dir.
    #[test]
    fn repack_tb322fc_samples_round_trip() {
        let Ok(dir) = std::env::var("LTBOX_TB322_IMAGES") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        for img_name in ["init_boot.img", "boot.img", "vendor_boot.img"] {
            let src = dir.join(img_name);
            if !src.exists() {
                continue;
            }
            let tmp = tempfile::tempdir().unwrap();
            let work1 = tmp.path().join("work1");
            unpack(&src, &work1, false, true)
                .unwrap_or_else(|e| panic!("{img_name} first unpack: {e}"));

            let dst = tmp.path().join("dst.img");
            repack(&src, &work1, &dst, false).unwrap_or_else(|e| panic!("{img_name} repack: {e}"));

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

    // ---------- id field patching (SHA-1 / SHA-256) ----------

    /// Offset of the `id` field inside `BootImgHdrV0`. Layout (packed):
    /// magic(8) + 8×u32(32) + 2×u32(8) + name(16) + cmdline(512) = 576.
    const V0_ID_OFFSET: usize = 576;

    #[test]
    fn repack_v1_patches_sha1_id() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KERNEL-IDSHA1".to_vec();
        let ramdisk = b"RAMDISK-IDSHA1".to_vec();
        let mut img = build_v1_image_for_repack(2048, &kernel, &ramdisk);

        // Stamp garbage over the first 20 id bytes; leave bytes 24..32
        // zero so `id_uses_sha1` detects SHA-1 mode on repack.
        for i in 0..20 {
            img[V0_ID_OFFSET + i] = 0xAB;
        }
        let src = tmp.path().join("v1_sha1.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let out = std::fs::read(&dst).unwrap();
        let new_id = &out[V0_ID_OFFSET..V0_ID_OFFSET + BOOT_ID_SIZE];

        // Independently reproduce the C++ feed sequence for v1:
        // kernel+ksize, ramdisk+rsize, second+ssize, recovery_dtbo+rdsize.
        let mut h = Sha1::new();
        h.update(&kernel);
        h.update(&(kernel.len() as u32).to_le_bytes());
        h.update(&ramdisk);
        h.update(&(ramdisk.len() as u32).to_le_bytes());
        h.update(&0u32.to_le_bytes()); // second empty + size
        h.update(&0u32.to_le_bytes()); // recovery_dtbo empty + size
        let expected = h.finalize();

        assert_eq!(
            &new_id[..SHA_DIGEST_SIZE],
            expected.as_slice(),
            "SHA-1 id digest mismatch"
        );
        assert!(
            new_id[SHA_DIGEST_SIZE..].iter().all(|&b| b == 0),
            "SHA-1 tail bytes must be zero-padded"
        );
    }

    #[test]
    fn repack_v1_patches_sha256_id() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KERNEL-IDSHA256".to_vec();
        let ramdisk = b"RAMDISK-IDSHA256".to_vec();
        let mut img = build_v1_image_for_repack(2048, &kernel, &ramdisk);

        // Any non-zero byte in id[24..32] flips detection to SHA-256.
        img[V0_ID_OFFSET + 24] = 0xFF;
        let src = tmp.path().join("v1_sha256.img");
        std::fs::write(&src, &img).unwrap();

        let work = tmp.path().join("work");
        crate::bootimg::unpack::unpack(&src, &work, true, false).unwrap();

        let dst = tmp.path().join("dst.img");
        repack(&src, &work, &dst, true).unwrap();

        let out = std::fs::read(&dst).unwrap();
        let new_id = &out[V0_ID_OFFSET..V0_ID_OFFSET + BOOT_ID_SIZE];

        let mut h = Sha256::new();
        h.update(&kernel);
        h.update(&(kernel.len() as u32).to_le_bytes());
        h.update(&ramdisk);
        h.update(&(ramdisk.len() as u32).to_le_bytes());
        h.update(&0u32.to_le_bytes());
        h.update(&0u32.to_le_bytes());
        let expected = h.finalize();

        assert_eq!(new_id, expected.as_slice(), "SHA-256 id digest mismatch");
    }

    /// Byte-for-byte parity against a C++ `magiskboot repack` result.
    /// Runs only when the reference env var (see body) names a
    /// directory that contains:
    ///
    /// - `src.img`       — original source image
    /// - `work/kernel`, `work/ramdisk.cpio` (+ `signature` for v4) —
    ///   the exact bytes the user plans to feed the repacker
    /// - `cpp.img`       — the reference C++ output
    ///
    /// We invoke the Rust repack with the same inputs and compare
    /// byte-for-byte. Only passes when both tools agree bit-exactly
    /// — currently expected only for `skip_comp = true`, since
    /// compressed output byte-drifts between libraries. A secondary
    /// env var (see body) gates that mode.
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
