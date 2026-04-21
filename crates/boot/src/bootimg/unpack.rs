//! Boot image unpack — pure-Rust port of the C++ `boot_img`
//! constructor + `parse_image` + `parse_hdr` + `dump` path.
//!
//! Scope: AOSP boot_img v3 / v4 + vendor_boot v3 / v4 + the outer
//! wrappers the sniffer already handles (direct AOSP / ChromeOS /
//! DHTB / Tegra Blob). Follow-up commits add legacy v0 / v1 / v2 +
//! PXA, MTK / Nook / Acclaim / Amonet / Z4 / zImage wrappers.
//!
//! The exit-code bitmask returned by [`unpack`] stays
//! binary-compatible with the upstream C++ build — callers read
//! individual bits to drive downstream logic (e.g. whether AVB
//! re-signing is required).

use std::fs::File;
use std::io;
use std::io::Write;
use std::mem::size_of;
use std::path::Path;

use bytemuck::Pod;

use crate::bootimg::hdr::{
    ACCLAIM_MAGIC, ACCLAIM_PRE_HEADER_SZ, AMONET_MICROLOADER_MAGIC, AMONET_MICROLOADER_SZ,
    BLOB_MAGIC, BOOT_FLAGS_MAX, BOOT_MAGIC, BootFlag, BootImgHdrPxa, BootImgHdrV0, BootImgHdrV1,
    BootImgHdrV2, BootImgHdrV3, BootImgHdrV4, BootImgHdrVndV3, BootImgHdrVndV4, CHROMEOS_MAGIC,
    DHTB_MAGIC, MTK_MAGIC, MtkHdr, NOOKHD_EB_MAGIC, NOOKHD_ER_MAGIC, NOOKHD_GL_MAGIC,
    NOOKHD_GR_MAGIC, NOOKHD_PRE_HEADER_SZ, NOOKHD_RL_MAGIC, VENDOR_BOOT_MAGIC,
    VendorRamdiskTableEntryV4, ZIMAGE_MAGIC, ZIMAGE_MAGIC_OFFSET, ZImageHdr, align_to,
    id_uses_sha1,
};

/// Directory under `out_dir` that holds per-entry vendor ramdisks for
/// vendor_boot v4 images with a non-empty ramdisk table.
pub const VND_RAMDISK_DIR: &str = "vendor_ramdisk";
/// Filename the vendor ramdisk table is dumped to so repack can
/// reconstruct it bit-for-bit (entry ordering + board_id payloads).
pub const VND_RAMDISK_TABLE_FILE: &str = "vendor_ramdisk_table";

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
    /// Byte offset of the AOSP/vendor_boot header inside the mmap'd
    /// file — 0 for unwrapped images, >0 when one of the outer
    /// wrappers was stripped.
    pub payload_offset: usize,
    /// `true` if the parsed image carries `VNDRBOOT` magic
    /// (vendor_boot), `false` for `ANDROID!` (boot/init_boot).
    pub is_vendor: bool,
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
/// `key=value` lines lands next to the sections — library callers
/// do not rely on this today but upstream CLI exposes it via
/// `--header-file`.
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

    // Slice from the detected header onward; headers + section
    // offsets are relative to this cursor.
    let payload = buf
        .get(header_offset..)
        .ok_or(UnpackError::NotAnAospBootImage)?;

    if payload.len() < BOOT_MAGIC.len() {
        return Err(UnpackError::NotAnAospBootImage);
    }
    let is_vendor = payload.starts_with(VENDOR_BOOT_MAGIC);
    let is_boot = payload.starts_with(BOOT_MAGIC);
    if !is_vendor && !is_boot {
        return Err(UnpackError::NotAnAospBootImage);
    }

    // Header version offset differs between AOSP boot and vendor_boot:
    // - AOSP boot v0..v4: magic(8) + 4*u32 + reserved[4] (v3/v4) OR
    //   magic(8) + 6*u32 (v0/v1/v2) — both land at offset 40.
    // - vendor_boot v3/v4: magic(8) directly followed by header_version = 8.
    let header_version_offset = if is_vendor { 8 } else { 40 };
    let header_version = {
        let slice = payload
            .get(header_version_offset..header_version_offset + 4)
            .ok_or(UnpackError::Truncated {
                section: "header_version",
            })?;
        u32::from_le_bytes(slice.try_into().unwrap())
    };

    // PXA detection (only for AOSP magic): page_size >= 0x02000000 is
    // impossible for a real device — upstream uses this sentinel as
    // the PXA-vs-AOSP discriminator. Field lives at offset 36 (after
    // magic + 6*u32 for size/addr pairs + tags_addr).
    let is_pxa = if !is_vendor {
        let page_size_slice = payload.get(36..40).ok_or(UnpackError::Truncated {
            section: "page_size",
        })?;
        let page_size = u32::from_le_bytes(page_size_slice.try_into().unwrap());
        page_size >= 0x0200_0000
    } else {
        false
    };

    // Effective version for the report — PXA gets its own synthetic
    // tag (0xFF) so downstream code can distinguish it from real v0.
    // The legacy v0 path falls through when header_version is 0 or
    // anything not in {1, 2, 3, 4} for AOSP magic.
    let effective_version = if is_pxa {
        0xFF
    } else if !is_vendor && !matches!(header_version, 1 | 2 | 3 | 4) {
        0
    } else {
        header_version
    };

    let mut report = UnpackReport {
        flags: outer_flags,
        header_version: effective_version,
        payload_offset: header_offset,
        is_vendor,
    };

    std::fs::create_dir_all(out_dir)?;

    if is_vendor {
        match header_version {
            3 => {
                let hdr: &BootImgHdrVndV3 = pod_ref(payload)?;
                unpack_vendor_v3_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
                if write_header_txt {
                    write_vendor_header_file(hdr, out_dir)?;
                }
            }
            4 => {
                let hdr: &BootImgHdrVndV4 = pod_ref(payload)?;
                unpack_vendor_v4_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
                if write_header_txt {
                    write_vendor_header_file(&hdr.vnd_v3, out_dir)?;
                }
            }
            other => return Err(UnpackError::UnsupportedVersion(other)),
        }
    } else if is_pxa {
        let hdr: &BootImgHdrPxa = pod_ref(payload)?;
        if !id_uses_sha1(&hdr.id) {
            report.flags |= flag_bit(BootFlag::Sha256);
        }
        unpack_pxa_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
    } else {
        match effective_version {
            0 => {
                let hdr: &BootImgHdrV0 = pod_ref(payload)?;
                if !id_uses_sha1(&hdr.id) {
                    report.flags |= flag_bit(BootFlag::Sha256);
                }
                unpack_v0_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
            }
            1 => {
                let hdr: &BootImgHdrV1 = pod_ref(payload)?;
                if !id_uses_sha1(&hdr.v0.id) {
                    report.flags |= flag_bit(BootFlag::Sha256);
                }
                unpack_v1_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
            }
            2 => {
                let hdr: &BootImgHdrV2 = pod_ref(payload)?;
                if !id_uses_sha1(&hdr.v1.v0.id) {
                    report.flags |= flag_bit(BootFlag::Sha256);
                }
                unpack_v2_sections(hdr, payload, out_dir, skip_decompress, &mut report)?;
            }
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
pub(crate) fn sniff_outer_for_repack(buf: &[u8]) -> (u32, usize) {
    sniff_outer(buf)
}

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
            // Post-AOSP-magic wrappers: NookHD / Acclaim / Amonet all
            // plant a "dummy" AOSP header whose name / cmdline / first
            // 1024 bytes carry the real wrapper magic — the actual
            // AOSP header lives at a fixed offset past the dummy.
            // Detected only at first AOSP hit so nested shifts don't
            // double-trip.

            // AMONET: first 1024 bytes contain "microloader" + real
            // BOOT_MAGIC at +1024.
            if rem.len() >= AMONET_MICROLOADER_SZ + BOOT_MAGIC.len()
                && memmem(&rem[..AMONET_MICROLOADER_SZ], AMONET_MICROLOADER_MAGIC).is_some()
                && rem[AMONET_MICROLOADER_SZ..].starts_with(BOOT_MAGIC)
            {
                flags |= flag_bit(BootFlag::Amonet);
                return (flags, i + AMONET_MICROLOADER_SZ);
            }
            // NOOKHD: dummy header's cmdline starts with a known
            // bootloader banner; real header at +0x4000.
            if rem.len() >= 64 + 32 {
                let cmd = &rem[64..64 + 32];
                if cmd.starts_with(NOOKHD_RL_MAGIC)
                    || cmd.starts_with(NOOKHD_GL_MAGIC)
                    || cmd.starts_with(NOOKHD_GR_MAGIC)
                    || cmd.starts_with(NOOKHD_EB_MAGIC)
                    || cmd.starts_with(NOOKHD_ER_MAGIC)
                {
                    flags |= flag_bit(BootFlag::NookHd);
                    if rem.len() >= NOOKHD_PRE_HEADER_SZ + BOOT_MAGIC.len() {
                        return (flags, i + NOOKHD_PRE_HEADER_SZ);
                    }
                }
            }
            // ACCLAIM: dummy header's `name` matches; real header at
            // +0x1000.
            if rem.len() >= 48 + ACCLAIM_MAGIC.len()
                && rem[48..48 + ACCLAIM_MAGIC.len()] == *ACCLAIM_MAGIC
            {
                flags |= flag_bit(BootFlag::Acclaim);
                if rem.len() >= ACCLAIM_PRE_HEADER_SZ + BOOT_MAGIC.len() {
                    return (flags, i + ACCLAIM_PRE_HEADER_SZ);
                }
            }
            return (flags, i);
        }
        if rem.starts_with(VENDOR_BOOT_MAGIC) {
            return (flags, i);
        }
        i += 1;
    }
    (flags, buf.len())
}

/// Naive `memmem` — search `needle` in `haystack`. Fine for the tiny
/// buffers used during wrapper sniffing.
fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| haystack[i..i + needle.len()] == *needle)
}

/// Legacy v0/v1/v2/PXA section walker. Upstream C++ dumps these in a
/// fixed order: kernel, ramdisk, second, extra (v0 only when
/// extra_size > 0), recovery_dtbo (v1/v2 only), dtb (v2 only). Every
/// section ends on the next `page` boundary measured from the AOSP
/// header start (C++ `file_align()` macro).
struct LegacyLayout {
    page: u64,
    hdr_size: u64,
    kernel_size: u64,
    ramdisk_size: u64,
    second_size: u64,
    extra_size: u64,
    recovery_dtbo_size: u64,
    dtb_size: u64,
}

fn unpack_legacy_sections(
    lay: &LegacyLayout,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    if lay.page == 0 {
        return Err(UnpackError::Truncated {
            section: "page_size",
        });
    }
    let mut off = align_to(lay.hdr_size, lay.page);

    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        lay.kernel_size as usize,
        out_dir,
        "kernel",
        skip_decompress,
        report,
        true,
    )?;
    off = align_to(off + lay.kernel_size, lay.page);

    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        lay.ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
        report,
        false,
    )?;
    off = align_to(off + lay.ramdisk_size, lay.page);

    if lay.second_size > 0 {
        dump_section(
            payload,
            off as usize,
            lay.second_size as usize,
            out_dir,
            "second",
            skip_decompress,
        )?;
    }
    off = align_to(off + lay.second_size, lay.page);

    if lay.extra_size > 0 {
        dump_section(
            payload,
            off as usize,
            lay.extra_size as usize,
            out_dir,
            "extra",
            skip_decompress,
        )?;
    }
    off = align_to(off + lay.extra_size, lay.page);

    if lay.recovery_dtbo_size > 0 {
        dump_section(
            payload,
            off as usize,
            lay.recovery_dtbo_size as usize,
            out_dir,
            "recovery_dtbo",
            true,
        )?;
    }
    off = align_to(off + lay.recovery_dtbo_size, lay.page);

    if lay.dtb_size > 0 {
        dump_section(
            payload,
            off as usize,
            lay.dtb_size as usize,
            out_dir,
            "dtb",
            true,
        )?;
    }
    Ok(())
}

fn unpack_v0_sections(
    hdr: &BootImgHdrV0,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    // On v0 the union field `header_version` carries `extra_size`.
    let extra_size = hdr.header_version as u64;
    let lay = LegacyLayout {
        page: hdr.page_size as u64,
        hdr_size: std::mem::size_of::<BootImgHdrV0>() as u64,
        kernel_size: hdr.kernel_size as u64,
        ramdisk_size: hdr.ramdisk_size as u64,
        second_size: hdr.second_size as u64,
        extra_size,
        recovery_dtbo_size: 0,
        dtb_size: 0,
    };
    unpack_legacy_sections(&lay, payload, out_dir, skip_decompress, report)
}

fn unpack_v1_sections(
    hdr: &BootImgHdrV1,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    let lay = LegacyLayout {
        page: hdr.v0.page_size as u64,
        hdr_size: hdr.header_size as u64,
        kernel_size: hdr.v0.kernel_size as u64,
        ramdisk_size: hdr.v0.ramdisk_size as u64,
        second_size: hdr.v0.second_size as u64,
        extra_size: 0,
        recovery_dtbo_size: hdr.recovery_dtbo_size as u64,
        dtb_size: 0,
    };
    unpack_legacy_sections(&lay, payload, out_dir, skip_decompress, report)
}

fn unpack_v2_sections(
    hdr: &BootImgHdrV2,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    let lay = LegacyLayout {
        page: hdr.v1.v0.page_size as u64,
        hdr_size: hdr.v1.header_size as u64,
        kernel_size: hdr.v1.v0.kernel_size as u64,
        ramdisk_size: hdr.v1.v0.ramdisk_size as u64,
        second_size: hdr.v1.v0.second_size as u64,
        extra_size: 0,
        recovery_dtbo_size: hdr.v1.recovery_dtbo_size as u64,
        dtb_size: hdr.dtb_size as u64,
    };
    unpack_legacy_sections(&lay, payload, out_dir, skip_decompress, report)
}

/// Samsung PXA: same outer sections as v0 but with a different header
/// mid-field layout (shorter `name`, `extra_size` moved earlier).
fn unpack_pxa_sections(
    hdr: &BootImgHdrPxa,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    let lay = LegacyLayout {
        page: hdr.page_size as u64,
        hdr_size: std::mem::size_of::<BootImgHdrPxa>() as u64,
        kernel_size: hdr.kernel_size as u64,
        ramdisk_size: hdr.ramdisk_size as u64,
        second_size: hdr.second_size as u64,
        extra_size: hdr.extra_size as u64,
        recovery_dtbo_size: 0,
        dtb_size: 0,
    };
    unpack_legacy_sections(&lay, payload, out_dir, skip_decompress, report)
}

/// Boot v3: layout is fixed — header (4096 B) → kernel → ramdisk,
/// each section padded up to the next 4 KiB boundary.
fn unpack_v3_sections(
    hdr: &BootImgHdrV3,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    const PAGE: u64 = 4096;
    let kernel_size = hdr.kernel_size as u64;
    let ramdisk_size = hdr.ramdisk_size as u64;

    let mut off = PAGE; // header is always one 4 KiB page in v3+
    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        kernel_size as usize,
        out_dir,
        "kernel",
        skip_decompress,
        report,
        true,
    )?;
    off = align_to(off + kernel_size, PAGE);

    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
        report,
        false,
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
    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        kernel_size as usize,
        out_dir,
        "kernel",
        skip_decompress,
        report,
        true,
    )?;
    off = align_to(off + kernel_size, PAGE);

    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
        report,
        false,
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

/// Vendor_boot v3: header (page-aligned) → ramdisk → dtb. `page_size`
/// is read from the header, not fixed at 4096.
fn unpack_vendor_v3_sections(
    hdr: &BootImgHdrVndV3,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    let page = hdr.page_size as u64;
    if page == 0 {
        return Err(UnpackError::Truncated {
            section: "vendor page_size",
        });
    }
    let hdr_size = std::mem::size_of::<BootImgHdrVndV3>() as u64;
    let ramdisk_size = hdr.ramdisk_size as u64;
    let dtb_size = hdr.dtb_size as u64;

    let mut off = align_to(hdr_size, page);
    dump_kernel_or_ramdisk(
        payload,
        off as usize,
        ramdisk_size as usize,
        out_dir,
        "ramdisk.cpio",
        skip_decompress,
        report,
        false,
    )?;
    off = align_to(off + ramdisk_size, page);

    dump_section(
        payload,
        off as usize,
        dtb_size as usize,
        out_dir,
        "dtb",
        true, // dtb is raw, never compressed
    )?;
    Ok(())
}

/// Vendor_boot v4: v3 layout + vendor ramdisk table (after dtb) +
/// bootconfig (after table). Multi-ramdisk images split the vendor
/// ramdisk section per table entry into `vendor_ramdisk/<name>.cpio`.
fn unpack_vendor_v4_sections(
    hdr: &BootImgHdrVndV4,
    payload: &[u8],
    out_dir: &Path,
    skip_decompress: bool,
    report: &mut UnpackReport,
) -> Result<(), UnpackError> {
    let page = hdr.vnd_v3.page_size as u64;
    if page == 0 {
        return Err(UnpackError::Truncated {
            section: "vendor page_size",
        });
    }
    let hdr_size = std::mem::size_of::<BootImgHdrVndV4>() as u64;
    let ramdisk_size = hdr.vnd_v3.ramdisk_size as u64;
    let dtb_size = hdr.vnd_v3.dtb_size as u64;
    let table_size = hdr.vendor_ramdisk_table_size as u64;
    let table_entry_num = hdr.vendor_ramdisk_table_entry_num as u64;
    let table_entry_size = hdr.vendor_ramdisk_table_entry_size as u64;
    let bootconfig_size = hdr.bootconfig_size as u64;

    let mut off = align_to(hdr_size, page);
    let ramdisk_off = off as usize;

    if table_size > 0 {
        // Multi-ramdisk: split the vendor ramdisk section per entry.
        if table_entry_size as usize != std::mem::size_of::<VendorRamdiskTableEntryV4>() {
            return Err(UnpackError::Truncated {
                section: "vendor_ramdisk_table_entry_size mismatch",
            });
        }
        // Skip past the ramdisk section first — table lives after dtb.
        off = align_to(off + ramdisk_size, page);
        let dtb_off = off as usize;
        dump_section(payload, dtb_off, dtb_size as usize, out_dir, "dtb", true)?;
        off = align_to(off + dtb_size, page);

        // Parse the table.
        let table_off_usize = off as usize;
        let table_end =
            table_off_usize
                .checked_add(table_size as usize)
                .ok_or(UnpackError::Truncated {
                    section: "vendor_ramdisk_table",
                })?;
        if table_end > payload.len() {
            return Err(UnpackError::Truncated {
                section: "vendor_ramdisk_table",
            });
        }
        let table_bytes = &payload[table_off_usize..table_end];
        // Store the raw table bytes so repack can reproduce board_id /
        // ramdisk_type exactly without re-encoding.
        std::fs::write(out_dir.join(VND_RAMDISK_TABLE_FILE), table_bytes)?;

        std::fs::create_dir_all(out_dir.join(VND_RAMDISK_DIR))?;
        for idx in 0..table_entry_num as usize {
            let e_off = idx * table_entry_size as usize;
            let entry: &VendorRamdiskTableEntryV4 =
                bytemuck::from_bytes(&table_bytes[e_off..e_off + table_entry_size as usize]);
            let entry_ramdisk_size = entry.ramdisk_size as usize;
            let entry_ramdisk_offset = entry.ramdisk_offset as usize;
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
            let rel_path = format!("{VND_RAMDISK_DIR}/{file_name}");
            let absolute_off = ramdisk_off + entry_ramdisk_offset;
            dump_section(
                payload,
                absolute_off,
                entry_ramdisk_size,
                out_dir,
                &rel_path,
                skip_decompress,
            )?;
        }
        off = align_to(off + table_size, page);
    } else {
        // Single-ramdisk: same layout as v3.
        dump_kernel_or_ramdisk(
            payload,
            ramdisk_off,
            ramdisk_size as usize,
            out_dir,
            "ramdisk.cpio",
            skip_decompress,
            report,
            false,
        )?;
        off = align_to(off + ramdisk_size, page);
        dump_section(
            payload,
            off as usize,
            dtb_size as usize,
            out_dir,
            "dtb",
            true,
        )?;
        off = align_to(off + dtb_size, page);
    }

    let _ = table_entry_num;
    if bootconfig_size > 0 {
        dump_section(
            payload,
            off as usize,
            bootconfig_size as usize,
            out_dir,
            "bootconfig",
            true,
        )?;
    }
    Ok(())
}

/// Strip an MTK wrapper header off the start of a kernel/ramdisk
/// slice if present. Returns `(stripped_slice, had_mtk_header)`.
/// The MTK header is a 512-byte preamble with a fixed magic that
/// some MTK SoCs require in front of the kernel/ramdisk payload.
fn strip_mtk(slice: &[u8]) -> (&[u8], bool) {
    if slice.len() >= size_of::<MtkHdr>() {
        let magic = u32::from_le_bytes(slice[..4].try_into().unwrap());
        if magic == MTK_MAGIC {
            return (&slice[size_of::<MtkHdr>()..], true);
        }
    }
    (slice, false)
}

/// Detect if a (post-MTK-strip) kernel slice is an ARM zImage wrapper.
/// zImage carries the bootstrap decompressor + a compressed piggy
/// payload. For round-trip parity we only flag it — the raw zImage
/// bytes already survive unpack → repack unchanged because check_fmt
/// returns UNKNOWN for the zImage outer shell, so no decompression /
/// recompression is attempted.
fn is_zimage(slice: &[u8]) -> bool {
    if slice.len() < ZIMAGE_MAGIC_OFFSET + 4 {
        return false;
    }
    let magic = u32::from_le_bytes(
        slice[ZIMAGE_MAGIC_OFFSET..ZIMAGE_MAGIC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    magic == ZIMAGE_MAGIC
}

/// Dump a kernel or ramdisk section, stripping MTK wrapper header if
/// present and flagging zImage kernels. Thin wrapper over
/// [`dump_section`] — only the two section types that carry these
/// wrappers in the wild call this; other sections (dtb, signature,
/// bootconfig, second, extra, recovery_dtbo) use `dump_section`
/// directly so their bytes round-trip verbatim.
fn dump_kernel_or_ramdisk(
    payload: &[u8],
    off: usize,
    len: usize,
    out_dir: &Path,
    name: &str,
    skip_decompress: bool,
    report: &mut UnpackReport,
    is_kernel: bool,
) -> Result<(), UnpackError> {
    if len == 0 {
        return Ok(());
    }
    let end = off
        .checked_add(len)
        .ok_or(UnpackError::Truncated { section: "section" })?;
    if end > payload.len() {
        return Err(UnpackError::Truncated { section: "section" });
    }
    let raw = &payload[off..end];
    let (inner, had_mtk) = strip_mtk(raw);
    if had_mtk {
        report.flags |= flag_bit(if is_kernel {
            BootFlag::MtkKernel
        } else {
            BootFlag::MtkRamdisk
        });
    }
    if is_kernel && is_zimage(inner) {
        report.flags |= flag_bit(BootFlag::ZImageKernel);
    }
    dump_section_bytes(inner, out_dir, name, skip_decompress)
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
    let end = off
        .checked_add(len)
        .ok_or(UnpackError::Truncated { section: "section" })?;
    if end > payload.len() {
        return Err(UnpackError::Truncated { section: "section" });
    }
    dump_section_bytes(&payload[off..end], out_dir, name, skip_decompress)
}

/// Inner form of [`dump_section`] that takes an already-sliced byte
/// view. Used directly by [`dump_kernel_or_ramdisk`] after the
/// wrapper strip so the same compression probe / decoder path runs
/// on the inner payload instead of the MTK-wrapped outer slice.
fn dump_section_bytes(
    slice: &[u8],
    out_dir: &Path,
    name: &str,
    skip_decompress: bool,
) -> Result<(), UnpackError> {
    if slice.is_empty() {
        return Ok(());
    }
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

/// Write a minimal `<out_dir>/header` file for vendor_boot images.
/// Same shape as [`write_header_file`] but with vendor-specific
/// fields (`name`, `board_name` are the only user-editable bits).
fn write_vendor_header_file(hdr: &BootImgHdrVndV3, out_dir: &Path) -> Result<(), UnpackError> {
    let mut f = File::create(out_dir.join("header"))?;
    let cmdline = cstr_slice(&hdr.cmdline);
    let name = cstr_slice(&hdr.name);
    writeln!(f, "name={name}")?;
    writeln!(f, "cmdline={cmdline}")?;
    Ok(())
}

fn cstr_slice(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
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

    fn build_hdr_vnd_v3(page_size: u32, ramdisk_size: u32, dtb_size: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; size_of::<BootImgHdrVndV3>()];
        hdr[..8].copy_from_slice(VENDOR_BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&3u32.to_le_bytes()); // header_version
        hdr[12..16].copy_from_slice(&page_size.to_le_bytes());
        hdr[16..20].copy_from_slice(&0u32.to_le_bytes()); // kernel_addr
        hdr[20..24].copy_from_slice(&0u32.to_le_bytes()); // ramdisk_addr
        hdr[24..28].copy_from_slice(&ramdisk_size.to_le_bytes());
        // cmdline[2048] @ offset 28
        let cmdline_end = 28 + 2048;
        // tags_addr @ cmdline_end
        hdr[cmdline_end..cmdline_end + 4].copy_from_slice(&0u32.to_le_bytes());
        // name[16] @ cmdline_end + 4
        let name_off = cmdline_end + 4;
        // header_size @ name_off+16
        let hsize_off = name_off + 16;
        hdr[hsize_off..hsize_off + 4]
            .copy_from_slice(&(size_of::<BootImgHdrVndV3>() as u32).to_le_bytes());
        // dtb_size @ hsize_off + 4
        let dtb_off = hsize_off + 4;
        hdr[dtb_off..dtb_off + 4].copy_from_slice(&dtb_size.to_le_bytes());
        // dtb_addr @ dtb_off + 4 (u64)
        hdr
    }

    fn assemble_vendor_v3_image(page: usize, ramdisk: &[u8], dtb: &[u8]) -> Vec<u8> {
        let mut out = build_hdr_vnd_v3(page as u32, ramdisk.len() as u32, dtb.len() as u32);
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

    #[test]
    fn unpack_vendor_v3_writes_ramdisk_and_dtb() {
        let tmp = tempfile::tempdir().unwrap();
        let ramdisk = b"0707010VENDOR".to_vec();
        let dtb = b"DTBRAWBYTES".to_vec();
        let img = assemble_vendor_v3_image(4096, &ramdisk, &dtb);
        let img_path = tmp.path().join("vendor_boot.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.is_vendor);
        assert_eq!(report.header_version, 3);

        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(out.join("dtb")).unwrap(), dtb);
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

    fn build_hdr_v0(kernel: u32, ramdisk: u32, second: u32, page: u32, extra: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; size_of::<BootImgHdrV0>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&kernel.to_le_bytes());
        // kernel_addr @ 12
        hdr[16..20].copy_from_slice(&ramdisk.to_le_bytes());
        // ramdisk_addr @ 20
        hdr[24..28].copy_from_slice(&second.to_le_bytes());
        // second_addr @ 28
        // tags_addr @ 32
        hdr[36..40].copy_from_slice(&page.to_le_bytes());
        // header_version (== extra_size for v0) @ 40
        hdr[40..44].copy_from_slice(&extra.to_le_bytes());
        hdr
    }

    fn assemble_v0_image(
        page: usize,
        kernel: &[u8],
        ramdisk: &[u8],
        second: &[u8],
        extra: &[u8],
    ) -> Vec<u8> {
        let mut out = build_hdr_v0(
            kernel.len() as u32,
            ramdisk.len() as u32,
            second.len() as u32,
            page as u32,
            extra.len() as u32,
        );
        while out.len() % page != 0 {
            out.push(0);
        }
        for section in [kernel, ramdisk, second, extra] {
            if !section.is_empty() {
                out.extend_from_slice(section);
                while out.len() % page != 0 {
                    out.push(0);
                }
            } else {
                // C++ still advances one page for zero-size v0 sections.
            }
        }
        out
    }

    #[test]
    fn unpack_v0_writes_all_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let page = 2048;
        let kernel = b"KKK".to_vec();
        let ramdisk = b"RRR".to_vec();
        let second = b"SS".to_vec();
        // extra_size must NOT be in 1..=4: on v0 the header field
        // overlaps with header_version, so an extra of length 1-4 is
        // ambiguous and the parser dispatches to that version path.
        // Matches upstream C++ behavior.
        let extra = b"EEEEEE".to_vec();
        let img = assemble_v0_image(page, &kernel, &ramdisk, &second, &extra);
        let img_path = tmp.path().join("v0.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert_eq!(report.header_version, 0);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
        assert_eq!(std::fs::read(out.join("second")).unwrap(), second);
        assert_eq!(std::fs::read(out.join("extra")).unwrap(), extra);
    }

    fn build_v1_image(page: usize, kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
        let hdr_size = size_of::<BootImgHdrV1>() as u32;
        let mut hdr = vec![0u8; size_of::<BootImgHdrV1>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        hdr[36..40].copy_from_slice(&(page as u32).to_le_bytes());
        hdr[40..44].copy_from_slice(&1u32.to_le_bytes()); // header_version = 1
        // v1 fields at size_of::<BootImgHdrV0>() = 1632
        let v1_off = size_of::<BootImgHdrV0>();
        // recovery_dtbo_size (u32) @ v1_off
        // recovery_dtbo_offset (u64) @ v1_off+4
        // header_size (u32) @ v1_off+12
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
    fn unpack_v1_writes_kernel_and_ramdisk() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"K1".to_vec();
        let ramdisk = b"R1".to_vec();
        let img = build_v1_image(2048, &kernel, &ramdisk);
        let img_path = tmp.path().join("v1.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert_eq!(report.header_version, 1);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn unpack_pxa_detected_by_sentinel_page_size() {
        let tmp = tempfile::tempdir().unwrap();
        let page: u32 = 0x0200_1000; // sentinel — PXA
        let kernel = b"Kpxa".to_vec();
        let ramdisk = b"Rpxa".to_vec();
        let mut hdr = vec![0u8; size_of::<BootImgHdrPxa>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        // second_size @ 24 = 0
        // extra_size (PXA-specific @ 32)
        hdr[32..36].copy_from_slice(&0u32.to_le_bytes());
        // unknown @ 36 — but unpack() reads page_size at offset 36 for PXA detection,
        // which means PXA `unknown` overlaps with v0 `page_size`. Upstream sets PXA
        // `page_size` at offset 44; our detection logic sniffs offset 36. To mirror
        // upstream behavior, put the sentinel at offset 36 for the test.
        hdr[36..40].copy_from_slice(&page.to_le_bytes());
        // PXA's real page_size @ offset 44
        hdr[44..48].copy_from_slice(&2048u32.to_le_bytes());
        let real_page = 2048usize;

        let mut img = hdr;
        while img.len() % real_page != 0 {
            img.push(0);
        }
        img.extend_from_slice(&kernel);
        while img.len() % real_page != 0 {
            img.push(0);
        }
        img.extend_from_slice(&ramdisk);
        while img.len() % real_page != 0 {
            img.push(0);
        }

        let img_path = tmp.path().join("pxa.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert_eq!(report.header_version, 0xFF);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
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
        // vendor_boot only supports v3/v4 — v5 should error.
        let tmp = tempfile::tempdir().unwrap();
        let mut hdr = vec![0u8; 4096];
        hdr[..8].copy_from_slice(VENDOR_BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&5u32.to_le_bytes()); // header_version = 5
        let img_path = tmp.path().join("vnd_v5.img");
        std::fs::write(&img_path, &hdr).unwrap();
        let out = tmp.path().join("out");
        let err = unpack(&img_path, &out, true, false).unwrap_err();
        assert!(matches!(err, UnpackError::UnsupportedVersion(5)));
    }

    // ---------- Section-wrapper detection (MTK / zImage) ----------

    /// Build a 512-byte MTK header wrapping `payload`. Layout mirrors
    /// `MtkHdr`: magic(LE u32) + size(LE u32) + name(32) + pad(472).
    fn build_mtk_wrapper(payload: &[u8], name: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; size_of::<MtkHdr>()];
        v[..4].copy_from_slice(&MTK_MAGIC.to_le_bytes());
        v[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let nlen = name.len().min(32);
        v[8..8 + nlen].copy_from_slice(&name[..nlen]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn unpack_flags_mtk_kernel_and_strips_header() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = b"--MTK-KERNEL-PAYLOAD--".to_vec();
        let wrapped = build_mtk_wrapper(&payload, b"KERNEL");
        let ramdisk = b"r".repeat(64);
        let img = assemble_v3_image(&wrapped, &ramdisk);
        let img_path = tmp.path().join("mtk_kernel.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::MtkKernel));
        assert!(!report.has(BootFlag::MtkRamdisk));
        // Kernel file should contain the stripped payload, not MTK bytes.
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), payload);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn unpack_flags_mtk_ramdisk_and_strips_header() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"k".repeat(64);
        let payload = b"--MTK-RAMDISK-CPIO--".to_vec();
        let wrapped = build_mtk_wrapper(&payload, b"RAMDISK");
        let img = assemble_v3_image(&kernel, &wrapped);
        let img_path = tmp.path().join("mtk_ramdisk.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::MtkRamdisk));
        assert!(!report.has(BootFlag::MtkKernel));
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), payload);
    }

    #[test]
    fn unpack_flags_zimage_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        // zImage: ZIMAGE_MAGIC at offset 0x24 (36). Anything before
        // that is free-form bootstrap code bytes.
        let mut zimage = vec![0xAAu8; 64];
        zimage[ZIMAGE_MAGIC_OFFSET..ZIMAGE_MAGIC_OFFSET + 4]
            .copy_from_slice(&ZIMAGE_MAGIC.to_le_bytes());
        let ramdisk = b"r".repeat(32);
        let img = assemble_v3_image(&zimage, &ramdisk);
        let img_path = tmp.path().join("zimage.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::ZImageKernel));
        // No MTK wrapper — raw zImage bytes survive unpack verbatim.
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), zimage);
    }

    // ---------- Pre-header wrapper detection (NookHD / Acclaim / Amonet) ----------

    /// Pad `pre` up to `size` bytes, then append the standard v3 image.
    fn assemble_prefixed_v3(pre: &[u8], size: usize, kernel: &[u8], ramdisk: &[u8]) -> Vec<u8> {
        assert!(pre.len() <= size);
        let mut out = pre.to_vec();
        out.resize(size, 0);
        out.extend_from_slice(&assemble_v3_image(kernel, ramdisk));
        out
    }

    #[test]
    fn sniff_outer_strips_nookhd_wrapper() {
        // NookHD dummy header: BOOT_MAGIC at 0 with a known banner in
        // the cmdline field at offset 64. Real AOSP image at +0x4000.
        let mut pre = vec![0u8; NOOKHD_PRE_HEADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre[64..64 + NOOKHD_RL_MAGIC.len()].copy_from_slice(NOOKHD_RL_MAGIC);
        // Append real AOSP v3 image.
        pre.extend_from_slice(&assemble_v3_image(b"KN", b"RN"));
        let (flags, off) = sniff_outer(&pre);
        assert!(flags & flag_bit(BootFlag::NookHd) != 0);
        assert_eq!(off, NOOKHD_PRE_HEADER_SZ);
    }

    #[test]
    fn unpack_strips_nookhd_pre_header() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pre = vec![0u8; 64];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre.resize(64, 0);
        // Re-allocate to the full NookHD pre-header layout.
        let kernel = b"KN-payload".to_vec();
        let ramdisk = b"RN-payload".to_vec();
        let mut pre_full = vec![0u8; NOOKHD_PRE_HEADER_SZ];
        pre_full[..8].copy_from_slice(BOOT_MAGIC);
        pre_full[64..64 + NOOKHD_RL_MAGIC.len()].copy_from_slice(NOOKHD_RL_MAGIC);
        let img = assemble_prefixed_v3(&pre_full, NOOKHD_PRE_HEADER_SZ, &kernel, &ramdisk);
        let img_path = tmp.path().join("nookhd.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::NookHd));
        assert_eq!(report.payload_offset, NOOKHD_PRE_HEADER_SZ);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn sniff_outer_strips_acclaim_wrapper() {
        // Acclaim dummy header: BOOT_MAGIC at 0, "BauwksBoot" at
        // offset 48 (name field). Real AOSP image at +0x1000.
        let mut pre = vec![0u8; ACCLAIM_PRE_HEADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre[48..48 + ACCLAIM_MAGIC.len()].copy_from_slice(ACCLAIM_MAGIC);
        pre.extend_from_slice(&assemble_v3_image(b"KA", b"RA"));
        let (flags, off) = sniff_outer(&pre);
        assert!(flags & flag_bit(BootFlag::Acclaim) != 0);
        assert_eq!(off, ACCLAIM_PRE_HEADER_SZ);
    }

    #[test]
    fn unpack_strips_acclaim_pre_header() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KA-payload".to_vec();
        let ramdisk = b"RA-payload".to_vec();
        let mut pre = vec![0u8; ACCLAIM_PRE_HEADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre[48..48 + ACCLAIM_MAGIC.len()].copy_from_slice(ACCLAIM_MAGIC);
        let img = assemble_prefixed_v3(&pre, ACCLAIM_PRE_HEADER_SZ, &kernel, &ramdisk);
        let img_path = tmp.path().join("acclaim.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::Acclaim));
        assert_eq!(report.payload_offset, ACCLAIM_PRE_HEADER_SZ);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    #[test]
    fn sniff_outer_strips_amonet_wrapper() {
        // Amonet microloader: BOOT_MAGIC at 0 followed by "microloader"
        // somewhere in first 1024 bytes. Real AOSP image at +1024.
        let mut pre = vec![0u8; AMONET_MICROLOADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        // Upstream places "microloader" in the name field at offset 48.
        pre[48..48 + AMONET_MICROLOADER_MAGIC.len()].copy_from_slice(AMONET_MICROLOADER_MAGIC);
        pre.extend_from_slice(&assemble_v3_image(b"KM", b"RM"));
        let (flags, off) = sniff_outer(&pre);
        assert!(flags & flag_bit(BootFlag::Amonet) != 0);
        assert_eq!(off, AMONET_MICROLOADER_SZ);
    }

    #[test]
    fn unpack_strips_amonet_pre_header() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = b"KM-payload".to_vec();
        let ramdisk = b"RM-payload".to_vec();
        let mut pre = vec![0u8; AMONET_MICROLOADER_SZ];
        pre[..8].copy_from_slice(BOOT_MAGIC);
        pre[48..48 + AMONET_MICROLOADER_MAGIC.len()].copy_from_slice(AMONET_MICROLOADER_MAGIC);
        let img = assemble_prefixed_v3(&pre, AMONET_MICROLOADER_SZ, &kernel, &ramdisk);
        let img_path = tmp.path().join("amonet.img");
        std::fs::write(&img_path, &img).unwrap();

        let out = tmp.path().join("out");
        let report = unpack(&img_path, &out, true, false).expect("unpack");
        assert!(report.has(BootFlag::Amonet));
        assert_eq!(report.payload_offset, AMONET_MICROLOADER_SZ);
        assert_eq!(std::fs::read(out.join("kernel")).unwrap(), kernel);
        assert_eq!(std::fs::read(out.join("ramdisk.cpio")).unwrap(), ramdisk);
    }

    /// Hardware-in-the-loop smoke test — runs only when the env var
    /// (see body) points at a firmware directory with
    /// `init_boot.img` and `boot.img`. Skipped otherwise so the
    /// default `cargo test` stays hermetic.
    ///
    /// We assert just layout-level invariants:
    ///
    /// - Header version is 4 (both vendor images).
    /// - Every non-empty section the header advertises actually
    ///   lands on disk with the declared byte count.
    ///
    /// AVB signature-block checks are deliberately absent — some
    /// vendor v4 images leave `signature_size = 0` and carry their
    /// AVB2 footer as an appended tail instead. Tail detection is
    /// added in the next sub-phase.
    #[test]
    fn unpack_tb322fc_samples() {
        let Ok(dir) = std::env::var("LTBOX_TB322_IMAGES") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        for img_name in ["init_boot.img", "boot.img", "vendor_boot.img"] {
            let img = dir.join(img_name);
            if !img.exists() {
                continue;
            }
            let tmp = tempfile::tempdir().unwrap();
            let out = tmp.path().join("out");
            let report =
                unpack(&img, &out, true, true).unwrap_or_else(|e| panic!("{img_name} unpack: {e}"));
            assert_eq!(report.header_version, 4, "{img_name} version");

            // Re-read the header to confirm the on-disk section
            // sizes match what unpack wrote.
            let bytes = std::fs::read(&img).unwrap();
            if report.is_vendor {
                let v4: &BootImgHdrVndV4 =
                    bytemuck::from_bytes(&bytes[..size_of::<BootImgHdrVndV4>()]);
                let rsz = v4.vnd_v3.ramdisk_size as u64;
                let dsz = v4.vnd_v3.dtb_size as u64;
                let tsz = v4.vendor_ramdisk_table_size as u64;
                if tsz == 0 && rsz > 0 {
                    let r = std::fs::read(out.join("ramdisk.cpio")).unwrap();
                    assert_eq!(r.len() as u64, rsz, "{img_name} ramdisk size");
                }
                if dsz > 0 {
                    let d = std::fs::read(out.join("dtb")).unwrap();
                    assert_eq!(d.len() as u64, dsz, "{img_name} dtb size");
                }
            } else {
                let v4: &BootImgHdrV4 = bytemuck::from_bytes(&bytes[..size_of::<BootImgHdrV4>()]);
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
    }

    /// Byte-for-byte parity against the C++ `magiskboot unpack`
    /// output. Runs only when the reference env var (see body)
    /// points at a directory that already contains the reference
    /// outputs a previous `magiskboot.exe` run produced in an
    /// otherwise-empty folder (the original `init_boot.img` must
    /// sit next to the reference `ramdisk.cpio`).
    ///
    /// This closes the loop on 7B: an unnoticed byte-drift in
    /// either the header carve or the downstream decompression
    /// trips here before it trips downstream Magisk patching.
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
            for name in [
                "kernel",
                "ramdisk.cpio",
                "dtb",
                "second",
                "signature",
                "header",
            ] {
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
