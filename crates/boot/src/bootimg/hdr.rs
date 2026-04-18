//! Boot-image header structs + magic constants.
//!
//! Direct port of `cpp/bootimg.hpp`. Every struct uses `#[repr(C)]`
//! with `#[repr(packed)]` where the C++ side used
//! `__attribute__((packed))` / `#pragma pack(1)`. `bytemuck::Pod`
//! enables zero-copy `&[u8] → &Struct` reinterpretation from a memory
//! map. All multi-byte fields are little-endian on-disk, matching
//! the Android boot image format + the original C++ code's direct
//! struct reads.
//!
//! Field names mirror the C++ originals so a side-by-side diff
//! against `bootimg.hpp` stays trivial.
//!
//! Notes on packing:
//! - The v0/v1/v2 chain used C++ single-inheritance to concatenate
//!   fields. We inline the fields here instead because packed-repr
//!   + inheritance is not expressible in Rust. The byte layout is
//!   identical.
//! - `union { unknown; page_size; }` and `union { header_version;
//!   extra_size; }` in the C++ header are single `u32` fields here.
//!   The C++ code interprets them both ways depending on context,
//!   which is also how the Rust parser will read them.
//! - `pxa` (Samsung) lays its fields out slightly differently — the
//!   `name` is 24 bytes not 16, and `extra_size` moves earlier.
//!   Kept as its own struct rather than a variant to preserve the
//!   original layout.

use bytemuck::{Pod, Zeroable};

// ---------------------------------------------------------------------------
// Size constants (mirror bootimg.hpp #defines)
// ---------------------------------------------------------------------------

pub const BOOT_MAGIC_SIZE: usize = 8;
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ID_SIZE: usize = 32;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;
pub const VENDOR_BOOT_ARGS_SIZE: usize = 2048;
pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: usize = 16;

pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;

pub const AVB_FOOTER_MAGIC_LEN: usize = 4;
pub const AVB_MAGIC_LEN: usize = 4;
pub const AVB_RELEASE_STRING_SIZE: usize = 48;

// ---------------------------------------------------------------------------
// Magic byte sequences. Kept as `&[u8]` rather than `&str` so callers
// can `buf.starts_with(MAGIC)` without worrying about UTF-8 rules.
// ---------------------------------------------------------------------------

/// `"ANDROID!"` — magic for boot.img v0..v4.
pub const BOOT_MAGIC: &[u8] = b"ANDROID!";
/// `"VNDRBOOT"` — magic for vendor_boot.img v3/v4.
pub const VENDOR_BOOT_MAGIC: &[u8] = b"VNDRBOOT";
/// `"CHROMEOS"` — ChromeOS verified boot wrapper magic.
pub const CHROMEOS_MAGIC: &[u8] = b"CHROMEOS";
/// MTK bootloader magic (`0x58881688` little-endian).
pub const MTK_MAGIC: u32 = 0x8816_8858;
/// DHTB bootloader magic.
pub const DHTB_MAGIC: &[u8] = b"DHTB\x01\x00\x00\x00";
/// Samsung secure-signed blob magic.
pub const SEANDROID_MAGIC: &[u8] = b"SEANDROIDENFORCE";
/// LG / Bump magic.
pub const LG_BUMP_MAGIC: &[u8] = b"\x41\xa9\xe4\x67\x74\x4d\x1d\x1b";
/// Nook HD+ wrapper magic (at offset 0x4000).
pub const NOOKHD_RL_MAGIC: &[u8] = b"Red Loader";
pub const NOOKHD_GL_MAGIC: &[u8] = b"Green Loader";
pub const NOOKHD_GR_MAGIC: &[u8] = b"Green Recovery";
pub const NOOKHD_EB_MAGIC: &[u8] = b"eMMC boot.img+secondloader";
pub const NOOKHD_ER_MAGIC: &[u8] = b"eMMC recovery.img+secondloader";
pub const NOOKHD_PRE_HEADER_SZ: usize = 0x4000;
/// Acclaim wrapper magic (at offset 0x1000).
pub const ACCLAIM_MAGIC: &[u8] = b"BauwksBoot";
pub const ACCLAIM_PRE_HEADER_SZ: usize = 0x1000;
/// AMONET microloader magic at boot-image offset 0.
pub const AMONET_MICROLOADER_MAGIC: &[u8] = b"microloader";
pub const AMONET_MICROLOADER_SZ: usize = 1024;
/// AVB1 (Android Verified Boot, version 1) signature magic.
pub const AVB1_SIGNATURE_MAGIC: &[u8] = b"AVB\x00";
/// AVB2 footer + vbmeta magics.
pub const AVB_FOOTER_MAGIC: &[u8] = b"AVBf";
pub const AVB_MAGIC: &[u8] = b"AVB0";
/// Blob (MSM radio update) magic — the first 20 bytes of a blob image.
pub const BLOB_MAGIC: &[u8] = b"-SIGNED-BY-SIGNBLOB-";
/// Z4 (Samsung Z4) wrapper magic, found at offset 0.
pub const Z4_MAGIC: &[u8] = b"lokiloader";
/// zImage kernel magic (offset 0x24 — `code[9]` of `zimage_hdr`).
pub const ZIMAGE_MAGIC: u32 = 0x016f_2818;
/// zImage magic offset inside the header (`code[9]` → 36 bytes in).
pub const ZIMAGE_MAGIC_OFFSET: usize = 0x24;

// ---------------------------------------------------------------------------
// Alignment helpers (port of bootimg.hpp's `align_to` / `align_padding`).
// ---------------------------------------------------------------------------

/// Round `v` up to the next multiple of `a`. `a` must be non-zero.
pub fn align_to(v: u64, a: u64) -> u64 {
    debug_assert!(a > 0, "align_to called with zero alignment");
    v.div_ceil(a) * a
}

/// Number of zero bytes that need to be appended to reach the next
/// `a`-aligned offset from `v`.
pub fn align_padding(v: u64, a: u64) -> u64 {
    align_to(v, a) - v
}

// ---------------------------------------------------------------------------
// Special / wrapper headers
// ---------------------------------------------------------------------------

/// 512-byte MTK bootloader header. Prepended to kernel and ramdisk
/// blobs on some MTK SoC boot images.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MtkHdr {
    pub magic: u32,
    pub size: u32,
    pub name: [u8; 32],
    pub padding: [u8; 472],
}

/// 512-byte DHTB wrapper header. Used by some Qualcomm devices;
/// wraps the entire payload + `SEANDROIDENFORCE` trailer +
/// `0xFFFF_FFFF` marker.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct DhtbHdr {
    pub magic: [u8; 8],
    /// SHA-256 over payload + `SEANDROIDENFORCE` + `0xFFFF_FFFF`,
    /// stored as 40 bytes (the upstream C++ source reserves the
    /// same amount — extra trailing bytes are zero).
    pub checksum: [u8; 40],
    pub size: u32,
    pub padding: [u8; 460],
}

/// Samsung / MSM-RADIO-UPDATE blob header. Fixed layout, describes
/// a single partition blob.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BlobHdr {
    pub secure_magic: [u8; 20],
    pub datalen: u32,
    pub signature: u32,
    pub magic: [u8; 16],
    pub hdr_version: u32,
    pub hdr_size: u32,
    pub part_offset: u32,
    pub num_parts: u32,
    pub unknown: [u32; 7],
    pub name: [u8; 4],
    pub offset: u32,
    pub size: u32,
    pub version: u32,
}

/// ARM zImage header (partial). Only the fields we actually read.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ZImageHdr {
    pub code: [u32; 9],
    pub magic: u32,
    pub start: u32,
    pub end: u32,
    pub endian: u32,
}

// ---------------------------------------------------------------------------
// AVB (Android Verified Boot) headers
// ---------------------------------------------------------------------------

/// AVB footer found at the very end of a signed partition image.
/// Matches `libavb/avb_footer.h`.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct AvbFooter {
    pub magic: [u8; AVB_FOOTER_MAGIC_LEN],
    pub version_major: u32,
    pub version_minor: u32,
    pub original_image_size: u64,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
    pub reserved: [u8; 28],
}

/// AVB vbmeta header. Matches
/// `libavb/avb_vbmeta_image.h::AvbVBMetaImageHeader`.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct AvbVBMetaImageHeader {
    pub magic: [u8; AVB_MAGIC_LEN],
    pub required_libavb_version_major: u32,
    pub required_libavb_version_minor: u32,
    pub authentication_data_block_size: u64,
    pub auxiliary_data_block_size: u64,
    pub algorithm_type: u32,
    pub hash_offset: u64,
    pub hash_size: u64,
    pub signature_offset: u64,
    pub signature_size: u64,
    pub public_key_offset: u64,
    pub public_key_size: u64,
    pub public_key_metadata_offset: u64,
    pub public_key_metadata_size: u64,
    pub descriptors_offset: u64,
    pub descriptors_size: u64,
    pub rollback_index: u64,
    pub flags: u32,
    pub rollback_index_location: u32,
    pub release_string: [u8; AVB_RELEASE_STRING_SIZE],
    pub reserved: [u8; 80],
}

// ---------------------------------------------------------------------------
// AOSP boot_img headers (v0..v4). Fields inlined from the C++ single-
// inheritance chain.
// ---------------------------------------------------------------------------

/// AOSP boot image header, version 0 (legacy layout).
///
/// Two-way union fields (`unknown`/`page_size`, `header_version`/
/// `extra_size`) live as plain `u32`s — the parser reinterprets
/// them based on context.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrV0 {
    pub magic: [u8; BOOT_MAGIC_SIZE],

    pub kernel_size: u32,
    pub kernel_addr: u32,

    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,

    pub second_size: u32,
    pub second_addr: u32,

    pub tags_addr: u32,
    /// Union: AOSP → `page_size`, Samsung PXA → `unknown`.
    pub page_size: u32,
    /// Union: v1+ → `header_version`, v0 → `extra_size`.
    pub header_version: u32,

    pub os_version: u32,
    pub name: [u8; BOOT_NAME_SIZE],
    pub cmdline: [u8; BOOT_ARGS_SIZE],
    pub id: [u8; BOOT_ID_SIZE],
    pub extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],
}

/// AOSP boot image header, version 1 — adds recovery_dtbo + header_size.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrV1 {
    pub v0: BootImgHdrV0,
    pub recovery_dtbo_size: u32,
    pub recovery_dtbo_offset: u64,
    pub header_size: u32,
}

/// AOSP boot image header, version 2 — adds DTB section.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrV2 {
    pub v1: BootImgHdrV1,
    pub dtb_size: u32,
    pub dtb_addr: u64,
}

/// Samsung PXA header — same prefix as v0 but with a different
/// mid-field layout (shorter `name`, earlier `extra_size`).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrPxa {
    pub magic: [u8; BOOT_MAGIC_SIZE],
    pub kernel_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub second_size: u32,
    pub second_addr: u32,

    pub extra_size: u32,
    pub unknown: u32,
    pub tags_addr: u32,
    pub page_size: u32,

    pub name: [u8; 24],
    pub cmdline: [u8; BOOT_ARGS_SIZE],
    pub id: [u8; BOOT_ID_SIZE],
    pub extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],
}

/// AOSP boot image header, version 3 — flat layout, 4 KiB header.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrV3 {
    pub magic: [u8; BOOT_MAGIC_SIZE],
    pub kernel_size: u32,
    pub ramdisk_size: u32,
    pub os_version: u32,
    pub header_size: u32,
    pub reserved: [u32; 4],
    pub header_version: u32,
    /// `cmdline[0..BOOT_ARGS_SIZE]` = `cmdline`,
    /// `cmdline[BOOT_ARGS_SIZE..]` = `extra_cmdline`.
    pub cmdline: [u8; BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE],
}

/// AOSP boot image header, version 4 — v3 + signature size.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrV4 {
    pub v3: BootImgHdrV3,
    pub signature_size: u32,
}

/// AOSP vendor_boot header, version 3.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrVndV3 {
    pub magic: [u8; BOOT_MAGIC_SIZE],
    pub header_version: u32,
    pub page_size: u32,
    pub kernel_addr: u32,
    pub ramdisk_addr: u32,
    pub ramdisk_size: u32,
    pub cmdline: [u8; VENDOR_BOOT_ARGS_SIZE],
    pub tags_addr: u32,
    pub name: [u8; BOOT_NAME_SIZE],
    pub header_size: u32,
    pub dtb_size: u32,
    pub dtb_addr: u64,
}

/// AOSP vendor_boot header, version 4 — adds vendor ramdisk table +
/// bootconfig.
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdrVndV4 {
    pub vnd_v3: BootImgHdrVndV3,
    pub vendor_ramdisk_table_size: u32,
    pub vendor_ramdisk_table_entry_num: u32,
    pub vendor_ramdisk_table_entry_size: u32,
    pub bootconfig_size: u32,
}

/// Vendor ramdisk table entry (vendor_boot v4).
#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct VendorRamdiskTableEntryV4 {
    pub ramdisk_size: u32,
    pub ramdisk_offset: u32,
    pub ramdisk_type: u32,
    pub ramdisk_name: [u8; VENDOR_RAMDISK_NAME_SIZE],
    pub board_id: [u32; VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE],
}

// ---------------------------------------------------------------------------
// Flag bits — matches the upstream `BOOT_FLAGS_MAX` enum layout so
// the exit-code bitmask the CLI returns stays binary-compatible with
// the C++ build.
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootFlag {
    MtkKernel = 0,
    MtkRamdisk = 1,
    ChromeOs = 2,
    Dhtb = 3,
    SeAndroid = 4,
    LgBump = 5,
    Sha256 = 6,
    Blob = 7,
    NookHd = 8,
    Acclaim = 9,
    Amonet = 10,
    Avb1Signed = 11,
    Avb = 12,
    ZImageKernel = 13,
}

/// Total number of boot flags — mirrors C++ `BOOT_FLAGS_MAX`.
pub const BOOT_FLAGS_MAX: usize = 14;

// ---------------------------------------------------------------------------
// Tests — hand-crafted byte blobs to pin down layout (size + field
// offsets) against the C++ `sizeof` values. If any of these shift,
// the parser is silently reading the wrong bytes and parity with
// upstream breaks.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    // ------- Special headers -------

    #[test]
    fn sizes_special_headers() {
        assert_eq!(size_of::<MtkHdr>(), 512);
        assert_eq!(size_of::<DhtbHdr>(), 512);
        // BlobHdr: 20 + 4 + 4 + 16 + 4 + 4 + 4 + 4 + 7*4 + 4 + 4 + 4 + 4
        //        = 20 + 4 + 4 + 16 + 4 + 4 + 4 + 4 + 28 + 4 + 4 + 4 + 4 = 104
        assert_eq!(size_of::<BlobHdr>(), 104);
        // ZImageHdr: code[9] (36) + magic(4) + start(4) + end(4) + endian(4) = 52
        assert_eq!(size_of::<ZImageHdr>(), 52);
    }

    // ------- AVB headers -------

    #[test]
    fn sizes_avb_headers() {
        // AvbFooter: 4 + 4 + 4 + 8 + 8 + 8 + 28 = 64
        assert_eq!(size_of::<AvbFooter>(), 64);
        // AvbVBMetaImageHeader: 4 + 4+4 + 8+8 + 4 + 8*10 + 4+4 + 48 + 80 = 256
        assert_eq!(size_of::<AvbVBMetaImageHeader>(), 256);
    }

    // ------- AOSP boot headers v0..v4 -------

    #[test]
    fn size_boot_hdr_v0() {
        // kernel_size/addr, ramdisk_size/addr, second_size/addr: 6 * 4 = 24
        // tags_addr, page_size, header_version, os_version: 4 * 4 = 16
        // magic(8) + 24 + 16 + name(16) + cmdline(512) + id(32) +
        // extra_cmdline(1024) = 1632
        assert_eq!(size_of::<BootImgHdrV0>(), 1632);
    }

    #[test]
    fn size_boot_hdr_v1() {
        // v0(1632) + recovery_dtbo_size(4) + recovery_dtbo_offset(8) +
        // header_size(4) = 1648
        assert_eq!(size_of::<BootImgHdrV1>(), 1648);
    }

    #[test]
    fn size_boot_hdr_v2() {
        // v1(1648) + dtb_size(4) + dtb_addr(8) = 1660
        assert_eq!(size_of::<BootImgHdrV2>(), 1660);
    }

    #[test]
    fn size_boot_hdr_pxa() {
        // magic(8) + 6*4 + 4*4 + name(24) + cmdline(512) + id(32) +
        // extra_cmdline(1024) = 8 + 24 + 16 + 24 + 512 + 32 + 1024 = 1640
        assert_eq!(size_of::<BootImgHdrPxa>(), 1640);
    }

    #[test]
    fn size_boot_hdr_v3() {
        // magic(8) + kernel_size(4) + ramdisk_size(4) + os_version(4) +
        // header_size(4) + reserved[4](16) + header_version(4) +
        // cmdline(512+1024=1536) = 8 + 4+4+4+4 + 16 + 4 + 1536 = 1580
        assert_eq!(size_of::<BootImgHdrV3>(), 1580);
    }

    #[test]
    fn size_boot_hdr_v4() {
        // v3(1580) + signature_size(4) = 1584
        assert_eq!(size_of::<BootImgHdrV4>(), 1584);
    }

    // ------- Vendor boot headers -------

    #[test]
    fn size_boot_hdr_vnd_v3() {
        // magic(8) + header_version(4) + page_size(4) +
        // kernel_addr(4) + ramdisk_addr(4) + ramdisk_size(4) +
        // cmdline(2048) + tags_addr(4) + name(16) + header_size(4) +
        // dtb_size(4) + dtb_addr(8)
        //  = 8 + 20 + 2048 + 4 + 16 + 4 + 4 + 8 = 2112
        assert_eq!(size_of::<BootImgHdrVndV3>(), 2112);
    }

    #[test]
    fn size_boot_hdr_vnd_v4() {
        // vnd_v3(2112) + 4 * 4 = 2128
        assert_eq!(size_of::<BootImgHdrVndV4>(), 2128);
    }

    #[test]
    fn size_vendor_ramdisk_table_entry_v4() {
        // ramdisk_size(4) + ramdisk_offset(4) + ramdisk_type(4) +
        // ramdisk_name(32) + board_id(16*4) = 4+4+4+32+64 = 108
        assert_eq!(size_of::<VendorRamdiskTableEntryV4>(), 108);
    }

    // ------- Magic constants + align helpers -------

    #[test]
    fn magic_lengths_match_expectations() {
        assert_eq!(BOOT_MAGIC.len(), BOOT_MAGIC_SIZE);
        assert_eq!(VENDOR_BOOT_MAGIC.len(), BOOT_MAGIC_SIZE);
        assert_eq!(CHROMEOS_MAGIC.len(), 8);
        assert_eq!(AVB_FOOTER_MAGIC.len(), AVB_FOOTER_MAGIC_LEN);
        assert_eq!(AVB_MAGIC.len(), AVB_MAGIC_LEN);
        assert_eq!(BLOB_MAGIC.len(), 20);
    }

    #[test]
    fn align_to_rounds_up() {
        assert_eq!(align_to(0, 4096), 0);
        assert_eq!(align_to(1, 4096), 4096);
        assert_eq!(align_to(4095, 4096), 4096);
        assert_eq!(align_to(4096, 4096), 4096);
        assert_eq!(align_to(4097, 4096), 8192);
        assert_eq!(align_to(12345, 512), 12_800);
    }

    #[test]
    fn align_padding_is_delta_to_next_multiple() {
        assert_eq!(align_padding(0, 4096), 0);
        assert_eq!(align_padding(1, 4096), 4095);
        assert_eq!(align_padding(4096, 4096), 0);
        assert_eq!(align_padding(4097, 4096), 4095);
    }

    // ------- Zero-copy reinterpret sanity -------

    #[test]
    fn pod_from_bytes_reads_magic_fields() {
        // Build a minimal v3 header by hand and confirm the magic
        // and a couple of scalar fields round-trip through
        // `bytemuck::from_bytes`.
        let mut buf = vec![0u8; size_of::<BootImgHdrV3>()];
        buf[..8].copy_from_slice(BOOT_MAGIC);
        buf[8..12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        buf[12..16].copy_from_slice(&0x9abc_def0u32.to_le_bytes());
        let hdr: &BootImgHdrV3 = bytemuck::from_bytes(&buf);
        assert_eq!(&hdr.magic, BOOT_MAGIC);
        // Packed fields need a local copy to avoid an unaligned
        // reference; that's idiomatic for `#[repr(packed)]`.
        let ksize = hdr.kernel_size;
        let rsize = hdr.ramdisk_size;
        assert_eq!(ksize, 0x1234_5678);
        assert_eq!(rsize, 0x9abc_def0);
    }

    #[test]
    fn boot_flags_max_matches_variant_count() {
        assert_eq!(BOOT_FLAGS_MAX, BootFlag::ZImageKernel as usize + 1);
    }
}
