//! Pure-Rust boot-image pipeline — replaces upstream Magisk's
//! `cpp/bootimg.{cpp,hpp}`.
//!
//! The upstream `magiskboot` built its boot-image parser in C++ and
//! called it from Rust via a CXX bridge. That worked on the CLI
//! binary but aborted the whole process when the same code ran
//! in-process from a Windows Rust host (LTBox v3's GUI) on some
//! Lenovo ramdisks.
//!
//! Scope of this module:
//!
//! - `hdr`    — every AOSP + wrapper header struct + magic constant.
//! - `unpack` — outer-wrapper sniff (direct AOSP / ChromeOS / DHTB /
//!              Tegra Blob) + AOSP v3/v4 section carve + decompression.
//! - `repack` — AOSP v3/v4 rebuild, tail preservation, upstream-
//!              matching compression policy (v4 ramdisks force to
//!              `lz4_legacy`).
//! - `split`  — appended-DTB kernel split.
//!
//! Deferred (matches upstream surface area, added as needed):
//! vendor_boot, legacy v0/v1/v2 + Samsung PXA, MTK / Nook / Acclaim /
//! Amonet / Z4 / zImage wrappers, SHA id patching for v0–v2, AVB1
//! signature block, DHTB SHA-256 wrapper recompute.

pub mod hdr;
pub mod repack;
pub mod split;
pub mod unpack;

pub use hdr::*;
pub use repack::{repack, RepackError};
pub use split::{find_dtb_offset, split_image_dtb};
pub use unpack::{unpack, UnpackError, UnpackReport};
