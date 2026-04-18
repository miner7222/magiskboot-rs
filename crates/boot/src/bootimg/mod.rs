//! Pure-Rust replacement for `cpp/bootimg.{cpp,hpp}`.
//!
//! The upstream `magiskboot` built its boot-image parser in C++ and
//! called it from Rust via a CXX bridge. That worked on the CLI
//! binary but aborted the whole process when the same code ran
//! in-process from a Windows Rust host (LTBox v3's GUI) on some
//! Lenovo ramdisks.
//!
//! This module owns the header structs + magic constants. Later
//! modules will own the parse / unpack / repack logic.

pub mod hdr;
pub mod unpack;

pub use hdr::*;
pub use unpack::{unpack, UnpackError, UnpackReport};
