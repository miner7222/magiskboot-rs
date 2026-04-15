// Compatibility layer for upstream code that uses libc/nix types.
// Provides type aliases and constants so upstream code compiles with
// minimal modifications.

/// libc-compatible mode type constants for CPIO entries.
/// Upstream uses base::libc::{S_IFDIR, S_IFLNK, S_IFREG, S_IFMT, mode_t}
#[allow(non_camel_case_types, dead_code)]
pub mod libc_compat {
    pub type mode_t = u32;
    pub type dev_t = u64;
    pub type uid_t = u32;
    pub type gid_t = u32;

    pub const S_IFMT: mode_t = 0o170000;
    pub const S_IFDIR: mode_t = 0o040000;
    pub const S_IFREG: mode_t = 0o100000;
    pub const S_IFLNK: mode_t = 0o120000;
    pub const S_IFCHR: mode_t = 0o020000;
    pub const S_IFBLK: mode_t = 0o060000;
    pub const S_IFIFO: mode_t = 0o010000;
    pub const S_IFSOCK: mode_t = 0o140000;

    // Permission bits
    pub const S_IRUSR: mode_t = 0o400;
    pub const S_IWUSR: mode_t = 0o200;
    pub const S_IXUSR: mode_t = 0o100;
    pub const S_IRGRP: mode_t = 0o040;
    pub const S_IWGRP: mode_t = 0o020;
    pub const S_IXGRP: mode_t = 0o010;
    pub const S_IROTH: mode_t = 0o004;
    pub const S_IWOTH: mode_t = 0o002;
    pub const S_IXOTH: mode_t = 0o001;

    #[inline]
    pub fn major(dev: dev_t) -> u32 {
        ((dev >> 8) & 0xfff) as u32
    }

    #[inline]
    pub fn minor(dev: dev_t) -> u32 {
        (dev & 0xff) as u32
    }

    #[inline]
    pub fn makedev(maj: u32, min: u32) -> dev_t {
        ((maj as dev_t) << 8) | (min as dev_t)
    }

    /// No-op stub for mknod on Windows -- device nodes are not supported.
    ///
    /// # Safety
    /// This is a no-op; the pointer is unused.
    pub unsafe fn mknod(_path: *const i8, _mode: mode_t, _dev: dev_t) -> i32 {
        -1
    }
}
