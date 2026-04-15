// Standalone adaptation of Magisk base/files.rs
//
// Upstream: native/src/base/files.rs
// Changes: Removed libc/nix/Unix deps. Uses std and memmap2 for cross-platform.
// Wrapper approach: Same API surface, different implementation underneath.

use crate::{Utf8CStr, error};
use bytemuck::{Pod, bytes_of, bytes_of_mut};
use std::cmp::min;
use std::fs::File;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;

// ---------------------------------------------------------------------------
// I/O extension traits — identical API to upstream
// ---------------------------------------------------------------------------

pub trait ReadExt {
    fn skip(&mut self, len: usize) -> io::Result<()>;
    fn read_pod<F: Pod>(&mut self, data: &mut F) -> io::Result<()>;
}

impl<T: Read> ReadExt for T {
    fn skip(&mut self, mut len: usize) -> io::Result<()> {
        let mut buf = MaybeUninit::<[u8; 4096]>::uninit();
        let buf = unsafe { buf.assume_init_mut() };
        while len > 0 {
            let l = min(buf.len(), len);
            self.read_exact(&mut buf[..l])?;
            len -= l;
        }
        Ok(())
    }

    fn read_pod<F: Pod>(&mut self, data: &mut F) -> io::Result<()> {
        self.read_exact(bytes_of_mut(data))
    }
}

pub trait ReadSeekExt {
    fn skip(&mut self, len: usize) -> io::Result<()>;
}

impl<T: Read + Seek> ReadSeekExt for T {
    fn skip(&mut self, len: usize) -> io::Result<()> {
        if self.seek(SeekFrom::Current(len as i64)).is_err() {
            ReadExt::skip(self, len)?;
        }
        Ok(())
    }
}

pub trait BufReadExt {
    fn for_each_line<F: FnMut(&mut String) -> bool>(&mut self, f: F);
    fn for_each_prop<F: FnMut(&str, &str) -> bool>(&mut self, f: F);
}

impl<T: BufRead> BufReadExt for T {
    fn for_each_line<F: FnMut(&mut String) -> bool>(&mut self, mut f: F) {
        let mut buf = String::new();
        loop {
            match self.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if !f(&mut buf) {
                        break;
                    }
                }
                Err(e) => {
                    error!("{}", e);
                    break;
                }
            };
            buf.clear();
        }
    }

    fn for_each_prop<F: FnMut(&str, &str) -> bool>(&mut self, mut f: F) {
        self.for_each_line(|line| {
            line.reserve(1);
            let line = line.trim();
            if line.starts_with('#') {
                return true;
            }
            if let Some((key, value)) = line.split_once('=') {
                return f(key.trim(), value.trim());
            }
            true
        });
    }
}

pub trait WriteExt {
    fn write_zeros(&mut self, len: usize) -> io::Result<()>;
    fn write_pod<F: Pod>(&mut self, data: &F) -> io::Result<()>;
}

impl<T: Write> WriteExt for T {
    fn write_zeros(&mut self, mut len: usize) -> io::Result<()> {
        let buf = [0_u8; 4096];
        while len > 0 {
            let l = min(buf.len(), len);
            self.write_all(&buf[..l])?;
            len -= l;
        }
        Ok(())
    }

    fn write_pod<F: Pod>(&mut self, data: &F) -> io::Result<()> {
        self.write_all(bytes_of(data))
    }
}

// ---------------------------------------------------------------------------
// FileOrStd — standalone version (no raw fd transmute)
// ---------------------------------------------------------------------------

pub enum FileOrStd {
    StdIn,
    StdOut,
    StdErr,
    File(File),
}

impl FileOrStd {
    /// Get a reference suitable for Read/Write operations.
    /// On standalone builds, stdin/stdout/stderr are handled via std locks.
    pub fn as_file(&self) -> &File {
        match self {
            FileOrStd::File(file) => file,
            // Upstream uses raw fd transmute. We panic for stdin/stdout/stderr
            // as_file usage — callers should use read/write methods instead.
            _ => panic!("as_file() not supported for stdio in standalone mode; use read()/write()"),
        }
    }
}

impl Read for &FileOrStd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            FileOrStd::StdIn => io::stdin().lock().read(buf),
            FileOrStd::File(f) => (&*f).read(buf),
            _ => Err(io::Error::new(io::ErrorKind::Other, "Cannot read from stdout/stderr")),
        }
    }
}

impl Write for &FileOrStd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            FileOrStd::StdOut => io::stdout().lock().write(buf),
            FileOrStd::StdErr => io::stderr().lock().write(buf),
            FileOrStd::File(f) => (&*f).write(buf),
            FileOrStd::StdIn => Err(io::Error::new(io::ErrorKind::Other, "Cannot write to stdin")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            FileOrStd::StdOut => io::stdout().lock().flush(),
            FileOrStd::StdErr => io::stderr().lock().flush(),
            FileOrStd::File(f) => (&*f).flush(),
            FileOrStd::StdIn => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// MappedFile — uses memmap2 instead of libc::mmap
// ---------------------------------------------------------------------------

pub struct MappedFile {
    _mmap: memmap2::Mmap,
    ptr: *const u8,
    len: usize,
}

// Provide read-only mapped file access
impl MappedFile {
    pub fn open(path: &Utf8CStr) -> io::Result<MappedFile> {
        let file = File::open(path.as_str())?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        let ptr = mmap.as_ptr();
        let len = mmap.len();
        Ok(MappedFile { _mmap: mmap, ptr, len })
    }
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Mutable mapped file (for hexpatch etc.)
pub struct MappedFileMut {
    mmap: memmap2::MmapMut,
}

impl MappedFileMut {
    pub fn open(path: &Utf8CStr) -> io::Result<MappedFileMut> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_str())?;
        let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
        Ok(MappedFileMut { mmap })
    }
}

impl AsRef<[u8]> for MappedFileMut {
    fn as_ref(&self) -> &[u8] {
        &self.mmap
    }
}

impl AsMut<[u8]> for MappedFileMut {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.mmap
    }
}

// ---------------------------------------------------------------------------
// FsPathBuilder — upstream has this in files.rs, our extracted version has it
// in cstr.rs. Re-export for compatibility.
// ---------------------------------------------------------------------------

// Already in cstr.rs — no need to duplicate

// ---------------------------------------------------------------------------
// Compatibility wrappers for upstream API differences
// ---------------------------------------------------------------------------

// Upstream MappedFile has open_rw() returning OsResult.
// We provide the same API surface but return io::Result.
impl MappedFile {
    /// Open file read-write (mutable mapping).
    /// Wrapper: returns MappedFileMut for mutable access.
    pub fn open_rw(path: &Utf8CStr) -> io::Result<MappedFileMut> {
        MappedFileMut::open(path)
    }
}
