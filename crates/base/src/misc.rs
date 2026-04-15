use super::argh::{EarlyExit, MissingRequirements};
use crate::Utf8CString;
use std::fmt::Arguments;
use std::io::Write;
use std::process::exit;
use std::{fmt, slice};

pub trait BytesExt {
    fn find(&self, needle: &[u8]) -> Option<usize>;
    fn contains(&self, needle: &[u8]) -> bool {
        self.find(needle).is_some()
    }
}

impl<T: AsRef<[u8]> + ?Sized> BytesExt for T {
    fn find(&self, needle: &[u8]) -> Option<usize> {
        let haystack = self.as_ref();
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}

pub trait MutBytesExt {
    fn patch(&mut self, from: &[u8], to: &[u8]) -> Vec<usize>;
}

impl<T: AsMut<[u8]> + AsRef<[u8]> + ?Sized> MutBytesExt for T {
    fn patch(&mut self, from: &[u8], to: &[u8]) -> Vec<usize> {
        let buf = self.as_mut();
        let mut offsets = Vec::new();
        if from.is_empty() || from.len() != to.len() || from.len() > buf.len() {
            return offsets;
        }
        let mut pos = 0;
        while pos + from.len() <= buf.len() {
            if &buf[pos..pos + from.len()] == from {
                offsets.push(pos);
                buf[pos..pos + to.len()].copy_from_slice(to);
                pos += from.len();
            } else {
                pos += 1;
            }
        }
        offsets
    }
}

pub trait EarlyExitExt<T> {
    fn on_early_exit<F: FnOnce()>(self, print_help_msg: F) -> T;
}

impl<T> EarlyExitExt<T> for Result<T, EarlyExit> {
    fn on_early_exit<F: FnOnce()>(self, print_help_msg: F) -> T {
        match self {
            Ok(t) => t,
            Err(EarlyExit { output, is_help }) => {
                if is_help {
                    print_help_msg();
                    exit(0)
                } else {
                    eprintln!("{output}");
                    print_help_msg();
                    exit(1)
                }
            }
        }
    }
}

pub struct PositionalArgParser<'a>(pub slice::Iter<'a, &'a str>);

impl PositionalArgParser<'_> {
    pub fn required(&mut self, field_name: &'static str) -> Result<Utf8CString, EarlyExit> {
        if let Some(next) = self.0.next() {
            Ok((*next).into())
        } else {
            let mut missing = MissingRequirements::default();
            missing.missing_positional_arg(field_name);
            missing.err_on_any()?;
            unreachable!()
        }
    }

    pub fn optional(&mut self) -> Option<Utf8CString> {
        self.0.next().map(|s| (*s).into())
    }

    pub fn last_required(&mut self, field_name: &'static str) -> Result<Utf8CString, EarlyExit> {
        let r = self.required(field_name)?;
        self.ensure_end()?;
        Ok(r)
    }

    pub fn last_optional(&mut self) -> Result<Option<Utf8CString>, EarlyExit> {
        let r = self.optional();
        if r.is_none() {
            return Ok(r);
        }
        self.ensure_end()?;
        Ok(r)
    }

    fn ensure_end(&mut self) -> Result<(), EarlyExit> {
        match self.0.next() {
            None => Ok(()),
            Some(s) => Err(EarlyExit::from(format!("Unrecognized argument: {s}\n"))),
        }
    }
}

pub struct FmtAdaptor<'a, T>(pub &'a mut T)
where
    T: Write;

impl<T: Write> fmt::Write for FmtAdaptor<'_, T> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_all(s.as_bytes()).map_err(|_| fmt::Error)
    }
    fn write_fmt(&mut self, args: Arguments<'_>) -> fmt::Result {
        self.0.write_fmt(args).map_err(|_| fmt::Error)
    }
}

pub struct Chunker {
    chunk: Box<[u8]>,
    chunk_size: usize,
    pos: usize,
}

impl Chunker {
    pub fn new(chunk_size: usize) -> Self {
        Chunker {
            chunk: vec![0u8; chunk_size].into_boxed_slice(),
            chunk_size,
            pos: 0,
        }
    }

    pub fn set_chunk_size(&mut self, chunk_size: usize) {
        self.chunk_size = chunk_size;
        self.pos = 0;
        if self.chunk.len() < chunk_size {
            self.chunk = vec![0u8; chunk_size].into_boxed_slice();
        }
    }

    pub fn add_data<'a, 'b: 'a>(&'a mut self, mut buf: &'b [u8]) -> (&'b [u8], Option<&'a [u8]>) {
        let mut chunk = None;
        if self.pos > 0 {
            let len = std::cmp::min(self.chunk_size - self.pos, buf.len());
            self.chunk[self.pos..self.pos + len].copy_from_slice(&buf[..len]);
            self.pos += len;
            if self.pos == self.chunk_size {
                chunk = Some(&self.chunk[..self.chunk_size]);
                self.pos = 0;
            }
            buf = &buf[len..];
        } else if buf.len() >= self.chunk_size {
            chunk = Some(&buf[..self.chunk_size]);
            buf = &buf[self.chunk_size..];
        } else {
            self.chunk[self.pos..self.pos + buf.len()].copy_from_slice(buf);
            self.pos += buf.len();
            return (&[], None);
        }
        (buf, chunk)
    }

    pub fn get_available(&mut self) -> &[u8] {
        let chunk = &self.chunk[..self.pos];
        self.pos = 0;
        chunk
    }
}

/// Command-line arguments wrapper. Adapted for standalone use with std::env::args.
pub struct CmdArgs(pub Vec<&'static str>);

impl CmdArgs {
    /// Create CmdArgs from std::env::args() output.
    /// Leaks the strings to get 'static lifetimes (fine for CLI tools).
    pub fn from_env_args(args: Vec<String>) -> CmdArgs {
        CmdArgs(
            args.into_iter()
                .map(|s| -> &'static str { Box::leak(s.into_boxed_str()) })
                .collect(),
        )
    }

    pub fn as_slice(&self) -> &[&'static str] {
        self.0.as_slice()
    }

    pub fn iter(&self) -> slice::Iter<'_, &'static str> {
        self.0.iter()
    }
}
