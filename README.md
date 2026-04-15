# magiskboot-rs

Standalone magiskboot binary built from Magisk source. Rust + C++ via `cargo build` — no MSYS2, no CMake, no external DLLs.

## Based On

[Magisk](https://github.com/topjohnwu/Magisk/tree/v30.7) (`native/src/boot/` + `native/src/base/`)

Magisk rewrote most of magiskboot in Rust. Only boot image parsing/repacking remains in C++. This project extracts the full magiskboot into a standalone Cargo workspace that compiles on Windows (MSVC) and Linux without Android NDK.

## Supported Commands

```
magiskboot unpack [-n] [-h] <bootimg>
magiskboot repack [-n] <origbootimg> [outbootimg]
magiskboot verify <bootimg> [x509.pem]
magiskboot sign <bootimg> [name] [x509.pem pk8]
magiskboot extract <payload.bin> [partition] [outfile]
magiskboot hexpatch <file> <hexpattern1> <hexpattern2>
magiskboot cpio <incpio> [commands...]
magiskboot dtb <file> <action> [args...]
magiskboot split [-n] <file>
magiskboot sha1 <file>
magiskboot cleanup
magiskboot compress[=format] <infile> [outfile]
magiskboot decompress <infile> [outfile]
```

Supported compression formats: `gzip`, `zopfli`, `xz`, `lzma`, `bzip2`, `lz4`, `lz4_legacy`, `lz4_lg`

## Architecture

```
crates/
  base/       Stripped Magisk base crate (Utf8CStr, logging, I/O traits, argh)
  boot/       magiskboot binary — CLI, compression, CPIO, DTB, signing, C++ bridge
  derive/     Proc-macro crate for argh #[derive(FromArgs)]
```

**Rust layer** — compression, CPIO, DTB patching, OTA payload extraction, AVB signing, CLI dispatch

**C++ layer** — boot image header parsing, unpack/repack orchestration (`bootimg.cpp`)

**Bridge** — `extern "C"` functions export Rust compress/decompress/SHA/sign to C++. No CXX crate dependency.

## Build

```
cargo build --release
```

Requires Rust stable toolchain and a C++ compiler (MSVC on Windows, gcc/clang on Linux). No other dependencies.

Output: `target/release/magiskboot.exe` (Windows) or `target/release/magiskboot` (Linux)

## Differences from Magisk upstream

- Standalone binary — not part of the Magisk app
- Cross-platform — Windows MSVC + Linux (no Android NDK)
- `memmap2` replaces `libc::mmap` for portable memory mapping
- `extern "C"` bridge replaces CXX for Rust↔C++ interop
