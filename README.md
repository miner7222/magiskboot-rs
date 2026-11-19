# magiskboot-rs

A pure-Rust implementation of Magisk's `magiskboot`. It unpacks, repacks and signs
Android boot images, handles compression and CPIO in-process, and requires no C++
toolchain — `cargo build` is the whole build.

Upstream Magisk already had compression, CPIO, DTB patching, OTA payload extraction,
AVB signing and CLI dispatch in Rust; the boot image parser was the last block still in
C++. This crate ports that block, so the workspace builds without MSYS2, CMake or
external DLLs and can be embedded as a library without aborting its host process.

## Build

```sh
cargo build --release
```

Rust stable only. The binary is written to `target/release/magiskboot`
(`magiskboot.exe` on Windows).

## CLI

```text
magiskboot unpack [-n] [-h] <bootimg>
magiskboot repack [-n] <origbootimg> [outbootimg]
magiskboot verify <bootimg> [x509.pem]
magiskboot sign-avb1 <bootimg> [name] [x509.pem pk8]
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

Compression formats: `gzip`, `xz`, `lzma`, `bzip2`, `lz4`, `lz4_legacy`, `lz4_lg`.

`unpack` exits with 0 (boot image), 1 (error), 2 (ChromeOS) or 3 (vendor_boot);
`repack` exits with 1 on failure.

Environment switches: `KEEPVERITY`, `KEEPFORCEENCRYPT` (cpio patch), `PATCHVBMETAFLAG`
(repack sets the vbmeta disable flags), `XZBCJ` (see below). Each takes `true`.

## Library usage

```rust
use magiskboot::ffi::{self, BootImage};

// Carve a boot image into kernel / ramdisk.cpio / dtb in the current directory.
ffi::unpack("boot.img", false, false);

// Rebuild it, preserving the tail, id field and any outer wrapper.
ffi::repack("boot.img", "new-boot.img", false);

// Inspect without writing anything.
let img = BootImage::new("boot.img");
let payload = img.payload();
let signed = img.is_signed();
```

Entry points return values instead of terminating the process, so a host application
stays in control of its own error handling.

## Image coverage

- AOSP boot image header v0–v4, and the Samsung PXA variant
- `vendor_boot` header v3 and v4, including the multi-ramdisk table and bootconfig
- Whole-image wrappers: AOSP, ChromeOS, DHTB (size and SHA-256 recomputed on repack),
  Tegra Blob (size recomputed on repack)
- Tail trailers re-emitted on repack: Samsung `SEANDROIDENFORCE` with its `SignerVer02`
  block, and the LG bump magic
- Pre-header wrappers preserved byte-for-byte: NookHD, Acclaim, Amonet
- Section wrappers: MTK kernel/ramdisk headers with the size field patched on repack,
  and ARM32 zImage — parsed, so a resized piggy is relocated rather than rejected
- The v0/v1/v2/PXA `id` field recomputed with whichever hash the source used, detected
  from its trailer
- AVB1 `sign-avb1` / `verify` (RSA, ECDSA P-256/P-384/P-521 with DER signatures),
  writing a DER BootSignature tail with the bundled verity keypair or a supplied
  `x509.pem` + `pk8`; repack re-signs an image whose source tail verified
- AVB2 footers and vbmeta tails preserved through unpack/repack; vbmeta is copied
  verbatim and only the footer's `original_image_size` / `vbmeta_offset` change

Not implemented: the Z4 (lokiloader) wrapper.

## Layout

```text
crates/
  base/    Utf8CStr, logging, I/O traits, argh — stripped from Magisk's base crate
  boot/    the magiskboot binary: CLI, compression, CPIO, DTB, signing, bootimg
  derive/  proc macros for argh's #[derive(FromArgs)]
```

`crates/boot/cpp.archive/` keeps the retired Magisk C++ sources for historical
reference. Nothing in the build graph reads from it.

## Differences from upstream Magisk

- A standalone binary rather than part of the Magisk app.
- Cross-platform: Windows MSVC and Linux, no Android NDK.
- `memmap2` replaces `libc::mmap` for portable memory mapping.
- The boot image pipeline is Rust; upstream keeps it in C++.
- The `extern "C"` shims upstream used to drive the Rust codecs from C++ are kept in
  history for reference but are not compiled.
- XZ BCJ pre-filters (upstream v31.1) are opt-in through `XZBCJ=true`. Upstream ships
  magiskboot together with a magiskinit that decodes BCJ; magiskinit v31.0 and older
  cannot, and this binary is paired with arbitrary Magisk releases.
- ChromeOS images are not re-signed on repack (upstream v31.1 added `sign-chromeos`);
  `unpack` keeps returning 2 so the caller can sign them externally.

## Testing

```sh
cargo test
```

The default suite is hermetic. Additional tests that need real vendor images or a
reference binary are `#[test]`-gated behind environment variables; see the gated
functions under `crates/boot/src/bootimg/`.

The ARM32 zImage path is covered by unit tests against synthetic images only — no real
ARM32 boot image has been run through it end to end.

## License

Licensed under the GNU General Public License, version 3 or later
(`GPL-3.0-or-later`).
