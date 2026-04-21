# magiskboot-rs

Standalone pure-Rust `magiskboot` built from Magisk v30.7 sources.
Single `cargo build` — no MSYS2, no CMake, no C++ toolchain, no
external DLLs.

## Based On

[Magisk](https://github.com/topjohnwu/Magisk/tree/v30.7)
(`native/src/boot/` + `native/src/base/`).

Magisk v30.7 already shipped compression, CPIO, DTB patching, OTA
payload extraction, AVB signing, and CLI dispatch in Rust. The boot
image parser / unpack / repack was the last block still in C++.
This project ports that final block to Rust so the workspace builds
without any C++ toolchain and can be embedded as an in-process
library without aborting its host process.

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

Supported compression formats: `gzip`, `zopfli`, `xz`, `lzma`,
`bzip2`, `lz4`, `lz4_legacy`, `lz4_lg`.

## Boot Image Coverage

The pure-Rust `bootimg` pipeline covers the slice real Magisk /
KernelSU / APatch Root flows actually use:

- AOSP boot image header **v0**, **v1**, **v2**, **v3**, **v4**
- Samsung **PXA** variant (page_size sentinel ≥ `0x02000000`)
- **vendor_boot** header v3 and v4 (multi-ramdisk table + bootconfig)
- Outer whole-image wrappers: direct AOSP, ChromeOS, DHTB
  (size + SHA-256 checksum recomputed on repack), Tegra Blob
- Pre-header wrappers: **NookHD** (0x4000), **Acclaim** (0x1000),
  **Amonet** (microloader, 0x400) — preserved byte-for-byte on
  repack
- Section-level wrappers: **MTK** kernel / ramdisk header (512 B
  preamble, size field patched on repack), **zImage** kernel
  detection flag
- Kernel + ramdisk sections, v4 signature section
- v0 / v1 / v2 / PXA **`id` field** recomputed on repack with
  the same hash algorithm the source used (SHA-1 or SHA-256,
  auto-detected from the source id trailer)
- **AVB1** (Android Verified Boot v1) `magiskboot sign` /
  `magiskboot verify` — DER-encoded BootSignature tail written
  at `tail_off`, signed with the bundled verity keypair (or a
  user-supplied `x509.pem` + `pk8`)
- AVB2 footer + vbmeta tail preserved byte-for-byte through
  unpack / repack

**Deferred** (targeted follow-ups — not blocking the primary use
case): Z4 (lokiloader) wrapper.

## Architecture

```
crates/
  base/       Stripped Magisk base crate (Utf8CStr, logging, I/O traits, argh)
  boot/       magiskboot binary — CLI, compression, CPIO, DTB, signing, bootimg
  derive/     Proc-macro crate for argh #[derive(FromArgs)]
```

Inside `crates/boot/src/`:

- `bootimg/hdr.rs`    — AOSP + wrapper header structs + magic
                        constants, `#[repr(C, packed)]` + `bytemuck`
- `bootimg/unpack.rs` — outer-wrapper sniff + AOSP v3/v4 section
                        carve + decompression
- `bootimg/repack.rs` — AOSP v3/v4 rebuild, tail preservation,
                        compression policy matching upstream (v4
                        ramdisks force to `lz4_legacy`)
- `bootimg/split.rs`  — appended-DTB kernel split
- `ffi.rs`            — entry points consumed by the CLI and by
                        `BootImage` inspection
- `compress.rs`, `cpio.rs`, `dtb.rs`, `payload.rs`, `sign.rs` —
                        inherited from upstream Magisk Rust

`cpp.archive/` holds the retired Magisk C++ sources for historical
reference only. Nothing in the build graph pulls from it.

## Build

```
cargo build --release
```

Rust stable toolchain only. No C++ compiler required. Output:

- Windows: `target/release/magiskboot.exe`
- Linux:   `target/release/magiskboot`

## Regression Testing

### Default unit suite

```
cargo test -p magiskboot
```

Runs 40+ hermetic tests covering header struct layouts, outer
wrapper detection, AOSP v3/v4 unpack/repack, round-trip content
preservation, split-DTB, BootImage payload/tail parsing, and the
format sniffer.

### Live device-image smoke tests

Opt-in smoke tests exercise the unpack and unpack → repack →
unpack round-trip against real vendor images. See the gated
`#[test]` functions under `crates/boot/src/bootimg/` for the env
vars that enable them.

Assertions cover: header version 4, post-round-trip kernel +
`ramdisk.cpio` byte-for-byte parity with the source.

### C++ parity corpus

Two gated tests line the Rust output up against a reference C++
`magiskboot unpack` / `repack` run. They compare every section the
C++ binary produces against the Rust output byte-for-byte. See the
gated `#[test]` functions under `crates/boot/src/bootimg/` for the
env vars that enable them.

### End-to-end Magisk root patch parity

The strongest regression signal is to reproduce the full
`scripts/boot_patch.sh` flow from Magisk v30.7 with both the Rust
binary and a v30.7 C++ reference build, then diff the content of
each resulting `new-boot.img`.

Procedure:

1. Extract the Magisk payload once:

   ```
   mkdir -p /tmp/magisk_payload && cd /tmp/magisk_payload
   unzip -oj /path/to/Magisk-v30.7.apk \
       lib/arm64-v8a/libmagisk.so \
       lib/arm64-v8a/libmagiskinit.so \
       lib/arm64-v8a/libinit-ld.so \
       assets/stub.apk
   mv libmagisk.so magisk
   mv libmagiskinit.so magiskinit
   mv libinit-ld.so init-ld
   ```

2. Keep a C++ reference `magiskboot.exe` on hand (for example a
   v30.7 `MagiskbootAlone` build).

3. For each binary under test (Rust + C++), copy the Magisk
   payload and the target `init_boot.img` into a scratch dir, then
   run the boot_patch.sh sequence:

   ```
   magiskboot unpack init_boot.img
   magiskboot cpio ramdisk.cpio test
   cp ramdisk.cpio ramdisk.cpio.orig
   magiskboot compress=xz magisk  magisk.xz
   magiskboot compress=xz stub.apk stub.xz
   magiskboot compress=xz init-ld init-ld.xz
   cat > config <<EOF
   KEEPVERITY=false
   KEEPFORCEENCRYPT=false
   RECOVERYMODE=false
   VENDORBOOT=false
   SHA1=<sha1-of-source-init_boot.img>
   EOF
   magiskboot cpio ramdisk.cpio \
       "add 0750 init magiskinit" \
       "mkdir 0750 overlay.d" \
       "mkdir 0750 overlay.d/sbin" \
       "add 0644 overlay.d/sbin/magisk.xz magisk.xz" \
       "add 0644 overlay.d/sbin/stub.xz   stub.xz" \
       "add 0644 overlay.d/sbin/init-ld.xz init-ld.xz" \
       patch \
       "backup ramdisk.cpio.orig" \
       "mkdir 000 .backup" \
       "add 000 .backup/.magisk config"
   magiskboot repack init_boot.img
   ```

4. Compare the two `new-boot.img` outputs at the content level
   (byte equality of the file is not expected — xz compression is
   non-deterministic across codecs and cpio entry padding drifts
   between implementations):

   - Sizes must match.
   - Re-unpack each `new-boot.img`, then `cpio extract` the
     resulting `ramdisk.cpio` into a tree.
   - The entry set (recursive `cpio ls`) must match.
   - Every non-`.xz` file must be byte-for-byte identical.
   - Every `.xz` file must decompress to identical bytes — the xz
     wrappers differ, the payloads (the actual `magisk`, `stub.apk`,
     `init-ld` binaries Magisk injects) do not.

Real vendor firmware has been verified end-to-end with this
procedure — every injected payload matches the v30.7 C++ reference
after decompression.

## Differences from Magisk upstream

- Standalone binary, not part of the Magisk app.
- Cross-platform: Windows MSVC + Linux, no Android NDK.
- `memmap2` replaces `libc::mmap` for portable memory mapping.
- Boot image pipeline ported to Rust — upstream keeps it in C++.
- `extern "C"` helper shims that upstream used to drive the Rust
  codecs from C++ are retained under `extern_c` history for
  reference but no longer compiled into the binary.
