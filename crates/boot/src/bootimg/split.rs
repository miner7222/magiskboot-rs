//! `split_image_dtb` — pure-Rust port of the C++
//! `cpp/bootimg.cpp::split_image_dtb` + `find_dtb_offset` helpers.
//!
//! Some vendors concatenate an appended device-tree blob onto the
//! end of the kernel image. `split` walks the kernel buffer looking
//! for a valid FDT header, writes everything before the hit as
//! `kernel`, and everything from the hit onward as `kernel_dtb`.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use crate::ffi::{check_fmt, FileFormat};

/// Scan `buf` for a valid FDT header. Returns the byte offset of
/// the first candidate whose `totalsize` / `off_dt_struct` fields
/// pass sanity checks and whose first node tag is `FDT_BEGIN_NODE`.
/// Returns `None` if no candidate is found — the upstream C++
/// signals this with `-1`.
pub fn find_dtb_offset(buf: &[u8]) -> Option<usize> {
    const DTB_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];
    const FDT_HEADER_SIZE: usize = 40; // matches sizeof(fdt_header)
    const MIN_FDT_TOTALSIZE: u32 = 0x48;
    const FDT_BEGIN_NODE: u32 = 0x0000_0001;

    let mut start = 0usize;
    while start + FDT_HEADER_SIZE <= buf.len() {
        // memmem for the 4-byte magic.
        let Some(rel) = buf[start..]
            .windows(4)
            .position(|w| w == DTB_MAGIC)
        else {
            return None;
        };
        let pos = start + rel;
        if pos + FDT_HEADER_SIZE > buf.len() {
            return None;
        }
        let h = &buf[pos..pos + FDT_HEADER_SIZE];

        let totalsize = u32::from_be_bytes(h[4..8].try_into().unwrap());
        let off_dt_struct = u32::from_be_bytes(h[8..12].try_into().unwrap());
        let remaining = (buf.len() - pos) as u64;

        let ok_totalsize =
            totalsize as u64 <= remaining && totalsize >= MIN_FDT_TOTALSIZE;
        let ok_off_struct = (off_dt_struct as u64) <= remaining;
        if ok_totalsize && ok_off_struct {
            let node_off = pos + off_dt_struct as usize;
            if node_off + 4 <= buf.len() {
                let tag = u32::from_be_bytes(buf[node_off..node_off + 4].try_into().unwrap());
                if tag == FDT_BEGIN_NODE {
                    return Some(pos);
                }
            }
        }
        start = pos + FDT_HEADER_SIZE;
    }
    None
}

/// Port of the C++ CLI `magiskboot split`. Reads `image_path`,
/// locates the appended DTB, writes `<out_dir>/kernel` and
/// `<out_dir>/kernel_dtb`. When the head section is compressed and
/// `skip_decomp == false`, the kernel portion is decompressed before
/// being written — matching C++ behaviour.
///
/// Returns `Ok(0)` on success, `Ok(1)` when no DTB was found (same
/// exit-code contract as upstream).
pub fn split_image_dtb(
    image_path: &Path,
    out_dir: &Path,
    skip_decomp: bool,
) -> io::Result<i32> {
    let buf = std::fs::read(image_path)?;
    let Some(dtb_off) = find_dtb_offset(&buf) else {
        eprintln!("Cannot find DTB in {}", image_path.display());
        return Ok(1);
    };

    std::fs::create_dir_all(out_dir)?;
    let kernel_path = out_dir.join("kernel");
    let dtb_path = out_dir.join("kernel_dtb");

    // Head portion — kernel bytes. Decompress if format warrants.
    let head = &buf[..dtb_off];
    let fmt = check_fmt(head);
    if !skip_decomp && fmt.is_compressed() {
        let mut out = File::create(&kernel_path)?;
        let mut reader = crate::compress::get_decoder(fmt, std::io::Cursor::new(head))?;
        std::io::copy(&mut reader, &mut out)?;
    } else {
        File::create(&kernel_path)?.write_all(head)?;
    }

    // Tail portion — appended DTB bytes.
    let tail = &buf[dtb_off..];
    File::create(&dtb_path)?.write_all(tail)?;

    let _ = FileFormat::UNKNOWN; // silence unused-import warning when cfg switches
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_dtb(totalsize: u32, off_dt_struct: u32, extra_trailer: &[u8]) -> Vec<u8> {
        // Minimal fdt_header + a FDT_BEGIN_NODE tag at `off_dt_struct`.
        let mut out = Vec::new();
        out.extend_from_slice(&[0xd0, 0x0d, 0xfe, 0xed]);
        out.extend_from_slice(&totalsize.to_be_bytes());
        out.extend_from_slice(&off_dt_struct.to_be_bytes());
        // pad to off_dt_struct, write FDT_BEGIN_NODE tag
        while out.len() < off_dt_struct as usize {
            out.push(0);
        }
        out.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        while (out.len() as u32) < totalsize {
            out.push(0);
        }
        out.extend_from_slice(extra_trailer);
        out
    }

    #[test]
    fn find_dtb_offset_locates_hit_after_prefix() {
        let mut buf = b"KERNEL".repeat(50); // 300 bytes of fake kernel
        let prefix_len = buf.len();
        buf.extend_from_slice(&fake_dtb(0x100, 0x40, b""));
        assert_eq!(find_dtb_offset(&buf), Some(prefix_len));
    }

    #[test]
    fn find_dtb_offset_rejects_truncated_fdt() {
        // totalsize claims more bytes than actually present
        let mut buf = b"K".repeat(16);
        buf.extend_from_slice(&fake_dtb(0x1000, 0x40, b""));
        let cut = buf.len() - 0x20;
        buf.truncate(cut);
        // The fake DTB now overflows, find_dtb_offset must say None.
        assert_eq!(find_dtb_offset(&buf), None);
    }

    #[test]
    fn find_dtb_offset_rejects_tiny_totalsize() {
        // totalsize below 0x48
        let buf = fake_dtb(0x20, 0x14, b"");
        assert_eq!(find_dtb_offset(&buf), None);
    }

    #[test]
    fn split_writes_kernel_and_dtb() {
        let tmp = tempfile::tempdir().unwrap();
        let mut buf = b"KERNEL-BYTES".repeat(10);
        let prefix_len = buf.len();
        buf.extend_from_slice(&fake_dtb(0x80, 0x40, b""));
        let img = tmp.path().join("kernel.img");
        std::fs::write(&img, &buf).unwrap();
        let out = tmp.path().join("out");
        let rc = split_image_dtb(&img, &out, true).unwrap();
        assert_eq!(rc, 0);
        let k = std::fs::read(out.join("kernel")).unwrap();
        let d = std::fs::read(out.join("kernel_dtb")).unwrap();
        assert_eq!(k.len(), prefix_len);
        assert_eq!(d.len(), buf.len() - prefix_len);
    }

    #[test]
    fn split_returns_one_when_no_dtb() {
        let tmp = tempfile::tempdir().unwrap();
        let buf = b"no-dtb-here".to_vec();
        let img = tmp.path().join("kernel.img");
        std::fs::write(&img, &buf).unwrap();
        let out = tmp.path().join("out");
        let rc = split_image_dtb(&img, &out, true).unwrap();
        assert_eq!(rc, 1);
    }
}
