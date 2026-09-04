use base::argh::FromArgs;
use base::{LoggedResult, MappedFile, MappedFileMut, Utf8CStr};
use fdt::node::{FdtNode, NodeProperty};
use fdt::{Fdt, FdtError};
use std::cell::UnsafeCell;

use crate::check_env;
use crate::patch::patch_verity;

enum MappedFileHolder {
    ReadOnly(MappedFile),
    ReadWrite(MappedFileMut),
}

impl AsRef<[u8]> for MappedFileHolder {
    fn as_ref(&self) -> &[u8] {
        match self {
            MappedFileHolder::ReadOnly(f) => f.as_ref(),
            MappedFileHolder::ReadWrite(f) => f.as_ref(),
        }
    }
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub(crate) enum DtbAction {
    Print(Print),
    Patch(Patch),
    Test(Test),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "print")]
pub(crate) struct Print {
    #[argh(switch, short = 'f', long = none)]
    fstab: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "patch")]
pub(crate) struct Patch {}

#[derive(FromArgs)]
#[argh(subcommand, name = "test")]
pub(crate) struct Test {}

pub(crate) fn print_dtb_usage() {
    eprintln!(
        r#"Usage: magiskboot dtb <file> <action> [args...]
Do dtb related actions to <file>.

Supported actions:
  print [-f]
    Print all contents of dtb for debugging
    Specify [-f] to only print fstab nodes
  patch
    Search for fstab and remove verity/avb
    Modifications are done directly to the file in-place
    Configure with env variables: KEEPVERITY
  test
    Test the fstab's status
    Return values:
    0:valid    1:error"#
    );
}

const MAX_PRINT_LEN: usize = 32;
const DTB_MAGIC: &[u8] = b"\xd0\x0d\xfe\xed";
const FDT_HEADER_SIZE: usize = 40;

// Size of the flattened device tree produced by Linux's empty_root.dts.
// A candidate this small contains no useful device-tree data.
const MIN_NON_EMPTY_DTB_SIZE: usize = 0x84;

fn read_be_u32(buf: &[u8], offset: usize) -> Option<usize> {
    let bytes = buf.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes) as usize)
}

fn range_within(total: usize, offset: usize, size: usize) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| offset <= total && end <= total)
}

fn is_valid_dtb_candidate(buf: &[u8]) -> bool {
    let Some(total_size) = read_be_u32(buf, 4) else {
        return false;
    };
    if total_size <= MIN_NON_EMPTY_DTB_SIZE || total_size > buf.len() {
        return false;
    }

    let Some(struct_offset) = read_be_u32(buf, 8) else {
        return false;
    };
    let Some(strings_offset) = read_be_u32(buf, 12) else {
        return false;
    };
    let Some(reserve_offset) = read_be_u32(buf, 16) else {
        return false;
    };
    let Some(strings_size) = read_be_u32(buf, 32) else {
        return false;
    };
    let Some(struct_size) = read_be_u32(buf, 36) else {
        return false;
    };

    if !range_within(total_size, struct_offset, struct_size)
        || !range_within(total_size, strings_offset, strings_size)
        || !range_within(total_size, reserve_offset, 16)
        || struct_size < 8
    {
        return false;
    }

    // fdt 0.1.5 already supports unaligned byte slices, but its node parser
    // is infallible. Validate every range it indexes before asking it to
    // resolve the root node, which gives the v31 fallible-parse semantics
    // without a dependency upgrade.
    let Ok(fdt) = Fdt::new(&buf[..total_size]) else {
        return false;
    };
    fdt.find_node("/").is_some()
}

/// Return the first non-empty, parseable flattened-device-tree offset.
/// Malformed magic lookalikes are skipped so a later valid DTB can win.
pub fn find_dtb_offset(buf: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos + FDT_HEADER_SIZE <= buf.len() {
        let rel_pos = buf[pos..].windows(4).position(|w| w == DTB_MAGIC)?;
        let curr = pos + rel_pos;
        if is_valid_dtb_candidate(&buf[curr..]) {
            return Some(curr);
        }
        pos = curr + 4;
    }
    None
}

fn print_node(node: &FdtNode) {
    fn pretty_node(depth_set: &[bool]) {
        let mut depth_set = depth_set.iter().peekable();
        while let Some(depth) = depth_set.next() {
            let last = depth_set.peek().is_none();
            if *depth {
                if last {
                    print!("├── ");
                } else {
                    print!("│   ");
                }
            } else if last {
                print!("└── ");
            } else {
                print!("    ");
            }
        }
    }

    fn pretty_prop(depth_set: &[bool]) {
        let mut depth_set = depth_set.iter().peekable();
        while let Some(depth) = depth_set.next() {
            let last = depth_set.peek().is_none();
            if *depth {
                if last {
                    print!("│  ");
                } else {
                    print!("│   ");
                }
            } else if last {
                print!("└─ ");
            } else {
                print!("    ");
            }
        }
    }

    fn do_print_node(node: &FdtNode, depth_set: &mut Vec<bool>) {
        pretty_node(depth_set);
        let depth = depth_set.len();
        depth_set.push(true);
        println!("{}", node.name);
        let mut properties = node.properties().peekable();
        let mut children = node.children().peekable();
        while let Some(NodeProperty { name, value }) = properties.next() {
            let size = value.len();
            let is_str = !(size > 1 && value[0] == 0)
                && matches!(value.last(), Some(0u8) | None)
                && value.iter().all(|c| *c == 0 || (*c >= 32 && *c < 127));

            if depth_set[depth] && properties.peek().is_none() && children.peek().is_none() {
                depth_set[depth] = false;
            }

            pretty_prop(depth_set);
            if is_str {
                println!(
                    "[{}]: [\"{}\"]",
                    name,
                    if value.is_empty() {
                        ""
                    } else {
                        unsafe { Utf8CStr::from_bytes_unchecked(value) }
                    }
                );
            } else if size > MAX_PRINT_LEN {
                println!("[{name}]: <bytes>({size})");
            } else {
                println!("[{name}]: {value:02x?}");
            }
        }

        while let Some(child) = children.next() {
            if depth_set[depth] && children.peek().is_none() {
                depth_set[depth] = false;
            }
            do_print_node(&child, depth_set);
        }
        depth_set.pop();
    }

    do_print_node(node, &mut vec![]);
}

fn for_each_fdt<F: FnMut(usize, Fdt) -> LoggedResult<()>>(
    file: &Utf8CStr,
    rw: bool,
    mut f: F,
) -> LoggedResult<()> {
    eprintln!("Loading dtbs from [{file}]");
    let file = if rw {
        MappedFileHolder::ReadWrite(MappedFile::open_rw(file)?)
    } else {
        MappedFileHolder::ReadOnly(MappedFile::open(file)?)
    };
    let mut buf = Some(file.as_ref());
    let mut dtb_num = 0usize;
    while let Some(slice) = buf {
        let slice = if let Some(pos) = find_dtb_offset(slice) {
            &slice[pos..]
        } else {
            break;
        };
        if slice.len() < 40 {
            break;
        }
        let fdt = match Fdt::new(slice) {
            Err(FdtError::BufferTooSmall) => {
                eprintln!("dtb.{dtb_num:04} is truncated");
                break;
            }
            Ok(fdt) => fdt,
            e => e?,
        };

        let size = fdt.total_size();

        f(dtb_num, fdt)?;

        dtb_num += 1;
        buf = Some(&slice[size..]);
    }
    Ok(())
}

fn find_fstab<'b, 'a: 'b>(fdt: &'b Fdt<'a>) -> Option<FdtNode<'b, 'a>> {
    fdt.all_nodes().find(|node| node.name == "fstab")
}

fn dtb_print(file: &Utf8CStr, fstab: bool) -> LoggedResult<()> {
    for_each_fdt(file, false, |n, fdt| {
        if fstab {
            if let Some(fstab) = find_fstab(&fdt) {
                eprintln!("Found fstab in dtb.{n:04}");
                print_node(&fstab);
            }
        } else if let Some(mut root) = fdt.find_node("/") {
            eprintln!("Printing dtb.{n:04}");
            if root.name.is_empty() {
                root.name = "/";
            }
            print_node(&root);
        }
        Ok(())
    })
}

fn dtb_test(file: &Utf8CStr) -> LoggedResult<bool> {
    let mut ret = true;
    for_each_fdt(file, false, |_, fdt| {
        if let Some(fstab) = find_fstab(&fdt) {
            for child in fstab.children() {
                if child.name != "system" {
                    continue;
                }
                if let Some(mount_point) = child.property("mnt_point")
                    && mount_point.value == b"/system_root\0"
                {
                    ret = false;
                    break;
                }
            }
        }
        Ok(())
    })?;
    Ok(ret)
}

fn dtb_patch(file: &Utf8CStr) -> LoggedResult<bool> {
    let keep_verity = check_env("KEEPVERITY");
    let mut patched = false;
    for_each_fdt(file, true, |n, fdt| {
        for node in fdt.all_nodes() {
            if node.name != "chosen" {
                continue;
            }
            if let Some(boot_args) = node.property("bootargs") {
                let boot_args = unsafe {
                    &mut *std::mem::transmute::<&[u8], &UnsafeCell<[u8]>>(boot_args.value).get()
                };
                for _ in 0..patch_skip_initramfs(boot_args) {
                    eprintln!("Patch [skip_initramfs] -> [want_initramfs] in dtb.{n:04}");
                    patched = true;
                }
            }
        }
        if keep_verity {
            return Ok(());
        }
        if let Some(fstab) = find_fstab(&fdt) {
            for child in fstab.children() {
                if let Some(flags) = child.property("fsmgr_flags") {
                    let flags = unsafe {
                        &mut *std::mem::transmute::<&[u8], &UnsafeCell<[u8]>>(flags.value).get()
                    };
                    if patch_verity(flags) != flags.len() {
                        patched = true;
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(patched)
}

fn patch_skip_initramfs(buf: &mut [u8]) -> usize {
    const FROM: &[u8] = b"skip_initramfs";
    let mut count = 0;
    let mut offset = 0;
    while offset + FROM.len() <= buf.len() {
        if &buf[offset..offset + FROM.len()] == FROM {
            buf[offset..offset + 4].copy_from_slice(b"want");
            count += 1;
            offset += FROM.len();
        } else {
            offset += 1;
        }
    }
    count
}

pub(crate) fn dtb_commands(file: &Utf8CStr, action: &DtbAction) -> LoggedResult<bool> {
    match action {
        DtbAction::Print(Print { fstab }) => {
            dtb_print(file, *fstab)?;
            Ok(true)
        }
        DtbAction::Test(_) => Ok(dtb_test(file)?),
        DtbAction::Patch(_) => Ok(dtb_patch(file)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_dtb(total_size: usize) -> Vec<u8> {
        const STRUCT_OFFSET: usize = 0x38;
        const STRUCT_SIZE: usize = 16;
        const STRINGS_OFFSET: usize = STRUCT_OFFSET + STRUCT_SIZE;

        let mut out = vec![0u8; total_size];
        out[0..4].copy_from_slice(DTB_MAGIC);
        out[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
        out[8..12].copy_from_slice(&(STRUCT_OFFSET as u32).to_be_bytes());
        out[12..16].copy_from_slice(&(STRINGS_OFFSET as u32).to_be_bytes());
        out[16..20].copy_from_slice(&0x28u32.to_be_bytes());
        out[20..24].copy_from_slice(&17u32.to_be_bytes());
        out[24..28].copy_from_slice(&16u32.to_be_bytes());
        out[32..36].copy_from_slice(&0u32.to_be_bytes());
        out[36..40].copy_from_slice(&(STRUCT_SIZE as u32).to_be_bytes());
        out[STRUCT_OFFSET..STRUCT_OFFSET + 4].copy_from_slice(&1u32.to_be_bytes());
        out[STRUCT_OFFSET + 8..STRUCT_OFFSET + 12].copy_from_slice(&2u32.to_be_bytes());
        out[STRUCT_OFFSET + 12..STRUCT_OFFSET + 16].copy_from_slice(&9u32.to_be_bytes());
        out
    }

    #[test]
    fn find_dtb_skips_malformed_candidate_before_valid_one() {
        let mut buf = b"kernel".to_vec();
        buf.extend_from_slice(DTB_MAGIC);
        buf.extend_from_slice(&[0u8; FDT_HEADER_SIZE]);
        let expected = buf.len();
        buf.extend_from_slice(&valid_dtb(0x100));
        assert_eq!(find_dtb_offset(&buf), Some(expected));
    }

    #[test]
    fn find_dtb_rejects_empty_and_truncated_candidates() {
        assert_eq!(find_dtb_offset(&valid_dtb(MIN_NON_EMPTY_DTB_SIZE)), None);

        let mut truncated = valid_dtb(0x100);
        truncated.truncate(0x80);
        assert_eq!(find_dtb_offset(&truncated), None);
    }

    #[test]
    fn skip_initramfs_patch_has_equal_slice_lengths() {
        let mut args = *b"console=ttyS0 skip_initramfs rootwait";
        assert_eq!(patch_skip_initramfs(&mut args), 1);
        assert_eq!(&args, b"console=ttyS0 want_initramfs rootwait");
    }
}
