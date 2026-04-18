// Adapted from upstream: native/src/boot/cli.rs
// Changes: Replaced nix/libc APIs with std equivalents.
//          Removed umask() call. Adapted file I/O.
//          Uses base::CmdArgs::from_env_args instead of C-style argc/argv.

use crate::compress::{compress_cmd, decompress_cmd};
use crate::cpio::{cpio_commands, print_cpio_usage};
use crate::dtb::{DtbAction, dtb_commands, print_dtb_usage};
use crate::ffi::{FileFormat, cleanup, repack, split_image_dtb, unpack};
use crate::patch::hexpatch;
use crate::payload::extract_boot_from_payload;
use crate::sign::{sha1_hash, sign_boot_image};
use base::argh::{CommandInfo, EarlyExit, FromArgs, SubCommand};
use base::{
    CmdArgs, EarlyExitExt, LoggedResult, MappedFile, PositionalArgParser, ResultExt, Utf8CStr,
    Utf8CString, cstr, log_err,
};
use std::io::{Seek, SeekFrom, Write};
use std::str::FromStr;

#[derive(FromArgs)]
struct Cli {
    #[argh(subcommand)]
    action: Action,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Action {
    Unpack(Unpack),
    Repack(Repack),
    Verify(Verify),
    Sign(Sign),
    Extract(Extract),
    HexPatch(HexPatch),
    Cpio(Cpio),
    Dtb(Dtb),
    Split(Split),
    Sha1(Sha1),
    Cleanup(Cleanup),
    Compress(Compress),
    Decompress(Decompress),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "unpack")]
struct Unpack {
    #[argh(switch, short = 'n', long = none)]
    no_decompress: bool,
    #[argh(switch, short = 'h', long = none)]
    dump_header: bool,
    #[argh(positional)]
    img: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "repack")]
struct Repack {
    #[argh(switch, short = 'n', long = none)]
    no_compress: bool,
    #[argh(positional)]
    img: Utf8CString,
    #[argh(positional)]
    out: Option<Utf8CString>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
struct Verify {
    #[argh(positional)]
    img: Utf8CString,
    #[argh(positional)]
    cert: Option<Utf8CString>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "sign")]
struct Sign {
    #[argh(positional)]
    img: Utf8CString,
    #[argh(positional)]
    name: Option<Utf8CString>,
    #[argh(positional)]
    cert: Option<Utf8CString>,
    #[argh(positional)]
    key: Option<Utf8CString>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "extract")]
struct Extract {
    #[argh(positional)]
    payload: Utf8CString,
    #[argh(positional)]
    partition: Option<Utf8CString>,
    #[argh(positional)]
    outfile: Option<Utf8CString>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "hexpatch")]
struct HexPatch {
    #[argh(positional)]
    file: Utf8CString,
    #[argh(positional)]
    src: Utf8CString,
    #[argh(positional)]
    dest: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "cpio")]
struct Cpio {
    #[argh(positional)]
    file: Utf8CString,
    #[argh(positional)]
    cmds: Vec<String>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "dtb")]
struct Dtb {
    #[argh(positional)]
    file: Utf8CString,
    #[argh(subcommand)]
    action: DtbAction,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "split")]
struct Split {
    #[argh(switch, short = 'n', long = none)]
    no_decompress: bool,
    #[argh(positional)]
    file: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "sha1")]
struct Sha1 {
    #[argh(positional)]
    file: Utf8CString,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "cleanup")]
struct Cleanup {}

struct Compress {
    format: FileFormat,
    file: Utf8CString,
    out: Option<Utf8CString>,
}

impl FromArgs for Compress {
    fn from_args(command_name: &[&str], args: &[&str]) -> Result<Self, EarlyExit> {
        let cmd = command_name.last().copied().unwrap_or_default();
        let fmt = cmd.strip_prefix("compress=").unwrap_or("gzip");

        let Ok(fmt) = FileFormat::from_str(fmt) else {
            return Err(EarlyExit::from(format!(
                "Unsupported or unknown compression format: {fmt}\n"
            )));
        };

        let mut iter = PositionalArgParser(args.iter());
        Ok(Compress {
            format: fmt,
            file: iter.required("infile")?,
            out: iter.last_optional()?,
        })
    }
}

impl SubCommand for Compress {
    const COMMAND: &'static CommandInfo = &CommandInfo {
        name: "compress",
        description: "",
    };
}

#[derive(FromArgs)]
#[argh(subcommand, name = "decompress")]
struct Decompress {
    #[argh(positional)]
    file: Utf8CString,
    #[argh(positional)]
    out: Option<Utf8CString>,
}

fn print_usage(cmd: &str) {
    eprintln!(
        r#"MagiskBoot - Boot Image Modification Tool

Usage: {0} <action> [args...]

Supported actions:
  unpack [-n] [-h] <bootimg>
    Unpack <bootimg> to its individual components, each component to
    a file with its corresponding file name in the current directory.
    Supported components: kernel, kernel_dtb, ramdisk.cpio, second,
    dtb, extra, and recovery_dtbo.
    By default, each component will be decompressed on-the-fly.
    If '-n' is provided, all decompression operations will be skipped;
    each component will remain untouched, dumped in its original format.
    If '-h' is provided, the boot image header information will be
    dumped to the file 'header', which can be used to modify header
    configurations during repacking.
    Return values:
    0:valid    1:error    2:chromeos    3:vendor_boot

  repack [-n] <origbootimg> [outbootimg]
    Repack boot image components using files from the current directory
    to [outbootimg], or 'new-boot.img' if not specified.
    <origbootimg> is the original boot image used to unpack the components.
    By default, each component will be automatically compressed using its
    corresponding format detected in <origbootimg>.
    If '-n' is provided, all compression operations will be skipped.

  verify <bootimg> [x509.pem]
    Check whether the boot image is signed with AVB 1.0 signature.

  sign <bootimg> [name] [x509.pem pk8]
    Sign <bootimg> with AVB 1.0 signature.

  extract <payload.bin> [partition] [outfile]
    Extract [partition] from <payload.bin> to [outfile].

  hexpatch <file> <hexpattern1> <hexpattern2>
    Search <hexpattern1> in <file>, and replace it with <hexpattern2>

  cpio <incpio> [commands...]
    Do cpio commands to <incpio> (modifications are done in-place).

  dtb <file> <action> [args...]
    Do dtb related actions to <file>.

  split [-n] <file>
    Split image.*-dtb into kernel + kernel_dtb.

  sha1 <file>
    Print the SHA1 checksum for <file>

  cleanup
    Cleanup the current working directory

  compress[=format] <infile> [outfile]
    Compress <infile> with [format] to [outfile].
    Supported formats: {1}

  decompress <infile> [outfile]
    Detect format and decompress <infile> to [outfile].
    Supported formats: {1}
"#,
        cmd,
        FileFormat::formats()
    );
}

fn sign_cmd(
    image: &Utf8CStr,
    name: Option<&Utf8CStr>,
    cert: Option<&Utf8CStr>,
    key: Option<&Utf8CStr>,
) -> LoggedResult<()> {
    let _img_path = image.as_str();
    let name = name.unwrap_or(cstr!("/boot"));
    // BootImage C++ integration not yet available
    // For now, read the file directly
    let payload = std::fs::read(image.as_str())?;
    let sig = sign_boot_image(&payload, name, cert, key)?;
    // Append signature to file
    let mut fd = std::fs::OpenOptions::new()
        .write(true)
        .open(image.as_str())?;
    fd.seek(SeekFrom::End(0))?;
    fd.write_all(&sig)?;
    Ok(())
}

pub fn boot_main(cmds: CmdArgs) -> LoggedResult<i32> {
    let mut cmds = cmds.0;
    if cmds.len() < 2 {
        print_usage(cmds.first().unwrap_or(&"magiskboot"));
        return log_err!();
    }

    if cmds[1].starts_with("--") {
        cmds[1] = &cmds[1][2..];
    }

    let cli = if cmds[1].starts_with("compress=") {
        // Skip the main parser, directly parse the subcommand
        Compress::from_args(&cmds[..2], &cmds[2..]).map(|compress| Cli {
            action: Action::Compress(compress),
        })
    } else {
        Cli::from_args(&[cmds[0]], &cmds[1..])
    }
    .on_early_exit(|| match cmds[1] {
        "dtb" => print_dtb_usage(),
        "cpio" => print_cpio_usage(),
        _ => print_usage(cmds[0]),
    });

    match cli.action {
        Action::Unpack(Unpack {
            no_decompress,
            dump_header,
            img,
        }) => {
            return Ok(unpack(img.as_str(), no_decompress, dump_header));
        }
        Action::Repack(Repack {
            no_compress,
            img,
            out,
        }) => {
            repack(
                img.as_str(),
                out.as_ref().map(|s| s.as_str()).unwrap_or("new-boot.img"),
                no_compress,
            );
        }
        Action::Verify(Verify { img, cert }) => {
            let bi = crate::ffi::BootImage::new(img.as_str());
            if bi.payload().is_empty() {
                eprintln!("! verify: unsupported image format");
                return log_err!();
            }
            bi.verify(cert.as_deref())?;
        }
        Action::Sign(Sign {
            img,
            name,
            cert,
            key,
        }) => {
            sign_cmd(&img, name.as_deref(), cert.as_deref(), key.as_deref())?;
        }
        Action::Extract(Extract {
            payload,
            partition,
            outfile,
        }) => {
            extract_boot_from_payload(
                &payload,
                partition.as_ref().map(AsRef::as_ref),
                outfile.as_ref().map(AsRef::as_ref),
            )
            .log_with_msg(|w| w.write_str("Failed to extract from payload"))?;
        }
        Action::HexPatch(HexPatch { file, src, dest }) => {
            if !hexpatch(&file, &src, &dest) {
                log_err!("Failed to patch")?;
            }
        }
        Action::Cpio(Cpio { file, cmds }) => {
            return cpio_commands(&file, &cmds)
                .log_with_msg(|w| w.write_str("Failed to process cpio"));
        }
        Action::Dtb(Dtb { file, action }) => {
            return dtb_commands(&file, &action)
                .map(|b| if b { 0 } else { 1 })
                .log_with_msg(|w| w.write_str("Failed to process dtb"));
        }
        Action::Split(Split {
            no_decompress,
            file,
        }) => {
            return Ok(split_image_dtb(file.as_str(), no_decompress));
        }
        Action::Sha1(Sha1 { file }) => {
            let file = MappedFile::open(&file)?;
            let mut sha1 = [0u8; 20];
            sha1_hash(file.as_ref(), &mut sha1);
            for byte in &sha1 {
                print!("{byte:02x}");
            }
            println!();
        }
        Action::Cleanup(_) => {
            cleanup();
        }
        Action::Decompress(Decompress { file, out }) => {
            decompress_cmd(&file, out.as_deref())?;
        }
        Action::Compress(Compress { format, file, out }) => {
            compress_cmd(format, &file, out.as_deref())?;
        }
    }
    Ok(0)
}
