use base::cmdline_logging;

fn main() {
    cmdline_logging();
    let args: Vec<String> = std::env::args().collect();
    let cmds = base::CmdArgs::from_env_args(args);
    let ret = magiskboot::cli::boot_main(cmds).unwrap_or(1);
    std::process::exit(ret);
}
