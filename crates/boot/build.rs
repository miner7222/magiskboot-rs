use pb_rs::ConfigBuilder;
use pb_rs::types::FileDescriptor;

fn main() {
    // Protobuf codegen for the payload parser. The C++ build step
    // that used to sit here was retired — the boot-image pipeline is
    // fully Rust-side now (see `src/bootimg/`).
    println!("cargo:rerun-if-changed=proto/update_metadata.proto");
    let cb = ConfigBuilder::new(
        &["proto/update_metadata.proto"],
        None,
        Some(&"proto"),
        &["."],
    )
    .unwrap();
    FileDescriptor::run(
        &cb.single_module(true)
            .dont_use_cow(true)
            .build(),
    )
    .unwrap();
}
