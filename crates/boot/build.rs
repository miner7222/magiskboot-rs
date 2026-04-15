use pb_rs::ConfigBuilder;
use pb_rs::types::FileDescriptor;

fn main() {
    // Protobuf codegen
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

    // C++ compilation
    println!("cargo:rerun-if-changed=cpp/bootimg.cpp");
    println!("cargo:rerun-if-changed=cpp/wrapper.cpp");
    println!("cargo:rerun-if-changed=cpp/bootimg.hpp");
    println!("cargo:rerun-if-changed=cpp/magiskboot.hpp");
    println!("cargo:rerun-if-changed=cpp/base.hpp");

    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file("cpp/bootimg.cpp")
        .file("cpp/wrapper.cpp")
        .include("cpp")
        .warnings(false)
        .compile("magiskboot-cpp");
}
