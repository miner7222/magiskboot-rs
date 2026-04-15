// C wrapper functions for bootimg.cpp
//
// These provide a C ABI that Rust can call directly via extern "C",
// avoiding the need for CXX bridge type compatibility.
// The Magisk upstream C++ code uses Utf8CStr which is our shim class.

#include "base.hpp"
#include "magiskboot.hpp"

extern "C" {

int magiskboot_unpack(const char *image, int skip_decomp, int hdr) {
    return unpack(Utf8CStr(image), skip_decomp != 0, hdr != 0);
}

void magiskboot_repack(const char *src_img, const char *out_img, int skip_comp) {
    repack(Utf8CStr(src_img), Utf8CStr(out_img), skip_comp != 0);
}

int magiskboot_split_image_dtb(const char *filename, int skip_decomp) {
    return split_image_dtb(Utf8CStr(filename), skip_decomp != 0);
}

void magiskboot_cleanup() {
    cleanup();
}

} // extern "C"
