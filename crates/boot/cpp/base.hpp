// Minimal base.hpp shim for standalone magiskboot
//
// Provides the subset of Magisk's base.hpp that bootimg.cpp needs.
// Replaces: xopen, xwrite, write_zero, mmap_data, owned_fd, byte_view, etc.
// Platform: Windows + POSIX compatible via standard C/C++ and platform ifdefs.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <cerrno>
#include <algorithm>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <type_traits>

#ifdef _WIN32
// MSVC compatibility
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
// __attribute__((packed)) is GCC/Clang; MSVC uses #pragma pack
#define __attribute__(x)
// POSIX constants not in MSVC
#ifndef R_OK
#define R_OK 4
#endif
#ifndef W_OK
#define W_OK 2
#endif
// GCC builtins
#include <intrin.h>
#define __builtin_bswap64 _byteswap_uint64
#define __builtin_bswap32 _byteswap_ulong
// off64_t
typedef long long off64_t;
#endif

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <windows.h>
#undef min
#undef max
#define O_RDONLY _O_RDONLY
#define O_WRONLY _O_WRONLY
#define O_CREAT  _O_CREAT
#define O_TRUNC  _O_TRUNC
#define O_CLOEXEC 0  // Not available on Windows
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE
#define F_OK 0
#define getpagesize() 4096
#define creat(path, mode) _open(path, _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY, _S_IREAD | _S_IWRITE)
#define lseek64 _lseeki64
#define ftruncate64(fd, sz) _chsize_s(fd, sz)
#define access _access
#define close _close
#define read _read
#define lseek _lseek
inline int xopen(const char *path, int flags, ...) {
    int fd;
    if (flags & O_CREAT) {
        fd = _open(path, flags | _O_BINARY, _S_IREAD | _S_IWRITE);
    } else {
        fd = _open(path, flags | _O_BINARY);
    }
    if (fd < 0) {
        fprintf(stderr, "! Cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fd;
}
inline int xopenat(int, const char *path, int flags, int mode = 0) {
    // Windows doesn't have openat, just use path
    int fd = _open(path, flags | _O_BINARY, mode);
    if (fd < 0) {
        fprintf(stderr, "! Cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fd;
}
inline ssize_t xwrite(int fd, const void *buf, size_t count) {
    auto written = _write(fd, buf, (unsigned int)count);
    if (written < 0) {
        fprintf(stderr, "! Write error: %s\n", strerror(errno));
        exit(1);
    }
    return written;
}
inline void xmkdir(const char *path, int = 0) {
    CreateDirectoryA(path, nullptr);
}
inline void rm_rf(const char *path) {
    // Simple recursive delete (files only for now)
    std::string cmd = std::string("rd /s /q \"") + path + "\" 2>nul";
    system(cmd.c_str());
}
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <dirent.h>
inline int xopen(const char *path, int flags, ...) {
    int mode = 0644;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    int fd = open(path, flags, mode);
    if (fd < 0) {
        fprintf(stderr, "! Cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fd;
}
inline int xopenat(int dirfd, const char *path, int flags, int mode = 0644) {
    int fd = openat(dirfd, path, flags, mode);
    if (fd < 0) {
        fprintf(stderr, "! Cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fd;
}
inline ssize_t xwrite(int fd, const void *buf, size_t count) {
    auto written = write(fd, buf, count);
    if (written < 0) {
        fprintf(stderr, "! Write error: %s\n", strerror(errno));
        exit(1);
    }
    return written;
}
inline void xmkdir(const char *path, int mode = 0755) {
    mkdir(path, mode);
}
inline void rm_rf(const char *path) {
    std::string cmd = std::string("rm -rf '") + path + "'";
    system(cmd.c_str());
}
#ifndef lseek64
#define lseek64 lseek
#endif
#ifndef ftruncate64
#define ftruncate64 ftruncate
#endif
#endif

// ---------------------------------------------------------------------------
// write_zero — write count zero bytes to fd
// ---------------------------------------------------------------------------
inline void write_zero(int fd, size_t count) {
    char buf[4096] = {};
    while (count > 0) {
        size_t n = std::min(count, sizeof(buf));
        xwrite(fd, buf, n);
        count -= n;
    }
}

// ---------------------------------------------------------------------------
// xfopen — safe fopen wrapper
// ---------------------------------------------------------------------------
inline FILE *xfopen(const char *path, const char *mode) {
    FILE *fp = fopen(path, mode);
    if (!fp) {
        fprintf(stderr, "! Cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    return fp;
}

// ---------------------------------------------------------------------------
// xsendfile — copy data between fds
// ---------------------------------------------------------------------------
inline ssize_t xsendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
#ifdef _WIN32
    // Windows: manual copy
    char buf[65536];
    if (offset) _lseeki64(in_fd, *offset, SEEK_SET);
    size_t total = 0;
    while (total < count) {
        int n = _read(in_fd, buf, (unsigned)std::min(count - total, sizeof(buf)));
        if (n <= 0) break;
        xwrite(out_fd, buf, n);
        total += n;
    }
    if (offset) *offset += total;
    return (ssize_t)total;
#else
    return sendfile(out_fd, in_fd, offset, count);
#endif
}

// ---------------------------------------------------------------------------
// memmem — search for needle in haystack (not standard on Windows)
// ---------------------------------------------------------------------------
#ifdef _WIN32
inline void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen) {
    if (needlelen == 0) return const_cast<void*>(haystack);
    if (haystacklen < needlelen) return nullptr;
    const uint8_t *h = (const uint8_t *)haystack;
    const uint8_t *n = (const uint8_t *)needle;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0)
            return const_cast<void*>((const void*)(h + i));
    }
    return nullptr;
}
#endif

// ---------------------------------------------------------------------------
// String utilities
// ---------------------------------------------------------------------------
inline size_t strscpy(char *dest, const char *src, size_t size) {
    size_t len = strlen(src);
    if (size > 0) {
        size_t copy = std::min(len, size - 1);
        memcpy(dest, src, copy);
        dest[copy] = '\0';
    }
    return len;
}

template <size_t N>
inline int ssprintf(char (&dest)[N], const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(dest, N, fmt, args);
    va_end(args);
    return ret;
}

// Overload accepting explicit size (matches call sites using sizeof)
inline int ssprintf(char *dest, size_t size, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(dest, size, fmt, args);
    va_end(args);
    return ret;
}

// ---------------------------------------------------------------------------
// byte_view / byte_data — lightweight span-like types
// ---------------------------------------------------------------------------
struct byte_view {
    const uint8_t *_data;
    size_t _size;
    byte_view() : _data(nullptr), _size(0) {}
    byte_view(const void *p, size_t s) : _data((const uint8_t*)p), _size(s) {}
    const uint8_t *data() const { return _data; }
    size_t size() const { return _size; }
    const uint8_t &operator[](size_t i) const { return _data[i]; }
    // For rust::Slice compat — bootimg.hpp provides the conversion
};

struct byte_data {
    uint8_t *_data;
    size_t _size;
    byte_data() : _data(nullptr), _size(0) {}
    byte_data(void *p, size_t s) : _data((uint8_t*)p), _size(s) {}
    uint8_t *data() { return _data; }
    size_t size() const { return _size; }
};

// ---------------------------------------------------------------------------
// owned_fd — RAII file descriptor
// ---------------------------------------------------------------------------
struct owned_fd {
    int fd;
    owned_fd() : fd(-1) {}
    owned_fd(int f) : fd(f) {}  // Allow implicit conversion from int
    ~owned_fd() { if (fd >= 0) close(fd); }
    owned_fd(owned_fd &&o) noexcept : fd(o.fd) { o.fd = -1; }
    owned_fd &operator=(owned_fd &&o) noexcept {
        if (fd >= 0) close(fd);
        fd = o.fd; o.fd = -1;
        return *this;
    }
    operator int() const { return fd; }
    owned_fd(const owned_fd &) = delete;
    owned_fd &operator=(const owned_fd &) = delete;
};

// ---------------------------------------------------------------------------
// mmap_data — memory-mapped file (cross-platform)
// ---------------------------------------------------------------------------
class mmap_data {
    uint8_t *_data = nullptr;
    size_t _size = 0;
#ifdef _WIN32
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap = nullptr;
#endif
    void do_map(int fd, size_t sz, bool writable = false) {
        _size = sz;
#ifdef _WIN32
        DWORD prot = writable ? PAGE_READWRITE : PAGE_READONLY;
        DWORD access = writable ? FILE_MAP_WRITE : FILE_MAP_READ;
        hMap = CreateFileMapping((HANDLE)_get_osfhandle(fd), nullptr, prot, 0, (DWORD)sz, nullptr);
        if (!hMap) { _size = 0; return; }
        _data = (uint8_t*)MapViewOfFile(hMap, access, 0, 0, sz);
        if (!_data) { CloseHandle(hMap); hMap = nullptr; _size = 0; }
#else
        int flags = writable ? MAP_SHARED : MAP_PRIVATE;
        _data = (uint8_t*)mmap(nullptr, sz, PROT_READ | (writable ? PROT_WRITE : 0), flags, fd, 0);
        if (_data == MAP_FAILED) { _data = nullptr; _size = 0; }
#endif
    }
public:
    mmap_data() = default;
    mmap_data(const char *filename, bool writable = false) {
        int flags = writable ? O_RDWR : O_RDONLY;
        int fd = xopen(filename, flags);
        auto sz = lseek64(fd, 0, SEEK_END);
        lseek64(fd, 0, SEEK_SET);
        if (sz > 0) do_map(fd, (size_t)sz, writable);
        close(fd);
    }
    mmap_data(int dirfd, const char *filename) {
        int fd = xopenat(dirfd, filename, O_RDONLY);
        auto sz = lseek64(fd, 0, SEEK_END);
        lseek64(fd, 0, SEEK_SET);
        if (sz > 0) do_map(fd, (size_t)sz);
        close(fd);
    }
    // Map an already-open fd with known size (does NOT close fd)
    mmap_data(int fd, size_t size, bool writable) {
        if (size > 0) do_map(fd, size, writable);
    }
    ~mmap_data() {
#ifdef _WIN32
        if (_data) UnmapViewOfFile(_data);
        if (hMap) CloseHandle(hMap);
#else
        if (_data) munmap(_data, _size);
#endif
    }
    mmap_data(mmap_data &&o) noexcept : _data(o._data), _size(o._size) {
#ifdef _WIN32
        hFile = o.hFile; hMap = o.hMap;
        o.hFile = INVALID_HANDLE_VALUE; o.hMap = nullptr;
#endif
        o._data = nullptr; o._size = 0;
    }
    uint8_t *data() { return _data; }
    const uint8_t *data() const { return _data; }
    size_t size() const { return _size; }
    operator byte_view() const { return byte_view(_data, _size); }
    mmap_data(const mmap_data &) = delete;
    mmap_data &operator=(const mmap_data &) = delete;
};

// ---------------------------------------------------------------------------
// Utf8CStr — CXX-compatible string reference (standalone shim)
// ---------------------------------------------------------------------------
// In Magisk, this comes from CXX bridge. For standalone build,
// we provide a thin wrapper.
class Utf8CStr {
    const char *_str;
    size_t _len;
public:
    Utf8CStr() : _str(""), _len(0) {}
    Utf8CStr(const char *s) : _str(s), _len(strlen(s)) {}
    Utf8CStr(const char *s, size_t l) : _str(s), _len(l) {}
    const char *c_str() const { return _str; }
    const char *data() const { return _str; }
    size_t length() const { return _len; }
    bool operator==(const char *other) const { return strcmp(_str, other) == 0; }
    bool operator==(const Utf8CStr &other) const { return strcmp(_str, other._str) == 0; }
    operator const char*() const { return _str; }
};

// ---------------------------------------------------------------------------
// parse_prop_file — parse key=value file
// ---------------------------------------------------------------------------
inline void parse_prop_file(const char *filename,
    const std::function<bool(Utf8CStr, Utf8CStr)> &func) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return;
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        // Trim trailing newline
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        if (!func(Utf8CStr(line), Utf8CStr(eq + 1)))
            break;
    }
    fclose(fp);
}

// ---------------------------------------------------------------------------
// FileFormat enum — matches Rust FFI definition
// ---------------------------------------------------------------------------
// Defined in magiskboot.hpp via forward declaration.
// The actual enum is in the CXX bridge. For standalone, we define it here.
enum class FileFormat : uint8_t {
    UNKNOWN = 0,
    CHROMEOS, AOSP, AOSP_VENDOR, DHTB, BLOB,
    GZIP, ZOPFLI, XZ, LZMA, BZIP2, LZ4, LZ4_LEGACY, LZ4_LG,
    LZOP,
    MTK, DTB, ZIMAGE,
};

// ---------------------------------------------------------------------------
// Compression/format — wired to Rust implementations via extern "C"
// ---------------------------------------------------------------------------
extern "C" {
    void rust_decompress_bytes(int fmt, const uint8_t *in_ptr, size_t in_len, int out_fd);
    void rust_compress_bytes(int fmt, const uint8_t *in_ptr, size_t in_len, int out_fd);
    int rust_check_fmt(const uint8_t *buf, size_t len);
}

inline void decompress_bytes(FileFormat fmt, byte_view bv, int fd) {
    rust_decompress_bytes((int)fmt, bv.data(), bv.size(), fd);
}
inline void compress_bytes(FileFormat fmt, byte_view bv, int fd) {
    rust_compress_bytes((int)fmt, bv.data(), bv.size(), fd);
}
inline bool fmt_compressed(FileFormat fmt) {
    return fmt >= FileFormat::GZIP && fmt <= FileFormat::LZ4_LG;
}
inline bool fmt_compressed_any(FileFormat fmt) {
    return fmt_compressed(fmt) || fmt == FileFormat::LZOP;
}
inline const char* fmt2name(FileFormat fmt) {
    switch (fmt) {
        case FileFormat::GZIP: return "gzip";
        case FileFormat::ZOPFLI: return "zopfli";
        case FileFormat::XZ: return "xz";
        case FileFormat::LZMA: return "lzma";
        case FileFormat::BZIP2: return "bzip2";
        case FileFormat::LZ4: return "lz4";
        case FileFormat::LZ4_LEGACY: return "lz4_legacy";
        case FileFormat::LZ4_LG: return "lz4_lg";
        case FileFormat::DTB: return "dtb";
        case FileFormat::ZIMAGE: return "zimage";
        default: return "raw";
    }
}

// ---------------------------------------------------------------------------
// SHA — wired to Rust crypto via extern "C"
// ---------------------------------------------------------------------------
extern "C" {
    void *rust_sha_new(bool use_sha1);
    void rust_sha_update(void *ctx, const uint8_t *data, size_t len);
    size_t rust_sha_finalize(void *ctx, uint8_t *out, size_t out_len);
    size_t rust_sha_output_size(const void *ctx);
    void rust_sha_free(void *ctx);
    void rust_sha256_hash(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len);
    uint8_t *rust_sign_payload(const uint8_t *payload, size_t payload_len, size_t *out_len);
    void rust_free_vec(uint8_t *ptr, size_t len);
}

struct SHA {
    void *ctx;
    SHA(bool use_sha1) : ctx(rust_sha_new(use_sha1)) {}
    ~SHA() { if (ctx) rust_sha_free(ctx); }
    void update(const uint8_t *data, size_t len) { rust_sha_update(ctx, data, len); }
    void update(byte_view bv) { update(bv.data(), bv.size()); }
    void finalize_into(byte_data out) { rust_sha_finalize(ctx, out.data(), out.size()); }
    size_t output_size() const { return rust_sha_output_size(ctx); }
    SHA(const SHA &) = delete;
    SHA &operator=(const SHA &) = delete;
};

inline std::unique_ptr<SHA> get_sha(bool use_sha1) {
    return std::make_unique<SHA>(use_sha1);
}

inline void sha256_hash(byte_view data, byte_data out) {
    rust_sha256_hash(data.data(), data.size(), out.data(), out.size());
}

inline std::vector<uint8_t> sign_payload(byte_view payload) {
    size_t out_len = 0;
    uint8_t *ptr = rust_sign_payload(payload.data(), payload.size(), &out_len);
    if (!ptr || out_len == 0) return {};
    std::vector<uint8_t> result(ptr, ptr + out_len);
    rust_free_vec(ptr, out_len);
    return result;
}
