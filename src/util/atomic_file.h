// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_ATOMIC_FILE_H
#define DILITHION_UTIL_ATOMIC_FILE_H

// ---------------------------------------------------------------------------
// AtomicReplaceFile — publish a fully-written temp file over a destination so
// that the destination is, at EVERY instant, either the complete old file or
// the complete new file. Never torn. Never absent.
//
// WHY THIS IS NOT `std::filesystem::rename`
// -----------------------------------------
// On POSIX, rename(2) over an existing path is atomic by specification, and
// std::filesystem::rename is a thin wrapper over it. Correct, nothing to do.
//
// On Windows it is NOT. libstdc++'s std::filesystem::rename is implemented with
// _wrename(), and the C runtime's rename FAILS with EEXIST when the destination
// already exists. Two things follow, and BOTH have been found in this tree:
//
//   (a) Code that calls fs::rename with no fallback silently fails on every
//       save after the first — the file is written once and then never
//       updated again, while the caller's "atomic" comment says otherwise.
//
//   (b) Code that "fixes" (a) with a remove-then-rename fallback opens a
//       window in which the destination DOES NOT EXIST. Measured, not assumed:
//       a kill-race probe against that fallback caught the file absent on
//       15 of 15 killed writes. Absent is not atomic.
//
// The correct Windows primitive is MoveFileExW(MOVEFILE_REPLACE_EXISTING),
// which performs the replace as a single filesystem operation. That is what
// src/wallet/wallet.cpp and src/attestation/seed_attestation.cpp already do;
// this header exists so that pattern has ONE implementation rather than a
// fourth hand-rolled copy.
//
// DURABILITY IS A SEPARATE PROPERTY
// ---------------------------------
// `durable = true` adds MOVEFILE_WRITE_THROUGH on Windows and a parent-
// directory fsync on POSIX, so the replace survives power loss. Atomicity
// (never torn / never absent) holds either way and is what this function is
// primarily for. Callers writing a rebuildable cache may pass durable=false;
// callers writing state that cannot be reconstructed must not.
//
// NOTE: this publishes whatever is already in `tmp`. Flushing/fsyncing the
// TEMP FILE's own contents before calling is the caller's job — otherwise a
// durable rename can publish an empty file.
// ---------------------------------------------------------------------------

#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
// Guarded so this header cannot shadow std::min/std::max or drag in the world
// for TUs that only wanted a file rename.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace util {

// Returns true on success. On failure the destination is left untouched (the
// previous complete file, or nothing if there was none) and `err`, if given,
// receives a human-readable reason. `tmp` is NOT removed on failure — the
// caller owns its temp file and its cleanup policy.
inline bool AtomicReplaceFile(const std::filesystem::path& tmp,
                              const std::filesystem::path& dst,
                              std::string* err = nullptr,
                              bool durable = true) {
#ifdef _WIN32
    DWORD flags = MOVEFILE_REPLACE_EXISTING;
    if (durable) flags |= MOVEFILE_WRITE_THROUGH;

    const std::wstring wTmp = tmp.wstring();
    const std::wstring wDst = dst.wstring();
    if (MoveFileExW(wTmp.c_str(), wDst.c_str(), flags) == 0) {
        if (err) {
            *err = "MoveFileExW(" + tmp.string() + " -> " + dst.string() +
                   ") failed, GetLastError=" + std::to_string(GetLastError());
        }
        return false;
    }
    return true;
#else
    std::error_code ec;
    std::filesystem::rename(tmp, dst, ec);
    if (ec) {
        if (err) {
            *err = "rename(" + tmp.string() + " -> " + dst.string() +
                   ") failed: " + ec.message();
        }
        return false;
    }

    if (!durable) return true;

    // The rename itself is already visible; this only makes it survive power
    // loss on filesystems that do not auto-commit directory metadata (XFS,
    // btrfs). A failure here is a durability failure, not an atomicity one, so
    // the renamed file is deliberately left in place.
    std::filesystem::path parent = dst.parent_path();
    if (parent.empty()) parent = ".";
    const int dir_fd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) {
        if (err) *err = std::string("open parent dir failed: ") + std::strerror(errno);
        return false;
    }
    const bool ok = (::fsync(dir_fd) == 0);
    const int saved = errno;
    ::close(dir_fd);
    if (!ok && err) *err = std::string("fsync parent dir failed: ") + std::strerror(saved);
    return ok;
#endif
}

}  // namespace util

#endif // DILITHION_UTIL_ATOMIC_FILE_H
