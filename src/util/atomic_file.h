// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_UTIL_ATOMIC_FILE_H
#define DILITHION_UTIL_ATOMIC_FILE_H

// ---------------------------------------------------------------------------
// AtomicReplaceFile — publish a fully-written temp file over a destination so
// that the destination is, at EVERY instant, either the complete old file or
// the complete new file. Never torn. Never absent.
//
// WHY NOT JUST std::filesystem::rename -- WHAT WAS ACTUALLY MEASURED
// -------------------------------------------------------------------
// On POSIX, rename(2) over an existing path is atomic by specification and
// fs::rename is a thin wrapper over it. Nothing to fix there.
//
// On Windows the situation is more subtle than the folklore, so this comment
// records what was MEASURED rather than what is commonly asserted. On the
// toolchain this project ships with (MinGW-w64, GCC 15.2, __GLIBCXX__
// 20250808 -- the same rolling MSYS2 the release workflows install):
//
//     fs::rename(tmp, dst)   with dst existing -> SUCCEEDS, dst replaced
//     std::rename(tmp, dst)  with dst existing -> FAILS, errno EEXIST (17)
//
// i.e. libstdc++ is NOT calling _wrename here; it is making a Win32 replace
// call, so the operation is already a genuine atomic replace. Code on this
// path was therefore NOT producing torn or absent files today. Do not "fix"
// anything by citing the _wrename story as a current fact -- for this
// toolchain it is not one.
//
// What this helper buys anyway, and why the callers were moved onto it:
//
//   (1) The guarantee stops resting on an unspecified libstdc++ implementation
//       detail. The standard's replace semantics for fs::rename have not always
//       been delivered by MinGW libstdc++ (older releases did use _wrename,
//       which cannot replace), and this project ships three separately-built
//       binaries. MoveFileExW states the requirement in the source instead of
//       hoping the library keeps its current behaviour.
//
//   (2) Durability. MOVEFILE_WRITE_THROUGH makes the replace itself durable;
//       fs::rename gives no such guarantee.
//
//   (3) It retires the remove-then-rename FALLBACK that callers had grown to
//       paper over (1). That shape is genuinely destructive wherever it is
//       reached: a condition-triggered kill placed between the remove and the
//       rename left mik_registration.dat ABSENT on 20 of 20 killed writes. On
//       the current toolchain the fallback is dead code -- fs::rename succeeds
//       so it never runs, and in the two realistic triggers that DO make
//       fs::rename fail (destination held open by another handle; destination
//       marked read-only) the fallback's remove() also fails, so nothing was
//       lost. It is a loaded gun that currently happens not to fire.
//
//   (4) One implementation. src/wallet/wallet.cpp and
//       src/attestation/seed_attestation.cpp already hand-rolled this
//       MoveFileExW dance; this is the shared version rather than a fourth copy.
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
