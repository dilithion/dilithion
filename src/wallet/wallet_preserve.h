#ifndef DILITHION_WALLET_WALLET_PRESERVE_H
#define DILITHION_WALLET_WALLET_PRESERVE_H

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// Wallet-preservation guard — shared by every node binary that owns a wallet.
//
// A wallet file that FAILS TO LOAD is not an absent wallet. Before this guard,
// a failed CWallet::Load() only printed a warning and fell through to the
// ordinary "no wallet found" path, which offers to create one — and creation
// calls Save(wallet_path), whose SaveUnlocked writes a temp file, fsyncs, and
// atomically renames it OVER the user's wallet.dat. No copy is kept, so the
// encrypted key material is gone; only a BIP39 phrase can recover the funds.
//
// This is not hypothetical. v4.5.0 shipped LP-7's rule that a v7 record with an
// empty MAC invalidates the whole wallet, but not the fix (b34eb373) for the
// three store sites that wrote exactly such records. An encrypted HD wallet on
// v4.5.0 bricks as soon as it mints a receive or change address, and every
// affected user was then invited to overwrite it.
//
// Single-sourced deliberately: dilithion-node and dilv-node are near-identical
// twins, and the DilV copy of this bug was missed on the first pass. A shared
// header means a third binary cannot silently inherit the unguarded path.
//
// Copies (never moves) the file, so a user who reruns an older binary still
// finds their wallet where it expects it. Returns the backup path, or an empty
// string if no copy could be written — callers MUST handle the empty case and
// tell the user to copy the file themselves.
// ---------------------------------------------------------------------------
// Force a just-written file, and the directory entry naming it, to stable
// storage. copy_file is NOT durable: it returns once the data is in the page
// cache. The caller then goes on to overwrite the ORIGINAL wallet (the restore
// path does temp-write + fsync + rename over it), so a power loss between the
// copy and that rename would leave the user with neither file — on the one
// path whose whole justification is "only after a copy has been preserved".
// Best-effort by design: a preserved-but-unflushed copy still beats refusing
// to preserve at all, so failures here do not fail the preservation.
inline void DurablySync(const std::string& file_path,
                        const std::filesystem::path& dir) {
#ifdef _WIN32
    HANDLE h = CreateFileA(file_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }
    // Windows has no directory-handle fsync equivalent for this purpose;
    // NTFS metadata for the created entry is journalled. Nothing further.
    (void)dir;
#else
    int fd = ::open(file_path.c_str(), O_RDONLY);
    if (fd >= 0) {
        ::fsync(fd);
        ::close(fd);
    }
    // The directory entry itself must be flushed, or the file can survive
    // while its name does not.
    int dfd = ::open(dir.string().c_str(), O_RDONLY);
    if (dfd >= 0) {
        ::fsync(dfd);
        ::close(dfd);
    }
#endif
}

inline std::string PreserveUnreadableWallet(const std::string& wallet_path) {
    std::error_code ec;

    // Only ever copy a regular file. A directory, symlink-to-directory, or
    // special file at wallet_path would otherwise turn a recovery aid into a
    // recursive copy or an error we would report as success.
    if (!std::filesystem::is_regular_file(wallet_path, ec) || ec) {
        return std::string();
    }

    const std::time_t now = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    std::tm tm_buf{};
#ifdef _WIN32
    if (localtime_s(&tm_buf, &now) != 0) {
        return std::string();
    }
#else
    if (localtime_r(&now, &tm_buf) == nullptr) {
        return std::string();
    }
#endif
    char stamp[32] = {0};
    if (std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm_buf) == 0) {
        return std::string();
    }

    // A node in a restart loop (relay-only keeps running and can be restarted
    // repeatedly) would otherwise spray one full copy of the key material per
    // restart until the disk fills. If an existing preserved copy is already
    // byte-for-byte this same file, that copy IS the backup — return it and
    // write nothing. Compared by size first, then content, because these files
    // are small and a false match here would silently skip a real backup.
    // Compare BASENAMES, not full paths: wallet_path is built by string
    // concatenation and carries '/' separators, while directory_iterator emits
    // the platform form ('\' on Windows). Prefix-matching full paths therefore
    // never matched on Windows and this dedup was silently dead there.
    const std::filesystem::path wallet_fs(wallet_path);
    const std::string name_prefix = wallet_fs.filename().string() + ".unreadable-";
    auto dir = wallet_fs.parent_path();
    if (dir.empty()) dir = std::filesystem::path(".");
    const auto src_size = std::filesystem::file_size(wallet_path, ec);
    if (!ec) {
        std::error_code scan_ec;
        for (std::filesystem::directory_iterator it(dir, scan_ec), end;
             !scan_ec && it != end; it.increment(scan_ec)) {
            if (it->path().filename().string().rfind(name_prefix, 0) != 0) continue;
            const std::string candidate = it->path().string();
            std::error_code cmp_ec;
            if (std::filesystem::file_size(candidate, cmp_ec) != src_size || cmp_ec) continue;
            std::ifstream a(wallet_path, std::ios::binary);
            std::ifstream b(candidate, std::ios::binary);
            if (!a || !b) continue;
            // FOUR-argument std::equal, and check the stream state afterwards.
            // The three-argument form walks the second range only as far as the
            // first, and an I/O error part-way through ends both iterators
            // early — so a read failure reports "identical" for the bytes it
            // happened to read. That matters here more than anywhere: the
            // precondition for this whole function is a wallet that would not
            // load, which is exactly the file most likely to be on failing
            // media. Declaring a DIFFERENT backup identical would return it as
            // "the preserved copy", after which the restore path overwrites the
            // original leaving only a non-matching file behind.
            const bool identical = std::equal(
                std::istreambuf_iterator<char>(a), std::istreambuf_iterator<char>(),
                std::istreambuf_iterator<char>(b), std::istreambuf_iterator<char>());
            // Require BOTH streams to have reached a clean end-of-file. The
            // four-argument form's length equality is a weaker guarantee than
            // saying this outright: an error that ends a stream early looks
            // like exhaustion to the iterator, so without the explicit eof()
            // check a truncated read of a failing wallet could still be
            // reported as a match against a stale backup.
            if (identical && a.eof() && b.eof() && !a.bad() && !b.bad()) {
                return candidate;  // identical copy already preserved
            }
        }
    }

    // Second-resolution stamps collide if the node restarts twice inside one
    // second, so never overwrite an existing backup: walk a suffix until a free
    // name is found. Losing an older preserved copy defeats the whole point.
    std::string backup = (dir / (wallet_fs.filename().string() + ".unreadable-" + stamp)).string();
    ec.clear();
    if (std::filesystem::exists(backup, ec)) {
        bool placed = false;
        for (int n = 2; n < 1000; ++n) {
            const std::string candidate = backup + "-" + std::to_string(n);
            std::error_code exist_ec;
            if (!std::filesystem::exists(candidate, exist_ec)) {
                backup = candidate;
                placed = true;
                break;
            }
        }
        if (!placed) return std::string();
    }

    // copy_file without overwrite_existing: fail rather than clobber.
    ec.clear();
    std::filesystem::copy_file(wallet_path, backup, ec);
    if (ec) {
        // NEVER remove on file_exists. Without overwrite_existing that is the
        // MOST LIKELY error, and the file it names was written by somebody else
        // — a concurrent process that won the race, or a copy that appeared
        // between the exists() check above and here. Deleting it would destroy
        // a complete backup and leave zero, on the one path whose entire job is
        // to guarantee one. Only clean up a partial file we ourselves wrote
        // (ENOSPC, I/O error part-way through).
        if (ec != std::errc::file_exists) {
            std::error_code rm_ec;
            std::filesystem::remove(backup, rm_ec);
        }
        return std::string();
    }

    // Only now is the copy real. Without this the caller may overwrite the
    // original while this copy exists solely in the page cache.
    DurablySync(backup, dir);
    return backup;
}

#endif // DILITHION_WALLET_WALLET_PRESERVE_H
