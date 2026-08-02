#ifndef DILITHION_WALLET_WALLET_PRESERVE_H
#define DILITHION_WALLET_WALLET_PRESERVE_H

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

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
            if (std::equal(std::istreambuf_iterator<char>(a), std::istreambuf_iterator<char>(),
                           std::istreambuf_iterator<char>(b))) {
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
    return backup;
}

#endif // DILITHION_WALLET_WALLET_PRESERVE_H
