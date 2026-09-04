#ifndef DILITHION_WALLET_WALLET_LOAD_GUARD_H
#define DILITHION_WALLET_WALLET_LOAD_GUARD_H

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <string>
#include <system_error>
#include <thread>

// ---------------------------------------------------------------------------
// Wallet-file classification — shared by every node binary that owns a wallet.
//
// CWallet::Load() returns a single `false` for four completely different
// situations, and the startup guard that consumes it therefore cannot tell them
// apart:
//
//   1. a 0-byte (or sub-header) wallet.dat — is_open() succeeds and the 8-byte
//      magic read sets failbit. An installer that pre-creates the file, a
//      OneDrive placeholder that has not hydrated, an interrupted first run:
//      all land here. There are no keys in such a file, so there is nothing to
//      lose by proceeding.
//   2. a non-empty file whose magic is not DILWLT01..07 — a truncated rsync, a
//      copied-over-the-top text file, genuine corruption. Something IS in
//      there; it might be a wallet we cannot parse. Fail closed.
//   3. an OPEN failure: EACCES, an antivirus or backup process holding the
//      file, wrong ownership. Nothing is known about the contents at all, and
//      the condition is very often TRANSIENT — the scanner lets go a second
//      later.
//   4. a real, well-formed wallet whose body fails to parse. Fail closed.
//
// Before this header, (1) and (3) were reported to the user with the words
// "wallet.dat exists but could not be loaded … do not delete wallet.dat", and
// the node exited 1. On every subsequent start, forever: the file never
// changes, so the verdict never changes. A user who never had a wallet could
// not start the node at all, and was explicitly instructed not to remove the
// one file that would have unblocked them. A transient lock became permanent.
//
// This header does NOT weaken the guard that PR #151 added; case (2) and case
// (4) still refuse, still preserve a copy, still exit 1. It only stops the node
// from treating "there is provably nothing here" and "I could not look" as if
// they were "there are keys here and I cannot read them".
// ---------------------------------------------------------------------------

// The magic is the first 8 bytes of every wallet format version. A file shorter
// than this cannot be any wallet Dilithion has ever written, in any version, so
// it cannot contain key material. That is the entire justification for treating
// it as absent — keep the bound tied to the magic, and do NOT raise it to the
// full 16-byte header: a 12-byte file is a truncated wallet whose magic we can
// still check, and truncated wallets must fail closed, not be silently
// overwritten.
inline constexpr std::uintmax_t kWalletMagicBytes = 8;

enum class WalletFileState {
    Absent,      // no file at that path
    Empty,       // exists, but too small to hold even the magic — no keys possible
    Unopenable,  // exists and is non-empty, but could not be opened/read (lock, EACCES)
    Invalid,     // opened and read, and the magic is not a Dilithion wallet magic
    Present      // opened, magic recognised — hand it to CWallet::Load()
};

inline bool IsKnownWalletMagic(const char magic[8]) {
    static const char* kMagics[] = {
        "DILWLT01", "DILWLT02", "DILWLT03", "DILWLT04",
        "DILWLT05", "DILWLT06", "DILWLT07"
    };
    for (const char* m : kMagics) {
        if (std::memcmp(magic, m, 8) == 0) return true;
    }
    return false;
}

// Single-shot classification. `detail` (optional) receives a human-readable
// reason for Unopenable, which is the only state where the user needs to be
// told something beyond the state itself.
inline WalletFileState ClassifyWalletFileOnce(const std::string& wallet_path,
                                              std::string* detail = nullptr) {
    if (detail) detail->clear();
    std::error_code ec;

    const bool exists = std::filesystem::exists(wallet_path, ec);
    if (ec) {
        // stat() itself failed — typically a permissions problem on the
        // containing directory. We know nothing about the file, so this is the
        // "could not look" case, not the "nothing there" case.
        if (detail) *detail = ec.message();
        return WalletFileState::Unopenable;
    }
    if (!exists) return WalletFileState::Absent;

    ec.clear();
    if (!std::filesystem::is_regular_file(wallet_path, ec) || ec) {
        // A directory, fifo, or device at wallet_path. Never "empty" — a
        // directory has size 0 and would otherwise be silently overwritten.
        if (detail) *detail = "not a regular file";
        return WalletFileState::Invalid;
    }

    ec.clear();
    const std::uintmax_t size = std::filesystem::file_size(wallet_path, ec);
    if (ec) {
        if (detail) *detail = ec.message();
        return WalletFileState::Unopenable;
    }
    if (size < kWalletMagicBytes) return WalletFileState::Empty;

    // Open with stdio rather than ifstream purely so errno survives: an
    // ifstream that fails to open reports one undifferentiated failbit, and
    // distinguishing "locked" from "corrupt" is the whole point here.
    errno = 0;
    std::FILE* f = std::fopen(wallet_path.c_str(), "rb");
    if (f == nullptr) {
        if (detail) *detail = std::strerror(errno);
        return WalletFileState::Unopenable;
    }

    char magic[8] = {0};
    const size_t got = std::fread(magic, 1, sizeof(magic), f);
    const bool read_error = (std::ferror(f) != 0);
    std::fclose(f);

    if (read_error || got != sizeof(magic)) {
        // file_size() said there were at least 8 bytes and we could not read
        // them: a media error, or the file shrank underneath us. Retryable, and
        // fail-closed if it persists.
        if (detail) *detail = read_error ? "read error" : "short read";
        return WalletFileState::Unopenable;
    }

    if (!IsKnownWalletMagic(magic)) return WalletFileState::Invalid;
    return WalletFileState::Present;
}

// Classify, retrying ONLY while the answer is Unopenable. An antivirus scan, a
// backup snapshot, or a still-shutting-down sibling process holds the file for
// a fraction of a second; refusing to start for the lifetime of the install
// because of that window is the failure this exists to prevent. Every other
// state is a property of the file's contents and will not change by waiting, so
// it returns immediately — no start-up latency in the normal case.
//
// ~1.5s of total backoff: long enough to ride out a scanner, short enough that
// a genuinely locked file still reports promptly.
inline WalletFileState ClassifyWalletFileWithRetry(const std::string& wallet_path,
                                                   std::string* detail = nullptr,
                                                   int attempts = 5,
                                                   int first_delay_ms = 100) {
    WalletFileState state = WalletFileState::Unopenable;
    int delay_ms = first_delay_ms;
    for (int i = 0; i < attempts; ++i) {
        state = ClassifyWalletFileOnce(wallet_path, detail);
        if (state != WalletFileState::Unopenable) return state;
        if (i + 1 < attempts) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            delay_ms *= 2;
        }
    }
    return state;
}

#endif // DILITHION_WALLET_WALLET_LOAD_GUARD_H
