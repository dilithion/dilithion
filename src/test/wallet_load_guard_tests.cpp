// ============================================================================
// wallet_load_guard_tests — classification of wallet.dat before CWallet::Load()
//
// The shell suite (scripts/wallet_load_guard_test.sh) drives the real binary and
// proves the end-to-end behaviour. It cannot deterministically produce a
// TRANSIENT open failure: the lock would have to be released inside the exact
// window where the node happens to be doing wallet init, twenty-odd seconds
// into startup. That retry is the whole difference between "an antivirus scan
// costs you a second" and "an antivirus scan bricks your node", so it gets a
// deterministic test here, where the lock and the classifier are in one process.
//
// Header-only under test — no chain, no wallet, no datadir.
// ============================================================================

#include <wallet/wallet_load_guard.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

static int g_failed = 0;

static void check(bool ok, const std::string& what) {
    std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << what << std::endl;
    if (!ok) g_failed = 1;
}

static const char* StateName(WalletFileState s) {
    switch (s) {
        case WalletFileState::Absent: return "Absent";
        case WalletFileState::Empty: return "Empty";
        case WalletFileState::Unopenable: return "Unopenable";
        case WalletFileState::Invalid: return "Invalid";
        case WalletFileState::Present: return "Present";
    }
    return "?";
}

static void expect_state(const std::string& path, WalletFileState want,
                         const std::string& what) {
    const WalletFileState got = ClassifyWalletFileOnce(path, nullptr);
    check(got == want,
          what + " (want " + StateName(want) + ", got " + StateName(got) + ")");
}

static void write_bytes(const std::string& path, const char* data, size_t n) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(data, static_cast<std::streamsize>(n));
}

int main() {
    std::cout << "=== wallet_load_guard_tests ===" << std::endl;

    const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "dil_wallet_guard_tests";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);

    const std::string absent = (dir / "absent.dat").string();
    expect_state(absent, WalletFileState::Absent, "missing file is Absent");

    const std::string empty = (dir / "empty.dat").string();
    write_bytes(empty, "", 0);
    expect_state(empty, WalletFileState::Empty, "0-byte file is Empty");

    // Below the 8-byte magic: cannot be a wallet of any version, so no keys can
    // be lost by proceeding.
    const std::string shortf = (dir / "short.dat").string();
    write_bytes(shortf, "DILW", 4);
    expect_state(shortf, WalletFileState::Empty, "sub-magic file is Empty");

    // BOUND, the other way. Eight bytes of VALID magic is a wallet — truncated,
    // but a wallet — and must reach Load() and its fail-closed refusal, never
    // the "nothing here, overwrite freely" path.
    const std::string magic_only = (dir / "magic_only.dat").string();
    write_bytes(magic_only, "DILWLT07", 8);
    expect_state(magic_only, WalletFileState::Present,
                 "exactly-the-magic file is Present, not Empty");

    // Every shipped format version must be recognised, or upgrading users get
    // told their wallet is corrupt.
    static const char* kAll[] = {"DILWLT01", "DILWLT02", "DILWLT03", "DILWLT04",
                                 "DILWLT05", "DILWLT06", "DILWLT07"};
    bool all_ok = true;
    for (const char* m : kAll) {
        const std::string p = (dir / (std::string(m) + ".dat")).string();
        write_bytes(p, m, 8);
        if (ClassifyWalletFileOnce(p, nullptr) != WalletFileState::Present) all_ok = false;
    }
    check(all_ok, "all seven wallet magics DILWLT01..07 classify as Present");

    const std::string garbage = (dir / "garbage.dat").string();
    write_bytes(garbage, "NOT A WALLET AT ALL", 19);
    expect_state(garbage, WalletFileState::Invalid, "non-empty bad magic is Invalid");

    // One byte off must not be accepted.
    const std::string near_miss = (dir / "near.dat").string();
    write_bytes(near_miss, "DILWLT08", 8);
    expect_state(near_miss, WalletFileState::Invalid, "unknown version magic is Invalid");

    // A directory has size 0. If it were classified Empty the node would sail
    // past it and try to Save() a wallet over a directory.
    const std::string as_dir = (dir / "dir.dat").string();
    std::filesystem::create_directory(as_dir, ec);
    expect_state(as_dir, WalletFileState::Invalid, "a directory is Invalid, never Empty");

    // ------------------------------------------------------------------
    // Transient open failure: the case this whole change exists for.
    // ------------------------------------------------------------------
    const std::string locked = (dir / "locked.dat").string();
    write_bytes(locked, "NOT A WALLET AT ALL", 19);

#ifdef _WIN32
    // Exclusive share mode — exactly what an antivirus scanner or a backup
    // agent does to a file mid-scan.
    HANDLE h = CreateFileA(locked.c_str(), GENERIC_READ, 0 /*no sharing*/, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool can_lock = (h != INVALID_HANDLE_VALUE);
    auto unlock = [&]() { if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; } };
    auto relock = [&]() {
        h = CreateFileA(locked.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
        return h != INVALID_HANDLE_VALUE;
    };
#else
    // chmod is a no-op for root, so the arms below are only meaningful for an
    // unprivileged user.
    const bool can_lock = (geteuid() != 0) && (::chmod(locked.c_str(), 0) == 0);
    auto unlock = [&]() { ::chmod(locked.c_str(), 0644); };
    auto relock = [&]() { return ::chmod(locked.c_str(), 0) == 0; };
#endif

    if (!can_lock) {
        std::cout << "  [SKIP] lock arms — cannot deny reads to this process "
                     "(running as root, or no OS support here). Not a verdict."
                  << std::endl;
    } else {
        check(ClassifyWalletFileOnce(locked, nullptr) == WalletFileState::Unopenable,
              "a file that cannot be opened is Unopenable, not Invalid");

        std::string detail;
        ClassifyWalletFileOnce(locked, &detail);
        check(!detail.empty(), "Unopenable carries a reason string for the user");

        // TRANSIENT: released after ~250ms, well inside the ~1.5s of backoff.
        // The classifier must ride it out and return the file's REAL state.
        std::atomic<bool> released{false};
        std::thread releaser([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            unlock();
            released.store(true);
        });
        const auto t0 = std::chrono::steady_clock::now();
        const WalletFileState transient = ClassifyWalletFileWithRetry(locked, nullptr);
        const auto elapsed = std::chrono::steady_clock::now() - t0;
        releaser.join();
        check(released.load() && transient == WalletFileState::Invalid,
              std::string("a lock released after 250ms is ridden out, not fatal (got ") +
                  StateName(transient) + ")");
        // Guard against a "fix" that simply waits the full backoff every time:
        // that would add seconds to every single startup.
        check(elapsed < std::chrono::seconds(3),
              "retry returns as soon as the lock clears, not after the full backoff");

        // PERSISTENT: still fails after every attempt, and reports the lock —
        // the fail-closed direction must survive the retry loop.
        check(relock(), "re-locked for the persistent arm");
        const auto t1 = std::chrono::steady_clock::now();
        const WalletFileState persistent = ClassifyWalletFileWithRetry(locked, nullptr);
        const auto persist_elapsed = std::chrono::steady_clock::now() - t1;
        unlock();
        check(persistent == WalletFileState::Unopenable,
              "a lock that never clears stays Unopenable (fail closed)");
        // It must actually have retried; returning instantly would mean the
        // backoff loop is not wired up at all.
        check(persist_elapsed > std::chrono::milliseconds(400),
              "the persistent case really did retry with backoff before giving up");
    }

    // A never-openable path must not be mistaken for Absent by the exists()
    // probe: Absent is the ONE state that authorises overwriting.
    check(ClassifyWalletFileOnce(absent, nullptr) == WalletFileState::Absent,
          "Absent is still Absent after the lock arms (no state leakage)");

    std::filesystem::remove_all(dir, ec);

    std::cout << (g_failed ? "=== FAILED ===" : "=== all wallet_load_guard tests passed ===")
              << std::endl;
    return g_failed;
}
