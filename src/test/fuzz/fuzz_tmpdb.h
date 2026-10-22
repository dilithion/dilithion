// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_TEST_FUZZ_FUZZ_TMPDB_H
#define DILITHION_TEST_FUZZ_FUZZ_TMPDB_H

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

#include <unistd.h>

/**
 * Scratch database directories for fuzz harnesses that open a CUTXOSet.
 *
 * CUTXOSet::Open() always goes through the regular LevelDB code path and
 * Close() writes with sync=true, so on a disk-backed /tmp every input pays for
 * several fsyncs. The scratch directories are placed on a memory-backed
 * filesystem (/dev/shm) when one is available, which keeps the code under test
 * identical while making the syncs cheap. Falls back to the system temp
 * directory otherwise.
 *
 * Each process owns one root directory. libFuzzer ends the process with
 * _exit(), so no atexit handler can be relied on; instead every FuzzTmpDbDir
 * creates the root if needed, uses a fresh, uniquely named subdirectory, and on
 * destruction (including early return and exceptions) removes that subdirectory
 * and then the root if it is empty. No state is carried between inputs and
 * nothing is left behind after the last input.
 *
 * Declare the FuzzTmpDbDir before the CUTXOSet so the database is closed
 * before its directory is deleted.
 */
class FuzzTmpDbDir {
public:
    FuzzTmpDbDir() : path_(Root() + "/db" + std::to_string(counter_.fetch_add(1))) {
        std::error_code ec;
        std::filesystem::create_directories(Root(), ec);
    }
    ~FuzzTmpDbDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
        std::filesystem::remove(Root(), ec);  // only succeeds when empty
    }
    FuzzTmpDbDir(const FuzzTmpDbDir&) = delete;
    FuzzTmpDbDir& operator=(const FuzzTmpDbDir&) = delete;

    const std::string& path() const { return path_; }

private:
    static const std::string& Root() {
        static const std::string root = MakeRoot();
        return root;
    }

    static std::string MakeRoot() {
        std::error_code ec;
        std::filesystem::path base = "/dev/shm";
        if (!std::filesystem::is_directory(base, ec) || ::access(base.c_str(), W_OK) != 0) {
            base = std::filesystem::temp_directory_path(ec);
            if (ec) base = "/tmp";
        }
        RemoveStaleRoots(base);
        return (base / (kRootPrefix + std::to_string(::getpid()))).string();
    }

    // A process killed mid-input (crash, timeout, or libFuzzer's time limit)
    // cannot clean up after itself, so the next run removes roots whose owning
    // process no longer exists.
    static void RemoveStaleRoots(const std::filesystem::path& base) {
        std::error_code ec;
        for (std::filesystem::directory_iterator it(base, ec), end; !ec && it != end; it.increment(ec)) {
            const std::string name = it->path().filename().string();
            if (name.compare(0, kRootPrefix.size(), kRootPrefix) != 0) continue;
            const long pid = std::strtol(name.c_str() + kRootPrefix.size(), nullptr, 10);
            if (pid <= 0 || (::kill(static_cast<pid_t>(pid), 0) == 0 || errno != ESRCH)) continue;
            std::error_code rm_ec;
            std::filesystem::remove_all(it->path(), rm_ec);
        }
    }

    static inline const std::string kRootPrefix = "dilithion_fuzz_";
    static inline std::atomic<unsigned long> counter_{0};
    std::string path_;
};

#endif // DILITHION_TEST_FUZZ_FUZZ_TMPDB_H
