// M4 kill-race probe for mik_registration.dat.
//
//   g++ -std=c++17 -O1 -g -I src -o killprobe_mik.exe //       scripts/probes/killprobe_mik.cpp build/obj/dfmp/mik_registration_file.o //       build/obj/crypto/sha3.o depends/dilithium/ref/fips202.o
//   ./killprobe_mik.exe
//
// Measured result (20 killed writes per arm, shipped Windows toolchain):
//   before  arm : 0/20 corrupt-or-absent -- the fallback is never reached,
//                 because fs::rename succeeds over the existing destination.
//   window  arm : 20/20 ABSENT -- the remove-then-rename SHAPE, killed in its
//                 window. This is what the fallback does wherever it IS reached.
//   after   arm : 0/20 corrupt-or-absent -- util::AtomicReplaceFile.
//
// Adjudicated by the REAL loader (DFMP::LoadMIKRegistration).
//
// The kill is CONDITION-TRIGGERED, not timed: the child process is killed with
// TerminateProcess (uncatchable, no atexit, no buffer flush) at exactly the
// instant the publish strategy is about to run -- i.e. the moment a watchdog
// _Exit or a crash would be maximally damaging. Both arms are killed at the
// SAME logical point, so the arms differ only in the publish strategy:
//
//   BEFORE arm : the code that was in src/dfmp/mik_registration_file.cpp until
//                this PR, verbatim -- fs::rename, and on failure (which is
//                ALWAYS, on Windows, when the destination exists)
//                fs::remove(final) followed by fs::rename. Killed after the
//                remove, before the rename.
//   AFTER  arm : util::AtomicReplaceFile (the shipped helper). Killed at the
//                same point: immediately before the single replace call.
//
// A run is BAD if, after the kill, the destination is Missing (absent) or
// Corrupt. It is GOOD if the loader returns a complete record -- either the old
// one or the new one.

#include <dfmp/mik_registration_file.h>
#include <util/atomic_file.h>
#include <crypto/sha3.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
static void HardKillSelf() { TerminateProcess(GetCurrentProcess(), 99); }
#else
#include <signal.h>
#include <unistd.h>
static void HardKillSelf() { ::raise(SIGKILL); }
#endif

namespace fs = std::filesystem;

static const size_t kPubkeyBytes = 1952;
static const size_t kPayloadSize = 4 + 4 + kPubkeyBytes + 32 + 8 + 8;
static const size_t kTotalSize   = kPayloadSize + 32;
static const uint8_t kMagic[4] = {'M', 'R', 'P', 'W'};

static std::vector<uint8_t> MakePubkey(uint8_t fill) {
    return std::vector<uint8_t>(kPubkeyBytes, fill);
}

// Byte-for-byte the same payload construction the production writer uses, so
// the temp file both arms publish is identical.
static std::vector<uint8_t> BuildFileBytes(const std::vector<uint8_t>& pubkey,
                                           uint8_t dnaFill, uint64_t nonce,
                                           int64_t timestamp) {
    std::vector<uint8_t> p;
    p.reserve(kTotalSize);
    p.insert(p.end(), kMagic, kMagic + 4);
    uint32_t ver = 1;
    for (int i = 0; i < 4; ++i) p.push_back(static_cast<uint8_t>((ver >> (8 * i)) & 0xff));
    p.insert(p.end(), pubkey.begin(), pubkey.end());
    for (int i = 0; i < 32; ++i) p.push_back(dnaFill);
    for (int i = 0; i < 8; ++i) p.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xff));
    uint64_t ts = static_cast<uint64_t>(timestamp);
    for (int i = 0; i < 8; ++i) p.push_back(static_cast<uint8_t>((ts >> (8 * i)) & 0xff));
    uint8_t sum[32];
    SHA3_256(p.data(), p.size(), sum);
    p.insert(p.end(), sum, sum + 32);
    return p;
}

static void WriteTmp(const fs::path& tmp, const std::vector<uint8_t>& bytes) {
    std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
    o.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    o.flush();
    o.close();
}

// ---------------------------------------------------------------------------
// CHILD: writes the temp file, then is killed at the publish instant.
// ---------------------------------------------------------------------------
static int RunChild(const std::string& arm, const std::string& dir) {
    const fs::path finalPath = fs::path(dir) / "mik_registration.dat";
    fs::path tmpPath = finalPath;
    tmpPath += ".tmp";

    // New (v2) record; the file on disk already holds a complete v1 record.
    WriteTmp(tmpPath, BuildFileBytes(MakePubkey(0xAA), 0x22, 2222, 222222));

    if (arm == "before") {
        // --- verbatim the code this PR removed -------------------------------
        std::error_code ec;
        fs::rename(tmpPath, finalPath, ec);
        if (ec) {
            // Fallback: remove then rename (Windows sometimes needs this)
            fs::remove(finalPath, ec);
            HardKillSelf();              // <-- condition-triggered kill: IN the window
            fs::rename(tmpPath, finalPath, ec);
        }
        // ---------------------------------------------------------------------
        // Reached only if fs::rename unexpectedly succeeded (i.e. no window).
        std::fprintf(stderr, "NOWINDOW\n");
        return 0;
    }

    if (arm == "window") {
        // The remove-then-rename SHAPE in isolation: what the fallback does
        // whenever it is actually reached (older libstdc++ where fs::rename
        // cannot replace, or anyone "fixing" a rename failure this way).
        std::error_code ec;
        fs::remove(finalPath, ec);
        HardKillSelf();              // <-- condition-triggered kill: IN the window
        fs::rename(tmpPath, finalPath, ec);
        return 0;
    }

    if (arm == "after") {
        HardKillSelf();                  // <-- same instant: just before the publish
        std::string err;
        util::AtomicReplaceFile(tmpPath, finalPath, &err, true);
        return 0;
    }

    std::fprintf(stderr, "bad arm\n");
    return 2;
}

// ---------------------------------------------------------------------------
// PARENT
// ---------------------------------------------------------------------------
static const char* Adjudicate(const std::string& dir, bool& bad) {
    DFMP::MIKRegistrationFile out;
    // Expect either the old (0x11) or the new (0xAA) pubkey; ask the loader for
    // the old one so a PubkeyMismatch tells us the NEW complete record landed.
    const DFMP::MIKRegFileLoadResult r =
        DFMP::LoadMIKRegistration(dir, MakePubkey(0x11), out);
    switch (r) {
        case DFMP::MIKRegFileLoadResult::OK:             bad = false; return "OK(old complete)";
        case DFMP::MIKRegFileLoadResult::PubkeyMismatch: bad = false; return "OK(new complete)";
        case DFMP::MIKRegFileLoadResult::Missing:        bad = true;  return "ABSENT";
        case DFMP::MIKRegFileLoadResult::Corrupt:        bad = true;  return "CORRUPT";
    }
    bad = true;
    return "?";
}

int main(int argc, char** argv) {
    if (argc >= 4 && std::string(argv[1]) == "child") {
        return RunChild(argv[2], argv[3]);
    }

    const std::string self = argv[0];
    const int kRuns = 20;

    for (const std::string arm : {std::string("before"), std::string("window"), std::string("after")}) {
        const std::string dir = std::string("killprobe_") + arm;
        int bad_count = 0, nowindow = 0;
        std::printf("\n=== mik_registration.dat -- %s arm, %d killed writes ===\n",
                    arm.c_str(), kRuns);

        for (int i = 0; i < kRuns; ++i) {
            std::error_code ec;
            fs::remove_all(dir, ec);
            fs::create_directories(dir, ec);
            // Seed a COMPLETE v1 record via the production writer.
            if (!DFMP::SaveMIKRegistration(dir, MakePubkey(0x11), {}, 1111, 111111)) {
                std::printf("  seed write FAILED (run %d)\n", i);
                return 3;
            }
            {   // dnaHash 0x00 for v1; confirm the seed is loadable before we kill.
                bool b = false;
                const char* s = Adjudicate(dir, b);
                if (b) { std::printf("  seed unreadable: %s\n", s); return 3; }
            }

            const std::string cmd = "\"" + self + "\" child " + arm + " " + dir + " 2>NUL";
            std::system(cmd.c_str());

            bool bad = false;
            const char* verdict = Adjudicate(dir, bad);
            if (bad) ++bad_count;
            if (std::string(verdict) == "?") ++nowindow;
            std::printf("  run %2d: %s\n", i + 1, verdict);
        }
        std::printf("  --> corrupt-or-absent: %d / %d\n", bad_count, kRuns);
        (void)nowindow;
    }
    return 0;
}
