// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-13: seed-attestation private key at-rest hardening tests.
//
// Covers (per contract AC2-AC6, AC9):
//   - v2 encrypt -> decrypt round-trip (private key usable after reload)
//   - tampered ciphertext rejected (MAC fail)
//   - truncated file / empty MAC rejected
//   - wrong passphrase rejected cleanly
//   - v1 plaintext backward-compat load
//   - LoadOrGenerate auto-mint REFUSED without the flag, allowed with it
//   - (POSIX) saved key file is chmod 0600

#include <attestation/seed_attestation.h>
#include <dfmp/dfmp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#include <direct.h>
#endif

using namespace Attestation;

// Dilithium3 verify (same extern the production .cpp uses) — lets us prove the
// private key round-tripped by checking a signature it produced verifies under
// the saved public key.
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t* sig, size_t siglen,
                                          const uint8_t* m, size_t mlen,
                                          const uint8_t* ctx, size_t ctxlen,
                                          const uint8_t* pk);
}

static int g_failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::cerr << "  [FAIL] " << msg << std::endl; ++g_failures; } \
    else { std::cout << "  [ok] " << msg << std::endl; } \
} while (0)

// ---- temp dir helpers -------------------------------------------------------

static std::string MakeTempDir() {
#ifndef _WIN32
    char tmpl[] = "/tmp/lp13_seedkeyXXXXXX";
    char* d = mkdtemp(tmpl);
    if (!d) { std::cerr << "mkdtemp failed" << std::endl; std::exit(2); }
    return std::string(d);
#else
    // Windows: unique subdir under the system temp. A monotonic counter
    // guarantees uniqueness even when called faster than the clock resolution.
    static unsigned long s_counter = 0;
    std::string d = std::string(std::getenv("TEMP") ? std::getenv("TEMP") : ".")
                  + "\\lp13_seedkey_" + std::to_string(::GetCurrentProcessId())
                  + "_" + std::to_string((unsigned long long)::GetTickCount64())
                  + "_" + std::to_string(++s_counter);
    _mkdir(d.c_str());
    return d;
#endif
}

static std::string KeyPath(const std::string& dir) {
    return dir + "/" + SEED_KEY_FILENAME;
}

static std::vector<uint8_t> ReadFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static void WriteFileBytes(const std::string& path, const std::vector<uint8_t>& b) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), b.size());
}

static void SetPass(const char* v) {
#ifndef _WIN32
    if (v) setenv(SEED_KEY_PASSPHRASE_ENV, v, 1);
    else   unsetenv(SEED_KEY_PASSPHRASE_ENV);
#else
    std::string s = std::string(SEED_KEY_PASSPHRASE_ENV) + "=" + (v ? v : "");
    _putenv(s.c_str());
#endif
}

// Sign with `signer` and verify under `pubkey`. Proves the private key is intact.
static bool PrivKeyRoundTrips(const CSeedAttestationKey& signer,
                              const std::vector<uint8_t>& pubkey) {
    if (!signer.IsValid()) return false;
    std::vector<uint8_t> msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::vector<uint8_t> sig;
    if (!signer.Sign(msg, sig)) return false;
    int r = pqcrystals_dilithium3_ref_verify(sig.data(), sig.size(),
                                              msg.data(), msg.size(),
                                              nullptr, 0, pubkey.data());
    return r == 0;
}

// ---- tests ------------------------------------------------------------------

static void TestEncryptedRoundTrip() {
    std::cout << "[Test] v2 encrypted round-trip (AC2)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("correct horse battery staple");

    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate keypair");
    std::vector<uint8_t> pub = k1.GetPubKey();
    CHECK(k1.Save(dir), "save v2");

    // On-disk private key bytes must NOT appear in plaintext.
    std::vector<uint8_t> raw = ReadFileBytes(KeyPath(dir));
    CHECK(raw.size() > 5 && raw[4] == 2, "file version byte == 2 (encrypted)");

    CSeedAttestationKey k2;
    CHECK(k2.Load(dir), "load v2 with correct passphrase");
    CHECK(k2.GetPubKey() == pub, "pubkey matches after reload");
    CHECK(PrivKeyRoundTrips(k2, pub), "private key round-trips (sign+verify)");

    SetPass(nullptr);
}

static void TestWrongPassphrase() {
    std::cout << "[Test] wrong passphrase rejected (AC4)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("right-passphrase");
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v2");

    SetPass("WRONG-passphrase");
    CSeedAttestationKey k2;
    CHECK(!k2.Load(dir), "load fails (MAC mismatch) with wrong passphrase");
    CHECK(!k2.IsValid(), "key not partially loaded");
    SetPass(nullptr);
}

static void TestMissingPassphraseOnV2() {
    std::cout << "[Test] v2 file + no passphrase rejected (AC3 variant)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("a-passphrase");
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v2");

    SetPass(nullptr);  // unset
    CSeedAttestationKey k2;
    CHECK(!k2.Load(dir), "load fails when v2 but passphrase unset");
    CHECK(!k2.IsValid(), "key not loaded");
}

static void TestTamperedCiphertext() {
    std::cout << "[Test] tampered ciphertext rejected (AC3)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("tamper-pass");
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v2");

    std::vector<uint8_t> raw = ReadFileBytes(KeyPath(dir));
    CHECK(!raw.empty(), "read raw file");
    raw[raw.size() - 1] ^= 0xFF;  // flip last ciphertext byte
    WriteFileBytes(KeyPath(dir), raw);

    CSeedAttestationKey k2;
    CHECK(!k2.Load(dir), "load fails on tampered ciphertext");
    CHECK(!k2.IsValid(), "key not loaded after tamper");
    SetPass(nullptr);
}

static void TestTruncatedAndEmptyMac() {
    std::cout << "[Test] truncated / zeroed-MAC rejected (AC3)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("trunc-pass");
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v2");

    std::vector<uint8_t> full = ReadFileBytes(KeyPath(dir));

    // Truncate to half -> header/length checks must reject.
    std::vector<uint8_t> trunc(full.begin(), full.begin() + full.size() / 2);
    WriteFileBytes(KeyPath(dir), trunc);
    CSeedAttestationKey kt;
    CHECK(!kt.Load(dir), "load fails on truncated file");

    // Zero out the 64-byte MAC field (offset 5 + 1952 pubkey + 16 salt + 16 iv).
    std::vector<uint8_t> zmac = full;
    size_t macOff = 5 + DFMP::MIK_PUBKEY_SIZE + 16 + 16;
    if (zmac.size() >= macOff + 64) {
        for (size_t i = 0; i < 64; ++i) zmac[macOff + i] = 0;
        WriteFileBytes(KeyPath(dir), zmac);
        CSeedAttestationKey kz;
        CHECK(!kz.Load(dir), "load fails on zeroed MAC");
    } else {
        std::cerr << "  [FAIL] file too small to locate MAC" << std::endl;
        ++g_failures;
    }
    SetPass(nullptr);
}

static void TestV1BackwardCompat() {
    std::cout << "[Test] v1 plaintext backward-compat load (AC5)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass(nullptr);  // no passphrase => Save writes v1 plaintext
    CSeedAttestationKey k1;
    k1.Generate();
    std::vector<uint8_t> pub = k1.GetPubKey();
    CHECK(k1.Save(dir), "save v1 (no passphrase)");

    std::vector<uint8_t> raw = ReadFileBytes(KeyPath(dir));
    CHECK(raw.size() > 5 && raw[4] == 1, "file version byte == 1 (plaintext)");

    CSeedAttestationKey k2;
    CHECK(k2.Load(dir), "load v1 plaintext");
    CHECK(k2.GetPubKey() == pub, "pubkey matches");
    CHECK(PrivKeyRoundTrips(k2, pub), "v1 private key round-trips");
}

static void TestAutoMintGate() {
    std::cout << "[Test] auto-mint refused without flag (AC6)" << std::endl;
    std::string dir = MakeTempDir();  // empty dir, no key file
    SetPass(nullptr);

    CSeedAttestationKey k1;
    CHECK(!k1.LoadOrGenerate(dir, /*allowGenerate=*/false),
          "LoadOrGenerate(false) on missing key FAILS LOUD");
    CHECK(!k1.IsValid(), "no key minted when flag absent");

    std::ifstream chk(KeyPath(dir), std::ios::binary);
    CHECK(!chk.good(), "no key file written when flag absent");

    CSeedAttestationKey k2;
    CHECK(k2.LoadOrGenerate(dir, /*allowGenerate=*/true),
          "LoadOrGenerate(true) mints + saves");
    CHECK(k2.IsValid(), "key valid after permitted mint");

    // Second call now LOADS the persisted key even without the flag.
    CSeedAttestationKey k3;
    CHECK(k3.LoadOrGenerate(dir, /*allowGenerate=*/false),
          "subsequent LoadOrGenerate(false) loads the existing key");
    CHECK(k3.GetPubKey() == k2.GetPubKey(), "loaded key matches minted key");
}

#ifndef _WIN32
static void TestPosixPerms() {
    std::cout << "[Test] POSIX key file is 0600 (AC1)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("perms-pass");
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v2");

    struct stat st;
    CHECK(stat(KeyPath(dir).c_str(), &st) == 0, "stat key file");
    mode_t perms = st.st_mode & 0777;
    CHECK(perms == (S_IRUSR | S_IWUSR), "perms == 0600");

    // Also verify v1 path sets 0600.
    SetPass(nullptr);
    std::string dir2 = MakeTempDir();
    CSeedAttestationKey k2;
    k2.Generate();
    CHECK(k2.Save(dir2), "save v1");
    struct stat st2;
    CHECK(stat(KeyPath(dir2).c_str(), &st2) == 0, "stat v1 key file");
    CHECK((st2.st_mode & 0777) == (S_IRUSR | S_IWUSR), "v1 perms == 0600");
}
#endif

int main() {
    std::cout << "=== LP-13 seed_attestation_key_tests ===" << std::endl;

    TestEncryptedRoundTrip();
    TestWrongPassphrase();
    TestMissingPassphraseOnV2();
    TestTamperedCiphertext();
    TestTruncatedAndEmptyMac();
    TestV1BackwardCompat();
    TestAutoMintGate();
#ifndef _WIN32
    TestPosixPerms();
#endif

    std::cout << "=========================================" << std::endl;
    if (g_failures == 0) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    }
    std::cerr << g_failures << " CHECK(S) FAILED" << std::endl;
    return 1;
}
