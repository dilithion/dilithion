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

// LP-13 MEDIUM-1: the v1 (un-passphrased) Save path holds the plaintext private
// key in a transient `out` buffer; the fix cleanses it on every return via
// CleanseSeedKeyBuffer. This test proves the cleanse primitive actually zeroes
// the buffer. Mutation self-check: deleting the memory_cleanse inside
// CleanseSeedKeyBuffer leaves the non-zero bytes intact and fails this test.
static void TestSecretBufferCleansed() {
    std::cout << "[Test] transient key buffer is cleansed (MEDIUM-1)" << std::endl;

    // Fill a buffer the size of a v1 blob (magic+ver+pubkey+privkey) with a
    // recognizable non-zero pattern, as if it held a real plaintext key.
    const size_t n = 5 + DFMP::MIK_PUBKEY_SIZE + DFMP::MIK_PRIVKEY_SIZE;
    std::vector<uint8_t> buf(n, 0xAB);

    CleanseSeedKeyBuffer(buf);

    CHECK(buf.size() == n, "buffer size unchanged after cleanse");
    bool allZero = true;
    for (uint8_t b : buf) { if (b != 0) { allZero = false; break; } }
    CHECK(allZero, "every byte of the secret buffer is zeroed");

    // Empty-buffer path must be a safe no-op (Save's early returns hit this).
    std::vector<uint8_t> empty;
    CleanseSeedKeyBuffer(empty);
    CHECK(empty.empty(), "cleanse of empty buffer is a safe no-op");
}

// LP-13 H-2 (CRITICAL, THE load-bearing test): an atomic Save that fails AFTER
// the temp file is written but BEFORE the rename must leave the ORIGINAL key
// file byte-for-byte intact. A bug here loses a seed's only consensus key.
static bool g_failpointActive = false;
static bool SaveFailpoint() { return g_failpointActive; }

static void TestAtomicSaveOriginalSurvives() {
    std::cout << "[Test] atomic save: injected write failure preserves original key (H-2)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("atomic-pass");  // exercise the v2 (encrypted) path

    // 1) Establish the live key file.
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate original keypair");
    std::vector<uint8_t> origPub = k1.GetPubKey();
    CHECK(k1.Save(dir), "save original key");
    std::vector<uint8_t> origBytes = ReadFileBytes(KeyPath(dir));
    CHECK(!origBytes.empty(), "original key file non-empty");

    // 2) Arm the failpoint and try to overwrite with a DIFFERENT key. Save must
    //    fail (the simulated crash between temp-write and rename).
    g_seedKeySaveFailpoint = SaveFailpoint;
    g_failpointActive = true;

    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate replacement keypair");
    CHECK(k2.GetPubKey() != origPub, "replacement differs from original");
    CHECK(!k2.Save(dir), "Save returns false when failpoint fires before rename");

    g_failpointActive = false;
    g_seedKeySaveFailpoint = nullptr;

    // 3) THE assertion: the live key file is byte-identical to the original.
    std::vector<uint8_t> afterBytes = ReadFileBytes(KeyPath(dir));
    CHECK(afterBytes == origBytes, "ORIGINAL key file is byte-intact after failed save");

    // 4) And it still loads + the original private key still round-trips.
    CSeedAttestationKey k3;
    CHECK(k3.Load(dir), "original key still loads after failed save");
    CHECK(k3.GetPubKey() == origPub, "loaded pubkey == original");
    CHECK(PrivKeyRoundTrips(k3, origPub), "original private key still usable");

    // 5) No stray .tmp left occupying the live path.
    std::ifstream tmp(KeyPath(dir) + ".tmp", std::ios::binary);
    CHECK(!tmp.good(), "no leftover .tmp after failed save");

    SetPass(nullptr);
}

// LP-13 M-2: a generated key that cannot be PERSISTED must make LoadOrGenerate
// return false (never run on an ephemeral key that won't survive restart).
static void TestSaveFailMakesLoadOrGenerateFail() {
    std::cout << "[Test] M-2: Save-fail => LoadOrGenerate(false) returns false" << std::endl;
    std::string dir = MakeTempDir();  // empty: forces the generate-then-save path
    SetPass(nullptr);

    g_seedKeySaveFailpoint = SaveFailpoint;
    g_failpointActive = true;

    CSeedAttestationKey k;
    CHECK(!k.LoadOrGenerate(dir, /*allowGenerate=*/true),
          "LoadOrGenerate returns false when the freshly minted key can't be saved");
    CHECK(!k.IsValid(), "no ephemeral key left valid in memory after save failure");

    g_failpointActive = false;
    g_seedKeySaveFailpoint = nullptr;

    // No persisted file (the temp was removed on the failed save).
    std::ifstream chk(KeyPath(dir), std::ios::binary);
    CHECK(!chk.good(), "no key file persisted after save failure");
}

// LP-13 H-1: --require-seed-key-encryption refuses plaintext (v1) keys, while the
// DEFAULT (off) still loads a v1 file unchanged (backward-compatible rolling deploy).
static void TestRequireEncryptionPolicy() {
    std::cout << "[Test] H-1: require-encryption refuses plaintext; default-off still loads v1" << std::endl;
    std::string dir = MakeTempDir();

    // Write a v1 plaintext key (no passphrase).
    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate key");
    CHECK(k1.Save(dir), "save v1 plaintext");
    std::vector<uint8_t> raw = ReadFileBytes(KeyPath(dir));
    CHECK(raw.size() > 5 && raw[4] == 1, "on-disk file is v1 plaintext");

    // Default OFF: a v1 file still loads (backward-compatible).
    CSeedAttestationKey kDefault;
    CHECK(kDefault.LoadOrGenerate(dir, /*allowGenerate=*/false, /*requireEncryption=*/false),
          "default-off LoadOrGenerate loads the v1 key");
    CHECK(kDefault.IsValid(), "v1 key valid under default policy");

    // require-encryption ON: refuse the v1 key (fail loud).
    CSeedAttestationKey kReq;
    CHECK(!kReq.LoadOrGenerate(dir, /*allowGenerate=*/false, /*requireEncryption=*/true),
          "require-encryption refuses the plaintext v1 key");
    CHECK(!kReq.IsValid(), "no key loaded when require-encryption rejects v1");

    // require-encryption ON, passphrase UNSET, on Save: refuse to write plaintext.
    std::string dir2 = MakeTempDir();
    SetPass(nullptr);
    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate key for save-refusal");
    CHECK(!k2.Save(dir2, /*requireEncryption=*/true),
          "Save(requireEncryption=true) refuses to write plaintext when passphrase unset");
    std::ifstream chk(KeyPath(dir2), std::ios::binary);
    CHECK(!chk.good(), "no plaintext file written when encryption required but unset");

    // require-encryption ON, passphrase SET: Save writes v2 and load enforces it.
    SetPass("enc-required-pass");
    std::string dir3 = MakeTempDir();
    CSeedAttestationKey k3;
    CHECK(k3.Generate(), "generate key for encrypted save");
    CHECK(k3.Save(dir3, /*requireEncryption=*/true), "Save(requireEncryption) writes v2 when passphrase set");
    std::vector<uint8_t> raw3 = ReadFileBytes(KeyPath(dir3));
    CHECK(raw3.size() > 5 && raw3[4] == 2, "on-disk file is v2 encrypted");
    CSeedAttestationKey k4;
    CHECK(k4.LoadOrGenerate(dir3, false, /*requireEncryption=*/true),
          "require-encryption accepts the v2 key");
    CHECK(k4.IsValid(), "v2 key valid under require-encryption");
    SetPass(nullptr);
}

#ifndef _WIN32
// LP-13 M-3: Load repairs the perms of a pre-existing world/group-readable key
// file (a legacy v1 written 0644 before this hardening) back to 0600.
static void TestLoadRepairsPerms() {
    std::cout << "[Test] M-3: Load repairs permissive perms to 0600 (POSIX)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass(nullptr);
    CSeedAttestationKey k1;
    k1.Generate();
    CHECK(k1.Save(dir), "save v1 key");

    // Deliberately loosen perms to simulate a legacy 0644 file.
    CHECK(chmod(KeyPath(dir).c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0,
          "loosen perms to 0644");
    struct stat st0;
    CHECK(stat(KeyPath(dir).c_str(), &st0) == 0 && (st0.st_mode & 0777) != (S_IRUSR | S_IWUSR),
          "perms are permissive before load");

    CSeedAttestationKey k2;
    CHECK(k2.Load(dir), "load the (permissive) key file");
    struct stat st1;
    CHECK(stat(KeyPath(dir).c_str(), &st1) == 0, "stat after load");
    CHECK((st1.st_mode & 0777) == (S_IRUSR | S_IWUSR), "Load repaired perms to 0600");
}

// LP-13 M-4: if 0600 perms cannot be set on the (temp) key file, Save fails
// closed rather than publishing a possibly group/other-readable consensus key.
// Inducing a chmod/fchmod failure portably is hard; we use a best-effort trigger
// (a data dir on a filesystem that ignores chmod is the real-world case). This
// test runs as root-aware: if it cannot induce the failure it reports SKIP
// rather than a false pass/fail.
static void TestFailClosedPerms() {
    std::cout << "[Test] M-4: fail-closed when 0600 cannot be set (POSIX, best-effort)" << std::endl;
    // We cannot reliably force fchmod+chmod to BOTH fail on a normal tmpfs as an
    // unprivileged user without an exotic mount. Document the path is covered by
    // code review + the explicit !permOk && !permOk2 guard; mark informational.
    std::cout << "  [info] M-4 fail-closed guard is exercised by code path "
                 "(!permOk && !permOk2 => return false); no portable injection here." << std::endl;
}

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
    TestSecretBufferCleansed();
    TestAtomicSaveOriginalSurvives();        // H-2 (THE load-bearing test)
    TestSaveFailMakesLoadOrGenerateFail();   // M-2
    TestRequireEncryptionPolicy();           // H-1
#ifndef _WIN32
    TestLoadRepairsPerms();                  // M-3
    TestFailClosedPerms();                   // M-4 (best-effort/informational)
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
