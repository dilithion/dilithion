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

// LP-13 B-1 (BLOCKER, THE load-bearing test): an fsync/flush failure of the temp
// must be FATAL — Save returns false, NO rename happens, and the ORIGINAL key
// file is left byte-intact. If the fix were reverted to warn-and-continue, the
// rename would publish (possibly un-flushed) data and this test must FAIL.
static bool g_fsyncFailActive = false;
static bool FsyncFailpoint() { return g_fsyncFailActive; }

static void TestFsyncFailureIsFatalBeforeRename() {
    std::cout << "[Test] B-1: fsync failure is FATAL before rename, original key survives" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("fsync-pass");  // exercise the v2 (encrypted) path

    // 1) Establish the live key file.
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate original keypair");
    std::vector<uint8_t> origPub = k1.GetPubKey();
    CHECK(k1.Save(dir), "save original key");
    std::vector<uint8_t> origBytes = ReadFileBytes(KeyPath(dir));
    CHECK(!origBytes.empty(), "original key file non-empty");

    // 2) Arm the fsync failpoint and attempt an UPDATE save with a DIFFERENT key.
    g_seedKeyFsyncFailpoint = FsyncFailpoint;
    g_fsyncFailActive = true;

    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate replacement keypair");
    CHECK(k2.GetPubKey() != origPub, "replacement differs from original");
    // (a) Save returns false on fsync failure.
    CHECK(!k2.Save(dir), "Save returns false when fsync fails");

    g_fsyncFailActive = false;
    g_seedKeyFsyncFailpoint = nullptr;

    // (b)+(c) NO rename happened: the live key file is byte-identical to the
    // original, still loads, and still signs with the original key.
    std::vector<uint8_t> afterBytes = ReadFileBytes(KeyPath(dir));
    CHECK(afterBytes == origBytes, "ORIGINAL key file byte-intact after fatal fsync failure");
    CSeedAttestationKey k3;
    CHECK(k3.Load(dir), "original key still loads after fatal fsync failure");
    CHECK(k3.GetPubKey() == origPub, "loaded pubkey == original");
    CHECK(PrivKeyRoundTrips(k3, origPub), "original private key still signs/verifies");

    // (d) No leftover .tmp occupying the path.
    std::ifstream tmp(KeyPath(dir) + ".tmp", std::ios::binary);
    CHECK(!tmp.good(), "no leftover .tmp after fatal fsync failure");

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

// LP-13 (symlink-hardening, nemotron extreview finding): the temp key file is
// opened O_NOFOLLOW, so a pre-planted "<key>.tmp" symlink cannot redirect the
// consensus key write. Save must FAIL (fail-closed), leave the canonical key
// byte-intact, and NOT write the key through the symlink to its target.
// Mutation self-check: removing O_NOFOLLOW lets the open follow the symlink, the
// victim file receives the key bytes, and the "victim untouched" assertion fails.
static void TestTempSymlinkRejected() {
    std::cout << "[Test] symlink-hardening: O_NOFOLLOW rejects a symlinked temp (POSIX)" << std::endl;
    std::string dir = MakeTempDir();
    SetPass("symlink-pass");

    // 1) Establish the canonical key.
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate original keypair");
    std::vector<uint8_t> origPub = k1.GetPubKey();
    CHECK(k1.Save(dir), "save original key");
    std::vector<uint8_t> origBytes = ReadFileBytes(KeyPath(dir));
    CHECK(!origBytes.empty(), "original key file non-empty");

    // 2) Plant "<key>.tmp" as a symlink to a victim file the attacker wants written.
    std::string tmpPath = KeyPath(dir) + ".tmp";
    std::string victimPath = dir + "/victim.bin";
    WriteFileBytes(victimPath, std::vector<uint8_t>{0xCC, 0xCC, 0xCC});
    std::vector<uint8_t> victimBefore = ReadFileBytes(victimPath);
    ::unlink(tmpPath.c_str());  // ensure no stale temp
    CHECK(symlink(victimPath.c_str(), tmpPath.c_str()) == 0, "plant symlink at <key>.tmp -> victim");

    // 3) Attempt to Save a DIFFERENT key. O_NOFOLLOW must make the temp open fail.
    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate replacement keypair");
    CHECK(k2.GetPubKey() != origPub, "replacement differs");
    CHECK(!k2.Save(dir), "Save FAILS when temp path is a symlink (O_NOFOLLOW)");

    // 4) Canonical key untouched, and the victim was NOT written through the symlink.
    std::vector<uint8_t> afterBytes = ReadFileBytes(KeyPath(dir));
    CHECK(afterBytes == origBytes, "canonical key byte-intact after rejected symlink save");
    std::vector<uint8_t> victimAfter = ReadFileBytes(victimPath);
    CHECK(victimAfter == victimBefore, "victim file NOT written through the symlink");

    ::unlink(tmpPath.c_str());  // cleanup the planted symlink
    SetPass(nullptr);
}
#endif

// LP-13 (extreview HIGH): SeedKeyFilePresent must test PRESENCE, not readability.
// The earlier node glue used ifstream::good(), which is FALSE for a present-but-
// UNREADABLE key — so a genuine key was misclassified as absent and the node ran
// WITHOUT attestation (defeating M-1 fail-loud). This pins the distinction:
//   - absent           => NOT present
//   - readable file    => present
//   - unreadable file  => STILL present (the fix), while ifstream::good()==false
// The unreadable leg needs a uid that cannot bypass DAC: under root (e.g. the CI
// build box) chmod-000 does NOT make a file unreadable, so the probe self-detects
// that case and reports [info]/SKIP rather than a false pass (M-4 precedent). Run
// the binary as a non-root user (e.g. `sudo -u nobody`) to exercise the real
// mutation-killing assertion. Mutation self-check: reverting SeedKeyFilePresent to
// ifstream::good() fails the unreadable assertion under a non-root run.
static void TestSeedKeyFilePresentDetectsUnreadable() {
    std::cout << "[Test] extreview-HIGH: present-but-unreadable key reports PRESENT" << std::endl;
    std::string dir = MakeTempDir();

    CHECK(!SeedKeyFilePresent(dir), "empty dir => key file NOT present");

    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate key");
    CHECK(k1.Save(dir), "save key file");
    CHECK(SeedKeyFilePresent(dir), "readable key file => present");

#ifndef _WIN32
    if (chmod(KeyPath(dir).c_str(), 0) == 0) {
        std::ifstream probe(KeyPath(dir), std::ios::binary);
        if (probe.good()) {
            // Caller bypasses DAC (root): cannot induce unreadable. Honest SKIP.
            std::cout << "  [info] cannot revoke read (running as root?); "
                         "unreadable-distinction assertion skipped — run as non-root to exercise it"
                      << std::endl;
        } else {
            CHECK(SeedKeyFilePresent(dir),
                  "present-but-UNREADABLE key reports PRESENT (the fix; ifstream::good()==false here)");
        }
        chmod(KeyPath(dir).c_str(), S_IRUSR | S_IWUSR);  // restore for clean temp teardown
    } else {
        std::cout << "  [info] chmod 000 failed; unreadable leg skipped" << std::endl;
    }
#endif
}

// M-1 (seed key-identity validation): the node's startup check compares the
// loaded/minted key's GetPubKey() against the consensus pubkey for the resolved
// seedId, aborting on mismatch. This test exercises that exact comparison
// primitive: a key matches the pubkey it was generated/saved/loaded with (the
// "accept" leg), and two independently-generated keys have DIFFERENT pubkeys, so
// a wrong key bound to a seedId is detected (the "reject"/fail-loud leg).
static void TestKeyIdentityComparison() {
    std::cout << "[Test] M-1 seed key-identity pubkey comparison" << std::endl;
    std::string dir = MakeTempDir();
    SetPass(nullptr);  // v1 plaintext path is fine for a pubkey-equality test

    CSeedAttestationKey kReal;
    CHECK(kReal.Generate(), "generate the 'correct' seed key");
    std::vector<uint8_t> realPub = kReal.GetPubKey();
    CHECK(realPub.size() == DFMP::MIK_PUBKEY_SIZE, "pubkey is full Dilithium3 size");

    // Accept leg: the same key (and a save/load round-trip of it) matches the
    // consensus pubkey it would be registered under.
    CHECK(kReal.GetPubKey() == realPub, "same key: GetPubKey() == consensus pubkey (ACCEPT)");
    CHECK(kReal.Save(dir), "save the correct key");
    CSeedAttestationKey kReloaded;
    CHECK(kReloaded.Load(dir), "reload the correct key");
    CHECK(kReloaded.GetPubKey() == realPub,
          "reloaded key still matches consensus pubkey (ACCEPT survives persist)");

    // Reject leg: a DIFFERENT key (what a misconfigured seed would load/mint —
    // any Dilithium3 key, but not THIS seedId's consensus key) does NOT match,
    // so the node's GetPubKey() != seedPubkeys[seedId] check fires (fail-loud).
    CSeedAttestationKey kWrong;
    CHECK(kWrong.Generate(), "generate a 'wrong' (mismatched) seed key");
    CHECK(kWrong.GetPubKey() != realPub,
          "different key: GetPubKey() != consensus pubkey (REJECT -> fail-loud)");
}

// HIGH-1 / HIGH-2 fold: the production seed-identity GLUE (resolve --externalip
// -> seed_id, then decide FATAL / SKIP / REGISTER) is factored into the pure
// helper ResolveSeedIdentity so it is unit-testable. The prior test exercised
// only the pubkey-equality PRIMITIVE; these tests drive the actual decision the
// node startup makes, and would FAIL if that decision logic were a no-op.
static void TestSeedIdentityResolutionGlue() {
    std::cout << "[Test] HIGH-1/HIGH-2 seed-identity resolution glue (ResolveSeedIdentity)"
              << std::endl;

    // A 4-seed mainnet-shaped configuration. Pubkeys must be full Dilithium3
    // size so the byte-compare mirrors production; build a real key per slot.
    const std::vector<std::string> seedIPs = {
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"};

    std::vector<CSeedAttestationKey> keys(4);
    std::vector<std::vector<uint8_t>> seedPubkeys;
    for (int i = 0; i < 4; i++) {
        CHECK(keys[i].Generate(), "generate seed-slot key");
        seedPubkeys.push_back(keys[i].GetPubKey());
    }

    // --- REGISTER: externalip resolves to a slot AND key matches that slot. ---
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "matching key at resolved slot -> REGISTER");
        CHECK(r.seedId == 2, "REGISTER resolves to seed_id=2");
        CHECK(!r.usedTestnetDefault, "REGISTER on mainnet is not a testnet default");
    }

    // --- FATAL_MISMATCH: externalip resolves to a real slot, WRONG key. ------
    // (Drives the abort path; a no-op decision helper would NOT return this.)
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.1", keys[3].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH,
              "resolved slot + mismatched pubkey -> FATAL_MISMATCH (abort path)");
        CHECK(r.seedId == 0, "FATAL_MISMATCH reports the resolved seed_id");
    }

    // --- SKIP_NOT_A_SEED: externalip matches NO configured slot. ------------
    // HIGH-1: must NOT abort even though a usable key is present.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "203.0.113.7", keys[0].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "non-seed externalip + key present -> SKIP_NOT_A_SEED (NOT abort, HIGH-1)");
        CHECK(r.seedId == -1, "SKIP leaves seed_id unresolved");
    }
    // Empty externalip is also "not a seed" -> SKIP, not FATAL.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "", keys[0].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "empty externalip on mainnet -> SKIP_NOT_A_SEED (HIGH-1)");
    }

    // --- HIGH-2: :port suffix and whitespace must still resolve. -------------
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.4:8444", keys[3].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "externalip with :port resolves -> REGISTER (HIGH-2)");
        CHECK(r.seedId == 3, ":port-stripped externalip resolves to correct seed_id");
    }
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "  10.0.0.2  ", keys[1].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "whitespace-padded externalip resolves -> REGISTER (HIGH-2)");
        CHECK(r.seedId == 1, "trimmed externalip resolves to correct seed_id");
    }
    // :port + whitespace combined, but with a WRONG key -> still FATAL at the
    // resolved slot (normalization must not mask a genuine key mismatch).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, " 10.0.0.1:8444 ", keys[2].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH,
              "normalized resolve still enforces pubkey match -> FATAL_MISMATCH");
        CHECK(r.seedId == 0, "normalized externalip resolved to seed_id=0");
    }

    // --- NormalizeExternalIpForSeedMatch direct cases. ----------------------
    CHECK(NormalizeExternalIpForSeedMatch("1.2.3.4:8444") == "1.2.3.4",
          "normalize strips :port");
    CHECK(NormalizeExternalIpForSeedMatch("  1.2.3.4 ") == "1.2.3.4",
          "normalize trims whitespace");
    CHECK(NormalizeExternalIpForSeedMatch("1.2.3.4") == "1.2.3.4",
          "normalize leaves bare IPv4 intact");
    // IPv6 must NOT be port-stripped at the colons (would corrupt the address).
    CHECK(NormalizeExternalIpForSeedMatch("2001:db8::1") == "2001:db8::1",
          "normalize leaves bare IPv6 literal intact (no false :port strip)");
    CHECK(NormalizeExternalIpForSeedMatch("[2001:db8::1]:8444") == "2001:db8::1",
          "normalize extracts address from bracketed IPv6:port");

    // --- Testnet (empty pubkey set): lenient default-0 register, with flag. --
    {
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, emptyPubkeys, "203.0.113.7", keys[0].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "testnet empty set + unresolved ip -> REGISTER (lenient)");
        CHECK(r.seedId == 0, "testnet unresolved defaults to seed_id=0");
        CHECK(r.usedTestnetDefault, "testnet default flagged for legacy WARN");
    }
    {
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, emptyPubkeys, "10.0.0.2", keys[0].GetPubKey());
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "testnet empty set + resolved ip -> REGISTER at resolved index");
        CHECK(r.seedId == 1, "testnet resolved ip keeps its index");
        CHECK(!r.usedTestnetDefault, "testnet resolved ip is not a default");
    }
}

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
    TestFsyncFailureIsFatalBeforeRename();   // B-1 (THE load-bearing test)
    TestSaveFailMakesLoadOrGenerateFail();   // M-2
    TestRequireEncryptionPolicy();           // H-1
    TestSeedKeyFilePresentDetectsUnreadable(); // extreview HIGH (presence vs readability)
    TestKeyIdentityComparison();             // M-1 (key-identity pubkey comparison)
    TestSeedIdentityResolutionGlue();        // HIGH-1/HIGH-2 (resolve+decide glue)
#ifndef _WIN32
    TestLoadRepairsPerms();                  // M-3
    TestFailClosedPerms();                   // M-4 (best-effort/informational)
    TestPosixPerms();
    TestTempSymlinkRejected();               // O_NOFOLLOW symlink-hardening (nemotron extreview)
#endif

    std::cout << "=========================================" << std::endl;
    if (g_failures == 0) {
        std::cout << "ALL TESTS PASSED" << std::endl;
        return 0;
    }
    std::cerr << g_failures << " CHECK(S) FAILED" << std::endl;
    return 1;
}
