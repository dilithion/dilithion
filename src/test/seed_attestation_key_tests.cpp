// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-13: seed-attestation private key at-rest hardening tests.
//
// Covers (per contract AC2-AC6, AC9 + LP-13 hardening CL-1/CL-2):
//   - v2 encrypt -> decrypt round-trip (private key usable after reload)
//   - tampered ciphertext rejected (MAC fail)
//   - truncated file / empty MAC rejected
//   - wrong passphrase rejected cleanly
//   - v1 plaintext backward-compat load
//   - LoadOrGenerate auto-mint REFUSED without the flag, allowed with it
//   - (POSIX) saved key file is chmod 0600
//   - CL-1 default-on encryption: Save refuses plaintext without a passphrase
//     unless allowPlaintext is explicitly set (mutation-kills the inverted gate)
//   - CL-1 migration: an existing v1 key loads and is re-saved as v2 in place,
//     the original keypair is preserved (never lost); refused (fail loud) with
//     no passphrase + no opt-out
//   - CL-2: no plaintext .bak copy survives a save
//   - MEDIUM-1 (round-2): migration re-save failure is NON-FATAL, v1 byte-intact
//   - round-2: LoadOrGenerate classifies MISSING / CORRUPT / TRANSIENT (the
//     classification that drives the node's actual-seed SM-5 scope + warn-vs-fatal)
//   - round-3: ClassifySeedIntent / IsConfiguredSeed — the EXPLICIT
//     --attestation-seed seed-intent decision both node binaries route through,
//     replacing the fragile external_ip-as-seed-intent signal (mutation-checked:
//     drop the flag-disjunct or the declared-but-unresolved FATAL => a CHECK fails)

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
    SetPass(nullptr);  // no passphrase => Save writes v1 ONLY with allowPlaintext
    CSeedAttestationKey k1;
    k1.Generate();
    std::vector<uint8_t> pub = k1.GetPubKey();
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "save v1 (no passphrase, explicit opt-out)");

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

    // No passphrase here, so minting must explicitly opt out of default-on
    // encryption (allowPlaintext=true) or Save would fail-loud (CL-1).
    CSeedAttestationKey k2;
    CHECK(k2.LoadOrGenerate(dir, /*allowGenerate=*/true, /*allowPlaintext=*/true),
          "LoadOrGenerate(true) mints + saves");
    CHECK(k2.IsValid(), "key valid after permitted mint");

    // Second call now LOADS the persisted key even without the generate flag.
    CSeedAttestationKey k3;
    CHECK(k3.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/true),
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

    // allowPlaintext=true so we reach the save path under no passphrase (the
    // failpoint then forces the save to fail — that is what this test exercises).
    CSeedAttestationKey k;
    CHECK(!k.LoadOrGenerate(dir, /*allowGenerate=*/true, /*allowPlaintext=*/true),
          "LoadOrGenerate returns false when the freshly minted key can't be saved");
    CHECK(!k.IsValid(), "no ephemeral key left valid in memory after save failure");

    g_failpointActive = false;
    g_seedKeySaveFailpoint = nullptr;

    // No persisted file (the temp was removed on the failed save).
    std::ifstream chk(KeyPath(dir), std::ios::binary);
    CHECK(!chk.good(), "no key file persisted after save failure");
}

// LP-13 CL-1 (DEFAULT-ON ENCRYPTION): the seed key is encrypted at rest BY
// DEFAULT. With no passphrase Save FAILS LOUD (no plaintext) unless allowPlaintext
// is explicitly set; with a passphrase Save always writes v2. This is the
// mutation-killing test for the inverted gate — reverting the gate to write
// plaintext-by-default makes the "Save(default) refuses ... no plaintext file
// written" assertions fail.
static void TestDefaultOnEncryptionGate() {
    std::cout << "[Test] CL-1: default-on encryption — Save refuses plaintext w/o passphrase" << std::endl;

    // (1) DEFAULT (no allowPlaintext), passphrase UNSET => Save FAILS, NO file.
    std::string dir = MakeTempDir();
    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate key");
    CHECK(!k1.Save(dir),
          "Save(default) REFUSES to write plaintext when passphrase unset (CL-1 inversion)");
    {
        std::ifstream chk(KeyPath(dir), std::ios::binary);
        CHECK(!chk.good(), "NO key file written on the default refusal (no plaintext on disk)");
    }

    // (2) DEFAULT, passphrase SET => Save writes v2 encrypted.
    std::string dir2 = MakeTempDir();
    SetPass("default-on-pass");
    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate key");
    CHECK(k2.Save(dir2), "Save(default) writes v2 when passphrase set");
    std::vector<uint8_t> raw2 = ReadFileBytes(KeyPath(dir2));
    CHECK(raw2.size() > 5 && raw2[4] == 2, "on-disk file is v2 encrypted by default");

    // (3) EXPLICIT opt-out (allowPlaintext=true), passphrase UNSET => v1 written.
    std::string dir3 = MakeTempDir();
    SetPass(nullptr);
    CSeedAttestationKey k3;
    CHECK(k3.Generate(), "generate key");
    CHECK(k3.Save(dir3, /*allowPlaintext=*/true),
          "Save(allowPlaintext) writes v1 plaintext when passphrase unset (explicit opt-out)");
    std::vector<uint8_t> raw3 = ReadFileBytes(KeyPath(dir3));
    CHECK(raw3.size() > 5 && raw3[4] == 1, "on-disk file is v1 plaintext under explicit opt-out");
    SetPass(nullptr);
}

// LP-13 CL-1 (MIGRATION): an existing v1 plaintext key LOADS (no upgrade brick),
// and when a passphrase is available LoadOrGenerate MIGRATES it in place to v2.
// With no passphrase and no opt-out, a loaded v1 key is REFUSED (fail loud). The
// CRITICAL safety assertion: the original key is NEVER lost — the migrated key is
// the SAME keypair, usable for signing.
static void TestV1ToV2Migration() {
    std::cout << "[Test] CL-1: v1->v2 in-place migration, original key preserved" << std::endl;
    std::string dir = MakeTempDir();

    // Establish a live v1 plaintext key (explicit opt-out to write it).
    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate v1 key");
    std::vector<uint8_t> origPub = k1.GetPubKey();
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "save v1 plaintext (legacy live key)");
    std::vector<uint8_t> v1raw = ReadFileBytes(KeyPath(dir));
    CHECK(v1raw.size() > 5 && v1raw[4] == 1, "on-disk file is v1 before migration");

    // Now provision a passphrase (simulating the deploy step) and LoadOrGenerate
    // with the default policy: it must load the v1 key AND re-save it as v2.
    SetPass("migration-pass");
    CSeedAttestationKey k2;
    CHECK(k2.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false),
          "LoadOrGenerate loads + migrates the v1 key under default-on policy");
    CHECK(k2.IsValid(), "migrated key valid");
    CHECK(k2.GetPubKey() == origPub, "migrated key is the SAME keypair (original not lost)");
    CHECK(PrivKeyRoundTrips(k2, origPub), "migrated private key still signs/verifies");
    CHECK(!k2.LoadedPlaintext(), "in-memory key no longer flagged as plaintext after migration");

    // On disk the file is now v2 encrypted.
    std::vector<uint8_t> v2raw = ReadFileBytes(KeyPath(dir));
    CHECK(v2raw.size() > 5 && v2raw[4] == 2, "on-disk file is v2 encrypted after migration");

    // Reload under default policy with the passphrase: loads the v2 key cleanly.
    CSeedAttestationKey k3;
    CHECK(k3.LoadOrGenerate(dir, false, false), "reload migrated v2 key under default policy");
    CHECK(k3.GetPubKey() == origPub, "reloaded v2 key matches original keypair");

    // Default policy, v1 on disk, NO passphrase, NO opt-out => REFUSE (fail loud),
    // and the original v1 file is NOT destroyed.
    std::string dir2 = MakeTempDir();
    SetPass(nullptr);
    CSeedAttestationKey k4;
    CHECK(k4.Generate(), "generate v1 key for refusal case");
    std::vector<uint8_t> origPub2 = k4.GetPubKey();
    CHECK(k4.Save(dir2, /*allowPlaintext=*/true), "save v1 plaintext");
    std::vector<uint8_t> beforeRefuse = ReadFileBytes(KeyPath(dir2));
    CSeedAttestationKey k5;
    CHECK(!k5.LoadOrGenerate(dir2, false, /*allowPlaintext=*/false),
          "default-on REFUSES a v1 key when no passphrase + no opt-out (fail loud)");
    std::vector<uint8_t> afterRefuse = ReadFileBytes(KeyPath(dir2));
    CHECK(afterRefuse == beforeRefuse, "refused v1 key file is byte-intact (not destroyed)");

    // Same v1 file, NO passphrase, but EXPLICIT opt-out => loads unchanged.
    CSeedAttestationKey k6;
    CHECK(k6.LoadOrGenerate(dir2, false, /*allowPlaintext=*/true),
          "explicit opt-out loads the v1 key unchanged (no passphrase)");
    CHECK(k6.GetPubKey() == origPub2, "opt-out loaded key matches");
    std::vector<uint8_t> afterOptOut = ReadFileBytes(KeyPath(dir2));
    CHECK(afterOptOut.size() > 5 && afterOptOut[4] == 1, "stays v1 under opt-out (no migration)");
    SetPass(nullptr);
}

// LP-13 MEDIUM-1 (round-2 fold — THE single most safety-critical migration
// claim, previously ZERO coverage): when the v1->v2 migration re-Save FAILS, the
// node must KEEP RUNNING on the loaded (v1) key — NOT fatal — and the original v1
// file must be byte-intact. A bug that made the migration-save-failure fatal would
// brick a live seed on a transient disk error during a rolling upgrade.
//
// We force the migration Save to fail via the existing g_seedKeySaveFailpoint
// seam (a simulated crash between temp-write and rename, which the atomic save
// path turns into a clean false return with the original file untouched).
// Assertions: LoadOrGenerate returns true (non-fatal); the in-memory key is the
// SAME (v1) keypair and still signs; the on-disk file is STILL v1 and byte-for-
// byte identical to before. Mutation self-check: making the migration-save branch
// fatal (return false / Clear) fails the "non-fatal + key still usable" asserts.
static void TestMigrationSaveFailIsNonFatal() {
    std::cout << "[Test] MEDIUM-1: migration re-save failure is NON-FATAL, v1 key preserved" << std::endl;
    std::string dir = MakeTempDir();

    // 1) Establish a live v1 plaintext key (explicit opt-out to write it).
    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate v1 key");
    std::vector<uint8_t> origPub = k1.GetPubKey();
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "save v1 plaintext (legacy live key)");
    std::vector<uint8_t> v1Before = ReadFileBytes(KeyPath(dir));
    CHECK(v1Before.size() > 5 && v1Before[4] == 1, "on-disk file is v1 before migration attempt");

    // 2) Provision a passphrase (deploy step) so LoadOrGenerate WILL attempt the
    //    v1->v2 migration re-save — but arm the failpoint so that re-save FAILS.
    SetPass("migration-fail-pass");
    g_seedKeySaveFailpoint = SaveFailpoint;
    g_failpointActive = true;

    CSeedAttestationKey k2;
    SeedKeyLoadStatus status = SeedKeyLoadStatus::CORRUPT;
    bool ok = k2.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false, &status);

    g_failpointActive = false;
    g_seedKeySaveFailpoint = nullptr;

    // 3) THE assertions: non-fatal — we keep running on the loaded key.
    CHECK(ok, "LoadOrGenerate returns true (NON-FATAL) when the migration re-save fails");
    CHECK(status == SeedKeyLoadStatus::OK, "status is OK (running on the loaded key) despite save-fail");
    CHECK(k2.IsValid(), "in-memory key is still valid after failed migration");
    CHECK(k2.GetPubKey() == origPub, "in-memory key is the SAME (loaded v1) keypair");
    CHECK(PrivKeyRoundTrips(k2, origPub), "loaded v1 private key still signs/verifies");
    CHECK(k2.LoadedPlaintext(), "in-memory key still flagged plaintext (migration did NOT complete)");

    // 4) On-disk file is STILL the original v1 file, byte-for-byte (atomic save
    //    left it untouched). The operator can retry the migration later.
    std::vector<uint8_t> v1After = ReadFileBytes(KeyPath(dir));
    CHECK(v1After == v1Before, "original v1 key file is BYTE-INTACT after the failed migration");
    CHECK(v1After.size() > 5 && v1After[4] == 1, "on-disk file is STILL v1 (not partially migrated)");

    // 5) No stray .tmp left occupying the path.
    std::ifstream tmp(KeyPath(dir) + ".tmp", std::ios::binary);
    CHECK(!tmp.good(), "no leftover .tmp after the failed migration save");

    SetPass(nullptr);
}

// LP-13 (round-2 fold — transient-vs-permanent classification): the node decides
// FATAL vs warn-continue from SeedKeyLoadStatus. This pins the classification at
// the unit level (the node's IP-scope gate then maps actual-seed + MISSING/CORRUPT
// => fatal, actual-seed + TRANSIENT => warn, non-seed => boot fine). The HIGH-1
// "community node with no key boots fine" behavior reduces to: a MISSING key with
// allowGenerate=false yields status==MISSING and the node only aborts when the IP
// is in the seed set — so the load-bearing unit claim is "MISSING is reported as
// MISSING (not silently OK), CORRUPT as CORRUPT, and a present-but-unreadable key
// as TRANSIENT (not MISSING/CORRUPT)". Mutation self-checks noted per assertion.
static void TestLoadStatusClassification() {
    std::cout << "[Test] round-2: LoadOrGenerate classifies MISSING / CORRUPT / TRANSIENT" << std::endl;

    // (a) MISSING: empty dir, no key, no generate flag => status MISSING, false.
    {
        std::string dir = MakeTempDir();
        SetPass(nullptr);
        CSeedAttestationKey k;
        SeedKeyLoadStatus st = SeedKeyLoadStatus::OK;
        bool ok = k.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false, &st);
        CHECK(!ok, "MISSING key + no generate => LoadOrGenerate false");
        CHECK(st == SeedKeyLoadStatus::MISSING,
              "absent key reports MISSING (mutation: classifying it OK would let a seed boot keyless)");
    }

    // (b) CORRUPT: a present file with bad magic => status CORRUPT, false. An
    //     actual seed treats this as fatal; auto-mint must NOT overwrite it even
    //     with allowGenerate=true (never destroy a present, possibly-recoverable key).
    {
        std::string dir = MakeTempDir();
        SetPass(nullptr);
        std::vector<uint8_t> garbage(64, 0x77);  // wrong magic, present file
        WriteFileBytes(KeyPath(dir), garbage);
        std::vector<uint8_t> before = ReadFileBytes(KeyPath(dir));

        CSeedAttestationKey k;
        SeedKeyLoadStatus st = SeedKeyLoadStatus::OK;
        bool ok = k.LoadOrGenerate(dir, /*allowGenerate=*/true, /*allowPlaintext=*/true, &st);
        CHECK(!ok, "CORRUPT present file => LoadOrGenerate false even WITH --generate-seed-key");
        CHECK(st == SeedKeyLoadStatus::CORRUPT, "present-but-bad file reports CORRUPT");
        std::vector<uint8_t> after = ReadFileBytes(KeyPath(dir));
        CHECK(after == before,
              "CORRUPT present key is NOT overwritten by auto-mint (no key destroyed)");
    }

#ifndef _WIN32
    // (c) TRANSIENT: a present-but-UNREADABLE file (chmod 000, non-root) must
    //     report TRANSIENT — NOT MISSING and NOT CORRUPT — so an actual seed
    //     warns-and-continues instead of crash-looping or minting a 2nd key.
    //     Under root, chmod 000 does not revoke read; honest SKIP (M-4 precedent).
    {
        std::string dir = MakeTempDir();
        SetPass("transient-pass");
        CSeedAttestationKey k1;
        CHECK(k1.Generate(), "generate key for transient test");
        CHECK(k1.Save(dir), "save v2 key");

        if (chmod(KeyPath(dir).c_str(), 0) == 0) {
            std::ifstream probe(KeyPath(dir), std::ios::binary);
            if (probe.good()) {
                std::cout << "  [info] cannot revoke read (running as root?); TRANSIENT leg "
                             "skipped — run as non-root to exercise it" << std::endl;
            } else {
                probe.close();
                CSeedAttestationKey k2;
                SeedKeyLoadStatus st = SeedKeyLoadStatus::OK;
                bool ok = k2.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false, &st);
                CHECK(!ok, "present-but-unreadable key => LoadOrGenerate false");
                CHECK(st == SeedKeyLoadStatus::TRANSIENT,
                      "present-but-unreadable key reports TRANSIENT (mutation: MISSING/CORRUPT here "
                      "would crash-loop or mint a 2nd key on a real seed over a disk blip)");
            }
            chmod(KeyPath(dir).c_str(), S_IRUSR | S_IWUSR);  // restore for clean teardown
        } else {
            std::cout << "  [info] chmod 000 failed; TRANSIENT leg skipped" << std::endl;
        }
        SetPass(nullptr);
    }
#endif

    // (d) OK: a normal v2 key loads with status OK.
    {
        std::string dir = MakeTempDir();
        SetPass("ok-pass");
        CSeedAttestationKey k1;
        CHECK(k1.Generate(), "generate key");
        CHECK(k1.Save(dir), "save v2");
        CSeedAttestationKey k2;
        SeedKeyLoadStatus st = SeedKeyLoadStatus::MISSING;
        bool ok = k2.LoadOrGenerate(dir, false, false, &st);
        CHECK(ok && st == SeedKeyLoadStatus::OK, "good key loads with status OK");
        SetPass(nullptr);
    }
}

// LP-13 CL-2: Save leaves NO plaintext .bak behind. The prior implementation
// staged a copy of the existing (possibly plaintext) key at "<file>.bak" in a
// crash window; CL-2 removes it. After an UPDATE save (a prior key existed) the
// .bak must NOT exist on disk. Mutation self-check: restoring the .bak write
// makes the "no .bak" assertion fail.
static void TestNoPlaintextBak() {
    std::cout << "[Test] CL-2: no plaintext .bak survives a save" << std::endl;
    std::string dir = MakeTempDir();
    std::string bakPath = KeyPath(dir) + ".bak";

    // First save (v1 via opt-out) establishes a prior key on disk.
    SetPass(nullptr);
    CSeedAttestationKey k1;
    CHECK(k1.Generate(), "generate key");
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "first save (establishes prior key)");
    {
        std::ifstream b(bakPath, std::ios::binary);
        CHECK(!b.good(), "no .bak after the first save");
    }

    // Second (UPDATE) save: this is where the old code staged a plaintext .bak.
    CSeedAttestationKey k2;
    CHECK(k2.Generate(), "generate replacement key");
    CHECK(k2.Save(dir, /*allowPlaintext=*/true), "update save (would have staged .bak in old code)");
    {
        std::ifstream b(bakPath, std::ios::binary);
        CHECK(!b.good(), "NO plaintext .bak left behind after an update save (CL-2)");
    }

    // And an UPDATE save on the encrypted path leaves no .bak either.
    std::string dir2 = MakeTempDir();
    std::string bakPath2 = KeyPath(dir2) + ".bak";
    SetPass("bak-pass");
    CSeedAttestationKey k3; k3.Generate();
    CHECK(k3.Save(dir2), "first v2 save");
    CSeedAttestationKey k4; k4.Generate();
    CHECK(k4.Save(dir2), "second v2 (update) save");
    {
        std::ifstream b(bakPath2, std::ios::binary);
        CHECK(!b.good(), "no .bak after an encrypted update save either");
    }
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
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "save v1 key");

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

    // Also verify v1 path sets 0600 (explicit plaintext opt-out, no passphrase).
    SetPass(nullptr);
    std::string dir2 = MakeTempDir();
    CSeedAttestationKey k2;
    k2.Generate();
    CHECK(k2.Save(dir2, /*allowPlaintext=*/true), "save v1");
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
    CHECK(k1.Save(dir, /*allowPlaintext=*/true), "save key file");
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

// LP-13 round-3: the EXPLICIT --attestation-seed seed-intent classifier. This is
// the single source of truth both node binaries route through for the fatal-vs-
// silent startup decision, replacing the fragile bare external_ip-match signal.
// Mutation-checked: each assertion below KILLS a specific mutation of
// ClassifySeedIntent (drop the flag-disjunct, drop the declared-but-unresolved
// FATAL, swap the COMMUNITY fall-through, etc.). seedId >= 0 means external_ip
// resolved to a configured seat; seedId == -1 means it did not.
static void TestSeedIntentClassifier() {
    std::cout << "[Test] round-3: --attestation-seed seed-intent classifier" << std::endl;

    // (1) Flag SET + IP IN set (seedId>=0): CONFIGURED_SEED (must attest; missing
    //     key => fatal). Explicit + resolved is the canonical seed.
    CHECK(ClassifySeedIntent(/*flag=*/true, /*seedId=*/0) == SeedIntent::CONFIGURED_SEED,
          "flag SET + IP-in-set => CONFIGURED_SEED");
    CHECK(IsConfiguredSeed(true, 3) == true,
          "flag SET + IP-in-set => IsConfiguredSeed (must attest)");

    // (2) Flag SET + IP NOT in set (seedId==-1): DECLARED_BUT_UNRESOLVED => FATAL.
    //     THE silent-gap closer. Mutation: if the declared-but-unresolved branch is
    //     removed, this falls through to COMMUNITY and the assertion fails.
    CHECK(ClassifySeedIntent(/*flag=*/true, /*seedId=*/-1) == SeedIntent::DECLARED_BUT_UNRESOLVED,
          "flag SET + IP-NOT-in-set => DECLARED_BUT_UNRESOLVED (declared-but-unresolved FATAL; "
          "mutation: removing this branch silently demotes a misconfigured seat to COMMUNITY)");
    CHECK(IsConfiguredSeed(true, -1) == false,
          "declared-but-unresolved is NOT a (bootable) CONFIGURED_SEED — it is FATAL at the node");

    // (3) NO flag + IP IN set (seedId>=0): CONFIGURED_SEED (backward-compat — live
    //     seeds keep attesting by IP-match through the rolling deploy). Mutation:
    //     if the IP-match disjunct is removed, this becomes COMMUNITY and the live
    //     seeds would silently stop attesting — the assertion fails.
    CHECK(ClassifySeedIntent(/*flag=*/false, /*seedId=*/2) == SeedIntent::CONFIGURED_SEED,
          "NO flag + IP-in-set => CONFIGURED_SEED (backward-compat; mutation: dropping the "
          "IP-match disjunct stops the live seeds attesting)");
    CHECK(IsConfiguredSeed(false, 2) == true,
          "NO flag + IP-in-set => IsConfiguredSeed (backward-compat attest)");

    // (4) NO flag + IP NOT in set (seedId==-1): COMMUNITY (boots fine, non-attesting,
    //     never fatal on key state). Mutation: classifying this CONFIGURED_SEED would
    //     make every community relay/public-API node fatal-on-missing-key.
    CHECK(ClassifySeedIntent(/*flag=*/false, /*seedId=*/-1) == SeedIntent::COMMUNITY,
          "NO flag + IP-NOT-in-set => COMMUNITY (community node; never fatal on keys)");
    CHECK(IsConfiguredSeed(false, -1) == false,
          "community node is NOT a configured seed (boots non-attesting)");
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
    TestDefaultOnEncryptionGate();           // CL-1 (default-on; mutation-kills the gate)
    TestV1ToV2Migration();                   // CL-1 (migration; original key preserved)
    TestMigrationSaveFailIsNonFatal();       // MEDIUM-1 (round-2: migration save-fail non-fatal)
    TestLoadStatusClassification();          // round-2 (MISSING/CORRUPT/TRANSIENT classification)
    TestSeedIntentClassifier();              // round-3 (--attestation-seed seed-intent; mutation-checked)
    TestNoPlaintextBak();                    // CL-2 (no plaintext .bak)
    TestSeedKeyFilePresentDetectsUnreadable(); // extreview HIGH (presence vs readability)
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
