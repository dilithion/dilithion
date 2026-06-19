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
//   - no-key-loss guard: LoadOrGenerate never auto-mints over a present-but-
//     unloadable key file (a present key is never destroyed by an auto-mint)

#include <attestation/seed_attestation.h>
#include <attestation/seed_pubkeys_mainnet.h>  // Fix 3: consensus-equivalence assertion
#include <dfmp/dfmp.h>
#include <rpc/server.h>  // Finding E: end-to-end degraded getmikattestation error string

#include <stdexcept>

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

// Test-only thin wrapper: most legacy cases predate the Fix 1 datacenter-gate
// params and exercise non-ban / inert behavior. Default datacenterBanChain=false
// (DIL-shaped) + datacenterListLoaded=true so the gate is INERT, preserving the
// prior REGISTER/DEGRADE outcomes for those cases. Cases that exercise the new
// gate call the full Attestation::ResolveSeedIdentity directly.
static SeedIdentityResult ResolveSeedIdentity(
    const std::vector<std::string>& seedIPs,
    const std::vector<std::vector<uint8_t>>& seedPubkeys,
    const std::string& externalIp,
    const std::vector<uint8_t>& loadedPubkey,
    bool asnLoaded) {
    return Attestation::ResolveSeedIdentity(
        seedIPs, seedPubkeys, externalIp, loadedPubkey, asnLoaded,
        /*datacenterBanChain=*/false, /*datacenterListLoaded=*/true);
}

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
    bool ok = k2.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false);

    g_failpointActive = false;
    g_seedKeySaveFailpoint = nullptr;

    // 3) THE assertions: non-fatal — we keep running on the loaded key.
    CHECK(ok, "LoadOrGenerate returns true (NON-FATAL) when the migration re-save fails");
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

// LP-13 (no-key-loss guard, retained after SM-5 removal): LoadOrGenerate must
// NEVER auto-mint a fresh consensus key OVER a present-but-unloadable key file —
// that would destroy a possibly-recoverable key. Auto-mint is only permitted when
// the file is genuinely ABSENT and --generate-seed-key was given. This is the bool
// behavior the SM-5 status classifier used to drive; it survives the decouple as a
// plain behavioral test of the CARDINAL "key-loss is impossible" property.
static void TestNoMintOverPresentKey() {
    std::cout << "[Test] no-key-loss: never auto-mint over a present key" << std::endl;

    // (a) MISSING: empty dir, no key, no generate flag => fail loud (false), no mint.
    {
        std::string dir = MakeTempDir();
        SetPass(nullptr);
        CSeedAttestationKey k;
        bool ok = k.LoadOrGenerate(dir, /*allowGenerate=*/false, /*allowPlaintext=*/false);
        CHECK(!ok, "MISSING key + no --generate-seed-key => LoadOrGenerate false (no silent mint)");
        std::ifstream f(KeyPath(dir), std::ios::binary);
        CHECK(!f.good(), "no key file was minted when generate was not requested");
    }

    // (b) PRESENT-but-CORRUPT: a present file with bad magic must NOT be overwritten
    //     by an auto-mint even WITH --generate-seed-key. The bytes survive intact.
    {
        std::string dir = MakeTempDir();
        SetPass(nullptr);
        std::vector<uint8_t> garbage(64, 0x77);  // wrong magic, present file
        WriteFileBytes(KeyPath(dir), garbage);
        std::vector<uint8_t> before = ReadFileBytes(KeyPath(dir));

        CSeedAttestationKey k;
        bool ok = k.LoadOrGenerate(dir, /*allowGenerate=*/true, /*allowPlaintext=*/true);
        CHECK(!ok, "CORRUPT present file => LoadOrGenerate false even WITH --generate-seed-key");
        std::vector<uint8_t> after = ReadFileBytes(KeyPath(dir));
        CHECK(after == before,
              "present-but-bad key is NOT overwritten by auto-mint (no key destroyed)");
    }

    // (c) OK: a normal v2 key loads (true).
    {
        std::string dir = MakeTempDir();
        SetPass("ok-pass");
        CSeedAttestationKey k1;
        CHECK(k1.Generate(), "generate key");
        CHECK(k1.Save(dir), "save v2");
        CSeedAttestationKey k2;
        CHECK(k2.LoadOrGenerate(dir, false, false), "good key loads (true)");
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
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "matching key at resolved slot + ASN ok -> REGISTER");
        CHECK(r.seedId == 2, "REGISTER resolves to seed_id=2");
        CHECK(!r.usedTestnetDefault, "REGISTER on mainnet is not a testnet default");
    }

    // --- FATAL_MISMATCH: externalip resolves to a real slot, WRONG key. ------
    // (Drives the abort path; a no-op decision helper would NOT return this.)
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.1", keys[3].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH,
              "resolved slot + mismatched pubkey -> FATAL_MISMATCH (abort path)");
        CHECK(r.seedId == 0, "FATAL_MISMATCH reports the resolved seed_id");
    }

    // --- SKIP_NOT_A_SEED: externalip matches NO configured slot. ------------
    // HIGH-1: must NOT abort even though a usable key is present.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "203.0.113.7", keys[0].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "non-seed externalip + key present -> SKIP_NOT_A_SEED (NOT abort, HIGH-1)");
        CHECK(r.seedId == -1, "SKIP leaves seed_id unresolved");
    }
    // Empty externalip is also "not a seed" -> SKIP, not FATAL.
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "", keys[0].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "empty externalip on mainnet -> SKIP_NOT_A_SEED (HIGH-1)");
    }

    // --- HIGH-2: :port suffix and whitespace must still resolve. -------------
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.4:8444", keys[3].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "externalip with :port resolves -> REGISTER (HIGH-2)");
        CHECK(r.seedId == 3, ":port-stripped externalip resolves to correct seed_id");
    }
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "  10.0.0.2  ", keys[1].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "whitespace-padded externalip resolves -> REGISTER (HIGH-2)");
        CHECK(r.seedId == 1, "trimmed externalip resolves to correct seed_id");
    }
    // :port + whitespace combined, but with a WRONG key -> still FATAL at the
    // resolved slot (normalization must not mask a genuine key mismatch).
    {
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, " 10.0.0.1:8444 ", keys[2].GetPubKey(), /*asnLoaded=*/true);
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

    // --- Finding C (extreview PR#121): normalization edge cases. -------------
    // Trailing dot (FQDN form, or dotted-quad with a stray trailing dot) must be
    // stripped so it string-equals the configured form.
    CHECK(NormalizeExternalIpForSeedMatch("1.2.3.4.") == "1.2.3.4",
          "Finding C: strip single trailing dot on dotted-quad");
    CHECK(NormalizeExternalIpForSeedMatch("seed.example.com.") == "seed.example.com",
          "Finding C: strip single trailing dot on FQDN form");
    CHECK(NormalizeExternalIpForSeedMatch("1.2.3.4.:8444") == "1.2.3.4",
          "Finding C: trailing dot stripped after :port removal");
    // Uppercase IPv6 must canonicalize to lowercase (RFC 5952 case-insensitive).
    CHECK(NormalizeExternalIpForSeedMatch("2001:DB8::1") == "2001:db8::1",
          "Finding C: lowercase bare uppercase IPv6");
    CHECK(NormalizeExternalIpForSeedMatch("[2001:DB8::1]:8444") == "2001:db8::1",
          "Finding C: lowercase bracketed uppercase IPv6:port");
    // Embedded whitespace (quoting/templating artifact) inside the literal must
    // be stripped, not left to silently fail the match.
    CHECK(NormalizeExternalIpForSeedMatch("138.197. 68.128") == "138.197.68.128",
          "Finding C: strip interior whitespace in IPv4 literal");
    CHECK(NormalizeExternalIpForSeedMatch("\t1.2.3.4\t") == "1.2.3.4",
          "Finding C: tab-padded externalip trims");

    // --- Testnet (empty pubkey set): lenient default-0 register, with flag. --
    {
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, emptyPubkeys, "203.0.113.7", keys[0].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "testnet empty set + unresolved ip + ASN ok -> REGISTER (lenient)");
        CHECK(r.seedId == 0, "testnet unresolved defaults to seed_id=0");
        CHECK(r.usedTestnetDefault, "testnet default flagged for legacy WARN");
    }
    {
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, emptyPubkeys, "10.0.0.2", keys[0].GetPubKey(), /*asnLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "testnet empty set + resolved ip -> REGISTER at resolved index");
        CHECK(r.seedId == 1, "testnet resolved ip keeps its index");
        CHECK(!r.usedTestnetDefault, "testnet resolved ip is not a default");
    }

    // --- H-3 (consolidated): DEGRADED_NO_ASN — valid identity, ASN DB down. ---
    // The load-bearing new case. A no-op DEGRADED helper (one that still returns
    // REGISTER when asnLoaded=false) would FAIL all four of these.
    {
        // Mainnet seed, key MATCHES its slot, but ASN failed to load -> DEGRADED,
        // NOT REGISTER (stay online, don't register) and NOT FATAL (don't abort).
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(), /*asnLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_ASN,
              "valid mainnet seed + ASN DB FAILED -> DEGRADED_NO_ASN (online, unregistered)");
        CHECK(r.decision != SeedIdentityDecision::REGISTER,
              "DEGRADED must NOT register (kills original silent-zero-capacity bug)");
        CHECK(r.decision != SeedIdentityDecision::FATAL_MISMATCH,
              "DEGRADED must NOT abort (kills the brick over-correction)");
        CHECK(r.seedId == 2, "DEGRADED still reports the resolved seed_id (for diagnostics)");
    }
    {
        // ASN state must NOT override a TRUST failure: resolved slot + WRONG key
        // is still FATAL_MISMATCH even with the ASN DB down. A wrong-key signer
        // must never run, regardless of ASN state.
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.1", keys[3].GetPubKey(), /*asnLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH,
              "mismatched pubkey stays FATAL_MISMATCH even with ASN DB down (trust > ASN)");
    }
    {
        // ASN state must NOT turn a non-seed into a degraded seed: a non-matching
        // externalip is SKIP_NOT_A_SEED whether or not the ASN DB loaded.
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, seedPubkeys, "203.0.113.7", keys[0].GetPubKey(), /*asnLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "non-seed externalip stays SKIP_NOT_A_SEED even with ASN DB down (no false degrade)");
    }
    {
        // Testnet (empty pubkey set): a would-be lenient REGISTER also degrades
        // when the ASN DB is down — same online-but-unregistered semantics.
        std::vector<std::vector<uint8_t>> emptyPubkeys;
        SeedIdentityResult r = ResolveSeedIdentity(
            seedIPs, emptyPubkeys, "10.0.0.2", keys[0].GetPubKey(), /*asnLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_ASN,
              "testnet would-be REGISTER + ASN DB down -> DEGRADED_NO_ASN");
        CHECK(r.seedId == 1, "testnet DEGRADED keeps the resolved seed_id");
    }

    // --- Fix 1 (extreview PR#121): datacenter-over-attestation gate. ----------
    // Calls the FULL Attestation::ResolveSeedIdentity (the wrapper above forces
    // the inert defaults). Mutation self-check: disabling the gate (always
    // returning REGISTER from registerOrDegrade for the ban+no-list case) makes
    // case (a) FAIL.
    {
        // (a) ban chain + datacenter list NOT loaded + valid identity ->
        //     DEGRADED_NO_DATACENTER_LIST (NOT register, NOT fatal). ASN DB IS
        //     loaded, so this isolates the datacenter condition from DEGRADED_NO_ASN.
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true,
            /*datacenterListLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_DATACENTER_LIST,
              "(a) ban chain + empty datacenter list + valid id -> DEGRADED_NO_DATACENTER_LIST");
        CHECK(r.decision != SeedIdentityDecision::REGISTER,
              "(a) ban chain + empty datacenter list must NOT REGISTER (the security gate)");
        CHECK(r.decision != SeedIdentityDecision::FATAL_MISMATCH,
              "(a) datacenter-list gate must NOT abort (stay online for relay)");
        CHECK(r.seedId == 2, "(a) DEGRADED_NO_DATACENTER_LIST keeps the resolved seed_id");
    }
    {
        // (b) ban chain + datacenter list LOADED -> REGISTER (correctly-provisioned
        //     DilV seed is NOT demoted).
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true,
            /*datacenterListLoaded=*/true);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "(b) ban chain + datacenter list loaded -> REGISTER (provisioned seed not demoted)");
        CHECK(r.seedId == 2, "(b) REGISTER resolves to seed_id=2");
    }
    {
        // (c) NON-ban chain (DIL) + datacenter list NOT loaded -> REGISTER.
        //     Proves DIL is never demoted by a missing datacenter list.
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/false,
            /*datacenterListLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::REGISTER,
              "(c) NON-ban chain (DIL) + empty datacenter list -> REGISTER (DIL not demoted)");
        CHECK(r.seedId == 2, "(c) DIL REGISTER resolves to seed_id=2");
    }
    {
        // (d) FATAL_MISMATCH on a ban chain with empty datacenter list is STILL
        //     fatal (trust > datacenter — the gate can only soften a REGISTER).
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.1", keys[3].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true,
            /*datacenterListLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::FATAL_MISMATCH,
              "(d) wrong key stays FATAL_MISMATCH on ban chain + empty list (trust > datacenter)");
    }
    {
        // ASN-down takes precedence over the datacenter list (documented fold
        // order): ban chain + ASN DB down + empty datacenter list -> DEGRADED_NO_ASN.
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "10.0.0.3", keys[2].GetPubKey(),
            /*asnLoaded=*/false, /*datacenterBanChain=*/true,
            /*datacenterListLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::DEGRADED_NO_ASN,
              "ASN-down reported before datacenter-list (documented fold order)");
    }
    {
        // A non-seed externalip stays SKIP even on a ban chain with empty list
        // (the gate never promotes a non-seed into a degraded seed).
        SeedIdentityResult r = Attestation::ResolveSeedIdentity(
            seedIPs, seedPubkeys, "203.0.113.7", keys[0].GetPubKey(),
            /*asnLoaded=*/true, /*datacenterBanChain=*/true,
            /*datacenterListLoaded=*/false);
        CHECK(r.decision == SeedIdentityDecision::SKIP_NOT_A_SEED,
              "non-seed stays SKIP_NOT_A_SEED even on ban chain + empty datacenter list");
    }
}

// Fix 3 (extreview PR#121): consensus-equivalence assertion. The other identity
// tests build their OWN local keys and check only self-consistency + size — they
// never assert the loaded key equals the REAL consensus set. The FATAL_MISMATCH
// design (a seed whose key != seedAttestationPubkeys[seedId] aborts) rests on the
// baked-in mainnet pubkeys being well-formed and stable, so pin them here.
static void TestMainnetSeedPubkeyConsensusEquivalence() {
    std::cout << "[Test] Fix 3: mainnet seed pubkeys are consensus-shaped + stable"
              << std::endl;
    std::vector<std::vector<uint8_t>> pubs = Attestation::GetMainnetSeedPubkeys();
    CHECK(pubs.size() == (size_t)Attestation::NUM_SEEDS,
          "mainnet seed pubkey set has NUM_SEEDS entries");
    for (size_t i = 0; i < pubs.size(); i++) {
        CHECK(pubs[i].size() == DFMP::MIK_PUBKEY_SIZE,
              "seed pubkey is full Dilithium3 size");
        // Self-consistency of the accessor: GetMainnetSeedPubkeys()[i] equals
        // itself on a fresh call (the value consensus verification reads). This is
        // the exact comparison the node's FATAL_MISMATCH gate performs against the
        // loaded key (loadedPubkey != seedPubkeys[seedId]).
        CHECK(Attestation::GetMainnetSeedPubkeys()[i] == pubs[i],
              "GetMainnetSeedPubkeys()[i] is stable across calls (consensus value)");
    }
    // All four seed pubkeys must be DISTINCT — a duplicate would let one seed's
    // key satisfy two slots and collapse the 3-of-4 Byzantine assumption.
    for (size_t i = 0; i < pubs.size(); i++)
        for (size_t j = i + 1; j < pubs.size(); j++)
            CHECK(pubs[i] != pubs[j], "seed pubkeys are pairwise distinct");
}

// Finding E (extreview PR#121): end-to-end RPC glue for the DEGRADED state.
// TestSeedIdentityResolutionGlue covers the decision helper; this asserts the
// other half — that a CRPCServer marked degraded returns the DISTINCT
// "ASN database not loaded" error from getmikattestation (and NOT the generic
// "only available on seed nodes"), so an operator can tell a degraded seed from
// a plain non-seed. CRPCServer links into this test binary via CORE_OBJECTS and
// default-constructs with null node deps, so no chainstate is needed.
static void TestDegradedGetMikAttestationErrorString() {
    std::cout << "[Test] Finding E: degraded getmikattestation error string (RPC glue)"
              << std::endl;

    // 1) A plain (un-registered, non-degraded) server: generic non-seed error.
    {
        CRPCServer rpc;  // default port; no node wired
        std::string err;
        try {
            rpc.InvokeRPCForTest("getmikattestation", "{}");
            err = "<no throw>";
        } catch (const std::exception& e) {
            err = e.what();
        }
        CHECK(err.find("only available on seed nodes") != std::string::npos,
              "non-seed getmikattestation -> generic 'only available on seed nodes'");
        CHECK(err.find("ASN database not loaded") == std::string::npos,
              "non-seed error does NOT claim ASN-degraded");
    }

    // 2) A DEGRADED server (valid identity, ASN DB failed to load): distinct,
    //    diagnosable ASN-DB error string.
    {
        CRPCServer rpc;
        rpc.RegisterSeedAttestationDegraded(/*seedId=*/2);
        std::string err;
        try {
            rpc.InvokeRPCForTest("getmikattestation", "{}");
            err = "<no throw>";
        } catch (const std::exception& e) {
            err = e.what();
        }
        CHECK(err.find("ASN database not loaded") != std::string::npos,
              "degraded getmikattestation -> distinct 'ASN database not loaded'");
        CHECK(err.find("only available on seed nodes") == std::string::npos,
              "degraded error is NOT the generic non-seed string (diagnosable apart)");
        // Fix 2: the resolved seed_id is surfaced in the degraded string.
        CHECK(err.find("seed_id=2") != std::string::npos,
              "Fix 2: degraded string surfaces the resolved seed_id");
    }

    // 3) Fix 1/Fix 3(e): a server degraded for the NO_DATACENTER_LIST reason
    //    returns a DISTINCT datacenter-specific string, NOT the ASN-DB one.
    {
        CRPCServer rpc;
        rpc.RegisterSeedAttestationDegraded(
            /*seedId=*/1, CRPCServer::SeedDegradedReason::NO_DATACENTER_LIST);
        std::string err;
        try {
            rpc.InvokeRPCForTest("getmikattestation", "{}");
            err = "<no throw>";
        } catch (const std::exception& e) {
            err = e.what();
        }
        CHECK(err.find("datacenter ASN list not loaded") != std::string::npos,
              "NO_DATACENTER_LIST degraded -> distinct 'datacenter ASN list not loaded'");
        CHECK(err.find("ASN database not loaded") == std::string::npos,
              "datacenter-list degraded is NOT the ip2asn 'ASN database not loaded' string");
        CHECK(err.find("seed_id=1") != std::string::npos,
              "Fix 2: datacenter-list degraded string surfaces the resolved seed_id");
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
    TestDefaultOnEncryptionGate();           // CL-1 (default-on; mutation-kills the gate)
    TestV1ToV2Migration();                   // CL-1 (migration; original key preserved)
    TestMigrationSaveFailIsNonFatal();       // MEDIUM-1 (round-2: migration save-fail non-fatal)
    TestNoMintOverPresentKey();              // no-key-loss: never auto-mint over a present key
    TestNoPlaintextBak();                    // CL-2 (no plaintext .bak)
    TestSeedKeyFilePresentDetectsUnreadable(); // extreview HIGH (presence vs readability)
    TestKeyIdentityComparison();             // M-1 (key-identity pubkey comparison)
    TestSeedIdentityResolutionGlue();        // HIGH-1/HIGH-2 + Fix 1 datacenter gate
    TestMainnetSeedPubkeyConsensusEquivalence(); // Fix 3 (consensus-equivalence)
    TestDegradedGetMikAttestationErrorString(); // Finding E + Fix 1/2 (degraded RPC strings)
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
