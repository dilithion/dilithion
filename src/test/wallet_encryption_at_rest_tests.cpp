// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * LP-7 — Wallet encryption-at-rest tests
 *
 * Covers the three load-bearing scenarios from the LP-7 contract (§3.2):
 *
 *   1. SECRECY REGRESSION (S-001) + NEGATIVE CONTROL
 *      - Create an HD wallet, save it UNENCRYPTED → the 32-byte seed and
 *        32-byte chaincode are PRESENT in the on-disk file (negative control:
 *        proves the byte-scan can find the seed when it is there).
 *      - Encrypt the same wallet, lock it, save → the seed and chaincode
 *        plaintext bytes are ABSENT from the on-disk file.
 *
 *   2. MIGRATION ROUND-TRIP (A-012 / S-002 / S-003) + INTERRUPTED MIGRATION
 *      - Hand-build a LEGACY v6 plaintext-seed encrypted wallet on disk
 *        (the pre-fix bug shape), open it with the fixed binary, unlock →
 *        assert (a) seed now ABSENT from disk, (b) file version bumped to 7,
 *        (c) mnemonic still exportable (Inv-4), (d) the default address is
 *        unchanged across migration.
 *      - INTERRUPTED migration: simulate a crash mid-rewrite by leaving a
 *        stale ".tmp" file and making the rename target read-only is not
 *        portable; instead we assert the atomicity *invariant directly*: after
 *        a forced save failure the ORIGINAL legacy file is byte-for-byte
 *        unchanged and still opens (old-or-new, never corrupt).
 *
 *   3. AUTH-TAMPER (S-004)
 *      - Take a migrated v7 wallet, flip a byte in the encrypted-seed
 *        ciphertext on disk → unlock/decrypt is REJECTED.
 *      - Strip the HD-master MAC to empty on a v7 wallet → REJECTED.
 *
 * These tests drive the real CWallet against real on-disk files (no mocks).
 */

#include <wallet/wallet.h>
#include <wallet/crypter.h>
#include <wallet/hd_derivation.h>
#include <wallet/mnemonic.h>

#include <crypto/sha3.h>
#include <crypto/hmac_sha3.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED   "\033[31m"
#define COLOR_BLUE  "\033[34m"
#define COLOR_RESET "\033[0m"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) {                                                          \
            std::cout << COLOR_GREEN "  [PASS] " COLOR_RESET << msg << "\n"; \
            ++g_pass;                                                        \
        } else {                                                            \
            std::cout << COLOR_RED   "  [FAIL] " COLOR_RESET << msg << "\n"; \
            ++g_fail;                                                        \
        }                                                                    \
    } while (0)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> ReadFileBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

static bool WriteFileBytes(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

// Search for a needle byte-sequence inside a haystack.
static bool Contains(const std::vector<uint8_t>& hay, const uint8_t* needle, size_t n) {
    if (n == 0 || hay.size() < n) return false;
    for (size_t i = 0; i + n <= hay.size(); ++i) {
        if (std::memcmp(hay.data() + i, needle, n) == 0) return true;
    }
    return false;
}

// Read the file-format version from a Dilithion wallet file (offset 8, uint32).
static uint32_t FileVersion(const std::string& path) {
    std::vector<uint8_t> b = ReadFileBytes(path);
    if (b.size() < 12) return 0;
    uint32_t v = 0;
    std::memcpy(&v, b.data() + 8, 4);
    return v;
}

// Derive the master seed+chaincode the wallet stores from a mnemonic.
static bool DeriveSeedChaincode(const std::string& mnemonic,
                                std::vector<uint8_t>& seedOut,
                                std::vector<uint8_t>& chaincodeOut) {
    uint8_t bip39seed[64];
    if (!CMnemonic::ToSeed(mnemonic, "", bip39seed)) return false;
    CHDExtendedKey master;
    DeriveMaster(bip39seed, master);
    memory_cleanse(bip39seed, 64);
    seedOut.assign(master.seed, master.seed + 32);
    chaincodeOut.assign(master.chaincode, master.chaincode + 32);
    return true;
}

// Buffered little-endian writers for the legacy v6 builder.
static void PutU32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}
static void PutBytes(std::vector<uint8_t>& v, const uint8_t* p, size_t n) {
    v.insert(v.end(), p, p + n);
}
static void PutBytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    v.insert(v.end(), b.begin(), b.end());
}

// Pad/truncate an address blob to the fixed 21-byte on-disk width.
static std::vector<uint8_t> out_default_or(const std::vector<uint8_t>& a) {
    std::vector<uint8_t> r = a;
    r.resize(21, 0);
    return r;
}

// Read a little-endian uint32 at an absolute byte offset.
static uint32_t GetU32(const std::vector<uint8_t>& b, size_t off) {
    uint32_t x = 0;
    if (off + 4 <= b.size()) std::memcpy(&x, b.data() + off, 4);
    return x;
}
static void SetU32(std::vector<uint8_t>& b, size_t off, uint32_t x) {
    if (off + 4 <= b.size()) std::memcpy(b.data() + off, &x, 4);
}

// ---------------------------------------------------------------------------
// MEDIUM-1 helper: recompute the OUTER file-integrity HMAC over a (possibly
// mutated) v7 wallet image so that Load() passes its file-HMAC check and the
// per-RECORD MAC verification becomes the only remaining authenticity gate.
//
// Mirrors CWallet::SaveUnlocked exactly for the encrypted case: the HMAC key is
// the first 32 bytes of the master-key salt (16 bytes here, zero-padded to 32),
// and the HMAC covers [file-HMAC salt 32][body...] = everything from offset
// HEADER_LEN onward. The master-key salt is in-file plaintext, so an attacker
// who strips a per-record MAC can trivially repair this outer HMAC — which is
// exactly why the per-record MAC is the real defense and must be enforced.
//
// v7 file layout (encrypted):
//   [0]  magic            8
//   [8]  version u32      4
//   [12] flags u32        4
//   [16] file-HMAC       32   (HEADER_LEN = 48)
//   [48] file-HMAC salt  32
//   [80] master-key block: cryptedLen u32 | ct | mkSalt 16 | mkIV 16 |
//                          derivMethod u32 | iters u32 | macLen u32 | mac
//   ... (mnemonic, HD-master, keys, ...)
// ---------------------------------------------------------------------------
static const size_t LP7_HEADER_LEN  = 48;   // magic+version+flags+HMAC
static const size_t LP7_MKSALT_OFF  = 80 + 4;  // after [file-salt 32][cryptedLen u32]; +cryptedLen

static bool RecomputeFileHMAC(std::vector<uint8_t>& file) {
    if (file.size() < LP7_HEADER_LEN + WALLET_FILE_SALT_SIZE) return false;
    // master-key salt sits at offset 80 + 4 + cryptedKeyLen
    uint32_t cryptedKeyLen = GetU32(file, 80);
    size_t mkSaltOff = 80 + 4 + cryptedKeyLen;
    if (mkSaltOff + WALLET_CRYPTO_SALT_SIZE > file.size()) return false;

    std::vector<uint8_t> hmac_key(32, 0);
    std::memcpy(hmac_key.data(), file.data() + mkSaltOff,
                std::min<size_t>(32, WALLET_CRYPTO_SALT_SIZE));

    const uint8_t* body = file.data() + LP7_HEADER_LEN;
    size_t body_len = file.size() - LP7_HEADER_LEN;
    std::vector<uint8_t> hmac(WALLET_FILE_HMAC_SIZE);
    HMAC_SHA3_256(hmac_key.data(), hmac_key.size(), body, body_len, hmac.data());
    std::memcpy(file.data() + 16, hmac.data(), WALLET_FILE_HMAC_SIZE);
    return true;
}

// Strip the MASTER-KEY MAC from a v7 image: locate the macLen field, set it to
// 0, and drop the trailing MAC bytes. Returns false if the layout doesn't match.
static bool StripMasterKeyMAC(std::vector<uint8_t>& file) {
    if (file.size() < 80 + 4) return false;
    uint32_t cryptedKeyLen = GetU32(file, 80);
    // macLen field offset: 80 + 4(cryptedLen) + cryptedKeyLen + 16(mkSalt)
    //                      + 16(mkIV) + 4(derivMethod) + 4(iters)
    size_t macLenOff = 80 + 4 + cryptedKeyLen + 16 + 16 + 4 + 4;
    if (macLenOff + 4 > file.size()) return false;
    uint32_t macLen = GetU32(file, macLenOff);
    if (macLen == 0 || macLen > 64) return false;            // expect a present MAC
    if (macLenOff + 4 + macLen > file.size()) return false;
    // Drop the MAC bytes and zero the length.
    file.erase(file.begin() + macLenOff + 4,
               file.begin() + macLenOff + 4 + macLen);
    SetU32(file, macLenOff, 0);
    return true;
}

// Strip a PER-ADDRESS key MAC from a v7 image. The on-disk per-address key
// record (SaveUnlocked) is:
//   [addr 21][pubKey 1952][cryptedLen u32][ct][iv 16][macLen u32][mac]
// We locate the record by its 21-byte address, then walk to the macLen field and
// drop the 64 MAC bytes. Unlike stripping the master-key MAC, this leaves
// masterKey.IsValid() TRUE, so Load()'s outer-HMAC key selection (which keys on
// the master-key salt only for valid master keys) is unchanged — isolating the
// PER-RECORD MAC verify as the sole remaining gate.
static bool StripPerAddressKeyMAC(std::vector<uint8_t>& file,
                                  const std::vector<uint8_t>& addr21) {
    if (addr21.size() < 21) return false;
    // Find the address bytes (search past the header/master/HD region).
    for (size_t i = 0; i + 21 <= file.size(); ++i) {
        if (std::memcmp(file.data() + i, addr21.data(), 21) != 0) continue;
        // Candidate record start at i. Layout: [addr 21][pubKey 1952]
        //   [cryptedLen u32][ct][iv 16][macLen u32][mac]
        size_t off = i + 21 + DILITHIUM_PUBLICKEY_SIZE;
        if (off + 4 > file.size()) continue;
        uint32_t cryptedLen = GetU32(file, off);
        if (cryptedLen == 0 || cryptedLen > 8192) continue;  // sanity / wrong match
        size_t macLenOff = off + 4 + cryptedLen + 16;        // after ct + iv16
        if (macLenOff + 4 > file.size()) continue;
        uint32_t macLen = GetU32(file, macLenOff);
        if (macLen != 64) continue;                          // a v7 per-address MAC is 64B
        if (macLenOff + 4 + macLen > file.size()) continue;
        // Found it — drop the MAC bytes and zero the length.
        file.erase(file.begin() + macLenOff + 4,
                   file.begin() + macLenOff + 4 + macLen);
        SetU32(file, macLenOff, 0);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Legacy v6 plaintext-seed encrypted-wallet builder.
//
// Reproduces the EXACT pre-LP-7 on-disk layout for a MINIMAL HD wallet that is
// encrypted but has NO mapKeys/mapCryptedKeys, NO txs, NO MIK, NO sentTx — i.e.
// the bug shape: master key encrypted, but the HD seed written PLAINTEXT in the
// fixed 32+32 slots and the mnemonic stored under the seed-derived obfuscation
// key. Layout (matches SaveUnlocked v6):
//   [Magic 8][Version u32][Flags u32][HMAC 32][Salt 32]
//   <master key block: cryptedLen u32, ct, salt16, iv16, derivMethod u32,
//                      iters u32, macLen u32, mac64>
//   <HD: mnemonicLen u32, ct, iv16 | seed32 | chaincode32 | depth u32 |
//        fingerprint u32 | child_index u32 | encFlag u8 (0) >
//   <HD chain state: account u32, ext u32, int u32>
//   <numPaths u32 = 0>
//   <numCryptedKeys u32 = 0>
//   <hasDefault u8 (1), addr 21>
//   <numTxs u32 = 0>
//   <bestHash 32><bestHeight i32>
//   <hasMIK u8 (0)>
//   <numSentTx u32 = 0>
//   [HMAC over Salt..end, keyed by first 32 bytes of master-key salt]
// ---------------------------------------------------------------------------
struct LegacyV6Result {
    std::vector<uint8_t> seed;        // plaintext seed (for scan assertions)
    std::vector<uint8_t> chaincode;   // plaintext chaincode
    std::string mnemonic;             // for Inv-4 export assertion
    std::vector<uint8_t> defaultAddr; // 21-byte default address
};

static bool BuildLegacyV6Wallet(const std::string& path,
                                const std::string& passphrase,
                                LegacyV6Result& out,
                                // LP-7 (F1) test hook: when non-empty, this string is
                                // encrypted into the legacy obfuscated-mnemonic slot
                                // INSTEAD of the real mnemonic. The obfuscation key and
                                // plaintext seed are unchanged, so the fixed binary's
                                // Step-1 decrypt SUCCEEDS (padding-valid) but yields
                                // these bytes — letting a test prove migration ABORTS
                                // when the recovered plaintext is not a valid BIP39
                                // mnemonic. Empty (default) ⇒ encrypt the real mnemonic.
                                const std::string& mnemonicPlaintextOverride = "",
                                // LP-7 (F1 fold, LOW-3) test hook: when true, the mnemonic
                                // slot is encrypted DIRECTLY under the wallet master key
                                // (no MAC) instead of the seed-derived obfuscation key.
                                // This is the legacy master-key-encrypted-mnemonic shape:
                                // migration's Step-1 obfuscation decrypt FAILS (wrong key)
                                // and the master-key FALLBACK arm (wallet.cpp ~5747)
                                // recovers the plaintext — exercising the fallback arm's
                                // path into the identity guard. Default false ⇒ Step-1.
                                bool encryptMnemonicUnderMasterKey = false) {
    // --- 1. Use a real CWallet to mint a consistent HD wallet, then read out the
    //        pieces we need (mnemonic, seed, chaincode, default address). ---
    std::string scratch = path + ".scratch";
    std::remove(scratch.c_str());

    std::string mnemonic;
    std::vector<uint8_t> defAddr;
    {
        CWallet w;
        w.SetWalletFile(scratch);
        if (!w.GenerateHDWallet(mnemonic)) return false;
        std::vector<CDilithiumAddress> addrs = w.GetAddresses();
        if (addrs.empty()) return false;
        CDilithiumAddress def = w.GetNewHDAddress();  // ensure a default exists
        (void)def;
        // The first sorted address is the v6 default for HD wallets.
        defAddr = w.GetAddresses().front().GetData();
    }
    std::remove(scratch.c_str());

    std::vector<uint8_t> seed, chaincode;
    if (!DeriveSeedChaincode(mnemonic, seed, chaincode)) return false;

    CHDExtendedKey master;
    {
        uint8_t bip39seed[64];
        if (!CMnemonic::ToSeed(mnemonic, "", bip39seed)) return false;
        DeriveMaster(bip39seed, master);
        memory_cleanse(bip39seed, 64);
    }

    // --- 2. Build the encrypted master key block (PBKDF2 + AES-CBC + MAC, legacy
    //        AES-keyed HMAC keying). ---
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) return false;

    std::vector<uint8_t> mkSalt;
    if (!GenerateSalt(mkSalt)) return false;
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, mkSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) return false;
    std::vector<uint8_t> mkIV;
    if (!GenerateIV(mkIV)) return false;

    CCrypter mkCrypter;
    if (!mkCrypter.SetKey(derivedKey, mkIV)) return false;
    std::vector<uint8_t> mkCipher;
    if (!mkCrypter.Encrypt(vMasterKeyPlain, mkCipher)) return false;
    std::vector<uint8_t> mkMAC;
    // Legacy keying (AES key == HMAC key) so the fixed binary's Unlock MAC check
    // (which uses legacy keying for v<7) passes.
    if (!mkCrypter.ComputeMAC(mkCipher, mkMAC, /*useLegacyKeying=*/true)) return false;

    // --- 3. Build the legacy mnemonic slot. By default it is obfuscated under the
    //        seed-derived key (HKDF(seed,"mnemonic")). For the LOW-3 fallback-arm
    //        fixture it is encrypted DIRECTLY under the master key (no MAC), so the
    //        migration's Step-1 obfuscation decrypt fails and the master-key fallback
    //        arm engages. ---
    std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
    if (encryptMnemonicUnderMasterKey) {
        obfKey = vMasterKeyPlain;  // legacy master-key-encrypted mnemonic (fallback arm)
    } else {
        std::vector<uint8_t> hdSeed(master.seed, master.seed + 32);
        DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());
    }
    std::vector<uint8_t> mnIV;
    if (!GenerateIV(mnIV)) return false;
    CCrypter mnCrypter;
    if (!mnCrypter.SetKey(obfKey, mnIV)) return false;
    // LP-7 (F1): optionally encrypt garbage plaintext instead of the real mnemonic,
    // so the fixed binary's Step-1 decrypt round-trips (padding-valid) to non-BIP39
    // bytes — the exact precondition F1 must catch and abort on.
    const std::string& mnSource = mnemonicPlaintextOverride.empty()
                                      ? mnemonic : mnemonicPlaintextOverride;
    std::vector<uint8_t> mnemonicBytes(mnSource.begin(), mnSource.end());
    std::vector<uint8_t> mnCipher;
    if (!mnCrypter.Encrypt(mnemonicBytes, mnCipher)) return false;

    // --- 4. Assemble the body (everything after the [Salt]). ---
    std::vector<uint8_t> hmacSalt(WALLET_FILE_SALT_SIZE);  // 32 bytes (NOT the 16-byte IV size)
    if (!GetStrongRandBytes(hmacSalt.data(), hmacSalt.size())) return false;

    std::vector<uint8_t> body;  // starts at the file-HMAC salt
    PutBytes(body, hmacSalt);

    // master key block
    PutU32(body, static_cast<uint32_t>(mkCipher.size()));
    PutBytes(body, mkCipher);
    PutBytes(body, mkSalt);                // 16
    PutBytes(body, mkIV);                  // 16
    PutU32(body, 0u);                      // nDerivationMethod
    PutU32(body, WALLET_CRYPTO_PBKDF2_ROUNDS);
    PutU32(body, static_cast<uint32_t>(mkMAC.size()));
    PutBytes(body, mkMAC);

    // HD block (v6 layout): mnemonic
    PutU32(body, static_cast<uint32_t>(mnCipher.size()));
    PutBytes(body, mnCipher);
    PutBytes(body, mnIV);                  // 16
    // HD master key — PLAINTEXT seed + chaincode (the bug)
    PutBytes(body, master.seed, 32);
    PutBytes(body, master.chaincode, 32);
    PutU32(body, master.depth);
    PutU32(body, master.fingerprint);
    PutU32(body, master.child_index);
    body.push_back(0);                     // encrypted_flag = 0 (no IV follows)
    // HD chain state
    PutU32(body, 0u);                      // account
    PutU32(body, 0u);                      // external index (0 ⇒ no derived paths,
    PutU32(body, 0u);                      // internal index   consistent with 0 paths
                                           //                  → passes the HD gap check)
    // HD path mappings — 0 (keeps the builder minimal; load tolerates this)
    PutU32(body, 0u);

    // keys (encrypted wallet) — 0 crypted keys
    PutU32(body, 0u);

    // default address
    body.push_back(1);                     // hasDefault
    PutBytes(body, out_default_or(defAddr));// 21 bytes

    // transactions — 0
    PutU32(body, 0u);

    // best block pointer
    std::vector<uint8_t> bestHash(32, 0);
    PutBytes(body, bestHash);
    int32_t bestHeight = -1;
    PutBytes(body, reinterpret_cast<const uint8_t*>(&bestHeight), sizeof(bestHeight));

    // MIK — none
    body.push_back(0);                     // hasMIK = 0

    // sent tx — 0
    PutU32(body, 0u);

    // --- 5. Compute the file integrity HMAC (key = first 32 bytes of mk salt). ---
    std::vector<uint8_t> hmacKey(32, 0);
    std::memcpy(hmacKey.data(), mkSalt.data(), std::min<size_t>(32, mkSalt.size()));
    std::vector<uint8_t> fileHMAC(32);
    HMAC_SHA3_256(hmacKey.data(), hmacKey.size(), body.data(), body.size(), fileHMAC.data());

    // --- 6. Assemble the full file: [Magic][Version][Flags][HMAC][body...] ---
    std::vector<uint8_t> file;
    file.insert(file.end(), WALLET_FILE_MAGIC_V6, WALLET_FILE_MAGIC_V6 + 8);
    PutU32(file, WALLET_FILE_VERSION_6);
    uint32_t flags = 0x01 /*encrypted*/ | 0x02 /*HD*/;
    PutU32(file, flags);
    PutBytes(file, fileHMAC);
    PutBytes(file, body);

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());
    memory_cleanse(obfKey.data(), obfKey.size());

    out.seed = seed;
    out.chaincode = chaincode;
    out.mnemonic = mnemonic;
    out.defaultAddr = defAddr;

    return WriteFileBytes(path, file);
}

// ---------------------------------------------------------------------------
// Legacy v6 builder WITH a per-address spending key carrying a LEGACY-keyed MAC.
//
// HIGH-2 regression scaffold. Reproduces the exact pre-LP-7 v6 on-disk shape of
// a wallet that holds ONE encrypted per-address spending key whose MAC was
// computed with the LEGACY AES-keyed HMAC (AES key == HMAC key) — the keying
// every pre-LP-7 build used before key separation was introduced. On the
// unfixed binary, GetKey verifies this MAC with the SEPARATED keying (the :336
// default), so it mismatches and the key is unspendable. On the fixed binary the
// version-keyed gate selects legacy keying for v6 and the key is spendable; and
// migration re-MACs it under v7 keying so it stays spendable post-migration.
//
// Builds on the v6 layout from BuildLegacyV6Wallet but sets numCryptedKeys=1 and
// emits one per-address key record:
//   [addr 21][pubKey 1952][cryptedLen u32][ct][iv 16][macLen u32][mac 64]
// ---------------------------------------------------------------------------
struct LegacyV6KeyResult {
    std::vector<uint8_t> seed;
    std::vector<uint8_t> chaincode;
    std::string mnemonic;
    std::vector<uint8_t> defaultAddr;   // 21-byte default (HD) address
    CDilithiumAddress    perAddr;       // address of the imported per-address key
    std::vector<uint8_t> perAddrPriv;   // its plaintext private key (for spend assertion)
};

static bool BuildLegacyV6WalletWithPerAddressKey(const std::string& path,
                                                 const std::string& passphrase,
                                                 LegacyV6KeyResult& out) {
    std::string scratch = path + ".scratch";
    std::remove(scratch.c_str());

    std::string mnemonic;
    std::vector<uint8_t> defAddr;
    {
        CWallet w;
        w.SetWalletFile(scratch);
        if (!w.GenerateHDWallet(mnemonic)) return false;
        std::vector<CDilithiumAddress> addrs = w.GetAddresses();
        if (addrs.empty()) return false;
        defAddr = w.GetAddresses().front().GetData();
    }
    std::remove(scratch.c_str());

    std::vector<uint8_t> seed, chaincode;
    if (!DeriveSeedChaincode(mnemonic, seed, chaincode)) return false;

    CHDExtendedKey master;
    {
        uint8_t bip39seed[64];
        if (!CMnemonic::ToSeed(mnemonic, "", bip39seed)) return false;
        DeriveMaster(bip39seed, master);
        memory_cleanse(bip39seed, 64);
    }

    // Encrypted master key block (legacy AES-keyed MAC so v<7 Unlock passes).
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) return false;
    std::vector<uint8_t> mkSalt;
    if (!GenerateSalt(mkSalt)) return false;
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, mkSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) return false;
    std::vector<uint8_t> mkIV;
    if (!GenerateIV(mkIV)) return false;
    CCrypter mkCrypter;
    if (!mkCrypter.SetKey(derivedKey, mkIV)) return false;
    std::vector<uint8_t> mkCipher;
    if (!mkCrypter.Encrypt(vMasterKeyPlain, mkCipher)) return false;
    std::vector<uint8_t> mkMAC;
    if (!mkCrypter.ComputeMAC(mkCipher, mkMAC, /*useLegacyKeying=*/true)) return false;

    // Legacy obfuscated mnemonic (key = HKDF(seed,"mnemonic")).
    std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
    {
        std::vector<uint8_t> hdSeed(master.seed, master.seed + 32);
        DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());
    }
    std::vector<uint8_t> mnIV;
    if (!GenerateIV(mnIV)) return false;
    CCrypter mnCrypter;
    if (!mnCrypter.SetKey(obfKey, mnIV)) return false;
    std::vector<uint8_t> mnemonicBytes(mnemonic.begin(), mnemonic.end());
    std::vector<uint8_t> mnCipher;
    if (!mnCrypter.Encrypt(mnemonicBytes, mnCipher)) return false;

    // --- The per-address spending key: real keypair, encrypted under the master
    //     key with its own IV, MAC'd with LEGACY keying. ---
    CKey perKey;
    if (!WalletCrypto::GenerateKeyPair(perKey)) return false;
    CDilithiumAddress perAddr(perKey.vchPubKey);  // same derivation Load uses
    std::vector<uint8_t> keyIV;
    if (!GenerateIV(keyIV)) return false;
    CCrypter keyCrypter;
    if (!keyCrypter.SetKey(vMasterKeyPlain, keyIV)) return false;
    std::vector<uint8_t> keyCipher;
    if (!keyCrypter.Encrypt(perKey.vchPrivKey, keyCipher)) return false;
    std::vector<uint8_t> keyMAC;
    // LEGACY keying — this is the crux: a pre-LP-7 build wrote per-address MACs
    // keyed with the AES key, NOT the separated MAC key.
    if (!keyCrypter.ComputeMAC(keyCipher, keyMAC, /*useLegacyKeying=*/true)) return false;

    // --- Assemble the body. ---
    std::vector<uint8_t> hmacSalt(WALLET_FILE_SALT_SIZE);
    if (!GetStrongRandBytes(hmacSalt.data(), hmacSalt.size())) return false;

    std::vector<uint8_t> body;
    PutBytes(body, hmacSalt);

    // master key block
    PutU32(body, static_cast<uint32_t>(mkCipher.size()));
    PutBytes(body, mkCipher);
    PutBytes(body, mkSalt);
    PutBytes(body, mkIV);
    PutU32(body, 0u);
    PutU32(body, WALLET_CRYPTO_PBKDF2_ROUNDS);
    PutU32(body, static_cast<uint32_t>(mkMAC.size()));
    PutBytes(body, mkMAC);

    // HD block (v6): mnemonic + PLAINTEXT seed (the bug shape)
    PutU32(body, static_cast<uint32_t>(mnCipher.size()));
    PutBytes(body, mnCipher);
    PutBytes(body, mnIV);
    PutBytes(body, master.seed, 32);
    PutBytes(body, master.chaincode, 32);
    PutU32(body, master.depth);
    PutU32(body, master.fingerprint);
    PutU32(body, master.child_index);
    body.push_back(0);                     // encrypted_flag = 0

    // HD chain state + 0 path mappings
    PutU32(body, 0u);
    PutU32(body, 0u);
    PutU32(body, 0u);
    PutU32(body, 0u);                      // numPaths = 0

    // keys — ONE encrypted per-address key
    PutU32(body, 1u);                      // numCryptedKeys = 1
    PutBytes(body, out_default_or(perAddr.GetData()));     // [addr 21]
    PutBytes(body, perKey.vchPubKey);                      // [pubKey 1952]
    PutU32(body, static_cast<uint32_t>(keyCipher.size())); // [cryptedLen]
    PutBytes(body, keyCipher);                             // [ct]
    PutBytes(body, keyIV);                                 // [iv 16]
    PutU32(body, static_cast<uint32_t>(keyMAC.size()));    // [macLen = 64]
    PutBytes(body, keyMAC);                                // [mac]

    // default address (HD default)
    body.push_back(1);
    PutBytes(body, out_default_or(defAddr));

    // transactions — 0
    PutU32(body, 0u);
    // best block
    std::vector<uint8_t> bestHash(32, 0);
    PutBytes(body, bestHash);
    int32_t bestHeight = -1;
    PutBytes(body, reinterpret_cast<const uint8_t*>(&bestHeight), sizeof(bestHeight));
    // MIK — none
    body.push_back(0);
    // sent tx — 0
    PutU32(body, 0u);

    // file integrity HMAC (key = first 32 bytes of mk salt)
    std::vector<uint8_t> hmacKey(32, 0);
    std::memcpy(hmacKey.data(), mkSalt.data(), std::min<size_t>(32, mkSalt.size()));
    std::vector<uint8_t> fileHMAC(32);
    HMAC_SHA3_256(hmacKey.data(), hmacKey.size(), body.data(), body.size(), fileHMAC.data());

    std::vector<uint8_t> file;
    file.insert(file.end(), WALLET_FILE_MAGIC_V6, WALLET_FILE_MAGIC_V6 + 8);
    PutU32(file, WALLET_FILE_VERSION_6);
    uint32_t flags = 0x01 | 0x02;
    PutU32(file, flags);
    PutBytes(file, fileHMAC);
    PutBytes(file, body);

    out.seed = seed;
    out.chaincode = chaincode;
    out.mnemonic = mnemonic;
    out.defaultAddr = defAddr;
    out.perAddr = perAddr;
    out.perAddrPriv.assign(perKey.vchPrivKey.begin(), perKey.vchPrivKey.end());

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());
    memory_cleanse(obfKey.data(), obfKey.size());

    return WriteFileBytes(path, file);
}

// ---------------------------------------------------------------------------
// v7-HEADER + PLAINTEXT-SEED builder (Cursor L2 regression scaffold).
//
// Reproduces the EXACT on-disk shape a *pre-fix binary that already wrote v7*
// could have produced: a v7 file ("DILWLT07") whose WALLET is encrypted (master
// key under a passphrase) but whose HD master SEED is still PLAINTEXT at rest in
// the v7 plaintext-HD-block slots (encrypted_flag=0, hdEncLen=0). This is the LP-7
// plaintext-seed-at-rest state with a v7 header — detection is handled at
// wallet.cpp:2169 (arm migration when isEncrypted && plaintext-seed v7 branch),
// but until now only the legacy-v6 shape was byte-tested (Test 2c). This builder
// lets us byte-test the v7-labelled shape end-to-end (load → armed + plaintext at
// rest → unlock → migrate → no plaintext at rest, flag clear), the same
// ReadFileBytes/Contains approach as Test 2c.
//
// v7 layout differences vs v6 (see Load: wallet.cpp ~2055 mnemonic, ~2099 HD):
//   - magic "DILWLT07", version 7
//   - mnemonic block carries a trailing [mnMacLen][mnMAC] (v7 requires non-empty
//     MAC on an encrypted wallet; Load only checks mnMacLen!=0, migration recovers
//     the mnemonic via the obfuscation key, so a legacy-keyed MAC blob suffices)
//   - HD block: [encrypted_flag=0][hdEncLen=0][seed32][chaincode32][depth][fp][ci]
//     (NOTE the leading hdEncLen=0 u32 — absent in the v6 layout)
// ---------------------------------------------------------------------------
static bool BuildV7PlaintextSeedWallet(const std::string& path,
                                       const std::string& passphrase,
                                       LegacyV6Result& out) {
    std::string scratch = path + ".scratch";
    std::remove(scratch.c_str());

    std::string mnemonic;
    std::vector<uint8_t> defAddr;
    {
        CWallet w;
        w.SetWalletFile(scratch);
        if (!w.GenerateHDWallet(mnemonic)) return false;
        std::vector<CDilithiumAddress> addrs = w.GetAddresses();
        if (addrs.empty()) return false;
        CDilithiumAddress def = w.GetNewHDAddress();
        (void)def;
        defAddr = w.GetAddresses().front().GetData();
    }
    std::remove(scratch.c_str());

    std::vector<uint8_t> seed, chaincode;
    if (!DeriveSeedChaincode(mnemonic, seed, chaincode)) return false;

    CHDExtendedKey master;
    {
        uint8_t bip39seed[64];
        if (!CMnemonic::ToSeed(mnemonic, "", bip39seed)) return false;
        DeriveMaster(bip39seed, master);
        memory_cleanse(bip39seed, 64);
    }

    // Encrypted master key block. v7 master MAC uses the SEPARATED (default) keying.
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) return false;
    std::vector<uint8_t> mkSalt;
    if (!GenerateSalt(mkSalt)) return false;
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, mkSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) return false;
    std::vector<uint8_t> mkIV;
    if (!GenerateIV(mkIV)) return false;
    CCrypter mkCrypter;
    if (!mkCrypter.SetKey(derivedKey, mkIV)) return false;
    std::vector<uint8_t> mkCipher;
    if (!mkCrypter.Encrypt(vMasterKeyPlain, mkCipher)) return false;
    std::vector<uint8_t> mkMAC;
    // v7 master record: separated keying (useLegacyKeying=false) so the fixed
    // binary's v7 Unlock MAC check passes.
    if (!mkCrypter.ComputeMAC(mkCipher, mkMAC, /*useLegacyKeying=*/false)) return false;

    // Legacy obfuscated mnemonic (key = HKDF(seed,"mnemonic")). The pre-fix binary
    // never re-encrypted the mnemonic under the master key (the same as v6), so the
    // obfuscation-keyed ciphertext is faithful. We attach a non-empty MAC because v7
    // Load requires mnMacLen!=0 on an encrypted wallet (wallet.cpp:2089).
    std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
    {
        std::vector<uint8_t> hdSeed(master.seed, master.seed + 32);
        DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());
    }
    std::vector<uint8_t> mnIV;
    if (!GenerateIV(mnIV)) return false;
    CCrypter mnCrypter;
    if (!mnCrypter.SetKey(obfKey, mnIV)) return false;
    std::vector<uint8_t> mnemonicBytes(mnemonic.begin(), mnemonic.end());
    std::vector<uint8_t> mnCipher;
    if (!mnCrypter.Encrypt(mnemonicBytes, mnCipher)) return false;
    std::vector<uint8_t> mnMAC;
    if (!mnCrypter.ComputeMAC(mnCipher, mnMAC, /*useLegacyKeying=*/false)) return false;

    // --- Assemble the body. ---
    std::vector<uint8_t> hmacSalt(WALLET_FILE_SALT_SIZE);
    if (!GetStrongRandBytes(hmacSalt.data(), hmacSalt.size())) return false;

    std::vector<uint8_t> body;
    PutBytes(body, hmacSalt);

    // master key block
    PutU32(body, static_cast<uint32_t>(mkCipher.size()));
    PutBytes(body, mkCipher);
    PutBytes(body, mkSalt);                // 16
    PutBytes(body, mkIV);                  // 16
    PutU32(body, 0u);                      // nDerivationMethod
    PutU32(body, WALLET_CRYPTO_PBKDF2_ROUNDS);
    PutU32(body, static_cast<uint32_t>(mkMAC.size()));
    PutBytes(body, mkMAC);

    // HD block (v7): mnemonic + trailing MAC
    PutU32(body, static_cast<uint32_t>(mnCipher.size()));
    PutBytes(body, mnCipher);
    PutBytes(body, mnIV);                  // 16
    PutU32(body, static_cast<uint32_t>(mnMAC.size()));   // v7-only mnemonic MAC len
    PutBytes(body, mnMAC);                               // v7-only mnemonic MAC

    // HD master key — v7 PLAINTEXT layout (the bug): [enc_flag=0][hdEncLen=0][seed][cc]...
    body.push_back(0);                     // encrypted_flag = 0 (plaintext seed)
    PutU32(body, 0u);                      // hdEncLen = 0 (plaintext branch)
    PutBytes(body, master.seed, 32);
    PutBytes(body, master.chaincode, 32);
    PutU32(body, master.depth);
    PutU32(body, master.fingerprint);
    PutU32(body, master.child_index);

    // HD chain state + 0 path mappings
    PutU32(body, 0u);                      // account
    PutU32(body, 0u);                      // external index
    PutU32(body, 0u);                      // internal index
    PutU32(body, 0u);                      // numPaths = 0

    // keys (encrypted wallet) — 0 crypted keys
    PutU32(body, 0u);

    // default address
    body.push_back(1);                     // hasDefault
    PutBytes(body, out_default_or(defAddr));

    // transactions — 0
    PutU32(body, 0u);
    // best block
    std::vector<uint8_t> bestHash(32, 0);
    PutBytes(body, bestHash);
    int32_t bestHeight = -1;
    PutBytes(body, reinterpret_cast<const uint8_t*>(&bestHeight), sizeof(bestHeight));
    // MIK — none
    body.push_back(0);
    // sent tx — 0
    PutU32(body, 0u);

    // file integrity HMAC (key = first 32 bytes of mk salt)
    std::vector<uint8_t> hmacKey(32, 0);
    std::memcpy(hmacKey.data(), mkSalt.data(), std::min<size_t>(32, mkSalt.size()));
    std::vector<uint8_t> fileHMAC(32);
    HMAC_SHA3_256(hmacKey.data(), hmacKey.size(), body.data(), body.size(), fileHMAC.data());

    // Full file: v7 magic + version 7
    std::vector<uint8_t> file;
    file.insert(file.end(), WALLET_FILE_MAGIC_V7, WALLET_FILE_MAGIC_V7 + 8);
    PutU32(file, WALLET_FILE_VERSION_7);
    uint32_t flags = 0x01 /*encrypted*/ | 0x02 /*HD*/;
    PutU32(file, flags);
    PutBytes(file, fileHMAC);
    PutBytes(file, body);

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());
    memory_cleanse(obfKey.data(), obfKey.size());

    out.seed = seed;
    out.chaincode = chaincode;
    out.mnemonic = mnemonic;
    out.defaultAddr = defAddr;

    return WriteFileBytes(path, file);
}

// ---------------------------------------------------------------------------
// Legacy v6 NON-HD builder with ONE legacy-MAC'd per-address key.
//
// Isolates the RAW v6 GetKey path (manifestation 1 of HIGH-2): a NON-HD
// encrypted wallet has no plaintext HD seed, so loading it does NOT set the
// seed-migration flag and Unlock does NOT migrate — m_loadedFileVersion stays 6
// when GetKey runs. This exercises the version-keyed selection in isolation
// (legacyKeying==true for v6) without any in-memory migration masking it. On the
// unfixed binary GetKey verifies the legacy-keyed MAC with separated keying →
// fails → the key is unspendable on a wallet that never migrates.
//
// Non-HD encrypted v6 layout (matches SaveUnlocked for is_hd_wallet=false):
//   [Magic 8][Version u32][Flags=0x01][HMAC 32][salt 32]
//   <master key block>
//   <numCryptedKeys u32 = 1><addr 21><pubKey 1952><cryptedLen u32><ct><iv 16>
//     <macLen u32 = 64><mac>
//   <hasDefault u8><addr 21><numTxs u32 = 0><bestHash 32><bestHeight i32>
//   <hasMIK u8 = 0><numSentTx u32 = 0>
// ---------------------------------------------------------------------------
struct LegacyV6NonHDResult {
    CDilithiumAddress    perAddr;
    std::vector<uint8_t> perAddrPriv;
};

static bool BuildLegacyV6NonHDWalletWithKey(const std::string& path,
                                            const std::string& passphrase,
                                            LegacyV6NonHDResult& out) {
    // Encrypted master key block (legacy AES-keyed MAC).
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) return false;
    std::vector<uint8_t> mkSalt;
    if (!GenerateSalt(mkSalt)) return false;
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, mkSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) return false;
    std::vector<uint8_t> mkIV;
    if (!GenerateIV(mkIV)) return false;
    CCrypter mkCrypter;
    if (!mkCrypter.SetKey(derivedKey, mkIV)) return false;
    std::vector<uint8_t> mkCipher;
    if (!mkCrypter.Encrypt(vMasterKeyPlain, mkCipher)) return false;
    std::vector<uint8_t> mkMAC;
    if (!mkCrypter.ComputeMAC(mkCipher, mkMAC, /*useLegacyKeying=*/true)) return false;

    // Per-address spending key: real keypair, encrypted under the master key,
    // MAC'd with LEGACY keying.
    CKey perKey;
    if (!WalletCrypto::GenerateKeyPair(perKey)) return false;
    CDilithiumAddress perAddr(perKey.vchPubKey);
    std::vector<uint8_t> keyIV;
    if (!GenerateIV(keyIV)) return false;
    CCrypter keyCrypter;
    if (!keyCrypter.SetKey(vMasterKeyPlain, keyIV)) return false;
    std::vector<uint8_t> keyCipher;
    if (!keyCrypter.Encrypt(perKey.vchPrivKey, keyCipher)) return false;
    std::vector<uint8_t> keyMAC;
    if (!keyCrypter.ComputeMAC(keyCipher, keyMAC, /*useLegacyKeying=*/true)) return false;

    std::vector<uint8_t> hmacSalt(WALLET_FILE_SALT_SIZE);
    if (!GetStrongRandBytes(hmacSalt.data(), hmacSalt.size())) return false;

    std::vector<uint8_t> body;
    PutBytes(body, hmacSalt);

    // master key block
    PutU32(body, static_cast<uint32_t>(mkCipher.size()));
    PutBytes(body, mkCipher);
    PutBytes(body, mkSalt);
    PutBytes(body, mkIV);
    PutU32(body, 0u);
    PutU32(body, WALLET_CRYPTO_PBKDF2_ROUNDS);
    PutU32(body, static_cast<uint32_t>(mkMAC.size()));
    PutBytes(body, mkMAC);

    // keys — ONE encrypted per-address key (no HD block; flags has no 0x02)
    PutU32(body, 1u);
    PutBytes(body, out_default_or(perAddr.GetData()));
    PutBytes(body, perKey.vchPubKey);
    PutU32(body, static_cast<uint32_t>(keyCipher.size()));
    PutBytes(body, keyCipher);
    PutBytes(body, keyIV);
    PutU32(body, static_cast<uint32_t>(keyMAC.size()));
    PutBytes(body, keyMAC);

    // default address = the per-address key
    body.push_back(1);
    PutBytes(body, out_default_or(perAddr.GetData()));
    // transactions — 0
    PutU32(body, 0u);
    // best block
    std::vector<uint8_t> bestHash(32, 0);
    PutBytes(body, bestHash);
    int32_t bestHeight = -1;
    PutBytes(body, reinterpret_cast<const uint8_t*>(&bestHeight), sizeof(bestHeight));
    // MIK — none
    body.push_back(0);
    // sent tx — 0
    PutU32(body, 0u);

    std::vector<uint8_t> hmacKey(32, 0);
    std::memcpy(hmacKey.data(), mkSalt.data(), std::min<size_t>(32, mkSalt.size()));
    std::vector<uint8_t> fileHMAC(32);
    HMAC_SHA3_256(hmacKey.data(), hmacKey.size(), body.data(), body.size(), fileHMAC.data());

    std::vector<uint8_t> file;
    file.insert(file.end(), WALLET_FILE_MAGIC_V6, WALLET_FILE_MAGIC_V6 + 8);
    PutU32(file, WALLET_FILE_VERSION_6);
    uint32_t flags = 0x01;   // encrypted, NOT HD
    PutU32(file, flags);
    PutBytes(file, fileHMAC);
    PutBytes(file, body);

    out.perAddr = perAddr;
    out.perAddrPriv.assign(perKey.vchPrivKey.begin(), perKey.vchPrivKey.end());

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());

    return WriteFileBytes(path, file);
}

// ---------------------------------------------------------------------------
// Legacy v6 NON-HD builder WITH an encrypted MIK present (round-5 BLOCKER-5).
//
// This is the missing builder: every existing legacy-v6 builder hard-codes
// hasMIK=0, so they never exercised the MIK record on the v6 write path — which
// is exactly where the BLOCKER-5 desync lived. A genuine pre-LP-7 v6 file with
// an encrypted MIK carries the MIK block WITHOUT any per-record mikMacLen field
// (the v7-only MAC field did not exist pre-LP-7). On the UNFIXED binary
// (8e4d3abb), ChangePassphrase rewrites this wallet at v6 via SaveUnlocked, which
// (pre-fix) emits the mikMacLen field UNCONDITIONALLY → the v6 reader (which gates
// the read on version>=V7) never consumes it → the stream desyncs and the MIK /
// sent-history / best-block fields are misparsed → reload fails or loads corrupt
// MIK state. On the FIXED binary the mikMacLen field is !writeLegacyV6-gated, so
// the v6 rewrite is byte-symmetric with the v6 reader and the MIK round-trips.
//
// NON-HD is deliberate: a non-HD encrypted wallet never sets the seed-migration
// flag, so it STAYS v6 forever and EVERY SaveUnlocked runs in writeLegacyV6 mode
// (the broadest, irreversible trigger surface). A mining wallet carrying a MIK is
// the common case this protects.
//
// Non-HD encrypted v6 layout WITH MIK (matches SaveUnlocked for is_hd_wallet=false):
//   [Magic 8][Version=6 u32][Flags=0x01][HMAC 32][salt 32]
//   <master key block>
//   <numCryptedKeys u32 = 1><addr 21><pubKey 1952><cryptedLen u32><ct><iv 16>
//     <macLen u32 = 64><mac>
//   <hasDefault u8><addr 21><numTxs u32 = 0><bestHash 32><bestHeight i32>
//   <hasMIK u8 = 1>
//     <pubkeyLen u32><MIK pubKey>
//     <encPrivKeyLen u32><MIK priv ct>
//     <ivLen u32><MIK iv>
//     ( NO mikMacLen field — v6 never had it )
//     <mikRegistered u8 = 0>
//     <hasUnencryptedMIK u8 = 0>   (encrypted wallet → MIK priv stored encrypted)
//   <numSentTx u32 = 0>
// ---------------------------------------------------------------------------
struct LegacyV6MIKResult {
    CDilithiumAddress    perAddr;
    std::vector<uint8_t> perAddrPriv;
    std::string          mikIdentityHex;   // expected MIK identity after round-trip
};

static bool BuildLegacyV6NonHDWalletWithMIK(const std::string& path,
                                            const std::string& passphrase,
                                            LegacyV6MIKResult& out) {
    // Encrypted master key block (legacy AES-keyed MAC so v<7 Unlock passes).
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) return false;
    std::vector<uint8_t> mkSalt;
    if (!GenerateSalt(mkSalt)) return false;
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, mkSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) return false;
    std::vector<uint8_t> mkIV;
    if (!GenerateIV(mkIV)) return false;
    CCrypter mkCrypter;
    if (!mkCrypter.SetKey(derivedKey, mkIV)) return false;
    std::vector<uint8_t> mkCipher;
    if (!mkCrypter.Encrypt(vMasterKeyPlain, mkCipher)) return false;
    std::vector<uint8_t> mkMAC;
    if (!mkCrypter.ComputeMAC(mkCipher, mkMAC, /*useLegacyKeying=*/true)) return false;

    // Per-address spending key: real keypair, encrypted under the master key,
    // MAC'd with LEGACY keying (so it stays spendable across the v6 rewrite).
    CKey perKey;
    if (!WalletCrypto::GenerateKeyPair(perKey)) return false;
    CDilithiumAddress perAddr(perKey.vchPubKey);
    std::vector<uint8_t> keyIV;
    if (!GenerateIV(keyIV)) return false;
    CCrypter keyCrypter;
    if (!keyCrypter.SetKey(vMasterKeyPlain, keyIV)) return false;
    std::vector<uint8_t> keyCipher;
    if (!keyCrypter.Encrypt(perKey.vchPrivKey, keyCipher)) return false;
    std::vector<uint8_t> keyMAC;
    if (!keyCrypter.ComputeMAC(keyCipher, keyMAC, /*useLegacyKeying=*/true)) return false;

    // --- The MIK: a real Dilithium3 keypair, private key encrypted under the
    //     master key with its own IV. NO MAC field is written (v6 shape). ---
    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) return false;
    if (!mik.IsValid() || !mik.HasPrivateKey()) return false;
    std::string mikIdentityHex = mik.GetIdentityHex();

    std::vector<uint8_t> mikIV;
    if (!GenerateIV(mikIV)) return false;
    CCrypter mikCrypter;
    if (!mikCrypter.SetKey(vMasterKeyPlain, mikIV)) return false;
    std::vector<uint8_t> mikPlain(mik.privkey.begin(), mik.privkey.end());
    std::vector<uint8_t> mikCipher;
    if (!mikCrypter.Encrypt(mikPlain, mikCipher)) {
        memory_cleanse(mikPlain.data(), mikPlain.size());
        return false;
    }
    memory_cleanse(mikPlain.data(), mikPlain.size());

    std::vector<uint8_t> hmacSalt(WALLET_FILE_SALT_SIZE);
    if (!GetStrongRandBytes(hmacSalt.data(), hmacSalt.size())) return false;

    std::vector<uint8_t> body;
    PutBytes(body, hmacSalt);

    // master key block
    PutU32(body, static_cast<uint32_t>(mkCipher.size()));
    PutBytes(body, mkCipher);
    PutBytes(body, mkSalt);
    PutBytes(body, mkIV);
    PutU32(body, 0u);
    PutU32(body, WALLET_CRYPTO_PBKDF2_ROUNDS);
    PutU32(body, static_cast<uint32_t>(mkMAC.size()));
    PutBytes(body, mkMAC);

    // keys — ONE encrypted per-address key (no HD block; flags has no 0x02)
    PutU32(body, 1u);
    PutBytes(body, out_default_or(perAddr.GetData()));
    PutBytes(body, perKey.vchPubKey);
    PutU32(body, static_cast<uint32_t>(keyCipher.size()));
    PutBytes(body, keyCipher);
    PutBytes(body, keyIV);
    PutU32(body, static_cast<uint32_t>(keyMAC.size()));
    PutBytes(body, keyMAC);

    // default address = the per-address key
    body.push_back(1);
    PutBytes(body, out_default_or(perAddr.GetData()));
    // transactions — 0
    PutU32(body, 0u);
    // best block
    std::vector<uint8_t> bestHash(32, 0);
    PutBytes(body, bestHash);
    int32_t bestHeight = -1;
    PutBytes(body, reinterpret_cast<const uint8_t*>(&bestHeight), sizeof(bestHeight));

    // MIK — PRESENT (the whole point of this builder). v6 shape: NO mikMacLen.
    body.push_back(1);                                          // hasMIK = 1
    PutU32(body, static_cast<uint32_t>(mik.pubkey.size()));     // pubkeyLen
    PutBytes(body, mik.pubkey);                                 // MIK pubkey
    PutU32(body, static_cast<uint32_t>(mikCipher.size()));      // encPrivKeyLen
    PutBytes(body, mikCipher);                                  // MIK priv ciphertext
    PutU32(body, static_cast<uint32_t>(mikIV.size()));          // ivLen
    PutBytes(body, mikIV);                                      // MIK iv
    // NO mikMacLen field — a genuine v6 file never carried it.
    body.push_back(0);                                          // mikRegistered = 0
    body.push_back(0);                                          // hasUnencryptedMIK = 0

    // sent tx — 0
    PutU32(body, 0u);

    std::vector<uint8_t> hmacKey(32, 0);
    std::memcpy(hmacKey.data(), mkSalt.data(), std::min<size_t>(32, mkSalt.size()));
    std::vector<uint8_t> fileHMAC(32);
    HMAC_SHA3_256(hmacKey.data(), hmacKey.size(), body.data(), body.size(), fileHMAC.data());

    std::vector<uint8_t> file;
    file.insert(file.end(), WALLET_FILE_MAGIC_V6, WALLET_FILE_MAGIC_V6 + 8);
    PutU32(file, WALLET_FILE_VERSION_6);
    uint32_t flags = 0x01;   // encrypted, NOT HD
    PutU32(file, flags);
    PutBytes(file, fileHMAC);
    PutBytes(file, body);

    out.perAddr = perAddr;
    out.perAddrPriv.assign(perKey.vchPrivKey.begin(), perKey.vchPrivKey.end());
    out.mikIdentityHex = mikIdentityHex;

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());

    return WriteFileBytes(path, file);
}

// ---------------------------------------------------------------------------
// Test 1 — secrecy regression + negative control
// ---------------------------------------------------------------------------
static void Test_Secrecy() {
    std::cout << COLOR_BLUE "\n[Test 1] Secrecy at rest (S-001) + negative control\n" COLOR_RESET;

    const std::string path = "lp7_secrecy_wallet.dat";
    std::remove(path.c_str());

    std::string mnemonic;
    {
        CWallet w;
        w.SetWalletFile(path);
        bool ok = w.GenerateHDWallet(mnemonic);
        CHECK(ok, "Generated HD wallet");
        if (!ok) return;
        // GenerateHDWallet auto-saves an UNENCRYPTED wallet.
    }

    std::vector<uint8_t> seed, chaincode;
    CHECK(DeriveSeedChaincode(mnemonic, seed, chaincode), "Derived seed+chaincode from mnemonic");

    // NEGATIVE CONTROL: unencrypted wallet's seed IS on disk (scan can find it).
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, seed.data(), seed.size()),
              "NEGATIVE CONTROL: unencrypted wallet file CONTAINS the seed (scan works)");
        CHECK(Contains(bytes, chaincode.data(), chaincode.size()),
              "NEGATIVE CONTROL: unencrypted wallet file CONTAINS the chaincode");
    }

    // Now encrypt + lock + save, then re-scan: seed/chaincode must be ABSENT.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded unencrypted wallet");
        CHECK(w.EncryptWallet("Str0ng!Passphrase#42"), "Encrypted wallet (re-encrypts seed+mnemonic)");
        CHECK(w.Lock(), "Locked wallet");
        // Encryption auto-saved; force a save to be sure the locked-state file is written.
        CHECK(w.Save(path), "Saved encrypted wallet");
    }

    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Encrypted wallet written at v7");
        CHECK(!Contains(bytes, seed.data(), seed.size()),
              "SECRECY: encrypted wallet file does NOT contain the seed plaintext");
        CHECK(!Contains(bytes, chaincode.data(), chaincode.size()),
              "SECRECY: encrypted wallet file does NOT contain the chaincode plaintext");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2 — migration round-trip + interrupted-migration atomicity
// ---------------------------------------------------------------------------
static void Test_Migration() {
    std::cout << COLOR_BLUE "\n[Test 2] Migration round-trip (A-012/S-002/S-003) + interrupted\n" COLOR_RESET;

    const std::string path = "lp7_migrate_wallet.dat";
    const std::string pass = "Migrate!Me#2026";
    std::remove(path.c_str());

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy);
    CHECK(built, "Built legacy v6 plaintext-seed encrypted wallet");
    if (!built) { std::remove(path.c_str()); return; }

    // Sanity: the legacy file IS v6 and DOES contain the plaintext seed.
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Legacy file is v6");
        CHECK(Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Legacy v6 file CONTAINS plaintext seed (pre-migration bug confirmed)");
    }

    // --- Interrupted-migration atomicity invariant ---
    // Capture the exact legacy bytes; load with autosave DISABLED so the unlock's
    // migration attempt cannot rewrite the file. The original file must remain
    // byte-for-byte identical and still open afterwards.
    std::vector<uint8_t> legacyBytesBefore = ReadFileBytes(path);
    {
        CWallet w;
        // Do NOT SetWalletFile() (which enables autosave). Load directly so
        // m_walletFile is set but m_autoSave stays false → migration re-encrypts
        // in memory but the SaveUnlocked step is skipped (no rewrite), modelling
        // an interruption BEFORE the atomic rename.
        CHECK(w.Load(path), "Loaded legacy wallet (autosave off)");
        CHECK(w.Unlock(pass), "Unlocked legacy wallet (migration attempted, rewrite skipped)");
    }
    std::vector<uint8_t> legacyBytesAfter = ReadFileBytes(path);
    CHECK(legacyBytesBefore == legacyBytesAfter,
          "INTERRUPTED MIGRATION: original legacy file is byte-for-byte unchanged");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "INTERRUPTED MIGRATION: file still opens as the intact v6 wallet (no corruption)");

    // --- Full migration round-trip (autosave ON → atomic v7 rewrite) ---
    std::string exportedMnemonic;
    std::vector<uint8_t> defAddrAfter;
    {
        CWallet w;
        w.SetWalletFile(path);  // enables autosave
        CHECK(w.Load(path), "Loaded legacy wallet (autosave on)");
        CHECK(w.Unlock(pass), "Unlocked → triggers atomic migration to v7");
        CHECK(w.ExportMnemonic(exportedMnemonic), "ExportMnemonic works post-migration (Inv-4)");
        std::vector<CDilithiumAddress> addrs = w.GetAddresses();
        if (!addrs.empty()) defAddrAfter = addrs.front().GetData();
    }

    CHECK(exportedMnemonic == legacy.mnemonic, "Mnemonic round-trips identically after migration");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "File version bumped to v7 after migration");

    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "MIGRATED: seed plaintext ABSENT from the v7 file");
        CHECK(!Contains(bytes, legacy.chaincode.data(), legacy.chaincode.size()),
              "MIGRATED: chaincode plaintext ABSENT from the v7 file");
    }

    // Reopen the migrated v7 wallet and confirm it still unlocks + exports.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded migrated v7 wallet");
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Reloaded file is v7");
        CHECK(w.Unlock(pass), "Migrated v7 wallet unlocks");
        std::string m2;
        CHECK(w.ExportMnemonic(m2) && m2 == legacy.mnemonic,
              "Migrated v7 wallet exports the original mnemonic");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2c — surfaced state: NeedsSeedMigration() is the load-bearing hook for the
// force-migrate fix (round-3 SURVIVING-LEAK). A pre-fix-encrypted wallet must
// report needs_seed_migration==true at rest (while LOCKED, never unlocked), and
// the flag must flip false exactly once the migration completes. This is what
// drives the UI banner / operator remediation / RPC field and proves the
// drive-to-safety path end to end (load → unlock → migrate → no plaintext seed).
// ---------------------------------------------------------------------------
static void Test_NeedsSeedMigrationSurfaced() {
    std::cout << COLOR_BLUE "\n[Test 2c] Surfaced state: NeedsSeedMigration() flips false on migrate\n" COLOR_RESET;

    const std::string path = "lp7_needs_migration_wallet.dat";
    const std::string pass = "Surface!State#2026";
    std::remove(path.c_str());

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy);
    CHECK(built, "Built legacy v6 plaintext-seed encrypted wallet (pre-fix artifact)");
    if (!built) { std::remove(path.c_str()); return; }

    // --- State surfaced at rest: armed, encrypted, LOCKED, NOT yet migrated ---
    // Load with autosave OFF so nothing migrates; this models the receive/mine-only
    // wallet that sits plaintext-at-rest forever. The surfaced flag must be true.
    {
        CWallet w;
        CHECK(w.Load(path), "Loaded pre-fix wallet (autosave off, never unlocked)");
        CHECK(w.IsCrypted(), "Wallet reports encrypted (has master key)");
        CHECK(w.IsLocked(), "Wallet is LOCKED at rest (masterKey invalid until unlock)");
        CHECK(w.NeedsSeedMigration(),
              "SURFACED: NeedsSeedMigration()==true while encrypted+plaintext-seed-at-rest");
        // Confirm the on-disk seed really is plaintext here (the thing we surface).
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Seed plaintext IS at rest while NeedsSeedMigration()==true (the leak being surfaced)");
    }

    // --- Migrate-on-unlock: flag flips false, no plaintext seed remains ---
    {
        CWallet w;
        w.SetWalletFile(path);  // enables autosave → atomic v7 rewrite on unlock
        CHECK(w.Load(path), "Reloaded pre-fix wallet (autosave on)");
        CHECK(w.NeedsSeedMigration(), "Pre-unlock: still armed (NeedsSeedMigration()==true)");
        CHECK(w.Unlock(pass), "Unlock → drives the one-time migration");
        CHECK(!w.NeedsSeedMigration(),
              "DRIVE-TO-SAFETY: NeedsSeedMigration() flips FALSE after migration");
    }

    // After migration the wallet is genuinely safe at rest: v7, no plaintext seed.
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Post-migration file is v7");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Post-migration: NO plaintext seed at rest (drive-to-safety verified)");
        CHECK(!Contains(bytes, legacy.chaincode.data(), legacy.chaincode.size()),
              "Post-migration: NO plaintext chaincode at rest");
    }

    // Reload the migrated wallet: the surfaced flag stays false (no false alarm).
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded migrated v7 wallet");
        CHECK(w.IsCrypted(), "Migrated wallet still reports encrypted");
        CHECK(!w.NeedsSeedMigration(),
              "Migrated v7 wallet reports NeedsSeedMigration()==false at rest (no false alarm)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2d — v7-HEADER + plaintext-seed artifact (Cursor L2). Test 2c covered the
// legacy-v6 byte shape; this covers the OTHER pre-fix shape detection handles
// (wallet.cpp:2169): a v7-labelled file whose seed is still plaintext-at-rest.
// Same ReadFileBytes/Contains byte-level approach: load → assert armed + plaintext
// seed IS at rest (while LOCKED) → unlock/migrate → assert NO plaintext seed at
// rest + flag false.
// ---------------------------------------------------------------------------
static void Test_V7PlaintextSeedArtifactMigrates() {
    std::cout << COLOR_BLUE "\n[Test 2d] v7-header + plaintext-seed artifact: armed at rest, migrates clean\n" COLOR_RESET;

    const std::string path = "lp7_v7_plaintext_seed_wallet.dat";
    const std::string pass = "V7Header!Plain#2026";
    std::remove(path.c_str());

    LegacyV6Result art;
    bool built = BuildV7PlaintextSeedWallet(path, pass, art);
    CHECK(built, "Built v7-header + plaintext-seed encrypted wallet (pre-fix v7 artifact)");
    if (!built) { std::remove(path.c_str()); return; }

    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Artifact carries a v7 header");

    // --- Surfaced at rest: encrypted, LOCKED, armed, plaintext seed on disk ---
    {
        CWallet w;
        CHECK(w.Load(path), "Loaded v7-plaintext artifact (autosave off, never unlocked)");
        CHECK(w.IsCrypted(), "Wallet reports encrypted (has master key)");
        CHECK(w.IsLocked(), "Wallet is LOCKED at rest");
        CHECK(w.NeedsSeedMigration(),
              "SURFACED: NeedsSeedMigration()==true for a v7-header plaintext-seed wallet");
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, art.seed.data(), art.seed.size()),
              "Plaintext seed IS at rest in the v7-header artifact (the leak being surfaced)");
        CHECK(Contains(bytes, art.chaincode.data(), art.chaincode.size()),
              "Plaintext chaincode IS at rest in the v7-header artifact");
    }

    // --- Migrate-on-unlock: flag flips false, no plaintext seed remains ---
    {
        CWallet w;
        w.SetWalletFile(path);  // enables autosave → atomic v7 rewrite on unlock
        CHECK(w.Load(path), "Reloaded v7-plaintext artifact (autosave on)");
        CHECK(w.NeedsSeedMigration(), "Pre-unlock: still armed");
        CHECK(w.Unlock(pass), "Unlock → drives the one-time re-encryption migration");
        CHECK(!w.NeedsSeedMigration(),
              "DRIVE-TO-SAFETY: NeedsSeedMigration() flips FALSE after migration");
    }

    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Post-migration file is (still) v7");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, art.seed.data(), art.seed.size()),
              "Post-migration: NO plaintext seed at rest (v7-header artifact drive-to-safety verified)");
        CHECK(!Contains(bytes, art.chaincode.data(), art.chaincode.size()),
              "Post-migration: NO plaintext chaincode at rest");
    }

    // Reload: armed flag stays false (no false alarm on the now-clean v7 file).
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded migrated v7 wallet");
        CHECK(w.IsCrypted(), "Migrated wallet still reports encrypted");
        CHECK(!w.NeedsSeedMigration(),
              "Migrated wallet reports NeedsSeedMigration()==false at rest (no false alarm)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2e — Cursor M1: the migration flag tracks ON-DISK state, NOT in-memory
// re-encryption success. When a wallet is unlocked with autosave OFF (no wallet
// file / persistence skipped), the migration MUST NOT clear the flag, because the
// on-disk file STILL carries the plaintext seed. The invariant: NeedsSeedMigration()
// is true exactly while a plaintext seed is still at rest on disk. Before the fix,
// MigrateToEncryptedSeedV7Unlocked returned true on in-memory success and Unlock
// cleared the flag + bumped to v7 → false-negative (surfacing turned off while the
// disk file was still plaintext).
// ---------------------------------------------------------------------------
static void Test_M1_FlagTracksOnDiskNotInMemory() {
    std::cout << COLOR_BLUE "\n[Test 2e] M1: migration flag tracks on-disk state (autosave-off stays armed)\n" COLOR_RESET;

    const std::string path = "lp7_m1_autosave_off_wallet.dat";
    const std::string pass = "AutoSaveOff!M1#2026";
    std::remove(path.c_str());

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy);
    CHECK(built, "Built legacy v6 plaintext-seed encrypted wallet (pre-fix artifact)");
    if (!built) { std::remove(path.c_str()); return; }

    std::vector<uint8_t> before = ReadFileBytes(path);
    CHECK(Contains(before, legacy.seed.data(), legacy.seed.size()),
          "Plaintext seed IS at rest before any unlock");

    // Load with autosave OFF (no SetWalletFile) → Unlock cannot persist a v7 rewrite.
    {
        CWallet w;
        CHECK(w.Load(path), "Loaded pre-fix wallet (autosave OFF)");
        CHECK(w.NeedsSeedMigration(), "Pre-unlock: armed (autosave off)");
        CHECK(w.Unlock(pass), "Unlock succeeds (migration cannot persist, must not fail unlock)");
        // THE M1 INVARIANT: flag STAYS armed because the on-disk file is still plaintext.
        CHECK(w.NeedsSeedMigration(),
              "M1: NeedsSeedMigration() STAYS true after autosave-off unlock (false-negative closed)");
    }

    // The on-disk file must be byte-identical (still legacy v6, still plaintext seed):
    // nothing was persisted, so no in-memory-only half-migration reached disk.
    std::vector<uint8_t> after = ReadFileBytes(path);
    CHECK(after == before, "M1: on-disk file is byte-identical after autosave-off unlock");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "M1: on-disk file is still legacy v6");
    CHECK(Contains(after, legacy.seed.data(), legacy.seed.size()),
          "M1: plaintext seed STILL at rest (flag correctly stayed armed)");

    // Sanity: with autosave ON, the same wallet DOES migrate and clears the flag.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded (autosave ON)");
        CHECK(w.Unlock(pass), "Unlock → migrates + persists");
        CHECK(!w.NeedsSeedMigration(), "M1 sanity: flag clears once the v7 file is persisted");
    }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "M1 sanity: file is v7 after persisted migration");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "M1 sanity: NO plaintext seed at rest after persisted migration");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2b — fail-closed guard on the scrubbed-seed / legacy-v6 corruption window
// (red-team LOW-1 hardening). A `friend struct` (declared in wallet.h) so the
// test can construct the otherwise-unreachable window state and drive the
// PRIVATE SaveUnlocked() writer directly.
//
// THE WINDOW: after a migration scrubs+encrypts the in-memory seed
// (fHDMasterKeyEncrypted=true, memory_cleanse'd seed/chaincode slots) but BEFORE
// m_loadedFileVersion is promoted to v7, the legacy-v6 writer path
// (writeLegacyV6 == true) would write the now-ZEROED fixed seed/chaincode slots
// → a structurally corrupt, unrecoverable wallet. In production Unlock promotes
// the version atomically under cs_wallet the instant it scrubs, so this state is
// never observable to any saver — but we harden the writer to fail-closed so the
// corruption is structurally impossible even under a future refactor.
// ---------------------------------------------------------------------------
struct LP7FailClosedTester {
    // Force the in-memory wallet into the window: encrypted-flag set + seed slots
    // scrubbed (exactly what EncryptHDMasterKey leaves behind) while
    // m_loadedFileVersion stays at v6. Returns true if the wallet looked like a
    // loaded legacy-v6 HD wallet to begin with (precondition for the window).
    static bool EnterScrubbedV6Window(CWallet& w) {
        if (!w.fIsHDWallet) return false;
        if (w.m_loadedFileVersion != WALLET_FILE_VERSION_6) return false;
        // Model EncryptHDMasterKey's post-state: ciphertext present, slots scrubbed.
        w.vchEncryptedHDMasterKey.assign(48, 0xAB);          // non-empty ciphertext
        w.vchHDMasterKeyMAC.assign(32, 0xCD);                // non-empty MAC
        w.vchHDMasterKeyIV.assign(WALLET_CRYPTO_IV_SIZE, 0xEF);
        memory_cleanse(w.hdMasterKey.seed, 32);              // seed now ZEROED
        memory_cleanse(w.hdMasterKey.chaincode, 32);         // chaincode now ZEROED
        w.fHDMasterKeyEncrypted = true;
        // m_loadedFileVersion deliberately LEFT at v6 → writeLegacyV6 == true.
        return true;
    }

    // Drive the private writer the public Save() path reaches (Save() just locks
    // cs_wallet then calls SaveUnlocked). Calling SaveUnlocked directly here is
    // equivalent for this single-threaded test and avoids re-locking.
    static bool ForceSave(CWallet& w, const std::string& path) {
        return w.SaveUnlocked(path);
    }

    static uint32_t LoadedVersion(const CWallet& w) { return w.m_loadedFileVersion; }
    static bool IsHDEncrypted(const CWallet& w) { return w.fHDMasterKeyEncrypted; }
};

static void Test_FailClosedScrubbedV6Window() {
    std::cout << COLOR_BLUE "\n[Test 2b] Fail-closed guard: scrubbed-seed / legacy-v6 window (LOW-1)\n" COLOR_RESET;

    const std::string path = "lp7_failclosed_wallet.dat";
    const std::string savePath = "lp7_failclosed_save.dat";
    const std::string pass = "FailClosed!Me#2026";
    std::remove(path.c_str());
    std::remove(savePath.c_str());

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy);
    CHECK(built, "Built legacy v6 plaintext-seed encrypted wallet");
    if (!built) { std::remove(path.c_str()); return; }

    // Load autosave-OFF so m_loadedFileVersion stays at v6 (no SetWalletFile()).
    CWallet w;
    CHECK(w.Load(path), "Loaded legacy v6 wallet (autosave off)");
    CHECK(LP7FailClosedTester::LoadedVersion(w) == WALLET_FILE_VERSION_6,
          "Loaded version is v6 (writeLegacyV6 would be true on save)");
    CHECK(!LP7FailClosedTester::IsHDEncrypted(w),
          "Post-load: HD master not yet flagged encrypted (plaintext-seed legacy)");

    // Construct the corruption window: scrub the seed + set the encrypted flag,
    // leaving the version at v6 (exactly the transient migration state).
    CHECK(LP7FailClosedTester::EnterScrubbedV6Window(w),
          "Entered scrubbed-seed / v6 window (fHDMasterKeyEncrypted=true, seed zeroed)");
    CHECK(LP7FailClosedTester::IsHDEncrypted(w) &&
          LP7FailClosedTester::LoadedVersion(w) == WALLET_FILE_VERSION_6,
          "Window invariant holds: encrypted-in-memory AND m_loadedFileVersion still v6");

    // Force a save to a SEPARATE path. With the fail-closed guard this must FAIL
    // and write nothing. Without the guard, the legacy-v6 writer emits a v6 file
    // whose fixed seed/chaincode slots are 64 zero bytes → corrupt wallet.
    std::remove(savePath.c_str());
    bool saved = LP7FailClosedTester::ForceSave(w, savePath);
    CHECK(!saved, "FAIL-CLOSED: SaveUnlocked REFUSED to persist the scrubbed-seed v6 wallet");

    // The atomic writer renames only on success; on a refusal the destination must
    // not exist at all (no corrupt artifact, no zeroed-seed file left behind).
    std::vector<uint8_t> savedBytes = ReadFileBytes(savePath);
    CHECK(savedBytes.empty(),
          "FAIL-CLOSED: no wallet file was written at the destination (no corrupt artifact)");

    // Defensive cross-check: even if a future regression let a byte slip through,
    // a v6 file with the seed scrubbed would carry 64 consecutive zero bytes in the
    // HD-master slots. Assert no such all-zero seed block was persisted.
    if (!savedBytes.empty()) {
        std::vector<uint8_t> zero64(64, 0);
        CHECK(!Contains(savedBytes, zero64.data(), zero64.size()),
              "FAIL-CLOSED: no zeroed 64-byte seed/chaincode block persisted to disk");
    }

    std::remove(path.c_str());
    std::remove(savePath.c_str());
}

// ---------------------------------------------------------------------------
// Test 3 — auth-tamper rejection
// ---------------------------------------------------------------------------
static void Test_AuthTamper() {
    std::cout << COLOR_BLUE "\n[Test 3] Authenticated-before-decrypt (S-004)\n" COLOR_RESET;

    const std::string path = "lp7_tamper_wallet.dat";
    const std::string pass = "T@mper!Test#77";
    std::remove(path.c_str());

    // Produce a clean v7 encrypted wallet.
    std::string mnemonic;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet");
        CHECK(w.EncryptWallet(pass), "Encrypted → v7");
        CHECK(w.Lock(), "Locked");
        CHECK(w.Save(path), "Saved v7 wallet");
    }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Wallet is v7");

    std::vector<uint8_t> clean = ReadFileBytes(path);
    CHECK(!clean.empty(), "Read v7 wallet bytes");

    // Baseline: the clean wallet unlocks.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Loaded clean v7 wallet");
        CHECK(w.Unlock(pass), "Clean v7 wallet unlocks (baseline)");
    }

    // TAMPER A: flip a byte in the second half of the file (HD-master ciphertext /
    // MAC region lives well past the header). Flipping any authenticated byte must
    // cause unlock/decrypt to fail (either the outer file-HMAC or a record MAC).
    {
        std::vector<uint8_t> bad = clean;
        size_t idx = bad.size() * 3 / 4;   // deep in the HD/MAC region
        bad[idx] ^= 0xFF;
        CHECK(WriteFileBytes(path, bad), "Wrote byte-flipped wallet");

        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(!unlocked, "TAMPER A: byte-flipped ciphertext is REJECTED (no unlock)");
    }

    // Restore clean, then TAMPER B: corrupt the LAST 64 bytes region of the body,
    // which on a freshly-saved v7 HD wallet sits inside MAC-protected content, and
    // additionally verify that an empty-MAC HD record on a v7 wallet is refused by
    // direct unit assertion below.
    {
        CHECK(WriteFileBytes(path, clean), "Restored clean wallet");
        std::vector<uint8_t> bad = clean;
        // Flip a byte near the front of the encrypted-seed region (right after the
        // header+master block is variable, so flip mid-file too).
        size_t idx = clean.size() / 2;
        bad[idx] ^= 0x01;
        CHECK(WriteFileBytes(path, bad), "Wrote second tampered wallet");

        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(!unlocked, "TAMPER B: mid-file corruption is REJECTED");
    }

    // EMPTY-MAC REJECTION (unit-level): a v7 CCrypter VerifyMAC of an empty MAC
    // must fail (mac.size()!=64), which is what the v7 decrypt paths rely on to
    // reject a stripped MAC.
    {
        std::vector<uint8_t> key(32, 0x11), iv(16, 0x22), ct(32, 0x33), emptyMac;
        CCrypter c;
        c.SetKey(key, iv);
        CHECK(!c.VerifyMAC(ct, emptyMac), "EMPTY-MAC: VerifyMAC rejects an empty MAC (v7 stripping closed)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 4 — MEDIUM-1: ISOLATING per-record MAC test (HIGH-1 regression guard)
//
// The TAMPER A/B tests are satisfied by the OUTER file-HMAC alone — they would
// pass even if every per-record MAC check were deleted. This test isolates the
// per-record MAC path: it strips the master-key MAC AND repairs the outer
// file-HMAC (keyed with the in-file plaintext master-key salt), so Load()'s
// integrity check passes and the only remaining authenticity gate is the
// per-record MAC verify. Asserting the wallet refuses to unlock proves the v7
// empty-MAC rejection on the MASTER KEY is live.
//
// This test FAILS without the HIGH-1 fix (a stripped master-key MAC makes
// IsLegacy() true → MAC verify skipped → root secret decrypts unauthenticated →
// Unlock succeeds) and PASSES with it (load/verify reject the empty MAC).
// ---------------------------------------------------------------------------
static void Test_PerRecordMACIsolation() {
    std::cout << COLOR_BLUE "\n[Test 4] Per-record MAC isolation (MEDIUM-1 / HIGH-1 guard)\n" COLOR_RESET;

    const std::string path = "lp7_macstrip_wallet.dat";
    const std::string pass = "M@cStr1p!Test#88";
    std::remove(path.c_str());

    // Clean v7 encrypted wallet WITH a per-address (non-HD) spending key. We add
    // the key BEFORE encryption so EncryptWallet migrates it into mapCryptedKeys
    // with a per-record MAC and writes it to disk — giving us a per-address key
    // record to isolate. Capture its 21-byte address by diffing GetAddresses.
    std::string mnemonic;
    std::vector<uint8_t> importedAddr21;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet");
        std::vector<CDilithiumAddress> before = w.GetAddresses();
        CHECK(w.GenerateNewKey(), "Added a non-HD spending key (pre-encryption)");
        std::vector<CDilithiumAddress> after = w.GetAddresses();
        // The new address is the one in `after` not in `before`.
        for (const auto& a : after) {
            bool seen = false;
            for (const auto& b : before) {
                if (a.GetData() == b.GetData()) { seen = true; break; }
            }
            if (!seen) { importedAddr21 = a.GetData(); importedAddr21.resize(21, 0); break; }
        }
        CHECK(importedAddr21.size() == 21, "Captured the new spending key's 21-byte address");
        CHECK(w.EncryptWallet(pass), "Encrypted → v7 (per-address key → mapCryptedKeys + MAC)");
        CHECK(w.Lock(), "Locked");
        CHECK(w.Save(path), "Saved v7 wallet");
    }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Wallet is v7");

    std::vector<uint8_t> clean = ReadFileBytes(path);
    CHECK(!clean.empty(), "Read v7 wallet bytes");

    // POSITIVE CONTROL: recompute the outer file-HMAC over the UNMODIFIED image.
    // This proves RecomputeFileHMAC is faithful — so any rejection in the strip
    // cases below comes from the per-record MAC gate, not a broken outer HMAC.
    {
        std::vector<uint8_t> repaired = clean;
        CHECK(RecomputeFileHMAC(repaired), "POSITIVE CONTROL: recomputed outer file-HMAC");
        CHECK(repaired == clean,
              "POSITIVE CONTROL: recomputed HMAC matches the writer's HMAC (helper is faithful)");
        CHECK(WriteFileBytes(path, repaired), "Wrote HMAC-recomputed (unmodified) wallet");
        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(unlocked, "POSITIVE CONTROL: unmodified+rehmac'd wallet still unlocks (no false reject)");
    }

    // ISOLATING CASE 1 (the load-bearing HIGH-1 guard) — PER-ADDRESS KEY.
    // Strip the per-address key's MAC, then REPAIR the outer file-HMAC so Load()
    // passes. Stripping a per-address MAC keeps masterKey.IsValid() TRUE, so
    // Load's outer-HMAC key is unchanged and the per-record MAC verify is the ONLY
    // remaining gate. Without the HIGH-1 fix, IsLegacy() becomes true → verify
    // skipped → the spending key decrypts unauthenticated and unlock SUCCEEDS.
    // With the fix, load/verify reject the empty MAC. This assertion is the one
    // that flips between fixed/unfixed.
    {
        std::vector<uint8_t> bad = clean;
        bool stripped = StripPerAddressKeyMAC(bad, importedAddr21);
        CHECK(stripped, "Stripped PER-ADDRESS key MAC (macLen→0, 64 bytes dropped)");
        CHECK(RecomputeFileHMAC(bad),
              "Repaired outer file-HMAC over the stripped image (forgeable: salt is in-file)");
        CHECK(WriteFileBytes(path, bad), "Wrote per-address stripped-MAC, valid-outer-HMAC wallet");

        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(!unlocked,
              "ISOLATING (per-address): v7 spending key with stripped MAC is REJECTED (HIGH-1 closed)");
    }

    // ISOLATING CASE 2 — MASTER KEY. Strip the master-key MAC and repair the outer
    // HMAC. The fix rejects a v7 master key with an empty MAC at the load gate
    // (and at the unlock verify-gate as defense-in-depth). Must not unlock.
    {
        std::vector<uint8_t> bad = clean;
        bool stripped = StripMasterKeyMAC(bad);
        CHECK(stripped, "Stripped MASTER-KEY MAC (macLen→0, 64 bytes dropped)");
        CHECK(RecomputeFileHMAC(bad),
              "Repaired outer file-HMAC over the master-stripped image");
        CHECK(WriteFileBytes(path, bad), "Wrote master stripped-MAC, valid-outer-HMAC wallet");

        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(!unlocked,
              "ISOLATING (master): v7 master key with stripped MAC is REJECTED (HIGH-1 closed)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 5 — MEDIUM-2: atomic-rename crash-window invariant (S-002, real windows)
//
// The interrupted-migration test in Test 2 disables autosave, so it models
// "SaveUnlocked was never called" — NOT "SaveUnlocked was interrupted
// mid-rewrite". SaveUnlocked is temp-write+fsync → atomic rename over the
// original (the original is never truncated), so the only crash windows are:
//   (A) crash AFTER temp-write+fsync but BEFORE rename → on disk: original
//       intact + an orphan ".tmp"; recovery opens the intact OLD wallet.
//   (B) crash AFTER rename → on disk: the complete NEW wallet, no temp.
// This test reconstructs each on-disk state from REAL saved images and asserts
// the wallet is never corrupt/lost (old-or-new, always intact).
// ---------------------------------------------------------------------------
static void Test_AtomicRenameCrashWindow() {
    std::cout << COLOR_BLUE "\n[Test 5] Atomic-rename crash window (MEDIUM-2 / S-002)\n" COLOR_RESET;

    const std::string path = "lp7_atomic_wallet.dat";
    const std::string pass = "At0mic!Rename#99";
    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());

    // --- Produce a real OLD on-disk image (v7 encrypted wallet, version 1). ---
    std::string mnemonic;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet");
        CHECK(w.EncryptWallet(pass), "Encrypted → v7");
        CHECK(w.Lock(), "Locked");
        CHECK(w.Save(path), "Saved OLD image");
    }
    std::vector<uint8_t> oldImage = ReadFileBytes(path);
    CHECK(!oldImage.empty() && FileVersion(path) == WALLET_FILE_VERSION_7, "OLD image is a valid v7 wallet");

    // --- Produce a real NEW on-disk image (re-save: a second valid v7 image). ---
    // Re-saving the same wallet yields a byte-different but equally-valid image
    // (fresh random IVs/salt), which stands in for "the rewrite the migration
    // would have produced". This is the content the rename moves into place.
    std::vector<uint8_t> newImage;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded wallet to produce NEW image");
        CHECK(w.Unlock(pass), "Unlocked");
        CHECK(w.Save(path), "Saved NEW image (atomic rewrite)");
        newImage = ReadFileBytes(path);
    }
    CHECK(!newImage.empty() && FileVersion(path) == WALLET_FILE_VERSION_7, "NEW image is a valid v7 wallet");
    CHECK(oldImage != newImage, "OLD and NEW images differ (fresh IVs/salt — distinguishable)");

    // --- WINDOW A: crash AFTER temp-write+fsync, BEFORE rename. ---
    // On-disk state: original (OLD) intact + orphan ".tmp" (the unfinished NEW).
    // The wallet path still holds the OLD image; the orphan temp must NOT prevent
    // a clean open of the intact OLD wallet (no data loss, no corruption).
    {
        CHECK(WriteFileBytes(path, oldImage), "WINDOW A: restored OLD image at the wallet path");
        CHECK(WriteFileBytes(path + ".tmp", newImage), "WINDOW A: left an orphan .tmp (unfinished rename)");
        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(unlocked, "WINDOW A: intact OLD wallet opens despite orphan temp (no loss)");
        std::string m;
        CHECK(loaded && w.ExportMnemonic(m) && m == mnemonic,
              "WINDOW A: OLD wallet's mnemonic is fully recoverable");
        std::remove((path + ".tmp").c_str());
    }

    // --- WINDOW B: crash AFTER rename completed. ---
    // On-disk state: the wallet path holds the complete NEW image, no temp.
    {
        CHECK(WriteFileBytes(path, newImage), "WINDOW B: NEW image is in place (rename completed)");
        CWallet w;
        w.SetWalletFile(path);
        bool loaded = w.Load(path);
        bool unlocked = loaded && w.Unlock(pass);
        CHECK(unlocked, "WINDOW B: complete NEW wallet opens cleanly");
        std::string m;
        CHECK(loaded && w.ExportMnemonic(m) && m == mnemonic,
              "WINDOW B: NEW wallet's mnemonic is fully recoverable (same seed)");
    }

    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());
}

// ---------------------------------------------------------------------------
// Test 6 — HIGH-2: legacy per-address spending key is SPENDABLE (direct read
// AND after migration).
//
// Builds a genuine legacy v6 encrypted wallet that carries ONE per-address
// spending key whose MAC was written with the LEGACY AES-keyed HMAC. The round-2
// finding: the per-address GetKey verify (wallet.cpp:336) used the SEPARATED
// keying unconditionally while the other four decrypt paths were version-keyed,
// so this legacy key's MAC mismatches → GetKey fails → funds unspendable, both on
// direct read and baked into the migrated v7 file (no per-address re-MAC loop).
//
// This test MUST FAIL on commit b7534b1c (key unspendable) and PASS after the
// fold (centralized version-keyed VerifyRecordMAC + per-address re-MAC in
// migration). The load-bearing assertions are the two "spendable" checks.
// ---------------------------------------------------------------------------
static void Test_LegacyPerAddressKey() {
    std::cout << COLOR_BLUE "\n[Test 6] Legacy per-address spending key spendable (HIGH-2)\n" COLOR_RESET;

    const std::string path = "lp7_legacy_peraddr_wallet.dat";
    const std::string pass = "Leg@cyKey!Spend#2026";
    std::remove(path.c_str());

    LegacyV6KeyResult legacy;
    bool built = BuildLegacyV6WalletWithPerAddressKey(path, pass, legacy);
    CHECK(built, "Built legacy v6 wallet WITH a legacy-MAC'd per-address key");
    if (!built) { std::remove(path.c_str()); return; }

    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Legacy file is v6");
    CHECK(legacy.perAddrPriv.size() == DILITHIUM_SECRETKEY_SIZE,
          "Captured the per-address plaintext private key");

    // --- (A) DIRECT LEGACY READ: the per-address key must be SPENDABLE without
    //         any migration. Load with autosave OFF so we exercise the raw v6
    //         read path (m_loadedFileVersion == 6) before any rewrite. ---
    {
        CWallet w;
        bool loaded = w.Load(path);   // no SetWalletFile → autosave off → no rewrite
        CHECK(loaded, "Loaded legacy v6 wallet (autosave off, no migration)");
        CHECK(loaded && w.Unlock(pass), "Unlocked legacy v6 wallet");

        CKey recovered;
        bool got = loaded && w.GetKey(legacy.perAddr, recovered);
        CHECK(got, "DIRECT READ: GetKey succeeds on the legacy-MAC'd per-address key");
        CHECK(got && recovered.vchPrivKey.size() == DILITHIUM_SECRETKEY_SIZE &&
              std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                  == legacy.perAddrPriv,
              "DIRECT READ (LOAD-BEARING): decrypted private key matches — key is SPENDABLE");
        // Confirm still v6 on disk (no rewrite happened).
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
              "DIRECT READ: file untouched (still v6, autosave off)");
    }

    // --- (B) AFTER MIGRATION: load with autosave ON → unlock triggers the atomic
    //         v7 rewrite (incl. the per-address re-MAC loop). The same key must
    //         remain spendable, and the re-MAC must persist to disk. ---
    {
        CWallet w;
        w.SetWalletFile(path);  // autosave on
        CHECK(w.Load(path), "Loaded legacy v6 wallet (autosave on)");
        CHECK(w.Unlock(pass), "Unlocked → triggers atomic migration to v7");
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "File migrated to v7");

        CKey recovered;
        bool got = w.GetKey(legacy.perAddr, recovered);
        CHECK(got, "POST-MIGRATION (in memory): GetKey still succeeds");
        CHECK(got && std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                  == legacy.perAddrPriv,
              "POST-MIGRATION (LOAD-BEARING): key still SPENDABLE in the migrating instance");
    }

    // --- (C) RELOAD the migrated v7 file fresh: the per-address key must be
    //         spendable from the on-disk v7 record (proves the re-MAC was
    //         written, not just held in memory). ---
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded migrated v7 wallet from disk");
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "Reloaded file is v7");
        CHECK(w.Unlock(pass), "Migrated v7 wallet unlocks");

        CKey recovered;
        bool got = w.GetKey(legacy.perAddr, recovered);
        CHECK(got, "RELOADED v7: GetKey succeeds on the re-MAC'd per-address key");
        CHECK(got && std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                  == legacy.perAddrPriv,
              "RELOADED v7 (LOAD-BEARING): on-disk v7 per-address key is SPENDABLE (re-MAC persisted)");
    }

    std::remove(path.c_str());

    // --- (D) RAW v6 READ, NO MIGRATION (manifestation 1, isolated). A NON-HD
    //         encrypted v6 wallet never sets the seed-migration flag, so Unlock
    //         does NOT migrate and m_loadedFileVersion stays 6 when GetKey runs.
    //         This drives the per-address VerifyRecordMAC with legacyKeying==true
    //         in isolation (no in-memory migration to mask it). On the unfixed
    //         binary the legacy-keyed MAC is verified with separated keying →
    //         GetKey fails → the key is unspendable on a wallet that never
    //         migrates. ---
    {
        const std::string nhpath = "lp7_legacy_peraddr_nonhd.dat";
        std::remove(nhpath.c_str());
        LegacyV6NonHDResult nh;
        bool nbuilt = BuildLegacyV6NonHDWalletWithKey(nhpath, pass, nh);
        CHECK(nbuilt, "Built legacy v6 NON-HD wallet with a legacy-MAC'd per-address key");
        if (nbuilt) {
            CWallet w;
            bool loaded = w.Load(nhpath);   // autosave off
            CHECK(loaded, "Loaded non-HD legacy v6 wallet");
            CHECK(loaded && w.Unlock(pass), "Unlocked non-HD legacy v6 wallet (NO migration)");
            // File must still be v6 — proves migration did not run.
            CHECK(FileVersion(nhpath) == WALLET_FILE_VERSION_6,
                  "RAW v6: file still v6 after unlock (no migration ran)");

            CKey recovered;
            bool got = loaded && w.GetKey(nh.perAddr, recovered);
            CHECK(got, "RAW v6: GetKey succeeds while m_loadedFileVersion==6");
            CHECK(got && std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                      == nh.perAddrPriv,
                  "RAW v6 (LOAD-BEARING): legacy-keyed per-address key SPENDABLE on un-migrated v6 wallet");
        }
        std::remove(nhpath.c_str());
    }
}

// ---------------------------------------------------------------------------
// Test 7 — LP-7 ratified ChangePassphrase-in-place design.
//
// ChangePassphrase rotates the passphrase on the wallet's EXISTING format ONLY. It
// must NOT promote the file to v7, NOT migrate the HD seed, and NOT re-MAC the
// non-master records. The one-time v6->v7 migration happens on the NEXT Unlock.
// This test pins all three legs:
//   (a) ChangePassphrase on a LOADED legacy v6 ENCRYPTED HD wallet (no prior unlock,
//       the RPC-reachable path): correct old pass SUCCEEDS, the file STAYS v6, the
//       wallet still unlocks + the mnemonic is still exportable under the NEW pass,
//       and a WRONG old pass is rejected (negative control).
//   (b) After (a)'s passphrase change, the NEXT Unlock migrates the (still-v6) file
//       to v7 correctly: seed plaintext ABSENT from the v7 file, mnemonic still
//       exportable.
//   (c) ChangePassphrase on a NATIVE v7 wallet keeps it v7 and still works.
//
// Round-4 BLOCKER-1 (ChangePassphrase mints a v7-labelled plaintext-seed file that
// permanently disarms migration) and BLOCKER-2 (empty-MAC mnemonic/MIK bricked on the
// v7 re-save) are both structurally impossible under this design: leg (a) asserts the
// file stays v6 (so no v7 promotion, no empty-MAC v7 rejection), and leg (b) asserts
// migration still fires + succeeds on the next Unlock.
// ---------------------------------------------------------------------------
static void Test_ChangePassphraseLegacyNonHD() {
    std::cout << COLOR_BLUE "\n[Test 7] ChangePassphrase-in-place: v6 stays v6, next Unlock migrates (LP-7 ratified)\n" COLOR_RESET;

    const std::string oldPass = "Leg@cyOldP@ss!2026#";
    const std::string newPass = "N3w$tr0ngP@ss!2026#";

    // === Leg (a): ChangePassphrase on a loaded legacy v6 ENCRYPTED HD wallet ===
    const std::string path = "lp7_changepass_hd_v6.dat";
    std::remove(path.c_str());

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, oldPass, legacy);
    CHECK(built, "Built legacy v6 plaintext-seed encrypted HD wallet");
    if (!built) { std::remove(path.c_str()); return; }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Legacy HD file is v6 before change");

    // walletpassphrasechange does NOT require a prior unlock → call ChangePassphrase
    // directly on a loaded-but-locked wallet (the RPC-reachable path). Autosave ON.
    {
        CWallet w;
        w.SetWalletFile(path);  // autosave on → the change rewrites the file in place
        CHECK(w.Load(path), "Loaded legacy v6 HD wallet (locked)");

        bool changed = w.ChangePassphrase(oldPass, newPass);
        CHECK(changed,
              "LOAD-BEARING: ChangePassphrase SUCCEEDS with the CORRECT old passphrase "
              "on a loaded legacy v6 HD wallet (no prior unlock)");
    }

    // BLOCKER-1 structural guard: the file must STAY v6 (NOT promoted to v7). A v7
    // promotion here without seed migration is exactly the round-4 plaintext-seed
    // re-introduction that permanently disarmed migration.
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "LOAD-BEARING (BLOCKER-1 closed): file STAYS v6 after ChangePassphrase (no v7 promotion)");

    // The legacy file still legitimately carries the plaintext seed (we did NOT migrate
    // — migration is the NEXT Unlock's job). The seed-at-rest is the PRE-EXISTING v6
    // state, re-armed for migration on reload, NOT a new v7 exposure.
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "v6 file still carries plaintext seed (migration deferred to next Unlock, as designed)");
    }

    // Reload + unlock under the NEW passphrase, and confirm the mnemonic is still
    // exportable → proves the master-key rotation kept legacy keying that round-trips,
    // and the non-master (mnemonic) record was untouched and stays readable.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded the rotated v6 wallet");
        CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Reloaded file is still v6");
        CHECK(w.Unlock(newPass), "NEW passphrase unlocks the rotated v6 wallet");
        std::string m;
        CHECK(w.ExportMnemonic(m) && m == legacy.mnemonic,
              "LOAD-BEARING (BLOCKER-2 closed): mnemonic still exportable after passphrase change");
    }

    // === Leg (b): the NEXT Unlock migrates the (rotated) v6 wallet to v7 ===
    // The Unlock above (autosave ON) already triggered migration. Confirm the file is
    // now v7 with the seed plaintext ABSENT, and the mnemonic still exports.
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7,
          "LOAD-BEARING: next Unlock migrated the rotated v6 wallet to v7");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "MIGRATED: seed plaintext ABSENT from the v7 file after Unlock migration");
        CHECK(!Contains(bytes, legacy.chaincode.data(), legacy.chaincode.size()),
              "MIGRATED: chaincode plaintext ABSENT from the v7 file after Unlock migration");

        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded the migrated v7 wallet");
        CHECK(w.Unlock(newPass), "Migrated v7 wallet unlocks under the NEW passphrase");
        std::string m;
        CHECK(w.ExportMnemonic(m) && m == legacy.mnemonic,
              "Migrated v7 wallet still exports the original mnemonic");
    }
    std::remove(path.c_str());

    // === Leg (a) negative control: a WRONG old passphrase must be rejected ===
    {
        const std::string npath = "lp7_changepass_hd_v6_neg.dat";
        std::remove(npath.c_str());
        LegacyV6Result neg;
        bool b2 = BuildLegacyV6Wallet(npath, oldPass, neg);
        CHECK(b2, "Built second legacy v6 HD wallet (negative control)");
        if (b2) {
            CWallet w;
            w.SetWalletFile(npath);
            CHECK(w.Load(npath), "Loaded negative-control legacy wallet");
            CHECK(!w.ChangePassphrase("Wr0ngOldP@ss!2026#", newPass),
                  "NEGATIVE CONTROL: ChangePassphrase REJECTS a wrong old passphrase");
            CHECK(FileVersion(npath) == WALLET_FILE_VERSION_6,
                  "NEGATIVE CONTROL: file left untouched at v6 after a rejected change");
        }
        std::remove(npath.c_str());
    }

    // === Also pin the legacy NON-HD path (never migrates; stays v6 forever) ===
    {
        const std::string nhpath = "lp7_changepass_nonhd_v6.dat";
        std::remove(nhpath.c_str());
        LegacyV6NonHDResult nh;
        bool nbuilt = BuildLegacyV6NonHDWalletWithKey(nhpath, oldPass, nh);
        CHECK(nbuilt, "Built legacy v6 NON-HD wallet (legacy-keyed master MAC, never migrates)");
        if (nbuilt) {
            {
                CWallet w;
                w.SetWalletFile(nhpath);
                CHECK(w.Load(nhpath), "Loaded legacy v6 non-HD wallet");
                CHECK(w.ChangePassphrase(oldPass, newPass),
                      "ChangePassphrase SUCCEEDS on a legacy v6 non-HD wallet");
            }
            // Non-HD wallet never migrates → STAYS v6.
            CHECK(FileVersion(nhpath) == WALLET_FILE_VERSION_6,
                  "Non-HD wallet STAYS v6 after ChangePassphrase (never migrates)");
            {
                CWallet w;
                w.SetWalletFile(nhpath);
                CHECK(w.Load(nhpath), "Reloaded the rotated non-HD v6 wallet");
                CHECK(w.Unlock(newPass), "NEW passphrase unlocks the rotated non-HD v6 wallet");
                CKey recovered;
                bool got = w.GetKey(nh.perAddr, recovered);
                CHECK(got && std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                          == nh.perAddrPriv,
                      "LOAD-BEARING: per-address key SPENDABLE after non-HD passphrase change (legacy MACs intact)");
            }
        }
        std::remove(nhpath.c_str());
    }

    // === Leg (c): ChangePassphrase on a NATIVE v7 wallet keeps v7 + works ===
    {
        const std::string vpath = "lp7_changepass_native_v7.dat";
        std::remove(vpath.c_str());
        std::string mnemonic;
        {
            CWallet w;
            w.SetWalletFile(vpath);
            CHECK(w.GenerateHDWallet(mnemonic), "Generated native HD wallet");
            CHECK(w.EncryptWallet(oldPass), "Encrypted → native v7");
            CHECK(w.Save(vpath), "Saved native v7 wallet");
        }
        CHECK(FileVersion(vpath) == WALLET_FILE_VERSION_7, "Native wallet is v7");
        {
            CWallet w;
            w.SetWalletFile(vpath);
            CHECK(w.Load(vpath), "Loaded native v7 wallet");
            CHECK(w.ChangePassphrase(oldPass, newPass),
                  "ChangePassphrase SUCCEEDS on a native v7 wallet");
        }
        CHECK(FileVersion(vpath) == WALLET_FILE_VERSION_7,
              "LOAD-BEARING (leg c): native v7 wallet STAYS v7 after ChangePassphrase");
        {
            CWallet w;
            w.SetWalletFile(vpath);
            CHECK(w.Load(vpath), "Reloaded the rotated native v7 wallet");
            CHECK(w.Unlock(newPass), "NEW passphrase unlocks the rotated native v7 wallet");
            std::string m;
            CHECK(w.ExportMnemonic(m) && m == mnemonic,
                  "Native v7 wallet still exports its mnemonic after passphrase change");
        }
        std::remove(vpath.c_str());
    }
}

// ---------------------------------------------------------------------------
// Test 8 — ChangePassphrase on a legacy v6 wallet WITH an encrypted MIK
//          (round-5 BLOCKER-5 regression).
//
// FAILS on 8e4d3abb (unfixed: SaveUnlocked emits the v7-only mikMacLen field into
// the v6 layout → reader desyncs → reload fails / MIK corrupt). PASSES after the
// !writeLegacyV6 gate on the MIK-MAC write. The decisive assertion is that the
// wallet OPENS and the MIK round-trips after ChangePassphrase-in-place.
// ---------------------------------------------------------------------------
static void Test_ChangePassphraseLegacyV6WithMIK() {
    std::cout << COLOR_BLUE "\n[Test 8] ChangePassphrase v6-in-place with an encrypted MIK present "
                            "(BLOCKER-5: MIK-MAC field must NOT leak into v6)\n" COLOR_RESET;

    const std::string oldPass = "M1n3rOldP@ss!2026#";
    const std::string newPass = "M1n3rN3wP@ss!2026#";
    const std::string path = "lp7_changepass_mik_v6.dat";
    std::remove(path.c_str());

    LegacyV6MIKResult mikw;
    bool built = BuildLegacyV6NonHDWalletWithMIK(path, oldPass, mikw);
    CHECK(built, "Built legacy v6 non-HD ENCRYPTED wallet WITH an encrypted MIK (hasMIK=1, no mikMacLen)");
    if (!built) { std::remove(path.c_str()); return; }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "MIK wallet file is v6 before change");

    // Sanity: the freshly-built v6 file loads and the MIK round-trips BEFORE any
    // ChangePassphrase — isolates the regression to the v6 WRITE path, not the build.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Pre-change: loaded the v6 MIK wallet");
        CHECK(w.HasMIK(), "Pre-change: MIK present after load");
        CHECK(w.Unlock(oldPass), "Pre-change: OLD passphrase unlocks the v6 MIK wallet");
        CHECK(w.GetMIKIdentityHex() == mikw.mikIdentityHex,
              "Pre-change: MIK identity matches (encrypted MIK decrypts on the legacy path)");
    }
    // Unlock with autosave on a NON-HD wallet does NOT migrate (no seed-migration
    // flag), so the file must still be v6.
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "Pre-change: non-HD wallet stays v6 after unlock (no migration)");

    // The load-bearing path: ChangePassphrase rewrites the v6 file in place via
    // SaveUnlocked(writeLegacyV6). On the unfixed binary this emits the spurious
    // mikMacLen field and desyncs the stream.
    {
        CWallet w;
        w.SetWalletFile(path);   // autosave on → the change rewrites the file in place
        CHECK(w.Load(path), "Loaded v6 MIK wallet (locked) for ChangePassphrase");
        CHECK(w.ChangePassphrase(oldPass, newPass),
              "ChangePassphrase SUCCEEDS on a legacy v6 wallet WITH a MIK");
    }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "File STAYS v6 after ChangePassphrase (no v7 promotion)");

    // THE decisive assertion: the rewritten v6 file must OPEN and the MIK must
    // still round-trip. On 8e4d3abb the spurious mikMacLen field desyncs the
    // reader and either Load() fails outright or the MIK is misparsed.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path),
              "LOAD-BEARING (BLOCKER-5): rewritten v6 MIK wallet OPENS (no stream desync)");
        CHECK(w.HasMIK(),
              "LOAD-BEARING (BLOCKER-5): MIK still present after the v6 rewrite");
        CHECK(w.Unlock(newPass),
              "NEW passphrase unlocks the rotated v6 MIK wallet");
        CHECK(w.GetMIKIdentityHex() == mikw.mikIdentityHex,
              "LOAD-BEARING (BLOCKER-5): MIK identity ROUND-TRIPS after ChangePassphrase "
              "(encrypted MIK private key intact, no desync)");
        // The per-address spending key must also survive (proves the stream stayed
        // in sync through the MIK block: a desync would corrupt everything after it).
        CKey recovered;
        bool got = w.GetKey(mikw.perAddr, recovered);
        CHECK(got && std::vector<uint8_t>(recovered.vchPrivKey.begin(), recovered.vchPrivKey.end())
                  == mikw.perAddrPriv,
              "Per-address key still SPENDABLE after the v6 MIK rewrite (stream stayed in sync)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 9 — Cursor HIGH-2: EncryptWallet is transactional + the v7 plaintext-seed
//          SaveUnlocked branch is fail-closed for an encrypted wallet.
//
// THE BUG (Cursor NO-GO): EncryptWallet clears mapKeys + sets the master key, then
// on any HD-step failure (mnemonic recover / re-encrypt / EncryptHDMasterKey)
// returned false WITHOUT rollback — leaving the wallet encrypted-in-memory
// (masterKey valid) with fHDMasterKeyEncrypted==false and a PLAINTEXT seed. A new
// HD wallet (m_loadedFileVersion==0 ⇒ writes v7) in that state, on the next
// autosave, persisted a v7 file with encrypted spending keys + PLAINTEXT seed =
// the LP-7 plaintext-at-rest bug reintroduced, with no migration arm on reload.
//
// This test pins BOTH halves of the fold:
//   PART A (rollback): force an EncryptWallet mid-HD-step failure by corrupting
//     vchEncryptedMnemonic so the mnemonic-recover Decrypt fails, then assert
//     (a) EncryptWallet returns false, (b) the wallet rolled back to UNENCRYPTED
//     (IsCrypted()==false, fHDMasterKeyEncrypted==false), and (c) the in-memory
//     plaintext seed is intact (not scrubbed) — i.e. the wallet is exactly as it
//     was before the failed attempt and can be retried.
//   PART B (fail-closed guard): force the otherwise-unreachable encrypted-in-memory
//     + plaintext-seed window directly, then drive SaveUnlocked and assert it
//     REFUSES (no v7 plaintext-seed file for an encrypted wallet ever reaches disk).
//
// On the UNFIXED branch (b5a71676): PART A's rollback asserts FAIL (the wallet is
// left encrypted with a plaintext seed) and PART B's Save SUCCEEDS writing a v7
// file that contains the plaintext seed. On the fixed branch both PARTs pass.
// ---------------------------------------------------------------------------
struct LP7EncryptRollbackTester {
    // Corrupt the encrypted-mnemonic ciphertext so EncryptWallet's mnemonic-recover
    // Decrypt fails deterministically: appending one byte makes the length not a
    // multiple of the AES block size, which DecryptAES256 rejects up front.
    static bool CorruptMnemonicCiphertext(CWallet& w) {
        if (w.vchEncryptedMnemonic.empty()) return false;
        w.vchEncryptedMnemonic.push_back(0x00);  // length now %16 != 0 → Decrypt fails
        return true;
    }

    // Force the encrypted-in-memory + plaintext-seed window that EncryptWallet used
    // to leave behind on a failed HD step. Mirrors that exact partial state: a valid
    // master key (so IsCrypted()==true) but fHDMasterKeyEncrypted==false with the
    // plaintext seed still in the fixed slots, at v7 (a freshly generated HD wallet).
    static bool ForceEncryptedPlaintextSeedWindow(CWallet& w) {
        if (!w.fIsHDWallet) return false;
        // Fabricate a structurally-valid master key so masterKey.IsValid() is true
        // WITHOUT going through EncryptWallet (which we are deliberately bypassing).
        w.masterKey.vchCryptedKey.assign(48, 0x11);
        w.masterKey.vchSalt.assign(WALLET_CRYPTO_SALT_SIZE, 0x22);
        w.masterKey.vchIV.assign(WALLET_CRYPTO_IV_SIZE, 0x33);
        w.masterKey.vchMAC.assign(64, 0x44);
        if (!w.masterKey.IsValid()) return false;
        // The HD seed is STILL plaintext (not encrypted) — the bug state.
        w.fHDMasterKeyEncrypted = false;
        // A freshly generated wallet writes v7 (m_loadedFileVersion == 0). Pin it.
        w.m_loadedFileVersion = WALLET_FILE_VERSION_7;
        return true;
    }

    // red-team HIGH-1 variant: the SAME encrypted-in-memory + plaintext-seed window
    // but pinned to the LEGACY-v6 writer (m_loadedFileVersion == 6 ⇒ writeLegacyV6
    // == true). This exercises the legacy-v6 plaintext-seed write path (wallet.cpp
    // ~3000), which the v7 guard did NOT cover. The dangerous state is the same:
    // masterKey.IsValid()==true && fHDMasterKeyEncrypted==false flowing to a 32-byte
    // plaintext seed write. On the pre-fix-#1 binary the legacy-v6 branch's only
    // guard checks the INVERSE (fHDMasterKeyEncrypted), so this Save SUCCEEDS and
    // leaks the plaintext seed; with the masterKey.IsValid() guard it must REFUSE.
    static bool ForceEncryptedPlaintextSeedWindowV6(CWallet& w) {
        if (!ForceEncryptedPlaintextSeedWindow(w)) return false;
        // Override the version: legacy-v6 writer path instead of v7.
        w.m_loadedFileVersion = WALLET_FILE_VERSION_6;
        return true;
    }

    static bool ForceSave(CWallet& w, const std::string& path) { return w.SaveUnlocked(path); }
    static bool IsHDEncrypted(const CWallet& w) { return w.fHDMasterKeyEncrypted; }
    static bool SeedMatches(const CWallet& w, const std::vector<uint8_t>& seed) {
        return seed.size() == 32 && std::memcmp(w.hdMasterKey.seed, seed.data(), 32) == 0;
    }

    // LP-7 (F1 fold, MED-2): replace the in-memory obfuscated-mnemonic slot with a
    // DIFFERENT but syntactically-VALID BIP39 phrase, encrypted under the SAME
    // obfuscation key the wallet derives from its (plaintext) seed. EncryptWallet's
    // Step-1 decrypt then round-trips cleanly to a valid-but-WRONG phrase that passes
    // CMnemonic::Validate — the exact MED-1/MED-2 precondition: only the identity
    // cross-check (re-derive seed + compare) catches it. Returns false if the wallet
    // isn't a plaintext-seed HD wallet (the only state where this injection is valid).
    static bool InjectValidButWrongMnemonic(CWallet& w, const std::string& wrongValidPhrase) {
        if (!w.fIsHDWallet || w.fHDMasterKeyEncrypted) return false;
        if (!CMnemonic::Validate(wrongValidPhrase)) return false;  // must be VALID BIP39
        std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(w.hdMasterKey.seed, w.hdMasterKey.seed + 32);
        DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());
        std::vector<uint8_t> mnIV;
        if (!GenerateIV(mnIV)) { memory_cleanse(obfKey.data(), obfKey.size()); return false; }
        CCrypter mnCrypter;
        if (!mnCrypter.SetKey(obfKey, mnIV)) { memory_cleanse(obfKey.data(), obfKey.size()); return false; }
        std::vector<uint8_t> bytes(wrongValidPhrase.begin(), wrongValidPhrase.end());
        std::vector<uint8_t> cipher;
        bool ok = mnCrypter.Encrypt(bytes, cipher);
        memory_cleanse(obfKey.data(), obfKey.size());
        if (!ok) return false;
        w.vchEncryptedMnemonic = std::move(cipher);
        w.vchMnemonicIV.assign(mnIV.begin(), mnIV.end());
        w.vchMnemonicMAC.clear();  // legacy obfuscation-key slot carries no MAC
        return true;
    }
    // LP-7 (F1 round 4, red-team HIGH-1): in the DEFERRED-AND-PRESERVE state (seed
    // encrypted at rest, empty mnemonic MAC), simulate on-disk tamper / bit-rot of the
    // mnemonic ciphertext. We re-encrypt a GARBAGE non-mnemonic plaintext under the SAME
    // obfuscation key the deferred export path derives (from the LIVE seed via
    // DecryptHDMasterKey, since hdMasterKey.seed is scrubbed once encrypted). The garbage
    // therefore DECRYPTS cleanly (PKCS#7 unpads) but FAILS CMnemonic::Validate — exactly
    // the "valid padding, invalid mnemonic" attack the export gate must reject. Wallet
    // must be encrypted + unlocked + deferred for this to be meaningful.
    static bool TamperDeferredMnemonicWithGarbage(CWallet& w, const std::string& garbage) {
        if (!w.m_migrationDeferredPassphrase || !w.vchMnemonicMAC.empty()) return false;
        CHDExtendedKey live;
        if (!w.DecryptHDMasterKey(live)) return false;  // need the live seed (unlocked)
        std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(live.seed, live.seed + 32);
        DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());
        live.Wipe();
        std::vector<uint8_t> mnIV;
        if (!GenerateIV(mnIV)) { memory_cleanse(obfKey.data(), obfKey.size()); return false; }
        CCrypter mnCrypter;
        if (!mnCrypter.SetKey(obfKey, mnIV)) { memory_cleanse(obfKey.data(), obfKey.size()); return false; }
        std::vector<uint8_t> bytes(garbage.begin(), garbage.end());
        std::vector<uint8_t> cipher;
        bool ok = mnCrypter.Encrypt(bytes, cipher);
        memory_cleanse(obfKey.data(), obfKey.size());
        if (!ok) return false;
        w.vchEncryptedMnemonic = std::move(cipher);
        w.vchMnemonicIV.assign(mnIV.begin(), mnIV.end());
        w.vchMnemonicMAC.clear();  // stays empty (deferred-state invariant)
        return true;
    }
    static bool MnemonicCiphertextMatches(const CWallet& w, const std::vector<uint8_t>& ct) {
        return w.vchEncryptedMnemonic == ct;
    }
    static std::vector<uint8_t> MnemonicCiphertext(const CWallet& w) {
        return w.vchEncryptedMnemonic;
    }
    // LP-7 (F1 round 3): observe the defer-and-preserve internal flag directly.
    static bool DeferredPassphrase(const CWallet& w) { return w.m_migrationDeferredPassphrase; }
    static bool NeedsMigrationRaw(const CWallet& w) { return w.m_fNeedsSeedMigration; }
    static bool HDSeedEncrypted(const CWallet& w) { return w.fHDMasterKeyEncrypted; }
    static std::vector<uint8_t> MnemonicMAC(const CWallet& w) { return w.vchMnemonicMAC; }
    // LP-7 (F1 round 3): exercise the passphrase-threaded identity check directly.
    static bool ReDerives(const CWallet& w, const std::string& mnemonic,
                          const std::string& candidatePassphrase) {
        return w.MnemonicReDerivesSeed(mnemonic, candidatePassphrase);
    }
};

// Convenience: empty-passphrase re-derive (must FAIL for a passphrase wallet).
static bool LP7Reseed_Empty(const CWallet& w, const std::string& mnemonic) {
    return LP7EncryptRollbackTester::ReDerives(w, mnemonic, "");
}

static void Test_EncryptWalletRollback() {
    std::cout << COLOR_BLUE "\n[Test 9] EncryptWallet transactional rollback + v7 plaintext-seed Save fail-closed (Cursor HIGH-1/HIGH-2)\n" COLOR_RESET;

    const std::string pass = "R0llb@ck!Test#2026";

    // === PART A: forced mid-HD-step failure rolls back to UNENCRYPTED ===
    {
        const std::string path = "lp7_rollback_wallet.dat";
        std::remove(path.c_str());

        std::string mnemonic;
        CWallet w;
        w.SetWalletFile(path);            // autosave on → a fresh v7 unencrypted wallet
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet (unencrypted v7)");

        std::vector<uint8_t> seed, chaincode;
        CHECK(DeriveSeedChaincode(mnemonic, seed, chaincode), "Derived expected seed from mnemonic");

        // Corrupt the encrypted mnemonic so the mnemonic-recover step inside
        // EncryptWallet fails AFTER the master key + key maps have been set up.
        CHECK(LP7EncryptRollbackTester::CorruptMnemonicCiphertext(w),
              "Corrupted vchEncryptedMnemonic (forces mnemonic-recover Decrypt to fail mid-encrypt)");

        bool encrypted = w.EncryptWallet(pass);
        CHECK(!encrypted, "LOAD-BEARING (a): EncryptWallet RETURNS FALSE on the mid-HD-step failure");

        // Rollback invariants: the wallet must be back to its original UNENCRYPTED state.
        CHECK(!w.IsCrypted(),
              "LOAD-BEARING (b): wallet rolled back to UNENCRYPTED (IsCrypted()==false, master key cleared)");
        CHECK(!LP7EncryptRollbackTester::IsHDEncrypted(w),
              "LOAD-BEARING (b): fHDMasterKeyEncrypted==false after rollback");
        CHECK(LP7EncryptRollbackTester::SeedMatches(w, seed),
              "LOAD-BEARING (b): in-memory plaintext seed intact after rollback (not scrubbed)");

        // A subsequent Save now writes a LEGITIMATE unencrypted wallet (the rollback
        // returned it to unencrypted), so a plaintext seed on disk here is correct —
        // and crucially the file must NOT be an encrypted wallet carrying a plaintext
        // seed. Assert the file is unencrypted (flags bit 0 clear).
        CHECK(w.Save(path), "Saved the rolled-back wallet");
        {
            std::vector<uint8_t> bytes = ReadFileBytes(path);
            CHECK(bytes.size() >= 16, "Read the saved wallet file");
            uint32_t flags = GetU32(bytes, 12);
            CHECK((flags & 0x01) == 0,
                  "LOAD-BEARING (c): saved file is UNENCRYPTED (no encrypted-wallet+plaintext-seed file produced)");
            // The seed IS present, which is correct for an unencrypted wallet (matches
            // Test 1's negative control). This is NOT the bug: the bug is an ENCRYPTED
            // file with a plaintext seed, excluded by the flag assertion above.
            CHECK(Contains(bytes, seed.data(), seed.size()),
                  "Unencrypted rolled-back wallet legitimately stores the seed (negative-control consistency)");
        }
        std::remove(path.c_str());
    }

    // === PART B: SaveUnlocked is fail-closed for an encrypted wallet with a
    //             plaintext seed (the v7 plaintext-branch guard) ===
    {
        const std::string path    = "lp7_rollback_src.dat";
        const std::string savePath = "lp7_rollback_guard.dat";
        std::remove(path.c_str());
        std::remove(savePath.c_str());

        std::string mnemonic;
        CWallet w;                         // no SetWalletFile → autosave off
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet for guard test");
        std::vector<uint8_t> seed, chaincode;
        CHECK(DeriveSeedChaincode(mnemonic, seed, chaincode), "Derived expected seed");

        // Force the exact bug window: encrypted-in-memory (master key valid) + the HD
        // seed still PLAINTEXT, at v7. This is what a pre-fix failed EncryptWallet (or
        // a future refactor) could leave behind.
        CHECK(LP7EncryptRollbackTester::ForceEncryptedPlaintextSeedWindow(w),
              "Entered encrypted-in-memory + plaintext-seed v7 window (IsCrypted && !fHDMasterKeyEncrypted)");
        CHECK(w.IsCrypted() && !LP7EncryptRollbackTester::IsHDEncrypted(w),
              "Window invariant holds: master key valid AND HD seed not encrypted");

        // Drive the writer the public Save() reaches. With the v7 plaintext-branch
        // guard this MUST refuse. Without it, a v7 file with the plaintext seed is
        // written for an encrypted wallet (the LP-7 exposure).
        bool saved = LP7EncryptRollbackTester::ForceSave(w, savePath);
        CHECK(!saved,
              "LOAD-BEARING: SaveUnlocked REFUSES to write a v7 plaintext seed for an encrypted wallet");

        std::vector<uint8_t> savedBytes = ReadFileBytes(savePath);
        CHECK(savedBytes.empty(),
              "FAIL-CLOSED: no file written at the destination (no v7 encrypted+plaintext-seed artifact)");
        if (!savedBytes.empty()) {
            CHECK(!Contains(savedBytes, seed.data(), seed.size()),
                  "FAIL-CLOSED: no plaintext seed persisted for the encrypted wallet");
        }

        std::remove(path.c_str());
        std::remove(savePath.c_str());
    }

    // === PART C (red-team HIGH-1): the LEGACY-v6 writer path is ALSO fail-closed
    //             for an encrypted wallet with a plaintext seed. The first fold
    //             only guarded the v7 plaintext branch; the parallel legacy-v6
    //             writer (writeLegacyV6 == true, wallet.cpp ~3000) wrote the 32-byte
    //             plaintext seed with no masterKey.IsValid() guard, so the LP-7 leak
    //             stayed live for v6-loaded encrypted wallets. This case FAILS on
    //             head 6d6e0b3a (proving HIGH-1) and PASSES after fix #1. ===
    {
        const std::string path     = "lp7_rollback_v6_src.dat";
        const std::string savePath = "lp7_rollback_v6_guard.dat";
        std::remove(path.c_str());
        std::remove(savePath.c_str());

        std::string mnemonic;
        CWallet w;                         // no SetWalletFile → autosave off
        CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet for v6 guard test");
        std::vector<uint8_t> seed, chaincode;
        CHECK(DeriveSeedChaincode(mnemonic, seed, chaincode), "Derived expected seed (v6 case)");

        // Force the SAME bug window but pinned to the legacy-v6 writer: encrypted-
        // in-memory (master key valid) + HD seed still PLAINTEXT, m_loadedFileVersion
        // == 6 ⇒ writeLegacyV6 == true. The seed is intact (not scrubbed), so the
        // pre-existing scrubbed-seed guard (fHDMasterKeyEncrypted) does NOT catch it —
        // only the new masterKey.IsValid() guard refuses this write.
        CHECK(LP7EncryptRollbackTester::ForceEncryptedPlaintextSeedWindowV6(w),
              "Entered encrypted-in-memory + plaintext-seed LEGACY-V6 window");
        CHECK(w.IsCrypted() && !LP7EncryptRollbackTester::IsHDEncrypted(w),
              "Window invariant holds (v6): master key valid AND HD seed not encrypted");

        // Drive the legacy-v6 writer. With fix #1 (masterKey.IsValid() guard on the
        // v6 branch) this MUST refuse. Without it, a v6 file with the plaintext seed
        // is written for an encrypted wallet — the LP-7 leak on the v6 path.
        bool saved = LP7EncryptRollbackTester::ForceSave(w, savePath);
        CHECK(!saved,
              "LOAD-BEARING (HIGH-1): SaveUnlocked REFUSES to write a legacy-v6 plaintext seed for an encrypted wallet");

        std::vector<uint8_t> savedBytes = ReadFileBytes(savePath);
        CHECK(savedBytes.empty(),
              "FAIL-CLOSED (v6): no file written at the destination (no v6 encrypted+plaintext-seed artifact)");
        if (!savedBytes.empty()) {
            CHECK(!Contains(savedBytes, seed.data(), seed.size()),
                  "FAIL-CLOSED (v6): no plaintext seed persisted for the encrypted wallet");
        }

        std::remove(path.c_str());
        std::remove(savePath.c_str());
    }
}

// ---------------------------------------------------------------------------
// Test 2e — F1 (BLOCKER): v7 migration MUST ABORT when the recovered mnemonic
// plaintext is padding-valid but NOT a valid BIP39 mnemonic. A successful
// CCrypter::Decrypt() only proves PKCS#7 padding was well-formed — it does NOT
// prove the content is a real seed phrase. If migration re-encrypted that garbage
// as the authoritative v7 mnemonic and rewrote the file at v7, the original seed
// ciphertext would be GONE → permanent, irreversible seed-phrase loss.
//
// Fixture: a legacy v6 plaintext-seed wallet whose obfuscated-mnemonic slot holds
// garbage (encrypted under the CORRECT obfuscation key, so Step-1 decrypt
// succeeds). The guard must:
//   (1) ABORT the migration for this record (no v7 rewrite is committed),
//   (2) leave the on-disk file byte-for-byte unchanged (original ciphertext NOT
//       discarded; file stays v6),
//   (3) keep the wallet loadable in its prior valid state.
//
// NOTE on Unlock's return value: by EXISTING design (wallet.cpp Unlock ~1310-1345),
// a migration failure does NOT fail the unlock — the wallet stays usable in memory
// and migration retries on the next unlock, with the on-disk file left byte-
// identical. So the F1-load-bearing assertion is NOT "Unlock returns false"; it is
// "the file is byte-for-byte unchanged and stays v6 (original ciphertext preserved,
// garbage NOT committed as the seed)". That is the irreversible-loss invariant.
//
// MUTATION CHECK: a no-op guard (one that proceeds to EncryptMnemonic(garbage))
// FAILS this test — migration would commit, the file would be rewritten to v7, the
// byte-identity assertion would break AND FileVersion would read v7. This proves the
// assertions are load-bearing, not decorative.
// ---------------------------------------------------------------------------
static void Test_F1_AbortOnInvalidMnemonic() {
    std::cout << COLOR_BLUE "\n[Test 2e] F1: v7 migration ABORTS on padding-valid non-BIP39 mnemonic\n" COLOR_RESET;

    const std::string path = "lp7_f1_garbage_mnemonic_wallet.dat";
    const std::string pass = "F1Abort!Garbage#2026";
    std::remove(path.c_str());

    // Padding-valid bytes that are NOT a valid BIP39 mnemonic (wrong word count and
    // non-wordlist tokens → CMnemonic::Validate() must reject). AES-CBC+PKCS7
    // round-trips ANY plaintext, so this decrypts cleanly under the obfuscation key.
    const std::string garbage = "this is not a valid bip39 seed phrase zzz qqq xyzzy plugh";
    CHECK(!CMnemonic::Validate(garbage),
          "Precondition: the injected plaintext is NOT a valid BIP39 mnemonic");

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy, /*mnemonicPlaintextOverride=*/garbage);
    CHECK(built, "Built legacy v6 wallet with padding-valid garbage in the mnemonic slot");
    if (!built) { std::remove(path.c_str()); return; }

    // Sanity: file is v6 and the plaintext seed is present (the migration trigger).
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Fixture file is v6");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Fixture v6 file contains plaintext seed (migration would be attempted)");
    }

    // Capture exact bytes BEFORE the migration attempt.
    std::vector<uint8_t> bytesBefore = ReadFileBytes(path);

    // --- Unlock with autosave ON → would normally drive the atomic v7 rewrite.
    //     The F1 guard must ABORT the migration (no v7 rewrite committed) because the
    //     recovered mnemonic fails BIP39 validation. Unlock itself still returns true
    //     by existing design (migration failure is non-fatal to the unlock). ---
    {
        CWallet w;
        w.SetWalletFile(path);  // enables autosave
        CHECK(w.Load(path), "Loaded the garbage-mnemonic legacy wallet (autosave on)");
        bool unlocked = w.Unlock(pass);
        CHECK(unlocked,
              "Unlock still succeeds (migration failure is non-fatal to unlock, by design)");
        // The load-bearing F1 assertions are the on-disk-invariant checks below.
    }

    // --- INVARIANT: original seed ciphertext NEVER discarded. The on-disk file must
    //     be byte-for-byte unchanged (no v7 rewrite happened) and still be a v6 file. ---
    std::vector<uint8_t> bytesAfter = ReadFileBytes(path);
    CHECK(bytesBefore == bytesAfter,
          "F1 INVARIANT: on-disk file is byte-for-byte UNCHANGED (original ciphertext preserved)");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "F1: file was NOT promoted to v7 (migration did not commit)");

    // --- The wallet remains in its prior valid, loadable state. ---
    {
        CWallet w;
        CHECK(w.Load(path), "Wallet still LOADS in its prior valid state after the aborted migration");
        CHECK(w.IsCrypted(), "Wallet still reports encrypted (unchanged)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2e-2 — F1 FOLD (MED-1): v7 migration MUST ABORT when the recovered mnemonic
// is a DIFFERENT but syntactically-VALID BIP39 phrase. This is the gap the original
// F1 (CMnemonic::Validate-only) guard MISSED: Validate proves SYNTACTIC BIP39, NOT
// that the phrase is THIS wallet's seed. A confused/partial-corruption decrypt that
// yields a valid-but-wrong phrase would PASS Validate, get re-encrypted as the
// authoritative v7 mnemonic, and permanently replace the backup phrase with the
// WRONG one (latent seed loss: the live wallet keeps spending via the in-memory
// seed, but a later restore-from-phrase yields the wrong seed). The identity
// cross-check (re-derive the master seed from the recovered phrase, compare to the
// authoritative hdMasterKey.seed) is what catches this.
//
// Fixture: a legacy v6 plaintext-seed wallet whose obfuscated-mnemonic slot holds a
// VALID BIP39 phrase ("abandon"×11 + "absorb", the Dilithion-wordlist checksum-valid
// all-abandon-prefix vector, asserted valid in mnemonic_tests.cpp:193) that is
// NOT the wallet's actual mnemonic, encrypted under the CORRECT obfuscation key (so
// Step-1 decrypt succeeds and Validate PASSES). The identity guard must ABORT.
//
// MUTATION CHECK: a Validate-ONLY guard (the pre-fold behavior) PASSES Validate here
// and PROCEEDS to commit the wrong seed → the byte-identity / still-v6 assertions
// would break. This proves the identity cross-check (not just Validate) is the
// load-bearing element.
// ---------------------------------------------------------------------------
static void Test_F1_AbortOnValidButWrongMnemonic() {
    std::cout << COLOR_BLUE "\n[Test 2e-2] F1 FOLD (MED-1): v7 migration ABORTS on a valid-but-WRONG BIP39 mnemonic\n" COLOR_RESET;

    const std::string path = "lp7_f1_wrongvalid_mnemonic_wallet.dat";
    const std::string pass = "F1Abort!WrongValid#2026";
    std::remove(path.c_str());

    // A VALID BIP39 phrase (canonical all-zeros vector) that is NOT this wallet's
    // mnemonic. Passes CMnemonic::Validate → defeats the old Validate-only guard.
    const std::string wrongValid =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    CHECK(CMnemonic::Validate(wrongValid),
          "Precondition: the injected phrase IS a syntactically-valid BIP39 mnemonic");

    LegacyV6Result legacy;
    bool built = BuildLegacyV6Wallet(path, pass, legacy, /*mnemonicPlaintextOverride=*/wrongValid);
    CHECK(built, "Built legacy v6 wallet with a valid-but-WRONG mnemonic in the slot");
    if (!built) { std::remove(path.c_str()); return; }
    // The fixture mnemonic (the real seed source) must differ from the injected one.
    CHECK(legacy.mnemonic != wrongValid,
          "Precondition: the wallet's real mnemonic differs from the injected valid phrase");

    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6, "Fixture file is v6");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Fixture v6 file contains plaintext seed (migration would be attempted)");
    }

    std::vector<uint8_t> bytesBefore = ReadFileBytes(path);

    {
        CWallet w;
        w.SetWalletFile(path);  // autosave on
        CHECK(w.Load(path), "Loaded the wrong-valid-mnemonic legacy wallet (autosave on)");
        bool unlocked = w.Unlock(pass);
        CHECK(unlocked,
              "Unlock still succeeds (migration failure is non-fatal to unlock, by design)");
    }

    // INVARIANT: original seed ciphertext NEVER discarded — file byte-for-byte
    // unchanged and still v6. A pre-fold Validate-only guard would FAIL these
    // (it would commit the wrong seed and promote the file to v7).
    std::vector<uint8_t> bytesAfter = ReadFileBytes(path);
    CHECK(bytesBefore == bytesAfter,
          "MED-1 INVARIANT: on-disk file byte-for-byte UNCHANGED (original ciphertext preserved)");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
          "MED-1: file was NOT promoted to v7 (wrong seed NOT committed)");

    {
        CWallet w;
        CHECK(w.Load(path), "Wallet still LOADS in its prior valid state after the aborted migration");
        CHECK(w.IsCrypted(), "Wallet still reports encrypted (unchanged)");
    }

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2e-3 — F1 FOLD (LOW-3): exercise the master-key FALLBACK decrypt arm
// (wallet.cpp ~5747), not just the Step-1 obfuscation arm. Fixture: a legacy wallet
// whose mnemonic slot is encrypted DIRECTLY under the master key (no MAC) → Step-1
// obfuscation decrypt fails, the fallback arm recovers the plaintext, and the
// identity guard runs on the fallback-recovered phrase.
//
// Two sub-cases pin both outcomes through the fallback arm:
//   (A) CORRECT mnemonic via the fallback arm → migration COMMITS (file → v7,
//       plaintext seed gone). Proves the fallback arm reaches and passes the guard.
//   (B) valid-but-WRONG mnemonic via the fallback arm → migration ABORTS, file
//       byte-for-byte preserved at v6. Proves the identity guard catches a wrong
//       phrase recovered through the fallback arm too (not only Step-1).
// ---------------------------------------------------------------------------
static void Test_F1_MasterKeyFallbackArm() {
    std::cout << COLOR_BLUE "\n[Test 2e-3] F1 FOLD (LOW-3): master-key fallback decrypt arm reaches the identity guard\n" COLOR_RESET;

    // --- (A) CORRECT mnemonic recovered via the fallback arm migrates cleanly. ---
    {
        const std::string path = "lp7_f1_fallback_correct.dat";
        const std::string pass = "F1Fallback!Correct#2026";
        std::remove(path.c_str());

        LegacyV6Result legacy;
        bool built = BuildLegacyV6Wallet(path, pass, legacy,
                                         /*mnemonicPlaintextOverride=*/"",
                                         /*encryptMnemonicUnderMasterKey=*/true);
        CHECK(built, "Built legacy wallet with the CORRECT mnemonic under the master key (fallback arm)");
        if (built) {
            std::string exported;
            {
                CWallet w;
                w.SetWalletFile(path);  // autosave on
                CHECK(w.Load(path), "Loaded fallback-arm (correct) legacy wallet");
                CHECK(w.Unlock(pass), "Unlock succeeds — correct mnemonic via fallback arm passes the guard");
                CHECK(w.ExportMnemonic(exported), "ExportMnemonic works post-migration");
            }
            CHECK(exported == legacy.mnemonic, "Mnemonic round-trips identically (fallback arm, correct)");
            CHECK(FileVersion(path) == WALLET_FILE_VERSION_7,
                  "LOW-3 (A): file promoted to v7 (fallback-arm migration committed)");
            {
                std::vector<uint8_t> bytes = ReadFileBytes(path);
                CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
                      "LOW-3 (A): plaintext seed ABSENT post-migration (drive-to-safety via fallback arm)");
            }
        }
        std::remove(path.c_str());
    }

    // --- (B) valid-but-WRONG mnemonic recovered via the fallback arm aborts. ---
    {
        const std::string path = "lp7_f1_fallback_wrongvalid.dat";
        const std::string pass = "F1Fallback!WrongValid#2026";
        std::remove(path.c_str());

        const std::string wrongValid =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
        CHECK(CMnemonic::Validate(wrongValid), "Precondition: injected phrase IS valid BIP39");

        LegacyV6Result legacy;
        bool built = BuildLegacyV6Wallet(path, pass, legacy,
                                         /*mnemonicPlaintextOverride=*/wrongValid,
                                         /*encryptMnemonicUnderMasterKey=*/true);
        CHECK(built, "Built legacy wallet with a valid-but-WRONG mnemonic under the master key (fallback arm)");
        if (built) {
            CHECK(legacy.mnemonic != wrongValid, "Precondition: real mnemonic differs from injected phrase");
            std::vector<uint8_t> bytesBefore = ReadFileBytes(path);
            {
                CWallet w;
                w.SetWalletFile(path);  // autosave on
                CHECK(w.Load(path), "Loaded fallback-arm (wrong-valid) legacy wallet");
                CHECK(w.Unlock(pass), "Unlock still succeeds (migration failure non-fatal)");
            }
            std::vector<uint8_t> bytesAfter = ReadFileBytes(path);
            CHECK(bytesBefore == bytesAfter,
                  "LOW-3 (B): on-disk file byte-for-byte UNCHANGED (fallback-arm wrong phrase aborted)");
            CHECK(FileVersion(path) == WALLET_FILE_VERSION_6,
                  "LOW-3 (B): file NOT promoted to v7 (wrong seed via fallback arm NOT committed)");
        }
        std::remove(path.c_str());
    }
}

// ---------------------------------------------------------------------------
// Test 9b — F1 FOLD (MED-2) + F1 ROUND-3 (Cursor HIGH): the EncryptWallet re-encrypt
// path has the SAME decrypt → EncryptMnemonic → discard-original shape as the v7
// migration. Inject a valid-but-WRONG BIP39 phrase into a fresh UNENCRYPTED HD
// wallet's obfuscated-mnemonic slot, then call EncryptWallet.
//
// ROUND-3 CONTRACT CHANGE: EncryptWallet now NEVER FAILS because the mnemonic can't be
// verified (the old behavior — return false + roll back to UNENCRYPTED — permanently
// stranded BIP39-passphrase wallets, since they could never encrypt). The new contract
// on a non-verifiable mnemonic is DEFER-AND-PRESERVE: encrypt the wallet + keys + seed,
// PRESERVE the original mnemonic ciphertext byte-for-byte (the wrong phrase is NEVER
// re-encrypted under the master key / committed as authoritative), set the
// deferred-passphrase diagnostic, and SUCCEED. The crucial seed-loss invariant — wrong
// phrase never committed as the authoritative mnemonic — is preserved, now via
// "preserved + deferred" rather than "rolled back to unencrypted".
//
// MUTATION CHECK: if EncryptWallet were to (wrongly) re-encrypt the recovered phrase
// under the master key here, the preserved-ciphertext-byte-for-byte assertion AND the
// "mnemonic MAC stays empty (not master-key MAC'd)" assertion break. Load-bearing.
// ---------------------------------------------------------------------------
static void Test_F1_EncryptWalletDefersOnValidButWrongMnemonic() {
    std::cout << COLOR_BLUE "\n[Test 9b] F1 r3: EncryptWallet DEFERS-AND-PRESERVES (never fails) on a valid-but-WRONG BIP39 mnemonic\n" COLOR_RESET;

    const std::string path = "lp7_f1_encwallet_wrongvalid.dat";
    const std::string pass = "F1EncWallet!WrongValid#2026";
    std::remove(path.c_str());

    const std::string wrongValid =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon absorb";
    CHECK(CMnemonic::Validate(wrongValid), "Precondition: injected phrase IS valid BIP39");

    std::string mnemonic;
    CWallet w;
    w.SetWalletFile(path);  // autosave on → fresh v7 unencrypted HD wallet
    CHECK(w.GenerateHDWallet(mnemonic), "Generated HD wallet (unencrypted)");
    CHECK(mnemonic != wrongValid, "Precondition: real mnemonic differs from injected phrase");

    std::vector<uint8_t> seed, chaincode;
    CHECK(DeriveSeedChaincode(mnemonic, seed, chaincode), "Derived expected seed from real mnemonic");

    // Inject the valid-but-WRONG phrase into the in-memory obfuscated-mnemonic slot
    // (re-encrypted under the wallet's own obfuscation key → EncryptWallet's Step-1
    // decrypt succeeds and CMnemonic::Validate passes; only the identity check fails).
    CHECK(LP7EncryptRollbackTester::InjectValidButWrongMnemonic(w, wrongValid),
          "Injected a valid-but-WRONG mnemonic under the wallet's obfuscation key");
    std::vector<uint8_t> ctBefore = LP7EncryptRollbackTester::MnemonicCiphertext(w);

    bool encrypted = w.EncryptWallet(pass);
    CHECK(encrypted,
          "LOAD-BEARING (r3): EncryptWallet SUCCEEDS (never fails on an unverifiable mnemonic)");
    CHECK(w.IsCrypted(),
          "LOAD-BEARING (r3): wallet IS encrypted (keys + seed encrypted)");
    CHECK(LP7EncryptRollbackTester::HDSeedEncrypted(w),
          "LOAD-BEARING (r3): HD seed encrypted at rest (fHDMasterKeyEncrypted == true)");
    CHECK(LP7EncryptRollbackTester::MnemonicCiphertextMatches(w, ctBefore),
          "LOAD-BEARING (r3/MED-2): mnemonic ciphertext PRESERVED byte-for-byte (wrong phrase never re-encrypted/committed)");
    CHECK(LP7EncryptRollbackTester::MnemonicMAC(w).empty(),
          "LOAD-BEARING (r3): mnemonic MAC stays EMPTY (NOT master-key re-encrypted — still under obfuscation key)");
    CHECK(w.MigrationDeferredForPassphrase(),
          "LOAD-BEARING (r3): deferred-passphrase diagnostic set (distinct observable, not corruption)");
    CHECK(w.NeedsSeedMigration(),
          "LOAD-BEARING (r3): NeedsSeedMigration armed so a later unlock can complete migration");

    std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// Test 2f — F1 happy path: a VALID mnemonic still migrates cleanly. Guards the
// guard against being over-broad (i.e. the validation must NOT block legitimate
// migrations). This is the same shape as Test_Migration but asserted alongside the
// abort test so the pair pins both arms of the branch.
// ---------------------------------------------------------------------------
static void Test_F1_ValidMnemonicStillMigrates() {
    std::cout << COLOR_BLUE "\n[Test 2f] F1 happy path: a VALID mnemonic still migrates to v7\n" COLOR_RESET;

    const std::string path = "lp7_f1_valid_mnemonic_wallet.dat";
    const std::string pass = "F1Valid!Migrate#2026";
    std::remove(path.c_str());

    LegacyV6Result legacy;
    // No override → the real (valid) mnemonic is encrypted into the slot.
    bool built = BuildLegacyV6Wallet(path, pass, legacy);
    CHECK(built, "Built legacy v6 wallet with a VALID mnemonic");
    if (!built) { std::remove(path.c_str()); return; }
    CHECK(CMnemonic::Validate(legacy.mnemonic), "Precondition: fixture mnemonic IS valid BIP39");

    std::string exported;
    {
        CWallet w;
        w.SetWalletFile(path);  // autosave on
        CHECK(w.Load(path), "Loaded valid-mnemonic legacy wallet (autosave on)");
        CHECK(w.Unlock(pass), "F1: Unlock SUCCEEDS — valid mnemonic is not blocked by the guard");
        CHECK(w.ExportMnemonic(exported), "ExportMnemonic works post-migration");
    }
    CHECK(exported == legacy.mnemonic, "Mnemonic round-trips identically after migration");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "File promoted to v7 (valid migration committed)");
    {
        std::vector<uint8_t> bytes = ReadFileBytes(path);
        CHECK(!Contains(bytes, legacy.seed.data(), legacy.seed.size()),
              "Post-migration: plaintext seed ABSENT (drive-to-safety still works for valid mnemonics)");
    }

    std::remove(path.c_str());
}

// ===========================================================================
// LP-7 F1 ROUND-3 — BIP39-passphrase cohort (Cursor HIGH)
//
// A wallet created with GenerateHDWallet(mnemonic, <bip39pp>) has
// seed = ToSeed(mnemonic, <bip39pp>), and its mnemonic is stored under the
// obfuscation key derived from THAT seed. So MnemonicReDerivesSeed(mnemonic, "")
// CANNOT match (empty passphrase → different seed), but
// MnemonicReDerivesSeed(mnemonic, <bip39pp>) DOES. The round-3 fix lets the user
// thread the BIP39 passphrase into encrypt/migrate so these wallets are no longer
// stranded — AND makes EncryptWallet never-fail (defer-and-preserve) when it can't
// verify.
// ===========================================================================
static const char* kTrezorPP = "TREZOR";

// (1) Passphrase wallet + CORRECT passphrase at encrypt time → migrates to v7
//     (mnemonic re-encrypted under master, seed absent at rest).
static void Test_F1R3_PassphraseWalletEncryptMigratesWithCorrectPassphrase() {
    std::cout << COLOR_BLUE "\n[Test r3-1] Passphrase wallet + CORRECT bip39passphrase at EncryptWallet → migrates to v7\n" COLOR_RESET;
    const std::string path = "lp7_r3_pp_encrypt_correct.dat";
    const std::string pass = "R3PP!Encrypt#Correct2026";
    std::remove(path.c_str());

    std::string mnemonic;
    CWallet w;
    w.SetWalletFile(path);  // autosave on
    CHECK(w.GenerateHDWallet(mnemonic, kTrezorPP), "Generated BIP39-passphrase HD wallet (TREZOR)");

    // Precondition: empty-passphrase re-derive must FAIL; passphrase re-derive must MATCH.
    CHECK(!LP7Reseed_Empty(w, mnemonic), "Precondition: empty-passphrase re-derive does NOT match (passphrase wallet)");

    // Expected seed = ToSeed(mnemonic, TREZOR) → master seed.
    uint8_t bip39seed[64];
    CHECK(CMnemonic::ToSeed(mnemonic, kTrezorPP, bip39seed), "Derived BIP39 seed with passphrase");
    CHDExtendedKey master; DeriveMaster(bip39seed, master); memory_cleanse(bip39seed, 64);
    std::vector<uint8_t> expectedSeed(master.seed, master.seed + 32);

    bool encrypted = w.EncryptWallet(pass, kTrezorPP);
    CHECK(encrypted, "EncryptWallet SUCCEEDS with the correct BIP39 passphrase");
    CHECK(w.IsCrypted(), "Wallet is encrypted");
    CHECK(LP7EncryptRollbackTester::HDSeedEncrypted(w), "HD seed encrypted at rest");
    CHECK(!LP7EncryptRollbackTester::MnemonicMAC(w).empty(),
          "LOAD-BEARING: mnemonic re-encrypted UNDER MASTER (non-empty MAC) — migration completed");
    CHECK(!w.MigrationDeferredForPassphrase(), "NOT deferred — verified + migrated");
    CHECK(!w.NeedsSeedMigration(), "NeedsSeedMigration cleared — fully migrated");

    // Mnemonic still round-trips (under master key now).
    std::string exported;
    CHECK(w.ExportMnemonic(exported), "ExportMnemonic works post-migration");
    CHECK(exported == mnemonic, "Mnemonic round-trips identically");

    // On disk: seed absent at rest.
    std::vector<uint8_t> bytes = ReadFileBytes(path);
    CHECK(!Contains(bytes, expectedSeed.data(), expectedSeed.size()),
          "LOAD-BEARING: plaintext seed ABSENT on disk (seed encrypted, passphrase wallet migrated)");
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "File at v7");

    std::remove(path.c_str());
}

// (2) Passphrase wallet + WRONG/ABSENT passphrase → migration defers, original
//     mnemonic ciphertext preserved byte-for-byte, EncryptWallet still SUCCEEDS.
static void Test_F1R3_PassphraseWalletDefersPreservesEncryptsWithoutPassphrase() {
    std::cout << COLOR_BLUE "\n[Test r3-2] Passphrase wallet + WRONG/ABSENT bip39passphrase → defers+preserves, EncryptWallet STILL SUCCEEDS\n" COLOR_RESET;
    const std::string path = "lp7_r3_pp_encrypt_wrong.dat";
    const std::string pass = "R3PP!Encrypt#Wrong2026";
    std::remove(path.c_str());

    std::string mnemonic;
    CWallet w;
    w.SetWalletFile(path);
    CHECK(w.GenerateHDWallet(mnemonic, kTrezorPP), "Generated BIP39-passphrase HD wallet (TREZOR)");

    // Snapshot the original obfuscation-key mnemonic ciphertext BEFORE encryption.
    std::vector<uint8_t> ctBefore = LP7EncryptRollbackTester::MnemonicCiphertext(w);

    // Encrypt with NO bip39 passphrase (the absent case) — must NOT fail.
    bool encrypted = w.EncryptWallet(pass /* bip39Passphrase defaults to "" */);
    CHECK(encrypted, "LOAD-BEARING: EncryptWallet STILL SUCCEEDS without the BIP39 passphrase (never fails)");
    CHECK(w.IsCrypted(), "Wallet IS encrypted (keys + seed)");
    CHECK(LP7EncryptRollbackTester::HDSeedEncrypted(w), "HD seed encrypted at rest");
    CHECK(LP7EncryptRollbackTester::MnemonicCiphertextMatches(w, ctBefore),
          "LOAD-BEARING: original mnemonic ciphertext PRESERVED byte-for-byte (not discarded/re-encrypted)");
    CHECK(LP7EncryptRollbackTester::MnemonicMAC(w).empty(),
          "LOAD-BEARING: mnemonic MAC still EMPTY (under obfuscation key, NOT master-key re-encrypted)");
    CHECK(w.MigrationDeferredForPassphrase(),
          "LOAD-BEARING: distinct deferred-passphrase diagnostic set (NOT corruption)");
    CHECK(w.NeedsSeedMigration(), "Migration armed for a later passphrase-supplied unlock");

    // Mnemonic is still recoverable in the deferred window (obfuscation-key fallback).
    std::string exported;
    CHECK(w.ExportMnemonic(exported), "Mnemonic still exportable in the deferred window (obfuscation-key fallback)");
    CHECK(exported == mnemonic, "Exported mnemonic matches the original (preserved phrase)");

    std::remove(path.c_str());
}

// (3) Passphrase wallet: encrypt WITHOUT passphrase (defers), then UNLOCK WITH the
//     correct passphrase → migration completes (mnemonic re-encrypted under master).
static void Test_F1R3_PassphraseWalletUnlockMigratesWithCorrectPassphrase() {
    std::cout << COLOR_BLUE "\n[Test r3-3] Passphrase wallet: defer at encrypt, then unlock WITH bip39passphrase → completes migration\n" COLOR_RESET;
    const std::string path = "lp7_r3_pp_unlock_correct.dat";
    const std::string pass = "R3PP!Unlock#Correct2026";
    std::remove(path.c_str());

    std::string mnemonic;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.GenerateHDWallet(mnemonic, kTrezorPP), "Generated BIP39-passphrase HD wallet (TREZOR)");
        CHECK(w.EncryptWallet(pass), "Encrypted without BIP39 passphrase (defers)");
        CHECK(w.MigrationDeferredForPassphrase(), "Deferred-passphrase state set");
    }

    // Reload (lock), then unlock WITH the BIP39 passphrase → migration completes.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "Reloaded the deferred-passphrase wallet");
        CHECK(w.NeedsSeedMigration(), "Reload re-armed migration (empty-MAC mnemonic detected)");
        CHECK(w.MigrationDeferredForPassphrase(), "Reload surfaced deferred-passphrase observable");
        // Unlock WITH the correct BIP39 passphrase.
        CHECK(w.Unlock(pass, 0, kTrezorPP), "Unlock with correct bip39passphrase succeeds");
        CHECK(!w.MigrationDeferredForPassphrase(), "LOAD-BEARING: migration COMPLETED (no longer deferred)");
        CHECK(!w.NeedsSeedMigration(), "NeedsSeedMigration cleared");
        CHECK(!LP7EncryptRollbackTester::MnemonicMAC(w).empty(),
              "LOAD-BEARING: mnemonic now under MASTER key (non-empty MAC)");
        std::string exported;
        CHECK(w.ExportMnemonic(exported), "ExportMnemonic works post-migration");
        CHECK(exported == mnemonic, "Mnemonic round-trips identically after passphrase-supplied migration");
    }
    CHECK(FileVersion(path) == WALLET_FILE_VERSION_7, "File at v7 after completed migration");

    std::remove(path.c_str());
}

// (4) Empty-passphrase wallet (the common cohort) → unchanged: still migrates with "".
static void Test_F1R3_EmptyPassphraseCohortUnchanged() {
    std::cout << COLOR_BLUE "\n[Test r3-4] Empty-passphrase wallet → unchanged (still migrates with \"\")\n" COLOR_RESET;
    const std::string path = "lp7_r3_emptypp.dat";
    const std::string pass = "R3Empty!Cohort#2026";
    std::remove(path.c_str());

    std::string mnemonic;
    CWallet w;
    w.SetWalletFile(path);
    CHECK(w.GenerateHDWallet(mnemonic /* empty passphrase */), "Generated empty-passphrase HD wallet");

    bool encrypted = w.EncryptWallet(pass);  // no bip39 passphrase needed
    CHECK(encrypted, "EncryptWallet succeeds");
    CHECK(!w.MigrationDeferredForPassphrase(), "NOT deferred — empty-passphrase verifies with \"\"");
    CHECK(!w.NeedsSeedMigration(), "NeedsSeedMigration cleared (fully migrated)");
    CHECK(!LP7EncryptRollbackTester::MnemonicMAC(w).empty(),
          "Mnemonic re-encrypted under master (non-empty MAC) — same as before round 3");
    std::string exported;
    CHECK(w.ExportMnemonic(exported), "ExportMnemonic works");
    CHECK(exported == mnemonic, "Mnemonic round-trips");

    std::remove(path.c_str());
}

// (5) The deferred state survives a reload (load gate accepts empty-MAC mnemonic on an
//     encrypted v7 wallet and re-arms migration), and the WRONG passphrase on unlock
//     keeps deferring + preserving while the wallet stays usable.
static void Test_F1R3_DeferredStateReloadsAndCompletes() {
    std::cout << COLOR_BLUE "\n[Test r3-5] Deferred state RELOADS (no brick), wrong passphrase keeps deferring, file usable\n" COLOR_RESET;
    const std::string path = "lp7_r3_deferred_reload.dat";
    const std::string pass = "R3Deferred!Reload#2026";
    std::remove(path.c_str());

    std::string mnemonic;
    std::vector<uint8_t> ctOriginal;
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.GenerateHDWallet(mnemonic, kTrezorPP), "Generated BIP39-passphrase HD wallet");
        ctOriginal = LP7EncryptRollbackTester::MnemonicCiphertext(w);
        CHECK(w.EncryptWallet(pass), "Encrypted (defers — no BIP39 passphrase)");
    }

    // Reload: the v7 ENCRYPTED + empty-MAC-mnemonic file must LOAD (not be rejected as
    // corrupt) and re-arm migration.
    {
        CWallet w;
        w.SetWalletFile(path);
        CHECK(w.Load(path), "LOAD-BEARING: deferred-state v7 file LOADS (empty-MAC mnemonic accepted, not bricked)");
        CHECK(w.IsCrypted(), "Loaded wallet is encrypted");
        CHECK(w.NeedsSeedMigration(), "Migration re-armed on reload");
        CHECK(w.MigrationDeferredForPassphrase(), "Deferred-passphrase observable re-surfaced");
        CHECK(LP7EncryptRollbackTester::MnemonicCiphertextMatches(w, ctOriginal),
              "Original mnemonic ciphertext preserved across the reload");

        // Unlock with a WRONG BIP39 passphrase → keeps deferring + preserving.
        std::vector<uint8_t> ctBeforeUnlock = LP7EncryptRollbackTester::MnemonicCiphertext(w);
        CHECK(w.Unlock(pass, 0, "WRONG-PASSPHRASE"), "Unlock (AES pass correct) succeeds even with wrong bip39pp");
        CHECK(w.MigrationDeferredForPassphrase(), "Still deferred after a WRONG bip39 passphrase");
        CHECK(LP7EncryptRollbackTester::MnemonicCiphertextMatches(w, ctBeforeUnlock),
              "LOAD-BEARING: original ciphertext preserved after a wrong-passphrase unlock (no destructive rewrite)");
    }

    std::remove(path.c_str());
}

// (6) LP-7 (F1 round 4, red-team HIGH-1 / extreview BLOCKER): the deferred-state
//     mnemonic EXPORT must be gated by CMnemonic::Validate. A legit deferred
//     passphrase wallet's VALID mnemonic still exports (NO re-break of the round-3
//     cohort); a TAMPERED/garbage ciphertext that decrypts to a non-mnemonic must be
//     REFUSED rather than handed to the user as their backup phrase.
static void Test_F1R4_DeferredExportGatedByValidate() {
    std::cout << COLOR_BLUE "\n[Test r4-1] Deferred mnemonic export GATED by Validate (tamper REFUSED, legit phrase OK)\n" COLOR_RESET;
    const std::string path = "lp7_r4_export_gate.dat";
    const std::string pass = "R4Export!Gate#2026";
    std::remove(path.c_str());

    std::string mnemonic;
    CWallet w;
    w.SetWalletFile(path);
    CHECK(w.GenerateHDWallet(mnemonic, kTrezorPP), "Generated BIP39-passphrase HD wallet (TREZOR)");

    // Encrypt WITHOUT the BIP39 passphrase → defer-and-preserve (seed encrypted, mnemonic
    // under obfuscation key, empty MAC). EncryptWallet leaves the wallet UNLOCKED.
    CHECK(w.EncryptWallet(pass), "EncryptWallet succeeds (defers BIP39-passphrase migration)");
    CHECK(w.MigrationDeferredForPassphrase(), "Deferred-passphrase state set");
    CHECK(LP7EncryptRollbackTester::HDSeedEncrypted(w), "Seed IS encrypted at rest (deferred)");
    CHECK(LP7EncryptRollbackTester::MnemonicMAC(w).empty(), "Mnemonic MAC empty (obfuscation-key window)");

    // NEGATIVE CONTROL (must NOT re-break round-3): the legit VALID mnemonic still exports
    // in the deferred window. If the gate used MnemonicReDerivesSeed("") instead of
    // CMnemonic::Validate, THIS assertion would FAIL for a passphrase wallet.
    {
        std::string exported;
        CHECK(w.ExportMnemonic(exported),
              "LOAD-BEARING (no re-break): legit passphrase-wallet mnemonic STILL exports in deferred window");
        CHECK(exported == mnemonic, "Exported phrase matches the original (Validate passes a real mnemonic)");
    }

    // Now TAMPER: replace the deferred ciphertext with garbage that decrypts (clean PKCS#7)
    // but is NOT a valid BIP39 mnemonic. Export MUST refuse.
    {
        const std::string garbage = "this is not a valid bip39 mnemonic phrase at all xyzzy";
        CHECK(LP7EncryptRollbackTester::TamperDeferredMnemonicWithGarbage(w, garbage),
              "Tampered the deferred mnemonic ciphertext with non-mnemonic garbage (decrypts cleanly)");
        std::string exported = "SENTINEL";
        bool ok = w.ExportMnemonic(exported);
        CHECK(!ok,
              "LOAD-BEARING (HIGH-1 closed): export REFUSES the tampered/garbage mnemonic (Validate gate)");
        CHECK(exported != garbage,
              "Garbage plaintext is NOT handed back to the user as a backup phrase");
    }

    std::remove(path.c_str());
}

int main() {
    std::cout << COLOR_BLUE "==== LP-7 wallet encryption-at-rest tests ====" COLOR_RESET "\n";

    Test_Secrecy();
    Test_Migration();
    Test_F1_AbortOnInvalidMnemonic();
    Test_F1_AbortOnValidButWrongMnemonic();          // MED-1: valid-but-wrong, migration path
    Test_F1_MasterKeyFallbackArm();                  // LOW-3: master-key fallback decrypt arm
    Test_F1_ValidMnemonicStillMigrates();
    Test_NeedsSeedMigrationSurfaced();
    Test_V7PlaintextSeedArtifactMigrates();
    Test_M1_FlagTracksOnDiskNotInMemory();
    Test_FailClosedScrubbedV6Window();
    Test_AuthTamper();
    Test_PerRecordMACIsolation();
    Test_AtomicRenameCrashWindow();
    Test_LegacyPerAddressKey();
    Test_ChangePassphraseLegacyNonHD();
    Test_ChangePassphraseLegacyV6WithMIK();
    Test_EncryptWalletRollback();
    Test_F1_EncryptWalletDefersOnValidButWrongMnemonic(); // r3: valid-but-wrong, EncryptWallet defers (never fails)
    // LP-7 (F1 round 3): BIP39-passphrase cohort — encrypt/migrate WITH passphrase,
    // defer-and-preserve WITHOUT, and the empty-passphrase cohort stays unchanged.
    Test_F1R3_PassphraseWalletEncryptMigratesWithCorrectPassphrase();
    Test_F1R3_PassphraseWalletDefersPreservesEncryptsWithoutPassphrase();
    Test_F1R3_PassphraseWalletUnlockMigratesWithCorrectPassphrase();
    Test_F1R3_EmptyPassphraseCohortUnchanged();
    Test_F1R3_DeferredStateReloadsAndCompletes();
    // LP-7 (F1 round 4): deferred-state export gated by Validate (tamper refused).
    Test_F1R4_DeferredExportGatedByValidate();

    std::cout << "\n=============================================\n";
    std::cout << "PASSED: " << g_pass << "   FAILED: " << g_fail << "\n";
    std::cout << "=============================================\n";
    return g_fail == 0 ? 0 : 1;
}
