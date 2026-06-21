// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <wallet/wallet.h>
#include <wallet/passphrase_validator.h>
#include <wallet/wal.h>  // PERSIST-008 FIX
#include <wallet/wal_recovery.h>  // PERSIST-008 FIX
#include <crypto/sha3.h>
#include <crypto/hmac_sha3.h>  // FIX-011: For file integrity HMAC
#include <digital_dna/sample_envelope.h>  // Phase 1.5: SignDNAEnvelope
#include <rpc/auth.h>  // FIX-011/FIX-012: For SecureCompare
#include <util/base58.h>
#include <node/utxo_set.h>
#include <node/mempool.h>
#include <node/blockchain_storage.h>  // BUG #56 FIX: For CBlockchainDB (RescanFromHeight)
#include <primitives/block.h>  // BUG #56 FIX: For CBlock (blockConnected/blockDisconnected)
#include <primitives/transaction.h>  // BUG #56 FIX: For CTransaction deserialization
#include <consensus/chain.h>  // BUG #56 FIX: For CChainState (RescanFromHeight)
#include <consensus/tx_validation.h>
#include <consensus/fees.h>
#include <consensus/sighash.h>  // WALLET-015 FIX: SIGHASH types
#include <consensus/validation.h>  // BUG #112 FIX: For CBlockValidator::DeserializeBlockTransactions
#include <core/chainparams.h>  // CHAIN-ID FIX: For replay protection

#include <algorithm>
#include <random>  // WALLET-007 FIX: For std::shuffle
#include <cstring>
#include <fstream>
#include <iostream>
#include <cstdio>   // For snprintf (thread-safe number formatting)
#include <limits>
#include <thread>
#include <chrono>

// FIX-002 (PERSIST-003): File permissions
// FIX-004 (PERSIST-002): fsync for atomic writes
#ifndef _WIN32
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <unistd.h>
#endif

// Dilithium3 API
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
    int pqcrystals_dilithium3_ref_signature(uint8_t *sig, size_t *siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *ctx, size_t ctxlen,
                                            const uint8_t *sk);
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace WalletCrypto {

bool GenerateKeyPair(CKey& key) {
    key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
    key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);

    int result = pqcrystals_dilithium3_ref_keypair(
        key.vchPubKey.data(),
        key.vchPrivKey.data()
    );

    if (result != 0) {
        key.Clear();
        return false;
    }

    return true;
}

bool Sign(const CKey& key, const uint8_t* data, size_t dataLen,
          std::vector<uint8_t>& signature) {
    if (!key.IsValid()) {
        return false;
    }

    signature.resize(DILITHIUM_SIGNATURE_SIZE);
    size_t siglen = 0;

    int result = pqcrystals_dilithium3_ref_signature(
        signature.data(), &siglen,
        data, dataLen,
        nullptr, 0,  // No context
        key.vchPrivKey.data()
    );

    if (result != 0) {
        signature.clear();
        return false;
    }

    signature.resize(siglen);
    return true;
}

bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* data,
            size_t dataLen, const std::vector<uint8_t>& signature) {
    if (pubkey.size() != DILITHIUM_PUBLICKEY_SIZE) {
        return false;
    }

    int result = pqcrystals_dilithium3_ref_verify(
        signature.data(), signature.size(),
        data, dataLen,
        nullptr, 0,  // No context
        pubkey.data()
    );

    return result == 0;
}

std::vector<uint8_t> HashPubKey(const std::vector<uint8_t>& pubkey) {
    // SHA3-256 the public key (quantum-resistant)
    uint8_t hash1[32];
    SHA3_256(pubkey.data(), pubkey.size(), hash1);

    // SHA3-256 again for double hashing
    uint8_t hash2[32];
    SHA3_256(hash1, 32, hash2);

    // Take first 20 bytes
    return std::vector<uint8_t>(hash2, hash2 + 20);
}

} // namespace WalletCrypto

// CDilithiumAddress implementation

CDilithiumAddress::CDilithiumAddress(const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> hash = WalletCrypto::HashPubKey(pubkey);

    // Create address data: version byte (0x1E) + hash (20 bytes)
    vchData.push_back(0x1E);
    vchData.insert(vchData.end(), hash.begin(), hash.end());

    // vchData is now 21 bytes (1 + 20)
}

std::string CDilithiumAddress::ToString() const {
    if (!IsValid()) {
        return "";
    }
    return ::EncodeBase58Check(vchData);
}

bool CDilithiumAddress::SetString(const std::string& str) {
    if (!::DecodeBase58Check(str, vchData)) {
        vchData.clear();
        return false;
    }

    // Verify version byte
    if (vchData.empty() || vchData[0] != 0x1E) {
        vchData.clear();
        return false;
    }

    // Should be 1 version byte + 20 hash bytes
    if (vchData.size() != 21) {
        vchData.clear();
        return false;
    }

    return true;
}

// CWallet implementation

CWallet::CWallet()
    : fWalletUnlocked(false),
      fWalletUnlockForStakingOnly(false),
      nUnlockTime(std::chrono::steady_clock::time_point::max()),
      nUnlockFailedAttempts(0),  // WL-011: Initialize rate limiting
      nLastFailedUnlock(std::chrono::steady_clock::time_point::min()),
      m_autoSave(false),
      m_bestBlockHeight(-1),  // BUG #56 FIX: Initialize to -1 (not synced)
      m_wal(nullptr),  // PERSIST-008 FIX: Initialize WAL
      fIsHDWallet(false),
      fHDMasterKeyEncrypted(false),
      fHDMasterKeyCached(false),  // WL-010: Initialize cache flag
      nHDAccountIndex(0),
      nHDExternalChainIndex(0),
      nHDInternalChainIndex(0),
      fHasMIK(false),  // MIK: No mining identity key yet
      fMIKRegistered(false)  // MIK: Not registered on-chain
{
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    // BUG #56 FIX: m_bestBlockHash is default-initialized to null hash
}

CWallet::~CWallet() {
    Clear();
}

bool CWallet::GenerateNewKey() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check if wallet is locked (don't call IsLocked() - we already have the mutex)
    if (masterKey.IsValid() && !fWalletUnlocked) {
        return false;  // Cannot generate keys when locked
    }

    CKey key;
    if (!WalletCrypto::GenerateKeyPair(key)) {
        return false;
    }

    CDilithiumAddress address(key.vchPubKey);

    // If wallet is encrypted, encrypt the key (don't call IsCrypted() - we already have the mutex)
    if (masterKey.IsValid()) {
        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;

        // FIX-010: Generate unique IV
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            return false;
        }

        // Encrypt private key with master key
        CCrypter crypter;
        std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                          vMasterKey.data_ptr() + vMasterKey.size());
        if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        // LP-7: a per-address at-rest key MUST carry a v7 MAC, or Load() (which
        // rejects any v7 record with an empty vchMAC) refuses the WHOLE wallet on
        // the next start — silent funds-access loss. Mirror EncryptWallet's per-
        // address MAC compute; GetKeyUnlocked already verifies it symmetrically.
        // The MAC keying MUST match the verify side (VerifyRecordMAC in
        // GetKeyUnlocked): a loaded v3-v6 wallet uses legacy AES-keyed HMAC, and a
        // non-HD v6 wallet never migrates — so a v7-keyed MAC written here would
        // make the freshly-minted key UNSPENDABLE on the next load. Select keying
        // by the loaded file version, exactly as EncryptWallet/ChangePassphrase do.
        const bool legacyKeying = LegacyRecordKeying();
        if (!ComputeRecordMAC(crypter, encKey.vchCryptedKey, encKey.vchMAC, legacyKeying)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();   // defense-in-depth: wipe the plaintext key on the failure
                           // path (mirrors DeriveAndCacheHDAddress's fail branch); CKey
                           // RAII already wipes on return, this makes the intent explicit.
            return false;
        }

        mapCryptedKeys[address] = encKey;
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
    } else {
        // Wallet not encrypted, store key as-is
        mapKeys[address] = key;
    }

    vchAddresses.push_back(address);

    // Set as default if first key
    if (vchAddresses.size() == 1) {
        defaultAddress = address;
    }

    // Auto-save wallet if enabled (we already hold the lock)
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

CDilithiumAddress CWallet::GetNewAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (vchAddresses.empty()) {
        return CDilithiumAddress();
    }

    return defaultAddress;
}

std::vector<CDilithiumAddress> CWallet::GetAddresses() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return vchAddresses;
}

bool CWallet::HasKey(const CDilithiumAddress& address) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check both encrypted and unencrypted key stores
    if (mapKeys.find(address) != mapKeys.end()) {
        return true;
    }

    return mapCryptedKeys.find(address) != mapCryptedKeys.end();
}

// LP-7 (HIGH-2): the ONE authenticated-decrypt gate shared by all five at-rest
// record types. See the declaration in wallet.h for the full policy contract.
// Returns true iff the caller may proceed to decrypt `ciphertext`.
//
// =====================================================================================
// LP-7 (round 3, MEDIUM-1): EXHAUSTIVE AT-REST RECORD MAC-CONSUMER ENUMERATION
// -------------------------------------------------------------------------------------
// Every per-record at-rest MAC verify/compute in the wallet MUST route through
// VerifyRecordMAC (reads) or ComputeRecordMAC (writes) so the keying selection is
// version-correct in exactly ONE place. The complete census (grep the wallet for
// `\.VerifyMAC(` / `\.ComputeMAC(`):
//
//   VERIFY (read-before-decrypt) — all 6 route through VerifyRecordMAC:
//     1. per-address spending key   wallet.cpp  GetKeyUnlocked        -> VerifyRecordMAC
//     2. master key                 wallet.cpp  Unlock                -> VerifyRecordMAC
//     3. HD-master seed             wallet.cpp  DecryptHDMasterKey    -> VerifyRecordMAC
//     4. mnemonic                   wallet.cpp  DecryptMnemonic       -> VerifyRecordMAC
//     5. MIK private key            wallet.cpp  DecryptMIKPrivKey     -> VerifyRecordMAC
//     6. master key (passphrase rotation)  wallet.cpp  ChangePassphrase
//                                                                     -> VerifyRecordMAC
//        (this was the MEDIUM-1 bypass: it open-coded crypter.VerifyMAC with default
//         v7 keying and bricked passphrase change on loaded legacy v3-v6 wallets;
//         now routed.)
//
//   COMPUTE (write / re-MAC) — all route through ComputeRecordMAC:
//     a. master key (EncryptWallet)          -> ComputeRecordMAC (separated v7 keying)
//     b. per-address key (EncryptWallet)     -> ComputeRecordMAC (separated v7 keying)
//     c. master key re-MAC (Unlock migration)-> ComputeRecordMAC (separated v7 keying)
//     d. per-address re-MAC (migration Step 2c) -> ComputeRecordMAC (separated v7 keying)
//     e. master key (ChangePassphrase write) -> ComputeRecordMAC with VERSION-MATCHED
//        keying: legacy AES-keyed HMAC when the loaded file is v3-v6 (the file STAYS
//        at its version — LP-7 ratified design: ChangePassphrase rotates the
//        passphrase in place and never promotes to v7), separated v7 keying when the
//        loaded file is already v7. The whole `ReMACAllRecordsToV7Unlocked`
//        re-MAC-everything surface that the round-1..4 recurrence lived in is DELETED:
//        ChangePassphrase touches ONLY the master-key record now; v3-v6 non-master
//        records keep their legacy MACs and stay valid because the file stays v6, and
//        the v6->v7 migration (with full re-MAC) happens exactly once, on the next
//        Unlock (MigrateToEncryptedSeedV7Unlocked — the single source of truth).
//     f. HD-master seed (EncryptHDMasterKey) -> ComputeRecordMAC (separated v7 keying)
//     g. mnemonic (EncryptMnemonic, encrypted branch) -> ComputeRecordMAC (separated v7 keying)
//     h. MIK private key (EncryptMIKPrivKey) -> ComputeRecordMAC (separated v7 keying)
//
//   The ONLY direct crypter.VerifyMAC / crypter.ComputeMAC calls remaining are the two
//   inside VerifyRecordMAC / ComputeRecordMAC themselves (the implementations).
//
//   LEGITIMATELY NOT routed (different mechanism, by design):
//     - The whole-file integrity HMAC (wallet.cpp Load/SaveUnlocked, HMAC_SHA3_256 over
//       [salt||data], keyed off the master-key salt). This is a file-level integrity
//       seal, NOT a per-record authenticated-decrypt MAC — it has no version-keyed
//       legacy/separated split and must not flow through the per-record helper.
//     - Obfuscation-keyed crypter.Decrypt paths on UNencrypted wallets (mnemonic/MIK
//       else-branches): by-design-unauthenticated obfuscation, no MAC is written or
//       checked (the write side clears the MAC), so there is nothing to route.
//
//   INVARIANT: there are ZERO at-rest record MAC verify/compute sites that bypass the
//   central helper. If you add a new at-rest encrypted record, its MAC verify/compute
//   MUST go through VerifyRecordMAC/ComputeRecordMAC — extend this census.
// =====================================================================================
bool CWallet::VerifyRecordMAC(CCrypter& crypter,
                             const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& mac) const {
    const bool isV7 = (m_loadedFileVersion >= WALLET_FILE_VERSION_7);

    if (mac.empty()) {
        // v7: an empty MAC is a corrupt/stripped record — refuse to decrypt the
        // secret unauthenticated. pre-v7: this is the genuine legacy record that
        // never carried a MAC — allow the (unauthenticated) legacy decrypt so the
        // wallet loads and can be migrated to v7.
        return !isV7;
    }

    // MAC present — verify it BEFORE the caller decrypts, with the keying that
    // matches the on-disk version: legacy AES-keyed HMAC for v3-v6, separated
    // MAC key for v7. (m_loadedFileVersion == 0 means a freshly-created in-memory
    // wallet whose records this build wrote with the default separated keying.)
    const bool legacyKeying = LegacyRecordKeying();
    return crypter.VerifyMAC(ciphertext, mac, legacyKeying);
}

// LP-7 (HIGH-2): the ONE MAC-compute helper for writes / re-MAC. Default = v7
// separated keying (new + migrated records). `useLegacyKeying == true` emits the
// pre-v7 AES-keyed HMAC, used ONLY when a record is persisted back into a file that
// stays at its existing v3-v6 version (LP-7 ratified ChangePassphrase-in-place).
bool CWallet::ComputeRecordMAC(CCrypter& crypter,
                              const std::vector<uint8_t>& ciphertext,
                              std::vector<uint8_t>& macOut,
                              bool useLegacyKeying) const {
    return crypter.ComputeMAC(ciphertext, macOut, useLegacyKeying);
}

// Public GetKey - acquires lock
bool CWallet::GetKey(const CDilithiumAddress& address, CKey& keyOut) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetKeyUnlocked(address, keyOut);
}

// Private GetKeyUnlocked - assumes caller holds lock
bool CWallet::GetKeyUnlocked(const CDilithiumAddress& address, CKey& keyOut) const {
    // First check unencrypted keys
    auto it = mapKeys.find(address);
    if (it != mapKeys.end()) {
        keyOut = it->second;
        return true;
    }

    // Then check encrypted keys
    auto itCrypted = mapCryptedKeys.find(address);
    if (itCrypted == mapCryptedKeys.end()) {
        return false;  // Key not found
    }

    // Wallet is encrypted - check if unlocked
    if (!fWalletUnlocked) {
        return false;  // Wallet is locked, cannot decrypt
    }

    const CEncryptedKey& encKey = itCrypted->second;

    // Decrypt private key
    CCrypter crypter;
    std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                      vMasterKey.data_ptr() + vMasterKey.size());
    if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;
    }

    // LP-7 (HIGH-2): authenticate-before-decrypt via the ONE centralized gate.
    // This is the per-address spending-key consumer that round-2 found left on
    // the default (separated) keying while the other four paths were version-
    // keyed — making legacy v3-v6 per-address keys (which carry a non-empty
    // legacy-AES-keyed MAC) fail verification and become unspendable. Routing
    // through VerifyRecordMAC fixes the keying selection AND the empty-MAC policy
    // in one place so this can never drift from the other four record types.
    if (!VerifyRecordMAC(crypter, encKey.vchCryptedKey, encKey.vchMAC)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;  // empty MAC on v7, or MAC verification failed — refuse
    }

    std::vector<uint8_t> decryptedPrivKey;
    if (!crypter.Decrypt(encKey.vchCryptedKey, decryptedPrivKey)) {
        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        return false;
    }

    // Construct decrypted key
    keyOut.vchPubKey = encKey.vchPubKey;
    // FIX-009: Use assign() to copy from regular vector to SecureAllocator vector
    keyOut.vchPrivKey.assign(decryptedPrivKey.begin(), decryptedPrivKey.end());

    // Wipe sensitive data
    memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
    memory_cleanse(decryptedPrivKey.data(), decryptedPrivKey.size());

    return true;
}

bool CWallet::ImportKey(const CKey& key, const CDilithiumAddress& address) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check key not already in wallet
    if (mapKeys.count(address) || mapCryptedKeys.count(address)) {
        return false;  // Already exists
    }

    // Validate key
    if (!key.IsValid()) {
        return false;
    }

    if (!mapCryptedKeys.empty()) {
        // Wallet is encrypted — encrypt the key before storing
        if (!fWalletUnlocked) {
            return false;  // Must unlock wallet first
        }

        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;

        // Generate unique IV (same pattern as key generation)
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            return false;
        }

        // Encrypt private key with master key
        CCrypter crypter;
        std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                          vMasterKey.data_ptr() + vMasterKey.size());
        if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        // LP-7: a per-address at-rest key MUST carry a v7 MAC, or Load() (which
        // rejects any v7 record with an empty vchMAC) refuses the WHOLE wallet on
        // the next start — silent funds-access loss. Mirror EncryptWallet's per-
        // address MAC compute; GetKeyUnlocked already verifies it symmetrically.
        // The MAC keying MUST match the verify side (VerifyRecordMAC in
        // GetKeyUnlocked): a loaded v3-v6 wallet uses legacy AES-keyed HMAC, and a
        // non-HD v6 wallet never migrates — so a v7-keyed MAC written here would
        // make the freshly-minted key UNSPENDABLE on the next load. Select keying
        // by the loaded file version, exactly as EncryptWallet/ChangePassphrase do.
        const bool legacyKeying = LegacyRecordKeying();
        if (!ComputeRecordMAC(crypter, encKey.vchCryptedKey, encKey.vchMAC, legacyKeying)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            return false;
        }

        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        mapCryptedKeys[address] = encKey;
    } else {
        // Wallet not encrypted — store key directly
        mapKeys[address] = key;
    }

    // Add to address list
    vchAddresses.push_back(address);

    // Save wallet to disk
    if (!SaveUnlocked(m_walletFile)) {
        return false;
    }

    return true;
}

bool CWallet::SignHash(const CDilithiumAddress& address, const uint256& hash,
                       std::vector<uint8_t>& signature) {
    CKey key;
    if (!GetKey(address, key)) {
        return false;
    }

    return WalletCrypto::Sign(key, hash.begin(), 32, signature);
}

// FIX-006 (WALLET-002): Internal helper that assumes lock is already held
// Used by ScanUTXOs to avoid deadlock
bool CWallet::AddTxOutUnlocked(const uint256& txid, uint32_t vout, int64_t nValue,
                                const CDilithiumAddress& address, uint32_t nHeight,
                                bool fCoinbase) {
    // REQUIRES: cs_wallet must be held by caller

    CWalletTx wtx;
    wtx.txid = txid;
    wtx.vout = vout;
    wtx.nValue = nValue;
    wtx.address = address;
    wtx.fSpent = false;
    wtx.fCoinbase = fCoinbase;
    wtx.nHeight = nHeight;

    // FIX-005 (WALLET-001): Use COutPoint as key to prevent collision
    // Old bug: mapWalletTx[txid] overwrites when same tx has multiple outputs
    COutPoint outpoint(txid, vout);
    mapWalletTx[outpoint] = wtx;
    return true;
}

bool CWallet::AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue,
                       const CDilithiumAddress& address, uint32_t nHeight,
                       bool fCoinbase) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return AddTxOutUnlocked(txid, vout, nValue, address, nHeight, fCoinbase);
}

bool CWallet::MarkSpent(const uint256& txid, uint32_t vout) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // FIX-005 (WALLET-001): Use COutPoint to find exact output
    COutPoint outpoint(txid, vout);
    auto it = mapWalletTx.find(outpoint);
    if (it == mapWalletTx.end()) {
        return false;
    }

    // No need to check vout - COutPoint key already identifies exact output

    it->second.fSpent = true;
    return true;
}

int64_t CWallet::GetBalance() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    int64_t balance = 0;
    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;
        if (!wtx.fSpent) {
            // VULN-001 FIX: Protect against integer overflow
            if (balance > std::numeric_limits<int64_t>::max() - wtx.nValue) {
                // Overflow would occur - this indicates corrupted wallet or attack
                std::cerr << "[Wallet] ERROR: Balance overflow detected - wallet may be corrupted" << std::endl;
                return std::numeric_limits<int64_t>::max();  // Return max value instead of wrapping
            }
            balance += wtx.nValue;
        }
    }

    return balance;
}

std::vector<CWalletTx> CWallet::GetUnspentTxOuts() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CWalletTx> vUnspent;
    for (const auto& pair : mapWalletTx) {
        if (!pair.second.fSpent) {
            vUnspent.push_back(pair.second);
        }
    }

    return vUnspent;
}

// ============================================================================
// WALLET-008 FIX: Stale UTXO Cleanup
// ============================================================================

// CID 1675287 FIX: Public method acquires lock and calls unlocked version
// WARNING: Do NOT call this method from contexts that already hold cs_wallet lock
// (e.g., blockConnected/blockDisconnected). Use CleanupStaleUTXOsUnlocked() instead.
// This method unconditionally acquires cs_wallet, which would cause deadlock if
// called from a context that already holds the lock.
size_t CWallet::CleanupStaleUTXOs(CUTXOSet& utxo_set) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return CleanupStaleUTXOsUnlocked(utxo_set);
}

// CID 1675287 FIX: Unlocked version - assumes caller already holds cs_wallet lock
// This allows safe calling from blockConnected/blockDisconnected which already hold the lock
size_t CWallet::CleanupStaleUTXOsUnlocked(CUTXOSet& utxo_set) {
    // Note: Caller must hold cs_wallet lock

    size_t removed_count = 0;
    std::vector<COutPoint> to_mark_spent;

    // Iterate through all wallet transactions to find stale UTXOs
    for (auto& pair : mapWalletTx) {
        CWalletTx& wtx = pair.second;

        // Skip already spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Check if this UTXO still exists in the current blockchain UTXO set
        COutPoint outpoint(wtx.txid, wtx.vout);

        // Query the UTXO set to see if this output still exists
        // If the UTXO doesn't exist in the set, it's stale (invalidated by reorg)
        if (!utxo_set.HaveUTXO(outpoint)) {
            // UTXO no longer exists in blockchain - mark for removal
            to_mark_spent.push_back(outpoint);
            removed_count++;

            std::cout << "[WALLET] Detected stale UTXO at index " << outpoint.n
                      << " (amount: " << wtx.nValue << " ions)"
                      << std::endl;
        }
    }

    // Mark stale UTXOs as spent
    // Note: We don't delete them from mapWalletTx to preserve transaction history,
    // just mark them as spent so they won't be selected for new transactions
    for (const COutPoint& outpoint : to_mark_spent) {
        auto it = mapWalletTx.find(outpoint);
        if (it != mapWalletTx.end()) {
            it->second.fSpent = true;
        }
    }

    if (removed_count > 0) {
        std::cout << "[WALLET] Cleaned up " << removed_count << " stale UTXO(s)" << std::endl;

        // Mark wallet as needing save
        // CID 1675287 FIX: Use SaveUnlocked since we already hold cs_wallet
        if (m_autoSave && !m_walletFile.empty()) {
            SaveUnlocked(m_walletFile);
        }
    }

    return removed_count;
}

size_t CWallet::ClearAllTransactions() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    size_t count = mapWalletTx.size();

    size_t sentCount = mapSentTx.size();

    if (count > 0 || sentCount > 0) {
        std::cout << "[WALLET] Clearing " << count << " received + " << sentCount << " sent transaction(s) from wallet history..." << std::endl;
        mapWalletTx.clear();
        mapSentTx.clear();

        // Reset best block pointer to genesis
        m_bestBlockHeight = 0;
        m_bestBlockHash = uint256();

        // Save the cleared wallet
        if (m_autoSave && !m_walletFile.empty()) {
            SaveUnlocked(m_walletFile);
        }

        std::cout << "[WALLET] Cleared all transaction history. Wallet ready for rescan." << std::endl;
    } else {
        std::cout << "[WALLET] No transactions to clear." << std::endl;
    }

    return count + sentCount;
}

// ============================================================================
// BUG #56 FIX: Chain Notifications Implementation (Bitcoin Core Pattern)
// ============================================================================

void CWallet::blockConnected(const CBlock& block, int height, const uint256& hash) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Process all transactions in the block
    ProcessBlockTransactionsUnlocked(block, height, true /* connecting */, hash);

    // v4.0.17: any queued mining-reward notification whose block was buried
    // by this connect (i.e. its height < current height) is now considered
    // settled — print and drop it.
    FlushSettledMiningNotificationsUnlocked(height);

    // Update best block pointer and persist to disk
    // IBD OPTIMIZATION: Use passed hash instead of computing RandomX hash
    SetLastBlockProcessedUnlocked(hash, height);

    // Periodic persistence (Bitcoin Core: every 144 blocks = ~1 day)
    // This ensures progress is saved even if no wallet transactions found
    static const int WRITE_INTERVAL = 144;
    if (height % WRITE_INTERVAL == 0 && m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }
}

void CWallet::blockDisconnected(const CBlock& block, int height, const uint256& hash) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // v4.0.17: silently drop any pending mining-reward notifications for
    // this block — it lost the round and the reward never settled.
    DropPendingMiningNotificationsForBlockUnlocked(hash);

    // Process transactions in REVERSE to undo the effects
    ProcessBlockTransactionsUnlocked(block, height, false /* disconnecting */, hash);

    // Update best block pointer to previous block
    // Note: We use hashPrevBlock from the disconnected block
    SetLastBlockProcessedUnlocked(block.hashPrevBlock, height - 1);
}

void CWallet::ProcessBlockTransactionsUnlocked(const CBlock& block, int height, bool connecting, const uint256& blockHash) {
    // Note: Caller must hold cs_wallet lock

    // Build set of wallet pubkey hashes for fast lookup
    std::set<std::vector<uint8_t>> walletPubKeyHashes;
    for (const auto& addr : vchAddresses) {
        std::vector<uint8_t> pkh = GetPubKeyHashFromAddress(addr);
        if (!pkh.empty()) {
            walletPubKeyHashes.insert(pkh);
        }
    }

    if (walletPubKeyHashes.empty()) {
        // No addresses in wallet, nothing to process
        return;
    }

    // BUG #112 FIX: Correctly parse transactions from block.vtx
    // block.vtx format is: [count][tx1][tx2]... (count is compact size)
    // Use CBlockValidator::DeserializeBlockTransactions which handles this correctly
    CBlockValidator validator;
    std::vector<CTransactionRef> transactions;
    std::string deserializeError;

    if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
        // Failed to parse transactions - log error and return
        std::cerr << "[WALLET] ERROR: Failed to deserialize block transactions: " << deserializeError << std::endl;
        return;
    }

    for (const CTransactionRef& txRef : transactions) {
        const CTransaction& tx = *txRef;

        if (connecting) {
            // Block connected: add outputs, mark inputs spent

            // Check outputs - add any that belong to wallet
            for (uint32_t i = 0; i < tx.vout.size(); ++i) {
                const CTxOut& out = tx.vout[i];
                std::vector<uint8_t> scriptPKH = WalletCrypto::ExtractPubKeyHash(out.scriptPubKey);

                if (!scriptPKH.empty() && walletPubKeyHashes.count(scriptPKH) > 0) {
                    // This output belongs to our wallet
                    // Find the corresponding address
                    for (const auto& addr : vchAddresses) {
                        std::vector<uint8_t> addrPKH = GetPubKeyHashFromAddress(addr);
                        if (addrPKH == scriptPKH) {
                            AddTxOutUnlocked(tx.GetHash(), i, out.nValue, addr, height, tx.IsCoinBase());

                            // Notify user when mining reward is credited
                            if (tx.IsCoinBase()) {
                                // Calculate new balance — use UTXO-validated sum to
                                // exclude stale entries from other chains (e.g. DIL
                                // transactions cached in wallet.dat on a DilV node).
                                int64_t newBalance = 0;
                                if (m_utxo_set_ref) {
                                    // UTXO-validated: only counts outputs present in this chain
                                    for (const auto& pair : mapWalletTx) {
                                        if (pair.second.fSpent) continue;
                                        COutPoint op(pair.second.txid, pair.second.vout);
                                        CUTXOEntry ent;
                                        if (m_utxo_set_ref->GetUTXO(op, ent)) {
                                            newBalance += pair.second.nValue;
                                        }
                                    }
                                } else {
                                    // Fallback (no UTXO ref set): raw sum — may include stale entries
                                    for (const auto& pair : mapWalletTx) {
                                        if (!pair.second.fSpent) {
                                            newBalance += pair.second.nValue;
                                        }
                                    }
                                }

                                // v4.0.17: don't print MINING REWARD CREDITED inline.
                                // On DilV, lowest-VDF-output tiebreaks displace this
                                // block within ~2s in 30-50% of rounds. Queue the
                                // notification; it will print from
                                // FlushSettledMiningNotificationsUnlocked() once a
                                // higher block is connected on top, or be silently
                                // dropped from DropPendingMiningNotificationsForBlockUnlocked()
                                // if this block loses the round.
                                m_pendingMiningNotifications.push_back({
                                    blockHash,
                                    height,
                                    static_cast<int64_t>(out.nValue),
                                    newBalance,
                                    addr.ToString()
                                });

                                // BUG #99 FIX: Immediately save wallet after mining reward
                                // This ensures check-wallet-balance can see the new balance
                                if (m_autoSave && !m_walletFile.empty()) {
                                    SaveUnlocked();
                                }
                            }
                            break;
                        }
                    }
                }
            }

            // Check inputs - mark any wallet UTXOs as spent
            if (!tx.IsCoinBase()) {  // Coinbase has no real inputs
                for (const auto& in : tx.vin) {
                    COutPoint outpoint(in.prevout.hash, in.prevout.n);
                    auto it = mapWalletTx.find(outpoint);
                    if (it != mapWalletTx.end() && !it->second.fSpent) {
                        it->second.fSpent = true;
                    }
                }
            }

            // BUG #112 FIX: Update sent transaction confirmation height
            // If this TX was sent by us (in mapSentTx), update its height
            UpdateSentTransactionHeightUnlocked(tx.GetHash(), height);
        } else {
            // Block disconnected: remove outputs, restore inputs

            // Restore spent inputs (mark as unspent)
            if (!tx.IsCoinBase()) {
                for (const auto& in : tx.vin) {
                    COutPoint outpoint(in.prevout.hash, in.prevout.n);
                    auto it = mapWalletTx.find(outpoint);
                    if (it != mapWalletTx.end() && it->second.fSpent) {
                        // Only unspend if this was the transaction that spent it
                        // Note: For full correctness we'd need to track which tx spent it
                        // For now, we mark as unspent and let CleanupStaleUTXOs fix any issues
                        it->second.fSpent = false;
                    }
                }
            }

            // Remove outputs that were added by this block
            for (uint32_t i = 0; i < tx.vout.size(); ++i) {
                COutPoint outpoint(tx.GetHash(), i);
                auto it = mapWalletTx.find(outpoint);
                if (it != mapWalletTx.end() && it->second.nHeight == static_cast<uint32_t>(height)) {
                    // This output was added at this height, remove it
                    mapWalletTx.erase(it);
                }
            }

            // BUG #112 FIX: Reset sent transaction height on disconnect
            // If this TX was sent by us and is being disconnected, mark as unconfirmed
            UpdateSentTransactionHeightUnlocked(tx.GetHash(), 0);
        }
    }
}

void CWallet::FlushSettledMiningNotificationsUnlocked(int currentHeight) {
    // Print and remove any pending notifications whose block has now been
    // buried by ≥ 1 further block (the round is settled). Same-height
    // tip-swap reorgs at the original height never reach here because the
    // disconnect path in blockDisconnected() drops them first.
    auto it = m_pendingMiningNotifications.begin();
    while (it != m_pendingMiningNotifications.end()) {
        if (it->blockHeight < currentHeight) {
            double rewardCoins  = static_cast<double>(it->reward) / 100000000.0;
            double balanceCoins = static_cast<double>(it->balanceSnapshot) / 100000000.0;

            char rewardStr[64], balanceStr[64];
            snprintf(rewardStr,  sizeof(rewardStr),  "%.8f", rewardCoins);
            snprintf(balanceStr, sizeof(balanceStr), "%.8f", balanceCoins);

            const char* coinLabel =
                (Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV()) ? "DilV" : "DIL";

            std::cout << "\n"
                << "============================================================\n"
                << "  MINING REWARD CREDITED!\n"
                << "============================================================\n"
                << "  Block Height:    " << it->blockHeight << "\n"
                << "  Reward:          +" << rewardStr << " " << coinLabel << "\n"
                << "  New Balance:     " << balanceStr << " " << coinLabel << "\n"
                << "  Address:         " << it->addressStr << "\n"
                << "============================================================"
                << std::endl;

            it = m_pendingMiningNotifications.erase(it);
        } else {
            ++it;
        }
    }
}

void CWallet::DropPendingMiningNotificationsForBlockUnlocked(const uint256& blockHash) {
    m_pendingMiningNotifications.erase(
        std::remove_if(m_pendingMiningNotifications.begin(),
                       m_pendingMiningNotifications.end(),
                       [&blockHash](const PendingMiningNotification& n) {
                           return n.blockHash == blockHash;
                       }),
        m_pendingMiningNotifications.end()
    );
}

void CWallet::SetLastBlockProcessedUnlocked(const uint256& hash, int height) {
    // Note: Caller must hold cs_wallet lock

    m_bestBlockHash = hash;
    m_bestBlockHeight = height;

    // Auto-save to persist the best block pointer
    // This is critical for crash recovery - ensures we resume from correct block
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }
}

uint256 CWallet::GetBestBlockHash() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return m_bestBlockHash;
}

int32_t CWallet::GetBestBlockHeight() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return m_bestBlockHeight;
}

bool CWallet::RescanFromHeight(CChainState& chainstate, CBlockchainDB& blockchain,
                               int startHeight, int endHeight) {
    std::cout << "[WALLET] Rescanning blocks " << startHeight << " to " << endHeight << "..." << std::endl;

    int blocksProcessed = 0;
    int txsFound = 0;

    for (int height = startHeight; height <= endHeight; ++height) {
        // Get block hashes at this height (typically just one on main chain)
        std::vector<uint256> blockHashes = chainstate.GetBlocksAtHeight(height);
        if (blockHashes.empty()) {
            std::cerr << "[WALLET] Failed to get block hash at height " << height << std::endl;
            return false;
        }

        // Use the first hash (main chain block)
        uint256 blockHash = blockHashes[0];

        // Load the block
        CBlock block;
        if (!blockchain.ReadBlock(blockHash, block)) {
            std::cerr << "[WALLET] Failed to load block at height " << height << std::endl;
            return false;
        }

        // Process the block (this acquires and releases cs_wallet)
        {
            std::lock_guard<std::mutex> lock(cs_wallet);

            size_t txsBefore = mapWalletTx.size();
            ProcessBlockTransactionsUnlocked(block, height, true, blockHash);
            // v4.0.17: rescan path is replaying historical blocks; never
            // print mining reward popups for them. Drop anything queued.
            DropPendingMiningNotificationsForBlockUnlocked(blockHash);
            size_t txsAfter = mapWalletTx.size();

            if (txsAfter > txsBefore) {
                txsFound += (txsAfter - txsBefore);
            }

            // Update best block pointer (persists to disk)
            SetLastBlockProcessedUnlocked(blockHash, height);
        }

        blocksProcessed++;

        // Progress report every 100 blocks
        if (blocksProcessed % 100 == 0) {
            std::cout << "[WALLET] Processed " << blocksProcessed << " blocks, "
                      << txsFound << " wallet outputs found..." << std::endl;
        }
    }

    std::cout << "[WALLET] Rescan complete: " << blocksProcessed << " blocks, "
              << txsFound << " wallet outputs found" << std::endl;

    return true;
}

// ============================================================================

size_t CWallet::GetKeyPoolSize() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Return total number of keys (encrypted + unencrypted)
    return mapKeys.size() + mapCryptedKeys.size();
}

// CID 1675320 FIX: Thread-safe accessor - acquires lock before reading fIsHDWallet
bool CWallet::IsHDWallet() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return fIsHDWallet;
}

// ============================================================================
// Wallet Encryption Implementation
// ============================================================================

bool CWallet::IsCrypted() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return IsCryptedUnlocked();
}

// Private helper - assumes caller holds cs_wallet lock
bool CWallet::IsCryptedUnlocked() const {
    // Wallet is encrypted if master key has been set up
    return masterKey.IsValid();
}

bool CWallet::IsLocked() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Don't call IsCrypted() here to avoid deadlock (it also acquires mutex)
    return masterKey.IsValid() && !fWalletUnlocked;
}

bool CWallet::NeedsSeedMigration() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // m_fNeedsSeedMigration is armed at load (CWallet::Load) only when the wallet
    // is encrypted (masterKey valid) AND the on-disk format held the HD seed in
    // plaintext (pre-fix bug shape); it is cleared the moment the v7 migration
    // completes inside Unlock. We additionally require masterKey.IsValid() so a
    // non-encrypted wallet can never report this state.
    return masterKey.IsValid() && m_fNeedsSeedMigration;
}

bool CWallet::MigrationDeferredForPassphrase() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    // Only meaningful while a migration is still pending on an encrypted wallet.
    return masterKey.IsValid() && m_fNeedsSeedMigration && m_migrationDeferredPassphrase;
}

// VULN-002 FIX: Helper to check if unlock is still valid (not expired)
// Assumes caller holds cs_wallet lock
// BUG #74 FIX: Internal version that assumes caller already holds cs_wallet
// This avoids deadlock when called from within SignTransaction which already holds the lock
bool CWallet::_IsUnlockValidNoLock() const {
    // If wallet is not encrypted, it doesn't need to be unlocked
    if (!masterKey.IsValid()) {
        return true;  // Unencrypted wallet is always "unlocked"
    }

    // Wallet is encrypted - check if unlocked
    if (!fWalletUnlocked) {
        return false;  // Wallet is locked
    }

    // If no timeout set, unlock is always valid
    if (nUnlockTime == std::chrono::steady_clock::time_point::max()) {
        return true;
    }

    // Check if timeout has expired
    return std::chrono::steady_clock::now() < nUnlockTime;
}

bool CWallet::IsUnlockValid() const {
    // WL-005 FIX: Add mutex protection to prevent race condition
    // Without this lock, concurrent calls to CheckUnlockTimeout() or Lock()
    // could modify fWalletUnlocked/nUnlockTime while we're reading them,
    // leading to inconsistent state and potential security issues
    std::lock_guard<std::mutex> lock(cs_wallet);
    return _IsUnlockValidNoLock();
}

void CWallet::CheckUnlockTimeout() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fWalletUnlocked) {
        return;  // Already locked
    }

    if (nUnlockTime == std::chrono::steady_clock::time_point::max()) {
        return;  // No timeout (unlocked forever)
    }

    if (std::chrono::steady_clock::now() >= nUnlockTime) {
        // Timeout expired, lock wallet
        fWalletUnlocked = false;
        // Clear master key from memory
        if (!vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
        }
        // WL-010 FIX: Clear cached decrypted HD master key
        if (fHDMasterKeyCached) {
            memory_cleanse(hdMasterKeyDecrypted.seed, 32);
            memory_cleanse(hdMasterKeyDecrypted.chaincode, 32);
            fHDMasterKeyCached = false;
        }
    }
}

// ============================================================================
// FIX-010 (CRYPT-002): IV Reuse Detection
// ============================================================================

// Internal helper: Generate unique IV (assumes caller holds cs_wallet lock)
template<typename Alloc>
bool CWallet::GenerateUniqueIV_Locked(std::vector<uint8_t, Alloc>& iv) {
    // Try up to 10 times to generate a unique IV
    // If we hit a collision after 10 attempts, the RNG is broken
    for (int attempts = 0; attempts < 10; attempts++) {
        // Generate random IV
        if (!GenerateIV(iv)) {
            return false;  // RNG failure
        }

        // Convert to std::vector for set lookup
        std::vector<uint8_t> iv_std(iv.begin(), iv.end());

        // Check if this IV has been used before
        if (usedIVs.find(iv_std) == usedIVs.end()) {
            // Unique IV found, register it
            usedIVs.insert(iv_std);
            return true;
        }

        // Collision detected, retry
        // Note: With a good RNG, probability of collision is ~2^-128 for 16-byte IVs
        // If we see collisions here, it indicates RNG failure
    }

    // Failed to generate unique IV after 10 attempts
    // This should NEVER happen with a properly functioning RNG
    return false;
}

bool CWallet::GenerateUniqueIV(std::vector<uint8_t, SecureAllocator<uint8_t>>& iv) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GenerateUniqueIV_Locked(iv);
}

void CWallet::RegisterIV(const std::vector<uint8_t>& iv) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Only register if IV is correct size (16 bytes for AES)
    if (iv.size() == WALLET_CRYPTO_IV_SIZE) {
        usedIVs.insert(iv);
    }
}

bool CWallet::IsIVUsed(const std::vector<uint8_t>& iv) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return usedIVs.find(iv) != usedIVs.end();
}

size_t CWallet::GetIVCount() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return usedIVs.size();
}

// CID 1675307 FIX: Public method acquires lock and calls unlocked version
// This prevents double-lock deadlock if called from context that already holds cs_wallet
bool CWallet::Lock() {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return LockUnlocked();
}

// CID 1675307 FIX: Unlocked version - assumes caller already holds cs_wallet lock
// This allows safe calling from recovery functions which already hold the lock
bool CWallet::LockUnlocked() {
    // Note: Caller must hold cs_wallet lock

    if (!masterKey.IsValid()) {
        return false;  // Can't lock unencrypted wallet
    }

    fWalletUnlocked = false;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // Clear master key from memory
    if (!vMasterKey.empty()) {
        memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
    }

    // WL-010 FIX: Clear cached decrypted HD master key
    if (fHDMasterKeyCached) {
        memory_cleanse(hdMasterKeyDecrypted.seed, 32);
        memory_cleanse(hdMasterKeyDecrypted.chaincode, 32);
        fHDMasterKeyCached = false;
    }

    return true;
}

bool CWallet::Unlock(const std::string& passphrase, int64_t timeout,
                     const std::string& bip39Passphrase) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }

    if (passphrase.empty()) {
        return false;
    }

    // WL-011 FIX: Rate limiting with exponential backoff
    // Delay = 2^(attempts-1) seconds, capped at 1 hour
    // Attempts:  1→0s, 2→1s, 3→2s, 4→4s, 5→8s, 10→512s, 15+→3600s
    if (nUnlockFailedAttempts > 0) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - nLastFailedUnlock).count();

        // Calculate required delay: 2^(attempts-1) seconds, max 3600s (1 hour)
        int64_t required_delay = 1LL << (nUnlockFailedAttempts - 1);
        if (required_delay > 3600) required_delay = 3600;

        if (elapsed < required_delay) {
            std::cerr << "[Wallet] Rate limit: " << (required_delay - elapsed)
                     << " seconds remaining (attempt " << (nUnlockFailedAttempts + 1)
                     << ")" << std::endl;
            return false;
        }
    }

    // Derive key from passphrase
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, masterKey.vchSalt, masterKey.nDeriveIterations, derivedKey)) {
        return false;
    }

    // Decrypt master key
    CCrypter crypter;
    if (!crypter.SetKey(derivedKey, masterKey.vchIV)) {
        return false;
    }

    // LP-7 (HIGH-2): authenticate-before-decrypt via the ONE centralized gate.
    // Master-key consumer. The gate handles both the v7-empty-MAC rejection and
    // the version-keyed verify; on any failure we still record a failed-unlock
    // attempt (WL-011) since a tampered/empty MAC is indistinguishable from a
    // wrong passphrase from the user's perspective.
    if (!VerifyRecordMAC(crypter, masterKey.vchCryptedKey, masterKey.vchMAC)) {
        nUnlockFailedAttempts++;
        nLastFailedUnlock = std::chrono::steady_clock::now();
        return false;  // empty MAC on v7, or MAC verification failed
    }

    std::vector<uint8_t> decryptedKey;
    if (!crypter.Decrypt(masterKey.vchCryptedKey, decryptedKey)) {
        // WL-011 FIX: Track failed unlock attempt
        nUnlockFailedAttempts++;
        nLastFailedUnlock = std::chrono::steady_clock::now();
        return false;  // Wrong passphrase
    }

    if (decryptedKey.size() != WALLET_CRYPTO_KEY_SIZE) {
        return false;  // Invalid key size
    }

    // Store decrypted master key in memory
    memcpy(vMasterKey.data_ptr(), decryptedKey.data(), WALLET_CRYPTO_KEY_SIZE);

    fWalletUnlocked = true;

    // WL-011 FIX: Reset failed attempt counter on successful unlock
    nUnlockFailedAttempts = 0;

    // WL-010 FIX: Decrypt and cache HD master key for performance
    if (fIsHDWallet && fHDMasterKeyEncrypted) {
        // Decrypt HD master key into cache
        if (DecryptHDMasterKey(hdMasterKeyDecrypted)) {
            fHDMasterKeyCached = true;
        }
        // Note: If decryption fails, cache remains invalid (fHDMasterKeyCached = false)
        // This is acceptable - DecryptHDMasterKey will decrypt on-demand if cache invalid
    }

    // Set unlock timeout
    if (timeout > 0) {
        nUnlockTime = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    } else {
        nUnlockTime = std::chrono::steady_clock::time_point::max();  // No timeout
    }

    // Wipe derived key
    memory_cleanse(derivedKey.data(), derivedKey.size());
    memory_cleanse(decryptedKey.data(), decryptedKey.size());

    // LP-7 (wallet-Inv-5 migration): if this encrypted wallet was loaded from a
    // legacy plaintext-seed format, re-encrypt the seed+mnemonic now that we hold
    // the master key, and atomically rewrite the file at v7. The rewrite is
    // atomic + reversible-on-failure (SaveUnlocked: temp-write + fsync + rename;
    // the original is never truncated). A migration failure does NOT fail the
    // unlock — the wallet is fully usable in memory and migration retries on the
    // next unlock; the on-disk file is left byte-identical.
    if (m_fNeedsSeedMigration) {
        // The master-key MAC on a v3-v6 file was computed with the legacy
        // AES-keyed HMAC. Once we rewrite as v7, Unlock will verify it with the
        // separated-key HMAC, so recompute it here with the SAME crypter that just
        // decrypted the master key (keyed with the passphrase-derived key) using
        // the new (default) separated keying. Snapshot for rollback symmetry.
        std::vector<uint8_t> snap_masterMAC = masterKey.vchMAC;
        std::vector<uint8_t> newMasterMAC;
        bool macOk = ComputeRecordMAC(crypter, masterKey.vchCryptedKey, newMasterMAC);
        if (macOk) {
            masterKey.vchMAC = newMasterMAC;
        }

        // Cursor M1: clear the migration flag / promote to v7 ONLY when the migrated
        // v7 (no-plaintext) file actually reached disk (persistedToDisk == true).
        // MigrateToEncryptedSeedV7Unlocked returns false (no in-memory mutation) when
        // it cannot persist (autosave off / no file), so the flag STAYS armed and the
        // on-disk-plaintext state keeps surfacing. Invariant: NeedsSeedMigration() is
        // true exactly while a plaintext seed is still at rest on disk.
        bool migrationPersisted = false;
        if (macOk && MigrateToEncryptedSeedV7Unlocked(&migrationPersisted, bip39Passphrase) && migrationPersisted) {
            m_fNeedsSeedMigration = false;
            m_migrationDeferredPassphrase = false;  // F1 r3: verified + migrated
            m_loadedFileVersion = WALLET_FILE_VERSION_7;
            std::cout << "[Wallet] LP-7: migrated wallet to encrypted-seed v7 format" << std::endl;
        } else {
            // Restore the legacy master MAC so the in-memory state stays consistent
            // with the untouched on-disk legacy file. Reached when the MAC recompute
            // failed, the migration could not persist (autosave off → flag stays
            // armed, surfaced), or the identity check could not verify the mnemonic
            // (BIP39-passphrase wallet with no/wrong passphrase supplied — retry by
            // re-running unlock with the correct "bip39passphrase").
            masterKey.vchMAC = snap_masterMAC;
            // F1 r3: surface the passphrase-required state ONLY when migration was
            // genuinely ATTEMPTED (autosave on + wallet file present) and failed — i.e.
            // the identity check could not verify the mnemonic. We exclude the
            // autosave-off / no-file early-return (a node-config issue, NOT a
            // passphrase problem) so the UI does not falsely prompt for a BIP39
            // passphrase. NeedsSeedMigration() still surfaces the general migration-
            // pending state in those cases.
            if (macOk && fIsHDWallet && m_autoSave && !m_walletFile.empty()) {
                m_migrationDeferredPassphrase = true;
            }
            std::cerr << "[Wallet] LP-7: seed migration to v7 not persisted; "
                         "original wallet file left unchanged, will retry on next unlock" << std::endl;
        }
    }

    // Wipe the unlock crypter's key material is handled by CCrypter's destructor.
    return true;
}

bool CWallet::EncryptWallet(const std::string& passphrase,
                            const std::string& bip39Passphrase) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (masterKey.IsValid()) {
        return false;  // Already encrypted
    }

    if (passphrase.empty()) {
        return false;
    }

    // Validate passphrase strength
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(passphrase);

    if (!validation.is_valid) {
        std::cerr << "[Wallet] Passphrase validation failed: "
                  << validation.error_message << std::endl;
        return false;
    }

    // Log passphrase strength
    std::cout << "[Wallet] Passphrase strength: "
              << PassphraseValidator::GetStrengthDescription(validation.strength_score)
              << " (" << validation.strength_score << "/100)" << std::endl;

    // Display any warnings
    for (const auto& warning : validation.warnings) {
        std::cout << "[Wallet] Warning: " << warning << std::endl;
    }

    // Allow encrypting empty wallet - keys will be encrypted as they're generated

    // --- TRANSACTIONAL SNAPSHOT (Cursor HIGH-2) ---
    // EncryptWallet mutates the master key, the key maps, the in-memory unlocked
    // state, and (for HD wallets) the HD seed/mnemonic/MIK ciphertext fields, and
    // it scrubs the plaintext seed in EncryptHDMasterKey(). If any later step fails
    // (mnemonic recover/re-encrypt, EncryptHDMasterKey), the previous code returned
    // false WITHOUT undoing those mutations — leaving the wallet encrypted-in-memory
    // (masterKey valid) with fHDMasterKeyEncrypted==false and a plaintext seed. A new
    // HD wallet (m_loadedFileVersion==0 ⇒ v7 writer) in that state would persist a v7
    // file with encrypted spending keys + PLAINTEXT seed on the next autosave — the
    // LP-7 bug reintroduced, with no migration arm on reload.
    //
    // Snapshot the full pre-encryption state here (BEFORE any mutation) and RESTORE it
    // on every failure path so the wallet returns to its original UNENCRYPTED state.
    // Mirrors the snapshot/rollback structure of MigrateToEncryptedSeedV7Unlocked().
    CMasterKey snap_masterKey = masterKey;
    std::map<CDilithiumAddress, CKey> snap_mapKeys = mapKeys;
    std::map<CDilithiumAddress, CEncryptedKey> snap_mapCryptedKeys = mapCryptedKeys;
    bool snap_fWalletUnlocked = fWalletUnlocked;
    std::chrono::time_point<std::chrono::steady_clock> snap_nUnlockTime = nUnlockTime;
    bool snap_vMasterKey_set = !vMasterKey.empty();
    CHDExtendedKey snap_hdMasterKey = hdMasterKey;
    bool snap_fHDMasterKeyEncrypted = fHDMasterKeyEncrypted;
    bool snap_fHDMasterKeyCached = fHDMasterKeyCached;
    CHDExtendedKey snap_hdMasterKeyDecrypted = hdMasterKeyDecrypted;
    std::vector<uint8_t> snap_vchEncryptedMnemonic = vchEncryptedMnemonic;
    std::vector<uint8_t> snap_vchMnemonicMAC = vchMnemonicMAC;
    std::vector<uint8_t> snap_vchMnemonicIV(vchMnemonicIV.begin(), vchMnemonicIV.end());
    std::vector<uint8_t> snap_vchEncryptedHDMasterKey = vchEncryptedHDMasterKey;
    std::vector<uint8_t> snap_vchHDMasterKeyMAC = vchHDMasterKeyMAC;
    std::vector<uint8_t> snap_vchHDMasterKeyIV(vchHDMasterKeyIV.begin(), vchHDMasterKeyIV.end());
    bool snap_fHasMIK = fHasMIK;
    std::vector<uint8_t> snap_vchEncryptedMIKPrivKey = vchEncryptedMIKPrivKey;
    std::vector<uint8_t> snap_vchMIKPrivKeyMAC = vchMIKPrivKeyMAC;
    std::vector<uint8_t> snap_vchMIKPrivKeyIV(vchMIKPrivKeyIV.begin(), vchMIKPrivKeyIV.end());
    std::vector<uint8_t> snap_vchMIKPubKey = vchMIKPubKey;
    uint32_t snap_loadedFileVersion = m_loadedFileVersion;
    // LP-7 (red-team MEDIUM-1): snapshot the in-memory MIK plaintext private key.
    // EncryptMIKPrivKey() + m_mik->privkey.clear() below moves the MIK to a
    // ciphertext-only in-memory state. The rollback restores the MIK CIPHERTEXT
    // fields (vchEncryptedMIKPrivKey/...MAC/...IV) to their PRE-encryption snapshot
    // (i.e. empty, since the wallet was unencrypted) AND restores masterKey to
    // invalid — so without restoring the plaintext too, a save-failure rollback
    // would leave the MIK with neither a usable plaintext nor a decryptable
    // ciphertext (no master key to decrypt with), permanently losing the mining
    // identity. Snapshot the plaintext so rollback can restore it verbatim.
    bool snap_mikHadPriv = (m_mik && m_mik->HasPrivateKey());
    std::vector<uint8_t, SecureAllocator<uint8_t>> snap_mikPrivKey =
        snap_mikHadPriv ? m_mik->privkey
                        : std::vector<uint8_t, SecureAllocator<uint8_t>>();

    auto rollback = [&]() {
        masterKey = snap_masterKey;
        mapKeys = snap_mapKeys;
        mapCryptedKeys = snap_mapCryptedKeys;
        fWalletUnlocked = snap_fWalletUnlocked;
        nUnlockTime = snap_nUnlockTime;
        // The wallet was UNENCRYPTED before this call (guarded by masterKey.IsValid()
        // at the top), so vMasterKey must not retain a usable master key after a
        // failed encryption — scrub it. (snap_vMasterKey_set is false in the normal
        // pre-encryption case; this is belt-and-suspenders.)
        if (!snap_vMasterKey_set && !vMasterKey.empty()) {
            memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
        }
        hdMasterKey = snap_hdMasterKey;
        fHDMasterKeyEncrypted = snap_fHDMasterKeyEncrypted;
        fHDMasterKeyCached = snap_fHDMasterKeyCached;
        hdMasterKeyDecrypted = snap_hdMasterKeyDecrypted;
        vchEncryptedMnemonic = snap_vchEncryptedMnemonic;
        vchMnemonicMAC = snap_vchMnemonicMAC;
        vchMnemonicIV.assign(snap_vchMnemonicIV.begin(), snap_vchMnemonicIV.end());
        vchEncryptedHDMasterKey = snap_vchEncryptedHDMasterKey;
        vchHDMasterKeyMAC = snap_vchHDMasterKeyMAC;
        vchHDMasterKeyIV.assign(snap_vchHDMasterKeyIV.begin(), snap_vchHDMasterKeyIV.end());
        fHasMIK = snap_fHasMIK;
        vchEncryptedMIKPrivKey = snap_vchEncryptedMIKPrivKey;
        vchMIKPrivKeyMAC = snap_vchMIKPrivKeyMAC;
        vchMIKPrivKeyIV.assign(snap_vchMIKPrivKeyIV.begin(), snap_vchMIKPrivKeyIV.end());
        vchMIKPubKey = snap_vchMIKPubKey;
        m_loadedFileVersion = snap_loadedFileVersion;
        // LP-7 (red-team MEDIUM-1): restore the in-memory MIK plaintext private key
        // that EncryptMIKPrivKey()+clear() may have scrubbed. Without this the MIK
        // would be unrecoverable after a save-failure rollback (ciphertext snapshot
        // is the pre-encryption empty state and masterKey is restored to invalid).
        if (m_mik && snap_mikHadPriv) {
            m_mik->privkey = snap_mikPrivKey;
        }
    };

    // Generate random master key
    std::vector<uint8_t> vMasterKeyPlain(WALLET_CRYPTO_KEY_SIZE);
    if (!GetStrongRandBytes(vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE)) {
        return false;
    }

    // Generate salt for PBKDF2
    if (!GenerateSalt(masterKey.vchSalt)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        rollback();
        return false;
    }

    // Derive key from passphrase
    std::vector<uint8_t> derivedKey;
    if (!DeriveKey(passphrase, masterKey.vchSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKey)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        rollback();
        return false;
    }

    // FIX-010: Generate unique IV for master key encryption
    if (!GenerateUniqueIV_Locked(masterKey.vchIV)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        rollback();
        return false;
    }

    // Encrypt master key with passphrase-derived key
    CCrypter masterCrypter;
    if (!masterCrypter.SetKey(derivedKey, masterKey.vchIV)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        rollback();
        return false;
    }

    if (!masterCrypter.Encrypt(vMasterKeyPlain, masterKey.vchCryptedKey)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        rollback();
        return false;
    }

    // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption (master key).
    // LP-7 (round 3): route through ComputeRecordMAC — at-rest record, always v7.
    if (!ComputeRecordMAC(masterCrypter, masterKey.vchCryptedKey, masterKey.vchMAC)) {
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        memory_cleanse(derivedKey.data(), derivedKey.size());
        rollback();
        return false;
    }

    masterKey.nDerivationMethod = 0;  // PBKDF2-SHA3
    masterKey.nDeriveIterations = WALLET_CRYPTO_PBKDF2_ROUNDS;

    // Now encrypt all existing keys with the master key
    for (const auto& pair : mapKeys) {
        const CDilithiumAddress& address = pair.first;
        const CKey& key = pair.second;

        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;  // Public key stays unencrypted

        // FIX-010: Generate unique IV for this key
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            rollback();
            return false;
        }

        // Encrypt private key with master key
        CCrypter keyCrypter;
        if (!keyCrypter.SetKey(vMasterKeyPlain, encKey.vchIV)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            rollback();
            return false;
        }

        if (!keyCrypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            rollback();
            return false;
        }

        // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption (per-address key).
        // LP-7 (round 3): route through ComputeRecordMAC — at-rest record, always v7.
        if (!ComputeRecordMAC(keyCrypter, encKey.vchCryptedKey, encKey.vchMAC)) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            rollback();
            return false;
        }

        mapCryptedKeys[address] = encKey;
    }

    // Clear unencrypted keys
    mapKeys.clear();

    // Keep wallet unlocked after encryption
    memcpy(vMasterKey.data_ptr(), vMasterKeyPlain.data(), WALLET_CRYPTO_KEY_SIZE);
    fWalletUnlocked = true;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // LP-7 (wallet-Inv-5 + wallet-Inv-4): re-encrypt the HD seed + mnemonic under
    // the wallet master key. The previous code never did this, so encrypted HD
    // wallets shipped a PLAINTEXT seed at rest and ExportMnemonic broke (the
    // mnemonic stayed under the unencrypted-obfuscation key while DecryptMnemonic
    // switched to the master-key branch).
    //
    // ORDER MATTERS: decrypt the mnemonic FIRST (while the HD seed is still
    // plaintext, since the obfuscation key is derived from it), re-encrypt the
    // mnemonic under the master key, THEN encrypt the HD master key (which scrubs
    // the plaintext seed). Both are encrypted under, and later decrypted with, the
    // SAME master key — fixing the key mismatch.
    if (fIsHDWallet) {
        if (!vchEncryptedMnemonic.empty()) {
            // Recover the plaintext mnemonic using the current (pre-encryption,
            // obfuscation-key) representation. masterKey is now valid, so call the
            // obfuscation-key derivation explicitly rather than via DecryptMnemonic
            // (which would already take the master-key branch).
            std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
            std::vector<uint8_t> hdSeed(hdMasterKey.seed, hdMasterKey.seed + 32);
            DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
            memory_cleanse(hdSeed.data(), hdSeed.size());

            CCrypter obfCrypter;
            std::vector<uint8_t> ivVec(vchMnemonicIV.begin(), vchMnemonicIV.end());
            std::vector<uint8_t> mnemonicPlain;
            if (!obfCrypter.SetKey(obfKey, ivVec) ||
                !obfCrypter.Decrypt(vchEncryptedMnemonic, mnemonicPlain)) {
                memory_cleanse(obfKey.data(), obfKey.size());
                memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
                memory_cleanse(derivedKey.data(), derivedKey.size());
                std::cerr << "[Wallet] CRITICAL: failed to recover mnemonic for re-encryption" << std::endl;
                rollback();
                return false;
            }
            memory_cleanse(obfKey.data(), obfKey.size());

            std::string mnemonicStr(mnemonicPlain.begin(), mnemonicPlain.end());
            memory_cleanse(mnemonicPlain.data(), mnemonicPlain.size());

            // LP-7 (F1 fold, MED-2): this re-encrypt path has the SAME discard-original
            // shape as the v7 seed migration — recover under the obfuscation key, then
            // EncryptMnemonic overwrites vchEncryptedMnemonic/IV/MAC. If the recovered
            // plaintext were a valid-but-WRONG BIP39 phrase (confused/partial-corruption
            // decrypt), we'd permanently replace the backup phrase with the wrong one.
            // Apply the SAME identity guard: re-derive the master seed from the recovered
            // mnemonic and require an exact match to the authoritative in-memory
            // hdMasterKey.seed BEFORE re-encrypting.
            //
            // F1 round 3 (Cursor HIGH): EncryptWallet must NEVER FAIL because the
            // mnemonic can't be verified. The previous code rolled back + returned false
            // here — which permanently stranded BIP39-passphrase wallets (they could
            // never encrypt at all). Instead:
            //   verified (empty passphrase OR supplied bip39Passphrase)
            //       → re-encrypt under master, discard the original (safe: PROVEN identity).
            //   NOT verified (passphrase wallet w/o passphrase, or valid-but-wrong phrase)
            //       → DEFER-AND-PRESERVE: leave vchEncryptedMnemonic/IV/MAC byte-for-byte
            //         intact (do NOT call EncryptMnemonic), still encrypt the seed + keys
            //         below, arm m_fNeedsSeedMigration so the next unlock retries, and
            //         SUCCEED with a distinct "passphrase required" diagnostic.
            // INVARIANT (absolute): the original mnemonic ciphertext is discarded ONLY
            // when the recovered phrase PROVABLY re-derives this wallet's seed.
            bool mnemonicVerified = MnemonicReDerivesSeed(mnemonicStr, "");
            if (!mnemonicVerified && !bip39Passphrase.empty()) {
                mnemonicVerified = MnemonicReDerivesSeed(mnemonicStr, bip39Passphrase);
            }

            if (mnemonicVerified) {
                // Re-encrypt under master key (masterKey.IsValid() is now true → master
                // branch → also computes the mnemonic MAC). This overwrites the original
                // obfuscation-key ciphertext — safe, identity is PROVEN.
                bool ok = EncryptMnemonic(mnemonicStr);
                if (!mnemonicStr.empty()) {
                    memory_cleanse(&mnemonicStr[0], mnemonicStr.size());
                }
                if (!ok) {
                    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
                    memory_cleanse(derivedKey.data(), derivedKey.size());
                    std::cerr << "[Wallet] CRITICAL: failed to re-encrypt mnemonic" << std::endl;
                    rollback();
                    return false;
                }
            } else {
                // DEFER-AND-PRESERVE. Do NOT touch vchEncryptedMnemonic/IV/MAC — the
                // original obfuscation-key ciphertext stays byte-for-byte intact and
                // remains recoverable (the seed is encrypted below but re-derived into
                // hdMasterKey.seed on every unlock, so the migration path can re-derive
                // the obfuscation key and read it). Arm the migration so a later unlock
                // with the correct BIP39 passphrase completes the v7 re-encryption.
                if (!mnemonicStr.empty()) {
                    memory_cleanse(&mnemonicStr[0], mnemonicStr.size());
                }
                m_fNeedsSeedMigration = true;
                m_migrationDeferredPassphrase = true;
                std::cerr << "[Wallet] LP-7: wallet ENCRYPTED, mnemonic migration "
                             "DEFERRED — the recovered mnemonic does not re-derive this "
                             "wallet's seed under the empty passphrase"
                          << (bip39Passphrase.empty()
                                  ? " (no BIP39 passphrase was supplied)"
                                  : " or the supplied BIP39 passphrase")
                          << ". This is EXPECTED for a BIP39-passphrase wallet. The wallet "
                             "and all keys ARE encrypted and the ORIGINAL backup phrase "
                             "ciphertext was PRESERVED unchanged. Re-run unlock "
                             "(walletpassphrase) with the correct \"bip39passphrase\" to "
                             "complete migration. This is NOT corruption." << std::endl;
                // Fall through to encrypt the HD seed + remaining state and SUCCEED.
            }
        }

        // Encrypt the HD master seed (scrubs the plaintext seed; stores the
        // variable-length ciphertext + MAC; sets fHDMasterKeyEncrypted).
        if (!EncryptHDMasterKey()) {
            memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
            memory_cleanse(derivedKey.data(), derivedKey.size());
            std::cerr << "[Wallet] CRITICAL: failed to encrypt HD master key" << std::endl;
            rollback();
            return false;
        }
    }

    // Encrypt MIK private key if present (must happen after vMasterKey is set)
    if (fHasMIK && m_mik && m_mik->HasPrivateKey()) {
        if (!EncryptMIKPrivKey()) {
            std::cerr << "[Wallet] WARNING: Failed to encrypt MIK private key during wallet encryption" << std::endl;
            // Don't fail entire encryption - MIK can be regenerated
        } else {
            // Clear in-memory private key (will decrypt on demand)
            m_mik->privkey.clear();
            std::cout << "[Wallet] MIK private key encrypted successfully" << std::endl;
        }
    }

    // Wipe sensitive data
    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
    memory_cleanse(derivedKey.data(), derivedKey.size());

    // LP-7 (version-aware writer): encrypting the wallet produces v7-shaped records
    // (encrypted variable-length HD seed when HD; separated-keyed master + per-record
    // MACs). Promote the loaded version to v7 so SaveUnlocked emits the v7 layout — a
    // v6 write here would (a) re-emit the now-SCRUBBED plaintext seed slots as zeros
    // and (b) write separated-keyed MACs under a v6 header. New wallets are
    // m_loadedFileVersion==0 (already write v7); this matters for a wallet LOADED from
    // a v6 file and then encrypted in place.
    m_loadedFileVersion = WALLET_FILE_VERSION_7;

    // Save wallet to disk — encryption MUST be persisted
    if (m_autoSave && !m_walletFile.empty()) {
        if (!SaveUnlocked()) {
            // Transactional (Cursor HIGH-2): the in-memory encryption is complete
            // and correct (HD seed encrypted, fHDMasterKeyEncrypted==true) so this
            // is NOT the plaintext-at-rest state — but the encryption did not reach
            // disk. Roll the in-memory state back to UNENCRYPTED so the on-disk file
            // and memory agree (both unencrypted) and the failure is total rather
            // than leaving the wallet encrypted-in-memory-but-unsaved. EncryptWallet
            // can then be retried cleanly.
            std::cerr << "[Wallet] CRITICAL: Wallet encrypted in memory but failed to save to disk — rolling back to unencrypted state" << std::endl;
            rollback();
            return false;
        }
    }

    return true;
}

bool CWallet::ChangePassphrase(const std::string& passphraseOld,
                                const std::string& passphraseNew) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }

    if (passphraseNew.empty()) {
        return false;
    }

    // Validate new passphrase strength
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(passphraseNew);

    if (!validation.is_valid) {
        std::cerr << "[Wallet] New passphrase validation failed: "
                  << validation.error_message << std::endl;
        return false;
    }

    // Log passphrase strength
    std::cout << "[Wallet] New passphrase strength: "
              << PassphraseValidator::GetStrengthDescription(validation.strength_score)
              << " (" << validation.strength_score << "/100)" << std::endl;

    // Display any warnings
    for (const auto& warning : validation.warnings) {
        std::cout << "[Wallet] Warning: " << warning << std::endl;
    }

    // Derive old key
    std::vector<uint8_t> derivedKeyOld;
    if (!DeriveKey(passphraseOld, masterKey.vchSalt, masterKey.nDeriveIterations, derivedKeyOld)) {
        return false;
    }

    // Decrypt current master key
    CCrypter crypterOld;
    if (!crypterOld.SetKey(derivedKeyOld, masterKey.vchIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Verify MAC before decryption (prevents padding oracle).
    // LP-7 (MEDIUM-1, round 3): route through the central VerifyRecordMAC gate so the
    // keying selection matches the LOADED file version, exactly like the five read
    // paths. The previous open-coded `crypterOld.VerifyMAC(...)` used the default
    // separated (v7) keying unconditionally; on a loaded legacy v3-v6 wallet whose
    // master MAC is legacy-AES-keyed (and non-empty, so IsLegacy()==false), that
    // mismatched the on-disk MAC and made ChangePassphrase reject the CORRECT
    // passphrase — permanently bricking passphrase rotation for non-HD legacy
    // wallets (which never migrate). VerifyRecordMAC also subsumes the empty-MAC
    // pre-v7 case, so the IsLegacy() special-case is no longer needed.
    if (!VerifyRecordMAC(crypterOld, masterKey.vchCryptedKey, masterKey.vchMAC)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        return false;  // MAC verification failed - wrong passphrase or tampered data
    }

    std::vector<uint8_t> vMasterKeyPlain;
    if (!crypterOld.Decrypt(masterKey.vchCryptedKey, vMasterKeyPlain)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        return false;  // Wrong old passphrase
    }

    // Generate new salt
    std::vector<uint8_t> newSalt;
    if (!GenerateSalt(newSalt)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Derive new key
    std::vector<uint8_t> derivedKeyNew;
    if (!DeriveKey(passphraseNew, newSalt, WALLET_CRYPTO_PBKDF2_ROUNDS, derivedKeyNew)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // FIX-010: Generate unique IV for re-encryption
    std::vector<uint8_t> newIV;
    if (!GenerateUniqueIV_Locked(newIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Re-encrypt master key with new passphrase
    CCrypter crypterNew;
    if (!crypterNew.SetKey(derivedKeyNew, newIV)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    std::vector<uint8_t> newCryptedKey;
    if (!crypterNew.Encrypt(vMasterKeyPlain, newCryptedKey)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // FIX-008 (CRYPT-007): Compute MAC for authenticated encryption.
    // LP-7 (ratified design): route through ComputeRecordMAC with the keying that
    // MATCHES the file's current on-disk version. ChangePassphrase rotates the
    // passphrase IN PLACE and does NOT promote the file to v7 (SaveUnlocked re-emits
    // the loaded version), so the rewritten master-key MAC must use the SAME keying
    // the rest of that file uses, or VerifyRecordMAC rejects the correct passphrase on
    // the next load:
    //   - loaded v3-v6  -> legacy AES-keyed HMAC (file stays v6)
    //   - loaded v7 / 0 -> separated v7 keying (file is/stays v7)
    // (The single v6->v7 migration — which DOES recompute every MAC to separated
    // keying — still happens exactly once, on the next Unlock, never here.)
    const bool legacyMasterKeying = LegacyRecordKeying();
    std::vector<uint8_t> newMAC;
    if (!ComputeRecordMAC(crypterNew, newCryptedKey, newMAC, legacyMasterKeying)) {
        memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
        memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());
        memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
        return false;
    }

    // Save old master key state in case disk write fails and we need to revert
    auto oldCryptedKey = masterKey.vchCryptedKey;
    auto oldSalt = masterKey.vchSalt;
    auto oldMAC = masterKey.vchMAC;
    auto oldIV = masterKey.vchIV;

    // Update master key in memory
    masterKey.vchCryptedKey = newCryptedKey;
    masterKey.vchSalt = newSalt;
    masterKey.vchMAC = newMAC;  // FIX-008: Store MAC
    masterKey.vchIV = newIV;

    // LP-7 (ratified design): ChangePassphrase rotates the passphrase IN PLACE only.
    // It touches ONLY the master-key record (re-encrypted above under the new
    // passphrase-derived key + version-matched MAC). It deliberately does NOT:
    //   - promote m_loadedFileVersion to v7,
    //   - touch fHDMasterKeyEncrypted or migrate the HD seed,
    //   - re-MAC the per-address / HD-master / mnemonic / MIK records.
    // Those non-master records are encrypted under the (UNCHANGED) master key, so a
    // passphrase rotation leaves their ciphertext + IV + MAC byte-identical — nothing
    // to rewrite. SaveUnlocked re-emits the file at its existing version (legacy v6
    // layout for a loaded v6 wallet), so the legacy-keyed non-master MACs stay valid
    // on reload. The one-time v6->v7 migration (re-encrypt seed + re-MAC every record)
    // happens on the next Unlock via MigrateToEncryptedSeedV7Unlocked — the single
    // source of truth. This DELETES the round-1..4 ReMACAllRecordsToV7Unlocked seam
    // that re-introduced plaintext-seed-at-rest (BLOCKER-1) and bricked empty-MAC
    // mnemonic/MIK records (BLOCKER-2).

    // Wipe sensitive data
    memory_cleanse(derivedKeyOld.data(), derivedKeyOld.size());
    memory_cleanse(derivedKeyNew.data(), derivedKeyNew.size());

    // Save wallet to disk — passphrase change MUST be persisted
    if (m_autoSave && !m_walletFile.empty()) {
        if (!SaveUnlocked()) {
            std::cerr << "[Wallet] CRITICAL: Passphrase changed in memory but failed to save to disk!" << std::endl;
            std::cerr << "[Wallet] wallet.dat still has the OLD passphrase. Retrying..." << std::endl;

            // Retry once after a brief pause (handles transient file locks on Windows)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (!SaveUnlocked()) {
                std::cerr << "[Wallet] CRITICAL: Retry failed. Reverting passphrase change." << std::endl;
                // Revert the master key so in-memory state matches what's on disk
                // (the original, untouched file). Only the master-key record changed.
                masterKey.vchCryptedKey = oldCryptedKey;
                masterKey.vchSalt = oldSalt;
                masterKey.vchMAC = oldMAC;
                masterKey.vchIV = oldIV;
                memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());
                return false;
            }
        }
    }

    memory_cleanse(vMasterKeyPlain.data(), vMasterKeyPlain.size());

    return true;
}

// ============================================================================
// Persistence
// ============================================================================

// CID 1675316/1675317/1675318/1675319/1675321 FIX: This entire function is protected by cs_wallet lock
// All member variable reads and writes throughout this function are thread-safe
bool CWallet::Load(const std::string& filename) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;  // File doesn't exist or can't be opened
    }

    // SEC-001 FIX: Load into temporary variables first (atomic load pattern)
    // Only clear existing wallet if load succeeds completely
    std::map<CDilithiumAddress, CKey> temp_mapKeys;
    std::map<CDilithiumAddress, CEncryptedKey> temp_mapCryptedKeys;
    std::vector<CDilithiumAddress> temp_vchAddresses;
    // FIX-005 (WALLET-001): Changed to COutPoint key for v3 format
    std::map<COutPoint, CWalletTx> temp_mapWalletTx;
    CDilithiumAddress temp_defaultAddress;
    CMasterKey temp_masterKey;
    bool temp_fWalletUnlocked = true;
    // BUG #56 FIX: Best block pointer temp variables
    uint256 temp_bestBlockHash;
    int32_t temp_bestBlockHeight = -1;

    // Read header
    char magic[8];
    file.read(magic, 8);
    if (!file.good()) return false;  // SEC-001: Check I/O error

    std::string magic_str(magic, 8);
    // FIX-011 (PERSIST-001): Support DILWLT03 format with file integrity HMAC
    // v4: Added fCoinbase field to track mining rewards
    // LP-7: v7 (DILWLT07) — encryption-at-rest fix (variable-length encrypted seed
    // + per-record MACs).
    if (magic_str != "DILWLT01" && magic_str != "DILWLT02" && magic_str != "DILWLT03" && magic_str != "DILWLT04" && magic_str != "DILWLT05" && magic_str != "DILWLT06" && magic_str != "DILWLT07") {
        return false;  // Invalid file format
    }

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (version != 1 && version != 2 && version != 3 && version != 4 && version != 5 && version != 6 && version != 7) {
        return false;  // Unsupported version
    }

    uint32_t flags;
    file.read(reinterpret_cast<char*>(&flags), sizeof(flags));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    bool is_hd_wallet = (flags & 0x02) != 0;

    // FIX-011 (PERSIST-001): Read HMAC and salt for v3 format
    std::vector<uint8_t> stored_hmac;
    std::vector<uint8_t> hmac_salt;
    std::streampos data_start_pos;  // Position where HMAC-protected data starts (salt position)

    if (version >= 3) {
        // v3+ format: [Magic][Version][Flags][HMAC][Salt][Data...]
        // Read stored HMAC
        stored_hmac.resize(WALLET_FILE_HMAC_SIZE);
        file.read(reinterpret_cast<char*>(stored_hmac.data()), WALLET_FILE_HMAC_SIZE);
        if (!file.good()) return false;

        // Remember position where HMAC-protected data starts (before reading salt)
        // HMAC covers [Salt][Data...], not [HMAC][Salt][Data...]
        data_start_pos = file.tellg();

        // Read HMAC salt
        hmac_salt.resize(WALLET_FILE_SALT_SIZE);
        file.read(reinterpret_cast<char*>(hmac_salt.data()), WALLET_FILE_SALT_SIZE);
        if (!file.good()) return false;
    } else {
        // v1/v2 format: Skip reserved bytes (no HMAC)
        uint8_t reserved[16];
        file.read(reinterpret_cast<char*>(reserved), 16);
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // Read master key if encrypted
    bool isEncrypted = (flags & 0x01) != 0;
    if (isEncrypted) {
        uint32_t cryptedKeyLen;
        file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // SEC-001 FIX: Validate cryptedKeyLen to prevent memory exhaustion
        const uint32_t MAX_ENCRYPTED_KEY_SIZE = 8192;  // Reasonable upper bound
        if (cryptedKeyLen > MAX_ENCRYPTED_KEY_SIZE) {
            return false;  // Reject malicious sizes
        }

        temp_masterKey.vchCryptedKey.resize(cryptedKeyLen);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchCryptedKey.data()), cryptedKeyLen);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        temp_masterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchSalt.data()), WALLET_CRYPTO_SALT_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        temp_masterKey.vchIV.resize(WALLET_CRYPTO_IV_SIZE);
        file.read(reinterpret_cast<char*>(temp_masterKey.vchIV.data()), WALLET_CRYPTO_IV_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-010: Register master key IV to prevent reuse
        // CID 1675317 FIX: Access to usedIVs is protected by lock acquired at line 1260
        usedIVs.insert(temp_masterKey.vchIV);

        file.read(reinterpret_cast<char*>(&temp_masterKey.nDerivationMethod), sizeof(temp_masterKey.nDerivationMethod));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&temp_masterKey.nDeriveIterations), sizeof(temp_masterKey.nDeriveIterations));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-008 (CRYPT-007): Load MAC for authenticated encryption
        // For legacy wallets (v2 without MAC), this field won't exist
        // Check if there's more data to read
        uint32_t macLen = 0;
        std::streampos pos_before = file.tellg();
        file.read(reinterpret_cast<char*>(&macLen), sizeof(macLen));
        if (file.good() && macLen > 0 && macLen <= 64) {  // HMAC-SHA3-512 is 64 bytes
            temp_masterKey.vchMAC.resize(macLen);
            file.read(reinterpret_cast<char*>(temp_masterKey.vchMAC.data()), macLen);
            if (!file.good()) {
                // Failed to read MAC - might be EOF, treat as legacy wallet
                file.clear();  // Clear error state
                file.seekg(pos_before);  // Restore position
                temp_masterKey.vchMAC.clear();
            }
        } else {
            // No MAC or invalid length - legacy wallet
            file.clear();  // Clear error state if EOF
            file.seekg(pos_before);  // Restore position
            temp_masterKey.vchMAC.clear();
        }

        // LP-7 (HIGH-1 / S-004 / A-007): a v7 wallet MUST carry a non-empty
        // master-key MAC. The v7 writer always populates it (wallet.cpp), so an
        // empty/absent MAC on a v7 file means the MAC was stripped — reject it as
        // corrupt rather than silently falling back to the unauthenticated
        // "legacy" path (which would re-open the encrypt-then-MAC downgrade on the
        // root secret). The legacy unauthenticated path is preserved ONLY for
        // genuine v3-v6 files being read for migration.
        if (version >= WALLET_FILE_VERSION_7 && temp_masterKey.vchMAC.empty()) {
            return false;  // v7 master key with stripped/absent MAC — reject as tampered
        }

        // Wallet starts locked (encryption status determined by masterKey.IsValid())
        temp_fWalletUnlocked = false;
    }

    // Read HD wallet data (v2 only)
    bool temp_fIsHDWallet = false;
    std::vector<uint8_t> temp_vchEncryptedMnemonic;
    std::vector<uint8_t> temp_vchMnemonicMAC;          // LP-7 (v7)
    std::vector<uint8_t> temp_vchMnemonicIV;
    CHDExtendedKey temp_hdMasterKey;
    bool temp_fHDMasterKeyEncrypted = false;
    std::vector<uint8_t> temp_vchEncryptedHDMasterKey;  // LP-7 (v7): variable-length seed ciphertext
    std::vector<uint8_t> temp_vchHDMasterKeyMAC;        // LP-7 (v7)
    std::vector<uint8_t> temp_vchHDMasterKeyIV;
    // LP-7: true if this is an encrypted wallet whose HD seed is plaintext at rest
    // (the pre-v7 bug) and therefore needs migration on next unlock.
    bool temp_fNeedsSeedMigration = false;
    // LP-7 (F1 round 3): set when a v7 ENCRYPTED wallet carries a present mnemonic
    // ciphertext with an EMPTY MAC — the defer-and-preserve (BIP39-passphrase) state.
    // Combined with isEncrypted after the HD block is parsed to arm migration.
    bool mnemonicNeedsMigration = false;
    uint32_t temp_nHDAccountIndex = 0;
    uint32_t temp_nHDExternalChainIndex = 0;
    uint32_t temp_nHDInternalChainIndex = 0;
    std::map<CDilithiumAddress, CHDKeyPath> temp_mapAddressToPath;
    std::map<CHDKeyPath, CDilithiumAddress> temp_mapPathToAddress;

    if (is_hd_wallet) {
        temp_fIsHDWallet = true;

        // Read encrypted mnemonic
        uint32_t mnemonicLen;
        file.read(reinterpret_cast<char*>(&mnemonicLen), sizeof(mnemonicLen));
        if (!file.good()) return false;

        // Validate mnemonic length
        const uint32_t MAX_MNEMONIC_SIZE = 1024;  // Reasonable upper bound
        if (mnemonicLen > MAX_MNEMONIC_SIZE) {
            return false;
        }

        if (mnemonicLen > 0) {
            temp_vchEncryptedMnemonic.resize(mnemonicLen);
            file.read(reinterpret_cast<char*>(temp_vchEncryptedMnemonic.data()), mnemonicLen);
            if (!file.good()) return false;

            temp_vchMnemonicIV.resize(WALLET_CRYPTO_IV_SIZE);
            file.read(reinterpret_cast<char*>(temp_vchMnemonicIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;

            // FIX-010: Register mnemonic IV to prevent reuse
            // CID 1675317 FIX: Access to usedIVs is protected by lock acquired at line 1260
            usedIVs.insert(temp_vchMnemonicIV);

            // LP-7 (v7): read the mnemonic MAC (variable-length). Absent in v3-v6.
            if (version >= WALLET_FILE_VERSION_7) {
                uint32_t mnMacLen = 0;
                file.read(reinterpret_cast<char*>(&mnMacLen), sizeof(mnMacLen));
                if (!file.good()) return false;
                if (mnMacLen > 64) return false;  // HMAC-SHA3-512 is 64 bytes
                // LP-7 (HIGH-2 item 3, load-symmetry): on a v7 ENCRYPTED wallet a
                // present mnemonic ciphertext MUST carry a non-empty MAC IF it was
                // master-key-encrypted-then-MAC'd. (An UNencrypted v7 wallet
                // legitimately writes mnMacLen==0 because the mnemonic is under the
                // obfuscation key.)
                //
                // F1 round 3 EXCEPTION: a BIP39-passphrase wallet encrypted via the
                // defer-and-preserve path is a v7 ENCRYPTED wallet whose mnemonic was
                // intentionally LEFT under the obfuscation key (empty MAC), pending the
                // user supplying the passphrase to complete migration. That is a
                // legitimate state, NOT corruption. We cannot tell the two apart from
                // the mnemonic record alone, so DEFER the decision: capture the
                // empty-MAC-on-encrypted condition here and, after the HD-master block
                // is parsed, ARM migration for it (mnemonicNeedsMigration). The
                // downstream migration is fail-closed — it re-derives + identity-checks
                // the mnemonic before any rewrite, so a genuinely corrupt/truncated
                // mnemonic simply fails the identity check and defers (preserving),
                // never destructively rewriting. This keeps the wallet LOADABLE instead
                // of bricking it on a hard reject.
                if (mnMacLen == 0 && temp_masterKey.IsValid()) {
                    mnemonicNeedsMigration = true;
                }
                if (mnMacLen > 0) {
                    temp_vchMnemonicMAC.resize(mnMacLen);
                    file.read(reinterpret_cast<char*>(temp_vchMnemonicMAC.data()), mnMacLen);
                    if (!file.good()) return false;
                }
            }
        }

        // LP-7: the HD-master block layout depends on the file version.
        if (version >= WALLET_FILE_VERSION_7) {
            // v7 layout: [encrypted_flag]
            //   if encrypted: [hdEncLen][ciphertext][hdMacLen][mac][depth][fp][ci][IV]
            //   if plaintext: [hdEncLen=0][seed32][chaincode32][depth][fp][ci]
            uint8_t encrypted_flag;
            file.read(reinterpret_cast<char*>(&encrypted_flag), 1);
            if (!file.good()) return false;
            temp_fHDMasterKeyEncrypted = (encrypted_flag != 0);

            uint32_t hdEncLen = 0;
            file.read(reinterpret_cast<char*>(&hdEncLen), sizeof(hdEncLen));
            if (!file.good()) return false;

            if (temp_fHDMasterKeyEncrypted) {
                // Variable-length ciphertext (bounded: 64-byte plaintext → 80-byte
                // ciphertext; allow generous slack but reject absurd sizes).
                const uint32_t MAX_HD_ENC_SIZE = 4096;
                if (hdEncLen == 0 || (hdEncLen % 16) != 0 || hdEncLen > MAX_HD_ENC_SIZE) {
                    return false;
                }
                temp_vchEncryptedHDMasterKey.resize(hdEncLen);
                file.read(reinterpret_cast<char*>(temp_vchEncryptedHDMasterKey.data()), hdEncLen);
                if (!file.good()) return false;

                uint32_t hdMacLen = 0;
                file.read(reinterpret_cast<char*>(&hdMacLen), sizeof(hdMacLen));
                if (!file.good()) return false;
                if (hdMacLen == 0 || hdMacLen > 64) return false;  // v7 requires a MAC
                temp_vchHDMasterKeyMAC.resize(hdMacLen);
                file.read(reinterpret_cast<char*>(temp_vchHDMasterKeyMAC.data()), hdMacLen);
                if (!file.good()) return false;

                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.depth), sizeof(temp_hdMasterKey.depth));
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.fingerprint), sizeof(temp_hdMasterKey.fingerprint));
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.child_index), sizeof(temp_hdMasterKey.child_index));
                if (!file.good()) return false;

                temp_vchHDMasterKeyIV.resize(WALLET_CRYPTO_IV_SIZE);
                file.read(reinterpret_cast<char*>(temp_vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
                if (!file.good()) return false;
                usedIVs.insert(temp_vchHDMasterKeyIV);
                // seed/chaincode slots remain zero in memory; ciphertext is the
                // storage-of-record. No plaintext seed present in a v7 file.
            } else {
                // Plaintext (unencrypted wallet) — hdEncLen must be 0.
                if (hdEncLen != 0) return false;
                file.read(reinterpret_cast<char*>(temp_hdMasterKey.seed), 32);
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(temp_hdMasterKey.chaincode), 32);
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.depth), sizeof(temp_hdMasterKey.depth));
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.fingerprint), sizeof(temp_hdMasterKey.fingerprint));
                if (!file.good()) return false;
                file.read(reinterpret_cast<char*>(&temp_hdMasterKey.child_index), sizeof(temp_hdMasterKey.child_index));
                if (!file.good()) return false;

                // LOAD-TIME DEFENSE-IN-DEPTH (Cursor HIGH-1/HIGH-2): a v7 file whose
                // HD seed is PLAINTEXT (this branch) while the WALLET is encrypted
                // (isEncrypted: spending keys under a passphrase master key) is the
                // LP-7 plaintext-seed-at-rest state — it should never have been
                // written (the SaveUnlocked guard now refuses it, and EncryptWallet
                // is now transactional), but a wallet produced by a pre-fix binary
                // could still exist on disk. Arm migration so the next Unlock
                // re-encrypts the seed and rewrites the file at v7, exactly as the
                // legacy-layout branch below does for legacy plaintext seeds. (An
                // UNencrypted v7 wallet legitimately stores a plaintext seed here —
                // only arm when the wallet has a master key.)
                if (isEncrypted) {
                    temp_fNeedsSeedMigration = true;
                }
            }
        } else {
            // LEGACY v3-v6 layout: fixed [seed32][chaincode32][depth][fp][ci]
            //                      [encrypted_flag] [IV if encrypted]
            // In this format the seed is ALWAYS stored in the fixed slots, in
            // PLAINTEXT (the LP-7 bug) — the encrypted_flag only ever gated the IV.
            file.read(reinterpret_cast<char*>(temp_hdMasterKey.seed), 32);
            if (!file.good()) return false;
            file.read(reinterpret_cast<char*>(temp_hdMasterKey.chaincode), 32);
            if (!file.good()) return false;
            file.read(reinterpret_cast<char*>(&temp_hdMasterKey.depth), sizeof(temp_hdMasterKey.depth));
            if (!file.good()) return false;
            file.read(reinterpret_cast<char*>(&temp_hdMasterKey.fingerprint), sizeof(temp_hdMasterKey.fingerprint));
            if (!file.good()) return false;
            file.read(reinterpret_cast<char*>(&temp_hdMasterKey.child_index), sizeof(temp_hdMasterKey.child_index));
            if (!file.good()) return false;

            uint8_t encrypted_flag;
            file.read(reinterpret_cast<char*>(&encrypted_flag), 1);
            if (!file.good()) return false;
            bool legacyEncFlag = (encrypted_flag != 0);

            if (legacyEncFlag) {
                temp_vchHDMasterKeyIV.resize(WALLET_CRYPTO_IV_SIZE);
                file.read(reinterpret_cast<char*>(temp_vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
                if (!file.good()) return false;
                usedIVs.insert(temp_vchHDMasterKeyIV);
            }

            // LP-7 (wallet-Inv-5): in legacy files the seed is plaintext at rest
            // regardless of the flag. We deliberately treat the in-memory HD master
            // as NOT encrypted (plaintext seed loaded into the slots) and, if the
            // wallet is encrypted (has a passphrase master key), flag it for
            // migration on next unlock so the seed gets re-encrypted and rewritten
            // at v7. The stored legacyEncFlag is ignored on purpose: the old
            // "encrypted" path never produced a recoverable ciphertext.
            temp_fHDMasterKeyEncrypted = false;
            if (isEncrypted) {
                temp_fNeedsSeedMigration = true;
            }
        }

        // LP-7 (F1 round 3): a v7 ENCRYPTED wallet whose mnemonic record had an empty
        // MAC (mnemonicNeedsMigration) is the defer-and-preserve state — the mnemonic
        // is still under the obfuscation key (recoverable from the seed at unlock) and
        // migration must complete once the BIP39 passphrase is supplied. Arm it here.
        // (Note the seed itself may already be ENCRYPTED in this state, so the
        // plaintext-seed detection above does not catch it.) Only meaningful for an
        // encrypted wallet — isEncrypted is the master-key gate.
        if (mnemonicNeedsMigration && isEncrypted) {
            temp_fNeedsSeedMigration = true;
        }

        // Read HD chain state
        file.read(reinterpret_cast<char*>(&temp_nHDAccountIndex), sizeof(temp_nHDAccountIndex));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_nHDExternalChainIndex), sizeof(temp_nHDExternalChainIndex));
        if (!file.good()) return false;
        file.read(reinterpret_cast<char*>(&temp_nHDInternalChainIndex), sizeof(temp_nHDInternalChainIndex));
        if (!file.good()) return false;

        // Read HD path mappings
        uint32_t numPaths;
        file.read(reinterpret_cast<char*>(&numPaths), sizeof(numPaths));
        if (!file.good()) return false;

        // Validate numPaths
        const uint32_t MAX_HD_PATHS = 100000;  // Reasonable upper bound
        if (numPaths > MAX_HD_PATHS) {
            return false;
        }

        for (uint32_t i = 0; i < numPaths; i++) {
            // Read path indices count
            uint32_t numIndices;
            file.read(reinterpret_cast<char*>(&numIndices), sizeof(numIndices));
            if (!file.good()) return false;

            // Validate numIndices (BIP44 has 5 levels)
            const uint32_t MAX_PATH_DEPTH = 10;
            if (numIndices > MAX_PATH_DEPTH) {
                return false;
            }

            // Read indices
            CHDKeyPath path;
            path.indices.resize(numIndices);
            for (uint32_t j = 0; j < numIndices; j++) {
                file.read(reinterpret_cast<char*>(&path.indices[j]), sizeof(uint32_t));
                if (!file.good()) return false;
            }

            // Read address
            std::vector<uint8_t> addrData(21);
            file.read(reinterpret_cast<char*>(addrData.data()), 21);
            if (!file.good()) return false;

            // Reconstruct address from raw data
            CDilithiumAddress address = CDilithiumAddress::FromData(addrData);

            // Store path mappings
            temp_mapPathToAddress[path] = address;
            temp_mapAddressToPath[address] = path;
        }
    }

    // Read keys
    uint32_t numKeys;
    file.read(reinterpret_cast<char*>(&numKeys), sizeof(numKeys));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // SEC-001 FIX: Validate numKeys to prevent iteration bomb / DoS
    const uint32_t MAX_WALLET_KEYS = 1000000;  // 1M keys is already excessive
    if (numKeys > MAX_WALLET_KEYS) {
        return false;  // Reject malicious loop counts
    }

    for (uint32_t i = 0; i < numKeys; i++) {
        // Read address
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        CDilithiumAddress addr;
        if (!addr.SetString(::EncodeBase58Check(addrData))) {
            // Fallback: construct address directly from data
            // This is needed because SetString expects Base58-encoded string
            // but we have raw bytes. We'll need a different approach.
            // For now, skip validation and construct manually
        }

        if (isEncrypted) {
            // Read encrypted key
            CEncryptedKey encKey;

            encKey.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
            file.read(reinterpret_cast<char*>(encKey.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            uint32_t cryptedKeyLen;
            file.read(reinterpret_cast<char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // SEC-001 FIX: Validate cryptedKeyLen (same check as master key)
            const uint32_t MAX_ENCRYPTED_KEY_SIZE = 8192;
            if (cryptedKeyLen > MAX_ENCRYPTED_KEY_SIZE) {
                return false;  // Reject malicious sizes
            }

            encKey.vchCryptedKey.resize(cryptedKeyLen);
            file.read(reinterpret_cast<char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            encKey.vchIV.resize(16);
            file.read(reinterpret_cast<char*>(encKey.vchIV.data()), 16);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // FIX-010: Register encrypted key IV to prevent reuse
            // CID 1675317 FIX: Access to usedIVs is protected by lock acquired at line 1260
            usedIVs.insert(encKey.vchIV);

            // FIX-008 (CRYPT-007): Load MAC for authenticated encryption
            // v3 format always writes macLen (even if 0), so don't seek back
            // For legacy v1/v2 wallets without MAC, this field won't exist
            uint32_t macLen = 0;
            if (version >= 3) {
                // v3: macLen is always present
                file.read(reinterpret_cast<char*>(&macLen), sizeof(macLen));
                if (!file.good()) return false;  // SEC-001: Check I/O error
                if (macLen > 0 && macLen <= 64) {  // HMAC-SHA3-512 is 64 bytes
                    encKey.vchMAC.resize(macLen);
                    file.read(reinterpret_cast<char*>(encKey.vchMAC.data()), macLen);
                    if (!file.good()) return false;  // SEC-001: Check I/O error
                }
                // LP-7 (HIGH-1 / S-004 / A-007): a v7 wallet MUST carry a
                // non-empty MAC on every per-address spending key. The v7 writer
                // always populates it, so macLen==0 on a v7 file means the MAC was
                // stripped — reject as tampered rather than loading it as an
                // unauthenticated "legacy" key (which would re-open the MAC
                // downgrade on a spending key). v3-v6 keys keep the legacy path.
                if (version >= WALLET_FILE_VERSION_7 && encKey.vchMAC.empty()) {
                    return false;  // v7 per-address key with stripped/absent MAC — reject
                }
            } else {
                // Legacy v1/v2: try to read macLen, seek back if not present
                std::streampos pos_before = file.tellg();
                file.read(reinterpret_cast<char*>(&macLen), sizeof(macLen));
                if (file.good() && macLen > 0 && macLen <= 64) {
                    encKey.vchMAC.resize(macLen);
                    file.read(reinterpret_cast<char*>(encKey.vchMAC.data()), macLen);
                    if (!file.good()) {
                        file.clear();
                        file.seekg(pos_before);
                        encKey.vchMAC.clear();
                    }
                } else {
                    file.clear();
                    file.seekg(pos_before);
                    encKey.vchMAC.clear();
                }
            }

            // Create address from public key
            CDilithiumAddress keyAddr(encKey.vchPubKey);
            temp_mapCryptedKeys[keyAddr] = encKey;
            temp_vchAddresses.push_back(std::move(keyAddr));
        } else {
            // Read unencrypted key
            CKey key;

            key.vchPubKey.resize(DILITHIUM_PUBLICKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            key.vchPrivKey.resize(DILITHIUM_SECRETKEY_SIZE);
            file.read(reinterpret_cast<char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Create address from public key
            CDilithiumAddress keyAddr(key.vchPubKey);
            temp_mapKeys[keyAddr] = key;
            temp_vchAddresses.push_back(std::move(keyAddr));
        }
    }

    // Read default address
    uint8_t hasDefault;
    file.read(reinterpret_cast<char*>(&hasDefault), 1);
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (hasDefault) {
        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Find matching address in temp_vchAddresses
        for (const auto& addr : temp_vchAddresses) {
            if (addr.GetData() == addrData) {
                temp_defaultAddress = addr;
                break;
            }
        }
    }

    // Read transactions
    uint32_t numTxs;
    file.read(reinterpret_cast<char*>(&numTxs), sizeof(numTxs));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    // SEC-001 FIX: Validate numTxs to prevent iteration bomb / DoS
    const uint32_t MAX_WALLET_TXS = 10000000;  // 10M transactions is excessive
    if (numTxs > MAX_WALLET_TXS) {
        return false;  // Reject malicious loop counts
    }

    for (uint32_t i = 0; i < numTxs; i++) {
        CWalletTx wtx;

        file.read(reinterpret_cast<char*>(wtx.txid.begin()), 32);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&wtx.vout), sizeof(wtx.vout));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.read(reinterpret_cast<char*>(&wtx.nValue), sizeof(wtx.nValue));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        std::vector<uint8_t> addrData(21);
        file.read(reinterpret_cast<char*>(addrData.data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Find matching address in temp_vchAddresses
        for (const auto& addr : temp_vchAddresses) {
            if (addr.GetData() == addrData) {
                wtx.address = addr;
                break;
            }
        }

        uint8_t fSpent;
        file.read(reinterpret_cast<char*>(&fSpent), 1);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        wtx.fSpent = (fSpent != 0);

        file.read(reinterpret_cast<char*>(&wtx.nHeight), sizeof(wtx.nHeight));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // Read fCoinbase only for v4+ wallets (added to track mining rewards)
        wtx.fCoinbase = false;
        if (version >= 4) {
            uint8_t fCoinbase = 0;
            file.read(reinterpret_cast<char*>(&fCoinbase), 1);
            if (!file.good()) return false;
            wtx.fCoinbase = (fCoinbase != 0);
        }

        // FIX-005 (WALLET-001): Use COutPoint as composite key to prevent collision
        // When a transaction has multiple outputs to wallet, using only txid causes overwrites
        COutPoint outpoint(wtx.txid, wtx.vout);
        temp_mapWalletTx[outpoint] = wtx;
    }

    // BUG #56 FIX: Read best block pointer (Bitcoin Core pattern)
    // Note: For backwards compatibility with older wallet files, we treat read failure
    // as height -1 (triggers full rescan on startup)
    if (file.good()) {
        file.read(reinterpret_cast<char*>(temp_bestBlockHash.begin()), 32);
        if (file.good()) {
            file.read(reinterpret_cast<char*>(&temp_bestBlockHeight), sizeof(temp_bestBlockHeight));
            // If read fails, we'll use defaults (height -1 = full rescan)
            // This ensures backwards compatibility with pre-BUG#56 wallet files
        }
        // Note: It's OK if these reads fail for old wallet formats
        // Clear the EOF/fail bits so subsequent good() checks work
        if (file.eof()) {
            file.clear();  // Clear EOF state for v1/v2 formats without best block
        }
    }

    // DFMP v2.0: Read MIK (Mining Identity Key) data (v5+ format)
    // For backwards compatibility, treat read failure as no MIK
    bool temp_fHasMIK = false;
    bool temp_fMIKRegistered = false;
    std::vector<uint8_t> temp_vchMIKPubKey;
    std::vector<uint8_t> temp_vchEncryptedMIKPrivKey;
    std::vector<uint8_t> temp_vchMIKPrivKeyMAC;  // LP-7 (v7)
    std::vector<uint8_t, SecureAllocator<uint8_t>> temp_vchMIKPrivKeyIV;
    std::vector<uint8_t, SecureAllocator<uint8_t>> temp_vchMIKPrivKey;

    if (file.good() && version >= 5) {
        uint8_t hasMIK = 0;
        file.read(reinterpret_cast<char*>(&hasMIK), 1);
        if (file.good() && hasMIK) {
            temp_fHasMIK = true;

            // Read MIK public key
            uint32_t pubkeyLen = 0;
            file.read(reinterpret_cast<char*>(&pubkeyLen), sizeof(pubkeyLen));
            if (file.good() && pubkeyLen > 0 && pubkeyLen <= 2000) {
                temp_vchMIKPubKey.resize(pubkeyLen);
                file.read(reinterpret_cast<char*>(temp_vchMIKPubKey.data()), pubkeyLen);
            }

            // Read encrypted MIK private key
            uint32_t encPrivKeyLen = 0;
            file.read(reinterpret_cast<char*>(&encPrivKeyLen), sizeof(encPrivKeyLen));
            if (file.good() && encPrivKeyLen > 0 && encPrivKeyLen <= 5000) {
                temp_vchEncryptedMIKPrivKey.resize(encPrivKeyLen);
                file.read(reinterpret_cast<char*>(temp_vchEncryptedMIKPrivKey.data()), encPrivKeyLen);
            }

            // Read MIK private key IV
            uint32_t ivLen = 0;
            file.read(reinterpret_cast<char*>(&ivLen), sizeof(ivLen));
            if (file.good() && ivLen > 0 && ivLen <= 32) {
                temp_vchMIKPrivKeyIV.resize(ivLen);
                file.read(reinterpret_cast<char*>(temp_vchMIKPrivKeyIV.data()), ivLen);
            }

            // LP-7 (v7): Read MIK private-key MAC (variable-length). Absent in v5-v6.
            if (file.good() && version >= WALLET_FILE_VERSION_7) {
                uint32_t mikMacLen = 0;
                file.read(reinterpret_cast<char*>(&mikMacLen), sizeof(mikMacLen));
                if (mikMacLen > 64) return false;  // HMAC-SHA3-512 is 64 bytes
                // LP-7 (HIGH-2 item 3, load-symmetry): a v7 ENCRYPTED wallet that
                // carries an encrypted MIK private key MUST carry its MAC — an
                // empty MAC on that record is corrupt; reject at load to match the
                // other records. (Unencrypted wallets / no-MIK files write
                // mikMacLen==0 legitimately, so only enforce when both an encrypted
                // MIK privkey is present AND the wallet master key is valid.)
                if (mikMacLen == 0 && temp_masterKey.IsValid() &&
                    !temp_vchEncryptedMIKPrivKey.empty()) {
                    return false;
                }
                if (file.good() && mikMacLen > 0 && mikMacLen <= 64) {
                    temp_vchMIKPrivKeyMAC.resize(mikMacLen);
                    file.read(reinterpret_cast<char*>(temp_vchMIKPrivKeyMAC.data()), mikMacLen);
                }
            }

            // Read MIK registered flag
            uint8_t mikRegistered = 0;
            file.read(reinterpret_cast<char*>(&mikRegistered), 1);
            if (file.good()) {
                temp_fMIKRegistered = (mikRegistered != 0);
            }

            // Read unencrypted MIK private key (if present)
            uint8_t hasUnencryptedMIK = 0;
            file.read(reinterpret_cast<char*>(&hasUnencryptedMIK), 1);
            if (file.good() && hasUnencryptedMIK) {
                uint32_t privkeyLen = 0;
                file.read(reinterpret_cast<char*>(&privkeyLen), sizeof(privkeyLen));
                if (file.good() && privkeyLen > 0 && privkeyLen <= 5000) {
                    temp_vchMIKPrivKey.resize(privkeyLen);
                    file.read(reinterpret_cast<char*>(temp_vchMIKPrivKey.data()), privkeyLen);
                }
            }
        }
        // Clear EOF state for backwards compatibility
        if (file.eof()) {
            file.clear();
        }
    }

    // v6+: Read sent transaction history (mapSentTx)
    std::map<uint256, CSentTx> temp_mapSentTx;
    if (file.good() && version >= 6) {
        uint32_t numSentTx = 0;
        file.read(reinterpret_cast<char*>(&numSentTx), sizeof(numSentTx));
        if (file.good() && numSentTx <= 100000) {  // Sanity limit
            for (uint32_t i = 0; i < numSentTx; ++i) {
                CSentTx stx;

                // Read txid (32 bytes)
                file.read(reinterpret_cast<char*>(stx.txid.begin()), 32);
                if (!file.good()) break;

                // Read recipient address (21 bytes)
                std::vector<uint8_t> addrData(21);
                file.read(reinterpret_cast<char*>(addrData.data()), 21);
                if (!file.good()) break;
                stx.toAddress = CDilithiumAddress::FromData(addrData);

                // Read value, fee, time, height
                file.read(reinterpret_cast<char*>(&stx.nValue), sizeof(stx.nValue));
                if (!file.good()) break;
                file.read(reinterpret_cast<char*>(&stx.nFee), sizeof(stx.nFee));
                if (!file.good()) break;
                file.read(reinterpret_cast<char*>(&stx.nTime), sizeof(stx.nTime));
                if (!file.good()) break;
                file.read(reinterpret_cast<char*>(&stx.nHeight), sizeof(stx.nHeight));
                if (!file.good()) break;

                temp_mapSentTx[stx.txid] = stx;
            }
        }
        // Clear EOF state for backwards compatibility
        if (file.eof()) {
            file.clear();
        }
    }

    // SEC-001 FIX: Only if ALL data loaded successfully, swap into wallet
    // This ensures atomic load - either everything loads or nothing changes
    if (!file.good()) {
        return false;  // File error occurred, temp data discarded
    }

    // FIX-011 (PERSIST-001): Verify HMAC for v3+ format
    if (version >= 3) {
        // Remember current position (end of data)
        std::streampos end_pos = file.tellg();

        // Seek back to start of HMAC-protected data (salt position)
        file.seekg(data_start_pos);

        // Read all data from salt to end
        size_t data_size = static_cast<size_t>(end_pos - data_start_pos);
        std::vector<uint8_t> file_data(data_size);
        file.read(reinterpret_cast<char*>(file_data.data()), data_size);
        if (!file.good()) {
            return false;  // Failed to read data for HMAC verification
        }

        // Derive HMAC key (same strategy as SaveUnlocked)
        std::vector<uint8_t> hmac_key(32);
        if (temp_masterKey.IsValid()) {
            // Use first 32 bytes of master key salt as HMAC key (available without passphrase)
            memcpy(hmac_key.data(), temp_masterKey.vchSalt.data(),
                   std::min(hmac_key.size(), temp_masterKey.vchSalt.size()));
        } else {
            // For unencrypted wallets, derive HMAC key from wallet content (deterministic)
            // FIX: Use first address from temp_mapKeys (sorted order) for consistency between Save and Load
            // temp_vchAddresses is file order, but temp_mapKeys is sorted - use sorted order for determinism
            std::vector<uint8_t> key_material;
            if (!temp_mapKeys.empty()) {
                // Use first sorted address (deterministic across Save/Load)
                std::vector<uint8_t> addr_data = temp_mapKeys.begin()->first.GetData();
                key_material.insert(key_material.end(), addr_data.begin(), addr_data.end());
            }
            std::vector<uint8_t> default_data = temp_defaultAddress.GetData();
            key_material.insert(key_material.end(), default_data.begin(), default_data.end());

            SHA3_256(key_material.data(), key_material.size(), hmac_key.data());
        }

        // Compute HMAC-SHA3-256 over the data
        std::vector<uint8_t> computed_hmac(32);
        HMAC_SHA3_256(hmac_key.data(), hmac_key.size(),
                      file_data.data(), file_data.size(),
                      computed_hmac.data());

        // Constant-time comparison to prevent timing attacks (FIX-001)
        if (!RPCAuth::SecureCompare(stored_hmac.data(), computed_hmac.data(), WALLET_FILE_HMAC_SIZE)) {
            std::cerr << "ERROR: HMAC verification failed - file integrity check failed" << std::endl;
            return false;  // HMAC verification failed - file has been tampered with!
        }

        // HMAC verification passed - file integrity confirmed
    }

    // FIX-012 (WALLET-002): Validate wallet consistency before committing
    // This detects corruption/tampering beyond just HMAC failures
    // Create temporary wallet to test consistency before modifying this wallet
    CWallet temp_wallet_for_validation;

    // CID 1675316 FIX: Acquire temp wallet's lock before writing its members
    // This prevents Coverity from flagging a data race, even though
    // temp_wallet_for_validation is a local object not shared with other threads
    {
        std::lock_guard<std::mutex> temp_lock(temp_wallet_for_validation.cs_wallet);
        temp_wallet_for_validation.mapKeys = temp_mapKeys;
        temp_wallet_for_validation.mapCryptedKeys = temp_mapCryptedKeys;
        temp_wallet_for_validation.vchAddresses = temp_vchAddresses;
        temp_wallet_for_validation.mapWalletTx = temp_mapWalletTx;
        temp_wallet_for_validation.fIsHDWallet = temp_fIsHDWallet;
        temp_wallet_for_validation.mapAddressToPath = temp_mapAddressToPath;
        temp_wallet_for_validation.mapPathToAddress = temp_mapPathToAddress;
        temp_wallet_for_validation.nHDExternalChainIndex = temp_nHDExternalChainIndex;
        temp_wallet_for_validation.nHDInternalChainIndex = temp_nHDInternalChainIndex;
        temp_wallet_for_validation.nHDAccountIndex = temp_nHDAccountIndex;
        temp_wallet_for_validation.masterKey = temp_masterKey;
    }

    std::string consistency_error;
    if (!temp_wallet_for_validation.ValidateConsistency(consistency_error)) {
        // Consistency check failed - wallet is corrupted
        std::cerr << "ERROR: Wallet consistency validation failed: "
                  << consistency_error << std::endl;
        return false;  // Reject corrupted wallet
    }

    // All data loaded successfully - now atomically replace wallet contents
    // CID 1675316 FIX: All member variable writes below are protected by lock acquired at line 1260
    // The lock_guard ensures thread-safe access throughout this function
    {
        // Explicit scope to document that lock is held for all assignments
        // (lock was acquired at function start: std::lock_guard<std::mutex> lock(cs_wallet);)
        mapKeys = std::move(temp_mapKeys);
        mapCryptedKeys = std::move(temp_mapCryptedKeys);
        vchAddresses = std::move(temp_vchAddresses);
        mapWalletTx = std::move(temp_mapWalletTx);
        // CID 1675177 FIX: Use std::move to avoid unnecessary copy
        // temp_defaultAddress is a local variable that's no longer used after assignment
        defaultAddress = std::move(temp_defaultAddress);
        // CID 1675177 FIX: Use std::move to avoid unnecessary copy
        // temp_masterKey is a local variable that's no longer used after assignment
        masterKey = std::move(temp_masterKey);
        fWalletUnlocked = temp_fWalletUnlocked;

        // HD wallet data
        // CID 1675319 FIX: All HD wallet member variable writes below are protected by lock acquired at line 1260
        fIsHDWallet = temp_fIsHDWallet;
        vchEncryptedMnemonic = std::move(temp_vchEncryptedMnemonic);
        // FIX-009: Use assign() for SecureAllocator vectors
        vchMnemonicIV.assign(temp_vchMnemonicIV.begin(), temp_vchMnemonicIV.end());
        // CID 1675177 FIX: Use std::move to avoid unnecessary copy
        // temp_hdMasterKey is a local variable that's no longer used after assignment
        hdMasterKey = std::move(temp_hdMasterKey);
        fHDMasterKeyEncrypted = temp_fHDMasterKeyEncrypted;
        // LP-7 (v7) variable-length encrypted-seed + per-record MACs
        vchEncryptedHDMasterKey = std::move(temp_vchEncryptedHDMasterKey);
        vchHDMasterKeyMAC = std::move(temp_vchHDMasterKeyMAC);
        vchMnemonicMAC = std::move(temp_vchMnemonicMAC);
        // FIX-009: Use assign() for SecureAllocator vectors
        vchHDMasterKeyIV.assign(temp_vchHDMasterKeyIV.begin(), temp_vchHDMasterKeyIV.end());
        nHDAccountIndex = temp_nHDAccountIndex;
        nHDExternalChainIndex = temp_nHDExternalChainIndex;
        nHDInternalChainIndex = temp_nHDInternalChainIndex;
        mapAddressToPath = std::move(temp_mapAddressToPath);
        mapPathToAddress = std::move(temp_mapPathToAddress);

        // BUG #100 FIX: Set defaultAddress for HD wallets after loading
        // Without this, GetPubKeyHash() returns empty for loaded HD wallets,
        // causing mined blocks to not be credited to the wallet
        if (fIsHDWallet && !mapPathToAddress.empty() && !defaultAddress.IsValid()) {
            // Use the first receiving address (path 0/0/0) as default
            CHDKeyPath firstPath = CHDKeyPath::ReceiveAddress(0, 0);
            auto it = mapPathToAddress.find(firstPath);
            if (it != mapPathToAddress.end()) {
                defaultAddress = it->second;
            }
        }

        // BUG #56 FIX: Copy best block pointer
        // CID 1675318 FIX: All member variable writes below are protected by lock acquired at line 1260
        m_bestBlockHash = temp_bestBlockHash;
        m_bestBlockHeight = temp_bestBlockHeight;

        // DFMP v2.0: Copy MIK data
        fHasMIK = temp_fHasMIK;
        fMIKRegistered = temp_fMIKRegistered;
        vchMIKPubKey = std::move(temp_vchMIKPubKey);
        vchEncryptedMIKPrivKey = std::move(temp_vchEncryptedMIKPrivKey);
        vchMIKPrivKeyMAC = std::move(temp_vchMIKPrivKeyMAC);
        vchMIKPrivKeyIV = std::move(temp_vchMIKPrivKeyIV);

        if (temp_fHasMIK) {
            // Reconstruct m_mik from loaded data
            if (!temp_vchMIKPrivKey.empty()) {
                // Unencrypted wallet - restore full MIK
                m_mik = std::make_unique<DFMP::CMiningIdentityKey>();
                m_mik->pubkey = vchMIKPubKey;
                m_mik->privkey.assign(temp_vchMIKPrivKey.begin(), temp_vchMIKPrivKey.end());
                m_mik->identity = DFMP::DeriveIdentityFromMIK(vchMIKPubKey);
                m_mikIdentity = m_mik->identity;
            } else if (masterKey.IsValid() && vchEncryptedMIKPrivKey.empty()) {
                // Bug recovery: wallet was encrypted after MIK generation but
                // MIK private key was never encrypted (pre-v3.0.4 bug).
                // Clear broken MIK so it gets regenerated on next mining attempt.
                std::cerr << "[WALLET] WARNING: MIK private key lost during wallet encryption (pre-v3.0.4 bug)" << std::endl;
                std::cerr << "[WALLET] MIK will be automatically regenerated on next mining attempt" << std::endl;
                fHasMIK = false;
                vchMIKPubKey.clear();
                m_mikIdentity = DFMP::Identity();
            } else {
                // Encrypted wallet - just set the identity from pubkey
                // m_mik will be reconstructed when wallet is unlocked
                m_mikIdentity = DFMP::DeriveIdentityFromMIK(vchMIKPubKey);
            }
            if (fHasMIK) {
                std::cout << "[WALLET] Loaded MIK identity: " << m_mikIdentity.GetHex() << std::endl;
            }
        }

        // v6: Restore sent transaction history
        mapSentTx = std::move(temp_mapSentTx);

        // LP-7: record the on-disk format version + whether this encrypted wallet
        // carries a plaintext HD seed (pre-v7 bug) and therefore needs migration
        // on next unlock.
        m_loadedFileVersion = version;
        m_fNeedsSeedMigration = temp_fNeedsSeedMigration;
        // LP-7 (F1 round 3): if migration was armed specifically because a v7 ENCRYPTED
        // wallet carried an empty-MAC (obfuscation-key) mnemonic, this is the
        // defer-and-preserve / BIP39-passphrase-required state. Surface it so the UI can
        // prompt for the passphrase rather than presenting the wallet as fully migrated.
        m_migrationDeferredPassphrase = (mnemonicNeedsMigration && isEncrypted);

        m_walletFile = filename;  // Set wallet file path only on successful load

        // LP-7 (force-migrate / round-3 SURVIVING-LEAK): if this encrypted wallet
        // was loaded with a plaintext HD seed at rest (pre-fix bug), emit a LOUD
        // one-time-per-load CRITICAL so the operator/UI is driven to unlock-and-
        // migrate. A receive/mine-only wallet would otherwise sit plaintext forever
        // while reporting "encrypted". The per-autosave warning (SaveUnlocked) keeps
        // surfacing it until the migration runs on the next Unlock.
        if (m_fNeedsSeedMigration) {
            std::cerr << "[Wallet] CRITICAL: wallet seed is stored UNENCRYPTED at rest "
                         "despite the wallet being encrypted (fixed bug LP-7). Unlock once "
                         "to complete a one-time security upgrade." << std::endl;
        }
    }

    return true;
}

// Public Save() method - acquires lock and calls SaveUnlocked()
bool CWallet::Save(const std::string& filename) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return SaveUnlocked(filename);
}

// Private SaveUnlocked() method - assumes caller already holds cs_wallet lock
// ============================================================================
// LP-7 READER/WRITER VERSION-GATE SYMMETRY TABLE (authoritative)
// ----------------------------------------------------------------------------
// This writer (SaveUnlocked) emits ONLY v6 ("DILWLT06", writeLegacyV6==true) or
// v7 ("DILWLT07"). The matching reader is CWallet::Load. EVERY field whose
// presence/layout depends on the file version is listed below; for each, the
// writer's gate MUST exactly match the reader's gate. A field present in a v6
// write MUST be read in v6; a v7-only field MUST be `!writeLegacyV6`-gated on
// write AND `version >= WALLET_FILE_VERSION_7` on read. ZERO mismatches allowed.
//
//  field                | write-gate (SaveUnlocked)          | read-gate (Load)                 | status
//  ---------------------+------------------------------------+----------------------------------+-------
//  header magic+version | writeLegacyV6 ? v6 : v7            | reads+validates version 1..7     | MATCH
//  HMAC + salt block    | unconditional (writer always >=v6) | version >= 3                     | MATCH (v6,v7 >=3)
//  v1/v2 reserved[16]   | never written                      | version < 3 (else-branch)        | MATCH (writer never <v3)
//  master-key MAC       | uncond. within masterKey.IsValid() | v3+: always present (uncond.)    | MATCH
//  mnemonic MAC         | if (!writeLegacyV6)                | if (version >= V7)               | MATCH
//  HD-master block      | writeLegacyV6 ? legacy-slots : v7  | version >= V7 ? v7 : legacy      | MATCH
//  HD-master MAC        | v7 encrypted branch (!writeLegacyV6)| v7 encrypted branch (>= V7)     | MATCH
//  wtx fCoinbase        | unconditional (writer always >=v6) | version >= 4                     | MATCH (v6,v7 >=4)
//  MIK block (hasMIK..) | unconditional (writer always >=v6) | version >= 5                     | MATCH (v6,v7 >=5)
//  MIK private-key MAC  | if (!writeLegacyV6)   [LP-7 fix]    | if (version >= V7)               | MATCH
//  mapSentTx            | unconditional (writer always >=v6) | version >= 6                     | MATCH (v6,v7 >=6)
//
// Per-address spending-key MAC (macLen) is a v3+ field written unconditionally
// and read unconditionally for v3+ (v1/v2 seek-back), so it is NOT version-
// conditional within this writer's v6/v7 output — symmetric by construction.
//
// INVARIANT: every v7-only per-record MAC field (mnemonic, MIK) is
// `!writeLegacyV6`-gated on write. The HD-master MAC lives inside the v7-only
// encrypted HD-master branch, so it is structurally excluded from the v6 path.
// If you add ANY new version-conditional field, add a row here and confirm the
// write-gate equals the read-gate BEFORE merging — the MIK-MAC desync
// (round-5 BLOCKER-5) was exactly a missing row in this table.
// ============================================================================
bool CWallet::SaveUnlocked(const std::string& filename) const {
    // Use current wallet file if no filename specified
    std::string saveFile = filename.empty() ? m_walletFile : filename;
    if (saveFile.empty()) {
        return false;  // No wallet file specified
    }

    // LP-7 (force-migrate / round-3 SURVIVING-LEAK): re-emit the CRITICAL on EVERY
    // save while the seed is still plaintext-at-rest (not once). An armed wallet
    // that is never unlocked is autosaved repeatedly (receive/mine); each save
    // re-writes the plaintext seed to disk, so each save must re-surface the
    // remediation. This fires for the legacy v6 path (which re-emits v6 plaintext)
    // until the next Unlock runs MigrateToEncryptedSeedV7Unlocked() and clears the
    // flag. Caller holds cs_wallet (SaveUnlocked precondition), so the read is safe.
    if (masterKey.IsValid() && m_fNeedsSeedMigration) {
        std::cerr << "[Wallet] CRITICAL: wallet seed is stored UNENCRYPTED at rest "
                     "despite the wallet being encrypted (fixed bug LP-7). Unlock once "
                     "to complete a one-time security upgrade." << std::endl;
    }

    // SEC-001 FIX: Atomic file write pattern
    // Write to temporary file first, then atomically rename on success
    // This prevents corruption if write fails mid-operation
    std::string tempFile = saveFile + ".tmp";

    // FIX-002 (PERSIST-003): Set secure file permissions before creating file
    // Only owner can read/write (0600), prevents other users from reading private keys
    #ifndef _WIN32
        mode_t old_umask = umask(0077);  // Remove all group/other permissions
    #endif

    std::ofstream file(tempFile, std::ios::binary);

    #ifndef _WIN32
        umask(old_umask);  // Restore original umask
        // Double-check permissions were applied correctly
        // CID 1675198 FIX: Check return value of chmod to ensure permissions are set
        // chmod returns 0 on success, -1 on error
        if (file.is_open()) {
            if (chmod(tempFile.c_str(), S_IRUSR | S_IWUSR) != 0) {
                // Failed to set permissions - log warning but continue (non-fatal)
                std::cerr << "WARNING: Failed to set secure permissions on wallet file: " << tempFile << std::endl;
            }
        }
    #endif

    if (!file.is_open()) {
        return false;
    }

    // FIX-011 (PERSIST-001): Write header with file integrity HMAC (v3 format)
    // Format: [Magic][Version][Flags][HMAC-placeholder][Salt][Data...]
    //
    // LP-7 (ratified design, version-aware write): SaveUnlocked normally emits v7
    // ("DILWLT07") — variable-length encrypted HD seed + per-record MACs. The ONE
    // exception is a wallet LOADED from a legacy v3-v6 file that has NOT yet been
    // migrated (m_loadedFileVersion < v7): there we re-emit the SAME on-disk version
    // (legacy plaintext-seed layout, no per-record mnemonic/MIK MAC). This is what
    // lets ChangePassphrase rotate the passphrase IN PLACE without promoting the
    // file to v7 — which previously (round 4) re-introduced plaintext-seed-at-rest
    // (BLOCKER-1) and bricked empty-MAC mnemonic/MIK records (BLOCKER-2). The single
    // v6->v7 migration (re-encrypt seed, re-MAC every record) still happens exactly
    // once, on the next Unlock (MigrateToEncryptedSeedV7Unlocked) — which bumps
    // m_loadedFileVersion to v7, so this writer then emits v7 from then on. A freshly
    // created in-memory wallet (m_loadedFileVersion == 0) and an already-v7 wallet
    // both write v7.
    const bool writeLegacyV6 = LegacyRecordKeying();

    if (writeLegacyV6) {
        file.write(WALLET_FILE_MAGIC_V6, 8);  // "DILWLT06" — keep the loaded version
    } else {
        file.write(WALLET_FILE_MAGIC_V7, 8);  // "DILWLT07"
    }
    if (!file.good()) return false;

    uint32_t version = writeLegacyV6 ? WALLET_FILE_VERSION_6 : WALLET_FILE_VERSION_7;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    if (!file.good()) return false;

    // Flags: bit 0 = encrypted, bit 1 = is HD wallet
    uint32_t flags = 0;
    if (masterKey.IsValid()) flags |= 0x01;
    if (fIsHDWallet) flags |= 0x02;
    file.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
    if (!file.good()) return false;

    // FIX-011: Remember position for HMAC (will write real HMAC later)
    // CID 1675266 FIX: Check return value of tellp to ensure position is valid
    // tellp returns -1 on error
    std::streampos hmac_pos = file.tellp();
    if (hmac_pos == std::streampos(-1)) {
        return false;  // Failed to get file position
    }

    // Write placeholder HMAC (zeros for now, will compute and write later)
    std::vector<uint8_t> placeholder_hmac(WALLET_FILE_HMAC_SIZE, 0);
    file.write(reinterpret_cast<const char*>(placeholder_hmac.data()), WALLET_FILE_HMAC_SIZE);
    if (!file.good()) return false;

    // FIX-011: Generate random salt for HMAC
    std::vector<uint8_t> hmac_salt(WALLET_FILE_SALT_SIZE);
    if (!GenerateIV(hmac_salt)) {
        return false;
    }
    // FIX-011: Remember position before writing salt (HMAC covers [Salt][Data...])
    // CID 1675266 FIX: Check return value of tellp to ensure position is valid
    // tellp returns -1 on error
    std::streampos data_start_pos = file.tellp();
    if (data_start_pos == std::streampos(-1)) {
        return false;  // Failed to get file position
    }
    file.write(reinterpret_cast<const char*>(hmac_salt.data()), WALLET_FILE_SALT_SIZE);
    if (!file.good()) return false;

    // Write master key if encrypted
    if (masterKey.IsValid()) {
        uint32_t cryptedKeyLen = static_cast<uint32_t>(masterKey.vchCryptedKey.size());
        file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(masterKey.vchCryptedKey.data()), cryptedKeyLen);
        if (!file.good()) return false;  // SEC-001: Check I/O error

        file.write(reinterpret_cast<const char*>(masterKey.vchSalt.data()), WALLET_CRYPTO_SALT_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(masterKey.vchIV.data()), WALLET_CRYPTO_IV_SIZE);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&masterKey.nDerivationMethod), sizeof(masterKey.nDerivationMethod));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&masterKey.nDeriveIterations), sizeof(masterKey.nDeriveIterations));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        // FIX-008 (CRYPT-007): Save MAC for authenticated encryption
        uint32_t macLen = static_cast<uint32_t>(masterKey.vchMAC.size());
        file.write(reinterpret_cast<const char*>(&macLen), sizeof(macLen));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        if (macLen > 0) {
            file.write(reinterpret_cast<const char*>(masterKey.vchMAC.data()), macLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error
        }
    }

    // Write HD wallet data (v2 only)
    if (fIsHDWallet) {
        // Write encrypted mnemonic
        uint32_t mnemonicLen = static_cast<uint32_t>(vchEncryptedMnemonic.size());
        file.write(reinterpret_cast<const char*>(&mnemonicLen), sizeof(mnemonicLen));
        if (!file.good()) return false;
        if (mnemonicLen > 0) {
            file.write(reinterpret_cast<const char*>(vchEncryptedMnemonic.data()), mnemonicLen);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(vchMnemonicIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;

            // LP-7 (v7): write the mnemonic MAC (variable-length; empty for the
            // unencrypted-obfuscation case). LEGACY v3-v6 files never carried a
            // per-record mnemonic MAC, so when re-emitting at the loaded v6 version
            // we must NOT write the mnMacLen field — the v6 reader does not expect it
            // and writing it would desync the stream. (The mnemonic stays readable on
            // reload via the legacy unauthenticated path; it gains an authenticated
            // MAC only at the v6->v7 Unlock migration.)
            if (!writeLegacyV6) {
                uint32_t mnMacLen = static_cast<uint32_t>(vchMnemonicMAC.size());
                file.write(reinterpret_cast<const char*>(&mnMacLen), sizeof(mnMacLen));
                if (!file.good()) return false;
                if (mnMacLen > 0) {
                    file.write(reinterpret_cast<const char*>(vchMnemonicMAC.data()), mnMacLen);
                    if (!file.good()) return false;
                }
            }
        }

        // LP-7 (S-007 / S-001): NEVER write a plaintext seed for an encrypted
        // wallet. The writer is one-way: if the HD master key is encrypted we
        // emit ONLY the variable-length ciphertext; if (impossibly) the
        // ciphertext is missing, refuse the save rather than fall back to
        // plaintext.
        uint8_t encrypted_flag = fHDMasterKeyEncrypted ? 1 : 0;

        if (writeLegacyV6) {
            // LP-7 (ratified): re-emit the EXACT legacy v3-v6 HD-master layout when
            // the file stays at its loaded version (ChangePassphrase-in-place). A
            // legacy-loaded wallet keeps its seed in the fixed plaintext slots and is
            // flagged for migration on next Unlock — we are NOT migrating here, so we
            // preserve that on-disk shape byte-for-byte:
            //   [seed32][chaincode32][depth][fp][ci][encrypted_flag][IV if flagged]
            // This is NOT a NEW plaintext-at-rest exposure: the seed was already
            // plaintext in this v6 file before ChangePassphrase, Load re-arms
            // m_fNeedsSeedMigration for it, and the next Unlock encrypts it + rewrites
            // at v7. Writing v7 here instead (with fHDMasterKeyEncrypted==false) is
            // exactly round-4 BLOCKER-1: it would mint a v7-labelled plaintext-seed
            // file that permanently disarms migration. (Mirrors the pre-LP-7 writer.)
            //
            // FAIL-CLOSED GUARD (red-team LOW-1 hardening): the legacy-v6 layout
            // carries the seed in the FIXED plaintext slots written just below. If
            // fHDMasterKeyEncrypted is true at this point, the in-memory seed/chaincode
            // have already been scrubbed (memory_cleanse) by EncryptHDMasterKey — so
            // these slots would persist 32+32 ZERO bytes, corrupting the wallet
            // irrecoverably. By construction this combination is impossible (Unlock
            // promotes m_loadedFileVersion to v7 atomically under cs_wallet the instant
            // it scrubs, so writeLegacyV6 is never true while encrypted), but we refuse
            // here as belt-and-suspenders so the corruption is structurally impossible
            // even if a future refactor introduces a scrub-without-promote caller. This
            // mirrors the refuse-on-empty-ciphertext guard in the encrypted branch below.
            if (fHDMasterKeyEncrypted) {
                std::cerr << "[Wallet] CRITICAL: refusing legacy-v6 save of an encrypted "
                             "HD wallet — the plaintext seed slots have been scrubbed and "
                             "writing them would corrupt the wallet (version promotion to "
                             "v7 must precede any save of an encrypted seed)" << std::endl;
                return false;
            }
            // STRUCTURAL FAIL-CLOSED GUARD (red-team HIGH-1): close the LP-7
            // plaintext-seed-at-rest leak on the legacy-v6 write path.
            //
            // The dangerous state is masterKey.IsValid()==true (encrypted in memory)
            // && fHDMasterKeyEncrypted==false (HD seed still plaintext) flowing to the
            // 32-byte plaintext-seed write below. There are TWO ways to reach that
            // state on the v6 path, and they are NOT equivalent:
            //
            //   (1) LEGITIMATE (ratified BLOCKER-1, Test 7): a wallet LOADED from a
            //       legacy v3-v6 file is always re-armed for migration on load
            //       (m_fNeedsSeedMigration=true, see Load ~line 2191). ChangePassphrase
            //       rewrites it IN PLACE at v6 — preserving the PRE-EXISTING plaintext
            //       seed shape and deferring re-encryption to the next Unlock's
            //       migration. This is NOT a new exposure: the seed was already
            //       plaintext at rest, and migration is still armed to fix it.
            //
            //   (2) LEAK (red-team HIGH-1): a wallet that is encrypted-in-memory with a
            //       plaintext seed but is NOT armed for migration (m_fNeedsSeedMigration
            //       ==false) — e.g. an EncryptWallet that aborted mid-HD-step without
            //       rolling back. Persisting the plaintext seed here is a genuine new
            //       LP-7 exposure with no migration arm to ever fix it.
            //
            // Discriminator: refuse exactly the un-armed encrypted state. A migration-
            // armed legacy wallet (case 1) is allowed to round-trip its pre-existing v6
            // shape; an un-armed encrypted wallet (case 2) is refused. (The
            // fHDMasterKeyEncrypted guard above independently catches the scrubbed-seed
            // corruption window. This guard closes the plaintext-seed leak.)
            if (masterKey.IsValid() && !m_fNeedsSeedMigration) {
                std::cerr << "[Wallet] CRITICAL: refusing legacy-v6 plaintext-seed save of an "
                             "encrypted HD wallet that is NOT armed for seed migration — the "
                             "wallet has a master key but the HD seed is not encrypted "
                             "(fHDMasterKeyEncrypted==false) and m_fNeedsSeedMigration==false; "
                             "persisting a plaintext seed for an encrypted wallet with no "
                             "migration arm is the LP-7 plaintext-at-rest exposure. The HD seed "
                             "must be encrypted (EncryptHDMasterKey) before any save of such a "
                             "wallet." << std::endl;
                return false;
            }
            file.write(reinterpret_cast<const char*>(hdMasterKey.seed), 32);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(hdMasterKey.chaincode), 32);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.depth), sizeof(hdMasterKey.depth));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.fingerprint), sizeof(hdMasterKey.fingerprint));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.child_index), sizeof(hdMasterKey.child_index));
            if (!file.good()) return false;

            file.write(reinterpret_cast<const char*>(&encrypted_flag), 1);
            if (!file.good()) return false;
            if (fHDMasterKeyEncrypted) {
                file.write(reinterpret_cast<const char*>(vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
                if (!file.good()) return false;
            }
        } else if (fHDMasterKeyEncrypted) {
            if (vchEncryptedHDMasterKey.empty()) {
                // Encrypted-but-no-ciphertext is a programming error; refuse to
                // persist rather than risk writing/keeping plaintext.
                std::cerr << "[Wallet] CRITICAL: encrypted HD wallet has no seed ciphertext — refusing to save" << std::endl;
                return false;
            }
            // Write the encryption flag, then the variable-length ciphertext +
            // metadata. NO plaintext seed/chaincode slots are written.
            file.write(reinterpret_cast<const char*>(&encrypted_flag), 1);
            if (!file.good()) return false;

            uint32_t hdEncLen = static_cast<uint32_t>(vchEncryptedHDMasterKey.size());
            file.write(reinterpret_cast<const char*>(&hdEncLen), sizeof(hdEncLen));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(vchEncryptedHDMasterKey.data()), hdEncLen);
            if (!file.good()) return false;

            // HD-master MAC (variable-length; required non-empty for v7)
            uint32_t hdMacLen = static_cast<uint32_t>(vchHDMasterKeyMAC.size());
            file.write(reinterpret_cast<const char*>(&hdMacLen), sizeof(hdMacLen));
            if (!file.good()) return false;
            if (hdMacLen > 0) {
                file.write(reinterpret_cast<const char*>(vchHDMasterKeyMAC.data()), hdMacLen);
                if (!file.good()) return false;
            }

            // Metadata (depth/fingerprint/child_index) — non-secret
            file.write(reinterpret_cast<const char*>(&hdMasterKey.depth), sizeof(hdMasterKey.depth));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.fingerprint), sizeof(hdMasterKey.fingerprint));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.child_index), sizeof(hdMasterKey.child_index));
            if (!file.good()) return false;

            // IV
            file.write(reinterpret_cast<const char*>(vchHDMasterKeyIV.data()), WALLET_CRYPTO_IV_SIZE);
            if (!file.good()) return false;
        } else {
            // Unencrypted HD wallet: seed is plaintext by design (no passphrase
            // set). Write the fixed 32+32 plaintext slots + metadata. An
            // unencrypted seed length of 0 (variable-length) marks "plaintext".
            //
            // STRUCTURAL FAIL-CLOSED GUARD (Cursor HIGH-1): refuse to persist a
            // plaintext HD seed whenever the wallet is encrypted in memory. The
            // only legitimate way to reach this branch is an UNencrypted wallet
            // (no passphrase master key). If a master key exists
            // (masterKey.IsValid()) but fHDMasterKeyEncrypted is still false, the
            // wallet is encrypted-in-memory with a plaintext seed — exactly the
            // LP-7 plaintext-seed-at-rest exposure (e.g. an EncryptWallet that
            // aborted mid-HD-step without rolling back). Writing the v7 plaintext
            // layout here would mint a v7-labelled file carrying encrypted
            // spending keys alongside a 32-byte plaintext seed, with no migration
            // arm on reload (the loader only arms migration for the LEGACY layout).
            // Refuse the save so this combination is structurally impossible. This
            // mirrors the refuse guards in the legacy-v6 branch above and the
            // empty-ciphertext check in the encrypted branch.
            if (masterKey.IsValid()) {
                std::cerr << "[Wallet] CRITICAL: refusing v7 plaintext-seed save of an "
                             "encrypted HD wallet — the wallet has a master key but the HD "
                             "seed is not encrypted (fHDMasterKeyEncrypted==false); persisting "
                             "a plaintext seed for an encrypted wallet is the LP-7 "
                             "plaintext-at-rest exposure. The HD seed must be encrypted "
                             "(EncryptHDMasterKey) before any save of an encrypted wallet."
                          << std::endl;
                return false;
            }
            file.write(reinterpret_cast<const char*>(&encrypted_flag), 1);
            if (!file.good()) return false;

            uint32_t hdEncLen = 0;  // 0 ⇒ plaintext fixed-slot layout follows
            file.write(reinterpret_cast<const char*>(&hdEncLen), sizeof(hdEncLen));
            if (!file.good()) return false;

            file.write(reinterpret_cast<const char*>(hdMasterKey.seed), 32);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(hdMasterKey.chaincode), 32);
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.depth), sizeof(hdMasterKey.depth));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.fingerprint), sizeof(hdMasterKey.fingerprint));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&hdMasterKey.child_index), sizeof(hdMasterKey.child_index));
            if (!file.good()) return false;
        }

        // Write HD chain state
        file.write(reinterpret_cast<const char*>(&nHDAccountIndex), sizeof(nHDAccountIndex));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&nHDExternalChainIndex), sizeof(nHDExternalChainIndex));
        if (!file.good()) return false;
        file.write(reinterpret_cast<const char*>(&nHDInternalChainIndex), sizeof(nHDInternalChainIndex));
        if (!file.good()) return false;

        // Write HD path mappings
        uint32_t numPaths = static_cast<uint32_t>(mapPathToAddress.size());
        file.write(reinterpret_cast<const char*>(&numPaths), sizeof(numPaths));
        if (!file.good()) return false;

        for (const auto& pair : mapPathToAddress) {
            const CHDKeyPath& path = pair.first;
            const CDilithiumAddress& address = pair.second;

            // Write path indices count
            uint32_t numIndices = static_cast<uint32_t>(path.indices.size());
            file.write(reinterpret_cast<const char*>(&numIndices), sizeof(numIndices));
            if (!file.good()) return false;

            // Write indices
            for (uint32_t index : path.indices) {
                file.write(reinterpret_cast<const char*>(&index), sizeof(index));
                if (!file.good()) return false;
            }

            // Write address
            file.write(reinterpret_cast<const char*>(address.GetData().data()), 21);
            if (!file.good()) return false;
        }
    }

    // Write keys
    if (masterKey.IsValid()) {
        // Encrypted wallet - write encrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapCryptedKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        for (const auto& pair : mapCryptedKeys) {
            const CDilithiumAddress& addr = pair.first;
            const CEncryptedKey& encKey = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write public key
            file.write(reinterpret_cast<const char*>(encKey.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write encrypted private key
            uint32_t cryptedKeyLen = static_cast<uint32_t>(encKey.vchCryptedKey.size());
            file.write(reinterpret_cast<const char*>(&cryptedKeyLen), sizeof(cryptedKeyLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error
            file.write(reinterpret_cast<const char*>(encKey.vchCryptedKey.data()), cryptedKeyLen);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write IV
            file.write(reinterpret_cast<const char*>(encKey.vchIV.data()), 16);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // FIX-008 (CRYPT-007): Save MAC for authenticated encryption
            uint32_t macLen = static_cast<uint32_t>(encKey.vchMAC.size());
            file.write(reinterpret_cast<const char*>(&macLen), sizeof(macLen));
            if (!file.good()) return false;  // SEC-001: Check I/O error
            if (macLen > 0) {
                file.write(reinterpret_cast<const char*>(encKey.vchMAC.data()), macLen);
                if (!file.good()) return false;  // SEC-001: Check I/O error
            }
        }
    } else {
        // Unencrypted wallet - write unencrypted keys
        uint32_t numKeys = static_cast<uint32_t>(mapKeys.size());
        file.write(reinterpret_cast<const char*>(&numKeys), sizeof(numKeys));
        if (!file.good()) return false;  // SEC-001: Check I/O error

        for (const auto& pair : mapKeys) {
            const CDilithiumAddress& addr = pair.first;
            const CKey& key = pair.second;

            // Write address
            file.write(reinterpret_cast<const char*>(addr.GetData().data()), 21);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write public key
            file.write(reinterpret_cast<const char*>(key.vchPubKey.data()), DILITHIUM_PUBLICKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error

            // Write private key
            file.write(reinterpret_cast<const char*>(key.vchPrivKey.data()), DILITHIUM_SECRETKEY_SIZE);
            if (!file.good()) return false;  // SEC-001: Check I/O error
        }
    }

    // Write default address
    uint8_t hasDefault = defaultAddress.IsValid() ? 1 : 0;
    file.write(reinterpret_cast<const char*>(&hasDefault), 1);
    if (!file.good()) return false;  // SEC-001: Check I/O error
    if (hasDefault) {
        file.write(reinterpret_cast<const char*>(defaultAddress.GetData().data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // Write transactions
    uint32_t numTxs = static_cast<uint32_t>(mapWalletTx.size());
    file.write(reinterpret_cast<const char*>(&numTxs), sizeof(numTxs));
    if (!file.good()) return false;  // SEC-001: Check I/O error

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        file.write(reinterpret_cast<const char*>(wtx.txid.begin()), 32);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.vout), sizeof(wtx.vout));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.nValue), sizeof(wtx.nValue));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(wtx.address.GetData().data()), 21);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        uint8_t fSpent = wtx.fSpent ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&fSpent), 1);
        if (!file.good()) return false;  // SEC-001: Check I/O error
        file.write(reinterpret_cast<const char*>(&wtx.nHeight), sizeof(wtx.nHeight));
        if (!file.good()) return false;  // SEC-001: Check I/O error
        uint8_t fCoinbase = wtx.fCoinbase ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&fCoinbase), 1);
        if (!file.good()) return false;  // SEC-001: Check I/O error
    }

    // BUG #56 FIX: Write best block pointer (Bitcoin Core pattern)
    // This enables incremental rescanning on startup instead of full UTXO scan
    file.write(reinterpret_cast<const char*>(m_bestBlockHash.begin()), 32);
    if (!file.good()) return false;
    file.write(reinterpret_cast<const char*>(&m_bestBlockHeight), sizeof(m_bestBlockHeight));
    if (!file.good()) return false;

    // DFMP v2.0: Write MIK (Mining Identity Key) data
    uint8_t hasMIK = fHasMIK ? 1 : 0;
    file.write(reinterpret_cast<const char*>(&hasMIK), 1);
    if (!file.good()) return false;

    if (fHasMIK) {
        // Write MIK public key
        uint32_t pubkeyLen = static_cast<uint32_t>(vchMIKPubKey.size());
        file.write(reinterpret_cast<const char*>(&pubkeyLen), sizeof(pubkeyLen));
        if (!file.good()) return false;
        if (pubkeyLen > 0) {
            file.write(reinterpret_cast<const char*>(vchMIKPubKey.data()), pubkeyLen);
            if (!file.good()) return false;
        }

        // Write encrypted MIK private key (if wallet is encrypted)
        uint32_t encPrivKeyLen = static_cast<uint32_t>(vchEncryptedMIKPrivKey.size());
        file.write(reinterpret_cast<const char*>(&encPrivKeyLen), sizeof(encPrivKeyLen));
        if (!file.good()) return false;
        if (encPrivKeyLen > 0) {
            file.write(reinterpret_cast<const char*>(vchEncryptedMIKPrivKey.data()), encPrivKeyLen);
            if (!file.good()) return false;
        }

        // Write MIK private key IV
        uint32_t ivLen = static_cast<uint32_t>(vchMIKPrivKeyIV.size());
        file.write(reinterpret_cast<const char*>(&ivLen), sizeof(ivLen));
        if (!file.good()) return false;
        if (ivLen > 0) {
            file.write(reinterpret_cast<const char*>(vchMIKPrivKeyIV.data()), ivLen);
            if (!file.good()) return false;
        }

        // LP-7 (v7): write the MIK private-key MAC (variable-length; empty when
        // the wallet is unencrypted / no encrypted MIK present). LEGACY v3-v6 files
        // never carried a per-record MIK MAC, so when re-emitting at the loaded v6
        // version (ChangePassphrase-in-place / non-HD legacy autosave) we must NOT
        // write the mikMacLen field — the v6 reader does not expect it (it gates the
        // read on version >= WALLET_FILE_VERSION_7) and writing it would desync the
        // stream and silently corrupt the MIK / sent-history / best-block fields that
        // follow. This MUST mirror the mnemonic-MAC gating above exactly. (The MIK
        // gains its authenticated MAC at the v6->v7 Unlock migration, same as the
        // mnemonic — see MigrateToEncryptedSeedV7Unlocked.) See the reader/writer
        // version-gate symmetry table above SaveUnlocked: EVERY v7-only per-record
        // MAC field is !writeLegacyV6-gated.
        if (!writeLegacyV6) {
            uint32_t mikMacLen = static_cast<uint32_t>(vchMIKPrivKeyMAC.size());
            file.write(reinterpret_cast<const char*>(&mikMacLen), sizeof(mikMacLen));
            if (!file.good()) return false;
            if (mikMacLen > 0) {
                file.write(reinterpret_cast<const char*>(vchMIKPrivKeyMAC.data()), mikMacLen);
                if (!file.good()) return false;
            }
        }

        // Write MIK registered flag
        uint8_t mikRegistered = fMIKRegistered ? 1 : 0;
        file.write(reinterpret_cast<const char*>(&mikRegistered), 1);
        if (!file.good()) return false;

        // Write unencrypted MIK private key (if wallet is NOT encrypted)
        if (m_mik && !masterKey.IsValid()) {
            uint8_t hasUnencryptedMIK = 1;
            file.write(reinterpret_cast<const char*>(&hasUnencryptedMIK), 1);
            if (!file.good()) return false;

            uint32_t privkeyLen = static_cast<uint32_t>(m_mik->privkey.size());
            file.write(reinterpret_cast<const char*>(&privkeyLen), sizeof(privkeyLen));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(m_mik->privkey.data()), privkeyLen);
            if (!file.good()) return false;
        } else {
            uint8_t hasUnencryptedMIK = 0;
            file.write(reinterpret_cast<const char*>(&hasUnencryptedMIK), 1);
            if (!file.good()) return false;
        }
    }

    // v6: Write sent transaction history (mapSentTx)
    {
        uint32_t numSentTx = static_cast<uint32_t>(mapSentTx.size());
        file.write(reinterpret_cast<const char*>(&numSentTx), sizeof(numSentTx));
        if (!file.good()) return false;

        for (const auto& [txid, stx] : mapSentTx) {
            // Write txid (32 bytes)
            file.write(reinterpret_cast<const char*>(txid.begin()), 32);
            if (!file.good()) return false;

            // Write recipient address (21 bytes: 1 version + 20 hash)
            const auto& addrData = stx.toAddress.GetData();
            if (addrData.size() == 21) {
                file.write(reinterpret_cast<const char*>(addrData.data()), 21);
            } else {
                // Pad with zeros if address is invalid (shouldn't happen)
                std::vector<uint8_t> zeroPad(21, 0);
                file.write(reinterpret_cast<const char*>(zeroPad.data()), 21);
            }
            if (!file.good()) return false;

            // Write value, fee, time, height
            file.write(reinterpret_cast<const char*>(&stx.nValue), sizeof(stx.nValue));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&stx.nFee), sizeof(stx.nFee));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&stx.nTime), sizeof(stx.nTime));
            if (!file.good()) return false;
            file.write(reinterpret_cast<const char*>(&stx.nHeight), sizeof(stx.nHeight));
            if (!file.good()) return false;
        }
    }

    // FIX-011 (PERSIST-001): Compute and write file integrity HMAC
    // HMAC covers all data from HMAC field onwards (includes salt and all wallet data)
    // CID 1675266 FIX: Check return value of tellp to ensure position is valid
    // tellp returns -1 on error
    std::streampos end_pos = file.tellp();
    if (end_pos == std::streampos(-1)) {
        std::remove(tempFile.c_str());
        return false;  // Failed to get file position
    }

    // FIX-004 (PERSIST-002): Flush data before reopening for read
    file.flush();
    file.close();

    // Reopen file for reading to compute HMAC
    std::ifstream read_file(tempFile, std::ios::binary);
    if (!read_file.is_open()) {
        std::remove(tempFile.c_str());
        return false;
    }

    // Seek to start of HMAC-protected data
    // CID 1675266 FIX: Check return value of seekg to ensure seek succeeded
    // seekg can fail if position is invalid or stream is in bad state
    read_file.seekg(data_start_pos);
    if (!read_file.good()) {
        read_file.close();
        std::remove(tempFile.c_str());
        return false;
    }

    // Read all data from salt position to end
    size_t data_size = static_cast<size_t>(end_pos - data_start_pos);
    std::vector<uint8_t> file_data(data_size);
    // CID 1675266 FIX: Check return value of read to ensure expected bytes were read
    // read() returns stream reference, but we must check gcount() to verify bytes read
    read_file.read(reinterpret_cast<char*>(file_data.data()), data_size);
    if (!read_file.good() || static_cast<size_t>(read_file.gcount()) != data_size) {
        read_file.close();
        std::remove(tempFile.c_str());
        return false;
    }
    read_file.close();

    // Compute HMAC-SHA3-256 over the data
    // Using masterKey as HMAC key if encrypted, or derive from wallet content if not
    std::vector<uint8_t> hmac_key(32);
    if (masterKey.IsValid()) {
        // Use first 32 bytes of master key salt as HMAC key (available without passphrase)
        memcpy(hmac_key.data(), masterKey.vchSalt.data(), std::min(hmac_key.size(), masterKey.vchSalt.size()));
    } else {
        // For unencrypted wallets, derive HMAC key from wallet content (deterministic)
        // FIX: Use first address from mapKeys (sorted order) for consistency between Save and Load
        // vchAddresses is generation order, but mapKeys is sorted - use sorted order for determinism
        std::vector<uint8_t> key_material;
        if (!mapKeys.empty()) {
            // Use first sorted address (deterministic across Save/Load)
            std::vector<uint8_t> addr_data = mapKeys.begin()->first.GetData();
            key_material.insert(key_material.end(), addr_data.begin(), addr_data.end());
        }
        std::vector<uint8_t> default_data = defaultAddress.GetData();
        key_material.insert(key_material.end(), default_data.begin(), default_data.end());

        SHA3_256(key_material.data(), key_material.size(), hmac_key.data());
    }

    // Compute HMAC-SHA3-256
    std::vector<uint8_t> computed_hmac(32);
    HMAC_SHA3_256(hmac_key.data(), hmac_key.size(),
                  file_data.data(), file_data.size(),
                  computed_hmac.data());

    // Reopen file in update mode to write HMAC
    std::fstream update_file(tempFile, std::ios::binary | std::ios::in | std::ios::out);
    if (!update_file.is_open()) {
        std::remove(tempFile.c_str());
        return false;
    }

    // Write the computed HMAC
    // CID 1675266 FIX: Check return value of seekp to ensure seek succeeded
    // seekp can fail if position is invalid or stream is in bad state
    update_file.seekp(hmac_pos);
    if (!update_file.good()) {
        update_file.close();
        std::remove(tempFile.c_str());
        return false;
    }
    update_file.write(reinterpret_cast<const char*>(computed_hmac.data()), WALLET_FILE_HMAC_SIZE);
    if (!update_file.good()) {
        update_file.close();
        std::remove(tempFile.c_str());
        return false;
    }

    // FIX-004 (PERSIST-002): Flush and sync data before closing
    update_file.flush();
    update_file.close();

    // FIX-004 (PERSIST-002): Force data to disk before atomic rename
    // This prevents data loss if power failure occurs between close() and rename()
    #ifndef _WIN32
        // Linux/Unix: fsync() ensures data written to physical disk
        // CID 1675198 FIX: Check return value of fsync to ensure data is synced
        // fsync returns 0 on success, -1 on error
        int fd = open(tempFile.c_str(), O_RDONLY);
        if (fd >= 0) {
            if (fsync(fd) != 0) {
                // Failed to sync - log warning but continue (non-fatal, but data may not be on disk)
                std::cerr << "WARNING: Failed to sync wallet file to disk: " << tempFile << std::endl;
            }
            close(fd);  // Best-effort close (errors are usually non-critical)
        }

        // Also sync parent directory to persist rename operation metadata
        size_t last_slash = saveFile.find_last_of("/\\");
        if (last_slash != std::string::npos) {
            std::string parent_dir = saveFile.substr(0, last_slash);
            if (parent_dir.empty()) parent_dir = ".";
            int dirfd = open(parent_dir.c_str(), O_RDONLY);
            if (dirfd >= 0) {
                if (fsync(dirfd) != 0) {
                    // Failed to sync directory - log warning but continue (non-fatal)
                    std::cerr << "WARNING: Failed to sync wallet directory to disk: " << parent_dir << std::endl;
                }
                close(dirfd);  // Best-effort close (errors are usually non-critical)
            }
        }
    #endif
    // Windows already uses MOVEFILE_WRITE_THROUGH (ensures disk write)

    // WL-012 FIX: Atomically replace old file with new file
    // On Unix, rename() is atomic
    // On Windows, use MoveFileEx with MOVEFILE_REPLACE_EXISTING for atomic replace
    #ifdef _WIN32
        // Windows: Use MoveFileExW for atomic file replacement
        // This is ATOMIC - either fully succeeds or fully fails (no partial writes)
        std::wstring wTempFile(tempFile.begin(), tempFile.end());
        std::wstring wSaveFile(saveFile.begin(), saveFile.end());

        // MOVEFILE_REPLACE_EXISTING: Replace existing file atomically
        // MOVEFILE_WRITE_THROUGH: Ensure data written to disk before returning
        if (!MoveFileExW(wTempFile.c_str(), wSaveFile.c_str(),
                        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            // Move failed - clean up temp file
            std::remove(tempFile.c_str());
            return false;
        }
    #else
        // Unix/Linux: std::rename() is already atomic
        if (std::rename(tempFile.c_str(), saveFile.c_str()) != 0) {
            // Rename failed - clean up temp file
            std::remove(tempFile.c_str());
            return false;
        }
    #endif

    return true;
}

void CWallet::SetWalletFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    m_walletFile = filename;
    m_autoSave = true;  // Enable auto-save when wallet file is set
}

// PERSIST-008 FIX: Write-Ahead Log (WAL) integration
bool CWallet::InitializeWAL(const std::string& wallet_path) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Create WAL instance
    m_wal = std::make_unique<CWalletWAL>();

    // Initialize WAL with wallet path
    if (!m_wal->Initialize(wallet_path)) {
        std::cerr << "[WALLET ERROR] Failed to initialize WAL" << std::endl;
        m_wal.reset();
        return false;
    }

    std::cout << "[WALLET] WAL initialized for " << wallet_path << std::endl;
    return true;
}

// CID 1675307 FIX: Public method acquires lock and calls unlocked version
// WARNING: Do NOT call this method from contexts that already hold cs_wallet lock.
// Use RecoverFromWALUnlocked() instead if you already hold the lock.
// This method unconditionally acquires cs_wallet, which would cause deadlock if
// called from a context that already holds the lock.
bool CWallet::RecoverFromWAL() {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return RecoverFromWALUnlocked();
}

// CID 1675307 FIX: Unlocked version - assumes caller already holds cs_wallet lock
// This allows safe calling from contexts that already hold the lock
bool CWallet::RecoverFromWALUnlocked() {
    // Note: Caller must hold cs_wallet lock

    // Check if WAL is initialized
    if (!m_wal) {
        std::cerr << "[WALLET ERROR] WAL not initialized - call InitializeWAL() first" << std::endl;
        return false;
    }

    // Check for incomplete operations
    std::vector<std::string> incomplete_ops;
    if (!m_wal->HasIncompleteOperations(incomplete_ops)) {
        std::cerr << "[WALLET ERROR] Failed to check for incomplete operations" << std::endl;
        return false;
    }

    if (incomplete_ops.empty()) {
        std::cout << "[WALLET] No incomplete WAL operations found" << std::endl;
        return true;  // Nothing to recover
    }

    // Recover each incomplete operation
    std::cout << "[WALLET RECOVERY] Found " << incomplete_ops.size() << " incomplete operations" << std::endl;

    for (const auto& op_id : incomplete_ops) {
        RecoveryPlan plan;
        if (!CWalletRecovery::AnalyzeOperation(*m_wal, op_id, plan)) {
            std::cerr << "[WALLET RECOVERY ERROR] Failed to analyze operation " << op_id << std::endl;
            return false;
        }

        // Execute recovery (passes this wallet which already holds cs_wallet)
        // CID 1675307 FIX: Recovery functions will use unlocked wallet methods
        if (!CWalletRecovery::ExecuteRecovery(this, *m_wal, plan)) {
            std::cerr << "[WALLET RECOVERY ERROR] Failed to recover operation " << op_id << std::endl;
            return false;
        }

        std::cout << "[WALLET RECOVERY] Successfully recovered operation " << op_id.substr(0, 8) << "..." << std::endl;
    }

    std::cout << "[WALLET RECOVERY] All operations recovered successfully" << std::endl;
    return true;
}

void CWallet::Clear() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    mapKeys.clear();
    mapCryptedKeys.clear();
    vchAddresses.clear();
    mapWalletTx.clear();
    defaultAddress = CDilithiumAddress();

    // Clear encryption state
    fWalletUnlocked = false;
    nUnlockTime = std::chrono::steady_clock::time_point::max();

    // Wipe master key from memory
    if (!vMasterKey.empty()) {
        memory_cleanse(vMasterKey.data_ptr(), vMasterKey.size());
    }

    // Clear master key data
    masterKey = CMasterKey();

    // Clear HD wallet data (securely wipe sensitive data)
    fIsHDWallet = false;
    fHDMasterKeyEncrypted = false;

    // Wipe encrypted mnemonic
    if (!vchEncryptedMnemonic.empty()) {
        memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
    }
    vchEncryptedMnemonic.clear();
    vchMnemonicMAC.clear();   // LP-7
    vchMnemonicIV.clear();

    // Wipe HD master key
    hdMasterKey.Wipe();
    vchHDMasterKeyIV.clear();
    // LP-7: clear v7 encrypted-seed material + migration state
    if (!vchEncryptedHDMasterKey.empty()) {
        memory_cleanse(vchEncryptedHDMasterKey.data(), vchEncryptedHDMasterKey.size());
    }
    vchEncryptedHDMasterKey.clear();
    vchHDMasterKeyMAC.clear();
    m_fNeedsSeedMigration = false;
    m_loadedFileVersion = 0;

    // Clear HD chain state
    nHDAccountIndex = 0;
    nHDExternalChainIndex = 0;
    nHDInternalChainIndex = 0;

    // Clear HD mappings
    mapAddressToPath.clear();
    mapPathToAddress.clear();
}

// FIX-012 (WALLET-002): Wallet Consistency Validation
bool CWallet::ValidateConsistency(std::string& error_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // ========================================================================
    // Check #1: Address Reconstruction Verification
    // ========================================================================
    // Verify that all addresses can be correctly reconstructed from their public keys

    // Check unencrypted keys
    for (const auto& pair : mapKeys) {
        const CDilithiumAddress& address = pair.first;
        const CKey& key = pair.second;
        CDilithiumAddress reconstructed(key.vchPubKey);
        if (!(reconstructed == address)) {
            error_out = "[ADDRESS_RECONSTRUCTION] Mismatch for unencrypted key: expected " +
                       reconstructed.ToString() + ", got " + address.ToString();
            return false;
        }
    }

    // Check encrypted keys (public key is not encrypted, so we can reconstruct)
    for (const auto& pair : mapCryptedKeys) {
        const CDilithiumAddress& address = pair.first;
        const CEncryptedKey& encKey = pair.second;
        CDilithiumAddress reconstructed(encKey.vchPubKey);
        if (!(reconstructed == address)) {
            error_out = "[ADDRESS_RECONSTRUCTION] Mismatch for encrypted key: expected " +
                       reconstructed.ToString() + ", got " + address.ToString();
            return false;
        }
    }

    // ========================================================================
    // Check #3: Transaction Address Validation
    // ========================================================================
    // Verify all transaction addresses belong to wallet
    // (Check #3 is simpler than #2, so we do it before the complex HD check)

    // Optimization: Convert vchAddresses to set for O(log n) lookup
    std::set<CDilithiumAddress> address_set(vchAddresses.begin(), vchAddresses.end());

    for (const auto& pair : mapWalletTx) {
        const COutPoint& outpoint = pair.first;
        const CWalletTx& wtx = pair.second;
        if (address_set.find(wtx.address) == address_set.end()) {
            error_out = "[TX_ADDRESS_VALIDATION] Transaction (" +
                       outpoint.hash.GetHex() + ":" + std::to_string(outpoint.n) +
                       ") references unknown address " + wtx.address.ToString();
            return false;
        }
    }

    // ========================================================================
    // Check #4: Encrypted Key Count Consistency
    // ========================================================================
    // When encrypted, verify key/address counts match

    // BUG #56 FIX: Use IsCryptedUnlocked() to avoid deadlock (we already hold cs_wallet)
    if (IsCryptedUnlocked()) {
        // Encrypted wallet should have no unencrypted keys
        if (!mapKeys.empty()) {
            error_out = "[KEY_COUNT] Encrypted wallet has " +
                       std::to_string(mapKeys.size()) + " unencrypted keys (should be 0)";
            return false;
        }

        // Count of encrypted keys should match address count
        if (mapCryptedKeys.size() != vchAddresses.size()) {
            error_out = "[KEY_COUNT] Address count (" +
                       std::to_string(vchAddresses.size()) +
                       ") != encrypted key count (" +
                       std::to_string(mapCryptedKeys.size()) + ")";
            return false;
        }
    }

    // ========================================================================
    // Check #2: HD Path Gap Detection
    // ========================================================================
    // Detect gaps in HD derivation paths (missing indices)

    if (fIsHDWallet) {
        // External chain: Check indices [0, nHDExternalChainIndex)
        for (uint32_t i = 0; i < nHDExternalChainIndex; i++) {
            // Construct expected path: m/44'/573'/account'/0'/i'
            // NOTE: Dilithion uses hardened derivation at ALL levels for security
            CHDKeyPath expected;
            expected.indices.push_back(44 | 0x80000000);  // BIP44 purpose (hardened)
            expected.indices.push_back(573 | 0x80000000); // Dilithion coin type (hardened)
            expected.indices.push_back(nHDAccountIndex | 0x80000000); // Account (hardened)
            expected.indices.push_back(0 | 0x80000000);   // External chain (hardened for Dilithium security)
            expected.indices.push_back(i | 0x80000000);   // Address index (hardened for Dilithium security)

            if (mapPathToAddress.find(expected) == mapPathToAddress.end()) {
                error_out = "[HD_PATH_GAPS] Missing external chain address at index " +
                           std::to_string(i) + " (path: m/44'/573'/" +
                           std::to_string(nHDAccountIndex) + "'/0'/" + std::to_string(i) + "')";
                return false;
            }
        }

        // Internal chain: Check indices [0, nHDInternalChainIndex)
        for (uint32_t i = 0; i < nHDInternalChainIndex; i++) {
            // Construct expected path: m/44'/573'/account'/1'/i'
            // NOTE: Dilithion uses hardened derivation at ALL levels for security
            CHDKeyPath expected;
            expected.indices.push_back(44 | 0x80000000);  // BIP44 purpose (hardened)
            expected.indices.push_back(573 | 0x80000000); // Dilithion coin type (hardened)
            expected.indices.push_back(nHDAccountIndex | 0x80000000); // Account (hardened)
            expected.indices.push_back(1 | 0x80000000);   // Internal chain (hardened for Dilithium security)
            expected.indices.push_back(i | 0x80000000);   // Address index (hardened for Dilithium security)

            if (mapPathToAddress.find(expected) == mapPathToAddress.end()) {
                error_out = "[HD_PATH_GAPS] Missing internal chain address at index " +
                           std::to_string(i) + " (path: m/44'/573'/" +
                           std::to_string(nHDAccountIndex) + "'/1'/" + std::to_string(i) + "')";
                return false;
            }
        }
    }

    // ========================================================================
    // Check #5: HD Path Bidirectional Mapping Verification
    // ========================================================================
    // Ensure mapAddressToPath and mapPathToAddress are consistent

    if (fIsHDWallet) {
        // Check Address→Path mapping completeness
        for (const auto& pair : mapAddressToPath) {
            const CDilithiumAddress& addr = pair.first;
            const CHDKeyPath& path = pair.second;
            auto it = mapPathToAddress.find(path);
            if (it == mapPathToAddress.end()) {
                error_out = "[HD_BIDIRECTIONAL] Address→Path exists for " +
                           addr.ToString() + " but Path→Address mapping is missing";
                return false;
            }
            if (!(it->second == addr)) {
                error_out = std::string("[HD_BIDIRECTIONAL] Path→Address maps to different address: ") +
                           "expected " + addr.ToString() + ", got " + it->second.ToString();
                return false;
            }
        }

        // Check Path→Address mapping completeness
        for (const auto& pair : mapPathToAddress) {
            const CHDKeyPath& path = pair.first;
            const CDilithiumAddress& addr = pair.second;
            auto it = mapAddressToPath.find(addr);
            if (it == mapAddressToPath.end()) {
                error_out = "[HD_BIDIRECTIONAL] Path→Address exists for address " +
                           addr.ToString() + " but Address→Path mapping is missing";
                return false;
            }
            if (!(it->second == path)) {
                error_out = "[HD_BIDIRECTIONAL] Address→Path maps to different path than expected";
                return false;
            }
        }
    }

    // All checks passed
    error_out = "";
    return true;
}

// ============================================================================
// Phase 5.2: Transaction Creation Helper Functions
// ============================================================================

namespace WalletCrypto {

std::vector<uint8_t> CreateScriptPubKey(const std::vector<uint8_t>& pubkey_hash) {
    std::vector<uint8_t> script;

    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    // This creates a standard P2PKH script (25 bytes for 20-byte hash)

    // OP_DUP (0x76) - Duplicates top stack item
    script.push_back(0x76);

    // OP_HASH160 (0xA9) - Hash top stack item with RIPEMD160(SHA256())
    script.push_back(0xA9);

    // Push pubkey hash length (should be 20 bytes)
    script.push_back(static_cast<uint8_t>(pubkey_hash.size()));

    // Push pubkey hash data
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());

    // OP_EQUALVERIFY (0x88) - Verify top two items are equal
    script.push_back(0x88);

    // OP_CHECKSIG (0xAC) - Verify signature
    script.push_back(0xAC);

    return script;
}

std::vector<uint8_t> CreateScriptSig(const std::vector<uint8_t>& signature,
                                     const std::vector<uint8_t>& pubkey) {
    std::vector<uint8_t> script;

    // Push signature size (2 bytes, little-endian)
    uint16_t sig_size = static_cast<uint16_t>(signature.size());
    script.push_back(static_cast<uint8_t>(sig_size & 0xFF));
    script.push_back(static_cast<uint8_t>((sig_size >> 8) & 0xFF));

    // Push signature data
    script.insert(script.end(), signature.begin(), signature.end());

    // Push pubkey size (2 bytes, little-endian)
    uint16_t pk_size = static_cast<uint16_t>(pubkey.size());
    script.push_back(static_cast<uint8_t>(pk_size & 0xFF));
    script.push_back(static_cast<uint8_t>((pk_size >> 8) & 0xFF));

    // Push pubkey data
    script.insert(script.end(), pubkey.begin(), pubkey.end());

    return script;
}

std::vector<uint8_t> ExtractPubKeyHash(const std::vector<uint8_t>& scriptPubKey) {
    // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <hash_size> <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    // Expected size: 25 bytes (1+1+1+20+1+1) for 20-byte hash
    //           or: 37 bytes (1+1+1+32+1+1) for 32-byte hash

    // Minimum size: 25 bytes for P2PKH
    if (scriptPubKey.size() < 25) {
        return std::vector<uint8_t>();
    }

    // Verify P2PKH opcodes
    if (scriptPubKey[0] != 0x76) {  // OP_DUP
        return std::vector<uint8_t>();
    }
    if (scriptPubKey[1] != 0xA9) {  // OP_HASH160
        return std::vector<uint8_t>();
    }

    // SEC-002: Validate hash_size before using it in calculations
    uint8_t hash_size = scriptPubKey[2];

    // Only accept standard hash sizes: 20 (RIPEMD160) or 32 (SHA3-256)
    // This prevents potential overflow and malformed scripts
    if (hash_size != 20 && hash_size != 32) {
        return std::vector<uint8_t>();
    }

    // Verify script size matches P2PKH format: 3 (opcodes) + hash_size + 2 (opcodes)
    // Now safe because hash_size is validated to be 20 or 32
    size_t expected_size = 3 + static_cast<size_t>(hash_size) + 2;
    if (scriptPubKey.size() != expected_size) {
        return std::vector<uint8_t>();
    }

    // Verify OP_EQUALVERIFY and OP_CHECKSIG at the end
    // Safe to access because size was validated above
    if (scriptPubKey[3 + hash_size] != 0x88) {  // OP_EQUALVERIFY
        return std::vector<uint8_t>();
    }
    if (scriptPubKey[4 + hash_size] != 0xAC) {  // OP_CHECKSIG
        return std::vector<uint8_t>();
    }

    // Extract hash (skip OP_DUP, OP_HASH160, hash_size)
    return std::vector<uint8_t>(scriptPubKey.begin() + 3, scriptPubKey.begin() + 3 + hash_size);
}

} // namespace WalletCrypto

// ============================================================================
// Phase 5.2: UTXO Management & Transaction Creation Implementation
// ============================================================================

// Helper: Get public key hash (20 bytes) from CDilithiumAddress
std::vector<uint8_t> CWallet::GetPubKeyHashFromAddress(const CDilithiumAddress& address) {
    if (!address.IsValid()) {
        return std::vector<uint8_t>();
    }

    const std::vector<uint8_t>& addrData = address.GetData();

    // Address format: [version(1)] [hash(20)]
    if (addrData.size() != 21) {
        return std::vector<uint8_t>();
    }

    // Extract hash (skip version byte)
    return std::vector<uint8_t>(addrData.begin() + 1, addrData.end());
}

// Public methods - acquire lock and call unlocked versions
std::vector<uint8_t> CWallet::GetPubKeyHash() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetPubKeyHashUnlocked();
}

std::vector<uint8_t> CWallet::GetPublicKey() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return GetPublicKeyUnlocked();
}

// Private unlocked methods - assume caller already holds lock
std::vector<uint8_t> CWallet::GetPubKeyHashUnlocked() const {
    if (!defaultAddress.IsValid()) {
        return std::vector<uint8_t>();
    }

    return GetPubKeyHashFromAddress(defaultAddress);
}

std::vector<uint8_t> CWallet::GetPublicKeyUnlocked() const {
    if (!defaultAddress.IsValid()) {
        return std::vector<uint8_t>();
    }

    // Get key for default address (we already hold the lock)
    CKey key;
    if (GetKeyUnlocked(defaultAddress, key)) {
        return key.vchPubKey;
    }

    return std::vector<uint8_t>();
}

bool CWallet::ScanUTXOs(CUTXOSet& global_utxo_set) {
    // FIX-006 (WALLET-002): Hold wallet lock for entire scan operation
    // Prevents TOCTOU race: GetAddresses() → AddTxOut() gap where wallet could be modified
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::cout << "[Wallet] Scanning UTXO set for wallet outputs..." << std::endl;

    // Step 1: Get all wallet addresses and their pubkey hashes
    // FIX-006: Access vchAddresses directly since we hold lock (avoid deadlock with GetAddresses())
    const std::vector<CDilithiumAddress>& addresses = vchAddresses;
    if (addresses.empty()) {
        std::cout << "[Wallet] No addresses in wallet - nothing to scan" << std::endl;
        return true;
    }

    // Build set of pubkey hashes for fast lookup
    std::set<std::vector<uint8_t>> walletPubKeyHashes;
    for (const auto& addr : addresses) {
        std::vector<uint8_t> pkh = GetPubKeyHashFromAddress(addr);
        if (!pkh.empty()) {
            walletPubKeyHashes.insert(pkh);
        }
    }

    std::cout << "[Wallet] Scanning for " << walletPubKeyHashes.size() << " address(es)" << std::endl;

    // Step 2: Track found UTXOs
    size_t utxosScanned = 0;
    size_t utxosFound = 0;

    // Step 3: Scan all UTXOs using ForEach iterator
    global_utxo_set.ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        utxosScanned++;

        // Extract pubkey hash from scriptPubKey
        std::vector<uint8_t> scriptPubKeyHash = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);

        // Check if this UTXO belongs to our wallet
        if (!scriptPubKeyHash.empty() && walletPubKeyHashes.count(scriptPubKeyHash) > 0) {
            // Find which address this belongs to
            for (const auto& addr : addresses) {
                std::vector<uint8_t> addrHash = GetPubKeyHashFromAddress(addr);
                if (addrHash == scriptPubKeyHash) {
                    // FIX-006 (WALLET-002): Use unlocked version since we hold lock
                    AddTxOutUnlocked(outpoint.hash, outpoint.n, entry.out.nValue, addr, entry.nHeight, entry.fCoinBase);
                    utxosFound++;

                    {
                        const char* unitLabel = (Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV()) ? "volts" : "ions";
                        std::cout << "[Wallet] Found UTXO: " << outpoint.hash.GetHex().substr(0, 16)
                                  << ":" << outpoint.n << " (" << entry.out.nValue << " " << unitLabel << ")" << std::endl;
                    }
                    break;
                }
            }
        }

        // Progress update every 10000 UTXOs
        if (utxosScanned % 10000 == 0) {
            std::cout << "[Wallet] Scanned " << utxosScanned << " UTXOs..." << std::endl;
        }

        return true; // Continue iteration
    });

    std::cout << "[Wallet] Scan complete: Found " << utxosFound << " wallet UTXO(s) out of "
              << utxosScanned << " total" << std::endl;

    return true;
}

CAmount CWallet::GetAvailableBalance(CUTXOSet& utxo_set, unsigned int current_height) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    CAmount balance = 0;

    // Coinbase maturity requirement
    const unsigned int COINBASE_MATURITY = Dilithion::g_chainParams
        ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity) : 100;

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        // Skip spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Verify UTXO still exists in global set
        COutPoint outpoint(wtx.txid, wtx.vout);
        CUTXOEntry entry;
        if (!utxo_set.GetUTXO(outpoint, entry)) {
            continue;  // UTXO was spent elsewhere
        }

        // Check coinbase maturity
        if (entry.fCoinBase) {
            if (current_height < entry.nHeight + COINBASE_MATURITY) {
                continue;  // Immature coinbase
            }
        }

        // Add to balance (with overflow protection)
        if (balance > std::numeric_limits<CAmount>::max() - wtx.nValue) {
            // Overflow would occur - this should never happen in practice
            continue;
        }

        balance += wtx.nValue;
    }

    return balance;
}

CAmount CWallet::GetImmatureBalance(CUTXOSet& utxo_set, unsigned int current_height) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    CAmount immatureBalance = 0;

    // Coinbase maturity requirement
    const unsigned int COINBASE_MATURITY = Dilithion::g_chainParams
        ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity) : 100;

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        // Skip spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Verify UTXO still exists in global set
        COutPoint outpoint(wtx.txid, wtx.vout);
        CUTXOEntry entry;
        if (!utxo_set.GetUTXO(outpoint, entry)) {
            continue;  // UTXO was spent elsewhere
        }

        // Only count immature coinbase outputs
        if (entry.fCoinBase) {
            if (current_height < entry.nHeight + COINBASE_MATURITY) {
                // Add to immature balance (with overflow protection)
                if (immatureBalance > std::numeric_limits<CAmount>::max() - wtx.nValue) {
                    continue;  // Overflow would occur
                }
                immatureBalance += wtx.nValue;
            }
        }
    }

    return immatureBalance;
}

std::vector<CWalletTx> CWallet::ListUnspentOutputs(CUTXOSet& utxo_set, unsigned int current_height, unsigned int min_confirmations) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CWalletTx> unspent;
    const unsigned int COINBASE_MATURITY = Dilithion::g_chainParams
        ? static_cast<unsigned int>(Dilithion::g_chainParams->coinbaseMaturity) : 100;

    for (const auto& pair : mapWalletTx) {
        const CWalletTx& wtx = pair.second;

        // Skip spent outputs
        if (wtx.fSpent) {
            continue;
        }

        // Verify UTXO still exists
        COutPoint outpoint(wtx.txid, wtx.vout);
        CUTXOEntry entry;
        if (!utxo_set.GetUTXO(outpoint, entry)) {
            continue;
        }

        // WALLET-003 FIX: Check confirmation depth to prevent spending unconfirmed transactions
        // Confirmations = (current_height - tx_height) + 1
        // Note: no nHeight > 0 guard — genesis outputs (height 0) are valid (pre-fund)
        unsigned int depth = 0;
        if (current_height >= entry.nHeight) {
            depth = current_height - entry.nHeight + 1;
        }

        if (depth < min_confirmations) {
            continue;  // Insufficient confirmations
        }

        // Check coinbase maturity
        if (entry.fCoinBase) {
            if (current_height < entry.nHeight + COINBASE_MATURITY) {
                continue;  // Immature coinbase
            }
        }

        unspent.push_back(wtx);
    }

    return unspent;
}

// ============================================================================
// BUG #113 FIX: List ALL wallet outputs for transaction history
// ============================================================================

std::vector<CWalletTx> CWallet::ListAllOutputs(unsigned int current_height) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CWalletTx> allOutputs;

    for (const auto& pair : mapWalletTx) {
        CWalletTx wtx = pair.second;
        // Include all outputs - spent and unspent - for complete history
        allOutputs.push_back(wtx);
    }

    return allOutputs;
}

// ============================================================================
// BUG #104 FIX: Sent Transaction Tracking
// ============================================================================

void CWallet::RecordSentTransaction(const uint256& txid, const CDilithiumAddress& toAddress,
                                    int64_t nValue, int64_t nFee) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    CSentTx stx;
    stx.txid = txid;
    stx.toAddress = toAddress;
    stx.nValue = nValue;
    stx.nFee = nFee;
    stx.nTime = std::time(nullptr);
    stx.nHeight = 0;  // Unconfirmed initially

    mapSentTx[txid] = stx;

    // Persist immediately so sends survive node restart. Previously this
    // path only "marked as dirty" — relying on a later block-triggered
    // save to flush — which silently lost send history across restarts.
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked(m_walletFile);
    }
}

bool CWallet::GetSentTransaction(const uint256& txid, CSentTx& out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    auto it = mapSentTx.find(txid);
    if (it == mapSentTx.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool CWallet::GetWalletOutput(const uint256& txid, uint32_t vout,
                              CDilithiumAddress& addressOut,
                              int64_t& valueOut) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    auto it = mapWalletTx.find(COutPoint(txid, vout));
    if (it == mapWalletTx.end()) {
        return false;
    }
    addressOut = it->second.address;
    valueOut = it->second.nValue;
    return true;
}

std::vector<CSentTx> CWallet::ListSentTransactions() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    std::vector<CSentTx> result;
    result.reserve(mapSentTx.size());

    for (const auto& pair : mapSentTx) {
        result.push_back(pair.second);
    }

    // Sort by time (newest first)
    std::sort(result.begin(), result.end(), [](const CSentTx& a, const CSentTx& b) {
        return a.nTime > b.nTime;
    });

    return result;
}

void CWallet::UpdateSentTransactionHeight(const uint256& txid, uint32_t nHeight) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    UpdateSentTransactionHeightUnlocked(txid, nHeight);
}

// BUG #112 FIX: Unlocked version for use from blockConnected (which already holds cs_wallet)
void CWallet::UpdateSentTransactionHeightUnlocked(const uint256& txid, uint32_t nHeight) {
    // NOTE: Caller must hold cs_wallet lock
    auto it = mapSentTx.find(txid);
    if (it != mapSentTx.end()) {
        it->second.nHeight = nHeight;
    }
}

// ============================================================================
// WALLET-006 FIX: UTXO Locking Mechanism
// ============================================================================

void CWallet::LockCoin(const COutPoint& outpoint) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    setLockedCoins.insert(outpoint);
}

void CWallet::UnlockCoin(const COutPoint& outpoint) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    setLockedCoins.erase(outpoint);
}

bool CWallet::IsLocked(const COutPoint& outpoint) const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return setLockedCoins.count(outpoint) > 0;
}

std::vector<COutPoint> CWallet::ListLockedCoins() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return std::vector<COutPoint>(setLockedCoins.begin(), setLockedCoins.end());
}

void CWallet::UnlockAllCoins() {
    std::lock_guard<std::mutex> lock(cs_wallet);
    setLockedCoins.clear();
}

// ============================================================================

bool CWallet::SelectCoins(CAmount target_value,
                          std::vector<CWalletTx>& selected_coins,
                          CAmount& total_value,
                          CUTXOSet& utxo_set,
                          unsigned int current_height,
                          std::string& error,
                          const CDilithiumAddress& from_address) const {
    selected_coins.clear();
    total_value = 0;

    // Get all spendable UTXOs
    std::vector<CWalletTx> unspent = ListUnspentOutputs(utxo_set, current_height);

    // Filter by from_address if specified
    if (from_address.IsValid()) {
        std::vector<CWalletTx> filtered;
        for (const auto& wtx : unspent) {
            if (wtx.address == from_address) {
                filtered.push_back(wtx);
            }
        }
        unspent = std::move(filtered);
    }

    if (unspent.empty()) {
        error = from_address.IsValid()
            ? "No spendable outputs at address " + from_address.ToString()
            : "No spendable outputs available";
        return false;
    }

    // Select largest UTXOs first to minimise input count.
    // Dilithium signatures are ~2.4KB each, so fewer inputs = much smaller transactions.
    // This prevents the "too many small UTXOs" problem where random selection creates
    // 350KB+ transactions that fail fee checks or get evicted from mempools.
    std::sort(unspent.begin(), unspent.end(),
              [](const CWalletTx& a, const CWalletTx& b) {
                  return a.nValue > b.nValue;
              });

    // Select coins until we reach target, but stop before the tx grows past
    // the wallet size cap (MAX_WALLET_TX_SIZE). A tx that exceeds the mempool
    // 1 MB limit will be rejected regardless of fee; fail fast with a clear
    // "consolidate first" message instead.
    bool size_cap_hit = false;
    for (const CWalletTx& wtx : unspent) {
        // WALLET-006 FIX: Skip locked UTXOs to prevent concurrent transaction conflicts
        COutPoint outpoint(wtx.txid, wtx.vout);
        if (IsLocked(outpoint)) {
            continue;  // Skip this UTXO - it's locked by another transaction
        }

        // Size-aware cap: estimate the tx size if we added this UTXO and bail
        // if it would push past the wallet limit. Assumes 2 outputs (recipient +
        // change), which matches what CreateTransaction builds.
        size_t prospective_size = Consensus::EstimateDilithiumTxSize(selected_coins.size() + 1, 2);
        if (prospective_size > TxValidation::MAX_WALLET_TX_SIZE) {
            size_cap_hit = true;
            break;
        }

        // WALLET-004 FIX: Check for integer overflow when summing coin values
        // Without this check, selecting many large UTXOs could cause total_value to overflow,
        // resulting in an invalid negative or wrapped-around value that bypasses target_value check
        // Impact: Could create invalid transactions or select insufficient funds
        if (total_value > INT64_MAX - wtx.nValue) {
            error = "Selected coins value would overflow (exceeds maximum amount)";
            selected_coins.clear();
            total_value = 0;
            return false;
        }

        selected_coins.push_back(wtx);
        total_value += wtx.nValue;

        if (total_value >= target_value) {
            return true;  // Success - we have enough
        }
    }

    // Distinguish "ran out of coins" from "size cap hit before target" — the
    // fixes are different (top up vs consolidate).
    if (size_cap_hit) {
        error = "Send too large: would need more than " +
                std::to_string(selected_coins.size()) +
                " inputs (~" + std::to_string(Consensus::EstimateDilithiumTxSize(selected_coins.size(), 2)) +
                " bytes) to cover " + std::to_string(target_value) + " ions. " +
                "Covered so far: " + std::to_string(total_value) + " ions. " +
                "Consolidate small UTXOs first via 'consolidateutxos', then retry.";
    } else {
        error = "Insufficient balance (need " + std::to_string(target_value) +
                " but only have " + std::to_string(total_value) + ")";
    }
    selected_coins.clear();
    total_value = 0;
    return false;
}

bool CWallet::CreateTransaction(const CDilithiumAddress& recipient_address,
                                CAmount amount,
                                CAmount fee,
                                CUTXOSet& utxo_set,
                                unsigned int current_height,
                                CTransactionRef& tx_out,
                                std::string& error,
                                const CDilithiumAddress& from_address) {
    // Input validation
    if (!recipient_address.IsValid()) {
        error = "Invalid recipient address";
        return false;
    }

    if (amount <= 0) {
        error = "Invalid amount (must be positive)";
        return false;
    }

    if (fee < 0) {
        error = "Invalid fee (cannot be negative)";
        return false;
    }

    // WALLET-009 FIX: Validate fee meets network minimum relay fee
    // Without this check, transactions with too-low fees will be created and signed,
    // but then rejected by the network, wasting user's time and effort
    // Impact: Prevents transaction relay failures, improves UX
    if (fee < MIN_RELAY_FEE) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Fee below minimum relay fee (%.8f DIL minimum, got %.8f DIL). "
                 "Transaction will be rejected by the network.",
                 MIN_RELAY_FEE / 100000000.0, fee / 100000000.0);
        error = msg;
        return false;
    }

    // Calculate total needed
    CAmount total_needed = amount + fee;
    if (total_needed < amount) {  // Overflow check
        error = "Amount + fee overflow";
        return false;
    }

    // Select coins with iterative fee adjustment
    // More inputs = larger tx = higher fee, which may require more inputs
    std::vector<CWalletTx> selected_coins;
    CAmount total_selected = 0;

    if (!SelectCoins(total_needed, selected_coins, total_selected, utxo_set, current_height, error, from_address)) {
        return false;
    }

    // Recalculate fee based on actual input count (converges in 1-2 iterations)
    for (int iter = 0; iter < 5; ++iter) {
        size_t num_outputs = 2; // recipient + potential change
        size_t est_size = Consensus::EstimateDilithiumTxSize(selected_coins.size(), num_outputs);
        CAmount needed_fee = Consensus::CalculateMinFee(est_size);

        if (needed_fee <= fee) break; // Current fee is sufficient

        fee = needed_fee;
        total_needed = amount + fee;
        if (total_needed < amount) {
            error = "Amount + fee overflow";
            return false;
        }

        selected_coins.clear();
        total_selected = 0;
        if (!SelectCoins(total_needed, selected_coins, total_selected, utxo_set, current_height, error)) {
            return false;
        }
    }

    // WALLET-006 FIX: Lock selected coins to prevent concurrent transaction conflicts
    // Lock coins immediately after selection to ensure they won't be used by another
    // concurrent transaction. If this transaction fails, we'll unlock them before returning.
    for (const CWalletTx& wtx : selected_coins) {
        LockCoin(COutPoint(wtx.txid, wtx.vout));
    }

    // WALLET-012 FIX: Validate input count before creating transaction
    // Creating and signing large transactions wastes CPU/bandwidth if they'll be rejected anyway
    // Impact: Prevents unnecessary signing of oversized transactions
    if (selected_coins.size() > TxValidation::MAX_INPUT_COUNT_PER_TX) {
        error = "Too many inputs selected (" + std::to_string(selected_coins.size()) +
                " > " + std::to_string(TxValidation::MAX_INPUT_COUNT_PER_TX) + " max). " +
                "Transaction would be rejected by network.";
        // Unlock coins before returning
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    // Create transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    // Create inputs from selected coins
    for (const CWalletTx& wtx : selected_coins) {
        COutPoint outpoint(wtx.txid, wtx.vout);
        CTxIn txin(outpoint);
        // CID 1675180 FIX: Use std::move to avoid unnecessary copy
        // txin is a local variable that's no longer used after push_back
        tx.vin.push_back(std::move(txin));
    }

    // Create output for recipient
    std::vector<uint8_t> recipient_hash = GetPubKeyHashFromAddress(recipient_address);
    if (recipient_hash.empty()) {
        error = "Failed to extract recipient public key hash";
        // WALLET-006 FIX: Unlock coins on failure
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(recipient_hash);
    // CID 1675180 FIX: Move scriptPubKey into constructor to avoid unnecessary copy
    CTxOut txout_recipient(amount, std::move(scriptPubKey));
    // CID 1675180 FIX: Move txout_recipient into push_back to avoid unnecessary copy
    tx.vout.push_back(std::move(txout_recipient));

    // Create change output if needed
    CAmount change = total_selected - total_needed;

    // WALLET-005 FIX: Prevent dust output creation (economically unspendable UTXOs)
    // Dust outputs are smaller than the cost to spend them (tx fee > output value)
    // If change < DUST_THRESHOLD, add it to miner fee instead of creating dust output
    // Impact: Prevents UTXO bloat, saves blockchain space, improves user experience
    // DUST_THRESHOLD = 50,000 ions = 0.0005 DIL (defined in amount.h)
    if (change >= DUST_THRESHOLD) {
        // Change is economically spendable - create change output
        std::vector<uint8_t> change_hash;

        // WALLET-011 FIX: Use HD change address for privacy
        // For HD wallets, generate a new change address from internal chain (m/44'/573'/0'/1'/index')
        // instead of reusing the default address. This prevents address reuse and improves privacy.
        // Impact: Prevents transaction graph analysis and wallet fingerprinting
        if (IsHDWallet()) {
            CDilithiumAddress change_address = GetChangeAddress();
            if (!change_address.IsValid()) {
                error = "Failed to generate HD change address (wallet may be locked)";
                // WALLET-006 FIX: Unlock coins on failure
                for (const CWalletTx& wtx : selected_coins) {
                    UnlockCoin(COutPoint(wtx.txid, wtx.vout));
                }
                return false;
            }
            change_hash = GetPubKeyHashFromAddress(change_address);
        } else {
            // Non-HD wallet: Use default address (legacy behavior)
            change_hash = GetPubKeyHash();
            if (change_hash.empty()) {
                error = "Failed to get wallet public key hash for change";
                // WALLET-006 FIX: Unlock coins on failure
                for (const CWalletTx& wtx : selected_coins) {
                    UnlockCoin(COutPoint(wtx.txid, wtx.vout));
                }
                return false;
            }
        }

        std::vector<uint8_t> change_scriptPubKey = WalletCrypto::CreateScriptPubKey(change_hash);
        // CID 1675180 FIX: Move change_scriptPubKey into constructor to avoid unnecessary copy
        CTxOut txout_change(change, std::move(change_scriptPubKey));
        // CID 1675180 FIX: Move txout_change into push_back to avoid unnecessary copy
        tx.vout.push_back(std::move(txout_change));
    }
    // else: change < DUST_THRESHOLD - add to miner fee (implicit, not creating output)

    // Sign transaction
    if (!SignTransaction(tx, utxo_set, error)) {
        // WALLET-006 FIX: Unlock coins on failure
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    // WALLET-013 FIX: Verify fee is sufficient for actual transaction size
    // Uses consensus fee formula to ensure consistency with mempool admission
    size_t tx_size = tx.GetSerializedSize();
    CAmount required_fee = Consensus::CalculateMinFee(tx_size);

    if (fee < required_fee) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "Fee insufficient for transaction size (%zu bytes). "
                 "Required: %.8f DIL, Provided: %.8f DIL",
                 tx_size,
                 required_fee / 100000000.0,
                 fee / 100000000.0);
        error = msg;
        // WALLET-006 FIX: Unlock coins on failure
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    // Validate transaction
    CTransactionValidator validator;
    CAmount calculated_fee = 0;
    std::string validation_error;

    if (!validator.CheckTransaction(tx, utxo_set, current_height, calculated_fee, validation_error)) {
        error = "Transaction validation failed: " + validation_error;
        // WALLET-006 FIX: Unlock coins on failure
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    // Create transaction reference
    tx_out = MakeTransactionRef(std::move(tx));

    // WALLET-006 FIX: On success, keep coins locked until transaction is confirmed or manually unlocked
    // Caller should unlock coins when:
    // - Transaction is confirmed (spent UTXOs automatically removed from wallet)
    // - Transaction is abandoned/cancelled (call UnlockCoin for each input)
    // - Wallet shutdown (call UnlockAllCoins for recovery)

    return true;
}

bool CWallet::CreateTransactionToScript(const std::vector<uint8_t>& scriptPubKey,
                                         CAmount amount,
                                         CAmount fee,
                                         CUTXOSet& utxo_set,
                                         unsigned int current_height,
                                         uint32_t nLockTime,
                                         CTransactionRef& tx_out,
                                         std::string& error) {
    if (scriptPubKey.empty()) {
        error = "Empty scriptPubKey";
        return false;
    }
    if (amount <= 0) {
        error = "Invalid amount (must be positive)";
        return false;
    }
    if (fee < MIN_RELAY_FEE) {
        error = "Fee below minimum relay fee";
        return false;
    }

    if (IsCrypted() && IsLocked()) {
        error = "Wallet is encrypted and locked";
        return false;
    }

    CAmount total_needed = amount + fee;
    if (total_needed < amount) {
        error = "Amount + fee overflow";
        return false;
    }

    // Select coins
    std::vector<CWalletTx> selected_coins;
    CAmount total_selected = 0;
    if (!SelectCoins(total_needed, selected_coins, total_selected, utxo_set, current_height, error)) {
        return false;
    }

    // Recalculate fee based on actual input count
    for (int iter = 0; iter < 5; ++iter) {
        size_t num_outputs = 2;
        size_t est_size = Consensus::EstimateDilithiumTxSize(selected_coins.size(), num_outputs);
        CAmount needed_fee = Consensus::CalculateMinFee(est_size);
        if (needed_fee <= fee) break;
        fee = needed_fee;
        total_needed = amount + fee;
        if (total_needed < amount) {
            error = "Amount + fee overflow";
            return false;
        }
        selected_coins.clear();
        total_selected = 0;
        if (!SelectCoins(total_needed, selected_coins, total_selected, utxo_set, current_height, error)) {
            return false;
        }
    }

    // Lock selected coins
    for (const CWalletTx& wtx : selected_coins) {
        LockCoin(COutPoint(wtx.txid, wtx.vout));
    }

    // Build transaction
    CTransaction tx;
    tx.nVersion = 2;  // Version 2 for script V2 / BIP-68 support
    tx.nLockTime = nLockTime;

    for (const CWalletTx& wtx : selected_coins) {
        COutPoint outpoint(wtx.txid, wtx.vout);
        CTxIn txin(outpoint);
        if (nLockTime > 0) {
            txin.nSequence = CTxIn::SEQUENCE_FINAL - 1;  // Enable nLockTime
        }
        tx.vin.push_back(std::move(txin));
    }

    // Output: the custom script (HTLC)
    CTxOut txout_script(amount, scriptPubKey);
    tx.vout.push_back(std::move(txout_script));

    // Change output
    CAmount change = total_selected - total_needed;
    if (change >= DUST_THRESHOLD) {
        std::vector<uint8_t> change_hash;
        if (IsHDWallet()) {
            CDilithiumAddress change_address = GetChangeAddress();
            if (!change_address.IsValid()) {
                error = "Failed to generate HD change address";
                for (const CWalletTx& wtx : selected_coins) {
                    UnlockCoin(COutPoint(wtx.txid, wtx.vout));
                }
                return false;
            }
            change_hash = GetPubKeyHashFromAddress(change_address);
        } else {
            change_hash = GetPubKeyHash();
            if (change_hash.empty()) {
                error = "Failed to get wallet public key hash for change";
                for (const CWalletTx& wtx : selected_coins) {
                    UnlockCoin(COutPoint(wtx.txid, wtx.vout));
                }
                return false;
            }
        }
        std::vector<uint8_t> change_script = WalletCrypto::CreateScriptPubKey(change_hash);
        CTxOut txout_change(change, std::move(change_script));
        tx.vout.push_back(std::move(txout_change));
    }

    // Sign inputs (all are standard P2PKH from our wallet)
    if (!SignTransaction(tx, utxo_set, error)) {
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    // Validate
    CTransactionValidator validator;
    CAmount calculated_fee = 0;
    std::string validation_error;
    if (!validator.CheckTransaction(tx, utxo_set, current_height, calculated_fee, validation_error)) {
        error = "Transaction validation failed: " + validation_error;
        for (const CWalletTx& wtx : selected_coins) {
            UnlockCoin(COutPoint(wtx.txid, wtx.vout));
        }
        return false;
    }

    tx_out = MakeTransactionRef(std::move(tx));
    return true;
}

bool CWallet::SignTransaction(CTransaction& tx, CUTXOSet& utxo_set, std::string& error) {
    // BUG #74 FIX: Three-phase signing to avoid holding lock during CPU-intensive operations
    // Following Bitcoin Core pattern: collect data under lock, release, sign, re-acquire
    // This reduces lock hold time from 50-500ms to ~10ms, preventing RPC thread starvation

    // =========================================================================
    // PHASE 1: Collect signing data under lock (fast, ~5-10ms)
    // =========================================================================
    struct SigningData {
        size_t input_index;
        CKey signing_key;
        std::vector<uint8_t> sig_hash;
        std::vector<uint8_t> scriptPubKey;
    };
    std::vector<SigningData> signing_inputs;
    // BUG #86 FIX: Use GetSigningHash() which excludes scriptSig
    // This ensures the hash is the same during signing (empty scriptSig) and verification (filled scriptSig)
    uint256 tx_hash = tx.GetSigningHash();

    {
        std::lock_guard<std::mutex> lock(cs_wallet);

        // VULN-002 FIX: Check if unlock is still valid (not expired) before signing
        // BUG #74 FIX: Use NoLock version since we already hold cs_wallet
        if (!_IsUnlockValidNoLock()) {
            error = "Wallet is locked or unlock timeout has expired";
            return false;
        }

        // LP-7 L1 (opt-in --require-seed-migration, default OFF): refuse to sign any
        // spend while the HD seed is still plaintext-at-rest. This is the single spend
        // signing funnel, so this one gate covers sendtoaddress, raw-tx signing, HTLC,
        // and bridge spends. Default OFF leaves the warn-only behavior intact.
        // (masterKey.IsValid() && m_fNeedsSeedMigration mirrors NeedsSeedMigration()
        // without re-locking cs_wallet, which we already hold here.)
        if (m_requireSeedMigration && masterKey.IsValid() && m_fNeedsSeedMigration) {
            error = "Refusing to spend: wallet HD seed is still stored UNENCRYPTED at rest "
                    "(fixed bug LP-7). Unlock once to complete the one-time security upgrade "
                    "(walletpassphrase), then retry. (Started with --require-seed-migration.)";
            return false;
        }

        // Check chain params before loop
        if (Dilithion::g_chainParams == nullptr) {
            error = "Chain parameters not initialized";
            return false;
        }
        uint32_t chain_id = Dilithion::g_chainParams->chainID;
        uint32_t version = tx.nVersion;

        // Collect signing data for each input
        for (size_t i = 0; i < tx.vin.size(); i++) {
            const CTxIn& txin = tx.vin[i];

            // Lookup the UTXO being spent
            CUTXOEntry utxo_entry;
            if (!utxo_set.GetUTXO(txin.prevout, utxo_entry)) {
                error = "UTXO not found for input " + std::to_string(i);
                return false;
            }

            // Extract public key hash from scriptPubKey
            std::vector<uint8_t> required_hash = WalletCrypto::ExtractPubKeyHash(utxo_entry.out.scriptPubKey);
            if (required_hash.empty()) {
                error = "Failed to extract public key hash from scriptPubKey for input " + std::to_string(i);
                return false;
            }

            // VULN-003 FIX: Create signature message with version
            // CHAIN-ID FIX: Include chain ID to prevent cross-chain replay attacks (EIP-155 style)
            std::vector<uint8_t> sig_message;
            sig_message.reserve(32 + 4 + 4 + 4);  // hash + index + version + chainID
            sig_message.insert(sig_message.end(), tx_hash.begin(), tx_hash.end());

            // Add input index (4 bytes, little-endian)
            uint32_t input_idx = static_cast<uint32_t>(i);
            sig_message.push_back(static_cast<uint8_t>(input_idx & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((input_idx >> 8) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((input_idx >> 16) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((input_idx >> 24) & 0xFF));

            // Add transaction version
            sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));

            // Add chain ID
            sig_message.push_back(static_cast<uint8_t>(chain_id & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((chain_id >> 8) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((chain_id >> 16) & 0xFF));
            sig_message.push_back(static_cast<uint8_t>((chain_id >> 24) & 0xFF));

            // Hash the signature message
            SigningData data;
            data.input_index = i;
            data.sig_hash.resize(32);
            SHA3_256(sig_message.data(), sig_message.size(), data.sig_hash.data());
            data.scriptPubKey = utxo_entry.out.scriptPubKey;

            // Find the key for this address
            bool found_key = false;
            for (const auto& addr : vchAddresses) {
                CKey key;
                if (GetKeyUnlocked(addr, key)) {
                    std::vector<uint8_t> key_hash = WalletCrypto::HashPubKey(key.vchPubKey);
                    if (key_hash == required_hash) {
                        data.signing_key = key;
                        found_key = true;
                        break;
                    }
                }
            }

            if (!found_key) {
                error = "Wallet does not have key to sign input " + std::to_string(i);
                return false;
            }

            signing_inputs.push_back(std::move(data));
        }
    }  // Lock released here - Phase 1 complete

    // =========================================================================
    // PHASE 2: Sign all inputs WITHOUT holding lock (slow, 10-50ms per input)
    // Other wallet operations can proceed during this phase
    // =========================================================================
    struct SignatureResult {
        size_t input_index;
        std::vector<uint8_t> signature;
        std::vector<uint8_t> pubkey;
    };
    std::vector<SignatureResult> signatures;

    for (const auto& data : signing_inputs) {
        std::vector<uint8_t> signature;
        if (!WalletCrypto::Sign(data.signing_key, data.sig_hash.data(), 32, signature)) {
            error = "Failed to sign input " + std::to_string(data.input_index);
            return false;
        }

        SignatureResult result;
        result.input_index = data.input_index;
        result.signature = std::move(signature);
        result.pubkey = data.signing_key.vchPubKey;
        signatures.push_back(std::move(result));
    }

    // =========================================================================
    // PHASE 3: Apply signatures to transaction (no lock needed for tx modification)
    // Then verify signatures (UTXO lookup may need brief lock, but verification is fast)
    // =========================================================================
    for (const auto& sig_result : signatures) {
        // Create scriptSig
        std::vector<uint8_t> scriptSig = WalletCrypto::CreateScriptSig(sig_result.signature, sig_result.pubkey);
        tx.vin[sig_result.input_index].scriptSig = scriptSig;
    }

    // WALLET-014 FIX: Verify signatures immediately after signing (defense-in-depth)
    // This catches any bugs in the signing process before the transaction propagates
    CTransactionValidator validator;
    for (size_t i = 0; i < signing_inputs.size(); i++) {
        const auto& data = signing_inputs[i];
        const CTxIn& txin = tx.vin[data.input_index];

        // Verify the signature using cached scriptPubKey
        std::string verify_error;
        if (!validator.VerifyScript(tx, data.input_index, txin.scriptSig, data.scriptPubKey, verify_error)) {
            error = "Post-sign verification failed for input " + std::to_string(data.input_index) + ": " + verify_error;
            return false;
        }
    }

    // All signatures verified successfully
    return true;
}

bool CWallet::SendTransaction(const CTransactionRef& tx,
                              CTxMemPool& mempool,
                              CUTXOSet& utxo_set,
                              unsigned int current_height,
                              std::string& error) {
    if (!tx) {
        error = "Null transaction pointer";
        return false;
    }

    // Validate transaction one more time
    CTransactionValidator validator;
    CAmount fee = 0;
    std::string validation_error;

    if (!validator.CheckTransaction(*tx, utxo_set, current_height, fee, validation_error)) {
        error = "Transaction validation failed: " + validation_error;
        return false;
    }

    // Add to mempool
    int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::string mempool_error;
    if (!mempool.AddTx(tx, fee, current_time, current_height, &mempool_error)) {
        error = "Failed to add transaction to mempool: " + mempool_error;
        return false;
    }

    // Phase 5.3: Announce transaction to P2P network
    const uint256 txid = tx->GetHash();

    // Forward declaration from net/net.h
    extern void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer, bool force_reannounce = false);

    // Announce to all peers (-1 = no excluding peer)
    AnnounceTransactionToPeers(txid, -1);

    return true;
}

// ============================================================================
// HD Wallet (Hierarchical Deterministic) Implementation
// ============================================================================

extern "C" {
    int pqcrystals_dilithium3_ref_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
}

bool CWallet::InitializeHDWallet(const std::string& mnemonic, const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check if wallet already initialized
    if (fIsHDWallet || !mapKeys.empty() || !mapCryptedKeys.empty()) {
        return false;
    }

    // Validate mnemonic
    if (!CMnemonic::Validate(mnemonic)) {
        return false;
    }

    // WL-002 FIX: Use RAII for BIP39 seed to prevent memory leak on exception
    //
    // CRITICAL: If DeriveMaster() throws an exception or crashes, the seed
    // must still be wiped from memory. Using CKeyingMaterial ensures the
    // destructor wipes memory even on abnormal exit paths.
    //
    // This prevents seed extraction from core dumps if the node crashes.
    //
    CKeyingMaterial bip39_seed(64);  // RAII: auto-wipes on scope exit
    if (!CMnemonic::ToSeed(mnemonic, passphrase, bip39_seed.data_ptr())) {
        return false;  // RAII automatically wipes seed
    }

    // Derive master HD key (if this throws, RAII still wipes seed)
    DeriveMaster(bip39_seed.data_ptr(), hdMasterKey);

    // Seed will be automatically wiped when bip39_seed goes out of scope
    // (no explicit memory_cleanse needed)

    // Encrypt mnemonic if wallet is encrypted
    if (masterKey.IsValid()) {
        if (!EncryptMnemonic(mnemonic)) {
            hdMasterKey.Wipe();
            return false;
        }

        if (!EncryptHDMasterKey()) {
            hdMasterKey.Wipe();
            memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
            vchEncryptedMnemonic.clear();
            vchMnemonicIV.clear();
            return false;
        }
    } else {
        // Store encrypted mnemonic directly (no wallet encryption yet)
        if (!EncryptMnemonic(mnemonic)) {
            hdMasterKey.Wipe();
            return false;
        }
        fHDMasterKeyEncrypted = false;
    }

    // Initialize HD wallet state
    fIsHDWallet = true;
    nHDAccountIndex = 0;
    nHDExternalChainIndex = 0;
    nHDInternalChainIndex = 0;

    // BUG #115 FIX: Pre-generate HD_GAP_LIMIT (20) addresses on wallet creation
    // Without this, only 1 address is generated. When mining in "privacy mode"
    // generates new addresses, old blocks are never rescanned with those addresses.
    // By pre-generating 20 addresses, the initial rescan will check all of them.
    CHDKeyPath firstPath = CHDKeyPath::ReceiveAddress(0, 0);
    for (uint32_t i = 0; i < HD_GAP_LIMIT; i++) {
        CHDKeyPath path = CHDKeyPath::ReceiveAddress(0, i);
        if (!DeriveAndCacheHDAddress(path)) {
            if (i == 0) {
                // Rollback on failure of first address (critical)
                fIsHDWallet = false;
                hdMasterKey.Wipe();
                memory_cleanse(vchEncryptedMnemonic.data(), vchEncryptedMnemonic.size());
                vchEncryptedMnemonic.clear();
                vchMnemonicIV.clear();
                return false;
            }
            // Non-critical: proceed with addresses we have
            break;
        }
    }

    // BUG #100 FIX: Set defaultAddress for HD wallets so GetPubKeyHash() works for mining
    // Without this, GetPubKeyHash() returns empty for HD wallets, causing mined blocks
    // to not be credited to the wallet (coinbase hash comparison fails)
    auto it = mapPathToAddress.find(firstPath);
    if (it != mapPathToAddress.end()) {
        defaultAddress = it->second;
    }

    nHDExternalChainIndex = HD_GAP_LIMIT;  // Next address index after pre-generated ones

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

bool CWallet::GenerateHDWallet(std::string& mnemonic_out, const std::string& passphrase) {
    // Generate 256-bit (24-word) mnemonic
    if (!CMnemonic::Generate(256, mnemonic_out)) {
        return false;
    }

    // Initialize wallet with generated mnemonic
    if (!InitializeHDWallet(mnemonic_out, passphrase)) {
        memory_cleanse(&mnemonic_out[0], mnemonic_out.size());
        mnemonic_out.clear();
        return false;
    }

    return true;
}

bool CWallet::RestoreHDWallet(const std::string& mnemonic, const std::string& passphrase) {
    // Initialize HD wallet
    if (!InitializeHDWallet(mnemonic, passphrase)) {
        return false;
    }

    // Note: Actual blockchain scanning would require UTXO set
    // For now, just initialize with first address
    // User can call ScanHDChains() separately after loading blockchain

    return true;
}

CDilithiumAddress CWallet::GetNewHDAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CDilithiumAddress();  // Empty address
    }

    // RPC-003 FIX: Enforce wallet lock check with explicit error logging
    // Deriving new addresses when wallet is locked is a privacy/security issue:
    // - Attacker can enumerate future addresses without passphrase
    // - Breaks expectation that locked wallet doesn't expose sensitive operations
    // Impact: Prevents address enumeration attacks, protects user privacy
    // CID 1675174 FIX: Use IsCryptedUnlocked() since we already hold cs_wallet
    if (IsCryptedUnlocked() && !fWalletUnlocked) {
        std::cerr << "[ERROR] Cannot generate new address: wallet is locked. "
                  << "Please unlock wallet first." << std::endl;
        return CDilithiumAddress();
    }

    // Derive next address on external chain (receive)
    CHDKeyPath path = CHDKeyPath::ReceiveAddress(nHDAccountIndex, nHDExternalChainIndex);

    if (!DeriveAndCacheHDAddress(path)) {
        return CDilithiumAddress();
    }

    // Increment external chain index
    nHDExternalChainIndex++;

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CDilithiumAddress();
}

CDilithiumAddress CWallet::GetChangeAddress() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CDilithiumAddress();
    }

    // RPC-003 FIX: Enforce wallet lock check with explicit error logging
    // Same security issue as GetNewHDAddress() - prevents change address enumeration
    // CID 1675174 FIX: Use IsCryptedUnlocked() since we already hold cs_wallet
    if (IsCryptedUnlocked() && !fWalletUnlocked) {
        std::cerr << "[ERROR] Cannot generate change address: wallet is locked. "
                  << "Please unlock wallet first." << std::endl;
        return CDilithiumAddress();
    }

    // Derive next address on internal chain (change)
    CHDKeyPath path = CHDKeyPath::ChangeAddress(nHDAccountIndex, nHDInternalChainIndex);

    if (!DeriveAndCacheHDAddress(path)) {
        return CDilithiumAddress();
    }

    // Increment internal chain index
    nHDInternalChainIndex++;

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CDilithiumAddress();
}

CDilithiumAddress CWallet::DeriveAddress(const std::string& path_str) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return CDilithiumAddress();
    }

    // Check if wallet is locked and encrypted
    // CID 1675174 FIX: Use IsCryptedUnlocked() since we already hold cs_wallet
    if (IsCryptedUnlocked() && !fWalletUnlocked) {
        return CDilithiumAddress();
    }

    // Parse path
    CHDKeyPath path;
    if (!path.Parse(path_str) || !path.IsValid()) {
        return CDilithiumAddress();
    }

    // Check if already cached
    auto it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    // Derive and cache new address
    if (!DeriveAndCacheHDAddress(path)) {
        return CDilithiumAddress();
    }

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    // Return the address we just derived
    it = mapPathToAddress.find(path);
    if (it != mapPathToAddress.end()) {
        return it->second;
    }

    return CDilithiumAddress();
}

bool CWallet::ExportMnemonic(std::string& mnemonic_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    // Check if wallet is locked
    if (masterKey.IsValid() && !fWalletUnlocked) {
        return false;
    }

    // Decrypt mnemonic
    return DecryptMnemonic(mnemonic_out);
}

bool CWallet::GetHDWalletInfo(uint32_t& account, uint32_t& external_index,
                              uint32_t& internal_index) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    account = nHDAccountIndex;
    external_index = nHDExternalChainIndex;
    internal_index = nHDInternalChainIndex;

    return true;
}

bool CWallet::GetAddressPath(const CDilithiumAddress& address, CHDKeyPath& path_out) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return false;
    }

    auto it = mapAddressToPath.find(address);
    if (it == mapAddressToPath.end()) {
        return false;
    }

    path_out = it->second;
    return true;
}

size_t CWallet::ScanHDChains(CUTXOSet& utxo_set) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fIsHDWallet) {
        return 0;
    }

    // Check if wallet is locked
    // CID 1675174 FIX: Use IsCryptedUnlocked() since we already hold cs_wallet
    if (IsCryptedUnlocked() && !fWalletUnlocked) {
        return 0;
    }

    size_t found_count = 0;
    uint32_t gap_counter_external = 0;
    uint32_t gap_counter_internal = 0;

    // Scan external chain (receive addresses)
    for (uint32_t i = nHDExternalChainIndex; gap_counter_external < HD_GAP_LIMIT; i++) {
        CHDKeyPath path = CHDKeyPath::ReceiveAddress(nHDAccountIndex, i);

        if (!DeriveAndCacheHDAddress(path)) {
            break;  // Error deriving address
        }

        auto it = mapPathToAddress.find(path);
        if (it == mapPathToAddress.end()) {
            break;
        }

        // CID 1675306 FIX: Actually check if address has UTXOs instead of constant false
        // Get pubkey hash from this address
        std::vector<uint8_t> addrPKH = GetPubKeyHashFromAddress(it->second);
        bool has_utxos = false;

        if (!addrPKH.empty()) {
            // Iterate through UTXO set to find matches
            utxo_set.ForEach([&](const COutPoint& /*outpoint*/, const CUTXOEntry& entry) {
                std::vector<uint8_t> scriptPKH = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);
                if (scriptPKH == addrPKH) {
                    has_utxos = true;
                    return false;  // Stop iteration, found a match
                }
                return true;  // Continue iteration
            });
        }

        if (has_utxos) {
            found_count++;
            gap_counter_external = 0;  // Reset gap counter
            nHDExternalChainIndex = i + 1;  // Update index
        } else {
            gap_counter_external++;
        }
    }

    // Scan internal chain (change addresses)
    for (uint32_t i = nHDInternalChainIndex; gap_counter_internal < HD_GAP_LIMIT; i++) {
        CHDKeyPath path = CHDKeyPath::ChangeAddress(nHDAccountIndex, i);

        if (!DeriveAndCacheHDAddress(path)) {
            break;
        }

        auto it = mapPathToAddress.find(path);
        if (it == mapPathToAddress.end()) {
            break;
        }

        // CID 1675306 FIX: Actually check if address has UTXOs
        std::vector<uint8_t> addrPKH = GetPubKeyHashFromAddress(it->second);
        bool has_utxos = false;

        if (!addrPKH.empty()) {
            utxo_set.ForEach([&](const COutPoint& /*outpoint*/, const CUTXOEntry& entry) {
                std::vector<uint8_t> scriptPKH = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);
                if (scriptPKH == addrPKH) {
                    has_utxos = true;
                    return false;
                }
                return true;
            });
        }

        if (has_utxos) {
            found_count++;
            gap_counter_internal = 0;
            nHDInternalChainIndex = i + 1;
        } else {
            gap_counter_internal++;
        }
    }

    // Auto-save if we found any addresses
    if (found_count > 0 && m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return found_count;
}

// ============================================================================
// HD Wallet Private Helper Functions
// ============================================================================

bool CWallet::DeriveAndCacheHDAddress(const CHDKeyPath& path) {
    // Assumes caller holds cs_wallet lock

    // Check if already cached
    if (mapPathToAddress.find(path) != mapPathToAddress.end()) {
        return true;  // Already have this address
    }

    // Decrypt HD master key if encrypted
    CHDExtendedKey master_copy;
    if (fHDMasterKeyEncrypted) {
        if (!DecryptHDMasterKey(master_copy)) {
            return false;
        }
    } else {
        master_copy = hdMasterKey;
    }

    // Derive extended key at path
    CHDExtendedKey derived;
    if (!DerivePath(master_copy, path, derived)) {
        master_copy.Wipe();
        return false;
    }

    // Generate Dilithium keypair
    uint8_t pk[DILITHIUM_PUBLICKEY_SIZE];
    uint8_t sk[DILITHIUM_SECRETKEY_SIZE];

    if (!GenerateDilithiumKey(derived, pk, sk)) {
        derived.Wipe();
        master_copy.Wipe();
        memory_cleanse(sk, DILITHIUM_SECRETKEY_SIZE);
        return false;
    }

    // Create address from public key
    CDilithiumAddress address(std::vector<uint8_t>(pk, pk + DILITHIUM_PUBLICKEY_SIZE));

    // Create CKey structure
    CKey key;
    key.vchPubKey = std::vector<uint8_t>(pk, pk + DILITHIUM_PUBLICKEY_SIZE);
    // FIX-009: Use assign() for SecureAllocator vector
    key.vchPrivKey.assign(sk, sk + DILITHIUM_SECRETKEY_SIZE);

    // Store in wallet (encrypt if necessary)
    if (masterKey.IsValid()) {
        // Wallet is encrypted - encrypt the private key
        CEncryptedKey encKey;
        encKey.vchPubKey = key.vchPubKey;

        // FIX-010: Generate unique IV
        if (!GenerateUniqueIV_Locked(encKey.vchIV)) {
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        // Encrypt with master key
        CCrypter crypter;
        std::vector<uint8_t> masterKeyVec(vMasterKey.data_ptr(),
                                          vMasterKey.data_ptr() + vMasterKey.size());
        if (!crypter.SetKey(masterKeyVec, encKey.vchIV)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        if (!crypter.Encrypt(key.vchPrivKey, encKey.vchCryptedKey)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        // LP-7: a per-address at-rest key MUST carry a v7 MAC, or Load() (which
        // rejects any v7 record with an empty vchMAC) refuses the WHOLE wallet on
        // the next start — silent funds-access loss. Mirror EncryptWallet's per-
        // address MAC compute; GetKeyUnlocked already verifies it symmetrically.
        // The MAC keying MUST match the verify side (VerifyRecordMAC in
        // GetKeyUnlocked): a loaded v3-v6 wallet uses legacy AES-keyed HMAC, and a
        // non-HD v6 wallet never migrates — so a v7-keyed MAC written here would
        // make the freshly-minted key UNSPENDABLE on the next load. Select keying
        // by the loaded file version, exactly as EncryptWallet/ChangePassphrase do.
        const bool legacyKeying = LegacyRecordKeying();
        if (!ComputeRecordMAC(crypter, encKey.vchCryptedKey, encKey.vchMAC, legacyKeying)) {
            memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
            key.Clear();
            derived.Wipe();
            master_copy.Wipe();
            return false;
        }

        memory_cleanse(masterKeyVec.data(), masterKeyVec.size());
        mapCryptedKeys[address] = encKey;
    } else {
        // Wallet not encrypted - store key directly
        mapKeys[address] = key;
    }

    // Cache HD path mappings
    mapPathToAddress[path] = address;
    mapAddressToPath[address] = path;

    // Add to address list
    vchAddresses.push_back(address);

    // Wipe sensitive data
    key.Clear();  // This will securely wipe private key
    derived.Wipe();
    master_copy.Wipe();

    return true;
}

// LP-7 (wallet-Inv-5 migration): re-encrypt a legacy plaintext HD seed + mnemonic
// under the wallet master key and atomically rewrite the file at v7.
//
// Preconditions (asserted by caller Unlock): wallet is encrypted (masterKey valid),
// unlocked (vMasterKey populated), HD wallet, and the seed is currently PLAINTEXT in
// hdMasterKey.seed/chaincode (m_fHDMasterKeyEncrypted == false, loaded from a v3-v6
// file). cs_wallet is held.
//
// Atomicity / no-data-loss (S-002/S-003):
//   - The on-disk rewrite goes through SaveUnlocked, which writes a temp file,
//     fsyncs, then atomically renames over the original (MoveFileEx / rename).
//     The original is NEVER truncated; an interrupted rewrite leaves either the
//     intact legacy file or the complete v7 file.
//   - If ANY in-memory re-encryption step OR the save fails, we restore the
//     in-memory HD state to its pre-migration plaintext-seed form so the wallet
//     stays consistent with the still-on-disk legacy file, and return false. The
//     caller does not fail the unlock; migration retries next unlock.
bool CWallet::MigrateToEncryptedSeedV7Unlocked(bool* persistedToDisk,
                                               const std::string& bip39Passphrase) {
    if (persistedToDisk) *persistedToDisk = false;
    if (!masterKey.IsValid() || !fWalletUnlocked || !fIsHDWallet) {
        return false;
    }
    // F1 round 3: two migration shapes are handled here.
    //   (a) seed PLAINTEXT at rest (the original LP-7 bug) — re-encrypt the mnemonic
    //       AND the seed, rewrite at v7.
    //   (b) seed ALREADY ENCRYPTED but mnemonic still under the obfuscation key (empty
    //       MAC) — the defer-and-preserve / BIP39-passphrase state produced by the
    //       round-3 EncryptWallet. Only the MNEMONIC needs re-encrypting; the seed is
    //       already safe. seedAlreadyEncrypted gates the EncryptHDMasterKey step below.
    // Any OTHER fully-migrated state (encrypted seed + non-empty mnemonic MAC) is
    // nothing to do — refuse so we never rewrite a clean v7 wallet.
    const bool seedAlreadyEncrypted = fHDMasterKeyEncrypted;
    if (seedAlreadyEncrypted && !vchMnemonicMAC.empty()) {
        return false;  // already fully migrated — nothing to do
    }
    // Cursor M1: migration is only meaningful if we can PERSIST the migrated v7
    // (no-plaintext) file. If autosave is off / no wallet file, an in-memory-only
    // re-encryption would (a) scrub the plaintext seed in memory while the on-disk
    // file STILL holds it, and (b) leave m_loadedFileVersion at the legacy version,
    // so a later SaveUnlocked would emit the v6 layout from now-scrubbed seed slots
    // (data corruption). Skip migration entirely here: keep the wallet in its
    // consistent legacy-plaintext state (both in memory and on disk) and leave the
    // caller's m_fNeedsSeedMigration armed so NeedsSeedMigration() stays true and the
    // remediation keeps surfacing until a real, persistable rewrite can occur.
    if (!m_autoSave || m_walletFile.empty()) {
        return false;
    }

    // --- Snapshot pre-migration in-memory state for rollback ---
    CHDExtendedKey snap_hdMasterKey = hdMasterKey;
    bool snap_fHDMasterKeyEncrypted = fHDMasterKeyEncrypted;
    bool snap_fHDMasterKeyCached = fHDMasterKeyCached;
    CHDExtendedKey snap_hdMasterKeyDecrypted = hdMasterKeyDecrypted;
    std::vector<uint8_t> snap_vchEncryptedMnemonic = vchEncryptedMnemonic;
    std::vector<uint8_t> snap_vchMnemonicMAC = vchMnemonicMAC;
    std::vector<uint8_t> snap_vchMnemonicIV(vchMnemonicIV.begin(), vchMnemonicIV.end());
    std::vector<uint8_t> snap_vchEncryptedHDMasterKey = vchEncryptedHDMasterKey;
    std::vector<uint8_t> snap_vchHDMasterKeyMAC = vchHDMasterKeyMAC;
    std::vector<uint8_t> snap_vchHDMasterKeyIV(vchHDMasterKeyIV.begin(), vchHDMasterKeyIV.end());
    // MIK snapshot (re-MAC'd in Step 2b). Note: m_mik->privkey is kept cleared
    // outside migration, so only the at-rest ciphertext/IV/MAC + flag matter for
    // rollback consistency with the on-disk file.
    bool snap_fHasMIK = fHasMIK;
    std::vector<uint8_t> snap_vchEncryptedMIKPrivKey_all = vchEncryptedMIKPrivKey;
    std::vector<uint8_t> snap_vchMIKPrivKeyMAC_all = vchMIKPrivKeyMAC;
    std::vector<uint8_t> snap_vchMIKPrivKeyIV_all(vchMIKPrivKeyIV.begin(), vchMIKPrivKeyIV.end());
    std::vector<uint8_t> snap_vchMIKPubKey = vchMIKPubKey;
    // LP-7 (HIGH-2): per-address spending keys are re-MAC'd in Step 2c so the
    // migrated v7 file carries v7-keyed (not legacy-AES-keyed) per-address MACs.
    // Snapshot the whole map so a later failure restores the legacy MACs.
    std::map<CDilithiumAddress, CEncryptedKey> snap_mapCryptedKeys = mapCryptedKeys;
    // LP-7 (version-aware writer): migration IS the v6->v7 promotion event. We bump
    // m_loadedFileVersion to v7 BEFORE the Step-3 SaveUnlocked so the version-aware
    // writer emits the v7 layout (encrypted seed, per-record MACs). Snapshot for
    // rollback so a failed migration restores the loaded version → the version-aware
    // writer would then (correctly) emit the intact legacy layout again.
    uint32_t snap_loadedFileVersion = m_loadedFileVersion;

    auto rollback = [&]() {
        m_loadedFileVersion = snap_loadedFileVersion;
        hdMasterKey = snap_hdMasterKey;
        fHDMasterKeyEncrypted = snap_fHDMasterKeyEncrypted;
        fHDMasterKeyCached = snap_fHDMasterKeyCached;
        hdMasterKeyDecrypted = snap_hdMasterKeyDecrypted;
        vchEncryptedMnemonic = snap_vchEncryptedMnemonic;
        vchMnemonicMAC = snap_vchMnemonicMAC;
        vchMnemonicIV.assign(snap_vchMnemonicIV.begin(), snap_vchMnemonicIV.end());
        vchEncryptedHDMasterKey = snap_vchEncryptedHDMasterKey;
        vchHDMasterKeyMAC = snap_vchHDMasterKeyMAC;
        vchHDMasterKeyIV.assign(snap_vchHDMasterKeyIV.begin(), snap_vchHDMasterKeyIV.end());
        fHasMIK = snap_fHasMIK;
        vchEncryptedMIKPrivKey = snap_vchEncryptedMIKPrivKey_all;
        vchMIKPrivKeyMAC = snap_vchMIKPrivKeyMAC_all;
        vchMIKPrivKeyIV.assign(snap_vchMIKPrivKeyIV_all.begin(), snap_vchMIKPrivKeyIV_all.end());
        vchMIKPubKey = snap_vchMIKPubKey;
        mapCryptedKeys = snap_mapCryptedKeys;
    };

    // --- Step 1: recover + re-encrypt the mnemonic under the master key ---
    // Legacy HD-first wallets stored the mnemonic under an obfuscation key derived
    // from the (plaintext) seed; EncryptWallet never re-encrypted it. We still hold
    // the plaintext seed here, so derive that same obfuscation key, decrypt, then
    // re-encrypt under the master key (which also attaches a MAC).
    if (!vchEncryptedMnemonic.empty()) {
        std::vector<uint8_t> ivVec(vchMnemonicIV.begin(), vchMnemonicIV.end());
        std::vector<uint8_t> mnemonicPlain;
        bool decOk = false;

        // Primary case (legacy HD-first wallet): mnemonic under the obfuscation key
        // derived from the seed. F1 round 3: use the LIVE seed via DecryptHDMasterKey,
        // NOT hdMasterKey.seed directly — in the defer-and-preserve (seed-already-
        // encrypted) state that slot is scrubbed and the seed lives in the cache /
        // ciphertext. DecryptHDMasterKey returns the right value in both states.
        {
            CHDExtendedKey live;
            if (DecryptHDMasterKey(live)) {
                std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
                std::vector<uint8_t> hdSeed(live.seed, live.seed + 32);
                DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
                memory_cleanse(hdSeed.data(), hdSeed.size());
                live.Wipe();

                CCrypter obfCrypter;
                decOk = obfCrypter.SetKey(obfKey, ivVec) &&
                        obfCrypter.Decrypt(vchEncryptedMnemonic, mnemonicPlain);
                memory_cleanse(obfKey.data(), obfKey.size());
            }
        }

        // Fallback: a legacy wallet whose mnemonic was encrypted under the master
        // key directly (no MAC). Try the master key if the obfuscation key failed.
        if (!decOk) {
            std::vector<uint8_t> mkVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());
            CCrypter mkCrypter;
            mnemonicPlain.clear();
            decOk = mkCrypter.SetKey(mkVec, ivVec) &&
                    mkCrypter.Decrypt(vchEncryptedMnemonic, mnemonicPlain);
            memory_cleanse(mkVec.data(), mkVec.size());
        }

        if (!decOk) {
            // Could not recover the mnemonic plaintext under either key. Abort
            // migration (leave everything byte-identical) rather than risk a wallet
            // whose mnemonic becomes unreadable. Seed migration only proceeds when
            // the mnemonic can be carried forward.
            memory_cleanse(mnemonicPlain.data(), mnemonicPlain.size());
            rollback();
            return false;
        }

        std::string mnemonicStr(mnemonicPlain.begin(), mnemonicPlain.end());
        memory_cleanse(mnemonicPlain.data(), mnemonicPlain.size());

        // LP-7 (F1, BLOCKER + fold MED-1): a successful Decrypt() only proves PKCS#7
        // padding was well-formed — NOT that the recovered bytes are a real seed
        // phrase, and CMnemonic::Validate only proves SYNTACTIC BIP39 — NOT that the
        // phrase is THIS wallet's seed. Under a wrong-key edge case / partial
        // corruption / format confusion the decrypt can yield a DIFFERENT but
        // syntactically-valid BIP39 string. Re-encrypting that as the authoritative
        // v7 mnemonic and rewriting the file at v7 would discard the original
        // ciphertext => PERMANENT seed loss (the live wallet keeps spending via the
        // in-memory seed, but a later restore-from-phrase yields the WRONG seed).
        //
        // So positively confirm IDENTITY, not just syntax: re-derive the master seed
        // from the recovered mnemonic and compare it byte-for-byte to the wallet's
        // authoritative in-memory hdMasterKey.seed (MnemonicReDerivesSeed, which folds
        // in the CMnemonic::Validate structural gate). Only on an EXACT match do we
        // re-encrypt and discard the original. On ANY mismatch — garbage that passed
        // Validate, OR a legitimate but non-re-derivable BIP39-passphrase wallet —
        // ABORT migration loudly: do NOT call EncryptMnemonic (which would overwrite
        // vchEncryptedMnemonic/IV/MAC), roll back to the pre-migration snapshot so the
        // original ciphertext is preserved byte-for-byte, and leave the wallet in its
        // prior valid state. The migration safely defers and re-arms on the next
        // unlock. INVARIANT (absolute): the original seed ciphertext is NEVER discarded
        // unless the recovered phrase PROVABLY derives this wallet's seed.
        //
        // F1 round 3: try the empty passphrase FIRST (the common cohort, behaviour
        // unchanged), then — only if that fails AND the caller supplied a non-empty
        // BIP39 passphrase — retry the identity check WITH that passphrase so a
        // legitimate passphrase wallet can complete migration. Still fail-closed: a
        // wrong/absent passphrase leaves verified==false → ABORT-AND-PRESERVE.
        bool verified = MnemonicReDerivesSeed(mnemonicStr, "");
        if (!verified && !bip39Passphrase.empty()) {
            verified = MnemonicReDerivesSeed(mnemonicStr, bip39Passphrase);
        }
        if (!verified) {
            // LOW-5: &mnemonicStr[0] on an empty string is UB; guard the cleanse.
            if (!mnemonicStr.empty()) {
                memory_cleanse(&mnemonicStr[0], mnemonicStr.size());
            }
            std::cerr << "[Wallet] LP-7: v7 seed migration DEFERRED — the recovered "
                         "mnemonic does not re-derive this wallet's seed under the "
                         "empty passphrase"
                      << (bip39Passphrase.empty()
                              ? " (no BIP39 passphrase was supplied)"
                              : " or the supplied BIP39 passphrase")
                      << ". This wallet either uses an optional BIP39 passphrase (re-run "
                         "unlock with the correct \"bip39passphrase\") or the decrypt "
                         "produced a valid-but-wrong phrase. The original seed "
                         "ciphertext was NOT modified; the wallet remains fully "
                         "loadable and usable. Migration will be retried on the next "
                         "unlock." << std::endl;
            rollback();
            return false;
        }

        bool reOk = EncryptMnemonic(mnemonicStr);  // master-key branch + MAC
        // LOW-5: guard against &mnemonicStr[0] UB on an empty string.
        if (!mnemonicStr.empty()) {
            memory_cleanse(&mnemonicStr[0], mnemonicStr.size());
        }
        if (!reOk) {
            rollback();
            return false;
        }
    }

    // --- Step 2: encrypt the HD master seed (scrubs plaintext, sets ciphertext+MAC) ---
    // F1 round 3: in the defer-and-preserve state (b) the seed is ALREADY encrypted —
    // EncryptHDMasterKey would fail/double-encrypt, so skip it. Only the plaintext-seed
    // case (a) needs this step.
    if (!seedAlreadyEncrypted) {
        if (!EncryptHDMasterKey()) {
            rollback();
            return false;
        }
    }

    // --- Step 2b: re-MAC the MIK private key (legacy encrypted MIK had no MAC) ---
    // A legacy encrypted wallet stored the MIK ciphertext WITHOUT a MAC. Once we
    // mark this wallet v7, DecryptMIKPrivKey requires a non-empty MAC, so recover
    // the MIK plaintext (legacy path: empty MAC + pre-v7 version still set) and
    // re-encrypt it under the master key with a MAC. If the MIK can't be recovered
    // it is non-fatal (MIK is regenerable) — clear it so it regenerates on next use.
    if (fHasMIK && !vchEncryptedMIKPrivKey.empty() && vchMIKPrivKeyMAC.empty()) {
        std::vector<uint8_t, SecureAllocator<uint8_t>> mikPlain;
        if (DecryptMIKPrivKey(mikPlain)) {
            if (!m_mik) {
                m_mik = std::make_unique<DFMP::CMiningIdentityKey>();
                m_mik->pubkey = vchMIKPubKey;
                m_mik->identity = DFMP::DeriveIdentityFromMIK(vchMIKPubKey);
            }
            m_mik->privkey.assign(mikPlain.begin(), mikPlain.end());
            bool mikOk = EncryptMIKPrivKey();   // adds MAC under master key
            m_mik->privkey.clear();
            if (!mikOk) {
                rollback();
                return false;
            }
        } else {
            // MIK plaintext unrecoverable — drop it (regenerated on next mining).
            std::cerr << "[Wallet] LP-7: MIK private key unrecoverable during migration; "
                         "will regenerate on next mining attempt" << std::endl;
            fHasMIK = false;
            vchEncryptedMIKPrivKey.clear();
            vchMIKPrivKeyMAC.clear();
            vchMIKPubKey.clear();
            m_mikIdentity = DFMP::Identity();
            m_mik.reset();
        }
    }

    // --- Step 2c: re-MAC every per-address spending key under v7 keying ---
    // LP-7 (HIGH-2): a pre-LP-7 build computed per-address MACs with the legacy
    // AES-keyed HMAC (or, for a v3-v6 key that predates the MAC, with no MAC at
    // all). Once this file is marked v7, GetKey verifies per-address MACs with the
    // SEPARATED keying — so the legacy-keyed / empty MACs would mismatch and the
    // keys would become unspendable in a file that claims to be v7. Recompute each
    // MAC with v7 separated keying now (the encrypt-then-MAC tag is over the
    // ciphertext, which migration does NOT change, so no decrypt is needed — we
    // re-key the crypter with each key's own IV and recompute). The master key in
    // vMasterKey is the same key these were encrypted under.
    {
        std::vector<uint8_t> mkVec(vMasterKey.data_ptr(),
                                   vMasterKey.data_ptr() + vMasterKey.size());
        for (auto& kv : mapCryptedKeys) {
            CEncryptedKey& ek = kv.second;
            if (ek.vchCryptedKey.empty() || ek.vchIV.size() != WALLET_CRYPTO_IV_SIZE) {
                // Malformed entry — cannot re-MAC safely. Abort rather than write a
                // v7 file with a per-address key that can't be authenticated.
                memory_cleanse(mkVec.data(), mkVec.size());
                rollback();
                return false;
            }
            CCrypter keyCrypter;
            if (!keyCrypter.SetKey(mkVec, ek.vchIV)) {
                memory_cleanse(mkVec.data(), mkVec.size());
                rollback();
                return false;
            }
            std::vector<uint8_t> newMAC;
            if (!ComputeRecordMAC(keyCrypter, ek.vchCryptedKey, newMAC)) {
                memory_cleanse(mkVec.data(), mkVec.size());
                rollback();
                return false;
            }
            ek.vchMAC = newMAC;
        }
        memory_cleanse(mkVec.data(), mkVec.size());
    }

    // --- Step 3: atomic v7 rewrite. SaveUnlocked never truncates the original. ---
    // Promote to v7 FIRST so the version-aware SaveUnlocked emits the v7 layout (the
    // seed is now encrypted; a v6 write here would be wrong). rollback() restores the
    // loaded version if the save fails, keeping in-memory state consistent with the
    // still-intact on-disk legacy file.
    // Cursor M1: persist-capability (autosave on + wallet file set) was verified at
    // entry — if it had not held we returned early WITHOUT any in-memory mutation, so
    // we never reach here with a half-migrated state we cannot persist. The guard
    // below is kept defensively (the else-arm fails closed).
    if (m_autoSave && !m_walletFile.empty()) {
        m_loadedFileVersion = WALLET_FILE_VERSION_7;
        if (!SaveUnlocked()) {
            // The on-disk legacy file is still intact (temp file was discarded).
            // Roll back in-memory state to match it (including the loaded version).
            rollback();
            return false;
        }
        // The migrated v7 (no-plaintext) file is now on disk — only NOW is it safe
        // for the caller to clear the migration flag / treat the file as v7.
        if (persistedToDisk) *persistedToDisk = true;
    } else {
        // Unreachable given the entry guard, but fail closed rather than report a
        // half-migrated success: roll back so in-memory state stays consistent with
        // the unchanged on-disk legacy file.
        rollback();
        return false;
    }

    return true;
}

bool CWallet::EncryptHDMasterKey() {
    // Assumes caller holds cs_wallet lock

    if (!masterKey.IsValid()) {
        return false;  // Wallet not encrypted
    }
    if (!fWalletUnlocked) {
        return false;  // Need the in-memory master key to encrypt
    }

    // FIX-010: Generate unique IV for HD master key
    if (!GenerateUniqueIV_Locked(vchHDMasterKeyIV)) {
        return false;
    }

    // Prepare master key seed + chaincode (64 bytes total)
    std::vector<uint8_t> masterKeyData(64);
    std::memcpy(masterKeyData.data(), hdMasterKey.seed, 32);
    std::memcpy(masterKeyData.data() + 32, hdMasterKey.chaincode, 32);

    // Encrypt with wallet master key
    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    if (!crypter.SetKey(vMasterKeyVec, vchHDMasterKeyIV)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        return false;
    }

    // LP-7 (wallet-Inv-5): AES-256-CBC with PKCS#7 padding turns the 64-byte
    // plaintext (an exact multiple of the 16-byte block) into an 80-byte
    // ciphertext (a full extra padding block is appended). The old code rejected
    // any size != 64 and tried to cram the result into the fixed 32+32 slots,
    // which was unsatisfiable -> the encrypt path was dead. We now store the FULL
    // variable-length ciphertext in vchEncryptedHDMasterKey.
    std::vector<uint8_t> encrypted;
    if (!crypter.Encrypt(masterKeyData, encrypted)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        return false;
    }

    // Sanity: AES-CBC ciphertext must be a non-empty multiple of the block size.
    if (encrypted.empty() || (encrypted.size() % 16) != 0) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        memory_cleanse(encrypted.data(), encrypted.size());
        return false;
    }

    // LP-7 (wallet-Inv-2): authenticate the ciphertext (encrypt-then-MAC) with a
    // separately-derived MAC key (key separation, default keying).
    // LP-7 (round 3): route through ComputeRecordMAC — at-rest HD-master record, always v7.
    std::vector<uint8_t> mac;
    if (!ComputeRecordMAC(crypter, encrypted, mac)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(masterKeyData.data(), masterKeyData.size());
        memory_cleanse(encrypted.data(), encrypted.size());
        return false;
    }

    // Store the variable-length ciphertext + MAC.
    vchEncryptedHDMasterKey = encrypted;
    vchHDMasterKeyMAC = mac;

    // LP-7 (S-001 / S-006): scrub the plaintext seed/chaincode from the in-memory
    // struct now that the ciphertext is the storage-of-record. SaveUnlocked at v7
    // persists vchEncryptedHDMasterKey, NOT these slots, so no plaintext can reach
    // disk. The decrypted value lives only in hdMasterKeyDecrypted (re-cached below).
    memory_cleanse(hdMasterKey.seed, sizeof(hdMasterKey.seed));
    memory_cleanse(hdMasterKey.chaincode, sizeof(hdMasterKey.chaincode));

    fHDMasterKeyEncrypted = true;

    // Refresh the decrypted cache so callers that read it (e.g. address
    // derivation) keep working while unlocked.
    std::memcpy(hdMasterKeyDecrypted.seed, masterKeyData.data(), 32);
    std::memcpy(hdMasterKeyDecrypted.chaincode, masterKeyData.data() + 32, 32);
    hdMasterKeyDecrypted.depth = hdMasterKey.depth;
    hdMasterKeyDecrypted.fingerprint = hdMasterKey.fingerprint;
    hdMasterKeyDecrypted.child_index = hdMasterKey.child_index;
    fHDMasterKeyCached = true;

    // Wipe sensitive data
    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    memory_cleanse(masterKeyData.data(), masterKeyData.size());
    memory_cleanse(encrypted.data(), encrypted.size());

    return true;
}

bool CWallet::DecryptHDMasterKey(CHDExtendedKey& decrypted) const {
    // Assumes caller holds cs_wallet lock

    if (!fHDMasterKeyEncrypted) {
        // Not encrypted, just copy
        decrypted = hdMasterKey;
        return true;
    }

    if (!fWalletUnlocked) {
        return false;  // Wallet locked
    }

    // WL-010 FIX: Use cached decrypted key if available
    if (fHDMasterKeyCached) {
        decrypted = hdMasterKeyDecrypted;
        return true;
    }

    // LP-7 (wallet-Inv-5): the ciphertext must come from the variable-length
    // field. A v7 wallet always populates vchEncryptedHDMasterKey on load.
    if (vchEncryptedHDMasterKey.empty()) {
        return false;
    }

    // Cache miss - decrypt HD master key
    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    if (!crypter.SetKey(vMasterKeyVec, vchHDMasterKeyIV)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    // LP-7 (HIGH-2): authenticate-before-decrypt via the ONE centralized gate.
    // HD-master-seed consumer. Empty MAC on a v7 wallet is rejected; legacy v3-v6
    // records (no HD-master MAC) take the unauthenticated legacy path; a present
    // MAC is verified with the version-correct keying.
    if (!VerifyRecordMAC(crypter, vchEncryptedHDMasterKey, vchHDMasterKeyMAC)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;  // empty MAC on v7, or MAC verification failed
    }

    std::vector<uint8_t> decrypted_data;
    if (!crypter.Decrypt(vchEncryptedHDMasterKey, decrypted_data)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    if (decrypted_data.size() != 64) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(decrypted_data.data(), decrypted_data.size());
        return false;
    }

    // Copy decrypted data to output
    std::memcpy(decrypted.seed, decrypted_data.data(), 32);
    std::memcpy(decrypted.chaincode, decrypted_data.data() + 32, 32);
    decrypted.depth = hdMasterKey.depth;
    decrypted.fingerprint = hdMasterKey.fingerprint;
    decrypted.child_index = hdMasterKey.child_index;

    // Wipe sensitive data
    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    memory_cleanse(decrypted_data.data(), decrypted_data.size());

    return true;
}

bool CWallet::MnemonicReDerivesSeed(const std::string& mnemonic,
                                    const std::string& candidatePassphrase) const {
    // Assumes caller holds cs_wallet lock and the plaintext hdMasterKey.seed is
    // available (true on every legacy-migration / EncryptWallet re-encrypt path,
    // where the obfuscation key itself is derived from that same plaintext seed).
    //
    // LP-7 (F1 fold, MED-1/MED-2): positively confirm the recovered phrase IS this
    // wallet's seed before any caller discards the original mnemonic ciphertext.
    // CMnemonic::Validate (the existing guard) only proves SYNTACTIC BIP39 — a
    // wrong-but-valid phrase from a confused/partial-corruption decrypt would pass
    // it. Re-derive the 32-byte master seed from the recovered mnemonic and compare
    // it byte-for-byte against the authoritative in-memory hdMasterKey.seed. Only an
    // EXACT match proves identity.
    //
    // Passphrase note (F1 round 3): Dilithion's optional BIP39 passphrase is never
    // persisted, so it must be SUPPLIED to verify a passphrase-protected seed.
    // candidatePassphrase defaults to "" (the empty-passphrase cohort, unchanged).
    // A passphrase wallet matches ONLY when the caller threads the correct BIP39
    // passphrase through here; a wrong/absent candidate returns false and the caller
    // MUST ABORT-AND-PRESERVE — an unverifiable mnemonic is never permitted to
    // overwrite the authoritative ciphertext. Conservative by construction.

    // Cheap structural gate first (word count + wordlist + checksum). Keeps the
    // expensive PBKDF2 derive off obviously-garbage input.
    if (!CMnemonic::Validate(mnemonic)) {
        return false;
    }

    // Re-derive the BIP39 seed (with the supplied candidate passphrase, default "")
    // then the HD master seed.
    CKeyingMaterial bip39_seed(64);  // RAII: auto-wipes on scope exit
    if (!CMnemonic::ToSeed(mnemonic, candidatePassphrase, bip39_seed.data_ptr())) {
        return false;
    }

    CHDExtendedKey rederived;
    DeriveMaster(bip39_seed.data_ptr(), rederived);

    // F1 round 3: compare against the LIVE master seed obtained via DecryptHDMasterKey.
    // hdMasterKey.seed is the plaintext slot ONLY while the seed is plaintext at rest;
    // once EncryptHDMasterKey() has run (e.g. the defer-and-preserve EncryptWallet path,
    // or a reloaded deferred-state wallet), that slot is SCRUBBED and the live seed lives
    // in the decrypted cache / ciphertext. DecryptHDMasterKey returns the right value in
    // both states (plaintext copy, or cache/decrypt when encrypted+unlocked), so the
    // identity check works on the deferred (seed-encrypted) path too. Fail closed if the
    // live seed cannot be obtained (e.g. locked).
    CHDExtendedKey authoritative;
    if (!DecryptHDMasterKey(authoritative)) {
        rederived.Wipe();
        return false;
    }

    // Constant-time-ish byte compare against the authoritative live seed.
    // (memcmp is acceptable here: a mismatch means abort, not a secret-leaking
    //  timing oracle — both inputs are local and the decision is fail-closed.)
    const bool match =
        std::memcmp(rederived.seed, authoritative.seed, sizeof(authoritative.seed)) == 0;

    rederived.Wipe();
    authoritative.Wipe();
    return match;
}

bool CWallet::EncryptMnemonic(const std::string& mnemonic) {
    // Assumes caller holds cs_wallet lock

    // FIX-010: Generate unique IV
    if (!GenerateUniqueIV_Locked(vchMnemonicIV)) {
        return false;
    }

    std::vector<uint8_t> mnemonicBytes(mnemonic.begin(), mnemonic.end());

    if (masterKey.IsValid()) {
        // Wallet encrypted - use master key
        CCrypter crypter;
        std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                           vMasterKey.data_ptr() + vMasterKey.size());

        if (!crypter.SetKey(vMasterKeyVec, vchMnemonicIV)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        if (!crypter.Encrypt(mnemonicBytes, vchEncryptedMnemonic)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        // LP-7 (wallet-Inv-2): authenticate the mnemonic ciphertext (encrypt-then-MAC)
        // LP-7 (round 3): route through ComputeRecordMAC — at-rest mnemonic record, always v7.
        if (!ComputeRecordMAC(crypter, vchEncryptedMnemonic, vchMnemonicMAC)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    } else {
        // WL-003 FIX: Wallet not encrypted - derive obfuscation key from wallet-unique data
        //
        // CRITICAL SECURITY FIX: Old code used fixed key (0x42...) = trivially decryptable
        //
        // New approach: Derive obfuscation key from HD master key fingerprint
        // This creates a unique key per wallet that's not easily guessable.
        //
        // Security properties:
        // - Unique per wallet (derived from HD master key)
        // - Not plaintext or fixed key
        // - Attacker needs both wallet file AND swap/memory dump
        // - Still weaker than passphrase encryption (user should encrypt wallet!)
        //
        // WL-007 FIX: Use HKDF for proper key derivation with domain separation
        // Derive obfuscation key from HD master key using HKDF-SHA3-256
        std::vector<uint8_t> tempKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(hdMasterKey.seed,
                                    hdMasterKey.seed + 32);

        // Derive encryption key using HKDF with "mnemonic" context
        // This provides cryptographic domain separation from other derived keys
        DeriveEncryptionKey(hdSeed, "mnemonic", tempKey);

        // Wipe temporary HD seed copy
        memory_cleanse(hdSeed.data(), hdSeed.size());

        CCrypter crypter;
        if (!crypter.SetKey(tempKey, vchMnemonicIV)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        if (!crypter.Encrypt(mnemonicBytes, vchEncryptedMnemonic)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
            return false;
        }

        // Obfuscation-only (unencrypted wallet): no authenticated MAC. Clear any
        // stale MAC so it is never mistaken for an authenticated record.
        vchMnemonicMAC.clear();

        memory_cleanse(tempKey.data(), tempKey.size());
    }

    memory_cleanse(mnemonicBytes.data(), mnemonicBytes.size());
    return true;
}

bool CWallet::DecryptMnemonic(std::string& mnemonic) const {
    // Assumes caller holds cs_wallet lock

    if (vchEncryptedMnemonic.empty()) {
        return false;
    }

    std::vector<uint8_t> decrypted;

    if (masterKey.IsValid()) {
        // Wallet encrypted - decrypt with master key
        if (!fWalletUnlocked) {
            return false;  // Wallet locked
        }

        CCrypter crypter;
        std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                           vMasterKey.data_ptr() + vMasterKey.size());

        if (!crypter.SetKey(vMasterKeyVec, vchMnemonicIV)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            return false;
        }

        // LP-7 (F1 round 3): DEFER-AND-PRESERVE window. When a BIP39-passphrase wallet
        // was encrypted but its mnemonic migration was deferred, the mnemonic is still
        // under the OBFUSCATION key (empty MAC) — the master-key branch below would
        // (correctly, for the general case) reject the empty MAC. To keep the backup
        // phrase exportable in this window (e.g. so the user can verify it before
        // supplying the passphrase), fall back to the obfuscation key when migration is
        // deferred-for-passphrase AND no mnemonic MAC is present. The seed is encrypted
        // at rest but decrypted into hdMasterKey.seed while unlocked, so the obfuscation
        // key is re-derivable. This fallback is gated narrowly on the deferred flag —
        // it does NOT relax the authenticated master-key path for normal v7 wallets.
        if (m_migrationDeferredPassphrase && vchMnemonicMAC.empty()) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            // Use the LIVE seed (via DecryptHDMasterKey) — in the deferred state the seed
            // is encrypted at rest, so hdMasterKey.seed is scrubbed; the obfuscation key
            // must be derived from the decrypted cache / ciphertext.
            CHDExtendedKey live;
            if (!DecryptHDMasterKey(live)) {
                return false;
            }
            std::vector<uint8_t> obfKey(WALLET_CRYPTO_KEY_SIZE);
            std::vector<uint8_t> hdSeed(live.seed, live.seed + 32);
            DeriveEncryptionKey(hdSeed, "mnemonic", obfKey);
            memory_cleanse(hdSeed.data(), hdSeed.size());
            live.Wipe();

            CCrypter obfCrypter;
            bool ok = obfCrypter.SetKey(obfKey, vchMnemonicIV) &&
                      obfCrypter.Decrypt(vchEncryptedMnemonic, decrypted);
            memory_cleanse(obfKey.data(), obfKey.size());
            if (!ok) {
                return false;
            }
            std::string candidate(decrypted.begin(), decrypted.end());
            memory_cleanse(decrypted.data(), decrypted.size());
            // LP-7 (F1 round 4, red-team HIGH-1 / extreview BLOCKER): the deferred
            // obfuscation-key branch has NO per-record MAC (empty by construction in
            // this window), so a tampered/corrupt vchEncryptedMnemonic that happens to
            // unpad cleanly would otherwise be handed back to the user via
            // exportmnemonic as their authentic backup phrase. Gate on the BIP39
            // checksum/wordlist before returning: garbage/corruption fails Validate and
            // export REFUSES rather than emitting a useless "seed phrase".
            //
            // CRITICAL: this MUST be CMnemonic::Validate (the syntactic checksum gate),
            // NOT MnemonicReDerivesSeed("") — a legitimate BIP39-passphrase wallet's real
            // mnemonic does NOT re-derive the seed under an empty passphrase, so an
            // empty-passphrase identity check would WRONGLY refuse legit passphrase-wallet
            // exports (the exact cohort round-3 fixed). Validate catches tamper/corruption
            // without needing the passphrase.
            if (!CMnemonic::Validate(candidate)) {
                memory_cleanse(candidate.data(), candidate.size());
                return false;
            }
            mnemonic = candidate;
            memory_cleanse(candidate.data(), candidate.size());
            return true;
        }

        // LP-7 (HIGH-2): authenticate-before-decrypt via the ONE centralized gate.
        // Mnemonic consumer. Empty MAC on a v7 wallet is rejected; legacy v3-v6
        // (no mnemonic MAC) takes the unauthenticated legacy path; a present MAC
        // is verified with the version-correct keying.
        if (!VerifyRecordMAC(crypter, vchEncryptedMnemonic, vchMnemonicMAC)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            return false;  // empty MAC on v7, or MAC verification failed
        }

        if (!crypter.Decrypt(vchEncryptedMnemonic, decrypted)) {
            memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
            return false;
        }

        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    } else {
        // WL-003 FIX: Wallet not encrypted - derive same obfuscation key as EncryptMnemonic
        // WL-007 FIX: Use HKDF (must match EncryptMnemonic key derivation)
        std::vector<uint8_t> tempKey(WALLET_CRYPTO_KEY_SIZE);
        std::vector<uint8_t> hdSeed(hdMasterKey.seed,
                                    hdMasterKey.seed + 32);

        DeriveEncryptionKey(hdSeed, "mnemonic", tempKey);
        memory_cleanse(hdSeed.data(), hdSeed.size());

        CCrypter crypter;
        if (!crypter.SetKey(tempKey, vchMnemonicIV)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            return false;
        }

        if (!crypter.Decrypt(vchEncryptedMnemonic, decrypted)) {
            memory_cleanse(tempKey.data(), tempKey.size());
            return false;
        }

        memory_cleanse(tempKey.data(), tempKey.size());
    }

    mnemonic = std::string(decrypted.begin(), decrypted.end());
    memory_cleanse(decrypted.data(), decrypted.size());

    return true;
}

// ============================================================================
// Mining Identity Key (MIK) - DFMP v2.0
// ============================================================================

bool CWallet::GenerateMIK() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    // Check if MIK already exists
    if (fHasMIK) {
        std::cout << "[WALLET] MIK already exists for this wallet" << std::endl;
        return false;
    }

    // Check if wallet is locked
    if (masterKey.IsValid() && !fWalletUnlocked) {
        std::cerr << "[WALLET] Cannot generate MIK - wallet is locked" << std::endl;
        return false;
    }

    // Create new MIK
    m_mik = std::make_unique<DFMP::CMiningIdentityKey>();
    if (!m_mik->Generate()) {
        std::cerr << "[WALLET] Failed to generate MIK keypair" << std::endl;
        m_mik.reset();
        return false;
    }

    // Store public key and identity (always needed for coinbase)
    vchMIKPubKey = m_mik->pubkey;
    m_mikIdentity = m_mik->identity;

    // If wallet is encrypted, encrypt the MIK private key
    if (masterKey.IsValid()) {
        if (!EncryptMIKPrivKey()) {
            std::cerr << "[WALLET] Failed to encrypt MIK private key" << std::endl;
            m_mik.reset();
            vchMIKPubKey.clear();
            return false;
        }
        // Clear the in-memory private key (will be decrypted on demand)
        m_mik->privkey.clear();
    }

    fHasMIK = true;
    fMIKRegistered = false;  // Not yet on-chain

    std::cout << "[WALLET] Generated MIK identity: " << m_mikIdentity.GetHex() << std::endl;

    // Auto-save if enabled
    if (m_autoSave && !m_walletFile.empty()) {
        SaveUnlocked();
    }

    return true;
}

bool CWallet::EncryptMIKPrivKey() {
    // Assumes caller holds cs_wallet lock
    // Assumes m_mik is valid and has private key

    if (!masterKey.IsValid() || !m_mik || !m_mik->HasPrivateKey()) {
        return false;
    }

    // Generate unique IV
    if (!GenerateUniqueIV_Locked(vchMIKPrivKeyIV)) {
        return false;
    }

    // Encrypt MIK private key with wallet master key
    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    if (!crypter.SetKey(vMasterKeyVec, vchMIKPrivKeyIV)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    // Create plaintext from private key
    std::vector<uint8_t> plaintext(m_mik->privkey.begin(), m_mik->privkey.end());

    if (!crypter.Encrypt(plaintext, vchEncryptedMIKPrivKey)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(plaintext.data(), plaintext.size());
        return false;
    }

    // LP-7 (wallet-Inv-2): authenticate the MIK ciphertext (encrypt-then-MAC)
    // LP-7 (round 3): route through ComputeRecordMAC — at-rest MIK record, always v7.
    if (!ComputeRecordMAC(crypter, vchEncryptedMIKPrivKey, vchMIKPrivKeyMAC)) {
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        memory_cleanse(plaintext.data(), plaintext.size());
        return false;
    }

    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
    memory_cleanse(plaintext.data(), plaintext.size());

    return true;
}

bool CWallet::DecryptMIKPrivKey(std::vector<uint8_t, SecureAllocator<uint8_t>>& privkeyOut) const {
    // Assumes caller holds cs_wallet lock

    if (!masterKey.IsValid() || !fWalletUnlocked) {
        std::cerr << "[WALLET] DecryptMIKPrivKey: wallet not encrypted or not unlocked" << std::endl;
        return false;
    }

    if (vchEncryptedMIKPrivKey.empty() || vchMIKPrivKeyIV.empty()) {
        std::cerr << "[WALLET] DecryptMIKPrivKey: encrypted key empty=" << vchEncryptedMIKPrivKey.empty()
                  << " IV empty=" << vchMIKPrivKeyIV.empty() << std::endl;
        return false;
    }

    CCrypter crypter;
    std::vector<uint8_t> vMasterKeyVec(vMasterKey.data_ptr(),
                                       vMasterKey.data_ptr() + vMasterKey.size());

    // Convert SecureAllocator IV to regular vector for SetKey
    std::vector<uint8_t> iv(vchMIKPrivKeyIV.begin(), vchMIKPrivKeyIV.end());

    if (!crypter.SetKey(vMasterKeyVec, iv)) {
        std::cerr << "[WALLET] DecryptMIKPrivKey: SetKey failed" << std::endl;
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    // LP-7 (HIGH-2): authenticate-before-decrypt via the ONE centralized gate.
    // MIK-private-key consumer. Empty MAC on a v7 wallet is rejected; legacy v3-v6
    // (no MIK MAC) takes the unauthenticated legacy path; a present MAC is
    // verified with the version-correct keying.
    if (!VerifyRecordMAC(crypter, vchEncryptedMIKPrivKey, vchMIKPrivKeyMAC)) {
        std::cerr << "[WALLET] DecryptMIKPrivKey: MAC verification failed or missing on v7 wallet" << std::endl;
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    std::vector<uint8_t> decrypted;
    if (!crypter.Decrypt(vchEncryptedMIKPrivKey, decrypted)) {
        std::cerr << "[WALLET] DecryptMIKPrivKey: Decrypt failed" << std::endl;
        memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());
        return false;
    }

    memory_cleanse(vMasterKeyVec.data(), vMasterKeyVec.size());

    // Copy to secure output
    privkeyOut.assign(decrypted.begin(), decrypted.end());
    memory_cleanse(decrypted.data(), decrypted.size());

    return true;
}

bool CWallet::HasMIK() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return fHasMIK;
}

bool CWallet::GetMIKPubKey(std::vector<uint8_t>& pubkey) const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fHasMIK || vchMIKPubKey.empty()) {
        return false;
    }

    pubkey = vchMIKPubKey;
    return true;
}

DFMP::Identity CWallet::GetMIKIdentity() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fHasMIK) {
        return DFMP::Identity();  // Null identity
    }

    return m_mikIdentity;
}

bool CWallet::SignWithMIK(const uint256& prevHash, int height, uint32_t timestamp,
                          std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fHasMIK) {
        std::cerr << "[WALLET] Cannot sign - no MIK generated" << std::endl;
        return false;
    }

    // If wallet is encrypted, we need to decrypt the private key
    if (masterKey.IsValid()) {
        if (!fWalletUnlocked) {
            std::cerr << "[WALLET] Cannot sign - wallet is locked" << std::endl;
            return false;
        }

        // Decrypt private key temporarily
        std::vector<uint8_t, SecureAllocator<uint8_t>> privkey;
        if (!DecryptMIKPrivKey(privkey)) {
            std::cerr << "[WALLET] Failed to decrypt MIK private key" << std::endl;
            return false;
        }

        // Create temporary MIK with decrypted private key
        DFMP::CMiningIdentityKey tempMik;
        tempMik.pubkey = vchMIKPubKey;
        tempMik.privkey = std::move(privkey);
        tempMik.identity = m_mikIdentity;

        // Sign
        bool result = tempMik.Sign(prevHash, height, timestamp, signature);

        // tempMik destructor will securely wipe the private key
        return result;
    } else {
        // Wallet not encrypted - use in-memory MIK directly
        if (!m_mik || !m_mik->HasPrivateKey()) {
            std::cerr << "[WALLET] MIK private key not available" << std::endl;
            return false;
        }

        return m_mik->Sign(prevHash, height, timestamp, signature);
    }
}

bool CWallet::SignDNAEnvelope(const std::array<uint8_t, 20>& mik,
                              uint64_t timestamp_sec,
                              uint64_t nonce,
                              const std::vector<uint8_t>& dna_data,
                              std::vector<uint8_t>& signature_out) {
    std::lock_guard<std::mutex> lock(cs_wallet);
    signature_out.clear();

    if (!fHasMIK) return false;

    // Verify the requested MIK matches our wallet's MIK identity. Reject
    // attempts to sign for a different MIK (would always fail crypto verify
    // anyway, but reject early to avoid leaking the privkey to a no-op).
    if (std::memcmp(mik.data(), m_mikIdentity.data, 20) != 0) return false;

    // Encrypted wallet: decrypt privkey, sign, wipe on scope exit.
    if (masterKey.IsValid()) {
        if (!fWalletUnlocked) return false;  // locked — cannot decrypt

        std::vector<uint8_t, SecureAllocator<uint8_t>> privkey;
        if (!DecryptMIKPrivKey(privkey)) return false;
        bool ok = digital_dna::SampleEnvelope::Sign(
            privkey.data(), privkey.size(),
            mik, timestamp_sec, nonce, dna_data, signature_out);
        // privkey wiped by SecureAllocator destructor here.
        return ok;
    }

    // Unencrypted wallet: privkey already in m_mik->privkey.
    if (!m_mik || !m_mik->HasPrivateKey()) return false;
    return digital_dna::SampleEnvelope::Sign(
        m_mik->privkey.data(), m_mik->privkey.size(),
        mik, timestamp_sec, nonce, dna_data, signature_out);
}

bool CWallet::IsMIKRegistered() const {
    std::lock_guard<std::mutex> lock(cs_wallet);
    return fMIKRegistered;
}

void CWallet::SetMIKRegistered() {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (fHasMIK && !fMIKRegistered) {
        fMIKRegistered = true;
        std::cout << "[WALLET] MIK marked as registered on-chain" << std::endl;

        // Auto-save to persist registration status
        if (m_autoSave && !m_walletFile.empty()) {
            SaveUnlocked();
        }
    }
}

std::string CWallet::GetMIKIdentityHex() const {
    std::lock_guard<std::mutex> lock(cs_wallet);

    if (!fHasMIK) {
        return "";
    }

    return m_mikIdentity.GetHex();
}
