// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_WALLET_WALLET_H
#define DILITHION_WALLET_WALLET_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <amount.h>
#include <uint256.h>
#include <wallet/crypter.h>
#include <wallet/hd_derivation.h>
#include <wallet/mnemonic.h>
#include <dfmp/mik.h>

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <chrono>

// Forward declarations for PERSIST-008 FIX (WAL)
class CWalletWAL;
class CWalletRecovery;  // CID 1675307 FIX: Forward declaration for friend class

// Dilithium3 parameters (balanced security/performance)
static const size_t DILITHIUM_PUBLICKEY_SIZE = 1952;
static const size_t DILITHIUM_SECRETKEY_SIZE = 4032;
static const size_t DILITHIUM_SIGNATURE_SIZE = 3309;

// FIX-011 (PERSIST-001): Wallet File Format v3 with Integrity Protection
// File format: [Magic][Version][Flags][HMAC][Salt][Data...]
static const char WALLET_FILE_MAGIC_V3[] = "DILWLT03";
static const uint32_t WALLET_FILE_VERSION_3 = 3;
// v4: Added fCoinbase field to wallet transactions for tracking mining rewards
static const char WALLET_FILE_MAGIC_V4[] = "DILWLT04";
static const uint32_t WALLET_FILE_VERSION_4 = 4;
// v5: Added Mining Identity Key (MIK) for DFMP v2.0
static const char WALLET_FILE_MAGIC_V5[] = "DILWLT05";
static const uint32_t WALLET_FILE_VERSION_5 = 5;
// v6: Added sent transaction history persistence (mapSentTx)
static const char WALLET_FILE_MAGIC_V6[] = "DILWLT06";
static const uint32_t WALLET_FILE_VERSION_6 = 6;
// LP-7 (wallet-Inv-5/4/2): encryption-at-rest fix.
//   - HD master seed+chaincode stored as a VARIABLE-LENGTH AES-CBC+PKCS7
//     ciphertext (not the fixed 32+32 plaintext slots) when encrypted.
//   - Mnemonic / HD-master / MIK ciphertext records each carry an HMAC
//     (encrypt-then-MAC), verified before decrypt; empty MAC rejected on v7.
//   - HMAC keyed with a SEPARATELY-derived MAC key (key separation).
// One-way: encrypted wallets are written ONLY at v7; legacy plaintext-seed
// wallets are read for migration and rewritten at v7 on next unlock.
static const char WALLET_FILE_MAGIC_V7[] = "DILWLT07";
static const uint32_t WALLET_FILE_VERSION_7 = 7;
static const size_t WALLET_FILE_HMAC_SIZE = 32;    // HMAC-SHA3-256 output
static const size_t WALLET_FILE_SALT_SIZE = 32;    // Salt for HMAC
static const size_t WALLET_FILE_HEADER_SIZE = 8 + 4 + 4 + 32 + 32;  // Magic + Version + Flags + HMAC + Salt = 80 bytes

/**
 * Dilithium key pair
 * WS-001: Secure memory wiping for private keys
 * FIX-009 (CRYPT-004): Use SecureAllocator to prevent private key swapping
 */
struct CKey {
    std::vector<uint8_t> vchPubKey;  // Public key (1952 bytes) - can be public
    // FIX-009: Use SecureAllocator for private key to prevent swapping to disk
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchPrivKey; // Secret key (4032 bytes)

    CKey() {}

    // WS-001: Destructor securely wipes private key from memory
    ~CKey() {
        Clear();
    }

    bool IsValid() const {
        return vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchPrivKey.size() == DILITHIUM_SECRETKEY_SIZE;
    }

    // WS-001: Clear with secure memory wiping
    void Clear() {
        // Securely wipe private key before clearing
        if (!vchPrivKey.empty()) {
            memory_cleanse(vchPrivKey.data(), vchPrivKey.size());
        }
        vchPrivKey.clear();

        // Public key doesn't need secure wiping (it's public)
        vchPubKey.clear();
    }
};

/**
 * Encrypted key data
 * FIX-008 (CRYPT-007): Added HMAC for authenticated encryption (prevents padding oracle attacks)
 */
struct CEncryptedKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted private key
    std::vector<uint8_t> vchIV;          // Initialization vector
    std::vector<uint8_t> vchPubKey;      // Public key (unencrypted)
    std::vector<uint8_t> vchMAC;         // FIX-008: HMAC-SHA3-512 of (IV || ciphertext)

    CEncryptedKey() {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchMAC.size() == 64;  // FIX-008: HMAC-SHA3-512 is 64 bytes
    }

    // FIX-008: Check if this is a legacy key (no MAC)
    bool IsLegacy() const {
        return !vchCryptedKey.empty() &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchPubKey.size() == DILITHIUM_PUBLICKEY_SIZE &&
               vchMAC.empty();
    }
};

/**
 * Master key - encrypted with user passphrase
 * FIX-008 (CRYPT-007): Added HMAC for authenticated encryption
 */
struct CMasterKey {
    std::vector<uint8_t> vchCryptedKey;  // Encrypted master key
    std::vector<uint8_t> vchSalt;        // PBKDF2 salt
    std::vector<uint8_t> vchIV;          // Initialization vector
    std::vector<uint8_t> vchMAC;         // FIX-008: HMAC-SHA3-512 of (IV || ciphertext)
    unsigned int nDerivationMethod;       // 0 = PBKDF2-SHA3
    unsigned int nDeriveIterations;       // Number of iterations (default: 100,000)

    CMasterKey() : nDerivationMethod(0), nDeriveIterations(WALLET_CRYPTO_PBKDF2_ROUNDS) {}

    bool IsValid() const {
        return !vchCryptedKey.empty() &&
               vchSalt.size() == WALLET_CRYPTO_SALT_SIZE &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchMAC.size() == 64;  // FIX-008: HMAC-SHA3-512 is 64 bytes
    }

    // FIX-008: Check if this is a legacy key (no MAC)
    bool IsLegacy() const {
        return !vchCryptedKey.empty() &&
               vchSalt.size() == WALLET_CRYPTO_SALT_SIZE &&
               vchIV.size() == WALLET_CRYPTO_IV_SIZE &&
               vchMAC.empty();
    }
};

/**
 * Dilithium address - Base58 encoded hash of public key
 * Named CDilithiumAddress to avoid conflict with network CDilithiumAddress (P2P address)
 */
class CDilithiumAddress {
private:
    std::vector<uint8_t> vchData; // 20-byte hash + 4-byte checksum

public:
    CDilithiumAddress() {}
    explicit CDilithiumAddress(const std::vector<uint8_t>& pubkey);

    // Constructor from raw address data (for loading from wallet file)
    static CDilithiumAddress FromData(const std::vector<uint8_t>& data) {
        CDilithiumAddress addr;
        addr.vchData = data;
        return addr;
    }

    std::string ToString() const;
    bool SetString(const std::string& str);

    bool IsValid() const { return vchData.size() == 21; } // 1 version byte + 20 hash bytes

    const std::vector<uint8_t>& GetData() const { return vchData; }

    bool operator==(const CDilithiumAddress& other) const {
        return vchData == other.vchData;
    }

    bool operator<(const CDilithiumAddress& other) const {
        return vchData < other.vchData;
    }
};

/**
 * Wallet transaction output
 */
struct CWalletTx {
    uint256 txid;
    uint32_t vout;
    int64_t nValue;
    CDilithiumAddress address;
    bool fSpent;
    bool fCoinbase;  // True if this is a coinbase (mining reward) output
    uint32_t nHeight;

    CWalletTx() : vout(0), nValue(0), fSpent(false), fCoinbase(false), nHeight(0) {}
};

/**
 * BUG #104 FIX: Structure to track sent (outgoing) transactions
 * These are transactions where we spent from our wallet to another address
 */
struct CSentTx {
    uint256 txid;           // Transaction ID
    CDilithiumAddress toAddress;  // Recipient address
    int64_t nValue;         // Amount sent (excluding fee)
    int64_t nFee;           // Transaction fee
    int64_t nTime;          // Timestamp when sent
    uint32_t nHeight;       // Block height when confirmed (0 = unconfirmed/mempool)

    CSentTx() : nValue(0), nFee(0), nTime(0), nHeight(0) {}
};

/**
 * Wallet - manages keys, addresses, and transactions
 *
 * Features:
 * - CRYSTALS-Dilithium key pair generation
 * - Address generation and validation
 * - Transaction signing
 * - UTXO tracking
 * - Balance calculation
 *
 * Usage:
 *   CWallet wallet;
 *   wallet.GenerateNewKey();
 *   CDilithiumAddress addr = wallet.GetNewAddress();
 *   int64_t balance = wallet.GetBalance();
 */
class CWallet {
    // CID 1675307 FIX: Friend declaration to allow recovery functions to use unlocked methods
    friend class CWalletRecovery;

private:
    // Key storage
    std::map<CDilithiumAddress, CKey> mapKeys;              // Unencrypted keys (when wallet not encrypted)
    std::map<CDilithiumAddress, CEncryptedKey> mapCryptedKeys;  // Encrypted keys
    std::vector<CDilithiumAddress> vchAddresses;

    // FIX-005 (WALLET-001): Transaction tracking with composite key
    // Changed from std::map<uint256, CWalletTx> to prevent key collision
    // When a transaction has multiple outputs to wallet, old code overwrote entries
    // New code uses COutPoint(txid, vout) as key to store each output separately
    std::map<COutPoint, CWalletTx> mapWalletTx;

    // BUG #104 FIX: Track sent (outgoing) transactions
    // Key is txid since we only have one send per transaction
    std::map<uint256, CSentTx> mapSentTx;

    // Encryption
    CMasterKey masterKey;                           // Master key (encrypted with passphrase)
    CKeyingMaterial vMasterKey;                     // Decrypted master key (only when unlocked)
    bool fWalletUnlocked;                           // Is wallet currently unlocked?
    bool fWalletUnlockForStakingOnly;              // Unlock for staking only (future use)
    std::chrono::time_point<std::chrono::steady_clock> nUnlockTime;  // Auto-lock time
    // WL-011 FIX: Rate limiting with exponential backoff
    uint32_t nUnlockFailedAttempts;                // Consecutive failed unlock attempts
    std::chrono::time_point<std::chrono::steady_clock> nLastFailedUnlock;  // Time of last failed attempt

    // FIX-010 (CRYPT-002): IV Reuse Detection
    // Track all IVs used in this wallet to prevent reuse (which would break AES-CBC security)
    std::set<std::vector<uint8_t>> usedIVs;        // Set of all IVs used for encryption

    // Internal helper: Generate unique IV (assumes caller holds cs_wallet lock)
    template<typename Alloc>
    bool GenerateUniqueIV_Locked(std::vector<uint8_t, Alloc>& iv);

    // Thread safety
    mutable std::mutex cs_wallet;

    // Default address
    CDilithiumAddress defaultAddress;

    // Persistence
    std::string m_walletFile;  // Current wallet file path
    bool m_autoSave;           // Auto-save after changes

    // LP-7: on-disk format version the wallet was loaded from (0 if never loaded
    // / freshly created in memory). v3-v6 records used legacy AES-keyed HMAC and a
    // plaintext HD seed; v7 uses key-separated HMAC and a variable-length encrypted
    // HD seed. Used to (a) verify legacy MACs with the correct keying, and (b)
    // detect a legacy plaintext-seed encrypted wallet that needs migration on unlock.
    uint32_t m_loadedFileVersion{0};
    // LP-7: set true at load when an encrypted wallet was read in a pre-v7 format
    // with a plaintext HD seed at rest (the bug condition). Triggers atomic
    // re-encryption + v7 rewrite on the next successful unlock.
    bool m_fNeedsSeedMigration{false};

    // LP-7 migration helper (assumes caller holds cs_wallet, wallet unlocked).
    // Re-encrypts the plaintext HD seed + mnemonic under the master key and
    // rewrites the wallet file at v7 atomically (via SaveUnlocked). Leaves the
    // original file byte-identical on any failure (SaveUnlocked only renames a
    // fully-written temp file into place; the original is never truncated).
    bool MigrateToEncryptedSeedV7Unlocked();

    // LP-7 (HIGH-2): CENTRALIZED authenticated-decrypt gate for ALL five at-rest
    // encrypted record types (master key, per-address spending keys, HD-master
    // seed, mnemonic, MIK private key). Every decrypt path MUST route its MAC
    // check through this one helper so the version-keyed selection + empty-MAC
    // policy cannot be applied to four-of-five and missed on the fifth (the exact
    // shape of round-1 HIGH-1 and round-2 HIGH-2). Single source of truth for the
    // policy:
    //   (a) keying: v3-v6 records were MAC'd with the legacy AES-keyed HMAC; v7
    //       records use the separately-derived MAC key. Selected by the on-disk
    //       version (m_loadedFileVersion).
    //   (b) empty-MAC: on a v7 wallet an empty MAC is CORRUPT — reject (no
    //       unauthenticated decrypt of a root secret). On a pre-v7 wallet an
    //       empty MAC is the genuine legacy record — allow the unauthenticated
    //       decrypt so the wallet loads and can migrate.
    //   (c) verify-before-decrypt: when a MAC is present it is verified with the
    //       version-correct keying BEFORE the caller decrypts.
    // Returns true iff the caller may proceed to decrypt. `crypter` must already
    // have SetKey() called (same key the ciphertext was encrypted under).
    // Assumes caller holds cs_wallet.
    bool VerifyRecordMAC(CCrypter& crypter,
                         const std::vector<uint8_t>& ciphertext,
                         const std::vector<uint8_t>& mac) const;

    // LP-7 (HIGH-2): CENTRALIZED MAC computation for WRITES / re-MAC. Always uses
    // the v7 separated-key HMAC — new and migrated records are written ONLY at v7.
    // Routing all writes through here keeps write-keying in lockstep with the
    // read policy above. `crypter` must already have SetKey() called.
    bool ComputeRecordMAC(CCrypter& crypter,
                          const std::vector<uint8_t>& ciphertext,
                          std::vector<uint8_t>& macOut) const;

    // UTXO set reference for balance validation in callbacks
    class CUTXOSet* m_utxo_set_ref{nullptr};

    // ============================================================================
    // BUG #56 FIX: Best Block Tracking (Bitcoin Core Pattern - PR #30221)
    // ============================================================================
    // Tracks the last block the wallet was synced to, enabling:
    // - Incremental rescans on startup (not full UTXO scan)
    // - Proper crash recovery (resume from last persisted block)
    // - Correct reorg handling (blockDisconnected updates this)
    uint256 m_bestBlockHash;      // Hash of last block wallet was synced to
    int32_t m_bestBlockHeight;    // Height of last block (-1 = not initialized)

    // PERSIST-008 FIX: Write-Ahead Log for atomic multi-step operations
    std::unique_ptr<CWalletWAL> m_wal;  // WAL instance (nullptr if not initialized)

    // WALLET-006 FIX: UTXO locking mechanism to prevent concurrent transaction conflicts
    std::set<COutPoint> setLockedCoins;  // UTXOs locked for transaction creation (protected by cs_wallet)

    // v4.0.17: deferred mining-reward notifications
    //
    // DilV uses lowest-VDF-output tiebreak which causes 3-8 same-height tip
    // swaps within ~2s before a round settles. The previous behaviour fired
    // "MINING REWARD CREDITED" inline at block-connect time, so users saw
    // 4-8 reward messages for a single height while their balance never
    // changed. Now we queue the notification at connect, drop it silently if
    // the same block hash is later disconnected, and only print once a
    // higher block has been connected on top (the round is settled).
    struct PendingMiningNotification {
        uint256 blockHash;
        int     blockHeight;
        int64_t reward;
        int64_t balanceSnapshot;
        std::string addressStr;
    };
    std::vector<PendingMiningNotification> m_pendingMiningNotifications;  // protected by cs_wallet

    // ============================================================================
    // HD Wallet (Hierarchical Deterministic) - BIP32/BIP44
    // ============================================================================

    bool fIsHDWallet;                          // Is this an HD wallet?
    std::vector<uint8_t> vchEncryptedMnemonic; // Encrypted BIP39 mnemonic (already encrypted, can use normal allocator)
    std::vector<uint8_t> vchMnemonicMAC;       // LP-7 (wallet-Inv-2): HMAC over the mnemonic ciphertext (v7+)
    // FIX-009: Use SecureAllocator for IVs to prevent leakage
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchMnemonicIV;        // IV for mnemonic encryption
    CHDExtendedKey hdMasterKey;                // Master extended key (encrypted in memory)
    bool fHDMasterKeyEncrypted;                // Is master key encrypted?
    // LP-7 (wallet-Inv-5): variable-length AES-CBC+PKCS7 ciphertext of the
    // 64-byte seed+chaincode. Non-empty ONLY when fHDMasterKeyEncrypted is true
    // and the wallet was written/migrated at v7. When set, the in-memory
    // hdMasterKey.seed/chaincode hold THIS ciphertext (not plaintext) at rest,
    // and the variable-length blob is what is persisted (NOT the fixed 32+32 slots).
    std::vector<uint8_t> vchEncryptedHDMasterKey;
    std::vector<uint8_t> vchHDMasterKeyMAC;    // LP-7 (wallet-Inv-2): HMAC over the HD-master ciphertext (v7+)
    // FIX-009: Use SecureAllocator for IVs to prevent leakage
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchHDMasterKeyIV;     // IV for master key encryption
    // WL-010 FIX: Cache decrypted HD master key when wallet unlocked for performance
    CHDExtendedKey hdMasterKeyDecrypted;       // Cached decrypted HD master (only valid when unlocked)
    bool fHDMasterKeyCached;                   // Is cached key valid?

    // HD chain state (BIP44: m/44'/573'/account'/change'/index')
    uint32_t nHDAccountIndex;                  // Current account (default: 0)
    uint32_t nHDExternalChainIndex;            // Next receive address index
    uint32_t nHDInternalChainIndex;            // Next change address index

    // HD address mappings
    std::map<CDilithiumAddress, CHDKeyPath> mapAddressToPath;  // Address -> derivation path
    std::map<CHDKeyPath, CDilithiumAddress> mapPathToAddress;  // Derivation path -> address

    static const uint32_t HD_GAP_LIMIT = 20;   // BIP44 gap limit

    // ============================================================================
    // Mining Identity Key (MIK) - DFMP v2.0
    // ============================================================================

    /** Mining Identity Key (unique_ptr because CMiningIdentityKey is non-copyable) */
    std::unique_ptr<DFMP::CMiningIdentityKey> m_mik;

    /** Encrypted MIK private key (when wallet is encrypted) */
    std::vector<uint8_t> vchEncryptedMIKPrivKey;

    /** LP-7 (wallet-Inv-2): HMAC over the MIK private-key ciphertext (v7+) */
    std::vector<uint8_t> vchMIKPrivKeyMAC;

    /** IV for MIK private key encryption */
    std::vector<uint8_t, SecureAllocator<uint8_t>> vchMIKPrivKeyIV;

    /** MIK public key (stored even when encrypted, needed for coinbase creation) */
    std::vector<uint8_t> vchMIKPubKey;

    /** MIK identity (cached, derived from pubkey) */
    DFMP::Identity m_mikIdentity;

    /** True if MIK has been generated for this wallet */
    bool fHasMIK;

    /** True if MIK is registered on-chain (has mined at least one block) */
    bool fMIKRegistered;

    // MIK private helper methods - assume caller holds cs_wallet lock
    bool EncryptMIKPrivKey();
    bool DecryptMIKPrivKey(std::vector<uint8_t, SecureAllocator<uint8_t>>& privkeyOut) const;

    // Private helper methods - assume caller already holds cs_wallet lock
    bool SaveUnlocked(const std::string& filename = "") const;
    std::vector<uint8_t> GetPubKeyHashUnlocked() const;
    std::vector<uint8_t> GetPublicKeyUnlocked() const;
    bool GetKeyUnlocked(const CDilithiumAddress& address, CKey& keyOut) const;
    bool IsUnlockValid() const;  // VULN-002 FIX: Check if unlock hasn't expired (acquires cs_wallet)
    bool _IsUnlockValidNoLock() const;  // BUG #74 FIX: Same as above but assumes caller holds cs_wallet
    bool IsCryptedUnlocked() const;  // BUG #56 FIX: Check encryption without lock (avoids deadlock in ValidateConsistency)
    // FIX-006 (WALLET-002): Internal helper to add UTXO without acquiring lock (avoids deadlock in ScanUTXOs)
    bool AddTxOutUnlocked(const uint256& txid, uint32_t vout, int64_t nValue,
                          const CDilithiumAddress& address, uint32_t nHeight,
                          bool fCoinbase = false);

    // HD wallet private helpers - assume caller already holds cs_wallet lock
    bool DeriveAndCacheHDAddress(const CHDKeyPath& path);
    bool EncryptHDMasterKey();
    bool DecryptHDMasterKey(CHDExtendedKey& decrypted) const;
    bool EncryptMnemonic(const std::string& mnemonic);
    bool DecryptMnemonic(std::string& mnemonic) const;

    // ============================================================================
    // BUG #56 FIX: Block processing helpers (Bitcoin Core pattern)
    // ============================================================================

    /**
     * Process all transactions in a block for wallet relevance
     * Called by blockConnected/blockDisconnected
     *
     * @param block The block to process
     * @param height Block height
     * @param connecting True if block is being connected, false if disconnecting
     * @note Assumes caller holds cs_wallet lock
     */
    void ProcessBlockTransactionsUnlocked(const class CBlock& block, int height, bool connecting, const uint256& blockHash);

    // v4.0.17: settle / drop deferred mining-reward notifications.
    // FlushSettled prints any queued notifications whose block has now been
    // buried by at least one further block (round is settled). DropForBlock
    // silently removes notifications belonging to a specific block hash —
    // called from the disconnect path so transient tip-swap blocks never
    // produce a visible reward message.
    void FlushSettledMiningNotificationsUnlocked(int currentHeight);
    void DropPendingMiningNotificationsForBlockUnlocked(const uint256& blockHash);

    /**
     * Update best block pointer and persist to disk (Bitcoin Core: SetLastBlockProcessed)
     * This is the atomic update that ensures crash recovery works correctly
     *
     * @param hash Block hash
     * @param height Block height
     * @note Assumes caller holds cs_wallet lock
     */
    void SetLastBlockProcessedUnlocked(const uint256& hash, int height);

    /**
     * WALLET-008 FIX: Clean up stale UTXOs (unlocked version)
     * Internal helper that assumes caller already holds cs_wallet lock
     * 
     * @param utxo_set Current UTXO set from blockchain
     * @return Number of stale UTXOs removed
     * @note Caller must hold cs_wallet lock
     */
    size_t CleanupStaleUTXOsUnlocked(class CUTXOSet& utxo_set);

    /**
     * PERSIST-008 FIX: Check for incomplete WAL operations and recover (unlocked version)
     * Internal helper that assumes caller already holds cs_wallet lock
     * 
     * @return true if recovery successful or no recovery needed, false on error
     * @note Caller must hold cs_wallet lock
     */
    bool RecoverFromWALUnlocked();

    /**
     * Lock wallet (unlocked version)
     * Internal helper that assumes caller already holds cs_wallet lock
     *
     * @return true if successful
     * @note Caller must hold cs_wallet lock
     */
    bool LockUnlocked();

    /**
     * BUG #112 FIX: Update sent transaction height (unlocked version)
     * Internal helper that assumes caller already holds cs_wallet lock
     * Called from blockConnected to update TX confirmation heights
     *
     * @param txid Transaction ID to update
     * @param nHeight Block height where confirmed
     * @note Caller must hold cs_wallet lock
     */
    void UpdateSentTransactionHeightUnlocked(const uint256& txid, uint32_t nHeight);

public:
    CWallet();
    ~CWallet();

    // Prevent copying
    CWallet(const CWallet&) = delete;
    CWallet& operator=(const CWallet&) = delete;

    /**
     * Generate a new Dilithium key pair
     * @return true if successful
     */
    bool GenerateNewKey();

    /**
     * Get the default receiving address
     * @return address or empty if no keys
     */
    CDilithiumAddress GetNewAddress();

    /**
     * Get all addresses in wallet
     */
    std::vector<CDilithiumAddress> GetAddresses() const;

    /**
     * Check if wallet has a key for this address
     */
    bool HasKey(const CDilithiumAddress& address) const;

    /**
     * Get the key for an address
     * @param address Address to look up
     * @param keyOut Output key
     * @return true if key found
     */
    bool GetKey(const CDilithiumAddress& address, CKey& keyOut) const;

    /**
     * Import an external private key into the wallet.
     * Handles encryption if wallet is encrypted.
     * Saves wallet to disk after import.
     * @param key Key to import (pubkey + privkey must be set)
     * @param address Address derived from the key's pubkey
     * @return true if imported successfully
     */
    bool ImportKey(const CKey& key, const CDilithiumAddress& address);

    /**
     * Sign a message hash with address's private key
     * @param address Address whose key to use
     * @param hash Message hash to sign
     * @param signature Output signature
     * @return true if successful
     */
    bool SignHash(const CDilithiumAddress& address, const uint256& hash,
                  std::vector<uint8_t>& signature);

    /**
     * Add a transaction output to the wallet
     * @param fCoinbase True if this is a coinbase (mining reward) output
     */
    bool AddTxOut(const uint256& txid, uint32_t vout, int64_t nValue,
                  const CDilithiumAddress& address, uint32_t nHeight,
                  bool fCoinbase = false);

    /**
     * Mark a transaction output as spent
     */
    bool MarkSpent(const uint256& txid, uint32_t vout);

    /**
     * Get wallet balance (sum of unspent outputs)
     */
    int64_t GetBalance() const;

    /**
     * Get unspent transaction outputs
     */
    std::vector<CWalletTx> GetUnspentTxOuts() const;

    /**
     * WALLET-008 FIX: Clean up stale UTXOs after blockchain reorganization
     *
     * After a blockchain reorg, some UTXOs in the wallet may no longer exist in the
     * current chain. This function checks all wallet UTXOs against the current UTXO set
     * and removes those that are no longer valid.
     *
     * Should be called:
     * - After detecting a blockchain reorganization
     * - Periodically during wallet rescan
     * - On wallet startup (to recover from interrupted reorg handling)
     *
     * @param utxo_set Current UTXO set from blockchain
     * @return Number of stale UTXOs removed
     * Thread-safe: Acquires cs_wallet lock
     */
    size_t CleanupStaleUTXOs(class CUTXOSet& utxo_set);

    /**
     * Clear all transaction history from wallet
     *
     * Used after a blockchain reset to remove orphaned transactions
     * that no longer exist on the chain. Preserves wallet keys and addresses.
     *
     * @return Number of transactions cleared
     */
    size_t ClearAllTransactions();

    // ============================================================================
    // BUG #56 FIX: Chain Notifications (Bitcoin Core Pattern - PR #30221)
    // ============================================================================
    // These callbacks are invoked by CChainState when blocks are connected/disconnected
    // Following Bitcoin Core's interfaces::Chain::Notifications pattern

    /**
     * Called when a new block is connected to the main chain
     *
     * Processes all transactions in the block:
     * - Adds outputs belonging to wallet addresses
     * - Marks wallet inputs as spent
     * - Updates best block pointer (persists to disk)
     *
     * @param block The connected block
     * @param height Block height
     * @param hash Block hash (passed to avoid RandomX recomputation)
     * Thread-safe: Acquires cs_wallet lock
     */
    void blockConnected(const class CBlock& block, int height, const uint256& hash);

    /**
     * Called when a block is disconnected from the main chain (reorg)
     *
     * Reverses the effects of blockConnected:
     * - Removes outputs added by this block
     * - Marks wallet inputs as unspent
     * - Updates best block pointer to previous block
     *
     * @param block The disconnected block
     * @param height Block height being disconnected
     * @param hash Block hash (passed to avoid RandomX recomputation)
     * Thread-safe: Acquires cs_wallet lock
     */
    void blockDisconnected(const class CBlock& block, int height, const uint256& hash);

    /**
     * Get the best block hash the wallet is synced to
     * @return Block hash, or null hash if not initialized
     */
    uint256 GetBestBlockHash() const;

    /**
     * Get the best block height the wallet is synced to
     * @return Block height, or -1 if not initialized
     */
    int32_t GetBestBlockHeight() const;

    /**
     * Rescan blocks in a height range for wallet transactions
     *
     * True incremental scanning: loads each block and processes transactions
     * instead of scanning entire UTXO set. Updates best block after each block.
     *
     * @param chainstate Chain state for block index lookups
     * @param blockchain Database to read block data from
     * @param startHeight First block height to scan (inclusive)
     * @param endHeight Last block height to scan (inclusive)
     * @return true if rescan completed successfully
     * Thread-safe: Acquires cs_wallet lock per block
     */
    bool RescanFromHeight(class CChainState& chainstate, class CBlockchainDB& blockchain,
                          int startHeight, int endHeight);

    /**
     * Get number of keys in wallet
     */
    size_t GetKeyPoolSize() const;

    // ============================================================================
    // Wallet Encryption
    // ============================================================================

    /**
     * Encrypt the wallet with a passphrase
     *
     * This encrypts all existing private keys and sets up the master key.
     * Once encrypted, the wallet must be unlocked with the passphrase to:
     * - Generate new keys
     * - Sign transactions
     * - Export private keys
     *
     * @param passphrase User's wallet passphrase
     * @return true if successful, false if already encrypted or error
     */
    bool EncryptWallet(const std::string& passphrase);

    /**
     * Unlock the wallet for a specified time
     *
     * WL-015 FIX: Complete parameter documentation
     *
     * Decrypts the master key using PBKDF2-SHA3-256 key derivation (500,000 rounds)
     * and keeps it in memory for the timeout period. During this time, the wallet
     * can sign transactions, generate keys, and perform HD derivation.
     *
     * Rate Limiting: Failed unlock attempts trigger exponential backoff (2^n seconds,
     * max 1 hour). Prevents online brute force attacks.
     *
     * @param passphrase User's wallet passphrase. Must meet strength requirements:
     *                   - Minimum 16 characters
     *                   - Password complexity score >= 60
     *                   - See CPassphraseValidator for full requirements
     * @param timeout    Auto-lock timeout in seconds. Wallet automatically locks after
     *                   this duration. Special values:
     *                   - 0 = Never auto-lock (remains unlocked indefinitely)
     *                   - >0 = Lock after N seconds of being unlocked
     *                   Default: 0 (no auto-lock)
     * @return true on success, false if:
     *         - Wallet is not encrypted
     *         - Passphrase is incorrect (increments failed attempt counter)
     *         - Rate limited (too many recent failed attempts)
     *         - PBKDF2 key derivation fails
     * @see Lock(), IsLocked(), EncryptWallet()
     */
    bool Unlock(const std::string& passphrase, int64_t timeout = 0);

    /**
     * Lock the wallet
     *
     * Clears the master key from memory. After locking, signing operations
     * will fail until the wallet is unlocked again.
     *
     * @return true if successful
     */
    bool Lock();

    /**
     * Check if wallet is locked
     *
     * @return true if wallet is encrypted and currently locked
     */
    bool IsLocked() const;

    /**
     * Check if wallet is encrypted
     *
     * @return true if wallet has been encrypted
     */
    bool IsCrypted() const;

    /**
     * Change wallet passphrase
     *
     * WL-015 FIX: Complete parameter documentation
     *
     * Re-encrypts the wallet master key with a new passphrase. This operation:
     * 1. Verifies old passphrase and decrypts current master key
     * 2. Validates new passphrase meets strength requirements
     * 3. Re-encrypts master key with new passphrase using fresh PBKDF2 derivation
     * 4. Updates wallet file with new encrypted master key
     *
     * @param passphraseOld Current wallet passphrase. Must be correct to proceed.
     *                      Subject to same rate limiting as Unlock().
     * @param passphraseNew New wallet passphrase. Must meet strength requirements:
     *                      - Minimum 16 characters
     *                      - Password complexity score >= 60
     *                      - Different from old passphrase
     *                      Validated using CPassphraseValidator before accepting.
     * @return true if successful, false if:
     *         - Wallet is not encrypted
     *         - Old passphrase is incorrect
     *         - New passphrase fails strength validation
     *         - Rate limited from recent failed attempts
     *         - File write operation fails
     * @see Unlock(), EncryptWallet(), CPassphraseValidator
     */
    bool ChangePassphrase(const std::string& passphraseOld,
                          const std::string& passphraseNew);

    /**
     * Check if unlock timeout has expired and auto-lock if needed
     *
     * Called periodically to enforce timeout-based locking.
     */
    void CheckUnlockTimeout();

    // ============================================================================
    // FIX-010 (CRYPT-002): IV Reuse Detection
    // ============================================================================

    /**
     * Generate a unique IV that hasn't been used before
     *
     * Generates a cryptographically random IV and ensures it hasn't been used
     * in this wallet. If collision detected, retries up to 10 times.
     *
     * IV reuse with the same key breaks AES-CBC security - if two plaintexts
     * are encrypted with the same IV and key, an attacker can XOR the
     * ciphertexts to get the XOR of plaintexts, potentially recovering keys.
     *
     * @param iv Output buffer for generated IV (will be resized to 16 bytes)
     * @return true on success, false if collision persists after 10 attempts
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool GenerateUniqueIV(std::vector<uint8_t, SecureAllocator<uint8_t>>& iv);

    /**
     * Register an IV as used (for loading existing wallet IVs)
     *
     * Called when loading encrypted keys from file to populate usedIVs set.
     *
     * @param iv IV to register (must be 16 bytes)
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    void RegisterIV(const std::vector<uint8_t>& iv);

    /**
     * Check if an IV has been used before
     *
     * @param iv IV to check (must be 16 bytes)
     * @return true if IV exists in usedIVs, false otherwise
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool IsIVUsed(const std::vector<uint8_t>& iv) const;

    /**
     * Get count of tracked IVs
     *
     * @return Number of IVs in usedIVs set
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    size_t GetIVCount() const;

    // ============================================================================
    // HD Wallet (Hierarchical Deterministic Wallet) - BIP32/BIP44
    // ============================================================================

    /**
     * Initialize HD wallet from BIP39 mnemonic
     *
     * Creates a new HD wallet from a mnemonic phrase. The wallet will be marked
     * as an HD wallet and subsequent address generation will use HD derivation.
     *
     * BIP44 path: m/44'/573'/0'/0'/0' (Dilithion coin type = 573)
     *
     * @param mnemonic BIP39 mnemonic phrase (12-24 words)
     * @param passphrase Optional BIP39 passphrase (empty string if none)
     * @return true if successful, false if wallet already initialized or invalid mnemonic
     */
    bool InitializeHDWallet(const std::string& mnemonic, const std::string& passphrase = "");

    /**
     * Generate new HD wallet with random mnemonic
     *
     * Creates new BIP39 mnemonic (24 words) and initializes HD wallet.
     *
     * @param mnemonic_out Output parameter for generated mnemonic (24 words)
     * @param passphrase Optional BIP39 passphrase
     * @return true if successful
     */
    bool GenerateHDWallet(std::string& mnemonic_out, const std::string& passphrase = "");

    /**
     * Restore HD wallet from mnemonic and scan for existing addresses
     *
     * Similar to InitializeHDWallet but also scans blockchain for existing
     * addresses up to gap limit.
     *
     * @param mnemonic BIP39 mnemonic phrase
     * @param passphrase Optional BIP39 passphrase
     * @return true if successful
     */
    bool RestoreHDWallet(const std::string& mnemonic, const std::string& passphrase = "");

    /**
     * Get new HD receiving address
     *
     * Derives next address on external chain (m/44'/573'/account'/0'/index').
     * Increments external chain index counter.
     *
     * @return New receiving address, or empty if not HD wallet or locked
     */
    CDilithiumAddress GetNewHDAddress();

    /**
     * Get change address for HD wallet
     *
     * Derives address on internal chain (m/44'/573'/account'/1'/index').
     * Used for sending change back to own wallet.
     *
     * @return Change address, or empty if not HD wallet or locked
     */
    CDilithiumAddress GetChangeAddress();

    /**
     * Derive address at specific BIP44 path
     *
     * Advanced function for deriving addresses at custom paths.
     * Normal users should use GetNewHDAddress() instead.
     *
     * @param path BIP44 path (e.g., "m/44'/573'/0'/0'/5'")
     * @return Derived address, or empty if invalid path or locked
     */
    CDilithiumAddress DeriveAddress(const std::string& path);

    /**
     * Export BIP39 mnemonic phrase
     *
     * Returns the wallet's mnemonic phrase. Wallet must be unlocked.
     * Use with extreme caution - mnemonic provides full access to all funds.
     *
     * @param mnemonic_out Output parameter for mnemonic phrase
     * @return true if successful, false if not HD wallet or wallet locked
     */
    bool ExportMnemonic(std::string& mnemonic_out) const;

    /**
     * Get HD wallet information
     *
     * @param account Output: current account index
     * @param external_index Output: next receive address index
     * @param internal_index Output: next change address index
     * @return true if HD wallet, false otherwise
     */
    bool GetHDWalletInfo(uint32_t& account, uint32_t& external_index,
                         uint32_t& internal_index) const;

    /**
     * Scan HD address chains for existing addresses
     *
     * Scans both receive and change chains up to gap limit (20 unused addresses).
     * Used during wallet restoration to find all previously used addresses.
     *
     * @param utxo_set UTXO set to check for address usage
     * @return Number of addresses found and added to wallet
     */
    size_t ScanHDChains(class CUTXOSet& utxo_set);

    /**
     * Check if this is an HD wallet
     * CID 1675320 FIX: Thread-safe accessor - acquires lock before reading member variable
     */
    bool IsHDWallet() const;

    /**
     * Check if wallet is empty (has no keys/addresses)
     * @return true if wallet has no keys
     */
    bool IsEmpty() const { return vchAddresses.empty(); }

    /**
     * Get derivation path for an address
     *
     * @param address Address to look up
     * @param path_out Output parameter for path
     * @return true if address found and is HD-derived
     */
    bool GetAddressPath(const CDilithiumAddress& address, CHDKeyPath& path_out) const;

    // ============================================================================
    // Mining Identity Key (MIK) - DFMP v2.0
    // ============================================================================

    /**
     * Generate a new Mining Identity Key (MIK)
     *
     * Creates a new Dilithium3 keypair for mining identity. The MIK is separate
     * from payout addresses and persists across address changes, closing the
     * address rotation loophole in DFMP.
     *
     * If the wallet is encrypted, the MIK private key will be encrypted with
     * the master key. The wallet must be unlocked to generate a new MIK.
     *
     * @return true if successful, false if MIK already exists or wallet locked
     */
    bool GenerateMIK();

    /**
     * Check if wallet has a Mining Identity Key
     *
     * @return true if MIK has been generated
     */
    bool HasMIK() const;

    /**
     * Get the MIK public key for coinbase creation
     *
     * @param pubkey Output buffer for public key (1,952 bytes)
     * @return true if MIK exists
     */
    bool GetMIKPubKey(std::vector<uint8_t>& pubkey) const;

    /**
     * Get the MIK identity
     *
     * @return MIK identity (20 bytes), or null identity if no MIK
     */
    DFMP::Identity GetMIKIdentity() const;

    /**
     * Sign a block commitment with the MIK
     *
     * Creates a signature committing to the chain position (prevHash, height, timestamp).
     * This signature is included in the coinbase scriptSig for DFMP v2.0.
     *
     * @param prevHash Previous block hash
     * @param height Block height being mined
     * @param timestamp Block timestamp
     * @param signature Output signature (3,309 bytes)
     * @return true if successful, false if no MIK or wallet locked
     */
    bool SignWithMIK(const uint256& prevHash, int height, uint32_t timestamp,
                     std::vector<uint8_t>& signature);

    /**
     * Check if the MIK is registered on-chain
     *
     * A MIK is registered after its first block is mined and stored in the
     * identity database. Subsequent blocks use the shorter reference format.
     *
     * @return true if MIK has been registered on-chain
     */
    bool IsMIKRegistered() const;

    /**
     * Mark the MIK as registered on-chain
     *
     * Called after successfully mining a block with MIK registration.
     * Future blocks will use the reference format instead of registration.
     */
    void SetMIKRegistered();

    /**
     * Get MIK identity as hex string (for display/logging)
     *
     * @return Hex string (40 chars), or empty string if no MIK
     */
    std::string GetMIKIdentityHex() const;

    /**
     * Get raw pointer to MIK key (for DNA verification signing)
     *
     * @return Pointer to CMiningIdentityKey, or nullptr if no MIK
     *
     * NOTE: returns nullptr for ENCRYPTED wallets even when fHasMIK is true,
     * because the underlying CMiningIdentityKey is not constructed at load
     * time — only the public identity hash is. For signing, prefer
     * GetMIKPrivKey() below, which handles encrypted+unlocked wallets via
     * decrypt-on-demand (mirrors the SignWithMIK pattern).
     */
    const DFMP::CMiningIdentityKey* GetMIKKeyPtr() const { return m_mik.get(); }

    /**
     * Sign a DNA sample envelope (Phase 1.5) with the wallet's MIK private
     * key. Mirrors the SignWithMIK pattern: privkey is decrypted briefly
     * into a SecureAllocator-backed temporary, used for one signing op,
     * and wiped on scope exit. The privkey never leaves wallet scope.
     *
     * Handles both unencrypted and encrypted+unlocked wallets.
     *
     * @param mik           The MIK identity being signed for (must match wallet's MIK)
     * @param timestamp_sec Wall-clock timestamp embedded in the sign target
     * @param nonce         Random per-sample nonce for replay defense
     * @param dna_data      The exact dna_data wire bytes being committed to
     * @param[out] signature_out  Dilithium3 signature (MIK_SIGNATURE_SIZE bytes on success)
     * @return true on success, false if: no MIK / wallet locked / mik mismatch / Dilithium failure
     */
    bool SignDNAEnvelope(const std::array<uint8_t, 20>& mik,
                         uint64_t timestamp_sec,
                         uint64_t nonce,
                         const std::vector<uint8_t>& dna_data,
                         std::vector<uint8_t>& signature_out);

    // ============================================================================
    // Persistence
    // ============================================================================

    /**
     * Load wallet from file
     * @param filename Path to wallet file
     * @return true if successful
     */
    bool Load(const std::string& filename);

    /**
     * Save wallet to file
     * @param filename Path to wallet file (optional, uses current file if empty)
     * @return true if successful
     */
    bool Save(const std::string& filename = "") const;

    /**
     * Set wallet file path and enable auto-save
     * @param filename Path to wallet file
     */
    void SetWalletFile(const std::string& filename);

    /**
     * Get current wallet file path
     */
    std::string GetWalletFile() const { return m_walletFile; }

    /**
     * Enable/disable auto-save
     */
    void SetAutoSave(bool enabled) { m_autoSave = enabled; }
    void SetUTXOSetRef(class CUTXOSet* utxo_set) { m_utxo_set_ref = utxo_set; }

    /**
     * Clear all wallet data
     */
    void Clear();

    /**
     * PERSIST-008 FIX: Initialize Write-Ahead Log for atomic operations
     *
     * Must be called before using AtomicOperation(). Sets up WAL file path
     * and prepares wallet for multi-step atomic operations.
     *
     * @param wallet_path Path to wallet.dat file
     * @return true if WAL initialized successfully, false on error
     */
    bool InitializeWAL(const std::string& wallet_path);

    /**
     * PERSIST-008 FIX: Check for incomplete WAL operations and recover
     *
     * Called on wallet startup to detect crashes during previous operations.
     * If incomplete operations found, executes recovery (rollback or complete).
     *
     * @return true if recovery successful or no recovery needed, false on error
     */
    bool RecoverFromWAL();

    /**
     * PERSIST-008 FIX: Get WAL instance (for advanced operations)
     *
     * @return Pointer to WAL instance, or nullptr if not initialized
     */
    CWalletWAL* GetWAL() const { return m_wal.get(); }

    /**
     * FIX-012 (WALLET-002): Validate wallet structural consistency
     *
     * Performs comprehensive validation of wallet data structures to detect:
     * - Address reconstruction mismatches (public key → address)
     * - HD wallet path gaps (missing derivation indices)
     * - Transaction addresses not belonging to wallet
     * - Encrypted/unencrypted key count mismatches
     * - HD path bidirectional mapping inconsistencies
     *
     * This method performs 5 critical checks:
     *
     * 1. Address Reconstruction: Verifies all addresses match their public keys
     *    - Prevents address<→>key mismatch from file corruption
     *    - Detects tampering with address bytes
     *
     * 2. HD Path Gap Detection: Ensures no missing indices in derivation chains
     *    - External chain: [0, nHDExternalChainIndex)
     *    - Internal chain: [0, nHDInternalChainIndex)
     *    - Detects missing HD addresses in sequential range
     *
     * 3. Transaction Address Validation: All tx addresses belong to wallet
     *    - Prevents orphaned transactions referencing foreign addresses
     *
     * 4. Encrypted Key Count: Encrypted wallets have matching key/address counts
     *    - Detects incomplete encryption or decryption
     *
     * 5. HD Bidirectional Mapping: mapAddressToPath ↔ mapPathToAddress consistency
     *    - Prevents one-way mapping corruption
     *
     * Called automatically during Load() to fail-fast on corruption.
     *
     * @param error_out Output parameter for detailed error description
     * @return true if wallet passes all consistency checks, false if corruption detected
     * @note Thread-safe (acquires cs_wallet lock internally)
     */
    bool ValidateConsistency(std::string& error_out) const;

    // ============================================================================
    // Phase 5.2: UTXO Management & Transaction Creation
    // ============================================================================

    /**
     * Scan the global UTXO set and identify all UTXOs belonging to this wallet
     *
     * This function iterates through the global UTXO set and finds all outputs
     * that are spendable by this wallet's keys. Used for wallet synchronization.
     *
     * @param global_utxo_set The global UTXO set to scan
     * @return true if scan completed successfully
     */
    bool ScanUTXOs(class CUTXOSet& global_utxo_set);

    /**
     * Get wallet's spendable balance
     *
     * Calculates total balance from unspent outputs, excluding immature coinbase.
     * Thread-safe.
     *
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height (for maturity checks)
     * @return Total spendable balance in ions (1 DIL = 100,000,000 ions)
     */
    CAmount GetAvailableBalance(class CUTXOSet& utxo_set, unsigned int current_height) const;

    /**
     * Get wallet's immature coinbase balance
     *
     * Calculates total balance from immature coinbase outputs (not yet 100 confirmations).
     * Thread-safe.
     *
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height (for maturity checks)
     * @return Total immature coinbase balance in ions
     */
    CAmount GetImmatureBalance(class CUTXOSet& utxo_set, unsigned int current_height) const;

    /**
     * List all unspent transaction outputs for this wallet
     *
     * Returns only mature, spendable UTXOs (filters out immature coinbase).
     *
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height
     * @param min_confirmations Minimum confirmations required (default 1) - WALLET-003 FIX
     * @return Vector of wallet transaction outputs
     */
    std::vector<CWalletTx> ListUnspentOutputs(class CUTXOSet& utxo_set, unsigned int current_height, unsigned int min_confirmations = 1) const;

    /**
     * BUG #113 FIX: List ALL wallet outputs for transaction history
     *
     * Returns all outputs ever received by this wallet, including spent ones.
     * Used for displaying complete transaction history in wallet UI.
     *
     * @param current_height Current blockchain height (for confirmation count)
     * @return Vector of all wallet transaction outputs (spent and unspent)
     */
    std::vector<CWalletTx> ListAllOutputs(unsigned int current_height) const;

    // ========================================================================
    // BUG #104 FIX: Sent Transaction Tracking
    // ========================================================================

    /**
     * Record a sent transaction in the wallet
     *
     * @param txid Transaction ID
     * @param toAddress Recipient address
     * @param nValue Amount sent (excluding fee)
     * @param nFee Transaction fee
     * Thread-safe: Acquires cs_wallet lock
     */
    void RecordSentTransaction(const uint256& txid, const CDilithiumAddress& toAddress,
                               int64_t nValue, int64_t nFee);

    /**
     * Get all sent transactions
     *
     * @return Vector of sent transactions
     * Thread-safe: Acquires cs_wallet lock
     */
    std::vector<CSentTx> ListSentTransactions() const;

    /**
     * Update sent transaction with confirmation height
     *
     * @param txid Transaction ID to update
     * @param nHeight Block height where confirmed
     * Thread-safe: Acquires cs_wallet lock
     */
    void UpdateSentTransactionHeight(const uint256& txid, uint32_t nHeight);

    /**
     * Look up a single sent transaction by txid.
     *
     * @param txid Transaction ID to look up
     * @param out Output struct populated on success
     * @return true if the txid is in mapSentTx, false otherwise
     * Thread-safe: Acquires cs_wallet lock
     */
    bool GetSentTransaction(const uint256& txid, CSentTx& out) const;

    /**
     * Check if a specific tx output belongs to this wallet (and, if so,
     * return the stored address + value). Unlike HasKey, this works for
     * HD-derived addresses that aren't in mapKeys but are tracked as
     * UTXOs in mapWalletTx.
     *
     * @param txid Transaction ID
     * @param vout Output index
     * @param addressOut On success, set to the address of the output
     * @param valueOut On success, set to the output value in satoshis
     * @return true if (txid, vout) is in mapWalletTx, false otherwise
     * Thread-safe: Acquires cs_wallet lock
     */
    bool GetWalletOutput(const uint256& txid, uint32_t vout,
                         CDilithiumAddress& addressOut,
                         int64_t& valueOut) const;

    // ========================================================================
    // WALLET-006 FIX: UTXO Locking Mechanism
    // ========================================================================

    /**
     * Lock a UTXO to prevent it from being selected in concurrent transactions
     *
     * @param outpoint The UTXO to lock (txid + vout)
     * Thread-safe: Acquires cs_wallet lock
     */
    void LockCoin(const COutPoint& outpoint);

    /**
     * Unlock a previously locked UTXO
     *
     * @param outpoint The UTXO to unlock
     * Thread-safe: Acquires cs_wallet lock
     */
    void UnlockCoin(const COutPoint& outpoint);

    /**
     * Check if a UTXO is currently locked
     *
     * @param outpoint The UTXO to check
     * @return true if locked, false otherwise
     * Thread-safe: Acquires cs_wallet lock
     */
    bool IsLocked(const COutPoint& outpoint) const;

    /**
     * Get list of all locked UTXOs
     *
     * @return Vector of locked COutPoints
     * Thread-safe: Acquires cs_wallet lock
     */
    std::vector<COutPoint> ListLockedCoins() const;

    /**
     * Unlock all locked UTXOs
     *
     * Useful for recovery or manual intervention
     * Thread-safe: Acquires cs_wallet lock
     */
    void UnlockAllCoins();

    // ========================================================================

    /**
     * Select coins to fund a transaction (coin selection algorithm)
     *
     * Uses simple greedy algorithm: selects largest UTXOs first until target is reached.
     * Future versions can implement more sophisticated algorithms (knapsack, branch & bound).
     *
     * WALLET-006 FIX: Now skips locked UTXOs to prevent concurrent transaction conflicts
     *
     * @param target_value Amount needed (including fee)
     * @param selected_coins Output vector of selected UTXOs
     * @param total_value Output parameter for total value of selected coins
     * @param utxo_set UTXO set to query
     * @param current_height Current blockchain height
     * @param error Error message if selection fails
     * @return true if sufficient coins selected, false if insufficient balance
     */
    bool SelectCoins(CAmount target_value,
                    std::vector<CWalletTx>& selected_coins,
                    CAmount& total_value,
                    class CUTXOSet& utxo_set,
                    unsigned int current_height,
                    std::string& error,
                    const CDilithiumAddress& from_address = CDilithiumAddress()) const;

    /**
     * Create a new transaction
     *
     * Complete transaction creation pipeline:
     * 1. Select coins to cover amount + fee
     * 2. Create inputs from selected coins
     * 3. Create output for recipient
     * 4. Create change output if needed
     * 5. Sign all inputs
     * 6. Validate transaction
     *
     * @param recipient_address Recipient's wallet address
     * @param amount Amount to send (in ions)
     * @param fee Transaction fee (in ions)
     * @param utxo_set UTXO set for coin selection and validation
     * @param current_height Current blockchain height
     * @param tx_out Output parameter for created transaction
     * @param error Error message if creation fails
     * @return true if transaction created successfully
     */
    bool CreateTransaction(const CDilithiumAddress& recipient_address,
                          CAmount amount,
                          CAmount fee,
                          class CUTXOSet& utxo_set,
                          unsigned int current_height,
                          CTransactionRef& tx_out,
                          std::string& error,
                          const CDilithiumAddress& from_address = CDilithiumAddress());

    /**
     * Create a transaction with a custom scriptPubKey (e.g., HTLC).
     *
     * Same as CreateTransaction but accepts raw script bytes instead of address.
     * Used by HTLC RPC commands to lock funds in HTLC contracts.
     *
     * @param scriptPubKey Raw locking script bytes
     * @param amount Amount to lock (in ions/volts)
     * @param fee Transaction fee
     * @param utxo_set UTXO set for coin selection
     * @param current_height Current blockchain height
     * @param nLockTime Transaction nLockTime (0 = none)
     * @param tx_out Output parameter for created transaction
     * @param error Error message if creation fails
     * @return true if transaction created successfully
     */
    bool CreateTransactionToScript(const std::vector<uint8_t>& scriptPubKey,
                                   CAmount amount,
                                   CAmount fee,
                                   class CUTXOSet& utxo_set,
                                   unsigned int current_height,
                                   uint32_t nLockTime,
                                   CTransactionRef& tx_out,
                                   std::string& error);

    /**
     * Sign all inputs of a transaction
     *
     * For each input:
     * 1. Lookup the UTXO being spent
     * 2. Extract the public key hash from scriptPubKey
     * 3. Find corresponding wallet key
     * 4. Create signature message (tx hash + input index)
     * 5. Sign with Dilithium
     * 6. Build scriptSig with signature and public key
     *
     * @param tx Transaction to sign (modified in place)
     * @param utxo_set UTXO set to lookup previous outputs
     * @param error Error message if signing fails
     * @return true if all inputs signed successfully
     */
    bool SignTransaction(CTransaction& tx, class CUTXOSet& utxo_set, std::string& error);

    /**
     * Broadcast a transaction to the network
     *
     * Steps:
     * 1. Validate transaction against consensus rules
     * 2. Add to mempool
     * 3. (Future) Relay to P2P network
     *
     * @param tx Transaction to send
     * @param mempool Mempool to add transaction to
     * @param utxo_set UTXO set for validation
     * @param current_height Current blockchain height
     * @param error Error message if broadcast fails
     * @return true if transaction accepted to mempool
     */
    bool SendTransaction(const CTransactionRef& tx,
                        class CTxMemPool& mempool,
                        class CUTXOSet& utxo_set,
                        unsigned int current_height,
                        std::string& error);

    /**
     * Estimate transaction fee (v1.0: fixed fee)
     *
     * Returns fixed fee for v1.0. Future versions will implement:
     * - Size-based fees
     * - Priority-based fees
     * - Dynamic fee estimation based on mempool
     *
     * @return Estimated fee in ions
     */
    static CAmount EstimateFee() { return DEFAULT_TRANSACTION_FEE; }

    /**
     * Default transaction fee (0.00185000 DLT = 185000 ions)
     * Updated for P2PKH script format (larger than simplified script)
     */
    static const CAmount DEFAULT_TRANSACTION_FEE = 700000;

    /**
     * Get this wallet's public key hash (for receiving payments)
     *
     * @return SHA3-256 hash of default address's public key (32 bytes)
     */
    std::vector<uint8_t> GetPubKeyHash() const;

    /**
     * Get this wallet's public key
     *
     * @return Public key of default address (~1952 bytes for Dilithium3)
     */
    std::vector<uint8_t> GetPublicKey() const;

    /**
     * Get public key hash from an address
     *
     * @param address Address to extract hash from
     * @return Public key hash (20 bytes) or empty vector if invalid
     */
    static std::vector<uint8_t> GetPubKeyHashFromAddress(const CDilithiumAddress& address);
};

/**
 * Crypto utility functions
 */
namespace WalletCrypto {
    /**
     * Generate a new Dilithium3 key pair
     */
    bool GenerateKeyPair(CKey& key);

    /**
     * Sign data with Dilithium3
     */
    bool Sign(const CKey& key, const uint8_t* data, size_t dataLen,
              std::vector<uint8_t>& signature);

    /**
     * Verify Dilithium3 signature
     */
    bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* data,
                size_t dataLen, const std::vector<uint8_t>& signature);

    /**
     * Hash public key to create address
     */
    std::vector<uint8_t> HashPubKey(const std::vector<uint8_t>& pubkey);

    /**
     * Base58 encode with checksum
     */
    std::string EncodeBase58Check(const std::vector<uint8_t>& data);

    /**
     * Base58 decode and verify checksum
     */
    bool DecodeBase58Check(const std::string& str, std::vector<uint8_t>& data);

    /**
     * Create scriptPubKey from public key hash (P2PKH-like)
     *
     * Format: [hash_size(1)] [pubkey_hash(32)] [OP_CHECKSIG(1)]
     *
     * @param pubkey_hash Public key hash (32 bytes from SHA3-256)
     * @return scriptPubKey bytes
     */
    std::vector<uint8_t> CreateScriptPubKey(const std::vector<uint8_t>& pubkey_hash);

    /**
     * Create scriptSig from signature and public key
     *
     * Format: [sig_size(2)] [signature] [pubkey_size(2)] [pubkey]
     * Sizes are little-endian 16-bit integers
     *
     * @param signature Dilithium signature (~3293 bytes)
     * @param pubkey Dilithium public key (~1952 bytes)
     * @return scriptSig bytes
     */
    std::vector<uint8_t> CreateScriptSig(const std::vector<uint8_t>& signature,
                                         const std::vector<uint8_t>& pubkey);

    /**
     * Extract public key hash from scriptPubKey
     *
     * Parses P2PKH-like scriptPubKey to extract the hash.
     *
     * @param scriptPubKey Script to parse
     * @return Public key hash (32 bytes) or empty if invalid
     */
    std::vector<uint8_t> ExtractPubKeyHash(const std::vector<uint8_t>& scriptPubKey);
}

#endif // DILITHION_WALLET_WALLET_H
