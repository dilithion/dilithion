// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_ATTESTATION_SEED_ATTESTATION_H
#define DILITHION_ATTESTATION_SEED_ATTESTATION_H

/**
 * Seed Node Attestation for MIK Registration (Phase 2+3)
 *
 * Prevents datacenter Sybil attacks by requiring miners to obtain
 * attestations from seed nodes at MIK registration time. Seeds verify
 * the miner's TCP source IP against an ASN database and refuse to sign
 * attestations for datacenter IPs.
 *
 * Flow:
 *   1. Miner connects to 4 seed nodes, calls getmikattestation RPC
 *   2. Each seed checks IP against ASN database
 *   3. If residential: seed signs attestation with its Dilithium3 key
 *   4. Miner collects 3+ attestations
 *   5. Attestations embedded in coinbase alongside MIK registration data
 *   6. Consensus validates 3+ valid attestations from known seed keys
 *
 * Attestation message (signed by seed):
 *   SHA3-256("DILV_ATTEST" || mik_pubkey || dna_hash || timestamp_le32 || seed_id)
 *
 * On-chain format per attestation:
 *   [seed_id: 1 byte] [timestamp: 4 bytes LE] [signature: 3309 bytes]
 *   Total: 3314 bytes per attestation
 *
 * Coinbase marker: 0xDA (ATTESTATION_MARKER), followed by count byte,
 * then count × attestation entries.
 */

#include <dfmp/dfmp.h>
#include <dfmp/mik.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace Attestation {

// ============================================================================
// CONSTANTS
// ============================================================================

/** Number of seed nodes (3 for testnet, 4 for mainnet) */
constexpr int NUM_SEEDS = 4;

/** Minimum attestations required (Byzantine: 3-of-4) */
constexpr int MIN_ATTESTATIONS = 3;

/** Coinbase marker byte for attestation data */
constexpr uint8_t ATTESTATION_MARKER = 0xDA;

/** Domain separator for attestation messages */
constexpr const char* ATTESTATION_DOMAIN = "DILV_ATTEST";
constexpr size_t ATTESTATION_DOMAIN_LEN = 11;  // strlen("DILV_ATTEST")

/** Attestation validity window (seconds): attestation must be within this
 *  many seconds of the block timestamp to be accepted */
constexpr int64_t ATTESTATION_VALIDITY_WINDOW = 3600;  // 1 hour

/** Size of one on-chain attestation entry: seed_id(1) + timestamp(4) + signature(3309) */
constexpr size_t ATTESTATION_ENTRY_SIZE = 1 + 4 + DFMP::MIK_SIGNATURE_SIZE;

/** Seed attestation key file name (stored in data directory) */
constexpr const char* SEED_KEY_FILENAME = "seed_attestation_key.dat";

/** LP-13: Env var supplying the operator passphrase used to encrypt the seed
 *  attestation private key at rest. When set, Save() writes the v2 encrypted
 *  format and Load() requires it to decrypt v2 files. When unset, the legacy
 *  v1 plaintext format is used (backward compatible). NEVER hardcode a value. */
constexpr const char* SEED_KEY_PASSPHRASE_ENV = "DILITHION_SEED_KEY_PASSPHRASE";

// ============================================================================
// SEED ATTESTATION KEY
// ============================================================================

/** LP-13: securely zero a transient buffer that may hold plaintext key bytes
 *  (used by CSeedAttestationKey::Save on every exit path). Declared here so the
 *  test suite can verify the wipe; not intended for general use. */
void CleanseSeedKeyBuffer(std::vector<uint8_t>& buf);

/** LP-13 H-2 (atomic-save) TEST SEAM. When set to a non-null function, Save()
 *  invokes it immediately after the temp file has been fully written + fsynced
 *  but BEFORE the atomic rename over the target. If the hook returns true, Save
 *  aborts as if the rename leg failed (returns false, removes the temp file) so
 *  the test can assert the ORIGINAL key file survived byte-intact. nullptr in
 *  production (no overhead, no behavior change). Not for general use. */
extern bool (*g_seedKeySaveFailpoint)();

/**
 * Seed node's Dilithium3 keypair for signing attestations.
 *
 * Generated on first run (if --relay-only seed node), stored in data dir.
 * Public keys are hardcoded in chainparams for consensus verification.
 */
class CSeedAttestationKey {
public:
    CSeedAttestationKey() = default;
    ~CSeedAttestationKey();

    // Non-copyable (contains secret key)
    CSeedAttestationKey(const CSeedAttestationKey&) = delete;
    CSeedAttestationKey& operator=(const CSeedAttestationKey&) = delete;

    /**
     * Generate a new Dilithium3 keypair for this seed node.
     * @return true on success
     */
    bool Generate();

    /**
     * Load keypair from file in data directory.
     * @param dataDir Path to data directory (e.g., ~/.dilv)
     * @return true if loaded successfully, false if file doesn't exist or is corrupt
     */
    bool Load(const std::string& dataDir);

    /**
     * Save keypair to file in data directory.
     *
     * LP-13: The file is written with owner-only permissions (POSIX 0600;
     * Windows best-effort — NTFS already confines the user profile dir).
     * If the env var DILITHION_SEED_KEY_PASSPHRASE is set, the private key is
     * encrypted at rest (AES-256-CBC, PBKDF2-SHA3, encrypt-then-MAC) in the v2
     * file format. If absent, the legacy v1 plaintext format is written so
     * existing un-passphrased operators are not silently broken.
     *
     * LP-13 H-2: the write is ATOMIC — the blob is written to "<file>.tmp",
     * fsync'd, the prior key (if any) is copied to "<file>.bak", then the temp
     * is atomically renamed over the target. A crash / partial write / full disk
     * therefore can NEVER destroy the only copy of the consensus signing key.
     *
     * LP-13 M-4: if BOTH the create-time mode and the post-write chmod fail to
     * set 0600 (POSIX), Save REFUSES to publish a possibly group/other-readable
     * consensus key (fail-closed) and returns false.
     *
     * LP-13 H-1: when requireEncryption is true, Save REFUSES to write a v1
     * (plaintext) key — the passphrase env MUST be set or Save fails loud.
     *
     * @param dataDir Path to data directory
     * @param requireEncryption If true, refuse to write a plaintext (v1) key.
     * @return true on success
     */
    bool Save(const std::string& dataDir, bool requireEncryption = false) const;

    /**
     * Load or generate: tries Load first, generates + saves if not found.
     *
     * LP-13: Auto-minting a fresh consensus key is gated behind allowGenerate.
     * On a production seed a missing key file with allowGenerate=false FAILS
     * LOUD (returns false) instead of silently minting an unrecognized key.
     *
     * LP-13 M-2: if a fresh key is generated but cannot be PERSISTED, this
     * returns false. The node must never run on an in-memory-only key that
     * would not match chainparams after a restart.
     *
     * LP-13 H-1: when requireEncryption is true, a loaded v1 (plaintext) key is
     * REJECTED (returns false) and a generated key is only saved encrypted —
     * enforcing encryption-at-rest end to end.
     *
     * @param dataDir Path to data directory
     * @param allowGenerate If false and no key file exists, fail loudly instead
     *        of generating a new keypair. Set true via the --generate-seed-key
     *        operator flag for first-time key provisioning.
     * @param requireEncryption If true, refuse to load/save a plaintext (v1)
     *        key (--require-seed-key-encryption). Default false preserves the
     *        backward-compatible loadable behavior.
     * @return true on success
     */
    bool LoadOrGenerate(const std::string& dataDir, bool allowGenerate = false,
                        bool requireEncryption = false);

    /**
     * Sign an attestation message.
     * @param message The raw message bytes to sign
     * @param[out] signature Output signature (3309 bytes)
     * @return true on success
     */
    bool Sign(const std::vector<uint8_t>& message,
              std::vector<uint8_t>& signature) const;

    /** Check if key is loaded and valid */
    bool IsValid() const;

    /** Get the public key (1952 bytes) */
    const std::vector<uint8_t>& GetPubKey() const { return m_pubkey; }

    /** Get public key as hex string (for display/logging) */
    std::string GetPubKeyHex() const;

    /** LP-13 H-1: true if the key currently in memory was loaded from a v1
     *  (plaintext) on-disk file. Lets the node enforce
     *  --require-seed-key-encryption end to end. */
    bool LoadedPlaintext() const { return m_loadedV1Plaintext; }

private:
    std::vector<uint8_t> m_pubkey;   // 1952 bytes
    std::vector<uint8_t> m_privkey;  // 4032 bytes (should use SecureAllocator in production)
    bool m_loadedV1Plaintext = false;  // LP-13 H-1: provenance of the in-memory key

    void Clear();
};

// ============================================================================
// ATTESTATION DATA STRUCTURES
// ============================================================================

/**
 * A single seed attestation (on-chain format).
 */
struct CAttestation {
    uint8_t seedId;                              // 0-3, index into seed pubkey array
    uint32_t timestamp;                          // Unix timestamp when attestation was issued
    std::vector<uint8_t> signature;              // 3309 bytes, Dilithium3 signature

    CAttestation() : seedId(0), timestamp(0) {}

    bool IsValid() const {
        return seedId < NUM_SEEDS && signature.size() == DFMP::MIK_SIGNATURE_SIZE;
    }
};

/**
 * Collection of attestations for a MIK registration block.
 */
struct CAttestationSet {
    std::vector<CAttestation> attestations;

    /** Check if we have enough valid attestations */
    bool HasMinimum() const { return attestations.size() >= MIN_ATTESTATIONS; }

    /** Number of attestations */
    size_t Count() const { return attestations.size(); }
};

// ============================================================================
// MESSAGE BUILDING
// ============================================================================

/**
 * Build the attestation message that seeds sign.
 *
 * Message = SHA3-256("DILV_ATTEST" || mik_pubkey || dna_hash || timestamp_le32 || seed_id)
 *
 * @param mikPubkey MIK public key (1952 bytes)
 * @param dnaHash DNA fingerprint hash (32 bytes)
 * @param timestamp Unix timestamp
 * @param seedId Seed node index (0-3)
 * @return 32-byte message hash
 */
std::vector<uint8_t> BuildAttestationMessage(
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    uint32_t timestamp,
    uint8_t seedId);

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verify a single attestation signature against a known seed public key.
 *
 * @param attestation The attestation to verify
 * @param mikPubkey MIK public key (1952 bytes) — used to reconstruct message
 * @param dnaHash DNA hash (32 bytes) — used to reconstruct message
 * @param seedPubkey The seed node's public key (1952 bytes, from chainparams)
 * @return true if signature is valid
 */
bool VerifyAttestation(
    const CAttestation& attestation,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<uint8_t>& seedPubkey);

/**
 * Verify a set of attestations against known seed public keys.
 *
 * @param attestations The attestation set
 * @param mikPubkey MIK public key
 * @param dnaHash DNA hash
 * @param seedPubkeys Array of 4 seed public keys (from chainparams)
 * @param blockTimestamp Block timestamp (for freshness check)
 * @param[out] error Error message if validation fails
 * @return true if >= MIN_ATTESTATIONS are valid
 */
bool VerifyAttestationSet(
    const CAttestationSet& attestations,
    const std::vector<uint8_t>& mikPubkey,
    const std::array<uint8_t, 32>& dnaHash,
    const std::vector<std::vector<uint8_t>>& seedPubkeys,
    int64_t blockTimestamp,
    std::string& error);

// ============================================================================
// SERIALIZATION (on-chain format)
// ============================================================================

/**
 * Build attestation bytes for coinbase scriptSig.
 *
 * Format: [ATTESTATION_MARKER: 0xDA] [count: 1] [entry]...
 * Each entry: [seed_id: 1] [timestamp: 4 LE] [signature: 3309]
 *
 * @param attestations The attestation set
 * @param[out] data Output buffer (appended to)
 * @return true on success
 */
bool BuildAttestationScriptData(
    const CAttestationSet& attestations,
    std::vector<uint8_t>& data);

/**
 * Parse attestation data from coinbase scriptSig bytes.
 *
 * Looks for ATTESTATION_MARKER (0xDA) and extracts attestations.
 *
 * @param data Raw bytes starting at the 0xDA marker
 * @param dataLen Available bytes
 * @param[out] attestations Parsed attestation set
 * @param[out] consumed Number of bytes consumed
 * @return true if parsed successfully
 */
bool ParseAttestationScriptData(
    const uint8_t* data,
    size_t dataLen,
    CAttestationSet& attestations,
    size_t& consumed);

// ============================================================================
// RPC HELPERS
// ============================================================================

/**
 * Request attestation from a single seed node via HTTP RPC.
 *
 * Calls getmikattestation on the seed's RPC port, passing the miner's
 * MIK pubkey and DNA hash. Returns the signed attestation on success.
 *
 * @param seedIP Seed node IP address
 * @param rpcPort Seed node RPC port
 * @param mikPubkey Miner's MIK public key (hex)
 * @param dnaHashHex DNA hash (hex)
 * @param[out] attestation Returned attestation
 * @param[out] error Error message on failure
 * @return true on success
 */
bool RequestAttestation(
    const std::string& seedIP,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestation& attestation,
    std::string& error);

/**
 * Collect attestations from all seed nodes.
 *
 * Contacts each seed in sequence, collecting attestations.
 * Returns when MIN_ATTESTATIONS are collected or all seeds contacted.
 *
 * @param seedIPs Array of seed node IPs
 * @param rpcPort RPC port for seeds
 * @param mikPubkeyHex Miner's MIK pubkey (hex)
 * @param dnaHashHex DNA hash (hex)
 * @param[out] attestations Collected attestations
 * @param[out] error Error message if insufficient attestations
 * @return true if >= MIN_ATTESTATIONS collected
 */
bool CollectAttestations(
    const std::vector<std::string>& seedIPs,
    uint16_t rpcPort,
    const std::string& mikPubkeyHex,
    const std::string& dnaHashHex,
    CAttestationSet& attestations,
    std::string& error);

} // namespace Attestation

#endif // DILITHION_ATTESTATION_SEED_ATTESTATION_H
