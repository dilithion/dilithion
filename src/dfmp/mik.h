// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_DFMP_MIK_H
#define DILITHION_DFMP_MIK_H

/**
 * Mining Identity Key (MIK) - DFMP v2.0
 *
 * A dedicated Dilithium3 keypair for miner identity that is separate from
 * payout addresses. This closes the address rotation loophole where miners
 * could bypass DFMP penalties by using a new payout address for each block.
 *
 * MIK is mandatory in every block starting from DFMP v2.0 activation.
 *
 * Key Sizes (Dilithium3):
 * - Public key:  1,952 bytes
 * - Private key: 4,032 bytes
 * - Signature:   3,309 bytes
 *
 * Identity derivation: SHA3-256(pubkey)[:20 bytes]
 *
 * Signature message (avoids circular dependency with block hash):
 *   message = SHA3-256(prevBlockHash || height || timestamp || mikIdentity)
 *
 * Coinbase scriptSig format:
 *   [height: 4 bytes] [msg: ~20 bytes] [MIK_MARKER: 1 byte] [MIK_DATA: variable]
 *
 *   MIK_MARKER = 0xDF
 *
 *   MIK_DATA for registration (first block with this MIK):
 *     [0x01] [pubkey: 1952 bytes] [signature: 3309 bytes]
 *
 *   MIK_DATA for reference (subsequent blocks):
 *     [0x02] [identity: 20 bytes] [signature: 3309 bytes]
 *
 * See: docs/specs/DFMP-V2-SPEC.md
 */

#include <dfmp/dfmp.h>
#include <uint256.h>
#include <util/secure_allocator.h>

#include <array>
#include <cstdint>
#include <vector>
#include <string>

// Forward declaration for attestation data
namespace Attestation { struct CAttestationSet; }

namespace DFMP {

// ============================================================================
// MIK CONSTANTS
// ============================================================================

/** Dilithium3 public key size */
constexpr size_t MIK_PUBKEY_SIZE = 1952;

/** Dilithium3 private key size */
constexpr size_t MIK_PRIVKEY_SIZE = 4032;

/** Dilithium3 signature size */
constexpr size_t MIK_SIGNATURE_SIZE = 3309;

/** MIK identity size (SHA3-256 truncated to 20 bytes) */
constexpr size_t MIK_IDENTITY_SIZE = 20;

/** Marker byte in coinbase scriptSig indicating MIK data follows */
constexpr uint8_t MIK_MARKER = 0xDF;

/** MIK type: Registration (includes full public key) */
constexpr uint8_t MIK_TYPE_REGISTRATION = 0x01;

/** MIK type: Reference (includes only identity hash) */
constexpr uint8_t MIK_TYPE_REFERENCE = 0x02;

/** Minimum size for MIK reference: marker(1) + type(1) + identity(20) + sig(3309) */
constexpr size_t MIK_REFERENCE_MIN_SIZE = 1 + 1 + 20 + 3309;

/** Size for MIK registration (v2.0, no nonce): marker(1) + type(1) + pubkey(1952) + sig(3309) */
constexpr size_t MIK_REGISTRATION_SIZE_V2 = 1 + 1 + 1952 + 3309;

/** Size for MIK registration: marker(1) + type(1) + pubkey(1952) + sig(3309) + nonce(8) [v3.0] */
constexpr size_t MIK_REGISTRATION_SIZE = 1 + 1 + 1952 + 3309 + 8;

/** Marker byte indicating Digital DNA commitment follows (after MIK data) */
constexpr uint8_t DNA_COMMITMENT_MARKER = 0xDD;

/** DNA commitment size: marker(1) + hash(32) = 33 bytes */
constexpr size_t DNA_COMMITMENT_SIZE = 1 + 32;

// ============================================================================
// MINING IDENTITY KEY
// ============================================================================

/**
 * Mining Identity Key - Dilithium3 keypair for miner identification
 *
 * The private key uses SecureAllocator to prevent swapping to disk.
 */
struct CMiningIdentityKey {
    /** Public key (1,952 bytes) */
    std::vector<uint8_t> pubkey;

    /** Private key (4,032 bytes) - secured memory */
    std::vector<uint8_t, SecureAllocator<uint8_t>> privkey;

    /** Identity derived from public key (20 bytes) */
    Identity identity;

    /** Default constructor - creates empty/invalid MIK */
    CMiningIdentityKey();

    /** Destructor - securely wipes private key */
    ~CMiningIdentityKey();

    // Prevent copying (contains secure data)
    CMiningIdentityKey(const CMiningIdentityKey&) = delete;
    CMiningIdentityKey& operator=(const CMiningIdentityKey&) = delete;

    // Allow moving
    CMiningIdentityKey(CMiningIdentityKey&& other) noexcept;
    CMiningIdentityKey& operator=(CMiningIdentityKey&& other) noexcept;

    /**
     * Check if MIK is valid (has correct key sizes)
     */
    bool IsValid() const;

    /**
     * Check if MIK has a private key (can sign)
     */
    bool HasPrivateKey() const;

    /**
     * Generate a new MIK keypair
     *
     * @return true if generation successful
     */
    bool Generate();

    /**
     * Sign a block commitment message
     *
     * Message format: SHA3-256(prevBlockHash || height || timestamp || identity)
     *
     * @param prevHash Previous block hash (32 bytes)
     * @param height Block height being mined
     * @param timestamp Block timestamp
     * @param[out] signature Output signature (3,309 bytes)
     * @return true if signing successful
     */
    bool Sign(const uint256& prevHash, int height, uint32_t timestamp,
              std::vector<uint8_t>& signature) const;

    /**
     * Sign arbitrary data with the MIK private key (Dilithium3)
     *
     * Used for DNA attestation signing and other non-block signatures.
     *
     * @param message Raw message bytes to sign
     * @param[out] signature Output signature (3,309 bytes)
     * @return true if signing successful
     */
    bool SignArbitrary(const std::vector<uint8_t>& message,
                       std::vector<uint8_t>& signature) const;

    /**
     * Clear the MIK (secure wipe of private key)
     */
    void Clear();

    /**
     * Get identity as hex string
     */
    std::string GetIdentityHex() const;

    /**
     * Serialize public key and identity for storage
     *
     * @param[out] data Output buffer for serialized data
     */
    void SerializePublic(std::vector<uint8_t>& data) const;

    /**
     * Deserialize public key and derive identity (for validation)
     *
     * @param data Serialized public data
     * @return true if deserialization successful
     */
    bool DeserializePublic(const std::vector<uint8_t>& data);
};

// ============================================================================
// SIGNATURE VERIFICATION (Static - no private key needed)
// ============================================================================

/**
 * Build the message to sign for MIK authentication
 *
 * @param prevHash Previous block hash
 * @param height Block height
 * @param timestamp Block timestamp
 * @param identity MIK identity (20 bytes)
 * @return 32-byte message hash
 */
std::vector<uint8_t> BuildMIKSignatureMessage(
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity);

/**
 * v4.0.20: Backward-time-window for MIK signature verification.
 *
 * The current signing path has a race: signing happens in the RPC handler at
 * wall-clock T1, but the block's final nTime is set later — once after
 * CreateBlockTemplate (T2 ≈ T1), and again inside vdf_miner.cpp after the VDF
 * computation + grace period (T3, can be 45+ seconds after T1 on DilV).
 * Verification at fork-time uses block.nTime (T3), which doesn't match the
 * signed-with timestamp (T1). Result: every v4.0.18/4.0.19 block from a
 * v4.0.18+ miner fails fork-validation. This caused the 2026-04-25 mainnet
 * chain split between v4.0.17 and v4.0.18+ nodes.
 *
 * Until the signing path is moved to AFTER the final nTime is set
 * (planned for v4.1.0 — see roadmap below), v4.0.20 verifiers brute-force a
 * backward window from block.nTime, trying each candidate signing-time. The
 * window is sized to cover VDF (45s) + grace period (45s) + clock skew (90s
 * margin) = 180s.
 *
 * Roadmap to v4.1.0 (Option B from the v4.0.20 design discussion):
 *   - Move signing to immediately before block submission so it commits to
 *     the FINAL block.nTime — fixes the race at the source.
 *   - Once all miners are on v4.1.0+, the brute-force loop in this file is
 *     dead code and can be removed.
 *   - Activation: hard-fork height where verifiers REJECT signatures that
 *     don't match block.nTime exactly. Drop the backward window.
 *
 * Cost: in the worst case 181 Dilithium3 verifies (~1 ms each on x86_64).
 * For the common case (signature was made over block.nTime exactly), the
 * very first attempt succeeds and the window is never iterated.
 */
constexpr uint32_t kMIKVerifyBackwardWindowSeconds = 180;

/**
 * Verify a MIK signature.
 *
 * v4.0.20: First tries verification with the supplied timestamp; on failure,
 * scans backward up to kMIKVerifyBackwardWindowSeconds seconds to catch
 * blocks signed by v4.0.18/4.0.19 miners whose signing time predated
 * block.nTime by up to that window.
 *
 * @param pubkey Public key (1,952 bytes)
 * @param signature Signature to verify (3,309 bytes)
 * @param prevHash Previous block hash
 * @param height Block height
 * @param timestamp Block timestamp (typically block.nTime); also the upper
 *                  bound of the backward search window
 * @param identity Expected identity (must match SHA3-256(pubkey)[:20])
 * @return true if signature is valid for some timestamp in
 *         [timestamp - kMIKVerifyBackwardWindowSeconds, timestamp]
 */
bool VerifyMIKSignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity);

/**
 * Verify a MIK signature with EXACT timestamp match (no backward-window).
 *
 * Internal helper used by VerifyMIKSignature for each candidate timestamp.
 * Exposed for tests and for code paths that need strict matching (e.g. the
 * post-v4.1.0 strict verifier path once the timestamp race is fixed at the
 * signer side).
 */
bool VerifyMIKSignatureExact(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const uint256& prevHash,
    int height,
    uint32_t timestamp,
    const Identity& identity);

/**
 * Derive identity from MIK public key
 *
 * @param pubkey Public key (1,952 bytes)
 * @return Identity (20 bytes), or null identity if pubkey invalid
 */
Identity DeriveIdentityFromMIK(const std::vector<uint8_t>& pubkey);

/**
 * Verify an arbitrary Dilithium3 signature
 *
 * Used for DNA attestation verification and other non-block signatures.
 *
 * @param pubkey Public key (1,952 bytes)
 * @param signature Signature to verify (3,309 bytes)
 * @param message Raw message bytes that were signed
 * @return true if signature is valid
 */
bool VerifyArbitrarySignature(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& message);

// ============================================================================
// SCRIPTSIG PARSING
// ============================================================================

/**
 * Parsed MIK data from coinbase scriptSig
 */
struct CMIKScriptData {
    /** True if this is a registration (includes full pubkey) */
    bool isRegistration;

    /** MIK identity (20 bytes) */
    Identity identity;

    /** Public key (only set for registration, 1952 bytes) */
    std::vector<uint8_t> pubkey;

    /** Signature (3,309 bytes) */
    std::vector<uint8_t> signature;

    /** v3.0: PoW nonce for registration */
    uint64_t registrationNonce = 0;

    /** Digital DNA commitment hash (32 bytes, zero if not present) */
    std::array<uint8_t, 32> dna_hash{};
    bool has_dna_hash = false;

    /** Seed attestations (Phase 2+3: only present in MIK registration blocks) */
    bool has_attestations = false;
    uint8_t attestation_count = 0;
    // Raw attestation entries: each is [seed_id:1][timestamp:4][signature:3309]
    struct AttestationEntry {
        uint8_t seedId;
        uint32_t timestamp;
        std::vector<uint8_t> signature;
    };
    std::vector<AttestationEntry> attestations;

    CMIKScriptData() : isRegistration(false), registrationNonce(0) {}

    bool IsValid() const {
        return !identity.IsNull() && signature.size() == MIK_SIGNATURE_SIZE;
    }
};

/**
 * Parse MIK data from coinbase scriptSig
 *
 * Looks for MIK_MARKER (0xDF) and extracts:
 * - Type (registration or reference)
 * - Identity (from pubkey for registration, direct for reference)
 * - Public key (registration only)
 * - Signature
 *
 * @param scriptSig The coinbase input scriptSig
 * @param[out] mikData Parsed MIK data
 * @return true if MIK data found and parsed successfully, false otherwise
 */
bool ParseMIKFromScriptSig(
    const std::vector<uint8_t>& scriptSig,
    CMIKScriptData& mikData);

/**
 * Build MIK scriptSig data for registration (first block)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey: 1952] [signature: 3309]
 *
 * @param pubkey Public key
 * @param signature Signature
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data);

/**
 * Build MIK scriptSig data for reference (subsequent blocks)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REFERENCE] [identity: 20] [signature: 3309]
 *
 * @param identity MIK identity
 * @param signature Signature
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigReference(
    const Identity& identity,
    const std::vector<uint8_t>& signature,
    std::vector<uint8_t>& data);

/**
 * Build MIK scriptSig data for registration with PoW nonce (DFMP v3.0)
 *
 * Format: [MIK_MARKER] [MIK_TYPE_REGISTRATION] [pubkey: 1952] [signature: 3309] [nonce: 8]
 *
 * @param pubkey Public key
 * @param signature Signature
 * @param registrationNonce PoW nonce
 * @param[out] data Output buffer
 * @return true if successful
 */
bool BuildMIKScriptSigRegistration(
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    uint64_t registrationNonce,
    std::vector<uint8_t>& data);

/**
 * Build DNA commitment bytes for coinbase scriptSig
 *
 * Format: [DNA_COMMITMENT_MARKER: 0xDD] [dna_hash: 32 bytes]
 *
 * @param dna_hash 32-byte SHA3-256 hash of serialized DigitalDNA
 * @param[out] data Output buffer (appended to)
 */
void BuildDNACommitment(const std::array<uint8_t, 32>& dna_hash, std::vector<uint8_t>& data);

/**
 * Verify registration proof-of-work (DFMP v3.0)
 *
 * Registration PoW prevents mass MIK identity generation.
 * SHA3-256(pubkey || dna_hash || nonce) must have >= requiredBits leading zero bits.
 * If dnaHash is null or all zeros, uses legacy format: SHA3-256(pubkey || nonce).
 *
 * @param pubkey MIK public key (1,952 bytes)
 * @param nonce Registration nonce
 * @param requiredBits Number of leading zero bits required
 * @param dnaHash Optional 32-byte DNA hash to bind into PoW challenge
 * @return true if PoW is valid
 */
bool VerifyRegistrationPoW(const std::vector<uint8_t>& pubkey, uint64_t nonce, int requiredBits,
                            const std::array<uint8_t, 32>* dnaHash = nullptr);

/**
 * Mine registration proof-of-work nonce (DFMP v3.0)
 *
 * Finds a nonce such that SHA3-256(pubkey || dna_hash || nonce) has >= requiredBits
 * leading zero bits. If dnaHash is null, uses legacy format without DNA.
 * At 30 bits: ~40-60 min on a fast CPU.
 *
 * @param pubkey MIK public key (1,952 bytes)
 * @param requiredBits Number of leading zero bits required
 * @param[out] nonce Output nonce that satisfies the PoW requirement
 * @param running Optional pointer to a running flag; if it becomes false, mining aborts
 * @param dnaHash Optional 32-byte DNA hash to bind into PoW challenge
 * @return true if nonce found, false if aborted or failed
 */
bool MineRegistrationPoW(const std::vector<uint8_t>& pubkey, int requiredBits, uint64_t& nonce,
                          const std::atomic<bool>* running = nullptr,
                          const std::array<uint8_t, 32>* dnaHash = nullptr);

// ============================================================================
// DFMP V2.0 CONSTANTS
// ============================================================================

/** DFMP v2.0: Observation window (360 blocks = 24 hours at 4 min/block) */
constexpr int OBSERVATION_WINDOW_V2 = 360;

/** DFMP v2.0: Free tier threshold (20 blocks per window) */
constexpr int FREE_TIER_THRESHOLD_V2 = 20;

/** DFMP v2.0: Linear zone upper bound (blocks 21-25) */
constexpr int LINEAR_ZONE_UPPER_V2 = 25;

/** DFMP v2.0: Exponential growth rate (1.08 per block over linear zone) */
constexpr double HEAT_GROWTH_RATE_V2 = 1.08;

/** DFMP v2.0: Maturity blocks (400 blocks for full penalty decay) */
constexpr int MATURITY_BLOCKS_V2 = 400;

/** DFMP v2.0: Maturity step size (penalty drops every 100 blocks) */
constexpr int MATURITY_STEP_V2 = 100;

/** DFMP v2.0: Starting maturity penalty for new MIK */
constexpr double MATURITY_PENALTY_START_V2 = 3.0;

// Fixed-point versions for deterministic calculation
// Note: FP_SCALE is defined in dfmp.h
constexpr int64_t FP_LINEAR_INCREMENT_V2 = 100000;    // 0.1 × FP_SCALE (v2.0 linear zone step)
constexpr int64_t FP_LINEAR_BASE_V2 = 1500000;        // 1.5 × FP_SCALE (v2.0 exponential zone start)
constexpr int64_t FP_MATURITY_START_V2 = 3000000;     // 3.0 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_25 = 2500000;      // 2.5 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_20 = 2000000;      // 2.0 × FP_SCALE
constexpr int64_t FP_MATURITY_STEP_15 = 1500000;      // 1.5 × FP_SCALE

// ============================================================================
// DFMP V2.0 PENALTY CALCULATIONS
// ============================================================================

/**
 * Calculate maturity penalty (v2.0) - fixed-point
 *
 * NO first-block grace - new MIKs start at 3.0x
 * Step-wise decay: 3.0x → 2.5x → 2.0x → 1.5x → 1.0x over 400 blocks
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where MIK was first seen (-1 for new)
 * @return Maturity penalty × FP_SCALE
 */
int64_t CalculateMaturityPenaltyFP_V2(int currentHeight, int firstSeenHeight);

/**
 * Calculate heat penalty (v2.0) - fixed-point with dynamic scaling
 *
 * Uses 360-block observation window:
 * - 0-N blocks: Free tier (1.0x) where N = max(20, 360/uniqueMiners)
 * - N+1 to N+5: Linear zone (1.0x → 1.5x)
 * - N+6+ blocks: Exponential (1.5 × 1.08^(blocks-N-5))
 *
 * @param blocksInWindow Number of blocks by this identity in the window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Heat penalty × FP_SCALE
 */
int64_t CalculateHeatPenaltyFP_V2(int blocksInWindow, int uniqueMiners = 0);

/**
 * Calculate total DFMP v2.0 multiplier - fixed-point
 *
 * Total = maturity_penalty × heat_penalty
 *
 * @param currentHeight Current block height
 * @param firstSeenHeight Height where MIK was first seen (-1 for new)
 * @param blocksInWindow Number of blocks by this MIK in observation window
 * @param uniqueMiners Number of unique miners in window (0 = use static threshold)
 * @return Total multiplier × FP_SCALE
 */
int64_t CalculateTotalMultiplierFP_V2(int currentHeight, int firstSeenHeight, int blocksInWindow, int uniqueMiners = 0);

/**
 * Get maturity penalty as double (for display/logging)
 */
double GetMaturityPenalty_V2(int currentHeight, int firstSeenHeight);

/**
 * Get heat penalty as double (for display/logging)
 */
double GetHeatPenalty_V2(int blocksInWindow);

/**
 * Get total multiplier as double (for display/logging)
 */
double GetTotalMultiplier_V2(int currentHeight, int firstSeenHeight, int blocksInWindow);

} // namespace DFMP

#endif // DILITHION_DFMP_MIK_H
