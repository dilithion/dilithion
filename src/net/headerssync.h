// Copyright (c) 2022-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DILITHION_NET_HEADERSSYNC_H
#define DILITHION_NET_HEADERSSYNC_H

#include <primitives/block.h>
#include <crypto/sha3.h>
#include <net/iheader_proof_checker.h>  // Phase 3: chain-agnostic proof seam

#include <deque>
#include <vector>
#include <cstdint>
#include <memory>

/**
 * @file headerssync.h
 * @brief Bitcoin Core-style two-phase header synchronization with DoS protection
 *
 * This implements the "download-twice" approach from Bitcoin Core that prevents
 * memory exhaustion attacks during IBD. An attacker could send millions of fake
 * headers with valid PoW - without this protection, each header (~80 bytes)
 * would be stored, exhausting memory.
 *
 * Two-Phase Approach:
 *
 * Phase 1 (PRESYNC):
 *   - Receive headers but DON'T permanently store them
 *   - Store only 1-bit cryptographic commitments at periodic intervals
 *   - Track cumulative chain work from nBits fields
 *   - Memory usage: ~1 bit per commitment_period headers
 *
 * Phase 2 (REDOWNLOAD):
 *   - Once sufficient chain work is demonstrated (proves real chain)
 *   - Request headers AGAIN from the peer
 *   - Verify redownloaded headers match stored commitments
 *   - Only then accept headers for permanent storage
 *
 * This is CRITICAL for mainnet security at scale (17k+ nodes).
 */

// Forward declarations
typedef int NodeId;

/**
 * Parameters for header sync DoS protection
 */
struct HeadersSyncParams {
    //! Period between commitment samples (headers)
    //! Lower = more memory, higher security; Higher = less memory, lower security
    //! Bitcoin Core uses 584 for ~2KB per 1M headers
    uint32_t commitment_period = 584;

    //! Minimum headers in redownload buffer before accepting batch
    //! Higher = more latency, better batching
    uint32_t redownload_buffer_size = 8192;

    //! Maximum seconds from chain start for memory bounds calculation
    //! Used to cap m_max_commitments
    int64_t max_seconds_ahead = 2 * 365 * 24 * 60 * 60;  // 2 years
};

/**
 * Compressed header for phase 2 buffer
 *
 * Stores header without hashPrevBlock (can be reconstructed from chain).
 * Size: 48 bytes vs 80 bytes for full header.
 */
struct CompressedHeader {
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    int32_t nVersion;

    CompressedHeader() : nTime(0), nBits(0), nNonce(0), nVersion(0) {}

    explicit CompressedHeader(const CBlockHeader& header)
        : hashMerkleRoot(header.hashMerkleRoot),
          nTime(header.nTime),
          nBits(header.nBits),
          nNonce(header.nNonce),
          nVersion(header.nVersion) {}

    /**
     * Reconstruct full header given the previous block hash
     */
    CBlockHeader GetFullHeader(const uint256& hashPrevBlock) const {
        CBlockHeader header;
        header.nVersion = nVersion;
        header.hashPrevBlock = hashPrevBlock;
        header.hashMerkleRoot = hashMerkleRoot;
        header.nTime = nTime;
        header.nBits = nBits;
        header.nNonce = nNonce;
        return header;
    }
};

// Ensure CompressedHeader is actually smaller
static_assert(sizeof(CompressedHeader) <= 48, "CompressedHeader too large");

/**
 * @class HeadersSyncState
 * @brief Two-phase header synchronization state machine per peer
 *
 * Each peer gets its own HeadersSyncState to track their header sync progress
 * independently. This isolates misbehaving peers from affecting others.
 */
class HeadersSyncState {
public:
    /**
     * Synchronization phases
     */
    enum class State {
        //! Peer chain work unverified; building commitments only
        PRESYNC,
        //! Sufficient work demonstrated; redownloading and validating
        REDOWNLOAD,
        //! Sync complete; state can be discarded
        FINAL
    };

    /**
     * Result of processing a batch of headers
     */
    struct ProcessingResult {
        //! Headers that passed PoW validation and commitment checks
        std::vector<CBlockHeader> pow_validated_headers;
        //! Whether processing succeeded (false = peer misbehaving)
        bool success = false;
        //! Whether to request more headers from this peer
        bool request_more = false;
    };

    /**
     * Constructor
     *
     * @param peer_id Peer identifier for logging
     * @param params Sync parameters (commitment period, buffer size)
     * @param chain_start_hash Hash of the block we're syncing from
     * @param chain_start_height Height of the starting block
     * @param minimum_work Minimum chain work to accept (DoS threshold)
     * @param proof_checker Phase 3 chain-agnostic proof check (RandomX or
     *                      VDF impl). Non-owning; must outlive this state.
     *                      Pass nullptr to fall back to the legacy inline
     *                      `IsVDFBlock()`-branch + CheckProofOfWork path —
     *                      preserves pre-Phase-3 behaviour for tests that
     *                      don't wire a checker.
     */
    /**
     * @param chain_start_work CUMULATIVE chain work at chain_start_hash,
     *   i.e. work from genesis up to AND INCLUDING that block.
     *
     *   LP-10 §2.0 (2026-09-08). This parameter did not exist and the
     *   accumulator was memset to zero, while chain_start is our LOCAL TIP, not
     *   genesis. The gate then asked "has this peer supplied a whole threshold's
     *   worth of NEW work beyond our tip?" instead of "does this chain exceed
     *   the absolute minimum?" -- never true on a non-fresh node, so PRESYNC
     *   would never reach REDOWNLOAD and header sync would stall. Upstream seeds
     *   from chain_start->nChainWork; this restores that.
     *
     *   There is deliberately NO DEFAULT. A defaulted zero is exactly the bug,
     *   and it would reappear silently at any future call site.
     */
    HeadersSyncState(
        NodeId peer_id,
        const HeadersSyncParams& params,
        const uint256& chain_start_hash,
        int64_t chain_start_height,
        const uint256& chain_start_work,
        const uint256& minimum_work,
        const ::dilithion::net::IHeaderProofChecker* proof_checker = nullptr
    );

    ~HeadersSyncState() = default;

    // Disable copying (each peer has unique state)
    HeadersSyncState(const HeadersSyncState&) = delete;
    HeadersSyncState& operator=(const HeadersSyncState&) = delete;

    /**
     * Process next batch of headers from peer
     *
     * @param headers Headers received from peer
     * @param full_headers_available True if these are full headers (phase 2)
     * @return Processing result with validated headers and status
     */
    ProcessingResult ProcessNextHeaders(
        const std::vector<CBlockHeader>& headers,
        bool full_headers_available
    );

    /**
     * Generate locator for next GETHEADERS request
     *
     * @return Block locator hashes for request
     */
    std::vector<uint256> NextHeadersRequestLocator() const;

    // State queries
    State GetState() const { return m_download_state; }
    int64_t GetPresyncHeight() const { return m_current_height; }
    uint32_t GetPresyncTime() const;
    uint256 GetPresyncWork() const { return m_current_chain_work; }

private:
    //! Peer identifier for logging
    const NodeId m_id;

    //! Sync parameters
    const HeadersSyncParams m_params;

    //! Starting point for this sync
    const uint256 m_chain_start_hash;
    const int64_t m_chain_start_height;

    //! Minimum chain work to require before accepting headers
    const uint256 m_minimum_required_work;

    //! Current accumulated chain work
    uint256 m_current_chain_work;

    //! Salt for commitment hash (randomized per sync)
    uint256 m_commitment_salt;

    //! Commitment offset within period (randomized)
    const size_t m_commit_offset;

    //! Stored commitment bits (1 bit per commitment_period headers)
    std::deque<bool> m_header_commitments;

    //! Maximum commitments allowed (memory bound)
    uint64_t m_max_commitments;

    //! Last header received in PRESYNC
    CBlockHeader m_last_header_received;

    //! Current height in PRESYNC
    int64_t m_current_height;

    //! Redownloaded headers buffer (REDOWNLOAD phase)
    std::deque<CompressedHeader> m_redownloaded_headers;

    //! Height of last header in redownload buffer
    int64_t m_redownload_buffer_last_height;

    //! Hash of last header in redownload buffer
    uint256 m_redownload_buffer_last_hash;

    //! Previous hash of first header in buffer (for reconstruction)
    uint256 m_redownload_buffer_first_prev_hash;

    //! Accumulated work in redownload buffer
    uint256 m_redownload_chain_work;

    //! Flag to process all remaining headers (after meeting work threshold)
    bool m_process_all_remaining_headers;

    //! Current synchronization phase
    State m_download_state;

    //! Phase 3: chain-agnostic proof checker. Non-owning. Nullptr = legacy
    //! inline path (preserves pre-Phase-3 behaviour for un-migrated callers).
    const ::dilithion::net::IHeaderProofChecker* m_proof_checker;

    // Internal methods

    /**
     * Clear state and transition to FINAL
     */
    void Finalize();

    /**
     * Phase 1: Validate headers and store commitments
     *
     * @param headers Headers to process
     * @return true if all headers valid
     */
    bool ValidateAndStoreHeadersCommitments(const std::vector<CBlockHeader>& headers);

    /**
     * Validate a single header (PoW, continuity)
     *
     * @param header Header to validate
     * @return true if header is valid
     */
    bool ValidateAndProcessSingleHeader(const CBlockHeader& header);

    /**
     * Phase 2: Validate redownloaded header against commitment
     *
     * @param header Header to validate
     * @return true if header matches commitment
     */
    bool ValidateAndStoreRedownloadedHeader(const CBlockHeader& header);

    /**
     * Extract headers ready for permanent storage
     *
     * @return Vector of validated headers
     */
    std::vector<CBlockHeader> PopHeadersReadyForAcceptance();

    /**
     * Calculate commitment bit for a header
     *
     * @param hash Header hash
     * @return Commitment bit (0 or 1)
     */
    bool CalculateCommitment(const uint256& hash) const;

    /**
     * Calculate block work from nBits
     *
     * @param nBits Compact difficulty target
     * @return Block proof-of-work value
     */
    uint256 GetBlockWork(uint32_t nBits) const;

    /**
     * Add two uint256 chain work values
     *
     * @param a First value
     * @param b Second value
     * @return Sum (saturates at max)
     */
    uint256 AddChainWork(const uint256& a, const uint256& b) const;

    /**
     * Compare chain work values
     *
     * @param a First value
     * @param b Second value
     * @return true if a >= b
     */
    bool ChainWorkGreaterOrEqual(const uint256& a, const uint256& b) const;
};

#endif // DILITHION_NET_HEADERSSYNC_H
