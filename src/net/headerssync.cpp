// Copyright (c) 2022-2024 The Bitcoin Core developers
// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/headerssync.h>
#include <consensus/pow.h>
#include <consensus/chain_work.h>  // Phase 3: shared chain-work helper
#include <crypto/sha3.h>
#include <util/time.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>

// ============================================================================
// Constructor
// ============================================================================

HeadersSyncState::HeadersSyncState(
    NodeId peer_id,
    const HeadersSyncParams& params,
    const uint256& chain_start_hash,
    int64_t chain_start_height,
    const uint256& chain_start_work,
    const uint256& minimum_work,
    const ::dilithion::net::IHeaderProofChecker* proof_checker
)
    : m_id(peer_id),
      m_params(params),
      m_chain_start_hash(chain_start_hash),
      m_chain_start_height(chain_start_height),
      m_minimum_required_work(minimum_work),
      m_commit_offset(std::random_device{}() % params.commitment_period),
      m_max_commitments(0),
      m_current_height(chain_start_height),
      m_redownload_buffer_last_height(0),
      m_process_all_remaining_headers(false),
      m_download_state(State::PRESYNC),
      m_proof_checker(proof_checker)
{
    // LP-10 §2.0 (2026-09-08): SEED the accumulators from the chain start.
    //
    // These were memset to zero. chain_start is our LOCAL TIP (see
    // CHeadersManager::InitializeDoSProtectedSync, which passes hashBestHeader),
    // not genesis, so a zeroed accumulator made
    // ChainWorkGreaterOrEqual(m_current_chain_work, m_minimum_required_work)
    // ask "has this peer supplied a whole threshold's worth of NEW work beyond
    // our tip?" rather than "does this chain exceed the absolute minimum?".
    // Against an absolute, from-genesis nMinimumChainWork that is never true on
    // a node with any history: PRESYNC never reaches REDOWNLOAD,
    // pow_validated_headers stays empty, and header sync stalls.
    //
    // Upstream Core seeds from chain_start->nChainWork. Both accumulators are
    // seeded, not just m_current_chain_work, so the REDOWNLOAD tally is on the
    // same absolute scale as the PRESYNC one.
    //
    // Caller contract: chain_start_work is cumulative work INCLUDING
    // chain_start_hash. The caller must fail closed rather than pass zero for
    // an unknown start -- a zero here is indistinguishable from the bug this
    // replaces.
    m_current_chain_work = chain_start_work;
    m_redownload_chain_work = chain_start_work;

    // Generate random salt for commitment hashing
    // This prevents attackers from precomputing commitment collisions
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (int i = 0; i < 4; i++) {
        uint64_t r = gen();
        memcpy(m_commitment_salt.data + i * 8, &r, 8);
    }

    // Calculate maximum commitments based on consensus rules
    // Bitcoin Core: 6 blocks/second (fastest rate given MTP rule) * max_seconds
    // This bounds memory usage regardless of attacker behavior
    //
    // For Dilithion with 30-second blocks, theoretical max is much lower,
    // but we use conservative bounds for safety
    int64_t max_headers = 6 * m_params.max_seconds_ahead;
    m_max_commitments = max_headers / m_params.commitment_period;

    std::cout << "[HeadersSyncState] Initialized for peer " << m_id
              << " (commit_offset=" << m_commit_offset
              << ", max_commitments=" << m_max_commitments << ")" << std::endl;
}

// ============================================================================
// Public API
// ============================================================================

HeadersSyncState::ProcessingResult HeadersSyncState::ProcessNextHeaders(
    const std::vector<CBlockHeader>& headers,
    bool /* full_headers_available */)
{
    ProcessingResult result;
    result.success = false;
    result.request_more = false;

    if (headers.empty()) {
        // Empty headers message - peer has no more headers
        if (m_download_state == State::PRESYNC) {
            // Check if we have enough work to proceed
            if (ChainWorkGreaterOrEqual(m_current_chain_work, m_minimum_required_work)) {
                std::cout << "[HeadersSyncState] Peer " << m_id
                          << " PRESYNC complete, transitioning to REDOWNLOAD" << std::endl;
                m_download_state = State::REDOWNLOAD;
                result.success = true;
                result.request_more = true;  // Request headers again for phase 2
            } else {
                std::cout << "[HeadersSyncState] Peer " << m_id
                          << " insufficient chain work in PRESYNC" << std::endl;
                // LP-10: tell the caller WHY, so the punishment half can fire
                // for this reason and only this reason.
                result.insufficient_chain_work = true;
                Finalize();
            }
        } else if (m_download_state == State::REDOWNLOAD) {
            // Finished redownloading
            result.pow_validated_headers = PopHeadersReadyForAcceptance();
            result.success = true;
            Finalize();
        }
        return result;
    }

    if (m_download_state == State::PRESYNC) {
        // Phase 1: Build commitments
        if (!ValidateAndStoreHeadersCommitments(headers)) {
            std::cerr << "[HeadersSyncState] Peer " << m_id
                      << " sent invalid headers in PRESYNC" << std::endl;
            Finalize();
            return result;
        }

        // Check if we've accumulated enough work to transition
        if (ChainWorkGreaterOrEqual(m_current_chain_work, m_minimum_required_work)) {
            std::cout << "[HeadersSyncState] Peer " << m_id
                      << " sufficient work demonstrated at height " << m_current_height
                      << ", transitioning to REDOWNLOAD" << std::endl;
            m_download_state = State::REDOWNLOAD;
        }

        result.success = true;
        result.request_more = true;

    } else if (m_download_state == State::REDOWNLOAD) {
        // Phase 2: Validate against commitments
        for (const auto& header : headers) {
            if (!ValidateAndStoreRedownloadedHeader(header)) {
                std::cerr << "[HeadersSyncState] Peer " << m_id
                          << " commitment mismatch in REDOWNLOAD" << std::endl;
                Finalize();
                return result;
            }
        }

        // Check if buffer is large enough to return headers
        if (m_redownloaded_headers.size() >= m_params.redownload_buffer_size ||
            m_process_all_remaining_headers) {
            result.pow_validated_headers = PopHeadersReadyForAcceptance();
        }

        result.success = true;
        result.request_more = !m_header_commitments.empty();

        // If no more commitments to verify, we're done
        if (m_header_commitments.empty()) {
            result.pow_validated_headers = PopHeadersReadyForAcceptance();
            Finalize();
        }
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return result;
}

std::vector<uint256> HeadersSyncState::NextHeadersRequestLocator() const {
    std::vector<uint256> locator;

    if (m_download_state == State::PRESYNC) {
        // In PRESYNC, request from last received header
        if (!m_last_header_received.IsNull()) {
            locator.push_back(m_last_header_received.GetHash());
        }
        locator.push_back(m_chain_start_hash);
    } else if (m_download_state == State::REDOWNLOAD) {
        // In REDOWNLOAD, request from chain start (download everything again)
        if (!m_redownload_buffer_last_hash.IsNull()) {
            locator.push_back(m_redownload_buffer_last_hash);
        }
        locator.push_back(m_chain_start_hash);
    }

    // MAINNET FIX: Return without std::move to allow RVO
    return locator;
}

uint32_t HeadersSyncState::GetPresyncTime() const {
    if (m_last_header_received.IsNull()) {
        return 0;
    }
    return m_last_header_received.nTime;
}

// ============================================================================
// Phase 1: PRESYNC - Build Commitments
// ============================================================================

bool HeadersSyncState::ValidateAndStoreHeadersCommitments(
    const std::vector<CBlockHeader>& headers)
{
    for (const auto& header : headers) {
        if (!ValidateAndProcessSingleHeader(header)) {
            return false;
        }

        // Store commitment at periodic intervals
        int64_t next_height = m_current_height + 1;
        if (next_height % m_params.commitment_period == static_cast<int64_t>(m_commit_offset)) {
            // Check memory bounds
            if (m_header_commitments.size() >= m_max_commitments) {
                std::cerr << "[HeadersSyncState] Peer " << m_id
                          << " exceeded max commitments" << std::endl;
                return false;
            }

            // Store 1-bit commitment
            uint256 hash = header.GetHash();
            bool commitment = CalculateCommitment(hash);
            m_header_commitments.push_back(commitment);
        }

        // Accumulate chain work
        uint256 block_work = GetBlockWork(header.nBits);
        m_current_chain_work = AddChainWork(m_current_chain_work, block_work);

        // Update state
        m_last_header_received = header;
        m_current_height = next_height;
    }

    return true;
}

bool HeadersSyncState::ValidateAndProcessSingleHeader(const CBlockHeader& header) {
    // 1. Phase 3: route the proof check through the chain-agnostic
    // IHeaderProofChecker if injected. Falls back to the legacy inline
    // `IsVDFBlock()` branch + CheckProofOfWork path if no checker was
    // passed (un-migrated test callsites).
    if (m_proof_checker) {
        if (!m_proof_checker->CheckHeaderProof(header)) {
            std::cerr << "[HeadersSyncState] Invalid proof for header "
                      << header.GetHash().GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }
    } else if (!header.IsVDFBlock()) {
        uint256 hash = header.GetHash();
        if (!CheckProofOfWork(hash, header.nBits)) {
            std::cerr << "[HeadersSyncState] Invalid PoW for header "
                      << hash.GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }
    }

    // 2. Check continuity with previous header
    if (!m_last_header_received.IsNull()) {
        if (header.hashPrevBlock != m_last_header_received.GetHash()) {
            std::cerr << "[HeadersSyncState] Header chain discontinuity" << std::endl;
            return false;
        }
    } else {
        // First header - should connect to chain start
        if (header.hashPrevBlock != m_chain_start_hash) {
            std::cerr << "[HeadersSyncState] First header doesn't connect to chain start" << std::endl;
            return false;
        }
    }

    // 3. Basic sanity checks
    if (header.nBits == 0) {
        std::cerr << "[HeadersSyncState] Zero nBits" << std::endl;
        return false;
    }

    if (header.nVersion <= 0) {
        std::cerr << "[HeadersSyncState] Invalid version" << std::endl;
        return false;
    }

    return true;
}

// ============================================================================
// Phase 2: REDOWNLOAD - Validate Against Commitments
// ============================================================================

bool HeadersSyncState::ValidateAndStoreRedownloadedHeader(const CBlockHeader& header) {
    // 1. Phase 3: route through IHeaderProofChecker if injected (same
    // pattern as ValidateAndProcessSingleHeader above).
    uint256 hash = header.GetHash();
    if (m_proof_checker) {
        if (!m_proof_checker->CheckHeaderProof(header)) {
            std::cerr << "[HeadersSyncState] Invalid proof in REDOWNLOAD" << std::endl;
            return false;
        }
    } else if (!header.IsVDFBlock()) {
        if (!CheckProofOfWork(hash, header.nBits)) {
            std::cerr << "[HeadersSyncState] Invalid PoW in REDOWNLOAD" << std::endl;
            return false;
        }
    }

    // 2. Check continuity
    if (!m_redownloaded_headers.empty()) {
        if (header.hashPrevBlock != m_redownload_buffer_last_hash) {
            std::cerr << "[HeadersSyncState] Chain discontinuity in REDOWNLOAD" << std::endl;
            return false;
        }
    } else {
        // First redownloaded header
        m_redownload_buffer_first_prev_hash = header.hashPrevBlock;
    }

    // 3. Check commitment if at commitment position
    int64_t next_height = m_redownload_buffer_last_height + 1;
    if (next_height % m_params.commitment_period == static_cast<int64_t>(m_commit_offset)) {
        if (m_header_commitments.empty()) {
            // More headers than we have commitments for
            std::cerr << "[HeadersSyncState] No commitment for header at height "
                      << next_height << std::endl;
            return false;
        }

        bool expected_commitment = m_header_commitments.front();
        bool actual_commitment = CalculateCommitment(hash);

        if (expected_commitment != actual_commitment) {
            std::cerr << "[HeadersSyncState] Commitment mismatch at height "
                      << next_height << " (expected " << expected_commitment
                      << ", got " << actual_commitment << ")" << std::endl;
            return false;
        }

        m_header_commitments.pop_front();
    }

    // 4. Store compressed header
    m_redownloaded_headers.push_back(CompressedHeader(header));
    m_redownload_buffer_last_height = next_height;
    m_redownload_buffer_last_hash = hash;

    // 5. Accumulate work
    uint256 block_work = GetBlockWork(header.nBits);
    m_redownload_chain_work = AddChainWork(m_redownload_chain_work, block_work);

    return true;
}

std::vector<CBlockHeader> HeadersSyncState::PopHeadersReadyForAcceptance() {
    std::vector<CBlockHeader> result;

    if (m_redownloaded_headers.empty()) {
        return result;
    }

    result.reserve(m_redownloaded_headers.size());

    // Reconstruct full headers from compressed form
    uint256 prev_hash = m_redownload_buffer_first_prev_hash;
    for (const auto& compressed : m_redownloaded_headers) {
        CBlockHeader header = compressed.GetFullHeader(prev_hash);
        prev_hash = header.GetHash();
        result.push_back(header);
    }

    // Clear buffer
    m_redownloaded_headers.clear();

    std::cout << "[HeadersSyncState] Peer " << m_id
              << " returning " << result.size() << " validated headers" << std::endl;

    return result;
}

// ============================================================================
// Internal Helpers
// ============================================================================

void HeadersSyncState::Finalize() {
    m_download_state = State::FINAL;
    m_header_commitments.clear();
    m_redownloaded_headers.clear();

    std::cout << "[HeadersSyncState] Peer " << m_id << " sync finalized" << std::endl;
}

bool HeadersSyncState::CalculateCommitment(const uint256& hash) const {
    // Salted hash: SHA3-256(salt || hash)
    // Extract single bit for commitment

    // Concatenate salt and hash
    uint8_t data[64];
    memcpy(data, m_commitment_salt.data, 32);
    memcpy(data + 32, hash.data, 32);

    // One-shot SHA3-256 hash
    uint8_t result[32];
    SHA3_256(data, 64, result);

    // Return least significant bit
    return (result[0] & 1) != 0;
}

uint256 HeadersSyncState::GetBlockWork(uint32_t nBits) const {
    // Phase 3 (2026-04-26): consolidated through shared helper.
    return dilithion::consensus::ComputeChainWork(nBits);
}

uint256 HeadersSyncState::AddChainWork(const uint256& a, const uint256& b) const {
    return dilithion::consensus::AddChainWork(a, b);
}

bool HeadersSyncState::ChainWorkGreaterOrEqual(const uint256& a, const uint256& b) const {
    // Compare big-endian (most significant byte first)
    for (int i = 31; i >= 0; i--) {
        if (a.data[i] > b.data[i]) return true;
        if (a.data[i] < b.data[i]) return false;
    }
    return true;  // Equal
}
