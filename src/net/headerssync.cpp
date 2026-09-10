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

namespace {

// LP-10 A-2 / blocker 1 — reject nBits values that make chain-work accounting
// meaningless, in BOTH phases.
//
// THE EXPLOIT THIS CLOSES, measured on DilV before this check existed:
//   ComputeChainWork (consensus/chain_work.h:44-47) SATURATES to 0xFF..FF when
//   the MANTISSA is zero. 0x1e000000 qualifies -- a non-zero WORD with a zero
//   mantissa -- so it slipped past the old `nBits == 0` guard. One header with
//   that nBits was therefore worth MAXIMUM possible chain work and satisfied
//   DilV's measured nMinimumChainWork on its own: "sufficient work demonstrated
//   at HEIGHT 1". The honest-nBits control did NOT open the gate, so the
//   saturation was the cause and nothing else.
//
//   `nBits == 0` is the exact shape #189 proved insufficient in the census
//   generator, where a 0x1e000000 hole passed until the gate was tightened to
//   test the mantissa. Same defect, second location.
//
// WHY HERE AND NOT IN ComputeChainWork: that helper is shared consensus code used
// for the real chain's work accounting. Changing its saturation behaviour is a
// consensus change and out of scope. This rejects the input instead.
//
// CALLED FROM BOTH PHASES DELIBERATELY. PRESYNC had the weak guard; REDOWNLOAD
// had NO nBits check at all while still accumulating work from the peer's raw
// nBits. Guarding one and not the other is the sibling shape this mission keeps
// hitting.
bool NBitsIsSaneForWorkAccounting(uint32_t nBits)
{
    // Zero mantissa is the saturation trigger, and the only one:
    // ComputeChainWork's other paths clamp rather than saturate.
    if ((nBits & 0x00FFFFFFu) == 0) return false;
    // A zero word is a subset of the above, kept explicit for readers.
    if (nBits == 0) return false;
    return true;
}

}  // namespace

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
      m_chain_start_work(chain_start_work),   // LP-10 A-2: RETAIN it; see the header
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
    // Against an absolute, from-genesis nMinimumChainWork that is FALSE WHENEVER
    // THE RECEIVED SUFFIX CARRIES LESS THAN A FULL THRESHOLD OF WORK, however
    // much our own tip already has: PRESYNC never reaches REDOWNLOAD,
    // pow_validated_headers stays empty, and header sync stalls.
    //
    // (Three earlier wordings of this sentence were wrong in the same direction
    // -- "any node with history", then "any non-fresh node", then "any node
    // whose tip already carries a threshold". All three are refuted by the same
    // counterexample: a node at or past the threshold still PASSES if the peer
    // supplies a full threshold of NEW work. This site was the FIFTH sibling of
    // that fix, found by all three external seats after the .h twin, the seeding
    // suite and the KAT had already been corrected -- the same
    // fix-the-named-site-miss-the-siblings defect, five times over. The
    // invariant is about the SUFFIX, never about our tip.)
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
                EnterRedownloadPhase();   // LP-10 A-2: reseeds all five fields
                result.success = true;
                result.request_more = true;  // Request headers again for phase 2
            } else {
                std::cout << "[HeadersSyncState] Peer " << m_id
                          << " insufficient chain work in PRESYNC" << std::endl;
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
            EnterRedownloadPhase();   // LP-10 A-2: reseeds all five fields
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

        // ⛔ POP EXACTLY ONCE. This block used to call
        // PopHeadersReadyForAcceptance() twice and ASSIGN each result:
        //
        //     if (buffer full || process_all) result.pow_validated_headers = Pop();
        //     ...
        //     if (commitments empty)          result.pow_validated_headers = Pop();
        //
        // When BOTH conditions held, the first Pop drained the buffer into the
        // result and the second Pop — now running on an empty buffer, because Pop
        // clears it — returned an empty vector and OVERWROTE the first. Measured
        // by a reviewer's probe (P5): 2 headers in, 0 out. Validated headers were
        // silently dropped, with no error and no log line.
        //
        // Capturing `finished` once also removes a second read of
        // m_header_commitments, which Finalize() clears — so the old code read a
        // field for `request_more` and then re-read it after a call that could
        // change it.
        const bool finished  = m_header_commitments.empty();
        const bool drain_now = m_redownloaded_headers.size() >= m_params.redownload_buffer_size
                               || m_process_all_remaining_headers;

        if (drain_now || finished) {
            result.pow_validated_headers = PopHeadersReadyForAcceptance();
        }

        result.success = true;
        result.request_more = !finished;

        if (finished) {
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

// LP-10 A-2 / blocker 2 — the reseed block upstream performs at this transition
// (bitcoin-v28.0/src/headerssync.cpp:166-172), which our port dropped entirely.
//
// WHAT GOES WRONG WITHOUT IT. PRESYNC stores commitments at ABSOLUTE heights
// (m_current_height starts at chain_start_height) while REDOWNLOAD checks them at
// BUFFER-RELATIVE ones (m_redownload_buffer_last_height started at 0). The two
// phases evaluate the SAME `% commitment_period == m_commit_offset` predicate at
// heights offset by chain_start_height, so they agree ONLY when
// chain_start_height is an exact multiple of the period — a 1-in-584 accident.
// Every other start height checks commitments against the wrong headers and,
// composed with the mismatch penalty, rejects honest peers.
//
// MEASURED (A-2): with a 54,000 start height REDOWNLOAD failed; with 53,728
// (= 584 x 92) it passed, on the SAME binary and the SAME headers. After this
// reseed both pass.
//
// The anchor fields matter as much as the height: without them the first
// redownloaded header's hashPrevBlock was taken from the PEER's own header
// (making the peer choose the anchor) and m_redownload_buffer_last_hash was left
// null, which made the continuity check unreachable for that first header.
// Blocker 2 and the "unanchored first header" note were ONE missing block.
void HeadersSyncState::EnterRedownloadPhase()
{
    m_redownloaded_headers.clear();
    m_redownload_buffer_last_height     = m_chain_start_height;
    m_redownload_buffer_first_prev_hash = m_chain_start_hash;
    m_redownload_buffer_last_hash       = m_chain_start_hash;
    // The fifth field. Only expressible because m_chain_start_work is retained --
    // m_current_chain_work has absorbed every PRESYNC header by now, so it is NOT
    // a substitute. Reseeding here also RESTORES correctness after any PRESYNC
    // mutation, which the constructor's value alone could not do: that value was
    // correct at this point only by accident, since nothing happened to touch it.
    m_redownload_chain_work             = m_chain_start_work;

    m_download_state = State::REDOWNLOAD;
}

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
    if (!NBitsIsSaneForWorkAccounting(header.nBits)) {
        std::cerr << "[HeadersSyncState] Rejecting header with unusable nBits 0x"
                  << std::hex << header.nBits << std::dec << std::endl;
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
    // 0. LP-10 A-2 / blocker 1 — nBits sanity, BEFORE anything uses it.
    //
    // This phase previously had NO nBits check of any kind while still
    // accumulating chain work from the peer's raw nBits below (m_redownload_chain_work).
    // PRESYNC had the weak `nBits == 0` guard and this path had nothing, so a
    // saturating nBits rejected in phase 1 would have been accepted in phase 2 --
    // a guard present at one site and absent at its sibling.
    if (!NBitsIsSaneForWorkAccounting(header.nBits)) {
        std::cerr << "[HeadersSyncState] REDOWNLOAD: unusable nBits 0x"
                  << std::hex << header.nBits << std::dec << std::endl;
        return false;
    }

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

    // 2. Check continuity — UNCONDITIONALLY, first header included.
    //
    // ⛔ THIS SITE PREVIOUSLY EXEMPTED THE FIRST HEADER, and the blocker-2 commit
    // message claimed the exemption was closed by the transition reseed. IT WAS
    // NOT — a reviewer's probe (P1) drove a first REDOWNLOAD header with a garbage
    // hashPrevBlock and it returned success. The claim was wrong and this is the
    // code that makes it true.
    //
    // The old shape was:
    //     if (!m_redownloaded_headers.empty()) { ...check... }
    //     else { m_redownload_buffer_first_prev_hash = header.hashPrevBlock; }
    //
    // Two defects in four lines. The check was SKIPPED for the first header, and
    // the else-branch then took the anchor FROM THE PEER — so even after
    // EnterRedownloadPhase seeded both hash fields from m_chain_start_hash, the
    // very first header overwrote the anchor with a value the peer chose. The
    // reseed was correct and was immediately clobbered.
    //
    // Unconditional now, which is what upstream does: EnterRedownloadPhase sets
    // m_redownload_buffer_last_hash = m_chain_start_hash, so the first header's
    // hashPrevBlock MUST equal the chain start or the chain is not anchored to it.
    // Nothing assigns m_redownload_buffer_first_prev_hash here any more — the
    // reseed owns it, and PopHeadersReadyForAcceptance reconstructs from it.
    if (header.hashPrevBlock != m_redownload_buffer_last_hash) {
        std::cerr << "[HeadersSyncState] Chain discontinuity in REDOWNLOAD"
                  << (m_redownloaded_headers.empty()
                      ? " (FIRST header does not connect to chain start)" : "")
                  << std::endl;
        return false;
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
