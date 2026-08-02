// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/headers_manager.h>
#include <net/net.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <net/peers.h>
#include <net/port/header_proof_checkers.h>  // Phase 3: VDF + RandomX impls
#include <consensus/chain_work.h>             // Phase 3 BLOCKER fix: shared chain-work helper
#include <consensus/params.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <util/time.h>
#include <util/logging.h>  // For g_verbose flag
#include <node/genesis.h>
#include <net/port/sync_coordinator.h>  // Phase 6 PR6.5a: IsSynced() via adapter
#include <consensus/ichain_selector.h>  // Phase 6 PR6.1: chain_selector wiring
// PR5.5 (2026-04-26): node/fork_manager.h include retired from
// HeadersManager. ForkManager-driven fork-cancellation defensive cleanup
// during header invalidation has been removed in favor of relying on the
// block-validation layer for fork resolution. ForkManager file remains
// (Phase 7 deletes it) for ibd_coordinator + block_processing callers.
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/banman.h>   // v4.1: MisbehaviorType for header checkpoint enforcement
#include <net/peers.h>    // v4.1: CPeerManager::Misbehaving (already pulled by net/net.h but explicit for clarity)
#include <api/metrics.h>  // Fork detection metrics
#include <algorithm>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>

// BUG #150 FIX: Access to validated chainstate for fork-safe locator building
extern CChainState g_chainstate;

// BUG #261 FIX: Fork detection only when synced
// Prevents false fork detection when peers send headers during initial startup.
// Uses IsSynced() instead of time-based grace period - won't miss genuine forks.

// =============================================================================
// v4.1 — Header-time checkpoint enforcement helper
// =============================================================================
//
// Direct hash compare against any embedded checkpoint at the EXACT batch
// height. NO GetAncestor walk in the headers code path (Layer-2 v0.2 HIGH-5
// fix: GetAncestor walks pskip pointers that are mutated outside cs_main,
// which is unsafe in headers context where only cs_headers is held).
//
// Returns true if the header is acceptable (no checkpoint at this height,
// or the checkpoint matches). Returns false if the header violates an
// embedded checkpoint.
//
// Called from FIVE ingress sites in this file before each
// `mapHeaders[...] = headerData` write:
//   1. ProcessHeaders FAST PATH 1 (below-checkpoint)
//   2. ProcessHeaders slow path (above-checkpoint, after ValidateHeader)
//   3. ProcessHeadersWithDoSProtection (DoS-protected redownload)
//   4. QueueHeadersForValidation STEP 2 (below-checkpoint)
//   5. QueueHeadersForValidation STEP 2 (above-checkpoint)
//
// On rejection, the caller should bump peer misbehavior via
// CPeerManager::Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER)
// and return false to abort the batch.
static bool CheckpointCheckHeader(int height, const uint256& headerHash) {
    if (!Dilithion::g_chainParams) return true;
    for (const auto& cp : Dilithion::g_chainParams->checkpoints) {
        if (cp.nHeight == height) {
            if (headerHash != cp.hashBlock) {
                LogPrintf(NET, WARN,
                    "[HeadersManager] v4.1 header-time check: checkpoint violation at height %d "
                    "(got %s, expected %s) -- rejecting batch\n",
                    height,
                    headerHash.GetHex().substr(0, 16).c_str(),
                    cp.hashBlock.GetHex().substr(0, 16).c_str());
                return false;
            }
            return true;
        }
    }
    return true;  // no checkpoint at this height
}

CHeadersManager::CHeadersManager()
    : nBestHeight(-1)
{
    hashBestHeader = uint256();

    // Phase 3: read minimum chain work from chainparams (was hardcoded 0).
    nMinimumChainWork = (Dilithion::g_chainParams != nullptr)
        ? Dilithion::g_chainParams->nMinimumChainWork
        : uint256();

    // Phase 3: pick the chain-agnostic proof checker. DilV (VDF-only chain)
    // ships VDFHeaderProofChecker; DIL ships RandomXHeaderProofChecker.
    // The HeadersSyncState instances we construct below get a non-owning
    // pointer to this; lifetime: owned by manager, outlives all states.
    if (Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV()) {
        m_proof_checker =
            std::make_unique<::dilithion::net::port::VDFHeaderProofChecker>();
    } else {
        m_proof_checker =
            std::make_unique<::dilithion::net::port::RandomXHeaderProofChecker>();
    }

    // BUG FIX: Add genesis to mapHeaders so block 1 can accumulate chain work properly
    // Without this, block 1's pprev is nullptr and chainWork doesn't include genesis work
    CBlock genesis = (Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV()) ?
        Genesis::CreateDilVGenesisBlock() : Genesis::CreateGenesisBlock();
    // Single-source, integrity-validated genesis hash (see node/genesis.cpp
    // GetGenesisHash): keeps the headers-manager key consistent with the DB key
    // and the P2P-advertised hash, and never keys off a transient miscompute.
    uint256 genesisHash = Genesis::GetGenesisHash();
    uint256 genesisWork = GetBlockWork(genesis.nBits);

    HeaderWithChainWork genesisData(static_cast<CBlockHeader>(genesis), 0);  // height 0
    genesisData.chainWork = genesisWork;
    mapHeaders[genesisHash] = genesisData;
    AddToHeightIndex(genesisHash, 0);

    // Phase 6 PR6.1 (v1.5 fix-up 2026-04-27 per Cursor verification follow-up):
    // Genesis is NOT wired to chain_selector here. Same justification as
    // BulkLoadHeaders below: chain_selector's mapBlockIndex receives genesis
    // through CChainState's own AddBlockIndex call during chainstate init,
    // which happens BEFORE g_node_context.chain_selector is even
    // constructed. Wiring here would either fail (chain_selector pointer
    // is null at HeadersManager construction time) or be redundant once
    // chain_selector is up. If init order ever changes such that
    // chain_selector outlives HeadersManager construction, add the wiring
    // here in a guarded block.

    // Set genesis as initial best header
    hashBestHeader = genesisHash;
    nBestHeight = 0;

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Genesis added to mapHeaders: " << genesisHash.GetHex().substr(0, 16)
                  << " chainWork=" << genesisWork.GetHex().substr(genesisWork.GetHex().length() > 16 ? genesisWork.GetHex().length() - 16 : 0)
                  << std::endl;
}

CHeadersManager::~CHeadersManager()
{
    // Ensure threads are stopped (idempotent - safe to call multiple times)
    StopValidationThread();

    // Explicitly clear containers in a controlled order to prevent
    // any potential issues with default destruction order
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        mapHeadersSyncStates.clear();
        mapHeaders.clear();
        mapHeightIndex.clear();
        setChainTips.clear();
        m_chainTipsLastSeen.clear();  // Phase 6 PR6.2
        mapPeerStates.clear();
        mapPeerStartHeight.clear();
        m_rejectedHashes.clear();
        m_bestChainCache.clear();
    }

    // PR5.2.B: m_chainTipsTracker retired — setChainTips above already
    // serves as the canonical leaf set; no separate cache to clear.
}

// ============================================================================
// Public API: Header Processing
// ============================================================================

// Phase 6 PR6.1 (v1.5 §4 PR6.1 + DoS guards): per-peer header rate limit.
// Sliding-by-reset window. Caller MUST already hold cs_headers.
//
// Window + limit pulled from chainparams (Cursor v1.5+ per-spec fix B1):
//   * ChainParams.nHeaderRateWindowSec
//   * ChainParams.nHeaderRateLimitPerWindow
// Defaults (60s / 1000 headers) match the prior hardcoded values, so
// behavior is unchanged unless a factory overrides. If g_chainParams
// is null (test fixtures without setup), fall back to the same defaults.
bool CHeadersManager::CheckPeerHeaderRateLimit(NodeId peer, size_t batchSize)
{
    const int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    int window_sec = 60;
    int limit      = 5000;  // v4.1: bumped 1000->5000 to match chainparams default + standard MAX_HEADERS_RESULTS=2000 batch
    if (Dilithion::g_chainParams) {
        if (Dilithion::g_chainParams->nHeaderRateWindowSec > 0) {
            window_sec = Dilithion::g_chainParams->nHeaderRateWindowSec;
        }
        if (Dilithion::g_chainParams->nHeaderRateLimitPerWindow > 0) {
            limit = Dilithion::g_chainParams->nHeaderRateLimitPerWindow;
        }
    }

    auto& rate = m_peerHeaderRate[peer];
    if (now_sec - rate.window_start_unix_sec >= window_sec) {
        // Window expired — start a fresh window.
        rate.window_start_unix_sec = now_sec;
        rate.headers_in_window = 0;
    }
    rate.headers_in_window += static_cast<int>(batchSize);
    return rate.headers_in_window <= limit;
}

bool CHeadersManager::ProcessHeaders(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] ProcessHeaders called: peer=" << peer
                  << ", count=" << headers.size() << std::endl;

    // DEADLOCK FIX: Get chainstate tip BEFORE acquiring cs_headers
    // This is needed because GetLocatorImpl may be called while holding cs_headers,
    // and we must avoid calling GetTip() (which needs cs_main) while holding cs_headers.
    CBlockIndex* pTipPreFetched = g_chainstate.GetTip();
    int chainstateHeightPreFetched = (pTipPreFetched && pTipPreFetched->nHeight > 0) ? pTipPreFetched->nHeight : 0;

    std::lock_guard<std::mutex> lock(cs_headers);

    // Phase 6 PR6.1: per-peer rate limit. Drop the batch if peer is over budget.
    // v4.1 audit fix (twin of headers_manager.cpp:2495 fix in commit 3c5e0eb):
    // promote log to always-on WARN. This is one of two twins of the bug that
    // hid the rate-limit reject from operators during IBD. Always log so the
    // diagnostic trail is visible without --verbose.
    if (!headers.empty() && !CheckPeerHeaderRateLimit(peer, headers.size())) {
        LogPrintf(NET, WARN,
            "[HeadersManager] Rate-limit reject (Process): peer=%d batch=%zu "
            "(window limit = %d/%ds)\n",
            static_cast<int>(peer),
            headers.size(),
            Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateLimitPerWindow : 5000,
            Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateWindowSec : 60);
        return false;
    }
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Lock acquired" << std::endl;

    if (headers.empty()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Empty headers, returning true" << std::endl;
        return true;  // Empty is valid (no new headers)
    }

    if (headers.size() > MAX_HEADERS_BUFFER) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Too many headers (" << headers.size()
                      << " > " << MAX_HEADERS_BUFFER << "), returning false" << std::endl;
        return false;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Processing " << headers.size() << " headers" << std::endl;

    // COMMON ANCESTOR OPTIMIZATION: Find where incoming chain diverges from ours.
    // Headers below the common ancestor are identical on both chains - skip hash computation.
    // Only compute expensive RandomX hashes for headers ABOVE the divergence point.
    int commonAncestorHeight = -1;
    const HeaderWithChainWork* commonAncestor = nullptr;

    // Check first header's parent to find common ancestor
    if (!headers.empty()) {
        const uint256& firstParent = headers[0].hashPrevBlock;
        auto parentIt = mapHeaders.find(firstParent);
        if (parentIt != mapHeaders.end()) {
            commonAncestorHeight = parentIt->second.height;
            commonAncestor = &parentIt->second;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Common ancestor found at height " << commonAncestorHeight
                          << " - will skip hash computation for heights <= " << commonAncestorHeight << std::endl;
        }
    }

    // Process each header sequentially
    const HeaderWithChainWork* pprev = commonAncestor;  // Start from common ancestor if found
    uint256 prevHash;  // Track previous header's hash for sequential iteration
    int heightStart = commonAncestorHeight;

    // Get checkpoint height once
    int highestCheckpoint = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    // Independent height tracker: headers in GETHEADERS responses are sequential,
    // so we can track height even when pprev can't advance (e.g. below-checkpoint
    // headers where mapHeightIndex is missing entries from compact block sync).
    int sequentialHeight = (commonAncestorHeight >= 0) ? (commonAncestorHeight + 1) : 1;

    for (size_t i = 0; i < headers.size(); i++) {
        const CBlockHeader& header = headers[i];

        // Calculate expected height - use pprev when available, fall back to sequential tracker
        int expectedHeight = pprev ? (pprev->height + 1) : sequentialHeight;
        sequentialHeight = expectedHeight + 1;  // Always advance for next iteration

        auto heightIt = mapHeightIndex.find(expectedHeight);
        bool heightHasHeaders = (heightIt != mapHeightIndex.end() && !heightIt->second.empty());

        // FAST PATH 1: Below checkpoint - skip PoW validation but still store.
        // Checkpoints are hardcoded guarantees of the canonical chain.
        // No competing header below a checkpoint can ever produce a valid reorg,
        // so there's no reason to compute expensive RandomX PoW hashes.
        // But we MUST still store headers so the chain walk in
        // GetBestChainHashAtHeight() works during IBD block fetching.
        //
        // Phase 3 disposition (Q3 plan recommended PR3.4 deletion): Patch H
        // STAYS until Phase 5 retires the legacy `ProcessHeaders` path. The
        // upstream-pattern HeadersSyncStateV2 (Phase 3) bypasses this code
        // entirely (its `pow_validated_headers` get pushed into mapHeaders
        // through ProcessHeadersWithDoSProtection's success path), but
        // ProcessHeaders is still reachable for non-DoS-protected callers.
        // Deleting Patch H now would re-introduce the silent-drop bug for
        // any flow that lands here. Phase 5's chain-selection rewrite is the
        // natural retirement point.
        if (expectedHeight <= highestCheckpoint) {
            // Patch H (v4.0.22) -- Compute incoming hash and check for true
            // duplicate. PRIOR BUG: if mapHeightIndex already had ANY header
            // at this height, the incoming header was silently dropped via
            // *heightIt->second.begin() picking the first-arrived sibling.
            // That left competing siblings unstored, so when a node received
            // the canonical sibling AFTER committing to a wrong-fork sibling
            // (LDN/SGP at 44468 during the 2026-04-25 incident), the canonical
            // header was never seen by chain selection. UpdateBestHeader could
            // not reorg because the alternative chain did not exist in
            // mapHeaders. Fix: store every distinct sibling and let cumulative
            // chain work decide via UpdateBestHeader. Checkpoint at the next
            // height (or above) still enforces which sibling is canonical via
            // the parent-hash link from the checkpoint header.
            uint256 storageHash = header.GetHash();

            // True duplicate: same hash already stored - advance pprev and skip.
            auto existingIt = mapHeaders.find(storageHash);
            if (existingIt != mapHeaders.end()) {
                pprev = &existingIt->second;
                prevHash = storageHash;
                heightStart = existingIt->second.height;
                continue;
            }

            // New header at this height (either empty slot or competing sibling).
            // Skip the expensive RandomX PoW check (below checkpoint, trust
            // anchor handles validity) but DO store and register the header so
            // cumulative chain-work comparison can pick the canonical chain
            // over a stuck wrong-fork sibling.
            int height = pprev ? (pprev->height + 1) : expectedHeight;
            // v4.1 site 1/5: header-time checkpoint enforcement (BEFORE store)
            if (!CheckpointCheckHeader(height, storageHash)) {
                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
                }
                return false;
            }
            uint256 chainWork = CalculateChainWork(header, pprev);
            HeaderWithChainWork headerData(header, height);
            headerData.chainWork = chainWork;
            mapHeaders[storageHash] = headerData;
            AddToHeightIndex(storageHash, height);
            UpdateChainTips(storageHash);   // Patch H -- register competing tip
            UpdateBestHeader(storageHash);  // Patch H -- re-evaluate active chain

            // Phase 6 PR6.1: chain_selector wiring. Every accepted header
            // populates chain_selector's mapBlockIndex with a pre-validation
            // entry so chain_selector can authoritatively answer fork-detection
            // queries. Failure return is non-fatal (orphan / invalid parent);
            // chain_selector's own DoS guards apply.
            if (g_node_context.chain_selector) {
                (void)g_node_context.chain_selector->ProcessNewHeader(header);
            }

            pprev = &mapHeaders[storageHash];
            prevHash = storageHash;
            if (heightStart < 0) heightStart = height;
            continue;  // Skip PoW validation but header is now stored
        }

        // FAST PATH 2: Below common ancestor height, headers are identical on both chains
        // Skip hash computation - use our existing headers instead
        if (commonAncestorHeight > 0 && expectedHeight <= commonAncestorHeight && heightHasHeaders) {
            uint256 existingHash = *heightIt->second.begin();
            auto existingIt = mapHeaders.find(existingHash);
            if (existingIt != mapHeaders.end()) {
                pprev = &existingIt->second;
                prevHash = existingHash;
                heightStart = existingIt->second.height;
                // Don't update best header - just traversing common history
                continue;  // Skip without computing hash
            }
        }

        // SLOW PATH: Above common ancestor - compute hash for fork detection and work comparison
        uint256 storageHash = header.GetHash();

        // Skip if this hash was previously rejected (block failed validation)
        if (m_rejectedHashes.count(storageHash)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Skipping rejected header at height " << expectedHeight
                          << " hash=" << storageHash.GetHex().substr(0, 16) << "..." << std::endl;
            continue;
        }

        // Skip TRUE duplicates (same hash already exists)
        if (mapHeaders.find(storageHash) != mapHeaders.end()) {
            auto it = mapHeaders.find(storageHash);
            // BUG FIX: Recalculate chainwork if pprev gives higher work.
            // Stale headers stored with pprev=NULL have tiny chainwork.
            if (pprev) {
                uint256 newChainWork = CalculateChainWork(header, pprev);
                if (ChainWorkGreaterThan(newChainWork, it->second.chainWork)) {
                    it->second.chainWork = newChainWork;
                    int newHeight = pprev->height + 1;
                    if (it->second.height != newHeight) {
                        it->second.height = newHeight;
                    }
                }
            }
            pprev = &it->second;
            prevHash = storageHash;
            heightStart = it->second.height;
            UpdateBestHeader(storageHash);
            continue;
        }

        // FORK DETECTION: Only relevant above checkpoint
        if (heightHasHeaders && expectedHeight > highestCheckpoint) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Fork header received at height " << expectedHeight
                          << " - processing competing chain" << std::endl;
        }

        // SIMPLIFIED PARENT LOOKUP: With RandomX-only storage, hashPrevBlock directly
        // references the parent's storage hash (no mapping needed)

        // Check if parent is genesis block
        uint256 genesisHash = Genesis::GetGenesisHash();
        if (header.hashPrevBlock == genesisHash || header.hashPrevBlock.IsNull()) {
            if (i == 0 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[HeadersManager] Parent is genesis, startHeight=1 (prevBlock="
                          << header.hashPrevBlock.GetHex().substr(0, 16) << ", genesisHash="
                          << genesisHash.GetHex().substr(0, 16) << ")" << std::endl;
            }
            // BUG FIX: Look up genesis in mapHeaders to get cumulative chain work
            // Previously set pprev = nullptr, causing chainWork to not accumulate
            auto genesisIt = mapHeaders.find(genesisHash);
            if (genesisIt != mapHeaders.end()) {
                pprev = &genesisIt->second;
            } else {
                // Genesis not in mapHeaders yet - use nullptr (first block case)
                pprev = nullptr;
            }
        }
        // Direct parent lookup (hashPrevBlock = parent's RandomX hash = parent's storage hash)
        else {
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            if (parentIt != mapHeaders.end()) {
                pprev = &parentIt->second;
            } else {
                // Parent not found - this is a competing chain (fork on PoW, normal on VDF)

                // STALE FORK FILTER: If the expected height is far below our chain tip,
                // this fork can never trigger an automatic reorg (its depth exceeds the
                // consensus reorg cap Consensus::MAX_REORG_DEPTH, which the in-place
                // auto-reorg bound MAX_AUTO_REORG_DEPTH also tracks). Skip fork detection
                // to avoid log noise, unnecessary GETHEADERS, and wasted CPU on
                // obviously-stale competing chains. Keep in lockstep with the reorg cap.
                static const int STALE_FORK_THRESHOLD = Consensus::MAX_REORG_DEPTH;
                if (chainstateHeightPreFetched > 0 && expectedHeight > 0 &&
                    (chainstateHeightPreFetched - expectedHeight) > STALE_FORK_THRESHOLD) {
                    if (g_verbose.load(std::memory_order_relaxed)) {
                        std::cout << "[HeadersManager] Ignoring stale fork header at height " << expectedHeight
                                  << " (chain at " << chainstateHeightPreFetched << ", depth="
                                  << (chainstateHeightPreFetched - expectedHeight) << ")" << std::endl;
                    }
                    continue;
                }

                // Check if we already requested this parent (avoid duplicate requests)
                if (m_pendingParentRequests.find(header.hashPrevBlock) == m_pendingParentRequests.end()) {
                    std::cout << "[HeadersManager] FORK: Parent " << header.hashPrevBlock.GetHex().substr(0, 16)
                              << " unknown - requesting headers from common ancestor (peer=" << peer << ")" << std::endl;

                    // Track missing parent and request ancestors immediately
                    m_pendingParentRequests.insert(header.hashPrevBlock);

                    // DEADLOCK FIX: Use GetLocatorImpl directly since we already hold cs_headers.
                    // Calling RequestHeaders() would call GetLocator() which tries to relock cs_headers,
                    // causing a deadlock (std::mutex is not recursive).
                    // Pass pre-fetched tip to avoid cs_main/cs_headers lock inversion.
                    std::vector<uint256> locator = GetLocatorImpl(uint256(), pTipPreFetched, chainstateHeightPreFetched);

                    // Send GETHEADERS message directly
                    auto* connman = g_node_context.connman.get();
                    auto* msg_proc = g_message_processor.load();
                    if (connman && msg_proc) {
                        NetProtocol::CGetHeadersMessage msg(locator, uint256());
                        CNetMessage getheaders = msg_proc->CreateGetHeadersMessage(msg);
                        connman->PushMessage(peer, getheaders);
                        std::cout << "[HeadersManager] FORK: Sent GETHEADERS to peer " << peer << std::endl;
                    }

                    // BUG #261 FIX: Only signal fork if node is synced
                    // During startup/IBD, headers with "unknown parents" are normal
                    // because we're still loading/syncing. Only treat as fork if synced.
                    bool is_synced = g_node_context.sync_coordinator &&
                                     g_node_context.sync_coordinator->IsSynced();
                    if (is_synced) {
                        g_node_context.fork_detected.store(true);
                        g_metrics.SetForkDetected(true, 0, 0);
                    }
                }

                // Continue - remaining headers will also fail to connect, that's expected
                continue;
            }
        }

        // Validate header
        if (!ValidateHeader(header, pprev ? &pprev->header : nullptr)) {
            return false;
        }

        // Calculate height and chain work
        int height = pprev ? (pprev->height + 1) : 1;
        uint256 chainWork = CalculateChainWork(header, pprev);

        // v4.1 site 2/5: header-time checkpoint enforcement (BEFORE store)
        if (!CheckpointCheckHeader(height, storageHash)) {
            if (g_node_context.peer_manager) {
                g_node_context.peer_manager->Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
            }
            return false;
        }

        // Store header
        HeaderWithChainWork headerData(header, height);
        headerData.chainWork = chainWork;
        mapHeaders[storageHash] = headerData;
        AddToHeightIndex(storageHash, height);

        UpdateChainTips(storageHash);
        UpdateBestHeader(storageHash);

        // Phase 6 PR6.1: chain_selector wiring (normal path).
        if (g_node_context.chain_selector) {
            (void)g_node_context.chain_selector->ProcessNewHeader(header);
        }

        // FORK RESOLUTION: Check if this header was a pending parent
        // If so, the fork is resolving - clear from pending and check if fully resolved
        if (m_pendingParentRequests.erase(storageHash) > 0) {
            std::cout << "[HeadersManager] Pending parent " << storageHash.GetHex().substr(0, 16)
                      << " arrived at height " << height << " - fork resolving" << std::endl;

            // If no more pending parents, fork is fully resolved
            if (m_pendingParentRequests.empty()) {
                std::cout << "[HeadersManager] Fork resolved - all ancestors received, mining can resume" << std::endl;
                g_node_context.fork_detected.store(false);
                g_metrics.ClearForkDetected();  // Clear Prometheus metrics
            }
        }

        // Update for next iteration
        pprev = &mapHeaders[storageHash];
        prevHash = storageHash;

        if (heightStart < 0) {
            heightStart = height;
        }
    }

    // Update peer state
    if (!headers.empty() && !prevHash.IsNull()) {
        auto it = mapHeaders.find(prevHash);
        if (it != mapHeaders.end()) {
            UpdatePeerState(peer, prevHash, it->second.height);
        }
    }

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[HeadersManager] ProcessHeaders: " << headers.size()
                  << " headers, best=" << nBestHeight << std::endl;
    }

    // Bug #150: Trigger periodic orphan pruning
    m_headers_since_last_prune += headers.size();
    if (m_headers_since_last_prune >= PRUNE_BATCH_SIZE) {
        // Note: PruneOrphanedHeaders acquires its own lock, so we must release first
        // We can't call it here while holding cs_headers. Instead, we set a flag
        // and the caller can check if pruning is needed.
        // For now, just reset the counter - pruning will be triggered by external call
        m_headers_since_last_prune = 0;
    }

    return true;
}

// ============================================================================
// DoS-Protected Header Sync (Bitcoin Core two-phase)
// ============================================================================

bool CHeadersManager::ProcessHeadersWithDoSProtection(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    // Phase 6 PR6.1: per-peer rate limit. Same policy as ProcessHeaders.
    // We hold cs_headers for the rate-limit check (same lock).
    // v4.1 audit fix (twin of headers_manager.cpp:2495 fix in commit 3c5e0eb):
    // log the reject so operators can see the cause. Was completely silent.
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        if (!headers.empty() && !CheckPeerHeaderRateLimit(peer, headers.size())) {
            LogPrintf(NET, WARN,
                "[HeadersManager] Rate-limit reject (DoS): peer=%d batch=%zu "
                "(window limit = %d/%ds)\n",
                static_cast<int>(peer),
                headers.size(),
                Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateLimitPerWindow : 5000,
                Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateWindowSec : 60);
            return false;
        }
    }

    // Check if peer has active HeadersSyncState
    auto it = mapHeadersSyncStates.find(peer);
    if (it == mapHeadersSyncStates.end()) {
        return ProcessHeaders(peer, headers);
    }

    HeadersSyncState* sync_state = it->second.get();
    if (!sync_state || sync_state->GetState() == HeadersSyncState::State::FINAL) {
        mapHeadersSyncStates.erase(peer);
        return ProcessHeaders(peer, headers);
    }


    // Process through HeadersSyncState
    auto result = sync_state->ProcessNextHeaders(headers, true);

    if (!result.success) {
        mapHeadersSyncStates.erase(peer);
        return false;
    }

    // If we got validated headers back, store them
    if (!result.pow_validated_headers.empty()) {

        // Store validated headers using existing logic (but without re-validation)
        std::lock_guard<std::mutex> lock(cs_headers);
        for (const auto& header : result.pow_validated_headers) {
            uint256 hash = header.GetHash();

            // Skip if already stored
            if (mapHeaders.find(hash) != mapHeaders.end()) {
                continue;
            }

            // Find parent
            auto parentIt = mapHeaders.find(header.hashPrevBlock);
            const HeaderWithChainWork* pprev = nullptr;
            int height = 1;

            if (parentIt != mapHeaders.end()) {
                pprev = &parentIt->second;
                height = pprev->height + 1;
            }

            // Calculate chain work and store
            uint256 chainWork = CalculateChainWork(header, pprev);

            // v4.1 site 3/5: header-time checkpoint enforcement (BEFORE store)
            // NOTE: this site uses `hash` (declared at start of loop body),
            // NOT `storageHash` — Layer-2 v0.3 #2 caught this distinction.
            if (!CheckpointCheckHeader(height, hash)) {
                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
                }
                return false;
            }

            HeaderWithChainWork headerData(header, height);
            headerData.chainWork = chainWork;

            mapHeaders[hash] = headerData;
            AddToHeightIndex(hash, height);
            UpdateChainTips(hash);
            UpdateBestHeader(hash);

            // Phase 6 PR6.1: chain_selector wiring (DoS-protected REDOWNLOAD).
            if (g_node_context.chain_selector) {
                (void)g_node_context.chain_selector->ProcessNewHeader(header);
            }
        }

    }

    // Check if sync is complete
    if (sync_state->GetState() == HeadersSyncState::State::FINAL) {
        mapHeadersSyncStates.erase(peer);
    }

    return true;
}

bool CHeadersManager::ShouldUseDoSProtection(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Check if peer already has active HeadersSyncState
    if (mapHeadersSyncStates.find(peer) != mapHeadersSyncStates.end()) {
        return true;
    }

    // Bug #150: Lower threshold for DoS protection activation
    // If peer claims significantly more headers, use protected sync
    auto heightIt = mapPeerStartHeight.find(peer);
    if (heightIt != mapPeerStartHeight.end()) {
        int peerHeight = heightIt->second;
        // Bug #150: Reduced from 2000 to 500 blocks for earlier protection
        if (peerHeight > nBestHeight + 500) {
            std::cout << "[HeadersManager] DoS protection activated for peer " << peer
                      << " (claims height " << peerHeight << " vs our " << nBestHeight << ")" << std::endl;
            return true;
        }
    }

    // Bug #150: Also activate if we have competing forks
    // This helps protect against fork flooding attacks.
    // PR5.2.B: setChainTips replaces m_chainTipsTracker as the canonical
    // leaf set — size > 1 means competing forks exist.
    if (setChainTips.size() > 1) {
        std::cout << "[HeadersManager] DoS protection activated due to competing forks ("
                  << setChainTips.size() << " tips)" << std::endl;
        return true;
    }

    return false;
}

bool CHeadersManager::InitializeDoSProtectedSync(NodeId peer, const uint256& minimum_work)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Don't reinitialize if already exists
    if (mapHeadersSyncStates.find(peer) != mapHeadersSyncStates.end()) {
        return true;
    }

    // Create HeadersSyncState parameters
    HeadersSyncParams params;
    // Use defaults from HeadersSyncParams

    // Get chain start (our current best header or genesis)
    uint256 chainStartHash = hashBestHeader;
    int64_t chainStartHeight = nBestHeight;

    if (chainStartHash.IsNull()) {
        // Start from genesis
        chainStartHash = Genesis::GetGenesisHash();
        chainStartHeight = 0;
    }

    // Create the state — Phase 3: pass the chain-agnostic proof checker.
    auto state = std::make_unique<HeadersSyncState>(
        peer,
        params,
        chainStartHash,
        chainStartHeight,
        minimum_work,
        m_proof_checker.get()
    );

    mapHeadersSyncStates[peer] = std::move(state);


    return true;
}

bool CHeadersManager::ValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev)
{
    // VDF blocks (version >= 4) skip RandomX PoW check.
    // Their proof is validated during full block validation.
    if (header.IsVDFBlock()) {
        if (Dilithion::g_chainParams && Dilithion::g_chainParams->vdfActivationHeight >= 0) {
            // VDF block - PoW check handled by VDF consensus validation
            // Fall through to remaining checks (timestamp, etc.)
        } else {
            return false;
        }
    } else {
        uint256 hash = header.GetHash();

        // 1. Check Proof of Work
        if (!CheckProofOfWork(hash, header.nBits)) {
            // Compute target for debug
            uint256 target = CompactToBig(header.nBits);
            std::cerr << "  hash=   " << hash.GetHex() << std::endl;
            std::cerr << "  target= " << target.GetHex() << std::endl;
            std::cerr << "  Hash must be < target to be valid" << std::endl;
            return false;
        }
    }

    // If this is genesis block (no parent), that's all we need to check
    if (pprev == nullptr) {
        return true;
    }

    // Get parent header data for additional checks
    uint256 parentHash = pprev->GetHash();
    auto parentIt = mapHeaders.find(parentHash);
    if (parentIt == mapHeaders.end()) {
        // Parent not in our map yet - this shouldn't happen if ProcessHeaders calls us correctly
        return true;  // Allow it for now, parent checks will catch issues
    }

    const HeaderWithChainWork* pprevData = &parentIt->second;

    // 2. Check timestamp is valid (fork-aware: 600s limit post-timestampValidationHeight)
    if (!CheckTimestamp(header, pprevData, pprevData->height + 1)) {
        return false;
    }

    // 3. Check difficulty transition (simplified - full implementation would check retarget logic)
    // For now, just check bits are within reasonable range
    if (header.nBits == 0) {
        return false;
    }

    // 4. Check version (should be > 0)
    if (header.nVersion <= 0) {
        return false;
    }

    return true;
}

void CHeadersManager::RequestHeaders(NodeId peer, const uint256& hashStart)
{
    // No throttle needed - SyncHeadersFromPeer handles dedup via m_headers_requested_height
    // Build locator and send request

    // BUG #178 FIX (Part 2): Always use full exponential locator
    //
    // Old bug: Used single-hash locator when hashStart was provided.
    // Problem: If peer doesn't have that hash (we're on a fork), peer falls
    // back to genesis instead of finding the common ancestor.
    //
    // Fix: Always build exponential locator. If hashStart is provided,
    // prepend it so peer tries that first, but has fallback hashes.
    // This allows peers to find the fork point instead of starting from genesis.
    std::vector<uint256> locator = GetLocator(hashStart);

    // Prepend hashStart if it's not already first in locator
    if (!hashStart.IsNull() && (locator.empty() || locator[0] != hashStart)) {
        locator.insert(locator.begin(), hashStart);
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] RequestHeaders: Prepended hashStart to exponential locator" << std::endl;
    } else {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] RequestHeaders: Using exponential locator (size=" << locator.size() << ")" << std::endl;
    }

    auto* connman = g_node_context.connman.get();
    auto* msg_proc = g_message_processor.load();
    if (connman && msg_proc) {
        NetProtocol::CGetHeadersMessage msg(locator, uint256());
        CNetMessage getheaders = msg_proc->CreateGetHeadersMessage(msg);
        connman->PushMessage(peer, getheaders);
        {
            std::lock_guard<std::mutex> lock(cs_headers);
            m_last_header_request_time = std::chrono::steady_clock::now();
        }
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] RequestHeaders: Sent GETHEADERS to peer " << peer << std::endl;
    }
}

bool CHeadersManager::SyncHeadersFromPeer(NodeId peer, int peer_height, bool force)
{
    // SSOT: Single entry point for all header requests
    // Handles dedup, correct locator hash, and tracking

    // =========================================================================
    // PHASE 1: SYNCED STATE - SIMPLE HEADER REQUEST
    // =========================================================================
    // When node is synced (not in IBD), bypass dedup logic entirely.
    // In steady-state, we want to immediately request headers when:
    // - We receive an INV for an unknown block
    // - A peer announces a higher height
    // The dedup logic is only needed during IBD to prevent request spam.
    // =========================================================================

    if (g_node_context.sync_coordinator && g_node_context.sync_coordinator->IsSynced()) {
        // Synced state: Use m_last_request_hash to continue fork chain sync
        // Bug #179 Fix: If we received headers from a fork, hashBestHeader won't update
        // (fork has less work), but m_last_request_hash has the last received fork header.
        //
        // Bug #181 Fix: Add dedup to prevent flooding peer with duplicate requests.
        // Only send a new request if the locator hash has CHANGED since last request.
        uint256 request_from;
        {
            std::lock_guard<std::mutex> lock(cs_headers);
            request_from = m_last_request_hash.IsNull() ? hashBestHeader : m_last_request_hash;

            // Dedup: Skip if we already sent a request with this same hash
            if (request_from == m_last_sent_locator_hash && !force) {
                return false;  // Already requested from this point
            }

            // Update tracking BEFORE sending (prevents duplicate requests)
            m_last_sent_locator_hash = request_from;
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[SYNCED] Requesting headers from peer " << peer
                      << " (peer_height=" << peer_height
                      << ", locator=" << request_from.GetHex().substr(0, 16) << "...)" << std::endl;

        RequestHeaders(peer, request_from);
        return true;
    }

    // =========================================================================
    // IBD MODE: DEDUP LOGIC TO PREVENT REQUEST SPAM
    // =========================================================================

    int requested = m_headers_requested_height.load();

    // Already requested up to peer's height? Skip (unless forced).
    // Force is used when receiving INV for unknown blocks - we MUST request
    // headers even if our tracking says we already requested "enough".
    if (!force && peer_height <= requested) {
        return false;
    }

    // Calculate target (cap at requested + 2000 to limit pipeline depth)
    int expected_new_height = std::min(peer_height, requested + 2000);

    // Update tracking BEFORE sending request (prevents duplicate requests)
    m_headers_requested_height.store(expected_new_height);

    // Use last request hash if we have one, otherwise validated tip
    // m_last_request_hash is updated by QueueRawHeadersForProcessing when headers arrive
    uint256 request_from;
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        request_from = m_last_request_hash.IsNull() ? hashBestHeader : m_last_request_hash;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[IBD-SYNC] Requesting headers (requested=" << requested
                  << " -> " << expected_new_height << ", peer_height=" << peer_height
                  << ", locator=" << request_from.GetHex().substr(0, 16) << "...)" << std::endl;

    RequestHeaders(peer, request_from);
    return true;
}

void CHeadersManager::OnBlockActivated(const CBlockHeader& header, const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_headers);


    // Check if we already have this header
    auto it = mapHeaders.find(hash);
    if (it != mapHeaders.end()) {
        // BUG FIX: Recalculate chainwork if parent is now available.
        // Headers stored from a previous sync may have pprev=NULL (tiny chainwork)
        // because their parent wasn't in mapHeaders at the time. Now during chain
        // loading, the parent IS available. Recalculate and update if higher.
        auto parentIt = mapHeaders.find(header.hashPrevBlock);
        if (parentIt != mapHeaders.end()) {
            uint256 newChainWork = CalculateChainWork(header, &parentIt->second);
            if (ChainWorkGreaterThan(newChainWork, it->second.chainWork)) {
                it->second.chainWork = newChainWork;
                int newHeight = parentIt->second.height + 1;
                if (it->second.height != newHeight) {
                    it->second.height = newHeight;
                }
            }
        }
        UpdateBestHeader(hash);
        return;
    }

    // Find parent to determine height
    auto parentIt = mapHeaders.find(header.hashPrevBlock);
    int height = 1;  // Default for block 1 (parent is genesis at height 0)
    const HeaderWithChainWork* pprev = nullptr;

    if (parentIt != mapHeaders.end()) {
        pprev = &parentIt->second;
        height = pprev->height + 1;
    } else {
        // Parent not in map - this could be genesis (height 0) or block 1 (height 1)
        // If this is genesis block, height should be 0
        if (header.hashPrevBlock.IsNull()) {
            height = 0;  // Genesis block
        } else {
            // Parent not in mapHeaders (compact block arrived without header pipeline).
            // Look up actual height from chainstate block index.
            // Safe: cs_main is already held (called from ConnectTip→NotifyTipUpdate),
            // and cs_main is a recursive_mutex.
            CBlockIndex* pindex = g_chainstate.GetBlockIndex(hash);
            if (pindex) {
                height = pindex->nHeight;
            }
        }
    }

    // Calculate chain work
    uint256 chainWork = CalculateChainWork(header, pprev);

    // Store header
    HeaderWithChainWork headerData(header, height);
    headerData.chainWork = chainWork;
    mapHeaders[hash] = headerData;

    // Add to height index
    AddToHeightIndex(hash, height);

    // Update best header
    UpdateBestHeader(hash);

    // Phase 6 PR6.1: chain_selector wiring (post-activation hook).
    // Idempotent on re-call (chain_selector handles dup as no-op).
    if (g_node_context.chain_selector) {
        (void)g_node_context.chain_selector->ProcessNewHeader(header);
    }
}

void CHeadersManager::BulkLoadHeaders(const std::vector<CBlockIndex*>& chain)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Reserve nothing — std::map doesn't support reserve, but this is still
    // orders of magnitude faster than OnBlockActivated per-block because we
    // skip logging, chain work comparison, and fork detection.

    const HeaderWithChainWork* pprev = nullptr;

    for (const auto* pindex : chain) {
        const uint256& hash = pindex->GetBlockHash();
        const CBlockHeader& header = pindex->header;
        int height = pindex->nHeight;

        // Calculate chain work from parent
        uint256 chainWork = CalculateChainWork(header, pprev);

        // Insert directly — no duplicate check needed (chain is linear)
        HeaderWithChainWork headerData(header, height);
        headerData.chainWork = chainWork;
        mapHeaders[hash] = headerData;

        // Height index for peer serving
        mapHeightIndex[height].insert(hash);

        // Track pointer for next iteration's chain work calculation
        pprev = &mapHeaders[hash];

        // Phase 6 PR6.1 (v1.5 fix-up 2026-04-27 per Cursor "fix or document"):
        // BulkLoadHeaders is the chain-replay path called at startup from
        // CChainState's existing block index. chain_selector's mapBlockIndex
        // is populated by CChainState's own AddBlockIndex during the same
        // startup, so calling ProcessNewHeader here would be redundant
        // (idempotent on chain_selector's side, but a wasted lookup per
        // block). Intentionally NOT wired. If CChainState init order ever
        // changes such that BulkLoadHeaders runs BEFORE chain_selector's
        // own population, add the wiring here.
    }

    // Set best header to the tip (last element)
    if (!chain.empty()) {
        const CBlockIndex* tip = chain.back();
        hashBestHeader = tip->GetBlockHash();
        nBestHeight = tip->nHeight;
        InvalidateBestChainCache();
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "  [OK] Bulk-loaded " << chain.size()
                  << " headers (height 0 to " << nBestHeight << ")" << std::endl;
}

std::vector<uint256> CHeadersManager::GetLocator(const uint256& hashTip)
{
    // DEADLOCK FIX: Get chainstate tip BEFORE acquiring cs_headers
    // to avoid cs_headers/cs_main lock order inversion.
    // (OnBlockActivated holds cs_main and wants cs_headers;
    //  GetLocatorImpl would hold cs_headers and want cs_main via GetTip)
    CBlockIndex* pTip = g_chainstate.GetTip();
    int chainstateHeight = (pTip && pTip->nHeight > 0) ? pTip->nHeight : 0;

    std::lock_guard<std::mutex> lock(cs_headers);
    return GetLocatorImpl(hashTip, pTip, chainstateHeight);
}

std::vector<uint256> CHeadersManager::GetLocatorImpl(const uint256& hashTip, CBlockIndex* pTip, int chainstateHeight) const
{
    // NOTE: Caller MUST hold cs_headers lock
    // This is the implementation of GetLocator without lock acquisition.
    // Used by internal functions that already hold the lock to avoid deadlock.
    //
    // DEADLOCK FIX: pTip and chainstateHeight must be obtained BEFORE
    // acquiring cs_headers to avoid lock order inversion with cs_main.

    std::vector<uint256> locator;
    locator.reserve(32);  // Pre-allocate for efficiency

    // BUG #150 FIX (Part 3): Build locator from MAX(chainstate, headers_manager)
    //
    // Problem: If we build locator ONLY from chainstate and headers_manager has
    // more headers, we'll keep re-requesting the same headers we already have.
    //
    // Solution:
    // 1. Start from MAX(chainstate height, headers_manager best header height)
    // 2. For heights <= chainstate: use chainstate hashes (verified fork-safe)
    // 3. For heights > chainstate: use headers_manager best chain hashes
    //
    // This ensures we don't re-request headers while maintaining fork safety.
    // Note: pTip and chainstateHeight are pre-fetched before cs_headers lock.

    // Get headers_manager's best header height
    int headersHeight = 0;
    if (!hashBestHeader.IsNull()) {
        auto it = mapHeaders.find(hashBestHeader);
        if (it != mapHeaders.end()) {
            headersHeight = it->second.height;
        }
    }

    // Start from the HIGHER of the two to avoid re-requesting headers
    int startHeight = std::max(chainstateHeight, headersHeight);

    if (startHeight > 0) {
        int height = startHeight;
        int step = 1;
        int nStep = 0;

        while (height >= 0) {
            uint256 hashAtHeight;

            // Use chainstate for heights it covers (verified fork-safe)
            if (pTip && height <= chainstateHeight) {
                CBlockIndex* pBlock = pTip->GetAncestor(height);
                if (pBlock) {
                    hashAtHeight = pBlock->GetBlockHash();
                }
            } else {
                // Above chainstate: use headers_manager's best chain RandomX hashes
                // BUG FIX: GetBestChainHashAtHeight now returns RandomX hash, not SHA256
                hashAtHeight = GetBestChainHashAtHeight(height);
            }

            if (!hashAtHeight.IsNull()) {
                locator.push_back(hashAtHeight);
            }

            // Stop at genesis
            if (height == 0)
                break;

            // Exponential backoff after 10 entries
            if (nStep >= 10) {
                step *= 2;
            }

            height -= step;
            nStep++;

            // Limit total locator size (safety check)
            if (locator.size() >= 32) {
                break;
            }
        }

        if (!locator.empty()) {
            return locator;
        }
    }

    // Fallback: fresh node with no chainstate and no headers
    // Return empty locator - peer will send headers from genesis
    return locator;
}

// ============================================================================
// Public API: State Queries
// ============================================================================

bool CHeadersManager::IsSyncing() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Check if any peer is actively syncing
    for (const auto& pair : mapPeerStates) {
        if (pair.second.syncing) {
            return true;
        }
    }

    return false;
}

double CHeadersManager::GetSyncProgress() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (mapPeerStates.empty()) {
        return 0.0;
    }

    // Find highest claimed height from peers
    int maxPeerHeight = nBestHeight;
    for (const auto& pair : mapPeerStates) {
        if (pair.second.nSyncHeight > maxPeerHeight) {
            maxPeerHeight = pair.second.nSyncHeight;
        }
    }

    if (maxPeerHeight <= 0) {
        return 0.0;
    }

    return static_cast<double>(nBestHeight) / static_cast<double>(maxPeerHeight);
}

const CBlockHeader* CHeadersManager::GetBestHeader() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (hashBestHeader.IsNull()) {
        return nullptr;
    }

    auto it = mapHeaders.find(hashBestHeader);
    if (it == mapHeaders.end()) {
        return nullptr;
    }

    return &it->second.header;
}

uint256 CHeadersManager::GetBestHeaderHash() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return hashBestHeader;
}

int CHeadersManager::GetBestHeight() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return nBestHeight;
}

CHeadersManager::SyncSnapshot CHeadersManager::GetSyncSnapshot() const
{
    // Phase 10 PR10.2: atomic snapshot under a SINGLE cs_headers acquisition.
    // Eliminates Phase 9 PR9.6-RT-MEDIUM-2 (a) multi-lock tip-skew race.
    //
    // Body composes the same logic as GetSyncProgress() + GetBestHeight()
    // + GetBestHeaderHash() but reads all three protected fields once
    // under the lock. No new state is added; the lock-acquisition pattern
    // matches the existing three getters (same mutex, same scope) — no
    // new lock-ordering interaction with other subsystems.
    std::lock_guard<std::mutex> lock(cs_headers);

    SyncSnapshot snap;
    snap.best_height = nBestHeight;
    snap.best_hash = hashBestHeader;

    // Progress: walk peer states for max claimed height, divide by ours.
    if (mapPeerStates.empty()) {
        snap.progress = 0.0;
    } else {
        int maxPeerHeight = nBestHeight;
        for (const auto& pair : mapPeerStates) {
            if (pair.second.nSyncHeight > maxPeerHeight) {
                maxPeerHeight = pair.second.nSyncHeight;
            }
        }
        snap.progress = (maxPeerHeight <= 0)
            ? 0.0
            : static_cast<double>(nBestHeight) / static_cast<double>(maxPeerHeight);
    }

    return snap;
}

uint256 CHeadersManager::GetBestHash() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    // PR5.2.B: walk setChainTips for max-work tip. setChainTips is small
    // (typically O(1) tips, with rare O(N) during fork events); per-tip
    // mapHeaders lookup is O(1). Net O(K) where K = tip count.
    uint256 bestHash;
    uint256 bestWork;
    for (const auto& tipHash : setChainTips) {
        auto it = mapHeaders.find(tipHash);
        if (it == mapHeaders.end()) continue;
        if (bestHash.IsNull() || ChainWorkGreaterThan(it->second.chainWork, bestWork)) {
            bestHash = tipHash;
            bestWork = it->second.chainWork;
        }
    }
    return bestHash;
}

uint256 CHeadersManager::GetBestHeaderChainWork() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    uint256 bestWork;
    for (const auto& tipHash : setChainTips) {
        auto it = mapHeaders.find(tipHash);
        if (it == mapHeaders.end()) continue;
        if (bestWork.IsNull() || ChainWorkGreaterThan(it->second.chainWork, bestWork)) {
            bestWork = it->second.chainWork;
        }
    }
    return bestWork;
}

std::vector<CHeadersManager::HeaderTipInfo> CHeadersManager::GetCompetingHeaderTips() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    std::vector<HeaderTipInfo> out;
    out.reserve(setChainTips.size());
    for (const auto& tipHash : setChainTips) {
        auto it = mapHeaders.find(tipHash);
        if (it == mapHeaders.end()) continue;
        out.push_back({tipHash, it->second.height, it->second.chainWork});
    }
    return out;
}

bool CHeadersManager::IsHeaderSyncInProgress() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    if (m_last_request_hash.IsNull()) return false;

    // Check if the last header request is stale (no response in HEADER_SYNC_STALE_SECS)
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_header_request_time).count();
    if (elapsed > HEADER_SYNC_STALE_SECS) {
        return false;  // Stale - allow new requests
    }
    return true;
}

void CHeadersManager::ClearPendingSync()
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Bug #195 FIX: Clear request tracking state when switching peers after a stall.
    // This allows the next SyncHeadersFromPeer() call to:
    // 1. Use hashBestHeader (our validated tip) instead of stale m_last_request_hash
    // 2. Pass the dedup check (m_last_sent_locator_hash won't match the new locator)
    // 3. Make IsHeaderSyncInProgress() return false until new headers arrive

    if (!m_last_request_hash.IsNull() && g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[HeadersManager] Clearing pending sync state (was: "
                  << m_last_request_hash.GetHex().substr(0, 16) << "...)" << std::endl;
    }

    m_last_request_hash = uint256();
    m_last_sent_locator_hash = uint256();
}

bool CHeadersManager::GetHeader(const uint256& hash, CBlockHeader& header) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        return false;
    }

    header = it->second.header;
    return true;
}

bool CHeadersManager::HaveHeader(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return mapHeaders.find(hash) != mapHeaders.end();
}

int CHeadersManager::GetHeightForHash(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    auto it = mapHeaders.find(hash);
    if (it != mapHeaders.end()) {
        return it->second.height;
    }
    return -1;  // Not found
}

std::vector<uint256> CHeadersManager::GetHeadersAtHeight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    std::vector<uint256> result;

    auto it = mapHeightIndex.find(height);
    if (it != mapHeightIndex.end()) {
        result.insert(result.end(), it->second.begin(), it->second.end());
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

uint256 CHeadersManager::GetRandomXHashAtHeight(int height) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Bug #150 Fix: Use fork-safe lookup that follows best-work chain
    // Previously used *heightIt->second.begin() which selected by hash order,
    // NOT by chain work. This caused wrong block downloads during forks.
    return GetBestChainHashAtHeight(height);
}

// ============================================================================
// Public API: Peer Management
// ============================================================================

void CHeadersManager::OnPeerConnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates[peer] = PeerSyncState();

}

void CHeadersManager::OnPeerDisconnected(NodeId peer)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapPeerStates.erase(peer);
    mapPeerStartHeight.erase(peer);  // BUG #62: Clean up peer height tracking
    mapHeadersSyncStates.erase(peer);  // Clean up DoS protection state
    m_peerHeaderRate.erase(peer);  // Phase 6 PR6.1 fix-up (subagent v1.5+ BLOCKER): prevent monotonic
                                   // memory leak under Bitcoin-level peer churn
}

void CHeadersManager::SetPeerStartHeight(NodeId peer, int height)
{
    std::lock_guard<std::mutex> lock(cs_headers);
    mapPeerStartHeight[peer] = height;
}

int CHeadersManager::GetPeerStartHeight(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    auto it = mapPeerStartHeight.find(peer);
    return (it != mapPeerStartHeight.end()) ? it->second : 0;
}

bool CHeadersManager::ShouldFetchHeaders(NodeId peer) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        return false;
    }

    // Rate limiting: Don't request more than once per 30 seconds
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastUpdate);

    return elapsed.count() >= 30;
}

void CHeadersManager::UpdatePeerState(NodeId peer, const uint256& hash, int height)
{
    // BUG #35 FIX: Do NOT lock here - ProcessHeaders already holds cs_headers
    // Locking again causes deadlock since std::mutex is not recursive
    // NOTE: This function is ONLY called from ProcessHeaders which holds the lock

    auto it = mapPeerStates.find(peer);
    if (it == mapPeerStates.end()) {
        mapPeerStates[peer] = PeerSyncState();
        it = mapPeerStates.find(peer);
    }

    it->second.hashLastHeader = hash;
    it->second.nSyncHeight = height;
    it->second.lastUpdate = std::chrono::steady_clock::now();
    it->second.syncing = true;
}

// ============================================================================
// Public API: Diagnostics
// ============================================================================

size_t CHeadersManager::GetHeaderCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return mapHeaders.size();
}

size_t CHeadersManager::GetMemoryUsage() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Rough estimate: 80 bytes per header + overhead
    return mapHeaders.size() * 128;  // Conservative estimate
}

void CHeadersManager::Clear()
{
    std::lock_guard<std::mutex> lock(cs_headers);

    mapHeaders.clear();
    mapHeightIndex.clear();
    mapPeerStates.clear();
    hashBestHeader = uint256();
    nBestHeight = -1;
    setChainTips.clear();
    m_chainTipsLastSeen.clear();  // Phase 6 PR6.2: keep TTL map in sync with setChainTips
    // PR5.2.B: m_chainTipsTracker retired; setChainTips.clear() above is sufficient.
    InvalidateBestChainCache();

    // Clear rejected hashes on full reset
    m_rejectedHashes.clear();

    // Reset request tracking state (critical for resync after fork)
    m_headers_requested_height.store(0);
    m_last_request_hash = uint256();
}

void CHeadersManager::ClearAboveHeight(int keepHeight, const uint256& preferredHash)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Clearing headers above height " << keepHeight << std::endl;

    // Collect hashes to remove (heights > keepHeight)
    std::vector<uint256> hashesToRemove;
    for (auto it = mapHeightIndex.begin(); it != mapHeightIndex.end(); ) {
        if (it->first > keepHeight) {
            // Add all hashes at this height to removal list
            for (const auto& hash : it->second) {
                hashesToRemove.push_back(hash);
            }
            it = mapHeightIndex.erase(it);
        } else {
            ++it;
        }
    }

    // Remove headers from mapHeaders
    for (const auto& hash : hashesToRemove) {
        mapHeaders.erase(hash);
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Removed " << hashesToRemove.size() << " headers above height " << keepHeight << std::endl;

    // Find the new best header at or below keepHeight
    hashBestHeader = uint256();
    nBestHeight = -1;

    // Look for the header at keepHeight (should be the fork point)
    auto heightIt = mapHeightIndex.find(keepHeight);
    if (heightIt != mapHeightIndex.end() && !heightIt->second.empty()) {
        // BUG #194 FIX: If preferredHash is provided and exists at this height, use it
        // This ensures we select the header matching chainstate, not arbitrary hash order
        if (!preferredHash.IsNull() && heightIt->second.count(preferredHash) > 0) {
            hashBestHeader = preferredHash;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Using preferred hash (chainstate match) at height " << keepHeight << std::endl;
        } else {
            // Fall back to first hash (original behavior)
            hashBestHeader = *heightIt->second.begin();
            if (heightIt->second.size() > 1 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[HeadersManager] WARNING: Multiple headers at height " << keepHeight
                          << ", selecting " << hashBestHeader.GetHex().substr(0, 16) << "... (no preferred hash provided)" << std::endl;
            }
        }
        nBestHeight = keepHeight;
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] New best header at height " << nBestHeight
                      << " hash=" << hashBestHeader.GetHex().substr(0, 16) << "..." << std::endl;
    } else {
        // Fall back to finding the highest header below keepHeight
        for (auto it = mapHeightIndex.rbegin(); it != mapHeightIndex.rend(); ++it) {
            if (it->first <= keepHeight && !it->second.empty()) {
                hashBestHeader = *it->second.begin();
                nBestHeight = it->first;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[HeadersManager] Best header found at height " << nBestHeight << std::endl;
                break;
            }
        }
    }

    // Clear chain tips and rebuild with just the best header
    // PR5.2.B: m_chainTipsTracker retired; setChainTips alone is canonical.
    setChainTips.clear();
    m_chainTipsLastSeen.clear();  // Phase 6 PR6.2: keep TTL map in sync
    if (!hashBestHeader.IsNull()) {
        setChainTips.insert(hashBestHeader);
        const int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        m_chainTipsLastSeen[hashBestHeader] = now_sec;  // Phase 6 PR6.2: stamp the rebuilt tip
    }

    // Invalidate cache
    InvalidateBestChainCache();

    // Reset request tracking to continue from the new best header
    // Note: Do NOT update m_last_header_request_time here - this is initialization, not an active request
    m_headers_requested_height.store(nBestHeight);
    m_last_request_hash = hashBestHeader;

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Headers pruned to height " << nBestHeight
                  << ", mapHeaders.size=" << mapHeaders.size() << std::endl;
}

// ============================================================================
// Bug #150 Fix: Fork Management API
// ============================================================================

bool CHeadersManager::HasCompetingForks() const
{
    // PR5.2.B: setChainTips.size() > 1 ⇔ competing tips exist.
    std::lock_guard<std::mutex> lock(cs_headers);
    return setChainTips.size() > 1;
}

size_t CHeadersManager::GetForkCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return setChainTips.size();
}

std::string CHeadersManager::GetForkDebugInfo() const
{
    // PR5.2.B: format from setChainTips + mapHeaders rather than the
    // retired m_chainTipsTracker. Same data, different source of truth.
    std::lock_guard<std::mutex> lock(cs_headers);
    std::string out = "Tips (" + std::to_string(setChainTips.size()) + "):\n";
    for (const auto& tipHash : setChainTips) {
        auto it = mapHeaders.find(tipHash);
        if (it == mapHeaders.end()) continue;
        out += "  hash=" + tipHash.GetHex().substr(0, 16) + "...";
        out += " height=" + std::to_string(it->second.height);
        out += " work=" + it->second.chainWork.GetHex().substr(0, 16) + "...\n";
    }
    return out;
}

bool CHeadersManager::GetParentHash(const uint256& hash, uint256& parentHash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        return false;
    }

    parentHash = it->second.hashPrevBlock;
    return !parentHash.IsNull();
}

bool CHeadersManager::BuildForkAncestryHashes(const uint256& tipHash, int32_t forkPointHeight,
                                               std::map<int32_t, uint256>& ancestryHashes) const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    ancestryHashes.clear();

    // Walk from tip back to fork point
    uint256 currentHash = tipHash;

    while (!currentHash.IsNull()) {
        auto it = mapHeaders.find(currentHash);
        if (it == mapHeaders.end()) {
            // Hash not found - broken chain
            std::cerr << "[HeadersManager] BuildForkAncestryHashes: hash not found "
                      << currentHash.GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }

        int32_t height = it->second.height;

        // Stop if we've reached or passed the fork point
        if (height <= forkPointHeight) {
            break;
        }

        // Add this hash to the ancestry map
        ancestryHashes[height] = currentHash;

        // Move to parent
        currentHash = it->second.hashPrevBlock;
    }

    if (ancestryHashes.empty()) {
        std::cerr << "[HeadersManager] BuildForkAncestryHashes: no ancestry found "
                  << "(tip=" << tipHash.GetHex().substr(0, 16)
                  << ", forkPoint=" << forkPointHeight << ")" << std::endl;
        return false;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] BuildForkAncestryHashes: built " << ancestryHashes.size()
                  << " hashes from height " << forkPointHeight + 1
                  << " to " << ancestryHashes.rbegin()->first << std::endl;

    return true;
}

size_t CHeadersManager::PruneOrphanedHeaders()
{
    std::lock_guard<std::mutex> lock(cs_headers);

    if (nBestHeight < ORPHAN_HEADER_EXPIRY_BLOCKS) {
        return 0;  // Chain too short for pruning
    }

    // Get the minimum height to keep (best - expiry blocks)
    int minHeightToKeep = nBestHeight - ORPHAN_HEADER_EXPIRY_BLOCKS;

    // Get current best chain work for comparison
    uint256 bestWork;
    if (!hashBestHeader.IsNull()) {
        auto it = mapHeaders.find(hashBestHeader);
        if (it != mapHeaders.end()) {
            bestWork = it->second.chainWork;
        }
    }

    // Build set of hashes on best chain (these are NOT orphans)
    std::set<uint256> onBestChain;
    uint256 current = hashBestHeader;
    while (!current.IsNull()) {
        onBestChain.insert(current);
        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) break;
        current = it->second.hashPrevBlock;
    }

    // Find headers to prune
    std::vector<uint256> toPrune;
    for (const auto& pair : mapHeaders) {
        const uint256& hash = pair.first;
        const HeaderWithChainWork& header = pair.second;

        // Skip if on best chain
        if (onBestChain.count(hash)) {
            continue;
        }

        // Keep chain tips that still have significant work
        // (Simplified: keep tips that are close to best work)
        // PR5.2.B: setChainTips replaces m_chainTipsTracker as canonical leaf set.
        if (setChainTips.count(hash) > 0) {
            // Keep this tip if it has at least some work (non-null)
            // More sophisticated pruning can compare work percentages later
            if (!header.chainWork.IsNull()) {
                continue;
            }
        }

        // Prune if height is below threshold
        if (header.height < minHeightToKeep) {
            toPrune.push_back(hash);
        }
    }

    // Actually remove the orphaned headers
    size_t pruned = 0;
    for (const uint256& hash : toPrune) {
        auto it = mapHeaders.find(hash);
        if (it != mapHeaders.end()) {
            int height = it->second.height;

            // Remove from height index
            RemoveFromHeightIndex(hash, height);

            // Remove from chain tips (if present)
            // PR5.2.B: m_chainTipsTracker retired; setChainTips alone.
            setChainTips.erase(hash);
            m_chainTipsLastSeen.erase(hash);  // Phase 6 PR6.2

            // Remove the header itself
            mapHeaders.erase(it);
            pruned++;
        }
    }

    if (pruned > 0) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Pruned " << pruned << " orphaned headers"
                      << " (below height " << minHeightToKeep << " or <"
                      << ORPHAN_HEADER_MIN_WORK_PERCENT << "% best work)" << std::endl;
        InvalidateBestChainCache();  // Cache may be affected
    }

    // Reset prune counter
    m_headers_since_last_prune = 0;

    return pruned;
}

size_t CHeadersManager::GetOrphanedHeaderCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Build set of hashes on best chain
    std::set<uint256> onBestChain;
    uint256 current = hashBestHeader;
    while (!current.IsNull()) {
        onBestChain.insert(current);
        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) break;
        current = it->second.hashPrevBlock;
    }

    // Count headers not on best chain
    size_t orphaned = 0;
    for (const auto& pair : mapHeaders) {
        if (!onBestChain.count(pair.first)) {
            orphaned++;
        }
    }

    return orphaned;
}

// ============================================================================
// Rejected Hash Tracking (blocks that failed validation)
// ============================================================================

size_t CHeadersManager::InvalidateHeader(const uint256& hash)
{
    std::lock_guard<std::mutex> lock(cs_headers);

    // Already rejected?
    if (m_rejectedHashes.count(hash)) {
        return 0;
    }

    size_t removedCount = 0;

    // Find header
    auto it = mapHeaders.find(hash);
    if (it != mapHeaders.end()) {
        int invalidHeight = it->second.height;
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Invalidating header at height " << invalidHeight
                      << " hash=" << hash.GetHex().substr(0, 16) << "..." << std::endl;

        // Find all descendants (headers whose hashPrevBlock is this hash or any descendant)
        std::vector<uint256> toRemove;
        toRemove.push_back(hash);

        std::set<uint256> removeSet;
        removeSet.insert(hash);

        bool foundMore = true;
        while (foundMore) {
            foundMore = false;
            for (const auto& pair : mapHeaders) {
                if (removeSet.count(pair.first)) continue;
                if (removeSet.count(pair.second.hashPrevBlock)) {
                    removeSet.insert(pair.first);
                    toRemove.push_back(pair.first);
                    foundMore = true;
                }
            }
        }

        // Remove all from mapHeaders and track as rejected
        for (const auto& h : toRemove) {
            auto headerIt = mapHeaders.find(h);
            if (headerIt != mapHeaders.end()) {
                int height = headerIt->second.height;

                // Remove from height index
                auto heightIt = mapHeightIndex.find(height);
                if (heightIt != mapHeightIndex.end()) {
                    heightIt->second.erase(h);
                    if (heightIt->second.empty()) {
                        mapHeightIndex.erase(heightIt);
                    }
                }

                // Remove from chain tips
                // PR5.2.B: m_chainTipsTracker retired; setChainTips alone.
                setChainTips.erase(h);
                m_chainTipsLastSeen.erase(h);  // Phase 6 PR6.2

                // Remove from mapHeaders
                mapHeaders.erase(headerIt);
                removedCount++;
            }

            // Track as rejected
            m_rejectedHashes.insert(h);
            // BUG #275: Evict oldest half when limit exceeded
            if (m_rejectedHashes.size() > MAX_REJECTED_HASHES) {
                auto it = m_rejectedHashes.begin();
                std::advance(it, m_rejectedHashes.size() / 2);
                m_rejectedHashes.erase(m_rejectedHashes.begin(), it);
            }
        }

        // Update best header if needed
        if (removeSet.count(hashBestHeader)) {
            hashBestHeader = uint256();
            nBestHeight = -1;
            uint256 bestWork;

            for (const auto& pair : mapHeaders) {
                if (ChainWorkGreaterThan(pair.second.chainWork, bestWork)) {
                    bestWork = pair.second.chainWork;
                    hashBestHeader = pair.first;
                    nBestHeight = pair.second.height;
                }
            }

            if (!hashBestHeader.IsNull() && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[HeadersManager] Best header updated after invalidation: height="
                          << nBestHeight << " hash=" << hashBestHeader.GetHex().substr(0, 16)
                          << "..." << std::endl;
            }
        }

        InvalidateBestChainCache();

        // PR5.5 (2026-04-26): HeadersManager-side ForkManager retirement.
        //
        // Previously: when a header was invalidated, query ForkManager singleton
        // for an active fork covering this height range and explicitly cancel
        // it (CancelFork + ClearInFlightState) as defensive cleanup.
        //
        // Phase 5 retirement rationale:
        //   * ForkManager is being retired across the codebase (Phase 7
        //     deletes the file). Its remaining 52 call sites are in
        //     ibd_coordinator + block_processing + block_fetcher (Phase 6
        //     scope per plan §12 Q6).
        //   * The 5 HeadersManager-side calls were a defensive cleanup path:
        //     ensure fork state gets cancelled when a header on that fork
        //     gets invalidated. Without these, fork state stays "active" a
        //     bit longer until block-validation downstream detects the
        //     invalidity and clears state itself.
        //   * Net effect of retirement: minor delay in fork-state cleanup
        //     during invalidation. Consensus correctness unaffected — the
        //     block-validation layer is the authority for fork resolution,
        //     not HeadersManager's defensive cleanup.
        //
        // Phase 6 will replace this with index-tree-driven fork detection
        // via chain_selector once HeadersManager is wired to populate
        // CChainState::mapBlockIndex on header receipt.
        // (No-op intentional.)
    } else {
        // Header not in map, just track hash as rejected
        m_rejectedHashes.insert(hash);
        // BUG #275: Evict oldest half when limit exceeded
        if (m_rejectedHashes.size() > MAX_REJECTED_HASHES) {
            auto it = m_rejectedHashes.begin();
            std::advance(it, m_rejectedHashes.size() / 2);
            m_rejectedHashes.erase(m_rejectedHashes.begin(), it);
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Removed " << removedCount
                  << " header(s) (rejected " << m_rejectedHashes.size() << " total)" << std::endl;

    return removedCount;
}

bool CHeadersManager::IsHashRejected(const uint256& hash) const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return m_rejectedHashes.count(hash) > 0;
}

size_t CHeadersManager::GetRejectedHashCount() const
{
    std::lock_guard<std::mutex> lock(cs_headers);
    return m_rejectedHashes.size();
}

void CHeadersManager::ClearRejectedHashes()
{
    std::lock_guard<std::mutex> lock(cs_headers);
    m_rejectedHashes.clear();
}

// ============================================================================
// Note: Orphan header storage was removed (KISS approach)
// Fork handling now uses direct ancestor requests instead of storing orphans.
// See ProcessHeaders() - when parent not found, we request ancestors immediately.
// ============================================================================

// ============================================================================
// Private: Chain Work Calculations
// ============================================================================

uint256 CHeadersManager::CalculateChainWork(const CBlockHeader& header, const HeaderWithChainWork* pprev) const
{
    uint256 blockWork = GetBlockWork(header.nBits);

    if (pprev == nullptr) {
        return blockWork;  // Genesis/first block: chain work = block work
    }

    // Bug #46 Fix: Add parent's accumulated work + this block's work
    return AddChainWork(blockWork, pprev->chainWork);
}

uint256 CHeadersManager::GetBlockWork(uint32_t nBits) const
{
    // Phase 3 Cursor BLOCKER fix (2026-04-26): consolidated through the
    // shared helper `dilithion::consensus::ComputeChainWork`. Previously
    // this method had its own full formula copy — third copy missed
    // during Phase 3 Day 1 Day 1 helper extraction. Drift risk between
    // headers-manager work and block-index work eliminated.
    return dilithion::consensus::ComputeChainWork(nBits);
}

// Bug #47 Fix: Use consensus PoW functions instead of custom implementation
// The custom GetTarget() had incorrect byte ordering due to memcpy usage
bool CHeadersManager::CheckProofOfWork(const uint256& hash, uint32_t nBits) const
{
    // Use the consensus CheckProofOfWork which:
    // 1. Validates nBits range (MIN_DIFFICULTY_BITS to MAX_DIFFICULTY_BITS)
    // 2. Uses CompactToBig() for correct target expansion
    // 3. Performs proper big-endian comparison
    return ::CheckProofOfWork(hash, nBits);
}

bool CHeadersManager::CheckTimestamp(const CBlockHeader& header, const HeaderWithChainWork* pprev, int headerHeight) const
{
    // 1. Check not too far in future
    // Fork-aware: 600s post-fork (timestampValidationHeight), 7200s pre-fork
    // CID 1675246 FIX: Safe 64-to-32 bit time conversion (valid until 2106)
    uint32_t now = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);
    int tsValHeight = (Dilithion::g_chainParams)
        ? Dilithion::g_chainParams->timestampValidationHeight : 999999999;
    uint32_t maxFuture = (headerHeight >= 0 && headerHeight >= tsValHeight)
        ? static_cast<uint32_t>(Consensus::MAX_FUTURE_BLOCK_TIME_V2)   // 600s post-fork
        : MAX_HEADERS_AGE_SECONDS;                                      // 7200s pre-fork
    if (header.nTime > now + maxFuture) {
        return false;
    }

    // 2. Check greater than median of last 11 blocks
    if (pprev != nullptr) {
        uint32_t medianPast = GetMedianTimePast(pprev, MEDIAN_TIME_SPAN);
        if (header.nTime <= medianPast) {
            return false;
        }
    }

    return true;
}

uint32_t CHeadersManager::GetMedianTimePast(const HeaderWithChainWork* pprev, int span) const
{
    std::vector<uint32_t> times;

    const HeaderWithChainWork* pindex = pprev;
    for (int i = 0; i < span && pindex != nullptr; i++) {
        times.push_back(pindex->header.nTime);

        // Get parent
        uint256 parentHash = pindex->header.hashPrevBlock;
        auto it = mapHeaders.find(parentHash);
        if (it == mapHeaders.end()) {
            break;
        }
        pindex = &it->second;
    }

    if (times.empty()) {
        return 0;
    }

    // Sort and return median
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

bool CHeadersManager::UpdateBestHeader(const uint256& hash)
{
    auto it = mapHeaders.find(hash);
    if (it == mapHeaders.end()) {
        static int notfound_count = 0;
        if (notfound_count++ < 5 && g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[UpdateBestHeader] Header not found: " << hash.GetHex().substr(0, 16) << "..." << std::endl;
        }
        return false;
    }

    int newHeight = it->second.height;

    // Bug #46 Fix: Compare cumulative work, not height!
    // This is critical for chain reorganization

    // Check if this header has more work than current best
    if (hashBestHeader.IsNull()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[UpdateBestHeader] First header: height=" << newHeight << std::endl;
        hashBestHeader = hash;
        nBestHeight = newHeight;
        return true;
    }

    auto bestIt = mapHeaders.find(hashBestHeader);
    if (bestIt == mapHeaders.end()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[UpdateBestHeader] Best header missing, updating: height=" << newHeight << std::endl;
        hashBestHeader = hash;
        nBestHeight = newHeight;
        return true;
    }

    // Bug #46 Fix: Use ChainWorkGreaterThan() for proper cumulative work comparison
    // This enables reorganization to chains with more work but fewer blocks
    bool hasMoreWork = ChainWorkGreaterThan(it->second.chainWork, bestIt->second.chainWork);

    // Log chain work comparison only when relevant (competitive heights or verbose mode)
    // Suppress log noise from obviously-stale headers (e.g. height 25 vs 3600)
    bool isCompetitive = hasMoreWork || (newHeight > 0 && nBestHeight > 0 &&
                          (nBestHeight - newHeight) < 200);
    if (isCompetitive || g_verbose.load(std::memory_order_relaxed)) {
        std::string newWorkHex = it->second.chainWork.GetHex();
        std::string bestWorkHex = bestIt->second.chainWork.GetHex();
        std::cout << "[UpdateBestHeader] Comparing heights: " << nBestHeight << " vs " << newHeight
                  << " bestWork=" << bestWorkHex.substr(bestWorkHex.length() > 16 ? bestWorkHex.length() - 16 : 0)
                  << " newWork=" << newWorkHex.substr(newWorkHex.length() > 16 ? newWorkHex.length() - 16 : 0)
                  << " hasMoreWork=" << (hasMoreWork ? "YES" : "NO") << std::endl;
    }

    // FALLBACK: If both chainWork values are zero (IBD below checkpoint), use height comparison
    // This ensures proper header chain progression during initial sync
    if (!hasMoreWork && it->second.chainWork.IsNull() && bestIt->second.chainWork.IsNull()) {
        hasMoreWork = (newHeight > nBestHeight);
    }

    // Log updates and periodic comparisons (show LSB of chainWork)
    static int compare_count = 0;
    if (g_verbose.load(std::memory_order_relaxed)) {
        if (hasMoreWork) {
            std::cout << "[UpdateBestHeader] UPDATING: " << nBestHeight << " -> " << newHeight << std::endl;
        } else if (compare_count++ % 1000 == 0) {
            std::string bestHex = bestIt->second.chainWork.GetHex();
            std::string forkHex = it->second.chainWork.GetHex();
            std::cout << "[UpdateBestHeader] Comparing: height=" << nBestHeight << " vs fork=" << newHeight
                      << " bestWork(LSB)=" << bestHex.substr(bestHex.length() > 16 ? bestHex.length() - 16 : 0)
                      << " forkWork(LSB)=" << forkHex.substr(forkHex.length() > 16 ? forkHex.length() - 16 : 0) << std::endl;
        }
    }

    if (hasMoreWork) {
        hashBestHeader = hash;
        nBestHeight = newHeight;
        InvalidateBestChainCache();  // Bug #150: Cache is stale after chain tip change
        return true;
    }

    return false;
}

// ============================================================================
// Bug #150 Fix: Fork-Safe Height Lookup
// ============================================================================

void CHeadersManager::InvalidateBestChainCache()
{
    // Already holding cs_headers (called from UpdateBestHeader)
    m_bestChainCacheDirty = true;
    m_bestChainCache.clear();
}

uint256 CHeadersManager::GetBestChainHashAtHeight(int height) const
{
    // Already holding cs_headers (called from GetRandomXHashAtHeight/GetLocator)

    if (hashBestHeader.IsNull() || height < 0 || height > nBestHeight) {
        return uint256();
    }

    // Check cache first
    if (!m_bestChainCacheDirty) {
        auto cacheIt = m_bestChainCache.find(height);
        if (cacheIt != m_bestChainCache.end()) {
            return cacheIt->second;
        }
    }

    // Walk backward from best header to find block at target height
    // This ensures we follow the BEST-WORK chain, not arbitrary fork members
    uint256 current = hashBestHeader;
    int currentHeight = nBestHeight;

    // DEBUG: Detect infinite loops
    int loopCount = 0;
    const int MAX_LOOP = nBestHeight + 10;  // Should never exceed this

    // Build cache as we walk (we'll likely need nearby heights too)
    while (!current.IsNull() && currentHeight >= 0) {
        loopCount++;
        if (loopCount > MAX_LOOP) {
            std::cerr << "[GetBestChainHashAtHeight] INFINITE LOOP DETECTED at height " << currentHeight
                      << " after " << loopCount << " iterations!" << std::endl;
            break;
        }

        auto it = mapHeaders.find(current);
        if (it == mapHeaders.end()) {
            // v4.0.22 — Chain walk broken (parent hash not in mapHeaders).
            //
            // BUG #282 originally added a mapHeightIndex fallback here to "fix"
            // tight request loops. That fallback violates chain coherence: it
            // returns the highest-work header AT THIS HEIGHT, which may belong
            // to a DIFFERENT branch than the heights adjacent to it. The IBD
            // scheduler then assembles mixed-fork GETDATA batches, blocks from
            // different forks get applied to the same UTXO set, and we hit
            // "Input references non-existent UTXO" errors mid-IBD (fresh nodes)
            // or unable-to-reorg deadlock (existing nodes — incident 2026-04-25).
            //
            // Correct behaviour: return null. Caller (ibd_coordinator) MUST treat
            // null as "header chain incomplete here" and stop building the batch
            // at this height — never substitute a same-height header from a
            // different branch.
            static int chainBreakLogCount = 0;
            if (chainBreakLogCount < 10) {
                chainBreakLogCount++;
                std::cerr << "[GetBestChainHashAtHeight] CHAIN BREAK at height " << currentHeight
                          << " (target " << height << ") -- returning null. "
                          << "Caller should pause IBD here and trigger header recovery." << std::endl;
            }
            return uint256();
        }

        // BUG FIX: Return RandomX hash, not SHA256 hash
        // The mapHeaders key is SHA256, but peers use RandomX hashes for locators
        uint256 randomXHash = it->second.randomXHash;
        if (randomXHash.IsNull()) {
            // Fallback: If no RandomX hash, use the storage hash
            // This happens for headers below checkpoint where RandomX wasn't computed
            randomXHash = current;
        }

        // Cache this height (with RandomX hash for peer communication)
        m_bestChainCache[currentHeight] = randomXHash;

        if (currentHeight == height) {
            m_bestChainCacheDirty = false;  // Cache is now valid
            return randomXHash;
        }

        if (currentHeight < height) {
            // Overshot - should not happen if height <= nBestHeight
            break;
        }

        // Move to parent
        current = it->second.hashPrevBlock;
        currentHeight--;
    }

    // Fully populated cache from best header to genesis
    m_bestChainCacheDirty = false;

    // v4.0.22 — Height not found on the best-header-chain ancestry path.
    // BUG #282's mapHeightIndex fallback is removed for the same reason as
    // the in-walk fallback above (chain coherence). If the best-header chain
    // doesn't have a header at this height on its actual ancestry, the
    // caller MUST NOT request some other branch's header at this height --
    // doing so would assemble a mixed-fork GETDATA batch (incident
    // 2026-04-25). Return null so the caller pauses block fetching here.
    return uint256();
}

void CHeadersManager::AddToHeightIndex(const uint256& hash, int height)
{
    mapHeightIndex[height].insert(hash);

    // Log when multiple headers exist at same height
    if (mapHeightIndex[height].size() > 1 && g_verbose.load(std::memory_order_relaxed)) {
        size_t count = mapHeightIndex[height].size();
        if (Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV()) {
            // DilV: competing VDF blocks at same height is normal — all miners produce one
            std::cout << "[HeadersManager] VDF competition at height " << height
                      << " - " << count << " competing blocks. Determining lowest hash." << std::endl;
        } else {
            // DIL (PoW): multiple headers at same height is an actual fork
            std::cout << "[HeadersManager] FORK DETECTED at height " << height
                      << " - " << count << " competing headers" << std::endl;
        }
    }
}

void CHeadersManager::RemoveFromHeightIndex(const uint256& hash, int height)
{
    auto it = mapHeightIndex.find(height);
    if (it != mapHeightIndex.end()) {
        it->second.erase(hash);
        if (it->second.empty()) {
            mapHeightIndex.erase(it);
        }
    }
}

// ============================================================================
// Bug #46 Fix: Chain Reorganization Support
// ============================================================================

void CHeadersManager::UpdateChainTips(const uint256& hashNew)
{
    // Add the new header as a chain tip (legacy set)
    setChainTips.insert(hashNew);

    // Phase 6 PR6.2: stamp last-seen for TTL aging.
    const int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_chainTipsLastSeen[hashNew] = now_sec;

    // Remove its parent from chain tips (no longer a leaf)
    // PR5.2.B: m_chainTipsTracker retired; setChainTips alone is canonical.
    auto it = mapHeaders.find(hashNew);
    if (it != mapHeaders.end()) {
        const HeaderWithChainWork& header = it->second;
        if (!header.hashPrevBlock.IsNull()) {
            setChainTips.erase(header.hashPrevBlock);
            m_chainTipsLastSeen.erase(header.hashPrevBlock);
        }
    }

    // Phase 6 PR6.2: TTL aging — evict tips not re-seen within
    // 30 blocks worth of time (KISS: derived from chainparams.blockTime,
    // no new config required). DIL (240s blocks) → 7200s = 2 hours;
    // DilV (60s blocks) → 1800s = 30 minutes. Per-peer admission
    // limit DEFERRED to Phase 6.x (needs canonical peer-attribution
    // source — see v1.5 plan §3.3). Runs BEFORE the cap eviction
    // below: if TTL drops the count under the cap, no further
    // eviction needed.
    if (Dilithion::g_chainParams) {
        const int blockTime = Dilithion::g_chainParams->blockTime;
        const int64_t ttl_sec = static_cast<int64_t>(blockTime) * 30;
        const int64_t cutoff = now_sec - ttl_sec;
        // Don't evict the just-inserted tip; only stale ones.
        for (auto lsit = m_chainTipsLastSeen.begin();
             lsit != m_chainTipsLastSeen.end(); ) {
            if (lsit->first == hashNew) { ++lsit; continue; }
            if (lsit->second < cutoff) {
                setChainTips.erase(lsit->first);
                lsit = m_chainTipsLastSeen.erase(lsit);
            } else {
                ++lsit;
            }
        }
    }

    // CONCERN #2 fix (red-team audit 2026-04-26): bound setChainTips
    // size with eviction-by-lowest-work. Without this cap, an attacker
    // who feeds disjoint forks can grow setChainTips monotonically;
    // each ibd_coordinator tick then walks O(K) entries. At K >> 1000
    // this becomes a DoS amplifier.
    //
    // 256 is a balance: well above realistic tip-counts during normal
    // operation (typically 1-2; rare bursts to ~10 during fork events)
    // but well below pathological growth. When the cap is exceeded,
    // evict the LOWEST-work tip — these are the least useful for any
    // future reorg consideration.
    //
    // Validation pass 2026-04-26: tiebreaker concern — when multiple
    // tips share the same chainWork, an attacker who grinds nonces can
    // control which uint256 hash sorts lowest in std::set iteration.
    // Mitigation: NEVER evict any tip whose chainWork equals the best
    // chainWork — protect honest tips against same-work attackers.
    static constexpr size_t MAX_CHAIN_TIPS = 256;
    if (setChainTips.size() > MAX_CHAIN_TIPS) {
        // First pass: compute best chainWork (we MUST NOT evict any
        // tip at this work level).
        uint256 bestWork;
        for (const auto& tipHash : setChainTips) {
            auto tipIt = mapHeaders.find(tipHash);
            if (tipIt == mapHeaders.end()) continue;
            if (bestWork.IsNull() || ChainWorkGreaterThan(tipIt->second.chainWork, bestWork)) {
                bestWork = tipIt->second.chainWork;
            }
        }

        // Second pass: collect orphans (purge ALL of them, not just first)
        // and find lowest-strictly-below-best work.
        std::vector<uint256> orphans;
        uint256 worstHash;
        uint256 worstWork;
        bool worstSet = false;
        for (const auto& tipHash : setChainTips) {
            if (std::memcmp(tipHash.data, hashNew.data, 32) == 0) continue;
            auto tipIt = mapHeaders.find(tipHash);
            if (tipIt == mapHeaders.end()) {
                orphans.push_back(tipHash);
                continue;
            }
            // Skip tips whose work equals best — attacker-influenceable
            // tiebreaker would otherwise let them target honest tips.
            if (!ChainWorkGreaterThan(bestWork, tipIt->second.chainWork)) {
                continue;
            }
            if (!worstSet || ChainWorkGreaterThan(worstWork, tipIt->second.chainWork)) {
                worstHash = tipHash;
                worstWork = tipIt->second.chainWork;
                worstSet = true;
            }
        }

        // Sweep orphans first (free cleanup, lowest-priority entries).
        for (const auto& o : orphans) {
            setChainTips.erase(o);
            m_chainTipsLastSeen.erase(o);  // Phase 6 PR6.2: keep timestamp map in sync
        }
        // If still over cap and we found a strictly-below-best target, evict it.
        if (setChainTips.size() > MAX_CHAIN_TIPS && worstSet) {
            setChainTips.erase(worstHash);
            m_chainTipsLastSeen.erase(worstHash);  // Phase 6 PR6.2: keep timestamp map in sync
        }
        // Edge case: if EVERY non-just-inserted tip is at best chainWork
        // (extreme stress under nonce-grinding attack), no eviction
        // happens — set grows above cap until honest activity introduces
        // a new best. Prefer this over evicting honest tips.
    }
}

uint256 CHeadersManager::AddChainWork(const uint256& blockProof, const uint256& parentChainWork) const
{
    // Phase 3 Cursor BLOCKER fix (2026-04-26): consolidated through the
    // shared helper. Sum is commutative; argument-order is irrelevant.
    return dilithion::consensus::AddChainWork(blockProof, parentChainWork);
}

// ============================================================================
// BUG #125: Async Header Validation
// ============================================================================

bool CHeadersManager::QuickValidateHeader(const CBlockHeader& header, const CBlockHeader* pprev, int headerHeight) const
{
    // Quick structural validation - NO RandomX PoW check
    // This runs in <1ms per header

    // 1. Check version (should be > 0)
    if (header.nVersion <= 0) {
        std::cerr << "[HeadersManager] Quick validate FAILED: version <= 0" << std::endl;
        return false;
    }

    // 2. Check bits are set (non-zero difficulty)
    if (header.nBits == 0) {
        std::cerr << "[HeadersManager] Quick validate FAILED: nBits == 0" << std::endl;
        return false;
    }

    // 3. If we have a parent, check timestamp validity
    if (pprev != nullptr) {
        // Fork-aware: 600s post-fork (timestampValidationHeight), 7200s pre-fork
        uint32_t now = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);
        int tsValHeight = (Dilithion::g_chainParams)
            ? Dilithion::g_chainParams->timestampValidationHeight : 999999999;
        uint32_t maxFuture = (headerHeight >= 0 && headerHeight >= tsValHeight)
            ? static_cast<uint32_t>(Consensus::MAX_FUTURE_BLOCK_TIME_V2)   // 600s post-fork
            : MAX_HEADERS_AGE_SECONDS;                                      // 7200s pre-fork
        if (header.nTime > now + maxFuture) {
            std::cerr << "[HeadersManager] Quick validate FAILED: timestamp too far in future"
                      << " (limit: " << maxFuture << "s)" << std::endl;
            return false;
        }
    }

    // Structure is valid - PoW will be validated async
    return true;
}

bool CHeadersManager::FullValidateHeader(const CBlockHeader& header, int height)
{
    // CHECKPOINT OPTIMIZATION: Skip expensive PoW validation for headers at/before
    // the highest checkpoint. These headers are trusted by the hardcoded checkpoint.
    // This dramatically speeds up IBD (~100ms -> <1ms per header for checkpointed blocks).

    if (Dilithion::g_chainParams) {
        int highestCheckpoint = Dilithion::g_chainParams->GetHighestCheckpointHeight();
        if (highestCheckpoint >= 0 && height <= highestCheckpoint) {
            // PoW validation skipped - block is at/before checkpoint
            return true;
        }
    }

    // VDF blocks (version >= 4) use SHA3-256, not RandomX PoW.
    // Their proof is validated during full block validation (CheckVDFProof).
    // Here we just check they're above VDF activation height.
    if (header.IsVDFBlock()) {
        if (Dilithion::g_chainParams && height >= Dilithion::g_chainParams->vdfActivationHeight) {
            return true;  // VDF proof checked during block validation
        }
        return false;  // VDF block before activation height
    }

    // Full PoW validation - this is the expensive operation (50-250ms)
    uint256 hash = header.GetHash();
    return CheckProofOfWork(hash, header.nBits);
}

bool CHeadersManager::QueueHeadersForValidation(NodeId peer, const std::vector<CBlockHeader>& headers)
{
    // Phase 6 PR6.1: per-peer rate limit. Same policy as ProcessHeaders.
    // v4.1: added log message — previously silent return false here hid the
    // cause when the limit was set too low (1000 vs MAX_HEADERS_RESULTS=2000),
    // making IBD failures untraceable. Always log the rate-limit reject.
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        if (!headers.empty() && !CheckPeerHeaderRateLimit(peer, headers.size())) {
            LogPrintf(NET, WARN,
                "[HeadersManager] Rate-limit reject (Queue): peer=%d batch=%zu "
                "(window limit = %d/%ds)\n",
                static_cast<int>(peer),
                headers.size(),
                Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateLimitPerWindow : 5000,
                Dilithion::g_chainParams ? Dilithion::g_chainParams->nHeaderRateWindowSec : 60);
            return false;
        }
    }

    if (!m_validation_running.load()) {
        std::cerr << "[HeadersManager] Validation thread not running, falling back to sync" << std::endl;
        return ProcessHeaders(peer, headers);
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Queueing " << headers.size()
                  << " headers for async validation from peer " << peer << std::endl;

    if (headers.empty()) {
        return true;
    }

    if (headers.size() > MAX_HEADERS_BUFFER) {
        std::cerr << "[HeadersManager] Too many headers (" << headers.size() << ")" << std::endl;
        return false;
    }

    // =========================================================================
    // PROGRESSIVE HEADER PROCESSING (Compute & Store Immediately)
    // =========================================================================
    // Problem: Batch processing waits for ALL hashes before storing ANY headers.
    // This means blocks can't download new headers until entire batch is done.
    //
    // Solution: Process headers progressively in small batches.
    // - Compute hash for batch of N headers (lock-free)
    // - Store batch immediately (brief lock)
    // - Repeat until all headers processed
    //
    // This allows block downloading to start as soon as first headers are stored,
    // rather than waiting for all 2000 hashes to complete.
    // =========================================================================

    const size_t BATCH_SIZE = 100;  // Process 100 headers at a time
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;

    // Get initial parent info (brief lock)
    uint256 prevHash;
    int startHeight = 1;
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        uint256 genesisHash = Genesis::GetGenesisHash();

        if (headers[0].hashPrevBlock == genesisHash || headers[0].hashPrevBlock.IsNull()) {
            startHeight = 1;

            // BUG #178 FIX: REMOVED early "duplicate batch" optimization
            //
            // Old buggy code assumed any headers starting from genesis are duplicates
            // if we already have headers at height 1. This is WRONG because:
            //
            // 1. A competing fork ALSO starts from genesis
            // 2. Both forks may share headers 1-N, then diverge at height N+1
            // 3. Comparing only height 1 cannot detect forks at higher heights
            //
            // Example: London stuck at 5569, NYC at 5660 on different fork
            // - Both share headers 1-5568 (same hashes)
            // - Diverged at height 5569 (different hashes)
            // - NYC sends headers from genesis (London's locator unknown)
            // - Old code: "We have height 1, skip!" → London stays stuck
            // - Fixed code: Process all headers, per-header logic detects fork at 5569
            //
            // The per-header logic at lines ~1609-1623 correctly handles:
            // - True duplicates (same hash): continue, update pprev
            // - Fork headers (different hash at same height): detect and track
            //
            // Cost: ~50ms to compute 2000 hashes in parallel (acceptable)
            // Benefit: Fork safety - nodes can always sync to best chain
            if (nBestHeight > 0 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[HeadersManager] Headers start from genesis, nBestHeight="
                          << nBestHeight << " - processing to check for forks" << std::endl;
            }

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Parent is genesis, startHeight=1" << std::endl;
        } else {
            // DEBUG: Log the parent lookup attempt
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Looking up parent: " << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                          << "... mapHeaders.size=" << mapHeaders.size() << std::endl;

            auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
            if (parentIt != mapHeaders.end()) {
                startHeight = parentIt->second.height + 1;
                prevHash = headers[0].hashPrevBlock;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[HeadersManager] Parent found at height " << parentIt->second.height
                              << ", startHeight=" << startHeight << std::endl;

                // BUG FIX: Skip stale fork header batches below last checkpoint
                // Headers below checkpoints are guaranteed by checkpoint validation.
                // Processing them wastes time on expensive RandomX hash computation.
                int lastCheckpointHeight = Dilithion::g_chainParams ?
                    Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;
                int chainstateHeight = g_chainstate.GetHeight();
                if (lastCheckpointHeight > 0 && startHeight < lastCheckpointHeight &&
                    chainstateHeight >= lastCheckpointHeight) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[HeadersManager] Skipping stale fork header batch starting at height "
                                  << startHeight << " (below checkpoint " << lastCheckpointHeight << ")" << std::endl;
                    return true;  // Not an error, just nothing useful to process
                }
            } else {
                std::cerr << "[HeadersManager] ORPHAN: Parent " << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                          << " not found (best=" << nBestHeight << ")" << std::endl;
                return false;
            }
        }
    }

    auto total_start = std::chrono::steady_clock::now();
    size_t totalProcessed = 0;

    // =========================================================================
    // COMMON ANCESTOR OPTIMIZATION (Bug #180)
    // =========================================================================
    // If all headers in this batch are below our current best height AND we can
    // verify a sample matches, skip the expensive hash computation entirely.
    // This dramatically speeds up fork chain sync through shared history.
    int endHeight = startHeight + static_cast<int>(headers.size()) - 1;
    bool skipHashComputation = false;

    // CHECK ALL HEADERS for duplicate detection
    // =========================================================================
    // If all headers in this batch are below our current best height AND all
    // headers' hashPrevBlock match our stored hashes, skip hash computation.
    // This is O(n) map lookups (microseconds) vs O(n) hash computations (100+ seconds).
    // =========================================================================

    // Track the stored hash at endHeight for FAST PATH m_last_request_hash update
    uint256 storedHashAtEndHeight;

    if (endHeight <= nBestHeight && startHeight > 0) {
        std::lock_guard<std::mutex> lock(cs_headers);
        bool allMatch = true;

        for (size_t i = 0; i < headers.size(); ++i) {
            int height = startHeight + static_cast<int>(i);
            int prevHeight = height - 1;

            // Every header's hashPrevBlock must match our stored hash at prevHeight
            auto prevHeightIt = mapHeightIndex.find(prevHeight);
            if (prevHeightIt == mapHeightIndex.end() || prevHeightIt->second.empty()) {
                allMatch = false;
                break;
            }

            uint256 storedPrevHash = *prevHeightIt->second.begin();
            if (headers[i].hashPrevBlock != storedPrevHash) {
                allMatch = false;
                break;
            }

            // BUG FIX #182: Also verify the header at THIS height matches the incoming header
            // Two different blocks can have the same parent (fork scenario), so we must
            // verify the actual header content matches, not just the parent hash.
            auto heightIt = mapHeightIndex.find(height);
            if (heightIt == mapHeightIndex.end() || heightIt->second.empty()) {
                // No header stored at this height - cannot skip
                allMatch = false;
                break;
            }

            uint256 storedHashAtHeight = *heightIt->second.begin();
            auto storedIt = mapHeaders.find(storedHashAtHeight);
            if (storedIt == mapHeaders.end()) {
                allMatch = false;
                break;
            }

            // Compare ALL header fields to confirm it's truly the same header
            const CBlockHeader& stored = storedIt->second.header;
            if (headers[i].nVersion != stored.nVersion ||
                headers[i].hashPrevBlock != stored.hashPrevBlock ||
                headers[i].hashMerkleRoot != stored.hashMerkleRoot ||
                headers[i].nTime != stored.nTime ||
                headers[i].nBits != stored.nBits ||
                headers[i].nNonce != stored.nNonce) {
                // Header fields differ - this is a FORK, cannot skip
                allMatch = false;
                break;
            }

            // Track the last (endHeight) stored hash for FAST PATH
            storedHashAtEndHeight = storedHashAtHeight;
        }

        if (allMatch) {
            skipHashComputation = true;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] OPTIMIZATION: Skipping hash computation for heights "
                          << startHeight << "-" << endHeight << " (shared history)" << std::endl;
        }
    }

    // FAST PATH: If all headers are shared history, return immediately
    // Do this BEFORE allocating allHashes to avoid unnecessary memory allocation
    if (skipHashComputation) {
        // BUG FIX #183: Update m_last_request_hash with our STORED hash at endHeight
        // This ensures the next GETHEADERS uses a hash we KNOW exists in our chain,
        // rather than the hash computed from incoming headers (which may differ).
        {
            std::lock_guard<std::mutex> lock(cs_headers);
            m_last_request_hash = storedHashAtEndHeight;
            m_last_header_request_time = std::chrono::steady_clock::now();
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] FAST PATH: Updated m_last_request_hash to stored hash at height "
                          << endHeight << " (" << storedHashAtEndHeight.GetHex().substr(0, 16) << "...)" << std::endl;
        }
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] FAST PATH: Skipped " << headers.size()
                      << " shared history headers (already stored)" << std::endl;

        // BUG FIX #183 Part 2: Request more headers NOW with the updated m_last_request_hash
        // The previous GETHEADERS was sent before this update, so we need to send another.
        // BUG FIX: Use dynamic best_known_height instead of static start_height.
        int peer_height = GetPeerStartHeight(peer);
        if (g_node_context.peer_manager) {
            auto p = g_node_context.peer_manager->GetPeer(peer);
            if (p && p->best_known_height > peer_height) {
                peer_height = p->best_known_height;
            }
        }
        if (peer_height > 0 && endHeight < peer_height) {
            SyncHeadersFromPeer(peer, peer_height, true);  // force=true to bypass dedup
        }

        return true;
    }

    // =========================================================================
    // STEP 1: Compute ALL hashes in PARALLEL using N worker threads
    // =========================================================================
    // Use fixed number of threads (= CPU cores) to avoid thread creation overhead.
    // Each thread processes a chunk of headers, reusing its thread-local RandomX VM.
    // This is MUCH faster than spawning 100 threads per batch.

    const size_t numWorkers = std::min(size_t(8), headers.size());  // Cap at 8 workers
    const size_t chunkSize = (headers.size() + numWorkers - 1) / numWorkers;

    std::vector<uint256> allHashes(headers.size());
    std::vector<std::future<void>> workers;
    workers.reserve(numWorkers);

    auto hash_start = std::chrono::steady_clock::now();

    for (size_t w = 0; w < numWorkers; ++w) {
        size_t start = w * chunkSize;
        size_t end = std::min(start + chunkSize, headers.size());
        if (start >= end) break;

        workers.push_back(std::async(std::launch::async, [&headers, &allHashes, start, end]() {
            // Each worker processes its chunk sequentially, reusing thread-local RandomX VM
            for (size_t i = start; i < end; ++i) {
                allHashes[i] = headers[i].GetHash();
            }
        }));
    }

    // Wait for all workers to complete
    for (auto& worker : workers) {
        worker.get();
    }

    auto hash_end = std::chrono::steady_clock::now();
    auto hash_ms = std::chrono::duration_cast<std::chrono::milliseconds>(hash_end - hash_start).count();

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[HeadersManager] Parallel hash computation: " << headers.size()
                  << " headers, " << numWorkers << " workers, " << hash_ms << "ms" << std::endl;
    }

    // =========================================================================
    // STEP 2: Store ALL headers progressively in batches (for block download)
    // =========================================================================
    // Even though hashes are already computed, we store in batches to release
    // cs_headers lock periodically, allowing block processing to proceed.

    size_t prevTotalProcessed = 0;  // For incremental processed count updates
    for (size_t batchStart = 0; batchStart < headers.size(); batchStart += BATCH_SIZE) {
        size_t batchEnd = std::min(batchStart + BATCH_SIZE, headers.size());
        size_t batchSize = batchEnd - batchStart;

        // STEP 2: Store this batch (brief lock)
        {
            std::lock_guard<std::mutex> lock(cs_headers);

            const HeaderWithChainWork* pprev = nullptr;

            // Find parent for first header in batch
            if (batchStart == 0) {
                uint256 genesisHash = Genesis::GetGenesisHash();
                if (headers[0].hashPrevBlock == genesisHash || headers[0].hashPrevBlock.IsNull()) {
                    // BUG FIX: Look up genesis in mapHeaders to get cumulative chain work
                    // Previously left pprev=nullptr, causing chainWork to not accumulate
                    auto genesisIt = mapHeaders.find(genesisHash);
                    if (genesisIt != mapHeaders.end()) {
                        pprev = &genesisIt->second;
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[HeadersManager] Batch 0: Genesis found, chainWork="
                                      << pprev->chainWork.GetHex().substr(pprev->chainWork.GetHex().length() > 16 ? pprev->chainWork.GetHex().length() - 16 : 0)
                                      << std::endl;
                    } else {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[HeadersManager] Batch 0: Genesis not in mapHeaders, pprev=NULL" << std::endl;
                    }
                } else {
                    auto parentIt = mapHeaders.find(headers[0].hashPrevBlock);
                    if (parentIt != mapHeaders.end()) {
                        pprev = &parentIt->second;
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[HeadersManager] Batch 0: Parent found at height " << pprev->height << std::endl;
                    } else {
                        // BUG: This should have been caught by the initial lookup!
                        std::cerr << "[HeadersManager] BUG: Batch 0 parent lookup failed but initial lookup succeeded!" << std::endl;
                        std::cerr << "[HeadersManager] BUG: hashPrevBlock=" << headers[0].hashPrevBlock.GetHex().substr(0, 16)
                                  << " mapHeaders.size=" << mapHeaders.size() << std::endl;
                        // Don't return false here - we already validated in initial lookup
                        // This might indicate a race condition
                    }
                }
            } else if (!prevHash.IsNull()) {
                auto parentIt = mapHeaders.find(prevHash);
                if (parentIt != mapHeaders.end()) {
                    pprev = &parentIt->second;
                } else {
                    std::cerr << "[HeadersManager] BUG: Subsequent batch parent lookup failed!" << std::endl;
                    std::cerr << "[HeadersManager] BUG: prevHash=" << prevHash.GetHex().substr(0, 16)
                              << " mapHeaders.size=" << mapHeaders.size() << std::endl;
                }
            }

            for (size_t i = 0; i < batchSize; ++i) {
                const CBlockHeader& header = headers[batchStart + i];
                int expectedHeight = startHeight + batchStart + i;

                // Check if height exists
                auto heightIt = mapHeightIndex.find(expectedHeight);
                bool heightHasHeaders = (heightIt != mapHeightIndex.end() && !heightIt->second.empty());

                // Patch H (v4.0.22) -- Same silent-drop bug as ProcessHeaders
                // FAST PATH 1. PRIOR BUG: when below checkpoint and we already
                // had ANY header at this height, code picked
                // *heightIt->second.begin() (first-arrived sibling) and dropped
                // the incoming header without comparing hashes. Competing
                // siblings were never stored, so chain selection could not
                // reorg from a wrong-fork sibling to the canonical sibling.
                // Fix: use the actual incoming hash for true-duplicate check;
                // store competing siblings so UpdateBestHeader can compare
                // cumulative chain work and pick the canonical chain.
                uint256 storageHash = allHashes[batchStart + i];

                if (expectedHeight <= checkpointHeight) {
                    auto existingIt = mapHeaders.find(storageHash);
                    if (existingIt != mapHeaders.end()) {
                        // True duplicate (same hash) -- advance pprev and skip.
                        UpdateBestHeader(storageHash);
                        pprev = &existingIt->second;
                        prevHash = storageHash;
                        continue;
                    }
                    // New header at this height (empty slot or competing sibling).
                    // Store with cumulative chain work but skip PoW validation
                    // (below checkpoint, trust anchor handles validity).
                    int height = pprev ? (pprev->height + 1) : expectedHeight;
                    // v4.1 site 4/5: header-time checkpoint enforcement (BEFORE store)
                    if (!CheckpointCheckHeader(height, storageHash)) {
                        if (g_node_context.peer_manager) {
                            g_node_context.peer_manager->Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
                        }
                        return false;
                    }
                    uint256 chainWork = CalculateChainWork(header, pprev);
                    HeaderWithChainWork headerData(header, height);
                    headerData.chainWork = chainWork;
                    mapHeaders[storageHash] = headerData;
                    AddToHeightIndex(storageHash, height);
                    UpdateChainTips(storageHash);   // register competing tip
                    UpdateBestHeader(storageHash);  // re-evaluate active chain

                    // Phase 6 PR6.1 (v1.5 fix-up 2026-04-27 per dual-validation):
                    // chain_selector wiring on the QueueHeadersForValidation
                    // below-checkpoint async path. Both reviewers (Cursor +
                    // subagent) flagged the original overnight diff missed
                    // these mapHeaders writes — this is the busiest path
                    // during IBD.
                    if (g_node_context.chain_selector) {
                        (void)g_node_context.chain_selector->ProcessNewHeader(header);
                    }

                    pprev = &mapHeaders[storageHash];
                    prevHash = storageHash;
                    totalProcessed++;
                    continue;  // Skip PoW validation but header is now stored
                }


                // Skip TRUE duplicates (same hash already exists)
                if (mapHeaders.find(storageHash) != mapHeaders.end()) {
                    // BUG FIX: Recalculate chainwork if pprev gives higher work.
                    // Headers stored from a previous sync may have pprev=NULL (tiny
                    // chainwork) because their parent wasn't in mapHeaders at the time.
                    // Now pprev is available — recalculate and update if higher.
                    auto& stored = mapHeaders[storageHash];
                    if (pprev) {
                        uint256 newChainWork = CalculateChainWork(headers[batchStart + i], pprev);
                        if (ChainWorkGreaterThan(newChainWork, stored.chainWork)) {
                            stored.chainWork = newChainWork;
                            int newHeight = pprev->height + 1;
                            if (stored.height != newHeight) {
                                stored.height = newHeight;
                            }
                        }
                    }
                    UpdateBestHeader(storageHash);
                    pprev = &stored;
                    prevHash = storageHash;
                    continue;
                }

                // FORK DETECTION: Only relevant above checkpoint
                if (heightHasHeaders && expectedHeight > checkpointHeight) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[HeadersManager] Fork header queued at height " << expectedHeight << std::endl;
                }

                // Quick validate (structure only - fast, fork-aware timestamp limit)
                if (!QuickValidateHeader(header, pprev ? &pprev->header : nullptr, expectedHeight)) {
                    return false;
                }

                // Calculate height and chain work
                int height = pprev ? (pprev->height + 1) : 1;
                uint256 chainWork = CalculateChainWork(header, pprev);

                // v4.1 site 5/5: header-time checkpoint enforcement (BEFORE store)
                if (!CheckpointCheckHeader(height, storageHash)) {
                    if (g_node_context.peer_manager) {
                        g_node_context.peer_manager->Misbehaving(peer, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
                    }
                    return false;
                }

                // Store header
                HeaderWithChainWork headerData(header, height);
                headerData.chainWork = chainWork;
                mapHeaders[storageHash] = headerData;
                AddToHeightIndex(storageHash, height);
                UpdateChainTips(storageHash);
                UpdateBestHeader(storageHash);

                // Phase 6 PR6.1 (v1.5 fix-up 2026-04-27 per dual-validation):
                // chain_selector wiring on the QueueHeadersForValidation
                // above-checkpoint path. Companion to the below-checkpoint
                // wiring ~50 lines above. Both reviewers flagged this gap.
                if (g_node_context.chain_selector) {
                    (void)g_node_context.chain_selector->ProcessNewHeader(header);
                }

                // Queue for background PoW validation (only for blocks above checkpoint)
                if (expectedHeight > checkpointHeight) {
                    std::lock_guard<std::mutex> vlock(m_validation_mutex);
                    m_validation_queue.emplace(peer, header, height, chainWork);
                }

                // Update for next iteration
                pprev = &mapHeaders[storageHash];
                prevHash = storageHash;
                totalProcessed++;
            }
        }  // Release cs_headers lock after each batch - allows block downloading to progress

        // BUG FIX: Update processed count incrementally after each batch.
        // Previously only updated after ALL 2000 headers finished (~74s on seed servers).
        // The IBD stall detector checks GetProcessedCount() for progress, but saw zero
        // during the entire processing window. On any CPU slower than seed servers,
        // this exceeded the 81s stall timeout → infinite stall/retry loop at height=0.
        if (totalProcessed > prevTotalProcessed) {
            m_headers_processed_count.fetch_add(totalProcessed - prevTotalProcessed);
            prevTotalProcessed = totalProcessed;
        }

        // Log batch progress
        if (batchStart > 0 && batchStart % 500 == 0 && g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[HeadersManager] Batch progress: " << totalProcessed
                      << "/" << headers.size() << " headers stored" << std::endl;
        }
    }  // End batch loop

    // Update peer state (final update after all batches)
    {
        std::lock_guard<std::mutex> lock(cs_headers);
        if (!headers.empty() && !prevHash.IsNull()) {
            auto it = mapHeaders.find(prevHash);
            if (it != mapHeaders.end()) {
                UpdatePeerState(peer, prevHash, it->second.height);
            }
        }
    }

    // Wake up validation thread (only if we queued any for validation)
    m_validation_cv.notify_one();

    auto total_end = std::chrono::steady_clock::now();
    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(total_end - total_start).count();
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Progressive processing complete: " << totalProcessed
                  << " headers stored in " << total_ms << "ms (hashes: " << hash_ms << "ms)" << std::endl;

    // Note: m_headers_processed_count already updated incrementally in batch loop above.
    // Final update for any remainder not covered by batch boundaries.
    if (totalProcessed > prevTotalProcessed) {
        m_headers_processed_count.fetch_add(totalProcessed - prevTotalProcessed);
    }

    // BUG FIX #183: Update m_last_request_hash AFTER successful processing
    // Use the hash of the last stored header (prevHash tracks this during processing)
    if (!prevHash.IsNull()) {
        std::lock_guard<std::mutex> lock(cs_headers);
        m_last_request_hash = prevHash;
        m_last_header_request_time = std::chrono::steady_clock::now();
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Updated m_last_request_hash to last stored hash: "
                      << prevHash.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // BUG FIX #184: Request more headers AFTER processing completes (SSOT)
    // This ensures m_last_request_hash is set correctly before the request is sent.
    // Previously, the request was sent from QueueRawHeadersForProcessing BEFORE
    // processing, causing infinite loops with stale hash values.
    // BUG FIX: Use dynamic best_known_height instead of static start_height.
    // start_height is set at VERSION handshake and never updates - if the peer's
    // chain grows during our sync, we'd stop requesting headers prematurely.
    int peer_height = GetPeerStartHeight(peer);
    if (g_node_context.peer_manager) {
        auto p = g_node_context.peer_manager->GetPeer(peer);
        if (p && p->best_known_height > peer_height) {
            peer_height = p->best_known_height;
        }
    }
    if (peer_height > 0 && !prevHash.IsNull()) {
        SyncHeadersFromPeer(peer, peer_height);
    }

    return true;
}

bool CHeadersManager::StartValidationThread()
{
    if (m_validation_running.load()) {
        std::cerr << "[HeadersManager] Validation thread pool already running" << std::endl;
        return false;
    }

    // IBD Redesign Phase 2: Spawn N worker threads where N = CPU cores
    // This parallelizes RandomX hash computation for massive speedup
    m_hash_worker_count = std::thread::hardware_concurrency();
    if (m_hash_worker_count == 0) {
        m_hash_worker_count = 4;  // Fallback if detection fails
    }
    // Cap at 8 threads to avoid memory contention with RandomX VMs
    if (m_hash_worker_count > 8) {
        m_hash_worker_count = 8;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Starting " << m_hash_worker_count
                  << " hash worker threads (Phase 2 parallel validation)..." << std::endl;

    m_validation_running.store(true);
    m_processor_running.store(true);

    try {
        // Start hash worker threads
        m_hash_workers.reserve(m_hash_worker_count);
        for (size_t i = 0; i < m_hash_worker_count; ++i) {
            m_hash_workers.emplace_back(&CHeadersManager::ValidationWorkerThread, this);
        }
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] " << m_hash_worker_count << " hash workers started" << std::endl;

        // Start header processor thread (offloads P2P thread)
        m_header_processor_thread = std::thread(&CHeadersManager::HeaderProcessorThread, this);
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Header processor thread started" << std::endl;

        return true;
    } catch (const std::exception& e) {
        m_validation_running.store(false);
        m_processor_running.store(false);
        // Join any threads that were started
        for (auto& thread : m_hash_workers) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        m_hash_workers.clear();
        if (m_header_processor_thread.joinable()) {
            m_raw_queue_cv.notify_all();
            m_header_processor_thread.join();
        }
        std::cerr << "[HeadersManager] Failed to start threads: " << e.what() << std::endl;
        return false;
    }
}

void CHeadersManager::StopValidationThread()
{
    if (!m_validation_running.load() && !m_processor_running.load()) {
        return;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Stopping " << m_hash_workers.size()
                  << " hash worker threads and header processor..." << std::endl;

    // Stop all threads
    m_validation_running.store(false);
    m_processor_running.store(false);
    m_validation_cv.notify_all();  // Wake all validation workers
    m_raw_queue_cv.notify_all();   // Wake header processor

    // Join hash worker threads
    for (auto& thread : m_hash_workers) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_hash_workers.clear();

    // Join header processor thread
    if (m_header_processor_thread.joinable()) {
        m_header_processor_thread.join();
    }

    // Clear remaining queues
    {
        std::lock_guard<std::mutex> lock(m_validation_mutex);
        while (!m_validation_queue.empty()) {
            m_validation_queue.pop();
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_raw_queue_mutex);
        while (!m_raw_header_queue.empty()) {
            m_raw_header_queue.pop();
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] All threads stopped. Validated: "
                  << m_validated_count.load() << ", Failures: "
                  << m_validation_failures.load() << std::endl;
}

void CHeadersManager::PauseHeaderProcessing()
{
    if (m_processing_paused.load()) {
        return;  // Already paused
    }

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[HeadersManager] Pausing header processing for fork recovery..." << std::endl;
        std::cout.flush();
    }

    // Set paused flag - workers will check this before starting new work
    m_processing_paused.store(true);

    // Wait for any active workers to finish (with timeout to prevent deadlock)
    {
        std::unique_lock<std::mutex> lock(m_pause_mutex);
        auto timeout = std::chrono::seconds(10);
        bool finished = m_pause_cv.wait_for(lock, timeout, [this] {
            return m_active_workers.load() == 0;
        });

        if (!finished) {
            std::cerr << "[HeadersManager] WARNING: Timeout waiting for workers, continuing anyway ("
                      << m_active_workers.load() << " workers still active)" << std::endl;
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Header processing paused" << std::endl;
}

void CHeadersManager::ResumeHeaderProcessing()
{
    if (!m_processing_paused.load()) {
        return;  // Not paused
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Resuming header processing..." << std::endl;
    m_processing_paused.store(false);

    // Wake up any waiting workers
    m_validation_cv.notify_all();
    m_raw_queue_cv.notify_all();
}

size_t CHeadersManager::GetValidationQueueDepth() const
{
    std::lock_guard<std::mutex> lock(m_validation_mutex);
    return m_validation_queue.size();
}

void CHeadersManager::ValidationWorkerThread()
{
    // IBD Redesign Phase 2: This runs in N parallel threads
    // Each thread has its own RandomX VM via thread-local storage in randomx_hash_thread()

    while (m_validation_running.load()) {
        // Check if paused for fork recovery - wait until unpaused
        if (m_processing_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        PendingValidation pending;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_validation_mutex);

            m_validation_cv.wait(lock, [this] {
                return !m_validation_running.load() || !m_validation_queue.empty() || m_processing_paused.load();
            });

            if (!m_validation_running.load()) {
                break;
            }

            // Recheck pause state after waking
            if (m_processing_paused.load() || m_validation_queue.empty()) {
                continue;
            }

            pending = m_validation_queue.front();
            m_validation_queue.pop();

            // RACE FIX: Increment INSIDE lock scope so pause can't miss us
            m_active_workers++;
        }

        // Validate PoW (expensive - runs outside lock, unless checkpointed)
        bool valid = FullValidateHeader(pending.header, pending.height);

        // Decrement active workers and notify pause waiter if needed
        if (--m_active_workers == 0 && m_processing_paused.load()) {
            std::lock_guard<std::mutex> lock(m_pause_mutex);
            m_pause_cv.notify_all();
        }

        if (valid) {
            m_validated_count++;

            // Log progress periodically
            size_t count = m_validated_count.load();
            if (count % 100 == 0 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[HeadersManager] Validated " << count << " headers (height "
                          << pending.height << ")" << std::endl;
            }
        } else {
            m_validation_failures++;
            std::cerr << "[HeadersManager] PoW FAILED for header at height "
                      << pending.height << " from peer " << pending.peer << std::endl;

            // TODO: Could disconnect peer or mark header as invalid
            // For now, just log the failure
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Validation worker thread stopped" << std::endl;
}

// ============================================================================
// Async Raw Header Processing (P2P Thread Offload)
// ============================================================================

bool CHeadersManager::QueueRawHeadersForProcessing(NodeId peer, std::vector<CBlockHeader> headers)
{
    // Instant return - just queue the headers for background processing
    // P2P thread only computes ONE hash (for prefetch locator)

    if (headers.empty()) {
        return true;
    }

    size_t header_count = headers.size();
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Queueing " << header_count
                  << " raw headers from peer " << peer << " for async processing" << std::endl;

    // Note: We no longer compute the last header's hash here.
    // m_last_request_hash is updated by AddHeaders AFTER validation.
    // This avoids the premature hash update that caused sync loops.

    {
        std::lock_guard<std::mutex> lock(m_raw_queue_mutex);
        m_raw_header_queue.push({peer, std::move(headers)});
    }

    m_raw_queue_cv.notify_one();

    // BUG FIX #184: DO NOT request headers here (before processing)!
    // The async worker will call SyncHeadersFromPeer AFTER processing completes,
    // using the correct m_last_request_hash (SSOT principle).
    // Requesting here caused infinite loops because m_last_request_hash was stale.

    return true;
}

void CHeadersManager::HeaderProcessorThread()
{
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Header processor thread started" << std::endl;

    while (m_processor_running.load()) {
        // Check if paused for fork recovery - wait until unpaused
        if (m_processing_paused.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        PendingHeaders pending;

        // Wait for raw headers
        {
            std::unique_lock<std::mutex> lock(m_raw_queue_mutex);

            m_raw_queue_cv.wait(lock, [this] {
                return !m_processor_running.load() || !m_raw_header_queue.empty() || m_processing_paused.load();
            });

            if (!m_processor_running.load()) {
                break;
            }

            // Recheck pause state after waking
            if (m_processing_paused.load() || m_raw_header_queue.empty()) {
                continue;
            }

            pending = std::move(m_raw_header_queue.front());
            m_raw_header_queue.pop();

            // RACE FIX: Increment INSIDE lock scope so pause can't miss us
            m_active_workers++;
        }

        // Process headers - hash computation happens HERE, not in P2P thread
        // This calls QueueHeadersForValidation which does hash computation + stores headers
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[HeadersManager] Processing " << pending.headers.size()
                      << " headers from peer " << pending.peer_id << std::endl;

        bool success = QueueHeadersForValidation(pending.peer_id, pending.headers);

        // Decrement active workers and notify pause waiter if needed
        if (--m_active_workers == 0 && m_processing_paused.load()) {
            std::lock_guard<std::mutex> lock(m_pause_mutex);
            m_pause_cv.notify_all();
        }

        if (success) {
            // Update peer's best known tip (height + hash) for fork divergence detection
            int bestHeight = GetBestHeight();
            uint256 bestHash = GetBestHash();
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[HeadersManager] Headers processed. Best height: " << bestHeight << std::endl;

            // Update peer tip tracking for FetchBlocks and fork detection
            if (g_node_context.peer_manager) {
                g_node_context.peer_manager->UpdatePeerBestKnownTip(pending.peer_id, bestHeight, bestHash);
            }
        } else {
            std::cerr << "[HeadersManager] Failed to process headers from peer "
                      << pending.peer_id << std::endl;
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[HeadersManager] Header processor thread stopped" << std::endl;
}
