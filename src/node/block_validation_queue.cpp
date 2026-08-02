// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/block_validation_queue.h>

#include <atomic>                  // advisory-cap log rate-limiter
#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/validation.h>  // For CheckCoinbase
#include <node/blockchain_storage.h>
#include <net/port/sync_coordinator.h>  // Phase 6 PR6.5a: OnBlockConnected via adapter
#include <net/net.h>               // A5: For SendRejectMessage()
#include <core/node_context.h>
#include <core/chainparams.h>
#include <net/peers.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // IBD BOTTLENECK FIX: For CBlockTracker updates
#include <net/orphan_manager.h>  // IBD HANG FIX #23b: For orphan resolution
#include <net/headers_manager.h>  // For InvalidateHeader()
#include <node/block_index.h>  // For CBlockIndex
#include <primitives/block.h>  // For CBlock
#include <util/logging.h>

#include <cassert>  // LOW-a: BLOCKER-1 by-hash-resolve debug guard
#include <iostream>
#include <chrono>
#include <queue>  // IBD HANG FIX #23b: For orphan queue

extern NodeContext g_node_context;

CBlockValidationQueue::CBlockValidationQueue(CChainState& chainstate, CBlockchainDB& db)
    : m_chainstate(chainstate), m_db(db) {}

CBlockValidationQueue::~CBlockValidationQueue() {
    Stop();
}

bool CBlockValidationQueue::Start() {
    if (m_running.load()) {
        return false;  // Already running
    }

    // Start watchdog first (monitors validation thread)
    // Watchdog will log timeouts for diagnostics but does NOT attempt to "skip" blocks
    // (skipping is impossible - breaks blockchain connectivity since Block N+1's parent is Block N)
    m_watchdog.Start();

    m_running.store(true);
    m_worker = std::thread(&CBlockValidationQueue::ValidationWorker, this);
    return true;
}

void CBlockValidationQueue::Stop() {
    if (!m_running.load()) {
        return;  // Already stopped
    }

    m_running.store(false);
    m_queue_cv.notify_all();  // Wake worker to check m_running

    if (m_worker.joinable()) {
        m_worker.join();
    }

    // Stop watchdog after worker thread is done
    m_watchdog.Stop();
}

bool CBlockValidationQueue::QueueBlock(int peer_id, const CBlock& block, int expected_height, const uint256& blockHash, CBlockIndex* pindex) {
    // Phase 2: Quick validation checks before queueing
    // IBD OPTIMIZATION: Use passed hash instead of computing RandomX

    // SSOT FIX #3: Use GetQueueDepth() instead of direct m_queue.size() access
    // This ensures atomic check with proper locking
    size_t queue_depth = GetQueueDepth();
    if (queue_depth >= MAX_QUEUE_DEPTH) {
        std::cerr << "[ValidationQueue] Queue full (" << queue_depth << " blocks), rejecting block from peer " << peer_id << std::endl;
        return false;
    }

    // Basic PoW check with DFMP enforcement
    // Skip PoW check for checkpointed blocks (same as current code)
    int currentChainHeight = m_chainstate.GetHeight();
    int checkpointHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->GetHighestCheckpointHeight() : 0;
    bool skipPoWCheck = (checkpointHeight > 0 && currentChainHeight < checkpointHeight);

    // BUG #250 FIX: Only run DFMP/Coinbase when parent is on ACTIVE chain.
    // Height-dependent validation (DFMP identity lookup, coinbase rules) can only be
    // authoritative when parent is on active chain. Otherwise, defer to ActivateBestChain.
    CBlockIndex* pParent = m_chainstate.GetBlockIndex(block.hashPrevBlock);
    bool parentOnActiveChain = (pParent != nullptr) && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);

    if (!skipPoWCheck) {
        // Get block height for DFMP (use expected_height if valid, else estimate)
        int blockHeight = (expected_height > 0) ? expected_height : (currentChainHeight + 1);

        if (!parentOnActiveChain) {
            // Parent missing or on competing chain - do basic PoW check only
            // VDF blocks skip hash-under-target check (proof validated in CheckVDFProof)
            if (!block.IsVDFBlock() && !CheckProofOfWork(blockHash, block.nBits)) {
                std::cerr << "[ValidationQueue] Block from peer " << peer_id << " has invalid basic PoW, rejecting" << std::endl;
                SendRejectMessage(peer_id, "block", "Invalid proof of work");
                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::INVALID_BLOCK_POW);  // Severe: invalid PoW
                }
                return false;
            }
            // Basic PoW passed - queue for processing (full DFMP + coinbase check happens during chain activation)
        } else {
            // Parent is on active chain - safe to run full validation

            // CRITICAL FIX: Validate nBits matches expected difficulty
            // Without this check, miners can use ANY difficulty forever.
            uint32_t expectedNBits = GetNextWorkRequired(pParent, static_cast<int64_t>(block.nTime));
            if (block.nBits != expectedNBits) {
                std::cerr << "[ValidationQueue] Block from peer " << peer_id << " has wrong difficulty" << std::endl;
                std::cerr << "  Block nBits:    0x" << std::hex << block.nBits << std::endl;
                std::cerr << "  Expected nBits: 0x" << expectedNBits << std::dec << std::endl;
                return false;
            }

            // Run full DFMP check
            int dfmpActivationHeight = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->dfmpActivationHeight : 0;

            if (!CheckProofOfWorkDFMP(block, blockHash, block.nBits, blockHeight, dfmpActivationHeight)) {
                std::cerr << "[ValidationQueue] Block from peer " << peer_id << " has invalid PoW (DFMP check failed), rejecting" << std::endl;
                SendRejectMessage(peer_id, "block", "Invalid proof of work (DFMP check failed)");

                // Invalidate header to prevent re-requesting this block
                if (g_node_context.headers_manager) {
                    g_node_context.headers_manager->InvalidateHeader(blockHash);
                }

                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->Misbehaving(peer_id, 100, MisbehaviorType::INVALID_BLOCK_POW);  // Severe: invalid PoW
                }
                return false;
            }
        }
    }

    // Coinbase validation removed from QueueBlock - it passed fees=0 which rejected
    // valid blocks that collected transaction fees, and banned the sending peer.
    // Coinbase is validated authoritatively in ProcessNewBlock Phase 2.5 (with
    // correct fee calculation) and again as part of ConnectTip's checks.
    // NOTE: CBlockValidator::CheckBlock is NOT in this path — it is dead code
    // (zero callers). Block-size enforcement is done by the storage-layer 4 MB
    // cap (blockchain_storage.cpp) and the P2P MAX_BLOCK_VTX_BYTES cap (net.cpp).

    // Check if we already have this block
    CBlockIndex* existing = m_chainstate.GetBlockIndex(blockHash);
    if (existing && existing->HaveData() && (existing->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[ValidationQueue] Block already in chain, skipping" << std::endl;
        return false;  // Already processed
    }

    // Create queued block entry
    QueuedBlock queued_block;
    queued_block.block = block;
    queued_block.peer_id = peer_id;
    queued_block.hash = blockHash;
    queued_block.expected_height = expected_height;
    queued_block.queued_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    queued_block.pindex = pindex ? pindex : existing;

    // SSOT FIX #3: Add to queue and update stats
    // Use GetQueueDepth() after adding to get accurate count
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);
        m_queue.push(queued_block);
        m_queued_heights.insert(expected_height);  // O(1) lookup for IsHeightQueued
        m_queued_hashes.insert(blockHash);          // PR #129 MEDIUM-2: pin source
    }
    queue_depth = GetQueueDepth();  // SSOT FIX #3: Reuse variable, don't redeclare

    // Update stats
    {
        std::lock_guard<std::mutex> lock(m_stats_mutex);
        m_stats.total_queued++;
        m_stats.queue_depth = queue_depth;
    }

    // Wake worker thread
    m_queue_cv.notify_one();

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ValidationQueue] Queued block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << " (queue depth: " << queue_depth << ")" << std::endl;

    return true;
}

bool CBlockValidationQueue::WaitForBlock(const uint256& hash, std::chrono::milliseconds timeout) {
    std::promise<bool> promise;
    auto future = promise.get_future();

    {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications[hash] = std::move(promise);
    }

    // Wait for validation to complete
    auto status = future.wait_for(timeout);
    if (status == std::future_status::timeout) {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications.erase(hash);
        return false;
    }

    bool result = future.get();

    {
        std::lock_guard<std::mutex> lock(m_notify_mutex);
        m_pending_notifications.erase(hash);
    }

    return result;
}

CBlockValidationQueue::Stats CBlockValidationQueue::GetStats() const {
    std::lock_guard<std::mutex> lock(m_stats_mutex);
    std::lock_guard<std::mutex> queue_lock(m_queue_mutex);
    m_stats.queue_depth = m_queue.size();
    return m_stats;
}

size_t CBlockValidationQueue::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    return m_queue.size();
}

bool CBlockValidationQueue::IsHeightQueued(int height) const {
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    // O(1) lookup using auxiliary set instead of O(n) queue copy
    return m_queued_heights.count(height) > 0;
}

std::set<uint256> CBlockValidationQueue::GetPendingBlockHashes() const {
    // PR #129 MEDIUM-2: union of queued hashes and the single in-flight hash.
    // Pure read under m_queue_mutex; returns hashes only. Lock order is
    // cs_main -> m_queue_mutex (eviction holds cs_main and calls this); this
    // function never calls back into CChainState, so the reverse order cannot
    // occur and there is no deadlock with eviction.
    std::lock_guard<std::mutex> lock(m_queue_mutex);
    std::set<uint256> pending = m_queued_hashes;
    if (m_has_inflight) {
        pending.insert(m_inflight_hash);
    }
    return pending;
}

void CBlockValidationQueue::ValidationWorker() {
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ValidationQueue] Worker thread started" << std::endl;

    while (m_running.load()) {
        QueuedBlock queued_block;
        bool has_block = false;

        // Wait for blocks in queue
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait(lock, [this] {
                return !m_queue.empty() || !m_running.load();
            });

            if (!m_running.load() && m_queue.empty()) {
                break;  // Shutting down
            }

            if (!m_queue.empty()) {
                queued_block = m_queue.top();
                m_queue.pop();
                m_queued_heights.erase(queued_block.expected_height);  // O(1) removal for IsHeightQueued
                m_queued_hashes.erase(queued_block.hash);              // PR #129 MEDIUM-2
                // PR #129 MEDIUM-2: hand the block to the in-flight slot ATOMICALLY
                // with its removal from m_queue, still under m_queue_mutex. This
                // closes the gap between "no longer queued" and "ProcessBlock has
                // started": from this instant the block is reported as pending via
                // the in-flight slot, so cap eviction (which can fire during the
                // cs_main-released wait inside ProcessBlock) pins it and its
                // ancestors rather than freeing them.
                m_inflight_hash = queued_block.hash;
                m_has_inflight = true;
                has_block = true;

                // SSOT FIX #3: Update queue depth in stats
                // IBD DEADLOCK FIX #11: Use m_queue.size() directly since we already hold m_queue_mutex
                // Calling GetQueueDepth() here would cause self-deadlock (tries to relock m_queue_mutex)
                {
                    std::lock_guard<std::mutex> stats_lock(m_stats_mutex);
                    m_stats.queue_depth = m_queue.size();  // Direct access - we already hold m_queue_mutex
                }
            }
        }

        if (!has_block) {
            continue;
        }

        // Process the block
        auto start_time = std::chrono::steady_clock::now();
        bool success = ProcessBlock(queued_block);
        // PR #129 MEDIUM-2: clear the in-flight slot now that ProcessBlock has
        // returned (success or fail). The block is fully indexed-or-rejected;
        // it no longer needs eviction protection. Cleared under m_queue_mutex so
        // the provider read stays consistent.
        {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_has_inflight = false;
        }
        auto end_time = std::chrono::steady_clock::now();
        auto validation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();

        // Update stats
        {
            std::lock_guard<std::mutex> lock(m_stats_mutex);
            if (success) {
                m_stats.total_validated++;
                m_stats.last_validated_height = queued_block.expected_height;
            } else {
                m_stats.total_rejected++;
            }

            // Update average validation time (exponential moving average)
            if (m_stats.total_validated > 0) {
                m_stats.avg_validation_time_ms = 
                    (m_stats.avg_validation_time_ms * 7 + validation_time) / 8.0;
            }

            m_stats.last_validation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }

        // Notify waiting threads
        NotifyBlockValidated(queued_block.hash, success);

        // Update last validated height
        if (success) {
            m_last_validated_height.store(queued_block.expected_height);
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ValidationQueue] Worker thread stopped" << std::endl;
}

bool CBlockValidationQueue::ProcessBlock(const QueuedBlock& queued_block) {
    const CBlock& block = queued_block.block;
    const uint256& blockHash = queued_block.hash;
    int expected_height = queued_block.expected_height;

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ValidationQueue] Processing block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << std::endl;

    // STRESS TEST FIX: Report to watchdog that validation is starting
    // Watchdog will alert if validation takes longer than VALIDATION_TIMEOUT_SECONDS
    m_watchdog.ReportValidationStart(blockHash, expected_height);

    // STRESS TEST FIX: Wrap validation in try-catch to ensure watchdog is notified
    // on any exception. This prevents the watchdog from falsely detecting a stuck
    // validation when an exception was thrown.
    try {
        // ORPHAN BOTTLENECK FIX #2: Ensure block is saved to database
        // For orphan blocks (peer_id == -1), block should already be saved before queueing
        // For regular blocks, block is saved in block handler before queueing
        // This is a safety check - should already be saved, but verify
        if (!m_db.BlockExists(blockHash)) {
            std::cerr << "[ValidationQueue] WARNING: Block not in database, saving now (should be rare)" << std::endl;
            if (!m_db.WriteBlock(blockHash, block)) {
                std::cerr << "[ValidationQueue] ERROR: Failed to save block to database" << std::endl;
                m_watchdog.ReportValidationComplete();
                return false;
            }
        }

    // Get or create block index.
    //
    // BLOCKER-1 (PR #129 re-red-team): do NOT trust queued_block.pindex. The
    // cached raw pointer was captured at QueueBlock() time, then cs_main was
    // released for the duration of async validation. While the entry waited,
    // EvictLowestWorkLeafNotPinned (now firing at the lowered 500K cap) could
    // have freed that index if it was an unpinned leaf — making the cached
    // pointer dangle, which then flowed into ActivateBestChain → use-after-free.
    // ALWAYS re-resolve by hash. LOW-b (PR #129 re-red-team): this function does
    // NOT hold cs_main for its duration — it never takes cs_main directly at all.
    // Each m_chainstate call (GetBlockIndex / AddBlockIndex / ActivateBestChain)
    // acquires cs_main internally for the span of THAT call and releases it on
    // return; cs_main is therefore released BETWEEN those calls. The by-hash
    // lookup below is authoritative precisely because it re-reads the map under a
    // FRESH cs_main acquisition immediately before use, rather than trusting a
    // pointer captured under an earlier, since-released lock. THIS re-resolve is
    // the SOLE mechanism that closes BLOCKER-1 for queued blocks.
    //
    // NOTE on the eviction pins (chain.cpp):
    //   * clause (c) does NOT cover a queued block: by the time a block is queued
    //     it has been stamped by MarkBlockReceived (block_index.h:182-184), so its
    //     validity is already BLOCK_VALID_TRANSACTIONS, and clause (c) only pins
    //     HAVE_DATA-WITHOUT-validity entries.
    //   * clause (d) (PR #129 MEDIUM-2) DOES now pin queued/in-flight blocks and
    //     their pprev ancestors, via the GetPendingBlockHashes() provider. That
    //     pin is a LIVENESS guarantee (it stops a cascade from freeing this
    //     block's parent and stalling adoption); it is NOT a correctness license.
    // Either way, this re-resolve stays MANDATORY and authoritative: pinning
    // guards against EVICTION, but the AddBlockIndex flag-merge can still destroy
    // a specific unique_ptr and re-home the canonical pointer for this hash even
    // while the hash is pinned. So do NOT re-introduce a cached-pointer fast-path:
    // the cached raw QueuedBlock::pindex MUST NOT be re-read across a cs_main
    // release. If the block was evicted while queued, GetBlockIndex returns null
    // below and the create-or-fail-closed path handles it.
    //
    // LOW-a (PR #129 re-red-team): the cached QueuedBlock::pindex field is left in
    // the struct for callers that still SET it (block_processing.cpp,
    // orphan-resolve path), but it is intentionally NEVER READ for use here. We
    // resolve strictly by hash. We deliberately do NOT name queued_block.pindex
    // anywhere in this function so that any future read shows up as a fresh
    // textual reference in review/grep — the structural absence IS the guard.
    CBlockIndex* const pindex_from_hash = m_chainstate.GetBlockIndex(blockHash);
    CBlockIndex* pindex = pindex_from_hash;

    // LOW-a debug guard: assert (debug builds only; compiles out under NDEBUG)
    // that the working pointer IS the by-hash re-resolve and was NOT seeded from
    // the cached QueuedBlock::pindex. This is a single-fetch identity check (no
    // second GetBlockIndex call, so no TOCTOU / no extra cs_main acquisition): it
    // pins the invariant at the use-site that the only sanctioned source of
    // `pindex` for a queued block is GetBlockIndex(hash) — the eviction-/merge-
    // safe path that closes BLOCKER-1.
    assert(pindex == pindex_from_hash &&
           "BLOCKER-1: pindex must come from the by-hash re-resolve, never the cached QueuedBlock::pindex");

    if (!pindex) {
        // MEDIUM-1 (PR #129 re-red-team): apply the mapBlockIndex cap on this
        // create-path too. ProcessNewHeader evicts down to cap-1 before adding a
        // header, but the queue's create path used to call AddBlockIndex with NO
        // cap check — so under sustained header pressure the index could overshoot
        // to cap + queue_depth (up to +MAX_QUEUE_DEPTH=100) via this path. We
        // mirror ProcessNewHeader: if at/over cap, evict the lowest-work unpinned
        // leaf down to cap-1 to make room for this one.
        //
        // NOT a ceiling. An earlier revision of this fold made it one and that was
        // a scheduled chain halt — see the advisory-cap note below.
        //
        // ORDERING IS LOAD-BEARING: we run eviction BEFORE looking up this block's
        // parent, and we resolve the parent by hash AFTER eviction. Eviction
        // (clause (d)) pins all pending blocks' ancestors, but this block is not
        // yet in mapBlockIndex (provider lookup misses it), so its parent is NOT
        // pinned via this block. If we had captured pprev before eviction and
        // eviction then freed the parent, that raw pointer would dangle — a NEW
        // UAF. By resolving the parent only after eviction, we never hold a
        // pre-eviction parent pointer across the eviction, and a parent freed by
        // the cascade is observed as a clean null (fail-closed), exactly like the
        // BLOCKER-1 by-hash discipline.
        // THE CAP IS ADVISORY HERE TOO — this must never reject a block.
        //
        // The version this replaces failed closed, and that was the single most
        // dangerous line in this PR. On origin/main this create path had NO cap
        // check at all, so blocks still connected when eviction failed. Adding a
        // hard ceiling here converted a header-layer degradation into a
        // BLOCK-CONNECT HALT, i.e. it turned a bounded overshoot into a scheduled
        // outage:
        //
        //   the pinned set pins every active-chain ancestor back to genesis, and
        //   mapBlockIndex is only ever erased by the evictor (which cannot touch a
        //   pinned entry), so size >= activeHeight + 1 always. At active height
        //   ~= cap, every entry is pinned, eviction returns false permanently, and
        //   a fail-closed create path means NO NODE CAN EVER SYNC PAST height
        //   500,000. Nodes already at the tip keep running via the uncapped
        //   synchronous path, so the network partitions into "already-synced" and
        //   "can-never-sync".
        //
        // Reproduce cheaply: regtest sets the cap to 1000 (chainparams.cpp), so the
        // old behaviour halts at height 1000 without flooding anything.
        //
        // The overshoot this check was written for (up to cap + MAX_QUEUE_DEPTH)
        // is a bounded, benign memory excess. Trading a liveness guarantee for it
        // was never a good trade. Evict opportunistically, log if we cannot, and
        // ALWAYS proceed.
        if (Dilithion::g_chainParams) {
            const int cap = Dilithion::g_chainParams->nMapBlockIndexCap;
            if (cap > 0 &&
                m_chainstate.GetBlockIndexSize() >= static_cast<size_t>(cap)) {
                const size_t target_max = static_cast<size_t>(cap) - 1;
                m_chainstate.EvictLowestWorkLeafNotPinned(target_max);
                if (m_chainstate.GetBlockIndexSize() >= static_cast<size_t>(cap)) {
                    // Rate-limited: past the height ceiling this is every block.
                    static std::atomic<uint64_t> s_overCapLogged{0};
                    const uint64_t n = s_overCapLogged.fetch_add(1, std::memory_order_relaxed);
                    if (n == 0 || (n % 10000) == 0) {
                        std::cerr << "[ValidationQueue] NOTE: mapBlockIndex at the "
                                  << cap << "-entry cap with no evictable unpinned leaf "
                                  << "(the map is active-chain ancestors). Connecting the "
                                  << "block anyway — the cap is advisory and must never "
                                  << "gate chain progress. Memory use exceeds the target. "
                                  << "Occurrence " << (n + 1) << "." << std::endl;
                    }
                }
                // Deliberately fall through and create the index either way.
            }
        }

        // Create block index
        auto pblockIndex = std::make_unique<CBlockIndex>(block);
        pblockIndex->phashBlock = blockHash;
        // v4.3.3 F14: canonical block-receipt flag-setter (F1 + F7 combined).
        pblockIndex->MarkBlockReceived();

        // Link to parent. Resolve by hash AFTER the cap eviction above (see the
        // ORDERING note): never carry a pre-eviction parent pointer across it.
        pblockIndex->pprev = m_chainstate.GetBlockIndex(block.hashPrevBlock);
        if (!pblockIndex->pprev) {
            std::cerr << "[ValidationQueue] ERROR: Parent block not found for block at height " << expected_height << std::endl;
            m_watchdog.ReportValidationComplete();
            return false;
        }

        // Calculate height and chain work
        pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
        pblockIndex->BuildChainWork();

        // Save block index to database
        if (!m_db.WriteBlockIndex(blockHash, *pblockIndex)) {
            std::cerr << "[ValidationQueue] ERROR: Failed to save block index" << std::endl;
            m_watchdog.ReportValidationComplete();
            return false;
        }

        // Add to chain state (may fail if another thread beat us - that's OK)
        if (!m_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
            // Another thread already added this block - get the existing index
            pindex = m_chainstate.GetBlockIndex(blockHash);
            if (!pindex) {
                std::cerr << "[ValidationQueue] ERROR: Block index not found after add failed" << std::endl;
                m_watchdog.ReportValidationComplete();
                return false;
            }
            // Continue with existing block index
        } else {
            pindex = m_chainstate.GetBlockIndex(blockHash);
            if (!pindex) {
                std::cerr << "[ValidationQueue] CRITICAL ERROR: Block index not found after adding!" << std::endl;
                m_watchdog.ReportValidationComplete();
                return false;
            }
        }
    }

    // Activate best chain (this is the slow operation that was blocking P2P thread)
    bool reorgOccurred = false;
    if (!m_chainstate.ActivateBestChain(pindex, block, reorgOccurred)) {
        std::cerr << "[ValidationQueue] ERROR: ActivateBestChain failed for block at height " << expected_height << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;
    }

    if (reorgOccurred) {
        std::cout << "[ValidationQueue] CHAIN REORGANIZATION occurred at height " << expected_height << std::endl;
    }

    // A1 FIX: Notify IBD coordinator that a block connected successfully
    // Resets orphan streak counter (Layer 2 fork detection) and updates block-flow timestamp
    if (g_node_context.sync_coordinator) {
        g_node_context.sync_coordinator->OnBlockConnected();
    }

    // DEAD CODE REMOVED: OnChunkBlockReceived and OnWindowBlockConnected
    // CBlockTracker is now the SSOT - tracking already updated via OnBlockReceived

    // Phase 2.2: Mark this block as received if it was a pending parent request
    if (g_node_context.orphan_manager) {
        g_node_context.orphan_manager->MarkParentReceived(blockHash);
    }

    // IBD HANG FIX #23b: Process orphan children after async validation completes
    // When a block validates successfully, check if any orphans were waiting for it as their parent
    // This was previously only done in the synchronous block handler path
    if (g_node_context.orphan_manager) {
        std::vector<uint256> orphanChildren = g_node_context.orphan_manager->GetOrphanChildren(blockHash);
        if (!orphanChildren.empty()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[ValidationQueue] Found " << orphanChildren.size()
                          << " orphan children waiting for block " << blockHash.GetHex().substr(0, 16)
                      << "... at height " << expected_height << std::endl;

            // Process orphan children (queue them for validation)
            for (const uint256& orphanHash : orphanChildren) {
                CBlock orphanBlock;
                if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                    uint256 orphanBlockHash = orphanBlock.GetHash();

                    // Verify parent is now available
                    CBlockIndex* pOrphanParent = m_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
                    if (!pOrphanParent) {
                        // Parent still not available - keep orphan for later
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ValidationQueue] Orphan " << orphanBlockHash.GetHex().substr(0, 16)
                                      << "... parent still not available, keeping in pool" << std::endl;
                        continue;
                    }

                    int orphanHeight = pOrphanParent->nHeight + 1;

                    // Check if already being processed (by IBD coordinator or another thread)
                    if (m_chainstate.GetBlockIndex(orphanBlockHash)) {
                        // Block index exists - another thread is handling it
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                        continue;
                    }

                    // Create block index for orphan
                    auto pOrphanIndex = std::make_unique<CBlockIndex>(orphanBlock);
                    pOrphanIndex->phashBlock = orphanBlockHash;
                    // v4.3.3 F14: canonical block-receipt flag-setter
                    // (F1 + F7 combined) at the orphan-resolve path.
                    pOrphanIndex->MarkBlockReceived();
                    pOrphanIndex->pprev = pOrphanParent;
                    pOrphanIndex->nHeight = orphanHeight;
                    pOrphanIndex->BuildChainWork();

                    // Save block to database
                    if (!m_db.WriteBlock(orphanBlockHash, orphanBlock)) {
                        std::cerr << "[ValidationQueue] Failed to save orphan block to database" << std::endl;
                        continue;
                    }

                    // Add to chain state. With Phase 11 ABI flag-merge semantics
                    // (chain.cpp AddBlockIndex), this returns true on merge into
                    // an existing entry — the moved-from unique_ptr is destroyed
                    // and any raw pointer to its payload is dangling. We must
                    // re-resolve via GetBlockIndex to get the canonical map-owned
                    // CBlockIndex* before any further use. (Cursor v4.3 close-readiness
                    // review of ABI surfaced this orphan-path UAF.)
                    if (!m_chainstate.AddBlockIndex(orphanBlockHash, std::move(pOrphanIndex))) {
                        // (Practically unreachable now that ABI returns true on merge.
                        // Kept defensively in case AddBlockIndex shape changes again.)
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                        continue;
                    }

                    // Re-resolve the raw pointer post-AddBlockIndex. Whether the
                    // moved unique_ptr was adopted (fresh insertion) or destroyed
                    // (merge into existing entry), the chainstate map now owns
                    // the canonical CBlockIndex* for this hash.
                    CBlockIndex* pOrphanIndexRaw = m_chainstate.GetBlockIndex(orphanBlockHash);
                    if (!pOrphanIndexRaw) {
                        // Should be impossible after AddBlockIndex returned true.
                        // Surface loudly rather than UAF on a dangling get().
                        std::cerr << "[ValidationQueue] FATAL: AddBlockIndex returned true but GetBlockIndex returned null for "
                                  << orphanBlockHash.GetHex().substr(0, 16) << "..." << std::endl;
                        continue;
                    }

                    // Save block index to database
                    if (!m_db.WriteBlockIndex(orphanBlockHash, *pOrphanIndexRaw)) {
                        std::cerr << "[ValidationQueue] Failed to save orphan block index" << std::endl;
                        continue;
                    }

                    // Queue orphan for async validation
                    // IBD OPTIMIZATION: Pass orphanBlockHash to avoid RandomX recomputation
                    if (QueueBlock(-1, orphanBlock, orphanHeight, orphanBlockHash, pOrphanIndexRaw)) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[ValidationQueue] Queued orphan " << orphanBlockHash.GetHex().substr(0, 16)
                                      << "... at height " << orphanHeight << " for validation" << std::endl;
                        // Successfully queued - now safe to remove from orphan pool
                        g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                    } else {
                        std::cerr << "[ValidationQueue] Failed to queue orphan for validation, keeping in pool" << std::endl;
                    }
                }
            }
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[ValidationQueue] Successfully validated block at height " << expected_height << std::endl;
    m_watchdog.ReportValidationComplete();
    return true;

    } catch (const std::exception& e) {
        // STRESS TEST FIX: Catch and log all exceptions to prevent frozen validation
        std::cerr << "[ValidationQueue] EXCEPTION validating block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << ": " << e.what() << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;

    } catch (...) {
        // STRESS TEST FIX: Catch unknown exceptions
        std::cerr << "[ValidationQueue] UNKNOWN EXCEPTION validating block " << blockHash.GetHex().substr(0, 16)
                  << "... at height " << expected_height << std::endl;
        m_watchdog.ReportValidationComplete();
        return false;
    }
}

void CBlockValidationQueue::NotifyBlockValidated(const uint256& hash, bool success) {
    std::lock_guard<std::mutex> lock(m_notify_mutex);
    auto it = m_pending_notifications.find(hash);
    if (it != m_pending_notifications.end()) {
        it->second.set_value(success);
    }
}

