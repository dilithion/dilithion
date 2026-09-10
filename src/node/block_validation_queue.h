// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_BLOCK_VALIDATION_QUEUE_H
#define DILITHION_NODE_BLOCK_VALIDATION_QUEUE_H

#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <atomic>
#include <future>
#include <string>

#include <primitives/block.h>  // CBlock (needed as complete type in QueuedBlock)
#include <uint256.h>           // uint256 (needed as complete type in QueuedBlock)
#include <node/validation_watchdog.h>  // CValidationWatchdog for stuck validation detection

// Forward declarations
class CChainState;
class CBlockchainDB;
class CBlockIndex;

/**
 * @brief Async block validation queue for IBD performance optimization
 *
 * Phase 2: Implements asynchronous block validation to prevent P2P thread
 * blocking during ActivateBestChain() calls (50-500ms per block).
 *
 * Architecture:
 * - P2P thread: Receives block → PoW check → Save to DB → Queue for validation → Return immediately
 * - Validation worker: Processes queue in height order → ActivateBestChain() → UTXO validation
 *
 * Benefits:
 * - P2P thread can continue receiving blocks while validation happens
 * - Blocks arrive faster during IBD (no blocking on slow validation)
 * - Better parallelization of network I/O and CPU validation
 *
 * Reference: Bitcoin Core PR #16175 (Async ProcessNewBlock)
 */
class CBlockValidationQueue {
public:
    /**
     * @brief Block queued for async validation
     */
    struct QueuedBlock {
        CBlock block;
        int peer_id;
        uint256 hash;
        int expected_height;
        int64_t queued_time;
        CBlockIndex* pindex;  // Block index (if already created)

        // Priority queue comparator: process lower heights first (min-heap)
        bool operator<(const QueuedBlock& other) const {
            return expected_height > other.expected_height;  // Min-heap by height
        }
    };

    /**
     * @brief Statistics for monitoring queue performance
     */
    struct Stats {
        size_t queue_depth{0};
        size_t total_queued{0};
        size_t total_validated{0};
        size_t total_rejected{0};
        double avg_validation_time_ms{0.0};
        int last_validated_height{-1};
        int64_t last_validation_time{0};
    };

    /**
     * @brief Constructor
     * @param chainstate Chain state for ActivateBestChain
     * @param db Blockchain database for block storage
     */
    explicit CBlockValidationQueue(CChainState& chainstate, CBlockchainDB& db);

    /**
     * @brief Destructor - stops worker thread
     */
    ~CBlockValidationQueue();

    /**
     * @brief Start the validation worker thread
     * @return true on success, false if already running
     */
    bool Start();

    /**
     * @brief Stop the validation worker thread
     */
    void Stop();

    /**
     * @brief Check if worker thread is running
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * @brief Queue block for async validation (returns immediately)
     *
     * Performs cheap checks (PoW, duplicate, parent exists) then queues
     * for full validation in worker thread.
     *
     * @param peer_id Peer that sent the block
     * @param block Block to validate
     * @param expected_height Expected height (from headers)
     * @param blockHash Block hash (passed to avoid RandomX recomputation)
     * @param pindex Block index (if already created)
     * @return true if queued successfully, false if queue is full or invalid
     */
    bool QueueBlock(int peer_id, const CBlock& block, int expected_height, const uint256& blockHash, CBlockIndex* pindex = nullptr);

    /**
     * @brief Wait for specific block to be validated
     * @param hash Block hash to wait for
     * @param timeout Maximum time to wait
     * @return true if validated successfully, false on timeout or rejection
     */
    bool WaitForBlock(const uint256& hash, std::chrono::milliseconds timeout);

    /**
     * @brief Get the last validated block height
     */
    int GetLastValidatedHeight() const { return m_last_validated_height.load(); }

    /**
     * @brief Get queue statistics
     */
    Stats GetStats() const;

    /**
     * @brief Get current queue depth (for backpressure)
     */
    size_t GetQueueDepth() const;

    /**
     * @brief Check if a specific height is queued for validation
     * 
     * IBD HANG FIX #3: Track validation queue status per height
     * Used to determine if blocks in "received" state are queued (processing) vs stuck
     * 
     * @param height Block height to check
     * @return true if height is queued for validation
     */
    bool IsHeightQueued(int height) const;

    /**
     * @brief PR #129 MEDIUM-2: hashes the queue is currently responsible for.
     *
     * Returns every QUEUED block hash plus the single block currently IN-FLIGHT
     * in the worker (popped from the queue but mid-ProcessBlock, with cs_main
     * released between ops). CChainState registers this as its
     * PendingBlockHashProvider and consults it during cap eviction (under
     * cs_main) to pin these blocks AND their pprev ancestors, so a multi-pass
     * cascade cannot free a queued block's parent out from under the worker's
     * create path (a liveness hole under adversarial cap pressure).
     *
     * Pure read of queue state under m_queue_mutex; returns HASHES (not raw
     * CBlockIndex*), which keeps the lock order cs_main -> m_queue_mutex clean
     * (eviction holds cs_main and calls this; this never calls into CChainState).
     *
     * NOTE — this is ADDITIVE liveness defense; it does NOT replace the worker's
     * by-hash re-resolve in ProcessBlock, which is the authoritative correctness
     * path for BLOCKER-1. The parenthetical that used to sit here — "pinning
     * guards eviction, not the AddBlockIndex flag-merge that can still re-home
     * the canonical pointer for a hash" — is FALSE: the merge mutates the
     * existing object in place, so the address is stable (asserted by
     * test_height_one_header_then_data_sequence). The re-resolve is mandatory
     * because the cached pointer predates the pin, not because a merge moves it.
     *
     * Returns the union of: queued hashes, the in-flight hash, and the PARENT
     * hash of each — the parents matter because a queued block that is not yet
     * in mapBlockIndex pins nothing via the child, which is exactly the
     * create-path case (external panel round 2).
     */
    std::set<uint256> GetPendingBlockHashes() const;

private:
    /**
     * @brief Validation worker thread main loop
     */
    void ValidationWorker();

    /**
     * @brief Process a single block from the queue
     * @param queued_block Block to process
     * @return true if validated successfully, false if rejected
     */
    bool ProcessBlock(const QueuedBlock& queued_block);

    /**
     * @brief Notify waiting threads that block validation completed
     * @param hash Block hash
     * @param success Whether validation succeeded
     */
    void NotifyBlockValidated(const uint256& hash, bool success);

    CChainState& m_chainstate;
    CBlockchainDB& m_db;

    // Watchdog to detect frozen validation threads (Issue 1 from stress test)
    CValidationWatchdog m_watchdog;

    // SSOT FIX #3: m_queue is private - all access must go through GetQueueDepth()
    // This ensures queue depth is always checked atomically with proper locking
    // Priority queue for blocks (min-heap by height)
    std::priority_queue<QueuedBlock> m_queue;
    std::set<int> m_queued_heights;  // O(1) lookup for IsHeightQueued - tracks heights in queue
    // PR #129 MEDIUM-2: hashes of blocks currently QUEUED (kept in sync with
    // m_queue) plus the single block IN-FLIGHT in the worker. Both are guarded
    // by m_queue_mutex. GetPendingBlockHashes() returns their union so eviction
    // can pin them and their ancestors. The in-flight slot is essential: between
    // the worker popping a block (removing it from m_queue / m_queued_hashes) and
    // ProcessBlock finishing, cs_main is released across ops — exactly the
    // BLOCKER-1 / cascade window — and the block is no longer in m_queue, so a
    // queue-contents-only set would miss it precisely when it is most exposed.
    std::set<uint256> m_queued_hashes;          // hashes currently in m_queue
    uint256 m_inflight_hash;                     // hash mid-ProcessBlock (or null)
    bool m_has_inflight{false};                  // whether m_inflight_hash is valid

    // PR #129 round-2 (external panel: gpt6 HIGH, kimi MEDIUM, found
    // independently) — PARENT HASHES, and this closes a hole the clause-(d)
    // comment claimed was already closed.
    //
    // Clause (d) in EvictLowestWorkLeafNotPinned pins a pending block AND walks
    // its pprev ancestors — but the walk starts from `mapBlockIndex.find(h)`,
    // and on a MISS it does `continue`. A queued block that is not yet in
    // mapBlockIndex is exactly the create-path case, so for precisely those
    // blocks the ancestor walk never ran and THE PARENT WAS NOT PINNED. The
    // create path could therefore evict the very parent it was about to resolve.
    // Safety was preserved by the resolve-AFTER-evict ordering (a freed parent
    // is observed as a clean null, not a dangling pointer); LIVENESS was not —
    // a valid competing fork stalls under cap pressure. ProcessBlock's own
    // comment conceded this while the clause-(d) comment asserted the opposite.
    //
    // Reporting the parent hash lets clause (d) pin it BY HASH, independently of
    // whether the child is indexed yet, which is the case that was missing.
    //
    // A MULTISET, DELIBERATELY: several queued blocks can share one parent, and
    // with a plain set, popping one of them would unpin a parent the others
    // still need. Erase with `erase(find(h))` — never `erase(h)`, which removes
    // EVERY equal element and reintroduces exactly that bug.
    std::multiset<uint256> m_queued_parent_hashes;  // parents of queued blocks
    uint256 m_inflight_parent_hash;                  // parent of the in-flight block
    bool m_has_inflight_parent{false};
    mutable std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Worker thread
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<int> m_last_validated_height{-1};

    // Blocking notifications for WaitForBlock()
    std::map<uint256, std::promise<bool>> m_pending_notifications;
    mutable std::mutex m_notify_mutex;

    // Statistics
    mutable Stats m_stats{};
    mutable std::mutex m_stats_mutex;

    // Maximum queue depth (backpressure limit)
    static constexpr size_t MAX_QUEUE_DEPTH = 100;
};

#endif // DILITHION_NODE_BLOCK_VALIDATION_QUEUE_H

