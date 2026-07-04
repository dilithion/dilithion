// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_IBD_COORDINATOR_H
#define DILITHION_NODE_IBD_COORDINATOR_H

#include <uint256.h>
#include <consensus/params.h>  // Consensus::MAX_REORG_DEPTH (auto-reorg bound tracks the consensus cap)
#include <atomic>
#include <chrono>
#include <set>
#include <string>

// Forward declarations
class CChainState;
class NodeContext;

/**
 * @brief IBD State Machine
 *
 * Phase 5.1: State machine for tracking IBD phases
 */
enum class IBDState {
    IDLE,              // No IBD needed (chain is synced)
    WAITING_FOR_PEERS, // Waiting for peers to connect
    HEADERS_SYNC,      // Syncing headers from peers
    BLOCKS_DOWNLOAD,   // Downloading blocks
    COMPLETE           // IBD complete
};

/**
 * @brief Fork recovery reason codes (A2: structured observability)
 *
 * Used for structured logging and metrics when fork recovery is triggered.
 */
enum class ForkRecoveryReason {
    LAYER1_TIP_MISMATCH,    // Layer 1: Our tip hash doesn't match header chain
    LAYER2_ORPHAN_STREAK,   // Layer 2: Consecutive orphan blocks exceeded threshold
    LAYER3_STALL_TIMEOUT,   // Layer 3: Chain stalled with IBD activity
};

inline const char* ForkRecoveryReasonToString(ForkRecoveryReason reason) {
    switch (reason) {
        case ForkRecoveryReason::LAYER1_TIP_MISMATCH: return "LAYER1_TIP_MISMATCH";
        case ForkRecoveryReason::LAYER2_ORPHAN_STREAK: return "LAYER2_ORPHAN_STREAK";
        case ForkRecoveryReason::LAYER3_STALL_TIMEOUT: return "LAYER3_STALL_TIMEOUT";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Encapsulates the Initial Block Download coordination logic.
 *
 * Phase 5.1: Encapsulates IBD logic from main loop
 * 
 * Dilithion originally embedded all block download orchestration inside
 * the main node loop.  This class collects the state (backoff counters,
 * header deltas) and exposes a single Tick() entry point, mirroring the
 * structure used by Bitcoin Core's net_processing loop.
 */
class CIbdCoordinator {
public:
    /**
     * @brief Constructor using NodeContext (Phase 5.1)
     * 
     * Uses NodeContext to access all required components, following
     * the pattern established in Phase 1.2.
     */
    CIbdCoordinator(CChainState& chainstate, NodeContext& node_context);

    /**
     * @brief Executes one maintenance pass of block download coordination.
     *
     * Call this from the main event loop once per second.  It handles:
     *  - State machine transitions
     *  - Exponential backoff when no peers are available.
     *  - Queueing headers-ahead blocks for download.
     *  - Dispatching GETDATA requests up to the in-flight limit.
     *  - Retrying timed-out blocks and disconnecting stalling peers.
     */
    void Tick();

    /**
     * @brief Get current IBD state
     */
    IBDState GetState() const { return m_state; }

    /**
     * @brief Get human-readable state name
     */
    std::string GetStateName() const;

    /**
     * @brief Check if IBD is active (not IDLE or COMPLETE)
     */
    bool IsActive() const {
        return m_state != IBDState::IDLE && m_state != IBDState::COMPLETE;
    }

    /**
     * @brief Check if node is synced with the network (not in IBD)
     *
     * Thread-safe. Returns true when the node's chain is within
     * SYNC_TOLERANCE_BLOCKS of the best known header height.
     *
     * Uses hysteresis to prevent state flapping:
     * - Becomes synced when within SYNC_TOLERANCE_BLOCKS of headers
     * - Becomes un-synced when more than UNSYNC_THRESHOLD_BLOCKS behind
     *
     * This method is designed to be called from any thread, including
     * header validation workers. The atomic m_synced flag ensures
     * thread-safe reads without locking.
     */
    bool IsSynced() const;

    /**
     * @brief Check if node is in Initial Block Download
     *
     * Inverse of IsSynced(). Returns true when the node is still
     * catching up to the network and should not mine or relay transactions.
     */
    bool IsInitialBlockDownload() const;

    /** @brief Get current headers sync peer ID (-1 if none) */
    int GetHeadersSyncPeer() const { return m_headers_sync_peer; }

    /**
     * @brief Called when an orphan block is received (Layer 2 fork detection)
     *
     * Consecutive orphan blocks during IBD suggest we may be on a fork.
     * After ORPHAN_FORK_THRESHOLD consecutive orphans, triggers fork detection.
     */
    void OnOrphanBlockReceived() {
        m_consecutive_orphan_blocks.fetch_add(1);
    }

    /**
     * @brief Called when a block successfully connects to the chain
     *
     * Resets the orphan counter since the chain is progressing normally.
     * Also updates block-flow timestamp for Layer 3 flow-aware gating (B3).
     */
    void OnBlockConnected() {
        m_consecutive_orphan_blocks.store(0);
        m_last_block_connected_ticks.store(
            std::chrono::steady_clock::now().time_since_epoch().count());
    }

    /**
     * @brief Check if reindex is required due to deep fork
     */
    bool RequiresReindex() const { return m_requires_reindex; }

private:
    void UpdateState();
    void ResetBackoffOnNewHeaders(int header_height);
    bool ShouldAttemptDownload() const;
    double GetDownloadRateMultiplier() const;  // IBD HANG FIX #1: Gradual backpressure (0.0-1.0)
    void HandleNoPeers(std::chrono::steady_clock::time_point now);
    void DownloadBlocks(int header_height, int chain_height, std::chrono::steady_clock::time_point now);
    bool FetchBlocks();
    void RetryTimeoutsAndStalls();

    // Fork detection and recovery
    int FindForkPoint(int chain_height);

    /**
     * @brief Attempt fork recovery: find fork point, validate chainwork, create ForkCandidate
     *
     * Unified recovery pipeline for all layers (A2/B1).
     * Returns true if a fork candidate was created or is already active.
     */
    bool AttemptForkRecovery(int chain_height, int header_height,
                             ForkRecoveryReason reason = ForkRecoveryReason::LAYER3_STALL_TIMEOUT);

    // Headers sync peer management (Bitcoin Core style)
    void SelectHeadersSyncPeer();           // Pick a sync peer if none selected
    bool CheckHeadersSyncProgress();        // Check if sync peer is making progress
    // v4.0.22 Patch F: penalize=true (default, used by stall-timeout path)
    // increments consecutive-stalls counter; penalize=false (used by
    // coherence-recovery path) skips the counter so peer rotation due to
    // chain coherence breaks doesn't exhaust the bad-peer pool.
    void SwitchHeadersSyncPeer(bool penalize = true);

    // IBD HANG FIX #6: Hang cause tracking
    enum class HangCause {
        NONE,
        VALIDATION_QUEUE_FULL,
        NO_PEERS_AVAILABLE,
        PEERS_AT_CAPACITY,
        WAITING_ON_PARENT_VALIDATION  // Parent block in DB but not yet connected
    };
    HangCause GetLastHangCause() const { return m_last_hang_cause; }

    CChainState& m_chainstate;
    NodeContext& m_node_context;

    // State machine
    IBDState m_state{IBDState::IDLE};

    // Sync state tracking (thread-safe)
    // Uses hysteresis to prevent flapping between synced/not-synced states
    std::atomic<bool> m_synced{false};
    static constexpr int SYNC_TOLERANCE_BLOCKS = 2;   // Become synced when within N blocks
    static constexpr int UNSYNC_THRESHOLD_BLOCKS = 10; // Become un-synced when N+ blocks behind

    // Headers sync peer tracking (Bitcoin Core style single-sync-peer)
    int m_headers_sync_peer{-1};                                    // NodeId of current sync peer (-1 = none)
    std::chrono::steady_clock::time_point m_headers_sync_timeout;   // When to consider sync peer stalled
    int m_headers_sync_last_height{0};                              // Header height at last progress check
    uint64_t m_headers_sync_last_processed{0};                      // Processed count at last progress check (fork catch-up)
    bool m_headers_in_flight{false};                                // True while awaiting headers from sync peer
    static constexpr int HEADERS_SYNC_TIMEOUT_BASE_SECS = 120;      // 120 sec base — accounts for RandomX LIGHT mode
                                                                     // processing time (~37ms/hash * 2000 = 74s on seed servers,
                                                                     // potentially 100s+ on slower CPUs)
    static constexpr int HEADERS_SYNC_TIMEOUT_PER_HEADER_MS = 1;    // +1ms per missing header
    std::set<int> m_headers_bad_peers;                              // Peers that have repeatedly failed to deliver headers
    int m_headers_sync_peer_consecutive_stalls{0};                  // Consecutive stalls for current peer
    static constexpr int MAX_HEADERS_CONSECUTIVE_STALLS = 3;        // Ban peer after N consecutive stalls

    // v4.0.22: Throttle for active header recovery on chain-coherence breaks.
    // Without throttle, FetchBlocks fires recovery on every tick (~1s) when
    // chain has a header gap, exhausting peer pool via bad-peer tracking.
    // 30s throttle gives header sync time to fill the gap before retrying.
    std::chrono::steady_clock::time_point m_last_active_recovery_time{};
    static constexpr int ACTIVE_RECOVERY_THROTTLE_SECONDS = 30;

    // Blocks sync peer tracking (single peer for block download, different from headers peer)
    int m_blocks_sync_peer{-1};                                     // NodeId of block sync peer (-1 = none)
    int m_blocks_sync_peer_consecutive_timeouts{0};                 // Consecutive 60s timeout cycles without delivery
    static constexpr int MAX_PEER_CONSECUTIVE_TIMEOUTS = 3;         // Force reselection after N consecutive timeouts
    // BUG #256: Track timed-out peers to avoid re-selecting them immediately
    // Cooldown duration varies by severity:
    //   - Hard timeout (3×60s no delivery): 1 hour - peer is likely broken/malicious
    //   - Capacity stall (15s no delivery): 60s - peer may just be temporarily slow
    int m_timed_out_peer{-1};                                       // Peer that timed out (excluded from selection)
    std::chrono::steady_clock::time_point m_timed_out_peer_time;    // When the peer timed out
    int m_timed_out_peer_cooldown_sec{0};                           // Cooldown duration for this specific timeout
    static constexpr int HARD_TIMEOUT_COOLDOWN_SEC = 3600;          // 1 hour for hard timeouts (Bitcoin-style penalty)
    static constexpr int CAPACITY_STALL_COOLDOWN_SEC = 60;          // 60s for capacity stalls (peer may recover)

    // Capacity stall detection: if peer is "at capacity" for too long without blocks arriving,
    // clear in-flight blocks and force peer reselection (much faster than 60s hard timeout)
    int m_consecutive_capacity_stalls{0};
    static constexpr int MAX_CAPACITY_STALLS_BEFORE_CLEAR = 15;  // 15 seconds of stalling
    int m_last_stall_check_height{0};  // Chain height when stall counter was last reset

    // BUG #272: Wrong-fork sync peer detection
    // When the sync peer delivers blocks that all become orphans (different fork),
    // the chain never advances despite blocks being delivered. Track batches sent
    // without chain progress to detect and switch away from wrong-fork peers.
    int m_sync_peer_futile_batches{0};           // Batches sent to sync peer without chain advancing
    int m_sync_peer_chain_height_at_start{-1};   // Chain height when current sync peer was selected
    static constexpr int MAX_FUTILE_BATCHES = 3; // Switch peer after 3 full batches (96 blocks) with no progress

    // Backoff state
    int m_last_header_height{0};
    int m_ibd_no_peer_cycles{0};
    std::chrono::steady_clock::time_point m_last_ibd_attempt;
    
    // IBD HANG FIX #6: Hang cause tracking
    mutable HangCause m_last_hang_cause{HangCause::NONE};

    // WAITING_ON_PARENT_VALIDATION timeout: if parent stays in DB but unconnected
    // for too long, escalate to full recovery (clear tracker, rotate peer).
    // Tracks the specific parent (height + hash) so the timer resets when the
    // chain advances and a *different* parent becomes the bottleneck.
    int m_waiting_parent_height{-1};
    uint256 m_waiting_parent_hash{};
    std::chrono::steady_clock::time_point m_parent_validation_wait_start{};
    bool m_parent_validation_wait_active{false};
    static constexpr int PARENT_VALIDATION_TIMEOUT_SECS = 30;  // Max wait before escalation

    // BUG #158 FIX: Fork detection state
    // THREAD SAFETY FIX: Using atomic for thread-safe access
    std::atomic<int> m_fork_stall_cycles{0};  // Cycles where blocks aren't connecting
    std::atomic<bool> m_fork_detected{false}; // Whether we've detected a fork
    std::atomic<int> m_fork_point{-1};        // Height of common ancestor

    // THREE-LAYER FORK DETECTION (Professional fix)
    // Layer 1: Proactive O(1) chain mismatch (handled inline in DownloadBlocks)
    // Layer 2: Orphan block counter - consecutive orphans suggest fork
    std::atomic<int> m_consecutive_orphan_blocks{0};
    static constexpr int ORPHAN_FORK_THRESHOLD = 5;   // A3: Trigger fork check after 5 consecutive orphans (was 10)
    // B3: Block-flow timestamp for flow-aware Layer 3 gating
    // Uses atomic<int64_t> (steady_clock ticks) to avoid data race between
    // block-processing threads (write) and IBD thread (read).
    std::atomic<int64_t> m_last_block_connected_ticks;
    // Layer 3: Deep fork handling - requires manual reindex for security
    bool m_requires_reindex{false};
    // Max blocks to auto-reorg in place. Tracks the consensus reorg cap
    // (Consensus::MAX_REORG_DEPTH, currently 60) so the cheap in-place
    // DisconnectToHeight recovery branch fires for EVERY fork the consensus
    // cap will accept. If this exceeded the cap, forks in the (cap, this]
    // band would skip in-place recovery, get consensus-rejected, and force a
    // wasteful full datadir wipe + genesis re-sync.
    static constexpr int MAX_AUTO_REORG_DEPTH = Consensus::MAX_REORG_DEPTH;

    // Resync tracking for completion message
    bool m_resync_in_progress{false};
    int m_resync_fork_point{0};
    int m_resync_original_height{0};
    int m_resync_target_height{0};

    // Fork detection frequency control (reduce CPU overhead)
    // PERFORMANCE FIX: Increased thresholds to prevent triggering during normal validation lag
    // Normal IBD has 2-10 second validation lag - don't misinterpret as fork
    int m_last_checked_chain_height{-1};      // Last chain height when fork detection ran
    static constexpr int FORK_DETECTION_THRESHOLD = 60;  // Cycles before triggering fork detection (was 5)
    std::chrono::steady_clock::time_point m_last_fork_check;  // Issue #6: Throttle fork checks
    static constexpr int FORK_CHECK_MIN_INTERVAL_SECS = 30;   // Min seconds between fork checks (was 5)

    // BUG #261: Fork recovery cooldown - prevent re-creating fork candidate
    // for the same fork point after cancellation due to hash mismatches.
    // Without this, the node loops: create fork → mismatches → cancel → create again
    int m_last_cancelled_fork_point{-1};
    std::chrono::steady_clock::time_point m_fork_cancel_time;
    static constexpr int FORK_COOLDOWN_SECS = 60;  // 1 minute before retrying same fork point (was 300s, too long for VDF block times)

    // Issue #11 FIX: Request tracking as member variables (not static)
    int m_last_request_trigger{-1};
    bool m_initial_request_done{false};

    // Issue #7 FIX: Orphan scan frequency control
    std::chrono::steady_clock::time_point m_last_orphan_scan;
    static constexpr int ORPHAN_SCAN_INTERVAL_SECS = 30;      // Scan orphans every 30 seconds (was 10)

    // BUG #273: Fork recovery stuck when all fork blocks already in DB
    // Track consecutive cycles where all requested blocks are in DB but chain
    // can't advance (individual fork blocks have less work than current tip).
    // After threshold, escalate to DisconnectToHeight to roll back chain.
    int m_fork_all_in_db_cycles{0};
    static constexpr int MAX_FORK_ALL_IN_DB_CYCLES = 3;  // Escalate after 3 consecutive stuck cycles

    // BUG #278: Prevent infinite re-validation loop
    // Track block hashes that have been re-cleared by BUG #270 recovery and then
    // failed validation AGAIN. These blocks are genuinely invalid under current
    // consensus rules (not stale from an old binary) and must not be re-cleared.
    std::set<uint256> m_permanently_failed_blocks;

    // BUG #278: Remember last fork point where chain switch failed (consensus violation).
    // Prevents fork detection from re-detecting the same invalid fork.
    int m_last_failed_fork_point{-1};

    // BUG #278: Count consecutive cycles where all blocks in range are permanently invalid.
    // After threshold, clear stale headers to re-fetch from correct-chain peers.
    int m_perm_failed_stuck_cycles{0};

    // BUG #261 FIX: Startup grace period for fork detection
    // Skip fork detection during first N seconds after creation to allow:
    // - Header population from local blockchain to complete
    // - Peer connections to stabilize
    // - Headers chain to be fully indexed
    std::chrono::steady_clock::time_point m_creation_time;
    static constexpr int STARTUP_GRACE_PERIOD_SECS = 60;      // Skip fork detection for 60 seconds on startup
};

#endif // DILITHION_NODE_IBD_COORDINATOR_H

