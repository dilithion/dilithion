// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/ibd_coordinator.h>

#include <fstream>
#include <iostream>
#include <set>
#include <vector>

#include <consensus/chain.h>
#include <consensus/pow.h>  // BUG #245: ChainWorkGreaterThan for fork work comparison
#include <vdf/cooldown_tracker.h>  // Cooldown undo during re-validation
#include <core/chainparams.h>  // Initial header request needs genesis hash
#include <node/genesis.h>      // Genesis::GetGenesisHash()
#include <node/blockchain_storage.h>  // BUG #159: Orphan block deletion
#include <core/node_context.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // BUG FIX: Clear in-flight blocks on peer rotation
#include <net/headers_manager.h>
#include <net/net.h>  // CNetMessageProcessor
#include <net/connman.h>  // Phase 5: CConnman
#include <net/peers.h>
#include <net/protocol.h>
#include <node/block_validation_queue.h>  // Phase 2: Async block validation
#include <util/chain_reset.h>  // v4.0.19: WriteAutoRebuildMarker
#include <node/fork_manager.h>  // Validate-before-disconnect fork handling
#include <net/orphan_manager.h>  // IBD STUCK FIX #3: Periodic orphan scan
#include <node/block_processing.h>  // BUG #260: ProcessNewBlock for orphan re-processing
#include <node/mempool.h>  // Deep fork recovery: Clear mempool before disconnect
#include <util/logging.h>
#include <util/bench.h>  // Performance: Benchmarking
#include <api/metrics.h>  // Fork detection metrics

// IBD STUCK FIX #3: Access to global NodeContext for orphan manager
extern NodeContext g_node_context;

// Forward-declare NodeState for clean shutdown during deep fork resync
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};
    std::atomic<bool> mining_enabled{false};
    std::atomic<uint64_t> template_version{0};
    std::string mining_address_override;
    bool rotate_mining_address{false};
    class CRPCServer* rpc_server;
    class CMiningController* miner;
    class CWallet* wallet;
    class CSocket* p2p_socket;
    class CHttpServer* http_server;
};
extern NodeState g_node_state;

CIbdCoordinator::CIbdCoordinator(CChainState& chainstate, NodeContext& node_context)
    : m_chainstate(chainstate),
      m_node_context(node_context),
      m_last_ibd_attempt(std::chrono::steady_clock::time_point()),
      m_last_block_connected_ticks(std::chrono::steady_clock::now().time_since_epoch().count()),
      m_creation_time(std::chrono::steady_clock::now()) {}

void CIbdCoordinator::Tick() {
    // IBD DEBUG: Confirm Tick() is being called
    static int tick_count = 0;
    if (g_verbose.load(std::memory_order_relaxed) && (++tick_count <= 5 || tick_count % 60 == 0)) {
        std::cerr << "[IBD-DEBUG] Tick() called #" << tick_count << std::endl;
    }

    // Phase 5.1: Update state machine
    UpdateState();

    // BUG #248: Check if block validation signaled that we're syncing to a wrong chain.
    // When blocks fail MIK validation, it means we got headers from a peer on a different
    // chain. We need to switch to a different headers sync peer.
    if (g_node_context.headers_chain_invalid.exchange(false)) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Headers chain invalid flag set - switching headers sync peer" << std::endl;

        // Mark current sync peer as bad - they sent us headers leading to invalid blocks
        if (m_headers_sync_peer != -1) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Marking peer " << m_headers_sync_peer << " as bad (sent invalid chain headers)" << std::endl;
            m_headers_bad_peers.insert(m_headers_sync_peer);
        }

        // Clear headers above current chain height - they led to invalid blocks
        int chain_height = m_chainstate.GetHeight();
        if (m_node_context.headers_manager) {
            // Get the hash at chain_height to use as preferred (matches our valid chain)
            uint256 chainTipHash;
            CBlockIndex* pTip = m_chainstate.GetTip();
            if (pTip) {
                chainTipHash = pTip->GetBlockHash();
            }
            m_node_context.headers_manager->ClearAboveHeight(chain_height, chainTipHash);
        }

        // Reset sync state and switch to a different peer
        m_headers_sync_peer = -1;
        m_headers_sync_peer_consecutive_stalls = 0;
        m_initial_request_done = false;
        m_headers_in_flight = false;

        // SwitchHeadersSyncPeer will select a new peer (excluding bad peers) and request headers
        SwitchHeadersSyncPeer();
    }

    // Check if IBD components are available
    if (!m_node_context.headers_manager || !m_node_context.block_fetcher) {
        // IBD DEBUG: Log why we're returning early
        static int no_components_count = 0;
        if (g_verbose.load(std::memory_order_relaxed) && ++no_components_count <= 5) {
            std::cerr << "[IBD-DEBUG] Tick() returning: no headers_manager or block_fetcher" << std::endl;
        }
        return;
    }

    // =========================================================================
    // BUG #277 + v4.0.19: Auto-recovery from chain corruption
    // =========================================================================
    // Two failure modes feed into one recovery path:
    //   - NeedsUTXORebuild()  : ConnectTip's ApplyBlock fails repeatedly (BUG #277)
    //   - NeedsChainRebuild() : DisconnectTip's UndoBlock fails repeatedly on the
    //                           same hash (v4.0.19, incident 2026-04-25)
    // In either case we write the auto_rebuild marker file with a reason describing
    // which signal fired, then trigger graceful shutdown.
    {
        const bool utxo_rebuild = m_chainstate.NeedsUTXORebuild();
        const bool chain_rebuild = m_chainstate.NeedsChainRebuild();
        if (utxo_rebuild || chain_rebuild) {
            static bool recovery_triggered = false;
            if (!recovery_triggered) {
                recovery_triggered = true;
                std::cerr << "\n==========================================================" << std::endl;
                if (utxo_rebuild) {
                    std::cerr << "CRITICAL: UTXO corruption detected! Auto-recovery initiated." << std::endl;
                } else {
                    std::cerr << "CRITICAL: Persistent UndoBlock failure detected! Auto-recovery initiated." << std::endl;
                }
                std::cerr << "The node will shut down and rebuild on next restart." << std::endl;
                std::cerr << "==========================================================" << std::endl;

                std::string datadir;
                if (Dilithion::g_chainParams) {
                    datadir = Dilithion::g_chainParams->dataDir;
                }
                // Build combined reason when BOTH signals fire so operators see the
                // full picture in auto_rebuild (Cursor review feedback, 2026-04-25).
                std::string reason;
                const std::string heightStr = std::to_string(m_chainstate.GetHeight());
                if (utxo_rebuild && chain_rebuild) {
                    uint256 failing = m_chainstate.GetLastUndoFailureHash();
                    reason = "UTXO corruption AND persistent UndoBlock failure at height "
                             + heightStr + " hash=" + failing.GetHex();
                } else if (utxo_rebuild) {
                    reason = "UTXO corruption detected at height " + heightStr;
                } else {
                    uint256 failing = m_chainstate.GetLastUndoFailureHash();
                    reason = "Persistent UndoBlock failure at height "
                             + heightStr + " hash=" + failing.GetHex();
                }
                Dilithion::WriteAutoRebuildMarker(datadir, reason);

                g_node_state.running = false;
            }
            return;
        }
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();

    // =========================================================================
    // IBD PROGRESS DISPLAY (user-facing)
    // =========================================================================
    // Show sync progress every 30 seconds so new users know what's happening
    {
        static auto last_progress_time = std::chrono::steady_clock::now();
        static int last_progress_height = 0;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_progress_time).count();

        if (elapsed >= 30 && header_height > 0 && chain_height < header_height) {
            int blocks_per_sec = (elapsed > 0) ? (chain_height - last_progress_height) / elapsed : 0;
            int remaining = header_height - chain_height;
            int eta_seconds = (blocks_per_sec > 0) ? remaining / blocks_per_sec : 0;

            std::cout << "[Sync] Progress: " << chain_height << "/" << header_height
                      << " blocks (" << (header_height > 0 ? (chain_height * 100 / header_height) : 0) << "%)";
            if (blocks_per_sec > 0) {
                std::cout << " - " << blocks_per_sec << " blocks/sec";
                if (eta_seconds > 0) {
                    int mins = eta_seconds / 60;
                    int secs = eta_seconds % 60;
                    if (mins > 0) {
                        std::cout << " - ~" << mins << "m " << secs << "s remaining";
                    } else {
                        std::cout << " - ~" << secs << "s remaining";
                    }
                }
            }
            std::cout << std::endl;

            last_progress_time = now;
            last_progress_height = chain_height;
        }
    }

    // =========================================================================
    // BITCOIN CORE STYLE SINGLE-SYNC-PEER HEADERS MANAGEMENT
    // =========================================================================

    // 1. Select a headers sync peer if we don't have one
    SelectHeadersSyncPeer();

    // 2. Check if current sync peer is making progress (or stalled)
    if (!CheckHeadersSyncProgress()) {
        // Sync peer stalled, switch to a different one
        SwitchHeadersSyncPeer();
    }

    // 3. Request initial headers if we have none
    // PIPELINE: After initial request, headers_manager handles prefetch on RECEIPT
    if (m_headers_sync_peer != -1) {
        // BUG FIX: Use best_known_height for dynamic peer height
        auto sync_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = sync_peer ? (sync_peer->best_known_height > 0 ? sync_peer->best_known_height : sync_peer->start_height)
                                    : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);

        if (!m_initial_request_done && header_height <= 0 && peer_height > 0) {
            // Initial request - kick off the pipeline via SSOT entry point
            m_initial_request_done = true;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Initial header request from sync peer " << m_headers_sync_peer
                          << " (peer_height=" << peer_height << ")" << std::endl;
            if (m_node_context.headers_manager->SyncHeadersFromPeer(m_headers_sync_peer, peer_height)) {
                m_headers_in_flight = true;
            }
            // IMPORTANT: Return here to prevent catch-up logic from firing in same tick
            // before first batch arrives and sets m_last_request_hash
            return;
        }
        // Note: Subsequent header requests are triggered by headers_manager's
        // SyncHeadersFromPeer() when headers are RECEIVED (not validated).
        // This creates a pipeline where we request batch N+1 while validating batch N.
    }

    // =========================================================================

    // If headers are not ahead, check if any peer has more blocks we need
    if (header_height <= chain_height) {
        // Check if any peer has higher height than our headers
        // This catches the case where we're "synced" but a miner just found new blocks
        static auto last_catchup_request = std::chrono::steady_clock::time_point();
        auto now_catchup = std::chrono::steady_clock::now();

        // Rate limit: only check for catchup every 2 seconds to prevent spam
        if (now_catchup - last_catchup_request > std::chrono::seconds(2)) {
            last_catchup_request = now_catchup;  // Update FIRST to guarantee rate limit
            if (m_node_context.peer_manager && m_node_context.headers_manager) {
                auto peers = m_node_context.peer_manager->GetConnectedPeers();
                int best_peer = -1;
                int best_height = header_height;

                for (const auto& peer : peers) {
                    if (!peer) continue;
                    // BUG FIX: Use best_known_height (updated dynamically) instead of
                    // GetPeerStartHeight (static from connection time). After reorg,
                    // peers may have advanced but start_height wouldn't reflect that.
                    int peer_height = peer->best_known_height;
                    if (peer_height == 0) peer_height = peer->start_height;
                    if (peer_height > best_height) {
                        best_height = peer_height;
                        best_peer = peer->id;
                    }
                }

                // SSOT: Just ask HeadersManager to sync - it handles all dedup internally
                // BUT: Only request if we don't have an outstanding prefetch
                // (prefetch is in progress when requested_height > validated_height)
                int requested_height = m_node_context.headers_manager->GetRequestedHeight();
                int validated_height = m_node_context.headers_manager->GetBestHeight();
                if (best_peer != -1 && requested_height <= validated_height) {
                    m_headers_sync_peer = best_peer;
                    m_node_context.headers_manager->SyncHeadersFromPeer(best_peer, best_height);
                }
            }
        }

        static int synced_count = 0;
        if (g_verbose.load(std::memory_order_relaxed) && (++synced_count <= 5 || synced_count % 60 == 0)) {
            std::cerr << "[IBD-DEBUG] Tick() returning: synced (header=" << header_height
                      << " <= chain=" << chain_height << ")" << std::endl;
        }
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;

            // Show resync completion summary if we just finished a resync
            if (m_resync_in_progress) {
                m_resync_in_progress = false;
                int blocks_recovered = m_resync_fork_point;  // Blocks that were on both chains
                int blocks_lost = m_resync_original_height - m_resync_fork_point;  // Forked blocks

                std::cout << "\n" << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << "                    RESYNC COMPLETE" << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << std::endl;
                std::cout << "  Chain Status:" << std::endl;
                std::cout << "    Current height:    " << chain_height << " blocks" << std::endl;
                std::cout << "    Synced with:       " << header_height << " network headers" << std::endl;
                std::cout << std::endl;
                std::cout << "  Fork Recovery Summary:" << std::endl;
                std::cout << "    Fork point:        Block " << m_resync_fork_point << std::endl;
                std::cout << "    Blocks preserved:  " << blocks_recovered << " (heights 0-" << m_resync_fork_point << ")" << std::endl;
                std::cout << "    Blocks discarded:  " << blocks_lost << " (were on fork)" << std::endl;
                std::cout << std::endl;
                std::cout << "  Wallet Status:" << std::endl;
                std::cout << "    Private keys:      SAFE (unchanged)" << std::endl;
                std::cout << "    Balance:           Recalculated from correct chain" << std::endl;
                std::cout << "    Mining rewards from forked blocks are no longer valid." << std::endl;
                std::cout << "    Your balance now reflects only confirmed transactions" << std::endl;
                std::cout << "    on the main network chain." << std::endl;
                std::cout << std::endl;
                std::cout << "════════════════════════════════════════════════════════════" << std::endl;
                std::cout << std::endl;
            }
        }
        return;
    }

    ResetBackoffOnNewHeaders(header_height);

    auto now = std::chrono::steady_clock::now();
    if (!ShouldAttemptDownload()) {
        // IBD DEBUG: Log why we're returning early
        static int backoff_count = 0;
        if (g_verbose.load(std::memory_order_relaxed) && (++backoff_count <= 5 || backoff_count % 60 == 0)) {
            std::cerr << "[IBD-DEBUG] Tick() returning: ShouldAttemptDownload=false (backoff)" << std::endl;
        }
        return;
    }

    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 0;

    if (peer_count == 0) {
        HandleNoPeers(now);
        return;
    }

    if (m_ibd_no_peer_cycles > 0) {
        m_ibd_no_peer_cycles = 0;
    }

    BENCHMARK_START("ibd_tick");
    DownloadBlocks(header_height, chain_height, now);
    BENCHMARK_END("ibd_tick");
}

void CIbdCoordinator::UpdateState() {
    if (!m_node_context.headers_manager) {
        m_state = IBDState::IDLE;
        m_synced.store(false, std::memory_order_release);
        return;
    }

    int header_height = m_node_context.headers_manager->GetBestHeight();
    int chain_height = m_chainstate.GetHeight();
    size_t peer_count = m_node_context.peer_manager ? m_node_context.peer_manager->GetConnectionCount() : 0;

    // =========================================================================
    // SYNC STATE DETECTION WITH HYSTERESIS
    // =========================================================================
    // Uses different thresholds for entering vs leaving synced state to prevent
    // flapping when chain height oscillates near header height.
    //
    // - Become synced: chain within SYNC_TOLERANCE_BLOCKS (2) of headers
    // - Become un-synced: chain more than UNSYNC_THRESHOLD_BLOCKS (10) behind
    //
    // This is thread-safe: m_synced is atomic, only written here (main thread).
    // =========================================================================

    bool currently_synced = m_synced.load(std::memory_order_acquire);
    int blocks_behind = header_height - chain_height;

    // Guard: Don't declare synced until we've heard from at least one peer.
    // At startup, header_height == chain_height (headers populated from local chain),
    // so blocks_behind == 0 which would incorrectly trigger SYNCED before any peer
    // has told us the real network tip.
    bool has_peer_info = m_node_context.peer_manager &&
                         m_node_context.peer_manager->HasCompletedHandshakes();

    if (currently_synced) {
        // Already synced - only become un-synced if significantly behind
        if (blocks_behind > UNSYNC_THRESHOLD_BLOCKS) {
            m_synced.store(false, std::memory_order_release);
            std::cout << "[IBD] Sync state: SYNCED -> NOT SYNCED (chain " << blocks_behind
                      << " blocks behind headers)" << std::endl;
        }
    } else {
        // Not synced - become synced if within tolerance AND we've heard from peers
        if (blocks_behind <= SYNC_TOLERANCE_BLOCKS && header_height > 0 && has_peer_info) {
            m_synced.store(true, std::memory_order_release);
            std::cout << "[IBD] Sync state: NOT SYNCED -> SYNCED (chain within "
                      << SYNC_TOLERANCE_BLOCKS << " blocks of headers)" << std::endl;
        }
    }

    // Determine IBD state based on current conditions
    if (header_height <= chain_height) {
        if (m_state != IBDState::IDLE && m_state != IBDState::COMPLETE) {
            m_state = IBDState::COMPLETE;
        }
    } else if (peer_count == 0) {
        m_state = IBDState::WAITING_FOR_PEERS;
    } else if (header_height > chain_height + 10) {
        // If headers are significantly ahead, we're in headers sync phase
        // (though headers sync happens in headers_manager, not here)
        m_state = IBDState::BLOCKS_DOWNLOAD;
    } else {
        m_state = IBDState::BLOCKS_DOWNLOAD;
    }
}

std::string CIbdCoordinator::GetStateName() const {
    switch (m_state) {
        case IBDState::IDLE: return "IDLE";
        case IBDState::WAITING_FOR_PEERS: return "WAITING_FOR_PEERS";
        case IBDState::HEADERS_SYNC: return "HEADERS_SYNC";
        case IBDState::BLOCKS_DOWNLOAD: return "BLOCKS_DOWNLOAD";
        case IBDState::COMPLETE: return "COMPLETE";
        default: return "UNKNOWN";
    }
}

bool CIbdCoordinator::IsSynced() const {
    return m_synced.load(std::memory_order_acquire);
}

bool CIbdCoordinator::IsInitialBlockDownload() const {
    return !IsSynced();
}

void CIbdCoordinator::ResetBackoffOnNewHeaders(int header_height) {
    if (header_height > m_last_header_height) {
        m_ibd_no_peer_cycles = 0;
        m_last_ibd_attempt = std::chrono::steady_clock::time_point();
    }
    m_last_header_height = header_height;
}

bool CIbdCoordinator::ShouldAttemptDownload() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_last_ibd_attempt);

    // IBD HANG FIX #1: Gradual backpressure instead of binary stop
    // Previously: queue > 80 = complete stop (binary)
    // Now: gradual rate reduction based on queue depth
    // - Queue 0-70: Full speed (1.0x)
    // - Queue 70-80: Reduced speed (0.5x)
    // - Queue 80-90: Further reduced (0.25x)
    // - Queue 90-95: Minimal speed (0.1x)
    // - Queue 95+: Complete stop
    if (m_node_context.validation_queue && m_node_context.validation_queue->IsRunning()) {
        size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
        if (queue_depth >= 95) {
            // Queue nearly full - complete stop
            m_last_hang_cause = HangCause::VALIDATION_QUEUE_FULL;
            LogPrintIBD(DEBUG, "Validation queue depth %zu - stopping downloads (queue nearly full)", queue_depth);
            return false;
        }
        // For queue 70-95, we'll use rate multiplier in DownloadBlocks()
        // Still return true here, but rate will be reduced
    }

    // BUG #147 FIX: During active IBD (blocks download), be aggressive - minimal backoff
    // Only use exponential backoff when truly stuck (no work available, no peers)
    int backoff_seconds;
    if (m_state == IBDState::BLOCKS_DOWNLOAD) {
        // During IBD: 1 second between attempts, even if peer selection failed once
        backoff_seconds = 1;
    } else {
        // Not in IBD: use exponential backoff (1, 2, 4, 8, 16, 30 seconds)
        backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
    }

    bool should_attempt = elapsed.count() >= backoff_seconds;
    if (!should_attempt) {
        m_last_hang_cause = HangCause::NONE;  // Just waiting for backoff
    }
    return should_attempt;
}

double CIbdCoordinator::GetDownloadRateMultiplier() const {
    // IBD HANG FIX #1: Gradual backpressure - returns multiplier (0.0-1.0)
    // Used to reduce request rate gradually instead of binary stop
    
    if (!m_node_context.validation_queue || !m_node_context.validation_queue->IsRunning()) {
        return 1.0;  // No validation queue - full speed
    }
    
    size_t queue_depth = m_node_context.validation_queue->GetQueueDepth();
    
    // Gradual backpressure zones
    if (queue_depth < 70) {
        return 1.0;  // Full speed
    } else if (queue_depth < 80) {
        return 0.5;  // Half speed
    } else if (queue_depth < 90) {
        return 0.25;  // Quarter speed
    } else if (queue_depth < 95) {
        return 0.1;  // Minimal speed
    } else {
        return 0.0;  // Should have been caught by ShouldAttemptDownload(), but return 0 for safety
    }
}

void CIbdCoordinator::HandleNoPeers(std::chrono::steady_clock::time_point now) {
    if (m_ibd_no_peer_cycles == 0) {
        LogPrintIBD(WARN, "No peers available for block download - entering backoff mode");
    }
    m_ibd_no_peer_cycles++;
    m_last_ibd_attempt = now;

    if (m_ibd_no_peer_cycles % 10 == 0) {
        int backoff_seconds = std::min(30, (1 << std::min(m_ibd_no_peer_cycles, 5)));
        LogPrintIBD(INFO, "Still waiting for peers (backoff: %ds, attempts: %d)", backoff_seconds, m_ibd_no_peer_cycles);
    }
}

void CIbdCoordinator::DownloadBlocks(int header_height, int chain_height,
                                     std::chrono::steady_clock::time_point now) {
    // IBD DEBUG: Track entry into DownloadBlocks
    if (g_verbose.load(std::memory_order_relaxed))
        std::cerr << "[IBD-DEBUG] DownloadBlocks entered: header=" << header_height << " chain=" << chain_height << std::endl;

    // Bug #150: Log fork status periodically (every 100 calls)
    static size_t download_call_count = 0;
    if (++download_call_count % 100 == 0 && m_node_context.headers_manager) {
        if (m_node_context.headers_manager->HasCompetingForks()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Fork status: " << m_node_context.headers_manager->GetForkCount()
                          << " competing chain tips detected" << std::endl;
        }
    }

    BENCHMARK_START("ibd_download_blocks");
    m_last_ibd_attempt = now;

    // Only log download status when chain height changes to reduce log spam
    static int s_last_logged_chain_height = -1;
    if (chain_height != s_last_logged_chain_height) {
        LogPrintIBD(INFO, "Headers ahead of chain - downloading blocks (header=%d chain=%d)", header_height, chain_height);
        s_last_logged_chain_height = chain_height;
    }

    // ============================================================================
    // LAYER 1: PROACTIVE CHAIN MISMATCH DETECTION (O(1) - runs every tick)
    // ============================================================================
    // This catches the case where we're on a stale fork IMMEDIATELY, without
    // waiting for stall detection. Critical for nodes that synced to a fork.
    //
    // BUG #250 FIX: Only run Layer 1 when near tip (same guard as Layer 3).
    // During bulk IBD, fresh nodes are thousands of blocks behind and will
    // always have mismatched hashes. This causes false-positive fork detection.
    // Checkpoints + PoW validation are sufficient protection during IBD.
    //
    // BUG #261 FIX: Skip Layer 1 during startup grace period.
    // During the first 10 seconds after coordinator creation, headers from the
    // local blockchain may not be fully indexed. This causes false fork detection
    // when GetRandomXHashAtHeight() returns the wrong hash.

    // BUG #261: Check if we're still in the startup grace period
    auto elapsed_secs = std::chrono::duration_cast<std::chrono::seconds>(now - m_creation_time).count();
    bool past_startup_grace = (elapsed_secs >= STARTUP_GRACE_PERIOD_SECS);

    // BUG #282 FIX: Suppress fork detection during bulk IBD.
    // During fresh IBD (chain far behind headers), hash comparisons always mismatch
    // because blocks haven't been validated yet. This caused false-positive fork
    // detection, constant peer disconnections, and extremely slow sync (109 blocks
    // in 30 minutes for a 5800-block chain). Checkpoints + PoW validation are
    // sufficient protection during IBD. Fork detection only needed near tip.
    bool bulk_ibd = (header_height - chain_height > 100);

    bool has_headers = (header_height >= chain_height && chain_height > 0);

    if (past_startup_grace && has_headers && !bulk_ibd && m_node_context.headers_manager && !m_fork_detected.load()) {
        CBlockIndex* tip = m_chainstate.GetTip();
        if (tip) {  // Only check if we have a valid tip
            uint256 our_tip_hash = tip->GetBlockHash();
            uint256 header_hash_at_our_height = m_node_context.headers_manager->GetRandomXHashAtHeight(chain_height);

            if (!header_hash_at_our_height.IsNull() && !our_tip_hash.IsNull() && our_tip_hash != header_hash_at_our_height) {
            // CHAIN MISMATCH: Our tip doesn't match the header chain at the same height
            // This means we're on a fork - trigger immediate detection
            if (g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "\n[FORK-DETECT] ════════════════════════════════════════════════════" << std::endl;
                std::cout << "[FORK-DETECT] CHAIN MISMATCH DETECTED (Layer 1 - Proactive)" << std::endl;
                std::cout << "[FORK-DETECT] Our chain tip at height " << chain_height << ":" << std::endl;
                std::cout << "[FORK-DETECT]   Local:  " << our_tip_hash.GetHex().substr(0, 16) << "..." << std::endl;
                std::cout << "[FORK-DETECT]   Header: " << header_hash_at_our_height.GetHex().substr(0, 16) << "..." << std::endl;
            }
            // B1: Route all recovery through unified AttemptForkRecovery pipeline
            // BUG FIX: Never return early here. Previously, when AttemptForkRecovery
            // returned true, DownloadBlocks exited immediately, skipping FetchBlocks()
            // at line 675. This meant blocks from the correct chain were never requested.
            // Now we always fall through to FetchBlocks regardless of recovery result.
            if (AttemptForkRecovery(chain_height, header_height, ForkRecoveryReason::LAYER1_TIP_MISMATCH)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Fork recovery initiated/active - continuing to fetch blocks" << std::endl;
            } else {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Recovery not initiated - continuing block download" << std::endl;
            }
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-DETECT] ════════════════════════════════════════════════════\n" << std::endl;
            }
        }
    }

    // ============================================================================
    // LAYER 2: ORPHAN BLOCK DETECTION (checked via m_consecutive_orphan_blocks)
    // ============================================================================
    // If we've received many consecutive orphan blocks, this is conclusive evidence
    // of being on a stale fork. Trigger fork recovery immediately - don't wait for
    // Layer 3's 60-cycle stall threshold (which can deadlock due to counter resets).
    //
    // BUG #261 FIX: Skip Layer 2 during startup grace period
    // BUG #282 FIX: Skip Layer 2 during bulk IBD (orphans are normal during IBD)
    int orphan_count = m_consecutive_orphan_blocks.load();
    bool force_fork_check = orphan_count >= ORPHAN_FORK_THRESHOLD;
    if (past_startup_grace && !bulk_ibd && force_fork_check && !m_fork_detected.load()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-DETECT] Layer 2 triggered: " << m_consecutive_orphan_blocks.load()
                      << " consecutive orphan blocks received - attempting immediate fork recovery" << std::endl;
        m_consecutive_orphan_blocks.store(0);  // Reset counter

        if (AttemptForkRecovery(chain_height, header_height, ForkRecoveryReason::LAYER2_ORPHAN_STREAK)) {
            // Fork recovery initiated or already active - skip Layer 3
        }
    } else if (force_fork_check) {
        m_consecutive_orphan_blocks.store(0);  // Reset even if fork already detected
    }

    // ============================================================================
    // LAYER 3: STALL-BASED DETECTION (safety net for cases Layer 2 doesn't catch)
    // ============================================================================
    // B3: Flow-aware gating - suppress stall detection only when blocks are actively connecting
    // Old guard (near_tip < 100) permanently disabled Layer 3 during bulk IBD, even when stalled on a fork.
    // New guard: suppress only when blocks are actively flowing (last OnBlockConnected < 30s ago).
    auto now_ticks = now.time_since_epoch().count();
    auto last_ticks = m_last_block_connected_ticks.load();
    auto since_last_block = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::duration(now_ticks - last_ticks)).count();
    bool blocks_flowing = (since_last_block < 30);

    if (blocks_flowing && !force_fork_check) {
        // Blocks actively connecting - IBD is progressing, skip stall detection
        m_fork_stall_cycles.store(0);
    } else if (m_last_checked_chain_height == chain_height && !m_fork_detected.load()) {
        // Chain height hasn't advanced since last tick
        m_fork_stall_cycles.fetch_add(1);
        int stall_cycles = m_fork_stall_cycles.load();

        // Check if there's IBD activity (blocks pending or in-flight)
        bool has_ibd_activity = false;
        if (m_node_context.block_fetcher) {
            has_ibd_activity = m_node_context.block_fetcher->GetPendingCount() > 0 ||
                              m_node_context.block_fetcher->GetInFlightCount() > 0;
        }

        // BUG #261 FIX: Skip Layer 3 during startup grace period
        // BUG #282 FIX: Skip Layer 3 during bulk IBD
        if (past_startup_grace && !bulk_ibd && has_ibd_activity && stall_cycles >= FORK_DETECTION_THRESHOLD) {
            // Issue #6 FIX: Throttle fork detection to avoid CPU overhead
            auto now_check = std::chrono::steady_clock::now();
            auto elapsed_check = std::chrono::duration_cast<std::chrono::seconds>(now_check - m_last_fork_check).count();
            if (elapsed_check >= FORK_CHECK_MIN_INTERVAL_SECS) {
                m_last_fork_check = now_check;

                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Layer 3: Chain stalled at height " << chain_height
                              << " for " << stall_cycles << " cycles - attempting fork recovery..." << std::endl;

                AttemptForkRecovery(chain_height, header_height, ForkRecoveryReason::LAYER3_STALL_TIMEOUT);
            }
        }
    } else {
        // Chain is advancing - reset stall detection
        m_fork_stall_cycles.store(0);
        int current_fork_point = m_fork_point.load();
        if (m_fork_detected.load() && chain_height > current_fork_point) {
            // BUG FIX: Verify we're on the correct chain before clearing fork state.
            // Previously, this only checked chain_height > fork_point, which is always
            // true when ON a fork (you're above the fork point, on the wrong chain).
            // Now we verify our tip hash matches the header chain's hash at the same height.
            bool on_correct_chain = false;
            if (m_node_context.headers_manager) {
                CBlockIndex* tip = m_chainstate.GetTip();
                if (tip) {
                    uint256 our_hash = tip->GetBlockHash();
                    uint256 header_hash = m_node_context.headers_manager->GetRandomXHashAtHeight(chain_height);
                    on_correct_chain = (!header_hash.IsNull() && our_hash == header_hash);
                }
            }

            // Guard against premature completion during deep resync:
            // After DisconnectToHeight, chain_height may be just above fork_point
            // on the correct chain, but we're not done syncing yet.
            if (on_correct_chain && m_resync_in_progress) {
                int header_tip = m_node_context.headers_manager ?
                    m_node_context.headers_manager->GetBestHeight() : 0;
                if (chain_height < header_tip - SYNC_TOLERANCE_BLOCKS) {
                    on_correct_chain = false;  // Still syncing, not done yet
                }
            }

            if (on_correct_chain) {
                // Actually recovered - clear fork state
                if (m_resync_in_progress) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[FORK-RECOVERY] Deep resync complete: "
                                  << m_resync_fork_point << " -> " << chain_height << std::endl;
                    m_resync_in_progress = false;
                }
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-RECOVERY] Chain advanced past fork point " << current_fork_point
                              << " to " << chain_height << " - fork recovery complete (hash verified)" << std::endl;
                m_fork_detected.store(false);
                g_node_context.fork_detected.store(false);  // Clear global flag so mining can resume
                g_metrics.ClearForkDetected();  // Clear Prometheus metrics
                m_fork_point.store(-1);
                m_last_cancelled_fork_point = -1;  // BUG #261: Clear cooldown
            } else if (!ForkManager::GetInstance().HasActiveFork()) {
                // BUG FIX: Fork switch succeeded (chain advanced past fork_point) but
                // orphan cascade put us on a different wrong chain. With no active fork
                // and m_fork_detected=true, all 3 detection layers are blocked by the
                // !m_fork_detected guard. Clear m_fork_detected so Layer 1 can detect
                // the new chain mismatch and initiate a fresh fork recovery.
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-RECOVERY] Chain past fork point " << current_fork_point
                              << " but hash mismatch at height " << chain_height
                              << " with no active fork - clearing for re-detection" << std::endl;
                m_fork_detected.store(false);
                g_node_context.fork_detected.store(false);
                g_metrics.ClearForkDetected();
                m_fork_point.store(-1);
            }
        }
    }

    // BUG #261: Clear cooldown if chain advanced past the cancelled fork point.
    // CRITICAL: This MUST run unconditionally (outside the if/else-if/else above).
    // Previously it was inside the "chain advancing" else branch, which never executes
    // when the chain is stalled on a fork — exactly when cooldown clearance is needed.
    if (m_last_cancelled_fork_point >= 0 && chain_height > m_last_cancelled_fork_point) {
        m_last_cancelled_fork_point = -1;
    }

    // BUG #278: Clear failed fork point when chain advances past it.
    // This allows fresh fork detection for new forks at different points.
    if (m_last_failed_fork_point >= 0 && chain_height > m_last_failed_fork_point) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Chain advanced past failed fork point " << m_last_failed_fork_point
                      << " - clearing BUG #278 suppression" << std::endl;
        m_last_failed_fork_point = -1;
    }

    m_last_checked_chain_height = chain_height;

    // FORK TIMEOUT CHECK: Check active fork timeout independently of detection layers.
    // Once a fork is active, Layer 3's !m_fork_detected guard prevents AttemptForkRecovery
    // from being called, so CheckTimeout() never fires. Check it here every tick.
    {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork() && forkMgr.CheckTimeout()) {
            auto activeFork = forkMgr.GetActiveFork();
            int receivedCount = activeFork ? activeFork->GetReceivedBlockCount() : 0;
            int cancelPoint = activeFork ? activeFork->GetForkPointHeight() : chain_height;
            int timeoutSecs = activeFork ? activeFork->GetTimeoutSeconds() : 60;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Active fork timed out (" << timeoutSecs << "s) with " << receivedCount
                          << " received blocks - cancelling" << std::endl;
            forkMgr.CancelFork("Timeout - no blocks delivered in " + std::to_string(timeoutSecs) + "s");
            forkMgr.ClearInFlightState(m_node_context, cancelPoint);
            m_fork_detected.store(false);
            g_node_context.fork_detected.store(false);
            g_metrics.ClearForkDetected();
            m_fork_point.store(-1);
            m_last_cancelled_fork_point = cancelPoint;
            m_fork_cancel_time = std::chrono::steady_clock::now();
            m_fork_stall_cycles.store(0);

            // BUG #279 FIX (Option B): After fork cancellation, check if there are
            // orphan blocks whose parents we can now request. This handles the case
            // where blocks arrived during the fork window but their parents (VDF
            // replacement blocks at the same height) were never fetched.
            if (m_node_context.orphan_manager && m_blocks_sync_peer != -1) {
                auto orphans = m_node_context.orphan_manager->GetAllOrphans();
                int requested = 0;
                for (const auto& orphanHash : orphans) {
                    CBlock orphanBlock;
                    if (m_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                        CBlockIndex* pParent = m_chainstate.GetBlockIndex(orphanBlock.hashPrevBlock);
                        if (!pParent) {
                            // Parent missing — request it
                            int ph = cancelPoint;  // Best guess for height
                            if (m_node_context.headers_manager) {
                                int hh = m_node_context.headers_manager->GetHeightForHash(orphanBlock.hashPrevBlock);
                                if (hh > 0) ph = hh;
                            }
                            if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, ph, orphanBlock.hashPrevBlock)) {
                                CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(
                                    {{NetProtocol::MSG_BLOCK_INV, orphanBlock.hashPrevBlock}});
                                m_node_context.connman->PushMessage(m_blocks_sync_peer, msg);
                                requested++;
                                if (requested >= 3) break;  // Rate limit: max 3 parent requests per cancellation
                            }
                        }
                    }
                }
                if (requested > 0) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Post-cancel: Requested " << requested
                                  << " missing parent blocks for stranded orphans" << std::endl;
                }
            }
        }
    }

    // IBD HANG FIX #1: Apply gradual backpressure rate multiplier
    // Reduces request rate gradually as validation queue fills, preventing binary stop/resume cycle
    double rate_multiplier = GetDownloadRateMultiplier();

    // PURE PER-BLOCK: No more window or queue population needed
    // GetNextBlocksToRequest() directly iterates from chain_height+1 to header_height
    // (download status already logged above when chain height changes)

    BENCHMARK_START("ibd_fetch_blocks");
    bool any_requested = FetchBlocks();
    BENCHMARK_END("ibd_fetch_blocks");
    if (!any_requested) {
        m_ibd_no_peer_cycles++;
        // IBD HANG FIX #6: Log specific hang cause (only on state change to reduce spam)
        std::string cause_str = "unknown";
        switch (m_last_hang_cause) {
            case HangCause::VALIDATION_QUEUE_FULL: cause_str = "validation queue full"; break;
            case HangCause::NO_PEERS_AVAILABLE: cause_str = "no peers available"; break;
            case HangCause::PEERS_AT_CAPACITY: cause_str = "all peers at capacity"; break;
            case HangCause::WAITING_ON_PARENT_VALIDATION: cause_str = "parent block awaiting validation"; break;
            case HangCause::NONE: cause_str = "no suitable peers"; break;
        }
        // Throttle: only log every 30s to avoid spam during normal IBD backpressure
        static auto s_last_capacity_log = std::chrono::steady_clock::time_point{};
        auto log_now = std::chrono::steady_clock::now();
        if (s_last_capacity_log == std::chrono::steady_clock::time_point{} ||
            std::chrono::duration_cast<std::chrono::seconds>(log_now - s_last_capacity_log).count() >= 30) {
            LogPrintIBD(WARN, "Could not send any block requests - %s", cause_str.c_str());
            s_last_capacity_log = log_now;
        }

        // CAPACITY STALL FIX: If peer stays "at capacity" for too many consecutive ticks
        // without delivering any blocks, the peer is likely dead/unresponsive.
        // Clear in-flight blocks, disconnect the peer, and force reselection.
        // Disconnecting (vs just rotating) ensures the TCP connection is reset and the
        // peer reconnects fresh through the normal connection cycle.
        if (m_last_hang_cause == HangCause::PEERS_AT_CAPACITY) {
            m_consecutive_capacity_stalls++;
            // Manual peers (--connect/--addnode) get 3x tolerance before disconnect
            // They may be slow when serving multiple concurrent IBD miners
            CNode* sync_node = (m_node_context.connman && m_blocks_sync_peer != -1)
                ? m_node_context.connman->GetNode(m_blocks_sync_peer) : nullptr;
            int max_stalls = (sync_node && sync_node->fManual) ? 45 : MAX_CAPACITY_STALLS_BEFORE_CLEAR;
            if (m_consecutive_capacity_stalls >= max_stalls &&
                m_blocks_sync_peer != -1) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Peer " << m_blocks_sync_peer
                              << " at capacity for " << m_consecutive_capacity_stalls
                              << "s without delivering blocks - disconnecting unresponsive peer"
                              << std::endl;
                if (g_node_context.block_tracker) {
                    auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                    if (!cleared.empty()) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Cleared " << cleared.size()
                                      << " stale in-flight blocks from peer "
                                      << m_blocks_sync_peer << std::endl;
                    }
                }
                // Disconnect the unresponsive peer - forces TCP reconnection
                if (m_node_context.connman) {
                    m_node_context.connman->DisconnectNode(m_blocks_sync_peer, "block delivery stall");
                }
                // Put peer on short cooldown (60s) - may just be temporarily slow
                m_timed_out_peer = m_blocks_sync_peer;
                m_timed_out_peer_time = std::chrono::steady_clock::now();
                m_timed_out_peer_cooldown_sec = CAPACITY_STALL_COOLDOWN_SEC;
                m_blocks_sync_peer = -1;
                m_consecutive_capacity_stalls = 0;
            }
        } else {
            m_consecutive_capacity_stalls = 0;
        }
    } else {
        m_last_hang_cause = HangCause::NONE;  // Clear hang cause on success
        m_parent_validation_wait_active = false;  // Reset validation wait on progress
        m_waiting_parent_height = -1;
        m_waiting_parent_hash = uint256{};
        // BUG FIX: Only reset capacity stall counter when chain actually advances.
        // Sending new GETDATA (triggered by incoming headers) doesn't prove the peer
        // is delivering blocks. Without this, incoming headers repeatedly reset the
        // 15s stall recovery counter, causing permanent stalls near the tip.
        if (chain_height > m_last_stall_check_height) {
            m_consecutive_capacity_stalls = 0;
            m_last_stall_check_height = chain_height;
        }
    }

    // FORK FIX: Check if fork is ready for chain switch after feeding blocks from DB
    // This handles the case where all fork blocks were already in DB (arrived as orphans
    // before fork detection). FetchBlocks above feeds them to ForkManager; now check
    // if the fork has enough work to trigger a chain switch.
    {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork()) {
            auto fork = forkMgr.GetActiveFork();
            if (fork && fork->AllReceivedBlocksPrevalidated()) {
                int32_t tipHeight = fork->GetHighestPrevalidatedHeight();
                if (tipHeight > 0) {
                    ForkBlock* tipBlock = fork->GetBlockAtHeight(tipHeight);
                    if (tipBlock) {
                        CBlockIndex* forkIndex = m_chainstate.GetBlockIndex(tipBlock->hash);
                        CBlockIndex* currentTip = m_chainstate.GetTip();
                        if (forkIndex && currentTip &&
                            currentTip->nChainWork < forkIndex->nChainWork) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] Fork ready with more work (fork="
                                          << forkIndex->nChainWork.GetHex().substr(0, 16) << " current="
                                          << currentTip->nChainWork.GetHex().substr(0, 16)
                                          << ") - triggering chain switch" << std::endl;
                            if (m_node_context.blockchain_db &&
                                forkMgr.TriggerChainSwitch(m_node_context, *m_node_context.blockchain_db)) {
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] Fork chain switch SUCCESSFUL!" << std::endl;
                                m_fork_detected.store(false);
                                g_node_context.fork_detected.store(false);
                                g_metrics.ClearForkDetected();
                            } else {
                                // BUG #278: Chain switch FAILED (consensus violation in fork chain).
                                // Record fork point so we don't re-detect and retry the same invalid fork.
                                int failedForkPoint = m_fork_point.load();
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] Fork chain switch FAILED at fork point " << failedForkPoint
                                              << " - marking fork as permanently invalid" << std::endl;
                                m_last_failed_fork_point = failedForkPoint;
                                m_fork_detected.store(false);
                                g_node_context.fork_detected.store(false);
                                g_metrics.ClearForkDetected();
                                m_fork_point.store(-1);
                            }
                        }
                    }
                }
            }
        }
    }

    // ORPHAN RESOLUTION: Periodically check for resolvable orphans.
    // When blocks arrive via INV before their parents during IBD, they become
    // orphans and their heights are marked "completed" in block_tracker (to prevent
    // re-request loops). But this also prevents GetNextBlocksToRequest from returning
    // those heights, causing a permanent deadlock: "no suitable peers" when all
    // orphan heights are completed but parents are already in the chain.
    //
    // Fix: Every 10s, if orphans exist and chain is STALLED (no progress for 30s),
    // try to resolve orphans whose parent is the chain tip, then clear completed
    // heights to unblock FetchBlocks.
    static auto last_orphan_scan = std::chrono::steady_clock::now();
    static int last_orphan_scan_height = -1;
    static auto chain_stall_start = std::chrono::steady_clock::now();
    auto now_orphan_scan = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now_orphan_scan - last_orphan_scan).count() >= 10) {
        last_orphan_scan = now_orphan_scan;

        int chain_height_snap = m_chainstate.GetHeight();
        int header_height_snap = m_node_context.headers_manager ? m_node_context.headers_manager->GetBestHeight() : 0;
        size_t orphan_count = g_node_context.orphan_manager ? g_node_context.orphan_manager->GetOrphanCount() : 0;

        // Track chain stall: reset timer when chain advances
        if (chain_height_snap != last_orphan_scan_height) {
            last_orphan_scan_height = chain_height_snap;
            chain_stall_start = now_orphan_scan;
        }
        auto stall_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            now_orphan_scan - chain_stall_start).count();

        if (orphan_count > 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Orphan pool: " << orphan_count << " blocks waiting for parents"
                          << " (stall=" << stall_seconds << "s)" << std::endl;
        }

        // Only attempt aggressive orphan resolution when chain is actually stalled.
        // During normal IBD, orphans are transient (parents arrive shortly after).
        // Clearing completed heights while the chain is progressing would drop
        // legitimate in-flight requests and cause re-request churn.
        static constexpr int ORPHAN_STALL_THRESHOLD_SECS = 30;

        if (orphan_count > 0 && header_height_snap > chain_height_snap &&
            stall_seconds >= ORPHAN_STALL_THRESHOLD_SECS && m_node_context.blockchain_db) {

            // Try to resolve orphans whose parent is the chain tip.
            // This handles the case where blocks arrived via INV out of order:
            // chain tip is at H, orphan at H+1 has parent=H, but was stored as
            // orphan before H was connected. Now H is the tip, so H+1 can connect.
            CBlockIndex* pTip = m_chainstate.GetTip();
            if (pTip) {
                uint256 tipHash = pTip->GetBlockHash();
                std::vector<uint256> children = g_node_context.orphan_manager->GetOrphanChildren(tipHash);
                if (!children.empty()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] ORPHAN-RESOLVE: Found " << children.size()
                                  << " orphan children of chain tip (height " << chain_height_snap
                                  << ") - resolving after " << stall_seconds << "s stall" << std::endl;
                    for (const uint256& orphanHash : children) {
                        CBlock orphanBlock;
                        if (g_node_context.orphan_manager->GetOrphanBlock(orphanHash, orphanBlock)) {
                            g_node_context.orphan_manager->EraseOrphanBlock(orphanHash);
                            uint256 oHash = orphanBlock.GetHash();
                            auto result = ProcessNewBlock(m_node_context, *m_node_context.blockchain_db,
                                                          -1, orphanBlock, &oHash);
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] ORPHAN-RESOLVE: Block "
                                          << oHash.GetHex().substr(0, 16) << "... result="
                                          << BlockProcessResultToString(result) << std::endl;
                        }
                    }
                }
            }

            // Clear completed heights above chain tip to unblock FetchBlocks.
            // Without this, GetNextBlocksToRequest sees all orphan heights as
            // "completed" and returns empty, preventing BUG #260 orphan resolution
            // and the ORPHAN-PARENT PRIORITY code from firing.
            // Guarded by stall check: only fires after 30s without chain progress,
            // so normal IBD with transient orphans is not disrupted.
            if (g_node_context.block_tracker) {
                g_node_context.block_tracker->ClearAboveHeight(chain_height_snap);
            }

            // Reset capacity stall counter after clearing orphan deadlock.
            // Without this, the counter accumulated during the orphan stall
            // carries over and immediately disconnects the next peer before
            // it has a chance to deliver the re-requested blocks.
            m_consecutive_capacity_stalls = 0;
        }
    }

    RetryTimeoutsAndStalls();
    BENCHMARK_END("ibd_download_blocks");

    // IBD DEBUG: DownloadBlocks complete
    if (g_verbose.load(std::memory_order_relaxed))
        std::cerr << "[IBD-DEBUG] DownloadBlocks complete" << std::endl;
}

// QueueMissingBlocks REMOVED - pure per-block model uses GetNextBlocksToRequest() directly

bool CIbdCoordinator::FetchBlocks() {
    if (!m_node_context.block_fetcher || !m_node_context.message_processor ||
        !m_node_context.connman || !m_node_context.peer_manager || !m_node_context.headers_manager) {
        return false;
    }

    // ============ SINGLE-PEER BLOCK DOWNLOAD ============
    // Use ONE peer for all block downloads (different from headers peer)
    // Max 32 blocks in-flight to this single peer
    // Switch peer only on disconnect or stall

    int chain_height = m_chainstate.GetHeight();
    int header_height = m_node_context.headers_manager->GetBestHeight();

    // Check for headers sync lag - need headers ahead of chain to download blocks
    if (header_height <= chain_height) {
        return false;
    }

    // ============ SELECT BLOCK SYNC PEER ============
    // Check if current block sync peer is still valid AND has blocks we need
    if (m_blocks_sync_peer != -1) {
        CNode* node = m_node_context.peer_manager->GetNode(m_blocks_sync_peer);
        if (!node || !node->IsConnected()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer << " disconnected" << std::endl;
            if (g_node_context.block_tracker) {
                auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                if (!cleared.empty()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Cleared " << cleared.size()
                                  << " stale in-flight blocks from disconnected peer " << m_blocks_sync_peer << std::endl;
                }
            }
            m_blocks_sync_peer = -1;
        } else {
            // BUG FIX: Re-select peer if their height is too low for blocks we need
            auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
            int peer_height = peer ? peer->best_known_height : 0;
            if (peer_height == 0 && peer) peer_height = peer->start_height;

            // BUG FIX #2: Also reselect if current peer is far below header height
            // This helps when better peers connect while we're stuck on a lower-height peer
            bool should_reselect = false;
            if (peer_height <= chain_height) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer
                              << " height (" << peer_height << ") too low (need > " << chain_height
                              << "), reselecting" << std::endl;
                should_reselect = true;
            } else if (peer_height < header_height && (header_height - peer_height) > 10) {
                // Current peer can't serve all headers - check if better peer exists
                auto all_peers = m_node_context.peer_manager->GetConnectedPeers();
                int better_peer_id = -1;
                int better_peer_height = peer_height;
                for (const auto& p : all_peers) {
                    if (!p || p->id == m_blocks_sync_peer) continue;
                    // BUG #256: Skip timed-out peer during cooldown
                    if (p->id == m_timed_out_peer && m_timed_out_peer != -1) {
                        auto elapsed = std::chrono::steady_clock::now() - m_timed_out_peer_time;
                        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < m_timed_out_peer_cooldown_sec) {
                            continue;
                        }
                    }
                    int ph = p->best_known_height;
                    if (ph == 0) ph = p->start_height;
                    if (ph > better_peer_height + 5) {  // Better peer with >5 blocks advantage
                        better_peer_id = p->id;
                        better_peer_height = ph;
                    }
                }
                if (better_peer_id != -1) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Found better peer " << better_peer_id << " (height=" << better_peer_height
                                  << ") vs current sync peer " << m_blocks_sync_peer
                                  << " (height=" << peer_height << "), switching directly" << std::endl;

                    // BUG FIX: Clear in-flight blocks from old peer before switching
                    if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                        auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                        if (!cleared.empty()) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] Cleared " << cleared.size()
                                          << " stale in-flight blocks from old peer " << m_blocks_sync_peer << std::endl;
                        }
                    }

                    m_blocks_sync_peer = better_peer_id;
                    m_blocks_sync_peer_consecutive_timeouts = 0;
                    m_consecutive_capacity_stalls = 0;  // New peer gets full stall window
                    m_sync_peer_futile_batches = 0;  // BUG #272: Reset wrong-fork counter
                    m_sync_peer_chain_height_at_start = chain_height;
                    should_reselect = false;  // Already switched
                }
            }

            if (should_reselect) {
                // BUG FIX: Clear in-flight blocks from old peer before reselecting
                if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                    auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                    if (!cleared.empty()) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Cleared " << cleared.size()
                                      << " stale in-flight blocks from reselected peer " << m_blocks_sync_peer << std::endl;
                    }
                }
                m_blocks_sync_peer = -1;
            }
        }
    }

    // Select a new block sync peer if needed
    if (m_blocks_sync_peer == -1) {
        auto peers = m_node_context.peer_manager->GetConnectedPeers();
        int best_peer = -1;
        int best_height = chain_height;

        // BUG #249: Check if we have an active fork - if so, we need peers on the fork chain
        ForkManager& forkMgr = ForkManager::GetInstance();
        bool has_active_fork = forkMgr.HasActiveFork();

        // BUG #249 DEBUG: Log available peers during fork
        if (has_active_fork && g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[IBD-FORK] Selecting fork block peer (chain=" << chain_height << " peers=" << peers.size() << ")" << std::endl;
        }

        for (const auto& peer : peers) {
            if (!peer) continue;

            // BUG #256: Skip timed-out peer during cooldown period
            if (peer->id == m_timed_out_peer && m_timed_out_peer != -1) {
                auto elapsed = std::chrono::steady_clock::now() - m_timed_out_peer_time;
                auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                if (elapsed_sec < m_timed_out_peer_cooldown_sec) {
                    continue;  // Still in cooldown, skip this peer
                } else {
                    // Cooldown expired, clear the timed-out peer tracking
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Peer " << m_timed_out_peer << " cooldown expired after "
                                  << elapsed_sec << " seconds, eligible for selection again" << std::endl;
                    m_timed_out_peer = -1;
                }
            }

            int peer_height = peer->best_known_height;
            if (peer_height == 0) peer_height = peer->start_height;

            // BUG #249 DEBUG: Log peer heights during fork
            if (has_active_fork && peer_height > chain_height && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[IBD-FORK]   peer=" << peer->id << " height=" << peer_height
                          << " (best_known=" << peer->best_known_height << " start=" << peer->start_height << ")" << std::endl;
            }

            // Skip headers sync peer in first pass - prefer other peers for block download
            // EXCEPT during active fork: the headers_sync_peer sent us the fork headers,
            // so they HAVE the fork blocks. Other peers on our chain don't have them.
            if (peer->id == m_headers_sync_peer && !has_active_fork) {
                continue;
            }

            if (peer_height > best_height) {
                best_height = peer_height;
                best_peer = peer->id;
            }
        }

        // If no other peer found, use headers sync peer for blocks too
        // BUG #249b FIX: During active fork, we SHOULD use headers_sync_peer as fallback
        // because they sent us the fork headers and therefore have the fork blocks.
        // Other peers on our chain don't have these blocks.
        // BUG FIX: Use header_height from headers manager (authoritative) instead of
        // peer->best_known_height which may be stale due to async header processing.
        // The headers sync peer sent us headers up to header_height, so they have those blocks.
        if (best_peer == -1 && m_headers_sync_peer != -1 && header_height > chain_height) {
            best_peer = m_headers_sync_peer;
            best_height = header_height;

            // BUG FIX: Also update the peer's best_known_height so subsequent checks
            // don't reselect based on stale start_height. The headers sync peer must
            // have blocks up to header_height since they sent us those headers.
            m_node_context.peer_manager->UpdatePeerBestKnownHeight(m_headers_sync_peer, header_height);
        }

        // BUG FIX: If still no peer found but we have headers ahead, try ANY connected
        // peer. This happens when peers' best_known_height is stale (set at handshake time,
        // never updated because no new INVs/headers arrived). If headers are ahead of our
        // chain, at least one peer on the network has those blocks.
        if (best_peer == -1 && header_height > chain_height) {
            for (const auto& peer : peers) {
                if (!peer) continue;
                CNode* pnode = m_node_context.peer_manager->GetNode(peer->id);
                if (!pnode || !pnode->IsConnected()) continue;
                // Skip timed-out peer during cooldown
                if (peer->id == m_timed_out_peer && m_timed_out_peer != -1) {
                    auto elapsed = std::chrono::steady_clock::now() - m_timed_out_peer_time;
                    if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < m_timed_out_peer_cooldown_sec) {
                        continue;
                    }
                }
                best_peer = peer->id;
                best_height = header_height;  // Assume they have up to header height
                m_node_context.peer_manager->UpdatePeerBestKnownHeight(peer->id, header_height);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] No peer with known height > chain, trying peer "
                              << peer->id << " (stale height fallback)" << std::endl;
                break;
            }
        }

        if (best_peer != -1) {
            m_blocks_sync_peer = best_peer;
            m_blocks_sync_peer_consecutive_timeouts = 0;  // Reset timeout counter for new peer
            m_consecutive_capacity_stalls = 0;  // Reset capacity stall counter - new peer gets full window
            m_sync_peer_futile_batches = 0;  // BUG #272: Reset wrong-fork counter
            m_sync_peer_chain_height_at_start = chain_height;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Selected blocks sync peer " << m_blocks_sync_peer
                          << " (height=" << best_height << ")" << std::endl;
        } else {
            // BUG #246b FIX: Before giving up, check for stale in-flight blocks from
            // disconnected peers. This can happen when a peer disconnects after being
            // selected but before blocks are delivered, and m_blocks_sync_peer was reset.
            if (g_node_context.block_tracker) {
                int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
                if (total_in_flight > 0) {
                    // There are in-flight blocks but no peers - they must be from disconnected peers
                    // Get the peers that have blocks assigned
                    auto tracked = g_node_context.block_tracker->GetTrackedHeights();
                    std::set<NodeId> peers_with_blocks;
                    for (const auto& [height, peer_id] : tracked) {
                        peers_with_blocks.insert(peer_id);
                    }

                    // Check each peer and clear if disconnected (use CNode state, not CPeer)
                    for (NodeId peer_id : peers_with_blocks) {
                        CNode* pnode = m_node_context.peer_manager->GetNode(peer_id);
                        if (!pnode || !pnode->IsConnected()) {
                            auto cleared = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
                            if (!cleared.empty()) {
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] Cleared " << cleared.size()
                                              << " stale in-flight blocks from orphaned peer " << peer_id << std::endl;
                            }
                        }
                    }
                }
            }

            m_ibd_no_peer_cycles++;
            m_last_hang_cause = HangCause::NO_PEERS_AVAILABLE;
            return false;
        }
    }

    // ============ REQUEST BLOCKS FROM SINGLE PEER ============
    CNode* sync_node = m_node_context.peer_manager->GetNode(m_blocks_sync_peer);
    if (!sync_node || !sync_node->IsConnected()) {
        // BUG FIX: Clear in-flight blocks from disconnected peer
        if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
            auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
            if (!cleared.empty()) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Cleared " << cleared.size()
                              << " stale in-flight blocks from gone peer " << m_blocks_sync_peer << std::endl;
            }
        }
        m_blocks_sync_peer = -1;
        return false;
    }

    // Check peer capacity
    int peer_blocks_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
    int peer_capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - peer_blocks_in_flight;
    if (peer_capacity <= 0) {
        m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
        return false;  // Peer at capacity - wait for blocks to arrive
    }

    // Get peer height
    // BUG FIX: If this peer is our headers sync peer, they have blocks up to header_height
    // (they sent us the headers). Use header_height instead of stale best_known_height.
    auto peer = m_node_context.peer_manager->GetPeer(m_blocks_sync_peer);
    int peer_height = peer ? peer->best_known_height : 0;
    if (peer_height == 0 && peer) peer_height = peer->start_height;
    if (m_blocks_sync_peer == m_headers_sync_peer) {
        // Headers sync peer definitely has blocks up to header_height
        peer_height = std::max(peer_height, header_height);
    }

    // Get next blocks to request
    int in_flight_before = g_node_context.block_tracker ? g_node_context.block_tracker->GetTotalInFlight() : 0;
    std::vector<int> blocks_to_request = m_node_context.block_fetcher->GetNextBlocksToRequest(
        peer_capacity, chain_height, header_height);

    // Diagnostic: show what we're about to request
    if (!blocks_to_request.empty() && (header_height - chain_height) > 5 && g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[IBD] FetchBlocks: chain=" << chain_height << " headers=" << header_height
                  << " peer=" << m_blocks_sync_peer << " inflight=" << in_flight_before
                  << " toRequest=" << blocks_to_request.size()
                  << " range=[" << blocks_to_request.front() << ".." << blocks_to_request.back() << "]"
                  << std::endl;
    }

    if (blocks_to_request.empty()) {
        // All needed blocks are already in-flight - waiting for delivery
        if (g_node_context.block_tracker) {
            int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
            if (total_in_flight > 0 && header_height > chain_height) {
                // Set accurate hang cause - blocks ARE requested, just waiting
                m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;

                // Check for stale peer assignments from disconnected peers
                auto tracked = g_node_context.block_tracker->GetTrackedHeights();
                std::set<NodeId> peers_with_blocks;
                for (const auto& [height, peer_id] : tracked) {
                    peers_with_blocks.insert(peer_id);
                }

                for (NodeId peer_id : peers_with_blocks) {
                    CNode* pnode = m_node_context.peer_manager->GetNode(peer_id);
                    if (!pnode || !pnode->IsConnected()) {
                        auto cleared = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
                        if (!cleared.empty()) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] Cleared " << cleared.size()
                                          << " stale in-flight blocks from dead peer " << peer_id << std::endl;
                        }
                    }
                }
            }
        }
        return false;  // All blocks either connected or in-flight
    }

    // Build GETDATA
    std::vector<NetProtocol::CInv> getdata;
    getdata.reserve(blocks_to_request.size());

    // BUG #247 FIX: During fork recovery, use fork_point as the lower bound
    // instead of chain_height. This ensures block 1068 is requested when
    // fork_point=1067 and chain_height=1068.
    int effective_lower_bound = chain_height;
    {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork()) {
            auto fork = forkMgr.GetActiveFork();
            if (fork) {
                effective_lower_bound = fork->GetForkPointHeight();
            }
        }
    }

    int null_hash_count = 0;
    int first_null_hash_height = -1;
    int already_have_count = 0;
    int failed_skip_count = 0;
    // BUG #260: Collect orphan blocks whose parents are now connected for re-processing
    std::vector<std::pair<uint256, CBlock>> orphans_to_reprocess;
    for (int h : blocks_to_request) {
        // Re-check capacity before each request
        int current_in_flight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
        if (current_in_flight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            break;
        }

        // Validate height range
        // BUG #247 FIX: Use effective_lower_bound (fork_point during fork, chain_height otherwise)
        if (h > header_height || h <= effective_lower_bound || h > peer_height) {
            continue;
        }

        // BUG #247 FIX: During fork recovery, use the ForkCandidate's expected hashes
        // to ensure we request the FORK chain's blocks, not our (wrong) chain's blocks.
        uint256 hash;
        {
            ForkManager& forkMgr = ForkManager::GetInstance();
            if (forkMgr.HasActiveFork()) {
                auto fork = forkMgr.GetActiveFork();
                if (fork) {
                    hash = fork->GetExpectedHashAtHeight(h);
                    if (!hash.IsNull()) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Fork recovery: requesting block " << h
                                      << " hash=" << hash.GetHex().substr(0, 16) << "..." << std::endl;
                    }
                }
            }
        }

        // Fall back to headers manager if not in fork mode or no expected hash
        if (hash.IsNull()) {
            hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
        }

        if (hash.IsNull()) {
            null_hash_count++;
            if (first_null_hash_height == -1) first_null_hash_height = h;
            continue;
        }

        // Check if already connected or marked as failed
        CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
        if (pindex) {
            // Skip already connected blocks
            if (pindex->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) {
                continue;
            }
            // BUG #255: Skip blocks marked as permanently failed
            // These failed authoritative validation in ConnectTip - no point retrying
            if (pindex->IsInvalid()) {
                failed_skip_count++;
                continue;
            }
            // BUG #255: Skip blocks whose parent is marked failed (BLOCK_FAILED_CHILD logic)
            // If parent failed, this block can never connect - don't waste bandwidth
            if (pindex->pprev && pindex->pprev->IsInvalid()) {
                // Mark this block as failed child
                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_CHILD;
                failed_skip_count++;
                continue;
            }
            // Block has data but isn't connected to active chain.
            // This is an orphan awaiting its parent.
            if (pindex->nStatus & CBlockIndex::BLOCK_HAVE_DATA) {
                // FORK FIX: If this is a fork block already in DB, feed it to ForkManager
                ForkManager& forkMgr2 = ForkManager::GetInstance();
                if (forkMgr2.HasActiveFork()) {
                    auto fork2 = forkMgr2.GetActiveFork();
                    if (fork2 && fork2->IsExpectedBlock(hash, h)) {
                        ForkBlock* existing = fork2->GetBlockAtHeight(h);
                        if (!existing || existing->status == ForkBlockStatus::PENDING) {
                            CBlock blockData;
                            if (m_node_context.blockchain_db &&
                                m_node_context.blockchain_db->ReadBlock(hash, blockData)) {
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] Fork block at height " << h
                                              << " already in DB - feeding to ForkManager for pre-validation" << std::endl;
                                forkMgr2.AddBlockToFork(blockData, hash, h);
                                ForkBlock* forkBlock = fork2->GetBlockAtHeight(h);
                                if (forkBlock && forkBlock->status == ForkBlockStatus::PENDING) {
                                    forkMgr2.PreValidateBlock(*forkBlock, *m_node_context.blockchain_db);
                                }
                            }
                        }
                    }
                }

                // BUG #260 FIX: Check if parent is now connected (orphan can be resolved).
                // Orphan blocks expire from orphan_manager after 20 minutes, but their
                // CBlockIndex with BLOCK_HAVE_DATA persists. If the parent arrived and
                // connected AFTER the orphan expired, orphan resolution never runs.
                // Fix: read the block from DB and use its actual hashPrevBlock to check
                // if parent is now on active chain, then queue for re-processing.
                if (m_node_context.blockchain_db) {
                    CBlock blockData;
                    if (m_node_context.blockchain_db->ReadBlock(hash, blockData)) {
                        CBlockIndex* pParent = m_chainstate.GetBlockIndex(blockData.hashPrevBlock);
                        if (pParent && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] Orphan at height " << h
                                          << " has connected parent (prevhash="
                                          << blockData.hashPrevBlock.GetHex().substr(0, 16)
                                          << "...) - queuing for re-processing" << std::endl;
                            orphans_to_reprocess.emplace_back(std::make_pair(hash, std::move(blockData)));
                        }
                    }
                }

                // BUG #279 FIX: If parent is NOT in chainstate at all, this is a VDF
                // divergence — the block's hashPrevBlock references a replacement tip
                // block we don't have. Request the missing parent by hash.
                // This is the core fix: without it, the block is skipped forever as
                // "already have" and the parent is never fetched.
                if (m_node_context.blockchain_db && m_blocks_sync_peer != -1) {
                    // Use header data (cheaper than DB read) if available
                    const uint256& parentHash = pindex->header.hashPrevBlock;
                    if (!parentHash.IsNull()) {
                        CBlockIndex* pParent = m_chainstate.GetBlockIndex(parentHash);
                        bool parentOnActiveChain = pParent && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);
                        if (!parentOnActiveChain) {
                            // Rate limit: only request each parent hash once per 30s
                            static std::map<uint256, std::chrono::steady_clock::time_point> s_parent_requests;
                            static std::mutex s_parent_req_mutex;
                            std::lock_guard<std::mutex> prl(s_parent_req_mutex);
                            auto now = std::chrono::steady_clock::now();
                            auto pit = s_parent_requests.find(parentHash);
                            if (pit == s_parent_requests.end() ||
                                std::chrono::duration_cast<std::chrono::seconds>(now - pit->second).count() > 30) {
                                s_parent_requests[parentHash] = now;

                                int parent_h = h - 1;
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] BUG#279: Block " << h << " in DB but parent "
                                              << parentHash.GetHex().substr(0, 16) << "... (height " << parent_h << ") "
                                              << (pParent ? "NOT on active chain" : "MISSING from chainstate")
                                              << " — requesting parent by hash from peer " << m_blocks_sync_peer << std::endl;

                                if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, parent_h, parentHash)) {
                                    getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, parentHash);
                                }
                            }
                        }
                    }
                }

                // NEVER MarkCompleted here. Only ProcessNewBlock results (ACCEPTED)
                // should mark a height completed. If reprocess fails or parent isn't
                // connected, the height stays untracked so it reappears in future ticks.
                already_have_count++;
                continue;
            }
        }

        // Request block from our single sync peer
        if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, h, hash)) {
            getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
        }
    }

    // Diagnostic: log when heights have null hashes (indicates header chain gap)
    if (null_hash_count > 0) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] WARNING: " << null_hash_count << " heights had null hashes (first=" << first_null_hash_height
                      << " chain=" << chain_height << " headers=" << header_height << ")" << std::endl;
    }
    if (already_have_count > 0) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Skipped " << already_have_count << " blocks already in DB (orphans awaiting parents)" << std::endl;
    }

    // =========================================================================
    // BUG #273: Fork recovery stuck when all fork blocks already in DB
    // =========================================================================
    // When a node has old fork blocks on its active chain, fork recovery requests
    // the correct fork blocks from peers. Those blocks arrive and get stored in DB,
    // but GetNextBlocksToRequest returns the same range again because:
    //   - The blocks are in DB (BLOCK_HAVE_DATA) but not on active chain
    //   - Individual fork blocks can't trigger a reorg (less chain work than tip)
    //   - Only the full fork chain from fork_point onward can beat the tip
    // Fix: After N consecutive cycles of all-in-DB with nothing new to request
    // during an active fork, escalate to DisconnectToHeight(fork_point) so the
    // chain rolls back and fork blocks can connect naturally via normal IBD.
    if (getdata.empty() && already_have_count > 0) {
        ForkManager& forkMgr = ForkManager::GetInstance();
        if (forkMgr.HasActiveFork()) {
            m_fork_all_in_db_cycles++;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] BUG#273: All " << already_have_count << " fork blocks in DB but chain stuck"
                          << " (cycle " << m_fork_all_in_db_cycles << "/" << MAX_FORK_ALL_IN_DB_CYCLES << ")" << std::endl;

            if (m_fork_all_in_db_cycles >= MAX_FORK_ALL_IN_DB_CYCLES) {
                auto activeFork = forkMgr.GetActiveFork();
                int fork_point = activeFork ? activeFork->GetForkPointHeight() : m_fork_point.load();
                int chain_height = m_chainstate.GetHeight();

                if (fork_point > 0 && fork_point <= chain_height && m_node_context.blockchain_db) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] BUG#273: Escalating to DisconnectToHeight(" << fork_point
                                  << ") - fork blocks in DB can't reorg individually" << std::endl;

                    // Chain work check: verify header chain has more work before disconnecting
                    bool should_disconnect = true;
                    uint256 localChainWork;
                    CBlockIndex* pTip = m_chainstate.GetTip();
                    if (pTip) localChainWork = pTip->nChainWork;

                    uint256 headerChainWork;
                    if (m_node_context.headers_manager)
                        headerChainWork = m_node_context.headers_manager->GetChainTipsTracker().GetBestChainWork();

                    if (!localChainWork.IsNull() && !headerChainWork.IsNull()) {
                        if (!ChainWorkGreaterThan(headerChainWork, localChainWork)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] BUG#273: Header chain has LESS work - NOT disconnecting" << std::endl;
                            should_disconnect = false;
                        }
                    }

                    if (should_disconnect) {
                        // Cancel active fork candidate first
                        forkMgr.CancelFork("BUG#273: escalating to DisconnectToHeight");
                        forkMgr.ClearInFlightState(m_node_context, fork_point);

                        // Disconnect to fork point (same as deep fork handler)
                        int disconnected = m_chainstate.DisconnectToHeight(fork_point, *m_node_context.blockchain_db);
                        if (disconnected < 0) {
                            std::cerr << "[IBD] BUG#273: DisconnectToHeight failed - requires --reindex" << std::endl;
                            m_requires_reindex = true;
                        } else {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] BUG#273: Disconnected " << disconnected
                                          << " blocks (chain now at " << m_chainstate.GetHeight() << ")" << std::endl;

                            // Clear stale state above fork point
                            uint256 forkPointHash;
                            CBlockIndex* pNewTip = m_chainstate.GetTip();
                            if (pNewTip) forkPointHash = pNewTip->GetBlockHash();

                            if (m_node_context.headers_manager)
                                m_node_context.headers_manager->ClearAboveHeight(fork_point, forkPointHash);
                            if (m_node_context.block_fetcher)
                                m_node_context.block_fetcher->ClearAboveHeight(fork_point);
                            if (g_node_context.block_tracker)
                                g_node_context.block_tracker->ClearAboveHeight(fork_point);

                            // Reset fork detection state
                            m_fork_detected.store(false);
                            g_node_context.fork_detected.store(false);
                            g_metrics.ClearForkDetected();
                            m_fork_point.store(-1);
                            m_fork_stall_cycles.store(0);
                            m_consecutive_orphan_blocks.store(0);
                            m_last_cancelled_fork_point = -1;

                            // Resume IBD to re-download correct chain
                            m_resync_in_progress = true;
                            m_resync_fork_point = fork_point;
                            m_resync_original_height = chain_height;
                            m_resync_target_height = m_node_context.headers_manager ?
                                m_node_context.headers_manager->GetBestHeight() : chain_height;
                            m_state = IBDState::BLOCKS_DOWNLOAD;
                            m_last_header_height = 0;

                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] BUG#273: Resync started from height " << fork_point << std::endl;
                        }
                    }
                }

                m_fork_all_in_db_cycles = 0;
                return true;  // Don't send getdata this cycle
            }
        } else {
            m_fork_all_in_db_cycles = 0;  // No active fork, reset counter
        }
    } else {
        m_fork_all_in_db_cycles = 0;  // Progress made or no blocks in DB, reset
    }

    // =========================================================================
    // BUG #270: Recovery from stuck failed-block ranges
    // =========================================================================
    // If ALL blocks in the requested range are marked as failed (e.g. from a
    // bootstrap or old software version), IBD loops forever on the same range.
    // Fix: During IBD (significantly behind peers), clear the BLOCK_FAILED_*
    // flags so blocks can be re-validated with current consensus rules.
    // Blocks with BLOCK_HAVE_DATA whose parent is connected get queued for
    // immediate re-processing via the existing orphan reprocessing path.
    //
    // BUG #278: Skip blocks in m_permanently_failed_blocks. These are blocks
    // that were already re-cleared and re-validated in THIS session but failed
    // again (genuine consensus violations, not stale flags from old binary).
    if (getdata.empty() && failed_skip_count > 0 && (header_height - chain_height) > 10) {
        int cleared_count = 0;
        int perm_failed_count = 0;
        for (int h : blocks_to_request) {
            uint256 hash = m_node_context.headers_manager->GetRandomXHashAtHeight(h);
            if (hash.IsNull()) continue;

            // BUG #278: Don't re-clear blocks that already failed re-validation
            if (m_permanently_failed_blocks.count(hash)) {
                perm_failed_count++;
                continue;
            }

            CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
            if (pindex && pindex->IsInvalid()) {
                // Clear the failed flags
                pindex->nStatus &= ~CBlockIndex::BLOCK_FAILED_MASK;
                cleared_count++;

                // Undo cooldown tracker state for this block so re-validation
                // doesn't hit false cooldown violations from the prior pass
                if (m_node_context.cooldown_tracker) {
                    m_node_context.cooldown_tracker->OnBlockDisconnected(pindex->nHeight);
                }

                // Track this block — if it fails again, it's permanently invalid
                m_permanently_failed_blocks.insert(hash);

                // If block data is in DB and parent is connected, queue for re-processing
                if ((pindex->nStatus & CBlockIndex::BLOCK_HAVE_DATA) && m_node_context.blockchain_db) {
                    CBlock blockData;
                    if (m_node_context.blockchain_db->ReadBlock(hash, blockData)) {
                        CBlockIndex* pParent = m_chainstate.GetBlockIndex(blockData.hashPrevBlock);
                        if (pParent && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] Re-queuing cleared block at height " << h
                                          << " for re-validation" << std::endl;
                            orphans_to_reprocess.emplace_back(std::make_pair(hash, std::move(blockData)));
                        }
                    }
                }
            }
        }
        if (cleared_count > 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Cleared failed flags on " << cleared_count << " blocks for re-validation"
                          << " (chain=" << chain_height << " headers=" << header_height << ")" << std::endl;
        }
        if (perm_failed_count > 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Skipped " << perm_failed_count
                          << " permanently invalid blocks (already re-validated and failed)" << std::endl;
        }

        // BUG #278: If ALL blocks in the range are permanently invalid and nothing
        // was cleared, our headers chain points to the wrong (fork) chain. Clear
        // headers above chain tip so they get re-fetched from correct-chain peers.
        if (cleared_count == 0 && perm_failed_count > 0) {
            m_perm_failed_stuck_cycles++;
            if (m_perm_failed_stuck_cycles >= 3) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] BUG #278: All blocks in range permanently invalid for "
                              << m_perm_failed_stuck_cycles << " cycles - clearing stale headers above "
                              << chain_height << " to re-fetch from correct chain" << std::endl;

                if (m_node_context.headers_manager) {
                    CBlockIndex* tip = m_chainstate.GetTip();
                    uint256 tipHash = tip ? tip->GetBlockHash() : uint256();
                    m_node_context.headers_manager->ClearAboveHeight(chain_height, tipHash);
                }
                if (g_node_context.block_tracker)
                    g_node_context.block_tracker->ClearAboveHeight(chain_height);

                // Clear permanently failed set so fresh headers get a clean start
                m_permanently_failed_blocks.clear();
                m_perm_failed_stuck_cycles = 0;
                m_last_failed_fork_point = -1;

                // Reset to header sync to re-fetch from peers
                m_state = IBDState::HEADERS_SYNC;
                m_last_header_height = 0;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] BUG #278: Switched to HEADERS_SYNC to get correct chain headers" << std::endl;
            }
        } else {
            m_perm_failed_stuck_cycles = 0;
        }
    }

    // Send GETDATA to our single sync peer
    if (!getdata.empty()) {
        CNetMessage msg = m_node_context.message_processor->CreateGetDataMessage(getdata);
        bool sent = m_node_context.connman->PushMessage(m_blocks_sync_peer, msg);
        if (!sent) {
            // BUG FIX: Clear ALL in-flight blocks from this peer, not just the ones we tried to send
            // The peer might have other blocks tracked from a previous batch
            if (g_node_context.block_tracker && m_blocks_sync_peer != -1) {
                auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                if (!cleared.empty()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Cleared " << cleared.size()
                                  << " stale in-flight blocks from failed send peer " << m_blocks_sync_peer << std::endl;
                }
            }
            m_blocks_sync_peer = -1;  // Force peer reselection on next call
            return false;
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Requested " << getdata.size() << " blocks from peer " << m_blocks_sync_peer
                      << " (in-flight=" << m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer)
                      << "/" << MAX_BLOCKS_IN_TRANSIT_PER_PEER << ")" << std::endl;

        // BUG #272: Wrong-fork sync peer detection
        // If we keep sending full batches but the chain never advances, the sync peer
        // is delivering blocks from a different fork (they arrive as orphans).
        // After MAX_FUTILE_BATCHES, switch to a different peer.
        if (m_sync_peer_chain_height_at_start >= 0 && chain_height == m_sync_peer_chain_height_at_start) {
            m_sync_peer_futile_batches++;
            if (m_sync_peer_futile_batches >= MAX_FUTILE_BATCHES) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] BUG #272: Sync peer " << m_blocks_sync_peer
                              << " delivered " << m_sync_peer_futile_batches
                              << " batches without chain advancing (stuck at " << chain_height
                              << ") - peer likely on different fork, switching" << std::endl;
                // Mark as timed out with short cooldown so we try a different peer
                m_timed_out_peer = m_blocks_sync_peer;
                m_timed_out_peer_time = std::chrono::steady_clock::now();
                m_timed_out_peer_cooldown_sec = 300;  // 5 min cooldown for wrong-fork peers
                // Clear in-flight from this peer
                if (g_node_context.block_tracker) {
                    g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                }
                m_blocks_sync_peer = -1;
                m_sync_peer_futile_batches = 0;
                m_sync_peer_chain_height_at_start = -1;
            }
        } else if (chain_height > m_sync_peer_chain_height_at_start) {
            // Chain advanced - this peer is working, reset counter
            m_sync_peer_futile_batches = 0;
            m_sync_peer_chain_height_at_start = chain_height;
        }
    }

    // BUG #260: Re-process orphan blocks whose parents are now connected.
    // This handles the case where orphan_manager expired the entries (20 min TTL)
    // but the blocks still have BLOCK_HAVE_DATA in chainstate. Without this,
    // orphan resolution never triggers and the node permanently stalls.
    bool chain_advanced = false;
    if (!orphans_to_reprocess.empty()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Re-processing " << orphans_to_reprocess.size()
                      << " orphan blocks with connected parents" << std::endl;
        int chain_before = m_chainstate.GetHeight();
        for (auto& [orphan_hash, orphan_block] : orphans_to_reprocess) {
            auto result = ProcessNewBlock(m_node_context, *m_node_context.blockchain_db,
                                          -1, orphan_block, &orphan_hash);
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Orphan re-process result: " << BlockProcessResultToString(result)
                          << " hash=" << orphan_hash.GetHex().substr(0, 16) << "..." << std::endl;
            if (result == BlockProcessResult::ACCEPTED) {
                // Successfully connected - mark height completed
                if (g_node_context.block_tracker) {
                    int reprocessed_height = m_chainstate.GetHeight();
                    g_node_context.block_tracker->MarkCompleted(reprocessed_height);
                }
            }
        }
        chain_advanced = (m_chainstate.GetHeight() > chain_before);
    }

    // Set hang cause when no GETDATA was sent and no orphans were resolved
    if (getdata.empty() && !chain_advanced) {
        int total_in_flight = g_node_context.block_tracker ? g_node_context.block_tracker->GetTotalInFlight() : 0;

        // ORPHAN-PARENT PRIORITY FIX: When candidate blocks are orphans in DB,
        // the pipeline is jammed. Check the critical parent (chain_height+1) to
        // determine the correct recovery action. This fires regardless of in-flight
        // count - the logs show stalls at inflight=22+ when children arrive via INV
        // but the parent is stuck or missing.
        //
        // Also trigger when orphans exist in the pool but already_have_count is 0.
        // This happens when orphan heights are in m_completed_heights: GetNextBlocksToRequest
        // filters them out, so blocks_to_request is empty and already_have_count stays 0.
        // Without this, the node deadlocks: "no suitable peers" forever.
        size_t fetch_orphan_count = g_node_context.orphan_manager ?
            g_node_context.orphan_manager->GetOrphanCount() : 0;
        if ((already_have_count > 0 || fetch_orphan_count > 0) && header_height > chain_height) {
            int next_needed = chain_height + 1;
            uint256 next_hash = m_node_context.headers_manager->GetRandomXHashAtHeight(next_needed);
            if (!next_hash.IsNull()) {
                CBlockIndex* pindex = m_chainstate.GetBlockIndex(next_hash);
                if (pindex && (pindex->nStatus & CBlockIndex::BLOCK_HAVE_DATA)) {
                    // Parent is in DB but not connected - validation queue should handle it.
                    // Use WAITING_ON_PARENT_VALIDATION to avoid wrongly disconnecting peer.
                    // BUT: add a timeout so we don't wait forever if validation is stuck.
                    // Track parent identity so timer resets when a different parent becomes
                    // the bottleneck (e.g., chain advanced past the previous stuck parent).
                    if (!m_parent_validation_wait_active ||
                        m_waiting_parent_height != next_needed ||
                        m_waiting_parent_hash != next_hash) {
                        m_parent_validation_wait_start = std::chrono::steady_clock::now();
                        m_parent_validation_wait_active = true;
                        m_waiting_parent_height = next_needed;
                        m_waiting_parent_hash = next_hash;
                    }
                    auto wait_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - m_parent_validation_wait_start).count();

                    if (wait_elapsed < PARENT_VALIDATION_TIMEOUT_SECS) {
                        // Still within timeout - give validation queue time to process
                        m_last_hang_cause = HangCause::WAITING_ON_PARENT_VALIDATION;
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Block " << next_needed
                                      << " is in DB awaiting validation (" << wait_elapsed << "s/"
                                      << PARENT_VALIDATION_TIMEOUT_SECS << "s)" << std::endl;
                    } else {
                        // Timeout expired - validation is stuck.
                        // BUG #279 FIX: Check if the block's parent is on the active chain.
                        // After a VDF distribution tiebreak, the block's hashPrevBlock may
                        // reference a different block at the same height (replacement tip).
                        // If the parent is missing or not on active chain, request it by hash.
                        m_parent_validation_wait_active = false;
                        m_waiting_parent_height = -1;
                        m_waiting_parent_hash = uint256{};

                        bool parent_fetched = false;
                        if (m_node_context.blockchain_db && m_node_context.blockchain_db->BlockExists(next_hash)) {
                            CBlock stuck_block;
                            if (m_node_context.blockchain_db->ReadBlock(next_hash, stuck_block)) {
                                const uint256& parentHash = stuck_block.hashPrevBlock;
                                CBlockIndex* pParent = m_chainstate.GetBlockIndex(parentHash);
                                bool parentOnActiveChain = pParent && (pParent->nStatus & CBlockIndex::BLOCK_VALID_CHAIN);

                                if (!parentOnActiveChain) {
                                    // Parent is missing or not on active chain — this is the VDF divergence case.
                                    // Request the PARENT block by hash from peers.
                                    if (g_verbose.load(std::memory_order_relaxed))
                                        std::cout << "[IBD] VALIDATION TIMEOUT: Block " << next_needed
                                                  << " stuck — parent " << parentHash.GetHex().substr(0, 16) << "..."
                                                  << " is " << (pParent ? "NOT on active chain" : "MISSING from chainstate")
                                                  << ". Requesting parent from peers." << std::endl;

                                    if (m_blocks_sync_peer != -1 && m_node_context.block_fetcher && m_node_context.connman) {
                                        int parent_height = next_needed - 1;  // Parent is at height below
                                        if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, parent_height, parentHash)) {
                                            CNetMessage parent_msg = m_node_context.message_processor->CreateGetDataMessage(
                                                {{NetProtocol::MSG_BLOCK_INV, parentHash}});
                                            m_node_context.connman->PushMessage(m_blocks_sync_peer, parent_msg);
                                            parent_fetched = true;
                                            if (g_verbose.load(std::memory_order_relaxed))
                                                std::cout << "[IBD] Requested missing parent block " << parentHash.GetHex().substr(0, 16)
                                                          << "... (height " << parent_height << ") from peer " << m_blocks_sync_peer << std::endl;
                                        }
                                    }
                                }
                            }
                        }

                        if (!parent_fetched) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] VALIDATION TIMEOUT: Block " << next_needed
                                          << " stuck in DB for " << wait_elapsed << "s - escalating to peer recovery"
                                          << std::endl;
                        }
                        m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
                    }
                } else {
                    // Block NOT in chainstate. Reset validation wait timer.
                    m_parent_validation_wait_active = false;
                    m_waiting_parent_height = -1;
                    m_waiting_parent_hash = uint256{};

                    // ORPHAN DB FIX: Block may already be in the block DB (received as
                    // orphan, saved to DB, but never got a CBlockIndex because parent
                    // wasn't connected at the time). Try to re-process from DB first
                    // to avoid an unnecessary network round-trip.
                    bool resolved_from_db = false;
                    if (m_node_context.blockchain_db && m_node_context.blockchain_db->BlockExists(next_hash)) {
                        CBlock db_block;
                        if (m_node_context.blockchain_db->ReadBlock(next_hash, db_block)) {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[IBD] ORPHAN-PARENT PRIORITY: Block " << next_needed
                                          << " found in DB - re-processing directly" << std::endl;
                            auto result = ProcessNewBlock(m_node_context, *m_node_context.blockchain_db,
                                                          -1, db_block, &next_hash);
                            if (result == BlockProcessResult::ACCEPTED) {
                                resolved_from_db = true;
                                chain_advanced = true;
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] ORPHAN-PARENT PRIORITY: Block " << next_needed
                                              << " accepted from DB" << std::endl;
                            }
                        }
                    }

                    if (!resolved_from_db) {
                        // Check if it's tracked (in-flight).
                        int tracking_age = g_node_context.block_tracker ?
                            g_node_context.block_tracker->GetTrackingAge(next_needed) : -1;
                        if (tracking_age >= 0 && tracking_age < 30) {
                            // Parent is in-flight and hasn't been waiting too long - let it arrive.
                            m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
                        } else {
                            // Parent is either not tracked at all (gap!) or has been in-flight
                            // for >30s (stale request). Force re-request it.
                            if (tracking_age >= 30) {
                                // Clear the stale tracking entry first
                                g_node_context.block_tracker->RemoveTimedOut(next_needed);
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] ORPHAN-PARENT PRIORITY: Block " << next_needed
                                              << " stale in tracker (" << tracking_age << "s) - clearing and re-requesting"
                                              << std::endl;
                            } else {
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[IBD] ORPHAN-PARENT PRIORITY: Block " << next_needed
                                              << " missing from DB and tracker - force requesting from peer "
                                              << m_blocks_sync_peer << std::endl;
                            }
                            // Only force-request if peer has capacity under the IBD scheduler limit
                            if (m_blocks_sync_peer != -1) {
                                int peer_inflight = m_node_context.block_fetcher->GetPeerBlocksInFlight(m_blocks_sync_peer);
                                if (peer_inflight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                                    if (m_node_context.block_fetcher->RequestBlockFromPeer(m_blocks_sync_peer, next_needed, next_hash)) {
                                        CNetMessage parent_msg = m_node_context.message_processor->CreateGetDataMessage(
                                            {{NetProtocol::MSG_BLOCK_INV, next_hash}});
                                        m_node_context.connman->PushMessage(m_blocks_sync_peer, parent_msg);
                                    }
                                }
                            }
                            m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
                        }
                    }
                }
            } else {
                m_parent_validation_wait_active = false;
                m_waiting_parent_height = -1;
                m_waiting_parent_hash = uint256{};
                m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
            }
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] " << already_have_count
                          << " orphan blocks awaiting parents (chain="
                          << chain_height << " headers=" << header_height
                          << " inflight=" << total_in_flight << ")" << std::endl;
        } else if (total_in_flight > 0) {
            m_last_hang_cause = HangCause::PEERS_AT_CAPACITY;
        }
    }

    return !getdata.empty() || chain_advanced;
}

void CIbdCoordinator::RetryTimeoutsAndStalls() {
    if (!m_node_context.block_fetcher || !m_node_context.connman || !m_node_context.headers_manager) {
        return;
    }

    // ============ HARD TIMEOUT: Remove blocks stuck too long ============
    // Use shorter timeout when close to tip (only a few blocks behind) since blocks
    // should arrive quickly. Use longer timeout during bulk IBD where validation
    // of RandomX PoW can take 1-2s per block on slower hardware.
    int chain_height_now = m_chainstate.GetHeight();
    int header_height_now = m_node_context.headers_manager ? m_node_context.headers_manager->GetBestHeight() : 0;
    int blocks_behind = header_height_now - chain_height_now;
    int timeout_seconds = (blocks_behind <= 20) ? 15 : 60;
    auto very_stalled = m_node_context.block_fetcher->GetStalledBlocks(
        std::chrono::seconds(timeout_seconds));

    if (!very_stalled.empty()) {
        int removed = 0;
        bool current_peer_timed_out = false;
        for (const auto& [height, peer] : very_stalled) {
            m_node_context.block_fetcher->RequeueBlock(height);
            removed++;
            // Track if current blocks sync peer had timeouts
            if (peer == m_blocks_sync_peer) {
                current_peer_timed_out = true;
            }
        }
        if (removed > 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[PerBlock] Removed " << removed << " blocks stuck >" << timeout_seconds
                          << "s from tracker (will re-request)" << std::endl;
        }

        // BAD PEER DETECTION: If current sync peer has consecutive timeout cycles, rotate to new peer
        // When close to tip, rotate after just 1 timeout (15s) instead of waiting for 3x60s
        int max_timeouts = (blocks_behind <= 20) ? 1 : MAX_PEER_CONSECUTIVE_TIMEOUTS;
        if (current_peer_timed_out && m_blocks_sync_peer != -1) {
            m_blocks_sync_peer_consecutive_timeouts++;
            if (m_blocks_sync_peer_consecutive_timeouts >= max_timeouts) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Blocks sync peer " << m_blocks_sync_peer
                              << " not delivering blocks (" << m_blocks_sync_peer_consecutive_timeouts
                              << " consecutive timeout cycles), forcing reselection" << std::endl;

                // BUG #256: Track this peer to avoid re-selecting it for 1 hour
                m_timed_out_peer = m_blocks_sync_peer;
                m_timed_out_peer_time = std::chrono::steady_clock::now();
                m_timed_out_peer_cooldown_sec = HARD_TIMEOUT_COOLDOWN_SEC;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Peer " << m_timed_out_peer << " excluded from selection for "
                              << m_timed_out_peer_cooldown_sec << " seconds" << std::endl;

                // BUG FIX: Clear in-flight blocks from this peer before reselecting
                // Without this, blocks would stay tracked until 60s timeout, causing
                // "all peers at capacity" errors when we accumulate stale entries
                if (g_node_context.block_tracker) {
                    auto cleared = g_node_context.block_tracker->OnPeerDisconnected(m_blocks_sync_peer);
                    if (!cleared.empty()) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Cleared " << cleared.size()
                                      << " stale in-flight blocks from bad peer " << m_blocks_sync_peer << std::endl;
                    }
                }

                m_blocks_sync_peer = -1;
                m_blocks_sync_peer_consecutive_timeouts = 0;
            }
        }
    }

    // Disconnect stalling peers
    std::vector<NodeId> stalling_peers;
    if (m_node_context.peer_manager) {
        stalling_peers = m_node_context.peer_manager->CheckForStallingPeers();
    }

    for (NodeId peer : stalling_peers) {
        LogPrintIBD(WARN, "Disconnecting stalling peer %d", peer);
        m_node_context.connman->DisconnectNode(peer, "stalling block download");
    }
}

/**
 * BUG #158 FIX: Find the fork point between local chain and header chain
 * BUG #194 FIX: Walk FORWARD from genesis to find true divergence point
 *
 * RACE CONDITION FIX: Uses thread-safe GetChainSnapshot() to avoid reading
 * pprev pointers without holding cs_main. Previously, this function could
 * cause use-after-free if validation workers modified the chain concurrently.
 *
 * CHAIN BREAK FIX: Uses GetHeadersAtHeight() instead of GetRandomXHashAtHeight()
 * to avoid chain walk issues when headers don't fully connect.
 *
 * Returns the height of the last common block (fork_point), or 0 if no match found.
 */
int CIbdCoordinator::FindForkPoint(int chain_height) {
    if (!m_node_context.headers_manager) {
        return 0;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[FORK-DETECT] Searching for fork point from height " << chain_height << std::endl;

    // RACE CONDITION FIX: Get a thread-safe snapshot of the chain
    // This holds cs_main while copying the data, then releases it
    const int MAX_CHECKS = chain_height + 1;  // +1 to include genesis if needed
    auto chainSnapshot = m_chainstate.GetChainSnapshot(MAX_CHECKS, 0);

    if (chainSnapshot.empty()) {
        std::cerr << "[FORK-DETECT] ERROR: Empty chain snapshot" << std::endl;
        return 0;
    }

    // BUG #194 FIX: Build height->hash map for forward iteration
    // chainSnapshot is tip-downward, we need to walk genesis-upward
    std::map<int, uint256> chainstateByHeight;
    for (const auto& [height, hash] : chainSnapshot) {
        chainstateByHeight[height] = hash;
    }

    // Step 1: Verify genesis matches
    auto genesisIt = chainstateByHeight.find(0);
    if (genesisIt != chainstateByHeight.end()) {
        std::vector<uint256> headersAtGenesis = m_node_context.headers_manager->GetHeadersAtHeight(0);
        bool genesisFound = false;
        for (const auto& h : headersAtGenesis) {
            if (h == genesisIt->second) {
                genesisFound = true;
                break;
            }
        }
        if (!genesisFound && !headersAtGenesis.empty()) {
            std::cerr << "[FORK-DETECT] CRITICAL: Genesis mismatch! Different chains." << std::endl;
            return 0;
        }
    }

    // Step 2: Walk FORWARD from genesis to find first divergence
    // The fork point is the LAST height where chains UNAMBIGUOUSLY match
    int last_common_height = 0;
    int first_divergence = -1;
    int logged_divergences = 0;

    for (int h = 0; h <= chain_height; h++) {
        auto it = chainstateByHeight.find(h);
        if (it == chainstateByHeight.end()) {
            continue;  // No chainstate block at this height (shouldn't happen)
        }

        uint256 local_hash = it->second;

        // BUG #194 FIX: Use GetHeadersAtHeight instead of GetRandomXHashAtHeight
        // This queries mapHeightIndex directly, avoiding chain walk issues
        std::vector<uint256> headers_at_height = m_node_context.headers_manager->GetHeadersAtHeight(h);

        if (headers_at_height.empty()) {
            // No headers at this height - network chain doesn't have this block yet
            // This is OK during IBD, continue checking
            continue;
        }

        // BUG #194 FIX: If there are MULTIPLE headers at this height, it means
        // competing forks exist. Even if our hash is among them, we can't be sure
        // we're on the same chain as the network. Treat as potential divergence.
        if (headers_at_height.size() > 1) {
            // Multiple competing headers = fork point
            if (first_divergence < 0) {
                first_divergence = h;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Competing forks at height " << h
                              << " (" << headers_at_height.size() << " headers)"
                              << " - treating as divergence point" << std::endl;
            }
            continue;  // Don't update last_common_height
        }

        // Exactly one header at this height - check if it matches chainstate
        if (headers_at_height[0] == local_hash) {
            last_common_height = h;
        } else {
            // Single header but doesn't match chainstate = divergence
            if (first_divergence < 0) {
                first_divergence = h;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Chain diverges at height " << h
                              << " local=" << local_hash.GetHex().substr(0, 16) << "..."
                              << " header=" << headers_at_height[0].GetHex().substr(0, 16) << "..." << std::endl;
            }
            if (logged_divergences < 5) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Height " << h << " diverges: local="
                              << local_hash.GetHex().substr(0, 16) << "..." << std::endl;
                logged_divergences++;
            }
        }
    }

    if (first_divergence >= 0) {
        // Chains diverge - fork point is the last UNAMBIGUOUS common height
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-DETECT] Found fork point at height " << last_common_height
                      << " (first divergence/fork at " << first_divergence << ")" << std::endl;
        return last_common_height;
    }

    // No divergence found - chains match completely
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[FORK-DETECT] No fork detected - chains match up to height " << chain_height << std::endl;
    return chain_height;
}

// HandleForkScenario was removed - it was dead code (never called).
// Its block disconnection functionality is handled by TriggerChainSwitch()
// in fork_manager.cpp, and block tracker clearing is now done in
// AttemptForkRecovery() when creating a fork candidate.

// ============================================================================
// FORK RECOVERY: Unified pipeline for all layers (A2/B1)
// ============================================================================

bool CIbdCoordinator::AttemptForkRecovery(int chain_height, int header_height, ForkRecoveryReason reason) {
    int fork_point = FindForkPoint(chain_height);

    // BUG #278: Don't retry fork recovery at a fork point that already failed chain switch.
    // The fork contains blocks with consensus violations (e.g., cooldown) that won't pass
    // on retry. Without this check, fork detection → recovery → switch fail → re-detection
    // creates an infinite loop that stalls the node.
    // Set m_fork_detected=true to suppress further detection attempts from all 3 layers.
    // Normal IBD continues for the valid chain; if the chain advances past this fork point,
    // m_last_failed_fork_point is cleared and fresh detection can occur.
    if (fork_point > 0 && fork_point == m_last_failed_fork_point) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Skipping fork at point " << fork_point
                      << " - chain switch already failed here (BUG #278), suppressing detection" << std::endl;
        m_fork_detected.store(true);  // Suppress further detection
        m_fork_point.store(fork_point);
        return false;
    }

    // BUG #189 FIX: Allow fork_point up to chain_height + 1 to handle race conditions
    if (fork_point <= 0 || fork_point > chain_height + 1) {
        if (fork_point == 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-RECOVERY] reason=" << ForkRecoveryReasonToString(reason)
                          << " result=no_common_ancestor chain_height=" << chain_height << std::endl;
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-RECOVERY] reason=" << ForkRecoveryReasonToString(reason)
                          << " result=invalid_fork_point fork_point=" << fork_point << std::endl;
        }
        m_fork_stall_cycles.store(0);
        return false;
    }

    int fork_depth = std::max(0, chain_height - fork_point);
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[FORK-RECOVERY] reason=" << ForkRecoveryReasonToString(reason)
                  << " fork_point=" << fork_point << " depth=" << fork_depth
                  << " chain_height=" << chain_height << " header_height=" << header_height << std::endl;

    // Deep fork handling: fork exceeds MAX_AUTO_REORG_DEPTH
    // Disconnect blocks back to fork point, then re-download correct chain via normal IBD
    if (fork_depth > MAX_AUTO_REORG_DEPTH) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Deep fork detected (" << fork_depth
                      << " blocks, fork_point=" << fork_point << ")" << std::endl;

        // Chain work check: verify header chain has more work BEFORE disconnecting
        uint256 localChainWork;
        CBlockIndex* pTipCheck = m_chainstate.GetTip();
        if (pTipCheck) localChainWork = pTipCheck->nChainWork;

        uint256 headerChainWork;
        if (m_node_context.headers_manager)
            headerChainWork = m_node_context.headers_manager->GetChainTipsTracker().GetBestChainWork();

        if (!localChainWork.IsNull() && !headerChainWork.IsNull()) {
            if (!ChainWorkGreaterThan(headerChainWork, localChainWork)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-RECOVERY] Header chain has LESS work - NOT disconnecting" << std::endl;
                m_fork_stall_cycles.store(0);
                return false;
            }
        }
        // If either is null, proceed on orphan-block evidence (same rationale as shallow fork path)

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Deep fork (" << fork_depth
                      << " blocks) - automatic disconnect-and-resync" << std::endl;

        // Clear mempool before deep disconnect: disconnecting hundreds of blocks would
        // flood mempool with old transactions from the wrong fork (stale anyway)
        auto* mempool = g_mempool.load();
        if (mempool) {
            mempool->Clear();
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-RECOVERY] Mempool cleared before deep disconnect" << std::endl;
        }

        // Disconnect to fork point using proper per-block UTXO/identity/mempool undo
        if (!m_node_context.blockchain_db) {
            std::cerr << "[FORK-RECOVERY] No blockchain DB - cannot disconnect" << std::endl;
            m_requires_reindex = true;
            return false;
        }
        int disconnected = m_chainstate.DisconnectToHeight(fork_point, *m_node_context.blockchain_db);
        if (disconnected < 0) {
            std::cerr << "[FORK-RECOVERY] Failed to disconnect - requires --reindex" << std::endl;
            m_requires_reindex = true;
            return false;
        }
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Disconnected " << disconnected
                      << " blocks (chain now at " << m_chainstate.GetHeight() << ")" << std::endl;

        // Clear stale state above fork point
        uint256 forkPointHash;
        CBlockIndex* pNewTip = m_chainstate.GetTip();
        if (pNewTip) forkPointHash = pNewTip->GetBlockHash();

        if (m_node_context.headers_manager)
            m_node_context.headers_manager->ClearAboveHeight(fork_point, forkPointHash);
        if (m_node_context.block_fetcher)
            m_node_context.block_fetcher->ClearAboveHeight(fork_point);
        if (g_node_context.block_tracker)
            g_node_context.block_tracker->ClearAboveHeight(fork_point);

        // Reset fork detection state
        m_fork_detected.store(false);
        g_node_context.fork_detected.store(false);
        g_metrics.ClearForkDetected();
        m_fork_point.store(-1);
        m_fork_stall_cycles.store(0);
        m_consecutive_orphan_blocks.store(0);
        m_last_cancelled_fork_point = -1;

        // Track resync progress
        m_resync_in_progress = true;
        m_resync_fork_point = fork_point;
        m_resync_original_height = chain_height;
        m_resync_target_height = header_height;

        // Resume IBD in BLOCKS_DOWNLOAD state (peers and headers already established)
        m_state = IBDState::BLOCKS_DOWNLOAD;
        m_last_header_height = 0;

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-RECOVERY] Deep resync started: downloading correct chain from height "
                      << fork_point << std::endl;
        return true;
    }

    // BUG #245 FIX: Only fork recover if incoming chain has MORE work than ours
    uint256 localChainWork;
    CBlockIndex* pTip = m_chainstate.GetTip();
    if (pTip) {
        localChainWork = pTip->nChainWork;
    }

    uint256 headerChainWork;
    if (m_node_context.headers_manager) {
        headerChainWork = m_node_context.headers_manager->GetChainTipsTracker().GetBestChainWork();
    }

    // If chainwork data is available for both sides, use it for the comparison.
    // If either is null (chain tips tracker may not track chainwork for competing
    // tips after a partial fork switch), skip the check - we already know we're
    // on a stale fork because we're receiving consecutive orphan blocks.
    if (!localChainWork.IsNull() && !headerChainWork.IsNull()) {
        if (!ChainWorkGreaterThan(headerChainWork, localChainWork)) {
            std::string localHex = localChainWork.GetHex();
            std::string headerHex = headerChainWork.GetHex();
            if (g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[FORK-DETECT] Incoming fork has LESS work than our chain - NOT switching" << std::endl;
                std::cout << "[FORK-DETECT] Local work=..." << localHex.substr(localHex.length() > 16 ? localHex.length() - 16 : 0)
                          << " Header work=..." << headerHex.substr(headerHex.length() > 16 ? headerHex.length() - 16 : 0) << std::endl;
            }
            m_fork_stall_cycles.store(0);
            return false;
        }
    } else {
        // Chainwork unavailable - proceed with fork recovery anyway.
        // Layer 2's 10+ consecutive orphan blocks is strong evidence of a stale fork.
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[FORK-DETECT] ChainWork unavailable (local="
                      << (localChainWork.IsNull() ? "null" : "set")
                      << " header=" << (headerChainWork.IsNull() ? "null" : "set")
                      << ") - proceeding based on orphan block evidence" << std::endl;
    }

    // VALIDATE-BEFORE-DISCONNECT: Use ForkManager staging approach
    ForkManager& forkMgr = ForkManager::GetInstance();

    // Check if we already have an active fork
    if (forkMgr.HasActiveFork()) {
        auto activeFork = forkMgr.GetActiveFork();

        // BUG #261: Check for excessive hash mismatches (stale expected hashes)
        if (activeFork && activeFork->HasExcessiveHashMismatches()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-DETECT] Fork has excessive hash mismatches"
                          << ", cancelling and setting cooldown" << std::endl;
            int cancelPoint = activeFork->GetForkPointHeight();
            forkMgr.CancelFork("Excessive hash mismatches - stale expected hashes");
            forkMgr.ClearInFlightState(m_node_context, cancelPoint);
            m_fork_detected.store(false);
            g_node_context.fork_detected.store(false);
            g_metrics.ClearForkDetected();
            m_fork_point.store(-1);
            // Set cooldown to prevent immediate re-creation
            m_last_cancelled_fork_point = fork_point;
            m_fork_cancel_time = std::chrono::steady_clock::now();
            m_fork_stall_cycles.store(0);
            return false;
        }

        if (forkMgr.CheckTimeout()) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-DETECT] Existing fork timed out, canceling and starting new" << std::endl;
            // BUG #261: If fork timed out with zero received blocks, set cooldown
            int receivedCount = activeFork ? activeFork->GetReceivedBlockCount() : 0;
            int cancelPoint = activeFork ? activeFork->GetForkPointHeight() : fork_point;
            int forkTimeout = activeFork ? activeFork->GetTimeoutSeconds() : 60;
            forkMgr.CancelFork("Timeout - " + std::to_string(forkTimeout) + "s without blocks");
            forkMgr.ClearInFlightState(m_node_context, cancelPoint);
            m_fork_detected.store(false);
            g_node_context.fork_detected.store(false);
            g_metrics.ClearForkDetected();
            m_fork_point.store(-1);
            if (receivedCount == 0) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Fork timed out with 0 received blocks - setting cooldown" << std::endl;
                m_last_cancelled_fork_point = fork_point;
                m_fork_cancel_time = std::chrono::steady_clock::now();
                m_fork_stall_cycles.store(0);
                return false;
            }
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-DETECT] Fork already active, waiting for blocks..." << std::endl;
            // BUG FIX: Set m_fork_detected so Layer 1 doesn't keep re-triggering,
            // and return false so DownloadBlocks falls through to FetchBlocks().
            // Previously returned true without setting m_fork_detected, which caused
            // an infinite loop: Layer 1 fires -> "Fork already active" -> return true
            // -> DownloadBlocks exits early -> FetchBlocks never called -> no blocks
            // ever requested -> fork recovery never progresses.
            m_fork_detected.store(true);
            m_fork_point.store(fork_point);
            m_fork_stall_cycles.store(0);
            return false;  // Fall through to FetchBlocks so blocks get requested
        }
    }

    // BUG #261: Cooldown check - don't re-create fork for same fork point too soon
    if (fork_point == m_last_cancelled_fork_point) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_fork_cancel_time);
        if (elapsed.count() < FORK_COOLDOWN_SECS) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[FORK-DETECT] Fork at point " << fork_point
                          << " on cooldown (" << elapsed.count() << "s/"
                          << FORK_COOLDOWN_SECS << "s) - skipping" << std::endl;
            m_fork_stall_cycles.store(0);
            return false;
        }
        // Cooldown expired, allow re-creation
        m_last_cancelled_fork_point = -1;
    }

    // Get the expected fork tip height from headers manager
    int headerTipHeight = header_height;
    if (m_node_context.headers_manager) {
        headerTipHeight = m_node_context.headers_manager->GetBestHeight();
    }

    // Get fork tip from competing tips (storage hash domain)
    uint256 forkTipHash;
    std::map<int32_t, uint256> expectedHashes;

    if (m_node_context.headers_manager) {
        const auto& tipsTracker = m_node_context.headers_manager->GetChainTipsTracker();
        auto competingTips = tipsTracker.GetCompetingTips();

        for (const auto& tip : competingTips) {
            if (tip.height == headerTipHeight) {
                forkTipHash = tip.hash;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Found fork tip from competing tips: "
                              << forkTipHash.GetHex().substr(0, 16)
                              << "... at height " << tip.height << std::endl;
                break;
            }
        }

        if (!forkTipHash.IsNull()) {
            if (!m_node_context.headers_manager->BuildForkAncestryHashes(
                    forkTipHash, fork_point, expectedHashes)) {
                std::cerr << "[FORK-DETECT] Failed to build fork ancestry" << std::endl;
            }
        } else {
            forkTipHash = m_node_context.headers_manager->GetRandomXHashAtHeight(headerTipHeight);
            std::cerr << "[FORK-DETECT] Warning: Using RandomX hash fallback" << std::endl;
        }
    }

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[FORK-DETECT] Creating fork staging candidate..." << std::endl;
        std::cout << "[FORK-DETECT] Fork point=" << fork_point
                  << " chain=" << chain_height
                  << " expected_tip=" << headerTipHeight
                  << " expected_hashes=" << expectedHashes.size() << std::endl;
    }

    auto forkCandidate = forkMgr.CreateForkCandidate(
        forkTipHash,
        chain_height,
        fork_point,
        headerTipHeight,
        expectedHashes
    );

    if (forkCandidate) {
        m_fork_detected.store(true);
        g_node_context.fork_detected.store(true);
        m_fork_point.store(fork_point);

        // BUG FIX: Clear block tracker above fork point so blocks can be re-requested
        // from the correct chain. Without this, IsTracked() may return true for heights
        // that are in m_completed_heights, preventing GetNextBlocksToRequest from
        // returning them. This was previously in HandleForkScenario() (dead code).
        if (m_node_context.block_fetcher) {
            int cleared = m_node_context.block_fetcher->ClearAboveHeight(fork_point);
            if (cleared > 0) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[FORK-DETECT] Cleared " << cleared << " tracked blocks above fork point " << fork_point << std::endl;
            }
        }

        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[FORK-DETECT] Fork candidate created, blocks will be staged for pre-validation" << std::endl;
            std::cout << "[FORK-DETECT] Original chain remains ACTIVE until fork is fully validated" << std::endl;
        }
    } else {
        std::cerr << "[FORK-DETECT] Failed to create fork candidate" << std::endl;
    }

    m_fork_stall_cycles.store(0);
    m_last_checked_chain_height = -1;  // Reset to allow fresh tracking
    return forkCandidate != nullptr;
}

// ============================================================================
// HEADERS SYNC PEER MANAGEMENT (Bitcoin Core style single-sync-peer)
// ============================================================================

void CIbdCoordinator::SelectHeadersSyncPeer() {
    // If we already have a sync peer, check if they're still connected
    if (m_headers_sync_peer != -1) {
        if (m_node_context.peer_manager) {
            // Use CNode::IsConnected() (authoritative) instead of CPeer::IsConnected() (deprecated)
            CNode* node = m_node_context.peer_manager->GetNode(m_headers_sync_peer);
            if (node && node->IsConnected()) {
                return;  // Current sync peer still valid
            }
        }
        // Sync peer disconnected, need to select a new one
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Headers sync peer " << m_headers_sync_peer << " disconnected" << std::endl;
        m_headers_sync_peer = -1;
    }

    // Select a new sync peer - prefer peers with more blocks
    if (!m_node_context.peer_manager || !m_node_context.headers_manager) {
        return;
    }

    auto peers = m_node_context.peer_manager->GetConnectedPeers();
    int best_peer = -1;
    int best_height = 0;

    for (const auto& peer : peers) {
        if (!peer) continue;
        // Skip peers that have been marked as bad (repeatedly failed to deliver headers)
        if (m_headers_bad_peers.count(peer->id) > 0) {
            continue;
        }
        // BUG FIX: Use best_known_height (dynamic) instead of GetPeerStartHeight (static)
        int peer_height = peer->best_known_height;
        if (peer_height == 0) peer_height = peer->start_height;
        if (peer_height > best_height) {
            best_height = peer_height;
            best_peer = peer->id;
        }
    }

    if (best_peer != -1) {
        m_headers_sync_peer = best_peer;
        m_headers_sync_peer_consecutive_stalls = 0;  // Reset stall counter for new peer
        m_headers_sync_last_height = m_node_context.headers_manager->GetBestHeight();
        m_headers_sync_last_processed = m_node_context.headers_manager->GetProcessedCount();

        // Calculate timeout: base + 1ms per missing header (Bitcoin Core style)
        // Manual peers (--connect/--addnode) get extended base timeout
        CNode* hdr_sync_node = m_node_context.connman ? m_node_context.connman->GetNode(best_peer) : nullptr;
        int hdr_base_secs = (hdr_sync_node && hdr_sync_node->fManual) ? 120 : HEADERS_SYNC_TIMEOUT_BASE_SECS;
        int headers_missing = best_height - m_headers_sync_last_height;
        int timeout_ms = hdr_base_secs * 1000 +
                         headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;
        m_headers_sync_timeout = std::chrono::steady_clock::now() +
                                 std::chrono::milliseconds(timeout_ms);

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Selected headers sync peer " << best_peer
                      << " (height=" << best_height << ", timeout=" << (timeout_ms/1000) << "s)" << std::endl;
    }
}

bool CIbdCoordinator::CheckHeadersSyncProgress() {
    if (m_headers_sync_peer == -1) {
        return true;  // No sync peer, nothing to check
    }

    // Manual peers (--connect/--addnode) get extended base timeout (120s vs 45s)
    CNode* hdr_sync_node = m_node_context.connman ? m_node_context.connman->GetNode(m_headers_sync_peer) : nullptr;
    int hdr_base_secs = (hdr_sync_node && hdr_sync_node->fManual) ? 120 : HEADERS_SYNC_TIMEOUT_BASE_SECS;

    // Skip stall check if already synced (header_height >= peer_height)
    if (m_node_context.headers_manager && m_node_context.peer_manager) {
        int header_height = m_node_context.headers_manager->GetBestHeight();
        // BUG FIX: Use best_known_height for dynamic peer height
        auto sync_peer = m_node_context.peer_manager->GetPeer(m_headers_sync_peer);
        int peer_height = sync_peer ? (sync_peer->best_known_height > 0 ? sync_peer->best_known_height : sync_peer->start_height)
                                    : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        if (header_height >= peer_height && peer_height > 0) {
            return true;  // Already synced with this peer
        }
    }

    auto now = std::chrono::steady_clock::now();
    int current_height = m_node_context.headers_manager ?
                         m_node_context.headers_manager->GetBestHeight() : 0;

    // Check if we've made progress (height increased = best chain advanced)
    if (current_height > m_headers_sync_last_height) {
        // Progress made, update tracking and extend timeout
        m_headers_sync_last_height = current_height;

        // FIX 2: Headers received - clear in-flight flag so this peer can receive block requests
        m_headers_in_flight = false;

        // Recalculate timeout based on remaining headers
        // BUG FIX: Use best_known_height for dynamic peer height
        auto progress_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = progress_peer ? (progress_peer->best_known_height > 0 ? progress_peer->best_known_height : progress_peer->start_height)
                                        : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        int headers_missing = peer_height - current_height;
        if (headers_missing > 0) {
            int timeout_ms = hdr_base_secs * 1000 +
                             headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;
            m_headers_sync_timeout = now + std::chrono::milliseconds(timeout_ms);
        }
        return true;  // Making progress
    }

    // Fork catch-up detection: headers may be received on a competing chain
    // without nBestHeight changing (canonical chain hasn't surpassed fork yet).
    // Track processed count to detect this and extend the timeout.
    if (m_node_context.headers_manager) {
        uint64_t current_processed = m_node_context.headers_manager->GetProcessedCount();
        if (current_processed > m_headers_sync_last_processed) {
            m_headers_sync_last_processed = current_processed;
            // Headers are being received and stored - extend timeout
            auto progress_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
            int peer_height = progress_peer ? (progress_peer->best_known_height > 0 ? progress_peer->best_known_height : progress_peer->start_height)
                                            : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
            int headers_missing = peer_height - current_height;
            if (headers_missing > 0) {
                int timeout_ms = hdr_base_secs * 1000 +
                                 headers_missing * HEADERS_SYNC_TIMEOUT_PER_HEADER_MS;
                m_headers_sync_timeout = now + std::chrono::milliseconds(timeout_ms);
            }
            return true;  // Fork catch-up in progress
        }
    }

    // Check for timeout
    if (now > m_headers_sync_timeout) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[IBD] Headers sync peer " << m_headers_sync_peer
                      << " STALLED (no progress, timeout reached)" << std::endl;
        return false;  // Stalled
    }

    return true;  // Not stalled yet
}

void CIbdCoordinator::SwitchHeadersSyncPeer() {
    int old_peer = m_headers_sync_peer;

    // BAD PEER TRACKING: Track consecutive stalls for this peer
    if (old_peer != -1) {
        m_headers_sync_peer_consecutive_stalls++;
        if (m_headers_sync_peer_consecutive_stalls >= MAX_HEADERS_CONSECUTIVE_STALLS) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Headers sync peer " << old_peer
                          << " repeatedly failed to deliver headers (" << m_headers_sync_peer_consecutive_stalls
                          << " stalls), marking as bad peer" << std::endl;
            m_headers_bad_peers.insert(old_peer);
            m_headers_sync_peer_consecutive_stalls = 0;
        }
    }

    m_headers_sync_peer = -1;  // Force reselection

    SelectHeadersSyncPeer();

    if (m_headers_sync_peer != -1) {
        if (m_headers_sync_peer != old_peer) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Switched headers sync peer: " << old_peer
                          << " -> " << m_headers_sync_peer << std::endl;
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Retrying headers sync with same peer " << m_headers_sync_peer << std::endl;
        }

        // BUG #195 FIX: Clear pending sync state when switching peers after a stall.
        // This ensures the new request uses our validated tip (hashBestHeader) instead of
        // a stale m_last_request_hash that the new peer may not recognize.
        m_node_context.headers_manager->ClearPendingSync();

        // SSOT: Request headers via single entry point
        // BUG FIX: Use best_known_height for dynamic peer height
        auto new_peer = m_node_context.peer_manager ? m_node_context.peer_manager->GetPeer(m_headers_sync_peer) : nullptr;
        int peer_height = new_peer ? (new_peer->best_known_height > 0 ? new_peer->best_known_height : new_peer->start_height)
                                   : m_node_context.headers_manager->GetPeerStartHeight(m_headers_sync_peer);
        if (m_node_context.headers_manager->SyncHeadersFromPeer(m_headers_sync_peer, peer_height)) {
            m_headers_in_flight = true;
        }
    }
}


