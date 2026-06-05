// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_BLOCK_TRACKER_H
#define DILITHION_BLOCK_TRACKER_H

#include <uint256.h>
#include <map>
#include <set>
#include <vector>
#include <mutex>
#include <chrono>
#include <iostream>
#include <sstream>

/**
 * @file block_tracker.h
 * @brief SINGLE SOURCE OF TRUTH for per-block download tracking
 *
 * CBlockTracker tracks all in-flight block requests. No window - tracks exactly
 * what's requested. When a block arrives (by hash), lookup the height and clean up.
 *
 * Design:
 * - AddBlock(height, hash, peer) - called when requesting a block
 * - OnBlockReceived(hash) - called when block arrives, O(1) cleanup via hash lookup
 * - GetPeerInFlightCount(peer) - for capacity limits
 * - OnPeerDisconnected(peer) - cleanup when peer goes away
 */

using NodeId = int;

/**
 * @brief Block state (simplified - just tracking in-flight)
 */
enum class BlockState {
    IN_FLIGHT,    ///< Requested from peer, awaiting response
    RECEIVED      ///< Block received (will be removed from tracking shortly)
};

/**
 * @class CBlockTracker
 * @brief Single source of truth for block download state
 *
 * Thread-safe: All public methods acquire the internal mutex.
 */
class CBlockTracker {
public:
    // Configuration
    static constexpr int MAX_PER_PEER = 128;           ///< Maximum in-flight blocks per peer
    static constexpr int MAX_TOTAL = 256;              ///< Maximum total in-flight blocks
    static constexpr int TIMEOUT_SECONDS = 120;        ///< Seconds before block times out
    static constexpr int COMPLETED_HEIGHT_TTL_SECONDS = 120; ///< M-2: age out stuck completed heights after this (F-013 §M-2)

    CBlockTracker() = default;

    // =========================================================================
    // Core Operations
    // =========================================================================

    /**
     * @brief Add a block to tracking when requesting from peer
     * @param height Block height
     * @param hash Block hash
     * @param peer Peer we're requesting from
     * @return true if added, false if already tracked or at capacity
     */
    bool AddBlock(int height, const uint256& hash, NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Already tracking this height?
        if (m_heights.count(height) > 0) {
            return false;
        }

        // DEDUP-LIVELOCK FIX (mission dilv-dedup-livelock-fix, F-001):
        // Also reject heights already marked completed. MarkCompleted means the block
        // is already in the DB (orphan-with-data / blockInDb / reprocessed paths), so it
        // must NOT be re-requested over the wire -- it resolves via parent-connection
        // orphan processing once its parent connects. IsTracked() already consults
        // m_completed_heights, so GetNextBlocksToRequest skips these; this closes the
        // gap for DIRECT callers (stall-recovery ibd_coordinator.cpp:2135/2057/1657) that
        // bypass selection and previously re-requested completed heights every ~1s,
        // tripping the seed's 3-strike DEDUP disconnect and stalling IBD. Reorg-safe:
        // ClearAboveHeight() clears m_completed_heights above a fork point before any
        // legitimate post-reorg re-fetch. Restores the invariant that the dedup read
        // tracks the MarkCompleted write (principle #3).
        if (m_completed_heights.count(height) > 0) {
            return false;
        }

        // Check capacity
        if (GetPeerInFlightCountLocked(peer) >= MAX_PER_PEER) {
            return false;
        }
        if (GetTotalInFlightLocked() >= MAX_TOTAL) {
            return false;
        }

        // Add to tracking
        m_heights[height] = BlockInfo{
            hash,
            peer,
            std::chrono::steady_clock::now()
        };

        // Update indexes
        m_hash_to_height[hash] = height;
        m_peer_heights[peer].insert(height);

        return true;
    }

    /**
     * @brief Called when block arrives - looks up height from hash and cleans up
     * @param hash Block hash
     * @return height if found and cleaned up, -1 if not tracked
     */
    int OnBlockReceived(const uint256& hash) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Lookup height from hash
        auto hash_it = m_hash_to_height.find(hash);
        if (hash_it == m_hash_to_height.end()) {
            return -1;  // Not tracked
        }

        int height = hash_it->second;

        // Get the block info
        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            // Inconsistent state - clean up hash map
            m_hash_to_height.erase(hash_it);
            return -1;
        }

        NodeId peer = height_it->second.peer;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up hash and height maps
        m_hash_to_height.erase(hash_it);
        m_heights.erase(height_it);

        return height;
    }

    /**
     * @brief Called when block arrives (by height if known)
     * @param height Block height
     * @return true if found and cleaned up
     */
    bool OnBlockReceivedByHeight(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            return false;  // Not tracked
        }

        uint256 hash = height_it->second.hash;
        NodeId peer = height_it->second.peer;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up hash and height maps
        m_hash_to_height.erase(hash);
        m_heights.erase(height_it);

        return true;
    }

    /**
     * @brief Handle peer disconnection - remove all peer's blocks from tracking
     * @param peer Disconnected peer ID
     * @return Vector of heights that were being downloaded from this peer
     */
    std::vector<int> OnPeerDisconnected(NodeId peer) {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<int> heights_returned;

        auto peer_it = m_peer_heights.find(peer);
        if (peer_it == m_peer_heights.end()) {
            return heights_returned;
        }

        // Copy the set since we'll modify m_heights
        std::set<int> heights = peer_it->second;

        for (int height : heights) {
            auto h_it = m_heights.find(height);
            if (h_it != m_heights.end()) {
                // Remove from hash map
                m_hash_to_height.erase(h_it->second.hash);
                // Remove from heights
                m_heights.erase(h_it);
                heights_returned.push_back(height);
            }
        }

        m_peer_heights.erase(peer_it);

        return heights_returned;
    }

    // =========================================================================
    // Queries
    // =========================================================================

    /**
     * @brief Get number of in-flight blocks for a peer
     */
    int GetPeerInFlightCount(NodeId peer) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return GetPeerInFlightCountLocked(peer);
    }

    /**
     * @brief Check if peer has capacity for more blocks
     */
    bool HasPeerCapacity(NodeId peer) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return GetPeerInFlightCountLocked(peer) < MAX_PER_PEER;
    }

    /**
     * @brief Get total number of in-flight blocks
     */
    int GetTotalInFlight() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_heights.size();
    }

    /**
     * @brief Check if a height is being tracked (in-flight or completed)
     */
    bool IsTracked(int height) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_heights.count(height) > 0 || m_completed_heights.count(height) > 0;
    }

    /**
     * @brief Get height for a hash (for external callers)
     */
    int GetHeightForHash(const uint256& hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hash_to_height.find(hash);
        return (it != m_hash_to_height.end()) ? it->second : -1;
    }

    /**
     * @brief Get all tracked heights with their assigned peers
     * BUG #246b FIX: Used to identify stale in-flight blocks from disconnected peers
     * @return Map of height -> peer_id for all in-flight blocks
     */
    std::map<int, NodeId> GetTrackedHeights() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<int, NodeId> result;
        for (const auto& [height, info] : m_heights) {
            result[height] = info.peer;
        }
        return result;
    }

    /**
     * @brief Get heights that have timed out
     * @param timeout_seconds Custom timeout (default: TIMEOUT_SECONDS)
     */
    std::vector<std::pair<int, NodeId>> CheckTimeouts(int timeout_seconds = TIMEOUT_SECONDS) const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<std::pair<int, NodeId>> timed_out;
        auto now = std::chrono::steady_clock::now();
        auto timeout = std::chrono::seconds(timeout_seconds);

        for (const auto& [height, info] : m_heights) {
            if (now - info.request_time > timeout) {
                timed_out.push_back({height, info.peer});
            }
        }

        return timed_out;
    }

    /**
     * @brief Remove a timed-out block from tracking
     * @return The peer that was downloading it
     */
    NodeId RemoveTimedOut(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto height_it = m_heights.find(height);
        if (height_it == m_heights.end()) {
            return -1;
        }

        NodeId peer = height_it->second.peer;
        uint256 hash = height_it->second.hash;

        // Clean up peer tracking
        auto peer_it = m_peer_heights.find(peer);
        if (peer_it != m_peer_heights.end()) {
            peer_it->second.erase(height);
            if (peer_it->second.empty()) {
                m_peer_heights.erase(peer_it);
            }
        }

        // Clean up maps
        m_hash_to_height.erase(hash);
        m_heights.erase(height_it);

        return peer;
    }

    /**
     * @brief Get status string for logging
     */
    std::string GetStatus() const {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::ostringstream ss;
        ss << "InFlight=" << m_heights.size()
           << " peers=" << m_peer_heights.size();
        return ss.str();
    }

    /**
     * @brief Get the age (seconds) of a tracked height, or -1 if not tracked
     */
    int GetTrackingAge(int height) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_heights.find(height);
        if (it == m_heights.end()) return -1;
        auto age = std::chrono::steady_clock::now() - it->second.request_time;
        return std::chrono::duration_cast<std::chrono::seconds>(age).count();
    }

    /**
     * @brief Check if tracker has any blocks
     */
    bool IsInitialized() const {
        // For compatibility - always return true so callers use us
        return true;
    }

    /**
     * @brief Mark a height as completed (already in DB, no need to request)
     *
     * Used during fork recovery when blocks are found already in the DB.
     * Prevents GetNextBlocksToRequest from returning these heights again.
     */
    void MarkCompleted(int height) {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Record insert time so a stuck entry can be aged out (M-2 liveness backstop).
        // Use insert (not operator[]=) so an existing entry keeps its ORIGINAL insert
        // time -- re-marking a still-completed height must not refresh its age and
        // postpone the age-out backstop indefinitely.
        m_completed_heights.emplace(height, std::chrono::steady_clock::now());
    }

    /**
     * @brief M-2 LIVENESS BACKSTOP: age out stale completed-height entries.
     *
     * A completed height is normally cleared by Clear() (reset) or ClearAboveHeight()
     * (reorg). On the narrow divergent-hash-at-same-height-WITHOUT-reorg path
     * (F-013 §M-2) neither fires, so AddBlock's completed-height reject (line 86)
     * would permanently refuse the stall-recovery force-request and stall IBD silently.
     * This method clears completed entries older than COMPLETED_HEIGHT_TTL_SECONDS so the
     * next force-request's AddBlock succeeds and a GETDATA is pushed -- liveness restored.
     * Called on the existing RetryTimeoutsAndStalls cadence (ibd_coordinator.cpp).
     *
     * Reorg-safe: this only DROPS completed flags; it never re-fetches, never touches
     * m_heights, and is a strict superset of the existing ClearAboveHeight semantics
     * (which still clears the same set above a fork point).
     *
     * @param ttl_seconds Entries older than this are cleared (default COMPLETED_HEIGHT_TTL_SECONDS)
     * @return number of stale completed entries cleared
     */
    int RetryStaleCompleted(int ttl_seconds = COMPLETED_HEIGHT_TTL_SECONDS) {
        std::lock_guard<std::mutex> lock(m_mutex);
        int cleared = 0;
        auto now = std::chrono::steady_clock::now();
        auto ttl = std::chrono::seconds(ttl_seconds);
        for (auto it = m_completed_heights.begin(); it != m_completed_heights.end();) {
            if (now - it->second > ttl) {
                it = m_completed_heights.erase(it);
                ++cleared;
            } else {
                ++it;
            }
        }
        return cleared;
    }

    /**
     * @brief Clear all tracking (for reset/reinit)
     */
    void Clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_heights.clear();
        m_hash_to_height.clear();
        m_peer_heights.clear();
        m_completed_heights.clear();
    }

    /**
     * @brief Clear all blocks above a given height (for fork recovery)
     * @param fork_point All blocks with height > fork_point will be removed
     * @return Number of blocks removed
     */
    int ClearAboveHeight(int fork_point) {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<int> heights_to_remove;

        // Find all heights above fork_point
        for (const auto& [height, info] : m_heights) {
            if (height > fork_point) {
                heights_to_remove.push_back(height);
            }
        }

        // Remove each one
        for (int height : heights_to_remove) {
            auto height_it = m_heights.find(height);
            if (height_it != m_heights.end()) {
                NodeId peer = height_it->second.peer;
                uint256 hash = height_it->second.hash;

                // Clean up peer tracking
                auto peer_it = m_peer_heights.find(peer);
                if (peer_it != m_peer_heights.end()) {
                    peer_it->second.erase(height);
                    if (peer_it->second.empty()) {
                        m_peer_heights.erase(peer_it);
                    }
                }

                // Clean up maps
                m_hash_to_height.erase(hash);
                m_heights.erase(height_it);
            }
        }

        // Also clear completed heights above fork_point
        for (auto it = m_completed_heights.begin(); it != m_completed_heights.end();) {
            if (it->first > fork_point) {
                it = m_completed_heights.erase(it);
            } else {
                ++it;
            }
        }

        return heights_to_remove.size();
    }

private:
    // Lock-ordering safety invariant (PR10.2-RT-INFO-1, 2026-05-01):
    //   m_mutex is acquired ONLY internally by CBlockTracker public methods.
    //   No method on CBlockTracker calls into CPeerManager (cs_peers),
    //   CConnman (cs_vNodes), CHeadersManager (cs_headers), or any other
    //   external subsystem from inside the locked region. This invariant
    //   preserves the one-way Dilithion lock-acquisition order
    //     {cs_vNodes, cs_peers, cs_headers} → block_tracker.m_mutex
    //   that PR10.2's CPeerManager::GetBlockDownloadSnapshot relies on
    //   for its `cs_peers → m_mutex` nested acquisition to be safe
    //   (no inversion possible).
    //
    //   FUTURE MAINTAINERS: adding any callback / peer-event / chain-
    //   state touch INTO this class from inside m_mutex's locked scope
    //   would silently break PR10.2's safety claim and could introduce
    //   deadlock with CPeerManager::GetBlockDownloadSnapshot or
    //   peers.cpp:1085 / :1242 nested-lock sites (PR10.6-RT-LOW-1
    //   corrected line numbers from initial PR10.2 commit). Don't.
    mutable std::mutex m_mutex;

    // Heights that are already in DB (no need to request).
    // M-2 LIVENESS FIX (F-013 §M-2): each completed height carries its insert time so
    // RetryStaleCompleted() can age out an entry that got stuck on the divergent-hash
    // no-reorg path (a completed height whose stored hash != IBD-expected hash, with no
    // reorg/ClearAboveHeight ever firing). Without this, AddBlock's completed-height
    // reject (line 86) permanently refuses the force-request at ibd_coordinator.cpp:2135,
    // pushing no GETDATA -> silent IBD stall with no timeout that ever clears the entry.
    std::map<int, std::chrono::steady_clock::time_point> m_completed_heights;

    // Per-height state
    struct BlockInfo {
        uint256 hash;
        NodeId peer;
        std::chrono::steady_clock::time_point request_time;
    };
    std::map<int, BlockInfo> m_heights;              ///< height -> info

    // Indexes for O(1) lookups
    std::map<uint256, int> m_hash_to_height;         ///< hash -> height
    std::map<NodeId, std::set<int>> m_peer_heights;  ///< peer -> set of heights

    // =========================================================================
    // Internal helpers (must be called with lock held)
    // =========================================================================

    int GetPeerInFlightCountLocked(NodeId peer) const {
        auto it = m_peer_heights.find(peer);
        return (it != m_peer_heights.end()) ? it->second.size() : 0;
    }

    int GetTotalInFlightLocked() const {
        return m_heights.size();
    }
};

#endif // DILITHION_BLOCK_TRACKER_H
