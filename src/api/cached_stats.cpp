// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <api/cached_stats.h>

#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <cmath>

// Deferred reclamation: this thread resolves CBlockIndex*, so it checkpoints.
// g_chainstate is defined in src/core/globals.cpp and declared per-TU (the idiom
// used by headers_manager.cpp / block_processing.cpp / tx_index.cpp).
#include <consensus/chain.h>
extern CChainState g_chainstate;

CCachedChainStats::CCachedChainStats() = default;

CCachedChainStats::~CCachedChainStats() {
    Stop();
}

bool CCachedChainStats::Start(UpdateCallback callback) {
    if (m_running.load()) {
        return false;  // Already running
    }

    m_callback = std::move(callback);
    m_shutdown.store(false);
    m_running.store(true);
    g_chainstate.DeclareEpochParticipant("cached-stats");
    m_thread = std::thread(&CCachedChainStats::UpdateThread, this);

    std::cout << "[CachedStats] Started background update thread (interval: "
              << UPDATE_INTERVAL_MS << "ms)" << std::endl;

    return true;
}

void CCachedChainStats::Stop() {
    if (!m_running.load()) {
        return;
    }

    m_shutdown.store(true);
    m_running.store(false);

    if (m_thread.joinable()) {
        m_thread.join();
    }

    std::cout << "[CachedStats] Stopped background update thread" << std::endl;
}

void CCachedChainStats::UpdateThread() {
    while (!m_shutdown.load()) {
        // DEFERRED-RECLAMATION CHECKPOINT — loop top, before the callback and the
        // sleep. The injected callback resolves the tip and walks up to 20 pprev
        // links (see the node binaries' cached_stats.Start lambda), so this thread
        // holds index pointers — and it runs on EVERY node, unconditionally, once
        // a second. Nothing in this file mentions CBlockIndex, which is exactly
        // why it was missed: the resolve is inside an injected callback.
        g_chainstate.EpochCheckpoint("cached-stats");

        try {
            // Get current state from callback
            UpdateData data = m_callback();

            // Update atomic values
            m_block_height.store(data.block_height);
            m_headers_height.store(data.headers_height);
            m_peer_count.store(data.peer_count);
            m_difficulty.store(data.difficulty);
            m_last_block_time.store(data.last_block_time);
            m_actual_block_time_ms.store(static_cast<int>(data.actual_block_time * 1000.0));
            m_is_syncing.store(data.is_syncing);

            // Update cache timestamp
            auto now = std::chrono::system_clock::now();
            m_cache_time.store(std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count());

        } catch (const std::exception& e) {
            std::cerr << "[CachedStats] Update error: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[CachedStats] Unknown update error" << std::endl;
        }

        // ⚠️ OFFLINE ACROSS THE SLEEP (round-8 F46). One second is a small pin
        // next to the miner's two minutes -- and it is a pin on EVERY node,
        // FOREVER, because this updater runs at 1 Hz for the life of the process.
        // It spends essentially all of its time here, so the epoch it published
        // before the sleep is the one that caps DrainGraveyard's minimum for
        // essentially all of that time. A small pin held permanently is not a
        // small problem, and the rule has to be uniform or the next reader has to
        // re-derive where the line is.
        //
        // Safe by construction: the update above has returned, so nothing resolved
        // in this round is still live, and the loop re-enters before the next one.
        {
            EpochOfflineScope offline(&g_chainstate);
            std::this_thread::sleep_for(std::chrono::milliseconds(UPDATE_INTERVAL_MS));
        }
    }
}

std::string CCachedChainStats::ToJSON(const std::string& network) const {
    // All reads are lock-free atomic loads
    int block_height = m_block_height.load();
    int headers_height = m_headers_height.load();
    int peer_count = m_peer_count.load();
    uint32_t difficulty = m_difficulty.load();
    int64_t cache_time = m_cache_time.load();
    int64_t last_block_time = m_last_block_time.load();
    bool is_syncing = m_is_syncing.load();

    // Calculate derived values
    int64_t total_supply = block_height * 50;  // 50 coins per block
    int blocks_until_halving = 210000 - block_height;
    int64_t cache_age = GetCacheAge();

    // Calculate network hashrate from nBits and actual block time
    // hashrate = (2^256 / target) / actual_block_time
    // Uses actual average block time from recent blocks instead of target (240s)
    // so the displayed hashrate reflects real mining power, not just difficulty
    int64_t network_hashrate = 0;
    double actual_block_time = m_actual_block_time_ms.load() / 1000.0;
    if (actual_block_time < 1.0) actual_block_time = 240.0;  // Safety floor
    if (difficulty > 0) {
        int exp = difficulty >> 24;
        uint32_t mantissa = difficulty & 0x7fffff;
        if (mantissa > 0 && exp > 0) {
            double log2_target = std::log2(static_cast<double>(mantissa)) + 8.0 * (exp - 3);
            double log2_hashes = 256.0 - log2_target;
            double expected_hashes = std::pow(2.0, log2_hashes);
            network_hashrate = static_cast<int64_t>(expected_hashes / actual_block_time);
        }
    }

    // Calculate human-readable difficulty (max_target / current_target)
    // Dilithion max target: 0x1f060000
    double difficulty_float = 0.0;
    if (difficulty > 0) {
        const uint32_t maxBits = 0x1f060000;
        int maxExp = maxBits >> 24;           // 31
        uint32_t maxMantissa = maxBits & 0x7fffff;  // 393216
        int curExp = difficulty >> 24;
        uint32_t curMantissa = difficulty & 0x7fffff;
        if (curMantissa > 0) {
            difficulty_float = static_cast<double>(maxMantissa) / static_cast<double>(curMantissa) * std::pow(256.0, maxExp - curExp);
        }
    }

    // Build JSON response
    std::ostringstream json;
    json << std::fixed;
    json << "{\n";
    json << "  \"timestamp\": \"" << std::time(nullptr) << "\",\n";
    json << "  \"network\": \"" << network << "\",\n";
    json << "  \"blockHeight\": " << block_height << ",\n";
    json << "  \"headersHeight\": " << headers_height << ",\n";
    json << std::setprecision(8);
    json << "  \"difficulty\": " << difficulty_float << ",\n";
    json << std::setprecision(0);
    json << "  \"networkHashRate\": " << network_hashrate << ",\n";
    json << "  \"totalSupply\": " << total_supply << ",\n";
    json << "  \"blockReward\": 50,\n";
    json << "  \"blocksUntilHalving\": " << blocks_until_halving << ",\n";
    json << "  \"peerCount\": " << peer_count << ",\n";
    json << "  \"averageBlockTime\": 240,\n";
    json << "  \"lastBlockTime\": " << last_block_time << ",\n";
    json << "  \"status\": \"" << (is_syncing ? "syncing" : "live") << "\",\n";
    json << "  \"cacheAge\": " << cache_age << ",\n";
    json << "  \"cached\": true\n";
    json << "}";

    return json.str();
}
