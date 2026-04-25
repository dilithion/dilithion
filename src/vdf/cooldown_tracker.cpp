#include "cooldown_tracker.h"
#include <algorithm>
#include <iostream>

int CCooldownTracker::CalculateCooldown(int activeMiners)
{
    // Formula: cooldown = floor(activeMiners * 0.67)
    // At 22 miners → 14 blocks cooldown (8 miners eligible per round)
    // At 10 miners →  6 blocks cooldown (4 miners eligible per round)
    // At 50 miners → 33 blocks cooldown (17 miners eligible per round)
    // Keeps ~33% of miners eligible at any given height, providing
    // randomness from the VDF distribution while still rate-limiting.
    int cooldown = static_cast<int>(activeMiners * 67 / 100);
    return std::clamp(cooldown, MIN_COOLDOWN, MAX_COOLDOWN);
}

int CCooldownTracker::ComputeEffectiveCooldown(int height) const
{
    // Caller must hold m_mutex.
    RecalcActiveMiners(height);
    int longCooldown = CalculateCooldown(m_cachedActiveMinersMut);

    if (height >= m_stabilizationHeight && m_shortWindow > 0) {
        RecalcShortActiveMiners(height);
        int shortMiners = m_cachedShortActiveMinersMut;
        int shortCooldown = CalculateCooldown(shortMiners);
        return std::min(longCooldown, shortCooldown);
    }

    return longCooldown;
}

bool CCooldownTracker::IsInCooldown(const Address& addr, int height, int64_t currentTimestamp) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_lastWinHeight.find(addr);
    if (it == m_lastWinHeight.end())
        return false;

    int cooldown = ComputeEffectiveCooldown(height);
    int blockGap = height - it->second;

    // Block-gap expiry: not in cooldown if enough blocks have passed
    if (blockGap >= cooldown)
        return false;

    // Time-based expiry (post-stabilization, when timestamp provided).
    if (height >= m_stabilizationHeight && currentTimestamp > 0) {
        auto tsIt = m_lastWinTimestamp.find(addr);
        if (tsIt != m_lastWinTimestamp.end() && tsIt->second > 0) {
            int64_t timeGap = currentTimestamp - tsIt->second;
            int64_t timeCooldown = static_cast<int64_t>(cooldown) * m_targetBlockTime;
            // DEBUG: dump full state for blocks near 259
            if (height >= 255 && height <= 265) {
                std::cerr << "[COOLDOWN-TRACE] h=" << height
                          << " lastWinH=" << it->second
                          << " blockGap=" << blockGap
                          << " cooldown=" << cooldown
                          << " blockTs=" << currentTimestamp
                          << " lastWinTs=" << tsIt->second
                          << " timeGap=" << timeGap
                          << " timeCooldown=" << timeCooldown
                          << " timeExpired=" << (timeGap >= timeCooldown ? "YES" : "NO")
                          << " entries=" << m_heightToWinner.size()
                          << " stabH=" << m_stabilizationHeight
                          << " target=" << m_targetBlockTime
                          << std::endl;
            }
            if (timeGap >= timeCooldown)
                return false;  // time-based expiry
        } else if (height >= 255 && height <= 265) {
            std::cerr << "[COOLDOWN-TRACE] h=" << height
                      << " lastWinH=" << it->second
                      << " NO TIMESTAMP for this MIK (tsIt="
                      << (tsIt == m_lastWinTimestamp.end() ? "END" : "ZERO")
                      << ")" << std::endl;
        }
    }

    return true;  // still in cooldown
}

bool CCooldownTracker::IsInCooldownExcludingHeight(const Address& addr, int height, int64_t currentTimestamp, int excludeHeight) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Fast path: nothing to exclude.
    if (excludeHeight < 0 || m_heightToWinner.find(excludeHeight) == m_heightToWinner.end()) {
        auto it = m_lastWinHeight.find(addr);
        if (it == m_lastWinHeight.end()) return false;
        int cooldown = ComputeEffectiveCooldown(height);
        int blockGap = height - it->second;
        if (blockGap >= cooldown) return false;
        if (height >= m_stabilizationHeight && currentTimestamp > 0) {
            auto tsIt = m_lastWinTimestamp.find(addr);
            if (tsIt != m_lastWinTimestamp.end() && tsIt->second > 0) {
                int64_t timeGap = currentTimestamp - tsIt->second;
                int64_t timeCooldown = static_cast<int64_t>(cooldown) * m_targetBlockTime;
                if (timeGap >= timeCooldown) return false;
            }
        }
        return true;
    }

    // Simulate state with excludeHeight removed.
    std::map<Address, int> simLastWin = m_lastWinHeight;
    std::map<int, Address> simHeightToWinner = m_heightToWinner;
    std::map<Address, int64_t> simLastWinTs = m_lastWinTimestamp;
    std::map<int, int64_t> simHeightToTs = m_heightToTimestamp;

    Address excludedWinner = simHeightToWinner[excludeHeight];
    simHeightToWinner.erase(excludeHeight);
    simHeightToTs.erase(excludeHeight);

    int lastWin = -1;
    for (auto rit = simHeightToWinner.rbegin(); rit != simHeightToWinner.rend(); ++rit) {
        if (rit->second == excludedWinner) {
            lastWin = rit->first;
            break;
        }
    }
    if (lastWin >= 0) {
        simLastWin[excludedWinner] = lastWin;
        auto tsIt = simHeightToTs.find(lastWin);
        if (tsIt != simHeightToTs.end()) simLastWinTs[excludedWinner] = tsIt->second;
        else simLastWinTs.erase(excludedWinner);
    } else {
        simLastWin.erase(excludedWinner);
        simLastWinTs.erase(excludedWinner);
    }

    auto it = simLastWin.find(addr);
    if (it == simLastWin.end()) return false;

    // Recompute active miners at target height from simulated winner map.
    int cutoff = height - m_activeWindow + 1;
    std::set<Address> uniqueLong;
    for (auto iter = simHeightToWinner.lower_bound(cutoff);
         iter != simHeightToWinner.end() && iter->first <= height; ++iter) {
        uniqueLong.insert(iter->second);
    }
    int longCooldown = CalculateCooldown(static_cast<int>(uniqueLong.size()));
    int cooldown = longCooldown;

    if (height >= m_stabilizationHeight && m_shortWindow > 0) {
        int shortCutoff = height - m_shortWindow + 1;
        std::set<Address> uniqueShort;
        for (auto iter = simHeightToWinner.lower_bound(shortCutoff);
             iter != simHeightToWinner.end() && iter->first <= height; ++iter) {
            uniqueShort.insert(iter->second);
        }
        int shortCooldown = CalculateCooldown(static_cast<int>(uniqueShort.size()));
        cooldown = std::min(longCooldown, shortCooldown);
    }

    int blockGap = height - it->second;
    if (blockGap >= cooldown) return false;

    if (height >= m_stabilizationHeight && currentTimestamp > 0) {
        auto tsIt = simLastWinTs.find(addr);
        if (tsIt != simLastWinTs.end() && tsIt->second > 0) {
            int64_t timeGap = currentTimestamp - tsIt->second;
            int64_t timeCooldown = static_cast<int64_t>(cooldown) * m_targetBlockTime;
            if (timeGap >= timeCooldown) return false;
        }
    }

    return true;
}

int CCooldownTracker::GetActiveMinersExcludingHeight(int height, int excludeHeight) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Fast path.
    if (excludeHeight < 0 || m_heightToWinner.find(excludeHeight) == m_heightToWinner.end()) {
        int cutoff = height - m_activeWindow + 1;
        std::set<Address> unique;
        for (auto it = m_heightToWinner.lower_bound(cutoff);
             it != m_heightToWinner.end() && it->first <= height; ++it) {
            unique.insert(it->second);
        }
        return static_cast<int>(unique.size());
    }

    std::map<int, Address> simHeightToWinner = m_heightToWinner;
    simHeightToWinner.erase(excludeHeight);

    int cutoff = height - m_activeWindow + 1;
    std::set<Address> unique;
    for (auto it = simHeightToWinner.lower_bound(cutoff);
         it != simHeightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }
    return static_cast<int>(unique.size());
}

int CCooldownTracker::GetCooldownBlocks() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    // Use the most recent cached count; caller should have triggered
    // a RecalcActiveMiners via IsInCooldown or OnBlockConnected first.
    return CalculateCooldown(m_cachedActiveMinersMut);
}

int CCooldownTracker::GetActiveMiners() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cachedActiveMinersMut;
}

int CCooldownTracker::GetShortActiveMiners() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_cachedShortActiveMinersMut;
}

int CCooldownTracker::GetBlockCountInWindow(const Address& addr, int height, int window) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int count = 0;
    int fromHeight = std::max(0, height - window + 1);
    // Iterate over the height→winner map in the window range
    auto it = m_heightToWinner.lower_bound(fromHeight);
    auto end = m_heightToWinner.upper_bound(height);
    for (; it != end; ++it) {
        if (it->second == addr)
            ++count;
    }
    return count;
}

std::vector<CCooldownTracker::Address> CCooldownTracker::GetKnownAddresses() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<Address> result;
    result.reserve(m_lastWinHeight.size());
    for (const auto& [addr, _] : m_lastWinHeight) {
        result.push_back(addr);
    }
    return result;
}

int CCooldownTracker::GetLastWinHeight(const Address& addr) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_lastWinHeight.find(addr);
    return (it != m_lastWinHeight.end()) ? it->second : -1;
}

int CCooldownTracker::GetEffectiveCooldown(int height) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return ComputeEffectiveCooldown(height);
}

void CCooldownTracker::OnBlockConnected(int height, const Address& winner, int64_t blockTimestamp)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_lastWinHeight[winner] = height;
    m_heightToWinner[height] = winner;

    // v4.0.21 — Patch C: increment lifetime block count for this winner.
    // Deterministic: pure function of canonical chain state.
    m_lifetimeBlockCount[winner]++;

    // Store timestamp for time-based expiry
    if (blockTimestamp > 0) {
        m_lastWinTimestamp[winner] = blockTimestamp;
        m_heightToTimestamp[height] = blockTimestamp;
    }

    // Evict entries outside the active window [height - m_activeWindow + 1, height].
    int cutoff = height - m_activeWindow + 1;
    auto it = m_heightToWinner.begin();
    while (it != m_heightToWinner.end() && it->first < cutoff) {
        // Only remove from m_lastWinHeight if this was their most recent win.
        auto lwh = m_lastWinHeight.find(it->second);
        if (lwh != m_lastWinHeight.end() && lwh->second == it->first) {
            m_lastWinHeight.erase(lwh);
            m_lastWinTimestamp.erase(it->second);
        }
        m_heightToTimestamp.erase(it->first);
        it = m_heightToWinner.erase(it);
    }

    // Recalc active miners at this height.
    RecalcActiveMiners(height);
    // Invalidate short cache (will be recomputed on next query)
    m_cachedShortAtHeightMut = -1;
}

void CCooldownTracker::OnBlockDisconnected(int height)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_heightToWinner.find(height);
    if (it == m_heightToWinner.end())
        return;

    Address winner = it->second;
    m_heightToWinner.erase(it);
    m_heightToTimestamp.erase(height);
    m_heightToRegistration.erase(height);  // Layer 3: undo registration tracking

    // v4.0.21 — Patch C: decrement lifetime block count. Remove the entry
    // entirely if it reaches zero so GetLifetimeMinerCount() returns the
    // accurate count of MIKs with at least one block on the active chain.
    auto lifeIt = m_lifetimeBlockCount.find(winner);
    if (lifeIt != m_lifetimeBlockCount.end()) {
        if (--lifeIt->second <= 0) {
            m_lifetimeBlockCount.erase(lifeIt);
        }
    }

    // Recompute the address's last win height from remaining entries.
    // Scan backwards from the end of m_heightToWinner.
    int lastWin = -1;
    for (auto rit = m_heightToWinner.rbegin(); rit != m_heightToWinner.rend(); ++rit) {
        if (rit->second == winner) {
            lastWin = rit->first;
            break;
        }
    }

    if (lastWin >= 0) {
        m_lastWinHeight[winner] = lastWin;
        // Recover timestamp from height→timestamp map
        auto tsIt = m_heightToTimestamp.find(lastWin);
        if (tsIt != m_heightToTimestamp.end()) {
            m_lastWinTimestamp[winner] = tsIt->second;
        } else {
            m_lastWinTimestamp.erase(winner);
        }
    } else {
        m_lastWinHeight.erase(winner);
        m_lastWinTimestamp.erase(winner);
    }

    // Invalidate caches so next query recalculates.
    m_cachedAtHeightMut = -1;
    m_cachedShortAtHeightMut = -1;
}

void CCooldownTracker::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastWinHeight.clear();
    m_heightToWinner.clear();
    m_lastWinTimestamp.clear();
    m_heightToTimestamp.clear();
    m_heightToRegistration.clear();
    m_lifetimeBlockCount.clear();  // v4.0.21 — Patch C
    m_cachedActiveMinersMut = 0;
    m_cachedAtHeightMut = -1;
    m_cachedShortActiveMinersMut = 0;
    m_cachedShortAtHeightMut = -1;
}

// v4.0.21 — Patch C: lifetime distinct-miner count. Deterministic across nodes
// with the same canonical chain because populated only via connect/disconnect
// callbacks, which fire deterministically per-block. On startup, the populator
// at dilithion-node.cpp:~4515 calls OnBlockConnected for every block from
// genesis to tip in order, rebuilding this map identically on every node.
int CCooldownTracker::GetLifetimeMinerCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_lifetimeBlockCount.size());
}

void CCooldownTracker::RecalcActiveMiners(int height) const
{
    // Caller must hold m_mutex.
    if (m_cachedAtHeightMut == height)
        return;

    int cutoff = height - m_activeWindow + 1;
    std::set<Address> unique;
    for (auto it = m_heightToWinner.lower_bound(cutoff);
         it != m_heightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }

    m_cachedActiveMinersMut = static_cast<int>(unique.size());
    m_cachedAtHeightMut = height;
}

void CCooldownTracker::RecalcShortActiveMiners(int height) const
{
    // Caller must hold m_mutex.
    if (m_cachedShortAtHeightMut == height)
        return;

    if (m_shortWindow <= 0) {
        m_cachedShortActiveMinersMut = 0;
        m_cachedShortAtHeightMut = height;
        return;
    }

    int cutoff = height - m_shortWindow + 1;
    std::set<Address> unique;
    for (auto it = m_heightToWinner.lower_bound(cutoff);
         it != m_heightToWinner.end() && it->first <= height; ++it) {
        unique.insert(it->second);
    }

    m_cachedShortActiveMinersMut = static_cast<int>(unique.size());
    m_cachedShortAtHeightMut = height;
}

// ============================================================================
// Sybil Defense Phase 4: Correlated Availability Detection
// ============================================================================

std::vector<CCooldownTracker::CorrelatedGroup> CCooldownTracker::DetectCorrelatedGroups(
    int currentHeight,
    int lookbackBlocks,
    int proximityBlocks,
    int minGroupSize) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CorrelatedGroup> result;

    int startHeight = std::max(1, currentHeight - lookbackBlocks);

    // Build per-MIK activity ranges: first and last block mined in the lookback window
    struct MIKActivity {
        Address addr;
        int firstSeen;  // first block mined in window
        int lastSeen;   // last block mined in window
    };

    std::map<Address, MIKActivity> activity;
    for (auto it = m_heightToWinner.lower_bound(startHeight);
         it != m_heightToWinner.end() && it->first <= currentHeight; ++it) {
        auto& a = activity[it->second];
        a.addr = it->second;
        if (a.firstSeen == 0) a.firstSeen = it->first;
        a.lastSeen = it->first;
    }

    // Detect "appearing" groups: MIKs whose firstSeen is within proximityBlocks of each other
    // (and whose firstSeen is well after the window start, indicating they weren't mining before)
    std::vector<MIKActivity> miners;
    for (auto& [addr, a] : activity) {
        if (a.firstSeen > startHeight + proximityBlocks) {  // appeared after window started
            miners.push_back(a);
        }
    }

    // Sort by firstSeen and group
    std::sort(miners.begin(), miners.end(),
              [](const MIKActivity& a, const MIKActivity& b) { return a.firstSeen < b.firstSeen; });

    std::vector<MIKActivity> currentGroup;
    for (size_t i = 0; i < miners.size(); ++i) {
        if (currentGroup.empty() ||
            miners[i].firstSeen - currentGroup.back().firstSeen <= proximityBlocks) {
            currentGroup.push_back(miners[i]);
        } else {
            if (static_cast<int>(currentGroup.size()) >= minGroupSize) {
                CorrelatedGroup g;
                g.transitionHeight = currentGroup[0].firstSeen;
                g.appearing = true;
                for (auto& m : currentGroup) g.miks.push_back(m.addr);
                result.push_back(std::move(g));
            }
            currentGroup.clear();
            currentGroup.push_back(miners[i]);
        }
    }
    if (static_cast<int>(currentGroup.size()) >= minGroupSize) {
        CorrelatedGroup g;
        g.transitionHeight = currentGroup[0].firstSeen;
        g.appearing = true;
        for (auto& m : currentGroup) g.miks.push_back(m.addr);
        result.push_back(std::move(g));
    }

    // Detect "disappearing" groups: MIKs whose lastSeen is within proximityBlocks
    // of each other AND well before the current tip (stopped mining together)
    std::vector<MIKActivity> stoppers;
    for (auto& [addr, a] : activity) {
        if (a.lastSeen < currentHeight - 20) {  // stopped mining at least 20 blocks ago
            stoppers.push_back(a);
        }
    }

    std::sort(stoppers.begin(), stoppers.end(),
              [](const MIKActivity& a, const MIKActivity& b) { return a.lastSeen < b.lastSeen; });

    currentGroup.clear();
    for (size_t i = 0; i < stoppers.size(); ++i) {
        if (currentGroup.empty() ||
            stoppers[i].lastSeen - currentGroup.back().lastSeen <= proximityBlocks) {
            currentGroup.push_back(stoppers[i]);
        } else {
            if (static_cast<int>(currentGroup.size()) >= minGroupSize) {
                CorrelatedGroup g;
                g.transitionHeight = currentGroup[0].lastSeen;
                g.appearing = false;
                for (auto& m : currentGroup) g.miks.push_back(m.addr);
                result.push_back(std::move(g));
            }
            currentGroup.clear();
            currentGroup.push_back(stoppers[i]);
        }
    }
    if (static_cast<int>(currentGroup.size()) >= minGroupSize) {
        CorrelatedGroup g;
        g.transitionHeight = currentGroup[0].lastSeen;
        g.appearing = false;
        for (auto& m : currentGroup) g.miks.push_back(m.addr);
        result.push_back(std::move(g));
    }

    return result;
}

// ---------------------------------------------------------------------------
// Layer 3 Sybil Defense: Registration Rate Tracking
// ---------------------------------------------------------------------------

void CCooldownTracker::OnRegistrationConnected(int height, const Address& mikId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_heightToRegistration[height] = mikId;
}

int CCooldownTracker::GetRegistrationCount(int height, int window) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    int fromHeight = std::max(0, height - window + 1);
    int count = 0;
    auto it = m_heightToRegistration.lower_bound(fromHeight);
    auto end = m_heightToRegistration.upper_bound(height);
    for (; it != end; ++it) {
        ++count;
    }
    return count;
}
