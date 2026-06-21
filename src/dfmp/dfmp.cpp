// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <dfmp/dfmp.h>
#include <dfmp/identity_db.h>
#include <crypto/sha3.h>

#include <cstring>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cmath>
#include <fstream>

namespace DFMP {

// C-3: the saturating maturity×heat combiner uses __uint128_t (a GCC/Clang extension) —
// the SAME 128-bit integer support already required by CalculateEffectiveTarget below.
// Fail the build LOUDLY on any toolchain lacking it rather than silently miscompiling
// consensus math. (Dilithion ships via MSYS2 GCC/Clang; this asserts the invariant.)
static_assert(sizeof(__uint128_t) == 16,
              "C-3 / DFMP requires 128-bit integer support (__uint128_t; GCC/Clang)");

// ============================================================================
// GLOBAL STATE
// ============================================================================

CHeatTracker* g_heatTracker = nullptr;
CHeatTracker* g_payoutHeatTracker = nullptr;
CIdentityDB* g_identityDb = nullptr;

// ============================================================================
// IDENTITY IMPLEMENTATION
// ============================================================================

Identity::Identity() {
    std::memset(data, 0, sizeof(data));
}

Identity::Identity(const uint8_t* bytes) {
    if (bytes) {
        std::memcpy(data, bytes, sizeof(data));
    } else {
        std::memset(data, 0, sizeof(data));
    }
}

bool Identity::IsNull() const {
    for (size_t i = 0; i < sizeof(data); ++i) {
        if (data[i] != 0) return false;
    }
    return true;
}

bool Identity::operator==(const Identity& other) const {
    return std::memcmp(data, other.data, sizeof(data)) == 0;
}

bool Identity::operator!=(const Identity& other) const {
    return !(*this == other);
}

bool Identity::operator<(const Identity& other) const {
    return std::memcmp(data, other.data, sizeof(data)) < 0;
}

std::string Identity::GetHex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < sizeof(data); ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool Identity::SetHex(const std::string& hex) {
    if (hex.length() != 40) return false;

    for (size_t i = 0; i < 20; ++i) {
        std::string byteStr = hex.substr(i * 2, 2);
        char* end;
        unsigned long val = std::strtoul(byteStr.c_str(), &end, 16);
        if (*end != '\0' || val > 255) return false;
        data[i] = static_cast<uint8_t>(val);
    }
    return true;
}

// ============================================================================
// IDENTITY DERIVATION
// ============================================================================

Identity DeriveIdentity(const CTransaction& coinbaseTx) {
    // Check for at least one output
    if (coinbaseTx.vout.empty()) {
        return Identity();  // Null identity
    }

    // Use first output's scriptPubKey
    return DeriveIdentityFromScript(coinbaseTx.vout[0].scriptPubKey);
}

Identity DeriveIdentityFromScript(const std::vector<uint8_t>& scriptPubKey) {
    if (scriptPubKey.empty()) {
        return Identity();  // Null identity
    }

    // Hash the scriptPubKey with SHA3-256
    uint8_t hash[32];
    SHA3_256(scriptPubKey.data(), scriptPubKey.size(), hash);

    // Take first 20 bytes as identity
    return Identity(hash);
}

// ============================================================================
// HEAT TRACKER IMPLEMENTATION
// ============================================================================

void CHeatTracker::OnBlockConnected(int height, const Identity& identity) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Add new entry
    m_window.push_back({height, identity});
    m_heatCache[identity]++;

    // Remove entries outside the observation window
    while (!m_window.empty() && m_window.front().first <= height - OBSERVATION_WINDOW) {
        const Identity& oldIdentity = m_window.front().second;

        // Decrement heat cache
        auto it = m_heatCache.find(oldIdentity);
        if (it != m_heatCache.end()) {
            it->second--;
            if (it->second <= 0) {
                m_heatCache.erase(it);
            }
        }

        m_window.pop_front();
    }
}

void CHeatTracker::OnBlockDisconnected(int height) {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Remove the most recent entry if it matches the height
    while (!m_window.empty() && m_window.back().first >= height) {
        const Identity& removedIdentity = m_window.back().second;

        // Decrement heat cache
        auto it = m_heatCache.find(removedIdentity);
        if (it != m_heatCache.end()) {
            it->second--;
            if (it->second <= 0) {
                m_heatCache.erase(it);
            }
        }

        m_window.pop_back();
    }
}

int CHeatTracker::GetHeat(const Identity& identity) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_heatCache.find(identity);
    if (it != m_heatCache.end()) {
        return it->second;
    }
    return 0;
}

int CHeatTracker::GetEffectiveHeat(const Identity& identity) const {
    int heat = GetHeat(identity);
    return std::max(0, heat - FREE_TIER_THRESHOLD);
}

void CHeatTracker::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_window.clear();
    m_heatCache.clear();
}

size_t CHeatTracker::GetWindowSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_window.size();
}

int CHeatTracker::GetUniqueMinerCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<int>(m_heatCache.size());
}

std::map<Identity, int> CHeatTracker::GetAllHeat() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_heatCache;  // Return a copy
}

// ============================================================================
// HEAT TRACKER PERSISTENCE
// ============================================================================
// Binary format:
//   4 bytes: magic (0x48454154 = "HEAT")
//   4 bytes: version (1)
//   4 bytes: tip height (for staleness detection)
//   4 bytes: entry count
//   For each entry:
//     4 bytes: block height (int32_t)
//     20 bytes: identity

static const uint32_t HEAT_FILE_MAGIC = 0x48454154;  // "HEAT"
static const uint32_t HEAT_FILE_VERSION = 1;

bool CHeatTracker::SaveToFile(const std::string& path, int tipHeight) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[DFMP] WARNING: Cannot open heat tracker file for writing: " << path << std::endl;
        return false;
    }

    uint32_t magic = HEAT_FILE_MAGIC;
    uint32_t version = HEAT_FILE_VERSION;
    int32_t tip = static_cast<int32_t>(tipHeight);
    uint32_t count = static_cast<uint32_t>(m_window.size());

    file.write(reinterpret_cast<const char*>(&magic), 4);
    file.write(reinterpret_cast<const char*>(&version), 4);
    file.write(reinterpret_cast<const char*>(&tip), 4);
    file.write(reinterpret_cast<const char*>(&count), 4);

    for (const auto& entry : m_window) {
        int32_t height = static_cast<int32_t>(entry.first);
        file.write(reinterpret_cast<const char*>(&height), 4);
        file.write(reinterpret_cast<const char*>(entry.second.data), sizeof(entry.second.data));
    }

    if (!file.good()) {
        std::cerr << "[DFMP] WARNING: Error writing heat tracker file: " << path << std::endl;
        return false;
    }

    file.close();
    return true;
}

bool CHeatTracker::LoadFromFile(const std::string& path, int expectedTipHeight) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;  // File doesn't exist - normal for first run
    }

    uint32_t magic = 0, version = 0, count = 0;
    int32_t tip = 0;

    file.read(reinterpret_cast<char*>(&magic), 4);
    file.read(reinterpret_cast<char*>(&version), 4);
    file.read(reinterpret_cast<char*>(&tip), 4);
    file.read(reinterpret_cast<char*>(&count), 4);

    if (!file.good() || magic != HEAT_FILE_MAGIC || version != HEAT_FILE_VERSION) {
        std::cerr << "[DFMP] Heat tracker file corrupt or wrong version, will rebuild from chain" << std::endl;
        return false;
    }

    if (tip != static_cast<int32_t>(expectedTipHeight)) {
        std::cout << "[DFMP] Heat tracker file stale (file tip=" << tip
                  << ", chain tip=" << expectedTipHeight << "), will rebuild from chain" << std::endl;
        return false;
    }

    if (count > static_cast<uint32_t>(OBSERVATION_WINDOW) + 10) {
        std::cerr << "[DFMP] Heat tracker file has too many entries (" << count << "), will rebuild from chain" << std::endl;
        return false;
    }

    // Clear existing state
    m_window.clear();
    m_heatCache.clear();

    // Read entries
    for (uint32_t i = 0; i < count; i++) {
        int32_t height = 0;
        Identity identity;

        file.read(reinterpret_cast<char*>(&height), 4);
        file.read(reinterpret_cast<char*>(identity.data), sizeof(identity.data));

        if (!file.good()) {
            std::cerr << "[DFMP] Heat tracker file truncated at entry " << i << ", will rebuild from chain" << std::endl;
            m_window.clear();
            m_heatCache.clear();
            return false;
        }

        m_window.push_back({static_cast<int>(height), identity});
        m_heatCache[identity]++;
    }

    return true;
}

// ============================================================================
// MULTIPLIER CALCULATION (Fixed-Point) - DFMP v2.0
// ============================================================================

int64_t CalculatePendingPenaltyFP(int currentHeight, int firstSeenHeight) {
    // DFMP v3.0: NO first-block grace - new identities start at 5.0x
    // Step-wise decay: 5.0x → 4.0x → 3.0x → 2.0x → 1.5x → 1.0x in 160-block steps
    // over 800 blocks total (MATURITY_BLOCKS)

    if (firstSeenHeight < 0) {
        return FP_PENDING_START;  // 5.0x for new identity
    }

    int age = currentHeight - firstSeenHeight;

    if (age < 160) return 5000000;   // 5.0x
    if (age < 320) return 4000000;   // 4.0x
    if (age < 480) return 3000000;   // 3.0x
    if (age < 640) return 2000000;   // 2.0x
    if (age < 800) return 1500000;   // 1.5x
    return FP_PENDING_END;           // 1.0x (mature)
}

int64_t CalculateHeatMultiplierFP(int heat, int uniqueMiners, bool saturate) {
    // DFMP v3.0 Heat Penalty with Dynamic Scaling:
    // Free tier scales by active miner count:
    //   effectiveFreeThreshold = max(FREE_TIER_THRESHOLD, OBSERVATION_WINDOW / uniqueMiners)
    // Above free tier: 2.0x cliff, then ×1.58 per additional block

    // Dynamic free tier: scale by active miner count
    int effectiveFreeThreshold = FREE_TIER_THRESHOLD;  // Default: 12
    if (uniqueMiners > 0) {
        int dynamicThreshold = OBSERVATION_WINDOW / std::max(1, uniqueMiners);
        effectiveFreeThreshold = std::max(FREE_TIER_THRESHOLD, dynamicThreshold);
    }

    // Free tier: no penalty
    if (heat <= effectiveFreeThreshold) {
        return FP_SCALE;  // 1.0x
    }

    // Cliff + exponential: blocks above free tier
    // penalty = 2.0 × 1.58^(blocks - effectiveFreeThreshold - 1)
    int64_t penalty = FP_HEAT_CLIFF;  // 2.0 × FP_SCALE
    int exponent = heat - effectiveFreeThreshold - 1;

    for (int i = 0; i < exponent; i++) {
        if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) { penalty = FP_HEAT_MULTIPLIER_MAX; break; }
        penalty = (penalty * FP_HEAT_GROWTH) / 100;  // × 1.58
    }

    if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) penalty = FP_HEAT_MULTIPLIER_MAX;
    return penalty;
}

int64_t CalculateTotalMultiplierFP(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners, bool saturate) {
    int64_t pendingFP = CalculatePendingPenaltyFP(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP(heat, uniqueMiners, saturate);

    // total = maturity × heat
    // In fixed-point: total_fp = (maturity_fp × heat_fp) / FP_SCALE
    // C-3: when saturating, a capped heatFP (≤ FP_HEAT_MULTIPLIER_MAX ≈ 5.83e16) times
    // maturity (≤ 5e6) would still overflow int64 in the raw multiply, so compute the
    // product in 128-bit and clamp to FP_HEAT_MULTIPLIER_MAX (already the hardest target).
    // saturate=false keeps the exact legacy int64 expression (byte-identical below gate).
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(pendingFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (pendingFP * heatFP) / FP_SCALE;
}

int64_t CombineMaturityHeatFP(int64_t maturityFP, int64_t heatFP, bool saturate) {
    // C-3: overflow-safe maturity × heat. See header. saturate=false is byte-identical
    // to the legacy inline `(maturityFP * heatFP) / FP_SCALE`.
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(maturityFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (maturityFP * heatFP) / FP_SCALE;
}

uint256 CalculateEffectiveTarget(const uint256& baseTarget, int64_t multiplierFP) {
    // effective_target = baseTarget / multiplier
    // In fixed-point: effective_target = baseTarget × FP_SCALE / multiplierFP

    // Ensure multiplier is at least 1× (shouldn't happen but be safe)
    // C-3: with the saturating cap upstream (saturate=true at/above the gate), every
    // multiplierFP reaching here is in [FP_SCALE, FP_HEAT_MULTIPLIER_MAX] and never
    // negative/wrapped, so this floor is now a true safety floor rather than a wrap-catcher.
    if (multiplierFP < FP_SCALE) {
        multiplierFP = FP_SCALE;
    }

    // For 256-bit division, we need to:
    // 1. Multiply baseTarget by FP_SCALE (may increase precision)
    // 2. Divide by multiplierFP

    // Since uint256 doesn't have built-in arithmetic operators,
    // we'll do byte-by-byte division for the high bits and use
    // the ratio for the result.

    // Simplified approach: convert to double for calculation, then back
    // This loses some precision but is deterministic enough for mining
    // because the hash comparison has plenty of margin.

    // Better approach: Do proper 256-bit integer division
    // target_new = target × 1,000,000 / multiplier_fp

    // For now, use a simpler approach:
    // Since multiplierFP ranges from 1,000,000 to maybe 50,000,000 (50×),
    // and baseTarget is 256 bits, we can safely divide.

    // Convert baseTarget to bytes for calculation
    uint256 result;
    result = baseTarget;  // Copy

    // We need: result = baseTarget × FP_SCALE / multiplierFP
    // But uint256 doesn't have division. We'll use byte-level ops.

    // Simplest correct approach: treat uint256 as a big integer
    // and perform long division.

    // For determinism, we'll compute: floor(baseTarget / (multiplierFP / FP_SCALE))
    // which is: floor(baseTarget × FP_SCALE / multiplierFP)

    // Implementation: do it bit by bit or use existing utilities

    // The baseTarget bytes are in little-endian order (data[0] is LSB)
    // We can convert to a big integer, divide, and convert back.

    // For simplicity and correctness, let's just do byte-level division
    // by the scalar ratio = multiplierFP / FP_SCALE

    // ratio = multiplierFP / FP_SCALE (this is the actual multiplier as integer part + fraction)
    // We want result = baseTarget / ratio

    // Actually, the cleanest way:
    // result_i = baseTarget_i × FP_SCALE / multiplierFP for each position
    // But that doesn't work for multi-precision.

    // Let's do proper multi-precision division:
    // We have a 256-bit number and want to divide by a 64-bit number.

    // Approach: Process 64 bits at a time from MSB
    // Note: multiplierFP is guaranteed >= FP_SCALE (clamped above), so divisor is never 0
    uint64_t divisor = static_cast<uint64_t>(multiplierFP);

    // We want: result = baseTarget × FP_SCALE / divisor
    // First, we multiply baseTarget by FP_SCALE (this may overflow 256 bits slightly
    // but for targets, the upper bits are usually zero, so it's fine).

    // Convert uint256 to array of uint64_t for easier math
    // uint256.data is uint8_t[32] in little-endian

    uint64_t words[4];  // Little-endian (words[0] = LSB)
    std::memcpy(words, baseTarget.data, 32);

    // Multiply by FP_SCALE (1,000,000)
    // We need to handle potential overflow into a 5th word
    __uint128_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        __uint128_t product = static_cast<__uint128_t>(words[i]) * FP_SCALE + carry;
        words[i] = static_cast<uint64_t>(product);
        carry = product >> 64;
    }
    // carry now holds the overflow (words[4] conceptually)

    // Now divide by divisor (long division from MSB)
    // We have 5 words (320 bits) to divide by 64-bit divisor

    uint64_t resultWords[4] = {0, 0, 0, 0};
    __uint128_t remainder = carry;  // Start with the overflow

    // Process from word 3 down to 0
    for (int i = 3; i >= 0; --i) {
        remainder = (remainder << 64) | words[i];
        resultWords[i] = static_cast<uint64_t>(remainder / divisor);
        remainder = remainder % divisor;
    }

    // Copy result back to uint256
    std::memcpy(result.data, resultWords, 32);

    // Ensure result is at least 1 (target can't be zero)
    bool allZero = true;
    for (size_t i = 0; i < 32; ++i) {
        if (result.data[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) {
        result.data[0] = 1;  // Minimum target
    }

    return result;
}

// ============================================================================
// DFMP v3.1 MULTIPLIER CALCULATION (Softened for small networks)
// ============================================================================

int64_t CalculatePendingPenaltyFP_V31(int currentHeight, int firstSeenHeight) {
    // DFMP v3.1: Softened maturity penalty
    // 2.0x → 1.5x → 1.0x over 400 blocks (100-block steps)

    if (firstSeenHeight < 0) {
        return FP_PENDING_START_V31;  // 2.0x for new identity
    }

    int age = currentHeight - firstSeenHeight;

    if (age < 100) return 2000000;   // 2.0x
    if (age < 200) return 1500000;   // 1.5x
    if (age < 300) return 1250000;   // 1.25x
    if (age < 400) return 1100000;   // 1.1x
    return FP_PENDING_END;           // 1.0x (mature)
}

int64_t CalculateHeatMultiplierFP_V31(int heat, int uniqueMiners, bool saturate) {
    // DFMP v3.1: Softened heat penalty
    // Free tier: 36 blocks (or dynamic if higher)
    // Above free tier: 1.5x cliff, then 1.08x per block

    // Dynamic free tier: scale by active miner count
    int effectiveFreeThreshold = FREE_TIER_THRESHOLD_V31;  // Default: 36
    if (uniqueMiners > 0) {
        int dynamicThreshold = OBSERVATION_WINDOW / std::max(1, uniqueMiners);
        effectiveFreeThreshold = std::max(FREE_TIER_THRESHOLD_V31, dynamicThreshold);
    }

    // Free tier: no penalty
    if (heat <= effectiveFreeThreshold) {
        return FP_SCALE;  // 1.0x
    }

    // Cliff + exponential: blocks above free tier
    // penalty = 1.5 × 1.08^(blocks - effectiveFreeThreshold - 1)
    int64_t penalty = FP_HEAT_CLIFF_V31;  // 1.5 × FP_SCALE
    int exponent = heat - effectiveFreeThreshold - 1;

    for (int i = 0; i < exponent; i++) {
        if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) { penalty = FP_HEAT_MULTIPLIER_MAX; break; }
        penalty = (penalty * FP_HEAT_GROWTH_V31) / 100;  // × 1.08
    }

    if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) penalty = FP_HEAT_MULTIPLIER_MAX;
    return penalty;
}

int64_t CalculateTotalMultiplierFP_V31(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners, bool saturate) {
    int64_t pendingFP = CalculatePendingPenaltyFP_V31(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP_V31(heat, uniqueMiners, saturate);

    // total = maturity × heat (C-3: 128-bit + clamp under saturate; see base combinator)
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(pendingFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (pendingFP * heatFP) / FP_SCALE;
}

// ============================================================================
// DFMP v3.2 MULTIPLIER CALCULATION (Tightened anti-whale)
// ============================================================================

int64_t CalculatePendingPenaltyFP_V32(int currentHeight, int firstSeenHeight) {
    // DFMP v3.2: Moderate maturity penalty (between v3.0 and v3.1)
    // 2.5x → 2.0x → 1.5x → 1.25x → 1.0x in 100-block steps over 500 blocks

    if (firstSeenHeight < 0) {
        return FP_PENDING_START_V32;  // 2.5x for new identity
    }

    int age = currentHeight - firstSeenHeight;

    if (age < 100) return 2500000;   // 2.5x
    if (age < 200) return 2000000;   // 2.0x
    if (age < 300) return 1500000;   // 1.5x
    if (age < 400) return 1250000;   // 1.25x
    if (age < 500) return 1100000;   // 1.1x
    return FP_PENDING_END;           // 1.0x (mature)
}

int64_t CalculateHeatMultiplierFP_V32(int heat, int uniqueMiners, bool saturate) {
    // DFMP v3.2: Aggressive heat penalty (same formula as v3.0)
    // Free tier: 12 blocks (or dynamic if higher)
    // Above free tier: 2.0x cliff, then 1.58x per block

    // Dynamic free tier: scale by active miner count
    int effectiveFreeThreshold = FREE_TIER_THRESHOLD_V32;  // Default: 12
    if (uniqueMiners > 0) {
        int dynamicThreshold = OBSERVATION_WINDOW / std::max(1, uniqueMiners);
        effectiveFreeThreshold = std::max(FREE_TIER_THRESHOLD_V32, dynamicThreshold);
    }

    // Free tier: no penalty
    if (heat <= effectiveFreeThreshold) {
        return FP_SCALE;  // 1.0x
    }

    // Cliff + exponential: blocks above free tier
    // penalty = 2.0 × 1.58^(blocks - effectiveFreeThreshold - 1)
    int64_t penalty = FP_HEAT_CLIFF_V32;  // 2.0 × FP_SCALE
    int exponent = heat - effectiveFreeThreshold - 1;

    for (int i = 0; i < exponent; i++) {
        if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) { penalty = FP_HEAT_MULTIPLIER_MAX; break; }
        penalty = (penalty * FP_HEAT_GROWTH_V32) / 100;  // × 1.58
    }

    if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) penalty = FP_HEAT_MULTIPLIER_MAX;
    return penalty;
}

int64_t CalculateTotalMultiplierFP_V32(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners, bool saturate) {
    int64_t pendingFP = CalculatePendingPenaltyFP_V32(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP_V32(heat, uniqueMiners, saturate);

    // total = maturity × heat (C-3: 128-bit + clamp under saturate; see base combinator)
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(pendingFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (pendingFP * heatFP) / FP_SCALE;
}

// ============================================================================
// DFMP v3.3 MULTIPLIER CALCULATION (No dynamic scaling, linear+exponential)
// ============================================================================

int64_t CalculatePendingPenaltyFP_V33(int currentHeight, int firstSeenHeight) {
    // Same maturity curve as v3.2
    return CalculatePendingPenaltyFP_V32(currentHeight, firstSeenHeight);
}

int64_t CalculateHeatMultiplierFP_V33(int heat, bool saturate) {
    // DFMP v3.3: Three-zone penalty, NO dynamic scaling
    //   Zone 1 (Free):        0-12 blocks  → 1.0x
    //   Zone 2 (Linear):     13-24 blocks  → 1.0 + (heat-12) × 0.25  (ramps to 4.0x)
    //   Zone 3 (Exponential): 25+ blocks   → 4.0 × 1.58^(heat-24)

    // Zone 1: Free tier
    if (heat <= FREE_TIER_THRESHOLD_V33) {
        return FP_SCALE;  // 1.0x
    }

    // Zone 2: Linear ramp from 1.0x to 4.0x
    if (heat <= LINEAR_ZONE_END_V33) {
        // penalty = 1.0 + (heat - 12) × 0.25
        // In fixed-point: FP_SCALE + (heat - 12) × FP_SCALE / 4
        int excess = heat - FREE_TIER_THRESHOLD_V33;
        return FP_SCALE + (static_cast<int64_t>(excess) * FP_SCALE) / 4;
    }

    // Zone 3: Exponential from 4.0x base
    // penalty = 4.0 × 1.58^(heat - 24)
    int64_t penalty = FP_LINEAR_END_PENALTY_V33;  // 4.0x
    int exponent = heat - LINEAR_ZONE_END_V33;

    for (int i = 0; i < exponent; i++) {
        if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) { penalty = FP_HEAT_MULTIPLIER_MAX; break; }
        penalty = (penalty * FP_HEAT_GROWTH_V33) / 100;  // × 1.58
    }

    if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) penalty = FP_HEAT_MULTIPLIER_MAX;
    return penalty;
}

int64_t CalculateTotalMultiplierFP_V33(int currentHeight, int firstSeenHeight, int heat, bool saturate) {
    int64_t pendingFP = CalculatePendingPenaltyFP_V33(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP_V33(heat, saturate);

    // total = maturity × heat (C-3: 128-bit + clamp under saturate; see base combinator)
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(pendingFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (pendingFP * heatFP) / FP_SCALE;
}

// ============================================================================
// DFMP v3.4 MULTIPLIER CALCULATION (Verification-Aware Free Tier)
// ============================================================================

int64_t CalculatePendingPenaltyFP_V34(int currentHeight, int firstSeenHeight) {
    // Same maturity curve as v3.3/v3.2
    return CalculatePendingPenaltyFP_V32(currentHeight, firstSeenHeight);
}

int64_t CalculateHeatMultiplierFP_V34(int heat, bool isVerified, bool saturate) {
    // DFMP v3.4: Same three-zone curve as v3.3, but free tier depends on
    // DNA verification status:
    //   Verified:   12 free blocks
    //   Unverified:  3 free blocks
    // Linear zone endpoint (24) and exponential growth (1.58x) unchanged.

    int freeTier = isVerified ? FREE_TIER_THRESHOLD_V34_VERIFIED
                              : FREE_TIER_THRESHOLD_V34_UNVERIFIED;

    // Zone 1: Free tier
    if (heat <= freeTier) {
        return FP_SCALE;  // 1.0x
    }

    // Zone 2: Linear ramp to 4.0x at LINEAR_ZONE_END_V34
    if (heat <= LINEAR_ZONE_END_V34) {
        int excess = heat - freeTier;
        int linearSpan = LINEAR_ZONE_END_V34 - freeTier;
        // Defensive: unreachable with current constants (freeTier 3|12 < LINEAR_ZONE_END 24,
        // so linearSpan is always > 0). If a future constant change made the linear zone
        // degenerate, fail SAFE to the HARDER zone-3 base (4.0x), NEVER the easiest 1.0x —
        // a concentration defense must never hand a degenerate case the easiest target.
        if (linearSpan <= 0) return FP_LINEAR_END_PENALTY_V34;
        // Ramp from 1.0x to 4.0x over linearSpan blocks
        // penalty = 1.0 + excess × 3.0 / linearSpan
        int64_t ramp = (static_cast<int64_t>(excess) * 3 * FP_SCALE) / linearSpan;
        return FP_SCALE + ramp;
    }

    // Zone 3: Exponential from 4.0x base
    int64_t penalty = FP_LINEAR_END_PENALTY_V34;  // 4.0x
    int exponent = heat - LINEAR_ZONE_END_V34;

    for (int i = 0; i < exponent; i++) {
        if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) { penalty = FP_HEAT_MULTIPLIER_MAX; break; }
        penalty = (penalty * FP_HEAT_GROWTH_V34) / 100;  // × 1.58
    }

    if (saturate && penalty > FP_HEAT_MULTIPLIER_MAX) penalty = FP_HEAT_MULTIPLIER_MAX;
    return penalty;
}

int64_t CalculateTotalMultiplierFP_V34(int currentHeight, int firstSeenHeight, int heat, bool isVerified, bool saturate) {
    int64_t pendingFP = CalculatePendingPenaltyFP_V34(currentHeight, firstSeenHeight);
    int64_t heatFP = CalculateHeatMultiplierFP_V34(heat, isVerified, saturate);

    // total = maturity × heat (C-3: 128-bit + clamp under saturate; see base combinator)
    if (saturate) {
        __uint128_t prod = (static_cast<__uint128_t>(pendingFP) * static_cast<__uint128_t>(heatFP)) / FP_SCALE;
        // Clamp at the TRUE int64 overflow boundary, NOT the heat-fn cap: the maturity×heat
        // PRODUCT legitimately exceeds FP_HEAT_MULTIPLIER_MAX (maturity up to ~5x stacks on the
        // capped heat) and still fits int64 (max ~2.9e17 < INT64_MAX). Ceiling at the heat cap
        // would flatten the stack ~2.5-5x EASIER at heat cap (Cursor MED-1). This clamp is
        // defensive — with capped heatFP the product never actually reaches INT64_MAX.
        return prod > static_cast<__uint128_t>(INT64_MAX)
            ? INT64_MAX : static_cast<int64_t>(prod);
    }
    return (pendingFP * heatFP) / FP_SCALE;
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

double GetPendingPenalty(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier(int heat, int uniqueMiners) {
    return static_cast<double>(CalculateHeatMultiplierFP(heat, uniqueMiners)) / FP_SCALE;
}

double GetTotalMultiplier(int currentHeight, int firstSeenHeight, int heat, int uniqueMiners) {
    return static_cast<double>(CalculateTotalMultiplierFP(currentHeight, firstSeenHeight, heat, uniqueMiners)) / FP_SCALE;
}

double GetPendingPenalty_V31(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP_V31(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier_V31(int heat, int uniqueMiners) {
    return static_cast<double>(CalculateHeatMultiplierFP_V31(heat, uniqueMiners)) / FP_SCALE;
}

double GetPendingPenalty_V32(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP_V32(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier_V32(int heat, int uniqueMiners) {
    return static_cast<double>(CalculateHeatMultiplierFP_V32(heat, uniqueMiners)) / FP_SCALE;
}

double GetPendingPenalty_V33(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP_V33(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier_V33(int heat) {
    return static_cast<double>(CalculateHeatMultiplierFP_V33(heat)) / FP_SCALE;
}

double GetPendingPenalty_V34(int currentHeight, int firstSeenHeight) {
    return static_cast<double>(CalculatePendingPenaltyFP_V34(currentHeight, firstSeenHeight)) / FP_SCALE;
}

double GetHeatMultiplier_V34(int heat, bool isVerified) {
    return static_cast<double>(CalculateHeatMultiplierFP_V34(heat, isVerified)) / FP_SCALE;
}

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

bool InitializeDFMP(const std::string& dataDir) {
    // Create heat tracker
    g_heatTracker = new CHeatTracker();
    g_payoutHeatTracker = new CHeatTracker();

    // Create and open identity database
    g_identityDb = new CIdentityDB();
    if (!g_identityDb->Open(dataDir + "/dfmp_identity")) {
        delete g_identityDb;
        g_identityDb = nullptr;
        delete g_heatTracker;
        g_heatTracker = nullptr;
        return false;
    }

    return true;
}

void ShutdownDFMP(const std::string& dataDir, int tipHeight) {
    // Persist heat trackers to disk before cleanup
    if (!dataDir.empty() && tipHeight > 0) {
        if (g_heatTracker) {
            if (g_heatTracker->SaveToFile(dataDir + "/dfmp_heat.dat", tipHeight)) {
                std::cout << "  [OK] MIK heat tracker saved to disk" << std::endl;
            }
        }
        if (g_payoutHeatTracker) {
            if (g_payoutHeatTracker->SaveToFile(dataDir + "/dfmp_payout_heat.dat", tipHeight)) {
                std::cout << "  [OK] Payout heat tracker saved to disk" << std::endl;
            }
        }
    }

    if (g_identityDb) {
        g_identityDb->Close();
        delete g_identityDb;
        g_identityDb = nullptr;
    }

    if (g_payoutHeatTracker) {
        delete g_payoutHeatTracker;
        g_payoutHeatTracker = nullptr;
    }

    if (g_heatTracker) {
        delete g_heatTracker;
        g_heatTracker = nullptr;
    }
}

bool IsDFMPReady() {
    return g_heatTracker != nullptr && g_payoutHeatTracker != nullptr && g_identityDb != nullptr;
}

} // namespace DFMP
