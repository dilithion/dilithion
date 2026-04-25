#ifndef COOLDOWN_TRACKER_H
#define COOLDOWN_TRACKER_H

#include <array>
#include <map>
#include <set>
#include <mutex>
#include <vector>
#include <cstdint>

/**
 * CCooldownTracker - VDF distribution rate limiter.
 *
 * After a miner wins a block, they enter a cooldown period during which
 * they cannot win again.  The cooldown length scales with the number of
 * active miners so that rotation is fair regardless of network size.
 *
 * Tracks by MIK identity (not payout address) to prevent address rotation
 * bypass.  Callers pass the 20-byte MIK identity extracted from the
 * coinbase scriptSig via ExtractCoinbaseMIKIdentity().
 *
 * Formula: cooldown = floor(activeMiners * 0.67)
 *   10 miners  →  6 blocks  (~33% eligible per round)
 *   22 miners  → 14 blocks  (~36% eligible per round)
 *   50 miners  → 33 blocks  (~34% eligible per round)
 *  100 miners  → 67 blocks  (~33% eligible per round)
 *
 * Dual-window (post-stabilization fork):
 *   effectiveCooldown = min(longCooldown, shortCooldown)
 *   Short window tracks recent participation; long window prevents gaming.
 *   Short window disabled at DilV genesis (vdfCooldownShortWindow=0).
 *
 * Time-based expiry (post-stabilization fork):
 *   Cooldown also expires when (currentTime - lastWinTime) >= cooldown × targetBlockTime.
 *   Handles chain stalls without needing a stall exemption.
 *
 * With MIN_COOLDOWN=2, a solo miner (n=1) gets cooldown=2 — they wait
 * ~95s between blocks (2 × 45s target via time-based expiry).  Chain
 * never stalls, just slows to ~95s/block during the solo phase.
 *
 * Thread-safe: all public methods acquire m_mutex.
 */
class CCooldownTracker {
public:
    using Address = std::array<uint8_t, 20>;

    // Consensus-level bounds.
    static constexpr int MIN_COOLDOWN = 2;    // blocks (solo miner waits ~95s with time-based expiry)
    static constexpr int MAX_COOLDOWN = 100;  // blocks

    // Default active window — kept for backward compatibility.
    // DIL mainnet/testnet: 360 blocks (~24h at 240s/block)
    // DilV: pass 1920 to constructor   (~24h at 45s/block)
    static constexpr int ACTIVE_WINDOW = 360;

    /** Constructor.
     *  activeWindow: long window (how many recent blocks define "active miners")
     *  shortWindow: short window for dual-window cooldown (0 = disabled)
     *  activationHeight: stabilization fork height (dual-window + time-based expiry)
     *  targetBlockTime: seconds per block (for time-based expiry calculation) */
    explicit CCooldownTracker(int activeWindow = ACTIVE_WINDOW,
                              int shortWindow = 0,
                              int activationHeight = 999999999,
                              int targetBlockTime = 45)
        : m_activeWindow(activeWindow),
          m_shortWindow(shortWindow),
          m_stabilizationHeight(activationHeight),
          m_targetBlockTime(targetBlockTime) {}

    /** Compute cooldown from active miner count. */
    static int CalculateCooldown(int activeMiners);

    /** Active window size this instance was constructed with. */
    int GetActiveWindow() const { return m_activeWindow; }

    // --- Query interface ---

    /** Is this address currently in cooldown at the given height?
     *  currentTimestamp: block timestamp for time-based expiry (0 = disabled). */
    bool IsInCooldown(const Address& addr, int height, int64_t currentTimestamp = 0) const;
    /** Option C simulation helper:
     *  evaluate cooldown as if `excludeHeight` were disconnected first.
     *  Used for VDF same-height replacement preflight checks. */
    bool IsInCooldownExcludingHeight(const Address& addr, int height, int64_t currentTimestamp, int excludeHeight) const;
    /** Option C simulation helper:
     *  active miner count at `height` as if `excludeHeight` were disconnected first. */
    int GetActiveMinersExcludingHeight(int height, int excludeHeight) const;

    /** Current cooldown length (long window only, clamped active miner count). */
    int GetCooldownBlocks() const;

    /** Number of unique miners seen in the last ACTIVE_WINDOW blocks. */
    int GetActiveMiners() const;

    /** Number of unique miners seen in the short window. */
    int GetShortActiveMiners() const;

    /** v4.0.21 — Patch C: Number of distinct MIKs with at least one block on
     *  the active chain (lifetime, not a sliding window). Used by the
     *  consecutive-miner consensus rule's solo-exemption gate. Deterministic:
     *  a function purely of canonical chain state, not of node restart history.
     *  See OnBlockConnected/OnBlockDisconnected for the per-MIK count maintenance.
     *  Reloaded by replaying connect events from genesis on startup. */
    int GetLifetimeMinerCount() const;

    /** All MIK addresses that have ever mined (for DNA discovery). */
    std::vector<Address> GetKnownAddresses() const;

    // --- Sybil Defense Phase 4: Correlated Availability Detection ---

    /** A group of MIKs that appeared or disappeared simultaneously. */
    struct CorrelatedGroup {
        std::vector<Address> miks;
        int transitionHeight;    // height where they all appeared/disappeared
        bool appearing;          // true = all started mining, false = all stopped
    };

    /** Detect groups of MIKs that started or stopped mining within `proximityBlocks`
     *  of each other. Returns groups of size >= `minGroupSize`.
     *  Looks at the trailing `lookbackBlocks` from the current tip. */
    std::vector<CorrelatedGroup> DetectCorrelatedGroups(
        int currentHeight,
        int lookbackBlocks = 200,
        int proximityBlocks = 3,
        int minGroupSize = 5) const;

    /** Height at which this address last won (or -1 if never). */
    int GetLastWinHeight(const Address& addr) const;

    /** Effective cooldown at a given height (considers dual-window after activation). */
    int GetEffectiveCooldown(int height) const;

    /** Count how many blocks a MIK has mined in the trailing `window` blocks up to `height`.
     *  Used for per-MIK window cap enforcement. */
    int GetBlockCountInWindow(const Address& addr, int height, int window) const;

    // --- Layer 3 Sybil Defense: Registration Rate Tracking ---

    /** Record that height contained a new MIK registration.
     *  Called from block connect callback when isRegistration=true. */
    void OnRegistrationConnected(int height, const Address& mikId);

    /** Count new MIK registrations in the trailing window [height-window+1, height]. */
    int GetRegistrationCount(int height, int window) const;

    // --- Mutation interface (called from block connect/disconnect) ---

    /** Record that `winner` mined the block at `height`.
     *  blockTimestamp: block's nTime (for time-based cooldown expiry, 0 = not provided). */
    void OnBlockConnected(int height, const Address& winner, int64_t blockTimestamp = 0);

    /** Undo the block at `height` (reorg support). */
    void OnBlockDisconnected(int height);

    /** Reset all state (e.g. on full chain resync). */
    void Clear();

private:
    mutable std::mutex m_mutex;

    int m_activeWindow{ACTIVE_WINDOW};      // long window
    int m_shortWindow{0};                   // short window (0 = disabled)
    int m_stabilizationHeight{999999999};   // activation height for dual-window + time expiry
    int m_targetBlockTime{45};              // seconds per block

    // address → height of most recent win
    std::map<Address, int> m_lastWinHeight;

    // height → winner address (for undo on disconnect)
    std::map<int, Address> m_heightToWinner;

    // address → timestamp of most recent win (for time-based expiry)
    std::map<Address, int64_t> m_lastWinTimestamp;

    // height → timestamp (for recovering timestamps during disconnect)
    std::map<int, int64_t> m_heightToTimestamp;

    // Layer 3: height → MIK identity (only for registration blocks, for rate limiting)
    std::map<int, Address> m_heightToRegistration;

    // v4.0.21 — Patch C: per-MIK count of blocks currently contributing to the
    // active chain. Updated in OnBlockConnected (++) and OnBlockDisconnected (--).
    // A MIK is "lifetime active" iff its count > 0. Lifetime miner count =
    // m_lifetimeBlockCount.size().
    // Deterministic: the count is a function purely of canonical chain state,
    // not of node restart history. Reloaded by replaying connect events from
    // genesis on startup (NOT from sliding window).
    std::map<Address, int> m_lifetimeBlockCount;

    /** Recount active miners up to `height` (long window).  Caller must hold m_mutex. */
    void RecalcActiveMiners(int height) const;

    /** Recount active miners up to `height` (short window).  Caller must hold m_mutex. */
    void RecalcShortActiveMiners(int height) const;

    /** Compute effective cooldown.  Caller must hold m_mutex. */
    int ComputeEffectiveCooldown(int height) const;

    // Lazy cache for active miner count (mutable for const query methods).
    mutable int m_cachedActiveMinersMut{0};
    mutable int m_cachedAtHeightMut{-1};
    mutable int m_cachedShortActiveMinersMut{0};
    mutable int m_cachedShortAtHeightMut{-1};
};

#endif // COOLDOWN_TRACKER_H
