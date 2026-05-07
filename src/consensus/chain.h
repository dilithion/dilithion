// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_CONSENSUS_CHAIN_H
#define DILITHION_CONSENSUS_CHAIN_H

#include <node/block_index.h>
#include <primitives/block.h>
#include <consensus/pow.h>      // Phase 5: ChainWorkGreaterThan for candidate-set comparator
#include <functional>
#include <map>
#include <set>                  // Phase 5: m_setBlockIndexCandidates
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>

// Forward declarations
class CBlockchainDB;
class CUTXOSet;
class CReorgWAL;
class CTxMemPool;  // BUG #109 FIX: Mempool for confirmed TX cleanup

/**
 * Phase 5: Comparator for ordering CBlockIndex candidates by chain work.
 *
 * Used by CChainState::m_setBlockIndexCandidates to maintain a strict
 * weak ordering with the heaviest-work block first. Tiebreakers (in order):
 *   1. Strictly greater chain work (ChainWorkGreaterThan)
 *   2. v4.3.3 F9: Lower vdfOutput on equal-work DilV siblings
 *      (consensus-deterministic; matches legacy ShouldReplaceVDFTip)
 *   3. Lower nSequenceId (earlier local insertion order — fallback)
 *   4. Pointer comparison (deterministic within a process)
 *
 * Mirrors upstream Bitcoin Core's `CBlockIndexWorkComparator` in
 * `validation.cpp` v28 PLUS the DilV-specific VDF tiebreak from the
 * legacy path. The selection algorithm pops the front of the set; that
 * block is the candidate-best leaf for the next reorg.
 *
 * v4.3.3 F9 (canary 4 mid-deploy fix, 2026-05-04):
 * Before F9 the comparator only used upstream's tiebreak (chainwork →
 * nSequenceId → pointer). nSequenceId is assigned at AddBlockIndex time
 * by LOCAL processing order, so two nodes that received sibling blocks
 * in different order would assign different nSequenceIds and pick
 * different siblings on equal-chainwork forks. Legacy DilV's
 * ShouldReplaceVDFTip (chain.cpp:226-260) uses pindex->header.vdfOutput
 * (block-intrinsic, consensus-deterministic) — every node agrees on the
 * winner. F9 ports that rule into the comparator BEFORE the nSequenceId
 * fallback so port and legacy paths agree on equal-work sibling
 * selection. NULL-safe for DIL chain (RandomX, no VDF) and for pre-VDF
 * activation DilV blocks: if either vdfOutput is null/zero, comparator
 * falls through to nSequenceId.
 *
 * Note: F9 is only the ORDERING rule. Legacy `ShouldReplaceVDFTip` also
 * has a temporal grace-period gate (m_vdfTipAcceptTime check) that
 * prevents oscillation after a tip is accepted. That's a separate
 * concern handled at activation logic, not at the comparator level.
 *
 * SCOPE NOTE (Cursor v4.3.3 review S8 LOW, 2026-05-04):
 * the F9 vdfOutput tie-break runs whenever chainwork is equal and both
 * vdfOutputs are non-null — it does NOT explicitly gate on "same-height
 * sibling only." In production this is benign because:
 *   * chainwork is the cumulative sum of (1/target) over the chain;
 *     equal chainwork at different heights would require difficulty
 *     asymmetry across the diverging parts of the two chains —
 *     extremely rare on DIL (RandomX+ASERT) and impossible on DilV
 *     (constant-difficulty VDF distribution).
 *   * Even if F9 ordered cross-height candidates "wrongly" by
 *     vdfOutput, the actual REORG decision is gated downstream at
 *     ActivateBestChain by F10's same-height + same-parent + equal-
 *     chainwork check. Cross-height candidates fall through to the
 *     normal chainwork-greater path and reorg correctly.
 * Documented per Cursor's request rather than hardening the comparator
 * itself; an in-comparator height check would add a chain.h dependency
 * on CBlockIndex::nHeight and is unnecessary given the downstream gate.
 */
struct CBlockIndexWorkComparator {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const {
        if (ChainWorkGreaterThan(a->nChainWork, b->nChainWork)) return true;
        if (ChainWorkGreaterThan(b->nChainWork, a->nChainWork)) return false;
        // v4.3.3 F9: VDF lowest-output tiebreak. Block-intrinsic and
        // consensus-deterministic. Skipped on null vdfOutput (DIL chain
        // or pre-VDF DilV) so legacy non-VDF behavior is unchanged.
        const uint256& vdfA = a->header.vdfOutput;
        const uint256& vdfB = b->header.vdfOutput;
        if (!vdfA.IsNull() && !vdfB.IsNull()) {
            if (HashLessThan(vdfA, vdfB)) return true;
            if (HashLessThan(vdfB, vdfA)) return false;
        }
        if (a->nSequenceId < b->nSequenceId) return true;
        if (b->nSequenceId < a->nSequenceId) return false;
        // Phase 5 red-team CONCERN fix: raw `a < b` between separately-
        // allocated objects is unspecified in C++17. std::less<T*> is
        // explicitly required to provide a total order across all pointers
        // of the type, regardless of whether they point into the same array.
        return std::less<const CBlockIndex*>{}(a, b);
    }
};

/**
 * Chain State Manager
 * Handles chain reorganization and maintains active chain tip
 */
class CChainState
{
private:
    // HIGH-C001 FIX: Use smart pointers for RAII memory management
    // In-memory block index: hash -> unique_ptr<CBlockIndex>
    // This provides O(1) lookup for any block by hash
    // Smart pointers ensure automatic cleanup, preventing memory leaks
    std::map<uint256, std::unique_ptr<CBlockIndex>> mapBlockIndex;

    // Active chain tip (block with most cumulative work)
    CBlockIndex* pindexTip;

    // Database reference for persisting chain state
    CBlockchainDB* pdb;

    // UTXO set reference for chain validation (CS-005)
    CUTXOSet* pUTXOSet;

    // BUG #109 FIX: Mempool reference for removing confirmed transactions
    // When a block is connected, we must remove its transactions from mempool
    // to prevent UTXO/mempool inconsistency (inputs appearing unavailable)
    CTxMemPool* pMemPool{nullptr};

    // P1-4 FIX: Write-Ahead Log for atomic reorganizations
    std::unique_ptr<CReorgWAL> m_reorgWAL;
    bool m_requiresReindex{false};

    // CRITICAL-1 FIX: Mutex for thread-safe access to chain state
    // Protects mapBlockIndex, pindexTip, and all chain operations
    // BUG #200 FIX: Changed to recursive_mutex to allow ActivateBestChain to call
    // DisconnectTip without self-deadlock (both acquire cs_main)
    mutable std::recursive_mutex cs_main;

    // BUG #74 FIX: Atomic cached height for lock-free reads
    // GetHeight() is called frequently by RPC and wallet operations
    // Using cs_main for height reads causes contention with block processing
    // This atomic is updated atomically whenever pindexTip changes
    std::atomic<int> m_cachedHeight{-1};

    // BUG #277: UTXO corruption detection and auto-recovery
    // Tracks consecutive UTXO failures to detect corruption (vs. one-off errors).
    // When threshold is reached, signals that the chain needs a full resync.
    std::atomic<int> m_consecutive_utxo_failures{0};
    std::atomic<bool> m_utxo_needs_rebuild{false};
    static constexpr int MAX_UTXO_FAILURES_BEFORE_REBUILD = 3;

    // v4.0.19: Persistent UndoBlock failure detection (parallel to BUG #277).
    // Catches the failure mode where DisconnectTip's UndoBlock returns false
    // repeatedly on the same block hash because undo data is missing on disk.
    // Without this, the node loops forever attempting reorgs it cannot complete
    // (incident 2026-04-25, NYC + LDN DilV seeds).
    // Counter is incremented on UndoBlock failure for the same hash, reset to 1
    // when the failing hash changes, and reset to 0 on any successful disconnect.
    // m_last_undo_failure_hash is uint256 (not trivially atomic) — protected by
    // m_undo_failure_mutex which is held only briefly to update both fields.
    std::atomic<int> m_consecutive_undo_failures{0};
    std::atomic<bool> m_chain_needs_rebuild{false};
    uint256 m_last_undo_failure_hash;
    mutable std::mutex m_undo_failure_mutex;
    static constexpr int kPersistentUndoFailureThreshold = 3;

public:
    // v4.3.3 F11 (Layer-3 round 2 MEDIUM-1): cause classification for
    // m_chain_needs_rebuild. The same flag is set by multiple distinct
    // failure modes — UndoBlock-undo (legacy v4.0.19), ReadBlock /
    // ConnectTip / WriteBestBlock failures mid-reorg (v4.3.1 BLOCKER #1
    // sites), and reorg-depth-cap rejection (v4.3.3 F8). The M1 helper
    // (Dilithion::MaybeTriggerChainRebuild) needs to know WHY in order
    // to emit a non-misleading [CRITICAL] banner and reason string.
    //
    // Default-initialized to UndoFailure (the only cause pre-F8); F8's
    // depth-rejection site sets DepthRejection BEFORE flipping
    // m_chain_needs_rebuild, so the helper observes the cause atomically
    // with the flag. First-set-wins semantics: M1 helper's once-latch
    // means only the first cause to fire is reported.
    enum class ChainRebuildReason : uint32_t {
        UndoFailure          = 0,  // BUG #277 persistent UndoBlock failure (chain.cpp:2257)
        DepthRejection       = 1,  // v4.3.3 F8: MAX_REORG_DEPTH exceeded (depth ≠ invalid)
        // v4.3.3 F16 (Layer-3 round 3 INFO-1): pre-F16 the ConnectTip-failure
        // and WriteBestBlock-failure sites in chain.cpp were mislabeled
        // "Persistent UndoBlock failure" by the M1 helper. F16 introduces
        // distinct cause classes so operator-facing banners are accurate
        // for each failure mode.
        ConnectTipFailure    = 2,  // chain.cpp:716/2812/2917 ConnectTip after disconnect/reorg
        DisconnectTipFailure = 3,  // chain.cpp:2842 DisconnectTip mid-reorg failure
        ReadBlockFailure     = 4,  // chain.cpp:2870/2887 ReadBlock fail with disconnects committed
        WriteBestBlockFailure = 5, // chain.cpp:2956 per-step WriteBestBlock failure (BLOCKER #1)
    };
private:
    std::atomic<ChainRebuildReason> m_chain_rebuild_reason{
        ChainRebuildReason::UndoFailure};

    // ============================================================
    // Phase 5: TEST-ONLY hooks for Patch B equivalence harness.
    // ============================================================
    //
    // These std::function hooks let the Day 4 equivalence test inject
    // controllable success/failure for the inner DisconnectTip/ConnectTip
    // primitives, without standing up the full validation pipeline (UTXO
    // mutations, MIK/DNA/cooldown checks, RandomX/VDF proofs).
    //
    // Production code MUST NOT set these. Default-constructed
    // std::function is empty; the production path checks `if (hook)`
    // and falls through to the real implementation when unset — zero
    // perf cost, zero behavior change in release.
    //
    // Used by chain_case_2_5_equivalence_tests.cpp ONLY.
public:
    using ConnectTipOverride = std::function<bool(CBlockIndex*, const CBlock&)>;
    using DisconnectTipOverride = std::function<bool(CBlockIndex*)>;
    using WriteBestBlockOverride = std::function<bool(const uint256&)>;
    // Phase 5 Day 4 V1: when set, ActivateBestChainStep consults this
    // INSTEAD of pdb->ReadBlock when fetching blocks for connect loop
    // retries. Lets unit tests serve block data from an in-memory map
    // without standing up a real CBlockchainDB. Production never sets this.
    using ReadBlockOverride = std::function<bool(const uint256&, CBlock&)>;

    void SetTestConnectTipOverride(ConnectTipOverride h) { m_testConnectTipOverride = std::move(h); }
    void SetTestDisconnectTipOverride(DisconnectTipOverride h) { m_testDisconnectTipOverride = std::move(h); }
    void SetTestWriteBestBlockOverride(WriteBestBlockOverride h) { m_testWriteBestBlockOverride = std::move(h); }
    void SetTestReadBlockOverride(ReadBlockOverride h) { m_testReadBlockOverride = std::move(h); }
private:
    ConnectTipOverride m_testConnectTipOverride;
    DisconnectTipOverride m_testDisconnectTipOverride;
    WriteBestBlockOverride m_testWriteBestBlockOverride;
    ReadBlockOverride m_testReadBlockOverride;

    // ============================================================
    // Phase 5: block-index-tree-based chain selection (PR5.1 scaffold)
    // ============================================================
    //
    // Set of leaf candidates ordered by descending chain work. The front
    // is the heaviest-work leaf — the next reorg target. Maintained by
    // ProcessNewHeader / AddBlockIndex / InvalidateBlockImpl /
    // ReconsiderBlockImpl. Empty until PR5.3 wires population.
    std::set<CBlockIndex*, CBlockIndexWorkComparator> m_setBlockIndexCandidates;

    // Bug #40 fix: Callback mechanism for tip updates
    // Allows HeadersManager and other components to be notified when chain tip changes
    using TipUpdateCallback = std::function<void(const CBlockIndex*)>;
    std::vector<TipUpdateCallback> m_tipCallbacks;

    // BUG #56 FIX: Block connect/disconnect callbacks (Bitcoin Core pattern)
    // Allows wallet to be notified when blocks are connected/disconnected
    // IBD OPTIMIZATION: Pass hash to avoid RandomX recomputation in callbacks
    using BlockConnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    using BlockDisconnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    std::vector<BlockConnectCallback> m_blockConnectCallbacks;
    std::vector<BlockDisconnectCallback> m_blockDisconnectCallbacks;

public:
    // VDF Distribution: Track when the first VDF block at the current tip height was accepted.
    // Used to enforce the grace period — replacements only allowed within this window.
    // INVARIANT: These are only modified under cs_main (ActivateBestChain holds the lock).
    // The first block at a height always enters via Case 2 (extending tip), which sets
    // these values. Subsequent siblings enter Case 2.5 (distribution comparison) and read them.
    // Replacements do NOT reset the accept time — the grace window is anchored to the
    // first block at a height to prevent infinite replacement chains.
    std::chrono::steady_clock::time_point m_vdfTipAcceptTime{};
    int m_vdfTipAcceptHeight{-1};


    CChainState();
    ~CChainState();

    /**
     * Initialize chain state with database
     */
    void SetDatabase(CBlockchainDB* database) { pdb = database; }

    /**
     * Initialize chain state with UTXO set (CS-005)
     */
    void SetUTXOSet(CUTXOSet* utxoSet) { pUTXOSet = utxoSet; }

    /**
     * BUG #109 FIX: Initialize chain state with mempool
     * Required for removing confirmed transactions when blocks are connected
     */
    void SetMemPool(CTxMemPool* mempool) { pMemPool = mempool; }

    /**
     * P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
     * MUST be called after SetDatabase() with the data directory
     * @param dataDir The data directory (e.g., ~/.dilithion-testnet)
     * @return true if initialized successfully, false if incomplete reorg detected
     */
    bool InitializeWAL(const std::string& dataDir);

    /**
     * P1-4 FIX: Check if an incomplete reorg was detected on startup
     * @return true if -reindex is required
     */
    bool RequiresReindex() const;

    /**
     * BUG #277: Check if UTXO corruption was detected and a rebuild is needed
     * The IBD coordinator or main loop should check this and trigger recovery.
     * @return true if UTXO set needs rebuilding
     */
    bool NeedsUTXORebuild() const { return m_utxo_needs_rebuild.load(); }

    /**
     * BUG #277: Clear the UTXO rebuild flag (after recovery is initiated)
     */
    void ClearUTXORebuildFlag() { m_utxo_needs_rebuild.store(false); m_consecutive_utxo_failures.store(0); }

    /**
     * v4.0.19: Check if persistent UndoBlock failure was detected and the chain
     * needs a full resync. Polled by IBDCoordinator::Tick alongside NeedsUTXORebuild.
     * @return true if chain undo state is unrecoverable and a rebuild is needed
     */
    bool NeedsChainRebuild() const { return m_chain_needs_rebuild.load(); }

    /**
     * v4.0.19: Clear the chain rebuild flag (after recovery is initiated).
     * Resets the consecutive failure counter and the last-failure hash.
     */
    void ClearChainRebuildFlag();

    /**
     * v4.0.19: Get the hash that triggered the most recent persistent undo failure.
     * Used by IBDCoordinator to write a useful reason into the auto_rebuild marker.
     * Returns null hash if no failure has been recorded.
     */
    uint256 GetLastUndoFailureHash() const;

    /**
     * v4.3.3 F11 (Layer-3 round 2 MEDIUM-1): read the cause that flagged
     * m_chain_needs_rebuild. M1 helper consults this to choose a non-
     * misleading [CRITICAL] banner. Atomic load — safe to call without
     * cs_main.
     */
    ChainRebuildReason GetChainRebuildReason() const {
        return m_chain_rebuild_reason.load(std::memory_order_acquire);
    }

    /**
     * v4.3.3 F11: atomic flag-and-reason setter. Stores the reason FIRST
     * (release semantics) then sets the rebuild flag — so any reader that
     * observes m_chain_needs_rebuild=true via acquire-load is guaranteed
     * to see the reason that was set in the same logical operation.
     *
     * First-cause-wins: M1 helper has a process-lifetime once-latch, so
     * only the first cause to fire is ever reported. Subsequent calls
     * are still recorded (the flag and reason are sticky-set) but the
     * helper bails at the latch.
     */
    void FlagChainRebuild(ChainRebuildReason reason) {
        m_chain_rebuild_reason.store(reason, std::memory_order_release);
        m_chain_needs_rebuild.store(true, std::memory_order_release);
    }

    /**
     * v4.3.3 F10 + F15 (Layer-3 round 3 HIGH-1, 2026-05-04): anchor the
     * VDF grace-period clock ONLY when a block at a NEW height connects.
     * Mirrors legacy semantics:
     *   - chain.cpp:622-627 (Case 2: extend-by-one to a NEW height) → anchor.
     *   - chain.cpp:723 (Case 2.5: sibling replacement at SAME height) →
     *     "Do NOT reset m_vdfTipAcceptTime — the grace window is anchored
     *     to the FIRST block at this height, preventing infinite
     *     replacement chains."
     *
     * Predicate: anchor only when `p->nHeight != m_vdfTipAcceptHeight`
     * (forward progress). Pre-F15 the anchor fired on EVERY successful
     * ConnectTip, including Case 2.5 replacements — letting a stream of
     * incoming lower-vdfOutput siblings within the original grace window
     * perpetuate replacements indefinitely. F15 closes that gap.
     *
     * Also gates on:
     *   - Block version >= 4 (VDF blocks).
     *   - p->nHeight >= vdfLotteryActivationHeight (post-VDF activation).
     *   - g_chainParams non-null.
     *
     * Public + virtual-free: callable from the connect-loop and from
     * unit tests directly without setting up a full ActivateBestChainStep
     * fixture.
     *
     * Returns true if the anchor was actually updated, false if the
     * predicate did not fire (already anchored at this height, or
     * not VDF-applicable). Tests use the return value to assert
     * first-arrival-only semantics.
     */
    bool MaybeAnchorVdfGrace(CBlockIndex* p);

    /**
     * v4.0.19: Record an UndoBlock failure for a specific block.
     * Increments counter if same hash as last failure, resets to 1 if different.
     * Sets m_chain_needs_rebuild when threshold reached.
     * Internal — called from DisconnectTip on UndoBlock failure path.
     */
    void RecordUndoFailure(const uint256& blockHash, int height);

    /**
     * v4.0.19: Reset undo failure tracking after a successful disconnect.
     * Called whenever DisconnectTip succeeds.
     */
    void ResetUndoFailureCounter();

    /**
     * v4.0.19: Startup-time integrity check for undo data on the active chain.
     *
     * Walks back up to probeDepth blocks from the current tip and confirms that
     * each block has a corresponding undo_<hash> entry in the UTXO LevelDB.
     * Catches the missing-undo-data corruption mode that causes reorg loops
     * (incident 2026-04-25). The check is cheap — one LevelDB Get per block,
     * called once at startup.
     *
     * If any probed block is missing its undo entry, fills the out parameters
     * with the FIRST missing block (closest to tip) and returns false.
     *
     * @param probeDepth Maximum number of blocks to walk back from tip
     * @param outMissingHash Receives the hash of the first missing-undo block
     * @param outMissingHeight Receives that block's height
     * @return true if all probed blocks have undo data (or chain is empty);
     *         false if any block is missing undo (out params populated)
     */
    bool VerifyRecentUndoIntegrity(int probeDepth,
                                   uint256& outMissingHash,
                                   int& outMissingHeight) const;

    /**
     * v4.4 Block 6: ChainstateIntegrityMonitor support — build a
     * (height, blockHash) snapshot of the most-recent windowBlocks of the
     * active chain, under a brief cs_main acquisition. Released on return.
     * The monitor walks the resulting vector lock-free (no cs_main held
     * during LevelDB reads).
     *
     * Returns an empty vector if the chain is too short, has no tip, or
     * windowBlocks <= 0. Heights in the returned vector are NOT clamped to
     * 1; if the chain is shorter than windowBlocks, the snapshot includes
     * everything from height 1 to the tip (genesis at height 0 is excluded
     * to mirror the genesis-exempt semantic in VerifyRecentUndoIntegrity).
     *
     * Pair ordering: descending height (tip first, oldest last) — matches
     * the pprev walk order.
     */
    std::vector<std::pair<int, uint256>> SnapshotIntegrityWindow(int windowBlocks) const;

    /**
     * v4.4 Block 6: ChainstateIntegrityMonitor revalidation gate (Inverse
     * Adversarial traps 2A + 2B). Under FRESH cs_main acquisition, walk back
     * from the current tip via pprev to the block at `height` and compare
     * its hash to `expectedHash`.
     *
     * Two outcomes:
     *   - Hashes match (block is still on the active chain): the failure
     *     represents real corruption. Calls onConfirmedCorruption() WHILE
     *     STILL HOLDING cs_main (trap 2B — marker write must happen under
     *     the same lock acquisition as the revalidation decision). Returns
     *     true.
     *   - Hashes differ (a reorg disconnected the snapshotted block; its
     *     undo entry was deleted by UndoBlock per utxo_set.cpp:881-882): the
     *     failure is an orphan-skip, not corruption. onConfirmedCorruption
     *     is NOT called. Returns false.
     *
     * The callback runs synchronously inside cs_main, so it MUST be quick
     * and non-recursive into any code that takes cs_main again (no risk
     * here since the mutex is recursive, but minimise lock-hold anyway).
     */
    bool RevalidateUnderCsMain(int height,
                               const uint256& expectedHash,
                               const std::function<void()>& onConfirmedCorruption) const;

    /**
     * Get current chain tip (most work)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    CBlockIndex* GetTip() const;

    /**
     * Set chain tip (used during initialization)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    void SetTip(CBlockIndex* pindex);

    /**
     * Test-only: Set tip without mapBlockIndex invariant check.
     * Used by unit tests that construct CBlockIndex objects directly.
     */
    void SetTipForTest(CBlockIndex* pindex) { pindexTip = pindex; }

    /**
     * Add (or merge) a block index entry in the in-memory map.
     *
     * HIGH-C001 FIX: Takes unique_ptr for automatic ownership transfer.
     *
     * Phase 11 ABI flag-merge semantics: if an entry for `hash` already
     * exists (normal during the headers-sync → block-data sequence on
     * the new peer manager / chain selector path), this MERGES the new
     * entry's nStatus bits into the existing entry via bitwise OR, and
     * adopts a previously-null pprev pointer if the new caller supplies
     * one. The incoming `pindex` is dropped on the merge path.
     *
     * Topology must agree on duplicate calls — same height, same chain
     * work, same parent (when both have one). Disagreement trips a
     * ConsensusInvariant.
     *
     * Returns true on first-time add OR successful merge. Returns false
     * only when `pindex == nullptr`. Aborts via Invariant/ConsensusInvariant
     * on hash mismatch, missing parent, or topology disagreement.
     *
     * This replaces the v4.1 silent-return-false-on-duplicate semantics
     * that left header-prepopulated entries stuck at BLOCK_VALID_HEADER
     * forever (SYD mainnet IBD silent-drop, 2026-05-02).
     */
    bool AddBlockIndex(const uint256& hash, std::unique_ptr<CBlockIndex> pindex);

    /**
     * Get block index by hash
     * Returns nullptr if not found
     */
    CBlockIndex* GetBlockIndex(const uint256& hash);

    /**
     * Check if block index exists in memory
     */
    bool HasBlockIndex(const uint256& hash) const;

    /**
     * Phase 6 PR6.1: number of entries in mapBlockIndex.
     * Used by ChainSelectorAdapter::ProcessNewHeader for cap eviction
     * (chainparams.nMapBlockIndexCap). Read is racy without cs_main but
     * the cap is sized for sustained-attack-rate so race-window overshoot
     * is irrelevant.
     */
    size_t GetBlockIndexSize() const { return mapBlockIndex.size(); }

    /**
     * Phase 6 PR6.1 (v1.5 §3.2 + Cursor v1.5+ A1): evict lowest-work
     * entry NOT on the active chain. Called by ChainSelectorAdapter when
     * mapBlockIndex hits chainparams.nMapBlockIndexCap to make room for
     * a new pre-validation header.
     *
     * Eviction policy: walk mapBlockIndex, find the entry with minimum
     * nChainWork that is NOT an ancestor of pindexTip; remove from
     * m_setBlockIndexCandidates if present, then erase from
     * mapBlockIndex. Holds cs_main for the duration to avoid use-after-
     * free against chain_selector pointers in m_setBlockIndexCandidates.
     *
     * Returns true on successful eviction. Returns false if the only
     * remaining entries are on the active chain (caller should fall back
     * to fail-closed, but this case is essentially unreachable at
     * production cap sizes — DIL=500K cap vs ~24K active chain height).
     */
    bool EvictLowestWorkNotOnBestChain();

    /**
     * Find the last common ancestor between two chains
     * Used to determine fork point during reorganization
     *
     * @param pindex1 Tip of first chain
     * @param pindex2 Tip of second chain
     * @return Pointer to common ancestor, or nullptr if no common ancestor
     */
    static CBlockIndex* FindFork(CBlockIndex* pindex1, CBlockIndex* pindex2);

    /**
     * Attempt to activate the best chain
     * Compares new block's chain work with current tip
     * If new chain has more work, reorganizes to it
     *
     * @param pindexNew Block index of newly received/mined block
     * @param block Full block data (needed for connecting)
     * @param reorgOccurred Output parameter: set to true if reorg happened
     * @return true if block successfully activated (may or may not cause reorg)
     */
    bool ActivateBestChain(CBlockIndex* pindexNew, const CBlock& block, bool& reorgOccurred);

    /**
     * VDF Distribution: Check if a competing VDF block should replace the current tip.
     * Returns true if pindexNew has a lower vdfOutput (big-endian) AND we're within grace period.
     * Uses HashLessThan() for consensus-safe comparison (NOT uint256::operator<).
     */
    bool ShouldReplaceVDFTip(CBlockIndex* pindexNew, const CBlock* pblockNew = nullptr) const;

    /**
     * Connect a block to the active chain
     * Updates pnext pointers and marks block as on main chain
     *
     * @param pindex Block index to connect
     * @param block Full block data
     * @return true on success, false on failure
     */
    bool ConnectTip(CBlockIndex* pindex, const CBlock& block, bool skipValidation = false);

    /**
     * Disconnect a block from the active chain
     * Clears pnext pointer and marks block as not on main chain
     *
     * @param pindex Block index to disconnect
     * @return true on success, false on failure
     */
    bool DisconnectTip(CBlockIndex* pindex, bool force_skip_utxo = false);

    /**
     * Disconnect blocks from current tip down to targetHeight.
     * Used for deep fork recovery: disconnect wrong-fork blocks, then
     * re-download the correct chain via normal IBD.
     *
     * Calls DisconnectTip() per block (proper UTXO/identity/mempool undo).
     * Enforces checkpoint validation. Batches of batchSize with lock release
     * between batches to avoid starving RPC/P2P threads.
     * WAL records intent for crash safety.
     *
     * @param targetHeight Height to disconnect down to (this block stays)
     * @param db Database reference for persisting progress
     * @param batchSize Blocks per batch before releasing cs_main (0 = no batching)
     * @return Number of blocks disconnected, or -1 on failure
     */
    int DisconnectToHeight(int targetHeight, CBlockchainDB& db, int batchSize = 100);

    /**
     * Get blockchain height (height of current tip)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    int GetHeight() const;

    /**
     * Get total chain work (cumulative PoW)
     * CRITICAL-1 FIX: Now implemented in .cpp with mutex protection
     */
    uint256 GetChainWork() const;

    /**
     * Get all block hashes at a specific height
     * Used for debugging forks and orphan blocks
     */
    std::vector<uint256> GetBlocksAtHeight(int height) const;

    /**
     * Get all chain tips (blocks with no children in the block index)
     * Used by block explorer to show fork visibility AND by Phase 5
     * ChainSelectorAdapter::GetChainTips (which maps string status to
     * the frozen ChainTipInfo::Status enum).
     *
     * Status taxonomy (Phase 5 Finding F3 — extended from 2 to 5 values):
     *   "active"        — pindex == pindexTip (main chain tip)
     *   "invalid"       — pindex->IsInvalid() (BLOCK_FAILED_VALID/CHILD)
     *   "valid-fork"    — non-active tip, block fully validated (>= BLOCK_VALID_TRANSACTIONS)
     *   "valid-headers" — non-active tip, header validated (>= BLOCK_VALID_HEADER) but block not
     *   "unknown"       — non-active tip with no validation level recorded
     *
     * chain_work mirrors pindex->nChainWork at the time of the call —
     * used by the adapter to populate ChainTipInfo::chain_work without
     * a second mapBlockIndex lookup.
     */
    struct ChainTip {
        int height;
        uint256 hash;
        int branchlen;
        std::string status;
        uint256 chain_work;  // Phase 5: mirrors pindex->nChainWork
    };
    std::vector<ChainTip> GetChainTips() const;

    /**
     * Clean up in-memory index
     * Deletes all CBlockIndex pointers
     */
    void Cleanup();

    /**
     * Register callback for chain tip updates (Bug #40)
     * Called whenever ActivateBestChain successfully updates the tip
     *
     * @param callback Function to call with new tip index
     */
    void RegisterTipUpdateCallback(TipUpdateCallback callback);

    /**
     * BUG #56 FIX: Register callback for block connect events
     * Called when a block is connected to the main chain
     *
     * @param callback Function to call with block data and height
     */
    void RegisterBlockConnectCallback(BlockConnectCallback callback);

    /**
     * BUG #56 FIX: Register callback for block disconnect events
     * Called when a block is disconnected from the main chain (reorg)
     *
     * @param callback Function to call with block data and height
     */
    void RegisterBlockDisconnectCallback(BlockDisconnectCallback callback);

    // ============================================================
    // Phase 5: chain-selection helpers (PR5.1 declarations only)
    // ============================================================
    //
    // These methods hold the actual block-index-tree algorithm. The
    // ChainSelectorAdapter in src/consensus/port/chain_selector_impl.cpp
    // is a thin wrapper that forwards into these. Real bodies land in
    // PR5.3 — PR5.1 ships assert(false) so the type system + linker are
    // exercised end-to-end.

    /**
     * Phase 5: pop max-work candidate leaf; if any ancestor is invalid,
     * mark BLOCK_FAILED_CHILD, remove from candidates, retry.
     * Returns the heaviest valid leaf or nullptr.
     */
    CBlockIndex* FindMostWorkChainImpl();

    /**
     * Phase 5: walk back to common ancestor and forward to pindexMostWork,
     * calling DisconnectTip / ConnectTip at each step. WAL-wrapped.
     * On ConnectTip failure: mark BLOCK_FAILED_VALID, set fInvalidFound.
     */
    bool ActivateBestChainStep(CBlockIndex* pindexMostWork,
                               std::shared_ptr<const CBlock> pblock_optional,
                               bool& fInvalidFound);

    /**
     * Phase 5: mark pindex BLOCK_FAILED_VALID; propagate BLOCK_FAILED_CHILD
     * to descendants; remove invalid leaves from candidate set; trigger
     * re-selection.
     */
    bool InvalidateBlockImpl(const uint256& hash);

    /**
     * Phase 5: reverse InvalidateBlockImpl. Clear failure flags on pindex
     * and descendants; re-add eligible leaves to candidate set; trigger
     * re-selection.
     */
    bool ReconsiderBlockImpl(const uint256& hash);

    /**
     * Phase 5: set BLOCK_FAILED_VALID on pindex AND propagate
     * BLOCK_FAILED_CHILD to all descendants in mapBlockIndex.
     */
    void MarkBlockAsFailed(CBlockIndex* pindex);

    /**
     * Phase 5: clear BLOCK_FAILED_VALID and BLOCK_FAILED_CHILD on pindex
     * AND its descendants.
     */
    void MarkBlockAsValid(CBlockIndex* pindex);

    /**
     * Phase 5: full rescan of mapBlockIndex; rebuilds m_setBlockIndexCandidates
     * from scratch. Called after major topology changes (Reconsider, startup).
     */
    void RecomputeCandidates();

    /**
     * v4.3.3 F6 (audit modality 2 HIGH-5): prune the candidate set of any
     * entry whose chainwork is strictly less than the current tip's. Mirrors
     * upstream Bitcoin Core's `PruneBlockIndexCandidates` at validation.cpp:3164.
     * Called after each successful tip activation in ActivateBestChainStep.
     *
     * Bounds memory growth (without it, every fork sibling and its leaves
     * stay in the candidate set forever) and ensures FindMostWorkChainImpl's
     * comparator-walk only considers entries that could actually be selected.
     *
     * Never erases the active tip itself.
     */
    void PruneBlockIndexCandidates();

    /**
     * Phase 5: predicate — pindex is a leaf, has BLOCK_VALID_TRANSACTIONS,
     * is not invalid, and has more work than current tip.
     */
    bool IsBlockACandidateForActivation(CBlockIndex* pindex) const;

    /**
     * RACE CONDITION FIX: Get a thread-safe snapshot of the chain path
     *
     * Returns a vector of (height, hash) pairs for blocks from current tip
     * down to minHeight, walking pprev pointers while holding cs_main.
     *
     * This allows callers to safely compare chainstate with other data
     * without risking use-after-free from concurrent modifications.
     *
     * @param maxBlocks Maximum number of blocks to include in snapshot
     * @param minHeight Stop when reaching this height (0 = genesis)
     * @return Vector of (height, hash) pairs from tip downward
     */
    std::vector<std::pair<int, uint256>> GetChainSnapshot(int maxBlocks = 1000, int minHeight = 0) const;

private:
    /**
     * Notify registered callbacks of tip update (Bug #40)
     * Called after tip successfully updated in ActivateBestChain
     *
     * @param pindex New chain tip
     */
    void NotifyTipUpdate(const CBlockIndex* pindex);
};

#endif // DILITHION_CONSENSUS_CHAIN_H
