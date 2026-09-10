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
#include <string>
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

    // ========================================================================
    // EVICTABLE-LEAF SIDE INDEX (PR #129 round 4) — O(log n) victim selection.
    //
    // WHY. The evictor used to rebuild an index-sized in-degree map on EVERY
    // call and then rescan the whole map once PER VICTIM. Measured at a 500,000
    // entry index that is 485 ms of cs_main hold and 43 MB transient against
    // main's 211 ms / 20 MB — 2.31x worse — on a path an attacker reaches by
    // spamming headers to the cap (src/tools/evict_cost_bench.cpp, CON-27).
    //
    // ── THE LEAF LEMMA, which is what makes this cheap and correct ───────────
    // in_degree[X] = number of entries in mapBlockIndex naming X as pprev.
    // X is a LEAF iff in_degree[X] == 0.
    //
    //   A LEAF CAN NEVER BE PINNED TRANSITIVELY.
    //
    // Proof: the pin set is built by walking pprev ANCESTORS of pinned roots.
    // If X were a strict ancestor of any entry E in the map, then the entry one
    // step from X toward E names X as its pprev and is itself in the map, so
    // in_degree[X] >= 1 and X is not a leaf. Contrapositive: a leaf is never a
    // strict ancestor of anything, so no ancestor walk can reach it.
    //
    // Therefore a leaf is pinned ONLY by being DIRECTLY in a pin set, and the
    // four clauses collapse to four direct tests with no walk at all:
    //   (a) active chain    -> X == pindexTip          (any other active-chain
    //                          entry has an active child, so is not a leaf)
    //   (b) candidates      -> m_setBlockIndexCandidates.count(X)
    //   (c) data-not-valid  -> a flag test on X itself (never transitive)
    //   (d) pending         -> pending.count(X->GetBlockHash())  (snapshot taken
    //                          once per call, not per candidate)
    //
    // So selection is: take the lowest-work leaf, apply four O(1)/O(log n)
    // tests, evict or skip. The number skipped is bounded by
    // 1 + (candidate leaves) + (pending), and a candidate costs PoW-bearing
    // block data to create, so it is not an attacker-controlled quantity.
    //
    // ── THE SORT KEY MUST NOT MUTATE IN PLACE ───────────────────────────────
    // Ordering is by (nChainWork, hash). A key that changes while the element
    // sits in a std::set is silent ordering corruption, not a crash — and
    // nChainWork is NOT serialised (it reads back zero from the DB; see
    // lesson_a_default_value_read_back_may_never_have_been_stored), so "it is
    // recomputed later" was a live hazard worth checking rather than assuming.
    //
    // CENSUSED, whole tree, every assignment shape: 10 non-test writers of
    // nChainWork — chain_selector_impl.cpp:412, block_index.cpp (2 ctors, the
    // copy-assign, and BuildChainWork's two arms), the two genesis sites in
    // dilithion-node/dilv-node, and the 8 BuildChainWork() call sites. EVERY ONE
    // writes BEFORE its entry reaches AddBlockIndex — verified per site by
    // locating the AddBlockIndex that follows it. AddBlockIndex's merge branch
    // does NOT write nChainWork; it ConsensusInvariant-ASSERTS the incoming and
    // existing values are equal, which enforces the immutability rather than
    // relying on it. No DB-load path inserts and then recomputes.
    //
    // Conclusion: nChainWork is immutable for the lifetime of an entry's
    // membership in mapBlockIndex, so it is a legal set key. If that ever stops
    // being true, this index must be re-keyed on write or rebuilt after the
    // recompute — it will NOT fail loudly on its own.
    //
    // MAINTENANCE IS FOUR SITES — and this block said "EXACTLY TWO" until two
    // separate reviews found the two it had missed. Both misses were live
    // use-after-frees, and both were missed the same way: the census looked for
    // the two OPERATIONS the author had in mind instead of for every mutation.
    //
    //   MEMBERSHIP  (grep: mapBlockIndex\.(insert|emplace|erase|clear) or [ ])
    //     chain.cpp Cleanup()      clear()  -> clear BOTH structures.
    //                              MISSED FIRST. Freed every node while the leaf
    //                              index kept the pointers; the next insert's
    //                              comparator read freed memory. Not teardown-only
    //                              — it is the corrupted-DB recovery path.
    //     chain.cpp AddBlockIndex  insert   -> LeafIndexOnInsert.
    //     chain.cpp evictor        erase()  -> LeafIndexOnErase.
    //
    //   pprev GRAPH OF A LIVE MEMBER  (grep: ->pprev\s*=)
    //     chain.cpp AddBlockIndex  merge-adopt -> in-degree += 1, parent leaves
    //                              the leaf set. MISSED SECOND. Adoption gives a
    //                              live entry a parent, so that parent stops being
    //                              a leaf; unmaintained, the evictor freed a node
    //                              a surviving child named as pprev — the exact
    //                              interior-node UAF this class exists to close.
    //
    // TREE-WIDE CENSUS (round-6, kimi MEDIUM): GetBlockIndex returns a NON-CONST
    // CBlockIndex*, so any translation unit can mutate a live member and evade a
    // chain.cpp-scoped census. Checked across all of src/ excluding tests:
    //
    //   `->pprev =`   16 hits. FIFTEEN are on a FRESH index before AddBlockIndex
    //                 (chain_selector_impl:410, block_processing:1094,
    //                 block_validation_queue:749/855, dilithion-node:2735/2824/
    //                 2909/6410/6637, dilv-node:2592/2681/2775/6446, the bench).
    //                 The DB-load sites construct make_unique<CBlockIndex> first —
    //                 verified, not assumed. The SIXTEENTH is chain.cpp:203, the
    //                 adopt arm, which is the one site that touches a live member
    //                 and is now unreachable (see below).
    //   `nChainWork =` 10 hits, ALL before the entry reaches AddBlockIndex; the
    //                 merge arm ASSERTS equality rather than writing. This is what
    //                 makes nChainWork legal as a std::set key.
    //
    //   ⚠️ ONE SHAPE DOES MUTATE A LIVE MEMBER AND IS NOT A MAINTENANCE SITE:
    //   `pblockIndex->pprev->pnext = ...` (dilithion-node:2913, dilv-node, the
    //   connect path). It writes the PARENT's pnext, which is a live map entry —
    //   but leafness is defined over pprev IN-EDGES only, so pnext cannot change
    //   in-degree or leaf status. Stated explicitly because "mutates a live
    //   member" is the alarm shape, and the reason it is harmless is not obvious.
    //
    // A pprev written on a NEW index BEFORE AddBlockIndex (block_processing.cpp
    // and friends) is NOT a maintenance site: the entry is not in the map yet and
    // LeafIndexOnInsert reads its pprev when it arrives. Only mutations of an
    // entry ALREADY IN THE MAP need maintenance — that is the distinction the two
    // misses turned on.
    //
    // The per-site effects:
    //   insert(X): X is new, so it is a leaf -> add X. X->pprev gains a child
    //              -> remove X->pprev.
    //   erase(X):  remove X. X->pprev loses a child -> if its in-degree hits 0,
    //              add X->pprev.
    //   clear():   drop both structures entirely.
    //   adopt(X):  X gains a pprev -> that parent gains a child -> in-degree += 1
    //              and it leaves the leaf set.
    // ========================================================================
    struct LeafWorkOrder {
        // Lowest work first, hash as the tiebreak so the order is total and
        // deterministic. ChainWorkGreaterThan, never memcmp/operator< — chainWork
        // is not memcmp-comparable.
        bool operator()(const CBlockIndex* a, const CBlockIndex* b) const;
    };
    std::map<const CBlockIndex*, size_t> m_inDegree;
    std::set<CBlockIndex*, LeafWorkOrder> m_evictableLeaves;

    // ========================================================================
    // DEFERRED RECLAMATION — the graveyard.
    //
    // WHAT IT IS FOR. 62 call sites resolve a CBlockIndex* under cs_main and use
    // it after the lock is released (census: scripts/census_blockindex_pointer_
    // windows.py). Guarding all 62 is a fix aimed at consumers when the defect has
    // ONE producer: eviction is the only runtime free. Eviction now UNLINKS
    // immediately — out of mapBlockIndex, the leaf index, the in-degree map and
    // the candidate set, so a by-hash re-resolve returns null exactly as today —
    // and the MEMORY is released only at a point where no thread can still hold a
    // pointer to it. Every one of those 62 windows then points at memory that
    // stays valid for the duration of the call.
    //
    // ⚠️ THIS IS NOT SUFFICIENT ON ITS OWN, AND THE ORDER MATTERS.
    //   * A grace period protects a pointer held by a THREAD.
    //   * It does NOTHING for a pointer stored in the GRAPH: if an interior node X
    //     is freed while a child C has C->pprev == X, deferring the free only
    //     moves WHEN C->pprev dangles, because C->pprev is not transient.
    // Leaf-only eviction (#129) is what makes an entry safe to free AT ALL; this
    // makes the timing safe. Both are required and neither substitutes.
    //
    // WHY AN EPOCH AND NOT A TIMER. A wall-clock grace is an assumption about
    // worst-case call duration, and the ProcessBlock path alone contains a LevelDB
    // write — milliseconds, bounded above by nothing in this repo. A stalled VM, a
    // slow disk or a debugger silently violates it and the failure is a
    // use-after-free. An epoch bound is a proof: each participating thread bumps
    // its counter at a point where it provably holds no CBlockIndex*, and an entry
    // is freed only once EVERY registered thread has moved past the epoch in which
    // it was unlinked. See docs/contracts/deferred-reclamation-quiescence-proof.md
    // for the thread-by-thread table of those points.
    struct GraveyardEntry {
        std::unique_ptr<CBlockIndex> node;   // owned, unlinked, not yet freed
        uint64_t unlinked_epoch;             // global epoch at unlink time
    };
    std::vector<GraveyardEntry> m_graveyard;

    // Bumped by each participating thread at its call boundary; the drain frees
    // entries older than the minimum across all of them.
    std::atomic<uint64_t> m_globalEpoch{1};

    // TEST-ONLY. When set, eviction frees the entry in place instead of parking it
    // in the graveyard -- the behaviour this branch replaced. It exists so the
    // ASan arms can put the defect and the fix in ONE binary with deferral as the
    // only variable; production never sets it.
    std::atomic<bool> m_immediateFreeForTest{false};

public:
    /**
     * Bump this thread's epoch. Called at the boundary where the calling thread
     * provably holds no CBlockIndex* — see the quiescence proof for which point
     * that is per thread. Cheap: one relaxed atomic store into a thread-local.
     */
    void EpochCheckpoint(const char* name = nullptr);

    /**
     * Declare that a thread called `name` will participate — called by whoever
     * spawns it. The declared set and the set that has actually checkpointed are
     * compared by EpochRegistrationComplete() at startup, so a thread that is
     * started and never checkpoints is named rather than merely missing from a
     * count. Deliberately built by the spawning code instead of a static list: a
     * static list cannot know whether the txindex thread was started on THIS run.
     */
    void DeclareEpochParticipant(const char* name);

    /** How many participants have been declared by spawn sites this run. */
    size_t DeclaredEpochParticipants() const;

    /**
     * Free graveyard entries that every participating thread has moved past.
     * Safe to call from anywhere; takes cs_main. Returns the number freed.
     */
    size_t DrainGraveyard();

    /** How many threads have checkpointed at least once (i.e. are participants). */
    size_t RegisteredEpochThreads() const;

    /**
     * Is every participant accounted for? Fails if a DECLARED thread has never
     * checkpointed (named in `why`), or if any thread has obtained a
     * CBlockIndex* while never having checkpointed (observed, needs no list).
     *
     * A thread that never checkpoints pins the graveyard for the process
     * lifetime -- safe, but an unbounded and SILENT leak, which is why this is
     * asserted at startup rather than assumed. `why` carries the diagnostic.
     */
    bool EpochRegistrationComplete(std::string& why) const;

    /**
     * Poll EpochRegistrationComplete() until it passes or `timeout_ms` elapses.
     * Called once at node startup after the last thread spawn. A failure means a
     * declared thread never checkpointed, or a thread holds pointers without
     * ever having checkpointed — either way the graveyard is pinned for the
     * process lifetime, so the node refuses to run rather than leaking silently.
     */
    bool AwaitEpochRegistration(int timeout_ms, std::string& why);

    /**
     * TEST-ONLY: make eviction free the entry in place, as it did before deferred
     * reclamation existed. The ASan arms use it to reproduce the use-after-free
     * and the fix in one binary on one fixture (src/test/blockindex_uaf_asan_arm.cpp
     * is the only caller). Never set in production.
     */
    void SetEvictionImmediateFreeForTest(bool on);

    /**
     * How many threads have obtained a CBlockIndex* and have NEVER checkpointed.
     *
     * ⚠️ THIS IS THE DETECTOR THAT DOES NOT DEPEND ON A LIST BEING MAINTAINED.
     * The participant count above is checked against a table, and the thread that
     * leaks is added by someone who would also have forgotten the table row — so
     * the count catches a wired thread that has not reached its checkpoint yet,
     * and this catches the unwired thread that was never written down. It is
     * recorded at the only place the hazard is visible without a list: the moment
     * a raw pointer leaves cs_main. Cleared when the thread checkpoints, so
     * resolving during startup before the first checkpoint is not counted.
     *
     * Non-zero means an unbounded, silent graveyard leak. `detail` names the
     * count and the thread ids.
     */
    size_t UnregisteredResolverThreads(std::string& detail) const;

    /** Test/diagnostic: how many entries are unlinked but not yet freed. */
    size_t GraveyardSize() const {
        std::lock_guard<std::recursive_mutex> lock(cs_main);
        return m_graveyard.size();
    }
private:

    // Maintain the two structures above. Called only from AddBlockIndex and the
    // evictor's erase; both hold cs_main.
    void LeafIndexOnInsert(CBlockIndex* pnew);
    void LeafIndexOnErase(CBlockIndex* pgone);

    // Debug-only: recompute in-degree and the leaf set from scratch and compare.
    // Used by the invariant test; not called in production.
public:
    bool LeafIndexMatchesBruteForce() const;
    bool IsLeafPinnedDirect(const CBlockIndex* leaf,
                            const std::set<uint256>& pending) const;
private:

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
    // Magnet v1a (fork-resistance, OBSERVABILITY ONLY): canonical
    // node-health signal. A node must never SILENTLY persist on a
    // losing / non-canonical fork — this exposes a loud, machine-
    // readable "I am off-canonical" signal. Pure read + report:
    // adds NO consensus state, changes NO fork-choice / reorg /
    // validation / mining behavior. See IsOnCanonical() below.
    //
    // Edge-trigger latch for the ONE structured ERROR log line emitted
    // when the node transitions INTO the off-canonical state. Set true
    // on the false→true transition so we log once, not every block;
    // cleared when the node returns on-canonical (e.g. rebuild flag
    // cleared) so a later re-entry logs again. mutable: the edge-trigger
    // is toggled from the const LogOffCanonicalTransition() accessor.
    mutable std::atomic<bool> m_off_canonical_logged{false};

    // Magnet v1a: monotonically counts how many times the edge-trigger in
    // LogOffCanonicalTransition ACTUALLY emitted (i.e. won the false→true
    // latch transition). Incremented ONLY on the emit path, so it directly
    // observes the latch: double-logging within one episode, or a failure to
    // re-arm, is detectable by the unit test (magnet_canonical_health_tests
    // M5) that IsOnCanonical() alone cannot see (IsOnCanonical reads the
    // rebuild flag, not this latch). Observability-only; production never
    // reads it. mutable: toggled from the const emitter.
    mutable std::atomic<uint64_t> m_off_canonical_emit_count{0};

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
    //
    // P2P-14/15 (2026-09-07): the callback passes VALUES, not a CBlockIndex*.
    //
    // It used to be `std::function<void(const CBlockIndex*)>`, fired from inside
    // ActivateBestChain with cs_main HELD. That produced two distinct defects:
    //
    //   1. LOCK-ORDER CYCLE. The registered consumer is CHeadersManager::
    //      OnBlockActivated, which takes cs_headers — so cs_main → cs_headers.
    //      The reverse edge, cs_headers → cs_main, exists on the header-processing
    //      path (ProcessHeaders holds cs_headers and reaches AddBlockIndex /
    //      EvictLowestWorkNotOnBestChain, both of which take cs_main). TSan
    //      CONSTRUCTS the resulting deadlock: docs/p2p14-lock-inversion/ —
    //      registered arm 2 lock-order-inversions, unregistered arm 0.
    //
    //   2. POINTER LIFETIME. Handing a raw CBlockIndex* to a callback that runs
    //      after the lock is released is a use-after-free waiting to happen:
    //      CBlockIndex objects ARE destroyed at runtime (mapBlockIndex.erase in
    //      EvictLowestWorkNotOnBestChain), and the headers thread itself drives
    //      that eviction. Eviction spares the active chain, so the tip is safe
    //      only until a reorg makes it non-active.
    //
    // Passing copies closes BOTH: there is no pointer to outlive the lock, so the
    // fire can move outside cs_main and the cycle has no edge to close on.
    //
    // Values, not a pointer. Do not "optimise" this back to a CBlockIndex* — that
    // reintroduces defect 2 silently and defect 1 the moment a consumer takes a
    // lock. Add a field to the snapshot instead.
    //
    // ⚠️ CONTRACT CHANGE FOR EVERY CONSUMER, PRESENT AND FUTURE (red-team H-3).
    // Before this change, callbacks fired INSIDE cs_main, so they were mutually
    // exclusive and totally ordered for free: one mutex serialised activations
    // and their notifications together. Firing after release DECOUPLES them.
    //
    //   * Two threads can be inside the callback list SIMULTANEOUSLY. A
    //     consumer must now be re-entrant.
    //   * A later tip's callback can COMPLETE BEFORE an earlier tip's. A
    //     consumer that tracks "best" must be monotonic on its own and must not
    //     assume delivery order matches activation order.
    //   * Per-activation order IS preserved (the queue is appended under
    //     cs_main and drained in order) — that is a narrower guarantee than it
    //     sounds, and it is NOT cross-activation ordering.
    //   * A thread can return from ActivateBestChain with its own notification
    //     not yet delivered, because another thread's drain may have swapped
    //     the queue out. Almost always delivered before return; never
    //     guaranteed. Do not build a barrier on it.
    //
    // The current consumer (CHeadersManager::OnBlockActivated) is safe under
    // this: its writes are idempotent and its best-header update is
    // work-monotone. That is a property of TODAY's consumer, not a guarantee of
    // the mechanism — which is why it is written here rather than assumed.
    using TipUpdateCallback = std::function<void(const CBlockHeader&, const uint256&)>;
    std::vector<TipUpdateCallback> m_tipCallbacks;

    // Snapshot of one tip update, taken under cs_main and fired after release.
    struct PendingTipNotification {
        CBlockHeader header;
        uint256 hash;
    };
    // Written by NotifyTipUpdate under cs_main; drained by TipNotifyDrain.
    std::vector<PendingTipNotification> m_pendingTipNotifications;

    // BUG #56 FIX: Block connect/disconnect callbacks (Bitcoin Core pattern)
    // Allows wallet to be notified when blocks are connected/disconnected
    // IBD OPTIMIZATION: Pass hash to avoid RandomX recomputation in callbacks
    using BlockConnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    using BlockDisconnectCallback = std::function<void(const CBlock&, int height, const uint256& hash)>;
    std::vector<BlockConnectCallback> m_blockConnectCallbacks;
    std::vector<BlockDisconnectCallback> m_blockDisconnectCallbacks;

    // PR #129 MEDIUM-2 (cascade-eviction liveness): pending-block-hash provider.
    // The async validation queue (CBlockValidationQueue) registers a provider
    // here that returns the set of block hashes it is currently responsible for
    // — every queued block AND the one in-flight in its worker (popped from the
    // queue but mid-ProcessBlock, with cs_main released between ops). Eviction
    // (EvictLowestWorkLeafNotPinned) consults this provider while holding cs_main
    // and pins each such block AND its pprev-ancestor chain, so a cascade cannot
    // free a queued block's parent out from under the worker's create path. The
    // provider returns HASHES only (a pure read of queue state under the queue's
    // own mutex); eviction does the mapBlockIndex lookup and pprev walk under the
    // cs_main it already holds. This keeps the lock order cs_main -> queue mutex
    // (never the reverse) and never re-enters a queue method that calls back into
    // CChainState. This is ADDITIVE liveness defense — it does NOT supersede the
    // queue worker's by-hash re-resolve, which remains the authoritative
    // eviction-/merge-safe correctness path for BLOCKER-1.
    using PendingBlockHashProvider = std::function<std::set<uint256>()>;
    PendingBlockHashProvider m_pendingBlockHashProvider;

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

    // ============================================================
    // Magnet v1a (fork-resistance): canonical node-health accessors.
    // OBSERVABILITY ONLY — pure read + report, no behavior change.
    // ============================================================
    /**
     * Magnet v1a: is this node on the canonical (best-known) chain?
     *
     * Returns false ("off-canonical") when EITHER:
     *   1. A pending chain-rebuild caused by DepthRejection exists — a
     *      strictly-better chain exists beyond MAX_REORG_DEPTH that the
     *      node knows about but cannot auto-switch to in-process
     *      (chain.cpp DepthRejection site). The canonical "I am stuck
     *      off the best chain" state.
     *   2. Drift signal: a candidate leaf in m_setBlockIndexCandidates
     *      has strictly greater chain-work than the active tip but was
     *      not adopted. Pure read of existing state under cs_main using
     *      ChainWorkGreaterThan — no new consensus state.
     *
     * Lock-free for case (1) (atomic loads); acquires cs_main briefly
     * for the case (2) candidate-vs-tip work comparison. Safe to call
     * from RPC threads. Does NOT mutate any state.
     *
     * @return true if on-canonical (nothing strictly better is known),
     *         false if off-canonical.
     */
    bool IsOnCanonical() const;

    /**
     * Magnet v1a: machine-readable reason string, empty when on-canonical.
     * One of: "" (on-canonical) or "depth-rejection" (a strictly-better chain
     * exists beyond MAX_REORG_DEPTH that the node cannot auto-switch to — the
     * node is genuinely stuck behind a better chain). The earlier "work-drift"
     * reason (a heavier candidate leaf was not adopted) was DROPPED per
     * red-team MED-1: its unique cases were false-positives (see chain.cpp).
     * Genuine drift detection is a v2 item (F7 anchored-root).
     */
    std::string OffCanonicalReason() const;

    /**
     * Magnet v1a: edge-triggered emitter for the single structured
     * ERROR log line on the on→off-canonical transition. Call at sites
     * that flag an off-canonical condition (e.g. the DepthRejection
     * rebuild site). Emits at most one line per off-canonical episode
     * via m_off_canonical_logged; the latch is cleared when the node
     * returns on-canonical. OBSERVABILITY ONLY — logs, changes nothing.
     *
     * @param reason        the off-canonical reason string (see above)
     * @param best_known_ht best-known height beyond the tip if available
     *                      (< 0 when unknown); local tip height is read here.
     */
    void LogOffCanonicalTransition(const std::string& reason, int64_t best_known_ht) const;

    /**
     * Magnet v1a TEST OBSERVABILITY: number of times LogOffCanonicalTransition
     * has actually emitted (won the edge-trigger latch). Lets the unit test
     * verify exactly-one-emit-per-episode and re-arm — behavior IsOnCanonical()
     * cannot observe. Not used by production code.
     */
    uint64_t OffCanonicalEmitCount() const {
        return m_off_canonical_emit_count.load(std::memory_order_acquire);
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
    void SetTipForTest(CBlockIndex* pindex) { pindexTip = pindex; m_chainTipsCacheDirty = true; }

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
     * PR #129 HIGH-1: scoped hold of cs_main, for the ONE pattern that needs it.
     *
     * THE BUG THIS EXISTS TO CLOSE. Every CChainState method acquires and
     * RELEASES cs_main individually, so a caller that does
     *
     *     pprev = GetBlockIndex(prevHash);   // lock taken AND released
     *     ... build a CBlockIndex from pprev ...
     *     AddBlockIndex(hash, std::move(pindex));   // lock re-taken
     *
     * is holding a raw CBlockIndex* on its own stack across a lock release.
     * A concurrent EvictLowestWorkLeafNotPinned on another thread can free
     * `pprev` in that window: it is a leaf (the child is not inserted yet, so
     * in-degree 0), header-only entries are never candidates, and the lowest-work
     * unpinned leaf is exactly what eviction selects. The caller then dereferences
     * freed memory and — worse — STORES the dangling pointer permanently into
     * mapBlockIndex as the new entry's pprev. That is the identical end state to
     * the v4.5.0 interior-node dangle, reached through a different door.
     *
     * The eviction-safety argument in EvictLowestWorkLeafNotPinned reasons about
     * pointers held INSIDE mapBlockIndex plus the enumerated cached-member holders
     * in the landmine ledger. It does not cover STACK-LOCAL holders across a lock
     * release, and cannot: they are invisible to it.
     *
     * WHAT THIS GUARD IS FOR — STATED AS PROPERTIES, NOT AS A SPAN. Two things
     * have to hold, and any arrangement of locking that delivers both is correct:
     *
     *   (a) NO DEREFERENCE OF A RESOLVED CBlockIndex* AFTER cs_main IS RELEASED.
     *       GetBlockIndex takes cs_main, looks up, and releases it before
     *       returning, so the returned pointer is only meaningful while a lock is
     *       still held. "Dereference" includes a WALK: GetNextWorkRequired follows
     *       pprev, so passing it a resolved pointer is a chain of unlocked derefs,
     *       not one — which is how the second instance in
     *       CBlockValidationQueue::QueueBlock survived the fix for the first.
     *   (b) PIN PUBLICATION UNDER cs_main. The evictor snapshots the pending-hash
     *       set under cs_main and deletes under the same cs_main, so a producer
     *       that publishes under m_queue_mutex alone loses a snapshot→publish→
     *       delete race that has nothing to do with the queue mutex. Publishing
     *       under cs_main makes admission atomic against an eviction in flight.
     *
     * WHY THAT PHRASING MATTERS. A review of PR #129 asked for ONE guard spanning
     * resolve → nStatus → publication in QueueBlock. That span holds cs_main
     * across CheckProofOfWorkDFMP on the block-admission path — cs_main is what
     * block processing, ActivateBestChain and the RPC tip cache contend on — so it
     * would have bought the two properties AND a contention regression. Three
     * narrow guards buy the properties alone. The properties are the requirement;
     * the span is an implementation choice, and a future edit should be checked
     * against (a) and (b), not against how many guards there are.
     *
     * THE CRITICAL SECTION IS EXACTLY [resolve pprev, insert the child]. Once the
     * child is in the map pointing at pprev, pprev has in-degree >= 1, is no longer
     * a leaf, and is ineligible for eviction. Before that instant it is naked.
     * Holding cs_main across those two calls is the whole fix.
     *
     * ⚠️ THIS GUARD IS APPLIED AT TWO SITES. THE CLASS IS LIVE AT **AT LEAST FIVE**
     * MORE, AND THE LIST BELOW IS A FLOOR, NOT A CENSUS (external panel /
     * non-author reader). Everything above describes what the guard does where it
     * is used; it is not a statement that the resolve→deref race is closed in the
     * node. It is not.
     *
     * ⚠️ "FOUR MORE" WAS ITSELF AN OVERCLAIM and is corrected here. The reader
     * found a FIFTH in this PR's own file — block_validation_queue.cpp QueueBlock,
     * `GetBlockIndex(block.hashPrevBlock)` then `pParent->nStatus`, resolved and
     * dereferenced across a cs_main release — and there are ~61 `GetBlockIndex(`
     * call sites across block_processing / block_validation_queue /
     * dilithion-node / dilv-node / ibd_coordinator / headers_manager /
     * orphan_manager that have never been swept for this shape. A hand-listed set
     * of sites read as a complete enumeration is exactly the defect
     * "a-fix-aimed-at-a-site-leaves-siblings" describes; the ENUMERATION itself is
     * a #193 deliverable, mechanical and grep-driven, not another hand count.
     *
     * The named ones so far:
     *
     *   src/node/block_processing.cpp:1094 → :1274 → :1281 → :1287
     *       resolve pprev, deref pprev->nHeight, LevelDB WriteBlockIndex, add.
     *       This file contains ZERO occurrences of cs_main or MainLockGuard, and
     *       the disk write sits INSIDE the window, so it is the widest of the six.
     *   src/node/dilithion-node.cpp:6413 → :6432
     *   src/node/dilithion-node.cpp:6622 → :6650
     *   src/node/dilv-node.cpp:6431 → :6459
     *   src/node/block_validation_queue.cpp — QueueBlock: GetBlockIndex(
     *       block.hashPrevBlock) then pParent->nStatus, across a cs_main release.
     *       In THIS PR's own file, pre-existing, unpinned.
     *
     * The FOREIGN-FILE ones are PRE-EXISTING and are fixed in the sibling PR, not
     * here — widenings of the hottest lock in the node need their own deadlock
     * argument against the queue mutex and ActivateBestChain, plus a TSan run
     * with a positive control and a test that goes RED by freeing the parent in
     * the window. That work does not belong inside a fold.
     *
     * The cap reduction rides with them for the same reason: eviction is
     * attacker-triggerable by header spam at any cap, so the cap does not create
     * or remove this race — it only prices the trigger. Lowering it while the
     * four sites are open would make a live class ~10x cheaper to reach.
     *
     * WHY A GUARD RATHER THAN A NEW ATOMIC METHOD. The two call sites build
     * materially different CBlockIndex objects (a header-only entry with
     * BLOCK_VALID_HEADER and a sequence id, vs. a received block with
     * MarkBlockReceived and a LevelDB write), and both run caller-specific checks
     * against pprev in between. Folding them into one CChainState method would
     * either need a callback invoked under the lock or duplicate the divergent
     * logic. A guard keeps each call site's semantics byte-identical and makes the
     * change reviewable as "the lock is now held across this region", nothing else.
     *
     * SELF-DEADLOCK IS SAFE. cs_main is a recursive_mutex (BUG #200), so the
     * acquisitions inside GetBlockIndex / AddBlockIndex / EvictLowestWorkLeafNotPinned
     * nest as no-ops while this guard is held.
     *
     * LOCK ORDER — read this before adding a third use site.
     *
     * vs. m_queue_mutex: CLEAN. The documented order is cs_main -> queue mutex
     * (eviction holds cs_main and calls GetPendingBlockHashes, which takes
     * m_queue_mutex). CBlockValidationQueue::ProcessBlock is invoked at
     * block_validation_queue.cpp:307, AFTER the worker's m_queue_mutex scope closes
     * at :299, and nothing under either guard takes m_queue_mutex, m_stats_mutex or
     * a watchdog lock. Taking m_queue_mutex first and then cs_main WOULD invert the
     * order — do NOT use this guard anywhere that already holds the queue mutex.
     *
     * vs. cs_headers: ONE-DIRECTIONAL AS OF #183. Re-verified on the merge of
     * origin/main into this branch, because the paragraph that used to stand here
     * had gone stale and would have justified live code with a dead fact.
     *
     * An earlier version of this comment claimed both call sites "hold no other
     * lock when they enter". That is FALSE and was corrected after a fresh-context
     * review caught it. CHeadersManager::ProcessHeaders takes cs_headers at
     * headers_manager.cpp:222 and calls ProcessNewHeader at :369 INSIDE that scope
     * (likewise the :546 and :689 holders). So on those paths the order is
     * cs_headers -> cs_main. THAT FORWARD EDGE IS STILL LIVE and is re-confirmed
     * above against the merged head, not carried over.
     *
     * WHAT CHANGED, AND WHY THE PREVIOUS TEXT HERE IS NOW WRONG. It read: "The
     * opposing edge is live and documented in-repo at headers_manager.cpp:1082-1085:
     * 'OnBlockActivated holds cs_main and wants cs_headers' ... Both directions
     * exist: a textbook ABBA." That citation now points at text saying the
     * OPPOSITE. #183 (P2P-14/15) removed the reverse edge:
     *
     *   - the tip callback passes VALUES, not a CBlockIndex*, so the fire no
     *     longer has to happen under cs_main (chain.h, TipUpdateCallback);
     *   - DrainTipNotifications copies the queue AND the callback vector under
     *     cs_main, closes that scope, and fires with cs_main NOT held
     *     (chain.cpp:2802-2839, its own comment: "cs_main is released. Consumers
     *     may now take their own locks (cs_headers) without inverting against it");
     *   - headers_manager.cpp:1103-1106 retracts the old rationale in as many words.
     *
     * The reverse edge was the ONLY one. The P2P-14/15 harness census
     * (src/test/p2p14_lock_inversion_tsan_tests.cpp:11-21) enumerates exactly one:
     * ActivateBestChain -> NotifyTipUpdate -> m_tipCallbacks -> OnBlockActivated ->
     * cs_headers. Independently: chain.cpp, which owns cs_main, contains ZERO calls
     * into CHeadersManager (3 textual mentions, all comments).
     *
     * A single direction is not a cycle. So this guard WIDENS A FORWARD-ONLY EDGE.
     *
     * THIS GUARD STILL DOES NOT CREATE AN INVERSION — before it, ProcessNewHeader
     * already called GetBlockIndex and AddBlockIndex, each taking cs_main
     * internally, so cs_headers -> cs_main was already on this path. What the guard
     * does is WIDEN the hold. The cost of that is now CONTENTION, not deadlock
     * exposure: there is no opposing edge left for the widened window to meet.
     * Do not restate the old "real increase in deadlock exposure" claim without
     * re-running the harness — and do not read this as "lock order preserved"
     * either, which was the error the old text was written to prevent.
     *
     * IF ANYONE REINTRODUCES A cs_main -> cs_headers EDGE, this analysis dies with
     * it and the ABBA is back, wider than before. The regression guard is the
     * registered arm of p2p14_lock_inversion_tsan_tests, which HANGS when the cycle
     * exists and exits 0 when it does not.
     *
     * SCOPE IT TIGHTLY. Widening a cs_main hold is a real cost: it is the lock
     * block processing, ActivateBestChain and the RPC tip-cache all contend on.
     * Hold it across the resolve->insert region and nothing more.
     */
    class MainLockGuard {
    public:
        explicit MainLockGuard(CChainState& chainstate)
            : m_lock(chainstate.cs_main) {}
        MainLockGuard(const MainLockGuard&) = delete;
        MainLockGuard& operator=(const MainLockGuard&) = delete;
    private:
        std::lock_guard<std::recursive_mutex> m_lock;
    };

    /**
     * Get block index by hash
     * Returns nullptr if not found
     *
     * PR #129 HIGH-1: the returned raw pointer is only guaranteed valid while
     * cs_main is held. If you intend to dereference it, or store it, after any
     * other CChainState call returns, you MUST hold a MainLockGuard across the
     * whole region — a concurrent evictor can free it otherwise. See MainLockGuard.
     */
    CBlockIndex* GetBlockIndex(const uint256& hash);

    /**
     * P2P-14/15 §0.3-POST: read a block's height BY VALUE, under cs_main.
     *
     * GetBlockIndex above acquires cs_main, releases it, and hands back a raw
     * pointer. Every caller that dereferences that pointer without separately
     * holding cs_main is racing the eviction path — the shape LP10 measured
     * under TSan at 6353bc33 ("a mutex on one side buys nothing").
     *
     * CHeadersManager::OnBlockActivated did exactly that, and got away with it
     * ONLY because its caller (ConnectTip → NotifyTipUpdate) still held cs_main
     * — a dependency its own comment relied on. The P2P-14/15 fix fires that
     * callback with cs_main RELEASED, which removed the guarantee. Snapshotting
     * the callback's parameters does NOT cover this: it is a second, internal
     * pointer.
     *
     * So: return the value, never the pointer. The read and the dereference
     * happen inside one lock scope.
     *
     * @param hash      block to look up
     * @param heightOut set to the block's height on success, untouched on failure
     * @return true if the block index exists
     */
    bool GetBlockHeightByHash(const uint256& hash, int& heightOut) const;

    /**
     * Check if block index exists in memory
     */
    bool HasBlockIndex(const uint256& hash) const;

    /**
     * Phase 6 PR6.1: number of entries in mapBlockIndex.
     * Used by the cap-eviction checks in ChainSelectorAdapter::ProcessNewHeader
     * and CBlockValidationQueue::ProcessBlock.
     *
     * TAKES cs_main (external panel, gpt6 HIGH). This used to read
     * `mapBlockIndex.size()` unlocked, excused by the comment "Read is racy
     * without cs_main but the cap is sized for sustained-attack-rate so
     * race-window overshoot is irrelevant."
     *
     * THAT EXCUSE ANSWERED THE WRONG OBJECTION. It defends a stale VALUE, and a
     * stale value genuinely would be harmless here — the cap is advisory. But
     * `std::map::size()` executing concurrently with `erase()` or `operator[]`
     * on another thread is a DATA RACE and therefore undefined behaviour,
     * whatever the number is used for afterwards. Three threads reach these
     * paths (the P2P message handler and the header-validation worker via
     * ProcessNewHeader, plus the queue worker), and eviction erases from this
     * very map, so the race is reachable rather than theoretical.
     *
     * cs_main is a RECURSIVE mutex and is `mutable`, so this is safe to call
     * from a const context and from callers that already hold it — which the
     * queue path does.
     */
    size_t GetBlockIndexSize() const {
        std::lock_guard<std::recursive_mutex> lock(cs_main);
        return mapBlockIndex.size();
    }

    /**
     * Phase 6 PR6.1 (v1.5 §3.2 + Cursor v1.5+ A1): evict the lowest-work
     * UNPINNED LEAF to make room for a new pre-validation header. Called by
     * ChainSelectorAdapter when mapBlockIndex hits nMapBlockIndexCap.
     *
     * LEAF-ONLY INVARIANT (the v4.5.0-pull fix). mapBlockIndex owns its
     * CBlockIndex via unique_ptr, but surviving entries reference their
     * parent by a RAW pprev pointer (dereferenced in ~50 places across
     * chain.cpp: FindMostWorkChain, MarkBlockAsFailed, GetChainTips, FindFork,
     * etc.). The prior implementation evicted the lowest-work entry not on the
     * active chain — which can be an INTERIOR fork node whose higher-work
     * child still points at it via pprev. Freeing it dangled the child's pprev
     * → use-after-free on the next chain walk. This version frees ONLY a leaf:
     * an entry with in-degree 0 in the pprev graph (no surviving entry names
     * it as pprev) that is also not in the pinned set.
     *
     * PINNED SET (never evicted, even if it is a leaf) — ALL FOUR CLAUSES. This
     * list used to stop after the first two, which understated what the evictor
     * refuses to touch and therefore understated the memory floor:
     *   (a) every ancestor of pindexTip (the active chain);
     *   (b) every entry in m_setBlockIndexCandidates AND all their pprev
     *       ancestors (the chain selector's activation-reachable set). Note:
     *       pindexBestHeader does NOT exist on CChainState; best-header tracking
     *       lives in the separate CHeadersManager.
     *   (c) every entry with BLOCK_HAVE_DATA but validity below
     *       BLOCK_VALID_TRANSACTIONS — defense-in-depth for a future split
     *       ingress path; no current path produces that state.
     *   (d) every hash the block-validation queue reports as pending (queued +
     *       the single in-flight block) AND their pprev ancestors — a LIVENESS
     *       pin, so a cascade cannot free a queued block's parent.
     *
     * ⚠️ CORRECTED (external panel, item 7): clause (b) previously claimed it
     * "also covers the best-header tip whenever it has a block-index entry, since
     * such a tip is a candidate". FALSE. IsBlockACandidateForActivation() requires
     * BLOCK_VALID_TRANSACTIONS and explicitly excludes BLOCK_VALID_HEADER entries,
     * so a header-only best-header tip is exactly what clause (b) does NOT pin.
     * That is correct behaviour — an un-downloaded header tip is re-obtainable by
     * PEER RE-ANNOUNCEMENT if that fork ever becomes the most-work chain — but the
     * old wording promised protection that nothing provides.
     *
     * (An earlier version of this paragraph said "re-obtainable from
     * CHeadersManager's separate unbounded mapHeaders". WRONG, and wrong against
     * an explicit warning ~20 lines below in this same file: mapHeaders is itself
     * capped and PruneOrphanedHeaders erases non-best-chain headers behind the
     * tip. Recovery-safety rests on peer re-announcement, never on a second
     * unbounded store. Caught by the non-author reader.)
     *
     * WHAT BOUNDS THE PINNED SET, since an advisory cap makes it the real memory
     * floor: every m_setBlockIndexCandidates.insert — there are exactly two, the
     * useNewPath arm of the connect path and RecomputeCandidates() — is gated by
     * IsBlockACandidateForActivation, which requires
     * >= BLOCK_VALID_TRANSACTIONS. Header spam CANNOT grow the pinned set.
     *
     * WHAT IT DOES COST, stated at the weaker true value: PoW-valid BLOCK DATA at
     * the fork point's difficulty. NOT "a fully validated block at the real
     * difficulty",
     * which is what this paragraph used to claim and which overstates the barrier
     * — MarkBlockReceived() (block_index.h) sets BLOCK_HAVE_DATA and raises
     * validity to BLOCK_VALID_TRANSACTIONS in ONE op ON RECEIPT, and the
     * connect-path insert runs before ConnectTip has ruled on the block. The
     * Two further claims that stood here are REMOVED rather than softened
     * (external panel round 3, gpt6 MEDIUM), because neither is proven by the
     * gates above and a security argument must not carry more than it shows:
     *   - "pinned only TRANSIENTLY until activation resolves the entry" — the
     *     prune in RecomputeCandidates drops strictly-LOWER-work candidates only,
     *     so equal-work alternatives persist until work advances, and
     *     RecomputeCandidates can repopulate them. Residency is not bounded by
     *     activation.
     *   - "not remotely exhaustible" — that is a conclusion about an attacker's
     *     whole budget, and the gates do not establish it.
     * WHAT THE GATES DO PROVE, and all this paragraph should be read as claiming:
     * header-only entries can NEVER pin, and pinning requires PoW-bearing block
     * data at the fork point's difficulty. Size the pinned set from that, and do
     * not inherit a stronger conclusion from this comment.
     *
     * If that gate ever admits header-only entries, the advisory cap becomes
     * remotely exhaustible and this argument has to be redone.
     *
     * (Cited BY SYMBOL. This paragraph previously gave line numbers — chain.cpp:761
     * and :3109 — which had drifted TWICE within this PR by the time a reviewer
     * read them. The chain.cpp twin of this text was corrected first and this
     * header copy was missed, which is the same leaves-siblings shape the PR keeps
     * producing; both are now symbol-cited so neither can drift again.)
     *
     * ALGORITHM — REWRITTEN, and this docstring described the OLD one until
     * round 5 caught it sitting next to the lemma that replaced it. It used to
     * say "build an in-degree map over mapBlockIndex, build the pinned set, then
     * evict"; that is the O(n)-per-call routine this PR removed, and a reader
     * would have taken the cost model from it.
     *
     * What it does NOW:
     *   1. O(1) EARLY-OUT: if mapBlockIndex.size() <= active chain length the
     *      index IS the active chain, everything is pinned by clause (a), and
     *      there is nothing to evict. Return immediately, building nothing.
     *   2. Take ONE snapshot of the pending-block hashes (not one per candidate).
     *   3. Select from m_evictableLeaves, which is maintained INCREMENTALLY at the
     *      four sites above and ordered lowest-(work, hash) first — so the victim
     *      is at begin() and selection is O(log n), not a scan.
     *   4. Pinnedness is four DIRECT tests (IsLeafPinnedDirect), never an ancestor
     *      walk: by the leaf lemma a leaf cannot be pinned transitively.
     *   5. Erase, maintain the index, repeat. A freed leaf's parent may become a
     *      leaf, and LeafIndexOnErase inserts it the moment its in-degree hits 0,
     *      so cascades still work with no rescan.
     *
     * No in-degree map and no pinned set are BUILT per call any more; both are
     * standing state. Measured effect at a 500K index: 485 ms and 43 MB of
     * transient per over-cap insert became 0.008 ms and 0 KB (CON-27).
     *
     * nChainWork comparisons use ChainWorkGreaterThan (chainWork is NOT
     * memcmp-comparable). Holds cs_main throughout.
     *
     * NOT consensus-affecting: an evicted leaf is a non-active-chain tip — never
     * the active chain, a reorg candidate, an ancestor of either, or an in-flight
     * (HAVE_DATA-not-VALID_TRANSACTIONS) block (all pinned). Recovery-safety does
     * NOT rest on "mapHeaders is unbounded" (it is not — mapHeaders is itself
     * capped and PruneOrphanedHeaders erases non-best-chain headers more than
     * ORPHAN_HEADER_EXPIRY_BLOCKS behind tip). The real basis: an evicted fork
     * tip's header is re-obtainable via PEER RE-ANNOUNCEMENT — if that fork ever
     * becomes the most-work chain, peers re-feed its headers and blocks and the
     * node re-derives the index. This matches Bitcoin Core's behaviour (a bounded
     * index converges on peer re-feed; it is not a hard split). Eviction therefore
     * never changes which chain a node ultimately accepts — it only bounds memory.
     *
     * @param target_max stop once mapBlockIndex.size() <= target_max (the
     *        caller passes cap-1 to make room for exactly one new header).
     *        target_max == 0 means "drain EVERY eligible leaf" — TEST/DIAGNOSTIC
     *        USE ONLY. LOW-c (PR #129 re-red-team): the prior signature gave this
     *        a DEFAULT ARGUMENT of 0, so a production caller that omitted the
     *        argument would silently drain the whole index. The default arg has
     *        been REMOVED — every caller must now pass an explicit target_max, so
     *        the destructive "drain all" path can only be reached by explicitly
     *        writing 0 (self-documenting). Production code always passes cap-1.
     *
     * @return true if AT LEAST ONE entry was evicted; false if nothing eligible
     *         was found.
     *
     * ⚠️ TRUE DOES NOT MEAN "REACHED target_max", AND CALLERS MUST NOT READ IT
     * THAT WAY. The value is `evicted_any`. A run that frees three leaves and is
     * still over the cap returns TRUE. A caller that wants to know whether the
     * cap was actually met must re-read GetBlockIndexSize() — not test this
     * return. That distinction is not academic: the over-cap log in
     * ChainSelectorAdapter::ProcessNewHeader was written as `if (!Evict(...))`
     * and was therefore SILENT in precisely the state it existed to report
     * (freed some, still over cap), which is the defect the external panel
     * caught. Its sibling in block_validation_queue.cpp had it right.
     *
     * ⚠️ TWO CLAIMS THAT USED TO STAND HERE WERE FALSE and are removed rather
     * than softened:
     *   - "caller falls back to fail-closed reject" — NO CALLER DOES ANY LONGER.
     *     Both production callers treat the cap as ADVISORY and proceed: refusing
     *     to extend the chain is strictly worse than exceeding a soft memory
     *     target. A doc promising fail-closed on a path that deliberately falls
     *     through is worse than no doc.
     *   - "The false case is unreachable at production cap sizes" — it is
     *     reachable, and reproducibly so. Once active height approaches the cap
     *     every entry is a pinned active-chain ancestor, so there is nothing to
     *     evict; regtest (cap 1000) reaches it by ordinary block generation and
     *     src/test/regtest_cap_rejection_tests.cpp demonstrates it. The advisory
     *     semantics exist BECAUSE this case is reachable.
     */
    bool EvictLowestWorkLeafNotPinned(size_t target_max);

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
     * Perf fix 2026-07-12: force the next GetChainTips() call to recompute.
     * mapBlockIndex insert/erase/clear already trigger this internally.
     * Call this too whenever code mutates an already-indexed CBlockIndex's
     * nStatus/pprev directly (bypassing AddBlockIndex) in a way that could
     * change a tip's reported status or membership — e.g. flagging a block
     * BLOCK_FAILED_VALID after the fact. Cheap and safe to over-call.
     */
    void InvalidateChainTipsCache() const {
        std::lock_guard<std::recursive_mutex> lock(cs_main);
        m_chainTipsCacheDirty = true;
    }

private:
    // Perf fix 2026-07-12: GetChainTips() did a full double-scan of
    // mapBlockIndex on every call (44% of sampled CPU on a DilV seed
    // whose mapBlockIndex has grown to 161K+ entries — explorer polls
    // this RPC frequently). Cache the result and invalidate it only
    // when mapBlockIndex membership or pprev topology actually changes:
    // AddBlockIndex (insert or merge-adopt-pprev), EvictLowestWorkLeafNotPinned
    // (erase), and Cleanup (clear) all flip this dirty. GetChainTips()
    // itself is the only reader/recomputer, always called under cs_main,
    // so no separate cache mutex is needed.
    mutable std::vector<ChainTip> m_chainTipsCache;
    mutable bool m_chainTipsCacheDirty{true};

public:
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

    /**
     * PR #129 MEDIUM-2: register the async validation queue's pending-block-hash
     * provider (see PendingBlockHashProvider above). At most one provider is
     * expected (the single CBlockValidationQueue); a second registration
     * replaces the first. Eviction calls it under cs_main to pin queued/in-flight
     * blocks and their ancestors. Pass an empty std::function to clear.
     *
     * @param provider returns the set of hashes the queue currently owns
     *        (queued + in-flight). Returning hashes (not raw pointers) keeps the
     *        lock order cs_main -> queue mutex clean.
     */
    void RegisterPendingBlockHashProvider(PendingBlockHashProvider provider);

    /**
     * PR #129 round-2 (external panel, kimi): is a pending-hash provider wired?
     *
     * The queue path's safety argument has three links, and the FIRST is "the
     * in-flight block's hash is pinned for the whole of ProcessBlock" — which is
     * delivered entirely by eviction clause (d) reading this provider. If nobody
     * registers one, that link is VOID and the argument silently degrades to the
     * by-hash re-resolve alone. Nothing would fail; eviction would simply stop
     * pinning queued work.
     *
     * Registration currently lives in the node wiring (dilithion-node.cpp,
     * dilv-node.cpp), NOT in CBlockValidationQueue itself, so a future wiring that
     * forgets is a silent regression. This accessor exists so the queue can assert
     * the link it depends on rather than assume it.
     */
    bool HasPendingBlockHashProvider() const {
        std::lock_guard<std::recursive_mutex> lock(cs_main);
        return static_cast<bool>(m_pendingBlockHashProvider);
    }

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
     * P2P-14/15: this no longer INVOKES the callbacks. It snapshots the tip's
     * header and hash into m_pendingTipNotifications; TipNotifyDrain fires them
     * after cs_main is released. Caller must hold cs_main (all four call sites
     * are inside ActivateBestChain, which owns the guard).
     *
     * @param pindex New chain tip — read here, never handed to a callback.
     */
    void NotifyTipUpdate(const CBlockIndex* pindex);

    /**
     * P2P-14/15: fire the pending tip notifications with cs_main NOT held.
     *
     * Declare a TipNotifyDrain BEFORE the cs_main lock_guard in any scope that
     * calls NotifyTipUpdate. C++ destroys locals in reverse declaration order,
     * so the drain runs AFTER the guard has released the mutex.
     *
     * WHY THAT IS SUFFICIENT HERE, and what would break it (measured 2026-09-07,
     * f47b9b24) — cs_main is a RECURSIVE mutex, so "the guard ended" does not by
     * itself mean "the mutex is free". It is free here because:
     *   - cs_main is PRIVATE (chain.h, `private:` section), so no external caller
     *     can hold it. Every ActivateBestChain caller measured [held: -]:
     *     block_processing.cpp:945/:1468, block_validation_queue.cpp:402,
     *     fork_manager.cpp:722, chain_selector_impl.cpp:213.
     *   - No CChainState method calls ActivateBestChain, so it never nests.
     *
     * IF EITHER CEASES TO BE TRUE — cs_main is exposed, or ActivateBestChain
     * becomes reachable from another CChainState method — this drain fires with
     * cs_main still held by an outer frame, the fix silently becomes a no-op, and
     * the deadlock returns while every test still passes. Re-check both before
     * changing either.
     */
    void DrainTipNotifications();

    /** RAII: drains pending tip notifications when it goes out of scope. */
    class TipNotifyDrain {
    public:
        explicit TipNotifyDrain(CChainState& chainstate) : m_chainstate(chainstate) {}
        ~TipNotifyDrain() {
            // Destructors are implicitly noexcept, so ANY exception escaping
            // here calls std::terminate and kills the node. DrainTipNotifications
            // catches what the callbacks throw, but not what its own lock
            // acquisition or vector allocation can throw. Killing a node over a
            // notification-bookkeeping failure would be a far worse outcome than
            // the failure itself. (Red-team M-4.)
            try {
                m_chainstate.DrainTipNotifications();
            } catch (...) {
                // Deliberately swallowed: see above. Not silent — the drain
                // logs per-callback failures itself.
            }
        }
        TipNotifyDrain(const TipNotifyDrain&) = delete;
        TipNotifyDrain& operator=(const TipNotifyDrain&) = delete;
    private:
        CChainState& m_chainstate;
    };
};

#endif // DILITHION_CONSENSUS_CHAIN_H
