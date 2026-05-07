// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <consensus/chain.h>
#include <consensus/pow.h>
#include <consensus/reorg_wal.h>  // P1-4: WAL for atomic reorgs
#include <consensus/validation.h> // BUG #109 FIX: DeserializeBlockTransactions
#include <consensus/vdf_validation.h> // CheckVDFCooldown, CheckConsecutiveMiner
#include <vdf/cooldown_tracker.h>  // CCooldownTracker full definition
#include <core/chainparams.h>     // MAINNET: Checkpoint validation
#include <core/node_context.h>    // g_node_context.cooldown_tracker
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <node/mempool.h>         // BUG #109 FIX: RemoveConfirmedTxs
#include <dfmp/identity_db.h>     // Identity undo during reorg
#include <dfmp/mik.h>             // MIK parsing for identity undo
#include <util/assert.h>
#include <util/logging.h>
#include <iostream>
#include <algorithm>
#include <cstring>      // std::strcmp (env-var check)
#include <mutex>        // std::once_flag (chain selector path startup log)
#include <set>
#include <thread>
#include <chrono>

CChainState::CChainState() : pindexTip(nullptr), pdb(nullptr), pUTXOSet(nullptr) {
}

CChainState::~CChainState() {
    Cleanup();
}

// P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
bool CChainState::InitializeWAL(const std::string& dataDir) {
    m_reorgWAL = std::make_unique<CReorgWAL>(dataDir);

    if (m_reorgWAL->HasIncompleteReorg()) {
        std::cerr << "[Chain] CRITICAL: Incomplete reorganization detected!" << std::endl;
        std::cerr << "[Chain] " << m_reorgWAL->GetIncompleteReorgInfo() << std::endl;
        std::cerr << "[Chain] The database may be in an inconsistent state." << std::endl;
        std::cerr << "[Chain] Please restart with -reindex to rebuild the blockchain." << std::endl;
        m_requiresReindex = true;
        return false;
    }

    return true;
}

bool CChainState::RequiresReindex() const {
    return m_requiresReindex;
}

void CChainState::Cleanup() {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // Phase 5: clear candidate set BEFORE freeing the underlying CBlockIndex
    // objects in mapBlockIndex. The set holds non-owning raw pointers; if
    // mapBlockIndex is cleared first, the set's destructor / further accesses
    // would dereference dangling pointers via the comparator.
    m_setBlockIndexCandidates.clear();

    // Phase 5 red-team CONCERN fix: drop registered callbacks too. External
    // components (HeadersManager, wallet) hold std::function<>s captured
    // with raw const CBlockIndex* pointers from prior callback invocations.
    // After Cleanup the underlying CBlockIndex objects are destroyed; firing
    // a stale callback after Cleanup would be use-after-free. The Shutdown
    // sequence in node_context.cpp resets HeadersManager BEFORE chainstate
    // tears down — but defense-in-depth says clear them anyway.
    m_tipCallbacks.clear();
    m_blockConnectCallbacks.clear();
    m_blockDisconnectCallbacks.clear();

    // HIGH-C001 FIX: Smart pointers automatically destruct when map is cleared
    // No need for manual delete - RAII handles cleanup
    mapBlockIndex.clear();
    pindexTip = nullptr;
    // BUG #74 FIX: Reset atomic cached height
    m_cachedHeight.store(-1, std::memory_order_release);
}

bool CChainState::AddBlockIndex(const uint256& hash, std::unique_ptr<CBlockIndex> pindex) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // HIGH-C001 FIX: Accept unique_ptr for automatic ownership transfer
    if (pindex == nullptr) {
        return false;
    }

    // Invariant: Hash must match block index hash
    Invariant(pindex->GetBlockHash() == hash);

    // Phase 11 ABI flag-merge: when an entry for this hash already exists
    // (normal during the headers-sync → block-data sequence on the new
    // peer manager / chain selector path), MERGE the new entry's nStatus
    // bits into the existing entry rather than silently dropping the new
    // call. The pre-fix behaviour was a silent return-false on duplicate
    // (chain.cpp:96-98 in v4.1), which left header-prepopulated entries
    // stuck at BLOCK_VALID_HEADER and prevented HaveData() from ever
    // becoming true — chain stayed at genesis on a fresh datadir running
    // with chain_selector enabled (SYD mainnet 2026-05-02).
    //
    // Merge semantics (mirrors Bitcoin Core's BlockManager::AddToBlockIndex
    // accumulating-flags model):
    //   - nStatus: existing |= incoming (monotonic, never loses a flag)
    //   - pprev:   if existing was null and incoming has a parent, adopt it
    //   - Topology disagreement (different parent / height / chain work)
    //     is a programming bug → ConsensusInvariant trip.
    //
    // The function returns true on the merge path. The incoming `pindex`
    // is dropped (its unique_ptr destructor runs at function exit).
    auto existing_it = mapBlockIndex.find(hash);
    if (existing_it != mapBlockIndex.end()) {
        CBlockIndex* existing = existing_it->second.get();
        ConsensusInvariant(existing != nullptr);

        // Topology must agree across the two CBlockIndex constructions.
        // Both calls compute height/chainwork from the same header chain,
        // so disagreement = bug, not a benign race.
        ConsensusInvariant(existing->nHeight == pindex->nHeight);
        ConsensusInvariant(existing->nChainWork == pindex->nChainWork);

        // Parent linkage: at least one of the two must agree, and if both
        // are present they must point to the same prev hash. Adoption of
        // a previously-null pprev is allowed (the second caller may know
        // the parent even if the first caller did not).
        if (existing->pprev != nullptr && pindex->pprev != nullptr) {
            ConsensusInvariant(existing->pprev->GetBlockHash() == pindex->pprev->GetBlockHash());
        } else if (existing->pprev == nullptr && pindex->pprev != nullptr) {
            // First caller did not know the parent; second caller does.
            // Adopt the new linkage. Validate the parent really is in the
            // map (same invariant the first-time-add path checks below).
            uint256 parentHash = pindex->pprev->GetBlockHash();
            ConsensusInvariant(mapBlockIndex.count(parentHash) > 0);
            existing->pprev = pindex->pprev;
        }
        // (existing->pprev != nullptr && pindex->pprev == nullptr): keep
        // existing linkage. The incoming entry simply lacks information
        // the existing entry already has.

        // The load-bearing line: monotonic flag accumulation. BLOCK_VALID_*
        // and BLOCK_HAVE_* and BLOCK_FAILED_* all OR cleanly. Idempotent
        // on identical-flag re-adds.
        existing->nStatus |= pindex->nStatus;

        return true;
    }

    // First-time add — original semantics from here on.

    // Consensus invariant: If block has parent, parent must exist in map
    if (pindex->pprev != nullptr) {
        uint256 parentHash = pindex->pprev->GetBlockHash();
        ConsensusInvariant(mapBlockIndex.count(parentHash) > 0);

        // Consensus invariant: Height must be parent height + 1
        ConsensusInvariant(pindex->nHeight == pindex->pprev->nHeight + 1);
    } else {
        // Genesis block must be at height 0
        ConsensusInvariant(pindex->nHeight == 0);
    }

    // Transfer ownership to map using move semantics
    mapBlockIndex[hash] = std::move(pindex);
    return true;
}

CBlockIndex* CChainState::GetBlockIndex(const uint256& hash) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // HIGH-C001 FIX: Return raw pointer (non-owning) via .get()
    auto it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end()) {
        return it->second.get();  // Extract raw pointer from unique_ptr
    }
    return nullptr;
}

bool CChainState::HasBlockIndex(const uint256& hash) const {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    return mapBlockIndex.count(hash) > 0;
}

// Phase 6 PR6.1 (v1.5 §3.2 + Cursor v1.5+ A1): cap-eviction policy.
// Evicts lowest-work entry NOT on the active chain.
bool CChainState::EvictLowestWorkNotOnBestChain() {
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    if (mapBlockIndex.empty()) return false;

    // Build a set of active-chain hashes by walking pindexTip → genesis.
    // O(active_chain_height); cheap relative to map walk below.
    std::set<uint256> active_chain_hashes;
    for (CBlockIndex* p = pindexTip; p != nullptr; p = p->pprev) {
        active_chain_hashes.insert(p->GetBlockHash());
    }

    // Find the entry with minimum nChainWork that is NOT on the active
    // chain. Use ChainWorkGreaterThan (from consensus/pow.h) — chainWork
    // stored in uint256 doesn't have a memcmp-compatible byte ordering;
    // raw memcmp gives wrong magnitude comparison.
    CBlockIndex* worst = nullptr;
    uint256      worst_work;
    bool         worst_set = false;
    for (auto& kv : mapBlockIndex) {
        CBlockIndex* p = kv.second.get();
        if (!p) continue;
        if (active_chain_hashes.count(kv.first) > 0) continue;  // skip active
        // We want minimum: p < worst means p has LESS work than current worst.
        // ChainWorkGreaterThan(a, b) = a > b. So p has less work iff
        // ChainWorkGreaterThan(worst_work, p->nChainWork) is true
        // (worst_work > p means p < worst_work, so p is lower-work).
        if (!worst_set || ChainWorkGreaterThan(worst_work, p->nChainWork)) {
            worst = p;
            worst_work = p->nChainWork;
            worst_set = true;
        }
    }

    if (!worst_set) {
        // All entries are on the active chain. At production cap sizes
        // (DIL=500K vs ~24K chain height) this is unreachable; if it
        // happens, caller falls back to fail-closed.
        return false;
    }

    // Remove from m_setBlockIndexCandidates if present (avoid dangling
    // pointer in the candidate set).
    m_setBlockIndexCandidates.erase(worst);

    // Erase from mapBlockIndex. unique_ptr cleanup destroys CBlockIndex.
    uint256 worst_hash = worst->GetBlockHash();
    mapBlockIndex.erase(worst_hash);

    return true;
}

CBlockIndex* CChainState::FindFork(CBlockIndex* pindex1, CBlockIndex* pindex2) {
    // Find the last common ancestor between two chains
    // This is used to determine where chains diverge

    if (pindex1 == nullptr || pindex2 == nullptr) {
        return nullptr;
    }

    // Walk both chains back to same height
    while (pindex1->nHeight > pindex2->nHeight) {
        pindex1 = pindex1->pprev;
        if (pindex1 == nullptr) return nullptr;
    }

    while (pindex2->nHeight > pindex1->nHeight) {
        pindex2 = pindex2->pprev;
        if (pindex2 == nullptr) return nullptr;
    }

    // Now both at same height, walk back until we find common block
    while (pindex1 != pindex2) {
        pindex1 = pindex1->pprev;
        pindex2 = pindex2->pprev;

        if (pindex1 == nullptr || pindex2 == nullptr) {
            return nullptr;
        }
    }

    return pindex1;  // Common ancestor
}

// ---------------------------------------------------------------------------
// VDF Distribution: ShouldReplaceVDFTip
// ---------------------------------------------------------------------------

bool CChainState::ShouldReplaceVDFTip(CBlockIndex* pindexNew, const CBlock* pblockNew) const
{
    // Must have chain params with distribution enabled
    if (!Dilithion::g_chainParams) return false;
    if (pindexNew->nHeight < Dilithion::g_chainParams->vdfLotteryActivationHeight) return false;

    // Both blocks must be VDF (version >= 4)
    if (pindexNew->nVersion < 4 || pindexTip->nVersion < 4) return false;

    // Must be at same height with same parent (sibling blocks)
    if (pindexNew->nHeight != pindexTip->nHeight) return false;
    if (pindexNew->pprev != pindexTip->pprev) return false;

    // Compare vdfOutput using HashLessThan (big-endian, consensus-safe)
    // CRITICAL: Do NOT use uint256::operator< — it's little-endian (memcmp)
    // and only suitable for STL containers, not consensus comparisons.
    const uint256& newOutput = pindexNew->header.vdfOutput;
    const uint256& tipOutput = pindexTip->header.vdfOutput;

    if (newOutput.IsNull() || tipOutput.IsNull()) return false;
    if (!HashLessThan(newOutput, tipOutput)) return false;

    // Grace period check
    if (m_vdfTipAcceptHeight != pindexTip->nHeight) return false;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_vdfTipAcceptTime).count();
    int gracePeriod = Dilithion::g_chainParams->vdfLotteryGracePeriod;

    if (elapsed > gracePeriod) return false;

    // Option C preflight: if we have block data, validate cooldown against
    // simulated post-replacement tracker state before mutating chain state.
    if (pblockNew != nullptr) {
        std::string preflightErr;
        if (g_node_context.cooldown_tracker &&
            !CheckVDFReplacementPreflight(*pblockNew, pindexNew, pindexTip, pdb, pindexNew->nHeight,
                                          *g_node_context.cooldown_tracker, preflightErr)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[VDF Distribution] Replacement preflight rejected: " << preflightErr << std::endl;
            return false;
        }
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[VDF Distribution] Lower output wins -- replacing tip (grace: "
                  << (gracePeriod - elapsed) << "s remaining)" << std::endl;

    return true;
}

// v4.3.3 F10 + F15 (Layer-3 round 3 HIGH-1): VDF grace-period anchor with
// first-arrival-only predicate. Called from the port-path connect-loop in
// ActivateBestChainStep. See doc in chain.h for full rationale.
bool CChainState::MaybeAnchorVdfGrace(CBlockIndex* p) {
    if (p == nullptr) return false;
    if (p->nVersion < 4) return false;
    if (!Dilithion::g_chainParams) return false;
    if (p->nHeight < Dilithion::g_chainParams->vdfLotteryActivationHeight) return false;
    // F15 first-arrival-only check: legacy Case 2.5 explicitly does NOT
    // reset m_vdfTipAcceptTime on sibling replacement at same height
    // (chain.cpp:723 comment: "Do NOT reset ... preventing infinite
    // replacement chains"). The port path's connect-loop iterates per
    // block; we anchor only when arriving at a height we have not yet
    // anchored at.
    if (p->nHeight == m_vdfTipAcceptHeight) return false;
    m_vdfTipAcceptTime = std::chrono::steady_clock::now();
    m_vdfTipAcceptHeight = p->nHeight;
    return true;
}

bool CChainState::ActivateBestChain(CBlockIndex* pindexNew, const CBlock& block, bool& reorgOccurred) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    // This protects pindexTip, mapBlockIndex, and all chain operations
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    reorgOccurred = false;

    if (pindexNew == nullptr) {
        std::cerr << "[Chain] ERROR: ActivateBestChain called with nullptr" << std::endl;
        return false;
    }

    // ============================================================
    // v4.1 — Three-tier checkpoint enforcement on legacy ABC path
    // ============================================================
    // Mirrors the new chain selector path's ancestry walk (chain.cpp:~390)
    // for the legacy path, with a graduated cost structure:
    //
    //   Tier 1 (always, O(1)): single-block check at activation height
    //   Tier 2 (always, O(log n)): re-verify highest checkpoint ancestor
    //          when pindexNew's tip is past the highest embedded checkpoint
    //   Tier 3 (reorg-only, O(checkpoints * log n)): full ancestry walk on
    //          multi-block activation (pindexNew->pprev != pindexTip)
    //
    // Tier 1 + Tier 2 always run, ~O(log n) per block under cs_main.
    // Tier 3 fires only on actual reorgs / IBD catchup / startup. Closes
    // the v0.2 IBD Case 2 sparse-checkpoint gap (Cursor F1) without
    // sacrificing the Case 2 single-extend hot path (Layer-2 CRIT-3).
    //
    // Defense-in-depth note: this works in concert with §3.3 header-time
    // CheckpointCheckHeader and §3.4 startup_checkpoint_validator;
    // architecturally either path alone suffices, but the redundancy
    // catches single-layer bugs.
    if (Dilithion::g_chainParams) {
        // Tier 1: single-block check at activation height.
        if (!Dilithion::g_chainParams->CheckpointCheck(pindexNew->nHeight, pindexNew->GetBlockHash())) {
            std::cerr << "[Chain] ERROR: Block at activation height does not match checkpoint!\n"
                      << "  Height: " << pindexNew->nHeight << "\n"
                      << "  Hash:   " << pindexNew->GetBlockHash().GetHex() << "\n"
                      << "  This may indicate an attack, corrupted block data, or a chain on the wrong fork.\n"
                      << "  Run: dilv-node --reset-chain --yes && dilv-node --rescan" << std::endl;
            return false;
        }

        // Tier 2: re-verify the highest checkpoint ancestor on every
        // activation past it. Catches sparse-checkpoint IBD Case 2 where
        // a wrong-fork chain's 44233 ancestor would not be re-verified
        // when activating subsequent blocks (44234, 44235, ...) that
        // themselves have no per-height checkpoint.
        int highestCheckpointHeight = -1;
        const Dilithion::CCheckpoint* highest = nullptr;
        for (const auto& cp : Dilithion::g_chainParams->checkpoints) {
            if (cp.nHeight > highestCheckpointHeight) {
                highestCheckpointHeight = cp.nHeight;
                highest = &cp;
            }
        }
        if (highest && pindexNew->nHeight > highestCheckpointHeight) {
            const CBlockIndex* anc = pindexNew->GetAncestor(highestCheckpointHeight);
            if (!anc || anc->GetBlockHash() != highest->hashBlock) {
                std::cerr << "[Chain] ERROR: Activation tip's ancestor at highest checkpoint violates expected hash\n"
                          << "  Checkpoint height:  " << highestCheckpointHeight << "\n"
                          << "  Expected hash:      " << highest->hashBlock.GetHex() << "\n"
                          << "  Got hash:           " << (anc ? anc->GetBlockHash().GetHex() : std::string("(null)")) << "\n"
                          << "  Tip being activated: height " << pindexNew->nHeight
                          << " hash " << pindexNew->GetBlockHash().GetHex() << "\n"
                          << "  Run: dilv-node --reset-chain --yes && dilv-node --rescan" << std::endl;
                return false;
            }
        }

        // Tier 3: full ancestry walk on multi-block activation only.
        // Skipped on Case 2 single-extend hot path. Catches deep reorgs
        // landing on a tip whose ancestry violates ANY checkpoint.
        const bool isMultiBlockActivation =
            (pindexTip == nullptr) || (pindexNew->pprev != pindexTip);
        if (isMultiBlockActivation) {
            for (const auto& cp : Dilithion::g_chainParams->checkpoints) {
                if (cp.nHeight > pindexNew->nHeight) continue;
                if (cp.nHeight == pindexNew->nHeight) continue;  // covered by Tier 1
                if (highest && cp.nHeight == highest->nHeight) continue;  // covered by Tier 2
                const CBlockIndex* ancestor = pindexNew->GetAncestor(cp.nHeight);
                if (!ancestor) {
                    std::cerr << "[Chain] ERROR: Cannot resolve ancestor at checkpoint height "
                              << cp.nHeight << " (chain truncated/corrupted)\n"
                              << "  Run: dilv-node --reset-chain --yes && dilv-node --rescan" << std::endl;
                    return false;
                }
                if (ancestor->GetBlockHash() != cp.hashBlock) {
                    std::cerr << "[Chain] ERROR: Checkpoint violation in candidate ancestry\n"
                              << "  Checkpoint height:  " << cp.nHeight << "\n"
                              << "  Expected hash:      " << cp.hashBlock.GetHex() << "\n"
                              << "  Got hash:           " << ancestor->GetBlockHash().GetHex() << "\n"
                              << "  Tip being activated: height " << pindexNew->nHeight
                              << " hash " << pindexNew->GetBlockHash().GetHex() << "\n"
                              << "  Run: dilv-node --reset-chain --yes && dilv-node --rescan" << std::endl;
                    return false;
                }
            }
        }
    }

    // ============================================================
    // Phase 5 PR5.3: env-var-gated dispatch to new chain-selection path.
    // ============================================================
    //
    // DILITHION_USE_NEW_CHAIN_SELECTOR:
    //   "1"          -> new path (FindMostWorkChainImpl + ActivateBestChainStep)
    //   "0" or unset -> legacy Cases 1/2/2.5/3 below (default OFF in PR5.3)
    //
    // PR5.4 flips the default to ON. Until then the legacy body remains
    // the production code path and is preserved verbatim — env-var=0 is
    // exactly the pre-Phase-5 behavior. Env-var=1 opt-in lets operators
    // exercise the new path during the burn-in window.
    {
        // Phase 5: read env-var per call. Block-receive rate is ~one per 4
        // minutes (DIL block spacing) — getenv overhead is negligible.
        //
        // Red-team audit 2026-04-26 BLOCKER #2: PR5.4's original default flip
        // (unset → new path) would silently switch every existing seed node
        // to the new selection logic on next restart with only a 30-second
        // regtest as evidence. During rolling restart, mainnet would have
        // heterogeneous selection logic across seeds — partition risk if any
        // divergence on a real reorg.
        //
        // Reverted to OPT-IN: operators must explicitly set "=1" to engage
        // the new path. Default (unset or any other value) routes to legacy
        // Cases 1/2/2.5/3 (Patch B retained — see PR5.4 status note below).
        // The default flip waits for real-network burn-in evidence after V2
        // proves byte-equivalence at multi-block depth.
        //
        // PR5.4 STATUS: with the env-var default REVERTED, the legacy path
        // is the production path. Patch B was DELETED in PR5.4 — meaning the
        // legacy path now sets m_chain_needs_rebuild on Case 2.5 ConnectTip
        // failure rather than re-applying the old tip in place. This is a
        // stricter failure mode than pre-PR5.4 (operator-consent recovery
        // via wrapper-restart) but produces the same end-state on success.
        const char* envVar = std::getenv("DILITHION_USE_NEW_CHAIN_SELECTOR");
        const bool useNewPath = (envVar && std::strcmp(envVar, "1") == 0);

        // Startup log on FIRST ActivateBestChain call — operator audit
        // visibility (red-team validation 2026-04-26 recommended item).
        // Static once-per-process so we don't spam every block.
        static std::once_flag pathLoggedFlag;
        std::call_once(pathLoggedFlag, [useNewPath]() {
            std::cerr << "[Chain] selection path: "
                      << (useNewPath ? "NEW (env-var=1 OPT-IN)"
                                     : "LEGACY (Cases 1/2/2.5/3, default)")
                      << std::endl;
        });

        if (useNewPath) {
            // Make sure pindexNew is in the candidate set if eligible. The
            // new path picks the heaviest leaf via FindMostWorkChainImpl.
            if (IsBlockACandidateForActivation(pindexNew)) {
                m_setBlockIndexCandidates.insert(pindexNew);
            }

            std::shared_ptr<const CBlock> pblockShared =
                std::make_shared<const CBlock>(block);

            // Capture old tip BEFORE the loop — reorgOccurred is "did the
            // tip move?" relative to entry, not relative to any
            // intermediate state.
            CBlockIndex* pindexOldTip = pindexTip;

            // Activation loop: try to activate the heaviest valid leaf;
            // if a ConnectTip fails (fInvalidFound), the failed leaf has
            // been marked + dropped, so we retry with the next-best.
            while (true) {
                CBlockIndex* pindexMostWork = FindMostWorkChainImpl();
                if (!pindexMostWork) break;
                if (pindexMostWork == pindexTip) break;  // already at best

                // v4.3.1: defense-in-depth chainwork gate. ONLY skip reorg
                // when current tip has STRICTLY GREATER work than the
                // candidate. Equal-work activation is LEGITIMATE under DilV
                // VDF distribution / Case 2.5 tiebreak semantics and must
                // NOT be blocked. The condition is `tip > candidate` (strict),
                // NOT `!greater(candidate, tip)` which would also fire on
                // equal-work and break legitimate reorgs.
                //
                // Cheap insurance against any future regression in the
                // candidate-set seeding (Fix 1 in this same change): if a
                // single-element candidate set ever surfaces a less-work
                // leaf, this gate prevents the disconnect-then-fail sequence
                // that caused the LDN tip-going-backwards deadlock 2026-05-04.
                if (pindexTip && ChainWorkGreaterThan(pindexTip->nChainWork,
                                                     pindexMostWork->nChainWork)) {
                    break;
                }

                // v4.3.3 F10 (companion to F9 — VDF tiebreak grace-period gate).
                // F9's comparator picks the lower-vdfOutput sibling on equal
                // chainwork. F10 stops VDF replacement once the grace window
                // has expired. Mirrors legacy ShouldReplaceVDFTip's grace-
                // period check (chain.cpp:300-309). Without F10, the port
                // path would flap indefinitely as later vdfOutputs propagate,
                // even when the network has settled on a tip at this height.
                //
                // Conditions for the gate to fire:
                //   * Both tip and candidate have non-null vdfOutput
                //     (skips DIL chain and pre-VDF DilV blocks).
                //   * Same height + same parent (a sibling).
                //   * Equal chainwork (chainwork-greater-than is the
                //     primary path; equal-work is the tiebreak case).
                //   * m_vdfTipAcceptHeight matches current tip height
                //     (timestamp was anchored at this height).
                //   * Elapsed > vdfLotteryGracePeriod.
                // When all conditions hold: KEEP current tip; do NOT replace.
                if (pindexTip != nullptr &&
                    Dilithion::g_chainParams &&
                    pindexMostWork->nHeight == pindexTip->nHeight &&
                    pindexMostWork->pprev == pindexTip->pprev &&
                    !pindexMostWork->header.vdfOutput.IsNull() &&
                    !pindexTip->header.vdfOutput.IsNull() &&
                    !ChainWorkGreaterThan(pindexMostWork->nChainWork,
                                          pindexTip->nChainWork) &&
                    !ChainWorkGreaterThan(pindexTip->nChainWork,
                                          pindexMostWork->nChainWork) &&
                    m_vdfTipAcceptHeight == pindexTip->nHeight) {
                    const auto now = std::chrono::steady_clock::now();
                    const auto elapsed =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            now - m_vdfTipAcceptTime).count();
                    if (elapsed > Dilithion::g_chainParams->vdfLotteryGracePeriod) {
                        // Grace expired. Keep current tip despite F9's
                        // "lower vdfOutput wins" ordering. The candidate
                        // stays in m_setBlockIndexCandidates — future
                        // chainwork-greater arrivals can still reorg.
                        break;
                    }
                }

                // Phase 5 BLOCKER 3 fix (red-team audit 2026-04-26):
                // checkpoint validation must cover the FULL ancestry from
                // the current tip up to pindexMostWork, not just the
                // single-block pindexNew. The legacy path activates one
                // block at a time so its top-of-function CheckpointCheck
                // is sufficient there. The new path's reorg loop can
                // activate a leaf many blocks ahead of the current tip;
                // any intermediate ancestor that violates a checkpoint
                // would otherwise slip through.
                if (Dilithion::g_chainParams) {
                    CBlockIndex* pindexFork = pindexTip
                        ? FindFork(pindexTip, pindexMostWork) : nullptr;
                    bool checkpointViolated = false;
                    CBlockIndex* violatingBlock = nullptr;
                    for (CBlockIndex* p = pindexMostWork;
                         p && p != pindexFork;
                         p = p->pprev) {
                        if (!Dilithion::g_chainParams->CheckpointCheck(
                                p->nHeight, p->GetBlockHash())) {
                            checkpointViolated = true;
                            violatingBlock = p;
                            break;
                        }
                    }
                    if (checkpointViolated) {
                        std::cerr << "[Chain] Checkpoint violation in candidate"
                                  << " ancestry at height " << violatingBlock->nHeight
                                  << " hash=" << violatingBlock->GetBlockHash().GetHex().substr(0, 16)
                                  << "... — marking subtree failed" << std::endl;
                        MarkBlockAsFailed(violatingBlock);
                        continue;  // retry with next-best leaf
                    }
                }

                bool fInvalidFound = false;
                if (!ActivateBestChainStep(pindexMostWork, pblockShared, fInvalidFound)) {
                    // Hard failure — abort entirely.
                    return false;
                }
                if (fInvalidFound) {
                    // The leaf was marked failed; loop to try next-best.
                    continue;
                }
                // Activation succeeded — break and report.
                break;
            }

            reorgOccurred = (pindexTip != pindexOldTip);
            if (pindexTip) {
                NotifyTipUpdate(pindexTip);
            }
            return true;
        }
        // Else: fall through to the legacy path preserved below.
    }

    // Case 1: Genesis block (first block in chain)
    if (pindexTip == nullptr) {

        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] ERROR: Failed to connect genesis block" << std::endl;
            return false;
        }

        pindexTip = pindexNew;
        // BUG #74 FIX: Update atomic cached height
        m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

        // Persist to database
        if (pdb != nullptr) {
            pdb->WriteBestBlock(pindexNew->GetBlockHash());
        }

        return true;
    }

    // Case 2: Extends current tip (simple case - no reorg needed)
    if (pindexNew->pprev == pindexTip) {

        // Compare chain work to be safe (should always be greater if extending tip)
        if (!ChainWorkGreaterThan(pindexNew->nChainWork, pindexTip->nChainWork)) {
            std::cerr << "[Chain] WARNING: Block extends tip but doesn't increase chain work" << std::endl;
            std::cerr << "  Current work: " << pindexTip->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
            std::cerr << "  New work:     " << pindexNew->nChainWork.GetHex().substr(0, 16) << "..." << std::endl;
            return false;
        }

        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] ERROR: Failed to connect block extending tip" << std::endl;
            return false;
        }

        pindexTip = pindexNew;
        // BUG #74 FIX: Update atomic cached height
        m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

        // VDF Distribution: Record when this height's first VDF block was accepted.
        // This starts the grace period clock. Only set here (Case 2), not in
        // Case 2.5 (distribution replacement), to anchor the deadline to the first arrival.
        if (pindexNew->nVersion >= 4 &&
            Dilithion::g_chainParams &&
            pindexNew->nHeight >= Dilithion::g_chainParams->vdfLotteryActivationHeight) {
            m_vdfTipAcceptTime = std::chrono::steady_clock::now();
            m_vdfTipAcceptHeight = pindexNew->nHeight;
        }

        // Persist to database
        if (pdb != nullptr) {
            bool success = pdb->WriteBestBlock(pindexNew->GetBlockHash());
        } else {
            std::cerr << "[Chain] ERROR: pdb is nullptr! Cannot write best block!" << std::endl;
        }

        // Bug #40 fix: Notify registered callbacks of tip update
        NotifyTipUpdate(pindexTip);

        return true;
    }

    // Case 2.5: VDF Distribution — competing VDF block at same height with lower output
    if (ShouldReplaceVDFTip(pindexNew, &block)) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[Chain] VDF DISTRIBUTION REPLACEMENT -- 1-block reorg" << std::endl;

        // PR5.4 (2026-04-26): Patch B (v4.0.21 rollback safety net) DELETED.
        //
        // Phase 5 byte-equivalence proof (commit ff1947c) demonstrated that the
        // new chain-selector path's symmetric-reapply failure handling produces
        // byte-identical on-disk state to legacy Case 2.5 + Patch B. The new
        // path is now the default (env-var unset → useNewPath=true); legacy
        // path remains under env-var=0 for operator rollback during burn-in.
        //
        // On Case 2.5 ConnectTip failure WITHOUT Patch B: m_chain_needs_rebuild
        // is set and the caller (IBDCoordinator) writes the auto_rebuild marker.
        // The wrapper script wipes the datadir and re-syncs. This is the
        // architecturally-clean failure mode (operator-consent path preserved
        // per plan §5.5) — Patch B's in-place rollback was a 2026-04-25
        // incident-response hotfix; the new path's structure makes it
        // unnecessary.

        // Disconnect current tip
        if (!DisconnectTip(pindexTip)) {
            std::cerr << "[Chain] ERROR: Failed to disconnect tip for VDF replacement" << std::endl;
            return false;
        }

        // Connect new block (shares same parent as old tip)
        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[CRITICAL] Case 2.5 ConnectTip failed. "
                      << "Triggering auto_rebuild (no in-place rollback — Patch B retired in PR5.4)."
                      << std::endl;
            // v4.3.3 F16: Case 2.5 ConnectTip failure → ConnectTipFailure cause.
            FlagChainRebuild(ChainRebuildReason::ConnectTipFailure);
            return false;
        }

        pindexTip = pindexNew;
        m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

        // Do NOT reset m_vdfTipAcceptTime — the grace window is anchored to
        // the FIRST block at this height, preventing infinite replacement chains.

        if (pdb != nullptr) {
            pdb->WriteBestBlock(pindexNew->GetBlockHash());
        }

        reorgOccurred = true;
        NotifyTipUpdate(pindexTip);

        return true;
    }

    // Case 3: Competing chain - need to compare chain work
    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "  Current tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexTip->nHeight << ")" << std::endl;
        std::cout << "  New block:   " << pindexNew->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexNew->nHeight << ")" << std::endl;
    }

    // Compare chain work
    if (!ChainWorkGreaterThan(pindexNew->nChainWork, pindexTip->nChainWork)) {
        // Case 3b: VDF Distribution tiebreaker for equal-work forks
        // When two VDF chains at the same height have equal chainwork,
        // the chain tip with the LOWER VDF output wins.
        // This is how divergent VDF forks converge — without this,
        // equal-work VDF forks never resolve (first-to-arrive always wins).
        bool vdfTiebreak = false;
        if (Dilithion::g_chainParams &&
            pindexNew->nHeight >= Dilithion::g_chainParams->vdfLotteryActivationHeight &&
            pindexNew->nHeight == pindexTip->nHeight &&
            pindexNew->nVersion >= 4 && pindexTip->nVersion >= 4) {

            const uint256& newOutput = pindexNew->header.vdfOutput;
            const uint256& tipOutput = pindexTip->header.vdfOutput;

            if (!newOutput.IsNull() && !tipOutput.IsNull() &&
                HashLessThan(newOutput, tipOutput)) {

                // Grace period check — only allow tiebreak within window
                // For fork convergence, use the current time minus a generous window
                // since we may not have accept time for a fork tip from a different chain
                bool withinGrace = true;
                if (m_vdfTipAcceptHeight == pindexTip->nHeight) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - m_vdfTipAcceptTime).count();
                    int gracePeriod = Dilithion::g_chainParams->vdfLotteryGracePeriod;
                    if (elapsed > gracePeriod) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[VDF Distribution] Fork tiebreak: lower output but grace expired ("
                                      << elapsed << "s > " << gracePeriod << "s)" << std::endl;
                        withinGrace = false;
                    }
                }

                if (withinGrace) {
                    std::string preflightErr;
                    if (g_node_context.cooldown_tracker &&
                        !CheckVDFReplacementPreflight(block, pindexNew, pindexTip, pdb, pindexNew->nHeight,
                                                      *g_node_context.cooldown_tracker, preflightErr)) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[VDF Distribution] Fork tiebreak preflight rejected: "
                                      << preflightErr << std::endl;
                        withinGrace = false;
                    }
                }

                if (withinGrace) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[VDF Distribution] FORK TIEBREAK -- equal work, lower VDF output wins!" << std::endl;
                    vdfTiebreak = true;
                }
            }
        }

        if (!vdfTiebreak) {
            // Block is valid but not on best chain - it's an orphan
            return true;  // Not an error - block is valid, just not best chain
        }
        // Fall through to reorg logic below (vdfTiebreak == true)
    }

    // New chain wins - REORGANIZATION REQUIRED (either more work or VDF tiebreak)
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[Chain] REORGANIZING to better chain at height " << pindexNew->nHeight << std::endl;

    // Find fork point
    CBlockIndex* pindexFork = FindFork(pindexTip, pindexNew);
    if (pindexFork == nullptr) {
        std::cerr << "[Chain] ERROR: Cannot find fork point between chains" << std::endl;
        return false;
    }


    // VULN-008 FIX: Protect against excessively deep reorganizations
    // CID 1675248 FIX: Use int64_t to prevent overflow when computing reorg depth
    // and add validation to ensure reorg_depth is non-negative
    static const int64_t MAX_REORG_DEPTH = 100;  // Similar to Bitcoin's practical limit
    int64_t reorg_depth = static_cast<int64_t>(pindexTip->nHeight) - static_cast<int64_t>(pindexFork->nHeight);
    if (reorg_depth < 0) {
        std::cerr << "[Chain] ERROR: Invalid reorg depth (negative): " << reorg_depth << std::endl;
        std::cerr << "  Tip height: " << pindexTip->nHeight << ", Fork height: " << pindexFork->nHeight << std::endl;
        return false;
    }
    if (reorg_depth > MAX_REORG_DEPTH) {
        std::cerr << "[Chain] ERROR: Reorganization too deep: " << reorg_depth << " blocks" << std::endl;
        std::cerr << "  Maximum allowed: " << MAX_REORG_DEPTH << " blocks" << std::endl;
        std::cerr << "  This may indicate a long-range attack or network partition" << std::endl;
        return false;
    }

    // MAINNET SECURITY: Checkpoint validation - prevent reorgs past checkpoints
    // Checkpoints are hardcoded trusted block hashes that protect old transaction history.
    // If a reorg would disconnect blocks before the last checkpoint, reject it.
    // Testnet has no checkpoints to allow testing deep reorgs.
    if (Dilithion::g_chainParams) {
        const Dilithion::CCheckpoint* checkpoint = Dilithion::g_chainParams->GetLastCheckpoint(pindexTip->nHeight);
        if (checkpoint && pindexFork->nHeight < checkpoint->nHeight) {
            std::cerr << "[Chain] ERROR: Cannot reorganize past checkpoint" << std::endl;
            std::cerr << "  Checkpoint height: " << checkpoint->nHeight << std::endl;
            std::cerr << "  Fork point height: " << pindexFork->nHeight << std::endl;
            std::cerr << "  This reorganization would undo blocks protected by a checkpoint." << std::endl;
            std::cerr << "  Checkpoints protect user funds from deep chain attacks." << std::endl;
            return false;
        }
    }

    if (reorg_depth > 10) {
        std::cout << "[Chain] WARNING: Deep reorganization (" << reorg_depth << " blocks)" << std::endl;
    }

    // Build list of blocks to disconnect (from current tip back to fork point)
    std::vector<CBlockIndex*> disconnectBlocks;
    CBlockIndex* pindex = pindexTip;
    while (pindex != pindexFork) {
        disconnectBlocks.push_back(pindex);
        pindex = pindex->pprev;

        if (pindex == nullptr) {
            std::cerr << "[Chain] ERROR: Hit nullptr while building disconnect list" << std::endl;
            return false;
        }
    }

    // Build list of blocks to connect (from fork point to new tip)
    std::vector<CBlockIndex*> connectBlocks;
    pindex = pindexNew;
    while (pindex != pindexFork) {
        connectBlocks.push_back(pindex);
        pindex = pindex->pprev;

        if (pindex == nullptr) {
            std::cerr << "[Chain] ERROR: Hit nullptr while building connect list" << std::endl;
            return false;
        }
    }

    // Reverse connect list so we connect from fork point -> new tip
    std::reverse(connectBlocks.begin(), connectBlocks.end());

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "  Disconnect " << disconnectBlocks.size() << ", connect " << connectBlocks.size() << " block(s)" << std::endl;

    // ============================================================================
    // DFMP FORK FIX: Skip reorg if any block in connect path is already invalid
    // ============================================================================
    // Fork blocks only get basic PoW validation (no DFMP) when received because
    // their parent is on a competing chain. Full DFMP validation runs at ConnectTip
    // during reorg. If a previous reorg attempt already found a DFMP-invalid block,
    // it's marked BLOCK_FAILED_VALID. Don't waste CPU disconnecting/reconnecting
    // the entire chain just to fail at the same block again.
    for (const auto* pindexCheck : connectBlocks) {
        if (pindexCheck->IsInvalid()) {
            std::cout << "[Chain] Skipping reorg: block at height " << pindexCheck->nHeight
                      << " is marked invalid" << std::endl;
            return true;  // Not an error - our chain is valid, fork is not
        }
    }

    // ============================================================================
    // CRITICAL-C002 FIX: Pre-validate ALL blocks exist before starting reorg
    // ============================================================================
    // This prevents the most common cause of rollback failure: missing block data.
    // By validating ALL blocks can be loaded BEFORE making any changes, we ensure
    // that if the reorg fails, it fails cleanly without corrupting the database.
    //
    // This is a defense-in-depth measure. The ultimate fix requires database-level
    // atomic transactions or write-ahead logging, but this significantly reduces
    // the risk of corruption.


    // Validate all disconnect blocks exist in database
    for (size_t i = 0; i < disconnectBlocks.size(); ++i) {
        CBlockIndex* pindexCheck = disconnectBlocks[i];
        CBlock blockCheck;

        if (pdb == nullptr) {
            std::cerr << "[Chain] ERROR: No database connection - cannot perform reorg" << std::endl;
            return false;
        }

        if (!pdb->ReadBlock(pindexCheck->GetBlockHash(), blockCheck)) {
            std::cerr << "[Chain] ERROR: Cannot load block for disconnect (PRE-VALIDATION FAILED)" << std::endl;
            std::cerr << "  Block: " << pindexCheck->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  Height: " << pindexCheck->nHeight << std::endl;
            std::cerr << "  Aborting reorg - database may be corrupted" << std::endl;
            return false;
        }
    }

    // Validate all connect blocks exist in database (except the new tip which we already have)
    for (size_t i = 0; i < connectBlocks.size(); ++i) {
        CBlockIndex* pindexCheck = connectBlocks[i];

        // Skip the new tip - we already have its block data in 'block' parameter
        if (pindexCheck == pindexNew) {
            continue;
        }

        CBlock blockCheck;
        if (!pdb->ReadBlock(pindexCheck->GetBlockHash(), blockCheck)) {
            std::cerr << "[Chain] ERROR: Cannot load block for connect (PRE-VALIDATION FAILED)" << std::endl;
            std::cerr << "  Block: " << pindexCheck->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  Height: " << pindexCheck->nHeight << std::endl;
            std::cerr << "  Aborting reorg - missing block data" << std::endl;
            return false;
        }
    }

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[Chain] Pre-validation passed: all " << (disconnectBlocks.size() + connectBlocks.size())
                  << " blocks loadable" << std::endl;
    }

    // ============================================================================
    // P1-4 FIX: Write-Ahead Logging for Crash-Safe Reorganization
    // ============================================================================
    // Write intent to WAL BEFORE making any changes. If we crash during reorg,
    // the WAL will be detected on startup and -reindex will be required.

    // Build hash lists for WAL
    std::vector<uint256> disconnectHashes;
    for (const auto* pblockindex : disconnectBlocks) {
        disconnectHashes.push_back(pblockindex->GetBlockHash());
    }
    std::vector<uint256> connectHashes;
    for (const auto* pblockindex : connectBlocks) {
        connectHashes.push_back(pblockindex->GetBlockHash());
    }

    if (m_reorgWAL) {
        if (!m_reorgWAL->BeginReorg(pindexFork->GetBlockHash(),
                                     pindexTip->GetBlockHash(),
                                     pindexNew->GetBlockHash(),
                                     disconnectHashes,
                                     connectHashes)) {
            std::cerr << "[Chain] ERROR: Failed to write reorg WAL - aborting" << std::endl;
            return false;
        }
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - Atomic Reorg with Rollback
    // ============================================================================

    // Disconnect old chain

    // P1-4: Enter disconnect phase in WAL
    if (m_reorgWAL) {
        m_reorgWAL->EnterDisconnectPhase();
    }
    size_t disconnectedCount = 0;
    for (size_t i = 0; i < disconnectBlocks.size(); ++i) {
        CBlockIndex* pindexDisconnect = disconnectBlocks[i];
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "  Disconnecting: " << pindexDisconnect->GetBlockHash().GetHex().substr(0, 16)
                      << " (height " << pindexDisconnect->nHeight << ")" << std::endl;

        if (!DisconnectTip(pindexDisconnect)) {
            std::cerr << "[Chain] ERROR: Failed to disconnect block during reorg at height "
                      << pindexDisconnect->nHeight << std::endl;

            // ROLLBACK: Reconnect all blocks we already disconnected
            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlockIndex* pindexReconnect = disconnectBlocks[j];
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling for block read failures
                // Since we pre-validated all blocks exist, if ReadBlock fails here,
                // it indicates database corruption or disk failure.
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Failed at block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(pindexReconnect->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(pindexReconnect, reconnectBlock, true)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << pindexReconnect->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  Height: " << pindexReconnect->nHeight << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        disconnectedCount++;

        // P1-4: Update disconnect progress in WAL
        if (m_reorgWAL) {
            m_reorgWAL->UpdateDisconnectProgress(static_cast<uint32_t>(disconnectedCount));
        }
    }

    // Connect new chain

    // P1-4: Enter connect phase in WAL
    if (m_reorgWAL) {
        m_reorgWAL->EnterConnectPhase();
    }
    size_t connectedCount = 0;
    for (size_t i = 0; i < connectBlocks.size(); ++i) {
        CBlockIndex* pindexConnect = connectBlocks[i];
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "  Connecting: " << pindexConnect->GetBlockHash().GetHex().substr(0, 16)
                      << " (height " << pindexConnect->nHeight << ")" << std::endl;

        // Load block data from database
        CBlock connectBlock;
        bool haveBlockData = false;

        if (pindexConnect == pindexNew) {
            // We have the full block data for the new tip
            connectBlock = block;
            haveBlockData = true;
        } else if (pdb != nullptr && pdb->ReadBlock(pindexConnect->GetBlockHash(), connectBlock)) {
            haveBlockData = true;
        }

        if (!haveBlockData) {
            std::cerr << "[Chain] ERROR: Cannot load block data for connect at height "
                      << pindexConnect->nHeight << std::endl;

            // ROLLBACK: Disconnect what we connected, reconnect what we disconnected
            std::cerr << "[Chain] ROLLBACK: Disconnecting " << connectedCount << " newly connected blocks..." << std::endl;
            for (int j = static_cast<int>(connectedCount) - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock, true)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        // BUG #279 FIX: Skip cooldown/MIK/DFMP validation during reorg connect.
        // The fork chain's blocks were validated by the network when mined, but
        // cooldown/consecutive-miner checks depend on chain-local state (the
        // cooldown tracker reflects the OLD chain, not the fork chain). VDF proof
        // and basic PoW are context-independent and were already checked in
        // PreValidateBlock or ProcessNewBlock. Without this skip, a legitimate
        // reorg (e.g., VDF tiebreak) gets rejected with "cooldown violation."
        if (!ConnectTip(pindexConnect, connectBlock, true /* skipValidation — reorg */)) {
            std::cerr << "[Chain] ERROR: Failed to connect block during reorg at height "
                      << pindexConnect->nHeight << std::endl;

            // DFMP FORK FIX: Mark remaining connect blocks as BLOCK_FAILED_CHILD
            // so future reorg attempts to this fork are skipped immediately.
            // The failed block itself is already marked BLOCK_FAILED_VALID by ConnectTip.
            for (size_t k = i + 1; k < connectBlocks.size(); ++k) {
                if (!(connectBlocks[k]->nStatus & CBlockIndex::BLOCK_FAILED_MASK)) {
                    connectBlocks[k]->nStatus |= CBlockIndex::BLOCK_FAILED_CHILD;
                    if (pdb != nullptr) {
                        pdb->WriteBlockIndex(connectBlocks[k]->GetBlockHash(), *connectBlocks[k]);
                    }
                }
            }
            std::cerr << "[Chain] Marked " << (connectBlocks.size() - i - 1)
                      << " descendant block(s) as BLOCK_FAILED_CHILD" << std::endl;

            // ROLLBACK: Same as above
            std::cerr << "[Chain] ROLLBACK: Disconnecting " << connectedCount << " newly connected blocks..." << std::endl;
            for (int j = static_cast<int>(connectedCount) - 1; j >= 0; --j) {
                if (!DisconnectTip(connectBlocks[j])) {
                    std::cerr << "[Chain] CRITICAL: Rollback failed during disconnect! Chain state corrupted!" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] ROLLBACK: Reconnecting " << disconnectedCount << " old blocks..." << std::endl;
            for (int j = static_cast<int>(disconnectedCount) - 1; j >= 0; --j) {
                CBlock reconnectBlock;

                // CRITICAL-C002 FIX: Explicit error handling
                if (pdb == nullptr) {
                    std::cerr << "[Chain] CRITICAL: No database during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!pdb->ReadBlock(disconnectBlocks[j]->GetBlockHash(), reconnectBlock)) {
                    std::cerr << "[Chain] CRITICAL: Cannot read block during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  This should be impossible - block passed pre-validation!" << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }

                if (!ConnectTip(disconnectBlocks[j], reconnectBlock, true)) {
                    std::cerr << "[Chain] CRITICAL: ConnectTip failed during rollback! Chain state corrupted!" << std::endl;
                    std::cerr << "  Block: " << disconnectBlocks[j]->GetBlockHash().GetHex() << std::endl;
                    std::cerr << "  RECOVERY REQUIRED: Restart node with -reindex" << std::endl;
                    if (m_reorgWAL) { m_reorgWAL->AbortReorg(); }
                    return false;
                }
            }

            std::cerr << "[Chain] Rollback complete. Reorg aborted." << std::endl;
            // P1-4: Rollback succeeded, abort WAL
            if (m_reorgWAL) {
                m_reorgWAL->AbortReorg();
            }
            return false;
        }

        connectedCount++;

        // P1-4: Update connect progress in WAL
        if (m_reorgWAL) {
            m_reorgWAL->UpdateConnectProgress(static_cast<uint32_t>(connectedCount));
        }
    }

    // Update tip
    pindexTip = pindexNew;
    // BUG #74 FIX: Update atomic cached height
    m_cachedHeight.store(pindexNew->nHeight, std::memory_order_release);

    // Persist to database
    if (pdb != nullptr) {
        pdb->WriteBestBlock(pindexNew->GetBlockHash());
    }

    if (g_verbose.load(std::memory_order_relaxed)) {
        std::cout << "[Chain] Reorganization complete" << std::endl;
        std::cout << "  New tip: " << pindexTip->GetBlockHash().GetHex().substr(0, 16)
                  << " (height " << pindexTip->nHeight << ")" << std::endl;
    }

    // P1-4: Reorg completed successfully - delete WAL
    if (m_reorgWAL) {
        m_reorgWAL->CompleteReorg();
    }

    // Bug #40 fix: Notify registered callbacks of tip update after reorg
    NotifyTipUpdate(pindexTip);

    reorgOccurred = true;
    return true;
}

bool CChainState::ConnectTip(CBlockIndex* pindex, const CBlock& block, bool skipValidation) {
    if (pindex == nullptr) {
        return false;
    }

    // Phase 5 TEST-ONLY override hook (chain_case_2_5_equivalence_tests).
    // Production never sets this; default-empty std::function falls through.
    if (m_testConnectTipOverride) {
        return m_testConnectTipOverride(pindex, block);
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - ConnectTip Implementation
    // ============================================================================

    // IBD OPTIMIZATION: Get cached hash once and reuse throughout
    const uint256& blockHash = pindex->GetBlockHash();

    // ============================================================================
    // FORK FIX: Validate MIK at connection time (not arrival time)
    // ============================================================================
    // MIK validation depends on the identity DB state. During fork recovery,
    // blocks may arrive before we have the correct identity DB state (our chain
    // is different from the fork chain). By validating at connection time:
    // 1. Identity DB reflects all blocks up to the parent (correct state)
    // 2. MIK can be validated against the correct identity registrations
    // 3. Fork blocks that passed PoW-only pre-validation get full MIK check here
    //
    // This allows fork recovery while maintaining MIK security:
    // - Fork pre-validation only checks PoW + hash match
    // - ConnectTip validates MIK when we have correct chain state
    //
    // skipValidation: Set during reorg reconnection and rollback. Re-validating
    // MIK/DNA/attestation during reorgs can fail because the identity DB is in
    // an inconsistent state (DisconnectTip only removes identities first seen at
    // the disconnected height — incomplete for multi-block reorgs).
    //
    // BUG #280/281 FIX: The following checks are now OUTSIDE this gate and
    // run for ALL block connects (including reorg/skipValidation):
    //   - Cooldown, consecutive, window-cap (BUG #280 — tracker-based)
    //   - Seed attestation (BUG #281 — context-independent, reads block + keys)
    //   - DNA hash equality (BUG #281 — degrades gracefully if registry missing)
    //
    // Only CheckProofOfWorkDFMP remains inside !skipValidation because it
    // depends on the identity DB which has incomplete undo during reorgs.

    // ====================================================================
    // ASSUME-VALID: Skip cooldown, consecutive, window cap, and attestation
    // checks for historical blocks below dfmpAssumeValidHeight.
    // These blocks were accepted by the network and are part of the canonical
    // chain. Computed before !skipValidation so it's available for both
    // identity-dependent checks (inside) and tracker-based checks (outside).
    // ====================================================================
    int assumeValidHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpAssumeValidHeight : 0;
    bool assumeValid = (assumeValidHeight > 0 && pindex->nHeight <= assumeValidHeight);

    if (!skipValidation) {
        int dfmpActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpActivationHeight : 0;

        // Only validate MIK for post-DFMP blocks (skip genesis - it predates any mining identity)
        if (pindex->nHeight > 0 && pindex->nHeight >= dfmpActivationHeight) {
            if (!CheckProofOfWorkDFMP(block, blockHash, block.nBits, pindex->nHeight, dfmpActivationHeight)) {
                std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                          << " failed MIK validation at connection time" << std::endl;
                std::cerr << "[Chain] Hash: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

                // BUG #255: Mark block as permanently failed (authoritative validation)
                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                std::cerr << "[Chain] Block marked BLOCK_FAILED_VALID - will not retry" << std::endl;

                if (pdb != nullptr) {
                    pdb->WriteBlockIndex(blockHash, *pindex);
                }

                return false;
            }
        }

        // ====================================================================
        // MIK EXPIRATION CHECK (Layer 2 Sybil Defense, hard fork)
        // ====================================================================
        // After activation, reference blocks from expired MIK identities are
        // rejected. Depends on identity DB (GetLastMined), so must be inside
        // !skipValidation gate. IBD blocks below assumeValid are exempt.
        if (block.IsVDFBlock() && !assumeValid && pindex->nHeight > 0) {
            std::string expirationError;
            if (!CheckMIKExpiration(block, pindex->nHeight, expirationError)) {
                std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                          << " REJECTED: MIK expired" << std::endl;
                std::cerr << "[Chain] " << expirationError << std::endl;

                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                if (pdb != nullptr) {
                    pdb->WriteBlockIndex(blockHash, *pindex);
                }
                return false;
            }
        }

        if (assumeValid && block.IsVDFBlock() && g_node_context.cooldown_tracker) {
            // Update tracker without enforcement so state is correct at assume-valid boundary
            std::array<uint8_t, 20> mikId{};
            if (ExtractCoinbaseMIKIdentity(block, mikId)) {
                g_node_context.cooldown_tracker->OnBlockConnected(
                    pindex->nHeight, mikId, static_cast<int64_t>(block.nTime));
            }
        }

    }

    // ========================================================================
    // REORG-SAFE CONSENSUS CHECKS (run for ALL block connects)
    // ========================================================================
    // These checks MUST run even during reorg connects (skipValidation=true),
    // because VDF block selection is effectively a reorg every block.
    //
    // BUG #281: Attestation and DNA checks were inside !skipValidation,
    // so reorg-connected blocks bypassed them. Same class as BUG #280.
    //
    // CheckMIKAttestations: fully context-independent (block data + hardcoded keys).
    // CheckDNAHashEquality: uses DNA registry but degrades gracefully — if the
    //   registry lacks data for a MIK during reorg, the check passes (can't verify).
    //   This prevents bypass while avoiding false rejections from stale state.
    //
    // CheckProofOfWorkDFMP remains inside !skipValidation because it depends on
    // the identity DB which has incomplete undo during multi-block reorgs.
    // ========================================================================

    // ====================================================================
    // DNA HASH-EQUALITY ENFORCEMENT (Phase 5A, hard fork at dnaHashEnforcementHeight)
    // ====================================================================
    // After activation, reject VDF blocks where the committed DNA hash
    // doesn't match the DNA we have on file for that MIK identity.
    // Safe during reorgs: if registry lacks MIK data, check passes (line 503-505).
    if (block.IsVDFBlock() && g_node_context.dna_registry) {
        std::string dnaError;
        if (!CheckDNAHashEquality(block, pindex->nHeight,
                                   *g_node_context.dna_registry, dnaError)) {
            std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                      << " REJECTED: DNA hash mismatch" << std::endl;
            std::cerr << "[Chain] " << dnaError << std::endl;

            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }
            return false;
        }
    }
    // They MUST run even during reorg connects (skipValidation=true),
    // because VDF block selection is effectively a reorg every block.
    //
    // BUG #281 FIX: Attestation was previously inside !skipValidation,
    // so reorg-connected blocks bypassed it — allowing unattested MIK
    // registrations into the canonical chain. Same class of bug as #280.
    //
    // MIK validation and DNA hash-equality remain inside !skipValidation
    // because they depend on identity DB / DNA registry state, which is
    // incomplete during multi-block reorgs.
    // ========================================================================

    // ====================================================================
    // SEED ATTESTATION CHECK (Phase 2+3, hard fork at seedAttestationActivationHeight)
    // ====================================================================
    // After activation, MIK registration blocks must include 3+ valid
    // attestations signed by known seed node keys.
    // Context-independent: reads only block coinbase + hardcoded seed pubkeys.
    // Skip attestation for genesis (height 0) — no MIK exists yet
    // Applies to both DIL (PoW, height 40,000) and DilV (VDF, height 2,000)
    if (pindex->nHeight > 0 && !assumeValid) {
        std::string attestError;
        if (!CheckMIKAttestations(block, pindex->nHeight, attestError)) {
            std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                      << " REJECTED: attestation check failed" << std::endl;
            std::cerr << "[Chain] " << attestError << std::endl;

            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }
            return false;
        }
    }

    // ========================================================================
    // COOLDOWN-TRACKER CONSENSUS CHECKS (run for ALL block connects)
    // ========================================================================
    // BUG #280 FIX: These checks use the cooldown tracker which is properly
    // maintained during reorgs via OnBlockDisconnected/OnBlockConnected
    // callbacks. After disconnecting old chain blocks, the tracker state at
    // the common ancestor is correct for validating the new chain's blocks.
    // ========================================================================

    // ====================================================================
    // CONSENSUS-ENFORCED COOLDOWN (hard fork at dfmpCooldownConsensusHeight)
    // ====================================================================
    // After activation, reject blocks where the miner's MIK identity
    // is still within its cooldown period. This prevents cheaters from
    // bypassing the voluntary miner-side cooldown.
    //
    // The block below has TWO PATHS:
    //
    //   v4.2.0 hard-fork (above timeDecayCooldownActivationHeight):
    //       Single self-correcting cooldown rule. Cooldown drains by 1 block
    //       per cooldownTimeDecaySeconds of wall-clock — no exemption tiers,
    //       no stall bypass needed because cooldowns naturally clear over
    //       time. See spec .claude/contracts/v4_2_time_decay_cooldown_spec.md.
    //
    //   Legacy v4.1 (below timeDecayCooldownActivationHeight):
    //       Block-count cooldown + V2 stall-exemption tiers. Comment for
    //       this path is INSIDE the `else` branch below — kept verbatim for
    //       historical-block validation but no new design discussion.
    if (block.IsVDFBlock() && g_node_context.cooldown_tracker && !assumeValid) {
        // ====================================================================
        // v4.2.0 — TIME-DECAY COOLDOWN PATH (replaces stall-exemption tier system)
        // ====================================================================
        // At and above timeDecayCooldownActivationHeight, the new self-correcting
        // rule applies via IsInCooldown's internal branch. The stall-exemption
        // tier 1/2 logic below is BYPASSED — under the new rule no exemption is
        // ever needed because cooldowns naturally drain with wall-clock time.
        //
        // CheckVDFCooldown calls cooldown_tracker.IsInCooldown(mik, height,
        // blockTimestamp) which branches internally: above activation it uses
        // the time-decay formula, below activation the legacy block-only path.
        // CheckConsecutiveMiner and CheckMIKWindowCap continue to run unchanged
        // below this block — they enforce orthogonal invariants that time-decay
        // does NOT subsume (HIGH-1 fix, see spec §4.2).
        int timeDecayActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->timeDecayCooldownActivationHeight : 999999999;

        if (pindex->nHeight >= timeDecayActivationHeight) {
            // v4.2.0 path — single check, no exemption tiers.
            std::string cooldownError;
            int64_t blockTs = static_cast<int64_t>(block.nTime);
            if (!CheckVDFCooldown(block, pindex->nHeight,
                                   *g_node_context.cooldown_tracker, cooldownError,
                                   blockTs)) {
                std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                          << " REJECTED: time-decay cooldown active" << std::endl;
                std::cerr << "[Chain] " << cooldownError << std::endl;

                pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                if (pdb != nullptr) {
                    pdb->WriteBlockIndex(blockHash, *pindex);
                }
                return false;
            }
        } else {
            // ----------------------------------------------------------------
            // LEGACY v4.1 PATH — block-count cooldown + stall-exemption tiers.
            // ----------------------------------------------------------------
            // STALL EXEMPTION: If the timestamp gap between this block and its
            // parent is large enough, bypass cooldown enforcement. During a
            // stall all miners may be in cooldown, creating a permanent
            // deadlock where no block can ever be produced (BUG #274).
            //
            // V2 (stallExemptionV2Height): Threshold raised from 300s to 600s.
            // Additionally, stall bypass requires a different miner from the
            // previous block (unless solo mining). Prevents private fork
            // mining via repeated stall exemption abuse.
            //
            // Subsumed by the v4.2.0 time-decay rule above-activation.
            // Retained for historical-block validation only.
            bool chainStalled = false;

            int stabilizationHeight = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->stabilizationForkHeight : 999999999;

            if (pindex->nHeight >= stabilizationHeight) {
                // Post-stabilization: NO stall exemption.
                // Time-based cooldown expiry handles stalls naturally.
                // Stall exemption was exploited for private fork mining (2026-03-31).
                // chainStalled stays false.
            } else if (pindex->pprev) {
                int64_t gap = static_cast<int64_t>(block.nTime) - static_cast<int64_t>(pindex->pprev->nTime);

                int stallV2Height = Dilithion::g_chainParams ?
                    Dilithion::g_chainParams->stallExemptionV2Height : 999999999;

                if (pindex->nHeight >= stallV2Height) {
                    // V2: Two-tier stall exemption to prevent private fork mining
                    // while avoiding deadlocks during genuine long stalls.
                    //
                    // Tier 1 (600-1199s): bypass cooldown ONLY if different miner
                    //   (or solo miner).  Blocks the ~384s attack pattern.
                    // Tier 2 (1200s+): bypass cooldown unconditionally.
                    //   Prevents permanent deadlock when only the previous miner
                    //   is available during a genuine extended stall.
                    static constexpr int64_t STALL_THRESHOLD_V2 = 600;
                    static constexpr int64_t STALL_UNCONDITIONAL = 1200;
                    chainStalled = (gap >= STALL_THRESHOLD_V2);

                    if (chainStalled && gap < STALL_UNCONDITIONAL) {
                        // Tier 1: require different miner (unless solo)
                        std::array<uint8_t, 20> currentMik{};
                        std::array<uint8_t, 20> prevMik{};
                        bool haveCurrent = ExtractCoinbaseMIKIdentity(block, currentMik);

                        CBlock prevBlock;
                        bool havePrev = false;
                        if (pdb != nullptr) {
                            havePrev = pdb->ReadBlock(pindex->pprev->GetBlockHash(), prevBlock);
                            if (havePrev) {
                                havePrev = ExtractCoinbaseMIKIdentity(prevBlock, prevMik);
                            }
                        }

                        if (haveCurrent && havePrev && currentMik == prevMik) {
                            // Same miner — force recalc of active miners at this
                            // height (fixes stale cache issue in stall path)
                            g_node_context.cooldown_tracker->IsInCooldown(currentMik, pindex->nHeight);
                            int activeMiners = g_node_context.cooldown_tracker->GetActiveMiners();
                            if (activeMiners > 1) {
                                chainStalled = false;  // Reject stall exemption
                                if (g_verbose.load(std::memory_order_relaxed))
                                    std::cout << "[Chain] Block " << pindex->nHeight
                                              << ": stall exemption DENIED (same miner as prev, "
                                              << activeMiners << " active miners)" << std::endl;
                            }
                        }
                    }
                    // Tier 2 (gap >= 1200s): chainStalled stays true unconditionally
                } else {
                    // Legacy: 300s threshold, no miner check
                    chainStalled = (gap >= 300);
                }
            }

            if (chainStalled) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[Chain] Block " << pindex->nHeight
                              << ": cooldown check skipped (chain stall -- "
                              << (block.nTime - pindex->pprev->nTime)
                              << "s since last block)" << std::endl;
            } else {
                std::string cooldownError;
                // Pass block.nTime for time-based cooldown expiry
                int64_t blockTs = static_cast<int64_t>(block.nTime);
                if (!CheckVDFCooldown(block, pindex->nHeight,
                                       *g_node_context.cooldown_tracker, cooldownError,
                                       blockTs)) {
                    std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                              << " REJECTED: cooldown violation" << std::endl;
                    std::cerr << "[Chain] " << cooldownError << std::endl;

                    pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
                    if (pdb != nullptr) {
                        pdb->WriteBlockIndex(blockHash, *pindex);
                    }
                    return false;
                }
            }
        }
    }

    // ====================================================================
    // CONSECUTIVE MINER CHECK (hard fork at consecutiveMinerCheckHeight)
    // ====================================================================
    // After activation, reject VDF blocks where the same MIK identity
    // has mined more than 3 consecutive blocks.  Prevents private fork
    // chain construction by a single miner.  Solo miner exemption applies.
    if (block.IsVDFBlock() && g_node_context.cooldown_tracker && !assumeValid) {
        std::string consecError;
        if (!CheckConsecutiveMiner(block, pindex, pdb,
                                   *g_node_context.cooldown_tracker, consecError)) {
            std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                      << " REJECTED: consecutive miner violation" << std::endl;
            std::cerr << "[Chain] " << consecError << std::endl;

            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }
            return false;
        }
    }

    // ====================================================================
    // PER-MIK WINDOW CAP (consensus rule)
    // ====================================================================
    // Reject blocks where the miner's MIK has already mined the maximum
    // allowed blocks in the trailing window.  Exemptions: solo miner,
    // liveness timeout (chain stall).
    if (block.IsVDFBlock() && g_node_context.cooldown_tracker && !assumeValid) {
        int64_t prevTime = pindex->pprev ? static_cast<int64_t>(pindex->pprev->nTime) : 0;
        int64_t blkTime = static_cast<int64_t>(block.nTime);
        std::string capError;
        if (!CheckMIKWindowCap(block, pindex->nHeight,
                                *g_node_context.cooldown_tracker,
                                prevTime, blkTime, capError)) {
            std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                      << " REJECTED: window cap exceeded" << std::endl;
            std::cerr << "[Chain] " << capError << std::endl;

            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }
            return false;
        }
    }

    // ====================================================================
    // REGISTRATION RATE LIMIT (Layer 3 Sybil Defense, hard fork)
    // ====================================================================
    // After activation, reject MIK registration blocks if too many new
    // registrations have occurred in the trailing window.
    // Uses cooldown tracker (reorg-safe): runs for all block connects.
    if (block.IsVDFBlock() && g_node_context.cooldown_tracker && !assumeValid) {
        std::string rateLimitError;
        if (!CheckRegistrationRateLimit(block, pindex->nHeight,
                                         *g_node_context.cooldown_tracker,
                                         rateLimitError)) {
            std::cerr << "[Chain] ERROR: Block " << pindex->nHeight
                      << " REJECTED: registration rate limit exceeded" << std::endl;
            std::cerr << "[Chain] " << rateLimitError << std::endl;

            pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;
            if (pdb != nullptr) {
                pdb->WriteBlockIndex(blockHash, *pindex);
            }
            return false;
        }
    }

    // Step 1: Update UTXO set (CS-004)
    if (pUTXOSet != nullptr) {
        if (!pUTXOSet->ApplyBlock(block, pindex->nHeight, blockHash)) {
            std::cerr << "[Chain] ERROR: Failed to apply block to UTXO set at height "
                      << pindex->nHeight << std::endl;

            // BUG #277: DON'T mark block as BLOCK_FAILED_VALID on UTXO errors.
            // UTXO lookup failures indicate UTXO set corruption (e.g., after OOM crash),
            // NOT that the block is actually invalid. Marking it permanently failed
            // prevents the node from ever syncing past this point.
            // Instead, track consecutive failures. If persistent, signal corruption
            // so the IBD coordinator can trigger a full chain resync.
            int failures = ++m_consecutive_utxo_failures;
            std::cerr << "[Chain] UTXO failure #" << failures << " at height " << pindex->nHeight
                      << " (threshold=" << MAX_UTXO_FAILURES_BEFORE_REBUILD << ")" << std::endl;

            if (failures >= MAX_UTXO_FAILURES_BEFORE_REBUILD) {
                std::cerr << "[Chain] CRITICAL: " << failures << " consecutive UTXO failures detected!"
                          << std::endl;
                std::cerr << "[Chain] UTXO set appears corrupted. Signaling auto-recovery."
                          << std::endl;
                m_utxo_needs_rebuild.store(true);
            }

            return false;
        }
    }

    // Reset UTXO failure counter on success
    m_consecutive_utxo_failures.store(0);

    std::cout << " done" << std::endl;

    // Step 2: Update pnext pointer on parent
    if (pindex->pprev != nullptr) {
        pindex->pprev->pnext = pindex;
    }

    // Step 3: Mark block as connected
    // v4.3.3 F2 (audit modality 2 HIGH-4): also OR in BLOCK_HAVE_DATA.
    // Upstream Bitcoin Core's ReceivedBlockTransactions sets BLOCK_HAVE_DATA
    // at disk-write of the full block; pre-fix, port-path blocks could reach
    // ConnectTip via header-first arrival paths without the flag ever being
    // set, leaving HaveData() permanently false. F5's per-ancestor data gate
    // depends on this flag being authoritative once a block is connected.
    pindex->nStatus |= CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

    // BUG #56 FIX: Notify block connect callbacks (wallet update)
    // NOTE: We don't hold cs_main during callbacks to prevent deadlock
    // The wallet has its own lock (cs_wallet)
    // IBD OPTIMIZATION: Pass cached hash to avoid RandomX recomputation
    for (size_t i = 0; i < m_blockConnectCallbacks.size(); ++i) {
        try {
            m_blockConnectCallbacks[i](block, pindex->nHeight, blockHash);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Chain] ERROR: Block connect callback " << i << " threw unknown exception" << std::endl;
        }
    }

    // ========================================================================
    // BUG #109 FIX: Remove confirmed transactions from mempool
    // ========================================================================
    // CRITICAL: After UTXO set is updated, we must remove confirmed transactions
    // from mempool to prevent:
    // 1. UTXO/mempool inconsistency (inputs appearing unavailable)
    // 2. Transactions remaining in mempool after being confirmed
    // 3. Template building seeing stale transactions with unavailable inputs
    if (pMemPool != nullptr) {
        // Deserialize block transactions (block.vtx is raw bytes)
        CBlockValidator validator;
        std::vector<CTransactionRef> block_txs;
        std::string error;

        if (validator.DeserializeBlockTransactions(block, block_txs, error)) {
            pMemPool->RemoveConfirmedTxs(block_txs);
        } else {
            std::cerr << "[Chain] WARNING: Failed to deserialize block txs for mempool cleanup: " << error << std::endl;
        }
    }

    return true;
}

bool CChainState::DisconnectTip(CBlockIndex* pindex, bool force_skip_utxo) {
    if (pindex == nullptr) {
        return false;
    }

    // Phase 5 TEST-ONLY override hook (chain_case_2_5_equivalence_tests).
    // Production never sets this; default-empty std::function falls through.
    if (m_testDisconnectTipOverride) {
        return m_testDisconnectTipOverride(pindex);
    }

    // ============================================================================
    // CS-005: Chain Reorganization Rollback - DisconnectTip Implementation
    // RACE CONDITION FIX: Steps 1-5 must be done under cs_main lock
    // ============================================================================

    CBlock block;
    bool block_loaded = false;
    int disconnectHeight = 0;
    uint256 disconnectHash;

    // CRITICAL: Hold cs_main during chain state modifications
    {
        std::lock_guard<std::recursive_mutex> lock(cs_main);

        // Step 1: Load block data from database (needed for UTXO undo)
        if (pdb != nullptr) {
            if (pdb->ReadBlock(pindex->GetBlockHash(), block)) {
                block_loaded = true;
            } else if (!force_skip_utxo) {
                std::cerr << "[Chain] ERROR: Failed to load block from database for disconnect at height "
                          << pindex->nHeight << std::endl;
                return false;
            } else {
                std::cout << "[Chain] WARNING: Block data missing for disconnect at height "
                          << pindex->nHeight << " (force_skip_utxo=true)" << std::endl;
            }
        } else if (!force_skip_utxo) {
            std::cerr << "[Chain] ERROR: Cannot disconnect block without database access" << std::endl;
            return false;
        }

        // Step 2: Undo UTXO set changes (CS-004)
        // BUG #159 FIX: Allow skipping UTXO undo during IBD fork recovery when undo data is missing
        // BUG #271 FIX: Pass block index hash to UndoBlock for consistent undo data lookup
        // v4.0.19: Track persistent UndoBlock failures so a stuck node can self-recover
        // via auto_rebuild instead of looping forever (incident 2026-04-25).
        if (pUTXOSet != nullptr && block_loaded) {
            if (!pUTXOSet->UndoBlock(block, pindex->GetBlockHash())) {
                if (!force_skip_utxo) {
                    std::cerr << "[Chain] ERROR: Failed to undo block from UTXO set at height "
                              << pindex->nHeight << std::endl;
                    RecordUndoFailure(pindex->GetBlockHash(), pindex->nHeight);
                    return false;
                } else {
                    std::cout << "[Chain] WARNING: Failed to undo UTXO at height "
                              << pindex->nHeight << " (force_skip_utxo=true, continuing anyway)" << std::endl;
                    // Don't track in force_skip_utxo path — caller has explicitly opted into
                    // continuing past undo failure (IBD fork recovery).
                }
            } else {
                // UndoBlock succeeded — clear any prior failure tracking.
                ResetUndoFailureCounter();
            }
        } else if (force_skip_utxo) {
            std::cout << "[Chain] Skipping UTXO undo for height " << pindex->nHeight
                      << " (force_skip_utxo=true)" << std::endl;
        }

        // Step 2.5: Undo identity DB changes (MIK registrations)
        // Only remove identities that were FIRST SEEN at this block height.
        // Identities introduced earlier remain valid on the remaining chain.
        if (block_loaded && DFMP::g_identityDb) {
            CBlockValidator validator;
            std::vector<CTransactionRef> txs;
            std::string err;
            if (validator.DeserializeBlockTransactions(block, txs, err) && !txs.empty()) {
                if (!txs[0]->vin.empty()) {
                    DFMP::CMIKScriptData mikData;
                    if (DFMP::ParseMIKFromScriptSig(txs[0]->vin[0].scriptSig, mikData)) {
                        DFMP::Identity identity = mikData.identity;
                        if (!identity.IsNull()) {
                            int firstSeen = DFMP::g_identityDb->GetFirstSeen(identity);
                            if (firstSeen == pindex->nHeight) {
                                // Identity was introduced at this height - safe to remove
                                DFMP::g_identityDb->RemoveMIKPubKey(identity);
                                DFMP::g_identityDb->RemoveFirstSeen(identity);
                            }
                            // If firstSeen != height, identity was introduced earlier - keep it
                        }
                    }
                }
            }
        }

        // Step 3: Clear pnext pointer on parent
        if (pindex->pprev != nullptr) {
            pindex->pprev->pnext = nullptr;
        }

        // Step 4: Clear own pnext pointer
        pindex->pnext = nullptr;

        // Step 5: Unmark block as on main chain
        pindex->nStatus &= ~CBlockIndex::BLOCK_VALID_CHAIN;

        // Cache values for callbacks (called outside lock)
        disconnectHeight = pindex->nHeight;
        disconnectHash = pindex->GetBlockHash();
    }
    // cs_main released here

    // Return non-coinbase transactions to mempool for re-mining
    // UTXO inputs have been restored by UndoBlock above, so txs are valid again
    if (pMemPool != nullptr && block_loaded) {
        CBlockValidator validator;
        std::vector<CTransactionRef> block_txs;
        std::string error;

        if (validator.DeserializeBlockTransactions(block, block_txs, error)) {
            int returned = 0;
            int failed = 0;
            for (const auto& tx : block_txs) {
                if (!tx || tx->IsCoinBase()) continue;
                int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count();
                std::string add_error;
                // bypass_fee_check=true: tx already passed fee validation when first accepted.
                // Reorg doesn't change the fee — only the chain tip changed.
                if (pMemPool->AddTx(tx, 0, current_time, disconnectHeight - 1, &add_error, true)) {
                    ++returned;
                } else {
                    ++failed;
                    std::cerr << "[Chain] WARNING: Failed to return tx " << tx->GetHash().GetHex().substr(0, 16)
                              << "... to mempool after disconnect: " << add_error << std::endl;
                }
            }
            if (returned > 0 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[Chain] Returned " << returned << " tx to mempool from disconnected block at height "
                          << disconnectHeight << std::endl;
            }
        }
    }

    // BUG #56 FIX: Notify block disconnect callbacks (wallet update)
    // NOTE: We don't hold cs_main during callbacks to prevent deadlock
    // The wallet has its own lock (cs_wallet)
    for (size_t i = 0; i < m_blockDisconnectCallbacks.size(); ++i) {
        try {
            m_blockDisconnectCallbacks[i](block, disconnectHeight, disconnectHash);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Block disconnect callback " << i << " threw exception: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "[Chain] ERROR: Block disconnect callback " << i << " threw unknown exception" << std::endl;
        }
    }

    return true;
}

int CChainState::DisconnectToHeight(int targetHeight, CBlockchainDB& db, int batchSize) {
    std::unique_lock<std::recursive_mutex> lock(cs_main);

    if (!pindexTip || targetHeight < 0) return -1;
    if (pindexTip->nHeight <= targetHeight) return 0;

    // Checkpoint enforcement: mirror ActivateBestChain's checkpoint logic (lines 267-281)
    if (Dilithion::g_chainParams) {
        const Dilithion::CCheckpoint* checkpoint = Dilithion::g_chainParams->GetLastCheckpoint(pindexTip->nHeight);
        if (checkpoint && targetHeight < checkpoint->nHeight) {
            std::cerr << "[DisconnectToHeight] Cannot disconnect below checkpoint "
                      << checkpoint->nHeight << " (target=" << targetHeight << ")" << std::endl;
            return -1;
        }
    }

    int totalDisconnected = 0;
    int remaining = pindexTip->nHeight - targetHeight;

    // WAL: Record deep disconnect intent for crash safety
    if (m_reorgWAL) {
        // Build disconnect hash list for WAL
        std::vector<uint256> disconnectHashes;
        disconnectHashes.reserve(remaining);
        CBlockIndex* pWalk = pindexTip;
        while (pWalk && pWalk->nHeight > targetHeight) {
            disconnectHashes.push_back(pWalk->GetBlockHash());
            pWalk = pWalk->pprev;
        }
        uint256 forkPointHash = pWalk ? pWalk->GetBlockHash() : uint256();

        m_reorgWAL->BeginReorg(forkPointHash,
                               pindexTip->GetBlockHash(),
                               uint256(),  // target tip unknown (IBD will find it)
                               disconnectHashes,
                               std::vector<uint256>());  // connect blocks unknown
        m_reorgWAL->EnterDisconnectPhase();
    }

    while (pindexTip && pindexTip->nHeight > targetHeight) {
        int batchCount = 0;

        while (pindexTip && pindexTip->nHeight > targetHeight &&
               (batchSize == 0 || batchCount < batchSize)) {

            if (!DisconnectTip(pindexTip, false /* force_skip_utxo */)) {
                std::cerr << "[DisconnectToHeight] DisconnectTip failed at height "
                          << pindexTip->nHeight << std::endl;
                if (m_reorgWAL) m_reorgWAL->AbortReorg();
                return -1;
            }

            // Move tip to previous block
            pindexTip = pindexTip->pprev;
            m_cachedHeight.store(pindexTip ? pindexTip->nHeight : -1, std::memory_order_release);
            totalDisconnected++;
            batchCount++;
        }

        // Persist progress after each batch
        if (pindexTip) {
            db.WriteBestBlock(pindexTip->GetBlockHash());
        }
        if (m_reorgWAL) {
            m_reorgWAL->UpdateDisconnectProgress(static_cast<uint32_t>(totalDisconnected));
        }

        // Release lock between batches to let RPC/P2P threads make progress
        if (batchSize > 0 && pindexTip && pindexTip->nHeight > targetHeight) {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            lock.lock();
        }

        if (totalDisconnected % 100 == 0 || totalDisconnected == remaining) {
            std::cout << "[DisconnectToHeight] Progress: " << totalDisconnected << "/"
                      << remaining << " blocks disconnected" << std::endl;
        }
    }

    // Final persist
    if (pindexTip) {
        db.WriteBestBlock(pindexTip->GetBlockHash());
    }

    // WAL: Mark disconnect phase complete (connect phase handled by normal IBD)
    if (m_reorgWAL) {
        m_reorgWAL->CompleteReorg();
    }

    return totalDisconnected;
}

std::vector<uint256> CChainState::GetBlocksAtHeight(int height) const {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<uint256> result;

    for (const auto& pair : mapBlockIndex) {
        if (pair.second->nHeight == height) {
            result.push_back(pair.first);
        }
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

// Block explorer: Find all chain tips (blocks with no children)
std::vector<CChainState::ChainTip> CChainState::GetChainTips() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<ChainTip> tips;
    if (!pindexTip) return tips;

    // Build set of blocks that have children (i.e., are referenced as pprev)
    std::set<const CBlockIndex*> hasChildren;
    for (const auto& pair : mapBlockIndex) {
        if (pair.second->pprev) {
            hasChildren.insert(pair.second->pprev);
        }
    }

    // Any block NOT in hasChildren set is a tip.
    // Skip tips more than 100 blocks behind active tip — on VDF chains,
    // same-height competing blocks create many short-lived forks that
    // accumulate in mapBlockIndex and never get extended.
    const int tipPruneDepth = 100;
    const int minTipHeight = pindexTip->nHeight - tipPruneDepth;

    for (const auto& pair : mapBlockIndex) {
        const CBlockIndex* pindex = pair.second.get();
        if (hasChildren.count(pindex) == 0) {
            // Skip deeply stale tips (except the active tip)
            if (pindex != pindexTip && pindex->nHeight < minTipHeight)
                continue;

            ChainTip tip;
            tip.height = pindex->nHeight;
            tip.hash = pair.first;
            tip.chain_work = pindex->nChainWork;  // Phase 5 PR5.2.A

            // Determine status and branch length.
            // Phase 5 PR5.2.A (Finding F3): expanded from 2 to 5 status values
            // to match the frozen ChainTipInfo::Status enum.
            if (pindex == pindexTip) {
                tip.status = "active";
                tip.branchlen = 0;
            } else {
                // Find fork point with main chain.
                const CBlockIndex* pWalk = pindex;
                int branchlen = 0;
                // Walk back to find where this tip diverges from main chain.
                // A block is on the main chain if walking from tip backwards reaches it.
                while (pWalk && pWalk->nHeight > 0) {
                    bool onMainChain = false;
                    if (pWalk->nHeight <= pindexTip->nHeight) {
                        const CBlockIndex* pMain = pindexTip;
                        while (pMain && pMain->nHeight > pWalk->nHeight) {
                            pMain = pMain->pprev;
                        }
                        if (pMain && pMain->GetBlockHash() == pWalk->GetBlockHash()) {
                            onMainChain = true;
                        }
                    }
                    if (onMainChain) break;
                    branchlen++;
                    pWalk = pWalk->pprev;
                }
                tip.branchlen = branchlen;

                // Status precedence: invalid > valid-fork (full block) >
                // valid-headers (headers only) > unknown.
                if (pindex->IsInvalid()) {
                    tip.status = "invalid";
                } else {
                    const uint32_t validLevel = pindex->nStatus & CBlockIndex::BLOCK_VALID_MASK;
                    if (validLevel >= CBlockIndex::BLOCK_VALID_TRANSACTIONS) {
                        tip.status = "valid-fork";
                    } else if (validLevel >= CBlockIndex::BLOCK_VALID_HEADER) {
                        tip.status = "valid-headers";
                    } else {
                        tip.status = "unknown";
                    }
                }
            }

            tips.push_back(tip);
        }
    }

    // Sort by height descending (active tip first)
    std::sort(tips.begin(), tips.end(), [](const ChainTip& a, const ChainTip& b) {
        if (a.status == "active") return true;
        if (b.status == "active") return false;
        return a.height > b.height;
    });

    return tips;
}

// RACE CONDITION FIX: Thread-safe chain snapshot for fork detection
std::vector<std::pair<int, uint256>> CChainState::GetChainSnapshot(int maxBlocks, int minHeight) const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    std::vector<std::pair<int, uint256>> result;
    result.reserve(std::min(maxBlocks, pindexTip ? pindexTip->nHeight + 1 : 0));

    CBlockIndex* pindex = pindexTip;
    int count = 0;

    while (pindex && pindex->nHeight >= minHeight && count < maxBlocks) {
        result.push_back({pindex->nHeight, pindex->GetBlockHash()});
        pindex = pindex->pprev;
        count++;
    }

    return result;
}

// CRITICAL-1 FIX: Thread-safe accessor methods moved from inline to .cpp

CBlockIndex* CChainState::GetTip() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return pindexTip;
}

void CChainState::SetTip(CBlockIndex* pindex) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    
    // Consensus invariant: If tip is set, it must exist in mapBlockIndex
    if (pindex != nullptr) {
        uint256 tipHash = pindex->GetBlockHash();
        ConsensusInvariant(mapBlockIndex.count(tipHash) > 0);
        
        // Consensus invariant: Tip height must be >= 0
        ConsensusInvariant(pindex->nHeight >= 0);
    }
    
    pindexTip = pindex;
    // BUG #74 FIX: Update atomic cached height for lock-free reads
    m_cachedHeight.store(pindex ? pindex->nHeight : -1, std::memory_order_release);
    
    // Invariant: Cached height must match tip height
    if (pindex != nullptr) {
        Invariant(m_cachedHeight.load(std::memory_order_acquire) == pindex->nHeight);
    }
}

int CChainState::GetHeight() const {
    // BUG #74 FIX: Lock-free read of cached height
    // This prevents RPC calls from blocking on cs_main during block processing
    // The atomic is updated atomically whenever pindexTip changes
    return m_cachedHeight.load(std::memory_order_acquire);
}

uint256 CChainState::GetChainWork() const {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    return pindexTip ? pindexTip->nChainWork : uint256();
}

// Bug #40 fix: Callback registration and notification

void CChainState::RegisterTipUpdateCallback(TipUpdateCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_tipCallbacks.push_back(callback);
}

void CChainState::NotifyTipUpdate(const CBlockIndex* pindex) {
    // NOTE: Caller must already hold cs_main lock
    // This is always called from within ActivateBestChain which holds the lock

    if (pindex == nullptr) {
        return;
    }

    // Execute all registered callbacks with exception handling
    for (size_t i = 0; i < m_tipCallbacks.size(); ++i) {
        try {
            m_tipCallbacks[i](pindex);
        } catch (const std::exception& e) {
            std::cerr << "[Chain] ERROR: Tip callback " << i << " threw exception: " << e.what() << std::endl;
            // Continue executing other callbacks even if one fails
        } catch (...) {
            std::cerr << "[Chain] ERROR: Tip callback " << i << " threw unknown exception" << std::endl;
            // Continue executing other callbacks even if one fails
        }
    }
}

// BUG #56 FIX: Block connect/disconnect callback registration

void CChainState::RegisterBlockConnectCallback(BlockConnectCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_blockConnectCallbacks.push_back(callback);
}

void CChainState::RegisterBlockDisconnectCallback(BlockDisconnectCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    m_blockDisconnectCallbacks.push_back(callback);
}

// ============================================================================
// v4.0.19: Persistent UndoBlock failure tracking
// ============================================================================
// Mirrors the BUG #277 UTXO-failure pattern but for the disconnect path. When
// DisconnectTip's UndoBlock returns false repeatedly on the SAME block hash,
// the chain is stuck — the node cannot reorg forward without manual recovery.
// At kPersistentUndoFailureThreshold, sets m_chain_needs_rebuild so the IBD
// coordinator can write the auto_rebuild marker and trigger graceful shutdown.

void CChainState::RecordUndoFailure(const uint256& blockHash, int height) {
    int failures;
    {
        std::lock_guard<std::mutex> lock(m_undo_failure_mutex);
        if (blockHash == m_last_undo_failure_hash) {
            failures = ++m_consecutive_undo_failures;
        } else {
            // Different block hash — reset to 1 (this is the first failure on this hash).
            // Persistent failures only count when on the SAME block; a sequence of failures
            // on different blocks is a different failure mode.
            m_last_undo_failure_hash = blockHash;
            m_consecutive_undo_failures.store(1);
            failures = 1;
        }
    }

    std::cerr << "[Chain] UndoBlock failure #" << failures << " at height " << height
              << " hash=" << blockHash.GetHex().substr(0, 16) << "..."
              << " (threshold=" << kPersistentUndoFailureThreshold << ")" << std::endl;

    if (failures >= kPersistentUndoFailureThreshold) {
        std::cerr << "[CRITICAL] DisconnectTip: persistent UndoBlock failure"
                  << " hash=" << blockHash.GetHex()
                  << " height=" << height
                  << " consecutive=" << failures
                  << ". Triggering auto_rebuild." << std::endl;
        // v4.3.3 F16: BUG #277 persistent UndoBlock failure → UndoFailure cause.
        FlagChainRebuild(ChainRebuildReason::UndoFailure);
    }
}

void CChainState::ResetUndoFailureCounter() {
    std::lock_guard<std::mutex> lock(m_undo_failure_mutex);
    m_consecutive_undo_failures.store(0);
    m_last_undo_failure_hash = uint256();  // default-constructed = zeroed (no SetNull on this type)
}

void CChainState::ClearChainRebuildFlag() {
    m_chain_needs_rebuild.store(false);
    // v4.3.3 F17 (Layer-3 round 3 INFO-2): setter symmetry. The reason
    // was set by FlagChainRebuild; on clear, reset to default UndoFailure
    // so a future fire that hits a default-only site (i.e., one of the
    // legacy `m_chain_needs_rebuild.store(true)` sites that hasn't been
    // converted to FlagChainRebuild) doesn't read back a stale prior
    // reason. No active caller relies on this today; defensive symmetry.
    m_chain_rebuild_reason.store(ChainRebuildReason::UndoFailure,
                                  std::memory_order_release);
    ResetUndoFailureCounter();
}

uint256 CChainState::GetLastUndoFailureHash() const {
    std::lock_guard<std::mutex> lock(m_undo_failure_mutex);
    return m_last_undo_failure_hash;
}

// ============================================================================
// v4.0.19: VerifyRecentUndoIntegrity — Fix B startup-time integrity check
// ============================================================================
// Walks back from the current tip up to probeDepth blocks, confirming each
// block has a corresponding undo_<hash> entry in the UTXO LevelDB. Used at
// startup to detect the missing-undo-data state BEFORE reorg attempts begin.
// On detection, the caller writes auto_rebuild and exits, instead of letting
// the node loop forever like NYC + LDN did 2026-04-25.
//
// v4.4: thin delegator. Routes through CUTXOSet::VerifyUndoDataInRange so all
// integrity-check call sites (this legacy 100-block-probe API + the new
// rolling-window startup walk + the periodic monitor) share one canonical
// pprev-walk + SHA3-checksum implementation. The legacy two-output failure
// shape (uint256 + int) is preserved for backwards-compatibility with any
// remaining callers; the v4.4 startup integration in dilv-node.cpp +
// dilithion-node.cpp uses the richer UndoIntegrityFailure shape directly.
// Marked deprecated; cleanup pass scheduled for v4.5.

bool CChainState::VerifyRecentUndoIntegrity(int probeDepth,
                                            uint256& outMissingHash,
                                            int& outMissingHeight) const {
    if (pUTXOSet == nullptr) {
        // No UTXO set wired — nothing to verify against. Treat as pass.
        return true;
    }

    std::lock_guard<std::recursive_mutex> lock(cs_main);

    if (pindexTip == nullptr || probeDepth <= 0) {
        return true;  // Empty chain or zero depth — nothing to check.
    }

    const int tipHeight = pindexTip->nHeight;
    // Genesis is exempt from the walk (matching v4.0.19 semantic): probeDepth=N
    // probes the most recent N non-genesis blocks. We translate that to
    // [tipHeight - probeDepth + 1, tipHeight] but clamp the lower bound to 1
    // so genesis itself (height 0) is never queried.
    const int fromHeight = std::max(1, tipHeight - probeDepth + 1);
    const int toHeight = tipHeight;

    UndoIntegrityFailure failure;
    if (pUTXOSet->VerifyUndoDataInRange(pindexTip, fromHeight, toHeight, failure)) {
        return true;
    }

    // Map v4.4 failure shape onto the legacy two-output API.
    outMissingHash = failure.blockHash;
    outMissingHeight = failure.height;
    return false;
}

// ============================================================================
// Phase 5: chain-selection helpers — PR5.1 scaffold (assert(false) bodies).
// ============================================================================
//
// These methods are declared in chain.h and consumed by ChainSelectorAdapter
// in src/consensus/port/chain_selector_impl.cpp. Real bodies land in PR5.3.
// PR5.1 ships the scaffold so the type system + linker are exercised
// end-to-end and the interface contract can be unit-tested for trivial
// getters (GetActiveTip, GetActiveHeight, etc.) before the algorithm goes in.

// ============================================================================
// Phase 5 Day 3 AM (PR5.3 algorithm core): real impls for the helpers
// declared in chain.h. Mirrors upstream Bitcoin Core's validation.cpp:
//   * IsBlockACandidateForActivation — eligibility predicate
//   * RecomputeCandidates           — full O(N) rebuild of the candidate set
//   * MarkBlockAsFailed             — set BLOCK_FAILED_VALID + propagate
//                                     BLOCK_FAILED_CHILD to descendants
//   * MarkBlockAsValid              — mirror: clear failure flags
//   * FindMostWorkChainImpl         — pop max-work leaf, skip invalid ancestry
//
// ActivateBestChainStep + InvalidateBlockImpl + ReconsiderBlockImpl are
// Day 3 PM (more interconnected with WAL + DisconnectTip calls).
// ============================================================================

bool CChainState::IsBlockACandidateForActivation(CBlockIndex* pindex) const
{
    if (!pindex) return false;
    if (pindex->IsInvalid()) return false;
    const uint32_t validLevel = pindex->nStatus & CBlockIndex::BLOCK_VALID_MASK;
    // Need at least full block validation to be activatable. Pre-validation
    // BLOCK_VALID_HEADER entries (PR5.3 prerequisite) are NOT candidates —
    // they live in mapBlockIndex for fork visibility, not for activation.
    return validLevel >= CBlockIndex::BLOCK_VALID_TRANSACTIONS;
}

void CChainState::RecomputeCandidates()
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // Build set of blocks that have at least one child (i.e., NOT a leaf).
    std::set<const CBlockIndex*> hasChildren;
    for (const auto& kv : mapBlockIndex) {
        if (kv.second->pprev) {
            hasChildren.insert(kv.second->pprev);
        }
    }

    m_setBlockIndexCandidates.clear();
    for (const auto& kv : mapBlockIndex) {
        CBlockIndex* p = kv.second.get();
        if (hasChildren.count(p) > 0) continue;  // not a leaf
        if (!IsBlockACandidateForActivation(p)) continue;
        m_setBlockIndexCandidates.insert(p);
    }
}

void CChainState::PruneBlockIndexCandidates()
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // v4.3.3 F6 (audit modality 2 HIGH-5): mirror upstream Bitcoin Core
    // validation.cpp:3164-3173. After a successful tip activation, any
    // candidate with strictly less work than the new tip can never be
    // selected (FindMostWorkChainImpl returns the heaviest), so erase it
    // to bound memory and avoid re-walking it on every header receipt.
    //
    // Do NOT erase the active tip itself — it stays in the set so the
    // next ActivateBestChain call's "no better candidate" path returns
    // the tip cleanly (FindMostWorkChainImpl returns pindexTip and the
    // outer loop short-circuits via pindexMostWork == pindexTip).
    if (!pindexTip) return;
    for (auto it = m_setBlockIndexCandidates.begin();
         it != m_setBlockIndexCandidates.end(); ) {
        CBlockIndex* p = *it;
        if (p != pindexTip &&
            ChainWorkGreaterThan(pindexTip->nChainWork, p->nChainWork)) {
            it = m_setBlockIndexCandidates.erase(it);
        } else {
            ++it;
        }
    }
}

void CChainState::MarkBlockAsFailed(CBlockIndex* pindex)
{
    if (!pindex) return;
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    pindex->nStatus |= CBlockIndex::BLOCK_FAILED_VALID;

    // Propagate BLOCK_FAILED_CHILD to all descendants. Worklist-style
    // walk over mapBlockIndex; iterates until no new descendants are
    // added. O(N * D) where D = depth — for mainnet (~50k) the bound is
    // small and this only runs on operator-triggered InvalidateBlock or
    // ConnectTip failure, not on every header.
    std::set<CBlockIndex*> failed{pindex};
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& kv : mapBlockIndex) {
            CBlockIndex* p = kv.second.get();
            if (failed.count(p) > 0) continue;
            if (!p->pprev) continue;
            if (failed.count(p->pprev) > 0) {
                p->nStatus |= CBlockIndex::BLOCK_FAILED_CHILD;
                failed.insert(p);
                changed = true;
            }
        }
    }

    // Any failed block must NOT remain a candidate.
    for (CBlockIndex* f : failed) {
        m_setBlockIndexCandidates.erase(f);
    }
}

void CChainState::MarkBlockAsValid(CBlockIndex* pindex)
{
    if (!pindex) return;
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // Clear failure flags on the target.
    pindex->nStatus &= ~CBlockIndex::BLOCK_FAILED_MASK;

    // Clear BLOCK_FAILED_CHILD on descendants. NOTE: BLOCK_FAILED_VALID on
    // a descendant stays — that flag means the descendant ITSELF failed
    // validation independently, not that an ancestor did. Reconsider only
    // unblocks the ancestry-implied failure.
    //
    // Phase 5 BLOCKER 2 fix (red-team audit 2026-04-26): an
    // independently-FAILED_VALID descendant must act as a BARRIER for
    // further propagation. Its OWN descendants may legitimately be
    // BLOCK_FAILED_CHILD because of the independently-failed sub-tree
    // root, NOT because of the originally-reconsidered ancestor. If we
    // propagated "reconsidered" through the still-invalid descendant
    // we'd incorrectly clear FAILED_CHILD on grandchildren that should
    // stay marked.
    std::set<CBlockIndex*> reconsidered{pindex};
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& kv : mapBlockIndex) {
            CBlockIndex* p = kv.second.get();
            if (reconsidered.count(p) > 0) continue;
            if (!p->pprev) continue;
            if (reconsidered.count(p->pprev) > 0) {
                p->nStatus &= ~CBlockIndex::BLOCK_FAILED_CHILD;
                // Only propagate "reconsidered" if this descendant is no
                // longer invalid after clearing FAILED_CHILD. An
                // independently-failed descendant blocks the walk so its
                // own sub-tree retains its inherited-failure flags.
                if (!p->IsInvalid()) {
                    reconsidered.insert(p);
                    changed = true;
                }
            }
        }
    }

    // Candidate set must be rebuilt — newly-eligible leaves may now qualify.
    RecomputeCandidates();
}

CBlockIndex* CChainState::FindMostWorkChainImpl()
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    // Pop the max-work leaf and walk its ancestry. If any ancestor is
    // invalid (BLOCK_FAILED_VALID/CHILD), mark the leaf itself
    // BLOCK_FAILED_CHILD, drop it from candidates, and retry. Mirrors
    // upstream `Chainstate::FindMostWorkChain`.
    //
    // v4.3.3 F5 (audit modality 1 I3 / modality 2 HIGH-1): also check
    // BLOCK_HAVE_DATA on every intermediate ancestor. Pre-fix the walk
    // only checked IsInvalid() — header-only ancestors (BLOCK_VALID_HEADER
    // with no BLOCK_HAVE_DATA, no BLOCK_FAILED_*) silently passed and the
    // candidate was returned to ActivateBestChainStep, which then attempted
    // the reorg and failed mid-connect on the missing data block (canary 3
    // LDN 2026-05-04). Upstream Bitcoin Core enforces this exact gate at
    // validation.cpp:3128-3157.
    //
    // Stop conditions for the walk:
    //   * pancestor == nullptr     — walked off the start of mapBlockIndex; leaf is fine
    //   * pancestor == pindexTip   — reached the active tip (have data by construction)
    //   * pancestor->IsOnMainChain() — reached an ancestor of the active tip
    //   * pancestor->nHeight == 0  — genesis (no parent; always materialized at startup)
    //
    // Failure handling differs from invalid-ancestor:
    //   * Invalid ancestor → MarkBlockAsFailed equivalent (set BLOCK_FAILED_CHILD on leaf,
    //     erase from candidates). The block is permanently disqualified.
    //   * Missing-data ancestor → erase from candidates ONLY. Do NOT mark FAILED_CHILD
    //     because the missing data may still arrive via P2P, at which point the leaf
    //     should become re-eligible. Mirrors upstream's "drop, don't fail" behavior.
    while (!m_setBlockIndexCandidates.empty()) {
        auto it = m_setBlockIndexCandidates.begin();
        CBlockIndex* pindexNew = *it;

        // Walk ancestry looking for any invalid OR missing-data ancestor.
        // The IsInvalid() check applies to the full chain INCLUSIVE of
        // pindexNew (a leaf marked FAILED_VALID must not be returned).
        // The BLOCK_HAVE_DATA check applies to INTERMEDIATES only —
        // pindexNew itself is gated upstream by IsBlockACandidateForActivation
        // and (post-F1) the predicate's literal-level semantics.
        bool fInvalidAncestor = false;
        bool fMissingData = false;
        for (CBlockIndex* pancestor = pindexNew; pancestor; pancestor = pancestor->pprev) {
            if (pancestor->IsInvalid()) {
                fInvalidAncestor = true;
                break;
            }
            // Stop walking once we reach the active chain — those blocks
            // are guaranteed to have data on disk by construction.
            if (pancestor == pindexTip) break;
            if (pancestor->IsOnMainChain()) break;
            // Genesis exemption: nHeight==0 has no parent block content
            // requirement we care about for a reorg plan (genesis is
            // materialized at startup, not via ConnectTip).
            if (pancestor->nHeight == 0) break;
            // F5 gate: every INTERMEDIATE (i.e., not the leaf itself) must
            // have BLOCK_HAVE_DATA. Skip the leaf — pindexNew's data
            // requirement is enforced by F3's pre-validation pass at
            // ActivateBestChainStep entry, which reads every block in the
            // disconnect+connect plan including the leaf.
            //
            // INVARIANT ASSUMPTION (Cursor pre-impl S4, 2026-05-04): F5's
            // intermediates-only design relies on F3 actually running and
            // catching a missing-data leaf. F3 in ActivateBestChainStep is
            // gated on `(pdb || m_testReadBlockOverride)`. In production
            // pdb is always non-null (constructed at node startup before
            // any reorg can happen), so the invariant holds. In test
            // scaffolds where neither pdb nor a test override is wired,
            // F3 is skipped and a missing-data leaf could slip through.
            // Tests that exercise FindMostWorkChainImpl directly with such
            // a state must either provide pdb/override OR explicitly add
            // BLOCK_HAVE_DATA to the leaf they synthesize.
            if (pancestor != pindexNew &&
                !(pancestor->nStatus & CBlockIndex::BLOCK_HAVE_DATA)) {
                fMissingData = true;
                break;
            }
        }

        if (!fInvalidAncestor && !fMissingData) {
            return pindexNew;
        }

        if (fInvalidAncestor) {
            // Mark this leaf as BLOCK_FAILED_CHILD (unless it's already
            // BLOCK_FAILED_VALID itself) and drop it from candidates. Retry
            // with the next-best candidate.
            if (!pindexNew->IsInvalid()) {
                pindexNew->nStatus |= CBlockIndex::BLOCK_FAILED_CHILD;
            }
            m_setBlockIndexCandidates.erase(it);
        } else {
            // fMissingData: drop without marking failed — data may still
            // arrive. RecomputeCandidates after a successful disk-write
            // re-adds the leaf. Mirrors upstream validation.cpp:3142-3155.
            m_setBlockIndexCandidates.erase(it);
        }
    }

    return nullptr;
}

// ============================================================================
// Phase 5 Day 3 PM: ActivateBestChainStep + InvalidateBlockImpl +
// ReconsiderBlockImpl.
// ============================================================================
//
// ActivateBestChainStep mirrors upstream Bitcoin Core's atomic reorg pattern:
//   1. Find common ancestor (FindFork)
//   2. WAL: BeginReorg, EnterDisconnectPhase
//   3. Disconnect-loop: walk pindexTip back to fork, DisconnectTip each
//   4. WAL: EnterConnectPhase
//   5. Connect-loop: walk fork forward to pindexMostWork, ConnectTip each
//   6. WAL: CompleteReorg on success / AbortReorg on any failure
//
// Failure handling:
//   * DisconnectTip failure → AbortReorg, return false (hard failure)
//   * ConnectTip failure   → MarkBlockAsFailed(p), set fInvalidFound=true,
//                            AbortReorg, return TRUE (caller retries with
//                            FindMostWorkChain — the failed leaf has been
//                            removed from candidates by MarkBlockAsFailed)
//   * Block-load failure   → AbortReorg, return false (hard failure)
//
// WAL call-site mapping (per plan §5.3 — re-verified Day 3 PM 2026-04-26):
//   * BeginReorg                   — line ~ActivateBestChainStep entry
//   * EnterDisconnectPhase         — before disconnect loop
//   * UpdateDisconnectProgress     — after each successful DisconnectTip
//   * EnterConnectPhase            — between disconnect and connect phases
//   * UpdateConnectProgress        — after each successful ConnectTip
//   * CompleteReorg                — only on full success
//   * AbortReorg                   — every failure return path

bool CChainState::ActivateBestChainStep(CBlockIndex* pindexMostWork,
                                        std::shared_ptr<const CBlock> pblock_optional,
                                        bool& fInvalidFound)
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);
    fInvalidFound = false;

    if (!pindexMostWork) return false;
    if (pindexMostWork == pindexTip) return true;  // already there — no-op success

    // 1) Common ancestor.
    CBlockIndex* pindexFork = pindexTip ? FindFork(pindexTip, pindexMostWork) : nullptr;
    // For genesis activation, pindexTip is null — pindexFork stays null and
    // disconnect list is empty; connect list walks pindexMostWork all the way back.

    // 1.5) v4.3.3 F4 (audit modality 1 I2 / modality 2 MEDIUM-6): reorg depth
    // cap on the port path. Mirrors legacy chain.cpp:780-792 MAX_REORG_DEPTH=100.
    //
    // Pre-fix, the port path's ActivateBestChainStep had no depth check —
    // canary 3 attempted a 441-block reorg unconstrained. The legacy cap
    // would have hard-rejected it.
    //
    // Genesis exemption: when pindexTip is null we are activating from a
    // fresh datadir / genesis-only state; the connect list legitimately
    // walks back to genesis and depth equals pindexMostWork->nHeight. No
    // reorg is happening (nothing to disconnect), so the cap is bypassed.
    //
    // v4.3.3 F8 (Layer-3 HIGH-2 + state-replay S3): on rejection, DROP the
    // candidate from m_setBlockIndexCandidates WITHOUT MarkBlockAsFailed.
    // The pre-F8 implementation called MarkBlockAsFailed(pindexMostWork)
    // which propagates BLOCK_FAILED_CHILD to all descendants — permanently
    // poisoning the canonical chain when a node restored from a >100-block-
    // stale snapshot. Depth ≠ invalid; the candidate is on a longer chain
    // we simply cannot safely reach in-process. Mirrors F5's "drop, don't
    // fail" semantics.
    //
    // S3 follow-on: depth-rejection is operationally a "we cannot catch up
    // in-process" condition. Set m_chain_needs_rebuild so the v4.3.2-M1
    // main-loop helper (Dilithion::MaybeTriggerChainRebuild) observes the
    // flag and writes the auto_rebuild marker via the user-respecting
    // config.datadir — wrapper restart triggers wipe-and-IBD recovery.
    // We DELIBERATELY do not call WriteAutoRebuildMarker directly here
    // because chain.cpp doesn't have config.datadir in scope; reusing the
    // M1 helper's plumbing is the only path that respects --datadir=PATH
    // (the H1 defect Layer-3 caught on v4.3.2-M1).
    if (pindexTip != nullptr && pindexFork != nullptr) {
        static const int64_t MAX_REORG_DEPTH = 100;  // matches legacy chain.cpp:780
        const int64_t reorg_depth =
            static_cast<int64_t>(pindexTip->nHeight) -
            static_cast<int64_t>(pindexFork->nHeight);
        if (reorg_depth > MAX_REORG_DEPTH) {
            std::cerr << "[Chain] ActivateBestChainStep: reorg depth " << reorg_depth
                      << " exceeds MAX_REORG_DEPTH=" << MAX_REORG_DEPTH
                      << " (tip h=" << pindexTip->nHeight
                      << ", fork h=" << pindexFork->nHeight
                      << "). Dropping candidate (NOT marking failed); flagging "
                      << "rebuild for wrapper-driven recovery." << std::endl;
            // F8 HIGH-2 fix: erase, don't MarkBlockAsFailed.
            m_setBlockIndexCandidates.erase(pindexMostWork);
            // F8 / S3 follow-on (F11 enriched): surface m_chain_needs_rebuild
            // with the cause = DepthRejection so the M1 main-loop helper can
            // emit a non-misleading [CRITICAL] banner ("reorg depth exceeded
            // — bootstrap stale" instead of the legacy "Persistent UndoBlock
            // failure" text). Atomic order in FlagChainRebuild guarantees
            // any observer of m_chain_needs_rebuild=true via acquire-load
            // also sees DepthRejection as the cause.
            FlagChainRebuild(ChainRebuildReason::DepthRejection);
            return false;
        }
    }

    // 2) Build disconnect list (pindexTip ... pindexFork-exclusive).
    std::vector<CBlockIndex*> disconnect;
    for (CBlockIndex* p = pindexTip; p && p != pindexFork; p = p->pprev) {
        disconnect.push_back(p);
    }

    // 3) Build connect list (pindexFork-exclusive ... pindexMostWork), then
    //    reverse so we connect from oldest to newest.
    std::vector<CBlockIndex*> connect;
    for (CBlockIndex* p = pindexMostWork; p && p != pindexFork; p = p->pprev) {
        connect.push_back(p);
    }
    std::reverse(connect.begin(), connect.end());

    // 3.5) v4.3.3 F3 (audit modality 1 I1 / modality 2 HIGH-1): pre-validate
    // every disconnect+connect block is readable BEFORE mutating chainstate.
    // Mirrors legacy Case 3 pattern at chain.cpp:874-910 (CRITICAL-C002).
    //
    // Pre-fix, the port path read blocks lazily inside the connect loop
    // (line ~2620 below) — by the time a missing-block ReadBlock failed,
    // the disconnect loop had already committed N tip rewinds and persisted
    // them via WriteBestBlock. The chain emerged truncated and required
    // operator-consent rebuild via auto_rebuild marker (canary 3, LDN
    // 2026-05-04 09:58:30: 441 disconnects committed, then ReadBlock failed
    // at the connect-list head).
    //
    // CLEAN FAIL semantics: return false with NO m_chain_needs_rebuild and
    // NO chainstate mutation. The candidate stays in the set but cannot be
    // activated until its data lands; F5's per-ancestor data gate will drop
    // it from the candidate set on the next FindMostWorkChainImpl call if
    // the missing block doesn't show up.
    //
    // Test-override symmetry: m_testReadBlockOverride is consulted with the
    // same per-block precedence as the connect loop below. Caller's optional
    // shared_ptr (pblock_optional) covers exactly one block and MUST be the
    // last connect entry (pindexMostWork) — that block's data is in-hand by
    // construction, so we skip the readability check for it.
    if (pdb || m_testReadBlockOverride) {
        CBlock blockCheck;
        for (CBlockIndex* p : disconnect) {
            bool ok = false;
            if (m_testReadBlockOverride) {
                ok = m_testReadBlockOverride(p->GetBlockHash(), blockCheck);
            } else {
                ok = pdb->ReadBlock(p->GetBlockHash(), blockCheck);
            }
            if (!ok) {
                std::cerr << "[Chain] ActivateBestChainStep: PRE-VALIDATION failed for "
                          << "disconnect block " << p->GetBlockHash().GetHex().substr(0, 16)
                          << "... at h=" << p->nHeight << ". Aborting reorg cleanly." << std::endl;
                // Clean abort: no WAL begin, no chainstate mutation, no
                // m_chain_needs_rebuild. Caller / outer loop retries.
                return false;
            }
        }
        for (CBlockIndex* p : connect) {
            // Caller's in-hand block is guaranteed-readable by construction.
            if (pblock_optional && pblock_optional->GetHash() == p->GetBlockHash()) continue;
            bool ok = false;
            if (m_testReadBlockOverride) {
                ok = m_testReadBlockOverride(p->GetBlockHash(), blockCheck);
            } else {
                ok = pdb->ReadBlock(p->GetBlockHash(), blockCheck);
            }
            if (!ok) {
                std::cerr << "[Chain] ActivateBestChainStep: PRE-VALIDATION failed for "
                          << "connect block " << p->GetBlockHash().GetHex().substr(0, 16)
                          << "... at h=" << p->nHeight << ". Aborting reorg cleanly." << std::endl;
                // Clean abort. Same semantics as above.
                return false;
            }
        }
    }

    // 4) WAL: BeginReorg with the full plan.
    if (m_reorgWAL) {
        std::vector<uint256> disconnectHashes;
        disconnectHashes.reserve(disconnect.size());
        for (CBlockIndex* p : disconnect) disconnectHashes.push_back(p->GetBlockHash());

        std::vector<uint256> connectHashes;
        connectHashes.reserve(connect.size());
        for (CBlockIndex* p : connect) connectHashes.push_back(p->GetBlockHash());

        const uint256 forkHash = pindexFork ? pindexFork->GetBlockHash() : uint256();
        const uint256 oldTipHash = pindexTip ? pindexTip->GetBlockHash() : uint256();
        const uint256 newTipHash = pindexMostWork->GetBlockHash();

        if (!m_reorgWAL->BeginReorg(forkHash, oldTipHash, newTipHash,
                                    disconnectHashes, connectHashes)) {
            return false;
        }
        m_reorgWAL->EnterDisconnectPhase();
    }

    // 5) Disconnect loop.
    // Track whether ANY disconnect succeeded — if yes, the chain has been
    // mutated mid-step and a recovery path is required on subsequent
    // failure (red-team audit BLOCKER #1, 2026-04-26).
    bool any_disconnect_committed = false;
    uint32_t disconnectedCount = 0;
    for (CBlockIndex* p : disconnect) {
        if (!DisconnectTip(p, /*force_skip_utxo=*/false)) {
            std::cerr << "[Chain] ActivateBestChainStep: DisconnectTip failed at height "
                      << p->nHeight << std::endl;
            if (m_reorgWAL) m_reorgWAL->AbortReorg();
            // BLOCKER #1 fix (red-team audit 2026-04-26): if any prior
            // disconnect succeeded, in-memory tip + on-disk UTXO have
            // already mutated. We cannot cleanly recover without
            // re-applying the disconnected blocks, which Patch B used to
            // do. Without Patch B, the safe failure mode is to surface
            // m_chain_needs_rebuild so IBDCoordinator writes the
            // auto_rebuild marker; wrapper wipes datadir + resyncs.
            //
            // Even on FIRST-disconnect failure, DisconnectTip may have
            // partially mutated UTXO/LevelDB before failing internally —
            // safer to flag rebuild unconditionally.
            std::cerr << "[CRITICAL] DisconnectTip failure mid-reorg — "
                      << (any_disconnect_committed ? "chain partially rewound. " : "")
                      << "Triggering auto_rebuild." << std::endl;
            // v4.3.3 F16: DisconnectTip mid-reorg → DisconnectTipFailure cause.
            FlagChainRebuild(ChainRebuildReason::DisconnectTipFailure);
            return false;
        }
        any_disconnect_committed = true;
        // Rewind tip after each successful disconnect (mirrors legacy
        // Case 3's per-step tip update pattern; keeps pindexTip consistent
        // with what's actually on-chain through the loop).
        pindexTip = p->pprev;
        m_cachedHeight.store(pindexTip ? pindexTip->nHeight : -1,
                             std::memory_order_release);
        // v4.3.1: persist DB best-block on every tip mutation so on-disk
        // state stays aligned with in-memory pindexTip across crash + restart.
        // Without this, a botched-reorg sequence leaves DB pointing at a hash
        // that is no longer the in-memory tip (LDN dual-hash deadlock 2026-05-04).
        // fsync per disconnect step — acceptable: production reorg depth
        // bounded by cooldown rules + per-MIK caps.
        // Test override takes precedence (consistent with legacy tail write
        // semantic at the end of this function); production path requires pdb.
        if (pindexTip && (m_testWriteBestBlockOverride || pdb)) {
            bool wbb_ok = false;
            if (m_testWriteBestBlockOverride) {
                wbb_ok = m_testWriteBestBlockOverride(pindexTip->GetBlockHash());
            } else {
                wbb_ok = pdb->WriteBestBlock(pindexTip->GetBlockHash());
            }
            if (!wbb_ok) {
                std::cerr << "[CRITICAL] ActivateBestChainStep: WriteBestBlock "
                          << "failed at disconnect step h=" << pindexTip->nHeight
                          << ". Triggering auto_rebuild." << std::endl;
                if (m_reorgWAL) m_reorgWAL->AbortReorg();
                // v4.3.3 F16: WriteBestBlock failure → WriteBestBlockFailure cause.
                FlagChainRebuild(ChainRebuildReason::WriteBestBlockFailure);
                return false;
            }
        }
        ++disconnectedCount;
        if (m_reorgWAL) m_reorgWAL->UpdateDisconnectProgress(disconnectedCount);
    }

    // 6) WAL: enter connect phase.
    if (m_reorgWAL) m_reorgWAL->EnterConnectPhase();

    // 7) Connect loop.
    uint32_t connectedCount = 0;
    for (CBlockIndex* p : connect) {
        // Choose the block source: caller's optional shared_ptr if it
        // matches by hash; otherwise read from disk via pdb.
        CBlock localBlock;
        const CBlock* pblock = nullptr;
        if (pblock_optional && pblock_optional->GetHash() == p->GetBlockHash()) {
            pblock = pblock_optional.get();
        } else if (m_testReadBlockOverride) {
            // Phase 5 Day 4 V1 TEST-ONLY: serve block from in-memory test map.
            // Production never sets this; default-empty std::function falls
            // through to the real pdb->ReadBlock path below.
            if (!m_testReadBlockOverride(p->GetBlockHash(), localBlock)) {
                if (m_reorgWAL) m_reorgWAL->AbortReorg();
                if (any_disconnect_committed) {
                    // BLOCKER #1 fix: disconnects committed; chain truncated.
                    // v4.3.3 F16: ReadBlock failure → ReadBlockFailure cause.
                    FlagChainRebuild(ChainRebuildReason::ReadBlockFailure);
                }
                return false;
            }
            pblock = &localBlock;
        } else {
            if (!pdb || !pdb->ReadBlock(p->GetBlockHash(), localBlock)) {
                std::cerr << "[Chain] ActivateBestChainStep: ReadBlock failed for "
                          << p->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
                if (m_reorgWAL) m_reorgWAL->AbortReorg();
                if (any_disconnect_committed) {
                    // BLOCKER #1 fix (red-team audit 2026-04-26): ReadBlock
                    // failure after disconnects committed → chain truncated.
                    // Surface m_chain_needs_rebuild for operator recovery.
                    std::cerr << "[CRITICAL] ReadBlock failed after committing "
                              << disconnectedCount << " disconnect(s). Triggering auto_rebuild."
                              << std::endl;
                    // v4.3.3 F16: ReadBlock failure → ReadBlockFailure cause.
                    FlagChainRebuild(ChainRebuildReason::ReadBlockFailure);
                }
                return false;
            }
            pblock = &localBlock;
        }

        if (!ConnectTip(p, *pblock)) {
            // Validation failure on a SPECIFIC block: mark it failed.
            std::cerr << "[Chain] ActivateBestChainStep: ConnectTip failed at height "
                      << p->nHeight << " — marking block failed" << std::endl;
            MarkBlockAsFailed(p);
            fInvalidFound = true;
            if (m_reorgWAL) m_reorgWAL->AbortReorg();

            // BLOCKER #1 fix (red-team audit 2026-04-26): if we already
            // disconnected blocks before this failure, the chain has been
            // truncated and there is no way to recover without re-fetching
            // the disconnected blocks (Patch B's job). The plain
            // MarkBlockAsFailed + retry pattern works ONLY when the failure
            // was on a sibling/forked candidate — when it was on a block
            // that REQUIRED prior disconnects, retry via FindMostWorkChain
            // returns to the same candidate (or no candidate) and the chain
            // is left silently shortened. Surface m_chain_needs_rebuild so
            // the operator-consent recovery path (auto_rebuild marker →
            // wrapper wipes datadir → resync) takes over.
            if (any_disconnect_committed) {
                std::cerr << "[CRITICAL] ConnectTip failed after committing "
                          << disconnectedCount << " disconnect(s). Chain truncated; "
                          << "triggering auto_rebuild." << std::endl;
                // v4.3.3 F16: ConnectTip-after-disconnect → ConnectTipFailure cause.
                FlagChainRebuild(ChainRebuildReason::ConnectTipFailure);
                return false;
            }
            // Pure no-disconnect-yet failure (e.g., genesis activation
            // failure or reconnect from current tip): caller can safely
            // re-enter FindMostWorkChain.
            return true;
        }
        // Advance tip after each successful connect.
        pindexTip = p;
        m_cachedHeight.store(p->nHeight, std::memory_order_release);

        // v4.3.3 F10 + F15: anchor the VDF grace-period clock ONLY on
        // first arrival at a height. See MaybeAnchorVdfGrace doc for
        // the legacy-equivalence rationale.
        MaybeAnchorVdfGrace(p);
        // v4.3.1: persist DB best-block on every tip mutation. Same rationale
        // as disconnect-loop write above. With per-step writes, the tail
        // post-loop write below is redundant on success but harmless.
        if (pindexTip && (m_testWriteBestBlockOverride || pdb)) {
            bool wbb_ok = false;
            if (m_testWriteBestBlockOverride) {
                wbb_ok = m_testWriteBestBlockOverride(pindexTip->GetBlockHash());
            } else {
                wbb_ok = pdb->WriteBestBlock(pindexTip->GetBlockHash());
            }
            if (!wbb_ok) {
                std::cerr << "[CRITICAL] ActivateBestChainStep: WriteBestBlock "
                          << "failed at connect step h=" << p->nHeight
                          << ". Triggering auto_rebuild." << std::endl;
                if (m_reorgWAL) m_reorgWAL->AbortReorg();
                // v4.3.3 F16: WriteBestBlock connect-step failure.
                FlagChainRebuild(ChainRebuildReason::WriteBestBlockFailure);
                return false;
            }
        }
        ++connectedCount;
        if (m_reorgWAL) m_reorgWAL->UpdateConnectProgress(connectedCount);
        // v4.3.3 F6 (audit modality 2 HIGH-5): prune candidates whose work
        // is strictly less than the new tip. Mirrors upstream Bitcoin Core
        // validation.cpp:3244 calling PruneBlockIndexCandidates() after each
        // successful step. Bounds memory; avoids re-walking stale leaves on
        // every header receipt.
        PruneBlockIndexCandidates();
    }

    // 8) Full reorg success — persist best block to disk.
    // v4.3.1: per-step writes above already persisted the latest tip on each
    // mutation. This tail write is now defense-in-depth (matches legacy
    // Case 2/2.5/3 final-write pattern at chain.cpp:560/614/1112). On
    // success this is a no-op duplicate write of the same hash already on
    // disk; if test override is set we still drive it through the same
    // sink for harness symmetry. Failure here NO LONGER triggers rebuild
    // because the per-step writes above already would have caught any
    // I/O failure mid-loop and aborted with auto_rebuild.
    if (pindexTip) {
        if (m_testWriteBestBlockOverride) {
            (void)m_testWriteBestBlockOverride(pindexTip->GetBlockHash());
        } else if (pdb) {
            (void)pdb->WriteBestBlock(pindexTip->GetBlockHash());
        }
    }
    if (m_reorgWAL) m_reorgWAL->CompleteReorg();
    return true;
}

bool CChainState::InvalidateBlockImpl(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    CBlockIndex* pindex = nullptr;
    {
        auto it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end()) return false;
        pindex = it->second.get();
    }
    if (!pindex) return false;

    // Mark target + descendants. MarkBlockAsFailed already removes the
    // failed entries from m_setBlockIndexCandidates.
    MarkBlockAsFailed(pindex);

    // Re-add eligible siblings/ancestors as candidates if they are leaves
    // (e.g., a previously-non-leaf entry whose only child just got marked
    // failed becomes a candidate).
    RecomputeCandidates();

    // NOTE: re-selection (calling ActivateBestChain) is the caller's job —
    // the RPC handler triggers it after this returns. Keeps Invalidate
    // mechanically separable from the reorg loop.
    return true;
}

bool CChainState::ReconsiderBlockImpl(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    CBlockIndex* pindex = nullptr;
    {
        auto it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end()) return false;
        pindex = it->second.get();
    }
    if (!pindex) return false;

    // MarkBlockAsValid clears failure flags and calls RecomputeCandidates
    // internally — newly-eligible leaves are re-added to the candidate set.
    MarkBlockAsValid(pindex);

    // NOTE: re-selection (calling ActivateBestChain) is the caller's job —
    // see InvalidateBlockImpl.
    return true;
}
