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

    // Check if already exists (normal during concurrent block processing)
    if (mapBlockIndex.count(hash) > 0) {
        return false;
    }

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

bool CChainState::ActivateBestChain(CBlockIndex* pindexNew, const CBlock& block, bool& reorgOccurred) {
    // CRITICAL-1 FIX: Acquire lock before accessing shared state
    // This protects pindexTip, mapBlockIndex, and all chain operations
    std::lock_guard<std::recursive_mutex> lock(cs_main);

    reorgOccurred = false;

    if (pindexNew == nullptr) {
        std::cerr << "[Chain] ERROR: ActivateBestChain called with nullptr" << std::endl;
        return false;
    }

    // MAINNET SECURITY: Validate block against checkpoint if one exists at this height
    // This ensures we never accept a block with a hash that doesn't match a checkpoint.
    // Testnet has no checkpoints, so this check will always pass on testnet.
    if (Dilithion::g_chainParams) {
        if (!Dilithion::g_chainParams->CheckpointCheck(pindexNew->nHeight, pindexNew->GetBlockHash())) {
            std::cerr << "[Chain] ERROR: Block hash does not match checkpoint!" << std::endl;
            std::cerr << "  Height: " << pindexNew->nHeight << std::endl;
            std::cerr << "  Block hash: " << pindexNew->GetBlockHash().GetHex() << std::endl;
            std::cerr << "  This may indicate an attack or corrupted block data." << std::endl;
            return false;
        }
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

        // v4.0.21 — Patch B: Capture the old tip's block data BEFORE disconnect so
        // we can roll back if ConnectTip(pindexNew) fails.
        //
        // Pre-fix bug (incident 2026-04-25): if ConnectTip below failed, undo data
        // for oldTip was already deleted by DisconnectTip → UndoBlock → batch.Delete(undoKey).
        // The function then returned false, leaving "block-is-tip-but-undo-missing".
        // Any subsequent reorg attempt would deterministically fail trying to disconnect
        // that block, looping forever. Fix B: re-apply old tip on failure.
        CBlockIndex* pindexOldTip = pindexTip;
        CBlock oldTipBlock;
        bool oldTipBlockLoaded = false;
        if (pdb != nullptr && pindexOldTip != nullptr) {
            oldTipBlockLoaded = pdb->ReadBlock(pindexOldTip->GetBlockHash(), oldTipBlock);
            if (!oldTipBlockLoaded) {
                std::cerr << "[Chain] WARN: Could not pre-load old tip block for Case 2.5 rollback safety; "
                          << "proceeding without rollback capability for height " << pindexOldTip->nHeight << std::endl;
            }
        }

        // Disconnect current tip
        if (!DisconnectTip(pindexTip)) {
            std::cerr << "[Chain] ERROR: Failed to disconnect tip for VDF replacement" << std::endl;
            return false;
        }

        // Connect new block (shares same parent as old tip)
        if (!ConnectTip(pindexNew, block)) {
            std::cerr << "[Chain] CRITICAL: Failed to connect VDF replacement block" << std::endl;

            // v4.0.21 — Patch B: roll back to old tip to restore undo data.
            if (oldTipBlockLoaded && pindexOldTip != nullptr) {
                std::cerr << "[Chain] Case 2.5 rollback: re-applying old tip "
                          << pindexOldTip->GetBlockHash().GetHex().substr(0, 16)
                          << " at height " << pindexOldTip->nHeight << std::endl;
                if (!ConnectTip(pindexOldTip, oldTipBlock)) {
                    std::cerr << "[CRITICAL] Case 2.5 rollback FAILED — chain state inconsistent at height "
                              << pindexOldTip->nHeight << ". Triggering auto_rebuild." << std::endl;
                    m_chain_needs_rebuild.store(true);
                    return false;
                }
                pindexTip = pindexOldTip;
                m_cachedHeight.store(pindexOldTip->nHeight, std::memory_order_release);
                std::cerr << "[Chain] Case 2.5 rollback succeeded; old tip restored." << std::endl;
            } else {
                std::cerr << "[CRITICAL] Case 2.5 ConnectTip failed and old tip block was unreadable. "
                          << "Cannot roll back. Triggering auto_rebuild." << std::endl;
                m_chain_needs_rebuild.store(true);
            }
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
    // is still within its cooldown period.  This prevents cheaters from
    // bypassing the voluntary miner-side cooldown.
    //
    // STALL EXEMPTION: If the timestamp gap between this block and its
    // parent is large enough, bypass cooldown enforcement.  During a
    // stall all miners may be in cooldown, creating a permanent deadlock
    // where no block can ever be produced (BUG #274).
    //
    // V2 (stallExemptionV2Height): Threshold raised from 300s to 600s.
    // Additionally, stall bypass requires a different miner from the
    // previous block (unless solo mining).  Prevents private fork mining
    // via repeated stall exemption abuse.
    if (block.IsVDFBlock() && g_node_context.cooldown_tracker && !assumeValid) {
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
    pindex->nStatus |= CBlockIndex::BLOCK_VALID_CHAIN;

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

            // Determine status and branch length
            if (pindex == pindexTip) {
                tip.status = "active";
                tip.branchlen = 0;
            } else {
                // Find fork point with main chain
                const CBlockIndex* pWalk = pindex;
                int branchlen = 0;
                // Walk back to find where this tip diverges from main chain
                // A block is on the main chain if walking from tip backwards reaches it
                while (pWalk && pWalk->nHeight > 0) {
                    // Check if this block is on the main chain by comparing with main chain at same height
                    bool onMainChain = false;
                    if (pWalk->nHeight <= pindexTip->nHeight) {
                        // Walk main chain to this height
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
                tip.status = "valid-fork";
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
        m_chain_needs_rebuild.store(true);
    }
}

void CChainState::ResetUndoFailureCounter() {
    std::lock_guard<std::mutex> lock(m_undo_failure_mutex);
    m_consecutive_undo_failures.store(0);
    m_last_undo_failure_hash = uint256();  // default-constructed = zeroed (no SetNull on this type)
}

void CChainState::ClearChainRebuildFlag() {
    m_chain_needs_rebuild.store(false);
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

    CBlockIndex* pwalker = pindexTip;
    int probed = 0;
    while (pwalker != nullptr && probed < probeDepth) {
        // Stop walking at genesis — we don't need to reorg past it, so verifying
        // its undo entry adds no operational value. (ApplyBlock does write an
        // undo_<hash> record for every connected block including genesis when
        // the genesis path runs through it; we just don't need to assert that
        // here. Per Cursor review 2026-04-25.)
        if (pwalker->pprev == nullptr) {
            break;
        }

        const uint256 hash = pwalker->GetBlockHash();
        if (!pUTXOSet->HasUndoData(hash)) {
            outMissingHash = hash;
            outMissingHeight = pwalker->nHeight;
            return false;
        }

        pwalker = pwalker->pprev;
        ++probed;
    }
    return true;
}
