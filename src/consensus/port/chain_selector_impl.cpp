// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 5 — ChainSelectorAdapter PR5.1 scaffold. All 11 IChainSelector
// methods declared and stubbed with assert(false). Real bodies land in:
//   * PR5.2.A — GetChainTips (status-enum mapping)
//   * PR5.3   — ProcessNewBlock, ProcessNewHeader, FindMostWorkChain,
//               InvalidateBlock, ReconsiderBlock, IsInitialBlockDownload
//   * PR5.1   — GetActiveTip / GetActiveHeight / GetActiveTipHash /
//               LookupBlockIndex (4 trivial getters wired now to keep
//               the type-system honest and validate adapter wiring)

#include <consensus/port/chain_selector_impl.h>

#include <consensus/chain.h>
#include <consensus/chain_work.h>
#include <core/chainparams.h>             // Phase 6 PR6.1: nMapBlockIndexCap
#include <core/node_context.h>           // g_node_context.sync_coordinator + fork_staging dispatch
#include <node/block_index.h>
#include <node/blockchain_storage.h>      // Phase 11 A1: CBlockchainDB
#include <node/fork_candidate.h>          // Phase 11 A1: ForkBlock / ForkBlockStatus
#include <node/fork_manager.h>            // Phase 11 A1: ForkManager singleton
#include <node/ibd_coordinator.h>         // IsInitialBlockDownload (legacy backing kept through Phase 9+)
#include <net/port/sync_coordinator.h>    // Phase 6 PR6.5a: ISyncCoordinator surface
#include <primitives/block.h>

#include <atomic>
#include <cassert>
#include <iostream>

namespace dilithion::consensus::port {

ChainSelectorAdapter::ChainSelectorAdapter(CChainState& chainstate)
    : m_chainstate(chainstate),
      m_fork_manager(nullptr),
      m_db(nullptr)
{
}

ChainSelectorAdapter::ChainSelectorAdapter(CChainState& chainstate,
                                           ForkManager* fork_manager,
                                           CBlockchainDB* db)
    : m_chainstate(chainstate),
      m_fork_manager(fork_manager),
      m_db(db)
{
}

// ============================================================================
// PR5.1 trivial getters — real wiring (NOT assert(false)).
// ============================================================================

CBlockIndex* ChainSelectorAdapter::GetActiveTip() const
{
    return m_chainstate.GetTip();
}

int ChainSelectorAdapter::GetActiveHeight() const
{
    return m_chainstate.GetHeight();
}

uint256 ChainSelectorAdapter::GetActiveTipHash() const
{
    const CBlockIndex* tip = m_chainstate.GetTip();
    return tip ? tip->GetBlockHash() : uint256();
}

CBlockIndex* ChainSelectorAdapter::LookupBlockIndex(const uint256& hash) const
{
    return m_chainstate.GetBlockIndex(hash);
}

// ============================================================================
// PR5.2.A / PR5.3 — assert(false) until those PRs land bodies.
// ============================================================================

// PR5.3: ProcessNewBlock entry point. The frozen Phase 0 contract says
// this is called by the IBlockSink consumer (HeadersManager / block-receive
// path). Phase 5 only owns the chain-selection plumbing, not the consumer
// wiring — the production block-receive code (block_processing.cpp,
// dilithion-node.cpp main loop) still drives validation directly into
// CChainState today, and Phase 6 retires that direct call in favor of
// this adapter entry point.
//
// For PR5.3 acceptance: provide a working forwarder so when a Phase 6
// caller does invoke this, the block flows through the same sequence as
// the legacy path: validate via existing block-receive helpers, AddBlockIndex,
// then ActivateBestChain (which dispatches to the new path under env-var=1).
//
// Keeping this minimal — full ProcessNewBlock contract (validation,
// orphan handling, block-relay coordination) is Phase 6 territory.
bool ChainSelectorAdapter::ProcessNewBlock(std::shared_ptr<const CBlock> block,
                                           bool /*force_processing*/,
                                           bool* triggered_reorg)
{
    if (!block) return false;
    if (triggered_reorg) *triggered_reorg = false;

    const uint256 hash = block->GetHash();

    // If we already have a CBlockIndex for this block, look it up. Otherwise
    // ProcessNewBlock isn't responsible for synthesizing one — the caller
    // (Phase 6 IBlockSink) must have already added it via the validation
    // pipeline. Returning false here matches the upstream contract.
    CBlockIndex* pindex = m_chainstate.GetBlockIndex(hash);
    if (!pindex) {
        return false;
    }

    // ========================================================================
    // Phase 11 A1: Fork-staging dispatch.
    //
    // If a fork is being staged (created upstream in ibd_coordinator's fork-
    // detection logic) AND this block belongs to that fork's expected range,
    // route it through ForkManager INSTEAD OF calling ActivateBestChain
    // directly. This restores the legacy block_processing.cpp:447-528 +
    // 1331-1417 staging guarantee on the port path:
    //   * Block is pre-validated (PoW + nBits + MIK) via PreValidateBlock
    //     BEFORE any chainstate mutation.
    //   * Active chain is NEVER disconnected until the fork has more
    //     cumulative work AND all received blocks pass pre-validation.
    //   * Pre-validation failure cancels the fork; the original chain
    //     remains untouched.
    //
    // Mirrors block_processing.cpp's invocation pattern. nullptr-guard on
    // m_fork_manager / m_db preserves the Phase 5 ctor's behavior for tests
    // that intentionally bypass staging.
    // ========================================================================
    if (m_fork_manager != nullptr && m_db != nullptr && m_fork_manager->HasActiveFork()) {
        auto fork = m_fork_manager->GetActiveFork();
        if (fork) {
            const int32_t height = pindex->nHeight;
            if (fork->IsExpectedBlock(hash, height)) {
                // Stage the block (idempotent on duplicate height).
                if (!m_fork_manager->AddBlockToFork(*block, hash, height)) {
                    // Out-of-range or other refusal — do NOT mutate chain.
                    return false;
                }

                // Pre-validate (PoW + nBits + MIK) — only if not already done.
                ForkBlock* forkBlock = fork->GetBlockAtHeight(height);
                if (forkBlock && forkBlock->status == ForkBlockStatus::PENDING) {
                    if (!m_fork_manager->PreValidateBlock(*forkBlock, *m_db)) {
                        // Pre-validation failed — cancel fork, leave chain untouched.
                        // Mirrors block_processing.cpp:507. We do NOT invalidate
                        // headers or ban peers from inside the chain-selector
                        // adapter — those are PeerManager concerns.
                        const std::string reason =
                            "Fork block failed pre-validation: " + forkBlock->invalidReason;
                        m_fork_manager->CancelFork(reason);
                        std::cerr << "[ChainSelectorAdapter] " << reason << std::endl;
                        return false;
                    }
                }

                // Decide whether to trigger chain switch. Mirrors the
                // block_processing.cpp:1343-1374 gate:
                //   * all received fork blocks must be PREVALIDATED
                //   * fork tip must have MORE chainwork than current tip
                // Otherwise stage and wait for more blocks.
                if (!fork->AllReceivedBlocksPrevalidated()) {
                    return true;  // Staged successfully; chainstate unchanged.
                }

                const int32_t highestPrevalidated = fork->GetHighestPrevalidatedHeight();
                if (highestPrevalidated < 0) {
                    return true;  // Nothing prevalidated yet — keep staging.
                }

                ForkBlock* highestBlock = fork->GetBlockAtHeight(highestPrevalidated);
                if (!highestBlock) {
                    return true;
                }
                CBlockIndex* forkIndex = m_chainstate.GetBlockIndex(highestBlock->hash);
                CBlockIndex* currentTip = m_chainstate.GetTip();
                bool forkHasMoreWork = false;
                if (forkIndex && currentTip) {
                    // v4.3.3 F13 (Layer-3 v4.3.1 I1, deferred until now):
                    // raw uint256 op< is little-endian (memcmp-based) and
                    // is NOT a consensus-safe comparison for chainwork.
                    // ChainWorkGreaterThan is the canonical big-endian
                    // comparator (declared at consensus/pow.h:149); both
                    // legacy and port paths use it elsewhere. Switching
                    // here ensures fork-staging's "fork has more work"
                    // decision matches the comparator's verdict.
                    forkHasMoreWork = ChainWorkGreaterThan(
                        forkIndex->nChainWork, currentTip->nChainWork);
                }
                if (!forkHasMoreWork) {
                    return true;  // Wait for more fork work; chainstate unchanged.
                }

                // Trigger chain switch. TriggerChainSwitch re-acquires the
                // ForkManager mutex briefly to read m_activeFork, then
                // releases it before calling g_chainstate.ActivateBestChain.
                // ActivateBestChain owns its own cs_main locking. Lock order
                // matches the legacy path at block_processing.cpp:1374.
                bool ok = m_fork_manager->TriggerChainSwitch(g_node_context, *m_db);
                if (triggered_reorg) *triggered_reorg = ok;  // chain switch == reorg
                return ok;
            }
            // Block is not in fork range. Fall through to ActivateBestChain.
            // (block_processing.cpp's hash-mismatch + RecordHashMismatch
            // handling lives in the receive layer; staging here just sees
            // "not for this fork" and processes normally.)
        }
    }

    // No active fork OR block not for the fork OR staging disabled (Phase 5
    // ctor / nullptr db). Default Phase 5 behavior: forward to ActivateBestChain.
    bool reorg = false;
    if (!m_chainstate.ActivateBestChain(pindex, *block, reorg)) {
        return false;
    }
    if (triggered_reorg) *triggered_reorg = reorg;
    return true;
}

// Phase 5 PR5.3 prerequisite (Day 2 PM, 2026-04-26):
// Populate CChainState::mapBlockIndex with EVERY received header, matching
// upstream Bitcoin Core's invariant. Pre-validation entries get nStatus =
// BLOCK_VALID_HEADER (NOT BLOCK_VALID_TRANSACTIONS); the existing
// block-receive code path upgrades the status when the block arrives and
// validates (PR5.3 Day 3+).
//
// Guardrails (per Cursor sign-off 2026-04-26):
//   G1 — pre-validation siblings remain visible to fork detection.
//   G2 — BLOCK_VALID_HEADER-only entries are NOT IsInvalid(); BLOCK_FAILED_*
//        flags are only set on entries that reached full block validation.
//
// Returns false (orphan) if parent is missing — caller (HeadersSync /
// HeadersManager) is responsible for topological-order delivery. Returns
// true (idempotent) if entry already exists.
bool ChainSelectorAdapter::ProcessNewHeader(const CBlockHeader& header)
{
    const uint256 hash = header.GetHash();

    // Idempotency: already in mapBlockIndex (could be from a prior
    // ProcessNewHeader call OR from full-block validation). No work needed.
    if (m_chainstate.HasBlockIndex(hash)) {
        return true;
    }

    // Phase 6 PR6.1 (v1.5 §3.2 + Cursor v1.5+ A1): mapBlockIndex cap with
    // LEAF-ONLY safe eviction. When the cap is reached, evict the lowest-work
    // UNPINNED LEAF (in-degree 0 in the pprev graph) to make room for the new
    // header without rejecting it.
    //
    // Eviction safety (the v4.5.0-pull fix): CChainState::
    // EvictLowestWorkLeafNotPinned holds cs_main and frees ONLY a leaf — an
    // entry that no surviving entry references via a raw pprev pointer — and
    // never an entry in the pinned set (active chain + reorg candidates and
    // their ancestors). The prior "lowest-work-not-on-best-chain" policy could
    // free an interior fork node whose higher-work child still pointed at it
    // via pprev → use-after-free on the next chain walk. The leaf invariant
    // makes that structurally impossible. It also drops the evicted node from
    // m_setBlockIndexCandidates before the unique_ptr destroys it.
    //
    // Fail-closed fallback: if no eligible unpinned leaf exists (pathological,
    // unreachable at production cap sizes: DIL/DilV=500K cap vs ~24K chain
    // height), eviction returns false and we reject the new header. Safety net
    // for misconfigured caps, not the primary path.
    if (Dilithion::g_chainParams) {
        const int cap = Dilithion::g_chainParams->nMapBlockIndexCap;
        if (cap > 0 && m_chainstate.GetBlockIndexSize() >= static_cast<size_t>(cap)) {
            // Make room for exactly one new header: evict down to cap-1.
            const size_t target_max = static_cast<size_t>(cap) - 1;
            if (!m_chainstate.EvictLowestWorkLeafNotPinned(target_max)) {
                return false;
            }
        }
    }

    // Locate parent. A null hashPrevBlock means genesis (height 0, no parent).
    CBlockIndex* pprev = nullptr;
    int nHeight = 0;
    uint256 nChainWork = ::dilithion::consensus::ComputeChainWork(header.nBits);
    if (!header.hashPrevBlock.IsNull()) {
        pprev = m_chainstate.GetBlockIndex(header.hashPrevBlock);
        if (!pprev) {
            // Orphan — caller must order parents before children.
            return false;
        }
        // Phase 5 BLOCKER 1 fix (red-team audit 2026-04-26): refuse to
        // extend a chain rooted in a known-invalid block. Without this,
        // an attacker who learns one rejected-block hash (visible via
        // getchaintips RPC) can flood the node with headers descended
        // from it — each one adding a CBlockIndex to mapBlockIndex,
        // computing chain-work, and worsening MarkBlockAsFailed's O(N²)
        // walk. Memory grows unbounded under sustained flood.
        // Mirrors upstream Bitcoin Core net_processing.cpp::AcceptBlockHeader.
        if (pprev->IsInvalid()) {
            return false;
        }
        nHeight = pprev->nHeight + 1;
        nChainWork = ::dilithion::consensus::AddChainWork(
            pprev->nChainWork,
            ::dilithion::consensus::ComputeChainWork(header.nBits));
    }

    auto pindex = std::make_unique<CBlockIndex>(header);
    pindex->pprev = pprev;
    pindex->nHeight = nHeight;
    pindex->nChainWork = nChainWork;
    pindex->nStatus = CBlockIndex::BLOCK_VALID_HEADER;  // G2: pre-validation only
    pindex->phashBlock = hash;

    // Deterministic insertion order for the candidate-set comparator
    // tiebreak. Process-local atomic — every header receipt gets a
    // fresh sequence id.
    static std::atomic<uint32_t> s_seq{1};
    pindex->nSequenceId = s_seq.fetch_add(1, std::memory_order_relaxed);

    return m_chainstate.AddBlockIndex(hash, std::move(pindex));
}

// Phase 5 PR5.2.A: real implementation. Forwards into the (extended)
// CChainState::GetChainTips and converts each string status into the
// frozen ChainTipInfo::Status enum.
//
// Mapping (must stay in sync with chain.cpp::GetChainTips status assignments):
//   "active"        -> Status::Active
//   "invalid"       -> Status::InvalidBlock
//   "valid-fork"    -> Status::ValidFork
//   "valid-headers" -> Status::ValidHeaders
//   "unknown"       -> Status::Unknown   (also fallback for any drift)
std::vector<ChainTipInfo> ChainSelectorAdapter::GetChainTips() const
{
    using Status = ChainTipInfo::Status;
    const auto legacy_tips = m_chainstate.GetChainTips();

    std::vector<ChainTipInfo> out;
    out.reserve(legacy_tips.size());
    for (const auto& t : legacy_tips) {
        ChainTipInfo info;
        info.hash = t.hash;
        info.height = t.height;
        info.branchlen = t.branchlen;
        info.chain_work = t.chain_work;
        if      (t.status == "active")        info.status = Status::Active;
        else if (t.status == "invalid")       info.status = Status::InvalidBlock;
        else if (t.status == "valid-fork")    info.status = Status::ValidFork;
        else if (t.status == "valid-headers") info.status = Status::ValidHeaders;
        else                                  info.status = Status::Unknown;
        out.push_back(info);
    }
    return out;
}

// PR5.3: thin wrapper around CChainState::FindMostWorkChainImpl. The Impl
// version is non-const because it mutates m_setBlockIndexCandidates when
// it removes invalid-ancestor leaves. The frozen interface declares
// FindMostWorkChain const — that const is a contract about the chain
// state appearing unchanged from the caller's perspective (no tip move,
// no commit), not about the candidate-set bookkeeping. We use a const_cast
// to bridge; documented inline.
CBlockIndex* ChainSelectorAdapter::FindMostWorkChain() const
{
    return const_cast<CChainState&>(m_chainstate).FindMostWorkChainImpl();
}

bool ChainSelectorAdapter::InvalidateBlock(const uint256& hash)
{
    return m_chainstate.InvalidateBlockImpl(hash);
}

bool ChainSelectorAdapter::ReconsiderBlock(const uint256& hash)
{
    return m_chainstate.ReconsiderBlockImpl(hash);
}

// PR5.3: route through ISyncCoordinator if wired (production), otherwise
// return false (fresh-test default — no IBD context). g_node_context.
// sync_coordinator is the canonical authority on IBD state.
bool ChainSelectorAdapter::IsInitialBlockDownload() const
{
    if (g_node_context.sync_coordinator) {
        return g_node_context.sync_coordinator->IsInitialBlockDownload();
    }
    return false;
}

}  // namespace dilithion::consensus::port
