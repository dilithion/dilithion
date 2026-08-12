// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// F-2 FOLD KAT — the reorg-depth belt in the AUTOMATIC IBD/fork-recovery path
// must route a refused >cap fork to the CONSUMED rebuild flow.
//
// Background (SECURITY-ecosystem-2026-08 FINAL_PASS §F-2): the belt in
// CIbdCoordinator::AttemptForkRecovery refused a fork deeper than
// Consensus::MAX_REORG_DEPTH and set a coordinator-local `m_requires_reindex`
// flag whose getter had ZERO production callers — every production
// RequiresReindex() reader is g_chainstate's (CChainState::m_requiresReindex),
// a DIFFERENT flag. So the belt's "route to the operator-gated rebuild flow"
// was a phantom: the node stayed on its shorter chain with no automatic
// recovery. The fix routes the refusal through the SAME consumed mechanism the
// in-band ActivateBestChain depth-cap site uses:
// m_chainstate.FlagChainRebuild(DepthRejection), which sets
// CChainState::m_chain_needs_rebuild — polled every main-loop tick by
// Dilithion::MaybeTriggerChainRebuild. (The suspenders — DisconnectToHeight's
// allowDeep=false cap — remain the load-bearing defense and are NOT touched.)
//
// These KATs drive the REAL private belt end-to-end (via the test-only
// IbdReorgBeltTestAccess friend) and assert on the flag PRODUCTION reads.
//
// Mutation control (verify-the-verifier): revert the belt's
//   m_chainstate.FlagChainRebuild(CChainState::ChainRebuildReason::DepthRejection)
// back to the old write-only `m_requires_reindex = true` and
// `belt_deep_fork_flags_depth_rejection` REDDENS — NeedsChainRebuild() stays
// false. The negative-control case (`no_belt_no_flag_when_fork_point_invalid`)
// proves the positive assertion is not green-by-construction: when the belt
// never runs, the flag is never set.

#include <boost/test/unit_test.hpp>

#include <consensus/chain.h>
#include <consensus/params.h>        // Consensus::MAX_REORG_DEPTH
#include <core/chainparams.h>
#include <core/node_context.h>
#include <node/block_index.h>
#include <node/ibd_coordinator.h>
#include <primitives/block.h>
#include <uint256.h>

// NodeContext holds unique_ptr members whose complete types are needed wherever
// a NodeContext is default-constructed/destructed. Mirror the include set that
// ibd_coordinator_tests.cpp uses to construct one, plus blockencodings.h for the
// PartiallyDownloadedBlock held inside NodeContext::partial_blocks.
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/blockencodings.h>
#include <net/connman.h>
#include <net/headers_manager.h>
#include <net/net.h>
#include <net/orphan_manager.h>
#include <net/peers.h>
#include <net/socket.h>
#include <node/block_validation_queue.h>

#include <cstdint>
#include <cstring>
#include <memory>

// TEST-ONLY accessor. Friended by BOTH CIbdCoordinator (to call the private
// AttemptForkRecovery deep-fork belt) and CHeadersManager (to seed the private
// height index so FindForkPoint yields a deeper-than-cap fork). Declared at
// global scope to match the `friend struct IbdReorgBeltTestAccess;` in each
// production header. No production code names this struct.
struct IbdReorgBeltTestAccess {
    static bool DriveForkRecovery(CIbdCoordinator& c, int chain_height,
                                  int header_height, ForkRecoveryReason reason) {
        return c.AttemptForkRecovery(chain_height, header_height, reason);
    }
    static void SeedHeightIndex(CHeadersManager& hm, const uint256& hash, int height) {
        hm.AddToHeightIndex(hash, height);
    }
};

namespace {

// Distinct non-null block hash per height (tag byte 0xC0 keeps it non-genesis-null
// and distinct from the divergent-hash tag below).
uint256 HashForHeight(int h) {
    uint256 x;
    std::memset(x.data, 0, 32);
    x.data[0] = static_cast<uint8_t>(h & 0xFF);
    x.data[1] = static_cast<uint8_t>((h >> 8) & 0xFF);
    x.data[2] = 0xC0;
    return x;
}

// A single header at a height that is guaranteed NOT to equal HashForHeight(h)
// (different tag byte) — used to inject the divergence FindForkPoint detects.
uint256 DivergentHashForHeight(int h) {
    uint256 x = HashForHeight(h);
    x.data[2] = 0xDD;  // != 0xC0 => never equal to any HashForHeight(*)
    return x;
}

// Build an in-memory validated active chain of heights 0..N on `cs`. Height 0 is
// `genesisHash` (so it can match — or, for the negative control, deliberately
// mismatch — the headers manager's seeded genesis); heights >=1 use
// HashForHeight. NO CBlockchainDB is required: the belt returns before any
// disconnect, and FindForkPoint / GetChainSnapshot walk the in-memory index only.
bool BuildInMemoryChain(CChainState& cs, int N, const uint256& genesisHash) {
    CBlockIndex* parent = nullptr;
    for (int h = 0; h <= N; ++h) {
        const uint256 hh = (h == 0) ? genesisHash : HashForHeight(h);

        auto idx = std::make_unique<CBlockIndex>();
        idx->pprev = parent;
        idx->nHeight = h;
        idx->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;
        idx->phashBlock = hh;
        std::memset(idx->nChainWork.data, 0, 32);
        idx->nChainWork.data[0] = static_cast<uint8_t>(h & 0xFF);
        idx->nChainWork.data[1] = static_cast<uint8_t>((h >> 8) & 0xFF);

        if (!cs.AddBlockIndex(hh, std::move(idx))) return false;
        parent = cs.GetBlockIndex(hh);
        if (parent == nullptr) return false;
    }
    cs.SetTip(parent);
    return true;
}

// Checkpoint-free Regtest params installed as g_chainParams, auto-restored. The
// headers manager reads g_chainParams at construction (to seed its genesis), so
// this fixture must be live BEFORE the manager is built in each test body.
struct BeltParamsFixture {
    Dilithion::ChainParams params;
    Dilithion::ChainParams* saved{nullptr};
    BeltParamsFixture() : params(Dilithion::ChainParams::Regtest()) {
        params.checkpoints.clear();
        saved = Dilithion::g_chainParams;
        Dilithion::g_chainParams = &params;
    }
    ~BeltParamsFixture() { Dilithion::g_chainParams = saved; }
};

constexpr int kTip = 200;
constexpr int kForkPoint = 100;  // fork_depth = kTip - kForkPoint = 100 (> cap 60)

}  // namespace

BOOST_AUTO_TEST_SUITE(reorg_belt_rebuild_flag_tests)

// PRIMARY (F-2): a > MAX_REORG_DEPTH fork refused by the AttemptForkRecovery belt
// must set the CONSUMED rebuild flag (NeedsChainRebuild) with cause DepthRejection
// — the flag the node main loop actually polls. Mutation control: revert the belt
// to the write-only m_requires_reindex and this REDDENS.
BOOST_FIXTURE_TEST_CASE(belt_deep_fork_flags_depth_rejection, BeltParamsFixture) {
    NodeContext ctx;
    ctx.headers_manager = std::make_unique<CHeadersManager>();

    // Match the manager's seeded genesis so FindForkPoint's Step-1 genesis check
    // passes and last_common_height can advance to the fork point.
    auto genesis = ctx.headers_manager->GetHeadersAtHeight(0);
    BOOST_REQUIRE_MESSAGE(!genesis.empty(),
        "headers manager must seed a genesis at height 0");
    const uint256 genesisHash = genesis[0];

    CChainState cs;
    ctx.chainstate = &cs;
    BOOST_REQUIRE(BuildInMemoryChain(cs, kTip, genesisHash));
    BOOST_REQUIRE_EQUAL(cs.GetHeight(), kTip);

    // Seed a MATCHING single header at the fork point and a DIVERGENT single header
    // one height above it (nothing higher) => FindForkPoint returns kForkPoint, so
    // fork_depth = kTip - kForkPoint = 100 (> MAX_REORG_DEPTH).
    IbdReorgBeltTestAccess::SeedHeightIndex(
        *ctx.headers_manager, HashForHeight(kForkPoint), kForkPoint);
    IbdReorgBeltTestAccess::SeedHeightIndex(
        *ctx.headers_manager, DivergentHashForHeight(kForkPoint + 1), kForkPoint + 1);

    CIbdCoordinator coordinator(cs, ctx);

    // Precondition: a fresh chainstate is NOT flagged (guards green-by-absence —
    // the assertion below can only pass because the belt set the flag).
    BOOST_REQUIRE(!cs.NeedsChainRebuild());

    const bool proceeded = IbdReorgBeltTestAccess::DriveForkRecovery(
        coordinator, kTip, kTip, ForkRecoveryReason::LAYER1_TIP_MISMATCH);

    // The belt refuses the deep disconnect (returns false) ...
    BOOST_CHECK_MESSAGE(!proceeded,
        "a > MAX_REORG_DEPTH fork must be REFUSED by the belt (return false)");
    // ... and routes to the CONSUMED rebuild path — the flag production reads.
    BOOST_CHECK_MESSAGE(cs.NeedsChainRebuild(),
        "the refused deep fork must set the CONSUMED rebuild flag (NeedsChainRebuild), "
        "not the removed write-only phantom");
    BOOST_CHECK_MESSAGE(
        cs.GetChainRebuildReason() == CChainState::ChainRebuildReason::DepthRejection,
        "rebuild cause must be DepthRejection (legitimate deep fork); got "
        << static_cast<uint32_t>(cs.GetChainRebuildReason()));
}

// DISCRIMINATOR (anti-vacuity): when FindForkPoint does not yield a deep fork the
// belt never runs, so the consumed flag stays false. Here the chainstate genesis
// deliberately MISMATCHES the headers-manager genesis => FindForkPoint returns 0
// => AttemptForkRecovery bails at the invalid-fork-point guard BEFORE the belt.
// This proves the PRIMARY case's "flag true" is caused by the belt, not by the
// harness merely constructing a flagged chainstate.
BOOST_FIXTURE_TEST_CASE(no_belt_no_flag_when_fork_point_invalid, BeltParamsFixture) {
    NodeContext ctx;
    ctx.headers_manager = std::make_unique<CHeadersManager>();

    const uint256 mismatchedGenesis = HashForHeight(0);
    auto genesis = ctx.headers_manager->GetHeadersAtHeight(0);
    BOOST_REQUIRE(!genesis.empty());
    BOOST_REQUIRE_MESSAGE(genesis[0] != mismatchedGenesis,
        "test needs the manager's genesis to differ from the synthetic one");

    CChainState cs;
    ctx.chainstate = &cs;
    BOOST_REQUIRE(BuildInMemoryChain(cs, kTip, mismatchedGenesis));
    BOOST_REQUIRE_EQUAL(cs.GetHeight(), kTip);

    CIbdCoordinator coordinator(cs, ctx);
    BOOST_REQUIRE(!cs.NeedsChainRebuild());

    const bool proceeded = IbdReorgBeltTestAccess::DriveForkRecovery(
        coordinator, kTip, kTip, ForkRecoveryReason::LAYER1_TIP_MISMATCH);

    BOOST_CHECK_MESSAGE(!proceeded, "an invalid fork point must return false");
    BOOST_CHECK_MESSAGE(!cs.NeedsChainRebuild(),
        "no belt fired => the consumed rebuild flag must remain unset");
}

BOOST_AUTO_TEST_SUITE_END()
