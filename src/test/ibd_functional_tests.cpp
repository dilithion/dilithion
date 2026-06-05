// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Functional tests for Initial Block Download (IBD) scenarios
 *
 * Tests end-to-end IBD behavior:
 * - Headers sync coordination
 * - Block download queueing
 * - Peer disconnection handling
 * - Timeout and retry logic
 *
 * These are higher-level tests that exercise the full IBD pipeline
 * rather than individual components.
 */

// Part of main Boost test suite (no BOOST_TEST_MODULE here)
#include <boost/test/unit_test.hpp>

#include <node/ibd_coordinator.h>
#include <core/node_context.h>
#include <consensus/chain.h>
#include <net/block_fetcher.h>
#include <net/block_tracker.h>
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/socket.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <node/block_validation_queue.h>
#include <primitives/block.h>
#include <core/chainparams.h>
#include <iostream>
#include <algorithm>

BOOST_AUTO_TEST_SUITE(ibd_functional_tests)

BOOST_AUTO_TEST_CASE(test_ibd_coordinator_integration) {
    // Test that IBD coordinator integrates correctly with all components
    if (!Dilithion::g_chainParams)
        Dilithion::g_chainParams = new Dilithion::ChainParams();
    CChainState chainstate;
    NodeContext node_context;

    // Initialize NodeContext components
    node_context.chainstate = &chainstate;
    node_context.peer_manager = std::make_unique<CPeerManager>("");
    node_context.headers_manager = std::make_unique<CHeadersManager>();
    node_context.orphan_manager = std::make_unique<COrphanManager>();
    node_context.block_tracker = std::make_unique<CBlockTracker>();
    node_context.block_fetcher = std::make_unique<CBlockFetcher>(node_context.peer_manager.get());

    CIbdCoordinator coordinator(chainstate, node_context);

    // Verify initial state
    BOOST_CHECK_EQUAL(chainstate.GetHeight(), -1);  // No blocks yet
    // Note: HeadersManager now auto-adds genesis block, so best height is 0
    BOOST_CHECK_EQUAL(node_context.headers_manager->GetBestHeight(), 0);  // Genesis added by constructor
    BOOST_CHECK_EQUAL(node_context.block_fetcher->GetInFlightCount(), 0);  // No blocks in flight
    BOOST_CHECK_EQUAL(node_context.peer_manager->GetConnectionCount(), 0);  // No peers

    // Tick should do nothing when synced
    coordinator.Tick();

    BOOST_CHECK_EQUAL(node_context.block_fetcher->GetInFlightCount(), 0);  // Still no blocks
}

BOOST_AUTO_TEST_CASE(test_block_fetcher_request_tracking) {
    // Test that block fetcher correctly tracks block requests by height
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    // Set up g_node_context.block_tracker (required by RequestBlockFromPeer)
    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    // Initially no blocks in flight
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    // Create test hashes
    uint256 hash1, hash2, hash3;
    hash1.data[0] = 1;
    hash2.data[0] = 2;
    hash3.data[0] = 3;

    // Request blocks from a mock peer (peer_id = 1)
    NodeId peer_id = 1;
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, 100, hash1));
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, 101, hash2));
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, 102, hash3));

    // Verify blocks are in flight
    BOOST_CHECK(fetcher.IsHeightInFlight(100));
    BOOST_CHECK(fetcher.IsHeightInFlight(101));
    BOOST_CHECK(fetcher.IsHeightInFlight(102));
    BOOST_CHECK(!fetcher.IsHeightInFlight(103));  // Not requested

    // Verify total count
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 3);

    // Verify per-peer count
    BOOST_CHECK_EQUAL(fetcher.GetPeerBlocksInFlight(peer_id), 3);
    BOOST_CHECK_EQUAL(fetcher.GetPeerBlocksInFlight(999), 0);  // Unknown peer

    // Restore previous tracker
    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_block_fetcher_deduplication) {
    // Test that block fetcher doesn't track duplicate heights
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    // Set up g_node_context.block_tracker (required by RequestBlockFromPeer)
    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    uint256 hash;
    hash.data[0] = 42;

    NodeId peer_id = 1;

    // Request same height twice
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, 100, hash));
    BOOST_CHECK(!fetcher.RequestBlockFromPeer(peer_id, 100, hash));  // Already tracked

    // Should only be tracked once
    BOOST_CHECK(fetcher.IsHeightInFlight(100));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 1);

    // Restore previous tracker
    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_block_fetcher_receive) {
    // Test marking blocks as received
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    // Set up g_node_context.block_tracker (required by RequestBlockFromPeer/OnBlockReceived)
    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    uint256 hash1, hash2;
    hash1.data[0] = 1;
    hash2.data[0] = 2;

    NodeId peer_id = 1;

    // Request blocks
    fetcher.RequestBlockFromPeer(peer_id, 100, hash1);
    fetcher.RequestBlockFromPeer(peer_id, 101, hash2);
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 2);

    // Receive first block
    BOOST_CHECK(fetcher.OnBlockReceived(peer_id, 100, hash1));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 1);
    BOOST_CHECK(!fetcher.IsHeightInFlight(100));
    BOOST_CHECK(fetcher.IsHeightInFlight(101));

    // Receive second block
    BOOST_CHECK(fetcher.OnBlockReceived(peer_id, 101, hash2));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    // Restore previous tracker
    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_addblock_rejects_completed_height_dedup_livelock) {
    // Regression for the DilV IBD dedup-livelock (mission dilv-dedup-livelock-fix, F-001).
    //
    // ROOT CAUSE: CBlockTracker::AddBlock (block_tracker.h:70) deduplicates ONLY against
    // m_heights (in-flight), never m_completed_heights -- while IsTracked checks BOTH.
    // During async IBD a received-but-unconnected block is an orphan whose height is
    // MarkCompleted'd (block_processing.cpp:1257). So:
    //   - GetNextBlocksToRequest (selection) skips it via IsTracked  -> the per-block
    //     request site ibd_coordinator.cpp:1674 never fires (so A2/A1 selection-layer
    //     fixes are INERT), BUT
    //   - the stall-recovery DIRECT path (ibd_coordinator.cpp:2135/2057/1657) calls
    //     RequestBlockFromPeer -> AddBlock directly, which checks only m_heights and
    //     RE-REQUESTS the completed height every ~1s -> duplicate-GETDATA storm ->
    //     the seed force-disconnects after 3 monotonic strikes -> IBD stalls.
    //
    // This test reproduces the exact tracker state and asserts the direct re-request is
    // REFUSED. It FAILS today (AddBlock returns true) and PASSES after the one-line
    // m_completed_heights guard in AddBlock.
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    const int H = 100;
    uint256 hash; hash.data[0] = 0xAB;
    const NodeId peer_id = 1;

    // 1. Request + receive the block (mirrors the async receive path: OnBlockReceived
    //    erases the in-flight tracker entry, so H leaves m_heights).
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, H, hash));
    BOOST_CHECK(fetcher.OnBlockReceived(peer_id, H, hash));
    BOOST_CHECK(!fetcher.IsHeightInFlight(H));  // no longer in-flight

    // 2. Mark the orphan height completed (the orphan receive path does exactly this
    //    via MarkCompleted(parent_height + 1) in block_processing.cpp:1257).
    g_node_context.block_tracker->MarkCompleted(H);

    // 3. Selection-layer suppression WORKS: IsTracked sees m_completed_heights, so
    //    GetNextBlocksToRequest skips H. (This is precisely why the selection-layer
    //    A2/A1 designs are inert for this bug.)
    BOOST_CHECK(g_node_context.block_tracker->IsTracked(H));
    {
        // GetNextBlocksToRequest must not re-select a completed height.
        auto sel = fetcher.GetNextBlocksToRequest(/*max_blocks=*/8, /*chain_height=*/H - 1,
                                                  /*header_height=*/H + 5);
        BOOST_CHECK(std::find(sel.begin(), sel.end(), H) == sel.end());
    }

    // 4. THE BUG / THE FIX: the DIRECT stall-recovery re-request must be REFUSED for a
    //    completed height. Pre-fix AddBlock checks only m_heights and ALLOWS it
    //    (returns true) -> duplicate GETDATA -> disconnect. This assertion FAILS today
    //    (red) and PASSES after the AddBlock m_completed_heights guard (green).
    BOOST_CHECK(!fetcher.RequestBlockFromPeer(peer_id, H, hash));
    // And the refused request must not have re-entered the IN-FLIGHT set as a side effect.
    // NOTE: use GetInFlightCount() (delegates to GetTotalInFlight() = m_heights only), NOT
    // IsHeightInFlight() -- the latter delegates to IsTracked(), which is true for
    // m_completed_heights entries too, so it is the wrong API for an "in-flight only" check.
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_clear_above_height_reenables_completed_refetch_after_reorg) {
    // Reorg-safety regression for Part A (mission dilv-dedup-livelock-fix, L-e / F-004 LOW-4).
    //
    // Part A's AddBlock rejects any height in m_completed_heights so the direct
    // stall-recovery path can't re-request a height already in the DB
    // (test_addblock_rejects_completed_height_dedup_livelock proves the reject).
    // The LOAD-BEARING-BUT-UNTESTED other half of that invariant is reorg safety:
    // after a reorg, ClearAboveHeight(fork_point) MUST clear m_completed_heights
    // above the fork point so the orphaned-then-completed height becomes
    // re-requestable again. If ClearAboveHeight did NOT clear m_completed_heights,
    // a height completed on the losing fork would be permanently un-fetchable on
    // the winning fork = a stall. This test exercises that clear-and-re-enable path
    // end to end through the public CBlockFetcher API.
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    const int H = 150;
    uint256 hash; hash.data[0] = 0xCD;
    const NodeId peer_id = 1;

    // 1. Mark height H completed (orphan-with-data path: MarkCompleted(parent+1)).
    g_node_context.block_tracker->MarkCompleted(H);
    BOOST_CHECK(g_node_context.block_tracker->IsTracked(H));

    // 2. AddBlock(H) is REFUSED while H is completed (Part A guard).
    BOOST_CHECK(!fetcher.RequestBlockFromPeer(peer_id, H, hash));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    // 3. A reorg clears everything above the fork point H-1. This MUST drop the
    //    completed flag for H (ClearAboveHeight clears m_completed_heights > fork_point).
    fetcher.ClearAboveHeight(H - 1);
    BOOST_CHECK(!g_node_context.block_tracker->IsTracked(H));  // completed flag gone

    // 4. THE RE-ENABLE: AddBlock(H) now SUCCEEDS — the height is re-requestable on
    //    the winning fork. Pre-clear it was permanently refused; post-clear it is fetchable.
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, H, hash));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 1);
    BOOST_CHECK(fetcher.IsHeightInFlight(H));

    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_completed_height_ages_out_on_divergent_hash_no_reorg) {
    // M-2 LIVENESS regression (F-013 §M-2, mission m2-liveness).
    //
    // THE BUG: the dedup fix's AddBlock rejects any height in m_completed_heights. That
    // set is cleared ONLY by Clear() (reset) and ClearAboveHeight() (reorg). On the
    // narrow divergent-hash-at-same-height-WITHOUT-reorg path, a completed height gets
    // stuck:
    //   - DB re-process (ibd_coordinator.cpp:2090) keys on the IBD-EXPECTED hash and
    //     MISSES because the stored block's hash diverges from it (a fork at that height);
    //   - GetTrackingAge(next) returns -1 (it consults m_heights only, NOT
    //     m_completed_heights, block_tracker.h:345-351), so the stall-recovery branch
    //     takes the FORCE-REQUEST path (ibd_coordinator.cpp:2132-2140);
    //   - that path calls RequestBlockFromPeer -> AddBlock, which returns FALSE
    //     (completed-height reject) -> no GETDATA pushed -> SILENT STALL.
    //   No reorg => ClearAboveHeight never fires => the entry is stuck FOREVER. The old
    //   ~1s re-request escape valve was removed and nothing replaced it for this path.
    //
    // THE FIX (option (a) — coarse age-out): MarkCompleted timestamps each entry, and the
    // existing RetryTimeoutsAndStalls cadence calls RetryStaleCompleted() to drop entries
    // older than the TTL. Once aged out, the next force-request's AddBlock SUCCEEDS and a
    // GETDATA flows -> liveness restored. Option (b) was rejected: making GetTrackingAge
    // consult m_completed_heights would change which branch is taken but the re-request at
    // :2135 would STILL hit AddBlock's completed-height reject -> still no GETDATA, unless
    // a force-clear is ALSO added -- which is exactly this age-out, just triggered
    // elsewhere. (a) is self-contained in CBlockTracker + one call site and reorg-safe.
    //
    // RED on HEAD / GREEN after fix: the divergent-completed height is REFUSED by
    // RequestBlockFromPeer (the stuck condition) and STAYS refused forever on HEAD --
    // there is no API that clears it without a reorg. After the fix, RetryStaleCompleted()
    // ages it out and the height becomes re-requestable. (This test references the new
    // RetryStaleCompleted backstop, which does not exist on HEAD; see the mission report
    // for the HEAD-compatible probe used to demonstrate the red state.)
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    const int H = 200;
    // IBD-expected (header-canonical) hash for height H.
    uint256 expected_hash; expected_hash.data[0] = 0xEE;
    // The block actually stored/completed at height H is a DIVERGENT fork block: its hash
    // differs from expected_hash. This is the M-2 precondition (fork at same height, no reorg).
    uint256 divergent_hash; divergent_hash.data[0] = 0xDD;
    const NodeId peer_id = 1;

    // 1. Height H is MarkCompleted (orphan-with-data path: MarkCompleted(parent+1)).
    //    The stored block diverges from the IBD-expected hash, and NO reorg occurs, so
    //    ClearAboveHeight is never called.
    g_node_context.block_tracker->MarkCompleted(H);
    BOOST_CHECK(g_node_context.block_tracker->IsTracked(H));

    // 2. STUCK STATE: the stall-recovery force-request for the IBD-expected hash is
    //    REFUSED because H is completed (AddBlock completed-height reject). No GETDATA.
    BOOST_CHECK(!fetcher.RequestBlockFromPeer(peer_id, H, expected_hash));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    // 3. No reorg fires. With a NON-zero TTL the entry is NOT yet stale, so the backstop
    //    leaves it in place and the height is STILL refused -- proving the age-out is
    //    time-gated and does not prematurely re-enable a freshly-completed height.
    int aged_now = g_node_context.block_tracker->RetryStaleCompleted(/*ttl_seconds=*/3600);
    BOOST_CHECK_EQUAL(aged_now, 0);
    BOOST_CHECK(g_node_context.block_tracker->IsTracked(H));
    BOOST_CHECK(!fetcher.RequestBlockFromPeer(peer_id, H, expected_hash));

    // 4. THE FIX / THE RE-ENABLE: once the entry ages past the TTL (ttl=0 forces immediate
    //    expiry of the already-inserted entry), RetryStaleCompleted clears it. The height
    //    is no longer completed, so the force-request SUCCEEDS and a GETDATA would flow.
    int aged = g_node_context.block_tracker->RetryStaleCompleted(/*ttl_seconds=*/0);
    BOOST_CHECK_EQUAL(aged, 1);
    BOOST_CHECK(!g_node_context.block_tracker->IsTracked(H));   // completed flag aged out
    BOOST_CHECK(fetcher.RequestBlockFromPeer(peer_id, H, expected_hash));  // re-requestable!
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 1);
    BOOST_CHECK(fetcher.IsHeightInFlight(H));

    // 5. REORG-SAFETY is unaffected: ClearAboveHeight still clears the (now in-flight)
    //    height above a fork point, same as before the age-out change.
    fetcher.ClearAboveHeight(H - 1);
    BOOST_CHECK(!fetcher.IsHeightInFlight(H));
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 0);

    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_headers_manager_basic) {
    // Test basic headers manager functionality
    if (!Dilithion::g_chainParams)
        Dilithion::g_chainParams = new Dilithion::ChainParams();
    CHeadersManager manager;

    // HeadersManager now auto-adds genesis in constructor, so best height is 0
    BOOST_CHECK_EQUAL(manager.GetBestHeight(), 0);

    // Create a test header
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1000000000;
    header.nBits = 0x1d00ffff;
    header.nNonce = 0;

    // Process header (should work even without parent for genesis)
    std::vector<CBlockHeader> headers;
    headers.push_back(header);

    // Note: Full processing requires proper parent linkage
    // This test verifies the manager can be instantiated and queried
    BOOST_CHECK_EQUAL(manager.GetBestHeight(), 0);  // Still 0 until more headers processed
}

BOOST_AUTO_TEST_CASE(test_peer_manager_misbehavior) {
    // Test that peer manager tracks misbehavior correctly
    CPeerManager peer_manager("");

    // Add a peer
    NetProtocol::CAddress addr;
    addr.SetIPv4(0x7F000001);  // 127.0.0.1
    addr.port = 8444;
    auto peer = peer_manager.AddPeer(addr);

    BOOST_CHECK(peer != nullptr);
    if (peer) {
        int peer_id = peer->id;

        // Initially no misbehavior (Phase 2 port: query via manager accessor)
        BOOST_CHECK_EQUAL(peer_manager.GetMisbehaviorScore(peer_id), 0);

        // Apply misbehavior penalty
        peer_manager.Misbehaving(peer_id, 10);

        // Verify score increased
        auto peer_after = peer_manager.GetPeer(peer_id);
        BOOST_CHECK(peer_after != nullptr);
        if (peer_after) {
            BOOST_CHECK_GE(peer_manager.GetMisbehaviorScore(peer_id), 10);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_ban_threshold_logic) {
    // Test that peers are marked when exceeding threshold
    CPeerManager peer_manager("");

    // Add a peer
    NetProtocol::CAddress addr;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;
    auto peer = peer_manager.AddPeer(addr);

    if (peer) {
        int peer_id = peer->id;
        int ban_threshold = CPeerManager::BAN_THRESHOLD;  // 100

        // Accumulate misbehavior up to threshold
        for (int i = 0; i < ban_threshold; i += 10) {
            peer_manager.Misbehaving(peer_id, 10);
        }

        // Verify peer score reached threshold
        auto peer_final = peer_manager.GetPeer(peer_id);
        BOOST_CHECK(peer_final != nullptr);
        if (peer_final) {
            BOOST_CHECK_GE(peer_manager.GetMisbehaviorScore(peer_id), ban_threshold);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_get_next_blocks_to_request) {
    // Test the GetNextBlocksToRequest function
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    // Set up g_node_context.block_tracker (required by GetNextBlocksToRequest)
    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    // With chain at height 10 and headers at height 20, should request blocks 11-20
    auto blocks = fetcher.GetNextBlocksToRequest(5, 10, 20);
    BOOST_CHECK_EQUAL(blocks.size(), 5);

    // First block should be 11 (chain_height + 1)
    if (!blocks.empty()) {
        BOOST_CHECK_EQUAL(blocks[0], 11);
    }

    // Restore previous tracker
    g_node_context.block_tracker = std::move(old_tracker);
}

BOOST_AUTO_TEST_CASE(test_clear_above_height) {
    // Test fork recovery by clearing blocks above a fork point
    CPeerManager peer_manager("");
    CBlockFetcher fetcher(&peer_manager);

    // Set up g_node_context.block_tracker (required by RequestBlockFromPeer/ClearAboveHeight)
    auto block_tracker = std::make_unique<CBlockTracker>();
    auto old_tracker = std::move(g_node_context.block_tracker);
    g_node_context.block_tracker = std::move(block_tracker);

    uint256 hash;
    hash.data[0] = 1;
    NodeId peer_id = 1;

    // Request blocks at heights 100-105
    for (int h = 100; h <= 105; h++) {
        hash.data[0] = static_cast<uint8_t>(h);
        fetcher.RequestBlockFromPeer(peer_id, h, hash);
    }
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 6);

    // Clear blocks above height 102 (fork recovery)
    int cleared = fetcher.ClearAboveHeight(102);
    BOOST_CHECK_EQUAL(cleared, 3);  // Heights 103, 104, 105

    // Only heights 100-102 should remain
    BOOST_CHECK_EQUAL(fetcher.GetInFlightCount(), 3);
    BOOST_CHECK(fetcher.IsHeightInFlight(100));
    BOOST_CHECK(fetcher.IsHeightInFlight(101));
    BOOST_CHECK(fetcher.IsHeightInFlight(102));
    BOOST_CHECK(!fetcher.IsHeightInFlight(103));

    // Restore previous tracker
    g_node_context.block_tracker = std::move(old_tracker);
}

// ============================================================================
// Part B seed-side rate-limited re-send test
// (dilv-dedup-livelock-fix mission, LOW-1 deterministic proof)
//
// Seam: CNetMessageProcessor::ProcessMessage() (public) dispatches to the
// private ProcessGetDataMessage which contains all the Part B logic.
//
// We drive the seam with serialized "getdata" CNetMessages. Pre-seeding the
// served-block state is automatic: the code records every block hash served
// via on_getdata in g_peer_served_blocks at the end of ProcessGetDataMessage.
//
// Time mocking: GetTime() is a thin inline over time(nullptr) with no mock
// hook. Assertions that require wall-clock gaps (cooldown) use distinct hashes
// so each gets its own per-(peer,hash) cooldown entry. Assertions that do NOT
// require time mocking (budget breach, cleanup observable) work deterministically.
//
// Disconnect observable: CleanupPeerRateLimitState() erases g_peer_served_blocks
// for the disconnected peer. We observe this by sending a post-disconnect GETDATA
// with one of the previously-served hashes and checking on_getdata fires (meaning
// the hash is no longer in the served set = cleanup occurred).
// ============================================================================
BOOST_AUTO_TEST_CASE(test_partb_seed_rate_limited_resend) {
    if (!Dilithion::g_chainParams)
        Dilithion::g_chainParams = new Dilithion::ChainParams();

    // -----------------------------------------------------------------------
    // Scaffold: a CPeerManager + CNetMessageProcessor with a minimal connman
    // so DisconnectNode() doesn't crash when called with an unknown peer ID.
    // CConnman::DisconnectNode iterates m_nodes and silently returns if the
    // peer ID is not found — safe to call on a default-constructed connman.
    // -----------------------------------------------------------------------
    CPeerManager peer_manager("");
    CNetMessageProcessor proc(peer_manager);

    // Wire g_node_context.connman so the disconnect path in ProcessGetDataMessage
    // doesn't dereference a null pointer.
    auto connman = std::make_unique<CConnman>();
    g_node_context.connman = std::move(connman);

    // Counters / observables updated by the on_getdata callback.
    std::atomic<int> getdata_call_count{0};
    std::vector<uint256> served_hashes;
    std::mutex served_mu;

    proc.SetGetDataHandler([&](int /*peer_id*/, const std::vector<NetProtocol::CInv>& items) {
        getdata_call_count.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lk(served_mu);
        for (const auto& inv : items) {
            if (inv.type == NetProtocol::MSG_BLOCK_INV)
                served_hashes.push_back(inv.hash);
        }
    });

    // Helper: build a serialized "getdata" CNetMessage for a list of CInv.
    // Mirrors CNetMessageProcessor::SerializeInvMessage + CreateGetDataMessage.
    auto make_getdata = [](const std::vector<NetProtocol::CInv>& invs) {
        CDataStream s;
        s.WriteCompactSize(invs.size());
        for (const auto& inv : invs) {
            s.WriteUint32(inv.type);
            s.WriteUint256(inv.hash);
        }
        return CNetMessage("getdata", s.GetData());
    };

    // Helper: build a single-hash CInv (MSG_BLOCK_INV).
    auto block_inv = [](uint8_t seed) {
        NetProtocol::CInv inv;
        inv.type = NetProtocol::MSG_BLOCK_INV;
        inv.hash.data[0] = seed;
        return inv;
    };

    // Pre-register test peer IDs with the peer manager so Misbehaving() is not
    // a no-op (CPeerManager::Misbehaving returns early when GetPeer(id) returns
    // null).  AddPeerWithId creates a minimal CPeer entry without requiring a
    // live socket or address.
    const int peer_a = 10, peer_b_id = 10, peer_c = 20, peer_d = 30, peer_e = 40;
    peer_manager.AddPeerWithId(peer_a);
    peer_manager.AddPeerWithId(peer_c);
    peer_manager.AddPeerWithId(peer_d);
    peer_manager.AddPeerWithId(peer_e);

    // -----------------------------------------------------------------------
    // (a) Re-send happens: a first GETDATA for an already-served block triggers
    //     a re-send (via on_getdata), not a permanent skip.
    //
    // Peer 10 serves hash A (first time, no duplicate). Then re-requests hash A
    // (now a duplicate). Under Part B, on_getdata should fire again (re-send
    // approved, within budget, cooldown just started this instant).
    //
    // NOTE: cooldown is RESEND_COOLDOWN_SECONDS=2. The cooldown timer is only
    // SET after a re-send is approved. Therefore the first re-request of a hash
    // is ALWAYS approved (no prior cooldown entry for that hash). The second
    // re-request of the SAME hash within 2s is what cooldown blocks (in (b)).
    // -----------------------------------------------------------------------
    {
        uint256 hash_a; hash_a.data[0] = 0x01;

        // First serve: non-duplicate, recorded in served set.
        getdata_call_count = 0;
        BOOST_CHECK(proc.ProcessMessage(peer_a, make_getdata({block_inv(0x01)})));
        BOOST_CHECK_EQUAL(getdata_call_count.load(), 1);  // served first time

        // Second send (duplicate): first re-request of this hash → no prior cooldown
        // entry → approved for re-send.
        int before = getdata_call_count.load();
        BOOST_CHECK(proc.ProcessMessage(peer_a, make_getdata({block_inv(0x01)})));
        // on_getdata must have fired again: re-send approved, not permanently skipped.
        BOOST_CHECK_GT(getdata_call_count.load(), before);  // (a) PASS
    }

    // -----------------------------------------------------------------------
    // (b) Cooldown: a re-request for a hash whose re-send was approved earlier in
    //     THIS test, within RESEND_COOLDOWN_SECONDS (2s), does NOT trigger another
    //     re-send and is NOT penalized (cooldown skip is silent).
    //
    //     L-d (wall-clock robustness): rather than rely on the (a)->(b) gap being
    //     < 2s (whole-second GetTime() with no mock hook — a stalled CI box could
    //     in principle straddle a 2s boundary), we make the cooldown set-and-test
    //     a single tight pair on a FRESH hash inside this block: approve a re-send
    //     for hash 0x02 (sets its cooldown at GetTime()=T), then IMMEDIATELY
    //     re-request 0x02 again. The two ProcessMessage calls are adjacent
    //     statements (microseconds apart), so the second is guaranteed to fall in
    //     [T, T+1] << 2s regardless of scheduling jitter. This removes the
    //     dependency on when (a) ran. peer_b_id = 10 (same peer as (a)).
    // -----------------------------------------------------------------------
    {
        // Serve a fresh hash 0x02 first (non-duplicate), so the next request is its
        // FIRST re-request → re-send approved → cooldown timer set at GetTime()=T.
        BOOST_CHECK(proc.ProcessMessage(peer_b_id, make_getdata({block_inv(0x02)})));   // serve
        int after_serve = getdata_call_count.load();
        BOOST_CHECK(proc.ProcessMessage(peer_b_id, make_getdata({block_inv(0x02)})));   // 1st re-request: approved
        BOOST_CHECK_GT(getdata_call_count.load(), after_serve);  // re-send happened, cooldown now set at T

        int before = getdata_call_count.load();
        int score_before = peer_manager.GetMisbehaviorScore(peer_b_id);

        // 2nd re-request of 0x02, adjacent statement → within [T, T+1] << 2s cooldown.
        BOOST_CHECK(proc.ProcessMessage(peer_b_id, make_getdata({block_inv(0x02)})));

        // on_getdata must NOT have fired: the single-item batch is purely cooldown-blocked.
        BOOST_CHECK_EQUAL(getdata_call_count.load(), before);  // (b) re-send count unchanged

        // Misbehaving must not have been called (cooldown skip is not a budget breach).
        BOOST_CHECK_EQUAL(peer_manager.GetMisbehaviorScore(peer_b_id), score_before);  // (b) no penalty
    }

    // -----------------------------------------------------------------------
    // (c) Within-budget = FREE: an honest peer doing within-budget re-requests
    //     (distinct hashes, each re-requested once) gets ZERO Misbehaving calls
    //     and is NOT disconnected.
    //
    //     Budget = RESEND_BUDGET_BLOCK_EQUIV (8) worst-case-block re-sends * 4 MiB
    //     = 32 MiB per 60s window.
    //     We issue 7 distinct-hash re-requests (under the 8 worst-case-block budget)
    //     using a fresh peer ID (peer 20) so the budget starts full.
    //     Each hash is re-requested only once (no cooldown issue — each has
    //     its own cooldown timer, and the timer is only set on re-send approval).
    //
    //     Assertion: misbehavior score stays 0 for the whole batch.
    // -----------------------------------------------------------------------
    {
        const int peer_c = 20;
        const int WITHIN_BUDGET_REQS = 7;  // 7 < 8 = budget capacity (block-equiv)

        // First: serve 15 distinct hashes to populate served set.
        {
            std::vector<NetProtocol::CInv> first_batch;
            for (int i = 0; i < WITHIN_BUDGET_REQS; ++i) {
                first_batch.push_back(block_inv(static_cast<uint8_t>(0x10 + i)));
            }
            BOOST_CHECK(proc.ProcessMessage(peer_c, make_getdata(first_batch)));
        }

        int score_before = peer_manager.GetMisbehaviorScore(peer_c);
        BOOST_CHECK_EQUAL(score_before, 0);  // sanity: no prior misbehavior

        // Re-request all 15 in a single batch (distinct hashes, each re-send
        // is the FIRST re-send for its hash so no cooldown applies).
        {
            std::vector<NetProtocol::CInv> dup_batch;
            for (int i = 0; i < WITHIN_BUDGET_REQS; ++i) {
                dup_batch.push_back(block_inv(static_cast<uint8_t>(0x10 + i)));
            }
            BOOST_CHECK(proc.ProcessMessage(peer_c, make_getdata(dup_batch)));
        }

        // Misbehaving must be ZERO: within-budget re-requests are served free.
        BOOST_CHECK_EQUAL(peer_manager.GetMisbehaviorScore(peer_c), 0);  // (c) PASS: no false positive
    }

    // -----------------------------------------------------------------------
    // (d) Budget breach penalizes: a peer that exhausts the byte budget by
    //     rotating distinct already-served hashes triggers a Misbehaving
    //     penalty on the batch that exceeds the budget.
    //
    //     Budget capacity = RESEND_BUDGET_BLOCK_EQUIV = 8 worst-case-block re-sends/window.
    //     RESEND_COST_BYTES = MAX_BLOCK_SIZE = 4 MiB per re-send.
    //     RESEND_BYTE_BUDGET_PER_WINDOW = 8 * 4 MiB = 32 MiB.
    //
    //     Strategy: serve 20 distinct hashes to peer 30 (so they're in served
    //     set). Then re-request all 20 in a single batch. The first 8 are
    //     approved (draining the budget), the 9th triggers budget_breached =
    //     true → Misbehaving is called with a non-zero penalty.
    //
    //     We use a fresh peer (peer 30) so budget starts full.
    // -----------------------------------------------------------------------
    {
        const int peer_d = 30;
        const int OVER_BUDGET_HASHES = 20;  // 20 > 8 (budget capacity, block-equiv)

        // First: serve 20 distinct hashes.
        {
            std::vector<NetProtocol::CInv> first_batch;
            for (int i = 0; i < OVER_BUDGET_HASHES; ++i) {
                first_batch.push_back(block_inv(static_cast<uint8_t>(0x30 + i)));
            }
            BOOST_CHECK(proc.ProcessMessage(peer_d, make_getdata(first_batch)));
        }

        int score_before = peer_manager.GetMisbehaviorScore(peer_d);
        BOOST_CHECK_EQUAL(score_before, 0);  // no prior misbehavior

        // Re-request all 20 (first 16 approved, 17th breaches budget).
        {
            std::vector<NetProtocol::CInv> dup_batch;
            for (int i = 0; i < OVER_BUDGET_HASHES; ++i) {
                dup_batch.push_back(block_inv(static_cast<uint8_t>(0x30 + i)));
            }
            BOOST_CHECK(proc.ProcessMessage(peer_d, make_getdata(dup_batch)));
        }

        // Misbehaving must have been called with a non-zero penalty.
        BOOST_CHECK_GT(peer_manager.GetMisbehaviorScore(peer_d), score_before);  // (d) PASS
    }

    // -----------------------------------------------------------------------
    // (e) Backstop disconnects on sustained abuse: 3 budget-breach batches
    //     accumulate 3 strikes → disconnect fires (via MAX_DEDUP_STRIKES = 3).
    //
    //     Strategy: peer 40 serves 20 hashes. We re-request all 20 three times.
    //     Each batch drains the budget past the breach threshold and increments
    //     the strike counter. After 3 batches, strikes = 3 = MAX_DEDUP_STRIKES
    //     → DisconnectNode() + CleanupPeerRateLimitState().
    //
    //     Observable: after disconnect, sending the same hash again must trigger
    //     on_getdata (the served set was erased by cleanup, so the hash is no
    //     longer a "known duplicate" and gets served as a first-time block).
    //
    //     NOTE: the byte token bucket refills at RESEND_BYTE_BUDGET_PER_WINDOW
    //     / RESEND_BUDGET_WINDOW_SECONDS per second of elapsed time. Within the
    //     same wall-clock second all three batches arrive, so the bucket stays
    //     drained (no meaningful refill). The first batch re-sends 8 hashes
    //     (budget exhausted), then reaches budget_breached, incrementing the
    //     strike counter once per batch (subsequent batches breach immediately
    //     since the budget is already drained). After 3 batches → 3 strikes →
    //     disconnect.
    //
    //     The second and third batches are NEW rotated hash sets (different
    //     seeds 0x40+20..0x40+39 and 0x40+40..0x40+59) to avoid the cooldown
    //     on hashes from the first batch that WERE approved for re-send.
    //     Budget is already exhausted from the first batch regardless.
    // -----------------------------------------------------------------------
    {
        const int peer_e = 40;
        const int HASHES_PER_BATCH = 20;   // > 8 (triggers breach on each batch)
        const int NUM_STRIKE_BATCHES = 3;  // = MAX_DEDUP_STRIKES

        // First: serve HASHES_PER_BATCH * NUM_STRIKE_BATCHES distinct hashes
        // so we have enough unique "already-served" hashes to rotate across batches.
        {
            std::vector<NetProtocol::CInv> first_serve;
            for (int b = 0; b < NUM_STRIKE_BATCHES; ++b) {
                for (int i = 0; i < HASHES_PER_BATCH; ++i) {
                    NetProtocol::CInv inv;
                    inv.type = NetProtocol::MSG_BLOCK_INV;
                    inv.hash.data[0] = static_cast<uint8_t>(0x40 + b * HASHES_PER_BATCH + i);
                    inv.hash.data[1] = 0xEE;  // distinguish from other test peers
                    first_serve.push_back(inv);
                }
            }
            BOOST_CHECK(proc.ProcessMessage(peer_e, make_getdata(first_serve)));
        }

        // Three breach batches — one per strike.
        for (int b = 0; b < NUM_STRIKE_BATCHES; ++b) {
            std::vector<NetProtocol::CInv> dup_batch;
            for (int i = 0; i < HASHES_PER_BATCH; ++i) {
                NetProtocol::CInv inv;
                inv.type = NetProtocol::MSG_BLOCK_INV;
                inv.hash.data[0] = static_cast<uint8_t>(0x40 + b * HASHES_PER_BATCH + i);
                inv.hash.data[1] = 0xEE;
                dup_batch.push_back(inv);
            }
            proc.ProcessMessage(peer_e, make_getdata(dup_batch));
        }

        // After 3 strike batches the code calls DisconnectNode(peer_e) then
        // CleanupPeerRateLimitState(peer_e), which erases g_peer_served_blocks[peer_e].
        // Observable: a now-"served" hash sent again must be treated as a first-time
        // request (no longer in the served set), so on_getdata fires.
        // Use hash data[0]=0x40, data[1]=0xEE which was in the first_serve batch.
        int before = getdata_call_count.load();
        {
            NetProtocol::CInv inv;
            inv.type = NetProtocol::MSG_BLOCK_INV;
            inv.hash.data[0] = 0x40;
            inv.hash.data[1] = 0xEE;
            BOOST_CHECK(proc.ProcessMessage(peer_e, make_getdata({inv})));
        }
        // If cleanup happened (disconnect fired), the hash is unknown → on_getdata fired.
        // If cleanup did NOT happen, the hash is in served set → duplicate path → no re-send.
        // (Well, the budget may be exhausted too, but clean state = on_getdata fires.)
        BOOST_CHECK_GT(getdata_call_count.load(), before);  // (e) PASS: cleanup confirms disconnect fired

        // Document which lever fired: the strike counter is the primary lever here.
        // MAX_DEDUP_STRIKES = 3. Each breach batch increments strikes by 1.
        // 3 batches → strikes = 3 = MAX_DEDUP_STRIKES → disconnect.
        // The RESEND_BACKSTOP_TOTAL_BYTES lever (2 GiB = 512 re-sends * 4 MiB) would
        // require ~512 re-sends to trip alone; only the FIRST batch re-sends (8, then
        // budget drained), so we are far below the backstop — the strike lever fires.
    }

    // Teardown: restore g_node_context.connman to avoid leaking into other tests.
    g_node_context.connman.reset();
}

BOOST_AUTO_TEST_SUITE_END()
