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

BOOST_AUTO_TEST_SUITE_END()
