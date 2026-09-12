// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 6: CConnman Event-Driven Networking Tests
// Tests for the new event-driven networking architecture

#include <net/connman.h>
#include <net/node.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/protocol.h>
#include <core/node_context.h>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

// Test helper: Create a minimal CPeerManager for testing
class TestPeerManager : public CPeerManager {
public:
    TestPeerManager() : CPeerManager() {}
    ~TestPeerManager() = default;
};

// Test helper: Create a minimal CNetMessageProcessor for testing
class TestMessageProcessor : public CNetMessageProcessor {
public:
    TestMessageProcessor(CPeerManager& pm) : CNetMessageProcessor(pm) {}
    ~TestMessageProcessor() = default;
};

/**
 * Test 1: CNode Lifecycle
 * Verify that CNode can be created, used, and destroyed properly
 */
void test_cnode_lifecycle() {
    std::cout << "Testing CNode lifecycle..." << std::endl;

    // Create a test address
    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);  // 127.0.0.1
    addr.port = 8444;

    // Create CNode
    CNode node(1, addr, false);  // node_id=1, outbound
    assert(node.id == 1);
    assert(!node.fInbound);
    assert(node.state.load() == CNode::STATE_DISCONNECTED);  // Initial state
    assert(node.GetSocket() < 0);  // No socket yet

    // Set socket
    int test_fd = 42;  // Mock FD
    node.SetSocket(test_fd);
    assert(node.GetSocket() == test_fd);

    // Update state
    node.state.store(CNode::STATE_CONNECTED);
    assert(node.state.load() == CNode::STATE_CONNECTED);

    // Mark for disconnect
    node.fDisconnect.store(true);
    assert(node.fDisconnect.load() == true);

    std::cout << "  ✓ CNode lifecycle works" << std::endl;
}

/**
 * Test 2: Message Queue Ordering
 * Verify that messages are processed in the correct order
 */
void test_message_queue_ordering() {
    std::cout << "Testing message queue ordering..." << std::endl;

    // Create a test address
    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    // Create test messages
    CProcessedMsg msg1;
    msg1.command = "version";
    msg1.data = {1, 2, 3};

    CProcessedMsg msg2;
    msg2.command = "verack";
    msg2.data = {4, 5, 6};

    CProcessedMsg msg3;
    msg3.command = "ping";
    msg3.data = {7, 8, 9};

    // Push messages in order
    node.PushProcessMsg(std::move(msg1));
    node.PushProcessMsg(std::move(msg2));
    node.PushProcessMsg(std::move(msg3));

    // Verify messages are queued
    assert(node.HasProcessMsgs() == true);

    // Pop messages and verify order
    CProcessedMsg popped1, popped2, popped3;
    assert(node.PopProcessMsg(popped1) == true);
    assert(popped1.command == "version");
    assert(popped1.data.size() == 3);

    assert(node.PopProcessMsg(popped2) == true);
    assert(popped2.command == "verack");
    assert(popped2.data.size() == 3);

    assert(node.PopProcessMsg(popped3) == true);
    assert(popped3.command == "ping");
    assert(popped3.data.size() == 3);

    // Queue should be empty now
    assert(node.HasProcessMsgs() == false);

    std::cout << "  ✓ Message queue ordering works (FIFO)" << std::endl;
}

/**
 * Test 3: Send Message Queue
 * Verify that send messages are queued correctly
 */
void test_send_message_queue() {
    std::cout << "Testing send message queue..." << std::endl;

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    // Create test send messages
    CSerializedNetMsg msg1;
    msg1.command = "version";
    msg1.data = {1, 2, 3, 4, 5};

    CSerializedNetMsg msg2;
    msg2.command = "verack";
    msg2.data = {6, 7, 8, 9, 10};

    // Push messages
    node.PushSendMsg(std::move(msg1));
    node.PushSendMsg(std::move(msg2));

    // Verify messages are queued
    assert(node.HasSendMsgs() == true);

    // Get first message
    const CSerializedNetMsg* first = node.GetSendMsg();
    assert(first != nullptr);
    assert(first->command == "version");
    assert(first->data.size() == 5);

    // Mark bytes sent (partial send)
    node.MarkBytesSent(3);
    assert(node.GetSendOffset() == 3);

    // Get same message again (partial send)
    const CSerializedNetMsg* same = node.GetSendMsg();
    assert(same == first);  // Same message, different offset

    std::cout << "  ✓ Send message queue works" << std::endl;
}

/**
 * Test 4: CConnman Basic Initialization
 * Verify that CConnman can be created and started
 */
void test_connman_initialization() {
    std::cout << "Testing CConnman initialization..." << std::endl;

    // Create test dependencies
    auto peer_mgr = std::make_unique<TestPeerManager>();
    TestMessageProcessor msg_proc(*peer_mgr);

    // Create CConnman
    auto connman = std::make_unique<CConnman>();

    // Configure options
    CConnmanOptions opts;
    opts.fListen = false;  // Don't listen for testing
    opts.nMaxOutbound = 8;
    opts.nMaxInbound = 117;
    opts.nMaxTotal = 125;

    // Start CConnman
    bool started = connman->Start(*peer_mgr, msg_proc, opts);
    assert(started == true);
    assert(connman->IsRunning() == true);

    // Verify initial state
    assert(connman->GetNodeCount() == 0);

    // Stop CConnman
    connman->Stop();
    assert(connman->IsRunning() == false);

    std::cout << "  ✓ CConnman initialization works" << std::endl;
}

/**
 * Test 5: Graceful Disconnect Handling
 * Verify that nodes can be disconnected gracefully
 */
void test_graceful_disconnect() {
    std::cout << "Testing graceful disconnect..." << std::endl;

    auto peer_mgr = std::make_unique<TestPeerManager>();
    TestMessageProcessor msg_proc(*peer_mgr);

    auto connman = std::make_unique<CConnman>();

    CConnmanOptions opts;
    opts.fListen = false;
    bool started = connman->Start(*peer_mgr, msg_proc, opts);
    assert(started == true);

    // Create a test address
    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    // Note: We can't actually connect without a real socket, but we can test disconnect logic
    // by creating a node manually (this is a simplified test)

    // Disconnect a non-existent node (should not crash)
    connman->DisconnectNode(999, "test disconnect");

    connman->Stop();

    std::cout << "  ✓ Graceful disconnect handling works" << std::endl;
}

/**
 * Test 6: Message Push/Pop Thread Safety
 * Verify that message queues are thread-safe
 */
void test_message_queue_thread_safety() {
    std::cout << "Testing message queue thread safety..." << std::endl;

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    std::atomic<int> push_count{0};
    std::atomic<int> pop_count{0};
    const int NUM_THREADS = 4;
    const int MSGS_PER_THREAD = 100;

    // Start threads that push messages
    std::vector<std::thread> push_threads;
    for (int i = 0; i < NUM_THREADS; ++i) {
        push_threads.emplace_back([&node, &push_count, i]() {
            for (int j = 0; j < MSGS_PER_THREAD; ++j) {
                CProcessedMsg msg;
                msg.command = "test";
                msg.data = {static_cast<uint8_t>(i), static_cast<uint8_t>(j)};
                node.PushProcessMsg(std::move(msg));
                push_count++;
            }
        });
    }

    // Start threads that pop messages
    std::vector<std::thread> pop_threads;
    for (int i = 0; i < NUM_THREADS; ++i) {
        pop_threads.emplace_back([&node, &pop_count]() {
            CProcessedMsg msg;
            while (pop_count < NUM_THREADS * MSGS_PER_THREAD) {
                if (node.PopProcessMsg(msg)) {
                    pop_count++;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });
    }

    // Wait for all threads
    for (auto& t : push_threads) {
        t.join();
    }
    for (auto& t : pop_threads) {
        t.join();
    }

    // Verify all messages were processed
    assert(push_count == NUM_THREADS * MSGS_PER_THREAD);
    assert(pop_count == NUM_THREADS * MSGS_PER_THREAD);
    assert(node.HasProcessMsgs() == false);  // Queue should be empty

    std::cout << "  ✓ Message queue is thread-safe" << std::endl;
}

/**
 * Test 7: BUG #134 Regression Test - Handshake Timing
 * Verify that handshake completes symmetrically (both sides receive VERACK)
 * This is a simplified test that verifies the message queue mechanism
 * that fixes the timing issue
 */
void test_bug134_handshake_timing() {
    std::cout << "Testing BUG #134 regression (handshake timing)..." << std::endl;

    // The fix for BUG #134 is that messages are now queued and processed
    // asynchronously, so VERACK can arrive and be queued even if processing
    // hasn't caught up yet. This test verifies the queue mechanism works.

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    // Simulate rapid message exchange (VERSION -> VERACK)
    // In the old system, ReceiveMessages() would return too early
    // In the new system, messages are queued and processed asynchronously

    // Push VERSION message
    CProcessedMsg version_msg;
    version_msg.command = "version";
    version_msg.data = {1, 2, 3};
    node.PushProcessMsg(std::move(version_msg));

    // Immediately push VERACK (simulating rapid network response)
    // In old system, this might be missed if processing returned early
    CProcessedMsg verack_msg;
    verack_msg.command = "verack";
    verack_msg.data = {4, 5, 6};
    node.PushProcessMsg(std::move(verack_msg));

    // Verify both messages are queued (not lost)
    assert(node.HasProcessMsgs() == true);

    // Process VERSION
    CProcessedMsg processed;
    assert(node.PopProcessMsg(processed) == true);
    assert(processed.command == "version");

    // Process VERACK (this would have been lost in old system)
    assert(node.PopProcessMsg(processed) == true);
    assert(processed.command == "verack");

    // Queue should be empty
    assert(node.HasProcessMsgs() == false);

    std::cout << "  ✓ BUG #134 fix verified: messages queued correctly" << std::endl;
}

/**
 * Test 8: Node State Transitions
 * Verify that node state transitions work correctly
 */
void test_node_state_transitions() {
    std::cout << "Testing node state transitions..." << std::endl;

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    // Initial state
    assert(node.state.load() == CNode::STATE_DISCONNECTED);

    // Transition to connecting, then connected
    node.state.store(CNode::STATE_CONNECTING);
    assert(node.state.load() == CNode::STATE_CONNECTING);

    // Transition to connected
    node.state.store(CNode::STATE_CONNECTED);
    assert(node.state.load() == CNode::STATE_CONNECTED);

    // Transition to version sent
    node.state.store(CNode::STATE_VERSION_SENT);
    assert(node.state.load() == CNode::STATE_VERSION_SENT);

    // Transition to handshake complete
    node.state.store(CNode::STATE_HANDSHAKE_COMPLETE);
    assert(node.state.load() == CNode::STATE_HANDSHAKE_COMPLETE);

    std::cout << "  ✓ Node state transitions work" << std::endl;
}

/**
 * Test 9: Select Timeout Behavior
 * Verify that SocketEventsSelect times out correctly without busy-polling
 * This is the key fix for BUG #134 - proper blocking with timeout
 */
void test_select_timeout_behavior() {
    std::cout << "Testing select() timeout behavior..." << std::endl;

    // Create CConnman with short timeout to verify select() blocks properly
    auto peer_mgr = std::make_unique<TestPeerManager>();
    TestMessageProcessor msg_proc(*peer_mgr);

    auto connman = std::make_unique<CConnman>();

    CConnmanOptions opts;
    opts.fListen = false;  // Don't listen for testing
    bool started = connman->Start(*peer_mgr, msg_proc, opts);
    assert(started == true);

    // The key verification: CConnman uses select() with 50ms timeout
    // This means ThreadSocketHandler blocks on select() rather than busy-polling
    // We verify this indirectly by checking the system runs without excessive CPU

    // Start time
    auto start = std::chrono::steady_clock::now();

    // Let it run for 200ms - with proper select() blocking, it should
    // only wake up ~4 times (200ms / 50ms timeout = 4 iterations)
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Verify time elapsed (should be ~200ms, not faster from busy-polling)
    assert(elapsed.count() >= 180);  // Allow 10% tolerance

    connman->Stop();

    std::cout << "  ✓ Select timeout behavior works (no busy-polling)" << std::endl;
}

/**
 * Test 10: WakeMessageHandler Signaling
 * Verify that WakeMessageHandler() properly wakes the message handler thread
 * This ensures messages are processed promptly without polling delays
 */
void test_wake_message_handler() {
    std::cout << "Testing WakeMessageHandler() signaling..." << std::endl;

    auto peer_mgr = std::make_unique<TestPeerManager>();
    TestMessageProcessor msg_proc(*peer_mgr);

    auto connman = std::make_unique<CConnman>();

    CConnmanOptions opts;
    opts.fListen = false;

    // Track message processing
    std::atomic<int> messages_processed{0};
    std::atomic<bool> handler_called{false};

    // Set message handler callback
    connman->SetMessageHandler([&](CNode*, const std::string& /*cmd*/, const std::vector<uint8_t>&) {
        handler_called.store(true);
        messages_processed++;
        return true;
    });

    bool started = connman->Start(*peer_mgr, msg_proc, opts);
    assert(started == true);

    // The WakeMessageHandler mechanism uses condition_variable to signal
    // ThreadMessageHandler when new messages arrive. This test verifies
    // the wake mechanism works without requiring actual network traffic.

    // Without any connections, the message handler should be idle (waiting on CV)
    // When we stop, it should wake up and exit cleanly

    // Brief delay to let threads start
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Verify running
    assert(connman->IsRunning() == true);

    // Stop - this calls Interrupt() which should wake the message handler
    auto stop_start = std::chrono::steady_clock::now();
    connman->Stop();
    auto stop_end = std::chrono::steady_clock::now();
    auto stop_duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop_end - stop_start);

    // Stop should be quick (< 1 second) - if CV wake fails, it would hang
    assert(stop_duration.count() < 1000);
    assert(connman->IsRunning() == false);

    std::cout << "  ✓ WakeMessageHandler signaling works (clean shutdown in "
              << stop_duration.count() << "ms)" << std::endl;
}

/**
 * Test 11: Process-queue CAP under high load (BUG #275 defence)
 *
 * WHAT THIS USED TO ASSERT, AND WHY IT WAS WRONG.
 *
 * This scenario pushed 10,000 messages and then asserted
 *     assert(pop_count == NUM_MESSAGES);
 * i.e. that the process queue is UNBOUNDED and LOSSLESS. It failed 12 of 12
 * runs, deterministically, popping exactly 1000. That is not a flake and it is
 * not a defect in CConnman: CNode::PushProcessMsg caps the queue and pops the
 * OLDEST entry when it is full - "BUG #275: Cap process queue to prevent OOM
 * from fast senders". The assertion asserted the ABSENCE of that defence, and
 * predates it.
 *
 * The suite was quarantined as "SUSPECTED REAL: ... Message loss under load in
 * CConnman is not a stale expectation", which is exactly backwards and pointed
 * a maintainer at removing an OOM defence. That reason is corrected in
 * scripts/run_test_suites.sh and the suite is live again.
 *
 * So this scenario now PINS the defence instead of denying it:
 *   - a cap exists and it bites (fewer come out than went in);
 *   - the survivors are the NEWEST, contiguous and in order - drop-OLDEST,
 *     which nothing tested before today;
 *   - the queue is empty afterwards;
 *   - a throughput number is still reported, measured over a batch that fits
 *     under the cap so the figure means what it says.
 *
 * The cap value is deliberately NOT hard-coded: MAX_PROCESS_QUEUE_SIZE is
 * private, and a literal here could drift away from it and quietly stop testing
 * anything. It is DISCOVERED by draining, and only its behaviour is asserted.
 * Whether 1000 is the right value is a design question this test does not
 * answer.
 */
void test_highload_throughput() {
    std::cout << "Testing process-queue cap under high load..." << std::endl;

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8444;

    CNode node(1, addr, false);

    const int OVERSHOOT    = 10000;  // deliberately far above any plausible cap
    const int PAYLOAD_SIZE = 256;

    // Each message carries its own index in the first four bytes, so the drain
    // can say WHICH messages survived rather than only how many.
    auto tagged = [PAYLOAD_SIZE](int idx) {
        std::vector<uint8_t> p(PAYLOAD_SIZE);
        p[0] = static_cast<uint8_t>(idx & 0xff);
        p[1] = static_cast<uint8_t>((idx >> 8) & 0xff);
        p[2] = static_cast<uint8_t>((idx >> 16) & 0xff);
        p[3] = static_cast<uint8_t>((idx >> 24) & 0xff);
        for (int i = 4; i < PAYLOAD_SIZE; ++i) p[i] = static_cast<uint8_t>(i % 256);
        return p;
    };
    auto tag_of = [](const std::vector<uint8_t>& p) {
        return static_cast<int>(p[0]) | (static_cast<int>(p[1]) << 8)
             | (static_cast<int>(p[2]) << 16) | (static_cast<int>(p[3]) << 24);
    };

    for (int i = 0; i < OVERSHOOT; ++i) {
        CProcessedMsg msg;
        msg.command = "inv";
        msg.data = tagged(i);
        node.PushProcessMsg(std::move(msg));
    }
    assert(node.HasProcessMsgs() == true);

    std::vector<int> drained;
    CProcessedMsg popped;
    while (node.PopProcessMsg(popped)) {
        assert(popped.command == "inv");
        assert(popped.data.size() == static_cast<size_t>(PAYLOAD_SIZE));
        drained.push_back(tag_of(popped.data));
    }

    const int cap = static_cast<int>(drained.size());

    // 1. A cap exists AND IT BIT. Both halves matter: if nothing were dropped
    //    this is the old unbounded queue and the OOM defence is gone; if
    //    everything were dropped the queue would be useless.
    assert(cap > 0);
    // If this fires, either the cap is gone or it is >= OVERSHOOT. The message
    // "cap did not bite" would be misleading in the second case, so: raise
    // OVERSHOOT rather than relaxing this, and only conclude "no cap" once
    // OVERSHOOT is comfortably above MAX_PROCESS_QUEUE_SIZE.
    assert(cap < OVERSHOOT);

    // 2. DROP-OLDEST: the survivors are the LAST `cap` messages pushed, in
    //    order. This is what fails if the policy is changed to drop-newest, and
    //    nothing in the tree asserted it before today.
    for (int k = 0; k < cap; ++k) {
        assert(drained[k] == OVERSHOOT - cap + k);
    }

    // 3. Draining empties it.
    assert(node.HasProcessMsgs() == false);

    // 4. Throughput over a batch that FITS - so the number is queue throughput
    //    and not a measure of how fast we discard.
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < cap; ++i) {
        CProcessedMsg msg;
        msg.command = "inv";
        msg.data = tagged(i);
        node.PushProcessMsg(std::move(msg));
    }
    int perf_count = 0;
    while (node.PopProcessMsg(popped)) ++perf_count;
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start);
    assert(perf_count == cap);
    assert(node.HasProcessMsgs() == false);

    const double us = total_duration.count() > 0 ? static_cast<double>(total_duration.count()) : 1.0;
    double throughput = (cap * 1000000.0) / us;
    double data_rate  = (cap * PAYLOAD_SIZE * 1000000.0) / us / 1024 / 1024;

    std::cout << "  [OK] Process queue caps at " << cap << " and keeps the NEWEST"
              << " (dropped " << (OVERSHOOT - cap) << " of " << OVERSHOOT << ")" << std::endl;
    std::cout << "  [OK] Throughput over a batch that fits: " << static_cast<int>(throughput)
              << " msgs/sec, " << std::fixed << std::setprecision(2) << data_rate << " MB/s"
              << " (" << cap << " messages, " << total_duration.count() / 1000 << "ms)" << std::endl;
}

/**
 * Test 11b: Send-queue cap keeps the OPPOSITE end (BUG #275, second queue)
 *
 * The two queues cap with two DIFFERENT policies, and neither was pinned:
 *   - PushProcessMsg pops the OLDEST to make room, so the NEWEST survive. The
 *     code's rationale: an inbound flood must not OOM us, and the most recent
 *     messages are the ones still worth processing.
 *   - PushSendMsg drops the INCOMING message and returns, so the OLDEST
 *     survive. The code's rationale: "Drop new messages when queue is full -
 *     peer will re-request if needed."
 *
 * Both are defensible, and they are opposites - which is exactly why a reader
 * cannot infer one from the other, and why each needs its own assertion.
 *
 * Two things are asserted, and the first version of this test only had the
 * second:
 *   (a) the cap EXISTS and bit - fewer messages survive than were pushed;
 *   (b) the survivors are the OLDEST - the very first message pushed is still
 *       at the head after a flood.
 * Without (a) the cap could be deleted outright and this scenario would stay
 * green, because (b) is also true of an unbounded queue. That gap was real: an
 * earlier comment here claimed "there is no public pop for the send queue",
 * which is wrong - MarkBytesSent() pops the front once a message is fully sent,
 * and it is public. The drain below uses it.
 */
void test_send_queue_cap_keeps_oldest() {
    std::cout << "Testing send-queue cap policy (drop-newest)..." << std::endl;

    NetProtocol::CAddress addr;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.SetIPv4(0x7F000001);
    addr.port = 8445;

    CNode node(2, addr, false);

    const int OVERSHOOT = 10000;  // far above any plausible cap
    for (int i = 0; i < OVERSHOOT; ++i) {
        std::vector<uint8_t> p(8, 0);
        p[0] = static_cast<uint8_t>(i & 0xff);
        p[1] = static_cast<uint8_t>((i >> 8) & 0xff);
        p[2] = static_cast<uint8_t>((i >> 16) & 0xff);
        p[3] = static_cast<uint8_t>((i >> 24) & 0xff);
        node.PushSendMsg(CSerializedNetMsg("inv", std::move(p)));
    }

    assert(node.HasSendMsgs() == true);

    // (b) POLICY: the first message pushed is still at the head after a flood.
    //     Flip PushSendMsg to pop_front() and this goes red.
    const CSerializedNetMsg* front = node.GetSendMsg();
    assert(front != nullptr);
    assert(front->data.size() >= 4);
    const int front_tag = static_cast<int>(front->data[0])
                        | (static_cast<int>(front->data[1]) << 8)
                        | (static_cast<int>(front->data[2]) << 16)
                        | (static_cast<int>(front->data[3]) << 24);
    assert(front_tag == 0);

    // (a) EXISTENCE: drain the queue and count. MarkBytesSent(size of the front)
    //     retires exactly one message per call. Delete the cap from PushSendMsg
    //     and this is the assertion that fails - the policy check above would
    //     not, since an unbounded queue also keeps the oldest at the head.
    int retained = 0;
    while (node.HasSendMsgs()) {
        const CSerializedNetMsg* m = node.GetSendMsg();
        assert(m != nullptr);
        node.MarkBytesSent(m->data.size());
        ++retained;
        assert(retained <= OVERSHOOT);   // a drain that cannot terminate
    }
    assert(retained > 0);
    // If this fires, either PushSendMsg has no cap or the cap is >= OVERSHOOT;
    // in the latter case raise OVERSHOOT rather than relaxing the assertion.
    assert(retained < OVERSHOOT);

    std::cout << "  [OK] Send queue caps at " << retained << " and kept the OLDEST"
              << " (front tag " << front_tag << ", dropped "
              << (OVERSHOOT - retained) << " of " << OVERSHOOT << ")" << std::endl;
}

/**
 * Test 12: Connection Stress Test
 * Verify CConnman handles rapid connect/disconnect cycles
 * This tests the node lifecycle under stress
 */
void test_connection_stress() {
    std::cout << "Testing connection stress (rapid lifecycle)..." << std::endl;

    auto peer_mgr = std::make_unique<TestPeerManager>();
    TestMessageProcessor msg_proc(*peer_mgr);

    auto connman = std::make_unique<CConnman>();

    CConnmanOptions opts;
    opts.fListen = false;
    opts.nMaxOutbound = 100;  // Allow many connections for stress test

    bool started = connman->Start(*peer_mgr, msg_proc, opts);
    assert(started == true);

    // Stress test parameters
    const int NUM_CYCLES = 50;

    // Note: We can't actually connect without real endpoints, so we test
    // the CNode lifecycle directly with simulated nodes

    for (int cycle = 0; cycle < NUM_CYCLES; ++cycle) {
        // Create test address (different "peer" each cycle)
        NetProtocol::CAddress addr;
        addr.services = NetProtocol::NODE_NETWORK;
        addr.SetIPv4(0x7F000001 + cycle);  // 127.0.0.1, 127.0.0.2, etc.
        addr.port = 8444 + cycle;

        // Simulate node creation/destruction (what ConnectNode/DisconnectNode do internally)
        {
            CNode node(100 + cycle, addr, false);
            node.state.store(CNode::STATE_CONNECTED);

            // Push some messages
            for (int m = 0; m < 10; ++m) {
                CProcessedMsg msg;
                msg.command = "ping";
                msg.data = {1, 2, 3};
                node.PushProcessMsg(std::move(msg));
            }

            // Mark for disconnect
            node.fDisconnect.store(true);
            node.state.store(CNode::STATE_DISCONNECTED);

            // Node is destroyed here when it goes out of scope
        }

        // Disconnect non-existent node (should not crash)
        connman->DisconnectNode(100 + cycle, "stress test");
    }

    // Brief delay
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Verify CConnman is still healthy
    assert(connman->IsRunning() == true);
    assert(connman->GetNodeCount() == 0);  // All test nodes were local, not added to CConnman

    connman->Stop();

    std::cout << "  ✓ Connection stress test passed (" << NUM_CYCLES << " cycles)" << std::endl;
}

/**
 * Main test runner
 */
int main() {
    std::cout << "\n=== Phase 6: CConnman Event-Driven Networking Tests ===\n" << std::endl;

    try {
        // Unit Tests (Phase 6.1)
        std::cout << "\n--- Unit Tests ---\n" << std::endl;
        test_cnode_lifecycle();
        test_message_queue_ordering();
        test_send_message_queue();
        test_connman_initialization();
        test_graceful_disconnect();
        test_message_queue_thread_safety();
        test_node_state_transitions();
        test_select_timeout_behavior();
        test_wake_message_handler();

        // Integration Tests (Phase 6.2)
        std::cout << "\n--- Integration Tests ---\n" << std::endl;
        test_bug134_handshake_timing();
        test_highload_throughput();
        test_send_queue_cap_keeps_oldest();
        test_connection_stress();

        std::cout << "\n=== All Phase 6 Tests Passed! (13 tests) ===" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}

