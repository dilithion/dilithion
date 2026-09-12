// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CConnman - Event-driven connection manager (Bitcoin Core pattern)
// Replaces polling-based CConnectionManager with proper select() blocking
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#ifndef DILITHION_NET_CONNMAN_H
#define DILITHION_NET_CONNMAN_H

#include <net/node.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <thread>
#include <vector>

// Forward declarations
class CPeerManager;
class CNetMessageProcessor;


/**
 * Connection manager options
 */
struct CConnmanOptions {
    int nMaxOutbound = 8;
    int nMaxInbound = 117;
    int nMaxTotal = 125;
    int nMaxInboundPerIP = 2;  // Max inbound connections per IP (Monero pattern, default 2)
    std::vector<NetProtocol::CAddress> vSeedNodes;
    bool fListen = true;
    uint16_t nListenPort = 18444;
    bool upnp_enabled = false;  // Enable UPnP automatic port mapping
};

/**
 * CConnman - Central connection manager with event-driven I/O
 *
 * Bitcoin Core pattern: Two-thread architecture
 * - ThreadSocketHandler: Handles all socket I/O with proper select() blocking
 * - ThreadMessageHandler: Processes messages from queue, decoupled from I/O
 *
 * Key improvements over CConnectionManager:
 * - select() blocks until data is available (no busy-polling)
 * - Condition variable wake mechanism (no fixed sleep intervals)
 * - Complete decoupling of I/O from message processing
 */
class CConnman {
public:
    // BKL-30 test seam: fdset_guard_tests.cpp reaches SocketEventsSelect()
    // without starting threads or a peer manager.
    friend struct CConnmanFdSetTestAccess;

    CConnman();
    ~CConnman();

    // Disable copy
    CConnman(const CConnman&) = delete;
    CConnman& operator=(const CConnman&) = delete;

    //
    // Lifecycle management
    //

    /**
     * Start the connection manager
     * @param peer_mgr Peer manager for node tracking
     * @param msg_proc Message processor for handling messages
     * @param options Configuration options
     * @return true if started successfully
     */
    bool Start(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc, const CConnmanOptions& options);

    /**
     * Stop the connection manager gracefully
     * Waits for threads to finish and cleans up resources
     */
    void Stop();

    /**
     * Interrupt the connection manager
     * Signals threads to stop but doesn't wait for completion
     */
    void Interrupt();

    /**
     * Check if running
     */
    bool IsRunning() const { return !interruptNet.load(); }

    //
    // Connection management
    //

    /**
     * Initiate outbound connection
     * @param addr Address to connect to
     * @param manual True for --connect/--addnode/RPC addnode peers (Bitcoin Core pattern)
     * @return CNode pointer on success, nullptr on failure
     */
    // Phase 4 port: connection class added (default FullRelay matches
    // pre-port behaviour). `manual=true` overrides the class to Manual.
    CNode* ConnectNode(
        const NetProtocol::CAddress& addr,
        bool manual = false,
        CNode::OutboundClass cls = CNode::OutboundClass::FullRelay);

    /**
     * Add a manual node for auto-reconnect tracking
     * Manual nodes are automatically reconnected if they disconnect (Bitcoin Core pattern)
     * @param addr Address of the manual node
     */
    void AddManualNode(const NetProtocol::CAddress& addr);

    /**
     * Remove a manual node from auto-reconnect tracking
     * @param ip_str IP string of the node to remove
     */
    void RemoveManualNode(const std::string& ip_str);

    /**
     * Accept inbound connection
     * @param socket Accepted socket (takes ownership)
     * @param addr Remote address
     * @return true if accepted
     */
    bool AcceptConnection(std::unique_ptr<class CSocket> socket, const NetProtocol::CAddress& addr);

    /**
     * Disconnect a node
     * @param nodeid Node ID to disconnect
     * @param reason Reason for disconnection (for logging)
     */
    void DisconnectNode(int nodeid, const std::string& reason = "");

    /**
     * Get all connected nodes
     */
    std::vector<CNode*> GetNodes() const;

    /**
     * Get node by ID
     */
    CNode* GetNode(int nodeid) const;

    /**
     * Get connection count
     */
    size_t GetNodeCount() const;

    //
    // External IP detection (for peer discovery)
    //

    /**
     * Record an external IP reported by a peer
     * Called when we receive VERSION and peer tells us what IP they see us as
     * @param ip The external IP reported by peer
     * @param peerId The peer that reported this IP
     */
    void RecordExternalIP(const std::string& ip, int peerId);

    /**
     * Get best known external IP
     * @return External IP string, or empty if unknown
     */
    std::string GetExternalIP() const;

    /**
     * Set external IP manually (for --externalip option)
     * Used when user has manually forwarded port on router
     * @param ip The external IP to advertise
     */
    void SetExternalIP(const std::string& ip);

    //
    // Message sending
    //

    /**
     * Push message to outgoing queue
     * Thread-safe, can be called from any thread
     * @param pnode Target node
     * @param msg Message to send
     */
    void PushMessage(CNode* pnode, CSerializedNetMsg&& msg);

    /**
     * Push message by node ID
     * @return true if message was queued, false if node not found
     */
    bool PushMessage(int nodeid, CSerializedNetMsg&& msg);

    /**
     * Push CNetMessage (converts to CSerializedNetMsg)
     * Convenience method for compatibility with existing code
     * @return true if message was queued, false if node not found
     */
    bool PushMessage(int nodeid, const class CNetMessage& msg);

    /**
     * Push CNetMessage by node pointer
     */
    void PushMessage(CNode* pnode, const class CNetMessage& msg);

    //
    // Message handler registration
    //

    using MessageHandler = std::function<bool(CNode*, const std::string&, const std::vector<uint8_t>&)>;

    /**
     * Set message handler callback
     * Called by ThreadMessageHandler for each complete message
     */
    void SetMessageHandler(MessageHandler handler) { m_msg_handler = handler; }

private:
    //
    // Thread functions
    //

    /**
     * Socket handler thread (Bitcoin Core: ThreadSocketHandler)
     * - Manages all socket I/O with proper select() blocking
     * - Reads data into node receive buffers
     * - Writes data from node send buffers
     * - Wakes message handler when data is available
     */
    void ThreadSocketHandler();

    /**
     * Message handler thread (Bitcoin Core: ThreadMessageHandler)
     * - Processes messages from node queues
     * - Decoupled from I/O for better performance
     * - Waits on condition variable when idle
     */
    void ThreadMessageHandler();

    /**
     * Open connections thread
     * - Manages outbound connection attempts
     * - Connects to seed nodes
     */
    void ThreadOpenConnections();

    //
    // Socket handling
    //

    /**
     * Main socket event loop
     * Called by ThreadSocketHandler
     */
    void SocketHandler();

    /**
     * Wait for socket events using select()
     * @param recv_set Sockets to check for read readiness (modified)
     * @param send_set Sockets to check for write readiness (modified)
     * @param error_set Sockets to check for errors (modified)
     * @return true if events occurred, false on timeout/interrupt
     */
    bool SocketEventsSelect(std::set<int>& recv_set, std::set<int>& send_set, std::set<int>& error_set);

    /**
     * Receive data from node socket into buffer
     * @param pnode Node to receive from
     * @return true if socket still valid, false on disconnect
     */
    bool ReceiveMsgBytes(CNode* pnode);

    /**
     * Send pending data from node buffer
     * @param pnode Node to send to
     * @return true if socket still valid, false on disconnect
     */
    bool SendMessages(CNode* pnode);

    /**
     * Extract complete messages from node's receive buffer
     * Parses message headers, validates checksums, and pushes to processing queue
     * @param pnode Node to extract messages from
     */
    void ExtractMessages(CNode* pnode);

    /**
     * Wake up the message handler thread
     * Called when new messages are available
     */
    void WakeMessageHandler();

    /**
     * Process disconnected nodes
     * Cleans up nodes marked for disconnect
     */
    void DisconnectNodes();

    /**
     * Check for inactive nodes and send keepalive pings
     * - Sends ping to nodes idle for >60 seconds
     * - Disconnects nodes unresponsive for >120 seconds
     */
    void InactivityCheck();

    /**
     * Check if an address is our own (for self-connection prevention)
     * @param addr Address to check
     * @return true if this is our own address
     */
    bool IsOurAddress(const NetProtocol::CAddress& addr) const;

    //
    // Node management
    //

    std::vector<std::unique_ptr<CNode>> m_nodes;
    // LOCK ORDERING: cs_vNodes must be acquired BEFORE cs_peers/cs_nodes (CPeerManager).
    // Code holding cs_peers or cs_nodes must NEVER call CConnman methods that acquire cs_vNodes
    // (e.g., GetNode, PushMessage(int)). Violating this causes ABBA deadlock.
    mutable std::mutex cs_vNodes;
    // P2P-14/15 red-team HIGH-2 (pre-existing race, fixed here because it is one
    // line and it invalidates another fix's stated premise).
    //
    // This was a plain `int` incremented as a non-atomic read-modify-write from
    // three sites with INCONSISTENT lock state:
    //     connman.cpp:413   ConnectNode (outbound)          INSIDE cs_vNodes
    //     connman.cpp:1294  SocketHandler inbound accept    OUTSIDE cs_vNodes  <-- LIVE path
    //     connman.cpp:559   AcceptConnection                OUTSIDE (dead code)
    //
    // Two threads interleaving the load can mint TWO LIVE CNodes WITH THE SAME
    // node_id. That is not cosmetic: node_refs[id] and peers[id] are keyed on it
    // (peers.cpp), so the second registration silently overwrites the first —
    // GetNode() then hands the wrong CNode to Misbehaving / PeriodicMaintenance,
    // and RemoveNode(id) erases the shared entry, leaving the survivor
    // unreachable with its dedup/rate-limit maps never cleaned. That unbounded-map
    // growth is exactly what peers.cpp:1763 says is prevented "because Node IDs
    // are monotonic (never reused, connman m_next_node_id)" — this race is what
    // breaks that premise.
    //
    // std::atomic makes operator++ atomic at all three sites with no change to
    // any lock discipline.
    std::atomic<int> m_next_node_id{1};

    // Listen socket (socket_t for cross-platform compatibility)
    socket_t m_listen_socket = static_cast<socket_t>(-1);

    //
    // Thread control
    //

    std::atomic<bool> interruptNet{false};
    std::atomic<bool> flagInterruptMsgProc{false};

    // Message handler wake mechanism
    std::condition_variable condMsgProc;
    std::mutex mutexMsgProc;
    std::atomic<bool> fMsgProcWake{false};

    // Threads
    std::thread threadSocketHandler;
    std::thread threadMessageHandler;
    std::thread threadOpenConnections;

    //
    // Async message dispatch (Phase 1 IBD redesign)
    // Headers and blocks are routed to async queues instead of processing inline
    //

    // Queued message for async processing
    struct QueuedMessage {
        int node_id;
        std::string command;
        std::vector<uint8_t> data;
    };

    // Headers queue and worker
    std::queue<QueuedMessage> m_headers_queue;
    std::mutex m_headers_queue_mutex;
    std::condition_variable m_headers_cv;
    std::thread m_headers_worker_thread;

    // Blocks queue and workers (multiple threads for parallel processing)
    std::queue<QueuedMessage> m_blocks_queue;
    std::mutex m_blocks_queue_mutex;
    std::condition_variable m_blocks_cv;
    std::vector<std::thread> m_blocks_worker_threads;
    static constexpr int NUM_BLOCK_WORKERS = 1;  // Single worker (validation is sequential anyway)

    // BUG #275: Memory limits for async queues to prevent OOM
    // Without limits, blocks/headers pile up faster than workers can process,
    // especially on fast chains (DilV ~45s blocks) with many peers.
    static constexpr size_t MAX_BLOCKS_QUEUE_SIZE = 500;    // ~500 blocks max in queue
    static constexpr size_t MAX_HEADERS_QUEUE_SIZE = 2000;  // ~2000 header batches max

    // Worker thread functions
    void HeadersWorkerThread();
    void BlocksWorkerThread();

    // Helper to process a message (used by workers)
    bool ProcessQueuedMessage(const QueuedMessage& msg);

    //
    // Configuration
    //

    CConnmanOptions m_options;

    // Manual node tracking for auto-reconnect (Bitcoin Core pattern)
    // Nodes added via --connect, --addnode, or RPC addnode are automatically
    // reconnected if they disconnect
    std::vector<NetProtocol::CAddress> m_manual_nodes;
    mutable std::mutex cs_manual_nodes;

    // v4.2.0: throttle the "Outbound connection limit reached" warning to
    // once per 60s. The connection-attempt scheduler retries frequently
    // while at capacity (the at-limit state is persistent on a healthy
    // mesh), so without throttling each attempt produces an identical WARN
    // line, drowning the log. Stores the unix timestamp of the last
    // emission; comparison uses unsigned-safe arithmetic.
    static constexpr int64_t OUTBOUND_LIMIT_LOG_INTERVAL_SECONDS = 60;
    mutable std::atomic<int64_t> m_outbound_limit_log_last{0};

public:
    // When true (--connect used), skip hardcoded seed connections and AddrMan.
    // Only connect to manually specified nodes.
    bool m_connect_only{false};
private:

    // Local addresses (for self-connection prevention)
    mutable std::mutex cs_localAddresses;
    std::set<std::string> m_localAddresses;

    //
    // External IP tracking - learn our public IP from peers
    //

    struct ExternalIPScore {
        std::string ip;
        int score;
        int64_t lastSeen;
    };
    mutable std::mutex cs_externalIP;
    std::vector<ExternalIPScore> m_externalIPs;
    std::string m_bestExternalIP;  // Highest scored external IP

    //
    // External references (set in Start())
    //

    CPeerManager* m_peer_manager = nullptr;
    CNetMessageProcessor* m_msg_processor = nullptr;
    MessageHandler m_msg_handler;

public:
    // Test-only: set the legacy m_peer_manager pointer without going through
    // Start(). Production code wires this via Start(peer_mgr, msg_proc, options).
    // Originally written for Phase 6 PR6.5b.1b dual-dispatch tests; dual-dispatch
    // wiring was retired in v4.3.4 Option C cut Block 6, but the test seam still
    // serves the regression-gate test (legacy_block_arrival_chainsel_gate_tests)
    // and any future test wanting legacy CPeerManager wired without I/O.
    // Restricted to test fixtures by convention.
    void SetTestPeerManager(::CPeerManager& pm) {
        m_peer_manager = &pm;
    }

    // Test-only: invoke the private ProcessQueuedMessage without spinning up
    // the BlocksWorker / HeadersWorker / inline control-thread path. Used by
    // PR6.5b.2 (v4.3) connman block-routing tests to exercise the port-
    // CPeerManager dispatch path deterministically. Restricted to test
    // fixtures by convention; matches SetTestPeerManager's "Test-only" tag.
    bool TestProcessQueuedMessage(int node_id, const std::string& command,
                                  const std::vector<uint8_t>& data) {
        return ProcessQueuedMessage(QueuedMessage{node_id, command, data});
    }

    // Centralized wrappers for legacy peer-event handling.
    bool DispatchPeerConnected(int node_id, CNode* pnode,
                               const NetProtocol::CAddress& addr, bool inbound);
    void DispatchPeerDisconnected(int node_id);
};

#endif // DILITHION_NET_CONNMAN_H
