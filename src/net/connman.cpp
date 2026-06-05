// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// CConnman - Event-driven connection manager implementation
// See: docs/developer/LIBEVENT-NETWORKING-PORT-PLAN.md

#include <net/connman.h>
#include <net/netaddress.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/socket.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/serialize.h>
#include <net/banman.h>  // For MisbehaviorType
#include <core/chainparams.h>  // Phase 4: per-chain outbound class targets
#include <util/time.h>
#include <util/logging.h>
#include <util/strencodings.h>  // For strprintf

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>  // For std::cout
#include <map>       // For std::map in InactivityCheck
#include <random>    // For std::random_device (CWE-676 fix: replaces unsafe rand())
#include <thread>  // For std::this_thread

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#endif

#include <atomic>

// Socket timeout for select() in milliseconds
static constexpr int SELECT_TIMEOUT_MS = 50;

// BLOCK PIPELINE COUNTERS - Track exactly where blocks are lost
static std::atomic<int> g_blocks_extracted{0};        // Step 1: Extracted from TCP
static std::atomic<int> g_blocks_pushed_to_node{0};   // Step 2: Pushed to node's vProcessMsg
static std::atomic<int> g_blocks_popped_from_node{0}; // Step 3: Popped from vProcessMsg
static std::atomic<int> g_blocks_routed_to_queue{0};  // Step 4: Pushed to m_blocks_queue
static std::atomic<int> g_blocks_worker_received{0};  // Step 5: Popped by BlocksWorkerThread
static std::atomic<int> g_blocks_processed{0};        // Step 6: ProcessQueuedMessage returned

CConnman::CConnman() = default;

bool CConnman::DispatchPeerConnected(int node_id, CNode* pnode,
                                     const NetProtocol::CAddress& addr, bool inbound)
{
    if (!m_peer_manager) return true;  // tolerated null in tests
    return m_peer_manager->RegisterNode(node_id, pnode, addr, inbound);
}

void CConnman::DispatchPeerDisconnected(int node_id)
{
    if (m_peer_manager) {
        m_peer_manager->OnPeerDisconnected(node_id);
    }
}

CConnman::~CConnman() {
    Interrupt();
    Stop();
}

bool CConnman::Start(CPeerManager& peer_mgr, CNetMessageProcessor& msg_proc, const CConnmanOptions& options) {
    m_peer_manager = &peer_mgr;
    m_msg_processor = &msg_proc;
    m_options = options;

    // Reset interrupt flags
    interruptNet.store(false);
    flagInterruptMsgProc.store(false);

    // Detect local addresses for self-connection prevention
    {
        std::lock_guard<std::mutex> lock(cs_localAddresses);
        m_localAddresses.insert("127.0.0.1");
        m_localAddresses.insert("0.0.0.0");
        m_localAddresses.insert("::1");

#ifdef _WIN32
        // Windows: Use gethostname + getaddrinfo
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            struct addrinfo hints, *res, *p;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;  // Both IPv4 and IPv6
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(hostname, nullptr, &hints, &res) == 0) {
                for (p = res; p != nullptr; p = p->ai_next) {
                    char ip_str[INET6_ADDRSTRLEN];
                    if (p->ai_family == AF_INET) {
                        struct sockaddr_in* sa4 = (struct sockaddr_in*)p->ai_addr;
                        if (inet_ntop(AF_INET, &sa4->sin_addr, ip_str, sizeof(ip_str)) != nullptr) {
                            m_localAddresses.insert(ip_str);
                            LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                        }
                    } else if (p->ai_family == AF_INET6) {
                        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)p->ai_addr;
                        if (inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, sizeof(ip_str)) != nullptr) {
                            m_localAddresses.insert(ip_str);
                            LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                        }
                    }
                }
                freeaddrinfo(res);
            }
        }
#else
        // Linux/macOS: Use getifaddrs
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == 0) {
            for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr == nullptr) continue;
                char ip_str[INET6_ADDRSTRLEN];
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in* sa4 = (struct sockaddr_in*)ifa->ifa_addr;
                    if (inet_ntop(AF_INET, &sa4->sin_addr, ip_str, sizeof(ip_str)) != nullptr) {
                        m_localAddresses.insert(ip_str);
                        LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                    }
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    struct sockaddr_in6* sa6 = (struct sockaddr_in6*)ifa->ifa_addr;
                    if (inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, sizeof(ip_str)) != nullptr) {
                        m_localAddresses.insert(ip_str);
                        LogPrintf(NET, INFO, "[CConnman] Detected local address: %s\n", ip_str);
                    }
                }
            }
            freeifaddrs(ifaddr);
        }
#endif
    }

    // Phase 2: Create listen socket if fListen (dual-stack IPv4+IPv6)
    if (m_options.fListen) {
        bool is_ipv6 = false;
        if (!CSock::CreateListenSocket(m_options.nListenPort, "", m_listen_socket, is_ipv6)) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to create listen socket\n");
            return false;
        }

        // Listen — use SOMAXCONN to handle connection bursts from many miners
        if (listen(m_listen_socket, SOMAXCONN) < 0) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to listen on socket\n");
            CSock::Close(m_listen_socket);
            return false;
        }

        // Set non-blocking
        if (!CSock::SetNonBlocking(m_listen_socket)) {
            LogPrintf(NET, ERROR, "[CConnman] Failed to set listen socket non-blocking\n");
            CSock::Close(m_listen_socket);
            return false;
        }

        if (is_ipv6) {
            LogPrintf(NET, INFO, "[CConnman] Listening on port %d (dual-stack IPv4+IPv6)\n", m_options.nListenPort);
        } else {
            LogPrintf(NET, WARN, "[CConnman] Listening on port %d (IPv4 only, IPv6 unavailable)\n", m_options.nListenPort);
        }
    }

    // Phase 2: Start ThreadSocketHandler
    try {
        threadSocketHandler = std::thread(&CConnman::ThreadSocketHandler, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadSocketHandler: %s\n", e.what());
        return false;
    }

    // Phase 2: Start ThreadMessageHandler
    try {
        threadMessageHandler = std::thread(&CConnman::ThreadMessageHandler, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadMessageHandler: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) {
            threadSocketHandler.join();
        }
        return false;
    }

    // Phase 2: Start ThreadOpenConnections
    try {
        threadOpenConnections = std::thread(&CConnman::ThreadOpenConnections, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start ThreadOpenConnections: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) {
            threadSocketHandler.join();
        }
        if (threadMessageHandler.joinable()) {
            threadMessageHandler.join();
        }
        return false;
    }

    // IBD Redesign Phase 1: Start async message worker threads
    // Headers and blocks are processed in dedicated threads to avoid blocking message handler
    try {
        m_headers_worker_thread = std::thread(&CConnman::HeadersWorkerThread, this);
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start HeadersWorkerThread: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) threadSocketHandler.join();
        if (threadMessageHandler.joinable()) threadMessageHandler.join();
        if (threadOpenConnections.joinable()) threadOpenConnections.join();
        return false;
    }

    // Start multiple block worker threads for parallel processing
    // This prevents queue bottlenecks when multiple peers send blocks simultaneously
    try {
        for (int i = 0; i < NUM_BLOCK_WORKERS; i++) {
            m_blocks_worker_threads.emplace_back(&CConnman::BlocksWorkerThread, this);
        }
    } catch (const std::exception& e) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to start BlocksWorkerThreads: %s\n", e.what());
        Interrupt();
        if (threadSocketHandler.joinable()) threadSocketHandler.join();
        if (threadMessageHandler.joinable()) threadMessageHandler.join();
        if (threadOpenConnections.joinable()) threadOpenConnections.join();
        if (m_headers_worker_thread.joinable()) m_headers_worker_thread.join();
        for (auto& t : m_blocks_worker_threads) {
            if (t.joinable()) t.join();
        }
        return false;
    }

    LogPrintf(NET, INFO, "[CConnman] Started successfully (with async headers + %d parallel block workers)\n", NUM_BLOCK_WORKERS);
    return true;
}

void CConnman::Stop() {
    // Signal interrupt
    Interrupt();

    // Wait for threads
    if (threadSocketHandler.joinable()) {
        threadSocketHandler.join();
    }
    if (threadMessageHandler.joinable()) {
        threadMessageHandler.join();
    }
    if (threadOpenConnections.joinable()) {
        threadOpenConnections.join();
    }

    // IBD Redesign Phase 1: Join async worker threads
    if (m_headers_worker_thread.joinable()) {
        m_headers_worker_thread.join();
    }
    // Join all block worker threads
    for (auto& t : m_blocks_worker_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    m_blocks_worker_threads.clear();

    // Close listen socket
    if (CSock::IsValid(m_listen_socket)) {
        CSock::Close(m_listen_socket);
    }

    // Disconnect all nodes
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            node->CloseSocket();
        }
        m_nodes.clear();
    }

    LogPrintf(NET, INFO, "[CConnman] Stopped\n");
}

void CConnman::Interrupt() {
    interruptNet.store(true);
    flagInterruptMsgProc.store(true);

    // Wake message handler
    WakeMessageHandler();

    // IBD Redesign Phase 1: Wake async worker threads so they can exit
    m_headers_cv.notify_all();
    m_blocks_cv.notify_all();
}

CNode* CConnman::ConnectNode(const NetProtocol::CAddress& addr, bool manual,
                             CNode::OutboundClass cls) {
    // Phase 2: Implement outbound connection

    // Extract IP string from address (supports both IPv4 and IPv6)
    std::string ip_str = addr.ToStringIP();

    // Prevent self-connection: check if target is our own IP AND our listen port
    // Different ports on the same IP are different nodes (e.g. multiple nodes behind NAT)
    if (IsOurAddress(addr) && addr.port == m_options.nListenPort) {
        LogPrintf(NET, WARN, "[CConnman] Preventing self-connection to %s:%d\n",
                  ip_str.c_str(), addr.port);
        return nullptr;
    }

    // Step 1: Create socket and initiate async TCP connect BEFORE locking.
    // This avoids holding cs_vNodes during potentially slow syscalls.
    int family = CSock::DetectFamily(ip_str);
    if (family == 0) {
        LogPrintf(NET, ERROR, "[CConnman] Invalid address family for %s\n", ip_str.c_str());
        return nullptr;
    }
    socket_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (!CSock::IsValid(sock)) {
        LogPrintf(NET, ERROR, "[CConnman] Failed to create socket for %s:%d\n",
                  ip_str.c_str(), addr.port);
        return nullptr;
    }

    if (!CSock::SetNonBlocking(sock)) {
        LogPrintf(NET, ERROR, "[CConnman] ConnectNode: Failed to set non-blocking for %s:%d\n",
                  ip_str.c_str(), addr.port);
        CSock::Close(sock);
        return nullptr;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len;
    if (!CSock::FillSockAddr(ip_str, addr.port, ss, ss_len)) {
        LogPrintf(NET, ERROR, "[CConnman] ConnectNode: Failed to fill address for %s:%d\n",
                  ip_str.c_str(), addr.port);
        CSock::Close(sock);
        return nullptr;
    }

    int result = connect(sock, (struct sockaddr*)&ss, ss_len);
#ifdef _WIN32
    int err = WSAGetLastError();
    if (result < 0 && err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        CSock::Close(sock);
        LogPrintf(NET, ERROR, "[CConnman] Failed to connect to %s:%d (error %d)\n",
                  ip_str.c_str(), addr.port, err);
        return nullptr;
    }
#else
    if (result < 0 && errno != EINPROGRESS && errno != EAGAIN) {
        CSock::Close(sock);
        LogPrintf(NET, ERROR, "[CConnman] Failed to connect to %s:%d (error %d)\n",
                  ip_str.c_str(), addr.port, errno);
        return nullptr;
    }
#endif

    // Step 2: ATOMIC check-and-add under a SINGLE lock acquisition.
    // This fixes the TOCTOU race where ThreadOpenConnections and the P2P
    // maintenance thread both pass the duplicate check before either adds
    // the node, creating 2 outbound connections to the same seed.
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);

        // Check for duplicate connection
        // For outbound: skip if we already have an outbound to this ip:port
        // Inbound connections from the same IP don't block new outbound to different ports
        for (const auto& node : m_nodes) {
            if (node && !node->fDisconnect.load() && !node->fInbound) {
                if (node->addr.ToStringIP() == ip_str && node->addr.port == addr.port) {
                    LogPrintf(NET, WARN, "[CConnman] Skipping duplicate outbound to %s:%d (already connected)\n",
                              ip_str.c_str(), addr.port);
                    CSock::Close(sock);
                    return nullptr;
                }
            }
        }

        // Check connection limits
        size_t outbound_count = 0;
        for (const auto& node : m_nodes) {
            if (!node->fInbound) {
                outbound_count++;
            }
        }
        if (outbound_count >= static_cast<size_t>(m_options.nMaxOutbound)) {
            // v4.2.0 — throttle this WARN to once per 60s. At-limit is a
            // persistent steady state on a healthy mesh (every retry by
            // the connection scheduler hits this branch), so without the
            // throttle the log floods. CAS so concurrent rejected
            // attempts only emit one line.
            const int64_t now = GetTime();
            int64_t last = m_outbound_limit_log_last.load();
            if (now - last >= OUTBOUND_LIMIT_LOG_INTERVAL_SECONDS &&
                m_outbound_limit_log_last.compare_exchange_strong(last, now)) {
                LogPrintf(NET, WARN, "[CConnman] Outbound connection limit reached (%zu/%d) — suppressing further at-limit warnings for %lds\n",
                          outbound_count, m_options.nMaxOutbound,
                          static_cast<long>(OUTBOUND_LIMIT_LOG_INTERVAL_SECONDS));
            }
            CSock::Close(sock);
            return nullptr;
        }

        // Create CNode and add to m_nodes (still holding lock)
        int node_id = m_next_node_id++;
        auto node = std::make_unique<CNode>(node_id, addr, false);  // false = outbound
        CNode* pnode = node.get();
        pnode->fManual = manual;
        // Phase 4 port: tag the connection class so per-class accounting
        // and per-class behaviour gating (no-tx-relay for BlockRelay etc.)
        // can dispatch on m_outbound_class.
        pnode->m_outbound_class = manual ? CNode::OutboundClass::Manual : cls;

        pnode->SetSocket(static_cast<int>(sock));
        pnode->state.store(CNode::STATE_CONNECTING);

        if (!DispatchPeerConnected(node_id, pnode, addr, false)) {
            LogPrintf(NET, WARN, "[CConnman] Not connecting to banned IP %s\n", ip_str.c_str());
            // node destructor closes socket
            return nullptr;
        }
        m_nodes.push_back(std::move(node));

        LogPrintf(NET, INFO, "[CConnman] Connecting to %s:%d (node %d)\n",
                  ip_str.c_str(), addr.port, pnode->id);
        return pnode;
    }
}

bool CConnman::AcceptConnection(std::unique_ptr<CSocket> socket, const NetProtocol::CAddress& addr) {
    // Phase 2: Implement inbound connection acceptance
    if (!socket || !socket->IsValid()) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: invalid socket\n");
        return false;
    }

    // Check connection limits
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        size_t inbound_count = 0;
        size_t total_count = m_nodes.size();
        for (const auto& node : m_nodes) {
            if (node->fInbound) {
                inbound_count++;
            }
        }
        if (inbound_count >= static_cast<size_t>(m_options.nMaxInbound)) {
            // Phase 4: Try to evict a low-trust peer to make room
            if (m_peer_manager && m_peer_manager->EvictPeersIfNeeded()) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Evicted low-value peer to accept new inbound" << std::endl;
                // Continue to accept — slot freed by eviction
            } else {
                LogPrintf(NET, WARN, "[CConnman] Inbound connection limit reached (%zu/%d)\n",
                          inbound_count, m_options.nMaxInbound);
                return false;
            }
        }
        if (total_count >= static_cast<size_t>(m_options.nMaxTotal)) {
            LogPrintf(NET, WARN, "[CConnman] Total connection limit reached (%zu/%d)\n",
                      total_count, m_options.nMaxTotal);
            return false;
        }
    }

    // Extract IP string (supports both IPv4 and IPv6)
    std::string ip_str = addr.ToStringIP();

    // Check if IP is banned
    if (m_peer_manager && m_peer_manager->IsBanned(ip_str)) {
        LogPrintf(NET, WARN, "[CConnman] Rejecting connection from banned IP %s\n", ip_str.c_str());
        return false;
    }

    // Per-IP connection limit with outbound duplicate prevention
    // Rule 1: If we already have an OUTBOUND to this IP, reject inbound (same node, wasteful)
    // Rule 2: Allow up to nMaxInboundPerIP INBOUND from same IP (NAT: multiple nodes behind one router)
    const int max_per_ip = m_options.nMaxInboundPerIP;
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        bool has_outbound = false;
        int inbound_count = 0;
        for (const auto& node : m_nodes) {
            if (node && !node->fDisconnect.load()) {
                if (node->addr.ToStringIP() == ip_str) {
                    if (!node->fInbound) {
                        has_outbound = true;
                        break;
                    }
                    ++inbound_count;
                }
            }
        }
        if (has_outbound) {
            LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (already have outbound connection)\n",
                      ip_str.c_str());
            return false;
        }
        if (inbound_count >= max_per_ip) {
            LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (%d inbound connections, max %d per IP)\n",
                      ip_str.c_str(), inbound_count, max_per_ip);
            return false;
        }
    }

    // Phase 2: Create CNode directly (CConnman owns nodes)
    int node_id = m_next_node_id++;
    auto node = std::make_unique<CNode>(node_id, addr, true);  // true = inbound
    CNode* pnode = node.get();

    // Get socket FD from CSocket and release ownership
    // ReleaseFD() transfers ownership so CSocket won't close it
    int sock_fd = socket->ReleaseFD();
    if (sock_fd < 0) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: failed to get socket FD\n");
        return false;
    }
    
    // Set socket options on the raw FD
    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(sock_fd, FIONBIO, &mode) == SOCKET_ERROR) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: ioctlsocket failed to set non-blocking mode\n");
        closesocket(sock_fd);
        return false;
    }
#else
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags == -1) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: fcntl F_GETFL failed\n");
        close(sock_fd);
        return false;
    }
    if (fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        LogPrintf(NET, ERROR, "[CConnman] AcceptConnection: fcntl F_SETFL failed to set non-blocking mode\n");
        close(sock_fd);
        return false;
    }
#endif

    pnode->SetSocket(sock_fd);
    pnode->state.store(CNode::STATE_CONNECTED);

    // Socket is now released and owned by CNode
    socket.reset();

    // Add to m_nodes
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        // FIX: Register BEFORE adding to m_nodes to prevent race condition
        // BUG #148 ROOT CAUSE FIX: Check return value (banned IP check)
        if (!DispatchPeerConnected(node_id, pnode, addr, true)) {
            LogPrintf(NET, WARN, "[CConnman] Rejecting banned inbound from %s\n", ip_str.c_str());
            // node destructor closes socket
            return false;
        }
        m_nodes.push_back(std::move(node));
    }

    LogPrintf(NET, INFO, "[CConnman] Accepted connection from %s:%d (node %d)\n",
              ip_str.c_str(), addr.port, node_id);
    return true;
}

void CConnman::DisconnectNode(int nodeid, const std::string& reason) {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    for (auto& node : m_nodes) {
        if (node->id == nodeid) {
            if (!reason.empty()) {
                LogPrintf(NET, INFO, "[CConnman] Disconnecting node %d: %s\n", nodeid, reason.c_str());
            }
            node->MarkDisconnect();
            return;
        }
    }
}

std::vector<CNode*> CConnman::GetNodes() const {
    std::vector<CNode*> result;
    std::lock_guard<std::mutex> lock(cs_vNodes);
    result.reserve(m_nodes.size());
    for (const auto& node : m_nodes) {
        result.push_back(node.get());
    }
    return result;
}

CNode* CConnman::GetNode(int nodeid) const {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    for (const auto& node : m_nodes) {
        if (node->id == nodeid) {
            return node.get();
        }
    }
    return nullptr;
}

size_t CConnman::GetNodeCount() const {
    std::lock_guard<std::mutex> lock(cs_vNodes);
    return m_nodes.size();
}

void CConnman::PushMessage(CNode* pnode, CSerializedNetMsg&& msg) {
    if (!pnode) return;
    pnode->PushSendMsg(std::move(msg));
}

bool CConnman::PushMessage(int nodeid, CSerializedNetMsg&& msg) {
    CNode* pnode = GetNode(nodeid);
    if (!pnode) {
        LogPrintf(NET, WARN, "[CConnman] PushMessage failed: node %d not found\n", nodeid);
        return false;
    }
    PushMessage(pnode, std::move(msg));
    return true;
}

bool CConnman::PushMessage(int nodeid, const CNetMessage& msg) {
    // Convert CNetMessage to CSerializedNetMsg
    std::string command = msg.header.GetCommand();
    std::vector<uint8_t> data = msg.Serialize();
    CSerializedNetMsg serialized(std::move(command), std::move(data));
    return PushMessage(nodeid, std::move(serialized));
}

void CConnman::PushMessage(CNode* pnode, const CNetMessage& msg) {
    if (!pnode) return;
    // Convert CNetMessage to CSerializedNetMsg
    std::string command = msg.header.GetCommand();
    std::vector<uint8_t> data = msg.Serialize();
    CSerializedNetMsg serialized(std::move(command), std::move(data));
    PushMessage(pnode, std::move(serialized));
}

void CConnman::WakeMessageHandler() {
    {
        std::lock_guard<std::mutex> lock(mutexMsgProc);
        fMsgProcWake.store(true);
    }
    condMsgProc.notify_one();
}

void CConnman::ThreadSocketHandler() {
    LogPrintf(NET, INFO, "[CConnman] ThreadSocketHandler started\n");

    // Track when we last ran inactivity check (don't run every iteration)
    auto last_inactivity_check = std::chrono::steady_clock::now();
    static constexpr int INACTIVITY_CHECK_INTERVAL_SECONDS = 10;

    // dilv-dedup-livelock-fix (F-007): track when we last swept the rate-limit /
    // dedup maps. PeriodicRateLimitCleanup was DEAD (no caller), so the per-peer
    // map-size cap (MAX_RATE_LIMIT_MAP_SIZE) never ran. Wire it on the same loop as
    // the inactivity check, gated to ~every 60s. This is belt-and-suspenders behind
    // NEW-1 (per-disconnect cleanup): with NEW-1 the maps already shrink on every
    // disconnect, so this sweep is a backstop against any path that leaves residue.
    auto last_ratelimit_cleanup = std::chrono::steady_clock::now();
    static constexpr int RATELIMIT_CLEANUP_INTERVAL_SECONDS = 60;

    while (!interruptNet.load()) {
        DisconnectNodes();
        SocketHandler();

        // Run inactivity check periodically (every 10 seconds)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_inactivity_check).count()
                >= INACTIVITY_CHECK_INTERVAL_SECONDS) {
            InactivityCheck();
            last_inactivity_check = now;
        }

        // Sweep stale rate-limit / dedup state periodically (every 60 seconds).
        // Lock-safe here: this is OUTSIDE the cs_vNodes scope, and
        // PeriodicRateLimitCleanup acquires only the rate-limit mutexes.
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_ratelimit_cleanup).count()
                >= RATELIMIT_CLEANUP_INTERVAL_SECONDS) {
            PeriodicRateLimitCleanup();
            last_ratelimit_cleanup = now;
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadSocketHandler stopped\n");
}

void CConnman::ThreadMessageHandler() {
    LogPrintf(NET, INFO, "[CConnman] ThreadMessageHandler started (async dispatch mode)\n");

    while (!flagInterruptMsgProc.load()) {
        bool fMoreWork = false;

        // IBD Redesign Phase 1: Collect messages and route by type
        // Headers and blocks go to async queues (never block this thread)
        // Control messages (version, verack, ping, pong, etc.) process inline (fast)

        struct PendingMessage {
            int node_id;
            CProcessedMsg msg;
        };
        std::vector<PendingMessage> pending_messages;

        // Collect messages while holding cs_vNodes (short lock duration)
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);

            // Fairness: Max messages per node per batch
            constexpr int MAX_MSGS_PER_NODE_PER_BATCH = 50;
            // Global batch limit
            constexpr int MAX_MSGS_TOTAL_PER_BATCH = 500;

            for (auto& node : m_nodes) {
                if (node->fDisconnect.load()) {
                    continue;
                }

                int msgs_from_this_node = 0;
                CProcessedMsg processed_msg;
                while (node->PopProcessMsg(processed_msg)) {
                    // PIPELINE COUNTER: Step 3 - Block popped from node's vProcessMsg
                    if (processed_msg.command == "block") {
                        g_blocks_popped_from_node++;
                    }
                    pending_messages.push_back({node->id, std::move(processed_msg)});
                    msgs_from_this_node++;

                    if (msgs_from_this_node >= MAX_MSGS_PER_NODE_PER_BATCH) {
                        break;
                    }
                    if (pending_messages.size() >= static_cast<size_t>(MAX_MSGS_TOTAL_PER_BATCH)) {
                        fMoreWork = true;
                        break;
                    }
                }

                if (node->HasProcessMsgs()) {
                    fMoreWork = true;
                }

                if (pending_messages.size() >= static_cast<size_t>(MAX_MSGS_TOTAL_PER_BATCH)) {
                    break;
                }
            }
        }
        // cs_vNodes released

        // Route messages by type
        int headers_queued = 0;
        int blocks_queued = 0;
        int control_processed = 0;

        for (const auto& pending : pending_messages) {
            const std::string& cmd = pending.msg.command;

            // IBD Redesign: Route headers and blocks to async queues
            if (cmd == "headers") {
                // Queue for async processing - NEVER BLOCK HERE
                {
                    std::lock_guard<std::mutex> lock(m_headers_queue_mutex);
                    // BUG #275: Drop oldest headers if queue is full to prevent OOM
                    if (m_headers_queue.size() >= MAX_HEADERS_QUEUE_SIZE) {
                        m_headers_queue.pop();
                        LogPrintf(NET, WARN, "[CConnman] Headers queue full (%zu), dropped oldest entry\n",
                                  MAX_HEADERS_QUEUE_SIZE);
                    }
                    m_headers_queue.push({pending.node_id, pending.msg.command, pending.msg.data});
                }
                m_headers_cv.notify_one();
                headers_queued++;
            }
            else if (cmd == "block") {
                // Queue for async processing - NEVER BLOCK HERE
                {
                    std::lock_guard<std::mutex> lock(m_blocks_queue_mutex);
                    // BUG #275: Drop oldest blocks if queue is full to prevent OOM
                    if (m_blocks_queue.size() >= MAX_BLOCKS_QUEUE_SIZE) {
                        m_blocks_queue.pop();
                        LogPrintf(NET, WARN, "[CConnman] Blocks queue full (%zu), dropped oldest entry\n",
                                  MAX_BLOCKS_QUEUE_SIZE);
                    }
                    m_blocks_queue.push({pending.node_id, pending.msg.command, pending.msg.data});
                }
                m_blocks_cv.notify_one();
                blocks_queued++;
                // PIPELINE COUNTER: Step 4 - Block pushed to m_blocks_queue
                g_blocks_routed_to_queue++;
            }
            else {
                // Control messages: process inline (fast - version, verack, ping, pong, inv, getdata, etc.)
                bool success = ProcessQueuedMessage({pending.node_id, pending.msg.command, pending.msg.data});
                if (!success) {
                    LogPrintf(NET, WARN, "[CConnman] Failed to process control message '%s' from node %d\n",
                              cmd.c_str(), pending.node_id);
                }
                control_processed++;
            }
        }

        // Log routing summary (reduced logging)
        if (headers_queued > 0 || blocks_queued > 0) {
            LogPrintf(NET, DEBUG, "[CConnman] Routed: %d headers, %d blocks to async; %d control inline\n",
                      headers_queued, blocks_queued, control_processed);
        }

        // Wait for more work
        if (!fMoreWork && !flagInterruptMsgProc.load()) {
            std::unique_lock<std::mutex> lock(mutexMsgProc);
            condMsgProc.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return fMsgProcWake.load() || flagInterruptMsgProc.load();
            });
            fMsgProcWake.store(false);
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadMessageHandler stopped\n");
}

// IBD Redesign Phase 1: Helper to process a queued message
bool CConnman::ProcessQueuedMessage(const QueuedMessage& msg) {
    // Convert to CNetMessage
    CNetMessage message(msg.command, msg.data);

    // Process using message processor or fallback handler
    bool success = false;
    if (m_msg_processor) {
        success = m_msg_processor->ProcessMessage(msg.node_id, message);
    } else if (m_msg_handler) {
        // Fallback to callback if processor not set
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            if (node->id == msg.node_id && !node->fDisconnect.load()) {
                success = m_msg_handler(node.get(), msg.command, msg.data);
                break;
            }
        }
    }

    // Handle misbehavior tracking on failure
    if (!success && m_peer_manager) {
        auto peer = m_peer_manager->GetPeer(msg.node_id);
        // Phase 2 port: misbehavior_score moved into CPeerScorer; query via
        // the manager's accessor.
        const int score = m_peer_manager->GetMisbehaviorScore(msg.node_id);
        if (peer && score > 100) {
            LogPrintf(NET, INFO, "[CConnman] Disconnecting node %d due to misbehavior (score: %d)\n",
                      msg.node_id, score);
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (auto& node : m_nodes) {
                if (node->id == msg.node_id) {
                    node->MarkDisconnect();
                    break;
                }
            }
        }
    }

    return success;
}

// IBD Redesign Phase 1: Headers worker thread
// Processes headers messages asynchronously - headers processing can take 100+ seconds
// for 2000 headers with RandomX, so this MUST NOT block the message handler
void CConnman::HeadersWorkerThread() {
    LogPrintf(NET, INFO, "[CConnman] HeadersWorkerThread started\n");

    while (!flagInterruptMsgProc.load()) {
        QueuedMessage msg;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_headers_queue_mutex);
            m_headers_cv.wait(lock, [this] {
                return !m_headers_queue.empty() || flagInterruptMsgProc.load();
            });

            if (flagInterruptMsgProc.load()) {
                break;
            }

            if (m_headers_queue.empty()) {
                continue;
            }

            msg = std::move(m_headers_queue.front());
            m_headers_queue.pop();
        }

        // Process headers message (expensive - RandomX hash computation)
        LogPrintf(NET, DEBUG, "[HeadersWorker] Processing headers from node %d\n", msg.node_id);
        auto start = std::chrono::steady_clock::now();

        bool success = ProcessQueuedMessage(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        LogPrintf(NET, DEBUG, "[HeadersWorker] Processed headers from node %d in %lld ms (success=%d)\n",
                  msg.node_id, elapsed, success);
    }

    LogPrintf(NET, INFO, "[CConnman] HeadersWorkerThread stopped\n");
}

// IBD Redesign Phase 1: Blocks worker thread
// Processes block messages asynchronously - block validation can take time
// and we don't want to block the message handler
void CConnman::BlocksWorkerThread() {
    LogPrintf(NET, INFO, "[CConnman] BlocksWorkerThread started\n");

    while (!flagInterruptMsgProc.load()) {
        QueuedMessage msg;

        // Wait for work
        {
            std::unique_lock<std::mutex> lock(m_blocks_queue_mutex);
            m_blocks_cv.wait(lock, [this] {
                return !m_blocks_queue.empty() || flagInterruptMsgProc.load();
            });

            if (flagInterruptMsgProc.load()) {
                break;
            }

            if (m_blocks_queue.empty()) {
                continue;
            }

            msg = std::move(m_blocks_queue.front());
            m_blocks_queue.pop();
        }

        // PIPELINE COUNTER: Step 5 - Block popped by BlocksWorkerThread
        g_blocks_worker_received++;

        // Process block message
        LogPrintf(NET, DEBUG, "[BlocksWorker] Processing block from node %d\n", msg.node_id);
        auto start = std::chrono::steady_clock::now();

        bool success = ProcessQueuedMessage(msg);

        // PIPELINE COUNTER: Step 6 - Block processed
        g_blocks_processed++;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        LogPrintf(NET, DEBUG, "[BlocksWorker] Processed block from node %d in %lld ms (success=%d)\n",
                  msg.node_id, elapsed, success);

        // PIPELINE COUNTER SUMMARY - Log every block to find where they drop
        LogPrintf(NET, INFO, "[PIPELINE] extracted=%d pushed=%d popped=%d routed=%d worker=%d processed=%d\n",
                  g_blocks_extracted.load(), g_blocks_pushed_to_node.load(),
                  g_blocks_popped_from_node.load(), g_blocks_routed_to_queue.load(),
                  g_blocks_worker_received.load(), g_blocks_processed.load());
    }

    LogPrintf(NET, INFO, "[CConnman] BlocksWorkerThread stopped\n");
}

void CConnman::AddManualNode(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::mutex> lock(cs_manual_nodes);
    std::string ip = addr.ToStringIP();
    // Avoid duplicates — compare by ip:port (not just IP)
    // Supports multiple manual nodes on the same IP with different ports
    for (const auto& existing : m_manual_nodes) {
        if (existing.ToStringIP() == ip && existing.port == addr.port) {
            return;
        }
    }
    m_manual_nodes.push_back(addr);
    LogPrintf(NET, INFO, "[CConnman] Added manual node %s:%d (auto-reconnect enabled)\n",
              ip.c_str(), addr.port);
}

void CConnman::RemoveManualNode(const std::string& ip_str) {
    std::lock_guard<std::mutex> lock(cs_manual_nodes);
    m_manual_nodes.erase(
        std::remove_if(m_manual_nodes.begin(), m_manual_nodes.end(),
            [&ip_str](const NetProtocol::CAddress& a) {
                return a.ToStringIP() == ip_str;
            }),
        m_manual_nodes.end());
    LogPrintf(NET, INFO, "[CConnman] Removed manual node %s (auto-reconnect disabled)\n",
              ip_str.c_str());
}

void CConnman::ThreadOpenConnections() {
    LogPrintf(NET, INFO, "[CConnman] ThreadOpenConnections started\n");

    // Phase 4 port: per-class outbound targets, sourced from chainparams.
    //   FullRelay   — default (Bitcoin's 8 for both chains)
    //   BlockRelay  — DilV 4, DIL 2 (plan §10 Q4 — DilV's 45s blocks
    //                 benefit from faster propagation)
    const size_t TARGET_FULL_RELAY = (Dilithion::g_chainParams != nullptr)
        ? static_cast<size_t>(Dilithion::g_chainParams->nOutboundFullRelayTarget) : 8;
    const size_t TARGET_BLOCK_RELAY = (Dilithion::g_chainParams != nullptr)
        ? static_cast<size_t>(Dilithion::g_chainParams->nOutboundBlockRelayTarget) : 2;
    constexpr int CONNECTION_INTERVAL_SECONDS = 10;  // Check every 10 seconds (was 60)

    while (!interruptNet.load()) {
        // Wait for connection interval or interrupt
        for (int i = 0; i < CONNECTION_INTERVAL_SECONDS && !interruptNet.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (interruptNet.load()) {
            break;
        }

        if (!m_peer_manager || !m_msg_processor) {
            continue;  // Not initialized yet
        }

        // Get currently connected peer IPs (both inbound AND outbound)
        // connected_ips: IP-only for seed/AddrMan dedup (one connection per IP)
        // connected_endpoints: ip:port for manual node reconnect (supports multiple ports per IP)
        std::set<std::string> connected_ips;
        std::set<std::string> connected_endpoints;
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (const auto& node : m_nodes) {
                if (node && !node->fDisconnect.load()) {
                    connected_ips.insert(node->addr.ToStringIP());
                    connected_endpoints.insert(node->addr.ToStringIP() + ":" + std::to_string(node->addr.port));
                }
            }
        }

        // PHASE 1: Ensure seed nodes are connected (skip if --connect used)
        if (!m_connect_only) {
        auto seeds = m_peer_manager->GetSeedNodes();
        for (const auto& seed_addr : seeds) {
            std::string seed_ip = seed_addr.ToStringIP();

            // Skip if already connected to this seed
            if (connected_ips.count(seed_ip)) {
                continue;
            }

            // Skip non-routable (shouldn't happen for seeds)
            if (!seed_addr.IsRoutable()) {
                continue;
            }

            // Attempt connection to seed
            LogPrintf(NET, INFO, "[CConnman] Connecting to seed node %s:%d\n",
                      seed_ip.c_str(), seed_addr.port);
            CNode* pnode = ConnectNode(seed_addr);
            if (pnode) {
                // Note: Connection is async - STATE_CONNECTING until TCP handshake completes
                // Don't mark as "connected" yet - SocketHandler will log when connection succeeds
                connected_ips.insert(std::move(seed_ip));  // Move instead of copy (perf fix)
                // NOTE: Do NOT call MarkAddressGood here - handshake hasn't completed yet.
                // Good is called after VERACK (ProcessVerackMessage).
            }
        }

        // PHASE 2: Per-class outbound fill (Phase 4 port).
        // Count current outbound by class, then fill FullRelay slots first
        // (chain-of-blocks sync priority), then BlockRelay slots (anti-
        // eclipse). Both classes draw from AddrMan via the same
        // SelectAddressesToConnect path; the class is set on the resulting
        // CNode at construction.
        size_t full_relay_count = 0;
        size_t block_relay_count = 0;
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (const auto& node : m_nodes) {
                if (!node || node->fInbound || node->fDisconnect.load()) continue;
                if (node->fManual) continue;  // Manual is its own bucket
                switch (node->m_outbound_class) {
                    case CNode::OutboundClass::FullRelay:  ++full_relay_count;  break;
                    case CNode::OutboundClass::BlockRelay: ++block_relay_count; break;
                    default: break;
                }
            }
        }

        auto fill_class = [&](CNode::OutboundClass cls,
                              size_t current,
                              size_t target,
                              const char* class_name) {
            if (current >= target) return;
            const size_t needed = target - current;
            auto addrs = m_peer_manager->SelectAddressesToConnect(
                static_cast<int>(needed * 3));
            size_t made = 0;
            for (const auto& addr : addrs) {
                if (made >= needed) break;
                std::string ip_str = addr.ToStringIP();
                if (connected_ips.count(ip_str)) continue;
                if (!addr.IsRoutable()) continue;
                m_peer_manager->MarkAddressTried(addr);
                CNode* pnode = ConnectNode(addr, /*manual=*/false, cls);
                if (pnode) {
                    LogPrintf(NET, INFO,
                        "[CConnman] ThreadOpenConnections: connected to %s as %s (node %d)\n",
                        ip_str.c_str(), class_name, pnode->id);
                    ++made;
                    connected_ips.insert(std::move(ip_str));
                }
            }
            if (made > 0) {
                LogPrintf(NET, INFO,
                    "[CConnman] Made %zu new %s outbound connection(s) from AddrMan\n",
                    made, class_name);
            }
        };

        fill_class(CNode::OutboundClass::FullRelay,  full_relay_count,
                   TARGET_FULL_RELAY,  "FullRelay");
        fill_class(CNode::OutboundClass::BlockRelay, block_relay_count,
                   TARGET_BLOCK_RELAY, "BlockRelay");

        } // end !m_connect_only (skip seeds + AddrMan when --connect used)

        // PHASE 3: Auto-reconnect manual nodes (Bitcoin Core pattern)
        // --connect, --addnode, and RPC addnode peers are automatically reconnected
        // Uses ip:port matching (not just IP) to support multiple manual nodes on same IP
        // Backoff: wait 60s between reconnect attempts per endpoint to avoid ID leak
        {
            static std::map<std::string, std::chrono::steady_clock::time_point> s_lastReconnectAttempt;
            auto now_tp = std::chrono::steady_clock::now();

            std::lock_guard<std::mutex> lock(cs_manual_nodes);
            for (const auto& manual_addr : m_manual_nodes) {
                std::string manual_ip = manual_addr.ToStringIP();
                std::string manual_endpoint = manual_ip + ":" + std::to_string(manual_addr.port);
                if (connected_endpoints.count(manual_endpoint)) {
                    s_lastReconnectAttempt.erase(manual_endpoint);  // Reset backoff on success
                    continue;  // Already connected to this ip:port
                }

                // Backoff: don't retry more than once per 60s per endpoint
                auto it = s_lastReconnectAttempt.find(manual_endpoint);
                if (it != s_lastReconnectAttempt.end()) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now_tp - it->second).count();
                    if (elapsed < 60) continue;
                }
                s_lastReconnectAttempt[manual_endpoint] = now_tp;

                LogPrintf(NET, INFO, "[CConnman] Auto-reconnecting manual node %s:%d\n",
                          manual_ip.c_str(), manual_addr.port);
                CNode* pnode = ConnectNode(manual_addr, true);
                if (pnode) {
                    connected_endpoints.insert(std::move(manual_endpoint));
                    connected_ips.insert(std::move(manual_ip));
                }
            }
        }
    }

    LogPrintf(NET, INFO, "[CConnman] ThreadOpenConnections stopped\n");
}

void CConnman::SocketHandler() {
    std::set<int> recv_set, send_set, error_set;

    // Collect sockets
    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (const auto& node : m_nodes) {
            int sock = node->GetSocket();
            if (sock < 0) continue;
            if (node->fDisconnect.load()) {
                LogPrintf(NET, DEBUG, "[CConnman] Node %d marked for disconnect, skipping\n", node->id);
                continue;
            }

            recv_set.insert(sock);
            // Add to send_set if: has messages to send OR connection is in progress
            // For non-blocking connect(), writability indicates connection completed
            int node_state = node->state.load();
            bool has_send = node->HasSendMsgs();
            if (has_send || node_state == CNode::STATE_CONNECTING) {
                send_set.insert(sock);
            }
            error_set.insert(sock);

            // Debug: Log each node's state periodically (every 100th call)
            static int call_count = 0;
            if (++call_count % 100 == 0) {
                LogPrintf(NET, DEBUG, "[CConnman] SocketHandler: node %d state=%d has_send=%d sock=%d\n",
                          node->id, node_state, has_send, sock);
            }
        }
    }

    // Add listen socket
    if (CSock::IsValid(m_listen_socket)) {
        recv_set.insert(m_listen_socket);
    }

    // Wait for events
    if (!SocketEventsSelect(recv_set, send_set, error_set)) {
        return;  // Timeout or interrupt
    }

    // Handle listen socket (new connections)
    // BUG #137 FIX: Loop to accept ALL pending connections, not just one
    // Multiple connections can arrive between select() calls
    if (CSock::IsValid(m_listen_socket) && recv_set.count(m_listen_socket)) {
        while (true) {
            struct sockaddr_storage client_addr;
            socklen_t addr_len = sizeof(client_addr);

            socket_t client_fd = accept(m_listen_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (!CSock::IsValid(client_fd)) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) {
                    LogPrintf(NET, ERROR, "[CConnman] Accept failed: %d\n", err);
                }
#else
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LogPrintf(NET, ERROR, "[CConnman] Accept failed: %d\n", errno);
                }
#endif
                break;  // No more pending connections
            }

            // Set non-blocking
            if (!CSock::SetNonBlocking(client_fd)) {
                LogPrintf(NET, ERROR, "[CConnman] SocketHandler: Failed to set non-blocking\n");
                CSock::Close(client_fd);
                continue;
            }

            // Extract address (unwraps IPv4-mapped IPv6 for backward compatibility)
            std::string ip_str_buf;
            uint16_t port;
            if (!CSock::ExtractAddress(client_addr, ip_str_buf, port)) {
                LogPrintf(NET, ERROR, "[CConnman] SocketHandler: Failed to extract address\n");
                CSock::Close(client_fd);
                continue;
            }
            const char* ip_str = ip_str_buf.c_str();

            // Create address (SetFromString handles both IPv4 and IPv6)
            NetProtocol::CAddress addr;
            addr.SetFromString(ip_str_buf);
            addr.port = port;
            addr.services = NetProtocol::NODE_NETWORK;

            // Create CNode first (before locking)
            int node_id = m_next_node_id++;
            auto node = std::make_unique<CNode>(node_id, addr, true);  // true = inbound
            CNode* pnode = node.get();

            pnode->SetSocket(static_cast<int>(client_fd));
            pnode->state.store(CNode::STATE_CONNECTED);

            // Per-IP connection limit with outbound duplicate prevention
            // Rule 1: If we already have an OUTBOUND to this IP, reject (same node, wasteful)
            // Rule 2: Allow up to nMaxInboundPerIP INBOUND from same IP (NAT: multiple nodes behind one router)
            const int max_per_ip = m_options.nMaxInboundPerIP;
            {
                std::lock_guard<std::mutex> lock(cs_vNodes);

                bool has_outbound = false;
                int inbound_count = 0;       // inbound from THIS ip (per-IP cap)
                size_t total_inbound = 0;    // all inbound (global inbound cap)
                size_t total_count = m_nodes.size();  // all nodes (global total cap)
                for (const auto& existing_node : m_nodes) {
                    if (existing_node && !existing_node->fDisconnect.load()) {
                        if (existing_node->fInbound) {
                            ++total_inbound;
                        }
                        if (existing_node->addr.ToStringIP() == std::string(ip_str)) {
                            if (!existing_node->fInbound) {
                                has_outbound = true;
                                break;
                            }
                            ++inbound_count;
                        }
                    }
                }

                if (has_outbound) {
                    LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (already have outbound connection)\n", ip_str);
                    // Node destructor will close socket
                    continue;  // Skip to next pending connection
                }

                if (inbound_count >= max_per_ip) {
                    LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (%d inbound connections, max %d per IP)\n",
                              ip_str, inbound_count, max_per_ip);
                    // Node destructor will close socket
                    continue;  // Skip to next pending connection
                }

                // Global cap enforcement (2026-06-01 fix): the dedicated
                // AcceptConnection() helper enforces nMaxInbound/nMaxTotal
                // (connman.cpp:445-471), but it has NO production caller — every
                // real inbound is accepted here in SocketHandler, which previously
                // enforced ONLY the per-IP cap. peers.size()/m_nodes could
                // therefore race up to MAX_TOTAL_CONNECTIONS unchecked. Mirror
                // AcceptConnection's caps. We intentionally do NOT call
                // EvictPeersIfNeeded() here: it would acquire CPeerManager's
                // cs_peers/cs_nodes while we hold cs_vNodes (extra cross-object
                // lock nesting in a hot accept path), and — since eviction now
                // marks-for-disconnect rather than freeing synchronously — it
                // would not free a slot this pass anyway. PeriodicMaintenance runs
                // eviction on its own cadence; here we simply reject over-cap
                // inbounds so the maps cannot exceed the configured limits.
                if (total_inbound >= static_cast<size_t>(m_options.nMaxInbound)) {
                    LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (inbound limit reached %zu/%d)\n",
                              ip_str, total_inbound, m_options.nMaxInbound);
                    // Node destructor will close socket
                    continue;  // Skip to next pending connection
                }

                if (total_count >= static_cast<size_t>(m_options.nMaxTotal)) {
                    LogPrintf(NET, WARN, "[CConnman] Rejecting inbound from %s (total connection limit reached %zu/%d)\n",
                              ip_str, total_count, m_options.nMaxTotal);
                    // Node destructor will close socket
                    continue;  // Skip to next pending connection
                }

                // FIX: Register with CPeerManager BEFORE adding to m_nodes
                // This prevents race condition where VERSION handler calls AddPeerWithId
                // before RegisterNode populates node_refs
                //
                // BUG #148 ROOT CAUSE FIX: Check return value!
                // If RegisterNode returns false (banned IP), do NOT add to m_nodes
                // Otherwise GetNode() will return nullptr during handshake
                if (!DispatchPeerConnected(node_id, pnode, addr, true)) {
                    LogPrintf(NET, WARN, "[CConnman] Rejecting banned inbound from %s\n", ip_str);
                    // Node destructor will close socket
                    continue;  // Skip to next pending connection
                }

                // Not a duplicate and not banned - add to m_nodes (still holding lock)
                m_nodes.push_back(std::move(node));
            }

            LogPrintf(NET, INFO, "[CConnman] Accepted inbound connection from %s:%d (node %d)\n",
                      ip_str, port, node_id);
        }
    }

    // Handle each node
    bool fWakeMessageHandler = false;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);
        for (auto& node : m_nodes) {
            int sock = node->GetSocket();
            if (sock < 0) continue;

            // Check for errors
            if (error_set.count(sock)) {
                node->MarkDisconnect();
                continue;
            }

            // Check for connect completion (writability on CONNECTING socket)
            if (node->state.load() == CNode::STATE_CONNECTING && send_set.count(sock)) {
                // Check if connection completed successfully
                int error = 0;
                socklen_t len = sizeof(error);
#ifdef _WIN32
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&error, &len) == 0) {
#else
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
#endif
                    if (error == 0) {
                        // Connection succeeded
                        node->state.store(CNode::STATE_CONNECTED);
                        LogPrintf(NET, INFO, "[CConnman] Connection established to node %d\n", node->id);

                        // BUG #139 FIX: Send VERSION immediately after connection completes
                        // Only send if node is outbound and VERSION hasn't been sent yet
                        if (!node->fInbound && !node->fVersionSent.load()) {
                            if (m_msg_processor) {
                                // PEER DISCOVERY FIX: Use learned external IP instead of 0.0.0.0
                                NetProtocol::CAddress local_addr;
                                local_addr.services = NetProtocol::NODE_NETWORK;
                                std::string externalIP = GetExternalIP();
                                if (!externalIP.empty()) {
                                    local_addr.SetFromString(externalIP);
                                    local_addr.port = m_options.nListenPort;
                                } else {
                                    local_addr.SetIPv4(0);
                                    local_addr.port = 0;
                                }
                                CNetMessage version_msg = m_msg_processor->CreateVersionMessage(node->addr, local_addr);
                                PushMessage(node.get(), version_msg);
                                node->fVersionSent.store(true);
                                // BUG #148 FIX: Also update CNode::state to prevent state drift
                                node->state.store(CNode::STATE_VERSION_SENT);
                                LogPrintf(NET, INFO, "[CConnman] Sent VERSION to node %d after connect\n", node->id);

                                // SSOT FIX #1: Update CNode::state (single source of truth) first
                                // CNode::state is authoritative - CPeer::state is deprecated
                                node->state.store(CNode::STATE_VERSION_SENT);
                                node->fVersionSent.store(true);
                                // Update deprecated CPeer::state for backward compatibility
                                if (m_peer_manager) {
                                    auto peer = m_peer_manager->GetPeer(node->id);
                                    if (peer) {
                                        peer->state = CPeer::STATE_VERSION_SENT;
                                    }
                                }
                            } else {
                                LogPrintf(NET, WARN, "[CConnman] Cannot send VERSION to node %d - m_msg_processor is null\n", node->id);
                            }
                        }
                    } else {
                        // Connection failed
                        LogPrintf(NET, WARN, "[CConnman] Connection to node %d failed: error %d\n", node->id, error);
                        node->MarkDisconnect();
                        continue;
                    }
                } else {
                    // getsockopt failed
                    node->MarkDisconnect();
                    continue;
                }
            }

            // Receive
            if (recv_set.count(sock)) {
                if (!ReceiveMsgBytes(node.get())) {
                    node->MarkDisconnect();
                } else if (node->HasProcessMsgs()) {
                    fWakeMessageHandler = true;
                }
            }

            // Send (only if not just connecting)
            if (send_set.count(sock) && node->state.load() != CNode::STATE_CONNECTING) {
                if (!SendMessages(node.get())) {
                    node->MarkDisconnect();
                }
            }
        }
    }

    if (fWakeMessageHandler) {
        WakeMessageHandler();
    }
}

bool CConnman::SocketEventsSelect(std::set<int>& recv_set, std::set<int>& send_set, std::set<int>& error_set) {
    if (recv_set.empty() && send_set.empty()) {
        // Nothing to wait for, just sleep briefly
        std::this_thread::sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MS));
        return false;
    }

    fd_set fd_recv, fd_send, fd_error;
    FD_ZERO(&fd_recv);
    FD_ZERO(&fd_send);
    FD_ZERO(&fd_error);

    int max_fd = 0;

    for (int sock : recv_set) {
        FD_SET(sock, &fd_recv);
        if (sock > max_fd) max_fd = sock;
    }
    for (int sock : send_set) {
        FD_SET(sock, &fd_send);
        if (sock > max_fd) max_fd = sock;
    }
    for (int sock : error_set) {
        FD_SET(sock, &fd_error);
        if (sock > max_fd) max_fd = sock;
    }

    struct timeval timeout;
    timeout.tv_sec = SELECT_TIMEOUT_MS / 1000;
    timeout.tv_usec = (SELECT_TIMEOUT_MS % 1000) * 1000;

    int result = select(max_fd + 1, &fd_recv, &fd_send, &fd_error, &timeout);

    if (result <= 0) {
        recv_set.clear();
        send_set.clear();
        error_set.clear();
        return false;
    }

    // Update sets to only include ready sockets
    std::set<int> ready_recv, ready_send, ready_error;
    for (int sock : recv_set) {
        if (FD_ISSET(sock, &fd_recv)) ready_recv.insert(sock);
    }
    for (int sock : send_set) {
        if (FD_ISSET(sock, &fd_send)) ready_send.insert(sock);
    }
    for (int sock : error_set) {
        if (FD_ISSET(sock, &fd_error)) ready_error.insert(sock);
    }

    recv_set = std::move(ready_recv);
    send_set = std::move(ready_send);
    error_set = std::move(ready_error);

    return true;
}

bool CConnman::ReceiveMsgBytes(CNode* pnode) {
    if (!pnode) return false;

    int sock = pnode->GetSocket();
    if (sock < 0) return false;

    uint8_t buf[4096];
    int nBytes;

#ifdef _WIN32
    nBytes = recv(sock, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (nBytes == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return true;  // No data, but socket OK
        }
        LogPrintf(NET, DEBUG, "[CConnman] recv() error on node %d: %d\n", pnode->id, err);
        return false;  // Real error
    }
#else
    nBytes = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
    if (nBytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;  // No data, but socket OK
        }
        LogPrintf(NET, DEBUG, "[CConnman] recv() error on node %d: errno=%d\n", pnode->id, errno);
        return false;  // Real error
    }
#endif

    if (nBytes == 0) {
        LogPrintf(NET, INFO, "[CConnman] Connection closed by peer (node %d)\n", pnode->id);
        return false;  // Connection closed
    }

    // Append to node's receive buffer
    pnode->AppendRecvBytes(buf, nBytes);
    pnode->nRecvBytes.fetch_add(nBytes);
    pnode->nLastRecv.store(GetTime());

    // Extract complete messages from buffer and push to processing queue
    ExtractMessages(pnode);

    return true;
}

bool CConnman::SendMessages(CNode* pnode) {
    if (!pnode) return false;

    int sock = pnode->GetSocket();
    if (sock < 0) return false;

    while (pnode->HasSendMsgs()) {
        const CSerializedNetMsg* msg = pnode->GetSendMsg();
        if (!msg || msg->data.empty()) break;

        // Get current send offset (for partial sends)
        size_t offset = pnode->GetSendOffset();
        size_t remaining = msg->data.size() - offset;
        
        if (remaining == 0) {
            // Message fully sent, move to next
            pnode->MarkBytesSent(msg->data.size());
            continue;
        }

        int nBytes;
#ifdef _WIN32
        nBytes = send(sock, reinterpret_cast<const char*>(msg->data.data() + offset),
                      static_cast<int>(remaining), 0);
        if (nBytes == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                break;  // Would block, try later
            }
            return false;  // Real error
        }
#else
        nBytes = send(sock, msg->data.data() + offset, remaining, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (nBytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // Would block, try later
            }
            return false;  // Real error
        }
#endif

        if (nBytes > 0) {
            pnode->MarkBytesSent(nBytes);
            pnode->nSendBytes.fetch_add(nBytes);
            pnode->nLastSend.store(GetTime());
        }
    }

    return true;
}

void CConnman::ExtractMessages(CNode* pnode) {
    if (!pnode) return;

    // Extract complete messages from receive buffer
    // Loop until no more complete messages can be extracted
    while (true) {
        // Use thread-safe locked accessor - lock is held for entire scope
        auto [lock, buffer] = pnode->GetLockedRecvBuffer();

        // Need at least 24 bytes for message header
        if (buffer.size() < 24) {
            break;  // Not enough data for header
        }

        // Parse message header
        NetProtocol::CMessageHeader header;
        std::memcpy(&header.magic, buffer.data(), 4);
        std::memcpy(header.command, buffer.data() + 4, 12);
        std::memcpy(&header.payload_size, buffer.data() + 16, 4);
        std::memcpy(&header.checksum, buffer.data() + 20, 4);

        // DEBUG: Log parsed header
        std::string cmd = header.GetCommand();
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[EXTRACT-DEBUG] node=" << pnode->id << " cmd=" << cmd
                      << " payload_size=" << header.payload_size
                      << " buffer=" << buffer.size() << std::endl;

        // Validate header
        if (!header.IsValid(NetProtocol::g_network_magic)) {
            std::cout << "[P2P] ERROR: Invalid magic from node " << pnode->id
                      << " (got 0x" << std::hex << header.magic
                      << ", expected 0x" << NetProtocol::g_network_magic << std::dec << ")" << std::endl;
            
            // Clear buffer and disconnect on invalid magic
            buffer.clear();
            pnode->MarkDisconnect();
            return;
        }

        // Check payload size
        if (header.payload_size > NetProtocol::MAX_MESSAGE_SIZE) {
            std::cout << "[P2P] ERROR: Payload too large from node " << pnode->id
                      << " (" << header.payload_size << " bytes)" << std::endl;
            
            // Clear buffer and disconnect on oversized message
            buffer.clear();
            pnode->MarkDisconnect();
            return;
        }

        // Calculate total message size
        size_t total_size = 24 + header.payload_size;

        // Check if we have the complete message
        if (buffer.size() < total_size) {
            // Log partial message waiting (verbose only — very noisy during sync)
            if (g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[EXTRACT-PARTIAL] node=" << pnode->id << " cmd=" << cmd
                          << " need=" << total_size << " have=" << buffer.size() << std::endl;
            }
            break;  // Partial message, need more data
        }

        // Extract payload
        std::vector<uint8_t> payload;
        if (header.payload_size > 0) {
            payload.assign(buffer.begin() + 24, buffer.begin() + 24 + header.payload_size);

            // Verify checksum (Bitcoin Core pattern - critical for message integrity)
            uint32_t calculated_checksum = CDataStream::CalculateChecksum(payload);
            if (calculated_checksum != header.checksum) {
                std::cout << "[P2P] ERROR: Checksum mismatch from node " << pnode->id
                          << " (got 0x" << std::hex << header.checksum
                          << ", expected 0x" << calculated_checksum << std::dec << ")" << std::endl;
                
                // Clear buffer and disconnect on checksum failure
                buffer.clear();
                pnode->MarkDisconnect();
                
                // Penalize node for checksum failure (could be attack or corruption)
                if (m_peer_manager) {
                    // Find corresponding peer if it exists
                    auto peers = m_peer_manager->GetAllPeers();
                    for (auto& peer : peers) {
                        if (peer->id == pnode->id) {
                            m_peer_manager->Misbehaving(peer->id, 50, MisbehaviorType::INVALID_CHECKSUM);
                            break;
                        }
                    }
                }
                return;
            }
        }

        // Remove processed message from buffer
        buffer.erase(buffer.begin(), buffer.begin() + total_size);

        // Create processed message and push to queue
        std::string command = header.GetCommand();

        // Log extracted messages (verbose only)
        if (g_verbose.load(std::memory_order_relaxed) && (command == "headers" || command == "block")) {
            std::cout << "[EXTRACT] node=" << pnode->id << " cmd=" << command
                      << " payload=" << header.payload_size << " bytes" << std::endl;
        } else if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[EXTRACT-PUSHED] node=" << pnode->id << " cmd=" << command
                      << " payload_size=" << header.payload_size << std::endl;
        }

        // PIPELINE COUNTER: Step 1 & 2 - Block extracted from TCP and pushed to vProcessMsg
        // Note: Steps 1 & 2 are atomic (PushProcessMsg is just a vector push)
        bool is_block = (command == "block");
        if (is_block) {
            g_blocks_extracted++;
            g_blocks_pushed_to_node++;
        }

        CProcessedMsg processed_msg(std::move(command), std::move(payload));
        pnode->PushProcessMsg(std::move(processed_msg));
    }
}

void CConnman::DisconnectNodes() {
    // BUG #148 + BUG #153 FIX: Remove from CPeerManager BEFORE destroying CNode
    // This eliminates race window where node_refs could point to freed memory
    std::vector<int> nodes_to_remove;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);

        auto it = m_nodes.begin();
        while (it != m_nodes.end()) {
            if ((*it)->fDisconnect.load()) {
                int node_id = (*it)->id;
                nodes_to_remove.push_back(node_id);

                // BUG #262 FIX (Memory Leak): Call OnPeerDisconnected BEFORE RemoveNode
                // OnPeerDisconnected calls GetAndClearPeerBlocks which needs the peer
                // to exist in the peers map to clean up mapBlocksInFlight entries.
                // If RemoveNode is called first, GetAndClearPeerBlocks bails early
                // and mapBlocksInFlight entries are never cleaned up = memory leak.
                DispatchPeerDisconnected(node_id);

                // BUG #153 FIX: Remove from CPeerManager BEFORE destroying CNode
                // This ensures node_refs is cleared while CNode still exists.
                if (m_peer_manager) {
                    m_peer_manager->RemoveNode(node_id);
                }

                (*it)->CloseSocket();
                it = m_nodes.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void CConnman::InactivityCheck() {
    // Constants for keepalive
    static constexpr int64_t PING_INTERVAL_SECONDS = 60;      // Send ping after 60s of inactivity
    static constexpr int64_t TIMEOUT_SECONDS = 120;           // Disconnect after 120s of no response
    static constexpr int64_t HANDSHAKE_TIMEOUT_SECONDS = 30;  // Disconnect if no VERSION exchange after 30s
    static constexpr int64_t VERACK_TIMEOUT_SECONDS = 60;     // Disconnect if VERSION sent but no VERACK after 60s

    // Track last ping sent time per node (static to persist across calls)
    static std::map<int, int64_t> last_ping_sent;

    int64_t now = GetTime();
    std::vector<int> nodes_to_disconnect;

    {
        std::lock_guard<std::mutex> lock(cs_vNodes);

        for (auto& node : m_nodes) {
            if (node->fDisconnect.load()) continue;

            // Skip nodes that haven't established TCP connection yet
            if (node->state.load() < CNode::STATE_CONNECTED) continue;

            int64_t last_recv = node->nLastRecv.load();
            int node_id = node->id;
            CNode::State node_state = node->state.load();

            // BUG #148 FIX: Check for handshake timeout
            // Only timeout nodes stuck in STATE_CONNECTED (no VERSION exchange at all)
            // Don't timeout STATE_VERSION_SENT - they've made progress and VERACK should follow
            // The old code timed out VERSION_SENT nodes, causing a race condition where:
            //   1. Node in VERSION_SENT receives VERACK and queues it for processing
            //   2. InactivityCheck sees node_state < HANDSHAKE_COMPLETE, marks for disconnect
            //   3. Node removed from node_refs before VERACK is processed
            //   4. ProcessVerackMessage can't find node, CNode::state never updated
            //   5. Node excluded from block downloads (GetValidPeersForDownload checks CNode::state)
            if (node_state == CNode::STATE_CONNECTED) {
                int64_t connect_time = node->nTimeConnected;
                if (connect_time > 0 && (now - connect_time) > HANDSHAKE_TIMEOUT_SECONDS) {
                    LogPrintf(NET, WARN, "[CConnman] Node %d handshake timeout (state=%d, no VERSION exchange in %llds)\n",
                              node_id, static_cast<int>(node_state), now - connect_time);
                    nodes_to_disconnect.push_back(node_id);
                    continue;
                }
            } else if (node_state == CNode::STATE_VERSION_SENT) {
                // VERSION exchanged but no VERACK yet - use longer timeout
                // This catches peers that send VERSION but never complete handshake
                int64_t connect_time = node->nTimeConnected;
                if (connect_time > 0 && (now - connect_time) > VERACK_TIMEOUT_SECONDS) {
                    LogPrintf(NET, WARN, "[CConnman] Node %d VERACK timeout (VERSION sent but no VERACK in %llds)\n",
                              node_id, now - connect_time);
                    nodes_to_disconnect.push_back(node_id);
                    continue;
                }
            }

            // If we've never received anything, use connect time
            if (last_recv == 0) {
                // Node just connected, give it time
                continue;
            }

            int64_t idle_time = now - last_recv;

            // Check if node is completely unresponsive (no data for TIMEOUT_SECONDS)
            if (idle_time > TIMEOUT_SECONDS) {
                // Check if we already sent a ping and got no response
                auto it = last_ping_sent.find(node_id);
                if (it != last_ping_sent.end() && (now - it->second) > PING_INTERVAL_SECONDS) {
                    // Ping was sent but no response - disconnect
                    LogPrintf(NET, WARN, "[CConnman] Node %d unresponsive for %llds, disconnecting\n",
                              node_id, idle_time);
                    nodes_to_disconnect.push_back(node_id);
                    last_ping_sent.erase(it);
                    continue;
                }
            }

            // Send ping if idle for PING_INTERVAL_SECONDS and we haven't pinged recently
            if (idle_time > PING_INTERVAL_SECONDS) {
                auto it = last_ping_sent.find(node_id);
                bool should_ping = (it == last_ping_sent.end()) ||
                                   (now - it->second > PING_INTERVAL_SECONDS);

                if (should_ping && m_msg_processor) {
                    // Generate random nonce for ping (CWE-676 fix: use std::random_device instead of rand())
                    static thread_local std::random_device rd;
                    uint64_t nonce = (static_cast<uint64_t>(rd()) << 32) | rd();
                    CNetMessage ping_msg = m_msg_processor->CreatePingMessage(nonce);
                    PushMessage(node.get(), ping_msg);
                    last_ping_sent[node_id] = now;

                    LogPrintf(NET, INFO, "[CConnman] Sent keepalive ping to node %d (idle %llds)\n",
                              node_id, idle_time);
                }
            }
        }
    }

    // Disconnect unresponsive nodes
    for (int node_id : nodes_to_disconnect) {
        DisconnectNode(node_id, "inactivity timeout");
    }

    // Clean up stale entries from last_ping_sent for disconnected nodes
    for (auto it = last_ping_sent.begin(); it != last_ping_sent.end(); ) {
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(cs_vNodes);
            for (const auto& node : m_nodes) {
                if (node->id == it->first) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            it = last_ping_sent.erase(it);
        } else {
            ++it;
        }
    }
}

bool CConnman::IsOurAddress(const NetProtocol::CAddress& addr) const {
    // Extract IP string from address (supports both IPv4 and IPv6)
    std::string ip_str = addr.ToStringIP();

    // Check localhost variants (IPv4 and IPv6)
    if (ip_str == "127.0.0.1" || ip_str == "0.0.0.0" ||
        ip_str == "::1" || ip_str == "::") {
        return true;
    }

    // Check against known local addresses
    std::lock_guard<std::mutex> lock(cs_localAddresses);
    return m_localAddresses.count(ip_str) > 0;
}

void CConnman::RecordExternalIP(const std::string& ip, int peerId) {
    // Don't record private/local IPs - they're useless for global peer discovery
    if (ip.empty() || ip == "0.0.0.0" || ip == "::") {
        return;
    }

    // Use CNetAddr::IsRoutable() for comprehensive routability check (covers both IPv4 and IPv6)
    CNetAddr netAddr;
    if (CNetAddr::FromString(ip, netAddr)) {
        if (!netAddr.IsRoutable()) {
            return;  // Non-routable address (private, link-local, loopback, etc.)
        }
    }

    std::lock_guard<std::mutex> lock(cs_externalIP);

    // Find existing entry or create new
    bool found = false;
    for (auto& entry : m_externalIPs) {
        if (entry.ip == ip) {
            entry.score++;
            entry.lastSeen = GetTime();
            found = true;
            LogPrintf(NET, DEBUG, "[CConnman] External IP %s score increased to %d (peer %d)\n",
                      ip.c_str(), entry.score, peerId);
            break;
        }
    }

    if (!found) {
        m_externalIPs.push_back({ip, 1, GetTime()});
        LogPrintf(NET, DEBUG, "[CConnman] New external IP candidate: %s (peer %d)\n",
                  ip.c_str(), peerId);
    }

    // Update best external IP (highest score)
    int bestScore = 0;
    std::string previousBest = m_bestExternalIP;
    for (const auto& entry : m_externalIPs) {
        if (entry.score > bestScore) {
            bestScore = entry.score;
            m_bestExternalIP = entry.ip;
        }
    }

    // Log when we have confirmed external IP (2+ peers agree)
    if (bestScore >= 2 && m_bestExternalIP != previousBest) {
        LogPrintf(NET, INFO, "[CConnman] External IP detected: %s (confirmed by %d peers)\n",
                  m_bestExternalIP.c_str(), bestScore);

        // Add external IP to local addresses for self-connection prevention
        // This prevents connecting to ourselves when our own address is advertised back to us
        {
            std::lock_guard<std::mutex> lock2(cs_localAddresses);
            if (m_localAddresses.insert(m_bestExternalIP).second) {
                LogPrintf(NET, INFO, "[CConnman] Added external IP %s to self-connection filter\n",
                          m_bestExternalIP.c_str());
            }
        }
    }
}

std::string CConnman::GetExternalIP() const {
    std::lock_guard<std::mutex> lock(cs_externalIP);
    return m_bestExternalIP;
}

void CConnman::SetExternalIP(const std::string& ip) {
    {
        std::lock_guard<std::mutex> lock(cs_externalIP);
        m_bestExternalIP = ip;
    }
    LogPrintf(NET, INFO, "[CConnman] External IP set manually: %s\n", ip.c_str());

    // Add to local addresses for self-connection prevention
    {
        std::lock_guard<std::mutex> lock(cs_localAddresses);
        if (m_localAddresses.insert(ip).second) {
            LogPrintf(NET, INFO, "[CConnman] Added external IP %s to self-connection filter\n",
                      ip.c_str());
        }
    }
}
