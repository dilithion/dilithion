// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <api/http_server.h>
#include <api/http_path_gate.h>
#include <api/wallet_html.h>
#include <net/sock.h>
#include <rpc/host_validator.h>
#include <rpc/ratelimiter.h>
#include <iostream>
#include <cstring>
#include <sstream>
#include <chrono>
#ifndef _WIN32
#include <errno.h>
#endif

// Cross-platform socket headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")

    // Windows socket compatibility
    typedef int socklen_t;
    #define SHUT_RDWR SD_BOTH
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <fcntl.h>

    // Linux socket compatibility
    typedef int SOCKET;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

// Constructor
CHttpServer::CHttpServer(int port, bool public_api)
    : m_port(port), m_public_api(public_api),
      m_num_threads(DEFAULT_HTTP_THREADS),
      m_work_queue(CHttpWorkQueue<SOCKET>::DEFAULT_HTTP_WORKQUEUE) {
}

// Destructor
CHttpServer::~CHttpServer() {
    Stop();
}

// Set stats handler function
void CHttpServer::SetStatsHandler(StatsHandler handler) {
    m_stats_handler = handler;
}

// Set metrics handler function (Prometheus format)
void CHttpServer::SetMetricsHandler(MetricsHandler handler) {
    m_metrics_handler = handler;
}

// Set REST API handler function for /api/v1/* endpoints
void CHttpServer::SetRestApiHandler(RestApiHandler handler) {
    m_rest_api_handler = handler;
}

// LP-12 (H-01): configure the anti-DNS-rebinding Host allowlist. Mirrors
// CRPCServer::Start()'s m_hostValidator.Configure() exactly: the validator is
// keyed to THIS server's port and the operator-explicit extra hosts; loopback
// names are always allowed by the validator itself. Setting the ready flag last
// keeps the fail-closed invariant (an un-configured validator rejects all REST).
void CHttpServer::ConfigureHostAllowlist(const std::vector<std::string>& extraAllowedHosts) {
    m_host_validator.Configure(static_cast<uint16_t>(m_port), extraAllowedHosts);
    m_host_validator_ready.store(true);
}

// Start the HTTP server
bool CHttpServer::Start() {
    if (m_running.load()) {
        std::cerr << "[HttpServer] Already running" << std::endl;
        return false;
    }

#ifdef _WIN32
    // Initialize Winsock on Windows
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[HttpServer] WSAStartup failed: " << result << std::endl;
        return false;
    }
#endif

    // CVE-2026-RPC-CORS: Bind to 127.0.0.1 by default. Only seed nodes that
    // opt in via --public-api (and have configured RPC auth) bind to all
    // interfaces. Previously this server bound 0.0.0.0 unconditionally,
    // exposing /api/v1/* + /wallet HTML + telemetry to any LAN attacker.
    std::string bind_addr;
    if (m_public_api) {
        bind_addr = "";  // All interfaces (dual-stack IPv4+IPv6)
        std::cout << "[HttpServer] Public API mode enabled - binding to all interfaces:" << m_port << std::endl;
    } else {
        bind_addr = "127.0.0.1";  // Localhost only
    }

    socket_t http_sock;
    bool is_ipv6;
    if (!CSock::CreateListenSocket(static_cast<uint16_t>(m_port), bind_addr, http_sock, is_ipv6)) {
        std::cerr << "[HttpServer] Failed to create listen socket on port " << m_port << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    m_server_socket = http_sock;

    // Listen for connections
    if (listen(m_server_socket, 10) == SOCKET_ERROR) {
        std::cerr << "[HttpServer] Failed to listen on port " << m_port << std::endl;
        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    m_running.store(true);

    // STRESS TEST FIX: Launch worker threads first (thread pool pattern)
    // This ensures workers are ready before accept thread starts queueing
    try {
        for (int i = 0; i < m_num_threads; i++) {
            m_workers.emplace_back(&CHttpServer::WorkerThread, this);
        }
        std::cout << "[HttpServer] Started " << m_num_threads << " worker threads" << std::endl;

        // Launch accept thread
        m_accept_thread = std::thread(&CHttpServer::AcceptThread, this);

        // LP-12 (M-01): launch the rate-limiter maintenance thread so the per-IP
        // record map is pruned on a cadence (bounded memory under rotating IPs).
        m_cleanup_thread = std::thread(&CHttpServer::CleanupThread, this);

        std::cout << "[HttpServer] Started on port " << m_port << " with " << m_num_threads << " workers" << std::endl;
        return true;
    } catch (const std::exception& e) {
        m_running.store(false);
        m_work_queue.Shutdown();

        // Wait for any started workers
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        m_workers.clear();

        close(m_server_socket);
#ifdef _WIN32
        WSACleanup();
#endif
        std::cerr << "[HttpServer] Failed to start server: " << e.what() << std::endl;
        return false;
    }
}

// Stop the HTTP server
void CHttpServer::Stop() {
    if (!m_running.load()) {
        return;
    }

    std::cout << "[HttpServer] Stopping..." << std::endl;

    // Signal server to stop
    m_running.store(false);

    // Signal work queue to wake up blocked workers
    m_work_queue.Shutdown();

    // Close server socket to unblock accept()
    if (m_server_socket != INVALID_SOCKET) {
        shutdown(m_server_socket, SHUT_RDWR);
        close(m_server_socket);
        m_server_socket = INVALID_SOCKET;
    }

    // Wait for accept thread to finish
    if (m_accept_thread.joinable()) {
        m_accept_thread.join();
    }

    // LP-12 (M-01): wait for the rate-limiter maintenance thread to finish.
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }

    // Wait for worker threads to finish
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();

#ifdef _WIN32
    // Cleanup Winsock on Windows
    WSACleanup();
#endif

    std::cout << "[HttpServer] Stopped" << std::endl;
}

// Accept thread main loop - STRESS TEST FIX: Only accepts connections and queues them
void CHttpServer::AcceptThread() {
    std::cout << "[HttpServer] Accept thread started" << std::endl;

    while (m_running.load()) {
        // Accept connection (supports both IPv4 and IPv6 clients)
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        SOCKET client_socket = accept(m_server_socket,
                                       (struct sockaddr*)&client_address,
                                       &client_len);

        if (client_socket == INVALID_SOCKET) {
            if (m_running.load()) {
                std::cerr << "[HttpServer] Failed to accept connection" << std::endl;
            }
            continue;
        }

        // STRESS TEST FIX: Queue request for worker thread instead of blocking here
        // This prevents one slow request from blocking the accept loop
        if (!m_work_queue.Enqueue(client_socket)) {
            // Queue is full - send 503 Service Unavailable
            std::cerr << "[HttpServer] Work queue full, rejecting request" << std::endl;
            Send503(client_socket);
            shutdown(client_socket, SHUT_RDWR);
            close(client_socket);
        }
        // Worker thread will close the socket after handling
    }

    std::cout << "[HttpServer] Accept thread stopped" << std::endl;
}

// Worker thread main loop - STRESS TEST FIX: Processes requests from queue
void CHttpServer::WorkerThread() {
    while (m_running.load()) {
        SOCKET client_socket;

        // Wait for work from queue (blocks until item available or shutdown)
        if (!m_work_queue.Dequeue(client_socket)) {
            break;  // Shutdown signaled
        }

        // Handle request
        try {
            HandleRequest(client_socket);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Exception handling request: " << e.what() << std::endl;
        }

        // Gracefully close client socket (shutdown prevents CLOSE-WAIT leak)
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
    }
}

// LP-12 (M-01): rate-limiter maintenance thread. Faithful mirror of
// CRPCServer::CleanupThread() — 5-minute cadence, wakes every second to observe
// m_running for prompt shutdown, wraps the body so a maintenance exception can
// never take down the process. Without this, the REST limiter's per-IP record
// map grows unbounded as source IPs rotate (slow memory-DoS), because the
// standalone HTTP server (unlike the RPC server) never ran the cleanup before.
void CHttpServer::CleanupThread() {
    try {
        const std::chrono::minutes CLEANUP_INTERVAL(5);
        (void)CLEANUP_INTERVAL;  // documented cadence; loop below counts seconds

        while (m_running.load()) {
            // Sleep up to 5 minutes, waking each second to honor shutdown.
            for (int i = 0; i < 300 && m_running.load(); i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (!m_running.load()) {
                break;
            }

            // Prune stale per-IP records (no-op if no limiter registered).
            if (m_rate_limiter) {
                m_rate_limiter->CleanupOldRecords();
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[HttpServer] Cleanup thread exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "[HttpServer] Cleanup thread unknown exception" << std::endl;
    }
}

// LP-12: extract the REAL kernel-reported peer IP from the connected socket
// (getpeername), mirroring CRPCServer::GetClientIP. Used for (a) the loopback
// wallet-HTML origin gate and (b) per-IP REST rate-limiting/attribution. Never
// trusts the client-supplied Host header. Returns "unknown" on failure, which
// IsLoopbackIP treats as non-loopback (default-deny).
static std::string GetPeerIP(SOCKET client_socket) {
    struct sockaddr_storage ss;
    socklen_t addr_size = sizeof(ss);
    if (getpeername(client_socket, (struct sockaddr*)&ss, &addr_size) != 0) {
        return "unknown";
    }
    std::string ip_str;
    uint16_t port;
    if (CSock::ExtractAddress(ss, ip_str, port)) {
        return ip_str;
    }
    return "unknown";
}

// Handle a single HTTP request
void CHttpServer::HandleRequest(SOCKET client_socket) {
    // LP-12: resolve the real peer IP once, up front, from the kernel socket.
    const std::string clientIP = GetPeerIP(client_socket);

    // Read request
    char buffer[4096];
#ifdef _WIN32
    int bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#else
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
#endif

    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    std::string request(buffer);

    // LP-12 (gate-bypass fold, MEDIUM) — TRUNCATION FAIL-CLOSED. We read at most
    // one 4095-byte chunk. If it came back completely full, the request may be
    // truncated mid-header, and a Host value cut at the buffer boundary
    // ("Host: 127.0.0.1<cut>.evil.com" -> "127.0.0.1") could spuriously match
    // the allowlist while the FULL header would not. We cannot see the complete
    // headers, so treat the request as untrusted: it is gated like any sensitive
    // path below and rejected unless the (possibly partial) Host still passes.
    // Rather than rely on that, force the gate's fail-closed branch.
    const bool requestMaybeTruncated =
        (static_cast<size_t>(bytes_read) >= sizeof(buffer) - 1);

    // Parse request
    std::string method, rawPath;
    if (!ParseRequest(request, method, rawPath)) {
        Send500(client_socket);
        return;
    }

    // ========================================================================
    // LP-12 (gate-bypass fold) — NORMALIZE THE PATH BEFORE ANY DECISION.
    //
    // The external-consensus review found the H-01 gate decided on the RAW
    // request path, so every alternate spelling of a sensitive path evaded it
    // (`/wallet?x`, `/wallet/`, `/API/v1/`, `/%61pi/v1/`, `/api/v1/../x402/`,
    // `//api//v1//`). We now canonicalize ONCE here — strip query/fragment,
    // percent-decode, collapse `//`, resolve `.`/`..`, drop the trailing slash —
    // and drive BOTH the gate AND handler dispatch off the SAME normalized path,
    // so a spelling can never reach a node-touching handler while skipping the
    // gate. A path that will not normalize (bad %-escape, `..` above root, an
    // embedded NUL) is treated as sensitive AND not routed — fail-closed.
    // ========================================================================
    const api::NormalizedPath norm = api::NormalizeRequestPath(rawPath);
    const std::string& path = norm.path;  // canonical; dispatch uses this below

    // STRESS TEST FIX: Handle GET /api/health - simple health check that NEVER
    // blocks. Stays ABOVE the Host gate as an intentional load-balancer probe;
    // it returns a STATIC liveness string only (no node/identity data). Matched
    // on the normalized path so a disguised spelling cannot smuggle something
    // else through this pre-gate branch. A non-normalizable path never matches.
    if (norm.ok && method == "GET" && path == "/api/health") {
        SendResponse(client_socket, 200, "application/json", R"({"status":"ok"})");
        return;
    }

    // CVE-2026-RPC-CORS: No CORS. All OPTIONS preflights rejected.
    // Same-origin requests do not preflight; cross-origin callers unsupported.
    if (method == "OPTIONS") {
        std::ostringstream response;
        response << "HTTP/1.1 403 Forbidden\r\n";
        response << "Content-Length: 0\r\n";
        response << "Connection: close\r\n";
        response << "\r\n";
        std::string response_str = response.str();
#ifdef _WIN32
        send(client_socket, response_str.c_str(), static_cast<int>(response_str.size()), 0);
#else
        send(client_socket, response_str.c_str(), response_str.size(), 0);
#endif
        return;
    }

    // ========================================================================
    // LP-12 (H-01) — ANTI-DNS-REBINDING HOST-HEADER ALLOWLIST.
    //
    // Mirrors CRPCServer::HandleRequest (server.cpp:~1095-1139). The standalone
    // CHttpServer routed /api/v1/* (incl. /api/v1/broadcast → mempool) and
    // /x402/* with NO Host check, so a DNS-rebound page (evil.com → a
    // --public-api seed IP) could POST a broadcast or scrape telemetry. This
    // gate rejects a missing / empty / duplicate / non-allowlisted Host BEFORE
    // any of those branches dispatch. The Host header is the only input here;
    // we deliberately do NOT consult X-Forwarded-* (attacker-controlled).
    //
    // ORDERING: strictly ABOVE the REST, wallet-HTML, /api/stats and /metrics
    // branches (every node-touching surface). Only /api/health (an intentional
    // load-balancer probe) and OPTIONS (already a blanket 403) sit above it.
    //
    // FAIL-CLOSED: if the validator was never configured (ready flag false),
    // REJECT rather than skip — an un-configured validator denies all REST, so
    // a future reorder of Start() can never silently disable the gate. In
    // production ConfigureHostAllowlist() runs before Start() spawns workers.
    // ========================================================================
    {
        // Fail-closed: a path that would not normalize (bad %-escape, traversal
        // above root, embedded NUL) is treated as sensitive — it must NOT slip
        // past the Host gate. Otherwise classify the canonical path.
        const bool sensitive_surface =
            !norm.ok || api::IsSensitiveSurface(path);
        if (sensitive_surface &&
            (requestMaybeTruncated ||
             !m_host_validator_ready.load() ||
             !m_host_validator.IsRequestHostAllowed(request))) {
            SendResponse(client_socket, 403, "application/json",
                R"({"error":"Forbidden: Host header not allowed (DNS-rebinding protection). Connect via 127.0.0.1/localhost or configure --rpcallowhost.","code":-32600})");
            return;
        }
        // A non-normalizable path that somehow passed the Host check (e.g. a
        // loopback operator hitting a malformed URL) is still never routed to a
        // node-touching handler: every dispatch branch below keys on the
        // canonical `path`, which is empty/garbage when !norm.ok, so it falls
        // through to 404. Make that explicit and fail-closed.
        if (!norm.ok) {
            Send404(client_socket);
            return;
        }
    }

    // Handle REST API requests for light wallet (/api/v1/*) and x402 facilitator (/x402/*)
    if (path.rfind("/api/v1/", 0) == 0 || path.rfind("/x402/", 0) == 0) {
        if (m_rest_api_handler) {
            try {
                // Extract request body for POST requests
                std::string body;
                if (method == "POST") {
                    // Find body after headers (double CRLF)
                    size_t body_start = request.find("\r\n\r\n");
                    if (body_start != std::string::npos) {
                        body = request.substr(body_start + 4);
                    }
                }

                // Call REST API handler (returns full HTTP response).
                // LP-12: pass the REAL peer IP (was hardcoded "0.0.0.0", which
                // collapsed every client onto one rate-limit bucket and erased
                // attribution). Per-IP limiting on the REST broadcast path now
                // keys on the actual connection.
                std::string response = m_rest_api_handler(method, path, body, clientIP);

                // Send raw response (handler builds complete HTTP response)
#ifdef _WIN32
                send(client_socket, response.c_str(), static_cast<int>(response.size()), 0);
#else
                send(client_socket, response.c_str(), response.size(), 0);
#endif
            } catch (const std::exception& e) {
                std::cerr << "[HttpServer] REST API error: " << e.what() << std::endl;
                Send500(client_socket);
            }
        } else {
            // REST API not configured
            SendResponse(client_socket, 503, "application/json",
                R"({"error":"REST API not available"})");
        }
        return;
    }

    // Handle GET /wallet or /wallet.html - serve embedded web wallet
    if (method == "GET" && (path == "/wallet" || path == "/wallet.html" || path == "/")) {
        // ====================================================================
        // LP-12 (mirrors server.cpp:1169-1232, C-01b/F-003) — the wallet UI is a
        // token-minting desktop affordance, NOT a seed feature. Bring the
        // standalone CHttpServer to parity with the RPC server, which previously
        // protected this same HTML while this path served it unconditionally.
        //
        //  1. On a --public-api node (all-interfaces bind) the wallet UI is
        //     DISABLED ENTIRELY — no page — regardless of socket peer. This
        //     structurally removes the remote-admin-token / phishing-origin class
        //     on network-bound seeds. Checked FIRST.
        //  2. Otherwise (localhost default bind) require the REAL kernel socket
        //     peer to be a loopback IP literal (IsLoopbackIP on getpeername's
        //     result) — the Host header is never trusted for this decision.
        // ====================================================================
        if (m_public_api) {
            SendResponse(client_socket, 403, "application/json",
                R"({"error":"Forbidden: the wallet UI is disabled on a public-API node. SSH-tunnel to a loopback RPC to use the wallet.","code":-32600})");
            return;
        }
        // LP-12 (gate-bypass fold, finding #3) — IPv4-mapped-IPv6 loopback spoof
        // is NOT exploitable here. clientIP is GetPeerIP(), which calls
        // getpeername() (kernel-reported peer, not attacker-supplied) and then
        // CSock::ExtractAddress(), which UNWRAPS any IPv4-mapped v6 source
        // (IN6_IS_ADDR_V4MAPPED -> dotted IPv4) BEFORE it reaches IsLoopbackIP.
        // So a REMOTE peer can never present "::ffff:127.0.0.1" to this check:
        // the kernel reports the peer's real address, and a real remote address
        // unwraps to its real (non-127) IPv4. A 127.x source on a remote socket
        // would be a martian packet rejected by the OS network stack. Belt-and-
        // suspenders: on --public-api nodes the wallet UI is already disabled
        // entirely above (the public-node branch), so this loopback gate is only
        // reached on a localhost-bound server in the first place.
        if (!rpc::HostValidator::IsLoopbackIP(clientIP)) {
            SendResponse(client_socket, 403, "application/json",
                R"({"error":"Forbidden: the wallet UI is served to loopback connections only. Use an SSH tunnel for remote access.","code":-32600})");
            return;
        }
        // ====================================================================
        // LP-12 (M-03) — SECONDARY loopback-Host check, for parity with the RPC
        // server's wallet gate (server.cpp:~1240-1261), which requires BOTH a
        // loopback socket peer (above) AND a loopback Host. The socket-peer gate
        // is the load-bearing loopback-ORIGIN assertion; this Host check is the
        // belt-and-suspenders anti-rebinding layer. Fail-closed if the validator
        // is not ready. Either failing rejects the token-minting page.
        // ====================================================================
        if (requestMaybeTruncated ||
            !m_host_validator_ready.load() ||
            !m_host_validator.IsRequestLoopbackHost(request)) {
            SendResponse(client_socket, 403, "application/json",
                R"({"error":"Forbidden: the wallet UI is served on loopback only (127.0.0.1/localhost). Use an SSH tunnel for remote access.","code":-32600})");
            return;
        }
        try {
            const std::string& html = GetWalletHTML();
            SendResponse(client_socket, 200, "text/html; charset=utf-8", html);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Error serving wallet: " << e.what() << std::endl;
            Send500(client_socket);
        }
        return;
    }

    // Handle GET /api/stats
    if (method == "GET" && path == "/api/stats") {
        if (!m_stats_handler) {
            Send500(client_socket);
            return;
        }

        try {
            std::string json = m_stats_handler();
            SendResponse(client_socket, 200, "application/json", json);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Error generating stats: " << e.what() << std::endl;
            Send500(client_socket);
        }
        return;
    }

    // Handle GET /metrics (Prometheus format)
    if (method == "GET" && path == "/metrics") {
        if (!m_metrics_handler) {
            Send500(client_socket);
            return;
        }

        try {
            std::string metrics = m_metrics_handler();
            SendResponse(client_socket, 200, "text/plain; version=0.0.4; charset=utf-8", metrics);
        } catch (const std::exception& e) {
            std::cerr << "[HttpServer] Error generating metrics: " << e.what() << std::endl;
            Send500(client_socket);
        }
        return;
    }

    // Not found
    Send404(client_socket);
}

// Parse HTTP request
bool CHttpServer::ParseRequest(const std::string& request,
                               std::string& method,
                               std::string& path) {
    std::istringstream stream(request);
    std::string http_version;

    // Parse first line: METHOD PATH HTTP/1.1
    if (!(stream >> method >> path >> http_version)) {
        return false;
    }

    return true;
}

// Send HTTP response
void CHttpServer::SendResponse(SOCKET client_socket,
                               int status_code,
                               const std::string& content_type,
                               const std::string& body) {
    std::ostringstream response;

    // Status line
    response << "HTTP/1.1 " << status_code << " ";
    switch (status_code) {
        case 200: response << "OK"; break;
        case 403: response << "Forbidden"; break;
        case 404: response << "Not Found"; break;
        case 500: response << "Internal Server Error"; break;
        case 503: response << "Service Unavailable"; break;
        default: response << "Unknown"; break;
    }
    response << "\r\n";

    // CVE-2026-RPC-CORS: NO CORS headers. Same-origin only.

    // Content headers
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";

    // Body
    response << body;

    // Send response
    std::string response_str = response.str();
    // CID 1675271 FIX: Check return value of send to ensure data was sent successfully
    // send() returns number of bytes sent on success, or SOCKET_ERROR (-1) on error
    // On Windows, SOCKET_ERROR is -1. On Unix, -1 indicates error and errno is set.
    size_t response_len = response_str.length();
#ifdef _WIN32
    int bytes_sent = send(client_socket, response_str.c_str(), static_cast<int>(response_len), 0);
    if (bytes_sent == SOCKET_ERROR) {
        // Failed to send response - log error but continue (connection may be closed)
        int error = WSAGetLastError();
        std::cerr << "[HttpServer] Warning: Failed to send HTTP response (error: " << error << ")" << std::endl;
    } else if (static_cast<size_t>(bytes_sent) != response_len) {
        // Partial send - log warning (connection may be closing)
        std::cerr << "[HttpServer] Warning: Partial HTTP response sent (" << bytes_sent 
                  << " of " << response_len << " bytes)" << std::endl;
    }
#else
    ssize_t bytes_sent = send(client_socket, response_str.c_str(), response_len, MSG_NOSIGNAL);
    if (bytes_sent < 0) {
        // Failed to send response - log error but continue (connection may be closed)
        std::cerr << "[HttpServer] Warning: Failed to send HTTP response (" << strerror(errno) << ")" << std::endl;
    } else if (static_cast<size_t>(bytes_sent) != response_len) {
        // Partial send - log warning (connection may be closing)
        std::cerr << "[HttpServer] Warning: Partial HTTP response sent (" << bytes_sent 
                  << " of " << response_len << " bytes)" << std::endl;
    }
#endif
}

// Send 404 Not Found
void CHttpServer::Send404(SOCKET client_socket) {
    std::string body = R"({"error": "Not Found"})";
    SendResponse(client_socket, 404, "application/json", body);
}

// Send 500 Internal Server Error
void CHttpServer::Send500(SOCKET client_socket) {
    std::string body = R"({"error": "Internal Server Error"})";
    SendResponse(client_socket, 500, "application/json", body);
}

// Send 503 Service Unavailable (STRESS TEST FIX: queue full)
void CHttpServer::Send503(SOCKET client_socket) {
    std::string body = R"({"error": "Service Unavailable", "reason": "Server busy"})";
    SendResponse(client_socket, 503, "application/json", body);
}
