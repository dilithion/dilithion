// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_API_HTTP_SERVER_H
#define DILITHION_API_HTTP_SERVER_H

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <memory>

// Forward declare SOCKET type (cross-platform)
#ifdef _WIN32
    #include <winsock2.h>
    // SOCKET is already defined by winsock2.h
#else
    typedef int SOCKET;
#endif

/**
 * CHttpWorkQueue - Thread-safe work queue for HTTP requests
 *
 * Based on Bitcoin Core's WorkQueue pattern from httpserver.cpp.
 * Provides producer-consumer queue for request processing.
 *
 * STRESS TEST FIX: Issue 2 - HTTP API unresponsive during load.
 * This allows multiple worker threads to process requests concurrently,
 * preventing one slow request from blocking others.
 */
template<typename T>
class CHttpWorkQueue {
public:
    explicit CHttpWorkQueue(size_t max_depth = DEFAULT_HTTP_WORKQUEUE)
        : m_max_depth(max_depth), m_shutdown(false) {}

    /**
     * Enqueue a work item
     * @param item Work item to enqueue
     * @return true if queued, false if queue is full or shutting down
     */
    bool Enqueue(T item) {
        std::unique_lock<std::mutex> lock(m_mutex);
        if (m_shutdown || m_queue.size() >= m_max_depth) {
            return false;
        }
        m_queue.push(std::move(item));
        m_cv.notify_one();
        return true;
    }

    /**
     * Dequeue a work item (blocks until item available or shutdown)
     * @return Work item, or empty optional if shutting down
     */
    bool Dequeue(T& item) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] {
            return !m_queue.empty() || m_shutdown;
        });

        if (m_queue.empty()) {
            return false;  // Shutdown signaled
        }

        item = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    /**
     * Signal shutdown and wake all waiting threads
     */
    void Shutdown() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_shutdown = true;
        m_cv.notify_all();
    }

    /**
     * Get current queue depth
     */
    size_t Size() const {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_queue.size();
    }

    // Configuration constants (match Bitcoin Core defaults)
    static constexpr size_t DEFAULT_HTTP_WORKQUEUE = 128;

private:
    std::queue<T> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    size_t m_max_depth;
    bool m_shutdown;
};

/**
 * CHttpServer - Multi-threaded HTTP server for REST API
 *
 * STRESS TEST FIX: Issue 2 - HTTP API unresponsive during load.
 * Uses a thread pool pattern from Bitcoin Core's httpserver.cpp.
 *
 * Architecture:
 * - Accept thread: Listens for connections and queues them
 * - Worker threads: Process requests from the queue concurrently
 *
 * Provides simple HTTP server for exposing node statistics via REST API.
 * Supports:
 * - GET /api/stats - Returns JSON with current node statistics
 * - GET /api/health - Returns simple health check (never blocks)
 * - GET /metrics - Returns Prometheus-format metrics
 * - CORS headers for cross-origin requests
 * - Non-blocking operation with background threads
 * - Graceful shutdown
 *
 * Usage:
 *   CHttpServer server(8334);
 *   server.SetStatsHandler([]() { return GetNodeStats(); });
 *   server.SetMetricsHandler([]() { return GetPrometheusMetrics(); });
 *   server.Start();
 */
class CHttpServer {
public:
    /**
     * Stats handler function type
     * Should return JSON string with current node statistics
     */
    using StatsHandler = std::function<std::string()>;

    /**
     * Metrics handler function type
     * Should return Prometheus-format metrics string
     */
    using MetricsHandler = std::function<std::string()>;

    /**
     * REST API handler function type
     * Takes method, path, body, clientIP and returns HTTP response
     */
    using RestApiHandler = std::function<std::string(const std::string& method,
                                                      const std::string& path,
                                                      const std::string& body,
                                                      const std::string& clientIP)>;

    /**
     * Constructor
     * @param port Port to listen on (default: 8334 for testnet)
     * @param public_api If true, bind to all interfaces (seed nodes / --public-api).
     *                   If false (default), bind to 127.0.0.1 only.
     *                   CVE-2026-RPC-CORS: prior default of all-interfaces exposed
     *                   /api/v1/* + /wallet to LAN.
     */
    explicit CHttpServer(int port = 8334, bool public_api = false);

    /**
     * Destructor - ensures server is stopped
     */
    ~CHttpServer();

    // Disable copy/move
    CHttpServer(const CHttpServer&) = delete;
    CHttpServer& operator=(const CHttpServer&) = delete;

    /**
     * Set stats handler function
     * @param handler Function that returns JSON stats string
     */
    void SetStatsHandler(StatsHandler handler);

    /**
     * Set metrics handler function (Prometheus format)
     * @param handler Function that returns Prometheus metrics string
     */
    void SetMetricsHandler(MetricsHandler handler);

    /**
     * Set REST API handler function for /api/v1/* endpoints
     * @param handler Function that handles REST API requests
     */
    void SetRestApiHandler(RestApiHandler handler);

    /**
     * Start the HTTP server
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop the HTTP server
     */
    void Stop();

    /**
     * Check if server is running
     * @return true if server thread is active
     */
    bool IsRunning() const { return m_running.load(); }

    /**
     * Get server port
     * @return Port number
     */
    int GetPort() const { return m_port; }

private:
    /**
     * Accept thread main loop
     * Listens for HTTP connections and queues them for worker threads
     */
    void AcceptThread();

    /**
     * Worker thread main loop
     * Processes requests from the work queue
     */
    void WorkerThread();

    /**
     * Handle a single HTTP request
     * @param client_socket Socket file descriptor for client connection
     */
    void HandleRequest(SOCKET client_socket);

    /**
     * Parse HTTP request and extract method and path
     * @param request Raw HTTP request string
     * @param method Output parameter for HTTP method (GET, POST, etc)
     * @param path Output parameter for request path
     * @return true if parsed successfully
     */
    bool ParseRequest(const std::string& request, std::string& method, std::string& path);

    /**
     * Send HTTP response
     * @param client_socket Socket file descriptor
     * @param status_code HTTP status code (200, 404, etc)
     * @param content_type Content-Type header value
     * @param body Response body
     */
    void SendResponse(SOCKET client_socket, int status_code,
                     const std::string& content_type,
                     const std::string& body);

    /**
     * Send 404 Not Found response
     * @param client_socket Socket file descriptor
     */
    void Send404(SOCKET client_socket);

    /**
     * Send 500 Internal Server Error response
     * @param client_socket Socket file descriptor
     */
    void Send500(SOCKET client_socket);

    /**
     * Send 503 Service Unavailable response (queue full)
     * @param client_socket Socket file descriptor
     */
    void Send503(SOCKET client_socket);

    // Configuration
    int m_port;                            // Server port
    bool m_public_api;                     // CVE-2026: if false, bind 127.0.0.1 only
    int m_num_threads;                     // Number of worker threads
    StatsHandler m_stats_handler;          // Stats handler function
    MetricsHandler m_metrics_handler;      // Prometheus metrics handler
    RestApiHandler m_rest_api_handler;     // REST API handler for light wallet

    // Server state - STRESS TEST FIX: Thread pool pattern
    std::thread m_accept_thread;           // Accept thread (listens for connections)
    std::vector<std::thread> m_workers;    // Worker threads (process requests)
    CHttpWorkQueue<SOCKET> m_work_queue;   // Work queue for pending requests
    std::atomic<bool> m_running{false};    // Running flag

#ifdef _WIN32
    SOCKET m_server_socket{INVALID_SOCKET}; // Server socket file descriptor
#else
    SOCKET m_server_socket{-1};             // Server socket file descriptor
#endif

    // Configuration constants (match Bitcoin Core defaults)
    static constexpr int DEFAULT_HTTP_THREADS = 4;
    static constexpr int HTTP_REQUEST_TIMEOUT_SECONDS = 30;
};

/**
 * Global HTTP server instance (initialized in dilithion-node.cpp)
 */
extern CHttpServer* g_http_server;

#endif // DILITHION_API_HTTP_SERVER_H
