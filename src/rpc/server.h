// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_RPC_SERVER_H
#define DILITHION_RPC_SERVER_H

#include <wallet/wallet.h>
#include <miner/controller.h>
#include <net/net.h>
#include <rpc/ratelimiter.h>
#include <rpc/permissions.h>
#include <rpc/logger.h>
#include <rpc/ssl_wrapper.h>
#include <rpc/websocket.h>
#include <rpc/rest_api.h>

// Forward declarations
namespace x402 { class CFacilitator; }
namespace Attestation { class CSeedAttestationKey; }
class CVDFMiner;
class CASNDatabase;
#include <digital_dna/digital_dna_rpc.h>
#include <script/atomic_swap.h>

#include <string>
#include <sstream>
#include <map>
#include <mutex>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include <atomic>
#include <queue>
#include <condition_variable>

/**
 * JSON-RPC 2.0 Request
 */
struct RPCRequest {
    std::string jsonrpc;  // Should be "2.0"
    std::string method;
    std::string params;   // JSON string
    std::string id;

    RPCRequest() : jsonrpc("2.0") {}
};

/**
 * JSON-RPC 2.0 Response
 */
struct RPCResponse {
    std::string jsonrpc;  // Should be "2.0"
    std::string result;   // JSON string (if success)
    std::string error;    // JSON string (if error)
    std::string id;

    RPCResponse() : jsonrpc("2.0") {}

    static RPCResponse Success(const std::string& result, const std::string& id) {
        RPCResponse resp;
        resp.result = result;
        resp.id = id;
        return resp;
    }

    static RPCResponse Error(int code, const std::string& message, const std::string& id) {
        RPCResponse resp;
        resp.error = "{\"code\":" + std::to_string(code) +
                     ",\"message\":\"" + message + "\"}";
        resp.id = id;
        return resp;
    }
    
    // UX: Enhanced error response with structured information
    static RPCResponse ErrorStructured(int code, const std::string& message, 
                                       const std::string& id,
                                       const std::string& error_code = "",
                                       const std::vector<std::string>& recovery_steps = {}) {
        RPCResponse resp;
        std::ostringstream oss;
        oss << "{\"code\":" << code << ",\"message\":\"" << message << "\"";
        if (!error_code.empty()) {
            oss << ",\"error_code\":\"" << error_code << "\"";
        }
        if (!recovery_steps.empty()) {
            oss << ",\"recovery_steps\":[";
            for (size_t i = 0; i < recovery_steps.size(); ++i) {
                if (i > 0) oss << ",";
                oss << "\"" << recovery_steps[i] << "\"";
            }
            oss << "]";
        }
        oss << "}";
        resp.error = oss.str();
        resp.id = id;
        return resp;
    }
};

/**
 * RPC Handler function type
 * Takes params JSON string, returns result JSON string
 * Throws std::runtime_error on error
 */
using RPCHandler = std::function<std::string(const std::string&)>;

/**
 * RPC Server - Lightweight JSON-RPC 2.0 over HTTP
 *
 * Features:
 * - JSON-RPC 2.0 protocol
 * - HTTP/1.1 transport
 * - Thread-safe request handling
 * - Wallet, mining, and network endpoints
 *
 * Usage:
 *   CRPCServer server(8332);
 *   server.RegisterWallet(&wallet);
 *   server.RegisterMiner(&miner);
 *   server.Start();
 */
class CRPCServer {
private:
    uint16_t m_port;
    std::atomic<bool> m_running{false};
    std::thread m_serverThread;
    std::thread m_cleanupThread;  // Rate limiter cleanup thread

    // RPC-002: Thread Pool Implementation
    std::vector<std::thread> m_workerThreads;
    std::queue<int> m_clientQueue;        // Queue of pending client sockets
    std::mutex m_queueMutex;              // Protects client queue
    std::condition_variable m_queueCV;    // Notifies workers of new work
    size_t m_threadPoolSize;              // Number of worker threads (default 8)

    // Component references
    CWallet* m_wallet;
    CMiningController* m_miner;
    class CVDFMiner* m_vdfMiner{nullptr};
    class CTxMemPool* m_mempool;
    class CBlockchainDB* m_blockchain;
    class CUTXOSet* m_utxo_set;
    class CChainState* m_chainstate;
    x402::CFacilitator* m_x402_facilitator{nullptr};

    // Network configuration
    bool m_testnet{false};

    // Data directory (for swap state persistence)
    std::string m_dataDir;

    // Atomic swap state store
    SwapStore m_swapStore;

    // Session accepted-blocks counter: # of blocks on the canonical chain
    // mined by our MIK this process lifetime. Incremented when a block
    // connects and its coinbase MIK == ours; decremented when one of our
    // blocks disconnects (tiebreak reorg in VDF lowest-output distribution).
    // Resets on process start.
    std::atomic<uint64_t> m_acceptedSession{0};
    // Network manager placeholder — not yet needed (P2P layer handles networking directly)

    // RPC handlers
    std::map<std::string, RPCHandler> m_handlers;
    std::mutex m_handlersMutex;

    // Current request's client IP (set before handler dispatch, used by getmikattestation)
    std::string m_currentClientIP;

    // Rate limiting
    CRateLimiter m_rateLimiter;

    // FIX-014: Role-based access control (RBAC)
    std::unique_ptr<CRPCPermissions> m_permissions;

    // Phase 1: Request logging and auditing
    std::unique_ptr<CRPCLogger> m_logger;

    // Phase 3: SSL/TLS support
    std::unique_ptr<CSSLWrapper> m_ssl_wrapper;
    bool m_ssl_enabled;
    std::map<int, SSL*> m_ssl_connections;  // Map socket to SSL connection
    std::mutex m_ssl_mutex;  // Protects SSL connections map

    // Phase 4: WebSocket server
    std::unique_ptr<class CWebSocketServer> m_websocket_server;

    // Phase 5: REST API for light wallets
    std::unique_ptr<CRestAPI> m_restAPI;
    bool m_publicAPI{false};  // --public-api flag: bind to 0.0.0.0 instead of 127.0.0.1

    // Seed attestation (Phase 2+3): only active on seed nodes (--relay-only + DilV)
    Attestation::CSeedAttestationKey* m_seedAttestationKey{nullptr};
    CASNDatabase* m_asnDatabase{nullptr};
    int m_seedId{-1};  // This seed's index (0-3), or -1 if not a seed

    // Attestation rate limiting (Sybil defense Phase 0)
    // Rate limits NEW MIK registrations per /24 subnet per day.
    // Re-attestation for previously-seen MIKs (restarts, refreshes) bypasses the limit.
    std::mutex m_attestRateMutex;
    struct SubnetAttestationState {
        int64_t currentDay{0};          // UTC day number for rate limiting new MIKs
        int newMIKsToday{0};            // Count of NEW (distinct) MIKs attested today
        std::map<std::string, int64_t> knownMIKs;  // MIK identity hex -> last attested day
    };
    std::map<std::string, SubnetAttestationState> m_attestationRateLimit;
    int m_attestationMaxPerDay{1};  // configurable via --attestation-rate-limit

    // Server socket
    int m_serverSocket;

    /**
     * Server thread function
     */
    void ServerThread();

    /**
     * Worker thread function (RPC-002)
     * Processes client connections from the queue
     */
    void WorkerThread();

    /**
     * Cleanup thread function (rate limiter maintenance)
     */
    void CleanupThread();

    /**
     * Handle a single client connection
     */
    void HandleClient(int clientSocket);

    /**
     * Parse HTTP POST request, extract JSON-RPC body
     */
    bool ParseHTTPRequest(const std::string& request, std::string& jsonrpc);

    /**
     * Build HTTP response
     */
    std::string BuildHTTPResponse(const std::string& body);

    /**
     * Build HTTP 401 Unauthorized response
     */
    std::string BuildHTTPUnauthorized();

    /**
     * Extract Authorization header from HTTP request
     */
    bool ExtractAuthHeader(const std::string& request, std::string& authHeader);

    /**
     * Parse JSON-RPC request
     */
    RPCRequest ParseRPCRequest(const std::string& json);

    /**
     * Phase 2: Parse batch JSON-RPC request
     */
    std::vector<RPCRequest> ParseBatchRPCRequest(const std::string& json);

    /**
     * Execute RPC method
     */
    RPCResponse ExecuteRPC(const RPCRequest& request);
    
    /**
     * Phase 2: Execute batch RPC requests
     * @param requests Vector of RPCRequest objects
     * @param clientIP Client IP address (for logging)
     * @param username Username (for logging)
     * @return Vector of RPCResponse objects
     */
    std::vector<RPCResponse> ExecuteBatchRPC(const std::vector<RPCRequest>& requests,
                                            const std::string& clientIP,
                                            const std::string& username);

    /**
     * Convert RPCResponse to JSON string
     */
    std::string SerializeResponse(const RPCResponse& response);
    
    /**
     * Phase 2: Serialize batch RPC responses to JSON array string
     * @param responses Vector of RPCResponse objects
     * @return JSON array string
     */
    std::string SerializeBatchResponse(const std::vector<RPCResponse>& responses);

    // RPC method handlers

    // Wallet information methods
    std::string RPC_GetNewAddress(const std::string& params);
    std::string RPC_GetBalance(const std::string& params);
    std::string RPC_GetAddresses(const std::string& params);
    std::string RPC_ListUnspent(const std::string& params);

    // Transaction creation methods
    std::string RPC_SendToAddress(const std::string& params);
    std::string RPC_EstimateSendFee(const std::string& params);
    std::string RPC_ConsolidateUTXOs(const std::string& params);
    std::string RPC_SignRawTransaction(const std::string& params);
    std::string RPC_SendRawTransaction(const std::string& params);

    // Transaction query methods
    std::string RPC_GetTransaction(const std::string& params);
    std::string RPC_ListTransactions(const std::string& params);
    std::string RPC_GetMempoolInfo(const std::string& params);

    // x402 payment methods (DilV only — requires m_x402_facilitator)
    std::string RPC_VerifyX402Payment(const std::string& params);
    std::string RPC_SettleX402Payment(const std::string& params);
    std::string RPC_GetX402Info(const std::string& params);

    // Blockchain query methods
    std::string RPC_GetBlockchainInfo(const std::string& params);
    std::string RPC_GetBlockTrackerInfo(const std::string& params);
    std::string RPC_GetBlock(const std::string& params);
    std::string RPC_GetBlockHash(const std::string& params);
    std::string RPC_GetTxOut(const std::string& params);
    std::string RPC_CheckChain(const std::string& params);

    // Wallet encryption methods
    std::string RPC_GetWalletInfo(const std::string& params);
    std::string RPC_EncryptWallet(const std::string& params);
    std::string RPC_WalletPassphrase(const std::string& params);
    std::string RPC_WalletLock(const std::string& params);
    std::string RPC_WalletPassphraseChange(const std::string& params);

    // HD Wallet methods
    std::string RPC_CreateHDWallet(const std::string& params);
    std::string RPC_RestoreHDWallet(const std::string& params);
    std::string RPC_ExportMnemonic(const std::string& params);
    std::string RPC_DumpPrivKey(const std::string& params);
    std::string RPC_ImportPrivKey(const std::string& params);

    // v4.0.19: Operator escape hatch — write auto_rebuild marker and shut down.
    // Admin-gated (ADMIN_SERVER), rate-limited 1/min, hidden from public help.
    std::string RPC_ForceRebuild(const std::string& params);
    std::string RPC_GetHDWalletInfo(const std::string& params);
    std::string RPC_ListHDAddresses(const std::string& params);
    std::string RPC_RescanWallet(const std::string& params);
    std::string RPC_ClearWalletTxs(const std::string& params);

    // Mining methods
    std::string RPC_GetMiningInfo(const std::string& params);
    std::string RPC_StartMining(const std::string& params);
    std::string RPC_StopMining(const std::string& params);
    std::string RPC_SetMiningAddress(const std::string& params);
    std::string RPC_SetMiningThreads(const std::string& params);
    std::string RPC_GetMiningAddress(const std::string& params);
    std::string RPC_GetDFMPInfo(const std::string& params);
    std::string RPC_GetMIKDistribution(const std::string& params);
    std::string RPC_GetFullMIKDistribution(const std::string& params);

    // Network methods
    std::string RPC_GetNetworkInfo(const std::string& params);
    std::string RPC_GetPeerInfo(const std::string& params);
    std::string RPC_GetConnectionCount(const std::string& params);

    // General methods
    std::string RPC_Help(const std::string& params);
    std::string RPC_Stop(const std::string& params);

    // Missing blockchain query methods (for functional tests)
    std::string RPC_GetBlockCount(const std::string& params);
    std::string RPC_GetBestBlockHash(const std::string& params);
    std::string RPC_GetChainTips(const std::string& params);

    // Missing mempool methods
    std::string RPC_GetRawMempool(const std::string& params);

    // Missing mining methods
    std::string RPC_GenerateToAddress(const std::string& params);

    // Missing transaction methods
    std::string RPC_GetRawTransaction(const std::string& params);
    std::string RPC_DecodeRawTransaction(const std::string& params);

    // Missing network methods
    std::string RPC_AddNode(const std::string& params);

    // Ban management methods
    std::string RPC_SetBan(const std::string& params);
    std::string RPC_ListBanned(const std::string& params);
    std::string RPC_ClearBanned(const std::string& params);
    std::string RPC_BanMIK(const std::string& params);
    std::string RPC_UnbanMIK(const std::string& params);
    std::string RPC_ListBannedMIKs(const std::string& params);

    // Sybil defense methods
    std::string RPC_GetSybilRelays(const std::string& params);
    std::string RPC_GetCorrelatedAlerts(const std::string& params);

    // UTXO set query methods
    std::string RPC_GetHolderCount(const std::string& params);
    std::string RPC_GetTopHolders(const std::string& params);

    // Block repair methods (Bug #243 fix)
    std::string RPC_RepairBlocks(const std::string& params);
    std::string RPC_CheckBlockDB(const std::string& params);
    std::string RPC_ScanBlockDB(const std::string& params);
    std::string RPC_RequestBlocks(const std::string& params);

    // Chain management methods (Bug #272 fix)
    std::string RPC_InvalidateBlock(const std::string& params);
    std::string RPC_ReconsiderBlock(const std::string& params);

    // Seed attestation methods (Phase 2+3)
    std::string RPC_GetMIKAttestation(const std::string& params);

    // HTLC (Hash Time-Locked Contract) methods
    std::string RPC_GeneratePreimage(const std::string& params);
    std::string RPC_CreateHTLC(const std::string& params);
    std::string RPC_ClaimHTLC(const std::string& params);
    std::string RPC_RefundHTLC(const std::string& params);
    std::string RPC_DecodeHTLC(const std::string& params);

    // Atomic swap orchestration (high-level)
    std::string RPC_InitiateSwap(const std::string& params);
    std::string RPC_AcceptSwap(const std::string& params);
    std::string RPC_ListSwaps(const std::string& params);

    // Helper functions
    std::string FormatAmount(CAmount amount) const;
    bool ValidateAddress(const std::string& addressStr, CDilithiumAddress& addressOut) const;
    std::string EscapeJSON(const std::string& str) const;

public:
    /**
     * Constructor
     * @param port RPC server port (default 8332)
     */
    explicit CRPCServer(uint16_t port = 8332);

    /**
     * Destructor - ensures server is stopped
     */
    ~CRPCServer();

    // Prevent copying
    CRPCServer(const CRPCServer&) = delete;
    CRPCServer& operator=(const CRPCServer&) = delete;

    /**
     * Register wallet instance
     */
    void RegisterWallet(CWallet* wallet) { m_wallet = wallet; }

    /**
     * Register miner instance
     */
    void RegisterMiner(CMiningController* miner) { m_miner = miner; }

    /**
     * Register VDF miner instance (DilV)
     */
    void RegisterVDFMiner(class CVDFMiner* vdfMiner) { m_vdfMiner = vdfMiner; }

    /**
     * Register mempool instance
     */
    void RegisterMempool(class CTxMemPool* mempool) { m_mempool = mempool; }

    /**
     * Register blockchain database instance
     */
    void RegisterBlockchain(class CBlockchainDB* blockchain) { m_blockchain = blockchain; }

    /**
     * Register UTXO set instance
     */
    void RegisterUTXOSet(class CUTXOSet* utxo_set) { m_utxo_set = utxo_set; }

    /**
     * Register chain state instance
     */
    void RegisterChainState(class CChainState* chainstate) { m_chainstate = chainstate; }

    /**
     * Register x402 facilitator instance (DilV only)
     */
    void RegisterX402Facilitator(x402::CFacilitator* facilitator) { m_x402_facilitator = facilitator; }

    /**
     * Set testnet mode
     */
    void SetTestnet(bool testnet) { m_testnet = testnet; }

    /**
     * Set data directory (for swap state persistence).
     * Must be called before Start().
     */
    void SetDataDir(const std::string& dataDir);


    /** Increment session accepted-blocks counter (one of our MIK's blocks just connected to the chain) */
    void IncrementAcceptedSession() { ++m_acceptedSession; }

    /** Decrement session accepted-blocks counter (one of our MIK's blocks was disconnected, e.g. VDF tiebreak reorg) */
    void DecrementAcceptedSession() {
        // Atomic saturating decrement — don't underflow if a disconnect fires
        // for a block whose corresponding connect wasn't seen this session.
        uint64_t cur = m_acceptedSession.load();
        while (cur > 0 && !m_acceptedSession.compare_exchange_weak(cur, cur - 1)) {}
    }

    /** Get session accepted blocks count */
    uint64_t GetAcceptedSession() const { return m_acceptedSession.load(); }

    /**
     * Register Digital DNA RPC handler
     */
    void RegisterDNARpc(digital_dna::DigitalDNARpc* dna_rpc);

    /**
     * Set public API mode (--public-api flag)
     * When enabled, RPC server binds to 0.0.0.0 instead of 127.0.0.1
     * allowing light wallet clients to connect from any IP.
     * SECURITY: Only enable on seed nodes, not home mining nodes.
     */
    void SetPublicAPI(bool publicAPI) { m_publicAPI = publicAPI; }

    /**
     * Register seed attestation components (Phase 2+3).
     * Only called on seed nodes (--relay-only + DilV).
     */
    void RegisterSeedAttestation(Attestation::CSeedAttestationKey* key,
                                  CASNDatabase* asnDb,
                                  int seedId) {
        m_seedAttestationKey = key;
        m_asnDatabase = asnDb;
        m_seedId = seedId;
    }

    /**
     * Check if public API mode is enabled
     */
    bool IsPublicAPI() const { return m_publicAPI; }

    /**
     * Set attestation rate limit (Sybil defense Phase 0).
     * @param maxPerDay Maximum attestations per /24 subnet per day (default 1)
     */
    void SetAttestationRateLimit(int maxPerDay) { m_attestationMaxPerDay = maxPerDay; }

    // Network manager registration — reserved for future use
    // void RegisterNetwork(CNetworkManager* network) { m_network = network; }

    /**
     * Start RPC server
     * @return true if started successfully
     */
    bool Start();

    /**
     * Stop RPC server
     */
    void Stop();

    /**
     * FIX-014: Initialize permission system
     *
     * Loads user permissions from configuration file. If file doesn't exist
     * or cannot be loaded, falls back to legacy mode (single admin user).
     *
     * This must be called before Start() to enable authorization checking.
     *
     * @param configPath Path to rpc_permissions.json (e.g., "~/.dilithion/rpc_permissions.json")
     * @param legacyUser Legacy username (used if config file missing)
     * @param legacyPassword Legacy password (used if config file missing)
     * @return true if initialized successfully, false on error
     *
     * Example:
     *   server.InitializePermissions("~/.dilithion/rpc_permissions.json", "admin", "password");
     */
    bool InitializePermissions(const std::string& configPath,
                              const std::string& legacyUser,
                              const std::string& legacyPassword);

    /**
     * Check if server is running
     */
    bool IsRunning() const { return m_running; }

    /**
     * Get server port
     */
    uint16_t GetPort() const { return m_port; }

    /**
     * Phase 1: Initialize logging
     * @param log_file Path to request log file (empty = disabled)
     * @param audit_file Path to audit log file (empty = disabled)
     * @param level Minimum log level
     */
    void InitializeLogging(const std::string& log_file = "",
                          const std::string& audit_file = "",
                          CRPCLogger::LogLevel level = CRPCLogger::LogLevel::INFO);

    /**
     * Phase 3: Initialize SSL/TLS support
     * @param cert_file Path to certificate file (PEM format)
     * @param key_file Path to private key file (PEM format)
     * @param ca_file Optional path to CA certificate file
     * @return true if initialization successful, false on error
     */
    bool InitializeSSL(const std::string& cert_file,
                      const std::string& key_file,
                      const std::string& ca_file = "");

    /**
     * Phase 3: Check if SSL is enabled
     */
    bool IsSSLEnabled() const { return m_ssl_enabled; }

    /**
     * Phase 4: Get WebSocket server instance
     */
    class CWebSocketServer* GetWebSocketServer() const { return m_websocket_server.get(); }
    
    /**
     * Phase 4: Initialize WebSocket server
     * @param port WebSocket server port (0 = disabled)
     * @return true if initialized successfully
     */
    bool InitializeWebSocket(uint16_t port = 0);
};

#endif // DILITHION_RPC_SERVER_H
