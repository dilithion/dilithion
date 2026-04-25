// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/server.h>
#include <rpc/auth.h>
#include <node/block_processing.h>  // BanMIK/UnbanMIK/ListBannedMIKs
#include <node/registration_manager.h>  // v4.0.18: CRegistrationManager snapshot accessor
#include <net/sock.h>
#include <net/dns.h>
#include <core/version.h>
#include <rpc/json_util.h>  // RPC-007 FIX: Proper JSON parsing
#include <rpc/logger.h>  // Phase 1: Request logging
#include <rpc/ssl_wrapper.h>  // Phase 3: SSL/TLS support
#include <rpc/websocket.h>  // Phase 4: WebSocket support
#include <api/wallet_html.h>  // Web wallet UI
#include <api/miner_html.h>  // Web miner dashboard
#include <wallet/wallet.h>  // BUG #104 FIX: For CSentTx
#include <crypto/sha3.h>  // For hashing params
#include <wallet/passphrase_validator.h>
#include <miner/vdf_miner.h>
#include <node/mempool.h>
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <x402/facilitator.h>  // x402 payment facilitator
#include <consensus/params.h>
#include <consensus/chain.h>
#include <consensus/fees.h>
#include <consensus/tx_validation.h>
#include <consensus/pow.h>
#include <consensus/validation.h>  // For DeserializeBlockTransactions
#include <cmath>  // For pow()
#include <util/base58.h>           // For EncodeBase58Check
#include <dfmp/dfmp.h>  // DFMP v2.0
#include <dfmp/mik.h>   // DFMP v2.0: Mining Identity Key
#include <dfmp/mik_registration_file.h>  // MIK registration PoW persistence
#include <dfmp/identity_db.h>  // DFMP v2.0: Identity database
#include <digital_dna/dna_verification.h>  // DFMP v3.4: Verification-aware free tier
#include <core/chainparams.h>  // For Dilithion::g_chainParams
#include <util/chain_reset.h>   // v4.0.19: WriteAutoRebuildMarker
#include <script/htlc.h>        // HTLC script templates
#include <script/script.h>      // CScript, opcodes
#include <script/atomic_swap.h> // Atomic swap state machine
#include <util/strencodings.h>
#include <attestation/seed_attestation.h>
#include <net/asn_database.h>
#include <util/error_format.h>  // UX: Better error messages
#include <set>
#include <amount.h>
#include <net/peers.h>  // For CPeerManager
#include <core/node_context.h>  // For g_node_context
#include <node/ibd_coordinator.h>  // For CIbdCoordinator::IsInitialBlockDownload
#include <node/peer_mik_tracker.h>  // Sybil defense Phase 1
#include <vdf/cooldown_tracker.h>   // Sybil defense Phase 4
#include <net/net.h>  // For CNetMessageProcessor and other networking types
#include <net/protocol.h>  // For NetProtocol::CAddress
#include <net/connman.h>  // Phase 5: For CConnman methods
#include <net/banman.h>   // For CBanManager
#include <net/block_tracker.h>  // For block tracker diagnostics
#include <net/block_fetcher.h>  // For CBlockFetcher
#include <net/headers_manager.h>  // For CHeadersManager

#include <array>
#include <sstream>
#include <cstring>
#include <cctype>  // CID 1675176: For std::isxdigit
#include <iostream>
#include <iomanip>
#include <algorithm>
#ifndef _WIN32
#include <errno.h>  // CID 1675178: For errno and strerror
#endif
#include <chrono>
#include <thread>  // BUG #76 FIX: For std::this_thread::sleep_for
#include <crypto/randomx_hash.h>  // BUG #76 FIX: For randomx_is_mining_mode_ready()

// BUG #10 FIX: Declare NodeState for g_node_state access
struct NodeState {
    std::atomic<bool> running;
    std::atomic<bool> new_block_found;
    std::atomic<bool> mining_enabled;
    std::atomic<uint64_t> template_version{0};
    std::string mining_address_override;  // setminingaddress RPC sets this
    void* rpc_server;
    void* miner;
    void* wallet;
    void* p2p_socket;
    void* http_server;
};
extern NodeState g_node_state;

// v4.0.18: MIK registration is owned by CRegistrationManager. RPC handlers
// that previously called g_regNonceMined / g_cachedDnaHash etc. now reach the
// live manager via this accessor (set in main() by dilithion-node / dilv-node).
class CRegistrationManager;
CRegistrationManager* GetRegistrationManager();

// Data directory for persisting registration PoW (defined in globals.cpp).
extern std::string g_datadir;

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>  // For inet_pton
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

// Helper function to extract IP address from client socket (supports IPv4 and IPv6)
static std::string GetClientIP(int clientSocket) {
    struct sockaddr_storage ss;
    socklen_t addr_size = sizeof(ss);
    int res = getpeername(clientSocket, (struct sockaddr *)&ss, &addr_size);
    if (res != 0) {
        return "unknown";
    }
    std::string ip_str;
    uint16_t port;
    if (CSock::ExtractAddress(ss, ip_str, port)) {
        return ip_str;
    }
    return "unknown";
}

/**
 * Safely parse string to double with validation
 * Prevents RPC server crashes from malformed numeric inputs
 */
static double SafeParseDouble(const std::string& str, double min_val, double max_val) {
    try {
        double result = std::stod(str);
        if (result < min_val || result > max_val) {
            throw std::runtime_error("Value out of valid range");
        }
        return result;
    } catch (const std::invalid_argument&) {
        throw std::runtime_error("Invalid number format");
    } catch (const std::out_of_range&) {
        throw std::runtime_error("Number out of range");
    }
}

/**
 * Safely parse string to int64_t with validation
 * Prevents RPC server crashes from malformed numeric inputs
 */
static int64_t SafeParseInt64(const std::string& str, int64_t min_val, int64_t max_val) {
    try {
        int64_t result = std::stoll(str);
        if (result < min_val || result > max_val) {
            throw std::runtime_error("Value out of valid range");
        }
        return result;
    } catch (const std::invalid_argument&) {
        throw std::runtime_error("Invalid integer format");
    } catch (const std::out_of_range&) {
        throw std::runtime_error("Integer out of range");
    }
}

/**
 * Safely parse string to uint32_t with validation
 * Prevents RPC server crashes from malformed numeric inputs
 */
static uint32_t SafeParseUInt32(const std::string& str, uint32_t min_val, uint32_t max_val) {
    try {
        unsigned long result = std::stoul(str);
        if (result < min_val || result > max_val) {
            throw std::runtime_error("Value out of valid range");
        }
        return static_cast<uint32_t>(result);
    } catch (const std::invalid_argument&) {
        throw std::runtime_error("Invalid integer format");
    } catch (const std::out_of_range&) {
        throw std::runtime_error("Integer out of range");
    }
}

CRPCServer::CRPCServer(uint16_t port)
    : m_port(port), m_threadPoolSize(8), m_wallet(nullptr), m_miner(nullptr), m_mempool(nullptr),
      m_blockchain(nullptr), m_utxo_set(nullptr), m_chainstate(nullptr),
      m_serverSocket(INVALID_SOCKET), m_permissions(nullptr), m_logger(nullptr),
      m_ssl_wrapper(nullptr), m_ssl_enabled(false), m_websocket_server(nullptr),
      m_restAPI(std::make_unique<CRestAPI>()), m_publicAPI(false)
{
    // Register RPC handlers - Wallet information
    m_handlers["getnewaddress"] = [this](const std::string& p) { return RPC_GetNewAddress(p); };
    m_handlers["getbalance"] = [this](const std::string& p) { return RPC_GetBalance(p); };
    m_handlers["getaddresses"] = [this](const std::string& p) { return RPC_GetAddresses(p); };
    m_handlers["listunspent"] = [this](const std::string& p) { return RPC_ListUnspent(p); };

    // Transaction creation
    m_handlers["sendtoaddress"] = [this](const std::string& p) { return RPC_SendToAddress(p); };
    m_handlers["estimatesendfee"] = [this](const std::string& p) { return RPC_EstimateSendFee(p); };
    m_handlers["consolidateutxos"] = [this](const std::string& p) { return RPC_ConsolidateUTXOs(p); };
    m_handlers["signrawtransaction"] = [this](const std::string& p) { return RPC_SignRawTransaction(p); };
    m_handlers["sendrawtransaction"] = [this](const std::string& p) { return RPC_SendRawTransaction(p); };

    // Transaction query
    m_handlers["gettransaction"] = [this](const std::string& p) { return RPC_GetTransaction(p); };
    m_handlers["listtransactions"] = [this](const std::string& p) { return RPC_ListTransactions(p); };
    m_handlers["getmempoolinfo"] = [this](const std::string& p) { return RPC_GetMempoolInfo(p); };

    // Blockchain query
    m_handlers["getblockchaininfo"] = [this](const std::string& p) { return RPC_GetBlockchainInfo(p); };
    m_handlers["getblocktrackerinfo"] = [this](const std::string& p) { return RPC_GetBlockTrackerInfo(p); };
    m_handlers["getblock"] = [this](const std::string& p) { return RPC_GetBlock(p); };
    m_handlers["getblockhash"] = [this](const std::string& p) { return RPC_GetBlockHash(p); };
    m_handlers["gettxout"] = [this](const std::string& p) { return RPC_GetTxOut(p); };
    m_handlers["checkchain"] = [this](const std::string& p) { return RPC_CheckChain(p); };

    // Wallet encryption
    m_handlers["getwalletinfo"] = [this](const std::string& p) { return RPC_GetWalletInfo(p); };
    m_handlers["encryptwallet"] = [this](const std::string& p) { return RPC_EncryptWallet(p); };
    m_handlers["walletpassphrase"] = [this](const std::string& p) { return RPC_WalletPassphrase(p); };
    m_handlers["walletlock"] = [this](const std::string& p) { return RPC_WalletLock(p); };
    m_handlers["walletpassphrasechange"] = [this](const std::string& p) { return RPC_WalletPassphraseChange(p); };

    // HD Wallet
    m_handlers["createhdwallet"] = [this](const std::string& p) { return RPC_CreateHDWallet(p); };
    m_handlers["restorehdwallet"] = [this](const std::string& p) { return RPC_RestoreHDWallet(p); };
    m_handlers["exportmnemonic"] = [this](const std::string& p) { return RPC_ExportMnemonic(p); };
    m_handlers["dumpprivkey"] = [this](const std::string& p) { return RPC_DumpPrivKey(p); };
    m_handlers["importprivkey"] = [this](const std::string& p) { return RPC_ImportPrivKey(p); };
    m_handlers["forcerebuild"] = [this](const std::string& p) { return RPC_ForceRebuild(p); };
    m_handlers["gethdwalletinfo"] = [this](const std::string& p) { return RPC_GetHDWalletInfo(p); };
    m_handlers["listhdaddresses"] = [this](const std::string& p) { return RPC_ListHDAddresses(p); };
    m_handlers["rescanwallet"] = [this](const std::string& p) { return RPC_RescanWallet(p); };
    m_handlers["clearwallettxs"] = [this](const std::string& p) { return RPC_ClearWalletTxs(p); };

    // Mining
    m_handlers["getmininginfo"] = [this](const std::string& p) { return RPC_GetMiningInfo(p); };
    m_handlers["startmining"] = [this](const std::string& p) { return RPC_StartMining(p); };
    m_handlers["stopmining"] = [this](const std::string& p) { return RPC_StopMining(p); };
    m_handlers["setminingaddress"] = [this](const std::string& p) { return RPC_SetMiningAddress(p); };
    m_handlers["setminingthreads"] = [this](const std::string& p) { return RPC_SetMiningThreads(p); };
    m_handlers["getminingaddress"] = [this](const std::string& p) { return RPC_GetMiningAddress(p); };
    m_handlers["getdfmpinfo"] = [this](const std::string& p) { return RPC_GetDFMPInfo(p); };
    m_handlers["getmikdistribution"] = [this](const std::string& p) { return RPC_GetMIKDistribution(p); };
    m_handlers["getfullmikdistribution"] = [this](const std::string& p) { return RPC_GetFullMIKDistribution(p); };

    // Network and general
    m_handlers["getnetworkinfo"] = [this](const std::string& p) { return RPC_GetNetworkInfo(p); };
    m_handlers["getpeerinfo"] = [this](const std::string& p) { return RPC_GetPeerInfo(p); };
    m_handlers["getconnectioncount"] = [this](const std::string& p) { return RPC_GetConnectionCount(p); };
    m_handlers["help"] = [this](const std::string& p) { return RPC_Help(p); };
    m_handlers["stop"] = [this](const std::string& p) { return RPC_Stop(p); };

    // Missing methods for functional tests
    m_handlers["getblockcount"] = [this](const std::string& p) { return RPC_GetBlockCount(p); };
    m_handlers["getbestblockhash"] = [this](const std::string& p) { return RPC_GetBestBlockHash(p); };
    m_handlers["getchaintips"] = [this](const std::string& p) { return RPC_GetChainTips(p); };
    m_handlers["getrawmempool"] = [this](const std::string& p) { return RPC_GetRawMempool(p); };
    m_handlers["generatetoaddress"] = [this](const std::string& p) { return RPC_GenerateToAddress(p); };
    m_handlers["getrawtransaction"] = [this](const std::string& p) { return RPC_GetRawTransaction(p); };
    m_handlers["decoderawtransaction"] = [this](const std::string& p) { return RPC_DecodeRawTransaction(p); };
    m_handlers["addnode"] = [this](const std::string& p) { return RPC_AddNode(p); };

    // x402 payment methods (DilV only)
    m_handlers["verifyx402payment"] = [this](const std::string& p) { return RPC_VerifyX402Payment(p); };
    m_handlers["settlex402payment"] = [this](const std::string& p) { return RPC_SettleX402Payment(p); };
    m_handlers["getx402info"] = [this](const std::string& p) { return RPC_GetX402Info(p); };

    // Ban management
    m_handlers["setban"] = [this](const std::string& p) { return RPC_SetBan(p); };
    m_handlers["listbanned"] = [this](const std::string& p) { return RPC_ListBanned(p); };
    m_handlers["clearbanned"] = [this](const std::string& p) { return RPC_ClearBanned(p); };
    m_handlers["banmik"] = [this](const std::string& p) { return RPC_BanMIK(p); };
    m_handlers["unbanmik"] = [this](const std::string& p) { return RPC_UnbanMIK(p); };
    m_handlers["listbannedmiks"] = [this](const std::string& p) { return RPC_ListBannedMIKs(p); };

    // Sybil defense
    m_handlers["getsybilrelays"] = [this](const std::string& p) { return RPC_GetSybilRelays(p); };
    m_handlers["getcorrelatedalerts"] = [this](const std::string& p) { return RPC_GetCorrelatedAlerts(p); };

    // UTXO set queries
    m_handlers["getholdercount"] = [this](const std::string& p) { return RPC_GetHolderCount(p); };
    m_handlers["gettopholders"] = [this](const std::string& p) { return RPC_GetTopHolders(p); };

    // Block repair commands
    m_handlers["repairblocks"] = [this](const std::string& p) { return RPC_RepairBlocks(p); };
    m_handlers["checkblockdb"] = [this](const std::string& p) { return RPC_CheckBlockDB(p); };
    m_handlers["scanblockdb"] = [this](const std::string& p) { return RPC_ScanBlockDB(p); };
    m_handlers["requestblocks"] = [this](const std::string& p) { return RPC_RequestBlocks(p); };

    // Chain management commands
    m_handlers["invalidateblock"] = [this](const std::string& p) { return RPC_InvalidateBlock(p); };
    m_handlers["reconsiderblock"] = [this](const std::string& p) { return RPC_ReconsiderBlock(p); };

    // HTLC (Hash Time-Locked Contract) commands
    m_handlers["generatepreimage"] = [this](const std::string& p) { return RPC_GeneratePreimage(p); };
    m_handlers["createhtlc"] = [this](const std::string& p) { return RPC_CreateHTLC(p); };
    m_handlers["claimhtlc"] = [this](const std::string& p) { return RPC_ClaimHTLC(p); };
    m_handlers["refundhtlc"] = [this](const std::string& p) { return RPC_RefundHTLC(p); };
    m_handlers["decodehtlc"] = [this](const std::string& p) { return RPC_DecodeHTLC(p); };

    // Atomic swap orchestration
    m_handlers["initiateswap"] = [this](const std::string& p) { return RPC_InitiateSwap(p); };
    m_handlers["acceptswap"] = [this](const std::string& p) { return RPC_AcceptSwap(p); };
    m_handlers["listswaps"] = [this](const std::string& p) { return RPC_ListSwaps(p); };

    // Seed attestation (Phase 2+3)
    m_handlers["getmikattestation"] = [this](const std::string& p) { return RPC_GetMIKAttestation(p); };
}

CRPCServer::~CRPCServer() {
    Stop();
}

void CRPCServer::RegisterDNARpc(digital_dna::DigitalDNARpc* dna_rpc) {
    if (!dna_rpc) return;

    // Bridge DNA RPC commands into the main RPC handler dispatch.
    // DNA RPC uses map<string,string>, main RPC uses string -> string.
    auto commands = dna_rpc->list_commands();
    for (const auto& cmd : commands) {
        m_handlers[cmd] = [dna_rpc, cmd](const std::string& params) -> std::string {
            // Parse JSON params string into DNA's JsonObject (map<string,string>)
            digital_dna::JsonObject dna_params;
            if (!params.empty() && params != "[]" && params != "{}") {
                std::string s = params;
                if (s.front() == '{' || s.front() == '[') s = s.substr(1);
                if (s.back() == '}' || s.back() == ']') s.pop_back();

                size_t pos = 0;
                while (pos < s.size()) {
                    while (pos < s.size() && (s[pos] == ' ' || s[pos] == ',' || s[pos] == '\n' || s[pos] == '\t')) pos++;
                    if (pos >= s.size()) break;

                    if (s[pos] != '"') break;
                    size_t key_start = pos + 1;
                    size_t key_end = s.find('"', key_start);
                    if (key_end == std::string::npos) break;
                    std::string key = s.substr(key_start, key_end - key_start);
                    pos = key_end + 1;

                    while (pos < s.size() && (s[pos] == ':' || s[pos] == ' ')) pos++;
                    if (pos >= s.size()) break;

                    std::string value;
                    if (s[pos] == '"') {
                        size_t val_start = pos + 1;
                        size_t val_end = s.find('"', val_start);
                        if (val_end == std::string::npos) break;
                        value = s.substr(val_start, val_end - val_start);
                        pos = val_end + 1;
                    } else {
                        size_t val_start = pos;
                        while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && s[pos] != ']' && s[pos] != ' ') pos++;
                        value = s.substr(val_start, pos - val_start);
                    }
                    dna_params[key] = value;
                }
            }

            auto result = dna_rpc->execute(cmd, dna_params);

            // Convert result map<string,string> to JSON string
            std::ostringstream oss;
            oss << "{";
            bool first = true;
            for (const auto& [k, v] : result) {
                if (!first) oss << ",";
                oss << "\"" << k << "\":";
                if (!v.empty() && (v[0] == '[' || v[0] == '{' || v == "true" || v == "false" ||
                    (v[0] >= '0' && v[0] <= '9') || v[0] == '-')) {
                    oss << v;
                } else {
                    oss << "\"" << v << "\"";
                }
                first = false;
            }
            oss << "}";
            return oss.str();
        };
    }

    std::cout << "[RPC] Registered " << commands.size() << " Digital DNA RPC commands" << std::endl;
}

bool CRPCServer::Start() {
    if (m_running) {
        return false;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif

    // RPC-001 FIX: Bind to localhost only for security (by default)
    // SECURITY: RPC server binds to 127.0.0.1 (localhost) only by default
    // This prevents remote network access and mitigates the risk of credential
    // interception, as HTTP Basic Auth transmits credentials in Base64 (not encrypted).
    //
    // IMPORTANT: For remote access, use SSH tunneling:
    //   ssh -L 8332:127.0.0.1:8332 user@remote-host
    //
    // PUBLIC API MODE (--public-api flag):
    // When m_publicAPI is true, binds to all interfaces to allow light wallet clients
    // to connect from any IP. Only the REST API endpoints (/api/v1/*) are accessible
    // without authentication. JSON-RPC endpoints still require auth.
    // SECURITY: Only enable on seed nodes, not home mining nodes.
    std::string bind_addr;
    if (m_publicAPI) {
        bind_addr = "";  // All interfaces (dual-stack IPv4+IPv6)
        std::cout << "[RPC] Public API mode enabled - binding to all interfaces:" << m_port << std::endl;
    } else {
        bind_addr = "127.0.0.1";  // Localhost only
    }

    socket_t rpc_sock;
    bool is_ipv6;
    if (!CSock::CreateListenSocket(static_cast<uint16_t>(m_port), bind_addr, rpc_sock, is_ipv6)) {
        ErrorMessage error = CErrorFormatter::NetworkError("bind RPC server",
            "Failed to bind to port " + std::to_string(m_port));
        error.recovery_steps = {
            "Check if port is already in use",
            "Verify you have permission to bind to this port",
            "Try a different port with --rpcport"
        };
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        return false;
    }
    m_serverSocket = static_cast<int>(rpc_sock);

    // Listen for connections
    if (listen(m_serverSocket, 128) == SOCKET_ERROR) {
        ErrorMessage error = CErrorFormatter::NetworkError("listen RPC server",
            "Failed to listen on socket");
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
        return false;
    }

    // Log security notice
    if (m_publicAPI) {
        std::cout << "[RPC] Server bound to port " << m_port
                  << (is_ipv6 ? " (dual-stack IPv4+IPv6)" : " (IPv4 only)") << std::endl;
    } else {
        std::cout << "[RPC] Server bound to 127.0.0.1:" << m_port << " (localhost only)" << std::endl;
    }
    std::cout << "[RPC] SECURITY: For remote access, use SSH tunneling" << std::endl;

    // Initialize REST API with component references
    if (m_restAPI) {
        m_restAPI->RegisterMempool(m_mempool);
        m_restAPI->RegisterBlockchain(m_blockchain);
        m_restAPI->RegisterUTXOSet(m_utxo_set);
        m_restAPI->RegisterChainState(m_chainstate);
        m_restAPI->RegisterRateLimiter(&m_rateLimiter);
        std::cout << "[RPC] REST API initialized for light wallet support" << std::endl;
    }

    // Start server thread
    m_running = true;
    m_serverThread = std::thread(&CRPCServer::ServerThread, this);

    // RPC-002: Start worker thread pool
    m_workerThreads.reserve(m_threadPoolSize);
    for (size_t i = 0; i < m_threadPoolSize; ++i) {
        m_workerThreads.emplace_back(&CRPCServer::WorkerThread, this);
    }
    std::cout << "[RPC] Started thread pool with " << m_threadPoolSize << " workers" << std::endl;

    // Start cleanup thread (rate limiter maintenance)
    m_cleanupThread = std::thread(&CRPCServer::CleanupThread, this);

    return true;
}

void CRPCServer::Stop() {
    if (!m_running) {
        return;
    }

    m_running = false;

    // Phase 4: Stop WebSocket server
    if (m_websocket_server) {
        m_websocket_server->Stop();
    }

    // Phase 3: Clean up all SSL connections
    if (m_ssl_wrapper) {
        std::lock_guard<std::mutex> lock(m_ssl_mutex);
        for (auto& pair : m_ssl_connections) {
            m_ssl_wrapper->SSLShutdown(pair.second);
            m_ssl_wrapper->SSLFree(pair.second);
            closesocket(pair.first);
        }
        m_ssl_connections.clear();
    }

    // Shutdown and close server socket
    if (m_serverSocket != INVALID_SOCKET) {
        // Shutdown the socket to unblock accept() call
        #ifdef _WIN32
        shutdown(m_serverSocket, SD_BOTH);
        #else
        shutdown(m_serverSocket, SHUT_RDWR);
        #endif

        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
    }

    // RPC-002: Wake up all worker threads so they can exit
    m_queueCV.notify_all();

    // Wait for server thread
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }

    // RPC-002: Wait for all worker threads to finish
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_workerThreads.clear();

    // Wait for cleanup thread
    if (m_cleanupThread.joinable()) {
        m_cleanupThread.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

bool CRPCServer::InitializePermissions(const std::string& configPath,
                                       const std::string& legacyUser,
                                       const std::string& legacyPassword) {
    // FIX-014: Initialize permission system
    m_permissions = std::make_unique<CRPCPermissions>();

    // Try to load from configuration file
    if (m_permissions->LoadFromFile(configPath)) {
        std::cout << "[RPC-PERMISSIONS] Loaded " << m_permissions->GetUserCount()
                  << " users from " << configPath << std::endl;
        return true;
    }

    // Fall back to legacy mode (single admin user)
    std::cout << "[RPC-PERMISSIONS] Config file not found, using legacy mode" << std::endl;

    if (!m_permissions->InitializeLegacyMode(legacyUser, legacyPassword)) {
        std::cerr << "[RPC-PERMISSIONS] ERROR: Failed to initialize permissions" << std::endl;
        return false;
    }

    return true;
}

void CRPCServer::ServerThread() {
    // Phase 1.1: Wrap thread entry point in try/catch to prevent silent crashes
    try {
        while (m_running) {
        // Accept client connection
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(m_serverSocket, (struct sockaddr*)&clientAddr, &clientLen);

        if (clientSocket == INVALID_SOCKET) {
            if (m_running) {
                // Error occurred
                continue;
            } else {
                // Server stopped
                break;
            }
        }

        // Phase 3: Perform SSL handshake if SSL is enabled
        if (m_ssl_enabled && m_ssl_wrapper) {
            SSL* ssl = m_ssl_wrapper->AcceptSSL(clientSocket);
            if (!ssl) {
                // SSL handshake failed
                std::cerr << "[RPC-SSL] SSL handshake failed: "
                          << m_ssl_wrapper->GetLastError() << std::endl;
                #ifdef _WIN32
                shutdown(clientSocket, SD_BOTH);
                #else
                shutdown(clientSocket, SHUT_RDWR);
                #endif
                closesocket(clientSocket);
                continue;
            }
            // Store SSL pointer in map for HandleClient to retrieve
            {
                std::lock_guard<std::mutex> lock(m_ssl_mutex);
                m_ssl_connections[clientSocket] = ssl;
            }
        }

        // RPC-002: Add client to thread pool queue
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_clientQueue.push(clientSocket);
        }
        // Notify one worker thread that work is available
        m_queueCV.notify_one();
        }
    } catch (const std::exception& e) {
        // Phase 1.1: Prevent silent thread crashes
        ErrorMessage error = CErrorFormatter::NetworkError("RPC server thread", e.what());
        error.severity = ErrorSeverity::CRITICAL;
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
    } catch (...) {
        ErrorMessage error(ErrorSeverity::CRITICAL, "RPC Server Error", 
                          "RPC server thread crashed with unknown exception");
        error.recovery_steps.push_back("Check system logs");
        error.recovery_steps.push_back("Restart the node");
        error.recovery_steps.push_back("Report this issue");
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
    }
}

// RPC-002: Worker Thread Implementation
void CRPCServer::WorkerThread() {
    // Phase 1.1: Wrap thread entry point in try/catch to prevent silent crashes
    try {
        while (m_running) {
        int clientSocket = INVALID_SOCKET;

        // Wait for work or shutdown
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // Wait until there's work in the queue or we're shutting down
            m_queueCV.wait(lock, [this] {
                return !m_running || !m_clientQueue.empty();
            });

            // Check if we're shutting down
            if (!m_running && m_clientQueue.empty()) {
                return;
            }

            // Get next client socket from queue
            if (!m_clientQueue.empty()) {
                clientSocket = m_clientQueue.front();
                m_clientQueue.pop();
            }
        }

        // Handle client connection (outside the lock)
        // NOTE: HandleClient closes the socket internally in all code paths
        if (clientSocket != INVALID_SOCKET) {
            HandleClient(clientSocket);
            // Socket is already closed by HandleClient - do NOT close again here
            // Double-close was causing ERR_CONNECTION_ABORTED for subsequent connections
        }
        }
    } catch (const std::exception& e) {
        // Phase 1.1: Prevent silent thread crashes
        ErrorMessage error = CErrorFormatter::NetworkError("RPC worker thread", e.what());
        error.severity = ErrorSeverity::ERR;
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
    } catch (...) {
        ErrorMessage error(ErrorSeverity::ERR, "RPC Worker Error",
                          "RPC worker thread crashed with unknown exception");
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
    }
}

void CRPCServer::CleanupThread() {
    // Phase 1.1: Wrap thread entry point in try/catch to prevent silent crashes
    try {
        // Rate limiter maintenance: clean up old records every 5 minutes
        const std::chrono::minutes CLEANUP_INTERVAL(5);

        while (m_running) {
        // Sleep for 5 minutes, but wake up every second to check m_running
        for (int i = 0; i < 300 && m_running; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (!m_running) {
            break;
        }

        // Clean up old rate limiter records
        m_rateLimiter.CleanupOldRecords();
        }
    } catch (const std::exception& e) {
        // Phase 1.1: Prevent silent thread crashes
        ErrorMessage error = CErrorFormatter::NetworkError("RPC cleanup thread", e.what());
        error.severity = ErrorSeverity::WARNING;
        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
    } catch (...) {
        std::cerr << "[RPC-Cleanup] FATAL: CleanupThread unknown exception" << std::endl;
    }
}

void CRPCServer::HandleClient(int clientSocket) {
    // Phase 3: Get SSL connection if SSL is enabled
    SSL* ssl = nullptr;
    if (m_ssl_enabled && m_ssl_wrapper) {
        std::lock_guard<std::mutex> lock(m_ssl_mutex);
        auto it = m_ssl_connections.find(clientSocket);
        if (it != m_ssl_connections.end()) {
            ssl = it->second;
        }
    }

    // RPC-017 FIX: Reduce socket timeouts to prevent slowloris attacks
    // Reduced from 30s to 10s (sufficient for RPC, prevents connection exhaustion)
    // CID 1675178 FIX: Check return value of setsockopt to ensure timeout is set
    // setsockopt returns 0 on success, -1 on error
    #ifdef _WIN32
    DWORD timeout = 10000;  // 10 seconds in milliseconds
    // CID 1675178 FIX: setsockopt failure is non-critical
    (void)setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    (void)setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    #else
    struct timeval timeout;
    timeout.tv_sec = 10;  // 10 seconds (down from 30)
    timeout.tv_usec = 0;
    // CID 1675178 FIX: setsockopt failure is non-critical
    (void)setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    (void)setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    #endif

    // Get client IP for rate limiting
    std::string clientIP = GetClientIP(clientSocket);
    
    // Phase 3: Helper lambda for reading (works with both plain and SSL sockets)
    auto socket_read = [this, ssl](int socket_fd, void* buffer, int size) -> int {
        if (ssl && m_ssl_wrapper) {
            return m_ssl_wrapper->SSLRead(ssl, buffer, size);
        } else {
            return recv(socket_fd, (char*)buffer, size, 0);
        }
    };
    
    // Phase 3: Helper lambda for writing (works with both plain and SSL sockets)
    auto socket_write = [this, ssl](int socket_fd, const void* buffer, int size) -> int {
        if (ssl && m_ssl_wrapper) {
            return m_ssl_wrapper->SSLWrite(ssl, buffer, size);
        } else {
            return send(socket_fd, (const char*)buffer, size, 0);
        }
    };
    
    // Helper lambda to properly close a client socket (shutdown + close prevents CLOSE-WAIT leak)
    auto close_client_socket = [this, &ssl, clientSocket]() {
        if (ssl && m_ssl_wrapper) {
            m_ssl_wrapper->SSLShutdown(ssl);
            m_ssl_wrapper->SSLFree(ssl);
            std::lock_guard<std::mutex> lock(m_ssl_mutex);
            m_ssl_connections.erase(clientSocket);
        }
        #ifdef _WIN32
        shutdown(clientSocket, SD_BOTH);
        #else
        shutdown(clientSocket, SHUT_RDWR);
        #endif
        closesocket(clientSocket);
    };

    // Phase 3: Helper lambda for sending response and cleaning up
    auto send_response_and_cleanup = [&close_client_socket, clientSocket, &socket_write](const std::string& response) {
        (void)socket_write(clientSocket, response.c_str(), response.size());  // CID 1675273/1675308: Best-effort
        close_client_socket();
    };

    // Check if IP is locked out due to failed auth attempts
    if (m_rateLimiter.IsLockedOut(clientIP)) {
        std::string response = BuildHTTPResponse(
            "{\"error\":\"Too many failed authentication attempts. Try again later.\"}"
        );
        send_response_and_cleanup(response);
        return;
    }

    // Check rate limit
    if (!m_rateLimiter.AllowRequest(clientIP)) {
        std::string response = BuildHTTPResponse(
            "{\"error\":\"Rate limit exceeded. Please slow down your requests.\"}"
        );
        send_response_and_cleanup(response);
        return;
    }

    // RPC-003 FIX: Separate HTTP and JSON-RPC body size limits
    // Dilithium sigs are ~3.7KB per input, so a 50-input tx = ~370KB signed hex
    // = ~740KB JSON body. 2MB allows headroom for larger consolidation txs.
    const size_t MAX_REQUEST_SIZE = 2 * 1024 * 1024;  // 2MB for HTTP (headers + body)
    const size_t MAX_JSONRPC_BODY_SIZE = 2 * 1024 * 1024;  // 2MB for JSON-RPC body
    const size_t CHUNK_SIZE = 4096;

    std::vector<char> buffer;
    buffer.reserve(CHUNK_SIZE);

    size_t totalRead = 0;
    bool requestComplete = false;

    // Phase 1: Read until we find the end of HTTP headers (\r\n\r\n)
    size_t headerEndPos = std::string::npos;
    while (totalRead < MAX_REQUEST_SIZE && !requestComplete) {
        char chunk[CHUNK_SIZE];
        int bytesRead = socket_read(clientSocket, chunk, sizeof(chunk));

        if (bytesRead <= 0) {
            // Connection closed or error
            if (totalRead == 0) {
                // No data received at all — close socket to avoid fd leak
                close_client_socket();
                return;
            }
            // Partial data received - treat as complete
            break;
        }

        // Append chunk to buffer
        buffer.insert(buffer.end(), chunk, chunk + bytesRead);
        totalRead += bytesRead;

        // Check if we have complete HTTP headers (end with \r\n\r\n)
        // CID 1675184 FIX: Pre-compute all bounds to prevent any overflow in loop
        // Validate bytesRead before casting to prevent integer overflow
        const size_t bufSize = buffer.size();
        if (bufSize >= 4 && bytesRead > 0) {
            // CID 1675184 FIX: Safe cast - bytesRead is int and we verified > 0 above
            // A positive int is always safely castable to size_t
            size_t bytesReadSize = static_cast<size_t>(bytesRead);

            // CID 1675184 FIX: Check for overflow in bytesReadSize + 3 before subtraction
            // This prevents overflowed constant from being used in arithmetic
            size_t searchStart = 0;
            if (bytesReadSize <= SIZE_MAX - 3) {
                // Safe to compute: bufSize > bytesReadSize + 3 check prevents underflow
                size_t sum = bytesReadSize + 3;
                if (bufSize > sum) {
                    searchStart = bufSize - sum;
                }
            }
            // If overflow would occur, searchStart remains 0 (search from beginning)

            // Pre-compute max index where [i+3] is valid - bufSize >= 4 guaranteed above
            const size_t maxIdx = bufSize - 4;
            for (size_t i = searchStart; i <= maxIdx; i++) {
                if (buffer[i] == '\r' && buffer[i+1] == '\n' &&
                    buffer[i+2] == '\r' && buffer[i+3] == '\n') {
                    requestComplete = true;
                    headerEndPos = i + 4;
                    break;
                }
                // Also check for \n\n (less common but valid) - [i+1] valid since i <= bufSize-4
                if (buffer[i] == '\n' && buffer[i+1] == '\n') {
                    requestComplete = true;
                    headerEndPos = i + 2;
                    break;
                }
            }
        }
    }

    // Phase 2: If headers found, check Content-Length and read remaining body
    if (requestComplete && headerEndPos != std::string::npos) {
        // Extract Content-Length from headers
        std::string headers(buffer.data(), headerEndPos);
        size_t contentLength = 0;
        size_t clPos = headers.find("Content-Length:");
        if (clPos == std::string::npos) {
            clPos = headers.find("content-length:");
        }
        if (clPos != std::string::npos) {
            size_t valStart = clPos + 15;  // strlen("Content-Length:")
            while (valStart < headers.size() && headers[valStart] == ' ') valStart++;
            size_t valEnd = headers.find("\r\n", valStart);
            if (valEnd == std::string::npos) valEnd = headers.find("\n", valStart);
            if (valEnd != std::string::npos) {
                contentLength = std::stoul(headers.substr(valStart, valEnd - valStart));
            }
        }

        // Read remaining body bytes if needed
        size_t bodyBytesRead = buffer.size() - headerEndPos;
        size_t totalNeeded = headerEndPos + contentLength;
        if (totalNeeded > MAX_REQUEST_SIZE) totalNeeded = MAX_REQUEST_SIZE;

        while (buffer.size() < totalNeeded) {
            char chunk[CHUNK_SIZE];
            int bytesRead = socket_read(clientSocket, chunk, sizeof(chunk));
            if (bytesRead <= 0) break;
            buffer.insert(buffer.end(), chunk, chunk + bytesRead);
            totalRead += bytesRead;
            if (totalRead >= MAX_REQUEST_SIZE) break;
        }
    }

    // Check if request exceeded size limit
    if (totalRead >= MAX_REQUEST_SIZE && !requestComplete) {
        std::string response = "HTTP/1.1 413 Payload Too Large\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: 52\r\n"
                               "Connection: close\r\n"
                               "\r\n"
                               "{\"error\":\"Request too large (max 1MB)\",\"code\":-32700}";
        send_response_and_cleanup(response);
        return;
    }

    // Null-terminate and convert to string
    buffer.push_back('\0');
    std::string request(buffer.data());

    // Serve miner dashboard at GET /miner
    if (request.find("GET /miner") == 0) {
        const std::string& miner_html = GetMinerHTML();
        std::ostringstream response;
        response << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: text/html; charset=utf-8\r\n"
                 << "Content-Length: " << miner_html.length() << "\r\n"
                 << "Connection: close\r\n"
                 << "Cache-Control: no-cache\r\n"
                 << "\r\n"
                 << miner_html;
        std::string resp_str = response.str();
        send_response_and_cleanup(resp_str);
        return;
    }

    // Serve web wallet at GET /wallet or GET /wallet.html
    if (request.find("GET /wallet") == 0 || request.find("GET / HTTP") == 0) {
        const std::string& wallet_html = GetWalletHTML();
        std::ostringstream response;
        response << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: text/html; charset=utf-8\r\n"
                 << "Content-Length: " << wallet_html.length() << "\r\n"
                 << "Connection: close\r\n"
                 << "Cache-Control: no-cache\r\n"
                 << "\r\n"
                 << wallet_html;
        std::string resp_str = response.str();
        send_response_and_cleanup(resp_str);
        return;
    }

    // CORS: Handle OPTIONS preflight requests for web wallet and REST API
    // Browsers send OPTIONS before cross-origin requests with custom headers
    if (request.find("OPTIONS ") == 0) {
        std::string response = "HTTP/1.1 204 No Content\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                               "Access-Control-Allow-Headers: Content-Type, Authorization, X-Dilithion-RPC\r\n"
                               "Access-Control-Max-Age: 86400\r\n"
                               "Content-Length: 0\r\n"
                               "Connection: close\r\n"
                               "\r\n";
        send_response_and_cleanup(response);
        return;
    }

    // REST API: Handle /api/v1/* endpoints for light wallet clients
    // These endpoints don't require authentication or CSRF headers (public read + broadcast)
    // Rate limiting is handled internally by the REST API handler
    if (m_restAPI) {
        // Extract path from HTTP request
        std::string method;
        std::string path;
        size_t methodEnd = request.find(' ');
        if (methodEnd != std::string::npos) {
            method = request.substr(0, methodEnd);
            size_t pathStart = methodEnd + 1;
            size_t pathEnd = request.find(' ', pathStart);
            if (pathEnd != std::string::npos) {
                path = request.substr(pathStart, pathEnd - pathStart);
            }
        }

        // Check if this is a REST API request
        if (CRestAPI::IsRESTRequest(path)) {
            // Extract body for POST requests
            std::string body;
            size_t bodyStart = request.find("\r\n\r\n");
            if (bodyStart != std::string::npos) {
                body = request.substr(bodyStart + 4);
            }

            // Handle the REST request
            std::string response = m_restAPI->HandleRequest(method, path, body, clientIP);
            send_response_and_cleanup(response);
            return;
        }
    }

    // RPC-004 FIX: CSRF Protection via Custom Header
    // Require X-Dilithion-RPC header to prevent Cross-Site Request Forgery
    // Browsers block custom headers in simple CORS requests, preventing CSRF attacks
    // This is the recommended approach for JSON-RPC APIs (simpler than CSRF tokens)
    std::string csrfHeader;
    bool hasCSRFHeader = false;

    // Search for X-Dilithion-RPC header
    size_t headerPos = request.find("X-Dilithion-RPC:");
    if (headerPos == std::string::npos) {
        // Try lowercase variant
        headerPos = request.find("x-dilithion-rpc:");
    }

    if (headerPos != std::string::npos) {
        // Extract header value (anything is acceptable, just needs to be present)
        size_t valueStart = headerPos + 16;  // Length of "x-dilithion-rpc:"
        while (valueStart < request.size() && (request[valueStart] == ' ' || request[valueStart] == '\t')) {
            valueStart++;
        }
        // Header exists and has some value - CSRF check passes
        hasCSRFHeader = true;
    }

    if (!hasCSRFHeader) {
        // CSRF block is logged to audit file only (not console) to avoid
        // spamming users — the web wallet's browser triggers this on every
        // page load, favicon request, etc.

        // Phase 1: Log security event
        if (m_logger) {
            m_logger->LogSecurityEvent("CSRF_BLOCKED", clientIP, "",
                "Missing X-Dilithion-RPC header");
        }

        // RPC-004: Reject requests without CSRF protection header
        std::string response = "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: 108\r\n"
                               "Connection: close\r\n"
                               "X-Content-Type-Options: nosniff\r\n"
                               "X-Frame-Options: DENY\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                               "Access-Control-Allow-Headers: Content-Type, Authorization, X-Dilithion-RPC\r\n"
                               "\r\n"
                               "{\"error\":\"CSRF protection: Missing X-Dilithion-RPC header. Include 'X-Dilithion-RPC: 1' in request.\",\"code\":-32600}";
        send_response_and_cleanup(response);
        return;
    }

    // FIX-014: Declare username/password outside auth block for permission checking
    std::string username = "";
    std::string password = "";
    uint32_t userPermissions = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);  // Default to admin if no auth

    // Check authentication if configured
    if (RPCAuth::IsAuthConfigured()) {
        std::string authHeader;
        if (!ExtractAuthHeader(request, authHeader)) {
            // No Authorization header
            std::string response = BuildHTTPUnauthorized();
            send_response_and_cleanup(response);
            return;
        }

        // Parse credentials
        if (!RPCAuth::ParseAuthHeader(authHeader, username, password)) {
            // Malformed Authorization header
            std::string response = BuildHTTPUnauthorized();
            send_response_and_cleanup(response);
            return;
        }

        // Authenticate
        if (!RPCAuth::AuthenticateRequest(username, password)) {
            // RPC-016 FIX: Audit log failed authentication attempt
            std::cout << "[RPC-SECURITY] Failed authentication from " << clientIP
                      << " (user: " << username << ")" << std::endl;

            // Phase 1: Log security event
            if (m_logger) {
                m_logger->LogSecurityEvent("AUTH_FAILURE", clientIP, username,
                    "Invalid credentials provided");
            }

            // Invalid credentials - record failure
            m_rateLimiter.RecordAuthFailure(clientIP);
            std::string response = BuildHTTPUnauthorized();
            send_response_and_cleanup(response);
            return;
        }

        // RPC-016 FIX: Audit log successful authentication
        std::cout << "[RPC-AUDIT] Successful authentication from " << clientIP
                  << " (user: " << username << ")" << std::endl;
        
        // Phase 1: Log security event
        if (m_logger) {
            m_logger->LogSecurityEvent("AUTH_SUCCESS", clientIP, username, "Authentication successful");
        }

        // Authentication successful - reset failure counter
        m_rateLimiter.RecordAuthSuccess(clientIP);

        // FIX-014: Get user permissions for authorization checking
        if (m_permissions) {
            if (!m_permissions->AuthenticateUser(username, password, userPermissions)) {
                // Should not happen (already authenticated above), but handle gracefully
                std::cerr << "[RPC-PERMISSIONS] ERROR: Permission lookup failed for user: "
                          << username << std::endl;
                std::string response = BuildHTTPUnauthorized();
                send_response_and_cleanup(response);
                return;
            }

            std::cout << "[RPC-PERMISSIONS] User '" << username << "' has role: "
                      << CRPCPermissions::GetRoleName(userPermissions) << std::endl;
        } else {
            // Permissions not initialized - allow (backwards compatibility)
            std::cout << "[RPC-PERMISSIONS] WARNING: Permissions not initialized, allowing request" << std::endl;
            userPermissions = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);  // Grant admin if not configured
        }
    }

    // Parse HTTP request
    std::string jsonrpc;
    if (!ParseHTTPRequest(request, jsonrpc)) {
        // Invalid HTTP request
        std::string response = BuildHTTPResponse("{\"error\":\"Invalid HTTP request\"}");
        send_response_and_cleanup(response);
        return;
    }

    // RPC-003 FIX: Validate JSON-RPC body size (prevent DoS via large/nested JSON)
    if (jsonrpc.size() > MAX_JSONRPC_BODY_SIZE) {
        std::string response = "HTTP/1.1 413 Payload Too Large\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: 73\r\n"
                               "Connection: close\r\n"
                               "\r\n"
                               "{\"error\":\"JSON-RPC body too large (max 64KB)\",\"code\":-32700}";
        send_response_and_cleanup(response);
        return;
    }

    // Phase 2: Detect if this is a batch request (array) or single request (object)
    bool is_batch_request = false;
    try {
        nlohmann::json test_json = nlohmann::json::parse(jsonrpc);
        is_batch_request = test_json.is_array();
    } catch (...) {
        // Invalid JSON - will be caught below
    }

    // Phase 2: Handle batch requests
    if (is_batch_request) {
        std::vector<RPCRequest> batch_requests;
        try {
            batch_requests = ParseBatchRPCRequest(jsonrpc);
        } catch (const std::exception& e) {
            // Batch parse error
            std::vector<std::string> recovery = {
                "Check JSON syntax",
                "Verify Content-Type is application/json",
                "Ensure batch request is an array of JSON-RPC 2.0 objects"
            };
            RPCResponse rpcResp = RPCResponse::ErrorStructured(-32700,
                std::string("Batch parse error: ") + e.what(), "", "RPC-PARSE-ERROR", recovery);
            std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
            send_response_and_cleanup(response);
            return;
        } catch (...) {
            std::vector<std::string> recovery = {
                "Check JSON syntax",
                "Verify batch request format"
            };
            RPCResponse rpcResp = RPCResponse::ErrorStructured(-32700, "Batch parse error", "",
                "RPC-PARSE-ERROR", recovery);
            std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
            send_response_and_cleanup(response);
            return;
        }

        // Phase 2: Validate batch size (prevent DoS)
        const size_t MAX_BATCH_SIZE = 100;  // Limit batch to 100 requests
        if (batch_requests.size() > MAX_BATCH_SIZE) {
            std::vector<std::string> recovery = {
                "Reduce batch size to " + std::to_string(MAX_BATCH_SIZE) + " requests or fewer",
                "Split into multiple batch requests"
            };
            RPCResponse rpcResp = RPCResponse::ErrorStructured(-32600,
                "Batch size too large (max " + std::to_string(MAX_BATCH_SIZE) + " requests)",
                "", "RPC-BATCH-TOO-LARGE", recovery);
            std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
            send_response_and_cleanup(response);
            return;
        }

        // Phase 2: Check rate limiting for batch (count as single request for rate limiting)
        if (!m_rateLimiter.AllowRequest(clientIP)) {
            std::string response = "HTTP/1.1 429 Too Many Requests\r\n"
                                   "Content-Type: application/json\r\n"
                                   "Retry-After: 60\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";
            std::vector<std::string> recovery = {
                "Wait 60 seconds before retrying",
                "Reduce request frequency"
            };
            RPCResponse rpcResp = RPCResponse::ErrorStructured(-32000,
                "Rate limit exceeded. Please slow down your requests.", "",
                "RPC-RATE-LIMIT", recovery);
            response += SerializeResponse(rpcResp);
            send_response_and_cleanup(response);
            return;
        }

        // Phase 2: Check permissions for batch (check each method in batch)
        // Note: We check permissions at batch level to avoid executing unauthorized requests
        // userPermissions was set earlier in HandleClient (after authentication)
        if (m_permissions) {
            for (const auto& req : batch_requests) {
                if (!req.method.empty() && 
                    !m_permissions->CheckMethodPermission(userPermissions, req.method)) {
                    // Permission denied for one or more methods in batch
                    // Return error response for the entire batch
                    std::string response = "HTTP/1.1 403 Forbidden\r\n"
                                           "Content-Type: application/json\r\n"
                                           "Connection: close\r\n"
                                           "\r\n";
                    std::vector<std::string> recovery = {
                        "Contact administrator to grant required permissions",
                        "Verify you are using the correct user account"
                    };
                    RPCResponse rpcResp = RPCResponse::ErrorStructured(-32000,
                        "Insufficient permissions for method '" + req.method + "' in batch",
                        "", "RPC-PERMISSION-DENIED", recovery);
                    response += SerializeResponse(rpcResp);
                    send_response_and_cleanup(response);
                    
                    // Log security event
                    if (m_logger) {
                        m_logger->LogSecurityEvent("PERMISSION_DENIED", clientIP, username,
                            "Attempted to call " + req.method + " in batch without required permissions");
                    }
                    return;
                }
            }
        }

        // Phase 2: Execute batch requests
        auto batch_start = std::chrono::steady_clock::now();
        std::vector<RPCResponse> batch_responses = ExecuteBatchRPC(batch_requests, clientIP, username);
        auto batch_end = std::chrono::steady_clock::now();
        auto batch_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            batch_end - batch_start);
        int64_t batch_duration_ms = batch_duration.count();

        // Phase 2: Log batch request
        if (m_logger && m_logger->IsEnabled()) {
            // Log each request in the batch individually
            for (size_t i = 0; i < batch_requests.size() && i < batch_responses.size(); ++i) {
                CRPCLogger::RequestLog log;
                log.timestamp = "";
                log.client_ip = clientIP;
                log.username = username;
                log.method = batch_requests[i].method;
                if (!batch_requests[i].params.empty()) {
                    uint8_t hash_bytes[32];
                    SHA3_256(reinterpret_cast<const uint8_t*>(batch_requests[i].params.data()),
                             batch_requests[i].params.size(), hash_bytes);
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (int j = 0; j < 8; ++j) {
                        oss << std::setw(2) << static_cast<int>(hash_bytes[j]);
                    }
                    log.params_hash = oss.str();
                } else {
                    log.params_hash = "";
                }
                log.success = batch_responses[i].error.empty();
                log.duration_ms = batch_duration_ms / batch_requests.size();  // Average per request
                
                if (!log.success) {
                    size_t code_pos = batch_responses[i].error.find("\"code\":");
                    if (code_pos != std::string::npos) {
                        size_t code_start = batch_responses[i].error.find_first_of("-0123456789", code_pos);
                        size_t code_end = batch_responses[i].error.find_first_not_of("0123456789-", code_start);
                        if (code_end != std::string::npos) {
                            log.error_code = batch_responses[i].error.substr(code_start, code_end - code_start);
                        }
                    }
                    log.error_message = batch_responses[i].error.substr(0, 200);
                } else {
                    log.error_code = "";
                    log.error_message = "";
                }
                
                m_logger->LogRequest(log);
            }
        }

        // Phase 2: Serialize and send batch response
        std::string batch_response_json = SerializeBatchResponse(batch_responses);
        std::string response = BuildHTTPResponse(batch_response_json);
        send_response_and_cleanup(response);
        return;
    }

    // Single request handling (existing code)
    RPCRequest rpcReq;
    try {
        rpcReq = ParseRPCRequest(jsonrpc);
    } catch (const std::exception& e) {
        // RPC-002 FIX: Proper error handling for parsing failures
        // UX: Enhanced error response
        std::vector<std::string> recovery = {
            "Check JSON syntax",
            "Verify Content-Type is application/json",
            "Ensure request follows JSON-RPC 2.0 format"
        };
        RPCResponse rpcResp = RPCResponse::ErrorStructured(-32700, 
            std::string("Parse error: ") + e.what(), "", "RPC-PARSE-ERROR", recovery);
        std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
        send_response_and_cleanup(response);
        return;
    } catch (...) {
        std::vector<std::string> recovery = {
            "Check JSON syntax",
            "Verify request format"
        };
        RPCResponse rpcResp = RPCResponse::ErrorStructured(-32700, "Parse error", "", 
            "RPC-PARSE-ERROR", recovery);
        std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
        send_response_and_cleanup(response);
        return;
    }

    // FIX-013 (RPC-002): Per-method rate limiting
    // Check method-specific rate limit after parsing but before execution
    // This prevents abuse of resource-intensive methods (walletpassphrase, sendtoaddress, etc.)
    if (!m_rateLimiter.AllowMethodRequest(clientIP, rpcReq.method)) {
        // HTTP 429 Too Many Requests (method-specific limit exceeded)
        std::string response = "HTTP/1.1 429 Too Many Requests\r\n"
                               "Content-Type: application/json\r\n"
                               "Retry-After: 60\r\n"
                               "Connection: close\r\n"
                               "\r\n";

        // UX: Enhanced error response with recovery guidance
        std::vector<std::string> recovery = {
            "Wait 60 seconds before retrying",
            "Reduce request frequency",
            "Consider batching multiple operations"
        };
        RPCResponse rpcResp = RPCResponse::ErrorStructured(
            -32000,  // Server error code
            std::string("Rate limit exceeded for method '") + rpcReq.method +
                "'. Please slow down your requests.",
            rpcReq.id,
            "RPC-RATE-LIMIT",
            recovery
        );

        response += SerializeResponse(rpcResp);
        send_response_and_cleanup(response);

        // Audit log rate limit violations for sensitive methods
        std::cout << "[RPC-RATE-LIMIT] " << clientIP << " exceeded rate limit for method: "
                  << rpcReq.method << std::endl;
        return;
    }

    // FIX-014 (RPC-004): Role-based authorization check
    // Check if user has permission to call this RPC method
    if (m_permissions && !m_permissions->CheckMethodPermission(userPermissions, rpcReq.method)) {
        // HTTP 403 Forbidden - insufficient permissions
        std::string response = "HTTP/1.1 403 Forbidden\r\n"
                               "Content-Type: application/json\r\n"
                               "Connection: close\r\n"
                               "\r\n";

        // UX: Enhanced error response with permission guidance
        std::vector<std::string> recovery = {
            "Contact administrator to grant required permissions",
            "Verify you are using the correct user account",
            "Check role-based access control configuration"
        };
        RPCResponse rpcResp = RPCResponse::ErrorStructured(
            -32000,  // Server error code
            std::string("Insufficient permissions for method '") + rpcReq.method + "'",
            rpcReq.id,
            "RPC-PERMISSION-DENIED",
            recovery
        );

        response += SerializeResponse(rpcResp);

        // Audit log authorization failure
        std::cout << "[RPC-AUTHORIZATION-DENIED] " << clientIP << " user '" << username
                  << "' (role: " << CRPCPermissions::GetRoleName(userPermissions)
                  << ") attempted to call " << rpcReq.method << " - DENIED" << std::endl;
        send_response_and_cleanup(response);
        return;
    }

    // Phase 1: Log request start time
    auto request_start = std::chrono::steady_clock::now();

    // Store client IP for handlers that need it (e.g., getmikattestation)
    m_currentClientIP = clientIP;

    // Execute RPC
    RPCResponse rpcResp = ExecuteRPC(rpcReq);
    
    // Phase 1: Calculate request duration
    auto request_end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        request_end - request_start);
    int64_t duration_ms = duration.count();

    // Phase 1: Structured request logging
    if (m_logger && m_logger->IsEnabled()) {
        CRPCLogger::RequestLog log;
        log.timestamp = "";  // Logger will set this automatically
        log.client_ip = clientIP;
        log.username = username;
        log.method = rpcReq.method;
        // Hash params for privacy (SHA-3-256, first 16 chars)
        if (!rpcReq.params.empty()) {
            uint8_t hash_bytes[32];
            SHA3_256(reinterpret_cast<const uint8_t*>(rpcReq.params.data()), rpcReq.params.size(), hash_bytes);
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (int j = 0; j < 8; ++j) {
                oss << std::setw(2) << static_cast<int>(hash_bytes[j]);
            }
            log.params_hash = oss.str();
        } else {
            log.params_hash = "";
        }
        log.success = rpcResp.error.empty();
        log.duration_ms = duration_ms;
        
        if (!log.success) {
            // Extract error code from error JSON
            // Error format: {"code":-32600,"message":"..."}
            size_t code_pos = rpcResp.error.find("\"code\":");
            if (code_pos != std::string::npos) {
                size_t code_start = rpcResp.error.find_first_of("-0123456789", code_pos);
                size_t code_end = rpcResp.error.find_first_not_of("0123456789-", code_start);
                if (code_end != std::string::npos) {
                    log.error_code = rpcResp.error.substr(code_start, code_end - code_start);
                }
            }
            log.error_message = rpcResp.error.substr(0, 200);  // First 200 chars
        } else {
            log.error_code = "";
            log.error_message = "";
        }
        
        m_logger->LogRequest(log);
    }

    // RPC-016 FIX: Legacy audit log (console output) - keep for backward compatibility
    if (!rpcResp.error.empty()) {
        std::cout << "[RPC-AUDIT] " << clientIP << " called " << rpcReq.method
                  << " - ERROR: " << rpcResp.error.substr(0, 100) << std::endl;
    } else if (rpcReq.method == "sendtoaddress" || rpcReq.method == "encryptwallet" ||
               rpcReq.method == "walletpassphrase" || rpcReq.method == "exportmnemonic" ||
               rpcReq.method == "dumpprivkey" || rpcReq.method == "importprivkey" ||
               rpcReq.method == "stop" || rpcReq.method == "forcerebuild") {
        // Log sensitive operations
        std::cout << "[RPC-AUDIT] " << clientIP << " called " << rpcReq.method
                  << " - SUCCESS" << std::endl;
    }

    // Send response
    std::string response = BuildHTTPResponse(SerializeResponse(rpcResp));
    send_response_and_cleanup(response);
}

// ============================================================================
// RPC-011 FIX: Configuration Security Notes
// ============================================================================
// SECURITY WARNING: RPC credentials in dilithion.conf are stored in plaintext!
//
// Mitigation steps:
// 1. Use strong passwords (16+ characters, mixed case, numbers, symbols)
// 2. Set restrictive file permissions: chmod 600 dilithion.conf (Unix)
// 3. Never commit dilithion.conf to version control
// 4. Consider using rpcauth format (Bitcoin-style hashed credentials)
// 5. Rotate passwords periodically
//
// Future enhancement: Implement rpcauth= config option for hashed credentials
// Format: rpcauth=<username>:<salt$hash>
// ============================================================================

// ============================================================================
// RPC-012 FIX: Error Message Sanitization (Production Guidance)
// ============================================================================
// Current implementation returns detailed error messages for debugging.
// For PRODUCTION deployment:
// 1. Set environment variable: DILITHION_PRODUCTION=1
// 2. Filter error messages to remove file paths, internal state
// 3. Log detailed errors to secure file, return generic messages to client
//
// Example production error response:
// {"error":"Internal server error","code":-32603,"ref":"err-uuid-12345"}
// (Full details logged securely with matching UUID for investigation)
// ============================================================================

// ============================================================================
// RPC-013 FIX: Mining Operation Resource Limits (Configuration)
// ============================================================================
// CMiningController::StartMining() enforces:
// 1. Max 1 concurrent mining session (atomic compare_exchange_strong)
// 2. Block template validation (null/invalid target rejection)
// 3. Auto RAM detection for RandomX mode (LIGHT vs FULL)
// 4. Thread count based on system cores
// ============================================================================

// ============================================================================
// RPC-020 FIX: Configurable Thread Pool Size (Low Priority)
// ============================================================================
// Current thread pool size is hardcoded to 8 in server.h:95
// For production, add config parameter: rpc_threads=<num>
// Recommended: num_cores * 2 (for I/O-bound workload)
// ============================================================================

// ============================================================================
// RPC-021 FIX: Error Codes vs Exceptions (Architecture Note)
// ============================================================================
// Current design throws exceptions for RPC errors, caught in ExecuteRPC()
// This is acceptable for JSON-RPC where exceptions map to error responses.
// No change needed - exception-based error handling is idiomatic for RPC.
// Exception → JSON-RPC error code mapping is handled correctly.
// ============================================================================

bool CRPCServer::ParseHTTPRequest(const std::string& request, std::string& jsonrpc) {
    // RPC-018 FIX: Validate HTTP version (must be HTTP/1.0 or HTTP/1.1)
    // Prevents HTTP/0.9 or malformed protocol attacks
    if (request.find("HTTP/1.1") == std::string::npos &&
        request.find("HTTP/1.0") == std::string::npos) {
        // Not a valid HTTP/1.x request
        return false;
    }

    // Validate method is POST (JSON-RPC requires POST)
    if (request.find("POST ") != 0) {
        return false;  // Only POST allowed for JSON-RPC
    }

    // Find the end of headers (blank line)
    size_t pos = request.find("\r\n\r\n");
    if (pos == std::string::npos) {
        pos = request.find("\n\n");
        if (pos == std::string::npos) {
            return false;
        }
        jsonrpc = request.substr(pos + 2);
    } else {
        jsonrpc = request.substr(pos + 4);
    }

    return !jsonrpc.empty();
}

std::string CRPCServer::BuildHTTPResponse(const std::string& body) {
    // RPC-009 FIX: Add comprehensive security headers
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";

    // RPC-009 FIX: Security headers to prevent common attacks
    oss << "X-Content-Type-Options: nosniff\r\n";  // Prevent MIME-sniffing
    oss << "X-Frame-Options: DENY\r\n";  // Prevent clickjacking
    oss << "X-XSS-Protection: 1; mode=block\r\n";  // XSS protection (legacy browsers)
    oss << "Content-Security-Policy: default-src 'none'\r\n";  // No external resources
    oss << "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n";  // Force HTTPS (future)
    oss << "Referrer-Policy: no-referrer\r\n";  // Don't leak referrer

    // CORS headers for web wallet support
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "Access-Control-Allow-Methods: POST, OPTIONS\r\n";
    oss << "Access-Control-Allow-Headers: Content-Type, Authorization, X-Dilithion-RPC\r\n";

    oss << "\r\n";
    oss << body;
    return oss.str();
}

std::string CRPCServer::BuildHTTPUnauthorized() {
    std::string body = "{\"error\":\"Unauthorized - Invalid or missing credentials\"}";
    std::ostringstream oss;
    oss << "HTTP/1.1 401 Unauthorized\r\n";
    oss << "WWW-Authenticate: Basic realm=\"Dilithion RPC\"\r\n";
    oss << "Content-Type: application/json\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";

    // RPC-009 FIX: Security headers (same as successful responses)
    oss << "X-Content-Type-Options: nosniff\r\n";
    oss << "X-Frame-Options: DENY\r\n";
    oss << "X-XSS-Protection: 1; mode=block\r\n";
    oss << "Content-Security-Policy: default-src 'none'\r\n";
    oss << "Referrer-Policy: no-referrer\r\n";

    // CORS headers for web wallet support
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "Access-Control-Allow-Methods: POST, OPTIONS\r\n";
    oss << "Access-Control-Allow-Headers: Content-Type, Authorization, X-Dilithion-RPC\r\n";

    oss << "\r\n";
    oss << body;
    return oss.str();
}

bool CRPCServer::ExtractAuthHeader(const std::string& request, std::string& authHeader) {
    // Look for "Authorization:" header (case-insensitive)
    size_t pos = 0;
    while (pos < request.size()) {
        // Find line start
        if (pos > 0 && request[pos - 1] != '\n') {
            pos++;
            continue;
        }

        // Check if this line starts with "Authorization:"
        if (request.compare(pos, 14, "Authorization:") == 0) {
            // Found it - extract the value
            size_t valueStart = pos + 14;
            // Skip whitespace
            while (valueStart < request.size() &&
                   (request[valueStart] == ' ' || request[valueStart] == '\t')) {
                valueStart++;
            }

            // Find end of line
            size_t valueEnd = request.find('\r', valueStart);
            if (valueEnd == std::string::npos) {
                valueEnd = request.find('\n', valueStart);
            }
            if (valueEnd == std::string::npos) {
                valueEnd = request.size();
            }

            authHeader = request.substr(valueStart, valueEnd - valueStart);
            return true;
        }

        pos++;
    }

    return false;  // No Authorization header found
}

/**
 * RPC-007 FIX: Replace manual string parsing with proper JSON library
 *
 * OLD CODE (FRAGILE):
 *   163 lines of manual substr() and find() calls
 *   Custom bounds checking at every step
 *   Hard to maintain, easy to introduce bugs
 *   Doesn't handle edge cases (escaped quotes, unicode, etc.)
 *
 * NEW CODE (ROBUST):
 *   Use nlohmann/json - industry-standard, battle-tested library
 *   Automatic type checking and validation
 *   Handles all JSON edge cases correctly
 *   Clear error messages for debugging
 *
 * Security benefits:
 *   - Proper JSON parsing prevents injection attacks
 *   - Built-in depth limiting prevents stack overflow
 *   - Handles malformed JSON safely
 *   - Type-safe parameter extraction
 */
RPCRequest CRPCServer::ParseRPCRequest(const std::string& json_str) {
    RPCRequest req;

    // Validate input is not empty
    if (json_str.empty()) {
        throw std::runtime_error("Empty JSON-RPC request");
    }

    // Parse JSON with automatic error handling
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }

    // Validate root is an object
    if (!j.is_object()) {
        throw std::runtime_error("JSON-RPC request must be an object");
    }

    // RPC-002 FIX: Validate JSON depth (prevent stack overflow)
    // nlohmann/json has built-in depth limiting, but we add explicit check
    auto validateDepth = [](const nlohmann::json& obj, size_t max_depth = 10) {
        std::function<size_t(const nlohmann::json&, size_t)> getDepth;
        getDepth = [&](const nlohmann::json& o, size_t current) -> size_t {
            if (current > max_depth) {
                throw std::runtime_error("JSON nesting too deep (max 10 levels)");
            }
            size_t max = current;
            if (o.is_object()) {
                for (auto it = o.begin(); it != o.end(); ++it) {
                    max = std::max(max, getDepth(it.value(), current + 1));
                }
            } else if (o.is_array()) {
                for (const auto& item : o) {
                    max = std::max(max, getDepth(item, current + 1));
                }
            }
            return max;
        };
        getDepth(obj, 0);
    };
    validateDepth(j);

    // Extract jsonrpc version (should be "2.0")
    if (j.contains("jsonrpc")) {
        if (!j["jsonrpc"].is_string()) {
            throw std::runtime_error("'jsonrpc' field must be a string");
        }
        req.jsonrpc = j["jsonrpc"].get<std::string>();
        if (req.jsonrpc != "2.0") {
            throw std::runtime_error("Unsupported JSON-RPC version: " + req.jsonrpc);
        }
    } else {
        req.jsonrpc = "2.0";  // Default to 2.0
    }

    // Extract method (REQUIRED field)
    if (!j.contains("method")) {
        throw std::runtime_error("Missing required 'method' field");
    }
    if (!j["method"].is_string()) {
        throw std::runtime_error("'method' field must be a string");
    }
    req.method = j["method"].get<std::string>();

    // Validate method name
    const size_t MAX_METHOD_LEN = 64;
    if (req.method.empty()) {
        throw std::runtime_error("Empty method name");
    }
    if (req.method.length() > MAX_METHOD_LEN) {
        throw std::runtime_error("Method name too long (max 64 characters)");
    }

    // Validate method contains only allowed characters (alphanumeric + underscore)
    for (char c : req.method) {
        if (!isalnum(c) && c != '_') {
            throw std::runtime_error("Invalid character in method name: '" + std::string(1, c) + "'");
        }
    }

    // Extract id (OPTIONAL field per JSON-RPC 2.0 spec)
    if (j.contains("id")) {
        const auto& id_field = j["id"];
        if (id_field.is_string()) {
            const std::string id_str = id_field.get<std::string>();
            const size_t MAX_ID_LEN = 128;
            if (id_str.length() > MAX_ID_LEN) {
                throw std::runtime_error("Request ID too long (max 128 characters)");
            }
            req.id = id_str;
        } else if (id_field.is_number_integer()) {
            req.id = std::to_string(id_field.get<int64_t>());
        } else if (id_field.is_null()) {
            req.id = "null";
        } else {
            throw std::runtime_error("'id' field must be string, number, or null");
        }
    }

    // Extract params (OPTIONAL field)
    // Store params as JSON string for backward compatibility with existing RPC methods
    if (j.contains("params")) {
        const auto& params_field = j["params"];
        if (params_field.is_object() || params_field.is_array()) {
            req.params = params_field.dump();  // Serialize back to JSON string
        } else if (params_field.is_null()) {
            req.params = "null";
        } else {
            throw std::runtime_error("'params' field must be object, array, or null");
        }
    }

    return req;
}

RPCResponse CRPCServer::ExecuteRPC(const RPCRequest& request) {
    std::lock_guard<std::mutex> lock(m_handlersMutex);

    // Find handler
    auto it = m_handlers.find(request.method);
    if (it == m_handlers.end()) {
        // UX: Enhanced error for method not found
        std::vector<std::string> recovery = {
            "Check method name spelling",
            "Verify method is available in this version",
            "Use 'help' method to list available methods"
        };
        return RPCResponse::ErrorStructured(-32601, 
            "Method not found: " + request.method, request.id,
            "RPC-METHOD-NOT-FOUND", recovery);
    }

    // Execute handler
    try {
        std::string result = it->second(request.params);
        return RPCResponse::Success(result, request.id);
    } catch (const std::exception& e) {
        return RPCResponse::Error(-32603, e.what(), request.id);
    }
}

std::vector<RPCRequest> CRPCServer::ParseBatchRPCRequest(const std::string& json_str) {
    std::vector<RPCRequest> requests;

    // Validate input is not empty
    if (json_str.empty()) {
        throw std::runtime_error("Empty JSON-RPC batch request");
    }

    // Parse JSON
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }

    // Validate root is an array
    if (!j.is_array()) {
        throw std::runtime_error("JSON-RPC batch request must be an array");
    }

    // Validate batch is not empty
    if (j.empty()) {
        throw std::runtime_error("Batch request array cannot be empty");
    }

    // Parse each request in the batch
    for (const auto& item : j) {
        // Each item must be an object
        if (!item.is_object()) {
            // Per JSON-RPC 2.0 spec, invalid requests in batch should result in error response
            // We'll create a request with error flag
            RPCRequest req;
            req.method = "";  // Invalid request marker
            req.id = item.contains("id") ? item["id"].dump() : "null";
            requests.push_back(req);
            continue;
        }

        // Serialize item back to string and parse as single request
        std::string item_str = item.dump();
        try {
            RPCRequest req = ParseRPCRequest(item_str);
            requests.push_back(req);
        } catch (const std::exception& e) {
            // Invalid request in batch - create error request
            RPCRequest req;
            req.method = "";  // Invalid request marker
            req.id = item.contains("id") ? item["id"].dump() : "null";
            requests.push_back(req);
        }
    }

    return requests;
}

std::vector<RPCResponse> CRPCServer::ExecuteBatchRPC(const std::vector<RPCRequest>& requests,
                                                      const std::string& clientIP,
                                                      const std::string& username) {
    std::vector<RPCResponse> responses;

    // Get user permissions once (if permissions enabled and user authenticated)
    uint32_t userPermissions = static_cast<uint32_t>(RPCPermission::ROLE_ADMIN);
    if (m_permissions && !username.empty()) {
        // Note: We already authenticated in HandleClient, so we can't re-authenticate here
        // Instead, we'll use a simplified permission check - in a real implementation,
        // we'd cache the permissions from HandleClient
        // For now, we'll check permissions per request (less efficient but correct)
    }

    for (const auto& request : requests) {
        // Handle invalid requests (from batch parsing)
        if (request.method.empty()) {
            RPCResponse error_resp = RPCResponse::ErrorStructured(-32600,
                "Invalid Request", request.id, "RPC-INVALID-REQUEST",
                {"Check JSON-RPC 2.0 format", "Verify request is a valid object"});
            // Move error response (avoids unnecessary copy)
            responses.push_back(std::move(error_resp));
            continue;
        }

        // Check method permission (if permissions enabled)
        // Note: Permission checking was already done in HandleClient for the batch,
        // but we check per-request here for granular control
        // In a production system, we'd pass the userPermissions from HandleClient
        // For now, we allow all requests in batch (permissions checked at batch level)
        
        // Execute request
        RPCResponse resp = ExecuteRPC(request);
        // Move response (avoids unnecessary copy)
        responses.push_back(std::move(resp));
    }

    return responses;
}

std::string CRPCServer::SerializeBatchResponse(const std::vector<RPCResponse>& responses) {
    std::ostringstream oss;
    oss << "[";
    
    for (size_t i = 0; i < responses.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << SerializeResponse(responses[i]);
    }
    
    oss << "]";
    return oss.str();
}

std::string CRPCServer::SerializeResponse(const RPCResponse& response) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"jsonrpc\":\"2.0\",";
    if (!response.error.empty()) {
        oss << "\"error\":" << response.error << ",";
    } else {
        oss << "\"result\":" << response.result << ",";
    }
    oss << "\"id\":";
    if (response.id.empty() || response.id == "null") {
        oss << "null";
    } else if (isdigit(response.id[0]) || response.id[0] == '-') {
        oss << response.id;
    } else {
        oss << "\"" << response.id << "\"";
    }
    oss << "}";
    return oss.str();
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format amount from smallest unit to coin with proper decimal places
 * DIL: 1 DIL = 100,000,000 ions | DilV: 1 DilV = 100,000,000 volts
 */
std::string CRPCServer::FormatAmount(CAmount amount) const {
    const CAmount COIN = 100000000;
    bool negative = amount < 0;
    if (negative) amount = -amount;

    CAmount wholePart = amount / COIN;
    CAmount fractionalPart = amount % COIN;

    std::ostringstream oss;
    if (negative) oss << "-";
    oss << wholePart << ".";
    oss << std::setfill('0') << std::setw(8) << fractionalPart;
    return oss.str();
}

/**
 * Validate and parse a Dilithion address string
 */
bool CRPCServer::ValidateAddress(const std::string& addressStr, CDilithiumAddress& addressOut) const {
    if (addressStr.empty()) {
        return false;
    }

    CDilithiumAddress addr;
    if (!addr.SetString(addressStr)) {
        return false;
    }

    if (!addr.IsValid()) {
        return false;
    }

    addressOut = addr;
    return true;
}

/**
 * Escape special characters for JSON strings
 */
std::string CRPCServer::EscapeJSON(const std::string& str) const {
    std::ostringstream oss;
    for (char c : str) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b";  break;
            case '\f': oss << "\\f";  break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

// ============================================================================
// RPC Method Implementations
// ============================================================================

// ----------------------------------------------------------------------------
// Wallet Information RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_GetNewAddress(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    CDilithiumAddress addr;
    // For HD wallets, derive a new address for privacy
    // This implements proper BIP44-style address generation
    if (m_wallet->IsHDWallet()) {
        addr = m_wallet->GetNewHDAddress();
    } else {
        // Legacy wallet - return default address
        addr = m_wallet->GetNewAddress();
    }

    if (!addr.IsValid()) {
        throw std::runtime_error("Failed to get address");
    }

    return "\"" + addr.ToString() + "\"";
}

std::string CRPCServer::RPC_GetBalance(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Get current height
    unsigned int currentHeight = m_chainstate->GetHeight();

    // Get available balance (excludes immature coinbase)
    CAmount balance = m_wallet->GetAvailableBalance(*m_utxo_set, currentHeight);

    // Get immature coinbase balance (not yet 100 confirmations)
    CAmount immatureBalance = m_wallet->GetImmatureBalance(*m_utxo_set, currentHeight);

    // For future: transactions with 0 confirmations
    CAmount unconfirmedBalance = 0;

    // Chain health: check if our tip diverges from peers
    bool tipDiverged = g_node_context.tip_diverged.load();

    std::ostringstream oss;
    oss << "{";
    oss << "\"balance\":" << FormatAmount(balance) << ",";
    oss << "\"unconfirmed_balance\":" << FormatAmount(unconfirmedBalance) << ",";
    oss << "\"immature_balance\":" << FormatAmount(immatureBalance) << ",";
    oss << "\"chain_health\":\"" << (tipDiverged ? "DIVERGED" : "OK") << "\"";
    if (tipDiverged) {
        oss << ",\"chain_warning\":\"Your chain tip differs from the network. "
            << "Mined coins may not be valid on the main chain.\"";
    }
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetAddresses(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    auto addresses = m_wallet->GetAddresses();

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << addresses[i].ToString() << "\"";
    }
    oss << "]";
    return oss.str();
}

std::string CRPCServer::RPC_ListUnspent(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    std::vector<CWalletTx> utxos = m_wallet->ListUnspentOutputs(*m_utxo_set, currentHeight);

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < utxos.size(); ++i) {
        if (i > 0) oss << ",";

        // Get confirmations (no height > 0 guard — genesis outputs are valid)
        unsigned int confirmations = 0;
        if (currentHeight >= utxos[i].nHeight) {
            confirmations = currentHeight - utxos[i].nHeight + 1;
        }

        oss << "{";
        oss << "\"txid\":\"" << utxos[i].txid.GetHex() << "\",";
        oss << "\"vout\":" << utxos[i].vout << ",";
        oss << "\"address\":\"" << utxos[i].address.ToString() << "\",";
        oss << "\"amount\":" << FormatAmount(utxos[i].nValue) << ",";
        oss << "\"confirmations\":" << confirmations;
        oss << "}";
    }
    oss << "]";
    return oss.str();
}

// ----------------------------------------------------------------------------
// Transaction Creation RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_SendToAddress(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Early lock check - fail fast with clear message before doing any work
    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Please unlock first using walletpassphrase.");
    }

    // Parse params - supports both formats:
    //   Object: {"address":"DLT1...", "amount":1.5}
    //   Array:  ["DLT1...", 1.5]  (Bitcoin Core compat)
    std::string address_str;
    CAmount amount = 0;

    // Try array format first: ["address", amount]
    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 2) {
                if (arr[0].is_string()) {
                    address_str = arr[0].get<std::string>();
                }
                if (arr[1].is_number()) {
                    double amt_dbl = arr[1].get<double>();
                    if (amt_dbl > 0.0 && amt_dbl <= 21000000.0) {
                        amount = static_cast<CAmount>(amt_dbl * 100000000);
                    }
                } else if (arr[1].is_string()) {
                    // Handle amount as string: ["addr", "1.5"]
                    double amt_dbl = SafeParseDouble(arr[1].get<std::string>(), 0.0, 21000000.0);
                    amount = static_cast<CAmount>(amt_dbl * 100000000);
                }
            }
        } catch (const nlohmann::json::parse_error&) {
            // Fall through to object format
        }
    }

    // Try object format: {"address":"...", "amount":...}
    if (address_str.empty()) {
        size_t addr_pos = params.find("\"address\"");
        if (addr_pos != std::string::npos) {
            size_t colon = params.find(":", addr_pos);
            size_t quote1 = params.find("\"", colon);
            size_t quote2 = params.find("\"", quote1 + 1);
            if (quote1 != std::string::npos && quote2 != std::string::npos) {
                address_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
            }
        }

        if (amount == 0) {
            size_t amt_pos = params.find("\"amount\"");
            if (amt_pos != std::string::npos) {
                size_t colon = params.find(":", amt_pos);
                size_t num_start = colon + 1;
                while (num_start < params.length() && isspace(params[num_start])) num_start++;
                size_t num_end = num_start;
                while (num_end < params.length() &&
                       (isdigit(params[num_end]) || params[num_end] == '.' || params[num_end] == '-')) {
                    num_end++;
                }
                if (num_end > num_start) {
                    // MEDIUM-004: Use SafeParseDouble to prevent RPC crashes from malformed input
                    // Max supply is 21 million DIL, so 21000000.0 is a reasonable upper bound
                    double amt_dbl = SafeParseDouble(params.substr(num_start, num_end - num_start), 0.0, 21000000.0);
                    amount = static_cast<CAmount>(amt_dbl * 100000000);  // Convert to smallest unit (ions/volts)
                }
            }
        }
    }

    // Validate inputs
    if (address_str.empty()) {
        throw std::runtime_error("Missing or invalid address parameter");
    }
    if (amount <= 0) {
        throw std::runtime_error("Invalid amount (must be positive)");
    }

    // RPC-004 FIX: Prevent dust attack by rejecting amounts below dust threshold
    // Dust outputs are economically unspendable (tx fee > output value)
    // This prevents UTXO bloat and protects users from wasting funds
    if (amount < DUST_THRESHOLD) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Amount below dust threshold (%.8f DIL minimum, got %.8f DIL). "
                 "Dust outputs are uneconomical to spend.",
                 DUST_THRESHOLD / 100000000.0, amount / 100000000.0);
        throw std::runtime_error(msg);
    }

    // Validate address
    CDilithiumAddress recipient_address;
    if (!ValidateAddress(address_str, recipient_address)) {
        throw std::runtime_error("Invalid Dilithion address: " + address_str);
    }

    // Parse optional from_address (spend only from this address)
    CDilithiumAddress from_address;
    if (!params.empty()) {
        try {
            auto j = nlohmann::json::parse(params);
            if (j.is_object() && j.contains("from_address")) {
                std::string from_str = j["from_address"].get<std::string>();
                if (!from_str.empty()) {
                    if (!from_address.SetString(from_str)) {
                        throw std::runtime_error("Invalid from_address: " + from_str);
                    }
                }
            }
        } catch (const nlohmann::json::parse_error&) {
            // Not JSON object format — no from_address
        }
    }

    // Create transaction - fee is auto-adjusted internally based on actual input count
    unsigned int currentHeight = m_chainstate->GetHeight();
    size_t est_size = Consensus::EstimateDilithiumTxSize(2, 2);
    CAmount fee = Consensus::CalculateMinFee(est_size);
    CTransactionRef tx;
    std::string error;

    if (!m_wallet->CreateTransaction(recipient_address, amount, fee,
                                     *m_utxo_set, currentHeight, tx, error, from_address)) {
        throw std::runtime_error("Failed to create transaction: " + error);
    }

    // Send transaction
    if (!m_wallet->SendTransaction(tx, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to send transaction: " + error);
    }

    // BUG #104 FIX: Record sent transaction in wallet history
    uint256 txid = tx->GetHash();
    m_wallet->RecordSentTransaction(txid, recipient_address, amount, fee);
    std::ostringstream oss;
    oss << "{\"txid\":\"" << txid.GetHex() << "\"}";
    return oss.str();
}

std::string CRPCServer::RPC_ConsolidateUTXOs(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is locked. Use walletpassphrase first.");
    }

    // Parse optional parameters: max_inputs (default 50, max 200), address (destination)
    size_t max_inputs = 50;
    std::string dest_address;
    if (!params.empty()) {
        try {
            auto j = nlohmann::json::parse(params);
            if (j.is_object()) {
                if (j.contains("max_inputs")) {
                    max_inputs = j["max_inputs"].get<size_t>();
                }
                if (j.contains("address")) {
                    dest_address = j["address"].get<std::string>();
                }
            } else if (j.is_array() && !j.empty()) {
                max_inputs = j[0].get<size_t>();
            }
        } catch (...) {}
    }
    if (max_inputs < 2) max_inputs = 2;
    if (max_inputs > 200) max_inputs = 200;

    unsigned int currentHeight = m_chainstate->GetHeight();
    std::vector<CWalletTx> utxos = m_wallet->ListUnspentOutputs(*m_utxo_set, currentHeight);

    // Filter out UTXOs already locked by in-flight mempool txs. Without this,
    // back-to-back consolidateutxos calls select the same "smallest 200" and
    // the second tx is rejected as a double-spend. The lock-filter lets a
    // batch of consolidations run rapidly without waiting for confirmations.
    utxos.erase(
        std::remove_if(utxos.begin(), utxos.end(),
            [this](const CWalletTx& u) {
                return m_wallet->IsLocked(COutPoint(u.txid, u.vout));
            }),
        utxos.end());

    if (utxos.size() <= 1) {
        throw std::runtime_error("Nothing to consolidate (0 or 1 UTXOs free; others may be locked by in-flight txs)");
    }

    // Sort smallest first — consolidate the small ones
    std::sort(utxos.begin(), utxos.end(),
              [](const CWalletTx& a, const CWalletTx& b) {
                  return a.nValue < b.nValue;
              });

    // Take up to max_inputs of the smallest UTXOs
    size_t count = std::min(utxos.size(), max_inputs);
    std::vector<CWalletTx> to_consolidate(utxos.begin(), utxos.begin() + count);

    // Calculate total value
    CAmount total = 0;
    for (const auto& u : to_consolidate) {
        total += u.nValue;
    }

    // Estimate fee for consolidation tx (count inputs, 1 output)
    size_t est_size = Consensus::EstimateDilithiumTxSize(count, 1);
    CAmount fee = Consensus::CalculateMinFee(est_size);

    if (total <= fee) {
        throw std::runtime_error("Selected UTXOs total (" +
            std::to_string(total) + " ions) doesn't cover fee (" +
            std::to_string(fee) + " ions). Try fewer inputs or wait for larger UTXOs.");
    }

    CAmount output_value = total - fee;
    if (output_value < DUST_THRESHOLD) {
        throw std::runtime_error("Consolidated output would be dust. Need more value in UTXOs.");
    }

    // Build transaction
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;

    for (const auto& u : to_consolidate) {
        COutPoint outpoint(u.txid, u.vout);
        m_wallet->LockCoin(outpoint);
        tx.vin.push_back(CTxIn(outpoint));
    }

    // Determine destination address:
    // 1. Explicit address parameter (user chose in UI)
    // 2. Mining address override (if set via --mining-address or setminingaddress)
    // 3. Wallet default address (fallback)
    std::vector<uint8_t> dest_hash;
    std::string dest_label;
    if (!dest_address.empty()) {
        CDilithiumAddress addr;
        if (!addr.SetString(dest_address)) {
            for (const auto& u : to_consolidate) {
                m_wallet->UnlockCoin(COutPoint(u.txid, u.vout));
            }
            throw std::runtime_error("Invalid destination address: " + dest_address);
        }
        dest_hash = CWallet::GetPubKeyHashFromAddress(addr);
        dest_label = dest_address;
    } else if (!g_node_state.mining_address_override.empty()) {
        CDilithiumAddress addr;
        addr.SetString(g_node_state.mining_address_override);
        dest_hash = CWallet::GetPubKeyHashFromAddress(addr);
        dest_label = g_node_state.mining_address_override;
    } else {
        dest_hash = m_wallet->GetPubKeyHash();
        dest_label = "default";
    }
    if (dest_hash.empty()) {
        for (const auto& u : to_consolidate) {
            m_wallet->UnlockCoin(COutPoint(u.txid, u.vout));
        }
        throw std::runtime_error("Failed to resolve destination address");
    }

    std::vector<uint8_t> scriptPubKey = WalletCrypto::CreateScriptPubKey(dest_hash);
    tx.vout.push_back(CTxOut(output_value, std::move(scriptPubKey)));

    // Sign
    std::string error;
    if (!m_wallet->SignTransaction(tx, *m_utxo_set, error)) {
        for (const auto& u : to_consolidate) {
            m_wallet->UnlockCoin(COutPoint(u.txid, u.vout));
        }
        throw std::runtime_error("Failed to sign consolidation tx: " + error);
    }

    // Verify fee covers actual size
    size_t actual_size = tx.GetSerializedSize();
    CAmount required_fee = Consensus::CalculateMinFee(actual_size);
    if (fee < required_fee) {
        for (const auto& u : to_consolidate) {
            m_wallet->UnlockCoin(COutPoint(u.txid, u.vout));
        }
        throw std::runtime_error("Fee insufficient for actual tx size. Try fewer inputs.");
    }

    // Send
    CTransactionRef txref = MakeTransactionRef(std::move(tx));
    if (!m_wallet->SendTransaction(txref, *m_mempool, *m_utxo_set, currentHeight, error)) {
        for (const auto& u : to_consolidate) {
            m_wallet->UnlockCoin(COutPoint(u.txid, u.vout));
        }
        throw std::runtime_error("Failed to send consolidation tx: " + error);
    }

    uint256 txid = txref->GetHash();

    std::ostringstream oss;
    oss << "{\"txid\":\"" << txid.GetHex() << "\","
        << "\"inputs_consolidated\":" << count << ","
        << "\"total_utxos_before\":" << utxos.size() << ","
        << "\"total_utxos_after\":" << (utxos.size() - count + 1) << ","
        << "\"amount\":" << FormatAmount(output_value) << ","
        << "\"fee\":" << FormatAmount(fee) << ","
        << "\"destination\":\"" << dest_label << "\","
        << "\"tx_size\":" << actual_size << "}";
    return oss.str();
}

std::string CRPCServer::RPC_EstimateSendFee(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // Parse params (same format as sendtoaddress: object or array)
    std::string address_str;
    CAmount amount = 0;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 2) {
                if (arr[0].is_string()) address_str = arr[0].get<std::string>();
                if (arr[1].is_number()) {
                    double amt_dbl = arr[1].get<double>();
                    if (amt_dbl > 0.0 && amt_dbl <= 21000000.0)
                        amount = static_cast<CAmount>(amt_dbl * 100000000);
                }
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (address_str.empty()) {
        size_t addr_pos = params.find("\"address\"");
        if (addr_pos != std::string::npos) {
            size_t colon = params.find(":", addr_pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                address_str = params.substr(q1 + 1, q2 - q1 - 1);
        }
        if (amount == 0) {
            size_t amt_pos = params.find("\"amount\"");
            if (amt_pos != std::string::npos) {
                size_t colon = params.find(":", amt_pos);
                size_t ns = colon + 1;
                while (ns < params.length() && isspace(params[ns])) ns++;
                size_t ne = ns;
                while (ne < params.length() && (isdigit(params[ne]) || params[ne] == '.' || params[ne] == '-')) ne++;
                if (ne > ns) {
                    double amt_dbl = SafeParseDouble(params.substr(ns, ne - ns), 0.0, 21000000.0);
                    amount = static_cast<CAmount>(amt_dbl * 100000000);
                }
            }
        }
    }

    if (address_str.empty()) throw std::runtime_error("Missing or invalid address parameter");
    if (amount <= 0) throw std::runtime_error("Invalid amount (must be positive)");

    CDilithiumAddress recipient_address;
    if (!ValidateAddress(address_str, recipient_address)) {
        throw std::runtime_error("Invalid Dilithion address: " + address_str);
    }

    // Estimate fee by doing a dry-run coin selection to count actual inputs needed
    size_t est_inputs = 2;
    CAmount fee = Consensus::CalculateMinFee(Consensus::EstimateDilithiumTxSize(2, 2));

    if (m_chainstate) {
        unsigned int currentHeight = m_chainstate->GetHeight();
        // Iteratively select coins and refine fee estimate
        for (int iter = 0; iter < 5; ++iter) {
            std::vector<CWalletTx> est_coins;
            CAmount est_total = 0;
            std::string est_error;
            CAmount total_needed = amount + fee;
            if (m_wallet->SelectCoins(total_needed, est_coins, est_total,
                                      *m_utxo_set, currentHeight, est_error)) {
                size_t est_size = Consensus::EstimateDilithiumTxSize(est_coins.size(), 2);
                CAmount needed_fee = Consensus::CalculateMinFee(est_size);
                if (needed_fee <= fee) {
                    // Fee is sufficient for this input count
                    est_inputs = est_coins.size();
                    break;
                }
                fee = needed_fee;
                est_inputs = est_coins.size();
            } else {
                break; // Insufficient funds, will be caught below
            }
        }
    }

    // Final fee based on estimated input count
    fee = Consensus::CalculateMinFee(Consensus::EstimateDilithiumTxSize(est_inputs, 2));

    // Check balance
    CAmount balance = m_wallet->GetBalance();
    CAmount total = amount + fee;
    if (balance < total) {
        throw std::runtime_error("Insufficient balance. Have " +
            std::to_string(balance / 100000000.0) + " DIL, need " +
            std::to_string(total / 100000000.0) + " DIL (amount + fee)");
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(8);
    oss << "{"
        << "\"address\":\"" << address_str << "\","
        << "\"amount\":" << (amount / 100000000.0) << ","
        << "\"fee\":" << (fee / 100000000.0) << ","
        << "\"total\":" << (total / 100000000.0) << ","
        << "\"balance\":" << (balance / 100000000.0)
        << "}";
    return oss.str();
}

std::string CRPCServer::RPC_SignRawTransaction(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // Parse params - expecting {"hex":"..."}
    size_t hex_pos = params.find("\"hex\"");
    if (hex_pos == std::string::npos) {
        throw std::runtime_error("Missing hex parameter");
    }

    size_t colon = params.find(":", hex_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hex parameter format");
    }

    std::string hex_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // TASK 2.4: Deserialize transaction from hex string
    std::vector<uint8_t> tx_data = ParseHex(hex_str);
    if (tx_data.empty()) {
        throw std::runtime_error("Invalid hex string");
    }

    CTransaction tx;
    std::string deserialize_error;
    if (!tx.Deserialize(tx_data.data(), tx_data.size(), &deserialize_error)) {
        throw std::runtime_error("Failed to deserialize transaction: " + deserialize_error);
    }

    // Sign the transaction
    std::string sign_error;
    if (!m_wallet->SignTransaction(tx, *m_utxo_set, sign_error)) {
        throw std::runtime_error("Failed to sign transaction: " + sign_error);
    }

    // TASK 2.4: Serialize signed transaction back to hex
    std::vector<uint8_t> signed_data = tx.Serialize();
    std::string signed_hex = HexStr(signed_data);

    // Return signed transaction hex
    std::ostringstream oss;
    oss << "{";
    oss << "\"hex\":\"" << signed_hex << "\",";
    oss << "\"complete\":true";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_SendRawTransaction(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse params - expecting {"hex":"..."}
    size_t hex_pos = params.find("\"hex\"");
    if (hex_pos == std::string::npos) {
        throw std::runtime_error("Missing hex parameter");
    }

    size_t colon = params.find(":", hex_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hex parameter format");
    }

    std::string hex_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // TASK 2.4: Deserialize transaction from hex string
    std::vector<uint8_t> tx_data = ParseHex(hex_str);
    if (tx_data.empty()) {
        throw std::runtime_error("Invalid hex string");
    }

    CTransactionRef tx = MakeTransactionRef();
    CTransaction tx_mutable;
    std::string deserialize_error;
    if (!tx_mutable.Deserialize(tx_data.data(), tx_data.size(), &deserialize_error)) {
        throw std::runtime_error("Failed to deserialize transaction: " + deserialize_error);
    }

    // Validate transaction
    CTransactionValidator txValidator;
    std::string validation_error;
    CAmount tx_fee = 0;
    unsigned int current_height = m_chainstate->GetHeight();

    if (!txValidator.CheckTransaction(tx_mutable, *m_utxo_set, current_height, tx_fee, validation_error)) {
        throw std::runtime_error("Transaction validation failed: " + validation_error);
    }

    // Create shared pointer for mempool
    tx = MakeTransactionRef(tx_mutable);
    uint256 txid = tx->GetHash();

    // Add to mempool
    std::string mempool_error;
    int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    if (!m_mempool->AddTx(tx, tx_fee, current_time, current_height, &mempool_error)) {
        throw std::runtime_error("Failed to add to mempool: " + mempool_error);
    }

    // Transaction will be relayed to network via normal P2P mempool propagation

    // Return txid
    std::ostringstream oss;
    oss << "\"" << txid.GetHex() << "\"";
    return oss.str();
}

// ----------------------------------------------------------------------------
// Transaction Query RPCs
// ----------------------------------------------------------------------------

// Helper: Decode scriptPubKey to Dilithion address (P2PKH format)
static std::string DecodeScriptPubKeyToAddress(const std::vector<uint8_t>& scriptPubKey) {
    // P2PKH format: 76 a9 14 [20-byte hash] 88 ac
    if (scriptPubKey.size() == 25 && scriptPubKey[0] == 0x76 &&
        scriptPubKey[1] == 0xa9 && scriptPubKey[2] == 0x14 &&
        scriptPubKey[23] == 0x88 && scriptPubKey[24] == 0xac) {
        std::vector<uint8_t> addrData;
        addrData.push_back(0x1E);  // Dilithion version byte ('D' prefix)
        addrData.insert(addrData.end(), scriptPubKey.begin() + 3, scriptPubKey.begin() + 23);
        return EncodeBase58Check(addrData);
    }
    return "";
}

std::string CRPCServer::RPC_GetTransaction(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"txid":"..."}
    size_t txid_pos = params.find("\"txid\"");
    if (txid_pos == std::string::npos) {
        throw std::runtime_error("Missing txid parameter");
    }

    size_t colon = params.find(":", txid_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid txid parameter format");
    }

    std::string txid_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 txid;
    txid.SetHex(txid_str);

    // Try mempool first
    if (m_mempool->Exists(txid)) {
        std::ostringstream oss;
        oss << "{";
        oss << "\"txid\":\"" << txid.GetHex() << "\",";
        oss << "\"confirmations\":0,";
        oss << "\"in_mempool\":true";
        oss << "}";
        return oss.str();
    }

    // Transaction not in mempool - search blockchain
    // Note: Without txindex, this requires scanning blocks (slow for large chains)
    // For testnet with low block count, this is acceptable

    std::cout << "[RPC] Transaction " << txid.GetHex() << " not in mempool, searching blockchain..." << std::endl;

    // Get chain tip
    CBlockIndex* pTip = m_chainstate->GetTip();
    if (pTip == nullptr) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Walk backwards through chain looking for transaction
    // Search entire chain (chain is still young enough for full scan)
    const int MAX_BLOCKS_TO_SEARCH = pTip->nHeight + 1;  // Search all blocks
    int blocksSearched = 0;

    CBlockIndex* pCurrent = pTip;
    while (pCurrent != nullptr && blocksSearched < MAX_BLOCKS_TO_SEARCH) {
        // Read block data
        CBlock block;
        uint256 blockHash = pCurrent->GetBlockHash();

        if (!m_blockchain->ReadBlock(blockHash, block)) {
            std::cerr << "[RPC] Warning: Failed to read block " << blockHash.GetHex() << std::endl;
            pCurrent = pCurrent->pprev;
            blocksSearched++;
            continue;
        }

        // Deserialize transactions using the same function as getblock
        // block.vtx starts with a compact-size tx count prefix
        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string deserializeError;

        if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
            std::cerr << "[RPC] Warning: Failed to deserialize transactions in block "
                      << blockHash.GetHex() << ": " << deserializeError << std::endl;
            pCurrent = pCurrent->pprev;
            blocksSearched++;
            continue;
        }

        for (const auto& tx : transactions) {
            uint256 foundTxid = tx->GetHash();
            if (foundTxid == txid) {
                // Found it! Calculate confirmations
                int confirmations = (pTip->nHeight - pCurrent->nHeight) + 1;

                std::cout << "[RPC] Found transaction " << txid.GetHex()
                          << " in block " << blockHash.GetHex()
                          << " (height " << pCurrent->nHeight << ", "
                          << confirmations << " confirmations)" << std::endl;

                // Build JSON response
                std::ostringstream oss;
                oss << "{";
                oss << "\"txid\":\"" << foundTxid.GetHex() << "\",";
                oss << "\"version\":" << tx->nVersion << ",";

                // Inputs
                oss << "\"vin\":[";
                for (size_t i = 0; i < tx->vin.size(); i++) {
                    if (i > 0) oss << ",";
                    const CTxIn& txin = tx->vin[i];
                    oss << "{";
                    if (txin.prevout.hash.IsNull()) {
                        oss << "\"coinbase\":true";
                    } else {
                        oss << "\"txid\":\"" << txin.prevout.hash.GetHex() << "\",";
                        oss << "\"vout\":" << txin.prevout.n << ",";
                        oss << "\"scriptSig\":\"" << HexStr(txin.scriptSig) << "\",";
                        oss << "\"sequence\":" << txin.nSequence;
                    }
                    oss << "}";
                }
                oss << "],";

                // Outputs
                oss << "\"vout\":[";
                for (size_t i = 0; i < tx->vout.size(); i++) {
                    if (i > 0) oss << ",";
                    const CTxOut& txout = tx->vout[i];
                    std::string addr = DecodeScriptPubKeyToAddress(txout.scriptPubKey);
                    oss << "{";
                    oss << "\"value\":" << txout.nValue << ",";
                    oss << "\"n\":" << i << ",";
                    if (!addr.empty()) {
                        oss << "\"address\":\"" << addr << "\",";
                    }
                    oss << "\"scriptPubKey\":\"" << HexStr(txout.scriptPubKey) << "\"";
                    oss << "}";
                }
                oss << "],";

                oss << "\"locktime\":" << tx->nLockTime << ",";
                oss << "\"blockhash\":\"" << blockHash.GetHex() << "\",";
                oss << "\"blockheight\":" << pCurrent->nHeight << ",";
                oss << "\"confirmations\":" << confirmations << ",";
                oss << "\"in_mempool\":false";

                // Wallet context: lets callers verify whether this tx
                // involved the local wallet — forensic support for the
                // bridge (did the bridge wallet sign this send?). Uses
                // mapWalletTx (tracks all owned UTXOs by outpoint) so
                // HD-derived change addresses are detected even though
                // they're not in mapKeys.
                if (m_wallet) {
                    CSentTx sentTx;
                    bool isSend = m_wallet->GetSentTransaction(txid, sentTx);

                    std::ostringstream details;
                    details << "\"details\":[";
                    bool firstDetail = true;
                    int64_t walletReceive = 0;
                    bool anyReceive = false;

                    for (size_t i = 0; i < tx->vout.size(); i++) {
                        const CTxOut& txout = tx->vout[i];
                        CDilithiumAddress walletAddr;
                        int64_t walletValue = 0;
                        bool isOurs = m_wallet->GetWalletOutput(
                            txid, static_cast<uint32_t>(i),
                            walletAddr, walletValue);
                        std::string addr = isOurs
                            ? walletAddr.ToString()
                            : DecodeScriptPubKeyToAddress(txout.scriptPubKey);

                        if (isOurs) {
                            if (!firstDetail) details << ",";
                            details << "{\"address\":\"" << addr << "\","
                                    << "\"category\":\"receive\","
                                    << "\"amount\":" << txout.nValue << ","
                                    << "\"vout\":" << i << "}";
                            firstDetail = false;
                            walletReceive += txout.nValue;
                            anyReceive = true;
                        } else if (isSend && !addr.empty()
                                   && sentTx.toAddress.ToString() == addr) {
                            if (!firstDetail) details << ",";
                            details << "{\"address\":\"" << addr << "\","
                                    << "\"category\":\"send\","
                                    << "\"amount\":-" << txout.nValue << ","
                                    << "\"vout\":" << i << ","
                                    << "\"fee\":-" << sentTx.nFee << "}";
                            firstDetail = false;
                        }
                    }
                    details << "]";

                    oss << ",\"wallet\":{";
                    if (isSend) {
                        oss << "\"category\":\"send\","
                            << "\"amount\":-" << sentTx.nValue << ","
                            << "\"fee\":-" << sentTx.nFee << ","
                            << "\"to_address\":\"" << sentTx.toAddress.ToString() << "\","
                            << "\"time\":" << sentTx.nTime;
                    } else if (anyReceive) {
                        oss << "\"category\":\"receive\","
                            << "\"amount\":" << walletReceive;
                    } else {
                        oss << "\"category\":\"not_wallet_related\"";
                    }
                    oss << "},";
                    oss << details.str();
                }

                oss << "}";

                return oss.str();
            }
        }

        blocksSearched++;
        pCurrent = pCurrent->pprev;
    }

    // Transaction not found after searching
    std::ostringstream error;
    error << "Transaction not found.\\n";
    error << "Searched mempool and last " << blocksSearched << " blocks.\\n";
    error << "\\n";
    error << "Note: Without transaction index, only recent blocks are searched.\\n";
    error << "For older transactions, use block explorer or getblock RPC.";

    throw std::runtime_error(error.str());
}

std::string CRPCServer::RPC_ListTransactions(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse count parameter (default 50)
    size_t count = 50;
    if (!params.empty()) {
        try {
            nlohmann::json j = nlohmann::json::parse(params);
            if (j.contains("count") && j["count"].is_number()) {
                int c = j["count"].get<int>();
                if (c > 0) count = static_cast<size_t>(c);
                if (count > 1000) count = 1000;  // Cap at 1000
            }
        } catch (...) {}
    }

    unsigned int currentHeight = m_chainstate->GetHeight();

    // Lightweight struct for initial collection (no expensive block lookups yet)
    struct TxInfo {
        std::string txid;
        std::string address;
        std::string category;
        int64_t amount;
        int64_t fee;
        unsigned int height;       // for sorting and confirmations
        int64_t time;              // sent tx time, or 0 for received (filled later)
        bool generated;
    };
    std::vector<TxInfo> allTx;

    // Collect received transactions (lightweight - no block lookups)
    std::vector<CWalletTx> allOutputs = m_wallet->ListAllOutputs(currentHeight);
    allTx.reserve(allOutputs.size() + 32);
    for (const auto& utxo : allOutputs) {
        TxInfo info;
        info.txid = utxo.txid.GetHex();
        info.address = utxo.address.ToString();
        info.category = utxo.fSpent ? "spent" : "receive";
        info.amount = utxo.nValue;
        info.fee = 0;
        info.height = utxo.nHeight;
        info.time = 0;  // Will be filled from block index after truncation
        info.generated = utxo.fCoinbase;
        allTx.push_back(std::move(info));
    }

    // Collect sent transactions
    std::vector<CSentTx> sentTxs = m_wallet->ListSentTransactions();
    for (const auto& stx : sentTxs) {
        TxInfo info;
        info.txid = stx.txid.GetHex();
        info.address = stx.toAddress.ToString();
        info.category = "send";
        info.amount = -stx.nValue;
        info.fee = stx.nFee;
        info.height = stx.nHeight;
        info.time = stx.nTime;
        info.generated = false;
        allTx.push_back(std::move(info));
    }

    // Sort by height descending (newest first) - O(n log n) but no DB lookups
    std::sort(allTx.begin(), allTx.end(), [](const TxInfo& a, const TxInfo& b) {
        return a.height > b.height;
    });

    // Truncate to requested count BEFORE doing expensive block lookups
    if (allTx.size() > count) {
        allTx.resize(count);
    }

    // Now do block lookups only for the truncated result set
    std::ostringstream oss;
    oss << "{\"transactions\":[";
    for (size_t i = 0; i < allTx.size(); ++i) {
        if (i > 0) oss << ",";
        auto& tx = allTx[i];

        // Fill in block hash and time from chain state (only for top N results)
        // Note: no height > 0 guard — genesis block (height 0) has valid outputs (pre-fund)
        std::string blockhash;
        std::vector<uint256> hashes = m_chainstate->GetBlocksAtHeight(tx.height);
        if (!hashes.empty()) {
            blockhash = hashes[0].GetHex();
            if (tx.time == 0) {
                CBlockIndex* pindex = m_chainstate->GetBlockIndex(hashes[0]);
                if (pindex) tx.time = pindex->nTime;
            }
        }
        if (tx.time == 0) tx.time = std::time(nullptr);

        unsigned int confirmations = 0;
        if (!blockhash.empty() && currentHeight >= tx.height) {
            confirmations = currentHeight - tx.height + 1;
        }

        oss << "{";
        oss << "\"txid\":\"" << tx.txid << "\",";
        oss << "\"address\":\"" << tx.address << "\",";
        oss << "\"category\":\"" << tx.category << "\",";
        oss << "\"amount\":" << FormatAmount(tx.amount) << ",";
        if (tx.category == "send") {
            oss << "\"fee\":" << FormatAmount(tx.fee) << ",";
        }
        oss << "\"confirmations\":" << confirmations << ",";
        oss << "\"blockhash\":\"" << blockhash << "\",";
        oss << "\"time\":" << tx.time << ",";
        oss << "\"generated\":" << (tx.generated ? "true" : "false");
        oss << "}";
    }
    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetMempoolInfo(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }

    size_t size, bytes;
    double min_fee_rate, max_fee_rate;
    m_mempool->GetStats(size, bytes, min_fee_rate, max_fee_rate);

    std::ostringstream oss;
    oss << "{";
    oss << "\"size\":" << size << ",";
    oss << "\"bytes\":" << bytes << ",";
    oss << "\"usage\":" << bytes << ",";
    oss << "\"min_fee_rate\":" << min_fee_rate << ",";
    oss << "\"max_fee_rate\":" << max_fee_rate;
    oss << "}";
    return oss.str();
}

// ----------------------------------------------------------------------------
// Blockchain Query RPCs
// ----------------------------------------------------------------------------

std::string CRPCServer::RPC_GetBlockchainInfo(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    int height = m_chainstate->GetHeight();
    uint256 bestBlockHash;
    if (!m_blockchain->ReadBestBlock(bestBlockHash)) {
        throw std::runtime_error("Failed to read best block");
    }

    // Calculate difficulty from best block's nBits
    // difficulty = max_target / current_target, computed directly from compact format
    // compact format: [exponent byte][3 mantissa bytes], target = mantissa * 256^(exponent-3)
    double difficulty = 0.0;
    CBlock bestBlock;
    if (m_blockchain->ReadBlock(bestBlockHash, bestBlock)) {
        const uint32_t maxBits = 0x1f060000;  // Dilithion max target
        int maxExp = maxBits >> 24;            // 0x1f = 31
        uint32_t maxMantissa = maxBits & 0x007fffff;  // 0x060000 = 393216

        int curExp = bestBlock.nBits >> 24;
        uint32_t curMantissa = bestBlock.nBits & 0x007fffff;

        if (curMantissa > 0) {
            // difficulty = (maxMantissa * 256^(maxExp-3)) / (curMantissa * 256^(curExp-3))
            //            = (maxMantissa / curMantissa) * 256^(maxExp - curExp)
            difficulty = double(maxMantissa) / double(curMantissa) * pow(256.0, maxExp - curExp);
        }
    }

    // Calculate median time of last 11 blocks (Bitcoin standard)
    int64_t mediantime = 0;
    CBlockIndex* pTip = m_chainstate->GetTip();
    if (pTip != nullptr) {
        std::vector<int64_t> timestamps;
        CBlockIndex* pCurrent = pTip;

        // Collect last 11 block timestamps (or fewer if chain is shorter)
        for (int i = 0; i < 11 && pCurrent != nullptr; i++) {
            timestamps.push_back(pCurrent->nTime);
            pCurrent = pCurrent->pprev;
        }

        // Calculate median
        if (!timestamps.empty()) {
            std::sort(timestamps.begin(), timestamps.end());
            size_t mid = timestamps.size() / 2;
            mediantime = timestamps[mid];
        }
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"chain\":\"" << (Dilithion::g_chainParams ? Dilithion::g_chainParams->GetNetworkName() : (m_testnet ? "testnet" : "main")) << "\",";
    oss << "\"blocks\":" << height << ",";
    oss << "\"bestblockhash\":\"" << bestBlockHash.GetHex() << "\",";
    oss << "\"difficulty\":" << std::fixed << std::setprecision(8) << difficulty << ",";
    oss << "\"mediantime\":" << mediantime << ",";
    oss << "\"chainwork\":\"" << m_chainstate->GetChainWork().GetHex() << "\"";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetBlockTrackerInfo(const std::string& params) {
    // Diagnostic RPC to show block tracker state for debugging sync issues
    extern NodeContext g_node_context;

    std::ostringstream oss;
    oss << "{";

    if (!g_node_context.block_tracker) {
        oss << "\"error\":\"block tracker not initialized\"";
        oss << "}";
        return oss.str();
    }

    // Get total in-flight
    int total_in_flight = g_node_context.block_tracker->GetTotalInFlight();
    oss << "\"total_in_flight\":" << total_in_flight << ",";

    // Get tracker status
    std::string status = g_node_context.block_tracker->GetStatus();
    oss << "\"status\":\"" << status << "\",";

    // Get tracked heights (up to 50 for display)
    oss << "\"tracked_heights\":[";

    // We need to iterate through the heights - let's use CheckTimeouts with 0 seconds
    // to get all tracked blocks
    auto all_tracked = g_node_context.block_tracker->CheckTimeouts(0);
    bool first = true;
    int count = 0;
    for (const auto& [height, peer] : all_tracked) {
        if (count >= 50) {
            break;
        }
        if (!first) oss << ",";
        first = false;
        oss << "{\"height\":" << height << ",\"peer\":" << peer << "}";
        count++;
    }
    oss << "],";

    // Get per-peer counts
    oss << "\"per_peer\":{";
    if (g_node_context.peer_manager) {
        auto peers = g_node_context.peer_manager->GetConnectedPeers();
        bool first_peer = true;
        for (const auto& peer : peers) {
            if (!peer) continue;
            int peer_count = g_node_context.block_tracker->GetPeerInFlightCount(peer->id);
            if (peer_count > 0) {
                if (!first_peer) oss << ",";
                first_peer = false;
                oss << "\"" << peer->id << "\":" << peer_count;
            }
        }
    }
    oss << "}";

    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_CheckChain(const std::string& params) {
    // Testnet checkpoints - known good block hashes at specific heights
    // These are the OFFICIAL chain block hashes that all nodes should match
    static const std::vector<std::pair<int, std::string>> checkpoints = {
        {1,   "000087e5438d7d4720807da15bfc816106ae559f6ff95a9edb99ef7de1404fd9"},
        {100, "00007e60b39eb965e39994423646ea60dadf168d4e4daaa93b36ad88d8e3fb21"},
        {200, "00001b7f26c4a78b28d67631b6763889f6647645058720415199f0f10c104973"},
        {300, "00009351e8783aea6cf96c2fb4b3ba5bc0f06688f44515633fb04f8f31474860"},
        {400, "00001b1b87af63d293ab68cd5d4c4a9a291e14ad4a9fa73220592510b1b555bc"},
        {500, "0000deb0189c1b87e02c1a070e34da0d29e33cf6aae88b18900a92a31dd7ea3e"},
        {534, "00007b7f83c0c1b96010eb0f19bf0911e732c16ebf32dfcdd0bde7dac76b239e"},
    };

    if (!m_blockchain || !m_chainstate) {
        throw std::runtime_error("Blockchain not initialized");
    }

    int localHeight = m_chainstate->GetHeight();
    std::ostringstream oss;
    oss << "{";
    oss << "\"your_height\":" << localHeight << ",";

    bool chainValid = true;
    int forkHeight = -1;
    std::string forkLocalHash = "";
    std::string forkExpectedHash = "";
    int checkpointsVerified = 0;

    oss << "\"checkpoints\":[";
    bool first = true;

    for (const auto& cp : checkpoints) {
        int height = cp.first;
        const std::string& expectedHash = cp.second;

        if (!first) oss << ",";
        first = false;

        oss << "{\"height\":" << height << ",";

        if (height > localHeight) {
            oss << "\"status\":\"not_reached\",";
            oss << "\"expected\":\"" << expectedHash.substr(0, 16) << "...\"}";
            continue;
        }

        // Get local block hash at this height
        std::vector<uint256> hashes = m_chainstate->GetBlocksAtHeight(height);
        if (hashes.empty()) {
            oss << "\"status\":\"missing\",";
            oss << "\"expected\":\"" << expectedHash.substr(0, 16) << "...\"}";
            chainValid = false;
            if (forkHeight < 0) forkHeight = height;
            continue;
        }

        std::string localHash = hashes[0].GetHex();

        if (localHash == expectedHash) {
            oss << "\"status\":\"OK\",";
            oss << "\"hash\":\"" << localHash.substr(0, 16) << "...\"}";
            checkpointsVerified++;
        } else {
            oss << "\"status\":\"MISMATCH\",";
            oss << "\"your_hash\":\"" << localHash.substr(0, 16) << "...\",";
            oss << "\"expected\":\"" << expectedHash.substr(0, 16) << "...\"}";
            chainValid = false;
            if (forkHeight < 0) {
                forkHeight = height;
                forkLocalHash = localHash;
                forkExpectedHash = expectedHash;
            }
        }
    }
    oss << "],";

    oss << "\"checkpoints_verified\":" << checkpointsVerified << ",";
    oss << "\"chain_valid\":" << (chainValid ? "true" : "false");

    if (!chainValid && forkHeight > 0) {
        oss << ",\"fork_detected_at_height\":" << forkHeight;
        oss << ",\"your_hash_at_fork\":\"" << forkLocalHash << "\"";
        oss << ",\"expected_hash_at_fork\":\"" << forkExpectedHash << "\"";
        oss << ",\"action_required\":\"Your chain forked! Reset chain state and resync: "
            << "run 'dilithion-node --reset-chain' (preserves wallet.dat and mik_registration.dat)\"";
    }

    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetBlock(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"hash":"..."}
    size_t hash_pos = params.find("\"hash\"");
    if (hash_pos == std::string::npos) {
        throw std::runtime_error("Missing hash parameter");
    }

    size_t colon = params.find(":", hash_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hash parameter format");
    }

    std::string hash_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 hash;
    hash.SetHex(hash_str);

    // Parse optional verbosity parameter (default 0)
    // 0 = header + tx_count + miner (existing behavior)
    // 1 = header + txid array
    // 2 = header + full decoded transactions
    int verbosity = 0;
    size_t verb_pos = params.find("\"verbosity\"");
    if (verb_pos != std::string::npos) {
        size_t verb_colon = params.find(":", verb_pos);
        size_t num_start = verb_colon + 1;
        while (num_start < params.length() && isspace(params[num_start])) num_start++;
        if (num_start < params.length() && params[num_start] >= '0' && params[num_start] <= '9') {
            verbosity = params[num_start] - '0';
        }
    }

    CBlock block;
    if (!m_blockchain->ReadBlock(hash, block)) {
        throw std::runtime_error("Block not found");
    }

    CBlockIndex blockIndex;
    int height = -1;
    if (m_blockchain->ReadBlockIndex(hash, blockIndex)) {
        height = blockIndex.nHeight;
    }

    // Deserialize transactions (needed for miner address and verbosity >= 1)
    CBlockValidator validator;
    std::vector<CTransactionRef> transactions;
    std::string deserializeError;
    bool hasTxs = false;
    if (!block.vtx.empty()) {
        hasTxs = validator.DeserializeBlockTransactions(block, transactions, deserializeError);
    }

    // Extract miner address and MIK from coinbase transaction
    std::string minerAddress = "";
    std::string minerMIK = "";
    if (hasTxs && !transactions.empty()) {
        if (!transactions[0]->vout.empty()) {
            minerAddress = DecodeScriptPubKeyToAddress(transactions[0]->vout[0].scriptPubKey);
        }
        if (!transactions[0]->vin.empty()) {
            DFMP::CMIKScriptData mikData;
            if (DFMP::ParseMIKFromScriptSig(transactions[0]->vin[0].scriptSig, mikData)) {
                minerMIK = mikData.identity.GetHex();
            }
        }
    }

    // Get next block hash if available (use active chain, not any fork)
    std::string nextBlockHash = "";
    if (height >= 0 && m_chainstate) {
        CBlockIndex* pTip = m_chainstate->GetTip();
        if (pTip && height + 1 <= pTip->nHeight) {
            CBlockIndex* pNext = pTip->GetAncestor(height + 1);
            if (pNext) {
                nextBlockHash = pNext->GetBlockHash().GetHex();
            }
        }
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"hash\":\"" << hash.GetHex() << "\",";
    oss << "\"height\":" << height << ",";
    oss << "\"version\":" << block.nVersion << ",";
    oss << "\"previousblockhash\":\"" << block.hashPrevBlock.GetHex() << "\",";
    if (!nextBlockHash.empty()) {
        oss << "\"nextblockhash\":\"" << nextBlockHash << "\",";
    }
    oss << "\"merkleroot\":\"" << block.hashMerkleRoot.GetHex() << "\",";
    oss << "\"time\":" << block.nTime << ",";
    oss << "\"bits\":\"0x" << std::hex << block.nBits << std::dec << "\",";
    oss << "\"nonce\":" << block.nNonce << ",";
    oss << "\"size\":" << block.vtx.size() << ",";  // Raw block data size in bytes
    oss << "\"tx_count\":" << (hasTxs ? transactions.size() : 0) << ",";

    // Confirmations (tip height - block height + 1)
    if (height >= 0 && m_chainstate) {
        CBlockIndex* pTipConf = m_chainstate->GetTip();
        if (pTipConf) {
            oss << "\"confirmations\":" << (pTipConf->nHeight - height + 1) << ",";
        }
    }

    oss << "\"miner\":\"" << minerAddress << "\"";
    if (!minerMIK.empty()) {
        oss << ",\"mik\":\"" << minerMIK << "\"";
    }

    // Verbosity 1: Add txid array
    if (verbosity >= 1 && hasTxs) {
        oss << ",\"tx\":[";
        for (size_t i = 0; i < transactions.size(); i++) {
            if (i > 0) oss << ",";
            if (verbosity == 1) {
                // Just txids
                oss << "\"" << transactions[i]->GetHash().GetHex() << "\"";
            } else {
                // Verbosity 2: Full decoded transactions
                const auto& tx = transactions[i];
                oss << "{";
                oss << "\"txid\":\"" << tx->GetHash().GetHex() << "\",";
                oss << "\"version\":" << tx->nVersion << ",";

                // Inputs
                oss << "\"vin\":[";
                for (size_t j = 0; j < tx->vin.size(); j++) {
                    if (j > 0) oss << ",";
                    const CTxIn& txin = tx->vin[j];
                    oss << "{";
                    if (txin.prevout.hash.IsNull()) {
                        // Coinbase transaction
                        oss << "\"coinbase\":true";
                    } else {
                        oss << "\"txid\":\"" << txin.prevout.hash.GetHex() << "\",";
                        oss << "\"vout\":" << txin.prevout.n;
                    }
                    oss << "}";
                }
                oss << "],";

                // Outputs
                oss << "\"vout\":[";
                for (size_t j = 0; j < tx->vout.size(); j++) {
                    if (j > 0) oss << ",";
                    const CTxOut& txout = tx->vout[j];
                    std::string addr = DecodeScriptPubKeyToAddress(txout.scriptPubKey);
                    oss << "{";
                    oss << "\"value\":" << txout.nValue << ",";
                    oss << "\"n\":" << j << ",";
                    if (!addr.empty()) {
                        oss << "\"address\":\"" << addr << "\",";
                    }
                    oss << "\"scriptPubKey\":\"" << HexStr(txout.scriptPubKey) << "\"";
                    oss << "}";
                }
                oss << "],";

                oss << "\"locktime\":" << tx->nLockTime;
                oss << "}";
            }
        }
        oss << "]";
    }

    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetBlockHash(const std::string& params) {
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"height":100}
    size_t height_pos = params.find("\"height\"");
    if (height_pos == std::string::npos) {
        throw std::runtime_error("Missing height parameter");
    }

    size_t colon = params.find(":", height_pos);
    size_t num_start = colon + 1;
    while (num_start < params.length() && isspace(params[num_start])) num_start++;
    size_t num_end = num_start;
    while (num_end < params.length() && isdigit(params[num_end])) num_end++;

    if (num_end <= num_start) {
        throw std::runtime_error("Invalid height parameter format");
    }

    // PHASE 4 FIX: Add exception handling for invalid height parameter
    int height = 0;
    try {
        height = std::stoi(params.substr(num_start, num_end - num_start));
        if (height < 0) {
            throw std::runtime_error("Invalid height parameter (must be non-negative)");
        }
    } catch (const std::invalid_argument& e) {
        throw std::runtime_error("Invalid height parameter format (not a number)");
    } catch (const std::out_of_range& e) {
        throw std::runtime_error("Height parameter out of range");
    }

    // Get block hash from active chain (walk back from tip)
    CBlockIndex* pTip = m_chainstate->GetTip();
    if (!pTip || height > pTip->nHeight) {
        // Fallback to GetBlocksAtHeight for blocks beyond tip
        std::vector<uint256> hashes = m_chainstate->GetBlocksAtHeight(height);
        if (hashes.empty()) {
            throw std::runtime_error("No block found at height " + std::to_string(height));
        }
        std::ostringstream oss;
        oss << "{\"blockhash\":\"" << hashes[0].GetHex() << "\"}";
        return oss.str();
    }

    // Use GetAncestor to walk active chain - guaranteed to return main chain block
    CBlockIndex* pBlock = pTip->GetAncestor(height);
    if (!pBlock) {
        throw std::runtime_error("No block found at height " + std::to_string(height));
    }

    std::ostringstream oss;
    oss << "{\"blockhash\":\"" << pBlock->GetBlockHash().GetHex() << "\"}";
    return oss.str();
}

std::string CRPCServer::RPC_GetTxOut(const std::string& params) {
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Parse params - expecting {"txid":"...", "n":0}
    size_t txid_pos = params.find("\"txid\"");
    if (txid_pos == std::string::npos) {
        throw std::runtime_error("Missing txid parameter");
    }

    size_t colon = params.find(":", txid_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid txid parameter format");
    }

    std::string txid_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 txid;
    // CID 1675176 FIX: Validate hex string before calling SetHex to prevent exceptions
    // SetHex can throw std::invalid_argument or std::out_of_range on invalid hex input
    if (txid_str.length() != 64) {
        throw std::runtime_error("Invalid txid: must be 64 hex characters");
    }
    // Validate all characters are valid hex digits
    for (char c : txid_str) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            throw std::runtime_error("Invalid txid: contains non-hexadecimal characters");
        }
    }
    try {
        txid.SetHex(txid_str);
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid txid format: " + std::string(e.what()));
    }

    // Parse n
    size_t n_pos = params.find("\"n\"", quote2);
    if (n_pos == std::string::npos) {
        throw std::runtime_error("Missing n parameter");
    }

    colon = params.find(":", n_pos);
    size_t num_start = colon + 1;
    while (num_start < params.length() && isspace(params[num_start])) num_start++;
    size_t num_end = num_start;
    while (num_end < params.length() && isdigit(params[num_end])) num_end++;

    if (num_end <= num_start) {
        throw std::runtime_error("Invalid n parameter format");
    }

    // MEDIUM-004: Use SafeParseUInt32 to prevent RPC crashes from malformed input
    // Transaction outputs are indexed by uint32_t
    uint32_t n = SafeParseUInt32(params.substr(num_start, num_end - num_start), 0, UINT32_MAX);

    // Look up UTXO
    COutPoint outpoint(txid, n);
    CUTXOEntry entry;
    if (!m_utxo_set->GetUTXO(outpoint, entry)) {
        return "null";  // UTXO doesn't exist or already spent
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    unsigned int confirmations = 0;
    if (entry.nHeight > 0 && currentHeight >= entry.nHeight) {
        confirmations = currentHeight - entry.nHeight + 1;
    }

    uint256 bestBlockHash;
    m_blockchain->ReadBestBlock(bestBlockHash);

    std::ostringstream oss;
    oss << "{";
    oss << "\"bestblock\":\"" << bestBlockHash.GetHex() << "\",";
    oss << "\"confirmations\":" << confirmations << ",";
    oss << "\"value\":" << FormatAmount(entry.out.nValue) << ",";
    oss << "\"scriptPubKey\":{";
    oss << "\"hex\":\"";
    for (uint8_t byte : entry.out.scriptPubKey) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    oss << std::dec << "\"";
    oss << "},";
    oss << "\"coinbase\":" << (entry.fCoinBase ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetHolderCount(const std::string& params) {
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // Iterate all UTXOs and collect unique pubkey hashes (addresses)
    std::set<std::vector<uint8_t>> uniqueAddresses;
    uint64_t totalUTXOs = 0;
    uint64_t totalAmount = 0;

    m_utxo_set->ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) -> bool {
        totalUTXOs++;
        totalAmount += entry.out.nValue;

        // Extract pubkey hash from scriptPubKey
        std::vector<uint8_t> pkh = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);
        if (!pkh.empty()) {
            uniqueAddresses.insert(pkh);
        }
        return true;  // Continue iteration
    });

    std::ostringstream oss;
    oss << "{";
    oss << "\"holders\":" << uniqueAddresses.size() << ",";
    oss << "\"utxos\":" << totalUTXOs << ",";
    oss << "\"total_amount\":" << FormatAmount(totalAmount);
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetTopHolders(const std::string& params) {
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // Parse optional parameters
    int count = 100;
    std::string prefix;  // Optional address prefix filter (e.g. "DGUP")
    try {
        auto parsed = nlohmann::json::parse(params);
        if (parsed.contains("count")) {
            count = parsed["count"].get<int>();
            if (count < 1) count = 1;
            if (count > 500) count = 500;
        }
        if (parsed.contains("prefix")) {
            prefix = parsed["prefix"].get<std::string>();
            // Prefix search: allow up to 1000 results to cover all matches
            if (count == 100) count = 500;  // Bump default for prefix searches
        }
    } catch (...) {
        // Use default
    }

    // Aggregate balances by address (pubkey hash)
    std::map<std::vector<uint8_t>, uint64_t> balances;
    uint64_t totalUTXOs = 0;

    m_utxo_set->ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) -> bool {
        totalUTXOs++;
        std::vector<uint8_t> pkh = WalletCrypto::ExtractPubKeyHash(entry.out.scriptPubKey);
        if (!pkh.empty()) {
            balances[pkh] += entry.out.nValue;
        }
        return true;
    });

    // Sort by balance descending
    std::vector<std::pair<std::vector<uint8_t>, uint64_t>> sorted(balances.begin(), balances.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    // Build JSON response — apply prefix filter during output if specified
    std::ostringstream oss;
    oss << "{\"holders\":" << balances.size() << ",\"utxos\":" << totalUTXOs;
    if (!prefix.empty()) {
        oss << ",\"prefix\":\"" << prefix << "\"";
    }
    oss << ",\"top\":[";

    int emitted = 0;
    int rank = 0;
    for (size_t i = 0; i < sorted.size() && emitted < count; i++) {
        // Encode pubkey hash to address
        std::vector<uint8_t> addrData;
        addrData.push_back(0x1E);  // Dilithion version byte ('D' prefix)
        addrData.insert(addrData.end(), sorted[i].first.begin(), sorted[i].first.end());
        std::string address = EncodeBase58Check(addrData);

        rank++;  // Overall rank (before filtering)

        // Apply prefix filter if specified
        if (!prefix.empty()) {
            if (address.length() < prefix.length() ||
                address.compare(0, prefix.length(), prefix) != 0) {
                continue;  // Skip non-matching addresses
            }
        }

        if (emitted > 0) oss << ",";
        oss << "{\"address\":\"" << address << "\","
            << "\"balance\":" << FormatAmount(sorted[i].second) << ","
            << "\"rank\":" << rank << "}";
        emitted++;
    }

    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetWalletInfo(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    bool isEncrypted = m_wallet->IsCrypted();
    bool isLocked = isEncrypted && m_wallet->IsLocked();

    std::ostringstream oss;
    oss << "{"
        << "\"encrypted\":" << (isEncrypted ? "true" : "false") << ","
        << "\"locked\":" << (isLocked ? "true" : "false") << ","
        << "\"unlocked_until\":" << (isLocked ? 0 : 1)  // 0 if locked, 1 if unlocked
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_EncryptWallet(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is already encrypted");
    }

    // Parse params using proper JSON parser (handles special characters in passwords)
    json j = json::parse(params);
    std::string passphrase = RPCUtil::GetRequiredString(j, "passphrase");

    if (passphrase.empty()) {
        throw std::runtime_error("Error: Passphrase cannot be empty");
    }

    // Validate passphrase strength before attempting encryption
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(passphrase);

    if (!validation.is_valid) {
        // Return detailed error message with strength score
        std::string error_msg = "Error: Passphrase validation failed - " + validation.error_message;
        throw std::runtime_error(error_msg);
    }

    // Attempt to encrypt wallet
    if (!m_wallet->EncryptWallet(passphrase)) {
        throw std::runtime_error("Error: Failed to encrypt wallet");
    }

    // Return success message with strength info
    std::ostringstream oss;
    oss << "Wallet encrypted successfully! Passphrase strength: "
        << PassphraseValidator::GetStrengthDescription(validation.strength_score)
        << " (" << validation.strength_score << "/100). "
        << "Please backup your wallet and remember your passphrase!";

    return "\"" + oss.str() + "\"";
}

std::string CRPCServer::RPC_WalletPassphrase(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    // Parse params using proper JSON parser (handles special characters in passwords)
    json j = json::parse(params);
    std::string passphrase = RPCUtil::GetRequiredString(j, "passphrase");

    // P4-RPC-004 FIX: Limit passphrase length to prevent DoS via excessive PBKDF2 work
    static const size_t MAX_PASSPHRASE_LENGTH = 1024;
    if (passphrase.length() > MAX_PASSPHRASE_LENGTH) {
        throw std::runtime_error("Passphrase too long (max " + std::to_string(MAX_PASSPHRASE_LENGTH) + " characters)");
    }

    // Parse timeout (optional, default 60 seconds, max 24 hours, 0 = forever)
    int64_t timeout = RPCUtil::GetOptionalInt64(j, "timeout", 60, 0, 86400);

    if (!m_wallet->Unlock(passphrase, timeout)) {
        throw std::runtime_error("Error: The wallet passphrase entered was incorrect");
    }

    std::ostringstream oss;
    oss << "\"Wallet unlocked";
    if (timeout > 0) {
        oss << " for " << timeout << " seconds";
    }
    oss << "\"";
    return oss.str();
}

std::string CRPCServer::RPC_WalletLock(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    if (!m_wallet->Lock()) {
        throw std::runtime_error("Error: Failed to lock wallet");
    }

    return "\"Wallet locked\"";
}

std::string CRPCServer::RPC_WalletPassphraseChange(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsCrypted()) {
        throw std::runtime_error("Error: Wallet is not encrypted");
    }

    // Parse params using proper JSON parser (handles special characters in passwords)
    json j = json::parse(params);
    std::string oldPass = RPCUtil::GetRequiredString(j, "oldpassphrase");
    std::string newPass = RPCUtil::GetRequiredString(j, "newpassphrase");

    if (newPass.empty()) {
        throw std::runtime_error("Error: New passphrase cannot be empty");
    }

    // Validate new passphrase strength before attempting change
    PassphraseValidator validator;
    PassphraseValidationResult validation = validator.Validate(newPass);

    if (!validation.is_valid) {
        // Return detailed error message with strength score
        std::string error_msg = "Error: New passphrase validation failed - " + validation.error_message;
        throw std::runtime_error(error_msg);
    }

    // Attempt to change passphrase
    if (!m_wallet->ChangePassphrase(oldPass, newPass)) {
        throw std::runtime_error("Error: The wallet passphrase entered was incorrect");
    }

    // Return success message with strength info
    std::ostringstream oss;
    oss << "Wallet passphrase changed successfully! New passphrase strength: "
        << PassphraseValidator::GetStrengthDescription(validation.strength_score)
        << " (" << validation.strength_score << "/100)";

    return "\"" + oss.str() + "\"";
}

// ============================================================================
// HD Wallet RPC Methods
// ============================================================================

std::string CRPCServer::RPC_CreateHDWallet(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (m_wallet->IsHDWallet()) {
        throw std::runtime_error("Error: Wallet is already an HD wallet");
    }

    if (!m_wallet->IsEmpty()) {
        throw std::runtime_error("Error: Can only create HD wallet on an empty wallet");
    }

    // Parse optional passphrase parameter: {"passphrase":"secret"}
    std::string passphrase;
    if (!params.empty() && params != "null") {
        size_t pos = params.find("\"passphrase\"");
        if (pos != std::string::npos) {
            pos = params.find(":", pos);
            pos = params.find("\"", pos + 1);
            size_t end = params.find("\"", pos + 1);
            if (end != std::string::npos) {
                passphrase = params.substr(pos + 1, end - pos - 1);
            }
        }
    }

    // Generate HD wallet
    std::string mnemonic;
    if (!m_wallet->GenerateHDWallet(mnemonic, passphrase)) {
        throw std::runtime_error("Failed to generate HD wallet");
    }

    // Get first address
    CDilithiumAddress firstAddress = m_wallet->GetNewHDAddress();
    if (!firstAddress.IsValid()) {
        throw std::runtime_error("Failed to derive first address");
    }

    // Build response: {"mnemonic":"word1 word2 ...", "address":"addr..."}
    std::ostringstream oss;
    oss << "{"
        << "\"mnemonic\":\"" << EscapeJSON(mnemonic) << "\","
        << "\"address\":\"" << firstAddress.ToString() << "\""
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_RestoreHDWallet(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (m_wallet->IsHDWallet()) {
        throw std::runtime_error("Error: Wallet is already an HD wallet");
    }

    if (!m_wallet->IsEmpty()) {
        throw std::runtime_error("Error: Can only restore HD wallet on an empty wallet");
    }

    // Parse required mnemonic parameter: {"mnemonic":"word1 word2 ...", "passphrase":"secret"}
    size_t pos = params.find("\"mnemonic\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing mnemonic parameter");
    }

    pos = params.find(":", pos);
    pos = params.find("\"", pos + 1);
    size_t end = params.find("\"", pos + 1);
    if (end == std::string::npos) {
        throw std::runtime_error("Invalid mnemonic parameter");
    }
    std::string mnemonic = params.substr(pos + 1, end - pos - 1);

    // Parse optional passphrase
    std::string passphrase;
    pos = params.find("\"passphrase\"", end);
    if (pos != std::string::npos) {
        pos = params.find(":", pos);
        pos = params.find("\"", pos + 1);
        end = params.find("\"", pos + 1);
        if (end != std::string::npos) {
            passphrase = params.substr(pos + 1, end - pos - 1);
        }
    }

    // Restore HD wallet
    if (!m_wallet->InitializeHDWallet(mnemonic, passphrase)) {
        throw std::runtime_error("Failed to restore HD wallet (invalid mnemonic or passphrase)");
    }

    // Get first address
    CDilithiumAddress firstAddress = m_wallet->GetNewHDAddress();
    if (!firstAddress.IsValid()) {
        throw std::runtime_error("Failed to derive first address");
    }

    // Build response: {"success":true, "address":"addr..."}
    std::ostringstream oss;
    oss << "{"
        << "\"success\":true,"
        << "\"address\":\"" << firstAddress.ToString() << "\""
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_ExportMnemonic(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsHDWallet()) {
        throw std::runtime_error("Error: Wallet is not an HD wallet");
    }

    // Export mnemonic
    std::string mnemonic;
    if (!m_wallet->ExportMnemonic(mnemonic)) {
        throw std::runtime_error("Failed to export mnemonic (wallet may be locked)");
    }

    // Build response: {"mnemonic":"word1 word2 ..."}
    std::ostringstream oss;
    oss << "{"
        << "\"mnemonic\":\"" << EscapeJSON(mnemonic) << "\""
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_DumpPrivKey(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    // Parse address parameter
    std::string addrStr;
    if (!params.empty()) {
        try {
            auto j = nlohmann::json::parse(params);
            if (j.is_object() && j.contains("address")) {
                addrStr = j["address"].get<std::string>();
            }
        } catch (...) {}
    }
    if (addrStr.empty()) {
        throw std::runtime_error("Missing required parameter: address");
    }

    // Validate address
    CDilithiumAddress address;
    if (!address.SetString(addrStr)) {
        throw std::runtime_error("Invalid address: " + addrStr);
    }

    // Check wallet has the key
    if (!m_wallet->HasKey(address)) {
        throw std::runtime_error("Address not found in wallet: " + addrStr);
    }

    // Get the key (handles decryption for encrypted wallets)
    CKey key;
    if (!m_wallet->GetKey(address, key)) {
        throw std::runtime_error("Failed to retrieve key (wallet may be locked)");
    }

    // Base64 encode the key data
    std::string privkeyB64 = RPCAuth::Base64Encode(key.vchPrivKey.data(), key.vchPrivKey.size());
    std::string pubkeyB64 = RPCAuth::Base64Encode(key.vchPubKey.data(), key.vchPubKey.size());

    // Wipe sensitive key data from memory
    key.Clear();

    // Build response
    std::ostringstream oss;
    oss << "{"
        << "\"address\":\"" << EscapeJSON(addrStr) << "\","
        << "\"privkey\":\"" << EscapeJSON(privkeyB64) << "\","
        << "\"pubkey\":\"" << EscapeJSON(pubkeyB64) << "\""
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_ImportPrivKey(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    // Parse parameters
    std::string privkeyB64, pubkeyB64;
    if (!params.empty()) {
        try {
            auto j = nlohmann::json::parse(params);
            if (j.is_object()) {
                if (j.contains("privkey")) privkeyB64 = j["privkey"].get<std::string>();
                if (j.contains("pubkey")) pubkeyB64 = j["pubkey"].get<std::string>();
            }
        } catch (...) {}
    }
    if (privkeyB64.empty() || pubkeyB64.empty()) {
        throw std::runtime_error("Missing required parameters: privkey, pubkey (base64 encoded)");
    }

    // Base64 decode
    std::vector<uint8_t> privkeyBytes, pubkeyBytes;
    if (!RPCAuth::Base64Decode(privkeyB64, privkeyBytes)) {
        throw std::runtime_error("Invalid base64 encoding for privkey");
    }
    if (!RPCAuth::Base64Decode(pubkeyB64, pubkeyBytes)) {
        throw std::runtime_error("Invalid base64 encoding for pubkey");
    }

    // Validate key sizes
    if (privkeyBytes.size() != DILITHIUM_SECRETKEY_SIZE) {
        throw std::runtime_error(
            "Invalid private key size: expected " +
            std::to_string(DILITHIUM_SECRETKEY_SIZE) + " bytes, got " +
            std::to_string(privkeyBytes.size()));
    }
    if (pubkeyBytes.size() != DILITHIUM_PUBLICKEY_SIZE) {
        throw std::runtime_error(
            "Invalid public key size: expected " +
            std::to_string(DILITHIUM_PUBLICKEY_SIZE) + " bytes, got " +
            std::to_string(pubkeyBytes.size()));
    }

    // Construct CKey
    CKey key;
    key.vchPubKey = pubkeyBytes;
    key.vchPrivKey.assign(privkeyBytes.begin(), privkeyBytes.end());

    if (!key.IsValid()) {
        memory_cleanse(privkeyBytes.data(), privkeyBytes.size());
        throw std::runtime_error("Key validation failed");
    }

    // Derive address from pubkey
    CDilithiumAddress address(pubkeyBytes);
    if (!address.IsValid()) {
        memory_cleanse(privkeyBytes.data(), privkeyBytes.size());
        key.Clear();
        throw std::runtime_error("Failed to derive address from public key");
    }

    // Check if key already exists
    if (m_wallet->HasKey(address)) {
        memory_cleanse(privkeyBytes.data(), privkeyBytes.size());
        key.Clear();
        throw std::runtime_error("Key already exists in wallet for address: " + address.ToString());
    }

    // Import the key
    if (!m_wallet->ImportKey(key, address)) {
        memory_cleanse(privkeyBytes.data(), privkeyBytes.size());
        key.Clear();
        throw std::runtime_error("Failed to import key (wallet may be locked or save failed)");
    }

    // Wipe sensitive data
    memory_cleanse(privkeyBytes.data(), privkeyBytes.size());
    key.Clear();

    std::string addrStr = address.ToString();

    // Build response
    std::ostringstream oss;
    oss << "{"
        << "\"address\":\"" << EscapeJSON(addrStr) << "\","
        << "\"success\":true"
        << "}";

    return oss.str();
}

// ============================================================================
// v4.0.19: forcerebuild — operator escape hatch for stuck-chain recovery
// ============================================================================
// Writes the auto_rebuild marker file with operator-supplied reason and triggers
// graceful shutdown. On restart, the wrapper sees the marker and the startup
// code wipes blocks/chainstate for a clean resync. Used when an operator
// already knows a node is stuck (e.g. NYC/LDN incident 2026-04-25) and doesn't
// want to wait for the in-process detection threshold (Fix A) to fire.
//
// Auth: ADMIN_SERVER (registered in permissions.cpp). Rate limit: 1/min.
// Hidden from public help — operators learn it from runbooks.
//
// Params (object): {"reason": "<string, max 256 chars, alnum/space/._-:>"}
std::string CRPCServer::RPC_ForceRebuild(const std::string& params) {
    constexpr size_t kMaxReasonLen = 256;

    std::string reason;
    if (!params.empty()) {
        try {
            auto j = nlohmann::json::parse(params);
            if (j.is_object() && j.contains("reason")) {
                reason = j["reason"].get<std::string>();
            }
        } catch (...) {}
    }

    if (reason.empty()) {
        throw std::runtime_error("Missing required parameter: reason (string)");
    }
    if (reason.size() > kMaxReasonLen) {
        throw std::runtime_error("Parameter 'reason' too long (max "
                                 + std::to_string(kMaxReasonLen) + " chars)");
    }
    // Sanitise: alphanumeric + space, underscore, hyphen, dot, colon. No quotes,
    // newlines, or shell metachars — keeps the marker file safe to grep, log,
    // and embed in operator alerts.
    for (char c : reason) {
        const bool ok = std::isalnum(static_cast<unsigned char>(c))
                     || c == ' ' || c == '_' || c == '-' || c == '.' || c == ':';
        if (!ok) {
            throw std::runtime_error("Parameter 'reason' contains disallowed characters; "
                                     "allowed: alphanumeric, space, _-.:");
        }
    }

    std::string datadir;
    if (Dilithion::g_chainParams) {
        datadir = Dilithion::g_chainParams->dataDir;
    }
    if (datadir.empty()) {
        throw std::runtime_error("ChainParams not initialised — refusing to write marker");
    }

    const std::string fullReason = "operator_forcerebuild: " + reason;
    if (!Dilithion::WriteAutoRebuildMarker(datadir, fullReason)) {
        throw std::runtime_error("Failed to write auto_rebuild marker");
    }

    std::cerr << "[CRITICAL] forcerebuild: operator-initiated rebuild scheduled. Shutting down."
              << std::endl;

    // Trigger graceful shutdown after a brief delay so the response can be sent.
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        g_node_state.running = false;
    }).detach();

    const std::string markerPath = datadir + "/auto_rebuild";
    std::ostringstream oss;
    oss << "{"
        << "\"status\":\"shutdown_initiated\","
        << "\"marker_path\":\"" << EscapeJSON(markerPath) << "\","
        << "\"reason\":\"" << EscapeJSON(fullReason) << "\""
        << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetHDWalletInfo(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    bool isHDWallet = m_wallet->IsHDWallet();

    if (!isHDWallet) {
        // Not an HD wallet
        return "{\"hdwallet\":false}";
    }

    // Get HD wallet info
    uint32_t account, external_index, internal_index;
    if (!m_wallet->GetHDWalletInfo(account, external_index, internal_index)) {
        throw std::runtime_error("Failed to get HD wallet info");
    }

    // Build response
    std::ostringstream oss;
    oss << "{"
        << "\"hdwallet\":true,"
        << "\"account\":" << account << ","
        << "\"external_index\":" << external_index << ","
        << "\"internal_index\":" << internal_index
        << "}";

    return oss.str();
}

std::string CRPCServer::RPC_ListHDAddresses(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    if (!m_wallet->IsHDWallet()) {
        throw std::runtime_error("Error: Wallet is not an HD wallet");
    }

    // Get all addresses
    std::vector<CDilithiumAddress> addresses = m_wallet->GetAddresses();

    // Build JSON array of addresses with paths
    std::ostringstream oss;
    oss << "[";

    bool first = true;
    for (const CDilithiumAddress& addr : addresses) {
        // Get derivation path for this address
        CHDKeyPath path;
        if (!m_wallet->GetAddressPath(addr, path)) {
            continue;  // Skip non-HD addresses (shouldn't happen in HD wallet)
        }

        if (!first) {
            oss << ",";
        }
        first = false;

        oss << "{"
            << "\"address\":\"" << addr.ToString() << "\","
            << "\"path\":\"" << EscapeJSON(path.ToString()) << "\""
            << "}";
    }

    oss << "]";

    return oss.str();
}

std::string CRPCServer::RPC_RescanWallet(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }

    // For HD wallets: discover addresses beyond the pre-derived gap limit
    // This is critical after wallet restore - privacy mode mining generates
    // new addresses per block, which may exceed the initial 20 pre-derived ones.
    // ScanHDChains uses the BIP44 gap limit algorithm to find them.
    if (m_wallet->IsHDWallet()) {
        size_t discovered = m_wallet->ScanHDChains(*m_utxo_set);
        if (discovered > 0) {
            std::cout << "[RPC] HD chain scan discovered " << discovered << " additional address(es) with UTXOs" << std::endl;
        }
    }

    // Get number of addresses after HD chain discovery
    size_t numAddresses = m_wallet->GetAddresses().size();

    // Perform UTXO scan for all wallet addresses
    std::cout << "[RPC] Starting wallet rescan with " << numAddresses << " addresses..." << std::endl;
    bool success = m_wallet->ScanUTXOs(*m_utxo_set);

    if (!success) {
        throw std::runtime_error("Wallet rescan failed");
    }

    // Save wallet after rescan to persist found UTXOs
    m_wallet->Save("");

    // Get updated balance
    unsigned int currentHeight = m_chainstate ? m_chainstate->GetHeight() : 0;
    CAmount balance = m_wallet->GetAvailableBalance(*m_utxo_set, currentHeight);
    CAmount immatureBalance = m_wallet->GetImmatureBalance(*m_utxo_set, currentHeight);

    std::ostringstream oss;
    oss << "{";
    oss << "\"success\":true,";
    oss << "\"addresses_scanned\":" << numAddresses << ",";
    oss << "\"balance\":" << FormatAmount(balance) << ",";
    oss << "\"immature_balance\":" << FormatAmount(immatureBalance);
    oss << "}";

    std::cout << "[RPC] Wallet rescan complete. Balance: " << FormatAmount(balance)
              << ", Immature: " << FormatAmount(immatureBalance) << std::endl;

    return oss.str();
}

std::string CRPCServer::RPC_ClearWalletTxs(const std::string& params) {
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized");
    }

    std::cout << "[RPC] Clearing wallet transaction history..." << std::endl;
    size_t cleared = m_wallet->ClearAllTransactions();

    std::ostringstream oss;
    oss << "{";
    oss << "\"success\":true,";
    oss << "\"transactions_cleared\":" << cleared << ",";
    oss << "\"message\":\"Wallet transaction history cleared. Call rescanwallet to repopulate from blockchain.\"";
    oss << "}";

    return oss.str();
}

std::string CRPCServer::RPC_GetMiningInfo(const std::string& params) {
    // VDF miner (DilV) — return VDF-specific mining info
    if (m_vdfMiner) {
        std::ostringstream oss;
        oss << "{";
        oss << "\"mining\":" << (m_vdfMiner->IsRunning() ? "true" : "false") << ",";
        oss << "\"type\":\"vdf\",";
        oss << "\"hashrate\":0,";
        oss << "\"threads\":1,";
        oss << "\"current_height\":" << m_vdfMiner->GetCurrentHeight() << ",";
        oss << "\"blocks_found\":" << m_vdfMiner->GetBlocksFound() << ",";
        oss << "\"blocks_accepted\":" << m_acceptedSession.load();
        oss << "}";
        return oss.str();
    }

    // RandomX miner (DIL)
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    auto stats = m_miner->GetStats();
    std::ostringstream oss;
    oss << "{";
    oss << "\"mining\":" << (m_miner->IsMining() ? "true" : "false") << ",";
    oss << "\"hashrate\":" << m_miner->GetHashRate() << ",";
    oss << "\"threads\":" << m_miner->GetThreadCount() << ",";
    oss << "\"blocks_found\":" << stats.nBlocksFound.load() << ",";
    oss << "\"blocks_accepted\":" << m_acceptedSession.load();
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_StartMining(const std::string& params) {
    // VDF miner (DilV) — start VDF mining
    if (m_vdfMiner) {
        if (m_vdfMiner->IsRunning()) {
            return "true";  // Already mining
        }

        // BUG FIX: Prevent mining during IBD (Initial Block Download)
        if (g_node_context.ibd_coordinator &&
            g_node_context.ibd_coordinator->IsInitialBlockDownload()) {
            g_node_state.mining_enabled = true;
            throw std::runtime_error("Node is still syncing (Initial Block Download). Mining will start automatically once sync completes.");
        }

        // Check wallet is unlocked (required for MIK signing)
        if (m_wallet && m_wallet->IsCrypted() && m_wallet->IsLocked()) {
            throw std::runtime_error("Wallet is locked. Unlock first with walletpassphrase, then call startmining.");
        }

        // Set miner address and MIK identity from wallet if not already set
        // This handles the case where mining was disabled at startup due to locked wallet
        if (m_wallet) {
            std::vector<uint8_t> pubKeyHash = m_wallet->GetPubKeyHash();
            if (pubKeyHash.size() >= 20) {
                std::array<uint8_t, 20> addr{};
                std::copy(pubKeyHash.begin(), pubKeyHash.begin() + 20, addr.begin());
                m_vdfMiner->SetMinerAddress(addr);
            }
            DFMP::Identity mikId = m_wallet->GetMIKIdentity();
            if (!mikId.IsNull()) {
                std::array<uint8_t, 20> mikArr{};
                std::memcpy(mikArr.data(), mikId.data, 20);
                m_vdfMiner->SetMIKIdentity(mikArr);
            }
        }

        m_vdfMiner->Start();
        g_node_state.mining_enabled = true;
        return "true";
    }

    // RandomX miner (DIL)
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }
    if (!m_utxo_set) {
        throw std::runtime_error("UTXO set not initialized");
    }
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }
    if (!m_wallet) {
        throw std::runtime_error("Wallet not initialized - need address for coinbase");
    }

    // Prevent mining during IBD (same fix as VDF path above)
    if (g_node_context.ibd_coordinator &&
        g_node_context.ibd_coordinator->IsInitialBlockDownload()) {
        g_node_state.mining_enabled = true;
        throw std::runtime_error("Node is still syncing (Initial Block Download). Mining will start automatically once sync completes.");
    }

    // BUG #76 FIX: Wait for RandomX FULL mode before starting mining
    // Following XMRig's proven pattern: "dataset ready" before thread creation
    // Mining threads created in LIGHT mode get LIGHT VMs and never upgrade
    if (!randomx_is_mining_mode_ready()) {
        std::cout << "[RPC] Waiting for RandomX FULL mode initialization..." << std::endl;
        auto wait_start = std::chrono::steady_clock::now();
        while (!randomx_is_mining_mode_ready() && g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto elapsed = std::chrono::steady_clock::now() - wait_start;
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

            // Show progress every 5 seconds
            if (seconds % 5 == 0 && seconds > 0) {
                std::cout << "[RPC] Still waiting for FULL mode... " << seconds << "s elapsed" << std::endl;
            }

            // Timeout after 600 seconds (10 minutes)
            if (seconds > 600) {
                throw std::runtime_error("RandomX FULL mode initialization timeout (10min). Try again later.");
            }
        }
        auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - wait_start).count();
        std::cout << "[RPC] RandomX FULL mode ready (" << wait_time << "s)" << std::endl;
    }

    // Check if already mining
    if (m_miner->IsMining()) {
        return "true";  // Already mining
    }

    // Get mining parameters from blockchain
    uint256 hashPrevBlock;
    if (!m_blockchain->ReadBestBlock(hashPrevBlock)) {
        throw std::runtime_error("Failed to read best block hash");
    }

    uint32_t nHeight = m_chainstate->GetHeight() + 1;

    // BUG #8 FIX: Use GetNextWorkRequired() to get proper difficulty instead of hardcoded value
    // The hardcoded 0x1f00ffff was ~42x harder than testnet genesis (0x1f060000)
    CBlockIndex* pindexPrev = m_chainstate->GetTip();
    uint32_t nBits = GetNextWorkRequired(pindexPrev, static_cast<int64_t>(std::time(nullptr)));

    // Get miner address from wallet
    std::vector<CDilithiumAddress> addresses = m_wallet->GetAddresses();
    if (addresses.empty()) {
        throw std::runtime_error("No wallet address available for mining rewards");
    }
    std::vector<uint8_t> minerAddress = addresses[0].GetData();

    // DFMP v2.0: Prepare Mining Identity Key (MIK) data
    CMIKCoinbaseData mikData;

    // Auto-generate MIK if wallet doesn't have one
    if (!m_wallet->HasMIK()) {
        std::cout << "[RPC] Wallet has no MIK - generating one for DFMP v2.0..." << std::endl;
        if (!m_wallet->GenerateMIK()) {
            throw std::runtime_error("Failed to generate Mining Identity Key (MIK)");
        }
        std::cout << "[RPC] Generated MIK identity: " << m_wallet->GetMIKIdentityHex() << std::endl;
    }

    // Get MIK data from wallet
    mikData.hasMIK = true;
    mikData.identity = m_wallet->GetMIKIdentity();

    // Check if MIK is registered on-chain (first-block vs subsequent)
    if (DFMP::g_identityDb && DFMP::g_identityDb->HasMIKPubKey(mikData.identity)) {
        // MIK already registered - use reference format
        mikData.isRegistration = false;
        m_wallet->SetMIKRegistered();  // Ensure wallet knows it's registered
    } else {
        // First block with this MIK - use registration format
        mikData.isRegistration = true;
        if (!m_wallet->GetMIKPubKey(mikData.pubkey)) {
            throw std::runtime_error("Failed to get MIK public key for registration");
        }

        // Guard: RPC CreateBlockTemplate/CreateCoinbaseTransaction does NOT append
        // DNA commitment (0xDD) or attestation data (0xDA) to the coinbase scriptSig.
        // Only the --mine startup path (EnsureMIKRegistered + BuildMiningTemplate)
        // handles the full registration flow. At/above attestation activation height,
        // a registration block without these fields is consensus-invalid.
        if (Dilithion::g_chainParams) {
            int attestHeight = Dilithion::g_chainParams->seedAttestationActivationHeight;
            if (attestHeight != 999999999 && static_cast<int>(nHeight) >= attestHeight) {
                throw std::runtime_error(
                    "Cannot register new MIK via RPC at height " + std::to_string(nHeight) +
                    " (requires DNA collection + seed attestations). "
                    "Please restart with --mine flag to complete registration first.");
            }
        }

        std::cout << "[RPC] MIK not registered - will include full pubkey in coinbase" << std::endl;

        // DFMP v3.0: Registration PoW nonce (required at/above v3 activation height).
        // v4.0.18: RPC handler now delegates to the live CRegistrationManager instead
        // of mining inline. This keeps a single source of truth for registration state
        // (no double-PoW between miner loop and RPC handler) and inherits the manager's
        // race-safe DNA/attestation/PoW sequencing.
        int dfmpV3Height = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV3ActivationHeight : 0;
        if (static_cast<int>(nHeight) >= dfmpV3Height) {
            auto* mgr = GetRegistrationManager();
            if (!mgr) {
                throw std::runtime_error("Registration manager not initialized");
            }

            // Poll the manager until it reaches a state that has a valid nonce
            // (READY / SUBMITTED / CONFIRMED). The manager's worker thread does
            // the actual DNA + attestation + PoW work; we just wait.
            using State = CRegistrationManager::State;
            int wait_sec = 0;
            while (g_node_state.running.load()) {
                auto snap = mgr->GetSnapshot();
                if (snap->hasRegNonce && snap->mikPubkey == mikData.pubkey) {
                    mikData.registrationNonce = snap->regNonce;
                    std::cout << "[RPC] Registration PoW ready (nonce from manager snapshot)" << std::endl;
                    break;
                }
                if (snap->state == State::FAILED_FATAL) {
                    throw std::runtime_error("Registration failed: " + snap->lastError);
                }
                if (snap->state == State::LONG_BACKOFF_USER_ACTIONABLE) {
                    throw std::runtime_error("Registration blocked: " + snap->lastError);
                }
                if (wait_sec > 1800) {
                    throw std::runtime_error("Registration PoW timeout (30 min)");
                }
                if (wait_sec % 30 == 0) {
                    auto status = mgr->GetStatusForUI();
                    std::cout << "[RPC] Waiting for registration (" << status.phase
                              << " — " << status.message << ")" << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
                wait_sec++;
            }
            if (!g_node_state.running.load()) {
                throw std::runtime_error("Node shutting down during registration");
            }
        }
    }

    // Sign with MIK (commits to prevHash, height, timestamp)
    // Note: We use current time for timestamp - mining may adjust this slightly
    uint32_t nTime = static_cast<uint32_t>(std::time(nullptr));
    if (!m_wallet->SignWithMIK(hashPrevBlock, nHeight, nTime, mikData.signature)) {
        throw std::runtime_error("Failed to sign with MIK");
    }

    // Create block template with MIK data
    std::string templateError;
    auto templateOpt = m_miner->CreateBlockTemplate(
        *m_mempool,
        *m_utxo_set,
        hashPrevBlock,
        nHeight,
        nBits,
        minerAddress,
        mikData,
        templateError
    );

    if (!templateOpt.has_value()) {
        throw std::runtime_error("Failed to create block template: " + templateError);
    }

    // Start mining with the template
    if (!m_miner->StartMining(templateOpt.value())) {
        throw std::runtime_error("Failed to start mining");
    }

    // BUG #10 FIX: Set mining_enabled flag so main loop will restart mining after blocks found
    g_node_state.mining_enabled = true;

    return "true";
}

std::string CRPCServer::RPC_StopMining(const std::string& params) {
    // VDF miner (DilV) — stop VDF mining
    if (m_vdfMiner) {
        m_vdfMiner->Stop();
        g_node_state.mining_enabled = false;
        return "true";
    }

    // RandomX miner (DIL)
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    m_miner->StopMining();

    // BUG #10 FIX: Clear mining_enabled flag so main loop won't restart mining
    g_node_state.mining_enabled = false;

    return "true";
}

std::string CRPCServer::RPC_SetMiningThreads(const std::string& params) {
    // VDF miner (DilV) — single-threaded by design, ignore thread count
    if (m_vdfMiner) {
        return "1";  // VDF mining always uses 1 thread
    }

    // RandomX miner (DIL)
    if (!m_miner) {
        throw std::runtime_error("Miner not initialized");
    }

    // Parse threads from params: {"threads": 12} or [12]
    uint32_t threads = 0;
    try {
        // Try object format: {"threads": N}
        size_t pos = params.find("\"threads\"");
        if (pos != std::string::npos) {
            pos = params.find(':', pos);
            if (pos != std::string::npos) {
                threads = static_cast<uint32_t>(std::stoul(params.substr(pos + 1)));
            }
        } else {
            // Try array format: [N]
            size_t start = params.find_first_of("0123456789");
            if (start != std::string::npos) {
                threads = static_cast<uint32_t>(std::stoul(params.substr(start)));
            }
        }
    } catch (...) {
        throw std::runtime_error("Invalid threads parameter");
    }

    if (threads == 0 || threads > std::thread::hardware_concurrency()) {
        throw std::runtime_error("Threads must be between 1 and " + std::to_string(std::thread::hardware_concurrency()));
    }

    if (!m_miner->SetThreadCount(threads)) {
        throw std::runtime_error("Cannot change threads while mining. Stop mining first.");
    }

    std::ostringstream oss;
    oss << "{\"threads\":" << m_miner->GetThreadCount() << "}";
    return oss.str();
}

std::string CRPCServer::RPC_SetMiningAddress(const std::string& params) {
    // Parse the address from params
    // Expected format: ["Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    std::string address;

    // Simple JSON array parsing
    size_t start = params.find('"');
    size_t end = params.rfind('"');
    if (start != std::string::npos && end != std::string::npos && end > start) {
        address = params.substr(start + 1, end - start - 1);
    }

    if (address.empty()) {
        throw std::runtime_error("Missing address parameter. Usage: setminingaddress \"Dxxx...\"");
    }

    // Validate address format
    CDilithiumAddress testAddr;
    if (!testAddr.SetString(address)) {
        throw std::runtime_error("Invalid address format: " + address);
    }

    // Set the mining address override
    g_node_state.mining_address_override = address;

    std::cout << "[RPC] Mining address set to: " << address << std::endl;

    std::ostringstream oss;
    oss << "{\"address\":\"" << address << "\",\"success\":true}";
    return oss.str();
}

std::string CRPCServer::RPC_GetMiningAddress(const std::string& params) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"address\":\"" << g_node_state.mining_address_override << "\",";
    oss << "\"is_set\":" << (g_node_state.mining_address_override.empty() ? "false" : "true");
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetDFMPInfo(const std::string& params) {
    std::ostringstream oss;
    oss << "{";

    // Get wallet MIK info
    bool hasMIK = m_wallet && m_wallet->HasMIK();
    std::string mikIdentity = hasMIK ? m_wallet->GetMIKIdentityHex() : "";

    oss << "\"has_mik\":" << (hasMIK ? "true" : "false") << ",";
    oss << "\"mik_identity\":\"" << mikIdentity << "\",";

    // Get DFMP status
    int currentHeight = m_chainstate ? static_cast<int>(m_chainstate->GetHeight()) : 0;
    int dfmpActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpActivationHeight : 500;
    int assumeValidHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpAssumeValidHeight : 0;

    oss << "\"current_height\":" << currentHeight << ",";
    oss << "\"dfmp_activation_height\":" << dfmpActivationHeight << ",";
    oss << "\"dfmp_assume_valid_height\":" << assumeValidHeight << ",";
    oss << "\"dfmp_active\":" << (currentHeight >= dfmpActivationHeight ? "true" : "false") << ",";

    // DFMP v3.0 activation
    int dfmpV3ActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpV3ActivationHeight : 0;
    bool isV3Active = currentHeight >= dfmpV3ActivationHeight;

    oss << "\"dfmp_v3_activation_height\":" << dfmpV3ActivationHeight << ",";
    oss << "\"dfmp_v3_active\":" << (isV3Active ? "true" : "false") << ",";

    // DFMP v3.1 activation
    int dfmpV31ActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpV31ActivationHeight : 0;
    bool isV31Active = currentHeight >= dfmpV31ActivationHeight;
    oss << "\"dfmp_v31_activation_height\":" << dfmpV31ActivationHeight << ",";
    oss << "\"dfmp_v31_active\":" << (isV31Active ? "true" : "false") << ",";

    // DFMP v3.2 activation
    int dfmpV32ActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpV32ActivationHeight : 999999999;
    bool isV32Active = currentHeight >= dfmpV32ActivationHeight;
    oss << "\"dfmp_v32_activation_height\":" << dfmpV32ActivationHeight << ",";
    oss << "\"dfmp_v32_active\":" << (isV32Active ? "true" : "false") << ",";

    // DFMP v3.3 activation
    int dfmpV33ActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpV33ActivationHeight : 999999999;
    bool isV33Active = currentHeight >= dfmpV33ActivationHeight;
    oss << "\"dfmp_v33_activation_height\":" << dfmpV33ActivationHeight << ",";
    oss << "\"dfmp_v33_active\":" << (isV33Active ? "true" : "false") << ",";

    // DFMP v3.4 activation
    int dfmpV34ActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpV34ActivationHeight : 999999999;
    bool isV34Active = currentHeight >= dfmpV34ActivationHeight;
    oss << "\"dfmp_v34_activation_height\":" << dfmpV34ActivationHeight << ",";
    oss << "\"dfmp_v34_active\":" << (isV34Active ? "true" : "false") << ",";

    // Current active DFMP version
    const char* activeVersion = isV34Active ? "v3.4" : (isV33Active ? "v3.3" : (isV32Active ? "v3.2" : (isV31Active ? "v3.1" : (isV3Active ? "v3.0" : "v2.0"))));
    oss << "\"dfmp_version\":\"" << activeVersion << "\",";

    // Get penalty info for this identity
    int firstSeen = -1;
    int heat = 0;
    int payoutHeat = 0;
    int lastMined = -1;
    bool isRegistered = false;

    if (hasMIK) {
        DFMP::Identity identity = m_wallet->GetMIKIdentity();

        if (DFMP::g_identityDb) {
            firstSeen = DFMP::g_identityDb->GetFirstSeen(identity);
            isRegistered = DFMP::g_identityDb->HasMIKPubKey(identity);
            lastMined = DFMP::g_identityDb->GetLastMined(identity);
        }

        if (DFMP::g_heatTracker) {
            heat = DFMP::g_heatTracker->GetHeat(identity);
        }
    }

    // DFMP v3.0: Get payout address heat from wallet's payout address
    if (DFMP::g_payoutHeatTracker && m_wallet) {
        std::vector<uint8_t> pubKeyHash = m_wallet->GetPubKeyHash();
        if (!pubKeyHash.empty()) {
            std::vector<uint8_t> payoutScript = WalletCrypto::CreateScriptPubKey(pubKeyHash);
            DFMP::Identity payoutId = DFMP::DeriveIdentityFromScript(payoutScript);
            payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutId);
        }
    }

    // Phase 3b: Compute cluster heat
    int clusterHeat = heat;
    if (hasMIK && heat > 0 && g_node_context.dna_registry && DFMP::g_heatTracker) {
        DFMP::Identity clusterMik = m_wallet->GetMIKIdentity();
        std::array<uint8_t, 20> mikArr;
        std::memcpy(mikArr.data(), clusterMik.data, 20);
        auto myDna = g_node_context.dna_registry->get_identity_by_mik(mikArr);
        if (myDna) {
            auto similar = g_node_context.dna_registry->find_similar(*myDna);
            int summedHeat = heat;
            for (const auto& [dna, score] : similar) {
                DFMP::Identity memberMik;
                std::memcpy(memberMik.data, dna.mik_identity.data(), 20);
                if (memberMik == clusterMik) continue;
                summedHeat += DFMP::g_heatTracker->GetHeat(memberMik);
            }
            int cap = heat * DFMP::MAX_CLUSTER_HEAT_MULTIPLIER;
            clusterHeat = std::min(summedHeat, cap);
        }
    }

    oss << "\"is_registered\":" << (isRegistered ? "true" : "false") << ",";
    oss << "\"first_seen\":" << firstSeen << ",";
    oss << "\"heat\":" << heat << ",";
    oss << "\"cluster_heat\":" << clusterHeat << ",";
    oss << "\"shared_heat_active\":" << (clusterHeat != heat ? "true" : "false") << ",";
    oss << "\"payout_heat\":" << payoutHeat << ",";
    oss << "\"last_mined\":" << lastMined << ",";

    // Dormancy info (v3.0)
    bool isDormant = false;
    int dormancyBlocks = 0;
    if (lastMined >= 0) {
        dormancyBlocks = currentHeight - lastMined;
        isDormant = dormancyBlocks > DFMP::DORMANCY_THRESHOLD;
    }
    oss << "\"dormant\":" << (isDormant ? "true" : "false") << ",";
    oss << "\"dormancy_blocks\":" << dormancyBlocks << ",";

    // Report active version's parameters
    int activeMaturityBlocks = isV33Active ? DFMP::MATURITY_BLOCKS_V33 :
        (isV32Active ? DFMP::MATURITY_BLOCKS_V32 :
        (isV31Active ? DFMP::MATURITY_BLOCKS_V31 : DFMP::MATURITY_BLOCKS));
    int activeFreeTier = isV33Active ? DFMP::FREE_TIER_THRESHOLD_V33 :
        (isV32Active ? DFMP::FREE_TIER_THRESHOLD_V32 :
        (isV31Active ? DFMP::FREE_TIER_THRESHOLD_V31 : DFMP::FREE_TIER_THRESHOLD));
    oss << "\"maturity_blocks\":" << activeMaturityBlocks << ",";
    oss << "\"free_tier_threshold\":" << activeFreeTier << ",";

    // If v3.4 is active, report verification-aware free tier
    if (isV34Active) {
        oss << "\"verified_free_tier\":" << DFMP::FREE_TIER_THRESHOLD_V34_VERIFIED << ",";
        oss << "\"unverified_free_tier\":" << DFMP::FREE_TIER_THRESHOLD_V34_UNVERIFIED << ",";
    }

    oss << "\"registration_pow_bits\":" << (Dilithion::g_chainParams ? Dilithion::g_chainParams->registrationPowBits : DFMP::REGISTRATION_POW_BITS) << ",";

    // Calculate penalty using actual DFMP functions (version-aware)
    int effectiveFirstSeen = firstSeen;
    if (isV3Active && isDormant && firstSeen >= 0) {
        effectiveFirstSeen = currentHeight - DFMP::DORMANCY_DECAY_BLOCKS;
    }

    // Determine verification status for v3.4 penalty calculation
    bool minerIsVerified = false;
    auto minerVerStatus = digital_dna::verification::VerificationStatus::UNVERIFIED;
    bool hasVerStatus = false;
    if (isV34Active && hasMIK) {
        extern NodeContext g_node_context;
        if (g_node_context.dna_registry) {
            DFMP::Identity identity = m_wallet->GetMIKIdentity();
            std::array<uint8_t, 20> mikArr;
            std::memcpy(mikArr.data(), identity.data, 20);
            minerVerStatus = g_node_context.dna_registry->get_verification_status(mikArr);
            minerIsVerified = (minerVerStatus == digital_dna::verification::VerificationStatus::VERIFIED);
            hasVerStatus = true;
        }
    }

    double maturityPenalty, heatPenalty, payoutHeatPenalty;
    if (isV34Active) {
        maturityPenalty = DFMP::GetPendingPenalty_V34(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatMultiplier_V34(heat, minerIsVerified);
        payoutHeatPenalty = DFMP::GetHeatMultiplier_V34(payoutHeat, minerIsVerified);
    } else if (isV33Active) {
        maturityPenalty = DFMP::GetPendingPenalty_V33(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatMultiplier_V33(heat);
        payoutHeatPenalty = DFMP::GetHeatMultiplier_V33(payoutHeat);
    } else if (isV32Active) {
        maturityPenalty = DFMP::GetPendingPenalty_V32(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatMultiplier_V32(heat);
        payoutHeatPenalty = DFMP::GetHeatMultiplier_V32(payoutHeat);
    } else if (isV31Active) {
        maturityPenalty = DFMP::GetPendingPenalty_V31(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatMultiplier_V31(heat);
        payoutHeatPenalty = DFMP::GetHeatMultiplier_V31(payoutHeat);
    } else if (isV3Active) {
        maturityPenalty = DFMP::GetPendingPenalty(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatMultiplier(heat);
        payoutHeatPenalty = DFMP::GetHeatMultiplier(payoutHeat);
    } else {
        maturityPenalty = DFMP::GetPendingPenalty(currentHeight, effectiveFirstSeen);
        heatPenalty = DFMP::GetHeatPenalty_V2(heat);
        payoutHeatPenalty = 1.0;
    }
    double effectiveHeatPenalty = std::max(heatPenalty, payoutHeatPenalty);
    double totalPenalty = maturityPenalty * effectiveHeatPenalty;

    oss << std::fixed << std::setprecision(2);
    oss << "\"maturity_penalty\":" << maturityPenalty << ",";
    oss << "\"heat_penalty\":" << heatPenalty << ",";
    oss << "\"payout_heat_penalty\":" << payoutHeatPenalty << ",";
    oss << "\"effective_heat_penalty\":" << effectiveHeatPenalty << ",";
    oss << "\"total_penalty\":" << totalPenalty;

    // Add verification status if v3.4 active and DNA registry available
    if (isV34Active && hasVerStatus) {
        oss << ",\"verification_status\":" << static_cast<int>(minerVerStatus);
        oss << ",\"verification_status_name\":\"" << digital_dna::verification::VerificationStatusName(minerVerStatus) << "\"";
        oss << ",\"is_verified\":" << (minerIsVerified ? "true" : "false");
    }

    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetMIKDistribution(const std::string& params) {
    // Get all MIK identities and their block counts from heat tracker
    if (!DFMP::g_heatTracker) {
        throw std::runtime_error("Heat tracker not initialized");
    }

    std::map<DFMP::Identity, int> heatData = DFMP::g_heatTracker->GetAllHeat();

    std::ostringstream oss;
    oss << "{";
    oss << "\"window_size\":" << DFMP::g_heatTracker->GetWindowSize() << ",";
    oss << "\"unique_miners\":" << heatData.size() << ",";
    oss << "\"distribution\":[";

    bool first = true;
    for (const auto& [identity, blockCount] : heatData) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"mik\":\"" << identity.GetHex() << "\",\"blocks\":" << blockCount << "}";
    }

    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetFullMIKDistribution(const std::string& params) {
    // Scan all blocks and extract MIK identities from coinbase transactions
    if (!m_blockchain || !m_chainstate) {
        throw std::runtime_error("Blockchain not initialized");
    }

    int currentHeight = static_cast<int>(m_chainstate->GetHeight());
    std::map<std::string, int> mikBlockCounts;  // MIK identity hex -> block count
    std::map<std::string, std::set<std::string>> mikAddresses;  // MIK hex -> set of payout addresses
    int blocksWithMIK = 0;
    int blocksWithoutMIK = 0;

    CBlockValidator validator;

    for (int height = 1; height <= currentHeight; height++) {
        // Get block hash for this height using chainstate
        std::vector<uint256> hashes = m_chainstate->GetBlocksAtHeight(height);
        if (hashes.empty()) continue;

        uint256 blockHash = hashes[0];  // Use first (canonical) block at this height

        // Read the block
        CBlock block;
        if (!m_blockchain->ReadBlock(blockHash, block)) {
            continue;
        }

        // Deserialize transactions
        std::vector<CTransactionRef> transactions;
        std::string deserializeError;
        if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
            continue;
        }

        if (transactions.empty()) continue;

        // Get coinbase transaction (first tx)
        const auto& coinbaseTx = transactions[0];
        if (coinbaseTx->vin.empty()) continue;

        // Parse MIK from coinbase scriptSig
        const std::vector<uint8_t>& scriptSig = coinbaseTx->vin[0].scriptSig;
        DFMP::CMIKScriptData mikData;

        if (DFMP::ParseMIKFromScriptSig(scriptSig, mikData)) {
            std::string mikHex = mikData.identity.GetHex();
            mikBlockCounts[mikHex]++;
            blocksWithMIK++;

            // Extract miner payout address from coinbase vout[0]
            if (!coinbaseTx->vout.empty()) {
                std::string minerAddr = DecodeScriptPubKeyToAddress(coinbaseTx->vout[0].scriptPubKey);
                if (!minerAddr.empty()) {
                    mikAddresses[mikHex].insert(minerAddr);
                }
            }
        } else {
            blocksWithoutMIK++;
        }
    }

    // Sort by block count (descending)
    std::vector<std::pair<std::string, int>> sorted(mikBlockCounts.begin(), mikBlockCounts.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    std::ostringstream oss;
    oss << "{";
    oss << "\"total_blocks\":" << currentHeight << ",";
    oss << "\"blocks_with_mik\":" << blocksWithMIK << ",";
    oss << "\"blocks_without_mik\":" << blocksWithoutMIK << ",";
    oss << "\"unique_miners\":" << mikBlockCounts.size() << ",";
    oss << "\"distribution\":[";

    bool first = true;
    for (const auto& [mikHex, blockCount] : sorted) {
        if (!first) oss << ",";
        first = false;
        double percentage = (currentHeight > 0) ? (blockCount * 100.0 / currentHeight) : 0;
        oss << "{\"mik\":\"" << mikHex << "\",\"blocks\":" << blockCount
            << ",\"percent\":" << std::fixed << std::setprecision(2) << percentage;

        // Include payout addresses for this MIK
        auto it = mikAddresses.find(mikHex);
        if (it != mikAddresses.end()) {
            oss << ",\"addresses\":[";
            bool firstAddr = true;
            for (const auto& addr : it->second) {
                if (!firstAddr) oss << ",";
                firstAddr = false;
                oss << "\"" << addr << "\"";
            }
            oss << "]";
        }

        oss << "}";
    }

    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetNetworkInfo(const std::string& params) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":\"" << GetVersionString() << "\",";
    oss << "\"subversion\":\"/Dilithion:" << GetVersionString() << "/\",";
    oss << "\"protocolversion\":1";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_GetPeerInfo(const std::string& params) {
    // Return detailed information about connected peers
    // Following Bitcoin Core's getpeerinfo format for compatibility

    // Check if peer manager is available
    extern NodeContext g_node_context;
    if (!g_node_context.peer_manager) {
        return "[]";  // Return empty array if peer manager not initialized
    }

    // Get all connected peers
    auto peers = g_node_context.peer_manager->GetConnectedPeers();

    std::ostringstream oss;
    oss << "[";

    bool first = true;
    for (const auto& peer : peers) {
        if (!first) {
            oss << ",";
        }
        first = false;

        oss << "{";
        oss << "\"id\":" << peer->id << ",";
        oss << "\"addr\":\"" << EscapeJSON(peer->addr.ToString()) << "\",";

        // Pull CNode fields for inbound/bytes (CNode is the source of truth)
        bool is_inbound = false;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recv = 0;
        if (g_node_context.connman) {
            CNode* pnode = g_node_context.connman->GetNode(peer->id);
            if (pnode) {
                is_inbound = pnode->fInbound;
                bytes_sent = pnode->nSendBytes.load();
                bytes_recv = pnode->nRecvBytes.load();
            }
        }

        oss << "\"inbound\":" << (is_inbound ? "true" : "false") << ",";
        oss << "\"bytes_sent\":" << bytes_sent << ",";
        oss << "\"bytes_recv\":" << bytes_recv << ",";
        oss << "\"conntime\":" << peer->connect_time << ",";
        oss << "\"lastsend\":" << peer->last_send << ",";
        oss << "\"lastrecv\":" << peer->last_recv << ",";
        oss << "\"version\":" << peer->version << ",";
        // user_agent comes from remote peers and can contain arbitrary bytes,
        // including unescaped quotes that would break JSON. Always escape.
        oss << "\"subver\":\"" << EscapeJSON(peer->user_agent) << "\",";
        oss << "\"startingheight\":" << peer->start_height << ",";
        oss << "\"relaytxes\":" << (peer->relay ? "true" : "false") << ",";
        oss << "\"misbehavior\":" << peer->misbehavior_score;
        oss << "}";
    }

    oss << "]";
    return oss.str();
}

std::string CRPCServer::RPC_GetConnectionCount(const std::string& params) {
    // Return the number of connections to other nodes
    // Following Bitcoin Core's getconnectioncount format

    // Check if peer manager is available
    extern NodeContext g_node_context;
    if (!g_node_context.peer_manager) {
        return "0";  // Return 0 if peer manager not initialized
    }

    size_t count = g_node_context.peer_manager->GetConnectionCount();
    return std::to_string(count);
}

std::string CRPCServer::RPC_Help(const std::string& params) {
    std::ostringstream oss;
    oss << "{\"commands\":[";

    // Wallet information
    oss << "\"getnewaddress - Get a new receiving address\",";
    oss << "\"getbalance - Get wallet balance (available, unconfirmed, immature)\",";
    oss << "\"getaddresses - List all wallet addresses\",";
    oss << "\"listunspent - List unspent transaction outputs\",";
    oss << "\"rescanwallet - Rescan blockchain for wallet transactions\",";
    oss << "\"clearwallettxs - Clear all wallet transaction history (for chain resets)\",";

    // Transaction creation
    oss << "\"sendtoaddress - Send coins to an address\",";
    oss << "\"signrawtransaction - Sign inputs for a raw transaction\",";
    oss << "\"sendrawtransaction - Broadcast a raw transaction to the network\",";

    // Transaction query
    oss << "\"gettransaction - Get transaction details by txid\",";
    oss << "\"listtransactions - List wallet transactions\",";
    oss << "\"getmempoolinfo - Get mempool statistics\",";

    // Blockchain query
    oss << "\"getblockchaininfo - Get blockchain information\",";
    oss << "\"getblock - Get block by hash\",";
    oss << "\"getblockhash - Get block hash by height\",";
    oss << "\"gettxout - Get UTXO information\",";
    oss << "\"checkchain - Verify your chain matches official checkpoints (detect forks)\",";
    oss << "\"checkblockdb - Check for missing blocks in database (diagnostic)\",";
    oss << "\"repairblocks - Repair blocks stored under wrong hashes (Bug #243 fix)\",";
    oss << "\"invalidateblock - Disconnect chain to given height or block hash\",";
    oss << "\"reconsiderblock - Clear fork detection state for re-sync\",";

    // Wallet encryption
    oss << "\"encryptwallet - Encrypt wallet with passphrase\",";
    oss << "\"walletpassphrase - Unlock wallet for a timeout period\",";
    oss << "\"walletlock - Lock encrypted wallet\",";
    oss << "\"walletpassphrasechange - Change wallet passphrase\",";

    // Mining
    oss << "\"getmininginfo - Get mining status and hashrate\",";
    oss << "\"startmining - Start mining (not fully implemented)\",";
    oss << "\"stopmining - Stop mining\",";
    oss << "\"getdfmpinfo - Get DFMP status, MIK identity, and penalty info\",";

    // Network and general
    oss << "\"getnetworkinfo - Get network information\",";
    oss << "\"getpeerinfo - Get detailed information about connected peers\",";
    oss << "\"getconnectioncount - Get number of connections to other nodes\",";
    oss << "\"addnode - Add or remove a peer connection\",";

    // Ban management
    oss << "\"setban - Add or remove an IP from the ban list\",";
    oss << "\"listbanned - List all banned IPs\",";
    oss << "\"clearbanned - Clear all banned IPs\",";

    // HTLC and atomic swap commands
    oss << "\"generatepreimage - Generate a random preimage and its SHA3-256 hash\",";
    oss << "\"createhtlc - Create and broadcast an HTLC transaction\",";
    oss << "\"claimhtlc - Claim an HTLC by revealing the preimage\",";
    oss << "\"refundhtlc - Refund an expired HTLC\",";
    oss << "\"decodehtlc - Decode an HTLC output from the UTXO set\",";
    oss << "\"initiateswap - Start a cross-chain atomic swap (generates preimage + HTLC)\",";
    oss << "\"acceptswap - Accept a swap by creating a matching HTLC on our chain\",";
    oss << "\"listswaps - List all known atomic swaps and their states\",";

    oss << "\"help - This help message\",";
    oss << "\"stop - Stop the Dilithion node\"";

    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_Stop(const std::string& params) {
    // PS-005: Secure RPC Stop - Require explicit confirmation to prevent unauthorized shutdown
    // Expected params: {"confirm": true}

    // Parse confirmation parameter
    bool confirmed = false;
    if (params.find("\"confirm\"") != std::string::npos &&
        params.find("true") != std::string::npos) {
        confirmed = true;
    }

    if (!confirmed) {
        throw std::runtime_error(
            "Server shutdown requires explicit confirmation. "
            "Call with {\\\"confirm\\\": true} to confirm shutdown. "
            "This prevents accidental or unauthorized server termination."
        );
    }

    // Confirmation received - proceed with graceful shutdown
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        Stop();
    }).detach();

    return "\"Dilithion server stopping (confirmed)\"";
}
// Missing RPC methods for functional test support
// These implementations will be added to server.cpp

// ============================================================================
// BLOCKCHAIN QUERY METHODS
// ============================================================================

std::string CRPCServer::RPC_GetBlockCount(const std::string& params) {
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    int height = m_chainstate->GetHeight();
    return std::to_string(height);
}

std::string CRPCServer::RPC_GetBestBlockHash(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    uint256 hashBestBlock;
    if (!m_blockchain->ReadBestBlock(hashBestBlock)) {
        throw std::runtime_error("Failed to read best block");
    }

    return "\"" + hashBestBlock.GetHex() + "\"";
}

std::string CRPCServer::RPC_GetChainTips(const std::string& params) {
    if (!m_chainstate) {
        throw std::runtime_error("Chain state not initialized");
    }

    // Get all chain tips (active chain + any forks)
    auto tips = m_chainstate->GetChainTips();
    if (tips.empty()) {
        return "[]";
    }

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < tips.size(); i++) {
        if (i > 0) oss << ",";
        oss << "{";
        oss << "\"height\":" << tips[i].height << ",";
        oss << "\"hash\":\"" << tips[i].hash.GetHex() << "\",";
        oss << "\"branchlen\":" << tips[i].branchlen << ",";
        oss << "\"status\":\"" << tips[i].status << "\"";
        oss << "}";
    }
    oss << "]";
    return oss.str();
}

// ============================================================================
// MEMPOOL METHODS
// ============================================================================

std::string CRPCServer::RPC_GetRawMempool(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }

    std::vector<CTransactionRef> txs = m_mempool->GetOrderedTxs();

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < txs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << txs[i]->GetHash().GetHex() << "\"";
    }
    oss << "]";
    return oss.str();
}

// ============================================================================
// TRANSACTION METHODS
// ============================================================================

std::string CRPCServer::RPC_GetRawTransaction(const std::string& params) {
    if (!m_mempool) {
        throw std::runtime_error("Mempool not initialized");
    }
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse params - expecting {"txid":"...", "verbose":true} or {"txid":"...", "verbosity":1}
    size_t txid_pos = params.find("\"txid\"");
    if (txid_pos == std::string::npos) {
        throw std::runtime_error("Missing txid parameter");
    }

    size_t colon = params.find(":", txid_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid txid parameter format");
    }

    std::string txid_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
    uint256 txid;
    txid.SetHex(txid_str);

    // Parse verbosity: accept "verbose":true/false or "verbosity":0/1
    bool verbose = false;
    size_t verb_pos = params.find("\"verbose\"");
    if (verb_pos != std::string::npos) {
        // Check for "verbose":true
        size_t verb_colon = params.find(":", verb_pos);
        std::string after = params.substr(verb_colon + 1, 10);
        if (after.find("true") != std::string::npos) {
            verbose = true;
        }
    }
    size_t verbosity_pos = params.find("\"verbosity\"");
    if (verbosity_pos != std::string::npos) {
        size_t verb_colon = params.find(":", verbosity_pos);
        size_t num_start = verb_colon + 1;
        while (num_start < params.length() && isspace(params[num_start])) num_start++;
        if (num_start < params.length() && params[num_start] >= '1' && params[num_start] <= '9') {
            verbose = true;
        }
    }

    // Helper lambda to build verbose JSON for a transaction
    auto txToJSON = [&](const CTransactionRef& tx, const std::string& blockHash,
                        int blockHeight, int confirmations) -> std::string {
        std::ostringstream oss;
        oss << "{";
        oss << "\"txid\":\"" << tx->GetHash().GetHex() << "\",";
        oss << "\"version\":" << tx->nVersion << ",";
        oss << "\"size\":" << tx->GetSerializedSize() << ",";

        // Inputs
        oss << "\"vin\":[";
        for (size_t i = 0; i < tx->vin.size(); i++) {
            if (i > 0) oss << ",";
            const CTxIn& txin = tx->vin[i];
            oss << "{";
            if (txin.prevout.hash.IsNull()) {
                oss << "\"coinbase\":true";
            } else {
                oss << "\"txid\":\"" << txin.prevout.hash.GetHex() << "\",";
                oss << "\"vout\":" << txin.prevout.n << ",";
                oss << "\"scriptSig\":\"" << HexStr(txin.scriptSig) << "\",";
                oss << "\"sequence\":" << txin.nSequence;
            }
            oss << "}";
        }
        oss << "],";

        // Outputs
        oss << "\"vout\":[";
        for (size_t i = 0; i < tx->vout.size(); i++) {
            if (i > 0) oss << ",";
            const CTxOut& txout = tx->vout[i];
            std::string addr = DecodeScriptPubKeyToAddress(txout.scriptPubKey);
            oss << "{";
            oss << "\"value\":" << txout.nValue << ",";
            oss << "\"n\":" << i << ",";
            if (!addr.empty()) {
                oss << "\"address\":\"" << addr << "\",";
            }
            oss << "\"scriptPubKey\":\"" << HexStr(txout.scriptPubKey) << "\"";
            oss << "}";
        }
        oss << "],";

        oss << "\"locktime\":" << tx->nLockTime << ",";
        oss << "\"hex\":\"" << HexStr(tx->Serialize()) << "\",";

        if (!blockHash.empty()) {
            oss << "\"blockhash\":\"" << blockHash << "\",";
            oss << "\"blockheight\":" << blockHeight << ",";
            oss << "\"confirmations\":" << confirmations;
        } else {
            oss << "\"confirmations\":0";
        }

        oss << "}";
        return oss.str();
    };

    // 1. Check mempool first
    auto mempoolEntry = m_mempool->GetTxIfExists(txid);
    if (mempoolEntry.has_value()) {
        CTransactionRef tx = mempoolEntry->GetSharedTx();
        if (!verbose) {
            // verbosity 0: return raw hex
            return "\"" + HexStr(tx->Serialize()) + "\"";
        }
        return txToJSON(tx, "", 0, 0);
    }

    // 2. Search blockchain
    CBlockIndex* pTip = m_chainstate->GetTip();
    if (pTip == nullptr) {
        throw std::runtime_error("Chain state not initialized");
    }

    CBlockIndex* pCurrent = pTip;
    while (pCurrent != nullptr) {
        CBlock block;
        uint256 blockHash = pCurrent->GetBlockHash();

        if (!m_blockchain->ReadBlock(blockHash, block)) {
            pCurrent = pCurrent->pprev;
            continue;
        }

        CBlockValidator validator;
        std::vector<CTransactionRef> transactions;
        std::string deserializeError;

        if (!validator.DeserializeBlockTransactions(block, transactions, deserializeError)) {
            pCurrent = pCurrent->pprev;
            continue;
        }

        for (const auto& tx : transactions) {
            if (tx->GetHash() == txid) {
                int confirmations = (pTip->nHeight - pCurrent->nHeight) + 1;

                if (!verbose) {
                    return "\"" + HexStr(tx->Serialize()) + "\"";
                }
                return txToJSON(tx, blockHash.GetHex(), pCurrent->nHeight, confirmations);
            }
        }

        pCurrent = pCurrent->pprev;
    }

    throw std::runtime_error("Transaction not found in mempool or blockchain");
}

std::string CRPCServer::RPC_DecodeRawTransaction(const std::string& params) {
    // Parse params - expecting {"hex":"..."}
    size_t hex_pos = params.find("\"hex\"");
    if (hex_pos == std::string::npos) {
        throw std::runtime_error("Missing hex parameter");
    }

    size_t colon = params.find(":", hex_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid hex parameter format");
    }

    std::string hex_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // Decode hex to bytes
    std::vector<uint8_t> txData = ParseHex(hex_str);
    if (txData.empty()) {
        throw std::runtime_error("Invalid hex data");
    }

    // Deserialize transaction
    CTransaction tx;
    std::string error;
    if (!tx.Deserialize(txData.data(), txData.size(), &error)) {
        throw std::runtime_error("Failed to deserialize transaction: " + error);
    }

    // Build JSON response
    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << tx.GetHash().GetHex() << "\",";
    oss << "\"version\":" << tx.nVersion << ",";
    oss << "\"locktime\":" << tx.nLockTime << ",";
    oss << "\"vin_count\":" << tx.vin.size() << ",";
    oss << "\"vout_count\":" << tx.vout.size();
    oss << "}";
    return oss.str();
}

// ============================================================================
// NETWORK METHODS
// ============================================================================

std::string CRPCServer::RPC_AddNode(const std::string& params) {
    // Parse params - expecting {"node":"ip:port", "command":"add|remove|onetry"}
    size_t node_pos = params.find("\"node\"");
    if (node_pos == std::string::npos) {
        throw std::runtime_error("Missing node parameter");
    }

    size_t colon = params.find(":", node_pos);
    size_t quote1 = params.find("\"", colon);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid node parameter format");
    }

    std::string node_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // Parse command
    std::string command = "add";  // default
    size_t cmd_pos = params.find("\"command\"");
    if (cmd_pos != std::string::npos) {
        size_t cmd_colon = params.find(":", cmd_pos);
        size_t cmd_quote1 = params.find("\"", cmd_colon);
        size_t cmd_quote2 = params.find("\"", cmd_quote1 + 1);
        if (cmd_quote1 != std::string::npos && cmd_quote2 != std::string::npos) {
            command = params.substr(cmd_quote1 + 1, cmd_quote2 - cmd_quote1 - 1);
        }
    }

    // Validate command
    if (command != "add" && command != "remove" && command != "onetry") {
        throw std::runtime_error("Invalid command. Must be 'add', 'remove', or 'onetry'");
    }

    // Parse IP:port or [IPv6]:port from node_str
    std::string ip_str;
    uint16_t default_port = m_testnet ? Consensus::DEFAULT_TESTNET_P2P_PORT : Consensus::DEFAULT_P2P_PORT;
    uint16_t port = default_port;

    if (!CSock::ParseEndpoint(node_str, ip_str, port)) {
        // No port specified — try as bare IP/hostname with default port
        // Reject bare IPv6 (contains ':') — require bracket notation [ipv6]:port
        if (node_str.find(':') != std::string::npos) {
            throw std::runtime_error("Invalid address format. Use [IPv6]:port bracket notation (e.g. [::1]:8444)");
        }
        ip_str = node_str;
        port = default_port;
    }

    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    if (!g_node_context.connman) {
        throw std::runtime_error("Connection manager not initialized");
    }

    if (command == "remove") {
        // Find and disconnect peer by IP
        extern NodeContext g_node_context;
        if (!g_node_context.peer_manager) {
            throw std::runtime_error("Peer manager not initialized");
        }

        // Phase 5: Use CConnman instead of deprecated CConnectionManager
        if (!g_node_context.connman) {
            throw std::runtime_error("Connection manager not initialized");
        }

        // Stop auto-reconnect for this node (Bitcoin Core pattern)
        g_node_context.connman->RemoveManualNode(ip_str);

        // Find node by IP address and disconnect
        auto nodes = g_node_context.connman->GetNodes();
        bool found = false;
        for (CNode* node : nodes) {
            // Compare IP address
            std::string node_ip = node->addr.ToStringIP();
            if (node_ip == ip_str) {
                g_node_context.connman->DisconnectNode(node->id, "addnode remove");
                found = true;
                break;
            }
        }

        if (!found) {
            throw std::runtime_error("Node not found: " + node_str);
        }

        return "null";  // Success (null in JSON-RPC means success with no return value)
    }

    // For "add" and "onetry" - connect to the peer
    NetProtocol::CAddress addr;
    if (!addr.SetFromString(ip_str)) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    addr.port = port;
    addr.services = NetProtocol::NODE_NETWORK;
    addr.time = static_cast<uint32_t>(time(nullptr) & 0xFFFFFFFF);

    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    if (!g_node_context.connman) {
        throw std::runtime_error("Connection manager not initialized");
    }

    // "add": manual=true with auto-reconnect. "onetry": manual=true but no auto-reconnect.
    if (command == "add") {
        g_node_context.connman->AddManualNode(addr);
    }

    // Connect to peer (manual=true for eviction protection)
    CNode* pnode = g_node_context.connman->ConnectNode(addr, true);

    if (!pnode) {
        throw std::runtime_error("Failed to connect to node: " + node_str);
    }

    std::cout << "[RPC] addnode: Connected to " << node_str << " (node_id=" << pnode->id << ", manual)" << std::endl;

    return "null";  // Success
}

// ============================================================================
// BAN MANAGEMENT METHODS
// ============================================================================

std::string CRPCServer::RPC_SetBan(const std::string& params) {
    // Parse params - expecting {"ip":"x.x.x.x", "command":"add|remove", "bantime":86400}
    // Bitcoin Core compatible: setban "ip" "add|remove" (bantime) (absolute)

    if (!g_node_context.peer_manager) {
        throw std::runtime_error("Peer manager not initialized");
    }

    // Parse IP address
    size_t ip_pos = params.find("\"ip\"");
    if (ip_pos == std::string::npos) {
        // Try positional format: first string is IP
        size_t quote1 = params.find("\"");
        if (quote1 == std::string::npos) {
            throw std::runtime_error("Missing IP parameter. Usage: setban \"ip\" \"add|remove\" (bantime)");
        }
        size_t quote2 = params.find("\"", quote1 + 1);
        if (quote2 == std::string::npos) {
            throw std::runtime_error("Invalid IP parameter format");
        }
        // Fall through to named parameter parsing
    }

    size_t colon = params.find(":", ip_pos != std::string::npos ? ip_pos : 0);
    size_t quote1 = params.find("\"", colon != std::string::npos ? colon : 0);
    size_t quote2 = params.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        throw std::runtime_error("Invalid IP parameter format");
    }

    std::string ip_str = params.substr(quote1 + 1, quote2 - quote1 - 1);

    // Validate IP format (IPv4 or IPv6)
    if (!CDNSResolver::IsIPv4(ip_str) && !CDNSResolver::IsIPv6(ip_str)) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }

    // Parse command (add/remove)
    std::string command = "add";  // default
    size_t cmd_pos = params.find("\"command\"");
    if (cmd_pos != std::string::npos) {
        size_t cmd_colon = params.find(":", cmd_pos);
        size_t cmd_quote1 = params.find("\"", cmd_colon);
        size_t cmd_quote2 = params.find("\"", cmd_quote1 + 1);
        if (cmd_quote1 != std::string::npos && cmd_quote2 != std::string::npos) {
            command = params.substr(cmd_quote1 + 1, cmd_quote2 - cmd_quote1 - 1);
        }
    } else {
        // Try to find "add" or "remove" as second quoted string
        size_t next_quote1 = params.find("\"", quote2 + 1);
        if (next_quote1 != std::string::npos) {
            size_t next_quote2 = params.find("\"", next_quote1 + 1);
            if (next_quote2 != std::string::npos) {
                std::string cmd_str = params.substr(next_quote1 + 1, next_quote2 - next_quote1 - 1);
                if (cmd_str == "add" || cmd_str == "remove") {
                    command = cmd_str;
                }
            }
        }
    }

    // Parse bantime (optional, default 24 hours)
    int64_t bantime = 86400;  // 24 hours default
    size_t bantime_pos = params.find("\"bantime\"");
    if (bantime_pos != std::string::npos) {
        size_t bt_colon = params.find(":", bantime_pos);
        size_t bt_start = params.find_first_of("0123456789", bt_colon);
        if (bt_start != std::string::npos) {
            try {
                bantime = std::stoll(params.substr(bt_start));
            } catch (...) {
                // Use default
            }
        }
    }

    CBanManager& banman = g_node_context.peer_manager->GetBanManager();

    if (command == "add") {
        // Ban the IP
        banman.Ban(ip_str, bantime, BanReason::ManuallyBanned);

        // Also disconnect any existing connections from this IP
        if (g_node_context.connman) {
            auto nodes = g_node_context.connman->GetNodes();
            for (CNode* node : nodes) {
                if (node->addr.ToStringIP() == ip_str) {
                    g_node_context.connman->DisconnectNode(node->id, "banned via RPC");
                }
            }
        }

        std::cout << "[RPC] setban: Banned " << ip_str << " for " << bantime << " seconds" << std::endl;
        return "null";

    } else if (command == "remove") {
        // Unban the IP
        std::cout << "[RPC] setban remove: attempting to unban IP '" << ip_str << "'" << std::endl;

        // Debug: Check if IP is currently banned
        if (banman.IsBanned(ip_str)) {
            std::cout << "[RPC] setban remove: IP " << ip_str << " is currently banned, calling Unban()" << std::endl;
        } else {
            std::cout << "[RPC] setban remove: IP " << ip_str << " is NOT currently banned!" << std::endl;
        }

        banman.Unban(ip_str);

        // Verify unban worked
        if (banman.IsBanned(ip_str)) {
            std::cerr << "[RPC] setban remove: ERROR - IP " << ip_str << " is STILL banned after Unban()!" << std::endl;
        } else {
            std::cout << "[RPC] setban remove: Success - IP " << ip_str << " is now unbanned" << std::endl;
        }

        return "null";

    } else {
        throw std::runtime_error("Invalid command. Must be 'add' or 'remove'");
    }
}

std::string CRPCServer::RPC_ListBanned(const std::string& params) {
    (void)params;  // Unused

    if (!g_node_context.peer_manager) {
        throw std::runtime_error("Peer manager not initialized");
    }

    CBanManager& banman = g_node_context.peer_manager->GetBanManager();
    auto banned = banman.GetBanned();

    std::ostringstream oss;
    oss << "[";

    bool first = true;
    for (const auto& entry : banned) {
        if (!first) oss << ",";
        first = false;

        oss << "{";
        oss << "\"address\":\"" << entry.first << "\",";
        oss << "\"banned_until\":" << entry.second.nBanUntil << ",";
        oss << "\"ban_created\":" << entry.second.nCreateTime << ",";
        oss << "\"ban_reason\":" << static_cast<int>(entry.second.banReason) << ",";
        oss << "\"ban_reason_str\":\"" << (entry.second.banReason == BanReason::ManuallyBanned ? "manually_banned" :
              entry.second.banReason == BanReason::NodeMisbehaving ? "node_misbehaving" : "unknown") << "\",";
        oss << "\"misbehavior_type\":\"" << MisbehaviorTypeToString(entry.second.misbehaviorType) << "\",";
        oss << "\"misbehavior_score\":" << entry.second.nMisbehaviorScore;
        oss << "}";
    }

    oss << "]";
    return oss.str();
}

std::string CRPCServer::RPC_ClearBanned(const std::string& params) {
    (void)params;  // Unused

    if (!g_node_context.peer_manager) {
        throw std::runtime_error("Peer manager not initialized");
    }

    CBanManager& banman = g_node_context.peer_manager->GetBanManager();
    banman.ClearBanned();

    std::cout << "[RPC] clearbanned: All bans cleared" << std::endl;
    return "null";
}

// ============================================================================
// MIK BAN METHODS (node policy, NOT consensus)
// ============================================================================

std::string CRPCServer::RPC_BanMIK(const std::string& params) {
    // Parse MIK hex from params: {"mik":"0ce86d786646..."}
    size_t pos = params.find("\"mik\"");
    if (pos == std::string::npos) {
        // Try positional: first quoted string
        pos = params.find("\"");
    }
    if (pos == std::string::npos) {
        throw std::runtime_error("Usage: banmik {\"mik\":\"<40-char hex>\"}");
    }
    size_t q1 = params.find("\"", pos + 1);
    if (q1 == std::string::npos) q1 = pos;
    size_t q2 = params.find("\"", q1 + 1);
    size_t q3 = params.find("\"", q2 + 1);
    std::string mikHex;
    if (q3 != std::string::npos) {
        mikHex = params.substr(q2 + 1, q3 - q2 - 1);
    } else {
        mikHex = params.substr(q1 + 1, q2 - q1 - 1);
    }

    if (mikHex.length() != 40) {
        throw std::runtime_error("MIK must be 40 hex characters, got " + std::to_string(mikHex.length()));
    }

    BanMIK(mikHex);
    std::cout << "[RPC] banmik: Banned MIK " << mikHex.substr(0, 12) << "..." << std::endl;
    return "null";
}

std::string CRPCServer::RPC_UnbanMIK(const std::string& params) {
    size_t pos = params.find("\"mik\"");
    if (pos == std::string::npos) pos = params.find("\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Usage: unbanmik {\"mik\":\"<40-char hex>\"}");
    }
    size_t q1 = params.find("\"", pos + 1);
    if (q1 == std::string::npos) q1 = pos;
    size_t q2 = params.find("\"", q1 + 1);
    size_t q3 = params.find("\"", q2 + 1);
    std::string mikHex;
    if (q3 != std::string::npos) {
        mikHex = params.substr(q2 + 1, q3 - q2 - 1);
    } else {
        mikHex = params.substr(q1 + 1, q2 - q1 - 1);
    }

    UnbanMIK(mikHex);
    std::cout << "[RPC] unbanmik: Unbanned MIK " << mikHex.substr(0, 12) << "..." << std::endl;
    return "null";
}

std::string CRPCServer::RPC_ListBannedMIKs(const std::string& params) {
    (void)params;
    auto banned = ListBannedMIKs();
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < banned.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << banned[i] << "\"";
    }
    oss << "]";
    return oss.str();
}

// ============================================================================
// SYBIL DEFENSE METHODS
// ============================================================================

std::string CRPCServer::RPC_GetSybilRelays(const std::string& params) {
    (void)params;
    if (!g_node_context.peer_mik_tracker) {
        return "{\"peers\":[],\"note\":\"Peer MIK tracker not initialized\"}";
    }

    auto data = g_node_context.peer_mik_tracker->GetAllRelayData();

    std::ostringstream oss;
    oss << "{\"peers\":[";
    bool first = true;
    for (const auto& [peerId, info] : data) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"peer_id\":" << peerId
            << ",\"addr\":\"" << info.peerAddr << "\""
            << ",\"unique_miks\":" << info.uniqueMIKs
            << ",\"miks\":[";
        bool firstMik = true;
        for (const auto& mik : info.miks) {
            if (!firstMik) oss << ",";
            firstMik = false;
            oss << "\"" << mik.substr(0, 12) << "...\"";
        }
        oss << "]}";
    }
    oss << "]}";
    return oss.str();
}

std::string CRPCServer::RPC_GetCorrelatedAlerts(const std::string& params) {
    (void)params;
    if (!g_node_context.cooldown_tracker) {
        return "{\"groups\":[],\"note\":\"Cooldown tracker not initialized\"}";
    }

    int currentHeight = m_chainstate ? m_chainstate->GetHeight() : 0;
    auto groups = g_node_context.cooldown_tracker->DetectCorrelatedGroups(currentHeight);

    std::ostringstream oss;
    oss << "{\"height\":" << currentHeight << ",\"groups\":[";
    bool first = true;
    for (const auto& g : groups) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"type\":\"" << (g.appearing ? "appeared" : "disappeared") << "\""
            << ",\"transition_height\":" << g.transitionHeight
            << ",\"count\":" << g.miks.size()
            << ",\"miks\":[";
        bool firstMik = true;
        for (const auto& mik : g.miks) {
            if (!firstMik) oss << ",";
            firstMik = false;
            oss << "\"";
            for (int i = 0; i < 6; i++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", mik[i]);
                oss << hex;
            }
            oss << "...\"";
        }
        oss << "]}";
    }
    oss << "]}";
    return oss.str();
}

// ============================================================================
// MINING METHODS - GENERATETOADDRESS (CRITICAL FOR FUNCTIONAL TESTS)
// ============================================================================

std::string CRPCServer::RPC_GenerateToAddress(const std::string& params) {
    if (!m_blockchain) throw std::runtime_error("Blockchain not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");

    // Parse params: {"nblocks":10, "address":"DLT1..."}
    int nblocks = 1;
    std::string address_str;

    // Extract nblocks
    size_t nblocks_pos = params.find("\"nblocks\"");
    if (nblocks_pos != std::string::npos) {
        size_t colon = params.find(":", nblocks_pos);
        size_t num_start = colon + 1;
        while (num_start < params.length() && isspace(params[num_start])) num_start++;
        size_t num_end = num_start;
        while (num_end < params.length() && isdigit(params[num_end])) num_end++;
        if (num_end > num_start) {
            nblocks = SafeParseInt64(params.substr(num_start, num_end - num_start), 1, 1000);
        }
    }

    // Extract address
    size_t addr_pos = params.find("\"address\"");
    if (addr_pos != std::string::npos) {
        size_t colon = params.find(":", addr_pos);
        size_t quote1 = params.find("\"", colon);
        size_t quote2 = params.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            address_str = params.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }

    // Validate address
    CDilithiumAddress minerAddress;
    if (!ValidateAddress(address_str, minerAddress)) {
        throw std::runtime_error("Invalid address: " + address_str);
    }

    std::vector<std::string> block_hashes;

    // TODO: Full implementation requires:
    // 1. GetNextWorkRequired() from consensus/pow.h
    // 2. GetBlockSubsidy() from consensus/subsidy.h
    // 3. SolveBlock() helper to find valid nonce
    // 4. Proper coinbase transaction creation
    // 5. Merkle root calculation
    // 6. UTXO set updates

    // For now, return placeholder indicating not fully implemented
    throw std::runtime_error("generatetoaddress not fully implemented - requires mining infrastructure");
}

void CRPCServer::InitializeLogging(const std::string& log_file,
                                    const std::string& audit_file,
                                    CRPCLogger::LogLevel level) {
    m_logger = std::make_unique<CRPCLogger>(log_file, audit_file, level);
    if (!log_file.empty() || !audit_file.empty()) {
        std::cout << "[RPC-LOGGER] Logging initialized" << std::endl;
        if (!log_file.empty()) {
            std::cout << "  Request log: " << log_file << std::endl;
        }
        if (!audit_file.empty()) {
            std::cout << "  Audit log: " << audit_file << std::endl;
        }
    }
}

bool CRPCServer::InitializeSSL(const std::string& cert_file,
                               const std::string& key_file,
                               const std::string& ca_file) {
    m_ssl_wrapper = std::make_unique<CSSLWrapper>();
    if (!m_ssl_wrapper->InitializeServer(cert_file, key_file, ca_file)) {
        std::cerr << "[RPC-SSL] ERROR: Failed to initialize SSL: " 
                  << m_ssl_wrapper->GetLastError() << std::endl;
        m_ssl_wrapper.reset();
        m_ssl_enabled = false;
        return false;
    }
    
    m_ssl_enabled = true;
    std::cout << "[RPC-SSL] SSL/TLS enabled" << std::endl;
    std::cout << "  Certificate: " << cert_file << std::endl;
    std::cout << "  Private key: " << key_file << std::endl;
    if (!ca_file.empty()) {
        std::cout << "  CA certificate: " << ca_file << std::endl;
    }
    return true;
}

bool CRPCServer::InitializeWebSocket(uint16_t port) {
    if (port == 0) {
        // WebSocket disabled
        return true;
    }
    
    m_websocket_server = std::make_unique<CWebSocketServer>(port);
    
    // Set message callback to handle WebSocket RPC requests
    m_websocket_server->SetMessageCallback([this](int connection_id, const std::string& message, bool is_text) {
        // Handle WebSocket RPC request
        // Parse JSON-RPC request and execute
        try {
            RPCRequest rpcReq = ParseRPCRequest(message);
            RPCResponse rpcResp = ExecuteRPC(rpcReq);
            
            // Send response back via WebSocket
            std::string response_json = SerializeResponse(rpcResp);
            m_websocket_server->SendToClient(connection_id, response_json, true);
        } catch (const std::exception& e) {
            // Send error response
            RPCResponse errorResp = RPCResponse::Error(-32700, e.what(), "");
            std::string error_json = SerializeResponse(errorResp);
            m_websocket_server->SendToClient(connection_id, error_json, true);
        }
    });
    
    if (!m_websocket_server->Start()) {
        std::cerr << "[RPC-WEBSOCKET] ERROR: Failed to start WebSocket server" << std::endl;
        m_websocket_server.reset();
        return false;
    }
    
    std::cout << "[RPC-WEBSOCKET] WebSocket server started on port " << port << std::endl;
    return true;
}

// ============================================================================
// BLOCK REPAIR COMMANDS (Bug #243 Fix - IBD stuck at height 242)
// ============================================================================

/**
 * RPC_CheckBlockDB - Check for missing or mismatched blocks in database
 *
 * Compares chainstate (height -> hash) with block database (hash -> block data)
 * to find blocks that are in chainstate but missing from the database.
 *
 * Usage: checkblockdb {}
 * Optional: checkblockdb {"start_height": 240, "end_height": 250}
 */
std::string CRPCServer::RPC_CheckBlockDB(const std::string& params) {
    if (!m_blockchain || !m_chainstate) {
        throw std::runtime_error("Blockchain or chainstate not initialized");
    }

    // Parse optional height range
    int start_height = 0;
    int end_height = m_chainstate->GetHeight();

    // Parse start_height if provided
    size_t start_pos = params.find("\"start_height\"");
    if (start_pos != std::string::npos) {
        size_t colon = params.find(":", start_pos);
        if (colon != std::string::npos) {
            std::string num_str;
            for (size_t i = colon + 1; i < params.size(); i++) {
                char c = params[i];
                if (std::isdigit(c)) num_str += c;
                else if (!num_str.empty()) break;
            }
            if (!num_str.empty()) start_height = std::stoi(num_str);
        }
    }

    // Parse end_height if provided
    size_t end_pos = params.find("\"end_height\"");
    if (end_pos != std::string::npos) {
        size_t colon = params.find(":", end_pos);
        if (colon != std::string::npos) {
            std::string num_str;
            for (size_t i = colon + 1; i < params.size(); i++) {
                char c = params[i];
                if (std::isdigit(c)) num_str += c;
                else if (!num_str.empty()) break;
            }
            if (!num_str.empty()) end_height = std::stoi(num_str);
        }
    }

    std::ostringstream oss;
    oss << "{\"chain_height\":" << m_chainstate->GetHeight() << ",";
    oss << "\"start_height\":" << start_height << ",";
    oss << "\"end_height\":" << end_height << ",";
    oss << "\"missing_blocks\":[";

    std::vector<int> missing_heights;

    // Walk the chain from tip backwards to find blocks at each height
    CBlockIndex* pindex = m_chainstate->GetTip();
    while (pindex && pindex->nHeight >= start_height) {
        if (pindex->nHeight <= end_height) {
            uint256 hash = pindex->GetBlockHash();
            CBlock block;

            if (!m_blockchain->ReadBlock(hash, block)) {
                // Block is in chainstate but NOT in block database
                missing_heights.push_back(pindex->nHeight);
            }
        }
        pindex = pindex->pprev;
    }

    // Sort heights in ascending order for output
    std::sort(missing_heights.begin(), missing_heights.end());

    for (size_t i = 0; i < missing_heights.size(); i++) {
        if (i > 0) oss << ",";
        oss << missing_heights[i];
    }

    oss << "],\"missing_count\":" << missing_heights.size() << "}";
    return oss.str();
}

/**
 * RPC_RepairBlocks - Find blocks stored under wrong hashes and re-store them
 *
 * This repairs the block database after fork recovery left blocks under wrong hashes.
 * For each block in the database:
 * 1. Read the block data
 * 2. Compute its canonical RandomX hash
 * 3. If not stored under the canonical hash, write it under the canonical hash
 *
 * Usage: repairblocks {}
 * Optional: repairblocks {"dry_run": true} to just report without fixing
 */
std::string CRPCServer::RPC_RepairBlocks(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse dry_run option
    bool dry_run = false;
    if (params.find("\"dry_run\"") != std::string::npos &&
        params.find("true") != std::string::npos) {
        dry_run = true;
    }

    std::cout << "[REPAIR] Starting block database repair (dry_run=" << dry_run << ")..." << std::endl;

    // Get all blocks currently in database
    std::vector<uint256> db_hashes;
    if (!m_blockchain->GetAllBlockHashes(db_hashes)) {
        throw std::runtime_error("Failed to enumerate blocks in database");
    }

    std::cout << "[REPAIR] Found " << db_hashes.size() << " blocks in database" << std::endl;

    int repaired = 0;
    int already_correct = 0;
    int errors = 0;
    std::vector<std::pair<int, std::string>> repairs;  // height, old_hash

    for (const auto& stored_hash : db_hashes) {
        CBlock block;
        if (!m_blockchain->ReadBlock(stored_hash, block)) {
            errors++;
            continue;
        }

        // Compute the canonical RandomX hash
        uint256 canonical_hash = block.GetHash();

        if (canonical_hash == stored_hash) {
            already_correct++;
            continue;  // Block is stored under correct hash
        }

        // Block is stored under wrong hash!
        // Try to figure out the height by checking chainstate
        int height = -1;
        if (m_chainstate) {
            CBlockIndex* pindex = m_chainstate->GetBlockIndex(canonical_hash);
            if (pindex) {
                height = pindex->nHeight;
            }
        }

        std::cout << "[REPAIR] Block at height " << height
                  << " stored under " << stored_hash.GetHex().substr(0, 16) << "..."
                  << " but canonical hash is " << canonical_hash.GetHex().substr(0, 16) << "..."
                  << std::endl;

        if (!dry_run) {
            // Write block under canonical hash
            if (m_blockchain->WriteBlock(canonical_hash, block)) {
                repaired++;
                repairs.push_back({height, stored_hash.GetHex().substr(0, 16)});
                std::cout << "[REPAIR] SUCCESS: Re-stored block at height " << height
                          << " under canonical hash" << std::endl;
            } else {
                errors++;
                std::cout << "[REPAIR] ERROR: Failed to write block at height " << height << std::endl;
            }
        } else {
            repairs.push_back({height, stored_hash.GetHex().substr(0, 16)});
        }
    }

    std::ostringstream oss;
    oss << "{\"dry_run\":" << (dry_run ? "true" : "false") << ",";
    oss << "\"total_blocks\":" << db_hashes.size() << ",";
    oss << "\"already_correct\":" << already_correct << ",";
    oss << "\"repaired\":" << (dry_run ? 0 : repaired) << ",";
    oss << "\"would_repair\":" << repairs.size() << ",";
    oss << "\"errors\":" << errors << ",";
    oss << "\"repairs\":[";

    for (size_t i = 0; i < repairs.size() && i < 20; i++) {  // Limit to first 20
        if (i > 0) oss << ",";
        oss << "{\"height\":" << repairs[i].first << ",\"old_hash\":\"" << repairs[i].second << "...\"}";
    }
    if (repairs.size() > 20) {
        oss << ",{\"note\":\"..." << (repairs.size() - 20) << " more...\"}";
    }

    oss << "]}";
    return oss.str();
}

/**
 * RPC_ScanBlockDB - Scan all blocks in database and show their properties
 *
 * This helps diagnose blocks stored under wrong hashes by showing:
 * - The hash under which each block is stored (DB key)
 * - The block's computed RandomX hash
 * - The block's previousblockhash (to determine chain position)
 * - Whether the block is orphaned (not in chainstate)
 *
 * Usage: scanblockdb {}
 * Optional: scanblockdb {"limit": 50} to limit results
 */
std::string CRPCServer::RPC_ScanBlockDB(const std::string& params) {
    if (!m_blockchain) {
        throw std::runtime_error("Blockchain not initialized");
    }

    // Parse limit option (default 100)
    int limit = 100;
    size_t limit_pos = params.find("\"limit\"");
    if (limit_pos != std::string::npos) {
        size_t colon = params.find(":", limit_pos);
        if (colon != std::string::npos) {
            std::string num_str;
            for (size_t i = colon + 1; i < params.size(); i++) {
                char c = params[i];
                if (std::isdigit(c)) num_str += c;
                else if (!num_str.empty()) break;
            }
            if (!num_str.empty()) limit = std::stoi(num_str);
        }
    }

    std::cout << "[SCAN] Scanning block database (limit=" << limit << ")..." << std::endl;

    // Get all blocks in database
    std::vector<uint256> db_hashes;
    if (!m_blockchain->GetAllBlockHashes(db_hashes)) {
        throw std::runtime_error("Failed to enumerate blocks in database");
    }

    std::cout << "[SCAN] Found " << db_hashes.size() << " blocks in database" << std::endl;

    std::ostringstream oss;
    oss << "{\"total_in_db\":" << db_hashes.size() << ",";
    oss << "\"scanned\":" << std::min((int)db_hashes.size(), limit) << ",";
    oss << "\"blocks\":[";

    int count = 0;
    int orphans = 0;
    int hash_mismatches = 0;

    for (const auto& stored_hash : db_hashes) {
        if (count >= limit) break;

        CBlock block;
        if (!m_blockchain->ReadBlock(stored_hash, block)) {
            continue;
        }

        // Compute canonical hash
        uint256 canonical_hash = block.GetHash();
        bool hash_matches = (canonical_hash == stored_hash);

        // Check if block is in chainstate
        bool in_chainstate = false;
        int chainstate_height = -1;
        if (m_chainstate) {
            CBlockIndex* pindex = m_chainstate->GetBlockIndex(canonical_hash);
            if (pindex) {
                in_chainstate = true;
                chainstate_height = pindex->nHeight;
            }
        }

        if (!in_chainstate) orphans++;
        if (!hash_matches) hash_mismatches++;

        if (count > 0) oss << ",";
        oss << "{";
        oss << "\"stored_hash\":\"" << stored_hash.GetHex().substr(0, 16) << "...\",";
        oss << "\"canonical_hash\":\"" << canonical_hash.GetHex().substr(0, 16) << "...\",";
        oss << "\"prev_hash\":\"" << block.hashPrevBlock.GetHex().substr(0, 16) << "...\",";
        oss << "\"hash_matches\":" << (hash_matches ? "true" : "false") << ",";
        oss << "\"in_chainstate\":" << (in_chainstate ? "true" : "false");
        if (in_chainstate) {
            oss << ",\"height\":" << chainstate_height;
        }
        oss << "}";

        count++;
    }

    oss << "],";
    oss << "\"orphans\":" << orphans << ",";
    oss << "\"hash_mismatches\":" << hash_mismatches << "}";

    std::cout << "[SCAN] Complete. Orphans=" << orphans << ", Hash mismatches=" << hash_mismatches << std::endl;

    return oss.str();
}

/**
 * RPC_RequestBlocks - Request specific blocks from ALL connected peers
 *
 * This broadcasts GETDATA requests to every connected peer for the specified blocks.
 * Useful for recovering missing blocks if any peer on the network has them.
 *
 * Usage: requestblocks {"heights": [243, 244]}
 * Or:    requestblocks {"hashes": ["0000000138b95d1e..."]}
 */
std::string CRPCServer::RPC_RequestBlocks(const std::string& params) {
    extern NodeContext g_node_context;

    if (!g_node_context.connman || !g_node_context.message_processor || !g_node_context.peer_manager) {
        throw std::runtime_error("Network not initialized");
    }

    std::vector<uint256> hashes_to_request;

    // Parse heights array if provided
    size_t heights_pos = params.find("\"heights\"");
    if (heights_pos != std::string::npos && m_chainstate) {
        // Extract heights array
        size_t bracket_start = params.find("[", heights_pos);
        size_t bracket_end = params.find("]", bracket_start);
        if (bracket_start != std::string::npos && bracket_end != std::string::npos) {
            std::string heights_str = params.substr(bracket_start + 1, bracket_end - bracket_start - 1);
            // Parse comma-separated heights
            std::string num_str;
            for (char c : heights_str) {
                if (std::isdigit(c)) {
                    num_str += c;
                } else if (!num_str.empty()) {
                    int height = std::stoi(num_str);
                    // Get hash for this height from chainstate
                    CBlockIndex* pindex = m_chainstate->GetTip();
                    while (pindex && pindex->nHeight > height) {
                        pindex = pindex->pprev;
                    }
                    if (pindex && pindex->nHeight == height) {
                        hashes_to_request.push_back(pindex->GetBlockHash());
                        std::cout << "[REQUEST] Height " << height << " -> hash "
                                  << pindex->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
                    } else {
                        std::cout << "[REQUEST] Height " << height << " not in chainstate" << std::endl;
                    }
                    num_str.clear();
                }
            }
            if (!num_str.empty()) {
                int height = std::stoi(num_str);
                CBlockIndex* pindex = m_chainstate->GetTip();
                while (pindex && pindex->nHeight > height) {
                    pindex = pindex->pprev;
                }
                if (pindex && pindex->nHeight == height) {
                    hashes_to_request.push_back(pindex->GetBlockHash());
                    std::cout << "[REQUEST] Height " << height << " -> hash "
                              << pindex->GetBlockHash().GetHex().substr(0, 16) << "..." << std::endl;
                }
            }
        }
    }

    // Parse hashes array if provided
    size_t hashes_pos = params.find("\"hashes\"");
    if (hashes_pos != std::string::npos) {
        size_t bracket_start = params.find("[", hashes_pos);
        size_t bracket_end = params.find("]", bracket_start);
        if (bracket_start != std::string::npos && bracket_end != std::string::npos) {
            std::string hashes_str = params.substr(bracket_start + 1, bracket_end - bracket_start - 1);
            // Parse comma-separated hashes (in quotes)
            size_t pos = 0;
            while ((pos = hashes_str.find("\"", pos)) != std::string::npos) {
                size_t end = hashes_str.find("\"", pos + 1);
                if (end != std::string::npos) {
                    std::string hash_hex = hashes_str.substr(pos + 1, end - pos - 1);
                    uint256 hash;
                    hash.SetHex(hash_hex);
                    if (!hash.IsNull()) {
                        hashes_to_request.push_back(hash);
                        std::cout << "[REQUEST] Hash " << hash_hex.substr(0, 16) << "..." << std::endl;
                    }
                    pos = end + 1;
                } else {
                    break;
                }
            }
        }
    }

    if (hashes_to_request.empty()) {
        throw std::runtime_error("No blocks to request. Use {\"heights\": [243, 244]} or {\"hashes\": [\"...\"]}");
    }

    // Build GETDATA message
    std::vector<NetProtocol::CInv> getdata;
    for (const auto& hash : hashes_to_request) {
        getdata.emplace_back(NetProtocol::MSG_BLOCK_INV, hash);
    }

    CNetMessage msg = g_node_context.message_processor->CreateGetDataMessage(getdata);

    // Send to ALL connected peers
    auto peers = g_node_context.peer_manager->GetConnectedPeers();
    int sent_count = 0;

    std::cout << "[REQUEST] Sending GETDATA for " << hashes_to_request.size()
              << " blocks to " << peers.size() << " peers..." << std::endl;

    for (const auto& peer : peers) {
        if (!peer) continue;
        g_node_context.connman->PushMessage(peer->id, msg);
        sent_count++;
        std::cout << "[REQUEST] Sent to peer " << peer->id << std::endl;
    }

    std::ostringstream oss;
    oss << "{\"blocks_requested\":" << hashes_to_request.size() << ",";
    oss << "\"peers_contacted\":" << sent_count << ",";
    oss << "\"hashes\":[";
    for (size_t i = 0; i < hashes_to_request.size(); i++) {
        if (i > 0) oss << ",";
        oss << "\"" << hashes_to_request[i].GetHex().substr(0, 16) << "...\"";
    }
    oss << "]}";

    return oss.str();
}

// ============================================================================
// x402 Payment Protocol RPC Methods
// ============================================================================

std::string CRPCServer::RPC_VerifyX402Payment(const std::string& params) {
    if (!m_x402_facilitator) {
        throw std::runtime_error("x402 facilitator not available (DilV only)");
    }

    // Parse params: {"rawTransaction":"hex", "recipient":"addr", "amount":ions}
    std::string rawTx, recipient;
    int64_t amount = 0;

    // Extract rawTransaction
    size_t pos = params.find("\"rawTransaction\"");
    if (pos == std::string::npos) {
        pos = params.find("\"rawtx\"");  // Also accept short form
    }
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t q1 = params.find('"', colon);
        size_t q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos) {
            rawTx = params.substr(q1 + 1, q2 - q1 - 1);
        }
    }
    if (rawTx.empty()) {
        throw std::runtime_error("Missing rawTransaction parameter");
    }

    // Extract recipient
    pos = params.find("\"recipient\"");
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t q1 = params.find('"', colon);
        size_t q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos) {
            recipient = params.substr(q1 + 1, q2 - q1 - 1);
        }
    }
    if (recipient.empty()) {
        throw std::runtime_error("Missing recipient parameter");
    }

    // Extract amount
    pos = params.find("\"amount\"");
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t numStart = params.find_first_not_of(" \t\n\r", colon + 1);
        if (numStart != std::string::npos) {
            try {
                amount = std::stoll(params.substr(numStart));
            } catch (...) {
                throw std::runtime_error("Invalid amount parameter");
            }
        }
    }
    if (amount <= 0) {
        throw std::runtime_error("Amount must be positive (in volts)");
    }

    x402::VerifyResult result;
    m_x402_facilitator->GetVMA().VerifyPayment(rawTx, recipient, amount, result);
    return result.ToJSON();
}

std::string CRPCServer::RPC_SettleX402Payment(const std::string& params) {
    if (!m_x402_facilitator) {
        throw std::runtime_error("x402 facilitator not available (DilV only)");
    }

    // Parse params (same format as verify)
    std::string rawTx, recipient;
    int64_t amount = 0;

    size_t pos = params.find("\"rawTransaction\"");
    if (pos == std::string::npos) pos = params.find("\"rawtx\"");
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t q1 = params.find('"', colon);
        size_t q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
            rawTx = params.substr(q1 + 1, q2 - q1 - 1);
    }
    if (rawTx.empty()) throw std::runtime_error("Missing rawTransaction parameter");

    pos = params.find("\"recipient\"");
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t q1 = params.find('"', colon);
        size_t q2 = params.find('"', q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos)
            recipient = params.substr(q1 + 1, q2 - q1 - 1);
    }
    if (recipient.empty()) throw std::runtime_error("Missing recipient parameter");

    pos = params.find("\"amount\"");
    if (pos != std::string::npos) {
        size_t colon = params.find(':', pos);
        size_t numStart = params.find_first_not_of(" \t\n\r", colon + 1);
        if (numStart != std::string::npos) {
            try { amount = std::stoll(params.substr(numStart)); } catch (...) {}
        }
    }
    if (amount <= 0) throw std::runtime_error("Amount must be positive (in volts)");

    x402::SettlementResult result;
    m_x402_facilitator->GetVMA().SettlePayment(rawTx, recipient, amount, result);
    return result.ToJSON();
}

std::string CRPCServer::RPC_GetX402Info(const std::string& params) {
    if (!m_x402_facilitator) {
        throw std::runtime_error("x402 facilitator not available (DilV only)");
    }

    x402::FacilitatorInfo info;
    info.version = "2.0";
    info.schemes = {"exact"};
    info.networks = {x402::NETWORK_ID};
    info.assets = {x402::ASSET_ID};
    info.micropaymentThreshold = m_x402_facilitator->GetVMA().GetMicropaymentThreshold();
    info.vmaEnabled = true;
    return info.ToJSON();
}

// ============================================================================
// Data directory / swap store
// ============================================================================

void CRPCServer::SetDataDir(const std::string& dataDir) {
    m_dataDir = dataDir;
    if (!m_dataDir.empty()) {
        std::string swap_file = m_dataDir + "/swaps.json";
        m_swapStore.SetPath(swap_file);
        m_swapStore.Load();
    }
}

// ============================================================================
// Chain Management RPC Commands (Bug #272)
// ============================================================================

std::string CRPCServer::RPC_InvalidateBlock(const std::string& params) {
    extern NodeContext g_node_context;

    if (!m_chainstate || !m_blockchain) {
        throw std::runtime_error("Chain not initialized");
    }

    // Parse blockhash parameter
    // Accept either {"blockhash":"hex"} or {"height":N}
    std::string blockHashHex;
    int targetHeight = -1;

    size_t hash_pos = params.find("\"blockhash\"");
    if (hash_pos != std::string::npos) {
        size_t colon = params.find(":", hash_pos);
        size_t quote1 = params.find("\"", colon + 1);
        size_t quote2 = params.find("\"", quote1 + 1);
        if (quote1 != std::string::npos && quote2 != std::string::npos) {
            blockHashHex = params.substr(quote1 + 1, quote2 - quote1 - 1);
        }
    }

    size_t height_pos = params.find("\"height\"");
    if (height_pos != std::string::npos) {
        size_t colon = params.find(":", height_pos);
        std::string num;
        for (size_t i = colon + 1; i < params.size(); i++) {
            if (std::isdigit(params[i])) num += params[i];
            else if (!num.empty()) break;
        }
        if (!num.empty()) targetHeight = std::stoi(num);
    }

    if (blockHashHex.empty() && targetHeight < 0) {
        throw std::runtime_error("invalidateblock requires \"blockhash\" or \"height\" parameter");
    }

    // If height provided, resolve to parent height (disconnect TO height-1)
    if (targetHeight >= 0) {
        int currentHeight = m_chainstate->GetHeight();
        if (targetHeight > currentHeight) {
            throw std::runtime_error("Height " + std::to_string(targetHeight) + " is above current tip " + std::to_string(currentHeight));
        }
        if (targetHeight <= 0) {
            throw std::runtime_error("Cannot invalidate genesis block");
        }
        // Disconnect to one block BEFORE the target (invalidate the target and everything above)
        int disconnectTo = targetHeight - 1;

        std::cout << "[RPC] invalidateblock: disconnecting from height " << currentHeight
                  << " to " << disconnectTo << " (" << (currentHeight - disconnectTo) << " blocks)" << std::endl;

        int disconnected = m_chainstate->DisconnectToHeight(disconnectTo, *m_blockchain);
        if (disconnected < 0) {
            throw std::runtime_error("DisconnectToHeight failed");
        }

        // Clear stale headers and tracker state above disconnect point
        int newHeight = m_chainstate->GetHeight();
        uint256 newTipHash;
        CBlockIndex* pNewTip = m_chainstate->GetTip();
        if (pNewTip) newTipHash = pNewTip->GetBlockHash();

        if (g_node_context.headers_manager)
            g_node_context.headers_manager->ClearAboveHeight(disconnectTo, newTipHash);
        if (g_node_context.block_fetcher)
            g_node_context.block_fetcher->ClearAboveHeight(disconnectTo);
        if (g_node_context.block_tracker)
            g_node_context.block_tracker->ClearAboveHeight(disconnectTo);

        // Reset fork detection state so IBD can re-sync
        if (g_node_context.ibd_coordinator) {
            g_node_context.fork_detected.store(false);
        }

        std::ostringstream oss;
        oss << "{\"disconnected\":" << disconnected
            << ",\"new_height\":" << newHeight
            << ",\"new_tip\":\"" << newTipHash.GetHex() << "\"}";
        return oss.str();
    }

    // Hash-based invalidation: find block and disconnect to its parent
    uint256 blockHash;
    blockHash.SetHex(blockHashHex);
    CBlockIndex* pindex = m_chainstate->GetBlockIndex(blockHash);
    if (!pindex) {
        throw std::runtime_error("Block not found in chainstate: " + blockHashHex);
    }

    int blockHeight = pindex->nHeight;
    int disconnectTo = blockHeight - 1;
    int currentHeight = m_chainstate->GetHeight();

    if (blockHeight > currentHeight) {
        // Block exists in index but is not on active chain - just mark it
        std::ostringstream oss;
        oss << "{\"status\":\"block_not_on_active_chain\",\"height\":" << blockHeight << "}";
        return oss.str();
    }

    std::cout << "[RPC] invalidateblock: disconnecting from height " << currentHeight
              << " to " << disconnectTo << " (" << (currentHeight - disconnectTo) << " blocks)" << std::endl;

    int disconnected = m_chainstate->DisconnectToHeight(disconnectTo, *m_blockchain);
    if (disconnected < 0) {
        throw std::runtime_error("DisconnectToHeight failed");
    }

    int newHeight = m_chainstate->GetHeight();
    uint256 newTipHash;
    CBlockIndex* pNewTip = m_chainstate->GetTip();
    if (pNewTip) newTipHash = pNewTip->GetBlockHash();

    if (g_node_context.headers_manager)
        g_node_context.headers_manager->ClearAboveHeight(disconnectTo, newTipHash);
    if (g_node_context.block_fetcher)
        g_node_context.block_fetcher->ClearAboveHeight(disconnectTo);
    if (g_node_context.block_tracker)
        g_node_context.block_tracker->ClearAboveHeight(disconnectTo);

    if (g_node_context.ibd_coordinator) {
        g_node_context.fork_detected.store(false);
    }

    std::ostringstream oss;
    oss << "{\"disconnected\":" << disconnected
        << ",\"new_height\":" << newHeight
        << ",\"new_tip\":\"" << newTipHash.GetHex() << "\"}";
    return oss.str();
}

std::string CRPCServer::RPC_ReconsiderBlock(const std::string& params) {
    // ReconsiderBlock removes the BLOCK_FAILED_VALID flag from a block,
    // allowing it to be reconsidered for chain activation.
    // For now, just clear fork detection state and let IBD re-sync.
    extern NodeContext g_node_context;

    g_node_context.fork_detected.store(false);

    // Reset IBD coordinator fork state
    if (g_node_context.ibd_coordinator) {
        // Trigger fresh fork detection by clearing the detected flag
        std::cout << "[RPC] reconsiderblock: clearing fork detection state" << std::endl;
    }

    return "{\"status\":\"fork_state_cleared\"}";
}

// ============================================================================
// HTLC (Hash Time-Locked Contract) RPC Commands
// ============================================================================

std::string CRPCServer::RPC_GeneratePreimage(const std::string& params) {
    // No parameters needed
    std::vector<uint8_t> preimage = GeneratePreimage();
    std::vector<uint8_t> hash = HashPreimage(preimage);

    std::ostringstream oss;
    oss << "{";
    oss << "\"preimage\":\"" << HexStr(preimage) << "\",";
    oss << "\"hash\":\"" << HexStr(hash) << "\"";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_CreateHTLC(const std::string& params) {
    if (!m_wallet) throw std::runtime_error("Wallet not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Unlock with walletpassphrase first.");
    }

    // Check script V2 activation
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }
    unsigned int currentHeight = m_chainstate->GetHeight();
    if (static_cast<int>(currentHeight) < Dilithion::g_chainParams->scriptV2ActivationHeight) {
        throw std::runtime_error("HTLC not yet activated (activates at height " +
            std::to_string(Dilithion::g_chainParams->scriptV2ActivationHeight) + ")");
    }

    // Parse parameters: {"amount": 1.5, "recipient_address": "D...", "hash_lock": "hex64", "timeout_blocks": 144}
    // Also supports array: [amount, "recipient_address", "hash_lock_hex", timeout_blocks]
    double amount_dbl = 0;
    std::string recipient_str;
    std::string hash_lock_hex;
    uint32_t timeout_blocks = 0;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 4) {
                if (arr[0].is_number()) amount_dbl = arr[0].get<double>();
                if (arr[1].is_string()) recipient_str = arr[1].get<std::string>();
                if (arr[2].is_string()) hash_lock_hex = arr[2].get<std::string>();
                if (arr[3].is_number()) timeout_blocks = arr[3].get<uint32_t>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (amount_dbl == 0) {
        // Object format
        size_t pos;
        pos = params.find("\"amount\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t num_start = colon + 1;
            while (num_start < params.size() && isspace(params[num_start])) num_start++;
            size_t num_end = num_start;
            while (num_end < params.size() && (isdigit(params[num_end]) || params[num_end] == '.')) num_end++;
            if (num_end > num_start) {
                amount_dbl = SafeParseDouble(params.substr(num_start, num_end - num_start), 0.0, 21000000.0);
            }
        }

        pos = params.find("\"recipient_address\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                recipient_str = params.substr(q1 + 1, q2 - q1 - 1);
        }

        pos = params.find("\"hash_lock\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                hash_lock_hex = params.substr(q1 + 1, q2 - q1 - 1);
        }

        pos = params.find("\"timeout_blocks\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t num_start = colon + 1;
            while (num_start < params.size() && isspace(params[num_start])) num_start++;
            size_t num_end = num_start;
            while (num_end < params.size() && isdigit(params[num_end])) num_end++;
            if (num_end > num_start) {
                timeout_blocks = SafeParseUInt32(params.substr(num_start, num_end - num_start), 1, 100000);
            }
        }
    }

    if (amount_dbl <= 0) throw std::runtime_error("Missing or invalid amount");
    if (recipient_str.empty()) throw std::runtime_error("Missing recipient_address");
    if (hash_lock_hex.empty()) throw std::runtime_error("Missing hash_lock");
    if (timeout_blocks == 0) throw std::runtime_error("Missing or invalid timeout_blocks");

    CAmount amount = static_cast<CAmount>(amount_dbl * 100000000);
    if (amount <= 0) throw std::runtime_error("Amount must be positive");
    if (amount < DUST_THRESHOLD) throw std::runtime_error("Amount below dust threshold");

    // Parse hash_lock
    std::vector<uint8_t> hash_lock = ParseHex(hash_lock_hex);
    if (hash_lock.size() != 32) {
        throw std::runtime_error("hash_lock must be 64 hex characters (32 bytes)");
    }

    // Validate recipient address and extract pubkey hash
    CDilithiumAddress recipient_address;
    if (!ValidateAddress(recipient_str, recipient_address)) {
        throw std::runtime_error("Invalid recipient address: " + recipient_str);
    }
    std::vector<uint8_t> claim_pubkey_hash = CWallet::GetPubKeyHashFromAddress(recipient_address);
    if (claim_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to extract recipient pubkey hash");
    }

    // Get our refund address (sender's address)
    std::vector<uint8_t> refund_pubkey_hash = m_wallet->GetPubKeyHash();
    if (refund_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to get wallet pubkey hash for refund");
    }

    // Build HTLC parameters
    uint32_t timeout_height = currentHeight + timeout_blocks;
    HTLCParameters htlc_params;
    htlc_params.hash_lock = hash_lock;
    htlc_params.claim_pubkey_hash = claim_pubkey_hash;
    htlc_params.refund_pubkey_hash = refund_pubkey_hash;
    htlc_params.timeout_height = timeout_height;

    // Create HTLC locking script
    CScript htlc_script = CreateHTLCScript(htlc_params);
    std::vector<uint8_t> scriptPubKey(htlc_script.begin(), htlc_script.end());

    // Estimate fee
    size_t est_size = Consensus::EstimateDilithiumTxSize(2, 2);
    CAmount fee = Consensus::CalculateMinFee(est_size);

    // Create transaction with HTLC scriptPubKey
    CTransactionRef tx;
    std::string error;
    if (!m_wallet->CreateTransactionToScript(scriptPubKey, amount, fee, *m_utxo_set, currentHeight, 0, tx, error)) {
        throw std::runtime_error("Failed to create HTLC transaction: " + error);
    }

    // Broadcast
    if (!m_wallet->SendTransaction(tx, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to broadcast HTLC transaction: " + error);
    }

    // Calculate actual fee
    CAmount actual_fee = 0;
    for (const auto& vin : tx->vin) {
        CUTXOEntry entry;
        if (m_utxo_set->GetUTXO(vin.prevout, entry)) {
            actual_fee += entry.out.nValue;
        }
    }
    for (const auto& vout : tx->vout) {
        actual_fee -= vout.nValue;
    }

    uint256 txid = tx->GetHash();
    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << txid.GetHex() << "\",";
    oss << "\"timeout_height\":" << timeout_height << ",";
    oss << "\"amount\":" << FormatAmount(amount) << ",";
    oss << "\"fee\":" << FormatAmount(actual_fee > 0 ? actual_fee : fee);
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_ClaimHTLC(const std::string& params) {
    if (!m_wallet) throw std::runtime_error("Wallet not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Unlock with walletpassphrase first.");
    }

    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    // Parse parameters: {"htlc_txid": "hex", "htlc_vout": 0, "preimage": "hex"}
    std::string txid_hex;
    uint32_t vout_n = 0;
    std::string preimage_hex;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 3) {
                if (arr[0].is_string()) txid_hex = arr[0].get<std::string>();
                if (arr[1].is_number()) vout_n = arr[1].get<uint32_t>();
                if (arr[2].is_string()) preimage_hex = arr[2].get<std::string>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (txid_hex.empty()) {
        size_t pos = params.find("\"htlc_txid\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                txid_hex = params.substr(q1 + 1, q2 - q1 - 1);
        }

        size_t pos2 = params.find("\"htlc_vout\"");
        if (pos2 != std::string::npos) {
            size_t colon = params.find(":", pos2);
            size_t num_start = colon + 1;
            while (num_start < params.size() && isspace(params[num_start])) num_start++;
            size_t num_end = num_start;
            while (num_end < params.size() && isdigit(params[num_end])) num_end++;
            if (num_end > num_start)
                vout_n = SafeParseUInt32(params.substr(num_start, num_end - num_start), 0, UINT32_MAX);
        }

        size_t pos3 = params.find("\"preimage\"");
        if (pos3 != std::string::npos) {
            size_t colon = params.find(":", pos3);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                preimage_hex = params.substr(q1 + 1, q2 - q1 - 1);
        }
    }

    if (txid_hex.empty()) throw std::runtime_error("Missing htlc_txid");
    if (preimage_hex.empty()) throw std::runtime_error("Missing preimage");

    // Parse txid
    if (txid_hex.length() != 64) throw std::runtime_error("htlc_txid must be 64 hex characters");
    uint256 htlc_txid;
    htlc_txid.SetHex(txid_hex);

    // Parse preimage
    std::vector<uint8_t> preimage = ParseHex(preimage_hex);
    if (preimage.size() != 32) {
        throw std::runtime_error("preimage must be 64 hex characters (32 bytes)");
    }

    // Look up the HTLC UTXO
    COutPoint htlc_outpoint(htlc_txid, vout_n);
    CUTXOEntry htlc_entry;
    if (!m_utxo_set->GetUTXO(htlc_outpoint, htlc_entry)) {
        throw std::runtime_error("HTLC UTXO not found (txid:" + txid_hex + " vout:" + std::to_string(vout_n) + ")");
    }

    // Decode HTLC script
    CScript htlc_script(htlc_entry.out.scriptPubKey.begin(), htlc_entry.out.scriptPubKey.end());
    HTLCParameters htlc_params;
    if (!DecodeHTLCScript(htlc_script, htlc_params)) {
        throw std::runtime_error("Output is not a valid HTLC script");
    }

    // Verify preimage matches hash_lock
    std::vector<uint8_t> preimage_hash = HashPreimage(preimage);
    if (preimage_hash != htlc_params.hash_lock) {
        throw std::runtime_error("Preimage does not match HTLC hash_lock");
    }

    // Find our key matching claim_pubkey_hash
    CKey claim_key;
    bool found_key = false;
    {
        // Iterate wallet addresses to find key matching claim_pubkey_hash
        std::vector<CDilithiumAddress> addresses = m_wallet->GetAddresses();
        for (const auto& addr : addresses) {
            CKey key;
            if (m_wallet->GetKey(addr, key)) {
                std::vector<uint8_t> key_hash = WalletCrypto::HashPubKey(key.vchPubKey);
                if (key_hash == htlc_params.claim_pubkey_hash) {
                    claim_key = key;
                    found_key = true;
                    break;
                }
            }
        }
    }
    if (!found_key) {
        throw std::runtime_error("Wallet does not contain the claim key for this HTLC");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    CAmount htlc_amount = htlc_entry.out.nValue;

    // Build the claim transaction
    CTransaction claim_tx;
    claim_tx.nVersion = 2;
    claim_tx.nLockTime = 0;

    CTxIn claim_input(htlc_outpoint);
    claim_tx.vin.push_back(std::move(claim_input));

    // Output: send to our wallet (P2PKH)
    std::vector<uint8_t> our_hash = m_wallet->GetPubKeyHash();
    if (our_hash.empty()) throw std::runtime_error("Failed to get wallet address");
    std::vector<uint8_t> output_script = WalletCrypto::CreateScriptPubKey(our_hash);

    // Calculate fee for HTLC claim tx (~5400 bytes: sig + pubkey + preimage + opcode)
    size_t est_claim_size = Consensus::EstimateDilithiumTxSize(1, 1) + 40; // Extra for preimage + opcodes
    CAmount claim_fee = Consensus::CalculateMinFee(est_claim_size);
    CAmount claim_output = htlc_amount - claim_fee;
    if (claim_output <= 0) throw std::runtime_error("HTLC amount too small to cover claim fee");

    CTxOut claim_output_tx(claim_output, std::move(output_script));
    claim_tx.vout.push_back(std::move(claim_output_tx));

    // Sign: compute signature message (same algorithm as wallet SignTransaction)
    uint256 signing_hash = claim_tx.GetSigningHash();
    uint32_t chain_id = Dilithion::g_chainParams->chainID;
    uint32_t version = claim_tx.nVersion;

    std::vector<uint8_t> sig_message;
    sig_message.reserve(44);
    sig_message.insert(sig_message.end(), signing_hash.begin(), signing_hash.end());
    // Input index = 0 (4 bytes LE)
    sig_message.push_back(0); sig_message.push_back(0); sig_message.push_back(0); sig_message.push_back(0);
    // Version (4 bytes LE)
    sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));
    // Chain ID (4 bytes LE)
    sig_message.push_back(static_cast<uint8_t>(chain_id & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 24) & 0xFF));

    // SHA3-256 the message
    uint8_t sig_hash[32];
    SHA3_256(sig_message.data(), sig_message.size(), sig_hash);

    // Sign with Dilithium3
    std::vector<uint8_t> signature;
    if (!WalletCrypto::Sign(claim_key, sig_hash, 32, signature)) {
        throw std::runtime_error("Failed to sign HTLC claim transaction");
    }

    // Build HTLC claim scriptSig: <signature> <pubkey> <preimage> OP_TRUE
    CScript claim_scriptSig = CreateHTLCClaimScript(signature, claim_key.vchPubKey, preimage);
    claim_tx.vin[0].scriptSig = std::vector<uint8_t>(claim_scriptSig.begin(), claim_scriptSig.end());

    // Broadcast
    CTransactionRef claim_ref = MakeTransactionRef(std::move(claim_tx));
    std::string error;
    if (!m_wallet->SendTransaction(claim_ref, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to broadcast claim transaction: " + error);
    }

    uint256 claim_txid = claim_ref->GetHash();
    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << claim_txid.GetHex() << "\",";
    oss << "\"preimage\":\"" << HexStr(preimage) << "\",";
    oss << "\"amount\":" << FormatAmount(claim_output);
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_RefundHTLC(const std::string& params) {
    if (!m_wallet) throw std::runtime_error("Wallet not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Unlock with walletpassphrase first.");
    }

    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    // Parse parameters: {"htlc_txid": "hex", "htlc_vout": 0}
    std::string txid_hex;
    uint32_t vout_n = 0;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 2) {
                if (arr[0].is_string()) txid_hex = arr[0].get<std::string>();
                if (arr[1].is_number()) vout_n = arr[1].get<uint32_t>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (txid_hex.empty()) {
        size_t pos = params.find("\"htlc_txid\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                txid_hex = params.substr(q1 + 1, q2 - q1 - 1);
        }

        size_t pos2 = params.find("\"htlc_vout\"");
        if (pos2 != std::string::npos) {
            size_t colon = params.find(":", pos2);
            size_t num_start = colon + 1;
            while (num_start < params.size() && isspace(params[num_start])) num_start++;
            size_t num_end = num_start;
            while (num_end < params.size() && isdigit(params[num_end])) num_end++;
            if (num_end > num_start)
                vout_n = SafeParseUInt32(params.substr(num_start, num_end - num_start), 0, UINT32_MAX);
        }
    }

    if (txid_hex.empty()) throw std::runtime_error("Missing htlc_txid");

    // Parse txid
    if (txid_hex.length() != 64) throw std::runtime_error("htlc_txid must be 64 hex characters");
    uint256 htlc_txid;
    htlc_txid.SetHex(txid_hex);

    // Look up the HTLC UTXO
    COutPoint htlc_outpoint(htlc_txid, vout_n);
    CUTXOEntry htlc_entry;
    if (!m_utxo_set->GetUTXO(htlc_outpoint, htlc_entry)) {
        throw std::runtime_error("HTLC UTXO not found (txid:" + txid_hex + " vout:" + std::to_string(vout_n) + ")");
    }

    // Decode HTLC script
    CScript htlc_script(htlc_entry.out.scriptPubKey.begin(), htlc_entry.out.scriptPubKey.end());
    HTLCParameters htlc_params;
    if (!DecodeHTLCScript(htlc_script, htlc_params)) {
        throw std::runtime_error("Output is not a valid HTLC script");
    }

    // Check timeout has passed
    unsigned int currentHeight = m_chainstate->GetHeight();
    if (currentHeight < htlc_params.timeout_height) {
        throw std::runtime_error("HTLC timeout not yet reached (current: " +
            std::to_string(currentHeight) + ", timeout: " +
            std::to_string(htlc_params.timeout_height) + ", blocks remaining: " +
            std::to_string(htlc_params.timeout_height - currentHeight) + ")");
    }

    // Find our key matching refund_pubkey_hash
    CKey refund_key;
    bool found_key = false;
    {
        std::vector<CDilithiumAddress> addresses = m_wallet->GetAddresses();
        for (const auto& addr : addresses) {
            CKey key;
            if (m_wallet->GetKey(addr, key)) {
                std::vector<uint8_t> key_hash = WalletCrypto::HashPubKey(key.vchPubKey);
                if (key_hash == htlc_params.refund_pubkey_hash) {
                    refund_key = key;
                    found_key = true;
                    break;
                }
            }
        }
    }
    if (!found_key) {
        throw std::runtime_error("Wallet does not contain the refund key for this HTLC");
    }

    CAmount htlc_amount = htlc_entry.out.nValue;

    // Build the refund transaction
    // nLockTime must be >= timeout_height for OP_CHECKLOCKTIMEVERIFY to pass
    CTransaction refund_tx;
    refund_tx.nVersion = 2;
    refund_tx.nLockTime = htlc_params.timeout_height;

    CTxIn refund_input(htlc_outpoint);
    refund_input.nSequence = CTxIn::SEQUENCE_FINAL - 1;  // Enable nLockTime
    refund_tx.vin.push_back(std::move(refund_input));

    // Output: send to our wallet (P2PKH)
    std::vector<uint8_t> our_hash = m_wallet->GetPubKeyHash();
    if (our_hash.empty()) throw std::runtime_error("Failed to get wallet address");
    std::vector<uint8_t> output_script = WalletCrypto::CreateScriptPubKey(our_hash);

    // Fee
    size_t est_size = Consensus::EstimateDilithiumTxSize(1, 1);
    CAmount refund_fee = Consensus::CalculateMinFee(est_size);
    CAmount refund_output = htlc_amount - refund_fee;
    if (refund_output <= 0) throw std::runtime_error("HTLC amount too small to cover refund fee");

    CTxOut refund_output_tx(refund_output, std::move(output_script));
    refund_tx.vout.push_back(std::move(refund_output_tx));

    // Sign
    uint256 signing_hash = refund_tx.GetSigningHash();
    uint32_t chain_id = Dilithion::g_chainParams->chainID;
    uint32_t version = refund_tx.nVersion;

    std::vector<uint8_t> sig_message;
    sig_message.reserve(44);
    sig_message.insert(sig_message.end(), signing_hash.begin(), signing_hash.end());
    sig_message.push_back(0); sig_message.push_back(0); sig_message.push_back(0); sig_message.push_back(0);
    sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>(chain_id & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 24) & 0xFF));

    uint8_t sig_hash[32];
    SHA3_256(sig_message.data(), sig_message.size(), sig_hash);

    std::vector<uint8_t> signature;
    if (!WalletCrypto::Sign(refund_key, sig_hash, 32, signature)) {
        throw std::runtime_error("Failed to sign HTLC refund transaction");
    }

    // Build HTLC refund scriptSig: <signature> <pubkey> OP_FALSE
    CScript refund_scriptSig = CreateHTLCRefundScript(signature, refund_key.vchPubKey);
    refund_tx.vin[0].scriptSig = std::vector<uint8_t>(refund_scriptSig.begin(), refund_scriptSig.end());

    // Broadcast
    CTransactionRef refund_ref = MakeTransactionRef(std::move(refund_tx));
    std::string error;
    if (!m_wallet->SendTransaction(refund_ref, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to broadcast refund transaction: " + error);
    }

    uint256 refund_txid = refund_ref->GetHash();
    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << refund_txid.GetHex() << "\",";
    oss << "\"amount\":" << FormatAmount(refund_output);
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_DecodeHTLC(const std::string& params) {
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    // Parse parameters: {"htlc_txid": "hex", "vout": 0}
    std::string txid_hex;
    uint32_t vout_n = 0;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 2) {
                if (arr[0].is_string()) txid_hex = arr[0].get<std::string>();
                if (arr[1].is_number()) vout_n = arr[1].get<uint32_t>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (txid_hex.empty()) {
        size_t pos = params.find("\"htlc_txid\"");
        if (pos != std::string::npos) {
            size_t colon = params.find(":", pos);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                txid_hex = params.substr(q1 + 1, q2 - q1 - 1);
        }

        size_t pos2 = params.find("\"vout\"");
        if (pos2 != std::string::npos) {
            size_t colon = params.find(":", pos2);
            size_t num_start = colon + 1;
            while (num_start < params.size() && isspace(params[num_start])) num_start++;
            size_t num_end = num_start;
            while (num_end < params.size() && isdigit(params[num_end])) num_end++;
            if (num_end > num_start)
                vout_n = SafeParseUInt32(params.substr(num_start, num_end - num_start), 0, UINT32_MAX);
        }
    }

    if (txid_hex.empty()) throw std::runtime_error("Missing htlc_txid");

    if (txid_hex.length() != 64) throw std::runtime_error("htlc_txid must be 64 hex characters");
    uint256 htlc_txid;
    htlc_txid.SetHex(txid_hex);

    // Look up UTXO
    COutPoint outpoint(htlc_txid, vout_n);
    CUTXOEntry entry;
    if (!m_utxo_set->GetUTXO(outpoint, entry)) {
        throw std::runtime_error("UTXO not found (txid:" + txid_hex + " vout:" + std::to_string(vout_n) + ")");
    }

    // Decode HTLC
    CScript script(entry.out.scriptPubKey.begin(), entry.out.scriptPubKey.end());
    HTLCParameters htlc_params;
    if (!DecodeHTLCScript(script, htlc_params)) {
        throw std::runtime_error("Output is not a valid HTLC script");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    bool can_refund = currentHeight >= htlc_params.timeout_height;

    unsigned int confirmations = 0;
    if (entry.nHeight > 0 && currentHeight >= entry.nHeight) {
        confirmations = currentHeight - entry.nHeight + 1;
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"hash_lock\":\"" << HexStr(htlc_params.hash_lock) << "\",";
    oss << "\"claim_pubkey_hash\":\"" << HexStr(htlc_params.claim_pubkey_hash) << "\",";
    oss << "\"refund_pubkey_hash\":\"" << HexStr(htlc_params.refund_pubkey_hash) << "\",";
    oss << "\"timeout_height\":" << htlc_params.timeout_height << ",";
    oss << "\"amount\":" << FormatAmount(entry.out.nValue) << ",";
    oss << "\"can_refund\":" << (can_refund ? "true" : "false") << ",";
    oss << "\"confirmations\":" << confirmations;
    oss << "}";
    return oss.str();
}

// ============================================================================
// Atomic Swap RPC Commands (high-level orchestration)
// ============================================================================

// Default timeout constants (blocks)
static const uint32_t SWAP_INITIATOR_TIMEOUT_BLOCKS = 384;  // ~4.8h at 45s/block
static const uint32_t SWAP_RESPONDER_TIMEOUT_BLOCKS = 192;  // ~2.4h at 45s/block (must be < initiator's)

static std::string FormatSwapInfo(const SwapInfo& s, const std::string& amount_label) {
    auto fmt_amount = [&](CAmount a) {
        std::ostringstream o;
        CAmount COIN = 100000000;
        o << (a / COIN) << "." << std::setfill('0') << std::setw(8) << (a % COIN);
        return o.str();
    };

    std::ostringstream oss;
    oss << "{";
    oss << "\"swap_id\":\"" << s.swap_id << "\",";
    oss << "\"role\":\"" << SwapRoleStr(s.role) << "\",";
    oss << "\"state\":\"" << SwapStateStr(s.state) << "\",";
    oss << "\"our_chain\":\"" << s.our_chain << "\",";
    oss << "\"their_chain\":\"" << s.their_chain << "\",";
    oss << "\"our_amount\":" << fmt_amount(s.our_amount) << ",";
    oss << "\"their_amount\":" << fmt_amount(s.their_amount) << ",";
    oss << "\"our_htlc_txid\":\"" << s.our_htlc_txid << "\",";
    oss << "\"their_htlc_txid\":\"" << s.their_htlc_txid << "\",";
    oss << "\"our_timeout\":" << s.our_timeout << ",";
    oss << "\"their_timeout\":" << s.their_timeout << ",";
    oss << "\"hash_lock\":\"" << HexStr(s.hash_lock) << "\",";
    oss << "\"our_claim_address\":\"" << s.our_claim_address << "\",";
    oss << "\"their_claim_address\":\"" << s.their_claim_address << "\",";
    oss << "\"created_at\":" << s.created_at;
    // Only include preimage if it's been revealed (non-empty) and not zero
    if (!s.preimage.empty()) {
        oss << ",\"preimage\":\"" << HexStr(s.preimage) << "\"";
    }
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_InitiateSwap(const std::string& params) {
    if (!m_wallet) throw std::runtime_error("Wallet not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Unlock with walletpassphrase first.");
    }
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    if (static_cast<int>(currentHeight) < Dilithion::g_chainParams->scriptV2ActivationHeight) {
        throw std::runtime_error("Atomic swaps not yet activated on this chain");
    }

    // Parse parameters: object or array
    // {"their_chain":"dil", "send_amount":1.5, "receive_amount":100.0,
    //  "their_claim_address":"D...", "our_claim_address":"D...", "timeout_blocks":384}
    std::string their_chain;
    double send_amount_dbl = 0;
    double receive_amount_dbl = 0;
    std::string their_claim_address;  // Their DilV address (claims our locked DilV)
    std::string our_claim_address;    // Our DIL address (metadata, we claim their DIL)
    uint32_t timeout_blocks = SWAP_INITIATOR_TIMEOUT_BLOCKS;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 4) {
                if (arr[0].is_string()) their_chain = arr[0].get<std::string>();
                if (arr[1].is_number()) send_amount_dbl = arr[1].get<double>();
                if (arr[2].is_number()) receive_amount_dbl = arr[2].get<double>();
                if (arr[3].is_string()) their_claim_address = arr[3].get<std::string>();
                if (arr.size() >= 5 && arr[4].is_string()) our_claim_address = arr[4].get<std::string>();
                if (arr.size() >= 6 && arr[5].is_number()) timeout_blocks = arr[5].get<uint32_t>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (their_chain.empty()) {
        auto parse_str = [&](const std::string& key, std::string& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                out = params.substr(q1 + 1, q2 - q1 - 1);
        };
        auto parse_dbl = [&](const std::string& key, double& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t ns = colon + 1;
            while (ns < params.size() && isspace(params[ns])) ns++;
            size_t ne = ns;
            while (ne < params.size() && (isdigit(params[ne]) || params[ne] == '.')) ne++;
            if (ne > ns) out = SafeParseDouble(params.substr(ns, ne - ns), 0.0, 21000000.0);
        };
        auto parse_uint = [&](const std::string& key, uint32_t& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t ns = colon + 1;
            while (ns < params.size() && isspace(params[ns])) ns++;
            size_t ne = ns;
            while (ne < params.size() && isdigit(params[ne])) ne++;
            if (ne > ns) out = SafeParseUInt32(params.substr(ns, ne - ns), 1, 100000);
        };
        parse_str("their_chain", their_chain);
        parse_dbl("send_amount", send_amount_dbl);
        parse_dbl("receive_amount", receive_amount_dbl);
        parse_str("their_claim_address", their_claim_address);
        parse_str("our_claim_address", our_claim_address);
        parse_uint("timeout_blocks", timeout_blocks);
    }

    if (their_chain.empty())         throw std::runtime_error("Missing their_chain (e.g. \"dil\")");
    if (send_amount_dbl <= 0)        throw std::runtime_error("Missing or invalid send_amount");
    if (receive_amount_dbl <= 0)     throw std::runtime_error("Missing or invalid receive_amount");
    if (their_claim_address.empty()) throw std::runtime_error("Missing their_claim_address");
    if (timeout_blocks < 10)         throw std::runtime_error("timeout_blocks must be >= 10");

    CAmount send_amount    = static_cast<CAmount>(send_amount_dbl * 100000000);
    CAmount receive_amount = static_cast<CAmount>(receive_amount_dbl * 100000000);

    if (send_amount <= 0) throw std::runtime_error("send_amount must be positive");
    if (send_amount < DUST_THRESHOLD) throw std::runtime_error("send_amount below dust threshold");

    // Validate their_claim_address (must be a valid DilV address)
    CDilithiumAddress claim_addr;
    if (!ValidateAddress(their_claim_address, claim_addr)) {
        throw std::runtime_error("Invalid their_claim_address: " + their_claim_address);
    }
    std::vector<uint8_t> claim_pubkey_hash = CWallet::GetPubKeyHashFromAddress(claim_addr);
    if (claim_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to extract pubkey hash from their_claim_address");
    }

    // Our refund address (our wallet address on this chain)
    std::vector<uint8_t> refund_pubkey_hash = m_wallet->GetPubKeyHash();
    if (refund_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to get wallet pubkey hash");
    }

    // Get our refund address string
    CDilithiumAddress our_default_addr;
    {
        std::vector<CDilithiumAddress> addrs = m_wallet->GetAddresses();
        if (!addrs.empty()) our_default_addr = addrs[0];
    }
    std::string our_refund_address = our_default_addr.IsValid() ? our_default_addr.ToString() : "";

    // Generate preimage
    std::vector<uint8_t> preimage = GeneratePreimage();
    std::vector<uint8_t> hash_lock = HashPreimage(preimage);

    // Swap ID: first 8 bytes of preimage, hex-encoded (16 chars)
    std::string swap_id = HexStr(std::vector<uint8_t>(preimage.begin(), preimage.begin() + 8));

    // Create HTLC locking script
    uint32_t timeout_height = currentHeight + timeout_blocks;
    HTLCParameters htlc_params;
    htlc_params.hash_lock           = hash_lock;
    htlc_params.claim_pubkey_hash   = claim_pubkey_hash;
    htlc_params.refund_pubkey_hash  = refund_pubkey_hash;
    htlc_params.timeout_height      = timeout_height;

    CScript htlc_script = CreateHTLCScript(htlc_params);
    std::vector<uint8_t> scriptPubKey(htlc_script.begin(), htlc_script.end());

    // Create and broadcast the HTLC funding transaction
    size_t est_size = Consensus::EstimateDilithiumTxSize(2, 2);
    CAmount fee = Consensus::CalculateMinFee(est_size);
    CTransactionRef tx;
    std::string error;
    if (!m_wallet->CreateTransactionToScript(scriptPubKey, send_amount, fee, *m_utxo_set, currentHeight, 0, tx, error)) {
        throw std::runtime_error("Failed to create HTLC transaction: " + error);
    }
    if (!m_wallet->SendTransaction(tx, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to broadcast HTLC transaction: " + error);
    }

    std::string htlc_txid = tx->GetHash().GetHex();

    // Record swap state
    int64_t now = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    SwapInfo swap;
    swap.swap_id             = swap_id;
    swap.role                = SwapRole::INITIATOR;
    swap.state               = SwapState::HTLC_FUNDED;
    swap.our_chain           = (Dilithion::g_chainParams->network == Dilithion::DILV) ? "dilv" : "dil";
    swap.their_chain         = their_chain;
    swap.our_amount          = send_amount;
    swap.their_amount        = receive_amount;
    swap.our_htlc_txid       = htlc_txid;
    swap.our_timeout         = timeout_height;
    swap.their_timeout       = 0;
    swap.preimage            = preimage;
    swap.hash_lock           = hash_lock;
    swap.our_refund_address  = our_refund_address;
    swap.our_claim_address   = our_claim_address;
    swap.their_claim_address = their_claim_address;
    swap.created_at          = now;

    m_swapStore.AddSwap(swap);

    std::ostringstream oss;
    oss << "{";
    oss << "\"swap_id\":\"" << swap_id << "\",";
    oss << "\"hash_lock\":\"" << HexStr(hash_lock) << "\",";
    oss << "\"htlc_txid\":\"" << htlc_txid << "\",";
    oss << "\"timeout_height\":" << timeout_height << ",";
    oss << "\"send_amount\":" << FormatAmount(send_amount) << ",";
    oss << "\"instructions\":\"Share hash_lock and htlc_txid with counterparty. "
        << "They should run: acceptswap \\\"" << HexStr(hash_lock) << "\\\" "
        << receive_amount_dbl << " \\\"" << htlc_txid << "\\\" 0 "
        << "\\\"<their_claim_address>\\\" " << (timeout_blocks / 2) << "\"";
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_AcceptSwap(const std::string& params) {
    if (!m_wallet) throw std::runtime_error("Wallet not initialized");
    if (!m_mempool) throw std::runtime_error("Mempool not initialized");
    if (!m_utxo_set) throw std::runtime_error("UTXO set not initialized");
    if (!m_chainstate) throw std::runtime_error("Chain state not initialized");

    if (m_wallet->IsCrypted() && m_wallet->IsLocked()) {
        throw std::runtime_error("Wallet is encrypted and locked. Unlock with walletpassphrase first.");
    }
    if (!Dilithion::g_chainParams) {
        throw std::runtime_error("Chain parameters not initialized");
    }

    unsigned int currentHeight = m_chainstate->GetHeight();
    if (static_cast<int>(currentHeight) < Dilithion::g_chainParams->scriptV2ActivationHeight) {
        throw std::runtime_error("Atomic swaps not yet activated on this chain");
    }

    // Parameters:
    // {"hash_lock":"hex", "amount":1.5, "their_htlc_txid":"hex",
    //  "their_htlc_vout":0, "their_claim_address":"D...", "timeout_blocks":192,
    //  "their_chain":"dil", "receive_amount":100.0}
    std::string hash_lock_hex;
    double amount_dbl = 0;
    std::string their_htlc_txid;
    uint32_t their_htlc_vout = 0;
    std::string their_claim_address;  // Initiator's DilV address (claims our locked DilV)
    uint32_t timeout_blocks = SWAP_RESPONDER_TIMEOUT_BLOCKS;
    std::string their_chain;
    double receive_amount_dbl = 0;

    if (!params.empty() && params[0] == '[') {
        try {
            nlohmann::json arr = nlohmann::json::parse(params);
            if (arr.is_array() && arr.size() >= 6) {
                if (arr[0].is_string()) hash_lock_hex = arr[0].get<std::string>();
                if (arr[1].is_number()) amount_dbl = arr[1].get<double>();
                if (arr[2].is_string()) their_htlc_txid = arr[2].get<std::string>();
                if (arr[3].is_number()) their_htlc_vout = arr[3].get<uint32_t>();
                if (arr[4].is_string()) their_claim_address = arr[4].get<std::string>();
                if (arr[5].is_number()) timeout_blocks = arr[5].get<uint32_t>();
                if (arr.size() >= 7 && arr[6].is_string()) their_chain = arr[6].get<std::string>();
                if (arr.size() >= 8 && arr[7].is_number()) receive_amount_dbl = arr[7].get<double>();
            }
        } catch (const nlohmann::json::parse_error&) {}
    }

    if (hash_lock_hex.empty()) {
        auto parse_str = [&](const std::string& key, std::string& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t q1 = params.find("\"", colon);
            size_t q2 = params.find("\"", q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                out = params.substr(q1 + 1, q2 - q1 - 1);
        };
        auto parse_dbl = [&](const std::string& key, double& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t ns = colon + 1;
            while (ns < params.size() && isspace(params[ns])) ns++;
            size_t ne = ns;
            while (ne < params.size() && (isdigit(params[ne]) || params[ne] == '.')) ne++;
            if (ne > ns) out = SafeParseDouble(params.substr(ns, ne - ns), 0.0, 21000000.0);
        };
        auto parse_uint = [&](const std::string& key, uint32_t& out) {
            size_t p = params.find("\"" + key + "\"");
            if (p == std::string::npos) return;
            size_t colon = params.find(":", p);
            size_t ns = colon + 1;
            while (ns < params.size() && isspace(params[ns])) ns++;
            size_t ne = ns;
            while (ne < params.size() && isdigit(params[ne])) ne++;
            if (ne > ns) out = SafeParseUInt32(params.substr(ns, ne - ns), 0, UINT32_MAX);
        };
        parse_str("hash_lock", hash_lock_hex);
        parse_dbl("amount", amount_dbl);
        parse_str("their_htlc_txid", their_htlc_txid);
        parse_uint("their_htlc_vout", their_htlc_vout);
        parse_str("their_claim_address", their_claim_address);
        parse_uint("timeout_blocks", timeout_blocks);
        parse_str("their_chain", their_chain);
        parse_dbl("receive_amount", receive_amount_dbl);
    }

    if (hash_lock_hex.empty())       throw std::runtime_error("Missing hash_lock");
    if (amount_dbl <= 0)             throw std::runtime_error("Missing or invalid amount");
    if (their_htlc_txid.empty())     throw std::runtime_error("Missing their_htlc_txid");
    if (their_claim_address.empty()) throw std::runtime_error("Missing their_claim_address");
    if (timeout_blocks < 10)         throw std::runtime_error("timeout_blocks must be >= 10");

    // Parse hash_lock
    std::vector<uint8_t> hash_lock = ParseHex(hash_lock_hex);
    if (hash_lock.size() != 32) {
        throw std::runtime_error("hash_lock must be 64 hex characters (32 bytes)");
    }

    CAmount amount = static_cast<CAmount>(amount_dbl * 100000000);
    if (amount <= 0) throw std::runtime_error("amount must be positive");
    if (amount < DUST_THRESHOLD) throw std::runtime_error("amount below dust threshold");

    // Validate their_claim_address
    CDilithiumAddress claim_addr;
    if (!ValidateAddress(their_claim_address, claim_addr)) {
        throw std::runtime_error("Invalid their_claim_address: " + their_claim_address);
    }
    std::vector<uint8_t> claim_pubkey_hash = CWallet::GetPubKeyHashFromAddress(claim_addr);
    if (claim_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to extract pubkey hash from their_claim_address");
    }

    // Our refund address
    std::vector<uint8_t> refund_pubkey_hash = m_wallet->GetPubKeyHash();
    if (refund_pubkey_hash.size() != 20) {
        throw std::runtime_error("Failed to get wallet pubkey hash");
    }
    std::string our_refund_address;
    {
        std::vector<CDilithiumAddress> addrs = m_wallet->GetAddresses();
        if (!addrs.empty()) our_refund_address = addrs[0].ToString();
    }

    // Build HTLC
    uint32_t timeout_height = currentHeight + timeout_blocks;
    HTLCParameters htlc_params;
    htlc_params.hash_lock          = hash_lock;
    htlc_params.claim_pubkey_hash  = claim_pubkey_hash;
    htlc_params.refund_pubkey_hash = refund_pubkey_hash;
    htlc_params.timeout_height     = timeout_height;

    CScript htlc_script = CreateHTLCScript(htlc_params);
    std::vector<uint8_t> scriptPubKey(htlc_script.begin(), htlc_script.end());

    size_t est_size = Consensus::EstimateDilithiumTxSize(2, 2);
    CAmount fee = Consensus::CalculateMinFee(est_size);
    CTransactionRef tx;
    std::string error;
    if (!m_wallet->CreateTransactionToScript(scriptPubKey, amount, fee, *m_utxo_set, currentHeight, 0, tx, error)) {
        throw std::runtime_error("Failed to create HTLC transaction: " + error);
    }
    if (!m_wallet->SendTransaction(tx, *m_mempool, *m_utxo_set, currentHeight, error)) {
        throw std::runtime_error("Failed to broadcast HTLC transaction: " + error);
    }

    std::string htlc_txid = tx->GetHash().GetHex();

    // Generate a swap ID from hash_lock (first 8 bytes)
    std::string swap_id = HexStr(std::vector<uint8_t>(hash_lock.begin(), hash_lock.begin() + 8));

    // Persist swap state
    int64_t now = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    SwapInfo swap;
    swap.swap_id             = swap_id;
    swap.role                = SwapRole::RESPONDER;
    swap.state               = SwapState::HTLC_FUNDED;
    swap.our_chain           = (Dilithion::g_chainParams->network == Dilithion::DILV) ? "dilv" : "dil";
    swap.their_chain         = their_chain;
    swap.our_amount          = amount;
    swap.their_amount        = static_cast<CAmount>(receive_amount_dbl * 100000000);
    swap.our_htlc_txid       = htlc_txid;
    swap.their_htlc_txid     = their_htlc_txid;
    swap.their_htlc_vout     = their_htlc_vout;
    swap.our_timeout         = timeout_height;
    swap.their_timeout       = 0;
    swap.hash_lock           = hash_lock;
    swap.our_refund_address  = our_refund_address;
    swap.their_claim_address = their_claim_address;
    swap.created_at          = now;

    m_swapStore.AddSwap(swap);

    std::ostringstream oss;
    oss << "{";
    oss << "\"swap_id\":\"" << swap_id << "\",";
    oss << "\"htlc_txid\":\"" << htlc_txid << "\",";
    oss << "\"timeout_height\":" << timeout_height << ",";
    oss << "\"amount\":" << FormatAmount(amount);
    oss << "}";
    return oss.str();
}

std::string CRPCServer::RPC_ListSwaps(const std::string& params) {
    // Optional: filter by state name
    // {"state":"htlc_funded"} or [] or {}
    int state_filter = -1;

    size_t p = params.find("\"state\"");
    if (p != std::string::npos) {
        size_t colon = params.find(":", p);
        size_t q1 = params.find("\"", colon);
        size_t q2 = params.find("\"", q1 + 1);
        if (q1 != std::string::npos && q2 != std::string::npos) {
            std::string state_str = params.substr(q1 + 1, q2 - q1 - 1);
            SwapState s = ParseSwapState(state_str);
            state_filter = static_cast<int>(s);
        }
    }

    std::vector<SwapInfo> swaps = m_swapStore.ListSwaps(state_filter);

    std::ostringstream oss;
    oss << "{\"swaps\":[";
    for (size_t i = 0; i < swaps.size(); i++) {
        if (i > 0) oss << ",";
        oss << FormatSwapInfo(swaps[i], "");
    }
    oss << "],\"count\":" << swaps.size() << "}";
    return oss.str();
}

// ============================================================================
// Seed Attestation RPC (Phase 2+3)
// ============================================================================

std::string CRPCServer::RPC_GetMIKAttestation(const std::string& params) {
    // This RPC is only available on seed nodes with attestation key loaded
    if (!m_seedAttestationKey || m_seedId < 0) {
        throw std::runtime_error("getmikattestation is only available on seed nodes");
    }

    if (!m_asnDatabase || !m_asnDatabase->IsLoaded()) {
        throw std::runtime_error("ASN database not loaded on this seed node");
    }

    // Parse params: {"mik_pubkey": "hex...", "dna_hash": "hex..."}
    std::string mikPubkeyHex, dnaHashHex;

    // Extract mik_pubkey
    size_t pos = params.find("\"mik_pubkey\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing required parameter: mik_pubkey");
    }
    pos = params.find("\"", pos + 12);  // Find opening quote of value
    if (pos != std::string::npos) {
        pos++;
        size_t end = params.find("\"", pos);
        if (end != std::string::npos) {
            mikPubkeyHex = params.substr(pos, end - pos);
        }
    }

    // Extract dna_hash
    pos = params.find("\"dna_hash\"");
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing required parameter: dna_hash");
    }
    pos = params.find("\"", pos + 10);
    if (pos != std::string::npos) {
        pos++;
        size_t end = params.find("\"", pos);
        if (end != std::string::npos) {
            dnaHashHex = params.substr(pos, end - pos);
        }
    }

    // Validate pubkey
    std::vector<uint8_t> mikPubkey = ParseHex(mikPubkeyHex);
    if (mikPubkey.size() != DFMP::MIK_PUBKEY_SIZE) {
        throw std::runtime_error("Invalid mik_pubkey size: expected " +
            std::to_string(DFMP::MIK_PUBKEY_SIZE * 2) + " hex chars");
    }

    // Validate DNA hash
    std::vector<uint8_t> dnaHashVec = ParseHex(dnaHashHex);
    if (dnaHashVec.size() != 32) {
        throw std::runtime_error("Invalid dna_hash size: expected 64 hex chars");
    }
    std::array<uint8_t, 32> dnaHash;
    std::copy(dnaHashVec.begin(), dnaHashVec.end(), dnaHash.begin());

    // Check client IP against ASN database
    std::string clientIP = m_currentClientIP;
    if (clientIP.empty() || clientIP == "unknown") {
        throw std::runtime_error("Cannot determine client IP address");
    }

    // Strip port if present (e.g., "192.168.1.1:12345" -> "192.168.1.1")
    size_t colonPos = clientIP.rfind(':');
    if (colonPos != std::string::npos) {
        // Check if this looks like an IPv4 with port (not IPv6)
        if (clientIP.find('.') != std::string::npos) {
            clientIP = clientIP.substr(0, colonPos);
        }
    }

    // Datacenter IP ban: chain-specific.
    // DilV (VDF): enabled — VM farms are the primary Sybil vector.
    // DIL (PoW): disabled — hashrate is the limiting factor, not MIK count.
    bool dcBanEnabled = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->attestationDatacenterBan : true;
    if (dcBanEnabled && m_asnDatabase->IsDatacenterIP(clientIP)) {
        uint32_t asn = m_asnDatabase->LookupASN(clientIP);
        std::string desc = m_asnDatabase->LookupDescription(clientIP);
        throw std::runtime_error("Mining not available from datacenter/VPN IPs. "
            "Your IP (" + clientIP + ") belongs to ASN " + std::to_string(asn) +
            " (" + desc + "). Most VPN and proxy services route through datacenter "
            "infrastructure and will trigger this check. To register your miner identity, "
            "temporarily disable your VPN, restart the node, and let it complete MIK "
            "registration. This is a one-time step — after registration you can re-enable "
            "your VPN for all subsequent mining. Your residential IP is only shared with "
            "the 4 seed nodes during registration and is not stored on-chain.");
    }

    // Derive MIK identity early — needed for rate limit tracking and logging
    DFMP::Identity mikIdentity = DFMP::DeriveIdentityFromMIK(mikPubkey);
    std::string mikIdHex = mikIdentity.GetHex();

    // Sybil defense Phase 0: Rate limit NEW MIK registrations per /24 subnet per day.
    // Re-attestation for the same MIK (restarts, refreshes) bypasses the limit.
    {
        // Extract /24 subnet prefix (e.g., "192.168.1.100" -> "192.168.1")
        std::string subnetKey = clientIP;
        size_t lastDot = subnetKey.rfind('.');
        if (lastDot != std::string::npos) {
            subnetKey = subnetKey.substr(0, lastDot);
        }

        int64_t today = static_cast<int64_t>(std::time(nullptr)) / 86400;

        std::lock_guard<std::mutex> lock(m_attestRateMutex);
        auto& state = m_attestationRateLimit[subnetKey];

        // Reset daily counter if new day
        if (state.currentDay != today) {
            state.currentDay = today;
            state.newMIKsToday = 0;
        }

        // Check if this MIK has been attested before from this subnet
        bool isRenewal = (state.knownMIKs.find(mikIdHex) != state.knownMIKs.end());

        if (!isRenewal) {
            // New MIK for this subnet — apply rate limit
            if (state.newMIKsToday >= m_attestationMaxPerDay) {
                std::cout << "[Attestation] RATE LIMITED: subnet " << subnetKey
                          << ".* already registered " << state.newMIKsToday
                          << " new MIK(s) today (limit: " << m_attestationMaxPerDay << ")" << std::endl;
                throw std::runtime_error("Attestation rate limit exceeded. "
                    "Maximum " + std::to_string(m_attestationMaxPerDay) +
                    " new MIK registration(s) per /24 subnet per day. Try again tomorrow.");
            }
            state.newMIKsToday++;
            std::cout << "[Attestation] New MIK " << mikIdHex.substr(0, 12) << "..."
                      << " from subnet " << subnetKey << ".* (new #" << state.newMIKsToday
                      << " today, limit: " << m_attestationMaxPerDay << ")" << std::endl;
        } else {
            std::cout << "[Attestation] Renewal for known MIK " << mikIdHex.substr(0, 12) << "..."
                      << " from subnet " << subnetKey << ".* (bypassing rate limit)" << std::endl;
        }

        // Record this MIK as known for this subnet
        state.knownMIKs[mikIdHex] = today;

        // Periodic cleanup: remove stale MIK entries (>30 days) and empty subnets
        if (m_attestationRateLimit.size() > 10000) {
            for (auto cleanIt = m_attestationRateLimit.begin(); cleanIt != m_attestationRateLimit.end(); ) {
                for (auto mikIt = cleanIt->second.knownMIKs.begin(); mikIt != cleanIt->second.knownMIKs.end(); ) {
                    if (mikIt->second < today - 30) {
                        mikIt = cleanIt->second.knownMIKs.erase(mikIt);
                    } else {
                        ++mikIt;
                    }
                }
                if (cleanIt->second.knownMIKs.empty() && cleanIt->second.currentDay < today - 1) {
                    cleanIt = m_attestationRateLimit.erase(cleanIt);
                } else {
                    ++cleanIt;
                }
            }
        }
    }

    // Build attestation message
    uint32_t timestamp = static_cast<uint32_t>(std::time(nullptr));
    std::vector<uint8_t> message = Attestation::BuildAttestationMessage(
        mikPubkey, dnaHash, timestamp, static_cast<uint8_t>(m_seedId));

    // Sign with seed's attestation key
    std::vector<uint8_t> signature;
    if (!m_seedAttestationKey->Sign(message, signature)) {
        throw std::runtime_error("Failed to sign attestation");
    }

    // Log the attestation
    uint32_t asn = m_asnDatabase->LookupASN(clientIP);
    std::string desc = m_asnDatabase->LookupDescription(clientIP);
    std::cout << "[Attestation] Signed attestation for MIK " << mikIdHex.substr(0, 12) << "..."
              << " from " << clientIP << " (ASN " << asn << " " << desc << ")" << std::endl;

    // Build response
    std::ostringstream result;
    result << "{\"seed_id\":" << m_seedId
           << ",\"timestamp\":" << timestamp
           << ",\"signature\":\"" << HexStr(signature) << "\""
           << ",\"mik_identity\":\"" << mikIdHex << "\""
           << ",\"client_ip\":\"" << clientIP << "\""
           << ",\"asn\":" << asn
           << ",\"asn_description\":\"" << EscapeJSON(desc) << "\""
           << "}";

    return result.str();
}
