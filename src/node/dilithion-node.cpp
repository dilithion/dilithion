// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Dilithion Node - Main Application
 *
 * Integrates all components:
 * - Phase 1: Blockchain storage, mempool, fees
 * - Phase 2: P2P networking
 * - Phase 3: Mining
 * - Phase 4: Wallet, RPC server
 *
 * Usage:
 *   dilithion-node [options]
 *     --datadir=<path>      Data directory (default: ~/.dilithion)
 *     --rpcport=<port>      RPC server port (default: 8332)
 *     --mine                Start mining automatically
 *     --threads=<n>         Mining threads (default: auto-detect)
 */

// Memory management: malloc_trim to combat glibc arena fragmentation
#ifdef __linux__
#include <malloc.h>  // malloc_trim()
#endif

// v4.1-rc2 ISSUE-2 fix: isatty() check for non-interactive stdin detection
#ifdef _WIN32
#include <io.h>      // _isatty / _fileno
#else
#include <unistd.h>  // isatty / fileno
#endif

#include <node/blockchain_storage.h>
#include <node/block_processing.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <node/chainstate_integrity_monitor.h>  // v4.4 Block 8
#include <node/genesis.h>
#include <node/block_index.h>
#include <consensus/params.h>
#include <net/peers.h>
#include <net/net.h>
#include <net/tx_relay.h>
#include <net/socket.h>
#include <net/sock.h>
#include <net/async_broadcaster.h>
// REMOVED: #include <net/message_queue.h> - CMessageProcessorQueue was unused (CConnman handles messages directly)
#include <net/headers_manager.h>
#include <net/orphan_manager.h>
#include <node/resource_monitor.h>  // BUG #275: Memory pressure monitoring
#include <net/block_fetcher.h>
#include <net/block_tracker.h>  // IBD BOTTLENECK FIX: For CBlockTracker state updates
// REMOVED: #include <net/node_state.h> - CNodeStateManager replaced by CPeerManager
#include <node/block_validation_queue.h>  // Phase 2: Async block validation queue
#include <net/feeler.h>  // Bitcoin Core-style feeler connections
#include <net/connman.h>  // Phase 5: Event-driven connection manager
#include <net/upnp.h>     // UPnP automatic port mapping
#include <api/http_server.h>
#include <api/cached_stats.h>
#include <api/metrics.h>
#include <miner/controller.h>
#include <miner/vdf_miner.h>
#include <vdf/vdf.h>
#include <vdf/cooldown_tracker.h>
#include <consensus/vdf_validation.h>
#include <wallet/wallet.h>
#include <wallet/passphrase_validator.h>
#include <rpc/server.h>
#include <rpc/rest_api.h>  // REST API for light wallet
#include <core/chainparams.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <consensus/validation.h>  // CRITICAL-3 FIX: For CBlockValidator
#include <dfmp/dfmp.h>             // DFMP: Fair Mining Protocol
#include <dfmp/identity_db.h>      // DFMP: Identity persistence
#include <dfmp/mik.h>              // DFMP v2.0: Mining Identity Key
#include <dfmp/mik_registration_file.h>  // Persistent MIK registration PoW
#include <node/registration_manager.h>   // v4.0.18: first-time registration state machine
#include <util/chain_reset.h>      // --reset-chain helper
#include <consensus/tx_validation.h>  // BUG #108 FIX: For CTransactionValidator
#include <consensus/signature_batch_verifier.h>  // Phase 3.2: Batch signature verification
#include <consensus/chain_verifier.h>  // Chain integrity validation (Bug #17)
#include <crypto/randomx_hash.h>
#include <util/logging.h>  // Bitcoin Core-style logging
#include <util/stacktrace.h>  // Phase 2.2: Crash diagnostics
#include <util/pidfile.h>  // STRESS TEST FIX: Stale lock detection
#include <util/system.h>  // EnsureDataDirExists for first-run setup
#include <util/config.h>  // Phase 10: Configuration system
#include <util/config_validator.h>  // UX: Configuration validation
#include <util/error_format.h>  // User experience: Better error messages
#include <util/bench.h>  // Performance: Benchmarking
#include <digital_dna/digital_dna_rpc.h>  // Digital DNA RPC commands
#include <digital_dna/verification_manager.h>  // Phase 2: DNA Verification & Attestation
#include <digital_dna/dna_verification.h>       // Phase 3: Verification status for DFMP v3.4
#include <digital_dna/sample_rate_limiter.h>   // Phase 1 propagation: receive-side rate limit
#include <attestation/seed_attestation.h>       // Phase 2+3: Seed-attested MIK registration
#include <net/asn_database.h>                    // Phase 2+3: ASN database for datacenter IP check
#include <util/strencodings.h>                   // HexStr, ParseHex

#include <algorithm>  // Phase 4: Trust-based relay sorting
#include <array>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <sstream>  // For mnemonic display parsing
#include <memory>
#include <csignal>
#include <cstring>
#include <cassert>
#include <thread>
#include <chrono>
#include <atomic>
#include <optional>
#include <queue>  // CRITICAL-2 FIX: For iterative orphan resolution
#include <deque>  // Tip divergence: Rolling window for self-mined block ratio
#include <set>  // BUG #109 FIX: For tracking spent outpoints in block template
#include <filesystem>  // BUG #56: For wallet file existence check
#include <unordered_map>  // BUG #149: For tracking requested parent blocks
#include <mutex>  // BUG #149: For thread-safe parent tracking
#include <random>  // Digital DNA: Random peer selection for P2P measurements

#ifdef _WIN32
    #include <winsock2.h>   // For socket functions
    #include <ws2tcpip.h>   // For inet_pton
    #include <windows.h>    // For GlobalMemoryStatusEx (Bug #23 fix)
    #include <dbghelp.h>    // For StackWalk64, SymFromAddr (crash stack traces)
#else
    #include <arpa/inet.h>  // For inet_pton on Unix
    #include <netdb.h>      // For gethostname, getaddrinfo
    #include <unistd.h>     // For gethostname
    #include <sys/stat.h>   // For chmod (RPC cookie file permissions)
#endif

// Windows API macro conflicts - undef after including headers
#ifdef _WIN32
    #ifdef SendMessage
        #undef SendMessage  // Windows defines this as SendMessageA/SendMessageW
    #endif

// CRASH HANDLER: Log crash info to file before terminating
static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    // Get data directory for crash log
    std::string crashLogPath = "dilithion_crash.log";
    char* appdata = std::getenv("APPDATA");
    if (appdata) {
        crashLogPath = std::string(appdata) + "\\.dilithion\\crash.log";
    }

    std::ofstream crashLog(crashLogPath, std::ios::app);
    if (crashLog) {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);

        crashLog << "\n========== CRASH REPORT ==========" << std::endl;
        crashLog << "Time: " << std::ctime(&time_t_now);
        crashLog << "Exception Code: 0x" << std::hex << pExceptionInfo->ExceptionRecord->ExceptionCode << std::dec << std::endl;
        crashLog << "Exception Address: 0x" << std::hex << (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionAddress << std::dec << std::endl;

        // Decode common exception codes
        switch (pExceptionInfo->ExceptionRecord->ExceptionCode) {
            case 0xC0000005: {
                crashLog << "Type: ACCESS_VIOLATION (segfault)" << std::endl;
                // Log read/write flag and target address for access violations
                if (pExceptionInfo->ExceptionRecord->NumberParameters >= 2) {
                    ULONG_PTR rwFlag = pExceptionInfo->ExceptionRecord->ExceptionInformation[0];
                    ULONG_PTR targetAddr = pExceptionInfo->ExceptionRecord->ExceptionInformation[1];
                    crashLog << "Access Type: " << (rwFlag == 0 ? "READ" : (rwFlag == 1 ? "WRITE" : "DEP"))
                             << " at address 0x" << std::hex << targetAddr << std::dec << std::endl;
                }
                break;
            }
            case 0xC00000FD: crashLog << "Type: STACK_OVERFLOW" << std::endl; break;
            case 0xC0000094: crashLog << "Type: INTEGER_DIVIDE_BY_ZERO" << std::endl; break;
            case 0xC000001D: crashLog << "Type: ILLEGAL_INSTRUCTION" << std::endl; break;
            case 0xC0000409: crashLog << "Type: STACK_BUFFER_OVERRUN" << std::endl; break;
            default: crashLog << "Type: Unknown" << std::endl; break;
        }

        // Log register state
        CONTEXT* ctx = pExceptionInfo->ContextRecord;
        crashLog << "Registers: RIP=0x" << std::hex << ctx->Rip
                 << " RSP=0x" << ctx->Rsp
                 << " RBP=0x" << ctx->Rbp
                 << " RAX=0x" << ctx->Rax
                 << " RBX=0x" << ctx->Rbx
                 << " RCX=0x" << ctx->Rcx
                 << " RDX=0x" << ctx->Rdx << std::dec << std::endl;

        // Stack trace using StackWalk64 from the exception context
        crashLog << "Stack trace:" << std::endl;
        {
            HANDLE process = GetCurrentProcess();
            HANDLE thread = GetCurrentThread();
            SymInitialize(process, NULL, TRUE);

            STACKFRAME64 sf = {};
            sf.AddrPC.Offset = ctx->Rip;
            sf.AddrPC.Mode = AddrModeFlat;
            sf.AddrFrame.Offset = ctx->Rbp;
            sf.AddrFrame.Mode = AddrModeFlat;
            sf.AddrStack.Offset = ctx->Rsp;
            sf.AddrStack.Mode = AddrModeFlat;

            // Get module base for RVA calculation
            HMODULE hModule = NULL;
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                              (LPCSTR)ctx->Rip, &hModule);
            uintptr_t moduleBase = (uintptr_t)hModule;
            crashLog << "Module base: 0x" << std::hex << moduleBase << std::dec << std::endl;

            for (int i = 0; i < 30; i++) {
                if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread,
                                &sf, ctx, NULL, SymFunctionTableAccess64,
                                SymGetModuleBase64, NULL)) {
                    break;
                }
                if (sf.AddrPC.Offset == 0) break;

                uintptr_t addr = sf.AddrPC.Offset;
                uintptr_t rva = addr - moduleBase;

                // Try to resolve symbol name
                char symBuf[sizeof(SYMBOL_INFO) + 256];
                SYMBOL_INFO* sym = (SYMBOL_INFO*)symBuf;
                sym->SizeOfStruct = sizeof(SYMBOL_INFO);
                sym->MaxNameLen = 255;
                DWORD64 displacement = 0;

                if (SymFromAddr(process, addr, &displacement, sym)) {
                    crashLog << "  [" << i << "] 0x" << std::hex << addr
                             << " (RVA 0x" << rva << ") " << sym->Name
                             << "+0x" << displacement << std::dec << std::endl;
                } else {
                    crashLog << "  [" << i << "] 0x" << std::hex << addr
                             << " (RVA 0x" << rva << ")" << std::dec << std::endl;
                }
            }
            SymCleanup(process);
        }

        crashLog << "===================================" << std::endl;
        crashLog.close();

        std::cerr << "\n[CRASH] Fatal exception occurred. Details written to: " << crashLogPath << std::endl;
        std::cerr << "[CRASH] Code=0x" << std::hex << pExceptionInfo->ExceptionRecord->ExceptionCode
                  << " Addr=0x" << (uintptr_t)pExceptionInfo->ExceptionRecord->ExceptionAddress
                  << " RIP=0x" << pExceptionInfo->ContextRecord->Rip << std::dec << std::endl;
        if (pExceptionInfo->ExceptionRecord->ExceptionCode == 0xC0000005 &&
            pExceptionInfo->ExceptionRecord->NumberParameters >= 2) {
            std::cerr << "[CRASH] " << (pExceptionInfo->ExceptionRecord->ExceptionInformation[0] == 0 ? "READ" : "WRITE")
                      << " at 0x" << std::hex << pExceptionInfo->ExceptionRecord->ExceptionInformation[1] << std::dec << std::endl;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;  // Let default handler terminate
}
#endif

// Global chain state (defined in src/core/globals.cpp)
extern CChainState g_chainstate;

// Phase 1.2: NodeContext for centralized global state management (Bitcoin Core pattern)
#include <core/node_context.h>
#include <node/ibd_coordinator.h>  // Phase 5.1: IBD Coordinator
#include <net/port/sync_coordinator_adapter.h>  // Phase 6 PR6.5a: adapter
extern NodeContext g_node_context;

// Phase 5: Helper function to connect to a peer (for outbound connections)
// BUG #139 FIX: Don't send VERSION here - SocketHandler will send it
// after connection completes (STATE_CONNECTING -> STATE_CONNECTED)
// Can be called from any thread since it uses g_node_context
static int ConnectAndHandshake(const NetProtocol::CAddress& addr, bool manual = false) {
    if (!g_node_context.connman || !g_node_context.peer_manager) {
        return -1;
    }
    CNode* pnode = g_node_context.connman->ConnectNode(addr, manual);
    if (!pnode) {
        return -1;
    }
    // BUG #139: Don't send VERSION here - connection is still in progress
    // SocketHandler will detect connection completion and send VERSION
    return pnode->id;
}

// Global node state for signal handling (defined in src/core/globals.cpp)
struct NodeState {
    std::atomic<bool> running{false};
    std::atomic<bool> new_block_found{false};  // Signals main loop to update mining template
    std::atomic<bool> mining_enabled{false};   // Whether user requested --mine
    std::atomic<uint64_t> template_version{0}; // BUG #109 FIX: Template version counter for race detection
    std::string mining_address_override;       // --mining-address=Dxxx (empty = use wallet default)
    bool rotate_mining_address{false};         // --rotate-mining-address (new HD address per block)
    bool shared_heat{true};                    // Phase 3b: shared cluster heat (default ON)
    CRPCServer* rpc_server = nullptr;
    CMiningController* miner = nullptr;
    CWallet* wallet = nullptr;
    CSocket* p2p_socket = nullptr;
    CHttpServer* http_server = nullptr;
};
extern NodeState g_node_state;

// Phase 1.2: NodeContext for centralized global state management (Bitcoin Core pattern)
#include <core/node_context.h>
#include <node/ibd_coordinator.h>  // Phase 5.1: IBD Coordinator
#include <net/port/sync_coordinator_adapter.h>  // Phase 6 PR6.5a: adapter
extern NodeContext g_node_context;

// Global flag for UTXO sync optimization (defined in utxo_set.cpp)
// false during IBD (speed), true after IBD (durability)
extern std::atomic<bool> g_utxo_sync_enabled;

// Global async broadcaster pointer (initialized in main)
CAsyncBroadcaster* g_async_broadcaster = nullptr;

// v4.0.17: Pending miner-win notifications. Pushed by the block-submit
// handler when our mined block initially becomes tip; consumed by the
// deferred-outcome block-connect callback once a child block is connected
// on top (settling the round). See callback registration ~line 5350 for
// the full rationale. Mirrors the dilv-node.cpp implementation.
struct PendingMinerWin {
    uint256 blockHash;
    int     height;
};
static std::vector<PendingMinerWin> g_pendingMinerWins;
static std::mutex g_pendingMinerWinsMutex;

// Phase 2: MIK → peer_id mapping for DNA verification routing
// Populated when we receive DNA identity responses from peers
static std::map<std::array<uint8_t, 20>, int> g_mik_peer_map;
static std::mutex g_mik_peer_mutex;

// DNA Propagation Phase 1: rate limiter for received DNA samples.
// Three layers: per-peer token bucket, per-MIK global interval, per-MIK-per-peer.
static digital_dna::DNASampleRateLimiter g_dna_sample_limiter;

// Helper: broadcast a DNA sample to all connected peers via dnaires.
// Extracted from the initial-registration path so both that path and the
// progressive-enrichment path can keep the network converged.
//
// Phase 1.5: if the wallet has a MIK whose identity matches the DNA's MIK,
// the broadcast is signed with a fresh (timestamp, nonce) envelope. The
// trailer is only emitted to peers at protocol version >=
// DNA_SMP1_MIN_PROTOCOL_VERSION — older peers receive the pre-1.5 payload
// shape to avoid tripping their smaller size gate.
static void BroadcastDNASample(const digital_dna::DigitalDNA& dna) {
    if (!g_node_context.connman || !g_node_context.message_processor) return;
    if (dna.mik_identity == std::array<uint8_t, 20>{}) return;
    auto dna_data = dna.serialize();

    // Attempt to sign. Seeds with no wallet-managed MIK fall back to unsigned.
    // wallet->SignDNAEnvelope handles unencrypted + encrypted-and-unlocked
    // wallets uniformly; the privkey is decrypted briefly inside wallet scope
    // and wiped on return — never crosses module boundaries.
    digital_dna::SampleEnvelope envelope;
    bool have_signed = false;
    if (g_node_context.wallet && g_node_context.wallet->HasMIK()) {
        envelope.timestamp_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        std::random_device rd;
        std::mt19937_64 gen(rd());
        envelope.nonce = gen();
        have_signed = g_node_context.wallet->SignDNAEnvelope(
            dna.mik_identity, envelope.timestamp_sec, envelope.nonce,
            dna_data, envelope.signature);
    }

    auto nodes = g_node_context.connman->GetNodes();
    int sent = 0;
    int signed_sent = 0;
    for (auto* n : nodes) {
        if (!n || !n->IsConnected()) continue;
        auto msg = g_node_context.message_processor->CreateDNAIdentResMessage(
            dna.mik_identity, true, dna_data,
            have_signed ? &envelope : nullptr,
            n->nVersion);
        g_node_context.connman->PushMessage(n->id, msg);
        ++sent;
        if (have_signed && n->nVersion >= NetProtocol::DNA_SMP1_MIN_PROTOCOL_VERSION) {
            ++signed_sent;
        }
    }
    std::cout << "[DNA] Broadcast identity to " << sent << " peers";
    if (have_signed) {
        std::cout << " (" << signed_sent << " signed, "
                  << (sent - signed_sent) << " unsigned legacy)";
    }
    std::cout << std::endl;
}

// Phase 1.2: Global state now managed via NodeContext
// Legacy globals kept for backward compatibility during migration
// TODO: Remove after full migration to NodeContext
CHeadersManager* g_headers_manager = nullptr;
COrphanManager* g_orphan_manager = nullptr;
CBlockFetcher* g_block_fetcher = nullptr;

/**
 * BUG #69 FIX: Bitcoin Core-style Initial Block Download detection
 *
 * Replaces custom peer-height-based detection with Bitcoin Core's proven approach:
 * 1. LATCH MECHANISM - Once IBD=false, it stays false permanently (like Bitcoin Core)
 * 2. TIP TIMESTAMP - Primary criterion: tip < 24 hours old = exit IBD
 * 3. HEADERS AHEAD - Secondary: if headers ahead of tip, still downloading
 *
 * This fixes BUG #69 where IsInitialBlockDownload() couldn't distinguish between:
 * - "Waiting for peer handshakes to complete" (version=0)
 * - "Peers have completed handshake but are at height 0" (true bootstrap)
 *
 * The old condition `bestPeerHeight == 0 && peerCount > 0` incorrectly returned
 * IBD=true when all peers were legitimately at height 0.
 *
 * Bitcoin Core reference: src/validation.cpp IsInitialBlockDownload()
 */
bool IsInitialBlockDownload() {
    // LATCH MECHANISM: Once we exit IBD, we never re-enter
    // This prevents mining from being disabled by transient network conditions
    // (e.g., a peer reconnecting, a temporary network split)
    static std::atomic<bool> s_initial_download_complete{false};
    if (s_initial_download_complete.load(std::memory_order_relaxed)) {
        return false;  // Already exited IBD - stay out forever
    }

    const CBlockIndex* tip = g_chainstate.GetTip();

    // No tip = no chain = definitely IBD
    if (!tip) {
        return true;
    }

    int ourHeight = tip->nHeight;

    // BUG #94 FIX: Check headers and peers BEFORE tip time!
    // The tip time check can exit IBD permanently (via the latch), so we MUST verify
    // we're actually synced before allowing that. During IBD, each newly downloaded
    // block has a recent timestamp (because blocks are actively being mined on the
    // network), which would cause premature IBD exit if checked first.

    // PRIMARY CRITERION: Check if headers are ahead of chain tip
    // This check MUST come first to prevent premature IBD exit during sync
    if (g_node_context.headers_manager) {
        int headerHeight = g_node_context.headers_manager->GetBestHeight();
        if (headerHeight > ourHeight) {
            return true;  // Headers ahead = actively downloading = IBD mode
        }
    }

    // SECONDARY CRITERION: Check peer heights (but only if peers have completed handshake)
    // Use the new HasCompletedHandshakes() to distinguish "waiting" from "at height 0"
    if (g_node_context.peer_manager) {
        int bestPeerHeight = g_node_context.peer_manager->GetBestPeerHeight();
        size_t peerCount = g_node_context.peer_manager->GetConnectionCount();

        // If we have peers that are ahead of us, stay in IBD
        if (bestPeerHeight > ourHeight + 6) {
            return true;  // Peers have 6+ more blocks - we're behind
        }

        // BUG #69 FIX: Only wait for handshakes if peers haven't completed any yet
        // If HasCompletedHandshakes() returns true, peers ARE at height 0 legitimately
        if (peerCount > 0 && bestPeerHeight == 0 && !g_node_context.peer_manager->HasCompletedHandshakes()) {
            // Connections exist but NO peer has completed handshake - wait
            return true;
        }

        // BUG #156 FIX: Require peers before allowing IBD exit
        // Without peers, we can't know if we're actually synced - stay in IBD
        // This prevents premature IBD exit when starting with existing chainstate
        if (peerCount == 0) {
            return true;  // No peers = can't verify sync status = stay in IBD
        }

        // BUG #156 FIX: Must have synced to peer's reported height
        // Don't exit IBD until our chain matches what peers report
        if (bestPeerHeight > 0 && ourHeight < bestPeerHeight - 1) {
            return true;  // Haven't reached peer height yet
        }
    }

    // TERTIARY CRITERION: Is tip timestamp recent?
    // Only check this AFTER verifying we're synced to peers.
    int64_t tipTime = tip->nTime;
    int64_t now = GetTime();
    const int64_t MAX_TIP_AGE = 24 * 60 * 60;  // 24 hours (same as Bitcoin Core)

    if (now - tipTime < MAX_TIP_AGE) {
        // Tip is recent AND we're synced to peers - exit IBD permanently
        std::cout << "[IBD] Exiting IBD - synced to height " << ourHeight << std::endl;
        s_initial_download_complete.store(true, std::memory_order_relaxed);
        g_utxo_sync_enabled.store(true, std::memory_order_relaxed);  // Enable disk sync for durability
        return false;
    }

    // If we get here:
    // - Tip exists but is stale (> 24 hours old)
    // - No headers ahead (not actively downloading)
    // - Have peers and synced to their height
    // This is likely a bootstrap scenario or stale network - allow mining
    std::cout << "[IBD] Exiting IBD (stale tip but synced) - height " << ourHeight << std::endl;
    s_initial_download_complete.store(true, std::memory_order_relaxed);
    g_utxo_sync_enabled.store(true, std::memory_order_relaxed);  // Enable disk sync for durability
    return false;
}

// Signal handler for graceful shutdown
void SignalHandler(int signal) {
    LogPrintf(ALL, INFO, "Received signal %d, shutting down gracefully...", signal);
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    g_node_state.running = false;

        if (g_node_state.rpc_server) {
            g_node_state.rpc_server->Stop();
            std::cout << " ✓" << std::endl;
        }
    if (g_node_state.miner) {
        g_node_state.miner->StopMining();
    }
    if (g_node_state.p2p_socket) {
        g_node_state.p2p_socket->Close();
    }
    if (g_node_state.http_server) {
        g_node_state.http_server->Stop();
    }
}

// Parse command line arguments
struct NodeConfig {
    bool testnet = false;
    bool regtest = false;  // Phase 5: regression-test mode (isolated network)
    std::string datadir = "";       // Will be set based on network
    uint16_t rpcport = 0;           // Will be set based on network
    uint16_t p2pport = 0;           // Will be set based on network
    bool start_mining = false;
    int mining_threads = 0;         // 0 = auto-detect
    std::string mining_address_override = "";  // --mining-address=Dxxx (empty = use wallet)
    bool rotate_mining_address = false;        // --rotate-mining-address (new HD address per block)
    std::string restore_mnemonic = "";        // --restore-mnemonic="word1 word2..." (restore wallet from seed)
    std::vector<std::string> connect_nodes;  // --connect nodes (exclusive)
    std::vector<std::string> add_nodes;      // --addnode nodes (additional)
    bool reindex = false;           // Phase 4.2: Rebuild block index from blocks on disk
    bool rescan = false;            // Phase 4.2: Rescan wallet transactions
    bool reset_chain = false;       // --reset-chain: wipe chain-derived state, keep wallet/MIK
    bool yes_flag = false;          // --yes: bypass --reset-chain confirmation prompt
    bool verbose = false;           // Show debug output (hidden by default)
    bool quiet = false;             // Quiet mode: only block lifecycle, errors, and warnings
    bool relay_only = false;        // Relay-only mode: skip wallet creation (for seed nodes)
    bool upnp_enabled = false;      // Enable UPnP automatic port mapping
    bool upnp_prompted = false;     // True if user was already prompted or used explicit flag
    std::string external_ip = "";   // --externalip: Manual external IP (for manual port forwarding)
    bool public_api = false;        // --public-api: Enable public REST API for light wallets (seed nodes only)
    int max_connections = 0;         // --maxconnections: Maximum peer connections (0 = default 125)
    int max_connections_per_ip = 2;  // --max-connections-per-ip: Max inbound per IP (default 2, range 1-64)
    int attestation_rate_limit = 1;  // --attestation-rate-limit: Max attestations per /24 subnet per day
    bool shared_heat = true;         // Phase 3b: shared cluster heat (default ON)
    // use_new_peerman field removed in v4.3.4 cut Block 8 with the --usenewpeerman
    // flag retirement (port::CPeerManager class deleted in Block 7; flag was a no-op
    // since Block 7).

    bool ParseArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);

            if (arg == "--testnet") {
                testnet = true;
            }
            else if (arg == "--regtest") {
                regtest = true;
            }
            else if (arg.find("--datadir=") == 0) {
                datadir = arg.substr(10);
            }
            else if (arg.find("--rpcport=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid port numbers
                try {
                    int port = std::stoi(arg.substr(10));
                    if (port < Consensus::MIN_PORT || port > Consensus::MAX_PORT) {
                        ErrorMessage error = CErrorFormatter::ConfigError("rpcport", 
                            "Port must be between " + std::to_string(Consensus::MIN_PORT) + 
                            " and " + std::to_string(Consensus::MAX_PORT));
                        std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
                        return false;
                    }
                    rpcport = static_cast<uint16_t>(port);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid RPC port format (not a number): " << arg << std::endl;
                    return false;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: RPC port number out of range: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--port=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid port numbers
                try {
                    int port = std::stoi(arg.substr(7));
                    if (port < Consensus::MIN_PORT || port > Consensus::MAX_PORT) {
                        std::cerr << "Error: Invalid P2P port (must be " << Consensus::MIN_PORT
                                  << "-" << Consensus::MAX_PORT << "): " << arg << std::endl;
                        return false;
                    }
                    p2pport = static_cast<uint16_t>(port);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: Invalid P2P port format (not a number): " << arg << std::endl;
                    return false;
                } catch (const std::out_of_range& e) {
                    std::cerr << "Error: P2P port number out of range: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--connect=") == 0) {
                connect_nodes.push_back(arg.substr(10));
            }
            else if (arg.find("--addnode=") == 0) {
                add_nodes.push_back(arg.substr(10));
            }
            else if (arg == "--mine") {
                start_mining = true;
            }
            else if (arg.find("--threads=") == 0) {
                // PHASE 4 FIX: Add exception handling for invalid thread count
                std::string threads_str = arg.substr(10);

                // Support "auto" for automatic thread detection
                if (threads_str == "auto" || threads_str == "AUTO") {
                    mining_threads = 0;  // 0 means auto-detect
                } else {
                    try {
                        int threads = std::stoi(threads_str);
                        if (threads < Consensus::MIN_MINING_THREADS || threads > Consensus::MAX_MINING_THREADS) {
                            std::cerr << "Error: Invalid thread count (must be " << Consensus::MIN_MINING_THREADS
                                      << "-" << Consensus::MAX_MINING_THREADS << " or 'auto'): " << arg << std::endl;
                            return false;
                        }
                        mining_threads = threads;
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Error: Invalid thread count (must be a number or 'auto'): " << arg << std::endl;
                        return false;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Error: Thread count number out of range: " << arg << std::endl;
                        return false;
                    }
                }
            }
            else if (arg.find("--mining-address=") == 0) {
                mining_address_override = arg.substr(17);
                // Validate address format (allow any valid address, even external)
                CDilithiumAddress testAddr;
                if (!testAddr.SetString(mining_address_override)) {
                    std::cerr << "Error: Invalid mining address: " << mining_address_override << std::endl;
                    std::cerr << "Address must start with 'D' and be 34 characters" << std::endl;
                    return false;
                }
            }
            else if (arg == "--rotate-mining-address") {
                rotate_mining_address = true;
            }
            else if (arg.find("--restore-mnemonic=") == 0) {
                restore_mnemonic = arg.substr(19);
                // Basic validation: should have 24 words
                std::istringstream iss(restore_mnemonic);
                std::vector<std::string> words;
                std::string word;
                while (iss >> word) {
                    words.push_back(word);
                }
                if (words.size() != 24) {
                    std::cerr << "Error: Recovery phrase must be exactly 24 words (got " << words.size() << ")" << std::endl;
                    return false;
                }
            }
            else if (arg == "--reindex" || arg == "-reindex") {
                // Phase 4.2: Rebuild block index from blocks on disk
                reindex = true;
            }
            else if (arg == "--reset-chain") {
                // Wipe chain-derived state (blocks, chainstate, headers, dna_registry),
                // preserve wallet.dat and mik_registration.dat. Exits after reset.
                reset_chain = true;
            }
            else if (arg == "--yes" || arg == "-y") {
                // Bypass interactive confirmation (currently only used by --reset-chain)
                yes_flag = true;
            }
            else if (arg == "--rescan" || arg == "-rescan") {
                // Phase 4.2: Rescan wallet transactions
                rescan = true;
            }
            else if (arg == "--verbose" || arg == "-v") {
                // Show debug output
                verbose = true;
            }
            else if (arg == "--quiet" || arg == "-q") {
                // Quiet mode: suppress operator-level messages, show only
                // block lifecycle events (SUBMITTED/CONFIRMED/NOT ACCEPTED),
                // errors, and warnings
                quiet = true;
            }
            else if (arg == "--relay-only") {
                // Relay-only mode: skip wallet creation (for seed nodes)
                relay_only = true;
            }
            else if (arg == "--public-api") {
                // Public REST API: bind to 0.0.0.0 for light wallet access (seed nodes only)
                public_api = true;
            }
            else if (arg == "--no-shared-heat") {
                // Disable Phase 3b shared cluster heat penalty
                shared_heat = false;
            }
            else if (arg == "--upnp") {
                // Enable UPnP automatic port mapping
                upnp_enabled = true;
                upnp_prompted = true;  // Don't prompt if explicitly enabled
            }
            else if (arg == "--no-upnp") {
                // Disable UPnP (don't prompt)
                upnp_enabled = false;
                upnp_prompted = true;  // Don't prompt if explicitly disabled
            }
            else if (arg.find("--externalip=") == 0) {
                // Manual external IP for port forwarding (when UPnP fails/unavailable)
                external_ip = arg.substr(13);
                upnp_prompted = true;  // Don't prompt for UPnP if using manual IP
            }
            else if (arg.find("--maxconnections=") == 0) {
                // Maximum peer connections (for limiting connections during sync)
                try {
                    int maxconn = std::stoi(arg.substr(17));
                    if (maxconn < 1 || maxconn > 1000) {
                        std::cerr << "Error: Invalid maxconnections (must be 1-1000): " << arg << std::endl;
                        return false;
                    }
                    max_connections = maxconn;
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid maxconnections format: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--max-connections-per-ip=") == 0) {
                // Max inbound connections per IP (for NAT: multiple nodes behind one router)
                try {
                    int val = std::stoi(arg.substr(25));
                    if (val < 1 || val > 64) {
                        std::cerr << "Error: Invalid max-connections-per-ip (must be 1-64): " << arg << std::endl;
                        return false;
                    }
                    max_connections_per_ip = val;
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid max-connections-per-ip format: " << arg << std::endl;
                    return false;
                }
            }
            else if (arg.find("--attestation-rate-limit=") == 0) {
                // Max MIK attestations per /24 subnet per day (Sybil defense).
                // Wired through SetAttestationRateLimit at startup. Was missing
                // a parser block until 2026-05-04 — flag silently fell through
                // to the unknown-arg handler.
                try {
                    int val = std::stoi(arg.substr(25));
                    if (val < 1 || val > 100) {
                        std::cerr << "Error: Invalid attestation-rate-limit (must be 1-100): " << arg << std::endl;
                        return false;
                    }
                    attestation_rate_limit = val;
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid attestation-rate-limit format: " << arg << std::endl;
                    return false;
                }
            }
            // --usenewpeerman flag arms removed in v4.3.4 cut Block 8.
            // The flag was retired alongside port::CPeerManager class
            // deletion (Block 7). Operator wrappers passing the flag will
            // hit the "Unknown option" error below; release notes call
            // this out so wrappers can be cleaned up.
            else if (arg == "--help" || arg == "-h") {
                return false;
            }
            else {
                std::cerr << "Unknown option: " << arg << std::endl;
                return false;
            }
        }
        return true;
    }

    void PrintUsage(const char* program) {
        std::cout << "Dilithion Node - Post-Quantum Cryptocurrency" << std::endl;
        std::cout << std::endl;
        std::cout << "Usage: " << program << " [options]" << std::endl;
        std::cout << std::endl;
        std::cout << "\033[1;32mQUICK START (Beginners):\033[0m" << std::endl;
        std::cout << "  " << program << "              No arguments = Auto-start testnet mining!" << std::endl;
        std::cout << "                            • Testnet mode" << std::endl;
        std::cout << "                            • Auto-connect to seed node" << std::endl;
        std::cout << "                            • Auto-detect CPU threads" << std::endl;
        std::cout << "                            • Start mining immediately" << std::endl;
        std::cout << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --testnet             Use testnet (production difficulty, ~60s blocks)" << std::endl;
        std::cout << "  --datadir=<path>      Data directory (default: network-specific)" << std::endl;
        std::cout << "  --port=<port>         P2P network port (default: network-specific)" << std::endl;
        std::cout << "  --rpcport=<port>      RPC server port (default: network-specific)" << std::endl;
        std::cout << "  --connect=<ip:port>   Connect to node (disables DNS seeds)" << std::endl;
        std::cout << "  --addnode=<ip:port>   Add node to connect to (repeatable)" << std::endl;
        std::cout << "  --mine                Start mining automatically" << std::endl;
        std::cout << "  --threads=<n|auto>    Mining threads (number or 'auto' to detect)" << std::endl;
        std::cout << "  --mining-address=<addr> Send mining rewards to this address" << std::endl;
        std::cout << "  --rotate-mining-address Use a new HD address for each mined block" << std::endl;
        std::cout << "  --restore-mnemonic=\"words\" Restore wallet from 24-word recovery phrase" << std::endl;
        std::cout << "  --verbose, -v         Show debug output (hidden by default)" << std::endl;
        std::cout << "  --quiet, -q           Quiet mode: only block events, errors, and warnings" << std::endl;
        std::cout << "  --reindex             Rebuild blockchain from scratch (use after crash)" << std::endl;
        std::cout << "  --reset-chain         Wipe chain state for a clean resync." << std::endl;
        std::cout << "                          Preserves wallet.dat and mik_registration.dat" << std::endl;
        std::cout << "                          so miners do NOT re-solve the registration PoW." << std::endl;
        std::cout << "                          Add --yes to skip the confirmation prompt." << std::endl;
        std::cout << "  --relay-only          Relay-only mode: skip wallet (for seed nodes)" << std::endl;
        std::cout << "  --public-api          Enable public REST API for light wallets (seed nodes)" << std::endl;
        std::cout << "  --no-shared-heat      Disable shared cluster heat penalty" << std::endl;
        std::cout << "  --upnp                Enable automatic port mapping (UPnP)" << std::endl;
        std::cout << "  --no-upnp             Disable UPnP (don't prompt)" << std::endl;
        std::cout << "  --externalip=<ip>     Your public IP (for manual port forwarding)" << std::endl;
        std::cout << "  --maxconnections=<n>  Maximum peer connections (default: 125)" << std::endl;
        std::cout << "  --max-connections-per-ip=<n>" << std::endl;
        std::cout << "                        Max inbound connections per IP (default: 2, range: 1-64)" << std::endl;
        std::cout << "  --help, -h            Show this help message" << std::endl;
        std::cout << std::endl;
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Configuration file: dilithion.conf (in data directory)" << std::endl;
        std::cout << "  Environment variables: DILITHION_* (e.g., DILITHION_RPCPORT=8332)" << std::endl;
        std::cout << "  Priority: Command-line > Environment > Config file > Default" << std::endl;
        std::cout << std::endl;
        std::cout << "Network Defaults:" << std::endl;
        std::cout << "  Mainnet:  datadir=.dilithion         port=8444  rpcport=8332" << std::endl;
        std::cout << "  Testnet:  datadir=.dilithion-testnet port=18444 rpcport=18332" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  " << program << "                                                    (Quick start mainnet)" << std::endl;
        std::cout << "  " << program << " --mine --threads=auto                               (Mainnet mining)" << std::endl;
        std::cout << "  " << program << " --testnet --mine                                    (Testnet mining)" << std::endl;
        std::cout << "  " << program << " --testnet --addnode=134.122.4.164:18444 --mine     (Testnet with seed)" << std::endl;
        std::cout << std::endl;
        std::cout << "Post-Quantum Security Stack:" << std::endl;
        std::cout << "  Mining:      RandomX (CPU-friendly, ASIC-resistant)" << std::endl;
        std::cout << "  Signatures:  CRYSTALS-Dilithium3 (NIST PQC standard)" << std::endl;
        std::cout << "  Hashing:     SHA-3/Keccak-256 (quantum-resistant)" << std::endl;
        std::cout << std::endl;
    }
};

// Global coinbase transaction reference for mining callback
static CTransactionRef g_currentCoinbase;
static std::mutex g_coinbaseMutex;

// v4.0.18: CRegistrationManager owns all first-time MIK registration state.
// BuildMiningTemplate is now a pure reader of its published snapshot. The old
// g_regCachedNonce / g_regNonceMined / g_regPowInProgress / g_regNonceIdentity
// / g_cachedAttestations / g_attestationsCollected / g_cachedDnaHash /
// g_dnaHashCached globals have been removed from globals.cpp — they were the
// race-condition anchor point.
//
// The RPC server reaches the live manager via GetRegistrationManager();
// the miner loop holds its own unique_ptr and also publishes via
// SetRegistrationManager() so the RPC server sees the same instance.
static std::unique_ptr<CRegistrationManager> s_registrationManager;
void SetRegistrationManager(CRegistrationManager* mgr);  // defined in globals.cpp

// Data directory (defined in globals.cpp, set in main before any PoW save/load).
extern std::string g_datadir;

/**
 * Ensure the registration manager exists; lazily construct on first call.
 * Requires wallet + g_node_context + g_chainParams to be fully initialized.
 */
static void EnsureRegistrationManagerInitialized(CWallet& wallet) {
    if (s_registrationManager) return;
    if (!Dilithion::g_chainParams) return;  // too early

    auto env = std::make_shared<CProductionRegistrationEnv>(
        wallet,
        g_node_context,
        g_datadir,
        Dilithion::g_chainParams->registrationPowBits,
        Dilithion::g_chainParams->dnaCommitmentActivationHeight,
        Dilithion::g_chainParams->seedAttestationActivationHeight);
    s_registrationManager = std::make_unique<CRegistrationManager>(std::move(env));
    // Publish to the global accessor so the RPC server can reach the same
    // instance (prevents two parallel registration flows / double-PoW).
    SetRegistrationManager(s_registrationManager.get());
}

/**
 * Drive the CRegistrationManager and block until registration is ready or
 * a fatal error occurs. Replaces the old inline DNA/attestation/PoW flow.
 *
 * Semantics match the old EnsureMIKRegistered():
 *   - true:  registration is ready (CanMine() == true) OR node below activation height
 *   - false: fatal or user-actionable error; mining must be deferred
 */
bool EnsureMIKRegistered(CWallet& wallet, unsigned int nextHeight) {
    if (!DFMP::g_identityDb) return true;
    if (!Dilithion::g_chainParams ||
        static_cast<int>(nextHeight) < Dilithion::g_chainParams->dfmpV3ActivationHeight) {
        return true;
    }

    // Generate MIK identity if wallet does not have one yet.
    DFMP::Identity identity = wallet.GetMIKIdentity();
    if (identity.IsNull()) {
        if (!wallet.GenerateMIK()) {
            std::cerr << "[Mining] WARNING: Failed to generate miner identity" << std::endl;
            return false;
        }
        identity = wallet.GetMIKIdentity();
        std::cout << "[Mining] Generated new miner identity: " << identity.GetHex() << std::endl;
    }

    EnsureRegistrationManagerInitialized(wallet);
    if (!s_registrationManager) return false;

    // First-time miner banner — fires once per process lifetime, only for
    // unregistered MIKs. Sets accurate expectations so users don't think
    // the node is stuck during the DNA-bound registration PoW.
    static bool s_bannerShown = false;
    if (!s_bannerShown && !DFMP::g_identityDb->HasMIKPubKey(identity)) {
        std::cout << std::endl;
        std::cout << "+----------------------------------------------------------------------+" << std::endl;
        std::cout << "|  FIRST-TIME MINER SETUP (DIL)                                        |" << std::endl;
        std::cout << "|                                                                      |" << std::endl;
        std::cout << "|  Your miner identity is not yet registered on DIL. Before your       |" << std::endl;
        std::cout << "|  first block, the node runs a ONE-TIME setup sequence:               |" << std::endl;
        std::cout << "|                                                                      |" << std::endl;
        std::cout << "|    1. Digital DNA fingerprint (hardware-bound, passive)              |" << std::endl;
        std::cout << "|    2. Seed attestations (3-of-4, required above height 40000)        |" << std::endl;
        std::cout << "|    3. Registration proof-of-work (DNA-bound)                         |" << std::endl;
        std::cout << "|                                                                      |" << std::endl;
        std::cout << "|  The proof-of-work dominates total time. On a modern CPU, typical    |" << std::endl;
        std::cout << "|  completion is 15-30 minutes. PoW is RANDOMLY PROBABILISTIC: you     |" << std::endl;
        std::cout << "|  may finish significantly faster, and ~12% of miners see 2x or       |" << std::endl;
        std::cout << "|  more (up to an hour). Both fast and slow outcomes are NORMAL hash   |" << std::endl;
        std::cout << "|  luck, not a stuck node. Let it run.                                 |" << std::endl;
        std::cout << "|                                                                      |" << std::endl;
        std::cout << "|  After setup, the solved PoW is saved to mik_registration.dat --     |" << std::endl;
        std::cout << "|  subsequent restarts skip all of this and begin mining immediately.  |" << std::endl;
        std::cout << "+----------------------------------------------------------------------+" << std::endl;
        std::cout << std::endl;
        s_bannerShown = true;
    }

    // Drive the manager and wait for readiness. The manager's worker thread
    // does DNA collection, seed attestations, and PoW; we poll the snapshot
    // and log progress as the mine-gate reason changes.
    auto tipHeight = (g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0);
    s_registrationManager->Tick(tipHeight, g_node_state.running.load());

    using State = CRegistrationManager::State;
    using Reason = CRegistrationManager::MineGateReason;
    Reason lastReason = Reason::BLOCKED_UNINITIALIZED;
    while (g_node_state.running.load()) {
        auto snap = s_registrationManager->GetSnapshot();

        if (snap->state == State::CONFIRMED ||
            snap->state == State::READY ||
            snap->state == State::SUBMITTED) {
            return true;
        }
        if (snap->state == State::FAILED_FATAL) {
            std::cerr << "[Mining] Registration fatal error: " << snap->lastError << std::endl;
            return false;
        }
        if (snap->state == State::LONG_BACKOFF_USER_ACTIONABLE) {
            std::cerr << "[Mining] Registration blocked: " << snap->lastError << std::endl;
            if (!snap->userActionHint.empty()) {
                std::cerr << "[Mining]   -> " << snap->userActionHint << std::endl;
            }
            return false;
        }

        if (snap->mineGate != lastReason) {
            auto status = s_registrationManager->GetStatusForUI();
            std::cout << "  [Mining] Phase: " << status.phase
                      << " — " << status.message;
            if (!status.etaText.empty()) std::cout << " (" << status.etaText << ")";
            std::cout << std::endl;
            lastReason = snap->mineGate;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
        s_registrationManager->Tick(tipHeight, g_node_state.running.load());
    }
    return false;
}

/**
 * Build mining template for next block
 * @param blockchain Reference to blockchain database
 * @param wallet Reference to wallet (for coinbase reward address)
 * @param verbose If true, print detailed template information
 * @param mining_address_override Optional address to override wallet address (for --mining-address flag)
 * @return Optional containing template if successful, nullopt if error
 */
std::optional<CBlockTemplate> BuildMiningTemplate(CBlockchainDB& blockchain, CWallet& wallet, bool verbose = false, const std::string& mining_address_override = "") {
    // Get blockchain tip to build on
    uint256 hashBestBlock;
    uint32_t nHeight = 0;

    // BUG #65 FIX: Add logging to diagnose template build failures
    std::cout << "[Mining] Building template - reading best block from DB..." << std::endl;

    if (!blockchain.ReadBestBlock(hashBestBlock)) {
        std::cerr << "[Mining] ERROR: Cannot read best block from blockchain database" << std::endl;
        return std::nullopt;
    }

    // BUG #65: Always log the best block hash for debugging
    std::cout << "[Mining] Building template on best block: "
              << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;

    if (verbose) {
        std::cout << "  Best block hash: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // CRITICAL FIX: Use g_chainstate.GetTip() for difficulty calculation
    // Database reads return CBlockIndex without pprev linkage, breaking
    // GetNextWorkRequired() which needs to walk back 2015 blocks via pprev.
    const CBlockIndex* pindexPrev = g_chainstate.GetTip();
    if (pindexPrev != nullptr && pindexPrev->GetBlockHash() == hashBestBlock) {
        nHeight = pindexPrev->nHeight + 1;  // New block height
        if (verbose) {
            std::cout << "  Building on block height " << pindexPrev->nHeight << std::endl;
            std::cout << "  Mining block height " << nHeight << std::endl;
        }
    } else if (pindexPrev != nullptr) {
        // Chain tip doesn't match DB - use chain tip anyway (has pprev linkage)
        std::cerr << "[Mining] WARNING: Chain tip doesn't match DB best block" << std::endl;
        hashBestBlock = pindexPrev->GetBlockHash();
        nHeight = pindexPrev->nHeight + 1;
        if (verbose) {
            std::cout << "  Using chain tip at height " << pindexPrev->nHeight << std::endl;
        }
    } else {
        if (verbose) {
            std::cout << "  WARNING: Chain state has no tip" << std::endl;
            std::cout << "  Assuming best block is genesis, mining block 1" << std::endl;
        }
        nHeight = 1;  // Mining block 1 (after genesis at 0)
    }

    // Create block header
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = hashBestBlock;
    // CID 1675302 FIX: Use safe 64-to-32 bit time conversion
    // Block timestamps are uint32_t per blockchain protocol (valid until year 2106)
    time_t currentTime = std::time(nullptr);
    block.nTime = static_cast<uint32_t>(currentTime & 0xFFFFFFFF);

    // MTP validation: block timestamp must exceed Median-Time-Past.
    // If current time is behind MTP (e.g. clock skew), bump to MTP + 1
    // to avoid mining a block that consensus would reject.
    // Same approach as Bitcoin Core's CreateNewBlock().
    if (pindexPrev) {
        int64_t nMedianTimePast = GetMedianTimePast(pindexPrev);
        if (static_cast<int64_t>(block.nTime) <= nMedianTimePast) {
            block.nTime = static_cast<uint32_t>(nMedianTimePast + 1);
        }
    }

    // Pass block timestamp to GetNextWorkRequired for EDA (Emergency Difficulty Adjustment)
    // If the gap since the last block exceeds the EDA threshold, difficulty is reduced
    block.nBits = GetNextWorkRequired(pindexPrev, static_cast<int64_t>(block.nTime));

    block.nNonce = 0;

    // Get wallet address for coinbase reward
    CDilithiumAddress minerAddress;
    std::vector<uint8_t> minerPubKeyHash;

    if (!mining_address_override.empty()) {
        // Fixed address mode: use the override address
        minerAddress.SetString(mining_address_override);
        // Extract pubkey hash from address (skip version byte)
        const std::vector<uint8_t>& addrData = minerAddress.GetData();
        if (addrData.size() >= 21) {
            minerPubKeyHash.assign(addrData.begin() + 1, addrData.begin() + 21);
        }
    } else if (g_node_state.rotate_mining_address && wallet.IsHDWallet()) {
        // Rotating address mode: derive a new HD address for each block
        minerAddress = wallet.GetNewHDAddress();
        if (!minerAddress.IsValid()) {
            // Fallback to default if HD derivation fails (e.g. wallet locked)
            minerAddress = wallet.GetNewAddress();
            minerPubKeyHash = wallet.GetPubKeyHash();
        } else {
            std::vector<uint8_t> addrData = minerAddress.GetData();
            if (addrData.size() >= 21) {
                minerPubKeyHash.assign(addrData.begin() + 1, addrData.begin() + 21);
            }
        }
    } else {
        // Default: use wallet's default address (same address every block)
        minerAddress = wallet.GetNewAddress();
        minerPubKeyHash = wallet.GetPubKeyHash();
    }

    // Calculate block subsidy using chain parameters (supports DIL and DilV)
    int64_t nSubsidy = Dilithion::g_chainParams ?
        static_cast<int64_t>(Dilithion::g_chainParams->initialReward) :
        Consensus::INITIAL_BLOCK_SUBSIDY;
    uint64_t halvingInterval = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->halvingInterval : Consensus::SUBSIDY_HALVING_INTERVAL;
    int nHalvings = static_cast<int>(nHeight / halvingInterval);
    if (nHalvings >= Consensus::SUBSIDY_HALVING_BITS) {
        nSubsidy = 0;
    } else {
        nSubsidy >>= nHalvings;
    }

    // Create coinbase transaction
    CTransaction coinbaseTx;
    coinbaseTx.nVersion = 1;
    coinbaseTx.nLockTime = 0;

    // Coinbase input (null prevout)
    CTxIn coinbaseIn;
    coinbaseIn.prevout.SetNull();

    // DFMP v2.0: Build coinbase scriptSig with MIK data
    // Format: [height: 1-4 bytes] [msg: ~30 bytes] [MIK_MARKER] [MIK_TYPE] [MIK_DATA] [signature]
    std::vector<uint8_t> scriptSig;

    // 1. Height encoding (BIP 34 style)
    if (nHeight < 17) {
        scriptSig.push_back(0x50 + nHeight);  // OP_1 through OP_16
    } else if (nHeight < 128) {
        scriptSig.push_back(0x01);
        scriptSig.push_back(static_cast<uint8_t>(nHeight));
    } else if (nHeight < 32768) {
        scriptSig.push_back(0x02);
        scriptSig.push_back(static_cast<uint8_t>(nHeight & 0xFF));
        scriptSig.push_back(static_cast<uint8_t>((nHeight >> 8) & 0xFF));
    } else {
        scriptSig.push_back(0x03);
        scriptSig.push_back(static_cast<uint8_t>(nHeight & 0xFF));
        scriptSig.push_back(static_cast<uint8_t>((nHeight >> 8) & 0xFF));
        scriptSig.push_back(static_cast<uint8_t>((nHeight >> 16) & 0xFF));
    }

    // 2. Coinbase message
    std::string coinbaseMsg = "Block " + std::to_string(nHeight) + " mined by Dilithion";
    scriptSig.insert(scriptSig.end(), coinbaseMsg.begin(), coinbaseMsg.end());

    // 3. DFMP v2.0 MIK data
    DFMP::Identity mikIdentity = wallet.GetMIKIdentity();
    std::vector<uint8_t> mikSignature;
    std::vector<uint8_t> mikData;
    bool mikDataIncluded = false;

    // Generate MIK if wallet doesn't have one
    if (mikIdentity.IsNull()) {
        if (wallet.GenerateMIK()) {
            mikIdentity = wallet.GetMIKIdentity();
            std::cout << "[Mining] Generated new MIK identity: " << mikIdentity.GetHex() << std::endl;
        } else {
            std::cerr << "[Mining] WARNING: Failed to generate MIK" << std::endl;
        }
    }

    if (!mikIdentity.IsNull()) {
        // Sign with MIK (commits to prevHash, height, timestamp)
        if (wallet.SignWithMIK(hashBestBlock, nHeight, block.nTime, mikSignature)) {
            // Check if MIK is already registered
            bool isRegistered = DFMP::g_identityDb && DFMP::g_identityDb->HasMIKPubKey(mikIdentity);

            if (!isRegistered) {
                // Registration path — all registration material comes from the
                // RegistrationManager's snapshot. BuildMiningTemplate is a PURE
                // READER: no inline PoW mining, no DNA collection, no attestation
                // RPC, no state mutation. All that work happens in the manager's
                // worker thread, gated through CanMine().
                std::vector<uint8_t> mikPubkey;
                std::shared_ptr<const CRegistrationManager::Snapshot> regSnap;
                if (s_registrationManager) regSnap = s_registrationManager->GetSnapshot();

                if (!regSnap || !regSnap->hasRegNonce || !regSnap->hasDnaHash ||
                    regSnap->mikPubkey.empty()) {
                    if (verbose) {
                        std::cout << "  MIK: Skipped (registration manager not ready)" << std::endl;
                    }
                } else {
                    mikPubkey = regSnap->mikPubkey;
                    uint64_t regNonce = regSnap->regNonce;
                    if (DFMP::BuildMIKScriptSigRegistration(mikPubkey, mikSignature, regNonce, mikData)) {
                        scriptSig.insert(scriptSig.end(), mikData.begin(), mikData.end());
                        mikDataIncluded = true;
                        if (verbose) {
                            std::cout << "  MIK: Registration (first block with this identity)" << std::endl;
                        }
                    }
                }
            } else {
                // MIK already registered - use reference format
                if (DFMP::BuildMIKScriptSigReference(mikIdentity, mikSignature, mikData)) {
                    scriptSig.insert(scriptSig.end(), mikData.begin(), mikData.end());
                    mikDataIncluded = true;
                    if (verbose) {
                        std::cout << "  MIK: Reference (identity already registered)" << std::endl;
                    }
                }
            }
        } else {
            std::cerr << "[Mining] WARNING: Failed to sign with MIK" << std::endl;
        }
    } else {
        std::cerr << "[Mining] WARNING: No MIK identity in wallet" << std::endl;
    }

    // Digital DNA commitment: append 0xDD + 32-byte hash after MIK data.
    // For registration blocks: use the manager's session DNA hash (consensus-
    // consistent with attestation + PoW since all three were locked together).
    // For normal blocks: use live DNA from collector.
    if (mikDataIncluded && Dilithion::g_chainParams &&
        static_cast<int>(nHeight) >= Dilithion::g_chainParams->dnaCommitmentActivationHeight) {
        bool isRegBlock = DFMP::g_identityDb && !mikIdentity.IsNull() &&
            !DFMP::g_identityDb->HasMIKPubKey(mikIdentity);

        std::shared_ptr<const CRegistrationManager::Snapshot> regSnap;
        if (s_registrationManager) regSnap = s_registrationManager->GetSnapshot();

        if (isRegBlock && regSnap && regSnap->hasDnaHash) {
            DFMP::BuildDNACommitment(regSnap->dnaHash, scriptSig);
            if (verbose) {
                std::cout << "  DNA: Registration commitment (session hash " << std::hex;
                for (int i = 0; i < 4; i++) std::cout << std::setfill('0') << std::setw(2) << (int)regSnap->dnaHash[i];
                std::cout << std::dec << "...)" << std::endl;
            }
        } else {
            auto collector = g_node_context.GetDNACollector();
            if (collector) {
                auto dna = collector->get_dna();
                if (dna) {
                    auto dnaHash = dna->hash();
                    DFMP::BuildDNACommitment(dnaHash, scriptSig);
                    if (verbose) {
                        std::cout << "  DNA: Commitment included (hash " << std::hex;
                        for (int i = 0; i < 4; i++) std::cout << (int)dnaHash[i];
                        std::cout << std::dec << "...)" << std::endl;
                    }
                }
            }
        }
    }

    // Phase 2+3: Append seed attestation data after DNA commitment (registration blocks only).
    // The CRegistrationManager owns attestation collection + freshness — BuildMiningTemplate
    // only READS the attestation set from the snapshot. Stale attestations are refreshed
    // automatically by the manager's worker (HandleReady_). If the manager doesn't have
    // a fresh attestation set, we return nullopt and the miner waits for the next template.
    bool isRegistrationBlock = mikDataIncluded &&
        DFMP::g_identityDb && !mikIdentity.IsNull() &&
        !DFMP::g_identityDb->HasMIKPubKey(mikIdentity);
    if (isRegistrationBlock) {
        int activationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->seedAttestationActivationHeight : 999999999;

        std::shared_ptr<const CRegistrationManager::Snapshot> regSnap;
        if (s_registrationManager) regSnap = s_registrationManager->GetSnapshot();

        if (static_cast<int>(nHeight) >= activationHeight) {
            if (!regSnap || !regSnap->hasAttestations || !regSnap->attestations ||
                !regSnap->attestations->HasMinimum()) {
                std::cerr << "[Mining] Template deferred - registration block at height "
                          << nHeight << " waiting for seed attestations (manager state="
                          << StateToString(regSnap ? regSnap->state
                                                    : CRegistrationManager::State::UNINITIALIZED)
                          << ")" << std::endl;
                return std::nullopt;
            }
        }

        if (regSnap && regSnap->attestations && regSnap->attestations->HasMinimum()) {
            std::vector<uint8_t> attestData;
            if (Attestation::BuildAttestationScriptData(*regSnap->attestations, attestData)) {
                scriptSig.insert(scriptSig.end(), attestData.begin(), attestData.end());
                if (verbose) {
                    std::cout << "  Attestations: " << regSnap->attestations->Count()
                              << " seed attestations included ("
                              << attestData.size() << " bytes)" << std::endl;
                }
            }
        }
    }

    // BUG #257 FIX: Refuse to build template without MIK data for post-assume-valid heights.
    // Race condition: if registration PoW is in progress on another thread, MIK data
    // is skipped (regNonce = UINT64_MAX sentinel). Mining with such a template produces
    // blocks that fail CheckProofOfWorkDFMP() with "Missing or malformed MIK data".
    // Return nullopt so the miner keeps its previous valid template.
    if (!mikDataIncluded && Dilithion::g_chainParams) {
        int assumeValidHeight = Dilithion::g_chainParams->dfmpAssumeValidHeight;
        if (static_cast<int>(nHeight) > assumeValidHeight) {
            std::cerr << "[Mining] WARNING: Template rejected - no MIK data for height "
                      << nHeight << " (required above assume-valid height " << assumeValidHeight << ")" << std::endl;
            std::cerr << "[Mining] This can happen during MIK registration PoW mining. "
                      << "Template will be rebuilt once registration completes." << std::endl;
            return std::nullopt;
        }
    }

    coinbaseIn.scriptSig = scriptSig;
    coinbaseIn.nSequence = 0xffffffff;
    coinbaseTx.vin.push_back(coinbaseIn);

    // BUG #109 FIX: Include mempool transactions in mined blocks
    // Previously, this function only included the coinbase transaction.
    // Now we select valid transactions from mempool just like CreateBlockTemplate does.

    // Load mempool and UTXO set from global atomic pointers
    CTxMemPool* mempool = g_mempool.load();
    CUTXOSet* utxoSet = g_utxo_set.load();

    // Select transactions from mempool if available
    std::vector<CTransactionRef> selectedTxs;
    uint64_t totalFees = 0;

    if (mempool && utxoSet) {
        // Get transactions ordered by fee rate (highest first)
        std::vector<CTransactionRef> candidateTxs = mempool->GetOrderedTxs();

        // Limit candidates and set resource limits
        const size_t MAX_CANDIDATES = 50000;
        const size_t MAX_BLOCK_SIZE = Dilithion::g_chainParams
            ? Dilithion::g_chainParams->maxBlockSize : 4 * 1024 * 1024;  // Use chain params (4 MB)
        size_t currentBlockSize = 200;  // Reserve for coinbase

        if (candidateTxs.size() > MAX_CANDIDATES) {
            candidateTxs.resize(MAX_CANDIDATES);
        }

        std::set<COutPoint> spentInBlock;
        CTransactionValidator validator;

        for (const auto& tx : candidateTxs) {
            if (tx->IsCoinBase()) continue;

            size_t txSize = tx->GetSerializedSize();
            if (currentBlockSize + txSize > MAX_BLOCK_SIZE) continue;

            // ========================================================================
            // BUG #109 FIX (Part 4): Enhanced input availability logging
            // ========================================================================
            // Check inputs are available and not double-spent in this block
            bool allInputsAvailable = true;
            bool hasConflict = false;
            std::string missingInputInfo;  // For detailed logging

            for (const auto& txin : tx->vin) {
                if (spentInBlock.count(txin.prevout) > 0) {
                    hasConflict = true;
                    missingInputInfo = "input " + txin.prevout.hash.GetHex().substr(0, 16) +
                                      ":" + std::to_string(txin.prevout.n) + " already spent in this block";
                    break;
                }

                CUTXOEntry utxoEntry;
                bool foundInUTXO = utxoSet->GetUTXO(txin.prevout, utxoEntry);

                bool foundInBlock = false;
                for (const auto& selectedTx : selectedTxs) {
                    if (selectedTx->GetHash() == txin.prevout.hash &&
                        txin.prevout.n < selectedTx->vout.size()) {
                        foundInBlock = true;
                        break;
                    }
                }

                if (!foundInUTXO && !foundInBlock) {
                    allInputsAvailable = false;
                    missingInputInfo = "input " + txin.prevout.hash.GetHex().substr(0, 16) +
                                      ":" + std::to_string(txin.prevout.n) +
                                      " NOT in UTXO set and NOT in selected block txs";
                    break;
                }
            }

            if (hasConflict || !allInputsAvailable) {
                std::cout << "[Mining] Skipping tx " << tx->GetHash().GetHex().substr(0, 16)
                          << "...: " << (hasConflict ? "conflict" : missingInputInfo) << std::endl;
                continue;
            }

            // Validate transaction (signature, coinbase maturity, etc.)
            std::string validationError;
            CAmount txFee = 0;
            if (!validator.CheckTransaction(*tx, *utxoSet, nHeight, txFee, validationError)) {
                std::cerr << "[Mining] Rejecting tx " << tx->GetHash().GetHex().substr(0, 16)
                          << "... from template: " << validationError << std::endl;
                continue;
            }

            // Sanity check on fee
            const uint64_t MAX_REASONABLE_FEE = 10 * COIN;
            if (txFee > MAX_REASONABLE_FEE) {
                std::cerr << "[Mining] Rejecting tx " << tx->GetHash().GetHex().substr(0, 16)
                          << "... from template: fee too high (" << txFee << " ions)" << std::endl;
                continue;
            }

            // Add transaction to block
            selectedTxs.push_back(tx);
            currentBlockSize += txSize;
            totalFees += static_cast<uint64_t>(txFee);

            // Mark inputs as spent
            for (const auto& txin : tx->vin) {
                spentInBlock.insert(txin.prevout);
            }
        }

        if (!selectedTxs.empty()) {
            std::cout << "[Mining] Including " << selectedTxs.size()
                      << " mempool transactions, fees: " << totalFees << " ions" << std::endl;
        }
    }

    // =========================================================================
    // Mining Development Contribution (2% of subsidy, MAINNET ONLY)
    // - Dev Fund:   1% of subsidy (infrastructure, audits, community)
    // - Dev Reward: 1% of subsidy (core developer compensation)
    // - Miner:      98% of subsidy + 100% of fees (mainnet)
    //               100% of subsidy + 100% of fees (testnet)
    // =========================================================================
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();

    int64_t minerAmount = nSubsidy;
    int64_t devFundAmount = 0;
    int64_t devRewardAmount = 0;

    if (!isTestnet) {
        // MAINNET: Apply 2% mining tax (split 50/50 between dev fund and dev reward)
        int64_t taxTotal = (nSubsidy * Consensus::MINING_TAX_PERCENT) / 100;
        devFundAmount = (taxTotal * Consensus::DEV_FUND_SHARE) / 100;
        devRewardAmount = taxTotal - devFundAmount;  // Remainder avoids rounding loss
        minerAmount = nSubsidy - taxTotal;

        std::cout << "[Mining] Mainnet tax: subsidy=" << nSubsidy
                  << " miner=" << minerAmount
                  << " devFund=" << devFundAmount
                  << " devReward=" << devRewardAmount << std::endl;
    }

    // Add fees to miner amount (miner gets 100% of fees regardless of network)
    minerAmount += static_cast<int64_t>(totalFees);

    // OUTPUT 0: Miner reward
    CTxOut minerOut;
    minerOut.nValue = minerAmount;
    minerOut.scriptPubKey = WalletCrypto::CreateScriptPubKey(minerPubKeyHash);
    coinbaseTx.vout.push_back(minerOut);

    // MAINNET ONLY: Add dev fund and dev reward outputs
    if (!isTestnet && devFundAmount > 0) {
        // OUTPUT 1: Dev Fund (1% of subsidy) -> DJrywx4AsVQSPLZCKRdg8erZdPMNaRSrKq
        CTxOut devFundOut;
        devFundOut.nValue = devFundAmount;
        std::vector<uint8_t> devFundScript;
        devFundScript.push_back(0x76);  // OP_DUP
        devFundScript.push_back(0xa9);  // OP_HASH160
        devFundScript.push_back(0x14);  // Push 20 bytes
        devFundScript.insert(devFundScript.end(),
            Consensus::DEV_FUND_PUBKEY_HASH,
            Consensus::DEV_FUND_PUBKEY_HASH + 20);
        devFundScript.push_back(0x88);  // OP_EQUALVERIFY
        devFundScript.push_back(0xac);  // OP_CHECKSIG
        devFundOut.scriptPubKey = devFundScript;
        coinbaseTx.vout.push_back(devFundOut);

        // OUTPUT 2: Dev Reward (1% of subsidy) -> DRne9ygVbQJFKma1pyEMPpyRbjmVKNcbWe
        CTxOut devRewardOut;
        devRewardOut.nValue = devRewardAmount;
        std::vector<uint8_t> devRewardScript;
        devRewardScript.push_back(0x76);  // OP_DUP
        devRewardScript.push_back(0xa9);  // OP_HASH160
        devRewardScript.push_back(0x14);  // Push 20 bytes
        devRewardScript.insert(devRewardScript.end(),
            Consensus::DEV_REWARD_PUBKEY_HASH,
            Consensus::DEV_REWARD_PUBKEY_HASH + 20);
        devRewardScript.push_back(0x88);  // OP_EQUALVERIFY
        devRewardScript.push_back(0xac);  // OP_CHECKSIG
        devRewardOut.scriptPubKey = devRewardScript;
        coinbaseTx.vout.push_back(devRewardOut);

        std::cout << "[Mining] Coinbase outputs: " << coinbaseTx.vout.size()
                  << " (miner=" << minerAmount/100000000.0
                  << " DIL, devFund=" << devFundAmount/100000000.0
                  << " DIL -> DJrywx..., devReward=" << devRewardAmount/100000000.0
                  << " DIL -> DRne9y...)" << std::endl;
    }

    // Store coinbase transaction globally for callback access
    {
        std::lock_guard<std::mutex> lock(g_coinbaseMutex);
        g_currentCoinbase = MakeTransactionRef(coinbaseTx);
    }

    // BUG #109 FIX: Serialize ALL transactions (coinbase + mempool) with proper count
    size_t txCount = 1 + selectedTxs.size();  // coinbase + selected transactions

    std::vector<uint8_t> coinbaseData = coinbaseTx.Serialize();
    block.vtx.clear();

    // Estimate total size and reserve
    size_t totalSize = 1 + coinbaseData.size();  // count + coinbase
    for (const auto& tx : selectedTxs) {
        totalSize += tx->GetSerializedSize();
    }
    block.vtx.reserve(totalSize + 10);

    // Write transaction count (compact size encoding)
    if (txCount < 253) {
        block.vtx.push_back(static_cast<uint8_t>(txCount));
    } else if (txCount <= 0xFFFF) {
        block.vtx.push_back(253);
        block.vtx.push_back(txCount & 0xFF);
        block.vtx.push_back((txCount >> 8) & 0xFF);
    } else {
        block.vtx.push_back(254);
        block.vtx.push_back(txCount & 0xFF);
        block.vtx.push_back((txCount >> 8) & 0xFF);
        block.vtx.push_back((txCount >> 16) & 0xFF);
        block.vtx.push_back((txCount >> 24) & 0xFF);
    }

    // Add coinbase transaction
    block.vtx.insert(block.vtx.end(), coinbaseData.begin(), coinbaseData.end());

    // Add all selected transactions
    for (const auto& tx : selectedTxs) {
        std::vector<uint8_t> txData = tx->Serialize();
        block.vtx.insert(block.vtx.end(), txData.begin(), txData.end());
    }

    // BUG #109 FIX: Calculate merkle root from ALL transaction hashes
    // Build vector of all transactions for merkle computation
    std::vector<CTransactionRef> allTransactions;
    allTransactions.reserve(1 + selectedTxs.size());
    allTransactions.push_back(MakeTransactionRef(coinbaseTx));
    for (const auto& tx : selectedTxs) {
        allTransactions.push_back(tx);
    }

    // Use CBlockValidator to compute merkle root properly
    CBlockValidator blockValidator;
    block.hashMerkleRoot = blockValidator.BuildMerkleRoot(allTransactions);

    // Calculate target from nBits (compact format)
    uint256 hashTarget = CompactToBig(block.nBits);

    // DFMP v2.0: Apply difficulty penalty based on MIK identity
    // New miners get 3.0x penalty that decays over 360 blocks
    int dfmpActivationHeight = Dilithion::g_chainParams ?
        Dilithion::g_chainParams->dfmpActivationHeight : 0;

    if (nHeight >= static_cast<uint32_t>(dfmpActivationHeight) && !mikIdentity.IsNull()) {
        // Get first-seen height (-1 for new identity)
        int firstSeen = -1;
        if (DFMP::g_identityDb != nullptr) {
            firstSeen = DFMP::g_identityDb->GetFirstSeen(mikIdentity);
        }

        // Get current heat from tracker
        int heat = 0;
        if (DFMP::g_heatTracker != nullptr) {
            heat = DFMP::g_heatTracker->GetHeat(mikIdentity);
        }

        // Phase 3b: Shared heat — augment own heat with DNA cluster members' heat
        int ownHeat = heat;
        if (g_node_state.shared_heat && heat > 0 &&
            g_node_context.dna_registry && DFMP::g_heatTracker) {
            std::array<uint8_t, 20> mikArr;
            std::memcpy(mikArr.data(), mikIdentity.data, 20);
            auto myDna = g_node_context.dna_registry->get_identity_by_mik(mikArr);
            if (myDna) {
                auto similar = g_node_context.dna_registry->find_similar(*myDna);
                int clusterHeat = heat;
                for (const auto& [dna, score] : similar) {
                    DFMP::Identity memberMik;
                    std::memcpy(memberMik.data, dna.mik_identity.data(), 20);
                    if (memberMik == mikIdentity) continue;  // Skip self
                    clusterHeat += DFMP::g_heatTracker->GetHeat(memberMik);
                }
                int cap = heat * DFMP::MAX_CLUSTER_HEAT_MULTIPLIER;
                heat = std::min(clusterHeat, cap);
            }
        }

        // Dynamic scaling: get unique miner count if active
        int dfmpDynamicScalingHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpDynamicScalingHeight : 999999999;
        int uniqueMiners = 0;
        if (static_cast<int>(nHeight) >= dfmpDynamicScalingHeight && DFMP::g_heatTracker) {
            uniqueMiners = DFMP::g_heatTracker->GetUniqueMinerCount();
        }

        // Calculate DFMP multiplier - must match validator (pow.cpp CheckProofOfWorkDFMP)
        int dfmpV3ActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV3ActivationHeight : 999999999;
        int dfmpV31ActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV31ActivationHeight : 999999999;
        int dfmpV32ActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV32ActivationHeight : 999999999;
        int dfmpV33ActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV33ActivationHeight : 999999999;
        int dfmpV34ActivationHeight = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->dfmpV34ActivationHeight : 999999999;

        int64_t multiplierFP;
        double payoutHeatMult = 1.0;

        if (static_cast<int>(nHeight) >= dfmpV34ActivationHeight) {
            // DFMP v3.4: Verification-aware free tier
            // Verified MIKs: 12 free blocks, Unverified: 3 free blocks

            // Determine verification status of this MIK
            bool isVerified = true;  // Default: verified (safe fallback during IBD)
            if (g_node_context.dna_registry) {
                std::array<uint8_t, 20> mikArr;
                std::memcpy(mikArr.data(), mikIdentity.data, 20);
                auto status = g_node_context.dna_registry->get_verification_status(mikArr);
                isVerified = (status == digital_dna::verification::VerificationStatus::VERIFIED);
            }

            // MIK identity heat penalty (v3.4 - verification-aware)
            int64_t mikHeatPenalty = DFMP::CalculateHeatMultiplierFP_V34(heat, isVerified);

            // Payout address heat penalty (uses same verification status as the MIK)
            int64_t payoutHeatPenalty = DFMP::FP_SCALE;  // 1.0x default
            if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                DFMP::Identity payoutIdentity = DFMP::DeriveIdentityFromScript(
                    coinbaseTx.vout[0].scriptPubKey);
                int payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutIdentity);
                payoutHeatPenalty = DFMP::CalculateHeatMultiplierFP_V34(payoutHeat, isVerified);
                payoutHeatMult = static_cast<double>(payoutHeatPenalty) / DFMP::FP_SCALE;
            }

            // Effective heat = max(MIK heat, payout heat)
            int64_t effectiveHeatPenalty = std::max(mikHeatPenalty, payoutHeatPenalty);

            // Maturity penalty (same as v3.3)
            int64_t maturityPenalty = DFMP::CalculatePendingPenaltyFP_V34(nHeight, firstSeen);

            // Total = maturity x heat
            multiplierFP = (maturityPenalty * effectiveHeatPenalty) / DFMP::FP_SCALE;

        } else if (static_cast<int>(nHeight) >= dfmpV33ActivationHeight) {
            // DFMP v3.3: No dynamic scaling, linear+exponential penalty (must match validator exactly)
            int64_t mikHeatPenalty = DFMP::CalculateHeatMultiplierFP_V33(heat);

            // Payout address heat penalty (v3.3, no dynamic scaling)
            int64_t payoutHeatPenalty = DFMP::FP_SCALE;  // 1.0x default
            if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                DFMP::Identity payoutIdentity = DFMP::DeriveIdentityFromScript(
                    coinbaseTx.vout[0].scriptPubKey);
                int payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutIdentity);
                payoutHeatPenalty = DFMP::CalculateHeatMultiplierFP_V33(payoutHeat);
                payoutHeatMult = static_cast<double>(payoutHeatPenalty) / DFMP::FP_SCALE;
            }

            // Effective heat = max(MIK heat, payout heat)
            int64_t effectiveHeatPenalty = std::max(mikHeatPenalty, payoutHeatPenalty);

            // Maturity penalty (v3.3 = same as v3.2)
            int64_t maturityPenalty = DFMP::CalculatePendingPenaltyFP_V33(nHeight, firstSeen);

            // Total = maturity × effective heat
            multiplierFP = (maturityPenalty * effectiveHeatPenalty) / DFMP::FP_SCALE;

        } else if (static_cast<int>(nHeight) >= dfmpV32ActivationHeight) {
            // DFMP v3.2: Tightened anti-whale (must match validator exactly)
            int64_t mikHeatPenalty = DFMP::CalculateHeatMultiplierFP_V32(heat, uniqueMiners);

            // Payout address heat penalty (v3.2 aggressive)
            int64_t payoutHeatPenalty = DFMP::FP_SCALE;  // 1.0x default
            if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                DFMP::Identity payoutIdentity = DFMP::DeriveIdentityFromScript(
                    coinbaseTx.vout[0].scriptPubKey);
                int payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutIdentity);
                int payoutUniqueMiners = 0;
                if (static_cast<int>(nHeight) >= dfmpDynamicScalingHeight) {
                    payoutUniqueMiners = DFMP::g_payoutHeatTracker->GetUniqueMinerCount();
                }
                payoutHeatPenalty = DFMP::CalculateHeatMultiplierFP_V32(payoutHeat, payoutUniqueMiners);
                payoutHeatMult = static_cast<double>(payoutHeatPenalty) / DFMP::FP_SCALE;
            }

            // Effective heat = max(MIK heat, payout heat)
            int64_t effectiveHeatPenalty = std::max(mikHeatPenalty, payoutHeatPenalty);

            // Maturity penalty (v3.2 moderate)
            int64_t maturityPenalty = DFMP::CalculatePendingPenaltyFP_V32(nHeight, firstSeen);

            // Total = maturity × effective heat
            multiplierFP = (maturityPenalty * effectiveHeatPenalty) / DFMP::FP_SCALE;

        } else if (static_cast<int>(nHeight) >= dfmpV31ActivationHeight) {
            // DFMP v3.1: Softened parameters (must match validator exactly)
            int64_t mikHeatPenalty = DFMP::CalculateHeatMultiplierFP_V31(heat, uniqueMiners);

            // Payout address heat penalty (v3.1 softened)
            int64_t payoutHeatPenalty = DFMP::FP_SCALE;  // 1.0x default
            if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                DFMP::Identity payoutIdentity = DFMP::DeriveIdentityFromScript(
                    coinbaseTx.vout[0].scriptPubKey);
                int payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutIdentity);
                int payoutUniqueMiners = 0;
                if (static_cast<int>(nHeight) >= dfmpDynamicScalingHeight) {
                    payoutUniqueMiners = DFMP::g_payoutHeatTracker->GetUniqueMinerCount();
                }
                payoutHeatPenalty = DFMP::CalculateHeatMultiplierFP_V31(payoutHeat, payoutUniqueMiners);
                payoutHeatMult = static_cast<double>(payoutHeatPenalty) / DFMP::FP_SCALE;
            }

            // Effective heat = max(MIK heat, payout heat)
            int64_t effectiveHeatPenalty = std::max(mikHeatPenalty, payoutHeatPenalty);

            // Maturity penalty (v3.1 softened)
            int64_t maturityPenalty = DFMP::CalculatePendingPenaltyFP_V31(nHeight, firstSeen);

            // Total = maturity × effective heat
            multiplierFP = (maturityPenalty * effectiveHeatPenalty) / DFMP::FP_SCALE;

        } else if (static_cast<int>(nHeight) >= dfmpV3ActivationHeight) {
            // DFMP v3.0: Multi-layer penalty (must match validator exactly)
            int64_t mikHeatPenalty = DFMP::CalculateHeatMultiplierFP(heat, uniqueMiners);

            // Payout address heat penalty
            int64_t payoutHeatPenalty = DFMP::FP_SCALE;  // 1.0x default
            if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                DFMP::Identity payoutIdentity = DFMP::DeriveIdentityFromScript(
                    coinbaseTx.vout[0].scriptPubKey);
                int payoutHeat = DFMP::g_payoutHeatTracker->GetHeat(payoutIdentity);
                int payoutUniqueMiners = 0;
                if (static_cast<int>(nHeight) >= dfmpDynamicScalingHeight) {
                    payoutUniqueMiners = DFMP::g_payoutHeatTracker->GetUniqueMinerCount();
                }
                payoutHeatPenalty = DFMP::CalculateHeatMultiplierFP(payoutHeat, payoutUniqueMiners);
                payoutHeatMult = static_cast<double>(payoutHeatPenalty) / DFMP::FP_SCALE;
            }

            // Effective heat = max(MIK heat, payout heat)
            int64_t effectiveHeatPenalty = std::max(mikHeatPenalty, payoutHeatPenalty);

            // Maturity penalty
            int64_t maturityPenalty = DFMP::CalculatePendingPenaltyFP(nHeight, firstSeen);

            // Total = maturity × effective heat
            multiplierFP = (maturityPenalty * effectiveHeatPenalty) / DFMP::FP_SCALE;
        } else {
            // DFMP v2.0: Standard penalty
            multiplierFP = DFMP::CalculateTotalMultiplierFP(nHeight, firstSeen, heat, uniqueMiners);
        }

        // Apply multiplier to get effective target (harder target = smaller value)
        hashTarget = DFMP::CalculateEffectiveTarget(hashTarget, multiplierFP);

        // Log DFMP info
        double multiplier = static_cast<double>(multiplierFP) / DFMP::FP_SCALE;
        if (multiplier > 1.01) {
            const char* versionTag;
            double maturityMult, heatMult;
            bool logIsVerified = true;
            if (static_cast<int>(nHeight) >= dfmpV34ActivationHeight) {
                versionTag = "v3.4";
                maturityMult = DFMP::GetPendingPenalty_V34(nHeight, firstSeen);
                // Determine verification status for logging
                if (g_node_context.dna_registry) {
                    std::array<uint8_t, 20> mikArr;
                    std::memcpy(mikArr.data(), mikIdentity.data, 20);
                    auto status = g_node_context.dna_registry->get_verification_status(mikArr);
                    logIsVerified = (status == digital_dna::verification::VerificationStatus::VERIFIED);
                }
                heatMult = DFMP::GetHeatMultiplier_V34(heat, logIsVerified);
            } else if (static_cast<int>(nHeight) >= dfmpV33ActivationHeight) {
                versionTag = "v3.3";
                maturityMult = DFMP::GetPendingPenalty_V33(nHeight, firstSeen);
                heatMult = DFMP::GetHeatMultiplier_V33(heat);
            } else if (static_cast<int>(nHeight) >= dfmpV32ActivationHeight) {
                versionTag = "v3.2";
                maturityMult = DFMP::GetPendingPenalty_V32(nHeight, firstSeen);
                heatMult = DFMP::GetHeatMultiplier_V32(heat, uniqueMiners);
            } else if (static_cast<int>(nHeight) >= dfmpV31ActivationHeight) {
                versionTag = "v3.1";
                maturityMult = DFMP::GetPendingPenalty_V31(nHeight, firstSeen);
                heatMult = DFMP::GetHeatMultiplier_V31(heat, uniqueMiners);
            } else {
                versionTag = "v3.0";
                maturityMult = DFMP::GetPendingPenalty(nHeight, firstSeen);
                heatMult = DFMP::GetHeatMultiplier(heat, uniqueMiners);
            }

            std::cout << "[Mining] DFMP " << versionTag << " penalty: MIK " << mikIdentity.GetHex().substr(0, 8) << "..."
                      << " firstSeen=" << firstSeen
                      << " heat=" << ownHeat
                      << (heat != ownHeat ? (" clusterHeat=" + std::to_string(heat)) : "")
                      << " maturity=" << std::fixed << std::setprecision(2) << maturityMult << "x"
                      << " mikHeat=" << heatMult << "x"
                      << " payoutHeat=" << payoutHeatMult << "x"
                      << " total=" << multiplier << "x";
            if (static_cast<int>(nHeight) >= dfmpV34ActivationHeight) {
                std::cout << " verified=" << (logIsVerified ? "YES" : "NO")
                          << " (freeTier=" << (logIsVerified ? DFMP::FREE_TIER_THRESHOLD_V34_VERIFIED : DFMP::FREE_TIER_THRESHOLD_V34_UNVERIFIED) << ")";
            } else if (static_cast<int>(nHeight) >= dfmpV33ActivationHeight) {
                std::cout << " (freeTier=12 fixed)";
            } else if (uniqueMiners > 0) {
                int freeTierBase;
                if (static_cast<int>(nHeight) >= dfmpV32ActivationHeight) freeTierBase = DFMP::FREE_TIER_THRESHOLD_V32;
                else if (static_cast<int>(nHeight) >= dfmpV31ActivationHeight) freeTierBase = DFMP::FREE_TIER_THRESHOLD_V31;
                else freeTierBase = DFMP::FREE_TIER_THRESHOLD;
                int effectiveFree = std::max(freeTierBase,
                    DFMP::OBSERVATION_WINDOW / std::max(1, uniqueMiners));
                std::cout << " (dynamic: " << uniqueMiners << " miners, free=" << effectiveFree << ")";
            }
            std::cout << std::endl;
        } else if (static_cast<int>(nHeight) < dfmpV33ActivationHeight && uniqueMiners > 0) {
            // Log dynamic scaling even when no penalty (so miners see it's working)
            // v3.3+ has no dynamic scaling, so skip this
            int freeTierBase;
            if (static_cast<int>(nHeight) >= dfmpV32ActivationHeight) freeTierBase = DFMP::FREE_TIER_THRESHOLD_V32;
            else if (static_cast<int>(nHeight) >= dfmpV31ActivationHeight) freeTierBase = DFMP::FREE_TIER_THRESHOLD_V31;
            else freeTierBase = DFMP::FREE_TIER_THRESHOLD;
            int effectiveFree = std::max(freeTierBase,
                DFMP::OBSERVATION_WINDOW / std::max(1, uniqueMiners));
            if (effectiveFree > freeTierBase) {
                std::cout << "[Mining] DFMP dynamic scaling: " << uniqueMiners
                          << " active miners, free tier=" << effectiveFree
                          << " (heat=" << heat << ")" << std::endl;
            }
        }
    }

    if (verbose) {
        std::cout << "  Block height: " << nHeight << std::endl;
        std::cout << "  Previous block: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;
        // CID 1675194/1675256 FIX: Save and restore ostream format state
        // This prevents format state leakage to subsequent output operations
        std::ios_base::fmtflags oldFlags = std::cout.flags();
        std::cout << "  Difficulty (nBits): 0x" << std::hex << block.nBits;
        std::cout.flags(oldFlags);  // Restore original format flags
        std::cout << std::endl;
        std::cout << "  Target: " << hashTarget.GetHex().substr(0, 16) << "..." << std::endl;
        std::cout << "  Coinbase: " << coinbaseMsg << std::endl;
        std::cout << "  Merkle root: " << block.hashMerkleRoot.GetHex().substr(0, 16) << "..." << std::endl;
    }

    // Create and return block template
    // BUG #109 FIX: Increment and set template version for race detection
    uint64_t version = ++g_node_state.template_version;
    return CBlockTemplate(block, hashTarget, nHeight, version);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Register crash handler to log crash info before terminating
    SetUnhandledExceptionFilter(CrashHandler);
#endif

    // Limit glibc malloc arenas to reduce memory fragmentation.
    // Default is 8*ncpus which causes RSS to grow unboundedly on long-running
    // multi-threaded nodes (OOM after ~4 days on 4GB servers).
#ifdef __linux__
    mallopt(M_ARENA_MAX, 4);
#endif

    // Quick Start Mode: If no arguments provided, use beginner-friendly defaults
    bool quick_start_mode = (argc == 1);

    // Parse configuration
    NodeConfig config;

    if (quick_start_mode) {
        // Smart defaults - MAINNET by default
        std::cout << "\033[1;32m" << std::endl;  // Green bold
        std::cout << "======================================" << std::endl;
        std::cout << "  DILITHION QUICK START MODE" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "\033[0m" << std::endl;  // Reset color
        std::cout << "No arguments detected - using defaults:" << std::endl;
        std::cout << "  • Network:    MAINNET (real coins with value)" << std::endl;
        std::cout << "  • Seed node:  138.197.68.128:8444 (NYC - official)" << std::endl;
        std::cout << "  • Mining:     ENABLED" << std::endl;
        std::cout << "  • Threads:    AUTO-DETECT (50-75% of your CPU)" << std::endl;
        std::cout << std::endl;
        std::cout << "For testnet (practice coins), run: " << argv[0] << " --testnet" << std::endl;
        std::cout << "To customize settings, run: " << argv[0] << " --help" << std::endl;
        std::cout << "To stop mining anytime: Press Ctrl+C" << std::endl;
        std::cout << std::endl;
        std::cout << "Starting in 3 seconds..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::cout << std::endl;

        // Apply smart defaults - MAINNET
        config.testnet = false;
        config.start_mining = true;
        config.mining_threads = 0;  // 0 = auto-detect
        config.add_nodes.push_back("138.197.68.128:8444");  // NYC mainnet seed node
    }
    else if (!config.ParseArgs(argc, argv)) {
        config.PrintUsage(argv[0]);
        return 1;
    }

    // Phase 10: Load configuration from dilithion.conf
    // Determine initial data directory based on command-line testnet flag
    // (Config file may override testnet, but we need initial location to load config)
    std::string initial_datadir = config.datadir;
    if (initial_datadir.empty()) {
        initial_datadir = GetDefaultDataDir(config.testnet);
    }
    
    // Load config file from initial datadir
    std::string config_file = GetConfigFilePath(initial_datadir);
    CConfigParser config_parser;
    if (!config_parser.LoadConfigFile(config_file)) {
        std::cerr << "ERROR: Failed to load configuration file: " << config_file << std::endl;
        return 1;
    }
    
    // Apply config file and environment variable settings (only if not set via command-line)
    // Priority: Command-line > Environment > Config file > Default
    
    // Testnet (only if not set via command-line)
    // Note: This may change the datadir location, but we've already loaded config from initial location
    if (!config.testnet) {
        config.testnet = config_parser.GetBool("testnet", false);
    }
    
    // Data directory (only if not set via command-line)
    // If testnet changed, update datadir accordingly
    if (config.datadir.empty()) {
        std::string conf_datadir = config_parser.GetString("datadir", "");
        if (!conf_datadir.empty()) {
            config.datadir = conf_datadir;
        } else {
            // Use default based on current testnet setting
            config.datadir = GetDefaultDataDir(config.testnet);
        }
    }
    
    // RPC port (only if not set via command-line)
    if (config.rpcport == 0) {
        int64_t conf_rpcport = config_parser.GetInt64("rpcport", 0);
        if (conf_rpcport > 0 && conf_rpcport <= 65535) {
            config.rpcport = static_cast<uint16_t>(conf_rpcport);
        }
    }
    
    // P2P port (only if not set via command-line)
    if (config.p2pport == 0) {
        int64_t conf_p2pport = config_parser.GetInt64("port", 0);
        if (conf_p2pport > 0 && conf_p2pport <= 65535) {
            config.p2pport = static_cast<uint16_t>(conf_p2pport);
        }
    }
    
    // Mining (only if not set via command-line)
    if (!config.start_mining) {
        config.start_mining = config_parser.GetBool("mine", false);
    }
    
    // Mining threads (only if not set via command-line)
    if (config.mining_threads == 0) {
        std::string conf_threads = config_parser.GetString("threads", "");
        if (!conf_threads.empty()) {
            if (conf_threads == "auto" || conf_threads == "AUTO") {
                config.mining_threads = 0;  // Auto-detect
            } else {
                int64_t threads = config_parser.GetInt64("threads", 0);
                if (threads > 0 && threads <= 256) {
                    config.mining_threads = static_cast<int>(threads);
                }
            }
        }
    }
    
    // Add nodes from config file (append to command-line nodes)
    std::vector<std::string> conf_addnodes = config_parser.GetList("addnode");
    for (const auto& node : conf_addnodes) {
        if (std::find(config.add_nodes.begin(), config.add_nodes.end(), node) == config.add_nodes.end()) {
            config.add_nodes.push_back(node);
        }
    }
    
    // Connect nodes from config file (append to command-line nodes)
    std::vector<std::string> conf_connect = config_parser.GetList("connect");
    for (const auto& node : conf_connect) {
        if (std::find(config.connect_nodes.begin(), config.connect_nodes.end(), node) == config.connect_nodes.end()) {
            config.connect_nodes.push_back(node);
        }
    }
    
    // Reindex (only if not set via command-line)
    if (!config.reindex) {
        config.reindex = config_parser.GetBool("reindex", false);
    }
    
    // Rescan (only if not set via command-line)
    if (!config.rescan) {
        config.rescan = config_parser.GetBool("rescan", false);
    }

    // Verbose mode (only if not set via command-line)
    if (!config.verbose) {
        config.verbose = config_parser.GetBool("verbose", false);
    }

    // Set global verbose flag for debug output
    g_verbose.store(config.verbose, std::memory_order_relaxed);
    // Set global quiet flag for minimal output
    g_quiet.store(config.quiet, std::memory_order_relaxed);

    if (config_parser.IsLoaded()) {
        LogPrintf(ALL, INFO, "Configuration loaded from: %s", config_file.c_str());
    }
    
    // UX: Validate configuration values
    std::vector<ConfigValidationResult> validation_results = CConfigValidator::ValidateAll(config_parser);
    bool has_errors = false;
    for (const auto& result : validation_results) {
        if (!result.valid) {
            has_errors = true;
            ErrorMessage error = CErrorFormatter::ConfigError(result.field_name, result.error_message);
            error.recovery_steps = result.suggestions;
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
        }
    }
    if (has_errors) {
        std::cerr << std::endl << "Please fix configuration errors and restart the node." << std::endl;
        return 1;
    }

    std::cout << "======================================" << std::endl;
    std::cout << "Dilithion Node" << std::endl;
    std::cout << "Post-Quantum Cryptocurrency" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    // Initialize chain parameters based on network
    if (config.regtest) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Regtest());
        std::cout << "Network: REGTEST (Phase 5 byte-equivalence integration testing)" << std::endl;
    } else if (config.testnet) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Testnet());
        std::cout << "Network: TESTNET (production difficulty, ~60s blocks)" << std::endl;
    } else {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::Mainnet());
        std::cout << "Network: MAINNET" << std::endl;
    }

    // Phase 10: Set default datadir, ports from chain params if not specified
    // (Config file values already applied above, now apply chain params as final fallback)
    if (config.datadir.empty()) {
        config.datadir = Dilithion::g_chainParams->dataDir;
    }
    if (config.rpcport == 0) {
        config.rpcport = Dilithion::g_chainParams->rpcPort;
    }
    if (config.p2pport == 0) {
        config.p2pport = Dilithion::g_chainParams->p2pPort;
    }

    // Publish datadir globally so MIK registration persistence + other
    // utilities can find the right path without threading it through
    // every call site.
    g_datadir = config.datadir;

    // --reset-chain: wipe chain-derived state and exit. Preserves wallet.dat
    // and mik_registration.dat so miners don't lose keys or re-solve PoW.
    if (config.reset_chain) {
        if (!std::filesystem::exists(config.datadir)) {
            std::cerr << "Data directory does not exist: " << config.datadir << std::endl;
            return 1;
        }
        if (!Dilithion::ConfirmChainReset(config.datadir, config.yes_flag)) {
            return 1;
        }
        auto report = Dilithion::ResetChainState(config.datadir);
        std::cout << "\n=== Reset complete ===" << std::endl;
        std::cout << "Removed:" << std::endl;
        if (report.removed.empty()) std::cout << "  (nothing - chain state already absent)" << std::endl;
        for (const auto& p : report.removed) std::cout << "  - " << p << std::endl;
        std::cout << "\nPreserved:" << std::endl;
        if (report.preserved.empty()) std::cout << "  (none found)" << std::endl;
        for (const auto& p : report.preserved) std::cout << "  + " << p << std::endl;
        if (!report.errors.empty()) {
            std::cerr << "\nErrors:" << std::endl;
            for (const auto& e : report.errors) std::cerr << "  ! " << e << std::endl;
        }
        std::cout << "\nRun the node again (without --reset-chain) to resync." << std::endl;
        return 0;
    }

    // Initialize logging system (Bitcoin Core style)
    if (!CLogger::GetInstance().Initialize(config.datadir)) {
        std::cerr << "Warning: Failed to initialize logging system" << std::endl;
    }
    InstallTimestampedStreams();
    LogPrintf(ALL, INFO, "Dilithion Node starting");
    LogPrintf(ALL, INFO, "Data directory: %s", config.datadir.c_str());
    LogPrintf(ALL, INFO, "P2P port: %d", config.p2pport);
    LogPrintf(ALL, INFO, "RPC port: %d", config.rpcport);

    std::cout << "Data directory: " << config.datadir << std::endl;
    std::cout << "P2P port: " << config.p2pport << std::endl;
    std::cout << "RPC port: " << config.rpcport << std::endl;
    std::cout << "Difficulty fork: height " << Dilithion::g_chainParams->difficultyForkHeight
              << " (interval " << Dilithion::g_chainParams->difficultyAdjustment
              << " -> " << Dilithion::g_chainParams->difficultyAdjustmentV2
              << ", max change " << Dilithion::g_chainParams->difficultyMaxChange << "x)" << std::endl;

    if (!config.connect_nodes.empty()) {
        std::cout << "Connect to: ";
        for (size_t i = 0; i < config.connect_nodes.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.connect_nodes[i];
        }
        std::cout << std::endl;
    }
    if (!config.add_nodes.empty()) {
        std::cout << "Additional nodes: ";
        for (size_t i = 0; i < config.add_nodes.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.add_nodes[i];
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;

    // Setup signal handlers
    // CID 1675274 FIX: Check return value of std::signal to ensure handlers are installed
    // std::signal returns the previous handler or SIG_ERR on error
    if (std::signal(SIGINT, SignalHandler) == SIG_ERR) {
        std::cerr << "WARNING: Failed to install SIGINT handler" << std::endl;
        LogPrintf(ALL, WARN, "Failed to install SIGINT handler");
    }
    if (std::signal(SIGTERM, SignalHandler) == SIG_ERR) {
        std::cerr << "WARNING: Failed to install SIGTERM handler" << std::endl;
        LogPrintf(ALL, WARN, "Failed to install SIGTERM handler");
    }
#ifndef _WIN32
    // Ignore SIGPIPE. Without this, a peer socket closing mid-send() terminates
    // the process with exit code 141. Bitcoin Core does the same in init.cpp.
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        std::cerr << "WARNING: Failed to install SIGPIPE handler" << std::endl;
        LogPrintf(ALL, WARN, "Failed to install SIGPIPE handler");
    }
#endif
#ifdef _WIN32
    // Windows console close handler — catches X button, logoff, shutdown.
    // Without this, closing the console window kills the process immediately,
    // leaving stale PID files and potentially corrupting LevelDB.
    SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
        if (dwCtrlType == CTRL_CLOSE_EVENT || dwCtrlType == CTRL_LOGOFF_EVENT ||
            dwCtrlType == CTRL_SHUTDOWN_EVENT || dwCtrlType == CTRL_C_EVENT) {
            std::cout << "\nWindows shutdown signal received, cleaning up..." << std::endl;
            SignalHandler(SIGINT);
            // Give the shutdown logic a few seconds to flush databases
            std::this_thread::sleep_for(std::chrono::seconds(3));
            return TRUE;
        }
        return FALSE;
    }, TRUE);
#endif

    // BUG #88: Windows startup crash diagnostics
    std::cerr.flush();

    // BUG #3 FIX: Create data directory on first run
    // Without this, PID file creation fails on fresh installs
    if (!EnsureDataDirExists(config.datadir)) {
        std::cerr << "ERROR: Failed to create data directory: " << config.datadir << std::endl;
        return 1;
    }

    try {
        // STRESS TEST FIX: Acquire PID file lock and clean up stale locks
        // This must happen before opening databases to handle crashed process locks
        std::cout << "Checking for existing instance..." << std::endl;
        CPidFile pidfile(config.datadir);
        if (!pidfile.TryAcquire()) {
            // Check if the lock is stale (crashed process)
            std::string pidfilePath = config.datadir + "/dilithion.pid";
            if (CPidFile::IsStale(pidfilePath)) {
                // Clean up stale database locks from crashed process
                std::cout << "  Detected crashed process, cleaning up stale locks..." << std::endl;
                CPidFile::RemoveStaleLocks(config.datadir);

                // Retry acquiring PID file
                if (!pidfile.TryAcquire()) {
                    std::cerr << "ERROR: Failed to acquire lock after cleanup" << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "ERROR: Another instance is already running" << std::endl;
                std::cerr << "If you believe this is an error, delete: " << pidfilePath << std::endl;
                return 1;
            }
        }
        std::cout << "  [OK] PID file lock acquired" << std::endl;

        // Store mining config in global state for callbacks to access
        g_node_state.mining_address_override = config.mining_address_override;
        g_node_state.rotate_mining_address = config.rotate_mining_address;
        g_node_state.shared_heat = config.shared_heat;

        // =================================================================
        // BUG #277: Auto-rebuild after UTXO corruption
        // =================================================================
        // Check for auto_rebuild marker (written by IBD coordinator when
        // UTXO corruption is detected). Wipe blocks+chainstate and resync.
        {
            std::string markerPath = config.datadir + "/auto_rebuild";
            std::ifstream marker(markerPath);
            if (marker.is_open()) {
                std::string reason;
                std::getline(marker, reason);
                marker.close();

                std::cout << "\n==========================================================" << std::endl;
                std::cout << "AUTO-REBUILD: UTXO corruption recovery in progress" << std::endl;
                if (!reason.empty()) {
                    std::cout << "Reason: " << reason << std::endl;
                }
                std::cout << "Wiping chain-derived state for clean resync" << std::endl;
                std::cout << "(wallet.dat and mik_registration.dat are preserved)" << std::endl;
                std::cout << "==========================================================" << std::endl;

                // Shared preserve-list logic — never touches wallet.dat / peers.dat /
                // mik_registration.dat. auto_rebuild marker itself is in the remove list.
                auto report = Dilithion::ResetChainState(config.datadir);
                for (const auto& p : report.removed) {
                    std::cout << "  [OK] Removed: " << p << std::endl;
                }
                for (const auto& p : report.preserved) {
                    std::cout << "  [OK] Preserved: " << p << std::endl;
                }
                std::cout << "  Resyncing from network..." << std::endl;
                std::cout << "==========================================================" << std::endl;
            }
        }

        // Phase 1: Initialize blockchain storage and mempool
        std::cerr.flush();
        LogPrintf(ALL, INFO, "Initializing blockchain storage...");
        std::cout << "Initializing blockchain storage..." << std::endl;
        CBlockchainDB blockchain;
        if (!blockchain.Open(config.datadir + "/blocks")) {
            ErrorMessage error = CErrorFormatter::DatabaseError("open blockchain database", config.datadir + "/blocks");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            pidfile.Release();  // Release PID file on error
            return 1;
        }
        LogPrintf(ALL, INFO, "Blockchain database opened successfully");
        std::cout << "  [OK] Blockchain database opened" << std::endl;

        // IBD BLOCK FIX #3: New blocks are stored with dual hashes (FastHash + RandomX)
        // Existing nodes should clear their DB and re-sync to get dual-hash storage
        // The migration function exists but is not called automatically due to LevelDB issues

        std::cout << "Initializing mempool..." << std::endl;
        CTxMemPool mempool;
        g_mempool.store(&mempool);  // BUG #108 FIX: Set global pointer for TX relay
        std::cout << "  [OK] Mempool initialized" << std::endl;

        // Initialize UTXO set
        std::cout << "Initializing UTXO set..." << std::endl;
        CUTXOSet utxo_set;
        if (!utxo_set.Open(config.datadir + "/chainstate")) {
            ErrorMessage error = CErrorFormatter::DatabaseError("open UTXO database", config.datadir + "/chainstate");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            return 1;
        }
        std::cout << "  [OK] UTXO set opened" << std::endl;
        g_utxo_set.store(&utxo_set);  // BUG #108 FIX: Set global pointer for TX validation

        // v4.4 Block 8: ChainstateIntegrityMonitor lifecycle.
        // Constructed AFTER the startup integrity check passes (below); started
        // via main-loop poll once g_utxo_sync_enabled.load() == true (i.e. IBD
        // has fully exited). Destructor (Stop() + join) runs when this scope
        // exits at end of main().
        std::unique_ptr<Dilithion::ChainstateIntegrityMonitor> integrity_monitor;
        bool integrity_monitor_started = false;

        // Initialize transaction validator
        CTransactionValidator tx_validator;
        g_tx_validator.store(&tx_validator);  // BUG #108 FIX: Set global pointer for TX validation

        // Initialize chain state
        std::cout << "Initializing chain state..." << std::endl;
        g_chainstate.SetDatabase(&blockchain);
        g_chainstate.SetUTXOSet(&utxo_set);
        g_chainstate.SetMemPool(&mempool);  // BUG #109 FIX: Enable mempool cleanup on block connect

        // DFMP: Initialize Fair Mining Protocol subsystem
        std::cout << "Initializing DFMP (Fair Mining Protocol)..." << std::endl;
        if (!DFMP::InitializeDFMP(config.datadir)) {
            std::cerr << "[ERROR] Failed to initialize DFMP subsystem" << std::endl;
            return 1;
        }
        std::cout << "  [OK] DFMP subsystem initialized" << std::endl;

        // Phase 1.5: MIK pubkey cache. Reads through to DFMP::g_identityDb
        // for missing keys; populated by block-connect callbacks for the
        // hot path. Must be constructed after InitializeDFMP returns.
        g_node_context.mik_pubkey_cache =
            std::make_unique<digital_dna::MikPubkeyCache>(DFMP::g_identityDb);

        // P1-4 FIX: Initialize Write-Ahead Log for atomic reorganizations
        if (!g_chainstate.InitializeWAL(config.datadir)) {
            if (g_chainstate.RequiresReindex()) {
                if (config.reindex) {
                    // User requested reindex - delete corrupted data and rebuild
                    std::cout << "\n==========================================================" << std::endl;
                    std::cout << "REINDEX: Incomplete reorg detected, rebuilding chain..." << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Delete WAL file
                    std::string walPath = config.datadir + "/wal";
                    std::remove(walPath.c_str());
                    std::cout << "  [OK] Deleted incomplete reorg WAL" << std::endl;

                    // Delete blocks and chainstate directories
                    std::string blocksPath = config.datadir + "/blocks";
                    std::string chainstPath = config.datadir + "/chainstate";

                    // Remove blocks directory recursively
                    std::filesystem::remove_all(blocksPath);
                    std::cout << "  [OK] Deleted blocks directory" << std::endl;

                    // Remove chainstate directory recursively
                    std::filesystem::remove_all(chainstPath);
                    std::cout << "  [OK] Deleted chainstate directory" << std::endl;

                    std::cout << "  [OK] Chain data cleared - will sync fresh from network" << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Re-initialize databases (they will be recreated)
                    if (!blockchain.Open(blocksPath)) {
                        std::cerr << "[ERROR] Failed to reinitialize blockchain database after reindex" << std::endl;
                        return 1;
                    }

                    if (!utxo_set.Open(chainstPath)) {
                        std::cerr << "[ERROR] Failed to reinitialize UTXO database after reindex" << std::endl;
                        return 1;
                    }

                    // Re-initialize WAL (should succeed now with clean state)
                    if (!g_chainstate.InitializeWAL(config.datadir)) {
                        std::cerr << "[ERROR] Failed to reinitialize WAL after reindex" << std::endl;
                        return 1;
                    }
                } else {
                    std::cerr << "========================================" << std::endl;
                    std::cerr << "CRITICAL: Incomplete reorganization detected!" << std::endl;
                    std::cerr << "The database may be in an inconsistent state." << std::endl;
                    std::cerr << "" << std::endl;
                    std::cerr << "Please restart with --reindex flag:" << std::endl;
                    std::cerr << "  dilithion-node --reindex" << std::endl;
                    std::cerr << "========================================" << std::endl;
                    return 1;
                }
            }
        }
        std::cout << "  [OK] Chain state initialized" << std::endl;

        // Initialize RandomX (required for block hashing)
        std::cout << "Initializing RandomX..." << std::endl;
        const char* rx_key = "Dilithion-RandomX-v1";

        // Auto-detect RAM to choose appropriate RandomX mode
        // LIGHT mode: ~256MB RAM, ~3-10 H/s (works on 2GB nodes)
        // FULL mode: ~2.5GB RAM, ~100 H/s (requires 4GB+ nodes)
        size_t total_ram_mb = 0;

#ifdef _WIN32
        // Windows: Use GlobalMemoryStatusEx()
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            total_ram_mb = memInfo.ullTotalPhys / (1024 * 1024);  // Convert bytes to MB
        }
#else
        // Linux: Read /proc/meminfo
        std::ifstream meminfo("/proc/meminfo");
        if (meminfo.is_open()) {
            std::string line;
            while (std::getline(meminfo, line)) {
                if (line.substr(0, 9) == "MemTotal:") {
                    size_t ram_kb = std::stoull(line.substr(9));
                    total_ram_mb = ram_kb / 1024;
                    break;
                }
            }
            meminfo.close();
        }
#endif

        // ========================================================================
        // BUG #55 FIX: Monero-Style Dual-Mode RandomX Architecture
        // ========================================================================
        // Following Monero's proven pattern for instant node startup:
        // - LIGHT mode (256MB): Used for ALL block validation - instant startup
        // - FULL mode (2GB): Used ONLY for mining - async background init
        //
        // This allows nodes to:
        // 1. Start validating blocks immediately (LIGHT mode)
        // 2. Mining starts with LIGHT mode, upgrades to FULL when ready
        // 3. No more 30-60s hang on high-RAM nodes like NYC (3.9GB)
        // ========================================================================
        std::cout << "  Detected RAM: " << total_ram_mb << " MB" << std::endl;

        // Step 1: Always initialize LIGHT mode first for validation (fast, 1-2 seconds)
        std::cout << "  Initializing validation mode (LIGHT)..." << std::endl;
        randomx_init_validation_mode(rx_key, strlen(rx_key));
        // Validation mode is now ready - node can verify blocks immediately

        // Step 2: Check if FULL mode will be available (RAM >= 3GB)
        // NOTE: Actual mining init is deferred until AFTER sync completes (BUG #97 fix)
        bool full_mode_available = (total_ram_mb >= 3072);
        if (config.start_mining && full_mode_available) {
            std::cout << "  Mining mode: FULL (will initialize after sync)" << std::endl;
        } else if (config.start_mining) {
            std::cout << "  Mining mode: LIGHT only (RAM < 3GB)" << std::endl;
        }

        // Step 3: For 8GB+ systems, start FULL mode init NOW for faster IBD verification
        // This makes IBD ~20x faster since FULL mode verifies at ~100 H/s vs ~5 H/s
        if (total_ram_mb >= 8192) {
            std::cout << "  Starting FULL mode init for faster IBD (8GB+ RAM detected)..." << std::endl;
            randomx_init_mining_mode_async(rx_key, strlen(rx_key));
        }

        // NO WAIT - node continues immediately, can validate blocks right away

        // Load and verify genesis block
load_genesis_block:  // Bug #29: Label for automatic retry after blockchain wipe
        std::cout << "[1/6] Loading genesis block..." << std::flush;
        CBlock genesis = Genesis::CreateGenesisBlock();

        if (!Genesis::IsGenesisBlock(genesis)) {
            ErrorMessage error = CErrorFormatter::ValidationError("genesis block", 
                "Genesis block verification failed. This indicates a critical configuration problem.");
            error.severity = ErrorSeverity::CRITICAL;
            error.recovery_steps = {
                "Verify you are using the correct network (mainnet/testnet)",
                "Check that blockchain data directory is correct",
                "Run `dilithion-node --reset-chain` to wipe chain data while preserving wallet and MIK registration",
                "Report this issue if it persists"
            };
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
            delete Dilithion::g_chainParams;
            return 1;
        }

        std::cout << "  Network: " << Dilithion::g_chainParams->GetNetworkName() << std::endl;
        std::cout << "  Genesis hash: " << genesis.GetHash().GetHex() << std::endl;
        std::cout << "  Genesis time: " << genesis.nTime << std::endl;
        std::cout << " ✓" << std::endl;
        std::cout << "  [OK] Genesis block verified" << std::endl;

        // Initialize blockchain with genesis block if needed
        uint256 genesisHash = genesis.GetHash();
        if (!blockchain.BlockExists(genesisHash)) {
            std::cout << "Initializing blockchain with genesis block..." << std::endl;

            // Save genesis block
            if (!blockchain.WriteBlock(genesisHash, genesis)) {
                ErrorMessage error = CErrorFormatter::DatabaseError("write genesis block", 
                    "Failed to write genesis block to database");
                error.severity = ErrorSeverity::CRITICAL;
                std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
                LogPrintf(ALL, ERROR, "%s", CErrorFormatter::FormatForLog(error).c_str());
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block saved to database" << std::endl;

            // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
            auto pgenesisIndex = std::make_unique<CBlockIndex>(genesis);
            pgenesisIndex->phashBlock = genesisHash;
            pgenesisIndex->nHeight = 0;
            pgenesisIndex->pprev = nullptr;
            pgenesisIndex->pnext = nullptr;
            pgenesisIndex->nChainWork = pgenesisIndex->GetBlockProof();
            pgenesisIndex->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;

            // Save to database
            if (!blockchain.WriteBlockIndex(genesisHash, *pgenesisIndex)) {
                std::cerr << "ERROR: Failed to write genesis block index!" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block index saved (height 0)" << std::endl;

            // Add to chain state and set as tip (transfer ownership with std::move)
            if (!g_chainstate.AddBlockIndex(genesisHash, std::move(pgenesisIndex))) {
                std::cerr << "ERROR: Failed to add genesis to chain state!" << std::endl;
                // HIGH-C001 FIX: No manual delete - ownership already transferred to map
                delete Dilithion::g_chainParams;
                return 1;
            }

            // HIGH-C001 FIX: After move, retrieve pointer from chain state
            CBlockIndex* pgenesisIndexPtr = g_chainstate.GetBlockIndex(genesisHash);
            if (pgenesisIndexPtr == nullptr) {
                std::cerr << "ERROR: Genesis block index not found after adding!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            bool reorgOccurred = false;
            if (!g_chainstate.ActivateBestChain(pgenesisIndexPtr, genesis, reorgOccurred)) {
                std::cerr << "ERROR: Failed to activate genesis block!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            // Set genesis as best block in database
            if (!blockchain.WriteBestBlock(genesisHash)) {
                std::cerr << "ERROR: Failed to set genesis as best block!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
            std::cout << "  [OK] Genesis block set as blockchain tip" << std::endl;
        } else {
            std::cout << "  [OK] Genesis block already in database" << std::endl;

            // Phase 4.2: Handle -reindex flag
            if (config.reindex) {
                LogPrintf(ALL, INFO, "Rebuilding block index from blocks on disk (--reindex)");
                std::cout << "\n==========================================================" << std::endl;
                std::cout << "REINDEX: Rebuilding block index from blocks on disk..." << std::endl;
                std::cout << "==========================================================" << std::endl;
                
                // Clear existing block index (but keep blocks)
                // We'll rebuild the index by reading all blocks
                std::cout << "  Clearing existing block index..." << std::endl;
                
                // Get all block hashes
                std::vector<uint256> all_blocks;
                if (!blockchain.GetAllBlockHashes(all_blocks)) {
                    std::cerr << "ERROR: Failed to enumerate blocks for reindex" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                
                std::cout << "  Found " << all_blocks.size() << " blocks to reindex" << std::endl;
                
                // Rebuild index
                if (!blockchain.RebuildBlockIndex()) {
                    std::cerr << "ERROR: Failed to rebuild block index" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                
                std::cout << "  [OK] Block index rebuilt successfully" << std::endl;
                std::cout << "==========================================================" << std::endl;
            }

            // Load existing chain state from database
            std::cout << "[2/6] Loading chain state from database..." << std::flush;

            // Load genesis block index first
            CBlockIndex genesisIndexFromDB;
            if (blockchain.ReadBlockIndex(genesisHash, genesisIndexFromDB)) {
                // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
                auto pgenesisIndex = std::make_unique<CBlockIndex>(genesisIndexFromDB);
                // IBD DEADLOCK FIX #10: Set phashBlock to prevent GetBlockHash from computing RandomX
                pgenesisIndex->phashBlock = genesisHash;
                pgenesisIndex->pprev = nullptr;
                g_chainstate.AddBlockIndex(genesisHash, std::move(pgenesisIndex));
                std::cout << " ✓" << std::endl;
                std::cout << "  Loaded genesis block index (height 0)" << std::endl;
            } else {
                std::cerr << "ERROR: Cannot load genesis block index from database!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }

            // Load current best block
            uint256 hashBestBlock;

            // BUG #5 FIX: If best block not set, initialize it to genesis
            // This handles the case where genesis block exists but best block pointer is missing
            if (!blockchain.ReadBestBlock(hashBestBlock)) {
                std::cout << "  Best block not set, initializing to genesis..." << std::endl;
                if (!blockchain.WriteBestBlock(genesisHash)) {
                    std::cerr << "ERROR: Failed to set genesis as best block!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                hashBestBlock = genesisHash;
                std::cout << "  [OK] Genesis set as best block" << std::endl;
            }

            if (hashBestBlock == genesisHash) {
                // Only genesis block exists - set it as tip
                CBlockIndex* pgenesisIndexPtr = g_chainstate.GetBlockIndex(genesisHash);
                if (pgenesisIndexPtr == nullptr) {
                    std::cerr << "ERROR: Genesis block index not found in chain state!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }
                g_chainstate.SetTip(pgenesisIndexPtr);
                // v4.3.1: seed candidate set after tip established. Without
                // this, m_setBlockIndexCandidates stays empty after disk load
                // — under env-var=1 path, FindMostWorkChainImpl returns
                // whichever single block was last inserted, never comparing
                // against tip's chainwork. Caused LDN tip-going-backwards /
                // dual-hash deadlock 2026-05-04.
                g_chainstate.RecomputeCandidates();
                std::cout << " ✓" << std::endl;
                std::cout << "  [OK] Loaded chain state: 1 block (height 0)" << std::endl;
            } else if (!(hashBestBlock.IsNull())) {
                std::cout << "  Best block hash: " << hashBestBlock.GetHex().substr(0, 16) << "..." << std::endl;

                // Load best block index and rebuild chain backwards to genesis
                std::vector<uint256> chainHashes;
                uint256 currentHash = hashBestBlock;

                while (!(currentHash == genesisHash)) {
                    chainHashes.push_back(currentHash);

                    CBlockIndex blockIndexFromDB;
                    if (!blockchain.ReadBlockIndex(currentHash, blockIndexFromDB)) {
                        std::cerr << "ERROR: Cannot load block index " << currentHash.GetHex().substr(0, 16) << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // If this block's previous hash is null/zero, it's the genesis block - stop here
                    if (blockIndexFromDB.header.hashPrevBlock.IsNull()) {
                        break;
                    }

                    currentHash = blockIndexFromDB.header.hashPrevBlock;
                }

                // Now load all blocks in forward order (genesis to tip)
                // Genesis already loaded, so start from the chain
                for (auto it = chainHashes.rbegin(); it != chainHashes.rend(); ++it) {
                    const uint256& blockHash = *it;

                    CBlockIndex blockIndexFromDB;
                    if (!blockchain.ReadBlockIndex(blockHash, blockIndexFromDB)) {
                        std::cerr << "ERROR: Cannot load block index " << blockHash.GetHex().substr(0, 16) << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
                    auto pblockIndex = std::make_unique<CBlockIndex>(blockIndexFromDB);
                    // IBD DEADLOCK FIX #10: Set phashBlock to prevent GetBlockHash from computing RandomX
                    pblockIndex->phashBlock = blockHash;
                    pblockIndex->pprev = g_chainstate.GetBlockIndex(pblockIndex->header.hashPrevBlock);

                    // PNEXT FIX: Set pnext on parent to enable forward chain traversal
                    // This is needed for GETHEADERS to serve headers from genesis
                    if (pblockIndex->pprev != nullptr) {
                        pblockIndex->pprev->pnext = pblockIndex.get();
                    }

                    if (pblockIndex->pprev == nullptr && !(blockHash == genesisHash)) {
                        std::cerr << "ERROR: Cannot find parent block for " << blockHash.GetHex().substr(0, 16) << std::endl;

                        // CHAIN INTEGRITY: Auto-wipe for testnet, manual intervention for mainnet
                        if (config.testnet) {
                            std::cout << "\n==========================================================" << std::endl;
                            std::cout << "TESTNET: Chain corruption detected during startup" << std::endl;
                            std::cout << "TESTNET: Missing parent block - database inconsistent" << std::endl;
                            std::cout << "TESTNET: Attempting automatic recovery..." << std::endl;
                            std::cout << "==========================================================" << std::endl;

                            // Bug #25 FIX: Close ALL databases before wiping to release file locks (Windows)
                            blockchain.Close();
                            utxo_set.Close();  // CRITICAL: Also close UTXO database (chainstate directory)

                            CChainVerifier verifier;
                            if (!verifier.RepairChain(true)) {
                                std::cerr << "ERROR: Failed to repair testnet blockchain data" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            std::cout << "==========================================================" << std::endl;
                            std::cout << "TESTNET: Blockchain data wiped successfully" << std::endl;
                            std::cout << "TESTNET: Reopening databases and continuing..." << std::endl;
                            std::cout << "==========================================================" << std::endl;

                            // Bug #29 Fix: Close and reopen databases instead of exiting
                            // Close existing databases first
                            blockchain.Close();
                            utxo_set.Close();

                            // Reopen blockchain database
                            std::string blocksPath = config.datadir + "/blocks";
                            if (!blockchain.Open(blocksPath)) {
                                std::cerr << "ERROR: Failed to reopen blockchain database after wipe" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            // Clear mempool (P0-5 FIX: use .load() for atomic)
                            auto* mempool = g_mempool.load();
                            if (mempool) mempool->Clear();

                            // Reopen UTXO set database
                            std::string chainstatePath = config.datadir + "/chainstate";
                            if (!utxo_set.Open(chainstatePath)) {
                                std::cerr << "ERROR: Failed to reopen UTXO database after wipe" << std::endl;
                                delete Dilithion::g_chainParams;
                                return 1;
                            }

                            // Reset chain state
                            g_chainstate.Cleanup();
                            g_chainstate.SetTip(nullptr);

                            // Jump back to genesis loading (will trigger IBD after handshake)
                            goto load_genesis_block;
                        } else {
                            std::cerr << "\n==========================================================" << std::endl;
                            std::cerr << "ERROR: Corrupted blockchain database detected" << std::endl;
                            std::cerr << "Missing parent block - database inconsistent" << std::endl;
                            std::cerr << "==========================================================" << std::endl;
                            std::cerr << "\nThis usually indicates:" << std::endl;
                            std::cerr << "  1. Database corruption from unclean shutdown" << std::endl;
                            std::cerr << "  2. Incomplete blockchain download" << std::endl;
                            std::cerr << "  3. Running different code versions" << std::endl;
                            std::cerr << "\nTo recover:" << std::endl;
                            std::cerr << "  Delete blockchain data for full re-sync:" << std::endl;
                            std::cerr << "    ./dilithion-node --reset-chain" << std::endl;
                            std::cerr << "    ./dilithion-node" << std::endl;
                            std::cerr << "  (--reset-chain preserves wallet.dat and mik_registration.dat)" << std::endl;
                            std::cerr << "\nFor more information, see docs/troubleshooting.md\n" << std::endl;

                            delete Dilithion::g_chainParams;
                            return 1;
                        }
                    }

                    // Rebuild chain work
                    pblockIndex->BuildChainWork();

                    // Add to chain state (transfer ownership with std::move)
                    if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                        std::cerr << "ERROR: Failed to add block index to chain state" << std::endl;
                        // HIGH-C001 FIX: No manual delete - ownership transferred
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    // HIGH-C001 FIX: After move, retrieve pointer from chain state
                    CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
                    // Set pnext pointer on parent to maintain chain
                    if (pblockIndexPtr->pprev != nullptr) {
                        pblockIndexPtr->pprev->pnext = pblockIndexPtr;
                    }
                }

                // Set the tip
                CBlockIndex* pindexTip = g_chainstate.GetBlockIndex(hashBestBlock);
                if (pindexTip == nullptr) {
                    std::cerr << "ERROR: Cannot find tip block index after loading!" << std::endl;
                    delete Dilithion::g_chainParams;
                    return 1;
                }

                g_chainstate.SetTip(pindexTip);
                // v4.3.1: seed candidate set after tip established. Without
                // this, m_setBlockIndexCandidates stays empty after disk load
                // — under env-var=1 path, FindMostWorkChainImpl returns
                // whichever single block was last inserted, never comparing
                // against tip's chainwork. Caused LDN tip-going-backwards /
                // dual-hash deadlock 2026-05-04.
                g_chainstate.RecomputeCandidates();
                g_chain_height.store(static_cast<unsigned int>(pindexTip->nHeight));  // BUG #108 FIX: Set global height for TX validation

                // BUG #270 FIX: Ensure all blocks on the active chain have BLOCK_VALID_CHAIN set.
                // Bootstrap imports store blocks with only BLOCK_HAVE_DATA (status=8),
                // missing the BLOCK_VALID_CHAIN flag that IBD orphan resolution depends on.
                // Walk from tip to genesis and fix any blocks missing the flag.
                {
                    CBlockIndex* pwalker = pindexTip;
                    int fixed_count = 0;
                    while (pwalker) {
                        if (!(pwalker->nStatus & CBlockIndex::BLOCK_VALID_CHAIN)) {
                            pwalker->nStatus |= CBlockIndex::BLOCK_VALID_CHAIN;
                            fixed_count++;
                        }
                        pwalker = pwalker->pprev;
                    }
                    if (fixed_count > 0) {
                        std::cout << "  [FIX] Set BLOCK_VALID_CHAIN on " << fixed_count
                                  << " blocks in active chain (bootstrap fix)" << std::endl;
                    }
                }

                // v4.4 Block 5: Startup chainstate-integrity check (rolling window).
                // Replaces the v4.0.19 fixed-depth (100-block) probe. Walks every block
                // in [highest_checkpoint+1 .. tip] via pprev (RT F-1 pattern), verifying
                // each has a present, SHA3-checksummed undo record. Detects both the
                // missing-undo-data mode (incident 2026-04-25) and silent checksum
                // corruption that the v4.0.19 path missed. Window-floor at the highest
                // checkpoint because (a) deeper history is consensus-anchored,
                // (b) operators recover by chain-rebuild and the rebuild restart-time
                // floor IS the checkpoint, so verifying below the checkpoint adds no
                // operational value. O(N) where N = (tipHeight - highestCheckpoint).
                {
                    int highestCheckpoint = -1;
                    if (Dilithion::g_chainParams) {
                        for (const auto& cp : Dilithion::g_chainParams->checkpoints) {
                            if (cp.nHeight > highestCheckpoint) highestCheckpoint = cp.nHeight;
                        }
                    }

                    const int tipHeight = pindexTip->nHeight;
                    if (highestCheckpoint < 0) {
                        std::cout << "  [v4.4] No checkpoints configured — startup integrity check skipped" << std::endl;
                    } else if (tipHeight <= highestCheckpoint) {
                        std::cout << "  [v4.4] Tip at height " << tipHeight
                                  << " not above highest checkpoint " << highestCheckpoint
                                  << " — startup integrity check skipped" << std::endl;
                    } else {
                        const int fromHeight = highestCheckpoint + 1;
                        const int toHeight = tipHeight;
                        std::cout << "  [v4.4] Startup integrity check: verifying undo data "
                                  << "for blocks [" << fromHeight << ".." << toHeight
                                  << "] via pprev walk..." << std::endl;
                        UndoIntegrityFailure failure;
                        if (!utxo_set.VerifyUndoDataInRange(pindexTip, fromHeight, toHeight, failure)) {
                            std::cerr << "\n==========================================================" << std::endl;
                            std::cerr << "[CRITICAL] Startup integrity check FAILED at height "
                                      << failure.height << " hash=" << failure.blockHash.GetHex()
                                      << " cause=" << failure.cause << std::endl;
                            std::cerr << "This node cannot perform reorgs without manual recovery."
                                      << " Writing auto_rebuild marker — node will wipe and resync"
                                      << " on next launch." << std::endl;
                            std::cerr << "==========================================================" << std::endl;

                            const std::string reason =
                                "Startup integrity check failed at height "
                                + std::to_string(failure.height)
                                + " cause=" + failure.cause
                                + " hash=" + failure.blockHash.GetHex();
                            Dilithion::WriteAutoRebuildMarker(config.datadir, reason);

                            delete Dilithion::g_chainParams;
                            return 2;  // Distinguishable exit code; wrapper restarts and wipes
                        }
                        std::cout << "  [OK] Startup integrity check passed: "
                                  << (toHeight - fromHeight + 1)
                                  << " blocks verified clean (pprev walk, O(N))" << std::endl;

                        // v4.4 Block 8: construct the periodic integrity monitor
                        // ONLY when the startup check actually walked (real chain
                        // past first checkpoint). Skipped on regtest (no checkpoints)
                        // and on chains whose tip is at-or-below the highest
                        // checkpoint, per contract scope item 5.
                        // Throws std::runtime_error if a second instance is
                        // constructed in the same process — the unique_ptr scope
                        // guarantees exactly-one for the lifetime of this run.
                        // Start() is deferred until the main-loop poll sees
                        // g_utxo_sync_enabled == true.
                        integrity_monitor = std::make_unique<Dilithion::ChainstateIntegrityMonitor>(
                            g_chainstate, utxo_set, config.datadir, &g_node_state.running);
                    }
                }

                std::cout << "  [OK] Loaded chain state: " << chainHashes.size() + 1 << " blocks (height "
                          << pindexTip->nHeight << ")" << std::endl;
            } else {
                std::cerr << "ERROR: Cannot read best block from database!" << std::endl;
                delete Dilithion::g_chainParams;
                return 1;
            }
        }

        // ========================================================================
        // CHAIN INTEGRITY VALIDATION (Bug #17)
        // Following Bitcoin Core, Ethereum Geth, Monero best practices
        // Prevents "Cannot find parent block" errors during systemd auto-restart
        // ========================================================================
        {
            std::cout << "Validating blockchain integrity..." << std::endl;

            CChainVerifier verifier;
            std::string error;

            // Quick validation on every startup (1-10 seconds)
            // Checks: genesis exists, best block valid, no missing parents
            if (!verifier.VerifyChainIntegrity(CChainVerifier::LEVEL_QUICK, error)) {

                if (config.testnet) {
                    // TESTNET: Auto-wipe corrupted data (following Ethereum Geth pattern)
                    std::cout << "==========================================================" << std::endl;
                    std::cout << "TESTNET: Chain corruption detected" << std::endl;
                    std::cout << "Error: " << error << std::endl;
                    std::cout << "TESTNET: Attempting automatic recovery..." << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Bug #25 FIX: Close ALL databases before wiping to release file locks (Windows)
                    blockchain.Close();
                    utxo_set.Close();  // CRITICAL: Also close UTXO database (chainstate directory)

                    if (!verifier.RepairChain(true)) {
                        std::cerr << "ERROR: Failed to repair testnet blockchain data" << std::endl;
                        delete Dilithion::g_chainParams;
                        return 1;
                    }

                    std::cout << "==========================================================" << std::endl;
                    std::cout << "TESTNET: Blockchain data wiped successfully" << std::endl;
                    std::cout << "TESTNET: Please restart the node" << std::endl;
                    std::cout << "TESTNET: Node will rebuild from genesis block" << std::endl;
                    std::cout << "TESTNET: This is normal after code updates" << std::endl;
                    std::cout << "==========================================================" << std::endl;

                    // Exit gracefully - systemd will auto-restart
                    delete Dilithion::g_chainParams;
                    return 0;  // Clean exit for systemd restart

                } else {
                    // MAINNET: Conservative approach (following Bitcoin Core pattern)
                    std::cerr << "\n==========================================================" << std::endl;
                    std::cerr << "ERROR: Corrupted blockchain database detected" << std::endl;
                    std::cerr << "Error: " << error << std::endl;
                    std::cerr << "==========================================================" << std::endl;
                    std::cerr << "\nThis usually indicates:" << std::endl;
                    std::cerr << "  1. Database corruption from unclean shutdown" << std::endl;
                    std::cerr << "  2. Incomplete blockchain download" << std::endl;
                    std::cerr << "  3. Disk corruption" << std::endl;
                    std::cerr << "\nTo recover:" << std::endl;
                    std::cerr << "  Option 1: Reset chain state for full re-sync" << std::endl;
                    std::cerr << "    ./dilithion-node --reset-chain" << std::endl;
                    std::cerr << "    ./dilithion-node" << std::endl;
                    std::cerr << "  (preserves wallet.dat and mik_registration.dat)" << std::endl;
                    std::cerr << "\nFor more information, see docs/troubleshooting.md\n" << std::endl;

                    delete Dilithion::g_chainParams;
                    return 1;
                }
            }

            std::cout << "  [OK] Chain integrity validation passed" << std::endl;
        }

        // Set network magic for P2P protocol
        if (config.testnet) {
            NetProtocol::g_network_magic = NetProtocol::TESTNET_MAGIC;
        } else {
            NetProtocol::g_network_magic = NetProtocol::MAINNET_MAGIC;
        }

        // Phase 2: Initialize P2P networking (prepare for later)
        std::cout << "Initializing P2P components..." << std::endl;

        // Phase 1.2: Initialize NodeContext using explicit Init() (Bitcoin Core pattern)
        std::cout << "Initializing NodeContext..." << std::endl;
        if (!g_node_context.Init(config.datadir, &g_chainstate)) {
            std::cerr << "ERROR: Failed to initialize NodeContext" << std::endl;
            return 1;
        }
        std::cout << "  [OK] NodeContext initialized" << std::endl;

        // Phase 2: Initialize async block validation queue for IBD performance
        std::cout << "Initializing async block validation queue..." << std::endl;
        g_node_context.validation_queue = std::make_unique<CBlockValidationQueue>(g_chainstate, blockchain);
        if (g_node_context.validation_queue->Start()) {
            std::cout << "  [OK] Async block validation queue started" << std::endl;
        } else {
            std::cerr << "  [WARN] Failed to start validation queue (will use synchronous validation)" << std::endl;
        }

        // Phase 3.2: Initialize batch signature verifier for parallel verification
        std::cout << "Initializing batch signature verifier..." << std::endl;
        InitSignatureVerifier(4);  // 4 worker threads for parallel verification
        std::cout << "  [OK] Batch signature verifier started with 4 workers" << std::endl;

        // IBD HANG FIX #14: Register blockchain_db for block serving
        g_node_context.blockchain_db = &blockchain;

        // Phase 11 A1: now that blockchain_db is wired, enable fork-staging
        // dispatch on the port chain selector adapter. This routes port-path
        // ProcessNewBlock through ForkManager (validate-before-disconnect)
        // instead of calling ActivateBestChain directly.
        // Post v4.3.4 cut: the port::CPeerManager bypass concern is moot
        // (class deleted, flag retired) — only the legacy block-arrival path
        // reaches ProcessNewBlock now, and it always traverses ForkManager.
        if (!g_node_context.WireForkStaging()) {
            std::cerr << "[startup] WARN: WireForkStaging failed — port path will not stage forks" << std::endl;
        }

        // Keep legacy globals for backward compatibility during migration
        // REMOVED: g_peer_manager assignment - CBlockFetcher now uses dependency injection
        // REMOVED: Legacy global assignments - use NodeContext directly

        // Initialize transaction relay manager (global)
        // P0-5 FIX: Use .store() for atomic pointer
        g_tx_relay_manager.store(new CTxRelayManager());

        // Initialize IBD managers (Bug #12 - Phase 4.1)
        std::cout << "Initializing IBD managers..." << std::endl;
        std::cout << "  [OK] Headers manager initialized" << std::endl;
        std::cout << "  [OK] Orphan manager initialized (max 100 blocks / 100 MB)" << std::endl;
        std::cout << "  [OK] Block fetcher initialized (max 16 blocks in-flight)" << std::endl;

        // Bug #40 fix: Register HeadersManager callback for chain tip updates
        g_chainstate.RegisterTipUpdateCallback([](const CBlockIndex* pindex) {
            if (g_node_context.headers_manager && pindex) {
                g_node_context.headers_manager->OnBlockActivated(pindex->header, pindex->GetBlockHash());
            }
        });
        std::cout << "  [OK] Chain tip callback registered for HeadersManager" << std::endl;

        // BUG #32 FIX: Register callback for mining template updates on chain tip change
        SetChainTipUpdateCallback([&blockchain](CBlockchainDB& db, int new_height, bool is_reorg) {
            // Only update if mining is enabled and not in IBD. BUG #278's extra
            // "skip during PoW" guard is no longer needed — BuildMiningTemplate
            // now returns nullopt when the CRegistrationManager isn't READY, so
            // concurrent calls during registration PoW are harmless no-ops.
            if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load()
                && !IsInitialBlockDownload()) {
                std::cout << "[Mining] " << (is_reorg ? "Reorg" : "New tip")
                          << " detected - updating template immediately..." << std::endl;
                auto templateOpt = BuildMiningTemplate(db, *g_node_state.wallet, false, g_node_state.mining_address_override);
                if (templateOpt) {
                    g_node_state.miner->UpdateTemplate(*templateOpt);
                    std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                }
            }
        });
        std::cout << "  [OK] Mining template update callback registered" << std::endl;

        // Bug #41 fix: Initialize HeadersManager with existing chain from database
        // This ensures HeadersManager can serve historical headers, not just newly mined ones
        {
            std::cout << "Populating HeadersManager with existing chain..." << std::endl;
            CBlockIndex* pindexTip = g_chainstate.GetTip();

            if (pindexTip != nullptr) {
                // Build chain from tip to genesis, then reverse for genesis-to-tip order
                std::vector<CBlockIndex*> chain;
                CBlockIndex* pindex = pindexTip;
                while (pindex != nullptr) {
                    chain.push_back(pindex);
                    pindex = pindex->pprev;
                }
                std::reverse(chain.begin(), chain.end());

                // Bulk-load all headers at once (skips per-block logging and comparisons)
                g_node_context.headers_manager->BulkLoadHeaders(chain);
            } else {
                std::cout << "  [WARN] No chain tip - HeadersManager empty (expected for fresh node)" << std::endl;
            }
        }

        // =========================================================================
        // BUG #252 FIX: Populate heat tracker from existing chain on startup
        // =========================================================================
        // Without this, nodes loading existing chain data have empty heat trackers,
        // while nodes syncing fresh have fully populated heat trackers. This causes
        // DFMP penalty calculation to differ between nodes, leading to consensus
        // failures where one node rejects valid blocks due to wrong penalty calculation.
        //
        // Solution: On startup, scan the last OBSERVATION_WINDOW blocks and
        // populate the heat tracker by calling OnBlockConnected for each block.
        //
        // CRITICAL: All blocks in the window MUST be readable and parseable for
        // deterministic consensus. Missing or corrupt blocks cause divergent penalties.
        // =========================================================================
        if (DFMP::g_heatTracker != nullptr) {
            CBlockIndex* pindexTip = g_chainstate.GetTip();
            if (pindexTip != nullptr && pindexTip->nHeight > 0) {
                // Try loading persisted heat tracker from disk (fast path)
                bool loadedFromFile = false;
                std::string mikHeatPath = config.datadir + "/dfmp_heat.dat";
                std::string payoutHeatPath = config.datadir + "/dfmp_payout_heat.dat";

                if (DFMP::g_heatTracker->LoadFromFile(mikHeatPath, pindexTip->nHeight)) {
                    bool payoutLoaded = !DFMP::g_payoutHeatTracker ||
                        DFMP::g_payoutHeatTracker->LoadFromFile(payoutHeatPath, pindexTip->nHeight);
                    if (payoutLoaded) {
                        loadedFromFile = true;
                        std::cout << "  [OK] Loaded heat tracker from disk ("
                                  << DFMP::g_heatTracker->GetWindowSize() << " entries, tip="
                                  << pindexTip->nHeight << ")" << std::endl;
                    } else {
                        // MIK loaded but payout failed - clear both and rebuild
                        DFMP::g_heatTracker->Clear();
                        std::cout << "  [INFO] Payout heat tracker file stale/missing, rebuilding both from chain" << std::endl;
                    }
                }

                if (!loadedFromFile) {
                std::cout << "Populating heat tracker from existing chain..." << std::endl;

                // CURSOR FIX #2: Use canonical constant instead of hardcoded value
                const int windowSize = DFMP::OBSERVATION_WINDOW;
                std::vector<CBlockIndex*> recentBlocks;
                CBlockIndex* pindex = pindexTip;
                int startHeight = std::max(1, pindexTip->nHeight - windowSize + 1);

                // Walk back to start height
                while (pindex != nullptr && pindex->nHeight >= startHeight) {
                    recentBlocks.push_back(pindex);
                    pindex = pindex->pprev;
                }

                // CURSOR FIX #3: Clear heat tracker before population to avoid accumulation
                // This ensures deterministic state even if startup flow changes
                DFMP::g_heatTracker->Clear();

                // DFMP v3.0: Clear payout heat tracker alongside MIK heat tracker
                if (DFMP::g_payoutHeatTracker) {
                    DFMP::g_payoutHeatTracker->Clear();
                }

                // Process from oldest to newest to maintain proper window ordering
                int populated = 0;
                int readFailed = 0;
                int parseFailed = 0;
                int dfmpActivationHeight = Dilithion::g_chainParams ?
                    Dilithion::g_chainParams->dfmpActivationHeight : 0;

                for (auto it = recentBlocks.rbegin(); it != recentBlocks.rend(); ++it) {
                    CBlockIndex* blockIndex = *it;

                    // Only process blocks after DFMP activation
                    if (blockIndex->nHeight < dfmpActivationHeight) {
                        continue;
                    }

                    // Read block data to extract miner identity
                    CBlock block;
                    if (!blockchain.ReadBlock(blockIndex->GetBlockHash(), block) || block.vtx.empty()) {
                        // CURSOR FIX #1: Log when ReadBlock fails - this causes divergent heat!
                        std::cerr << "[DFMP] WARNING: Cannot read block " << blockIndex->nHeight
                                  << " for heat tracker - consensus may diverge!" << std::endl;
                        readFailed++;
                        continue;
                    }

                    CBlockValidator validator;
                    std::vector<CTransactionRef> transactions;
                    std::string error;

                    if (!validator.DeserializeBlockTransactions(block, transactions, error) ||
                        transactions.empty() || transactions[0]->vin.empty()) {
                        // CURSOR FIX #4: Log when deserialization fails
                        std::cerr << "[DFMP] WARNING: Cannot deserialize block " << blockIndex->nHeight
                                  << " for heat tracker: " << error << std::endl;
                        parseFailed++;
                        continue;
                    }

                    DFMP::CMIKScriptData mikData;
                    if (!DFMP::ParseMIKFromScriptSig(transactions[0]->vin[0].scriptSig, mikData) ||
                        mikData.identity.IsNull()) {
                        // CURSOR FIX #4: Log when MIK parsing fails
                        std::cerr << "[DFMP] WARNING: Cannot parse MIK from block " << blockIndex->nHeight
                                  << " for heat tracker" << std::endl;
                        parseFailed++;
                        continue;
                    }

                    DFMP::g_heatTracker->OnBlockConnected(blockIndex->nHeight, mikData.identity);

                    // DFMP v3.0: Rebuild payout heat tracker
                    if (DFMP::g_payoutHeatTracker && !transactions[0]->vout.empty()) {
                        DFMP::Identity payoutId = DFMP::DeriveIdentityFromScript(
                            transactions[0]->vout[0].scriptPubKey);
                        DFMP::g_payoutHeatTracker->OnBlockConnected(blockIndex->nHeight, payoutId);
                    }

                    // DFMP v3.0: Rebuild last-mined heights for dormancy
                    if (DFMP::g_identityDb) {
                        DFMP::g_identityDb->SetLastMined(mikData.identity, blockIndex->nHeight);
                    }

                    populated++;
                }

                // Report results with failure counts for debugging
                std::cout << "  [OK] Populated heat tracker with " << populated
                          << " block(s) from height " << startHeight
                          << " to " << pindexTip->nHeight;
                if (readFailed > 0 || parseFailed > 0) {
                    std::cout << " (WARNING: " << readFailed << " read failures, "
                              << parseFailed << " parse failures)";
                }
                std::cout << std::endl;

                // FATAL: If any blocks failed to read, heat tracker is incomplete.
                // Nodes with incomplete heat trackers compute different DFMP multipliers,
                // causing chain splits. This is NOT recoverable without fixing the block DB.
                if (readFailed > 0) {
                    std::cerr << "[DFMP] FATAL: " << readFailed << " block(s) could not be read from database!" << std::endl;
                    std::cerr << "[DFMP] Heat tracker is INCOMPLETE - node CANNOT achieve consensus." << std::endl;
                    std::cerr << "[DFMP] This usually means block database corruption (e.g., from a crash)." << std::endl;
                    std::cerr << "[DFMP] To fix: restart with -reindex to rebuild the block database," << std::endl;
                    std::cerr << "[DFMP]   or delete blocks/ and chainstate/ directories and resync." << std::endl;
                    return 1;
                }
                } // end if (!loadedFromFile)
            } else {
                std::cout << "  [INFO] No existing chain - heat tracker will populate during sync" << std::endl;
            }
        }

        // =========================================================================
        // BUG #263 FIX: Rebuild identity DB from full chain when empty (bootstrap fix)
        // =========================================================================
        // When a node starts from a bootstrap snapshot, the dfmp_identity/ database
        // may be missing or empty. Without MIK pubkeys, blocks above dfmpAssumeValidHeight
        // fail validation because the miner's pubkey can't be found.
        // Fix: Scan ALL blocks from dfmpActivationHeight to tip and store all MIK
        // registrations (firstSeen + pubkey) in the identity database.
        if (DFMP::g_identityDb != nullptr) {
            CBlockIndex* pindexTip = g_chainstate.GetTip();
            if (pindexTip != nullptr && pindexTip->nHeight > 0) {
                size_t identityCount = DFMP::g_identityDb->GetIdentityCount();
                if (identityCount == 0) {
                    std::cout << "Rebuilding identity database from chain (bootstrap detected)..." << std::endl;

                    int dfmpActivation = Dilithion::g_chainParams ?
                        Dilithion::g_chainParams->dfmpActivationHeight : 0;
                    int tipHeight = pindexTip->nHeight;

                    // Walk the active chain from tip backward to collect all blocks
                    std::vector<CBlockIndex*> chainBlocks;
                    CBlockIndex* pindex = pindexTip;
                    while (pindex != nullptr && pindex->nHeight >= dfmpActivation) {
                        chainBlocks.push_back(pindex);
                        pindex = pindex->pprev;
                    }

                    int registered = 0;
                    int skipped = 0;

                    // Process from oldest to newest
                    for (auto it = chainBlocks.rbegin(); it != chainBlocks.rend(); ++it) {
                        CBlockIndex* blockIndex = *it;

                        CBlock block;
                        if (!blockchain.ReadBlock(blockIndex->GetBlockHash(), block) || block.vtx.empty()) {
                            skipped++;
                            continue;
                        }

                        CBlockValidator validator;
                        std::vector<CTransactionRef> transactions;
                        std::string error;
                        if (!validator.DeserializeBlockTransactions(block, transactions, error) ||
                            transactions.empty() || transactions[0]->vin.empty()) {
                            skipped++;
                            continue;
                        }

                        DFMP::CMIKScriptData mikData;
                        if (!DFMP::ParseMIKFromScriptSig(transactions[0]->vin[0].scriptSig, mikData) ||
                            mikData.identity.IsNull()) {
                            skipped++;
                            continue;
                        }

                        // Store first-seen height
                        if (!DFMP::g_identityDb->Exists(mikData.identity)) {
                            DFMP::g_identityDb->SetFirstSeen(mikData.identity, blockIndex->nHeight);
                        }

                        // Store MIK public key on registration
                        if (mikData.isRegistration && !DFMP::g_identityDb->HasMIKPubKey(mikData.identity)) {
                            DFMP::g_identityDb->SetMIKPubKey(mikData.identity, mikData.pubkey);
                            registered++;
                        }
                    }

                    std::cout << "  [OK] Rebuilt identity database: " << registered
                              << " MIK pubkey(s) registered from " << chainBlocks.size()
                              << " block(s) (height " << dfmpActivation << " to " << tipHeight << ")"
                              << std::endl;
                    if (skipped > 0) {
                        std::cerr << "  [WARN] " << skipped
                                  << " block(s) could not be parsed during identity rebuild" << std::endl;
                    }
                } else {
                    std::cout << "  [OK] Identity database has " << identityCount
                              << " known identities" << std::endl;
                }
            }
        }

        // Create message processor and connection manager (local, using NodeContext peer manager)
        CNetMessageProcessor message_processor(*g_node_context.peer_manager);
        
        // Phase 5: Replace CConnectionManager with CConnman (event-driven networking)
        auto connman = std::make_unique<CConnman>();
        CConnmanOptions connman_opts;
        connman_opts.fListen = true;
        connman_opts.nListenPort = config.p2pport;
        connman_opts.nMaxOutbound = 8;
        connman_opts.nMaxInbound = 117;
        connman_opts.nMaxTotal = 125;
        connman_opts.upnp_enabled = config.upnp_enabled;  // UPnP automatic port mapping
        connman_opts.nMaxInboundPerIP = config.max_connections_per_ip;  // Per-IP limit (default 2)

        // Apply --maxconnections override if specified
        if (config.max_connections > 0) {
            connman_opts.nMaxTotal = config.max_connections;
            // Adjust inbound/outbound proportionally
            if (config.max_connections <= 8) {
                connman_opts.nMaxOutbound = config.max_connections;
                connman_opts.nMaxInbound = 0;  // No inbound if very limited
                connman_opts.fListen = false;  // Disable listen socket entirely for single-peer mode
            } else {
                connman_opts.nMaxOutbound = std::min(8, config.max_connections / 2);
                connman_opts.nMaxInbound = config.max_connections - connman_opts.nMaxOutbound;
            }
            std::cout << "  [INFO] Max connections limited to " << config.max_connections
                      << " (outbound=" << connman_opts.nMaxOutbound
                      << ", inbound=" << connman_opts.nMaxInbound
                      << ", listen=" << (connman_opts.fListen ? "yes" : "no") << ")" << std::endl;
        }

        // BUG #138 FIX: Set g_node_context pointers BEFORE starting threads
        // This allows handlers to access connman immediately when messages arrive
        // Start() is called AFTER handlers are registered (see below after SetHeadersHandler)

        // Set global pointers for transaction announcement (NW-005)
        // P0-5 FIX: Use .store() for atomic pointers
        g_message_processor.store(&message_processor);

        // Phase 1.2: Store in NodeContext (Bitcoin Core pattern)
        g_node_context.connman = std::move(connman);
        g_node_context.message_processor = &message_processor;

        // Phase 5: Create and start async broadcaster for non-blocking message broadcasting
        // Now uses CConnman instead of CConnectionManager
        CAsyncBroadcaster async_broadcaster(g_node_context.connman.get());
        g_async_broadcaster = &async_broadcaster;  // Legacy global
        g_node_context.async_broadcaster = &async_broadcaster;

        // Phase 1.2: Store node state flags in NodeContext
        // Note: atomic values must use .load() when copying
        g_node_context.running.store(g_node_state.running.load());
        g_node_context.mining_enabled.store(g_node_state.mining_enabled.load());

        // Phase 5: Start async broadcaster
        if (!async_broadcaster.Start()) {
            std::cerr << "Failed to start async broadcaster" << std::endl;
            return 1;
        }

        // Phase 5: Create feeler connection manager (Bitcoin Core-style eclipse attack protection)
        // Now uses CConnman instead of CConnectionManager
        CFeelerManager feeler_manager(*g_node_context.peer_manager, g_node_context.connman.get(), &message_processor);

        // REMOVED: CMessageProcessorQueue - CConnman::ThreadMessageHandler handles messages directly
        // The async queue was created but never received messages (only deprecated CConnectionManager used it)
        std::cout << "  [OK] Message processing via CConnman::ThreadMessageHandler" << std::endl;

        // Create and start HTTP API server for dashboard
        // Use port 18334 for testnet, 8334 for mainnet (Bitcoin convention)
        int api_port = config.testnet ? 18334 : 8334;
        CHttpServer http_server(api_port);
        g_node_state.http_server = &http_server;

        // STRESS TEST FIX: Create cached stats for lock-free API responses
        // Stats are updated every 1 second by background thread, never blocking API
        CCachedChainStats cached_stats;
        cached_stats.Start([]() -> CCachedChainStats::UpdateData {
            CCachedChainStats::UpdateData data;

            // Get current stats from chain state
            CBlockIndex* tip = g_chainstate.GetTip();
            data.block_height = tip ? tip->nHeight : 0;
            data.difficulty = tip ? tip->nBits : 0;
            data.last_block_time = tip ? static_cast<int64_t>(tip->nTime) : 0;

            // Compute actual average block time from last 20 blocks
            // This gives a realistic hashrate instead of assuming 240s target
            if (tip && tip->nHeight >= 20) {
                CBlockIndex* older = tip;
                for (int i = 0; i < 20 && older->pprev; i++) {
                    older = older->pprev;
                }
                int64_t time_span = static_cast<int64_t>(tip->nTime) - static_cast<int64_t>(older->nTime);
                int block_span = tip->nHeight - older->nHeight;
                if (block_span > 0 && time_span > 0) {
                    data.actual_block_time = static_cast<double>(time_span) / block_span;
                }
            }

            // Get headers height
            if (g_node_context.headers_manager) {
                data.headers_height = g_node_context.headers_manager->GetBestHeight();
            }

            // Get peer count
            if (g_node_context.peer_manager) {
                data.peer_count = static_cast<int>(g_node_context.peer_manager->GetConnectedPeers().size());
            }

            // Check if syncing
            data.is_syncing = (data.headers_height > data.block_height + 10);

            return data;
        });

        // Set stats handler that returns cached statistics as JSON (never blocks)
        std::string network_name = config.testnet ? "testnet" : "mainnet";
        http_server.SetStatsHandler([&cached_stats, network_name]() -> std::string {
            return cached_stats.ToJSON(network_name);
        });

        // Set network name for Prometheus metrics labeling
        g_metrics.SetNetworkName(network_name);

        // Set metrics handler for Prometheus scraping
        http_server.SetMetricsHandler([&mempool]() -> std::string {
            // Update current metrics from live state
            CBlockIndex* tip = g_chainstate.GetTip();
            g_metrics.block_height = tip ? tip->nHeight : 0;
            g_metrics.last_block_time = tip ? static_cast<int64_t>(tip->nTime) : 0;

            if (g_node_context.headers_manager) {
                g_metrics.headers_height = g_node_context.headers_manager->GetBestHeight();
            }

            if (g_node_context.peer_manager) {
                auto peers = g_node_context.peer_manager->GetConnectedPeers();
                g_metrics.peer_count = peers.size();
                // TODO: Track inbound/outbound separately when CConnman tracks this
                g_metrics.inbound_peers = 0;
                g_metrics.outbound_peers = peers.size();
            }

            // Update mempool metrics
            g_metrics.mempool_size = mempool.Size();

            // Sync bandwidth metrics from g_network_stats
            g_metrics.bytes_received_total.store(g_network_stats.bytes_recv);
            g_metrics.bytes_sent_total.store(g_network_stats.bytes_sent);

            // Return Prometheus-format metrics
            return g_metrics.ToPrometheus();
        });

        // Set up REST API handler for light wallet support (/api/v1/*)
        // This allows light wallets to query balance, UTXOs, and broadcast transactions
        static CRestAPI rest_api;
        rest_api.RegisterMempool(&mempool);
        rest_api.RegisterBlockchain(&blockchain);
        rest_api.RegisterUTXOSet(&utxo_set);
        rest_api.RegisterChainState(&g_chainstate);
        rest_api.SetTestnet(config.testnet);
        // Note: Rate limiter is optional for HTTP server (RPC server has its own)

        http_server.SetRestApiHandler([](const std::string& method,
                                         const std::string& path,
                                         const std::string& body,
                                         const std::string& clientIP) -> std::string {
            return rest_api.HandleRequest(method, path, body, clientIP);
        });
        std::cout << "[HttpServer] REST API enabled for light wallet support" << std::endl;

        // BUG #140 FIX: Make HTTP server failure non-fatal
        // The stats endpoint is optional - core P2P functionality should continue
        bool http_started = http_server.Start();
        if (!http_started) {
            std::cerr << "[HttpServer] WARNING: Failed to start HTTP API server on port " << api_port << std::endl;
            std::cerr << "[HttpServer] Stats endpoint will be unavailable, but P2P will continue" << std::endl;
        } else {
            std::cout << "[HttpServer] API server started on port " << api_port << std::endl;
            std::cout << "[HttpServer] Dashboard endpoint: http://localhost:" << api_port << "/api/stats" << std::endl;
            std::cout << "[HttpServer] Prometheus metrics: http://localhost:" << api_port << "/metrics" << std::endl;
        }

        // Verify global pointers are properly initialized (audit recommendation)
        assert(g_node_context.connman != nullptr && "connman must be initialized");
        assert(g_node_context.message_processor != nullptr && "message_processor must be initialized");
        assert(g_node_context.peer_manager != nullptr && "peer_manager must be initialized");
        assert(g_tx_relay_manager != nullptr && "g_tx_relay_manager must be initialized");

        // Register version handler to automatically respond with version + verack
        // Bitcoin handshake: A->B: VERSION, B->A: VERSION + VERACK, A->B: VERACK
        message_processor.SetVersionHandler([](int peer_id, const NetProtocol::CVersionMessage& msg) {
            // BUG #62 FIX: Store peer's starting height for later header sync decision
            if (g_node_context.headers_manager) {
                g_node_context.headers_manager->SetPeerStartHeight(peer_id, msg.start_height);
            }

            // PEER DISCOVERY FIX: Learn our external IP from what peer sees us as
            // The peer's addr_recv field contains THEIR view of OUR address
            // This helps us learn our public IP for advertising to other peers
            if (g_node_context.connman) {
                std::string peerSeesUsAs = msg.addr_recv.ToStringIP();
                if (!peerSeesUsAs.empty() && peerSeesUsAs != "0.0.0.0") {
                    g_node_context.connman->RecordExternalIP(peerSeesUsAs, peer_id);
                }
            }

            // BUG #129 FIX: Only send VERSION for inbound connections (state < VERSION_SENT)
            // For outbound connections, we already sent VERSION in ConnectAndHandshake()
            // Sending VERSION again causes an infinite VERSION ping-pong loop
            auto peer = g_node_context.peer_manager->GetPeer(peer_id);

            if (peer && peer->state < CPeer::STATE_VERSION_SENT) {
                // Create and send version message for inbound peer
                // PEER DISCOVERY FIX: Use learned external IP instead of 0.0.0.0
                NetProtocol::CAddress local_addr;
                local_addr.services = NetProtocol::NODE_NETWORK;
                if (g_node_context.connman) {
                    std::string externalIP = g_node_context.connman->GetExternalIP();
                    if (!externalIP.empty()) {
                        local_addr.SetFromString(externalIP);
                        local_addr.port = 8444;  // Mainnet P2P port
                    } else {
                        local_addr.SetIPv4(0);
                        local_addr.port = 0;
                    }
                } else {
                    local_addr.SetIPv4(0);
                    local_addr.port = 0;
                }
                CNetMessage version_msg = g_node_context.message_processor->CreateVersionMessage(peer->addr, local_addr);
                if (g_node_context.connman) {
                    g_node_context.connman->PushMessage(peer_id, version_msg);
                    peer->state = CPeer::STATE_VERSION_SENT;
                    // BUG #148 FIX: Also update CNode::state to prevent state drift
                    // This ensures both CPeer and CNode states stay synchronized
                    if (g_node_context.peer_manager) {
                        CNode* node = g_node_context.peer_manager->GetNode(peer_id);
                        if (node && node->state.load() < CNode::STATE_VERSION_SENT) {
                            node->state.store(CNode::STATE_VERSION_SENT);
                        }
                    }
                }
            }

            // Always send VERACK to acknowledge their VERSION
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage verack_msg = g_node_context.message_processor->CreateVerackMessage();
                g_node_context.connman->PushMessage(peer_id, verack_msg);
            }
        });

        // Register verack handler to trigger IBD when handshake completes
        message_processor.SetVerackHandler([](int peer_id) {
            LogPrintf(NET, INFO, "Handshake complete with peer %d\n", peer_id);

            // BUG #36 FIX: Register peer with BlockFetcher so it can download blocks
            if (g_node_context.block_fetcher) {
                g_node_context.block_fetcher->OnPeerConnected(peer_id);
            }
            // v4.3.4 cut Block 5 (errata E2): verack-path dynamic_cast +
            // OnPeerConnected dispatch to port::CPeerManager removed. Block 4
            // already deleted the port-side per-peer state that this hook
            // initialized. Block 7 retires the class entirely.

            // Phase C FIX: Notify CPeerManager of handshake completion
            // This is CRITICAL for IsPeerSuitableForDownload() to return true
            if (g_node_context.peer_manager && g_node_context.headers_manager) {
                int peerHeight = g_node_context.headers_manager->GetPeerStartHeight(peer_id);
                g_node_context.peer_manager->OnPeerHandshakeComplete(peer_id, peerHeight, false);
            }

            // Request addresses from peer (Bitcoin Core pattern for peer discovery)
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage getaddr_msg = g_node_context.message_processor->CreateGetAddrMessage();
                g_node_context.connman->PushMessage(peer_id, getaddr_msg);
            }

            // Phase 5: Mark peer's address as "good" on successful handshake
            // This moves the address from "new" to "tried" table in AddrMan
            // CRITICAL: Only for OUTBOUND connections! Inbound peers have ephemeral
            // source ports (e.g., 46420) not their listening port (18444).
            // Bitcoin Core never adds inbound addresses to AddrMan for this reason.
            if (g_node_context.peer_manager) {
                auto peer = g_node_context.peer_manager->GetPeer(peer_id);
                auto node = g_node_context.peer_manager->GetNode(peer_id);
                if (peer && node && !node->fInbound && peer->addr.IsRoutable()) {
                    g_node_context.peer_manager->MarkAddressGood(peer->addr);
                }
            }

            // Check if headers_manager is initialized
            if (!g_node_context.headers_manager) {
                return;
            }

            // BUG #62 FIX: Compare our height with peer's announced height
            int ourHeight = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
            int peerHeight = g_node_context.headers_manager->GetPeerStartHeight(peer_id);

            // Request headers if peer is ahead OR if we're at genesis
            // Header requests are managed by IBD coordinator - don't request here.
            // Requesting from every peer on VERSION causes header racing.
            (void)peerHeight;  // Suppress unused warning
            (void)ourHeight;

            // BIP 130: Send sendheaders to request HEADERS instead of INV for new blocks
            // This reduces latency by 1 round trip when peer announces new blocks
            if (g_node_context.connman && g_node_context.message_processor) {
                CNode* node = g_node_context.connman->GetNode(peer_id);
                if (node && !node->fSentSendHeaders.load()) {
                    CNetMessage sendheaders_msg = g_node_context.message_processor->CreateSendHeadersMessage();
                    g_node_context.connman->PushMessage(peer_id, sendheaders_msg);
                    node->fSentSendHeaders.store(true);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[P2P] Sent sendheaders to peer " << peer_id << std::endl;
                }
            }

            // BIP 152: Send sendcmpct to signal we support compact blocks
            // high_bandwidth=true means we want unsolicited compact blocks for new blocks
            // version=1 is the only supported version (version 2 is for segwit)
            if (g_node_context.connman && g_node_context.message_processor) {
                CNode* node = g_node_context.connman->GetNode(peer_id);
                if (node && !node->fSentSendCmpct.load()) {
                    // Request high-bandwidth mode: peer sends cmpctblock immediately on new blocks
                    CNetMessage sendcmpct_msg = g_node_context.message_processor->CreateSendCmpctMessage(true, 1);
                    g_node_context.connman->PushMessage(peer_id, sendcmpct_msg);
                    node->fSentSendCmpct.store(true);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[BIP152] Sent sendcmpct (high_bandwidth=true, version=1) to peer " << peer_id << std::endl;
                }
            }
        });

        // Register ping handler to automatically respond with pong
        message_processor.SetPingHandler([](int peer_id, uint64_t nonce) {
            // Silently respond with pong - keepalive is automatic
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage pong_msg = g_node_context.message_processor->CreatePongMessage(nonce);
                g_node_context.connman->PushMessage(peer_id, pong_msg);
            }
        });

        // Register pong handler (keepalive response received)
        message_processor.SetPongHandler([](int peer_id, uint64_t nonce) {
            // Silently acknowledge - keepalive working
        });

        // Register ADDR handler to receive addresses from peers
        message_processor.SetAddrHandler([](int peer_id, const std::vector<NetProtocol::CAddress>& addrs) {
            if (addrs.empty()) {
                return;
            }

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Received " << addrs.size() << " addresses from peer " << peer_id << std::endl;

            // Add each address to AddrMan via peer manager
            int added = 0;
            for (const auto& addr : addrs) {
                // Skip non-routable addresses
                if (!addr.IsRoutable()) {
                    continue;
                }

                // Skip localhost
                std::string ip = addr.ToStringIP();
                if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) {
                    continue;
                }

                // Add to address manager
                if (g_node_context.peer_manager) {
                    g_node_context.peer_manager->AddPeerAddress(addr);
                    added++;
                }
            }

            if (added > 0 && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[P2P] Added " << added << " new addresses to AddrMan from peer " << peer_id << std::endl;
            }
        });

        // Register inv handler to request announced blocks
        message_processor.SetInvHandler([&blockchain](
            int peer_id, const std::vector<NetProtocol::CInv>& inv_items) {

            bool hasUnknownBlocks = false;
            std::vector<NetProtocol::CInv> getdata;

            for (const auto& item : inv_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // DEBUG: Log every block INV received
                    bool exists = blockchain.BlockExists(item.hash);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[INV-DEBUG] Peer " << peer_id << " announced block "
                                  << item.hash.GetHex().substr(0, 16) << "... exists="
                                  << (exists ? "YES" : "NO") << std::endl;

                    // Check if we already have this block
                    if (!exists) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[P2P] Peer " << peer_id << " announced new block: "
                                      << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                        hasUnknownBlocks = true;
                        getdata.push_back(item);
                    }
                }
            }

            // BUG #62 FIX: Request headers when peer announces unknown blocks
            // When a peer announces a block via INV, they have blocks we don't know about.
            // Request headers from them - use a large assumed height since peer will only
            // send headers they actually have. The peer's best_known_height will be updated
            // automatically when we receive their headers (in headers_manager.cpp).
            // NOTE: Use force=true to bypass dedup check - INV announcements indicate new
            // blocks exist that we haven't requested yet, regardless of tracking state.
            if (hasUnknownBlocks && g_node_context.headers_manager) {
                int our_header_height = g_node_context.headers_manager->GetBestHeight();
                // Use large number - peer sends whatever they actually have (up to 2000 per batch)
                int assumed_peer_height = our_header_height + 2000;
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[INV-SYNC] Unknown block announced by peer " << peer_id
                              << ", requesting headers (force=true)" << std::endl;
                g_node_context.headers_manager->SyncHeadersFromPeer(peer_id, assumed_peer_height, true);
            }

            // DISABLED: Legacy inv-based block requests
            // Bitcoin Core uses headers-first download for ALL block fetching.
            // Blocks announced via INV trigger header sync (above), which discovers
            // the new block and requests it through the IBD coordinator with proper
            // CBlockFetcher tracking.
            //
            // This legacy path bypassed tracking, breaking chunk-based downloads.
            // It is now permanently disabled - all block requests go through
            // headers-first download exclusively.
            if (!getdata.empty() && g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[P2P] Ignoring INV-announced blocks (using headers-first approach)" << std::endl;
            }
        });

        // Register getdata handler to serve blocks to requesting peers
        message_processor.SetGetDataHandler([&blockchain](
            int peer_id, const std::vector<NetProtocol::CInv>& requested_items) {

            for (const auto& item : requested_items) {
                if (item.type == NetProtocol::MSG_BLOCK_INV) {
                    // Look up block in database by RandomX hash
                    // SIMPLIFICATION: We now use RandomX hash everywhere, so direct lookup should work
                    CBlock block;
                    bool found = blockchain.ReadBlock(item.hash, block);

                    if (found) {
                        // Send block to requesting peer
                        if (g_node_context.connman && g_node_context.message_processor) {
                            CNetMessage blockMsg = g_node_context.message_processor->CreateBlockMessage(block);
                            auto serialized = blockMsg.Serialize();
                            if (g_verbose.load(std::memory_order_relaxed)) {
                                std::cout << "[BLOCK-SERVE] Sending block " << item.hash.GetHex().substr(0, 16)
                                          << "... to peer " << peer_id
                                          << " (vtx=" << block.vtx.size() << " bytes, msg=" << serialized.size() << " bytes)" << std::endl;
                            }
                            g_node_context.connman->PushMessage(peer_id, blockMsg);
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[BLOCK-SERVE] PushMessage SUCCEEDED for block to peer " << peer_id << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] Peer " << peer_id << " requested unknown block: "
                                  << item.hash.GetHex().substr(0, 16) << "..." << std::endl;
                        // DEBUG: Check if block exists in chainstate under this hash
                        if (g_verbose.load(std::memory_order_relaxed)) {
                            CBlockIndex* pindex = g_chainstate.GetBlockIndex(item.hash);
                            if (pindex) {
                                std::cout << "[DEBUG] Block IS in chainstate at height " << pindex->nHeight
                                          << " but NOT in block database!" << std::endl;
                            } else {
                                std::cout << "[DEBUG] Block NOT in chainstate either - hash doesn't exist" << std::endl;
                            }
                        }
                    }
                }
                // Phase 5: Transaction relay - implement MSG_TX_INV handling after testnet stabilizes
            }
        });

        // Register block handler to validate and save received blocks
        // Uses ProcessNewBlock() extracted function for reusability (BIP 152 compact blocks)
        message_processor.SetBlockHandler([&blockchain](int peer_id, const CBlock& block) {
            auto result = ProcessNewBlock(g_node_context, blockchain, peer_id, block);
            // Note: Invalid PoW tracking is handled inside ProcessNewBlock
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BLOCK-HANDLER] Result: " << BlockProcessResultToString(result) << std::endl;
        });

        // Register GETHEADERS handler - respond with block headers from our chain (Bug #12 - Phase 4.2)
        message_processor.SetGetHeadersHandler([&blockchain](
            int peer_id, const NetProtocol::CGetHeadersMessage& msg) {

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Peer " << peer_id << " requested headers (locator size: "
                          << msg.locator.size() << ")" << std::endl;

            // Find the best common block between us and the peer
            uint256 hashStart;
            bool found = false;

            // Search through locator hashes to find first one we have
            for (const uint256& hash : msg.locator) {
                if (g_chainstate.HasBlockIndex(hash)) {
                    hashStart = hash;
                    found = true;
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[IBD] Found common block: " << hash.GetHex().substr(0, 16) << "..." << std::endl;
                    break;
                }
            }

            if (!found) {
                // Bitcoin Core approach: empty locator means "send from genesis"
                // FIX: Use computed genesis hash, not hardcoded chainparams string
                // (The hardcoded string may not match the actual RandomX hash)
                hashStart = Genesis::GetGenesisHash();
                found = true;

                if (g_verbose.load(std::memory_order_relaxed)) {
                    if (msg.locator.empty()) {
                        std::cout << "[IBD] Empty locator - sending from genesis: "
                                  << hashStart.GetHex().substr(0,16) << "..." << std::endl;
                    } else {
                        std::cout << "[IBD] No common block in locator - falling back to genesis: "
                                  << hashStart.GetHex().substr(0,16) << "..." << std::endl;
                    }
                }
            }

            // Collect up to 2000 headers starting from hashStart
            std::vector<CBlockHeader> headers;
            CBlockIndex* pindex = g_chainstate.GetBlockIndex(hashStart);

            if (pindex) {
                // BUG FIX: Check if common block is on the active chain.
                // If it's on a fork, pnext will be NULL and we'd send 0 headers.
                // Instead, find the fork point and send active chain headers.
                CBlockIndex* pTip = g_chainstate.GetTip();
                if (pTip) {
                    CBlockIndex* pActiveAtHeight = pTip->GetAncestor(pindex->nHeight);
                    if (pActiveAtHeight && pActiveAtHeight->GetBlockHash() != pindex->GetBlockHash()) {
                        // Common block is on a fork - walk back to find fork point
                        int forkHeight = pindex->nHeight;
                        CBlockIndex* pForkWalk = pindex;
                        while (forkHeight > 0 && pForkWalk && pForkWalk->pprev) {
                            forkHeight--;
                            pForkWalk = pForkWalk->pprev;
                            CBlockIndex* pActiveCheck = pTip->GetAncestor(forkHeight);
                            if (pActiveCheck && pActiveCheck->GetBlockHash() == pForkWalk->GetBlockHash()) {
                                // Found the fork point
                                break;
                            }
                        }
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[IBD] Common block at height " << pindex->nHeight
                                      << " is on a fork, fork point at height " << forkHeight << std::endl;
                        // Send headers from active chain starting after fork point
                        for (int h = forkHeight + 1; h <= pTip->nHeight && headers.size() < 2000; h++) {
                            CBlockIndex* pBlock = pTip->GetAncestor(h);
                            if (pBlock) {
                                headers.push_back(pBlock->header);
                            }
                        }
                    } else {
                        // Common block is on active chain - walk forward via active chain
                        for (int h = pindex->nHeight + 1; h <= pTip->nHeight && headers.size() < 2000; h++) {
                            CBlockIndex* pBlock = pTip->GetAncestor(h);
                            if (pBlock) {
                                headers.push_back(pBlock->header);
                            }
                            // Stop if we reach the stop hash
                            if (!msg.hashStop.IsNull() && pBlock && pBlock->GetBlockHash() == msg.hashStop) {
                                break;
                            }
                        }
                    }
                }
            }

            // Always send HEADERS response, even if empty (Bitcoin Core protocol requirement)
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Sending " << headers.size() << " header(s) to peer " << peer_id << std::endl;
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage headersMsg = g_node_context.message_processor->CreateHeadersMessage(headers);
                g_node_context.connman->PushMessage(peer_id, headersMsg);
            }
        });

        // Register HEADERS handler - process received headers (Bug #12 - Phase 4.2)
        // ASYNC HEADER PROCESSING: P2P thread returns immediately (<1ms)
        // Background thread handles hash computation and validation
        message_processor.SetHeadersHandler([](int peer_id, const std::vector<CBlockHeader>& headers) {
            if (headers.empty()) {
                return;
            }

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[IBD] Received " << headers.size() << " header(s) from peer " << peer_id << std::endl;

            // FULLY ASYNC: Queue raw headers for background processing
            // P2P thread doesn't compute any hashes - just queues and returns immediately
            // Background HeaderProcessorThread handles hash computation + validation
            bool success = g_node_context.headers_manager->QueueRawHeadersForProcessing(
                peer_id, std::vector<CBlockHeader>(headers)  // Copy for async processing
            );

            if (success) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[IBD] Headers queued for async processing (P2P thread released)" << std::endl;

                // Note: Best height will be updated by background thread after processing
                // Peer height update moved to background thread completion
            } else {
                std::cerr << "[IBD] Failed to queue headers for processing" << std::endl;
            }
        });

        // BIP 130: Handle sendheaders from peers
        // When a peer sends sendheaders, they want us to announce new blocks via HEADERS
        // instead of INV (saves 1 round trip)
        message_processor.SetSendHeadersHandler([](int peer_id) {
            if (g_node_context.connman) {
                CNode* node = g_node_context.connman->GetNode(peer_id);
                if (node) {
                    node->fPreferHeaders.store(true);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[P2P] Peer " << peer_id << " now prefers HEADERS announcements" << std::endl;
                }
            }
        });

        // BIP 152: Handle sendcmpct from peers
        // When a peer sends sendcmpct, they support compact blocks and want us to send them
        message_processor.SetSendCmpctHandler([](int peer_id, bool high_bandwidth, uint64_t version) {
            if (version != 1) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Peer " << peer_id << " sent sendcmpct with unsupported version "
                              << version << " (ignoring)" << std::endl;
                return;
            }

            if (g_node_context.connman) {
                CNode* node = g_node_context.connman->GetNode(peer_id);
                if (node) {
                    node->fSupportsCompactBlocks.store(true);
                    node->fHighBandwidth.store(high_bandwidth);
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[BIP152] Peer " << peer_id << " supports compact blocks (high_bandwidth="
                                  << (high_bandwidth ? "true" : "false") << ")" << std::endl;
                }
            }
        });

        // BIP 152: Handle cmpctblock (compact block) from peers
        // Phase 4: Full mempool-based block reconstruction
        message_processor.SetCmpctBlockHandler([&blockchain, &message_processor](int peer_id, const CBlockHeaderAndShortTxIDs& cmpctblock) {
            uint256 blockHash = cmpctblock.header.GetHash();
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Received CMPCTBLOCK from peer " << peer_id
                          << " (hash=" << blockHash.GetHex().substr(0, 16) << "..."
                          << ", prefilled=" << cmpctblock.prefilledtxn.size()
                          << ", shorttxids=" << cmpctblock.shorttxids.size() << ")" << std::endl;

            // Check if we already have this block
            CBlockIndex* pindex = g_chainstate.GetBlockIndex(blockHash);
            if (pindex) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Already have block " << blockHash.GetHex().substr(0, 16)
                              << "... at height " << pindex->nHeight << std::endl;
                return;
            }

            // Phase 4: Full mempool reconstruction
            // 1. Get mempool transactions
            CTxMemPool* mempool = g_mempool.load();
            std::vector<CTransaction> mempool_txs;
            if (mempool) {
                auto tx_refs = mempool->GetOrderedTxs();
                mempool_txs.reserve(tx_refs.size());
                for (const auto& tx_ref : tx_refs) {
                    if (tx_ref) {
                        mempool_txs.push_back(*tx_ref);
                    }
                }
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Attempting reconstruction with " << mempool_txs.size() << " mempool txns" << std::endl;
            }

            // 2. Create PartiallyDownloadedBlock and fill from mempool
            auto partial_block = std::make_unique<PartiallyDownloadedBlock>();
            ReadStatus status = partial_block->InitData(cmpctblock, mempool_txs);

            if (status == ReadStatus::OK) {
                // 3a. Fully reconstructed - extract and validate block
                CBlock block;
                if (!partial_block->GetBlock(block)) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[BIP152] Block reconstruction failed (merkle mismatch) - requesting full block" << std::endl;
                    // Merkle root mismatch - request full block as fallback
                    if (g_node_context.connman && g_node_context.message_processor) {
                        NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, blockHash);
                        std::vector<NetProtocol::CInv> inv_vec = {block_inv};
                        CNetMessage getdata_msg = g_node_context.message_processor->CreateGetDataMessage(inv_vec);
                        g_node_context.connman->PushMessage(peer_id, getdata_msg);
                    }
                    return;
                }

                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Block fully reconstructed from mempool!" << std::endl;

                // Process the reconstructed block using ProcessNewBlock with precomputed hash
                auto result = ProcessNewBlock(g_node_context, blockchain, peer_id, block, &blockHash);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] ProcessNewBlock result: " << BlockProcessResultToString(result) << std::endl;

            } else if (status == ReadStatus::EXTRA_TXN) {
                // 3b. Need missing transactions - send GETBLOCKTXN
                auto missing_indices = partial_block->GetMissingTxIndices();
                size_t missing_count = missing_indices.size();
                size_t total_txns = cmpctblock.prefilledtxn.size() + cmpctblock.shorttxids.size();

                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Need " << missing_count << "/" << total_txns
                              << " missing transactions - sending GETBLOCKTXN" << std::endl;

                // Store partial block for completion when BLOCKTXN arrives
                {
                    std::lock_guard<std::mutex> lock(g_node_context.cs_partial_blocks);
                    g_node_context.partial_blocks[blockHash.GetHex()] =
                        std::make_pair(peer_id, std::move(partial_block));
                }

                // Send GETBLOCKTXN request
                if (g_node_context.connman && g_node_context.message_processor) {
                    BlockTransactionsRequest req;
                    req.blockhash = blockHash;
                    req.indexes = missing_indices;
                    CNetMessage getblocktxn_msg = g_node_context.message_processor->CreateGetBlockTxnMessage(req);
                    g_node_context.connman->PushMessage(peer_id, getblocktxn_msg);
                }

            } else {
                // 3c. Invalid compact block - request full block as fallback
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Compact block invalid (status=" << static_cast<int>(status)
                              << ") - requesting full block" << std::endl;
                if (g_node_context.connman && g_node_context.message_processor) {
                    NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, blockHash);
                    std::vector<NetProtocol::CInv> inv_vec = {block_inv};
                    CNetMessage getdata_msg = g_node_context.message_processor->CreateGetDataMessage(inv_vec);
                    g_node_context.connman->PushMessage(peer_id, getdata_msg);
                }
            }
        });

        // BIP 152: Handle getblocktxn (request for missing transactions)
        // Peer needs specific transactions from a block we sent as compact
        message_processor.SetGetBlockTxnHandler([&blockchain, &message_processor](int peer_id, const BlockTransactionsRequest& req) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Received GETBLOCKTXN from peer " << peer_id
                          << " (block=" << req.blockhash.GetHex().substr(0, 16)
                          << "..., " << req.indexes.size() << " txns requested)" << std::endl;

            // Load the requested block
            CBlock block;
            if (!blockchain.ReadBlock(req.blockhash, block)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Don't have requested block " << req.blockhash.GetHex().substr(0, 16) << "..." << std::endl;
                return;
            }

            // Deserialize transactions from block
            std::vector<CTransaction> transactions;
            if (!DeserializeTransactionsFromVtx(block.vtx, transactions)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Failed to deserialize transactions from block" << std::endl;
                return;
            }

            // Build response with requested transactions
            BlockTransactions resp;
            resp.blockhash = req.blockhash;

            for (uint16_t idx : req.indexes) {
                if (idx >= transactions.size()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[BIP152] Peer requested invalid tx index " << idx
                                  << " (block has " << transactions.size() << " txns)" << std::endl;
                    // Misbehave
                    if (g_node_context.peer_manager) {
                        g_node_context.peer_manager->Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
                    }
                    return;
                }
                resp.txn.push_back(transactions[idx]);
            }

            // Send blocktxn response
            if (g_node_context.connman && g_node_context.message_processor) {
                CNetMessage blocktxn_msg = g_node_context.message_processor->CreateBlockTxnMessage(resp);
                g_node_context.connman->PushMessage(peer_id, blocktxn_msg);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Sent BLOCKTXN with " << resp.txn.size() << " transactions to peer " << peer_id << std::endl;
            }
        });

        // BIP 152: Handle blocktxn (missing transactions response)
        // Phase 4: Complete block reconstruction with received transactions
        message_processor.SetBlockTxnHandler([&blockchain](int peer_id, const BlockTransactions& resp) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Received BLOCKTXN from peer " << peer_id
                          << " (block=" << resp.blockhash.GetHex().substr(0, 16)
                          << "..., " << resp.txn.size() << " txns)" << std::endl;

            // Find pending partial block
            std::unique_ptr<PartiallyDownloadedBlock> partial_block;
            int original_peer_id = -1;
            {
                std::lock_guard<std::mutex> lock(g_node_context.cs_partial_blocks);
                auto it = g_node_context.partial_blocks.find(resp.blockhash.GetHex());
                if (it == g_node_context.partial_blocks.end()) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[BIP152] No pending partial block for " << resp.blockhash.GetHex().substr(0, 16)
                                  << "... (may have been completed or timed out)" << std::endl;
                    return;
                }
                original_peer_id = it->second.first;
                partial_block = std::move(it->second.second);
                g_node_context.partial_blocks.erase(it);
            }

            // Verify response is from the peer we requested from
            if (g_verbose.load(std::memory_order_relaxed) && peer_id != original_peer_id) {
                std::cout << "[BIP152] BLOCKTXN from unexpected peer " << peer_id
                          << " (expected " << original_peer_id << ") - accepting anyway" << std::endl;
            }

            // Fill in missing transactions
            ReadStatus status = partial_block->FillMissingTxs(resp.txn);
            if (status != ReadStatus::OK) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Failed to fill missing transactions (status=" << static_cast<int>(status)
                              << ") - requesting full block" << std::endl;
                // Fall back to full block request
                if (g_node_context.connman && g_node_context.message_processor) {
                    NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, resp.blockhash);
                    std::vector<NetProtocol::CInv> inv_vec = {block_inv};
                    CNetMessage getdata_msg = g_node_context.message_processor->CreateGetDataMessage(inv_vec);
                    g_node_context.connman->PushMessage(peer_id, getdata_msg);
                }
                return;
            }

            // Extract reconstructed block
            CBlock block;
            if (!partial_block->GetBlock(block)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[BIP152] Block reconstruction failed (merkle mismatch) - requesting full block" << std::endl;
                if (g_node_context.connman && g_node_context.message_processor) {
                    NetProtocol::CInv block_inv(NetProtocol::MSG_BLOCK_INV, resp.blockhash);
                    std::vector<NetProtocol::CInv> inv_vec = {block_inv};
                    CNetMessage getdata_msg = g_node_context.message_processor->CreateGetDataMessage(inv_vec);
                    g_node_context.connman->PushMessage(peer_id, getdata_msg);
                }
                return;
            }

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] Block fully reconstructed with " << resp.txn.size() << " received transactions!" << std::endl;

            // Process the reconstructed block using ProcessNewBlock with precomputed hash
            auto result = ProcessNewBlock(g_node_context, blockchain, peer_id, block, &resp.blockhash);
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[BIP152] ProcessNewBlock result: " << BlockProcessResultToString(result) << std::endl;
        });

        // Digital DNA P2P Handlers: Clock drift and bandwidth measurement protocol
        // dnalping: Peer wants to measure latency -> respond with pong
        message_processor.SetDNALatencyPingHandler([&message_processor](int peer_id, uint64_t nonce) {
            if (g_node_context.connman) {
                CNetMessage pong = message_processor.CreateDNALatencyPongMessage(nonce);
                g_node_context.connman->PushMessage(peer_id, pong);
            }
        });

        // dnalpong: Latency pong received -> feed RTT to clock drift collector
        message_processor.SetDNALatencyPongHandler([](int peer_id, uint64_t nonce, uint64_t recv_ts_us) {
            // RTT measured by the nonce system; for DNA latency we just log it
            // Clock drift uses dnatsync, not dnalping/pong (those are for raw RTT only)
            (void)peer_id; (void)nonce; (void)recv_ts_us;
        });

        // dnatsync: Time synchronization exchange for clock drift measurement
        message_processor.SetDNATimeSyncHandler([&message_processor](int peer_id,
            uint64_t sender_ts_us, uint64_t sender_wall_ms, uint64_t nonce,
            bool is_response, uint64_t local_send_ts_us)
        {
            if (is_response) {
                // This is a response to our request - feed to collector
                // local_send_ts_us is the real send timestamp retrieved from nonce tracking
                auto collector = g_node_context.GetDNACollector();
                if (collector && local_send_ts_us > 0) {
                    std::array<uint8_t, 20> peer_addr{};
                    peer_addr[0] = static_cast<uint8_t>(peer_id & 0xFF);
                    peer_addr[1] = static_cast<uint8_t>((peer_id >> 8) & 0xFF);

                    auto local_now_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count());
                    collector->on_time_sync_response(
                        peer_addr, local_send_ts_us, sender_ts_us, local_now_us);
                }
            } else {
                // Peer is requesting a time sync - respond with our timestamps
                if (g_node_context.connman) {
                    auto ts_us = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count());
                    auto wall_ms = static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                    CNetMessage resp = message_processor.CreateDNATimeSyncMessage(
                        ts_us, wall_ms, nonce, true);
                    g_node_context.connman->PushMessage(peer_id, resp);
                }
            }
        });

        // dnabwtest: Peer sent bandwidth test payload -> measure and respond
        message_processor.SetDNABWTestHandler([&message_processor](int peer_id,
            uint32_t payload_size, uint64_t nonce, uint64_t send_wall_ms)
        {
            if (g_node_context.connman) {
                // Compute elapsed from sender's wall clock to our wall clock
                auto recv_wall_ms = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                uint64_t elapsed_ms = (recv_wall_ms > send_wall_ms) ?
                    (recv_wall_ms - send_wall_ms) : 1;
                if (elapsed_ms < 1) elapsed_ms = 1;  // Floor to 1ms

                double throughput_mbps = digital_dna::BandwidthProofCollector::compute_throughput_mbps(
                    payload_size, elapsed_ms);
                // Receiver's download = sender's upload. Report as sender's upload.
                CNetMessage result = message_processor.CreateDNABWResultMessage(
                    nonce, throughput_mbps, 0.0);
                g_node_context.connman->PushMessage(peer_id, result);
            }
        });

        // dnabwres: Bandwidth test result from peer
        message_processor.SetDNABWResultHandler([](int peer_id, uint64_t nonce,
            double upload_mbps, double download_mbps)
        {
            auto collector = g_node_context.GetDNACollector();
            if (collector) {
                std::array<uint8_t, 20> peer_addr{};
                peer_addr[0] = static_cast<uint8_t>(peer_id & 0xFF);
                peer_addr[1] = static_cast<uint8_t>((peer_id >> 8) & 0xFF);
                collector->on_bandwidth_result(
                    peer_addr, upload_mbps, download_mbps);
            }
        });

        // DNA identity request handler: respond with serialized DNA from registry
        message_processor.SetDNAIdentReqHandler([&message_processor](int peer_id,
            const std::array<uint8_t, 20>& mik)
        {
            if (!g_node_context.dna_registry) return;
            auto dna = g_node_context.dna_registry->get_identity_by_mik(mik);
            if (dna) {
                auto data = dna->serialize();
                auto msg = message_processor.CreateDNAIdentResMessage(mik, true, data);
                if (g_node_context.connman) {
                    g_node_context.connman->PushMessage(peer_id, msg);
                }
            } else {
                auto msg = message_processor.CreateDNAIdentResMessage(mik, false, {});
                if (g_node_context.connman) {
                    g_node_context.connman->PushMessage(peer_id, msg);
                }
            }
        });

        // DNA identity response handler: store received DNA in registry.
        //
        // Phase 1.5 staged 6-stage pipeline:
        //   1. Structural parse — done in ProcessDNAIdentResMessage (net.cpp).
        //      DNA deserialization + MIK match also happens here below.
        //   2. Per-peer token bucket — consume before any crypto work.
        //   3. Route by plausibility — mapped / signed-unmapped / unsigned-unmapped.
        //   4. Signature verification (signed paths only).
        //   5. MIK-scoped checks — timestamp skew, replay cache, MIK rate limits.
        //   6. Accept — append_sample + commit replay + commit MIK limits.
        //
        // Silent drops on failure everywhere except stage 1 (structural),
        // where misbehaviour is already assigned by the parser in net.cpp.
        message_processor.SetDNAIdentResHandler([](int peer_id,
            const std::array<uint8_t, 20>& mik, bool found,
            const std::vector<uint8_t>& dna_data,
            const digital_dna::SampleEnvelope& envelope)
        {
            if (!g_node_context.dna_registry) return;
            if (!found || dna_data.empty()) return;

            // Stage 1 continuation — DNA deserialize + MIK match.
            auto dna = digital_dna::DigitalDNA::deserialize(dna_data);
            if (!dna || !dna->is_valid) return;
            if (dna->mik_identity != mik) return;

            uint64_t now_sec = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());

            // Check by MIK (not address) to match how discovery decides what to request.
            auto existing = g_node_context.dna_registry->get_identity_by_mik(mik);
            if (!existing) {
                // First time seeing this MIK — accept without rate-limiting, as the
                // miner's initial-registration broadcast establishes the peer_id→MIK
                // mapping that subsequent samples rely on for plausibility.
                //
                // Signed trailer is intentionally ignored on first-registration:
                // the pubkey may not be in our identity DB yet (if the chain hasn't
                // processed the registration block) and we'd otherwise reject
                // legitimate initial broadcasts. Later samples use the registered
                // pubkey to verify the signed-full-replacement path.
                auto result = g_node_context.dna_registry->register_identity(*dna);
                const bool stored =
                    (result == digital_dna::IDNARegistry::RegisterResult::SUCCESS ||
                     result == digital_dna::IDNARegistry::RegisterResult::SYBIL_FLAGGED);
                if (stored) {
                    std::lock_guard<std::mutex> lock(g_mik_peer_mutex);
                    g_mik_peer_map[mik] = peer_id;
                    char hex[9];
                    snprintf(hex, sizeof(hex), "%02x%02x%02x%02x", mik[0], mik[1], mik[2], mik[3]);
                    std::cout << "[DNA] Stored DNA for MIK " << hex << "... from peer "
                              << peer_id << " (registry=" << g_node_context.dna_registry->count()
                              << ")" << std::endl;
                }
                return;
            }

            // ----- Existing-MIK path: the staged 6-stage pipeline. -----

            // Stage 2: per-peer token bucket. Caps verification work a single
            // peer can force on us regardless of MIK spread. Silent drop.
            if (!g_dna_sample_limiter.consume_peer_bucket(peer_id, now_sec)) {
                return;
            }

            // Stage 3: route by plausibility.
            bool mapped = false;
            {
                std::lock_guard<std::mutex> lock(g_mik_peer_mutex);
                auto it = g_mik_peer_map.find(mik);
                mapped = (it != g_mik_peer_map.end() && it->second == peer_id);
            }
            const bool signed_envelope = !envelope.signature.empty();

            // Fast path: mapped + unsigned → full replacement, skip crypto.
            // This preserves Phase 1 trust for the miner's own connection.
            if (mapped && !signed_envelope) {
                if (!g_dna_sample_limiter.check_mik_limits(peer_id, mik, now_sec)) return;
                auto result = g_node_context.dna_registry->append_sample(*dna);
                if (result == digital_dna::IDNARegistry::RegisterResult::UPDATED ||
                    result == digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED) {
                    g_dna_sample_limiter.commit_mik_limits(peer_id, mik, now_sec);
                    char hex[9];
                    snprintf(hex, sizeof(hex), "%02x%02x%02x%02x",
                             mik[0], mik[1], mik[2], mik[3]);
                    std::cout << "[DNA] Appended sample for MIK " << hex
                              << "... from peer " << peer_id << std::endl;
                }
                return;
            }

            // Merge-fill path: unmapped + unsigned → Phase 1.1 behaviour.
            if (!mapped && !signed_envelope) {
                int filled = 0;
                auto merged = digital_dna::merge_fill_missing_dims(*existing, *dna, &filled);
                if (filled == 0) return;  // Nothing to add — silent drop.
                if (!g_dna_sample_limiter.check_mik_limits(peer_id, mik, now_sec)) return;
                auto result = g_node_context.dna_registry->append_sample(merged);
                if (result == digital_dna::IDNARegistry::RegisterResult::UPDATED ||
                    result == digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED) {
                    g_dna_sample_limiter.commit_mik_limits(peer_id, mik, now_sec);
                    char hex[9];
                    snprintf(hex, sizeof(hex), "%02x%02x%02x%02x",
                             mik[0], mik[1], mik[2], mik[3]);
                    std::cout << "[DNA] Filled " << filled << " dim(s) for MIK "
                              << hex << "... from peer " << peer_id
                              << " (unmapped)" << std::endl;
                }
                return;
            }

            // Signed path: stage 4 — pubkey lookup + post-hit sanity check + verify.
            if (!g_node_context.mik_pubkey_cache) return;

            std::vector<uint8_t> pubkey;
            if (!g_node_context.mik_pubkey_cache->Lookup(mik, pubkey)) {
                return;  // Unknown MIK; peer may be ahead of our chain. Silent drop.
            }
            // Post-hit sanity check: DB must still know this MIK. If a reorg has
            // dropped it, evict our stale cache entry and silent-drop.
            if (!g_node_context.mik_pubkey_cache->DbStillHasMIK(mik)) {
                g_node_context.mik_pubkey_cache->Evict(mik);
                return;
            }
            if (!digital_dna::SampleEnvelope::Verify(
                    pubkey, mik, envelope.timestamp_sec, envelope.nonce,
                    dna_data, envelope.signature)) {
                return;
            }

            // Stage 5: MIK-scoped checks — skew, replay, MIK rate limits.
            // Timestamp skew (±600s relative to our wall clock).
            constexpr uint64_t SKEW_BOUND_SEC = 600;
            int64_t skew = static_cast<int64_t>(now_sec) -
                           static_cast<int64_t>(envelope.timestamp_sec);
            if (skew < -static_cast<int64_t>(SKEW_BOUND_SEC) ||
                skew >  static_cast<int64_t>(SKEW_BOUND_SEC)) {
                return;
            }
            if (g_dna_sample_limiter.replay_seen(mik, envelope.timestamp_sec, envelope.nonce)) {
                return;
            }
            if (!g_dna_sample_limiter.check_mik_limits(peer_id, mik, now_sec)) {
                return;
            }

            // Stage 6: accept + commit replay/limits.
            // Authoritative-merge with existing record: signed sample's
            // populated dims overwrite (MIK is authoritative for what they
            // assert), dims not asserted preserve the receiver's existing
            // value (preserves network-enriched data the MIK didn't include
            // in this broadcast). Without this, the dim-loss guard in
            // append_sample silently rejects signed samples whenever the
            // receiver has been enriched beyond what the MIK currently
            // knows.
            digital_dna::DigitalDNA to_store = digital_dna::merge_authoritative_dims(*existing, *dna);

            // Log every signed-verify-pass with the registry outcome — gives
            // operators end-to-end observability of the signed Phase 1.5 path
            // even when the sample doesn't update the registry.
            auto result = g_node_context.dna_registry->append_sample(to_store);
            char hex[9];
            snprintf(hex, sizeof(hex), "%02x%02x%02x%02x",
                     mik[0], mik[1], mik[2], mik[3]);
            const char* outcome = "OTHER";
            switch (result) {
                case digital_dna::IDNARegistry::RegisterResult::SUCCESS:        outcome = "SUCCESS"; break;
                case digital_dna::IDNARegistry::RegisterResult::UPDATED:        outcome = "UPDATED"; break;
                case digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED:    outcome = "DNA_CHANGED"; break;
                case digital_dna::IDNARegistry::RegisterResult::INVALID_DNA:    outcome = "INVALID_DNA (dim-loss guard)"; break;
                case digital_dna::IDNARegistry::RegisterResult::ALREADY_REGISTERED: outcome = "ALREADY_REGISTERED"; break;
                case digital_dna::IDNARegistry::RegisterResult::SYBIL_FLAGGED:  outcome = "SYBIL_FLAGGED"; break;
                case digital_dna::IDNARegistry::RegisterResult::SYBIL_REJECTED: outcome = "SYBIL_REJECTED"; break;
                case digital_dna::IDNARegistry::RegisterResult::DB_ERROR:       outcome = "DB_ERROR"; break;
            }
            std::cout << "[DNA] Signed accept for MIK " << hex
                      << "... from peer " << peer_id
                      << (mapped ? " (mapped)" : " (unmapped)")
                      << " result=" << outcome
                      << std::endl;
            // Commit replay + MIK limits ONLY when the registry actually
            // accepted the change. INVALID_DNA / DB_ERROR do not consume the
            // per-MIK rate-limit budget so honest signed pushes can retry.
            if (result == digital_dna::IDNARegistry::RegisterResult::UPDATED ||
                result == digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED) {
                g_dna_sample_limiter.commit_mik_limits(peer_id, mik, now_sec);
                g_dna_sample_limiter.replay_record(
                    mik, envelope.timestamp_sec, envelope.nonce, now_sec);
            }
        });

        // Phase 2: DNA Verification & Attestation P2P handlers
        // dnavchall: Verification challenge received (we are the target)
        message_processor.SetDNAVerifyChallengeHandler([](int peer_id,
            const std::vector<uint8_t>& data)
        {
            if (g_node_context.verification_manager) {
                g_node_context.verification_manager->OnChallengeReceived(peer_id, data);
            }
        });

        // dnavresp: Verification response received (we are the verifier)
        message_processor.SetDNAVerifyResponseHandler([](int peer_id,
            const std::vector<uint8_t>& data)
        {
            if (g_node_context.verification_manager) {
                g_node_context.verification_manager->OnResponseReceived(peer_id, data);
            }
        });

        // dnavatts: Attestation broadcast received
        message_processor.SetDNAVerifyAttestHandler([](int peer_id,
            const std::vector<uint8_t>& data)
        {
            if (g_node_context.verification_manager) {
                g_node_context.verification_manager->OnAttestationReceived(peer_id, data);
            }
        });

        // PEER DISCOVERY: UPnP prompt - ask user permission for automatic port mapping
        if (!config.upnp_prompted && !config.relay_only) {
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "  NETWORK CONNECTIVITY" << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << std::endl;
            std::cout << "For best mining performance, your node needs to accept" << std::endl;
            std::cout << "incoming connections from other miners." << std::endl;
            std::cout << std::endl;
            std::cout << "Would you like to enable automatic port mapping (UPnP)?" << std::endl;
            std::cout << std::endl;
            std::cout << "  YES - Automatically open port " << config.p2pport << " on your router" << std::endl;
            std::cout << "        (Recommended for home miners)" << std::endl;
            std::cout << std::endl;
            std::cout << "  NO  - I'll configure port forwarding manually" << std::endl;
            std::cout << "        (For advanced users or if UPnP is disabled)" << std::endl;
            std::cout << std::endl;
            std::cout << "Enable automatic port mapping? [Y/n]: ";

            std::string response;
            std::getline(std::cin, response);

            if (response.empty() || response[0] == 'Y' || response[0] == 'y') {
                config.upnp_enabled = true;
                connman_opts.upnp_enabled = true;
                std::cout << "  [OK] UPnP enabled - will attempt automatic port mapping" << std::endl;
            } else {
                config.upnp_enabled = false;
                connman_opts.upnp_enabled = false;
                std::cout << "  [OK] UPnP disabled - manual port forwarding required" << std::endl;
            }
            std::cout << std::endl;
        }

        // Handle external IP: --externalip takes priority, then UPnP
        std::string effectiveExternalIP;

        // Check for manual external IP first (manual port forwarding)
        if (!config.external_ip.empty()) {
            effectiveExternalIP = config.external_ip;
            std::cout << "  [OK] Using manual external IP: " << effectiveExternalIP << std::endl;
            std::cout << "    [INFO] Ensure port " << connman_opts.nListenPort
                      << " is forwarded on your router" << std::endl;
        }
        // Attempt UPnP port mapping if enabled (and no manual IP)
        else if (connman_opts.upnp_enabled) {
            std::cout << "  Attempting automatic port mapping (UPnP)..." << std::endl;
            std::string upnpExternalIP;
            if (UPnP::MapPort(connman_opts.nListenPort, upnpExternalIP)) {
                std::cout << "    [OK] Port " << connman_opts.nListenPort << " mapped via UPnP" << std::endl;
                if (!upnpExternalIP.empty()) {
                    effectiveExternalIP = upnpExternalIP;
                    std::cout << "    [OK] External IP: " << upnpExternalIP << std::endl;
                }
            } else {
                std::cout << "    [WARN] UPnP port mapping failed: " << UPnP::GetLastError() << std::endl;
                std::cout << "    [INFO] You may need to manually forward port "
                          << connman_opts.nListenPort << " on your router" << std::endl;
                std::cout << "    [INFO] Use --externalip=<your-public-ip> to enable inbound connections" << std::endl;
            }
        }

        // NOTE: CConnman::Start is DELAYED until after wallet initialization
        // This ensures interactive prompts happen before network threads start outputting logs

        // Phase 3: Initialize mining controller
        std::cout << "Initializing mining controller..." << std::endl;
        int mining_threads = config.mining_threads > 0 ?
                            config.mining_threads :
                            std::thread::hardware_concurrency();
        CMiningController miner(mining_threads);
        g_node_state.miner = &miner;
        std::cout << "  [OK] Mining controller initialized (" << mining_threads << " threads)" << std::endl;

        // Phase 3b: Initialize VDF mining subsystem
        bool vdf_available = vdf::init();
        if (vdf_available) {
            std::cout << "  [OK] VDF library initialized (" << vdf::version() << ")" << std::endl;
        } else {
            std::cout << "  [--] VDF library not available (VDF mining disabled)" << std::endl;
        }

        int vdf_cooldown_window = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->vdfCooldownActiveWindow : CCooldownTracker::ACTIVE_WINDOW;
        CCooldownTracker cooldown_tracker(vdf_cooldown_window);
        g_node_context.cooldown_tracker = &cooldown_tracker;

        CVDFMiner vdf_miner;
        g_node_context.vdf_miner = &vdf_miner;

        // VDF miner configuration (set up later after wallet is ready)
        uint64_t vdf_iterations = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->vdfIterations : 200'000'000;
        int vdf_activation = Dilithion::g_chainParams ?
            Dilithion::g_chainParams->vdfActivationHeight : 999999999;
        vdf_miner.SetIterations(vdf_iterations);
        vdf_miner.SetCooldownTracker(&cooldown_tracker);
        if (Dilithion::g_chainParams) {
            vdf_miner.SetMinBlockTime(Dilithion::g_chainParams->vdfMinBlockTime);
        }

        // =========================================================================
        // Populate cooldown tracker from existing chain on startup.
        //
        // Without this, the tracker starts empty after every restart, meaning
        // cooldown is effectively disabled for vdfCooldownActiveWindow blocks.
        // Pattern follows the DFMP heat tracker population (lines 2330-2440).
        // =========================================================================
        if (g_node_context.cooldown_tracker != nullptr) {
            CBlockIndex* pindexTip = g_chainstate.GetTip();
            if (pindexTip != nullptr && pindexTip->nHeight > 0) {
                const int windowSize = cooldown_tracker.GetActiveWindow();
                int startHeight = std::max(vdf_activation, pindexTip->nHeight - windowSize + 1);

                // Only attempt population if we're past VDF activation
                if (pindexTip->nHeight >= vdf_activation) {
                    std::cout << "Populating VDF cooldown tracker from existing chain..." << std::endl;

                    // Walk back from tip to startHeight
                    std::vector<CBlockIndex*> recentBlocks;
                    CBlockIndex* pindex = pindexTip;
                    while (pindex != nullptr && pindex->nHeight >= startHeight) {
                        recentBlocks.push_back(pindex);
                        pindex = pindex->pprev;
                    }

                    // Clear tracker before population for deterministic state
                    g_node_context.cooldown_tracker->Clear();

                    // Process oldest-to-newest to maintain proper window ordering
                    int populated = 0;
                    int readFailed = 0;

                    for (auto it = recentBlocks.rbegin(); it != recentBlocks.rend(); ++it) {
                        CBlockIndex* blockIndex = *it;

                        // Read block from disk
                        CBlock block;
                        if (!blockchain.ReadBlock(blockIndex->GetBlockHash(), block)) {
                            std::cerr << "[VDF] WARNING: Cannot read block " << blockIndex->nHeight
                                      << " for cooldown tracker" << std::endl;
                            readFailed++;
                            continue;
                        }

                        // Only process VDF blocks
                        if (!block.IsVDFBlock()) continue;

                        // Extract MIK identity from coinbase (falls back to payout address for pre-MIK blocks)
                        std::array<uint8_t, 20> mikId{};
                        if (!ExtractCoinbaseMIKIdentity(block, mikId)) continue;

                        g_node_context.cooldown_tracker->OnBlockConnected(
                            blockIndex->nHeight, mikId);
                        populated++;
                    }

                    std::cout << "  [OK] Populated cooldown tracker with " << populated
                              << " VDF block(s) from height " << startHeight
                              << " to " << pindexTip->nHeight;
                    if (readFailed > 0) {
                        std::cout << " (WARNING: " << readFailed << " read failures)";
                    }
                    std::cout << std::endl;

                    if (readFailed > 0) {
                        std::cerr << "[VDF] CRITICAL: " << readFailed << " blocks could not be read!"
                                  << " Cooldown tracker may be incomplete." << std::endl;
                        std::cerr << "[VDF] Consider running with -reindex to rebuild block database." << std::endl;
                    }
                }
            }
        }

        // Helper lambda: check if VDF mining should be used at given height
        auto shouldUseVDF = [&vdf_available, &vdf_activation](uint32_t height) -> bool {
            return vdf_available && static_cast<int>(height) >= vdf_activation;
        };

        // Phase 4: Initialize wallet (before mining callback setup)
        // BUG #56 FIX: Full wallet persistence with Bitcoin Core pattern
        CWallet wallet;
        g_node_state.wallet = &wallet;
        // Phase 1.5: also wire the wallet into NodeContext so BroadcastDNASample
        // can find the MIK private key for signing. Without this, signed-DNA
        // broadcasts are silently skipped and Phase 1.5 has no effect on the wire.
        g_node_context.wallet = &wallet;
        std::string wallet_path = config.datadir + "/wallet.dat";
        bool wallet_loaded = false;

        if (config.relay_only) {
            // Relay-only mode: load existing wallet but skip interactive creation
            if (std::filesystem::exists(wallet_path)) {
                std::cout << "Initializing wallet (relay-only, load-only)..." << std::endl;
                if (wallet.Load(wallet_path)) {
                    wallet_loaded = true;
                    std::cout << "  [OK] Wallet loaded (" << wallet.GetAddresses().size() << " addresses)" << std::endl;

                    // Enable auto-save and register chain callbacks (required for sendtoaddress)
                    wallet.SetWalletFile(wallet_path);
                    g_chainstate.RegisterBlockConnectCallback([&wallet](const CBlock& block, int height, const uint256& hash) {
                        wallet.blockConnected(block, height, hash);
                    });
                    g_chainstate.RegisterBlockDisconnectCallback([&wallet](const CBlock& block, int height, const uint256& hash) {
                        wallet.blockDisconnected(block, height, hash);
                    });
                    std::cout << "  [OK] Wallet chain callbacks registered" << std::endl;

                    // Incremental rescan to sync wallet with chain tip
                    int32_t wallet_height = wallet.GetBestBlockHeight();
                    int chain_height = g_chainstate.GetHeight();
                    if (wallet_height < 0 || wallet_height > chain_height) {
                        std::cout << "  Rescanning blockchain (full)..." << std::endl;
                        wallet.RescanFromHeight(g_chainstate, blockchain, 0, chain_height);
                    } else if (wallet_height < chain_height) {
                        std::cout << "  Rescanning blocks " << (wallet_height + 1) << " to " << chain_height << "..." << std::endl;
                        wallet.RescanFromHeight(g_chainstate, blockchain, wallet_height + 1, chain_height);
                    }
                    unsigned int h = static_cast<unsigned int>(g_chainstate.GetHeight());
                    int64_t mature = wallet.GetAvailableBalance(utxo_set, h);
                    std::cout << "  [OK] Wallet synced - balance: " << std::fixed << std::setprecision(8)
                              << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
                } else {
                    std::cerr << "  WARNING: Failed to load wallet" << std::endl;
                }
            } else {
                std::cout << "Initializing wallet... SKIPPED (relay-only, no wallet.dat)" << std::endl;
            }
        } else {
        std::cout << "Initializing wallet..." << std::endl;

        // Build wallet file path
        std::cout << "  Wallet file: " << wallet_path << std::endl;

        // Try to load existing wallet from disk
        if (std::filesystem::exists(wallet_path)) {
            std::cout << "[3/6] Loading wallet..." << std::flush;
            std::cout.flush();
            if (wallet.Load(wallet_path)) {
                wallet_loaded = true;
                std::cout << " ✓" << std::endl;
                std::cout << "  [OK] Wallet loaded (" << wallet.GetAddresses().size() << " addresses)" << std::endl;
                std::cout << "       Best block: height " << wallet.GetBestBlockHeight() << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Failed to load wallet, creating new one" << std::endl;
                std::cerr.flush();
            }
        } else {
            std::cout << "  No existing wallet found." << std::endl;
        }

        // Generate HD wallet if wallet is empty (new wallet creation) or restore from mnemonic
        if (wallet.GetAddresses().empty()) {
            // Check if restoring from mnemonic via command line
            if (!config.restore_mnemonic.empty()) {
                std::cout << "  Restoring wallet from provided recovery phrase..." << std::endl;
                if (wallet.InitializeHDWallet(config.restore_mnemonic, "")) {
                    std::cout << "  [OK] Wallet restored successfully from recovery phrase!" << std::endl;

                    // Generate and display first receiving address
                    CDilithiumAddress addr = wallet.GetNewHDAddress();
                    std::string addrStr = addr.ToString();
                    std::cout << "  First address from restored wallet: " << addrStr << std::endl;
                    std::cout << std::endl;
                } else {
                    std::cerr << "  ERROR: Failed to restore wallet from mnemonic" << std::endl;
                    std::cerr << "  Please check that your recovery phrase is correct" << std::endl;
                    return 1;
                }
            } else {
            // Interactive prompt: Create new or restore?
            // NOTE: Network threads may already be running, but we need user input here
            // Clear any buffered input before prompting
            std::cin.clear();

            // v4.1-rc2 ISSUE-2 fix: detect non-interactive stdin and exit cleanly
            // instead of looping forever printing "Invalid choice" on empty reads.
            // Common cause: nohup, systemd, or other non-TTY launches without
            // --relay-only. Without this guard, a user's log can grow to GB-scale
            // within minutes (we observed 2.2 GB in ~10 min during v4.1-rc1 testing).
#ifdef _WIN32
            const bool stdin_is_tty = (_isatty(_fileno(stdin)) != 0);
#else
            const bool stdin_is_tty = (isatty(fileno(stdin)) != 0);
#endif
            if (!stdin_is_tty) {
                std::cerr << std::endl
                          << "ERROR: Wallet setup requires an interactive terminal." << std::endl
                          << "stdin is not a TTY — cannot prompt for wallet creation." << std::endl
                          << std::endl
                          << "Options:" << std::endl
                          << "  1. For seed/relay-only operation:" << std::endl
                          << "       Add --relay-only to skip wallet creation entirely." << std::endl
                          << "  2. For mining:" << std::endl
                          << "       Run interactively (in a terminal) once to create" << std::endl
                          << "       the wallet, then move to non-interactive operation" << std::endl
                          << "       (nohup, systemd, etc.)." << std::endl
                          << std::endl;
                return 1;
            }

            std::cout << std::endl;
            std::cout << "+==============================================================================+" << std::endl;
            std::cout << "|                        WALLET SETUP                                         |" << std::endl;
            std::cout << "+==============================================================================+" << std::endl;
            std::cout << "|                                                                              |" << std::endl;
            std::cout << "|  1 - CREATE a new wallet (generates new 24-word recovery phrase)            |" << std::endl;
            std::cout << "|  2 - RESTORE wallet from existing recovery phrase                           |" << std::endl;
            std::cout << "|                                                                              |" << std::endl;
            std::cout << "+==============================================================================+" << std::endl;
            std::cout << std::endl;

            std::string wallet_choice;
            while (true) {
                std::cout << "Enter choice (1 or 2): ";
                std::cout.flush();
                std::getline(std::cin, wallet_choice);

                // v4.1-rc2 ISSUE-2 defense-in-depth: if stdin closes mid-prompt
                // (TTY check passed but EOF/fail now), exit instead of looping.
                if (std::cin.eof() || std::cin.fail()) {
                    std::cerr << std::endl
                              << "ERROR: stdin closed during wallet setup. Aborting." << std::endl;
                    return 1;
                }

                // Trim whitespace
                size_t start = wallet_choice.find_first_not_of(" \t\r\n");
                size_t end = wallet_choice.find_last_not_of(" \t\r\n");
                if (start != std::string::npos && end != std::string::npos) {
                    wallet_choice = wallet_choice.substr(start, end - start + 1);
                } else {
                    wallet_choice.clear();
                }

                if (wallet_choice == "1" || wallet_choice == "2") {
                    break;  // Valid input
                }
                std::cout << "  Invalid choice. Please enter 1 or 2." << std::endl;
            }

            if (wallet_choice == "2") {
                // Restore from mnemonic
                std::cout << std::endl;
                std::cout << "Enter your 24-word recovery phrase (words separated by spaces):" << std::endl;
                std::cout << std::endl;

                std::string normalized;
                while (true) {
                    std::cout << "> ";
                    std::cout.flush();

                    std::string mnemonic_input;
                    std::getline(std::cin, mnemonic_input);

                    // Normalize the mnemonic (trim, lowercase, collapse spaces)
                    normalized.clear();
                    bool last_was_space = false;
                    for (char c : mnemonic_input) {
                        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                            if (!last_was_space && !normalized.empty()) {
                                normalized += ' ';
                                last_was_space = true;
                            }
                        } else {
                            normalized += std::tolower(c);
                            last_was_space = false;
                        }
                    }
                    // Trim trailing space
                    if (!normalized.empty() && normalized.back() == ' ') {
                        normalized.pop_back();
                    }

                    // Count words
                    int word_count = 0;
                    if (!normalized.empty()) {
                        word_count = 1;
                        for (char c : normalized) {
                            if (c == ' ') word_count++;
                        }
                    }

                    if (word_count == 24) {
                        break;  // Valid 24-word phrase
                    }

                    if (normalized.empty()) {
                        std::cout << "  Please enter your recovery phrase." << std::endl;
                    } else {
                        std::cout << "  Invalid: Expected 24 words, got " << word_count << ". Please try again." << std::endl;
                    }
                }

                std::cout << std::endl;
                std::cout << "  Restoring wallet from recovery phrase..." << std::endl;

                if (wallet.InitializeHDWallet(normalized, "")) {
                    std::cout << "  [OK] Wallet restored successfully!" << std::endl;

                    CDilithiumAddress addr = wallet.GetNewHDAddress();
                    std::string addrStr = addr.ToString();
                    std::cout << "  First address: " << addrStr << std::endl;
                    std::cout << std::endl;

                    // Prompt for wallet encryption
                    std::cout << "+==============================================================================+" << std::endl;
                    std::cout << "|                    WALLET ENCRYPTION (RECOMMENDED)                           |" << std::endl;
                    std::cout << "+==============================================================================+" << std::endl;
                    std::cout << "|  Encrypting your wallet adds an extra layer of security.                     |" << std::endl;
                    std::cout << "|  You will need to enter a password to unlock the wallet for transactions.    |" << std::endl;
                    std::cout << "+------------------------------------------------------------------------------+" << std::endl;
                    std::cout << std::endl;

                    std::string encrypt_choice;
                    std::cout << "  Encrypt wallet with password? [Y/n]: ";
                    std::cout.flush();
                    std::getline(std::cin, encrypt_choice);

                    if (encrypt_choice.empty() || encrypt_choice == "Y" || encrypt_choice == "y" ||
                        encrypt_choice == "yes" || encrypt_choice == "YES") {
                        // Prompt for password
                        std::string password1, password2;
                        PassphraseValidator validator;
                        while (true) {
                            std::cout << std::endl;
                            std::cout << "  Enter encryption password (min 8 characters): ";
                            std::cout.flush();
                            std::getline(std::cin, password1);

                            // Validate at prompt level so user gets clear feedback
                            PassphraseValidationResult validation = validator.Validate(password1);
                            if (!validation.is_valid) {
                                std::cout << "  " << validation.error_message << std::endl;
                                continue;
                            }

                            // Show strength tips (advisory, not required)
                            for (const auto& warning : validation.warnings) {
                                std::cout << "  [TIP] " << warning << std::endl;
                            }

                            std::cout << "  Confirm password: ";
                            std::cout.flush();
                            std::getline(std::cin, password2);

                            if (password1 != password2) {
                                std::cout << "  Passwords do not match. Please try again." << std::endl;
                                continue;
                            }
                            break;
                        }

                        std::cout << std::endl;
                        std::cout << "  Encrypting wallet..." << std::endl;
                        if (wallet.EncryptWallet(password1)) {
                            std::cout << "  [OK] Wallet encrypted successfully!" << std::endl;
                            std::cout << "       You will need this password to unlock the wallet." << std::endl;
                        } else {
                            std::cout << "  [WARN] Failed to encrypt wallet. Continuing without encryption." << std::endl;
                            std::cout << "         You can encrypt later with 'encryptwallet' RPC command." << std::endl;
                        }
                        std::cout << std::endl;
                    } else {
                        std::cout << "  [INFO] Wallet not encrypted. You can encrypt later with 'encryptwallet' RPC." << std::endl;
                        std::cout << std::endl;
                    }
                } else {
                    std::cerr << "  ERROR: Failed to restore wallet. Check your recovery phrase." << std::endl;
                    return 1;
                }
            } else {  // wallet_choice == "1"
            // Create new wallet
            std::cout << "  Generating HD wallet with 24-word recovery phrase..." << std::endl;
            std::string mnemonic;
            if (wallet.GenerateHDWallet(mnemonic, "")) {
                // Display mnemonic prominently - this is CRITICAL for user to backup
                // BUG #97 FIX: Use ASCII box characters for Windows compatibility
                std::cout << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|              IMPORTANT: YOUR 24-WORD RECOVERY PHRASE                        |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|  Write these words on paper and store in a safe place.                      |" << std::endl;
                std::cout << "|  This is the ONLY way to recover your wallet if you lose access.            |" << std::endl;
                std::cout << "|  NEVER share this phrase with anyone or store it digitally.                 |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;

                // Parse and display words in a formatted grid (6 words per line)
                std::istringstream iss(mnemonic);
                std::vector<std::string> words;
                std::string word;
                while (iss >> word) {
                    words.push_back(word);
                }

                for (size_t i = 0; i < words.size(); i += 6) {
                    std::cout << "|  ";
                    for (size_t j = i; j < std::min(i + 6, words.size()); ++j) {
                        // Format: "NN.word      " (right-pad word to 10 chars)
                        std::ostringstream entry;
                        entry << (j + 1) << "." << std::setw(10) << std::left << words[j];
                        std::cout << std::setw(13) << std::left << entry.str();
                    }
                    // Pad remaining space to fill the row
                    size_t printed = std::min(size_t(6), words.size() - i);
                    for (size_t k = printed; k < 6; ++k) {
                        std::cout << "             ";  // 13 chars padding per missing word
                    }
                    std::cout << "|" << std::endl;
                }

                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;
                std::cout << "  [OK] HD Wallet created successfully!" << std::endl;
                std::cout << std::endl;

                // Display the wallet's primary address (same one shown by check-wallet-balance)
                auto walletAddresses = wallet.GetAddresses();
                CDilithiumAddress addr = walletAddresses.empty() ? wallet.GetNewAddress() : walletAddresses[0];
                std::string addrStr = addr.ToString();

                // SECURITY: Seed phrase is displayed on screen only — never saved to disk.
                // Users must write it down on paper. Digital copies are a theft vector.

                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|              YOUR MINING WALLET                                             |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;
                std::cout << "|  All mining rewards go to your wallet. You control them with your seed.     |" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  PRIVACY MODE (Default):                                                     |" << std::endl;
                std::cout << "|  - Each mined block uses a NEW address from your wallet                     |" << std::endl;
                std::cout << "|  - This prevents others from tracking your total mining income              |" << std::endl;
                std::cout << "|  - All addresses belong to YOU - check balance with 'getbalance' RPC        |" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  FIXED ADDRESS MODE (Optional):                                              |" << std::endl;
                std::cout << "|  - Use --mining-address=Dxxx to send ALL rewards to one address             |" << std::endl;
                std::cout << "|  - Useful for: pools, public transparency, or personal preference           |" << std::endl;
                std::cout << "|  - Less private: anyone can see your total mining income                    |" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  Example address from your wallet:                                          |" << std::endl;
                std::cout << "|  " << addrStr << std::string(76 - addrStr.length(), ' ') << "|" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;

                // CRITICAL: Pause to let user write down recovery phrase
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|  IMPORTANT: Have you written down your 24-word recovery phrase?             |" << std::endl;
                std::cout << "|                                                                              |" << std::endl;
                std::cout << "|  This is your ONLY backup. If you lose it, your funds are GONE FOREVER.     |" << std::endl;
                std::cout << "|  Store it safely on PAPER - never digitally!                                |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << std::endl;

                // Require explicit Y confirmation to ensure user has read and saved the phrase
                std::string confirm;
                while (true) {
                    std::cout << "  >>> Type 'Y' to confirm you have saved your recovery phrase: ";
                    std::cout.flush();
                    std::getline(std::cin, confirm);
                    if (confirm == "Y" || confirm == "y" || confirm == "yes" || confirm == "YES") {
                        break;
                    }
                    std::cout << "  Please type 'Y' to confirm. Your recovery phrase is critical!" << std::endl;
                }
                std::cout << std::endl;

                // Prompt for wallet encryption
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|                    WALLET ENCRYPTION (RECOMMENDED)                           |" << std::endl;
                std::cout << "+==============================================================================+" << std::endl;
                std::cout << "|  Encrypting your wallet adds an extra layer of security.                     |" << std::endl;
                std::cout << "|  You will need to enter a password to unlock the wallet for transactions.    |" << std::endl;
                std::cout << "+------------------------------------------------------------------------------+" << std::endl;
                std::cout << std::endl;

                std::string encrypt_choice;
                std::cout << "  Encrypt wallet with password? [Y/n]: ";
                std::cout.flush();
                std::getline(std::cin, encrypt_choice);

                if (encrypt_choice.empty() || encrypt_choice == "Y" || encrypt_choice == "y" ||
                    encrypt_choice == "yes" || encrypt_choice == "YES") {
                    // Prompt for password
                    std::string password1, password2;
                    while (true) {
                        std::cout << std::endl;
                        std::cout << "  Enter encryption password (min 8 characters): ";
                        std::cout.flush();
                        std::getline(std::cin, password1);

                        if (password1.length() < 8) {
                            std::cout << "  Password too short. Please use at least 8 characters." << std::endl;
                            continue;
                        }

                        std::cout << "  Confirm password: ";
                        std::cout.flush();
                        std::getline(std::cin, password2);

                        if (password1 != password2) {
                            std::cout << "  Passwords do not match. Please try again." << std::endl;
                            continue;
                        }
                        break;
                    }

                    std::cout << std::endl;
                    std::cout << "  Encrypting wallet..." << std::endl;
                    if (wallet.EncryptWallet(password1)) {
                        std::cout << "  [OK] Wallet encrypted successfully!" << std::endl;
                        std::cout << "       You will need this password to unlock the wallet." << std::endl;
                    } else {
                        std::cout << "  [WARN] Failed to encrypt wallet. Continuing without encryption." << std::endl;
                    }
                    std::cout << std::endl;
                } else {
                    std::cout << "  [INFO] Wallet not encrypted. You can encrypt later with 'encryptwallet' RPC." << std::endl;
                    std::cout << std::endl;
                }

                std::cout << "  [OK] Continuing with node startup..." << std::endl;
                std::cout << std::endl;
            } else {
                // Fallback to legacy key generation if HD fails
                std::cerr << "  WARNING: HD wallet generation failed, using legacy key" << std::endl;
                wallet.GenerateNewKey();
                CDilithiumAddress addr = wallet.GetNewAddress();
                std::cout << "  [OK] Initial address (legacy): " << addr.ToString() << std::endl;
            }
            }  // end else (create new wallet)
            }  // end else (interactive mode - not command line restore)
        }

        // Enable auto-save (CRITICAL: must be done after Load or key generation)
        wallet.SetWalletFile(wallet_path);
        std::cout << "  [OK] Auto-save enabled" << std::endl;
        std::cout.flush();

        // BUG #56 FIX: Register wallet callbacks with chain state (Bitcoin Core pattern)
        // Wallet will receive blockConnected/blockDisconnected notifications automatically
        // IBD OPTIMIZATION: Pass hash to avoid RandomX recomputation in wallet
        g_chainstate.RegisterBlockConnectCallback([&wallet](const CBlock& block, int height, const uint256& hash) {
            wallet.blockConnected(block, height, hash);
        });
        g_chainstate.RegisterBlockDisconnectCallback([&wallet](const CBlock& block, int height, const uint256& hash) {
            wallet.blockDisconnected(block, height, hash);
        });
        std::cout << "  [OK] Registered chain notification callbacks" << std::endl;
        std::cout.flush();

        // BUG #56 FIX: Incremental rescan based on best block pointer (Bitcoin Core pattern)
        int32_t wallet_height = wallet.GetBestBlockHeight();
        int chain_height = g_chainstate.GetHeight();
        std::cout << "  Wallet best block: " << wallet_height << ", Chain height: " << chain_height << std::endl;
        std::cout.flush();

        if (wallet_height < 0 || wallet_height > chain_height) {
            // Full rescan needed: new wallet OR wallet ahead of chain (possible reorg)
            std::cout << "  Rescanning blockchain (full scan from genesis)..." << std::endl;
            std::cout.flush();
            if (wallet.RescanFromHeight(g_chainstate, blockchain, 0, chain_height)) {
                unsigned int height = static_cast<unsigned int>(chain_height);
                // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                // Previously used GetBalance() - GetImmatureBalance() which could differ
                int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
                int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
                int64_t total = mature + immature;
                std::cout << "  [OK] Full scan complete" << std::endl;
                std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Total: " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Rescan failed" << std::endl;
            }
        } else if (wallet_height < chain_height) {
            // Incremental rescan: scan only blocks since wallet's last sync
            std::cout << "  Rescanning blocks " << (wallet_height + 1) << " to " << chain_height
                      << " (incremental)..." << std::endl;
            std::cout.flush();
            if (wallet.RescanFromHeight(g_chainstate, blockchain, wallet_height + 1, chain_height)) {
                unsigned int height = static_cast<unsigned int>(chain_height);
                // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
                int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
                int64_t total = mature + immature;
                std::cout << "  [OK] Incremental scan complete" << std::endl;
                std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
                std::cout << "       Total: " << std::fixed << std::setprecision(8)
                          << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
                std::cout.flush();
            } else {
                std::cerr << "  WARNING: Rescan failed" << std::endl;
            }
        } else {
            // wallet_height == chain_height: Already synced, no scan needed
            unsigned int height = static_cast<unsigned int>(chain_height);
            // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
            int64_t mature = wallet.GetAvailableBalance(utxo_set, height);
            int64_t immature = wallet.GetImmatureBalance(utxo_set, height);
            int64_t total = mature + immature;
            std::cout << "  [OK] Wallet already synced to chain tip" << std::endl;
            std::cout << "       Mature (spendable): " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(mature) / 100000000.0) << " DIL" << std::endl;
            std::cout << "       Immature (coinbase): " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(immature) / 100000000.0) << " DIL" << std::endl;
            std::cout << "       Total: " << std::fixed << std::setprecision(8)
                      << (static_cast<double>(total) / 100000000.0) << " DIL" << std::endl;
            std::cout.flush();
        }

        // Save wallet if newly created
        if (!wallet_loaded) {
            if (wallet.Save(wallet_path)) {
                std::cout << "  [OK] New wallet saved" << std::endl;
            } else {
                std::cerr << "  WARNING: Failed to save new wallet" << std::endl;
            }
        }

        // MAINNET FIX: If mining enabled with encrypted wallet, unlock NOW before threads start
        // Must happen BEFORE CConnman starts to avoid log spam during password entry
        if (config.start_mining && wallet.IsCrypted() && wallet.IsLocked()) {
            std::cout << std::endl;
            std::cout << "========================================================================" << std::endl;
            std::cout << "========================================================================" << std::endl;
            std::cout << std::endl;
            std::cout << "+----------------------------------------------------------------------+" << std::endl;
            std::cout << "| WALLET UNLOCK REQUIRED                                               |" << std::endl;
            std::cout << "+----------------------------------------------------------------------+" << std::endl;
            std::cout << std::endl;
            std::cout << "  Your wallet is encrypted. Mining requires wallet access to sign" << std::endl;
            std::cout << "  blocks with your Mining Identity Key (MIK)." << std::endl;
            std::cout << std::endl;
            std::cout << "  NOTE: Password will be visible as you type." << std::endl;
            std::cout << std::endl;

            // Try up to 3 times
            bool unlocked = false;
            for (int attempt = 1; attempt <= 3 && !unlocked; ++attempt) {
                std::cout << "  >>> Enter wallet password (attempt " << attempt << "/3): ";
                std::cout.flush();

                std::string password;
                std::getline(std::cin, password);

                // Trim whitespace
                size_t start = password.find_first_not_of(" \t\r\n");
                size_t end = password.find_last_not_of(" \t\r\n");
                if (start != std::string::npos && end != std::string::npos) {
                    password = password.substr(start, end - start + 1);
                } else {
                    password.clear();
                }

                if (password.empty()) {
                    std::cout << "  Password cannot be empty." << std::endl;
                    continue;
                }

                // Try to unlock (0 timeout = unlock until node stops)
                if (wallet.Unlock(password, 0)) {
                    unlocked = true;
                    std::cout << "  [OK] Wallet unlocked for mining session" << std::endl;
                    std::cout << std::endl;
                } else {
                    std::cout << "  Incorrect password." << std::endl;
                }
            }

            if (!unlocked) {
                std::cerr << std::endl;
                std::cerr << "  ERROR: Failed to unlock wallet after 3 attempts." << std::endl;
                std::cerr << "  Mining requires wallet access for MIK signing." << std::endl;
                std::cerr << "  Options:" << std::endl;
                std::cerr << "    1. Restart node and enter correct password" << std::endl;
                std::cerr << "    2. Unlock via RPC: walletpassphrase <password> <timeout>" << std::endl;
                std::cerr << "    3. Run without --mine flag and unlock later" << std::endl;
                std::cerr << std::endl;
                std::cerr << "  Continuing without mining..." << std::endl;
                config.start_mining = false;
                g_node_state.mining_enabled = false;
            }
        }

        }  // end else (!relay_only)

        // =========================================================================
        // DFMP v2.0: Register block connect/disconnect callbacks for fair mining protocol
        // CRITICAL: Must run for ALL modes (including relay-only) because:
        //   1. Relay-only nodes still validate blocks
        //   2. Block validation requires MIK identity lookup
        //   3. Identity DB must be populated during ConnectTip
        // Previously this was inside the wallet block, causing relay-only nodes to fail
        // MIK validation after checkpoint (Bug #251)
        // =========================================================================
        g_chainstate.RegisterBlockConnectCallback([](const CBlock& block, int height, const uint256& hash) {
            // Get DFMP activation height from chain params
            int activationHeight = Dilithion::g_chainParams ? Dilithion::g_chainParams->dfmpActivationHeight : 0;

            // Only process blocks after DFMP activation
            if (height >= activationHeight && !block.vtx.empty()) {
                // Deserialize block transactions to get coinbase
                CBlockValidator validator;
                std::vector<CTransactionRef> transactions;
                std::string error;

                if (validator.DeserializeBlockTransactions(block, transactions, error) && !transactions.empty()) {
                    // DFMP v2.0: Parse MIK from coinbase scriptSig
                    const CTransaction& coinbaseTx = *transactions[0];
                    const std::vector<uint8_t>& scriptSig = coinbaseTx.vin[0].scriptSig;

                    DFMP::CMIKScriptData mikData;
                    if (DFMP::ParseMIKFromScriptSig(scriptSig, mikData) && !mikData.identity.IsNull()) {
                        DFMP::Identity identity = mikData.identity;

                        // Record first-seen height if this is a new identity
                        if (DFMP::g_identityDb && !DFMP::g_identityDb->Exists(identity)) {
                            DFMP::g_identityDb->SetFirstSeen(identity, height);
                        }

                        // Store MIK public key on registration (first block with this MIK)
                        if (mikData.isRegistration && DFMP::g_identityDb) {
                            if (!DFMP::g_identityDb->HasMIKPubKey(identity)) {
                                DFMP::g_identityDb->SetMIKPubKey(identity, mikData.pubkey);
                            }
                            // Phase 1.5: warm the in-memory pubkey cache from the
                            // canonical block-connect path so signed-DNA verifies don't
                            // pay a LevelDB read on first use. Cache is internally
                            // idempotent on duplicate inserts.
                            if (g_node_context.mik_pubkey_cache) {
                                std::array<uint8_t, 20> mikArr{};
                                std::memcpy(mikArr.data(), identity.data, 20);
                                g_node_context.mik_pubkey_cache->Insert(mikArr, mikData.pubkey);
                            }
                        }

                        // Update heat tracker
                        if (DFMP::g_heatTracker) {
                            DFMP::g_heatTracker->OnBlockConnected(height, identity);
                        }

                        // DFMP v3.0: Track payout address heat
                        if (DFMP::g_payoutHeatTracker && !coinbaseTx.vout.empty()) {
                            DFMP::Identity payoutId = DFMP::DeriveIdentityFromScript(
                                coinbaseTx.vout[0].scriptPubKey);
                            DFMP::g_payoutHeatTracker->OnBlockConnected(height, payoutId);
                        }

                        // DFMP v3.0: Track last-mined height for dormancy
                        if (DFMP::g_identityDb) {
                            DFMP::g_identityDb->SetLastMined(mikData.identity, height);
                        }
                    }
                }
            }
        });

        g_chainstate.RegisterBlockDisconnectCallback([](const CBlock& block, int height, const uint256& hash) {
            // Update heat tracker on disconnect (reorg)
            // Note: Identity DB removal happens in chain.cpp DisconnectTip (first-seen gated)
            if (DFMP::g_heatTracker) {
                DFMP::g_heatTracker->OnBlockDisconnected(height);
            }

            // DFMP v3.0: Disconnect payout address heat
            if (DFMP::g_payoutHeatTracker) {
                DFMP::g_payoutHeatTracker->OnBlockDisconnected(height);
            }
        });
        std::cout << "  [OK] DFMP chain notification callbacks registered" << std::endl;

        // =========================================================================
        // Session accepted-blocks counter: mirror the canonical chain.
        //
        // Increment when a block connects whose coinbase MIK == ours.
        // Decrement when a block with our MIK disconnects (reorg).
        // Resets on process start — the wallet's tx history is the source of
        // truth for lifetime.
        // =========================================================================
        g_chainstate.RegisterBlockConnectCallback([&wallet](const CBlock& block, int /*height*/, const uint256& /*hash*/) {
            if (!g_node_state.rpc_server) return;
            DFMP::Identity ourMik = wallet.GetMIKIdentity();
            if (ourMik.IsNull()) return;
            std::array<uint8_t, 20> blockMik{};
            if (!ExtractCoinbaseMIKIdentity(block, blockMik)) return;
            if (std::memcmp(blockMik.data(), ourMik.data, 20) == 0) {
                g_node_state.rpc_server->IncrementAcceptedSession();
            }
        });
        g_chainstate.RegisterBlockDisconnectCallback([&wallet](const CBlock& block, int /*height*/, const uint256& /*hash*/) {
            if (!g_node_state.rpc_server) return;
            DFMP::Identity ourMik = wallet.GetMIKIdentity();
            if (ourMik.IsNull()) return;
            std::array<uint8_t, 20> blockMik{};
            if (!ExtractCoinbaseMIKIdentity(block, blockMik)) return;
            if (std::memcmp(blockMik.data(), ourMik.data, 20) == 0) {
                g_node_state.rpc_server->DecrementAcceptedSession();
            }
        });
        std::cout << "  [OK] Session accepted-blocks callbacks registered" << std::endl;

        // =========================================================================
        // VDF: Register block connect/disconnect callbacks for cooldown tracker.
        //
        // Fires for ALL blocks (self-mined and peer-received) via ConnectTip/
        // DisconnectTip in chain.cpp.  Only VDF blocks are processed.
        // Must run for ALL modes (including relay-only) so that the cooldown
        // tracker state is accurate on every node.
        // =========================================================================
        g_chainstate.RegisterBlockConnectCallback([](const CBlock& block, int height, const uint256& hash) {
            if (!block.IsVDFBlock()) return;
            if (g_node_context.cooldown_tracker) {
                std::array<uint8_t, 20> mikId{};
                if (ExtractCoinbaseMIKIdentity(block, mikId)) {
                    g_node_context.cooldown_tracker->OnBlockConnected(height, mikId);
                }
            }
        });

        g_chainstate.RegisterBlockDisconnectCallback([](const CBlock& block, int height, const uint256& hash) {
            if (!block.IsVDFBlock()) return;
            if (g_node_context.cooldown_tracker) {
                g_node_context.cooldown_tracker->OnBlockDisconnected(height);
            }
        });
        std::cout << "  [OK] VDF cooldown chain notification callbacks registered" << std::endl;

        // =========================================================================
        // v4.0.17: Deferred BLOCK CONFIRMED / BLOCK ORPHANED notifications.
        //
        // The previous "BLOCK CONFIRMED!" message fired at submit time when our
        // mined block became the chain tip. While DIL (RandomX) is far less
        // reorg-prone than DilV, brief same-height races still occur. The
        // user-experience contract is "if we say CONFIRMED, the block is settled".
        // We queue the win at submit time and only print CONFIRMED once a child
        // block has been connected on top. If the pending block is no longer
        // ancestor of the new tip at its height (a reorg displaced it), we fire
        // BLOCK ORPHANED instead.
        // =========================================================================
        g_chainstate.RegisterBlockConnectCallback([](const CBlock& /*block*/, int height, const uint256& /*hash*/) {
            std::lock_guard<std::mutex> lock(g_pendingMinerWinsMutex);
            auto it = g_pendingMinerWins.begin();
            while (it != g_pendingMinerWins.end()) {
                if (it->height >= height) { ++it; continue; }  // not yet settled

                CBlockIndex* tip    = g_chainstate.GetTip();
                CBlockIndex* ourIdx = g_chainstate.GetBlockIndex(it->blockHash);
                bool isCanonical = false;
                if (ourIdx && tip) {
                    CBlockIndex* ancestor = tip->GetAncestor(it->height);
                    isCanonical = (ancestor == ourIdx);
                }

                if (isCanonical) {
                    std::cout << std::endl
                              << "======================================" << std::endl
                              << "  BLOCK CONFIRMED!" << std::endl
                              << "  Height: " << it->height << std::endl
                              << "======================================" << std::endl;
                } else {
                    std::cout << std::endl
                              << "======================================" << std::endl
                              << "  BLOCK NOT SELECTED" << std::endl
                              << "  Another miner's block won at height "
                              << it->height << "." << std::endl
                              << "  This is normal - better luck next block!" << std::endl
                              << "======================================" << std::endl;
                }
                it = g_pendingMinerWins.erase(it);
            }
        });
        std::cout << "  [OK] Deferred mining-outcome callback registered" << std::endl;

        // Digital DNA: Behavioral profile + trust scoring block hook
        g_chainstate.RegisterBlockConnectCallback([](const CBlock& block, int height, const uint256& hash) {
            int dnaAct = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->digitalDnaActivationHeight : 999999999;
            if (height < dnaAct) return;

            // Behavioral profile hook
            auto collector = g_node_context.GetDNACollector();
            if (collector) {
                collector->on_block_received(static_cast<uint32_t>(height));
            }

            // Trust scoring: heartbeat for registered miners
            if (g_node_context.trust_manager && g_node_context.dna_registry) {
                std::array<uint8_t, 20> minerAddr{};
                if (ExtractCoinbaseAddress(block, minerAddr) &&
                    g_node_context.dna_registry->is_registered(minerAddr)) {
                    g_node_context.trust_manager->on_heartbeat_success(
                        minerAddr, static_cast<uint32_t>(height));
                }

                // Block relay credit for our own registered identity
                if (collector) {
                    auto my_dna = collector->get_dna();
                    if (my_dna && g_node_context.dna_registry->is_registered(my_dna->address)) {
                        g_node_context.trust_manager->on_block_relayed(
                            my_dna->address, static_cast<uint32_t>(height));
                    }
                }
            }

            // Phase 2: Trigger DNA verification for new registrations
            // When a miner's DNA is first registered, selected verifiers initiate challenges
            if (g_node_context.verification_manager && g_node_context.dna_registry) {
                // Check if this block contains a new DNA registration
                // (Look for MIK in coinbase that just registered in trust scoring above)
                std::array<uint8_t, 20> minerMik{};
                CBlockValidator validator_v;
                std::vector<CTransactionRef> txs_v;
                std::string err_v;
                if (validator_v.DeserializeBlockTransactions(block, txs_v, err_v) && !txs_v.empty()) {
                    DFMP::CMIKScriptData mikData_v;
                    if (DFMP::ParseMIKFromScriptSig(txs_v[0]->vin[0].scriptSig, mikData_v)) {
                        if (mikData_v.isRegistration) {
                            // New MIK registration — trigger verification
                            std::copy(mikData_v.identity.data,
                                      mikData_v.identity.data + 20, minerMik.begin());
                            std::array<uint8_t, 32> blockHash{};
                            std::copy(hash.begin(), hash.begin() + 32, blockHash.begin());
                            g_node_context.verification_manager->OnNewRegistration(
                                minerMik, static_cast<uint32_t>(height), blockHash);
                        }
                    }
                }
            }

            // DNA commitment soft integrity check (VDF blocks post-activation)
            int dnaCommitAct = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->dnaCommitmentActivationHeight : 999999999;
            if (height >= dnaCommitAct && block.IsVDFBlock() && g_node_context.dna_registry) {
                CBlockValidator validator;
                std::vector<CTransactionRef> txs;
                std::string err;
                if (validator.DeserializeBlockTransactions(block, txs, err) && !txs.empty()) {
                    DFMP::CMIKScriptData mikData;
                    if (DFMP::ParseMIKFromScriptSig(txs[0]->vin[0].scriptSig, mikData)) {
                        if (mikData.has_dna_hash) {
                            std::array<uint8_t, 20> mikArr{};
                            std::copy(mikData.identity.data, mikData.identity.data + 20, mikArr.begin());
                            auto existing = g_node_context.dna_registry->get_identity_by_mik(mikArr);
                            if (existing) {
                                auto localHash = existing->hash();
                                if (localHash != mikData.dna_hash) {
                                    std::cout << "[DNA] Block " << height
                                              << ": DNA commitment mismatch for MIK (soft check, not rejected)"
                                              << std::endl;
                                }
                            }
                        }
                    }
                }
            }
        });

        // NOW start CConnman (after all interactive wallet prompts are complete)
        // This runs for BOTH normal mode and relay-only mode
        // CRITICAL: Must be after wallet init to prevent network log spam during interactive prompts
        if (!g_node_context.connman->Start(*g_node_context.peer_manager, message_processor, connman_opts)) {
            std::cerr << "Failed to start CConnman" << std::endl;
            return 1;
        }

        // Set external IP if we have one (for advertising to peers)
        if (!effectiveExternalIP.empty()) {
            g_node_context.connman->SetExternalIP(effectiveExternalIP);
        }

        std::cout << "  [OK] P2P networking started" << std::endl;

        // BUG #275: Start resource monitor to prevent OOM crashes
        CResourceMonitor resource_monitor;
        size_t mem_limit = resource_monitor.AutoDetectMemoryLimit(0.85);
        resource_monitor.SetCleanupCallback([](int level) {
            if (level >= 2) {
                if (g_node_context.orphan_manager) {
                    g_node_context.orphan_manager->Clear();
                }
                if (g_node_context.headers_manager) {
                    g_node_context.headers_manager->PruneOrphanedHeaders();
                    g_node_context.headers_manager->ClearRejectedHashes();
                }
            } else if (level == 1) {
                if (g_node_context.orphan_manager) {
                    g_node_context.orphan_manager->EraseExpiredOrphans();
                }
                if (g_node_context.headers_manager) {
                    g_node_context.headers_manager->PruneOrphanedHeaders();
                }
            }
        });
        resource_monitor.Start();
        g_resource_monitor = &resource_monitor;
        std::cout << "  [OK] Resource monitor started (" << (mem_limit / (1024 * 1024)) << "MB limit, 85% of system RAM)" << std::endl;

        // Set up block found callback to save mined blocks and credit wallet
        miner.SetBlockFoundCallback([&blockchain, &wallet, &utxo_set](const CBlock& block) {
            // CRITICAL: Check shutdown flag FIRST to prevent database corruption during shutdown
            if (!g_node_state.running) {
                // Shutting down - discard this block to prevent race condition
                return;
            }

            uint256 blockHash = block.GetHash();
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "  BLOCK SUBMITTED" << std::endl;
            std::cout << "  Waiting for network confirmation..." << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << "Block hash: " << blockHash.GetHex() << std::endl;
            std::cout << "Block time: " << block.nTime << std::endl;
            std::cout << "Nonce: " << block.nNonce << std::endl;
            // CID 1675194 FIX: Save and restore ostream format state to prevent affecting subsequent output
            std::ios_base::fmtflags oldFlags = std::cout.flags();
            std::cout << "Difficulty: 0x" << std::hex << block.nBits;
            std::cout.flags(oldFlags);  // Restore original format flags
            std::cout << std::endl;
            std::cout << "======================================" << std::endl;
            std::cout << std::endl;

            // BUG #84 FIX: Extract coinbase from actual block, not global
            // Race condition: g_currentCoinbase might be overwritten by template updates
            // before the block is found, causing hash mismatch between wallet and UTXO set
            CTransactionRef coinbase;
            {
                CBlockValidator validator;
                std::vector<CTransactionRef> transactions;
                std::string error;
                if (validator.DeserializeBlockTransactions(block, transactions, error) && !transactions.empty()) {
                    coinbase = transactions[0];  // Coinbase is always first transaction
                } else {
                    std::cerr << "[Wallet] ERROR: Failed to deserialize coinbase from block: " << error << std::endl;
                }
            }

            // BUG #95 FIX: Wallet crediting moved to AFTER chain tip decision below
            // Only credit when block actually becomes chain tip, not for orphaned/stale blocks

            // Save block to blockchain database
            if (!blockchain.WriteBlock(blockHash, block)) {
                std::cerr << "[Blockchain] ERROR: Failed to save block to database!" << std::endl;
                return;
            }
            std::cout << "[Blockchain] Block saved to database" << std::endl;

            // Create block index with proper chain linkage
            // HIGH-C001 FIX: Use smart pointer for automatic RAII cleanup
            auto pblockIndex = std::make_unique<CBlockIndex>(block);
            pblockIndex->phashBlock = blockHash;
            // v4.3.3 F14: canonical block-receipt flag-setter (F1 + F7 combined).
            pblockIndex->MarkBlockReceived();

            // Link to parent block
            pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (pblockIndex->pprev == nullptr) {
                std::cerr << "[Blockchain] ERROR: Cannot find parent block "
                          << block.hashPrevBlock.GetHex().substr(0, 16) << "..." << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

            // Calculate height and chain work
            pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
            pblockIndex->BuildChainWork();

            std::cout << "[Blockchain] Block index created (height " << pblockIndex->nHeight << ")" << std::endl;

            // Save block index to database
            if (!blockchain.WriteBlockIndex(blockHash, *pblockIndex)) {
                std::cerr << "[Blockchain] ERROR: Failed to save block index" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - smart pointer auto-destructs
                return;
            }

            // Add to chain state memory map (transfer ownership with std::move)
            if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                std::cerr << "[Blockchain] ERROR: Failed to add block to chain state" << std::endl;
                // HIGH-C001 FIX: No manual delete needed - ownership transferred
                return;
            }

            // HIGH-C001 FIX: After move, retrieve pointer from chain state
            CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
            if (pblockIndexPtr == nullptr) {
                std::cerr << "[Blockchain] CRITICAL ERROR: Block index not found after adding!" << std::endl;
                return;
            }

            // Activate best chain (handles reorg if needed)
            bool reorgOccurred = false;
            if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
                if (g_chainstate.GetTip() == pblockIndexPtr) {
                    // v4.0.17: our block became tip. Queue for deferred
                    // CONFIRMED message — only print after a child block has
                    // settled the round, in case a reorg displaces ours.
                    {
                        std::lock_guard<std::mutex> lock(g_pendingMinerWinsMutex);
                        g_pendingMinerWins.push_back({blockHash, pblockIndexPtr->nHeight});
                    }
                    (void)reorgOccurred;

                    // Session accepted-blocks counter is maintained via
                    // RegisterBlockConnectCallback below. Do NOT increment
                    // here or we'd double-count.

                    // BUG #95 FIX: Only credit wallet when block actually becomes chain tip
                    // This prevents crediting for orphaned/stale blocks on competing chains
                    if (coinbase && !coinbase->vout.empty()) {
                        const CTxOut& coinbaseOut = coinbase->vout[0];
                        std::vector<uint8_t> pubkey_hash = WalletCrypto::ExtractPubKeyHash(coinbaseOut.scriptPubKey);
                        std::vector<uint8_t> our_hash = wallet.GetPubKeyHash();

                        if (!pubkey_hash.empty() && pubkey_hash == our_hash) {
                            CDilithiumAddress our_address = wallet.GetNewAddress();
                            wallet.AddTxOut(coinbase->GetHash(), 0, coinbaseOut.nValue, our_address, pblockIndexPtr->nHeight, true);  // true = coinbase

                            double amountDIL = static_cast<double>(coinbaseOut.nValue) / 100000000.0;
                            std::cout << "[Wallet] Coinbase credited: " << std::fixed << std::setprecision(8)
                                      << amountDIL << " DIL (immature for 100 blocks)" << std::endl;

                            // Get current height for maturity calculation
                            unsigned int current_height = static_cast<unsigned int>(g_chainstate.GetHeight());

                            // BUG #114 FIX: Use GetAvailableBalance() for consistency with RPC
                            // Mature balance (spendable) - verified against UTXO set
                            int64_t mature_balance = wallet.GetAvailableBalance(utxo_set, current_height);
                            double matureDIL = static_cast<double>(mature_balance) / 100000000.0;

                            // Immature balance (coinbase not yet mature)
                            int64_t immature_balance = wallet.GetImmatureBalance(utxo_set, current_height);
                            double immatureDIL = static_cast<double>(immature_balance) / 100000000.0;

                            // Total balance
                            int64_t total_balance = mature_balance + immature_balance;
                            double totalDIL = static_cast<double>(total_balance) / 100000000.0;

                            std::cout << "[Wallet] Balance: " << std::fixed << std::setprecision(8)
                                      << matureDIL << " DIL (mature/spendable)" << std::endl;
                            std::cout << "[Wallet]          " << std::fixed << std::setprecision(8)
                                      << immatureDIL << " DIL (immature coinbase)" << std::endl;
                            std::cout << "[Wallet]          " << std::fixed << std::setprecision(8)
                                      << totalDIL << " DIL (total)" << std::endl;
                        }
                    }

                    // BUG #32 FIX: Immediately update mining template for locally mined blocks
                    // BUG #65 FIX: Skip IBD check for locally mined blocks - we KNOW we're at chain tip
                    // because we just mined this block ourselves. The IBD check fails when peers
                    // are connected but haven't completed handshake (version=0), which incorrectly
                    // prevents mining from resuming after finding a block.
                    bool immediate_update_succeeded = false;
                    if (g_node_state.miner && g_node_state.wallet && g_node_state.mining_enabled.load()) {
                        std::cout << "[Mining] Locally mined block became new tip - updating template immediately..." << std::endl;
                        auto templateOpt = BuildMiningTemplate(blockchain, *g_node_state.wallet, false, g_node_state.mining_address_override);
                        if (templateOpt) {
                            g_node_state.miner->UpdateTemplate(*templateOpt);
                            std::cout << "[Mining] Template updated to height " << templateOpt->nHeight << std::endl;
                            immediate_update_succeeded = true;
                        } else {
                            std::cerr << "[Mining] ERROR: Immediate template build failed" << std::endl;
                        }
                    }

                    // Broadcast block to network (P2P block relay) - Using async broadcaster
                    auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();

                    if (!connected_peers.empty()) {
                        // Collect peer IDs with completed handshakes
                        std::vector<int> peer_ids;
                        for (const auto& peer : connected_peers) {
                            if (peer && peer->IsHandshakeComplete()) {
                                peer_ids.push_back(peer->id);
                            }
                        }

                        if (!peer_ids.empty()) {
                            // Phase 4: Sort relay peers by trust score (highest first)
                            if (g_node_context.GetPeerTrustScore) {
                                int chainHeight = g_chainstate.GetHeight();
                                bool trustActive = Dilithion::g_chainParams &&
                                    chainHeight >= Dilithion::g_chainParams->trustWeightedNetworkHeight;
                                if (trustActive) {
                                    std::sort(peer_ids.begin(), peer_ids.end(),
                                        [](int a, int b) {
                                            double ta = g_node_context.GetPeerTrustScore(a);
                                            double tb = g_node_context.GetPeerTrustScore(b);
                                            // Unknown (-1) treated as neutral (50.0)
                                            if (ta < 0) ta = 50.0;
                                            if (tb < 0) tb = 50.0;
                                            return ta > tb;  // Higher trust first
                                        });
                                }
                            }

                            // DEBUG: Log which peers we're broadcasting to
                            if (g_verbose.load(std::memory_order_relaxed)) {
                                std::cout << "[P2P-DEBUG] Broadcasting block to peers: ";
                                for (int id : peer_ids) {
                                    auto peer = g_node_context.peer_manager->GetPeer(id);
                                    std::cout << id;
                                    if (peer) {
                                        std::cout << "(" << peer->addr.ToStringIP() << ")";
                                    }
                                    std::cout << " ";
                                }
                                std::cout << std::endl;
                            }

                            // Queue block broadcast asynchronously (non-blocking!)
                            // BIP 130: Pass header to enable HEADERS vs INV routing by peer preference
                            if (g_node_context.async_broadcaster->BroadcastBlock(blockHash, block, peer_ids)) {
                                std::cout << "[P2P] Queued block broadcast to " << peer_ids.size()
                                          << " peer(s) (async)" << std::endl;
                            } else {
                                std::cerr << "[P2P] ERROR: Failed to queue block broadcast" << std::endl;
                            }
                        } else {
                            std::cout << "[P2P] WARNING: No peers with completed handshakes" << std::endl;
                        }
                    } else {
                        std::cout << "[P2P] WARNING: No connected peers to broadcast block" << std::endl;
                    }

                    // Check if VDF mining should activate for next height.
                    // The immediate update path only updates the RandomX template,
                    // so we must force the main loop handler to run for VDF switching.
                    unsigned int next_h = pblockIndexPtr->nHeight + 1;
                    int vdf_act = Dilithion::g_chainParams ?
                        Dilithion::g_chainParams->vdfActivationHeight : 999999999;
                    if (static_cast<int>(next_h) >= vdf_act) {
                        std::cout << "[Mining] VDF activation height reached (next=" << next_h
                                  << ", activation=" << vdf_act << ") - signaling main loop" << std::endl;
                        g_node_state.new_block_found = true;
                    } else if (!immediate_update_succeeded) {
                        // BUG #65 FIX: Only signal main loop if immediate update failed
                        g_node_state.new_block_found = true;
                    }
                } else {
                    // v4.0.17: print BLOCK NOT SELECTED immediately. We KNOW
                    // we lost right now (block is valid but did not become
                    // tip), so deferring would just hide the outcome behind
                    // the next round's BLOCK CANDIDATE PRODUCED message. Height
                    // label distinguishes from any concurrently-firing deferred
                    // notification for an earlier round.
                    std::cout << std::endl
                              << "======================================" << std::endl
                              << "  BLOCK NOT SELECTED" << std::endl
                              << "  Another miner's block won at height "
                              << pblockIndexPtr->nHeight << "." << std::endl
                              << "  This is normal - better luck next block!" << std::endl
                              << "======================================" << std::endl;
                    g_node_state.new_block_found = true;
                }
            } else {
                std::cerr << "[Blockchain] ERROR: Failed to activate mined block in chain" << std::endl;
            }
        });

        // Set up VDF miner callbacks (same block found handler, plus template provider)
        vdf_miner.SetBlockFoundCallback([&blockchain, &wallet, &utxo_set](const CBlock& block) {
            // Reuse the same block processing logic as RandomX miner.
            // The block found callback above (for RandomX) handles saving, chain activation,
            // wallet crediting, etc. We replicate the reference to the same callback.
            if (!g_node_state.running) return;

            uint256 blockHash = block.GetHash();
            std::cout << "[VDF] Processing mined VDF block: " << blockHash.GetHex().substr(0, 16) << "..." << std::endl;

            // Save block
            if (!blockchain.WriteBlock(blockHash, block)) {
                std::cerr << "[VDF] ERROR: Failed to save block" << std::endl;
                return;
            }

            // Create block index
            auto pblockIndex = std::make_unique<CBlockIndex>(block);
            pblockIndex->phashBlock = blockHash;
            // v4.3.3 F14: canonical block-receipt flag-setter for the DIL
            // local-mining path (F1 + F7 combined).
            pblockIndex->MarkBlockReceived();
            pblockIndex->pprev = g_chainstate.GetBlockIndex(block.hashPrevBlock);
            if (!pblockIndex->pprev) {
                std::cerr << "[VDF] ERROR: Cannot find parent block" << std::endl;
                return;
            }
            pblockIndex->nHeight = pblockIndex->pprev->nHeight + 1;
            pblockIndex->BuildChainWork();

            if (!blockchain.WriteBlockIndex(blockHash, *pblockIndex)) {
                std::cerr << "[VDF] ERROR: Failed to save block index" << std::endl;
                return;
            }

            if (!g_chainstate.AddBlockIndex(blockHash, std::move(pblockIndex))) {
                std::cerr << "[VDF] ERROR: Failed to add block to chain state" << std::endl;
                return;
            }

            CBlockIndex* pblockIndexPtr = g_chainstate.GetBlockIndex(blockHash);
            if (!pblockIndexPtr) return;

            bool reorgOccurred = false;
            if (g_chainstate.ActivateBestChain(pblockIndexPtr, block, reorgOccurred)) {
                if (g_chainstate.GetTip() == pblockIndexPtr) {
                    // v4.0.17: defer the BLOCK CONFIRMED message — queue and
                    // let the deferred-outcome callback print once the round
                    // is settled (see callback registration ~line 5350).
                    {
                        std::lock_guard<std::mutex> lock(g_pendingMinerWinsMutex);
                        g_pendingMinerWins.push_back({blockHash, pblockIndexPtr->nHeight});
                    }
                    std::cout << "[VDF] Block submitted at height "
                              << pblockIndexPtr->nHeight
                              << " - awaiting settlement..." << std::endl;

                    // Session accepted-blocks counter maintained via
                    // RegisterBlockConnectCallback (don't double-count here).

                    // NOTE: Cooldown tracker is now updated via chainstate
                    // RegisterBlockConnectCallback (fires for ALL blocks including
                    // self-mined).  Do NOT call OnBlockConnected here — it would
                    // double-count this block since ConnectTip already fired the
                    // callback above.

                    // BUG FIX: Broadcast VDF block to peers
                    // (Previously missing - VDF blocks were saved locally but never sent to network)
                    if (g_node_context.peer_manager && g_node_context.async_broadcaster) {
                        auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();
                        if (!connected_peers.empty()) {
                            std::vector<int> peer_ids;
                            for (const auto& peer : connected_peers) {
                                if (peer && peer->IsHandshakeComplete()) {
                                    peer_ids.push_back(peer->id);
                                }
                            }
                            // Phase 4: Sort relay peers by trust score (highest first)
                            if (!peer_ids.empty() && g_node_context.GetPeerTrustScore) {
                                int chainHeight = g_chainstate.GetHeight();
                                bool trustActive = Dilithion::g_chainParams &&
                                    chainHeight >= Dilithion::g_chainParams->trustWeightedNetworkHeight;
                                if (trustActive) {
                                    std::sort(peer_ids.begin(), peer_ids.end(),
                                        [](int a, int b) {
                                            double ta = g_node_context.GetPeerTrustScore(a);
                                            double tb = g_node_context.GetPeerTrustScore(b);
                                            // Unknown (-1) treated as neutral (50.0)
                                            if (ta < 0) ta = 50.0;
                                            if (tb < 0) tb = 50.0;
                                            return ta > tb;  // Higher trust first
                                        });
                                }
                            }

                            if (!peer_ids.empty()) {
                                if (g_node_context.async_broadcaster->BroadcastBlock(blockHash, block, peer_ids)) {
                                    std::cout << "[VDF] Queued block broadcast to " << peer_ids.size()
                                              << " peer(s) (async)" << std::endl;
                                } else {
                                    std::cerr << "[VDF] ERROR: Failed to queue block broadcast" << std::endl;
                                }
                            } else {
                                std::cout << "[VDF] WARNING: No peers with completed handshakes" << std::endl;
                            }
                        } else {
                            std::cout << "[VDF] WARNING: No connected peers to broadcast block" << std::endl;
                        }
                    }

                    // Credit wallet
                    CBlockValidator validator;
                    std::vector<CTransactionRef> transactions;
                    std::string error;
                    if (validator.DeserializeBlockTransactions(block, transactions, error) && !transactions.empty()) {
                        auto& coinbase = transactions[0];
                        if (!coinbase->vout.empty()) {
                            std::vector<uint8_t> pubkey_hash = WalletCrypto::ExtractPubKeyHash(coinbase->vout[0].scriptPubKey);
                            std::vector<uint8_t> our_hash = wallet.GetPubKeyHash();
                            if (!pubkey_hash.empty() && pubkey_hash == our_hash) {
                                CDilithiumAddress our_address = wallet.GetNewAddress();
                                wallet.AddTxOut(coinbase->GetHash(), 0, coinbase->vout[0].nValue,
                                               our_address, pblockIndexPtr->nHeight, true);
                            }
                        }
                    }
                }
                g_node_state.new_block_found = true;
            }
        });

        vdf_miner.SetTemplateProvider([&blockchain, &wallet]() -> std::optional<CBlockTemplate> {
            return BuildMiningTemplate(blockchain, wallet, false, g_node_state.mining_address_override);
        });

        // VDF Distribution: Provide current tip's VDF output for pre-submission comparison.
        // GetTip() acquires cs_main internally, so this is thread-safe.
        vdf_miner.SetTipOutputProvider([]() -> std::pair<int, uint256> {
            auto* tip = g_chainstate.GetTip();
            if (!tip) return {-1, uint256()};
            return {tip->nHeight, tip->header.vdfOutput};
        });

        // Phase 2.5: Start P2P networking server
        std::cerr.flush();
        std::cout << "[4/6] Starting P2P networking server..." << std::flush;

        // Set running flag before starting threads
        g_node_state.running = true;
        std::cerr.flush();

        // Initialize socket layer (required for Windows)
        std::cerr.flush();
        CSocketInit socket_init;
        std::cerr.flush();

        // Phase 5: CConnman handles socket binding and listening internally
        // The old CSocket p2p_socket code is removed - CConnman already bound to port in NodeContext init
        // g_node_state.p2p_socket is no longer used - kept as nullptr for backward compatibility

        std::cout << " ✓" << std::endl;
        std::cout << "  [OK] P2P server listening on port " << config.p2pport << " (CConnman)" << std::endl;

        // Phase 5: CConnman handles accept internally via ThreadSocketHandler
        // No need for separate p2p_thread - accept is handled in CConnman::SocketHandler()
        std::cout << "  [OK] P2P accept handled by CConnman::ThreadSocketHandler" << std::endl;

        // Helper to parse address string (IPv4, IPv6, or hostname) with port
        auto parseAddress = [](const std::string& node_addr, NetProtocol::CAddress& addr) -> bool {
            std::string ip;
            uint16_t port;
            if (!CSock::ParseEndpoint(node_addr, ip, port)) return false;
            if (port < Consensus::MIN_PORT || port > static_cast<uint16_t>(Consensus::MAX_PORT)) return false;
            if (ip == "localhost") ip = "127.0.0.1";
            if (!addr.SetFromString(ip)) return false;
            addr.port = port;
            addr.services = NetProtocol::NODE_NETWORK;
            addr.time = static_cast<uint32_t>(std::time(nullptr) & 0xFFFFFFFF);
            return true;
        };

        // Initiate outbound connections for --connect nodes (manual=true for auto-reconnect)
        if (!config.connect_nodes.empty()) {
            std::cout << "Initiating outbound connections..." << std::endl;
            for (const auto& node_addr : config.connect_nodes) {
                std::cout << "  Connecting to " << node_addr << "..." << std::endl;

                NetProtocol::CAddress addr;
                if (!parseAddress(node_addr, addr)) {
                    std::cerr << "    [FAIL] Invalid address: " << node_addr
                              << " (expected ip:port or [ipv6]:port)" << std::endl;
                    continue;
                }

                // Register for auto-reconnect (Bitcoin Core manual connection pattern)
                g_node_context.connman->AddManualNode(addr);

                // Phase 5: Use CConnman to connect (manual=true for eviction protection)
                int peer_id = ConnectAndHandshake(addr, true);
                if (peer_id >= 0) {
                    std::cout << "    [OK] Initiated connection to " << node_addr << " (peer_id=" << peer_id << ", manual)" << std::endl;
                    std::cout << "    [INFO] VERSION will be sent after connection completes" << std::endl;
                } else {
                    std::cout << "    [FAIL] Failed to connect to " << node_addr << " (will auto-reconnect)" << std::endl;
                }
            }
        }

        // Add additional nodes (non-exclusive, manual=true for auto-reconnect)
        if (!config.add_nodes.empty()) {
            std::cout << "Adding additional peer nodes..." << std::endl;
            for (const auto& node_addr : config.add_nodes) {
                std::cout << "  Adding node " << node_addr << "..." << std::endl;

                NetProtocol::CAddress addr;
                if (!parseAddress(node_addr, addr)) {
                    std::cerr << "    [FAIL] Invalid address: " << node_addr
                              << " (expected ip:port or [ipv6]:port)" << std::endl;
                    continue;
                }

                // Register for auto-reconnect (Bitcoin Core manual connection pattern)
                g_node_context.connman->AddManualNode(addr);

                // Phase 5: Use CConnman to initiate connection (manual=true)
                int peer_id = ConnectAndHandshake(addr, true);
                if (peer_id >= 0) {
                    std::cout << "    [OK] Added node " << node_addr << " (peer_id=" << peer_id << ", manual)" << std::endl;
                    std::cout << "    [INFO] VERSION will be sent after connection completes" << std::endl;
                } else {
                    std::cout << "    [FAIL] Failed to add node " << node_addr << " (will auto-reconnect)" << std::endl;
                }
            }
        }

        // Seed node connections are handled by CConnman::ThreadOpenConnections (Phase 1).
        // Removed manual seed connection code that raced with ThreadOpenConnections,
        // causing duplicate connections to each seed node.
        if (config.connect_nodes.empty()) {
            std::cout << "Seed node connections will be established by CConnman..." << std::endl;
        }

        // Phase 5: CConnman handles message receiving internally via ThreadSocketHandler and ThreadMessageHandler
        // No need for separate p2p_recv_thread
        std::cout << "  [OK] P2P receive handled by CConnman::ThreadSocketHandler and ThreadMessageHandler" << std::endl;

        // Launch P2P maintenance thread (ping/pong keepalive, reconnection, score decay)
        // BUG #49 FIX: Add automatic peer reconnection and misbehavior score decay
        // BUG #85 FIX: Add exception handling to prevent std::terminate
        // BUG #88: Windows startup crash fix - wrap thread creation in try/catch
        // Phase 5: Updated to use CConnman instead of CConnectionManager
        std::cerr.flush();
        std::thread p2p_maint_thread;
        try {
            p2p_maint_thread = std::thread([&feeler_manager]() {
            // Phase 1.1: Wrap thread entry point in try/catch to prevent silent crashes
            try {
                std::cout << "  [OK] P2P maintenance thread started" << std::endl;

                while (g_node_state.running) {
                    try {
                    // Seed reconnection is handled entirely by CConnman::ThreadOpenConnections()
                    // which runs every 60 seconds in a dedicated thread. Do NOT duplicate
                    // that logic here — it caused a TOCTOU race creating 2 outbound connections
                    // per seed, exhausting the per-IP inbound limit and blocking new nodes.

                    // BUG #49: Decay misbehavior scores (reduce by 1 point per minute)
                    // This happens every 30 seconds, so decay by 0.5 points
                    if (g_node_context.peer_manager) {
                        g_node_context.peer_manager->DecayMisbehaviorScores();
                        // Periodic maintenance: evict peers if needed, save peers
                        g_node_context.peer_manager->PeriodicMaintenance();
                    }

                    // Periodic transaction rebroadcast (every 60 seconds)
                    // Only rebroadcast txs older than 2 minutes (already had a chance to propagate).
                    // BATCHED: Send up to 8 txs per cycle as a single INV message per peer
                    // to stay well under the INV rate limit (10 messages/sec) on the receiving side.
                    {
                        static auto last_tx_rebroadcast = std::chrono::steady_clock::now();
                        auto now = std::chrono::steady_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_tx_rebroadcast).count();
                        if (elapsed >= 60) {
                            last_tx_rebroadcast = now;
                            auto* mempool = g_mempool.load();
                            if (mempool && g_node_context.peer_manager && g_node_context.connman && g_node_context.message_processor) {
                                auto txs = mempool->GetUnconfirmedOlderThan(120);
                                if (!txs.empty()) {
                                    const size_t MAX_REBROADCAST = 8;
                                    std::vector<NetProtocol::CInv> inv_vec;
                                    size_t count = 0;
                                    for (const auto& tx : txs) {
                                        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, tx->GetHash()));
                                        if (auto coll = g_node_context.GetDNACollector()) {
                                            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::system_clock::now().time_since_epoch()).count();
                                            coll->on_tx_relayed(static_cast<uint64_t>(now_ms));
                                        }
                                        if (++count >= MAX_REBROADCAST) break;
                                    }
                                    // Send single batched INV to all peers
                                    if (!inv_vec.empty()) {
                                        CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
                                        auto peers = g_node_context.peer_manager->GetConnectedPeers();
                                        for (const auto& peer : peers) {
                                            if (peer->IsHandshakeComplete() && peer->relay) {
                                                g_node_context.connman->PushMessage(peer->id, inv_msg);
                                            }
                                        }
                                    }
                                    std::cout << "[TX-RELAY] Rebroadcast " << count
                                              << " unconfirmed mempool transaction(s)" << std::endl;
                                }
                            }
                        }
                    }

                    // Digital DNA: Progressive registration (every ~60s)
                    {
                        static auto last_dna_check = std::chrono::steady_clock::now();
                        auto now_dna = std::chrono::steady_clock::now();
                        auto dna_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            now_dna - last_dna_check).count();
                        auto dna_coll = g_node_context.GetDNACollector();
                        if (dna_elapsed >= 60 && dna_coll &&
                            g_node_context.dna_registry) {
                            int dnaAct = Dilithion::g_chainParams ?
                                Dilithion::g_chainParams->digitalDnaActivationHeight : 999999999;
                            int curHeight = g_chainstate.GetHeight();
                            if (curHeight >= dnaAct) {
                                last_dna_check = now_dna;
                                auto dna_opt = dna_coll->get_dna();
                                if (dna_opt) {
                                    dna_opt->registration_height = static_cast<uint32_t>(curHeight);
                                    if (!g_node_context.dna_registry->is_registered(dna_opt->address)) {
                                        auto res = g_node_context.dna_registry->register_identity(*dna_opt);
                                        if (res == digital_dna::IDNARegistry::RegisterResult::SUCCESS ||
                                            res == digital_dna::IDNARegistry::RegisterResult::SYBIL_FLAGGED) {
                                            int dims = 3 + (dna_opt->memory ? 1 : 0) +
                                                (dna_opt->clock_drift ? 1 : 0) +
                                                (dna_opt->bandwidth ? 1 : 0) +
                                                (dna_opt->thermal ? 1 : 0) +
                                                (dna_opt->behavioral ? 1 : 0);
                                            std::cout << "[DNA] Registered identity at height "
                                                      << curHeight << " (dims: " << dims
                                                      << ")" << std::endl;
                                            // Initialize trust score for new identity
                                            if (g_node_context.trust_manager) {
                                                g_node_context.trust_manager->on_registration(
                                                    dna_opt->address, static_cast<uint32_t>(curHeight));
                                            }
                                            // Broadcast DNA to all connected peers.
                                            BroadcastDNASample(*dna_opt);
                                        }
                                    } else {
                                        // DNA Propagation Phase 1: drop the "new_dims > old_dims" gate
                                        // that silently discarded same-dim value changes. append_sample
                                        // accepts any non-shrinking sample, archives the old canonical
                                        // to history, and caps history at 100 entries per MIK. On
                                        // successful update, re-broadcast to peers so the network stays
                                        // converged — the original code only broadcast on initial
                                        // registration, which is why bandwidth/drift/perspective coverage
                                        // stuck at 1-15% despite miners collecting the data locally.
                                        auto result = g_node_context.dna_registry->append_sample(*dna_opt);
                                        if (result == digital_dna::IDNARegistry::RegisterResult::UPDATED ||
                                            result == digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED) {
                                            BroadcastDNASample(*dna_opt);
                                            // Phase 5: Apply trust penalty on DNA dimension changes.
                                            // core_dimensions_changed gates on timing >10% or latency
                                            // >20ms — bandwidth/drift/perspective/thermal value changes
                                            // do NOT trigger this path.
                                            if (result == digital_dna::IDNARegistry::RegisterResult::DNA_CHANGED &&
                                                g_node_context.trust_manager) {
                                                int rotationHeight = Dilithion::g_chainParams ?
                                                    Dilithion::g_chainParams->dnaRotationActivationHeight : 999999999;
                                                if (curHeight >= rotationHeight) {
                                                    g_node_context.trust_manager->on_dna_changed(
                                                        dna_opt->address, static_cast<uint32_t>(curHeight));
                                                    std::cout << "[DNA] Core dimensions changed at height " << curHeight
                                                              << " - trust penalty applied (-10)" << std::endl;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Phase 1.5: periodic re-broadcast of our own DNA every 15
                    // minutes, regardless of enrichment. Paired with the signed
                    // envelope + version-gated send in BroadcastDNASample, this
                    // keeps the network converged on our current sample without
                    // requiring a dimension change to trigger broadcast.
                    // Seeds without a wallet MIK still benefit — the unsigned
                    // path still propagates via merge-fill on receivers.
                    {
                        static auto last_dna_push = std::chrono::steady_clock::now();
                        auto now_push = std::chrono::steady_clock::now();
                        auto push_elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                            now_push - last_dna_push).count();
                        if (push_elapsed >= 15 &&
                            g_node_context.dna_registry &&
                            g_node_context.connman &&
                            g_node_context.message_processor) {
                            auto dna_coll_push = g_node_context.GetDNACollector();
                            if (dna_coll_push) {
                                auto dna_push = dna_coll_push->get_dna();
                                if (dna_push &&
                                    dna_push->mik_identity != std::array<uint8_t, 20>{}) {
                                    last_dna_push = now_push;
                                    BroadcastDNASample(*dna_push);
                                }
                            }
                        }
                    }

                    // Digital DNA Discovery: Request DNA from peers for known miners
                    // Fixed: round-robin across peers, rotating offset to cover all MIKs
                    {
                        static auto last_dna_discovery = std::chrono::steady_clock::now();
                        static size_t dna_disc_offset = 0;
                        auto now_disc = std::chrono::steady_clock::now();
                        auto disc_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            now_disc - last_dna_discovery).count();

                        if (disc_elapsed >= 60 && g_node_context.dna_registry &&
                            g_node_context.connman && g_node_context.message_processor) {
                            int dnaActDisc = Dilithion::g_chainParams ?
                                Dilithion::g_chainParams->digitalDnaActivationHeight : 999999999;
                            if (g_chainstate.GetHeight() >= dnaActDisc) {
                                last_dna_discovery = now_disc;
                                // Phase 1.2: source MIKs from dna_registry (always populated
                                // once DNA has been received) unioned with cooldown_tracker
                                // (VDF-only — empty on DIL). Pre-fix, DIL's discovery loop
                                // iterated over an empty cooldown_tracker and never sent a
                                // single dnaireq; bandwidth/clock_drift coverage stayed ~1%.
                                std::vector<std::array<uint8_t, 20>> known_miks =
                                    g_node_context.dna_registry->get_all_miks();
                                if (g_node_context.cooldown_tracker) {
                                    auto ct_miks = g_node_context.cooldown_tracker->GetKnownAddresses();
                                    for (const auto& m : ct_miks) {
                                        bool dup = false;
                                        for (const auto& e : known_miks) {
                                            if (e == m) { dup = true; break; }
                                        }
                                        if (!dup) known_miks.push_back(m);
                                    }
                                }
                                auto nodes = g_node_context.connman->GetNodes();
                                std::vector<int> peer_ids;
                                for (auto* n : nodes) {
                                    if (n && n->IsConnected()) peer_ids.push_back(n->id);
                                }

                                if (!peer_ids.empty()) {
                                    // Collect MIKs missing OR stale from our DNA registry.
                                    // Phase 1 propagation fix: we now also re-request DNA for
                                    // MIKs whose stored record has fewer than 8 populated
                                    // dimensions. Under mixed-version propagation, a miner's
                                    // early (sparse) broadcast may have been accepted before
                                    // bandwidth/drift/perspective collection caught up; a
                                    // later fresh request gives the enriched sample a path in.
                                    std::vector<std::array<uint8_t, 20>> missing_miks;
                                    for (const auto& mik : known_miks) {
                                        if (mik == std::array<uint8_t, 20>{}) continue;
                                        auto existing = g_node_context.dna_registry->get_identity_by_mik(mik);
                                        if (!existing) {
                                            missing_miks.push_back(mik);
                                            continue;
                                        }
                                        int dims = 2   // latency + timing (always on valid DNA)
                                            + ((existing->perspective.total_unique_peers() > 0 ||
                                                !existing->perspective.snapshots.empty()) ? 1 : 0)
                                            + (existing->memory      ? 1 : 0)
                                            + (existing->clock_drift ? 1 : 0)
                                            + (existing->bandwidth   ? 1 : 0)
                                            + (existing->thermal     ? 1 : 0)
                                            + (existing->behavioral  ? 1 : 0);
                                        if (dims < 8) missing_miks.push_back(mik);
                                    }

                                    if (!missing_miks.empty()) {
                                        if (dna_disc_offset >= missing_miks.size())
                                            dna_disc_offset = 0;

                                        // Send at most 1 request per peer (round-robin)
                                        size_t max_requests = std::min(peer_ids.size(), missing_miks.size());
                                        int requested = 0;
                                        for (size_t i = 0; i < max_requests; ++i) {
                                            size_t mik_idx = (dna_disc_offset + i) % missing_miks.size();
                                            int target = peer_ids[i % peer_ids.size()];
                                            auto msg = g_node_context.message_processor->CreateDNAIdentReqMessage(
                                                missing_miks[mik_idx]);
                                            g_node_context.connman->PushMessage(target, msg);
                                            ++requested;
                                        }
                                        dna_disc_offset += requested;

                                        std::cout << "[DNA] Discovery: requested " << requested
                                                  << " of " << missing_miks.size() << " missing MIKs"
                                                  << " (registered=" << g_node_context.dna_registry->count()
                                                  << ", total_known=" << known_miks.size() << ")"
                                                  << std::endl;
                                    }
                                }
                            }
                        }
                    }

                    // Digital DNA P2P: Periodic clock drift + bandwidth measurement initiators
                    // Gated by DNA activation height and collector existence
                    {
                        static auto last_tsync = std::chrono::steady_clock::now();
                        static auto last_bwtest = std::chrono::steady_clock::now();
                        auto now_p2p = std::chrono::steady_clock::now();
                        int dnaActP2P = Dilithion::g_chainParams ?
                            Dilithion::g_chainParams->digitalDnaActivationHeight : 999999999;
                        int curHeightP2P = g_chainstate.GetHeight();

                        if (curHeightP2P >= dnaActP2P &&
                            g_node_context.GetDNACollector() &&
                            g_node_context.connman && g_node_context.message_processor) {

                            // Collect peer IDs once for both operations
                            auto nodes = g_node_context.connman->GetNodes();
                            std::vector<int> peer_ids;
                            for (auto* n : nodes) {
                                if (n && n->IsConnected()) peer_ids.push_back(n->id);
                            }

                            // Clock drift: send dnatsync to random peer every 5 minutes
                            auto tsync_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                now_p2p - last_tsync).count();
                            if (tsync_elapsed >= 300 && !peer_ids.empty()) {
                                last_tsync = now_p2p;
                                std::mt19937 rng(std::random_device{}());
                                int target = peer_ids[rng() % peer_ids.size()];
                                auto ts_us = static_cast<uint64_t>(
                                    std::chrono::duration_cast<std::chrono::microseconds>(
                                        std::chrono::steady_clock::now().time_since_epoch()).count());
                                auto wall_ms = static_cast<uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                uint64_t nonce = (static_cast<uint64_t>(rng()) << 32) | rng();
                                g_node_context.message_processor->RegisterDNANonce(nonce, target, ts_us);
                                CNetMessage msg = g_node_context.message_processor->CreateDNATimeSyncMessage(
                                    ts_us, wall_ms, nonce, false);
                                g_node_context.connman->PushMessage(target, msg);
                            }

                            // Bandwidth: send dnabwtest to random peer every 15 minutes
                            auto bwtest_elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                now_p2p - last_bwtest).count();
                            if (bwtest_elapsed >= 900 && !peer_ids.empty()) {
                                last_bwtest = now_p2p;
                                std::mt19937 rng(std::random_device{}());
                                int target = peer_ids[rng() % peer_ids.size()];
                                uint64_t nonce = (static_cast<uint64_t>(rng()) << 32) | rng();
                                g_node_context.message_processor->RegisterDNANonce(nonce, target);
                                // Use smaller payload for testnet (256KB) vs mainnet (1MB)
                                bool is_testnet = Dilithion::g_chainParams &&
                                    Dilithion::g_chainParams->digitalDnaActivationHeight == 1;
                                uint32_t payload_sz = is_testnet ? 256 * 1024 : 1024 * 1024;
                                CNetMessage msg = g_node_context.message_processor->CreateDNABWTestMessage(
                                    nonce, payload_sz);
                                g_node_context.connman->PushMessage(target, msg);
                            }

                            // Cleanup expired nonces periodically
                            g_node_context.message_processor->CleanupDNANonces();
                        }
                    }

                    // Phase 2: DNA Verification manager tick (timeouts + queued verifications)
                    if (g_node_context.verification_manager) {
                        int verifyHeight = g_chainstate.GetHeight();
                        g_node_context.verification_manager->Tick(
                            static_cast<uint32_t>(verifyHeight));
                    }

                    // Process feeler connections (Bitcoin Core-style eclipse attack protection)
                    // Feeler connections test addresses we haven't tried recently
                    // Phase 5: Re-enabled after CFeelerManager migration to CConnman
                    feeler_manager.ProcessFeelerConnections();

                    // Periodic memory defragmentation (every 5 minutes).
                    // glibc malloc arenas fragment over time on long-running nodes,
                    // causing RSS to grow from ~300MB to 3+GB and trigger OOM kills.
                    // malloc_trim returns free pages to the OS (like Bitcoin Core does).
#ifdef __linux__
                    {
                        static int trim_counter = 0;
                        if (++trim_counter >= 10) {  // 10 × 30s = 5 minutes
                            trim_counter = 0;
                            malloc_trim(0);
                        }
                    }
#endif

                    // Sleep for 30 seconds between maintenance cycles
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                } catch (const std::system_error& e) {
                    std::cerr << "[P2P-Maint] System error in maintenance loop: " << e.what()
                              << " (code: " << e.code() << ")" << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                } catch (const std::exception& e) {
                    std::cerr << "[P2P-Maint] Exception in maintenance loop: " << e.what() << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                } catch (...) {
                    std::cerr << "[P2P-Maint] Unknown exception in maintenance loop" << std::endl;
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
                }

                std::cout << "  P2P maintenance thread stopping..." << std::endl;
            } catch (const std::exception& e) {
                // Phase 1.1: Prevent silent thread crashes
                LogPrintf(NET, ERROR, "P2P maintenance thread exception: %s", e.what());
                std::cerr << "[P2P-Maintenance] FATAL: Thread exception: " << e.what() << std::endl;
            } catch (...) {
                LogPrintf(NET, ERROR, "P2P maintenance thread unknown exception");
                std::cerr << "[P2P-Maintenance] FATAL: Unknown thread exception" << std::endl;
            }
            });
            std::cerr.flush();
        } catch (const std::exception& e) {
            std::cerr.flush();
            g_node_state.running = false;
            throw;
        } catch (...) {
            std::cerr.flush();
            g_node_state.running = false;
            throw;
        }

        // BUG #88: All P2P threads created successfully
        std::cerr.flush();

        // Phase 4: Initialize RPC server
        std::cerr.flush();
        std::cout << "[4/6] Initializing RPC server..." << std::flush;
        CRPCServer rpc_server(config.rpcport);
        g_node_state.rpc_server = &rpc_server;

        // Register components with RPC server
        rpc_server.RegisterWallet(&wallet);
        rpc_server.RegisterMiner(&miner);
        rpc_server.RegisterBlockchain(&blockchain);
        rpc_server.RegisterChainState(&g_chainstate);
        rpc_server.RegisterMempool(&mempool);
        rpc_server.RegisterUTXOSet(&utxo_set);
        rpc_server.SetTestnet(config.testnet);
        rpc_server.SetPublicAPI(config.public_api);  // Light wallet REST API (for seed nodes)
        rpc_server.SetAttestationRateLimit(config.attestation_rate_limit);  // Sybil defense Phase 0
        rpc_server.SetDataDir(Dilithion::g_chainParams->dataDir);  // For swap state persistence

        // Phase 2+3: Seed attestation initialization (relay-only seed nodes only)
        // Loads ASN database and attestation signing key so seeds can serve
        // getmikattestation RPC requests from miners.
        static Attestation::CSeedAttestationKey seedAttestKey;
        static CASNDatabase asnDatabase;
        if (config.relay_only && Dilithion::g_chainParams) {
            std::string dataDir = Dilithion::g_chainParams->dataDir;

            // Load ASN database from data directory (or project root)
            std::string asnPath = dataDir + "/ip2asn-v4.tsv";
            if (!asnDatabase.LoadDatabase(asnPath)) {
                std::cerr << "[Attestation] ASN database not found at " << asnPath
                          << ", trying ./ip2asn-v4.tsv" << std::endl;
                if (!asnDatabase.LoadDatabase("ip2asn-v4.tsv")) {
                    std::cerr << "[Attestation] WARNING: ASN database not loaded. "
                              << "getmikattestation RPC will be unavailable." << std::endl;
                }
            }

            if (asnDatabase.IsLoaded()) {
                std::string dcPath = dataDir + "/datacenter-asns.txt";
                if (!asnDatabase.LoadDatacenterList(dcPath)) {
                    asnDatabase.LoadDatacenterList("datacenter-asns.txt");
                }
                std::cout << "  [OK] ASN database loaded (" << asnDatabase.RangeCount()
                          << " ranges, " << asnDatabase.DatacenterASNCount()
                          << " datacenter ASNs)" << std::endl;
            }

            // Load or generate attestation key
            if (seedAttestKey.LoadOrGenerate(dataDir)) {
                int seedId = -1;
                const auto& seedIPs = Dilithion::g_chainParams->seedAttestationIPs;
                if (!config.external_ip.empty()) {
                    for (size_t i = 0; i < seedIPs.size(); i++) {
                        if (seedIPs[i] == config.external_ip) {
                            seedId = static_cast<int>(i);
                            break;
                        }
                    }
                }
                if (seedId < 0) {
                    seedId = 0;
                    std::cerr << "[Attestation] WARNING: Could not determine seed ID. "
                              << "Use --externalip=<IP> to set. Defaulting to seed_id=0" << std::endl;
                }

                if (asnDatabase.IsLoaded()) {
                    rpc_server.RegisterSeedAttestation(&seedAttestKey, &asnDatabase, seedId);
                    std::cout << "  [OK] Seed attestation ready (seed_id=" << seedId
                              << ", key=" << seedAttestKey.GetPubKeyHex().substr(0, 16) << "...)"
                              << std::endl;
                }
            }
        }

        // Register Digital DNA RPC commands
        std::unique_ptr<digital_dna::DigitalDNARpc> dna_rpc;
        if (g_node_context.dna_registry) {
            dna_rpc = std::make_unique<digital_dna::DigitalDNARpc>(*g_node_context.dna_registry);
            dna_rpc->register_commands();
            rpc_server.RegisterDNARpc(dna_rpc.get());
            std::cout << "  [OK] Digital DNA RPC commands registered" << std::endl;

            // Initialize DNA collector (miners AND relay-only nodes)
            int dnaActivation = Dilithion::g_chainParams ?
                Dilithion::g_chainParams->digitalDnaActivationHeight : 999999999;
            int tipHeight = g_chainstate.GetHeight();

            if (tipHeight >= dnaActivation) {
                std::array<uint8_t, 20> address{};
                bool have_mik = false;
                std::array<uint8_t, 20> mikArr{};

                if (!config.relay_only && wallet.GetAddresses().size() > 0) {
                    // Mining node: use wallet address + MIK
                    std::vector<uint8_t> pubKeyHash = wallet.GetPubKeyHash();
                    if (pubKeyHash.size() == 20) {
                        std::copy(pubKeyHash.begin(), pubKeyHash.end(), address.begin());
                        digital_dna::DigitalDNARpc::set_my_address(address);
                    }
                    DFMP::Identity mikId = wallet.GetMIKIdentity();
                    if (!mikId.IsNull()) {
                        std::copy(mikId.data, mikId.data + 20, mikArr.begin());
                        have_mik = true;
                    }
                }
                // Relay-only nodes: use zero address (latency/timing still measured)

                digital_dna::DigitalDNACollector::Config dna_config;
                dna_config.testnet = config.testnet;
                auto new_collector = std::make_shared<digital_dna::DigitalDNACollector>(address, dna_config);

                if (have_mik) {
                    new_collector->set_mik_identity(mikArr);
                }

                new_collector->start_collection();
                g_node_context.SetDNACollector(std::move(new_collector));

                std::ostringstream addr_hex;
                for (int i = 0; i < 4; ++i)
                    addr_hex << std::hex << std::setfill('0') << std::setw(2) << (int)address[i];
                std::cout << "  [OK] Digital DNA collection started (auto"
                          << (config.relay_only ? ", relay-only" : "")
                          << ", address: " << addr_hex.str() << "...)" << std::endl;
            }
        }

        // Phase 2: Wire DNA Verification Manager (MIK identity + P2P callbacks)
        if (g_node_context.verification_manager) {
            // Set this node's MIK identity for signing attestations
            DFMP::Identity vmMikId = wallet.GetMIKIdentity();
            if (!vmMikId.IsNull()) {
                std::array<uint8_t, 20> vmMikArr{};
                std::copy(vmMikId.data, vmMikId.data + 20, vmMikArr.begin());
                std::vector<uint8_t> vmPubkey;
                if (wallet.GetMIKPubKey(vmPubkey)) {
                    g_node_context.verification_manager->SetMyMIK(
                        vmMikArr, vmPubkey, wallet.GetMIKKeyPtr());
                    std::cout << "  [OK] DNA verification manager: MIK identity set" << std::endl;
                }
            }

            // Set P2P message sending callbacks
            g_node_context.verification_manager->SetSendChallenge(
                [](int peer_id, const std::vector<uint8_t>& data) {
                    if (g_node_context.connman && g_node_context.message_processor) {
                        auto msg = g_node_context.message_processor->CreateDNAVerifyChallengeMessage(data);
                        g_node_context.connman->PushMessage(peer_id, msg);
                    }
                });
            g_node_context.verification_manager->SetSendResponse(
                [](int peer_id, const std::vector<uint8_t>& data) {
                    if (g_node_context.connman && g_node_context.message_processor) {
                        auto msg = g_node_context.message_processor->CreateDNAVerifyResponseMessage(data);
                        g_node_context.connman->PushMessage(peer_id, msg);
                    }
                });
            g_node_context.verification_manager->SetBroadcastAttestation(
                [](const std::vector<uint8_t>& data) {
                    if (g_node_context.connman && g_node_context.message_processor) {
                        auto msg = g_node_context.message_processor->CreateDNAVerifyAttestMessage(data);
                        auto peers = g_node_context.peer_manager ?
                            g_node_context.peer_manager->GetConnectedPeers() :
                            std::vector<std::shared_ptr<CPeer>>{};
                        for (const auto& peer : peers) {
                            if (peer->IsHandshakeComplete()) {
                                g_node_context.connman->PushMessage(peer->id, msg);
                            }
                        }
                    }
                });
            g_node_context.verification_manager->SetFindPeerByMik(
                [](const std::array<uint8_t, 20>& mik) -> int {
                    // Look up peer by MIK from the identity response cache
                    std::lock_guard<std::mutex> lock(g_mik_peer_mutex);
                    auto it = g_mik_peer_map.find(mik);
                    if (it != g_mik_peer_map.end()) {
                        // Verify peer is still connected
                        if (g_node_context.peer_manager) {
                            auto peer = g_node_context.peer_manager->GetPeer(it->second);
                            if (peer && peer->IsHandshakeComplete()) {
                                return it->second;
                            }
                        }
                        g_mik_peer_map.erase(it);  // Stale entry
                    }
                    return -1;  // Not found or disconnected
                });

            std::cout << "  [OK] DNA verification manager: P2P callbacks wired" << std::endl;
        }

        // Phase 4: Wire trust score callback for P2P layer
        g_node_context.GetPeerTrustScore = [](int peer_id) -> double {
            // Reverse lookup: find MIK for this peer_id
            std::array<uint8_t, 20> mik{};
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(g_mik_peer_mutex);
                for (const auto& [m, pid] : g_mik_peer_map) {
                    if (pid == peer_id) {
                        mik = m;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) return -1.0;  // Unknown peer (grace period)

            // Look up trust score
            if (!g_node_context.trust_manager) return -1.0;
            if (!g_node_context.trust_manager->has_score(mik)) return -1.0;
            return g_node_context.trust_manager->get_score(mik).current_score;
        };

        // Phase 1: Initialize authentication and permissions
        std::string rpcuser = config_parser.GetString("rpcuser", "");
        std::string rpcpassword = config_parser.GetString("rpcpassword", "");
        std::string rpc_permissions_file = config.datadir + "/rpc_permissions.json";

        if (!rpcuser.empty() && !rpcpassword.empty()) {
            // Initialize permissions system
            if (!rpc_server.InitializePermissions(rpc_permissions_file, rpcuser, rpcpassword)) {
                std::cerr << "WARNING: Failed to initialize RPC permissions, continuing without authentication" << std::endl;
            } else {
                std::cout << "  [AUTH] RPC authentication enabled" << std::endl;
            }
        } else if (config.public_api) {
            // v4.1-rc2 ISSUE-1 fix: auto-generate secure random RPC credentials
            // for --public-api when none configured, instead of refusing to start.
            // The auto-generated dilithion.conf created by the binary on first
            // startup is empty, so a fresh seed/server with --public-api would
            // crash with "ERROR: --public-api requires RPC authentication" and
            // call terminate() — terrible UX. Now we generate random creds
            // (32-byte hex password), persist them to <datadir>/dilithion.conf
            // mode 0600, and use them. Operator can edit the config later to
            // change them.
            // FINDING-1 (red-team rc2 review): GenerateSalt() resizes to
            // WALLET_CRYPTO_SALT_SIZE=16, only filling 16 bytes (128 bits).
            // Use GetStrongRandBytes directly for the full 32 bytes (256 bits)
            // promised in the comments.
            extern bool GetStrongRandBytes(uint8_t* buf, size_t len);
            std::vector<uint8_t> pw_bytes(32);
            if (!GetStrongRandBytes(pw_bytes.data(), pw_bytes.size())) {
                std::cerr << "ERROR: --public-api requires RPC authentication, and "
                          << "auto-generation of random credentials failed.\n"
                          << "Add these lines to " << config.datadir << "/dilithion.conf:\n"
                          << "  rpcuser=<choose any username>\n"
                          << "  rpcpassword=<choose a strong password>\n"
                          << "Then restart." << std::endl;
                return 1;
            }
            std::string pw_hex;
            pw_hex.reserve(64);
            for (auto b : pw_bytes) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", b);
                pw_hex += hex;
            }
            rpcuser = "dilithion";
            rpcpassword = pw_hex;

            // Append to dilithion.conf for persistence across restarts.
            std::string conf_path = config.datadir + "/dilithion.conf";
            std::ofstream conf_file(conf_path, std::ios::app);
            if (conf_file.is_open()) {
                conf_file << "\n# v4.1-rc2: auto-generated for --public-api\n";
                conf_file << "rpcuser=" << rpcuser << "\n";
                conf_file << "rpcpassword=" << rpcpassword << "\n";
                conf_file.close();
#ifndef _WIN32
                chmod(conf_path.c_str(), 0600);
#endif
                std::cout << "  [AUTH] --public-api: auto-generated RPC credentials "
                          << "written to " << conf_path << " (mode 0600)" << std::endl;
                std::cout << "  [AUTH] rpcuser=" << rpcuser
                          << " (rpcpassword in conf file)" << std::endl;
            } else {
                std::cerr << "WARNING: --public-api auto-credentials generated but failed to "
                          << "persist to " << conf_path << ". They will work this session only "
                          << "and won't survive restart." << std::endl;
            }

            if (!rpc_server.InitializePermissions(rpc_permissions_file, rpcuser, rpcpassword)) {
                std::cerr << "ERROR: Failed to initialize RPC permissions with auto-generated credentials" << std::endl;
                return 1;
            }
            std::cout << "  [AUTH] RPC authentication enabled (auto-generated)" << std::endl;
        } else {
            // No credentials configured — generate a cookie file for local auth.
            // This mirrors Bitcoin Core's .cookie mechanism: a random credential
            // is written to <datadir>/.cookie on each startup. Local tools (relayer,
            // CLI) can read it. The file is deleted on clean shutdown.
            std::string cookie_path = config.datadir + "/.cookie";
            std::vector<uint8_t> cookie_bytes(32);
            extern bool GenerateSalt(std::vector<uint8_t>&);
            if (GenerateSalt(cookie_bytes)) {
                // Convert to hex string for use as password
                std::string cookie_password;
                for (auto b : cookie_bytes) {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02x", b);
                    cookie_password += hex;
                }
                rpcuser = "__cookie__";
                rpcpassword = cookie_password;

                // Write cookie file (mode 0600 on Unix for owner-only access)
                std::ofstream cookie_file(cookie_path);
                if (cookie_file.is_open()) {
                    cookie_file << rpcuser << ":" << rpcpassword;
                    cookie_file.close();
#ifndef _WIN32
                    chmod(cookie_path.c_str(), 0600);
#endif
                    std::cout << "  [AUTH] RPC cookie authentication enabled (credentials in "
                              << cookie_path << ")" << std::endl;

                    // Initialize permissions with cookie credentials
                    rpc_server.InitializePermissions(rpc_permissions_file, rpcuser, rpcpassword);
                } else {
                    std::cerr << "  [WARNING] Failed to write RPC cookie file. "
                              << "RPC authentication disabled." << std::endl;
                }
            } else {
                std::cerr << "  [WARNING] Failed to generate RPC cookie. "
                          << "RPC authentication disabled." << std::endl;
            }
        }

        // Phase 1: Initialize request logging
        std::string rpc_log_file = config.datadir + "/rpc.log";
        std::string rpc_audit_file = config.datadir + "/rpc_audit.log";
        rpc_server.InitializeLogging(rpc_log_file, rpc_audit_file, CRPCLogger::LogLevel::INFO);

        // Phase 3: Initialize SSL/TLS if configured
        std::string rpc_cert_file = config_parser.GetString("rpcsslcertificatechainfile", "");
        std::string rpc_key_file = config_parser.GetString("rpcsslprivatekeyfile", "");
        if (!rpc_cert_file.empty() && !rpc_key_file.empty()) {
            std::string rpc_ca_file = config_parser.GetString("rpcsslcapath", "");
            if (!rpc_server.InitializeSSL(rpc_cert_file, rpc_key_file, rpc_ca_file)) {
                std::cerr << "WARNING: Failed to initialize SSL/TLS, continuing without encryption" << std::endl;
            }
        }

        // Phase 4: Initialize WebSocket server if configured
        int64_t ws_port = config_parser.GetInt64("rpcwebsocketport", 0);
        if (ws_port > 0 && ws_port <= 65535) {
            if (!rpc_server.InitializeWebSocket(static_cast<uint16_t>(ws_port))) {
                std::cerr << "WARNING: Failed to initialize WebSocket server, continuing without WebSocket" << std::endl;
            }
        }

        if (!rpc_server.Start()) {
            std::cerr << "Failed to start RPC server on port " << config.rpcport << std::endl;
            return 1;
        }
        std::cout << "  [OK] RPC server listening on port " << config.rpcport << std::endl;

        // Start mining if requested
        // BUG #54 FIX: Don't block here - let main loop run for block downloads
        // Mining will start inside main loop after IBD completes
        bool mining_deferred_for_ibd = false;  // Track if we're waiting for IBD
        if (config.start_mining) {
            g_node_state.mining_enabled = true;  // Track that mining was requested
            std::cout << std::endl;

            // Display mining mode info
            if (!config.mining_address_override.empty()) {
                // Explicit address mode
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "| Mining Mode: FIXED ADDRESS                                          |" << std::endl;
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "  Mining to: " << config.mining_address_override << std::endl;
                std::cout << std::endl;
            } else if (config.rotate_mining_address) {
                // Rotating address mode (privacy)
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "| Mining Mode: ROTATING ADDRESS (new HD address per block)             |" << std::endl;
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "  Rewards go to your wallet (seed phrase controls all addresses)" << std::endl;
                std::cout << "  Check balance: 'getbalance' RPC or wallet.html" << std::endl;
                std::cout << "  For fixed address: restart with --mining-address=Dxxx" << std::endl;
                std::cout << std::endl;
            } else {
                // Default: wallet's default address — show it so miners know where rewards go
                std::string defaultAddr = "(unknown)";
                if (g_node_state.wallet) {
                    CDilithiumAddress addr = g_node_state.wallet->GetNewAddress();
                    if (addr.IsValid()) defaultAddr = addr.ToString();
                }
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "| Mining Mode: WALLET DEFAULT ADDRESS                                  |" << std::endl;
                std::cout << "+----------------------------------------------------------------------+" << std::endl;
                std::cout << "  Mining to: " << defaultAddr << std::endl;
                std::cout << "  For privacy: restart with --rotate-mining-address" << std::endl;
                std::cout << "  For explicit: restart with --mining-address=Dxxx" << std::endl;
                std::cout << std::endl;
            }

            std::cout << "Mining enabled - checking sync status..." << std::endl;

            // Wait for --connect peers to handshake before checking IBD
            // Without this, fresh --mine --connect=relay nodes see connections=0 and
            // incorrectly start mining on their own chain (Bitcoin Core pattern)
            if (config.start_mining && !config.connect_nodes.empty()) {
                std::cout << "  [SYNC] Waiting for --connect peers to handshake..." << std::endl;
                bool handshake_ok = false;
                for (int i = 0; i < 40; i++) {  // 40 x 250ms = 10s max
                    if (g_node_context.peer_manager && g_node_context.peer_manager->HasCompletedHandshakes()) {
                        std::cout << "  [OK] Peer handshake complete" << std::endl;
                        handshake_ok = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(250));
                }
                if (!handshake_ok) {
                    std::cout << "  [WARN] No handshakes completed after 10s (peers will auto-reconnect)" << std::endl;
                }
            }

            // BUG #52 FIX: Check IBD before starting mining (Bitcoin pattern)
            // This prevents fresh nodes from mining on their own chain before syncing
            // BUG #54 FIX: Don't BLOCK here - just defer mining and let main loop run
            // Note: config.start_mining may have been set to false above if wallet unlock failed
            if (config.start_mining && IsInitialBlockDownload()) {
                std::cout << "  [IBD] Node is syncing - mining will start after sync" << std::endl;
                std::cout << "  [IBD] Main loop will handle block downloads, mining deferred..." << std::endl;
                mining_deferred_for_ibd = true;
                // DO NOT block here - main loop needs to run for block downloads!
            } else if (config.start_mining) {
                std::cout << "  [OK] Already synced with network" << std::endl;

                // BUG #72 FIX: Wait for FULL mode before starting mining threads
                // Following XMRig's proven pattern: "dataset ready" before thread creation
                // Mining threads created in LIGHT mode get LIGHT VMs and never upgrade
                if (!randomx_is_mining_mode_ready()) {
                    // BUG #98 FIX: Must INITIALIZE FULL mode before waiting for it!
                    // The "already synced" path was waiting but never calling init_mining_mode_async
                    std::cout << "  Initializing RandomX mining mode (FULL)..." << std::endl;
                    randomx_init_mining_mode_async(rx_key, strlen(rx_key));
                    std::cout << "  [WAIT] Waiting for RandomX FULL mode..." << std::endl;
                    auto wait_start = std::chrono::steady_clock::now();
                    while (!randomx_is_mining_mode_ready() && g_node_state.running) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        auto elapsed = std::chrono::steady_clock::now() - wait_start;
                        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 600) {
                            std::cerr << "  [WARN] FULL mode init timeout (10min), starting with LIGHT mode" << std::endl;
                            break;
                        }
                        // Show progress every 60 seconds
                        auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                        if (elapsed_sec > 0 && elapsed_sec % 60 == 0) {
                            std::cout << "  [WAIT] Still initializing FULL mode... (" << elapsed_sec << "s)" << std::endl;
                        }
                    }
                    auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - wait_start).count();
                    std::cout << "  [OK] Mining mode ready (FULL, " << wait_time << "s)" << std::endl;
                } else {
                    std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                }

                // Now safe to start mining (synced with network)
                unsigned int current_height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                std::cout << "  [OK] Current blockchain height: " << current_height << std::endl;

                // Ensure MIK identity is registered before mining. If this
                // fails (wallet locked, seeds unreachable, etc.), do NOT start
                // any miner — Handler 1's CanMine() gate in the main loop
                // will start it once RegistrationManager reaches READY.
                if (EnsureMIKRegistered(wallet, current_height + 1)) {
                    if (shouldUseVDF(current_height + 1)) {
                        // VDF mining mode
                        std::cout << "  [VDF] VDF mining active (activation height: " << vdf_activation << ")" << std::endl;
                        std::cout << "  [VDF] Iterations: " << vdf_iterations << std::endl;

                        // Set miner address from wallet
                        std::vector<uint8_t> pubKeyHash = wallet.GetPubKeyHash();
                        if (pubKeyHash.size() >= 20) {
                            std::array<uint8_t, 20> addr{};
                            std::copy(pubKeyHash.begin(), pubKeyHash.begin() + 20, addr.begin());
                            vdf_miner.SetMinerAddress(addr);
                        }

                        vdf_miner.Start();
                        std::cout << "  [OK] VDF mining started (single-threaded, deterministic)" << std::endl;
                    } else {
                        // RandomX mining mode
                        auto templateOpt = BuildMiningTemplate(blockchain, wallet, true, config.mining_address_override);
                        if (!templateOpt) {
                            // Retry up to 3 times (safety net — registration should already be done)
                            for (int attempt = 1; attempt <= 3 && !templateOpt; attempt++) {
                                std::cerr << "[Mining] Template build failed, retrying (" << attempt << "/3)..." << std::endl;
                                std::this_thread::sleep_for(std::chrono::seconds(1));
                                templateOpt = BuildMiningTemplate(blockchain, wallet, true, config.mining_address_override);
                            }
                            if (!templateOpt) {
                                std::cerr << "ERROR: Failed to build mining template after retries" << std::endl;
                                return 1;
                            }
                        }

                        miner.StartMining(*templateOpt);

                        std::cout << "  [OK] RandomX mining started with " << mining_threads << " threads" << std::endl;
                        std::cout << "  Expected hash rate: ~" << (mining_threads * 65) << " H/s" << std::endl;
                    }
                } else {
                    std::cerr << "[Mining] MIK registration not ready — mining NOT started." << std::endl;
                    std::cerr << "[Mining] Main loop will retry via RegistrationManager; see manager status." << std::endl;
                }
            }
        }

        // Node is ready
        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "Node Status: RUNNING" << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << std::endl;
        std::cout << "RPC Interface:" << std::endl;
        std::cout << "  URL: http://localhost:" << config.rpcport << std::endl;
        std::cout << "  Methods: getnewaddress, getbalance, getmininginfo, help" << std::endl;
        std::cout << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        std::cout << std::endl;

        // Phase 5.1: Initialize IBD Coordinator (must be after all components are ready)
        CIbdCoordinator ibd_coordinator(g_chainstate, g_node_context);
        g_node_context.ibd_coordinator = &ibd_coordinator;  // Register for IsSynced() access

        // v4.3.4 cut Block 7+8: sync_coordinator always backs onto legacy
        // CIbdCoordinator via CIbdCoordinatorAdapter. port::CPeerManager
        // class was deleted (Block 7); --usenewpeerman flag retired (Block 8).
        // Closes audit gaps G08-G11.
        g_node_context.sync_coordinator =
            std::make_unique<dilithion::net::port::CIbdCoordinatorAdapter>(ibd_coordinator);
        LogPrintf(IBD, INFO, "IBD Coordinator initialized");

        // Solo mining prevention state - declared before new_block_found handler
        // so that the handler can check mining_paused_no_peers before restarting
        static int counter = 0;
        static auto no_peers_since = std::chrono::steady_clock::time_point{};  // When peers dropped to 0
        static bool mining_paused_no_peers = false;  // Whether we auto-paused mining
        static bool mining_paused_fork = false;  // Whether we auto-paused for fork resolution
        static int last_remaining_logged = -1;  // For countdown logging
        static constexpr int SOLO_MINING_GRACE_PERIOD_SECONDS = 120;  // 2 minute grace period

        // Consensus fork detection state - detects when miner is solo on a fork
        // by tracking consecutive blocks mined by our address with no peer blocks
        static uint256 last_checked_tip_hash;
        static int consecutive_self_mined = 0;
        static bool mining_paused_consensus_fork = false;
        static bool solo_warning_shown = false;
        static constexpr int SOLO_WARNING_THRESHOLD = 5;   // Warn after 5 consecutive self-mined blocks
        static constexpr int SOLO_PAUSE_THRESHOLD = 10;    // Pause after 10 consecutive self-mined blocks

        // Tip divergence detection state - compares our tip hash vs peers' tips
        // Catches the case where we have peers but are on a different chain
        static auto divergence_since = std::chrono::steady_clock::time_point{};
        static bool mining_paused_tip_divergence = false;
        static bool tip_divergence_warned = false;
        static auto last_divergence_check = std::chrono::steady_clock::now();
        static constexpr int TIP_CHECK_INTERVAL_S = 30;    // Check every 30 seconds
        static constexpr int TIP_DIVERGE_WARN_S = 120;     // Warn after 2 minutes
        static constexpr int TIP_DIVERGE_PAUSE_S = 300;    // Pause after 5 minutes
        static constexpr int TIP_FRESHNESS_S = 300;        // Ignore stale peer data (>5 min old)

        // Rolling window for self-mined block ratio (Phase 3)
        struct RecentBlock { bool self_mined; };
        static std::deque<RecentBlock> recent_blocks;
        static constexpr size_t RECENT_BLOCK_WINDOW = 20;
        static constexpr float SOLO_WARN_RATIO = 0.80f;
        static constexpr float SOLO_PAUSE_RATIO = 0.90f;

        // Main loop
        while (g_node_state.running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            // v4.0.18: keep the RegistrationManager driving on every iteration.
            // Non-blocking: just publishes fresh inputs and wakes its worker.
            if (s_registrationManager) {
                auto tipH = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                s_registrationManager->Tick(static_cast<uint32_t>(tipH),
                                             g_node_state.running.load());
            }

            // Check if new block was found and mining template needs update
            if (g_node_state.new_block_found.load()) {
                std::cout << "[Mining] New block found, updating template..." << std::endl;

                // Determine current height for VDF/RandomX decision
                unsigned int next_height = g_chainstate.GetTip() ?
                    g_chainstate.GetTip()->nHeight + 1 : 1;

                if (vdf_miner.IsRunning()) {
                    // VDF mining mode: signal epoch change (VDF miner handles restart internally)
                    // VDF Distribution: pass current tip height so miner can decide whether to
                    // abort (new height) or continue (same height — distribution opportunity)
                    int newTipHeight = g_chainstate.GetHeight();
                    vdf_miner.OnNewBlock(newTipHeight);
                } else if (miner.IsMining()) {
                    // ========================================================================
                    // BUG #109 FIX: Stop mining and WAIT for threads to fully stop
                    // ========================================================================
                    miner.StopMining();
                    int wait_count = 0;
                    while (miner.IsMining() && wait_count < 20) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        wait_count++;
                    }
                    if (wait_count >= 20) {
                        std::cerr << "[Mining] WARNING: Mining threads slow to stop" << std::endl;
                    }
                }
                // Additional small delay to ensure any in-flight block submission completes
                std::this_thread::sleep_for(std::chrono::milliseconds(50));

                // Restart mining if appropriate (skip if paused or VDF miner handles itself)
                if (g_node_state.mining_enabled.load() && !IsInitialBlockDownload()
                    && !mining_paused_no_peers && !mining_paused_fork && !mining_paused_consensus_fork
                    && !mining_paused_tip_divergence && !vdf_miner.IsRunning()) {

                    if (shouldUseVDF(next_height)) {
                        // Switch to VDF mining (if not already running)
                        std::cout << "[Mining] Switching to VDF mining at height " << next_height << std::endl;
                        std::vector<uint8_t> pubKeyHash = wallet.GetPubKeyHash();
                        if (pubKeyHash.size() >= 20) {
                            std::array<uint8_t, 20> addr{};
                            std::copy(pubKeyHash.begin(), pubKeyHash.begin() + 20, addr.begin());
                            vdf_miner.SetMinerAddress(addr);
                        }
                        vdf_miner.Start();
                    } else {
                        // RandomX mining: rebuild template and restart
                        std::optional<CBlockTemplate> templateOpt;
                        constexpr int MAX_TEMPLATE_RETRIES = 3;
                        for (int attempt = 1; attempt <= MAX_TEMPLATE_RETRIES; attempt++) {
                            templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                            if (templateOpt) break;
                            std::cerr << "[Mining] Template build failed (attempt " << attempt << "/" << MAX_TEMPLATE_RETRIES << ")" << std::endl;
                            if (attempt < MAX_TEMPLATE_RETRIES) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                            }
                        }
                        if (templateOpt) {
                            miner.StartMining(*templateOpt);
                            std::cout << "[Mining] Resumed mining on block height " << templateOpt->nHeight << std::endl;
                        } else {
                            std::cerr << "[ERROR] Failed to build mining template after " << MAX_TEMPLATE_RETRIES << " attempts!" << std::endl;
                        }
                    }
                }

                // Clear flag
                g_node_state.new_block_found = false;
            }

            // ========================================
            // BUG #54 FIX: Deferred mining startup after IBD
            // ========================================
            // If mining was deferred due to IBD, check if we can start now
            if (mining_deferred_for_ibd && !miner.IsMining() && !vdf_miner.IsRunning()) {
                static int ibd_progress_counter = 0;
                ibd_progress_counter++;

                if (!IsInitialBlockDownload()) {
                    // IBD complete - start mining!
                    std::cout << "[5/6] IBD sync complete!" << std::endl;
                    std::cout << "[6/6] Starting mining..." << std::endl;

                    // BUG #97 FIX: Initialize mining mode AFTER sync completes (not during startup)
                    // This prevents "[MINING] Initializing dataset..." messages during wallet setup
                    if (!randomx_is_mining_mode_ready()) {
                        std::cout << "  Initializing RandomX mining mode (FULL)..." << std::endl;
                        randomx_init_mining_mode_async(rx_key, strlen(rx_key));
                        std::cout << "  [WAIT] Waiting for dataset initialization..." << std::endl;
                        auto wait_start = std::chrono::steady_clock::now();
                        while (!randomx_is_mining_mode_ready() && g_node_state.running) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            auto elapsed = std::chrono::steady_clock::now() - wait_start;
                            if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > 120) {
                                std::cerr << "  [WARN] FULL mode init timeout, starting with LIGHT mode" << std::endl;
                                break;
                            }
                        }
                        auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - wait_start).count();
                        std::cout << "  [OK] Mining mode ready (FULL, " << wait_time << "s)" << std::endl;
                    } else {
                        std::cout << "  [OK] Mining mode ready (FULL mode)" << std::endl;
                    }

                    unsigned int current_height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                    std::cout << "  [OK] Current blockchain height: " << current_height << std::endl;

                    // Ensure MIK identity is registered before mining. If this
                    // fails (wallet locked, seeds unreachable, etc.), do NOT
                    // start any miner — Handler 1's CanMine() gate in the
                    // main loop will start it once RegistrationManager
                    // reaches READY.
                    if (EnsureMIKRegistered(wallet, current_height + 1)) {
                        if (shouldUseVDF(current_height + 1)) {
                            std::cout << "  [VDF] Starting VDF mining after IBD" << std::endl;
                            std::vector<uint8_t> pubKeyHash = wallet.GetPubKeyHash();
                            if (pubKeyHash.size() >= 20) {
                                std::array<uint8_t, 20> addr{};
                                std::copy(pubKeyHash.begin(), pubKeyHash.begin() + 20, addr.begin());
                                vdf_miner.SetMinerAddress(addr);
                            }
                            vdf_miner.Start();
                            mining_deferred_for_ibd = false;
                        } else {
                            auto templateOpt = BuildMiningTemplate(blockchain, wallet, true, config.mining_address_override);
                            if (!templateOpt) {
                                // Retry up to 3 times with 1s delays
                                for (int attempt = 1; attempt <= 3 && !templateOpt; attempt++) {
                                    std::cerr << "[Mining] Template build failed, retrying (" << attempt << "/3)..." << std::endl;
                                    std::this_thread::sleep_for(std::chrono::seconds(1));
                                    templateOpt = BuildMiningTemplate(blockchain, wallet, true, config.mining_address_override);
                                }
                            }
                            if (templateOpt) {
                                miner.StartMining(*templateOpt);
                                std::cout << "  [OK] Mining started with " << mining_threads << " threads" << std::endl;
                                mining_deferred_for_ibd = false;
                            } else {
                                std::cerr << "[ERROR] Failed to build mining template after retries!" << std::endl;
                            }
                        }
                    } else {
                        std::cerr << "[Mining] MIK registration not ready after IBD — mining deferred." << std::endl;
                        std::cerr << "[Mining] Main loop will retry via RegistrationManager." << std::endl;
                        mining_deferred_for_ibd = false;
                    }
                } else if (ibd_progress_counter % 10 == 0) {
                    // Show progress every 10 seconds
                    int height = g_chainstate.GetTip() ? g_chainstate.GetTip()->nHeight : 0;
                    int peerHeight = g_node_context.peer_manager ? g_node_context.peer_manager->GetBestPeerHeight() : 0;
                    bool hasHandshakes = g_node_context.peer_manager && g_node_context.peer_manager->HasCompletedHandshakes();
                    if (peerHeight > 0 || hasHandshakes) {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "  [IBD] Progress: height=" << height
                                      << " peers_best=" << peerHeight << std::endl;

                        // Diagnostic: warn if stuck at height 0 for >10 minutes despite having peers
                        if (height == 0 && peerHeight > 0) {
                            static auto stuck_since = std::chrono::steady_clock::now();
                            static auto last_warning = std::chrono::steady_clock::time_point();
                            auto now = std::chrono::steady_clock::now();
                            auto stuck_mins = std::chrono::duration_cast<std::chrono::minutes>(now - stuck_since).count();
                            auto since_warning = std::chrono::duration_cast<std::chrono::minutes>(now - last_warning).count();
                            if (stuck_mins >= 10 && since_warning >= 5) {
                                last_warning = now;
                                int hdrHeight = g_node_context.headers_manager ? g_node_context.headers_manager->GetBestHeight() : -1;
                                int syncPeer = g_node_context.sync_coordinator ? g_node_context.sync_coordinator->GetHeadersSyncPeer() : -1;
                                std::cout << "\n  [WARN] Node stuck at height 0 for " << stuck_mins << " minutes despite having peers." << std::endl;
                                std::cout << "  [WARN] Headers height: " << hdrHeight << ", sync peer: " << syncPeer << std::endl;
                                std::cout << "  [WARN] If headers=0, the seed may not be responding to GETHEADERS." << std::endl;
                                std::cout << "  [WARN] Try these fixes:" << std::endl;
                                std::cout << "  [WARN]   1. Download bootstrap from https://github.com/dilithion/dilithion/releases" << std::endl;
                                std::cout << "  [WARN]   2. Run `dilithion-node --reset-chain` to wipe chain data (preserves wallet.dat + mik_registration.dat)" << std::endl;
                                std::cout << "  [WARN]   3. Use --addnode=138.197.68.128:8444 to connect directly to seed nodes" << std::endl;
                                std::cout << "  [WARN]   4. If in a country with internet restrictions, use a VPN\n" << std::endl;
                            }
                        }
                    } else {
                        if (g_verbose.load(std::memory_order_relaxed)) {
                            size_t peerCount = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectionCount() : 0;
                            std::cout << "  [IBD] Waiting for peer handshakes... (connections=" << peerCount << ")" << std::endl;
                        }
                    }
                }
            }

            // Periodic tasks
            // - Update mempool
            // - Process P2P messages
            // - Update mining stats
            // - Block download coordination (IBD)

            // ========================================
            // BLOCK DOWNLOAD COORDINATION (IBD)
            // ========================================
            // Phase 5.1: Use IBD Coordinator instead of inline logic.
            // This encapsulates all IBD logic (backoff, queueing, fetching, retries).
            // Phase 6 PR6.5a fix-up 2026-04-27: route Tick() through
            // ISyncCoordinator. Post v4.3.4 cut, this always routes to
            // CIbdCoordinator::Tick via CIbdCoordinatorAdapter (the
            // alternate port::CPeerManager Tick was retired in Block 7).
            if (g_node_context.sync_coordinator) {
                g_node_context.sync_coordinator->Tick();
            }

            // v4.3.2 M1 fix: poll chainstate's UTXO/chain rebuild flags and
            // surface auto_rebuild + shutdown if either fires. Lifted out of
            // CIbdCoordinator::Tick so it runs in BOTH legacy (flag=0) and
            // port (flag=1) sync-coordinator configurations. Single helper,
            // single call site, single point of truth for the recovery path.
            // See dilv-node.cpp main loop for full context.
            //
            // v4.3.2 M1 H1 (Layer-3 review 2026-05-04): pass config.datadir,
            // NOT g_chainParams->dataDir — chainparams field ignores
            // --datadir=PATH; startup marker detection reads config.datadir.
            // Divergent paths silently sever recovery on non-default datadirs.
            Dilithion::MaybeTriggerChainRebuild(g_chainstate, config.datadir, &g_node_state.running);

            // v4.4 Block 8: start the periodic integrity monitor once IBD has
            // fully exited (g_utxo_sync_enabled == true). Lifecycle gate per
            // RT F-4 — the monitor would otherwise see read-merged LevelDB
            // state during IBD-tail that masks partial-write durability gaps.
            // Construction happened post-startup-integrity-check above; we just
            // need to flip the start-flag once the IBD exit signal fires.
            if (integrity_monitor && !integrity_monitor_started &&
                g_utxo_sync_enabled.load(std::memory_order_relaxed)) {
                integrity_monitor->Start();
                integrity_monitor_started = true;
                std::cout << "[v4.4] ChainstateIntegrityMonitor started "
                          << "(6h cycle, last 500 blocks, snapshot-then-walk)" << std::endl;
            }

            // IBD DEBUG: Log that Tick() returned and main loop continues
            static int main_loop_count = 0;
            if (g_verbose.load(std::memory_order_relaxed) && (++main_loop_count <= 5 || main_loop_count % 60 == 0)) {
                std::cerr << "[MAIN-LOOP-DEBUG] Tick() returned, loop iteration #" << main_loop_count << std::endl;
            }

            // Print mining stats every 10 seconds if mining
            // BUG #181 FIX: Use miner.IsMining() instead of config.start_mining
            // config.start_mining is only true for --mine flag. If mining was started
            // via RPC (startmining) or wallet UI, template refresh and mempool tx
            // inclusion never fired, causing transactions to never be mined.
            if (miner.IsMining() && ++counter % 10 == 0) {
                auto stats = miner.GetStats();
                std::cout << "[Mining] Hash rate: " << miner.GetHashRate() << " H/s, "
                         << "Total hashes: " << stats.nHashesComputed << std::endl;

                // Update mining metrics for Prometheus
                g_metrics.mining_active.store(miner.IsMining() ? 1 : 0);
                g_metrics.hashrate.store(miner.GetHashRate());
                g_metrics.hashes_total.store(stats.nHashesComputed);

                // ========================================================================
                // BUG #109 FIX: Periodic template refresh to include mempool transactions
                // ========================================================================
                // Previously, templates were only rebuilt when a new block was found.
                // This caused transactions to never be mined because the miner kept
                // using stale templates without mempool transactions.
                //
                // Now we refresh the template every 10 seconds if:
                // 1. Mining is active
                // 2. Mempool has transactions
                // 3. We're not in IBD
                //
                // This is similar to Bitcoin Core's getblocktemplate behavior.
                // Template refresh is active: rebuilds on mempool changes and
                // EDA gap detection (every 60s when gap > 6 blocks).
                if (miner.IsMining()) {
                    bool shouldRefresh = false;

                    // Refresh for mempool transactions
                    CTxMemPool* mempool = g_mempool.load();
                    if (mempool && mempool->Size() > 0) {
                        std::cout << "[Mining] Mempool has " << mempool->Size()
                                  << " tx(s), refreshing template..." << std::endl;
                        shouldRefresh = true;
                    }

                    // EDA template refresh: rebuild template every 60s so EDA difficulty
                    // steps down as the gap grows. Without this, the miner uses stale nBits
                    // from when the template was first built and never benefits from further
                    // EDA reductions.
                    static auto lastEdaRefresh = std::chrono::steady_clock::now();
                    if (!shouldRefresh && Dilithion::g_chainParams) {
                        int64_t blockTime = static_cast<int64_t>(Dilithion::g_chainParams->blockTime);
                        int64_t edaThreshold = 6 * blockTime;  // Same as EDA_THRESHOLD_BLOCKS * blockTime
                        CBlockIndex* pTip = g_chainstate.GetTip();
                        if (pTip) {
                            int64_t gap = static_cast<int64_t>(std::time(nullptr)) - static_cast<int64_t>(pTip->nTime);
                            auto timeSinceRefresh = std::chrono::steady_clock::now() - lastEdaRefresh;
                            if (gap > edaThreshold && timeSinceRefresh > std::chrono::seconds(60)) {
                                shouldRefresh = true;
                                lastEdaRefresh = std::chrono::steady_clock::now();
                            }
                        }
                    }

                    if (shouldRefresh) {
                        auto templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                        if (templateOpt) {
                            miner.UpdateTemplate(*templateOpt);
                        }
                    }
                }

                // ========================================================================
                // BUG #49 + BUG #180: Solo mining prevention with 120s grace period
                // ========================================================================
                // After IBD completes, if peers disconnect:
                // - Start 120 second countdown
                // - If no peer reconnects within 120s, auto-pause mining
                // - When peer reconnects, auto-resume mining
                // This prevents accidentally creating a fork while disconnected.
                size_t peer_count = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectionCount() : 0;
                auto now = std::chrono::steady_clock::now();

                if (peer_count == 0) {
                    // No peers - check if we need to start countdown or pause mining
                    if (no_peers_since == std::chrono::steady_clock::time_point{}) {
                        // Just lost peers - start the countdown
                        no_peers_since = now;
                        if (miner.IsMining()) {
                            std::cout << "[Mining] WARNING: No connected peers - " << SOLO_MINING_GRACE_PERIOD_SECONDS
                                      << "s grace period started" << std::endl;
                        }
                    } else if (miner.IsMining() && !mining_paused_no_peers) {
                        // Check if grace period expired
                        auto seconds_without_peers = std::chrono::duration_cast<std::chrono::seconds>(now - no_peers_since).count();

                        if (seconds_without_peers >= SOLO_MINING_GRACE_PERIOD_SECONDS) {
                            // Grace period expired - pause mining
                            std::cout << "[Mining] PAUSING: No peers for " << seconds_without_peers << " seconds" << std::endl;
                            std::cout << "[Mining] Mining will resume automatically when a peer connects" << std::endl;
                            if (vdf_miner.IsRunning()) vdf_miner.Stop();
                            miner.StopMining();
                            mining_paused_no_peers = true;
                        } else {
                            // Still in grace period - show countdown every 30 seconds
                            int remaining = SOLO_MINING_GRACE_PERIOD_SECONDS - static_cast<int>(seconds_without_peers);
                            if ((remaining % 30 == 0 || remaining <= 10) && remaining != last_remaining_logged) {
                                std::cout << "[Mining] WARNING: No peers - mining will pause in " << remaining << "s" << std::endl;
                                last_remaining_logged = remaining;
                            }
                        }
                    }
                } else {
                    // Have peers - reset countdown and resume if paused
                    if (no_peers_since != std::chrono::steady_clock::time_point{}) {
                        if (miner.IsMining() || mining_paused_no_peers) {
                            std::cout << "[Mining] Peer connected - grace period cancelled" << std::endl;
                        }
                        no_peers_since = std::chrono::steady_clock::time_point{};
                        last_remaining_logged = -1;
                    }

                    if (mining_paused_no_peers) {
                        // Was paused due to no peers - resume mining
                        std::cout << "[Mining] Peer connectivity restored - resuming mining" << std::endl;
                        mining_paused_no_peers = false;

                        // Rebuild template and restart mining
                        unsigned int resume_height = g_chainstate.GetTip() ?
                            g_chainstate.GetTip()->nHeight + 1 : 1;
                        if (shouldUseVDF(resume_height) && !vdf_miner.IsRunning()) {
                            vdf_miner.Start();
                            std::cout << "[Mining] VDF mining resumed" << std::endl;
                        } else if (!shouldUseVDF(resume_height)) {
                            auto templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                            if (templateOpt) {
                                miner.StartMining(*templateOpt);
                                std::cout << "[Mining] Mining resumed with fresh template" << std::endl;
                            } else {
                                std::cerr << "[Mining] ERROR: Failed to build template for resume" << std::endl;
                            }
                        }
                    }
                }

                // ========================================================================
                // Fork detection: Pause RandomX mining during fork resolution
                // ========================================================================
                // When a competing chain is detected (headers with unknown parent),
                // pause RandomX mining to avoid wasting hashpower on potentially orphaned blocks.
                // VDF miner is NOT stopped: VDF blocks are deterministic (no wasted work),
                // sequential (can't parallelize), and can help resolve the fork by advancing
                // the chain. Stopping VDF miners during fork detection caused chain stalls
                // when multiple VDF miners produced simultaneous blocks.
                if (g_node_context.fork_detected.load() && miner.IsMining() && !mining_paused_fork) {
                    std::cout << "[Mining] PAUSING RandomX: Fork detected - resolving competing chain..." << std::endl;
                    std::cout << "[Mining] Mining will resume automatically when fork is resolved" << std::endl;
                    miner.StopMining();
                    mining_paused_fork = true;
                }

                // Resume mining when fork is resolved
                if (mining_paused_fork && !g_node_context.fork_detected.load()) {
                    std::cout << "[Mining] Fork resolved - resuming mining" << std::endl;
                    mining_paused_fork = false;

                    // Rebuild template and restart mining
                    unsigned int fork_resume_height = g_chainstate.GetTip() ?
                        g_chainstate.GetTip()->nHeight + 1 : 1;
                    if (shouldUseVDF(fork_resume_height) && !vdf_miner.IsRunning()) {
                        vdf_miner.Start();
                        std::cout << "[Mining] VDF mining resumed after fork resolution" << std::endl;
                    } else if (!shouldUseVDF(fork_resume_height)) {
                        auto templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                        if (templateOpt) {
                            miner.StartMining(*templateOpt);
                            std::cout << "[Mining] Mining resumed with fresh template after fork resolution" << std::endl;
                        } else {
                            std::cerr << "[Mining] ERROR: Failed to build template after fork resolution" << std::endl;
                        }
                    }
                }
            }

            // ========================================================================
            // Consensus fork detection: Solo mining on private fork
            // ========================================================================
            // Detects when we've mined many consecutive blocks with no blocks from
            // other miners - a strong signal of a consensus fork. Our blocks are
            // valid locally but rejected by the network, causing wasted work.
            // Runs every iteration (cheap hash comparison, heavy work only on tip change).
            // Placed OUTSIDE the miner.IsMining() block so resume works when paused.
            {
                CBlockIndex* tipIndex = g_chainstate.GetTip();
                if (tipIndex && g_node_state.mining_enabled.load()) {
                    uint256 tipHash = tipIndex->GetBlockHash();

                    if (tipHash != last_checked_tip_hash) {
                        last_checked_tip_hash = tipHash;

                        // Read the tip block to identify the miner
                        CBlock tipBlock;
                        if (blockchain.ReadBlock(tipHash, tipBlock)) {
                            CBlockValidator validator;
                            std::vector<CTransactionRef> transactions;
                            std::string error;

                            if (validator.DeserializeBlockTransactions(tipBlock, transactions, error)
                                && !transactions.empty() && !transactions[0]->vout.empty()) {

                                std::vector<uint8_t> tipMinerPkh = WalletCrypto::ExtractPubKeyHash(
                                    transactions[0]->vout[0].scriptPubKey);

                                // Determine our mining pubkey hash
                                std::vector<uint8_t> ourPkh;
                                if (!config.mining_address_override.empty()) {
                                    CDilithiumAddress addr;
                                    addr.SetString(config.mining_address_override);
                                    const std::vector<uint8_t>& addrData = addr.GetData();
                                    if (addrData.size() >= 21) {
                                        ourPkh.assign(addrData.begin() + 1, addrData.begin() + 21);
                                    }
                                } else {
                                    ourPkh = wallet.GetPubKeyHash();
                                }

                                if (!tipMinerPkh.empty() && !ourPkh.empty()) {
                                    bool is_self_mined = (tipMinerPkh == ourPkh);

                                    // Rolling window: track self-mined ratio over last N blocks
                                    recent_blocks.push_back({is_self_mined});
                                    if (recent_blocks.size() > RECENT_BLOCK_WINDOW) {
                                        recent_blocks.pop_front();
                                    }

                                    // Check rolling window ratio (independent of sequential counter)
                                    if (recent_blocks.size() >= 10) {
                                        int self_count = 0;
                                        for (const auto& rb : recent_blocks) {
                                            if (rb.self_mined) self_count++;
                                        }
                                        float ratio = static_cast<float>(self_count) / static_cast<float>(recent_blocks.size());
                                        size_t peer_cnt = g_node_context.peer_manager ? g_node_context.peer_manager->GetConnectionCount() : 0;

                                        if (ratio >= SOLO_PAUSE_RATIO && peer_cnt > 0
                                            && !mining_paused_consensus_fork) {
                                            std::cout << std::endl;
                                            std::cout << "[Mining] WARNING: " << static_cast<int>(ratio * 100)
                                                      << "% of last " << recent_blocks.size()
                                                      << " blocks are self-mined (with " << peer_cnt << " peers)" << std::endl;
                                            std::cout << "[Mining] This strongly suggests a fork - pausing mining" << std::endl;
                                            std::cout << std::endl;
                                            if (miner.IsMining()) miner.StopMining();
                                            mining_paused_consensus_fork = true;
                                        } else if (ratio >= SOLO_WARN_RATIO && peer_cnt > 0
                                                   && !solo_warning_shown) {
                                            std::cout << "[Mining] WARNING: " << static_cast<int>(ratio * 100)
                                                      << "% of last " << recent_blocks.size()
                                                      << " blocks are self-mined" << std::endl;
                                        }
                                    }

                                    if (is_self_mined) {
                                        // Sequential counter (existing logic)
                                        consecutive_self_mined++;

                                        if (consecutive_self_mined >= SOLO_PAUSE_THRESHOLD
                                            && !mining_paused_consensus_fork) {
                                            // CRITICAL: Auto-pause mining
                                            std::cout << std::endl;
                                            std::cout << "[Mining] ================================================" << std::endl;
                                            std::cout << "[Mining] CRITICAL: " << consecutive_self_mined
                                                      << " consecutive blocks mined solo" << std::endl;
                                            std::cout << "[Mining] You appear to be on a CONSENSUS FORK" << std::endl;
                                            std::cout << "[Mining] Your blocks are NOT being accepted by the network" << std::endl;
                                            std::cout << "[Mining] ================================================" << std::endl;
                                            std::cout << "[Mining] Mining PAUSED to prevent further wasted work" << std::endl;
                                            std::cout << "[Mining] Please update to the latest version at dilithion.org" << std::endl;
                                            std::cout << "[Mining] Mining will resume when blocks from other miners arrive" << std::endl;
                                            std::cout << "[Mining] ================================================" << std::endl;
                                            std::cout << std::endl;
                                            if (miner.IsMining()) miner.StopMining();
                                            mining_paused_consensus_fork = true;
                                        } else if (consecutive_self_mined >= SOLO_WARNING_THRESHOLD
                                                   && !solo_warning_shown) {
                                            // Warning: unusual solo mining pattern
                                            std::cout << std::endl;
                                            std::cout << "[Mining] WARNING: You have mined " << consecutive_self_mined
                                                      << " consecutive blocks with no blocks from other miners" << std::endl;
                                            std::cout << "[Mining] This is unusual and may indicate a consensus fork" << std::endl;
                                            std::cout << "[Mining] Ensure you are running the latest version from dilithion.org" << std::endl;
                                            std::cout << std::endl;
                                            solo_warning_shown = true;
                                        }
                                    } else {
                                        // Another miner's block - healthy network activity
                                        if (consecutive_self_mined >= SOLO_WARNING_THRESHOLD) {
                                            std::cout << "[Mining] Block from another miner received - solo mining counter reset" << std::endl;
                                        }
                                        consecutive_self_mined = 0;
                                        solo_warning_shown = false;

                                        // Resume mining if paused due to consensus fork
                                        if (mining_paused_consensus_fork) {
                                            std::cout << std::endl;
                                            std::cout << "[Mining] ================================================" << std::endl;
                                            std::cout << "[Mining] Block from another miner detected!" << std::endl;
                                            std::cout << "[Mining] Consensus fork appears resolved - resuming mining" << std::endl;
                                            std::cout << "[Mining] ================================================" << std::endl;
                                            std::cout << std::endl;
                                            mining_paused_consensus_fork = false;

                                            unsigned int resume_height = tipIndex->nHeight + 1;
                                            if (shouldUseVDF(resume_height) && !vdf_miner.IsRunning()) {
                                                vdf_miner.Start();
                                                std::cout << "[Mining] VDF mining resumed after consensus fork resolved" << std::endl;
                                            } else if (!shouldUseVDF(resume_height)) {
                                                auto templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                                                if (templateOpt) {
                                                    miner.StartMining(*templateOpt);
                                                    std::cout << "[Mining] Mining resumed after consensus fork resolved" << std::endl;
                                                } else {
                                                    std::cerr << "[Mining] ERROR: Failed to build template for consensus fork resume" << std::endl;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ========================================================================
            // Tip Divergence Detection: Compare our chain tip vs peers' chain tips
            // ========================================================================
            // Detects when our tip hash diverges from all connected peers, even when
            // peers are connected and some blocks arrive. This catches the case where
            // we're mining on a minority fork (e.g. Captain Brown's scenario: 3 peers
            // connected, 26 blocks mined, 0 on main chain).
            {
                auto now_div = std::chrono::steady_clock::now();
                auto secs_since_check = std::chrono::duration_cast<std::chrono::seconds>(
                    now_div - last_divergence_check).count();

                if (secs_since_check >= TIP_CHECK_INTERVAL_S
                    && g_node_state.mining_enabled.load()
                    && !IsInitialBlockDownload()) {

                    last_divergence_check = now_div;

                    CBlockIndex* pTip = g_chainstate.GetTip();
                    if (pTip && g_node_context.peer_manager) {
                        uint256 our_hash = pTip->GetBlockHash();
                        int our_height = pTip->nHeight;

                        auto connected_peers = g_node_context.peer_manager->GetConnectedPeers();
                        int peers_with_data = 0;
                        int peers_at_our_level = 0;
                        int peers_agree = 0;

                        for (const auto& peer : connected_peers) {
                            if (peer->best_known_hash.IsNull()) continue;

                            // Skip peers with stale tip data
                            auto tip_age = std::chrono::duration_cast<std::chrono::seconds>(
                                now_div - peer->last_tip_update).count();
                            if (tip_age > TIP_FRESHNESS_S) continue;

                            peers_with_data++;

                            // Only compare peers within ±2 of our height
                            if (std::abs(peer->best_known_height - our_height) <= 2) {
                                peers_at_our_level++;

                                if (peer->best_known_hash == our_hash) {
                                    peers_agree++;
                                } else {
                                    // Check if peer is slightly behind us on the same chain
                                    CBlockIndex* pidx = g_chainstate.GetBlockIndex(peer->best_known_hash);
                                    if (pidx && pidx->nHeight <= pTip->nHeight) {
                                        CBlockIndex* atHeight = pTip->GetAncestor(pidx->nHeight);
                                        if (atHeight == pidx) {
                                            peers_agree++;
                                        }
                                    }
                                }
                            }
                        }

                        // Only assess if we have meaningful data
                        if (peers_with_data >= 1 && peers_at_our_level >= 1) {
                            if (peers_agree == 0) {
                                // DIVERGENCE: No peer at our height shares our chain
                                if (divergence_since == std::chrono::steady_clock::time_point{}) {
                                    divergence_since = now_div;
                                }
                                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                    now_div - divergence_since).count();

                                if (elapsed >= TIP_DIVERGE_PAUSE_S && !mining_paused_tip_divergence) {
                                    std::cout << std::endl;
                                    std::cout << "[Mining] ================================================" << std::endl;
                                    std::cout << "[Mining] CRITICAL: Chain tip differs from ALL peers" << std::endl;
                                    std::cout << "[Mining] for " << elapsed << " seconds (" << peers_at_our_level
                                              << " peers at height ~" << our_height << ", 0 agree)" << std::endl;
                                    std::cout << "[Mining] You appear to be mining on a MINORITY FORK" << std::endl;
                                    std::cout << "[Mining] Mined blocks will NOT be accepted by the network" << std::endl;
                                    std::cout << "[Mining] ================================================" << std::endl;
                                    std::cout << "[Mining] Mining PAUSED - will resume when chain agreement is restored" << std::endl;
                                    std::cout << "[Mining] Please check your version at dilithion.org" << std::endl;
                                    std::cout << "[Mining] ================================================" << std::endl;
                                    std::cout << std::endl;

                                    // Only stop RandomX miner during tip divergence.
                                    // VDF miner continues: deterministic blocks can resolve
                                    // the divergence by advancing the chain.
                                    if (miner.IsMining()) miner.StopMining();
                                    mining_paused_tip_divergence = true;
                                    g_node_context.tip_diverged.store(true);

                                } else if (elapsed >= TIP_DIVERGE_WARN_S && !tip_divergence_warned) {
                                    std::cout << std::endl;
                                    std::cout << "[Mining] WARNING: No peers share your chain tip for "
                                              << elapsed << " seconds" << std::endl;
                                    std::cout << "[Mining] " << peers_at_our_level << " peer(s) at height ~"
                                              << our_height << " have different chain tips" << std::endl;
                                    std::cout << "[Mining] If this persists, mining will be paused in "
                                              << (TIP_DIVERGE_PAUSE_S - elapsed) << "s" << std::endl;
                                    std::cout << std::endl;
                                    tip_divergence_warned = true;
                                }
                            } else {
                                // Agreement found - clear divergence state
                                if (mining_paused_tip_divergence) {
                                    std::cout << std::endl;
                                    std::cout << "[Mining] ================================================" << std::endl;
                                    std::cout << "[Mining] Peer chain agreement restored! (" << peers_agree
                                              << "/" << peers_at_our_level << " peers agree)" << std::endl;
                                    std::cout << "[Mining] Resuming mining..." << std::endl;
                                    std::cout << "[Mining] ================================================" << std::endl;
                                    std::cout << std::endl;

                                    mining_paused_tip_divergence = false;
                                    g_node_context.tip_diverged.store(false);

                                    unsigned int resume_height = pTip->nHeight + 1;
                                    if (shouldUseVDF(resume_height) && !vdf_miner.IsRunning()) {
                                        vdf_miner.Start();
                                        std::cout << "[Mining] VDF mining resumed after tip divergence resolved" << std::endl;
                                    } else if (!shouldUseVDF(resume_height) && g_node_state.mining_enabled.load()) {
                                        auto templateOpt = BuildMiningTemplate(blockchain, wallet, false, config.mining_address_override);
                                        if (templateOpt) {
                                            miner.StartMining(*templateOpt);
                                            std::cout << "[Mining] Mining resumed after tip divergence resolved" << std::endl;
                                        }
                                    }
                                }
                                divergence_since = std::chrono::steady_clock::time_point{};
                                tip_divergence_warned = false;
                            }
                        }
                    }
                }
            }
        }

        // Shutdown
        std::cout << std::endl;
        std::cout << "[Shutdown] Initiating graceful shutdown..." << std::endl;

        // Clear ibd_coordinator pointer before local variable goes out of scope
        g_node_context.ibd_coordinator = nullptr;
        // Phase 6 PR6.5a: also reset the sync_coordinator adapter (it holds
        // a reference to the about-to-go-out-of-scope ibd_coordinator).
        g_node_context.sync_coordinator.reset();

        if (vdf_miner.IsRunning()) {
            std::cout << "[Shutdown] Stopping VDF miner..." << std::flush;
            vdf_miner.Stop();
            std::cout << " done" << std::endl;
        }
        if (miner.IsMining()) {
            std::cout << "[Shutdown] Stopping mining..." << std::flush;
            miner.StopMining();
            std::cout << " done" << std::endl;
        }
        if (vdf_available) {
            vdf::shutdown();
        }
        g_node_context.vdf_miner = nullptr;
        g_node_context.cooldown_tracker = nullptr;

        // REMOVED: CMessageProcessorQueue shutdown (no longer used)

        // BUG #275: Stop resource monitor
        if (g_resource_monitor) {
            resource_monitor.Stop();
            g_resource_monitor = nullptr;
        }

        std::cout << "[Shutdown] Stopping P2P server..." << std::flush;
        // Phase 5: Stop CConnman (handles all socket cleanup internally)
        if (g_node_context.connman) {
            g_node_context.connman->Stop();
        }
        // p2p_socket removed - CConnman handles socket cleanup
        std::cout << " done" << std::endl;

        // Remove UPnP port mapping on shutdown
        if (connman_opts.upnp_enabled) {
            std::cout << "[Shutdown] Removing UPnP port mapping..." << std::flush;
            UPnP::UnmapPort(connman_opts.nListenPort);
            std::cout << " done" << std::endl;
        }

        // Phase 3.2: Shutdown batch signature verifier
        std::cout << "[Shutdown] Stopping batch signature verifier..." << std::endl;
        ShutdownSignatureVerifier();

        // Save trust scores before shutdown
        if (g_node_context.trust_manager) {
            std::string trust_path = config.datadir + "/dna_trust";
            if (g_node_context.trust_manager->save(trust_path)) {
                std::cout << "[Shutdown] Trust scores saved ("
                          << g_node_context.trust_manager->count() << " identities)" << std::endl;
            }
        }

        // Phase 1.2: Shutdown NodeContext (Bitcoin Core pattern)
        std::cout << "[Shutdown] NodeContext shutdown complete" << std::endl;
        g_node_context.Shutdown();
        
        // Phase 5: p2p_thread and p2p_recv_thread removed - handled by CConnman
        // Only join maintenance thread
        if (p2p_maint_thread.joinable()) {
            p2p_maint_thread.join();
        }

        // Clear global P2P networking pointers (NW-005)
        // P0-5 FIX: Use .store() for atomic pointers
        g_message_processor.store(nullptr);

        // Clean up transaction relay manager (P0-5 FIX: use load/store for atomic)
        delete g_tx_relay_manager.load();
        g_tx_relay_manager.store(nullptr);

        // Clear peer manager pointer (ownership in g_node_context)
        // REMOVED: g_peer_manager cleanup - no longer used

        std::cout << "[Shutdown] Stopping RPC server..." << std::flush;
        rpc_server.Stop();

        // DFMP: Shutdown Fair Mining Protocol subsystem (persist heat trackers)
        std::cout << "  Shutting down DFMP..." << std::endl;
        DFMP::ShutdownDFMP(config.datadir, g_chainstate.GetHeight());

        std::cout << "  Closing UTXO database..." << std::endl;
        utxo_set.Close();

        std::cout << "  Closing blockchain database..." << std::endl;
        blockchain.Close();

        // Phase 1.2: IBD managers are owned by NodeContext and cleaned up by Shutdown()
        // No manual cleanup needed - NodeContext.Shutdown() handles it

        std::cout << "  Cleaning up chain parameters..." << std::endl;
        delete Dilithion::g_chainParams;
        Dilithion::g_chainParams = nullptr;

        std::cout << std::endl;
        std::cout << "Dilithion node stopped cleanly" << std::endl;

    } catch (const std::exception& e) {
        // Phase 2.2: Enhanced crash diagnostics
        LogPrintf(ALL, ERROR, "===========================================================");
        LogPrintf(ALL, ERROR, "FATAL ERROR: Unhandled exception in main()");
        LogPrintf(ALL, ERROR, "Exception type: std::exception");
        LogPrintf(ALL, ERROR, "Exception message: %s", e.what());
        
        // Log stack trace in debug builds
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);  // Skip this frame
            LogPrintf(ALL, ERROR, "Stack trace:");
            LogPrintf(ALL, ERROR, "%s", stackTrace.c_str());
        } catch (...) {
            LogPrintf(ALL, ERROR, "Failed to capture stack trace");
        }
        #endif
        
        LogPrintf(ALL, ERROR, "===========================================================");
        
        // Also print to stderr for immediate visibility
        std::cerr << "\n===========================================================" << std::endl;
        std::cerr << "FATAL ERROR: Unhandled exception in main()" << std::endl;
        std::cerr << "Exception type: std::exception" << std::endl;
        std::cerr << "Exception message: " << e.what() << std::endl;
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);
            std::cerr << "\nStack trace:\n" << stackTrace << std::endl;
        } catch (...) {
            std::cerr << "Failed to capture stack trace" << std::endl;
        }
        #endif
        std::cerr << "===========================================================" << std::endl;

        // Cleanup on error (P0-5 FIX: use load/store for atomic)
        auto* relay_mgr = g_tx_relay_manager.load();
        if (relay_mgr) {
            delete relay_mgr;
            g_tx_relay_manager.store(nullptr);
        }
        // Phase 1.2: All cleanup handled by NodeContext.Shutdown()
        // No manual cleanup needed

        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        // Shutdown logging system
        CLogger::GetInstance().Shutdown();

        return 1;
    } catch (...) {
        // Phase 2.2: Catch all other exceptions (non-std::exception)
        LogPrintf(ALL, ERROR, "===========================================================");
        LogPrintf(ALL, ERROR, "FATAL ERROR: Unknown exception in main()");
        LogPrintf(ALL, ERROR, "Exception type: unknown (not std::exception)");
        
        // Log stack trace in debug builds
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);  // Skip this frame
            LogPrintf(ALL, ERROR, "Stack trace:");
            LogPrintf(ALL, ERROR, "%s", stackTrace.c_str());
        } catch (...) {
            LogPrintf(ALL, ERROR, "Failed to capture stack trace");
        }
        #endif
        
        LogPrintf(ALL, ERROR, "===========================================================");
        
        // Also print to stderr for immediate visibility
        std::cerr << "\n===========================================================" << std::endl;
        std::cerr << "FATAL ERROR: Unknown exception in main()" << std::endl;
        std::cerr << "Exception type: unknown (not std::exception)" << std::endl;
        #ifdef DEBUG
        try {
            std::string stackTrace = GetStackTrace(1);
            std::cerr << "\nStack trace:\n" << stackTrace << std::endl;
        } catch (...) {
            std::cerr << "Failed to capture stack trace" << std::endl;
        }
        #endif
        std::cerr << "===========================================================" << std::endl;

        // Cleanup on error (P0-5 FIX: use load/store for atomic)
        auto* relay_mgr = g_tx_relay_manager.load();
        if (relay_mgr) {
            delete relay_mgr;
            g_tx_relay_manager.store(nullptr);
        }
        // Phase 1.2: All cleanup handled by NodeContext.Shutdown()
        if (Dilithion::g_chainParams) {
            delete Dilithion::g_chainParams;
            Dilithion::g_chainParams = nullptr;
        }

        // Shutdown logging system
        CLogger::GetInstance().Shutdown();

        return 1;
    }

    // Shutdown logging system on successful exit
    LogPrintf(ALL, INFO, "Dilithion node shutting down normally");
    CLogger::GetInstance().Shutdown();

    return 0;
}
