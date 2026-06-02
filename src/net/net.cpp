// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/net.h>
#include <set>
#include <util/error_format.h>  // UX: Better error messages
#include <net/connection_quality.h>  // Network: Connection quality metrics
#include <net/partition_detector.h>  // Network: Partition detection
#include <consensus/params.h>
#include <consensus/chain.h>  // For CChainState
#include <net/tx_relay.h>
#include <net/banman.h>  // For MisbehaviorType
#include <net/features.h>  // Feature flags system
#include <core/node_context.h>  // Phase 1.2: NodeContext for global state
#include <net/connman.h>  // Phase 5: For CConnman::PushMessage
#include <net/node.h>     // For CNode (genesis mismatch IP tracking)
#include <net/headers_manager.h>  // For CHeadersManager (IBD check)
#include <util/strencodings.h>
#include <util/time.h>
#include <util/logging.h>  // Bitcoin Core-style logging
#include <core/chainparams.h>
#include <node/mempool.h>
#include <node/utxo_set.h>
#include <consensus/tx_validation.h>
#include <consensus/chain.h>  // BUG #50 FIX: For g_chainstate.GetHeight()
#include <node/genesis.h>     // P2-3: For GetGenesisHash() validation
#include <net/block_fetcher.h>  // BUG #68 FIX: For BlockFetcher peer disconnect notification
// REMOVED: #include <net/node_state.h> - CNodeStateManager replaced by CPeerManager
// REMOVED: #include <net/message_queue.h> - CMessageProcessorQueue was unused
#include <random>
#include <thread>   // BUG #91: For std::this_thread::sleep_for
#include <chrono>   // BUG #91: For std::chrono::milliseconds
#include <cstring>
#include <iostream>
#include <sstream>

// Platform-specific socket headers for error codes (WSAETIMEDOUT, EAGAIN, etc.)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// Undefine Windows macros that conflict with our method names
#undef SendMessage
#else
#include <errno.h>
#include <netdb.h>      // For gethostname, getaddrinfo
#include <unistd.h>     // For gethostname
#include <arpa/inet.h>  // For inet_ntop
#endif

// NET-003 FIX: Define consensus limits to prevent integer overflow in vector resize
// These prevent DoS attacks via malicious size values causing heap corruption
// Note: vtx is a byte vector (serialized tx data), so this limits BYTES not tx count.
// BUG-003 follow-up: references Consensus::MAX_BLOCK_SIZE directly so the P2P
// receive cap can never drift from the consensus block-size limit.
static const uint64_t MAX_BLOCK_VTX_BYTES = static_cast<uint64_t>(Consensus::MAX_BLOCK_SIZE);
static const uint64_t MAX_TX_INPUTS = 10000;            // Max inputs per transaction
static const uint64_t MAX_TX_OUTPUTS = 10000;           // Max outputs per transaction
static const uint64_t MAX_SCRIPT_SIZE = 20000;          // Max script size (raised for Dilithium sigs)

// P2-1 FIX: Rate limiting for GETDATA messages (DoS protection)
// Limits: 50 GETDATA messages per second per peer (increased from 10 for IBD sync)
static std::map<int, std::vector<int64_t>> g_peer_getdata_timestamps;
static std::mutex cs_getdata_rate;
static const size_t MAX_GETDATA_PER_SECOND = 50;

// P3-N2 FIX: Rate limiting for HEADERS messages (DoS protection)
// BUG #178 FIX: Increased from 3 to 10 per second
// During IBD/sync, peers legitimately send many header batches in response to
// GETHEADERS. 3/sec was too aggressive and caused peers to be banned mid-sync.
// 10/sec allows for fast sync while still protecting against DoS floods.
static std::map<int, std::vector<int64_t>> g_peer_headers_timestamps;
static std::mutex cs_headers_rate;
static const size_t MAX_HEADERS_PER_SECOND = 10;

// P2-2 FIX: Per-IP connection cooldown to prevent rapid reconnection DoS
// Prevents attackers from exhausting connection slots via reconnection churn
static std::map<std::string, int64_t> g_last_connection_attempt;
static std::mutex cs_connection_cooldown;
static const int64_t CONNECTION_COOLDOWN_SECONDS = 30;

// Per-connection GETDATA deduplication: track recently-served block hashes per peer
// If a peer re-requests blocks we already served ON THIS CONNECTION, increment misbehavior.
// Legitimate reconnecting peers get a fresh slate (new peer_id = new connection).
static std::map<int, std::set<uint256>> g_peer_served_blocks;
static std::mutex cs_served_blocks;
static const size_t MAX_SERVED_BLOCKS_TRACK = 500;  // Track last N served blocks per peer
static const int DUPLICATE_GETDATA_PENALTY = 5;     // Penalize re-requesting already-served blocks
static const int MAX_DEDUP_BATCH_PENALTY = 20;      // Cap per-batch penalty so one IBD retry can't trigger ban
static const int MAX_DEDUP_STRIKES = 3;             // Disconnect after this many duplicate GETDATA batches
static std::map<int, int> g_peer_dedup_strikes;      // Per-peer strike counter

// dilv-dedup-livelock-fix Part B (seed-side defense-in-depth).
// The old behavior at the "Skip already-served blocks" continue was PERMANENT STARVATION:
// a peer that re-requested an already-served block was never re-served and, after
// MAX_DEDUP_STRIKES *monotonic* strikes, force-disconnected. That bit honest IBD clients
// whose async validation lagged the wire by ~1s (the livelock this mission fixes) and the
// legitimate VDF-divergence parent re-requests (ibd_coordinator.cpp:2057/1657). Part A fixes
// the client root cause; Part B softens the seed so any residual re-request degrades to
// BOUNDED wasted bandwidth, not a forced disconnect + IBD stall — while still bounding a
// hostile peer that deliberately rotates hashes to amplify re-send bandwidth (red-team MED-2).
static const int64_t RESEND_COOLDOWN_SECONDS = 2;    // <=1 re-send per (peer,blockhash) per this window
static const int64_t RESEND_BUDGET_WINDOW_SECONDS = 60;
// L-b: this is the NUMBER OF WORST-CASE BLOCKS that fit in the per-window byte budget,
// i.e. a budget-derivation input — NOT a re-send COUNT cap (more smaller real blocks may
// re-send before the byte budget binds). Named accordingly.
// L-a: lowered 16 -> 8, halving the aggregate re-send ceiling (64 -> 32 MiB/60s).
static const int RESEND_BUDGET_BLOCK_EQUIV = 8;
// MED-2: bound AGGREGATE re-send BYTES, not count — a hash-rotating attacker keeps every
// per-hash cooldown at 1 while extracting re-send bandwidth under a plain count bucket.
// Debit the WORST-CASE block size (Consensus::MAX_BLOCK_SIZE = 4*1024*1024 = 4 MiB) per
// re-send so the token bucket caps aggregate re-send bandwidth regardless of how many
// distinct hashes rotate. Over-counting (real DilV blocks are far smaller) only throttles
// SOONER — the safe direction. Aggregate ceiling: 8 * 4 MiB = 32 MiB/60s (~4.3 Mbit/s).
static const int64_t RESEND_COST_BYTES = static_cast<int64_t>(MAX_BLOCK_VTX_BYTES);
static const int64_t RESEND_BYTE_BUDGET_PER_WINDOW =
    static_cast<int64_t>(RESEND_BUDGET_BLOCK_EQUIV) * RESEND_COST_BYTES;  // 32 MiB / 60s aggregate cap
// MED-3: this budget governs ONLY re-requests of already-served hashes. First-time block sends
// never enter this branch, so honest deep-IBD (32 in-transit, first-time delivery) never touches
// it; the only honest re-requests are the rare parent-recovery path — orders of magnitude under
// 8 worst-case-block re-sends/60s. No honest-client throttle.
// MED-4: the decaying strike counter alone lets a slow-drip attacker grief forever just under the
// disconnect threshold, so retain an INDEPENDENT non-decaying "you've cost me too much total
// re-send bandwidth on this connection" backstop that sustained abuse eventually trips regardless
// of decay. Sized far above any honest re-send total over a full IBD.
static const int64_t RESEND_BACKSTOP_TOTAL_BYTES = 512LL * RESEND_COST_BYTES;  // 2 GiB / connection
static const int64_t STRIKE_DECAY_SECONDS = 60;     // MED-4: strikes decay -1 per 60s without duplicates

// Per-(peer,blockhash) last re-send time — enforces RESEND_COOLDOWN_SECONDS.
static std::map<int, std::map<uint256, int64_t>> g_peer_resend_times;
// Per-peer byte token bucket (tokens in BYTES, refilled at RESEND_BYTE_BUDGET_PER_WINDOW/window).
struct ResendBucket { int64_t tokens = 0; int64_t last_refill = 0; bool init = false; };
static std::map<int, ResendBucket> g_peer_resend_bucket;
// Per-peer last strike-affecting activity time — drives strike decay.
static std::map<int, int64_t> g_peer_dedup_last_strike;
// Per-peer MONOTONIC total re-sent bytes this connection — non-decaying disconnect backstop.
static std::map<int, int64_t> g_peer_resend_total_bytes;
// ALL of the above maps (plus g_peer_served_blocks / g_peer_dedup_strikes) are guarded by the
// single cs_served_blocks mutex — one lock for all per-peer dedup/re-send state, no lock-ordering.

// NET-013 FIX: Maximum size for rate limit maps to prevent memory exhaustion
static const size_t MAX_RATE_LIMIT_MAP_SIZE = 1000;

/**
 * A4/A5: Send a reject message to a peer before banning/disconnecting.
 * Best-effort delivery - peer may disconnect before receiving.
 * This helps legitimate miners understand WHY they were banned.
 *
 * @param peer_id  The peer to notify
 * @param command  The command that caused the rejection (e.g., "version", "block")
 * @param reason   Human-readable reason string
 */
void SendRejectMessage(int peer_id, const std::string& command, const std::string& reason,
                       uint8_t code) {
    if (peer_id < 0) return;  // Guard against synthetic/invalid peer IDs
    if (!g_node_context.connman) return;

    // BIP 61 reject format: var_str(command) + uint8(code) + var_str(reason)
    std::vector<uint8_t> payload;

    // Write command string (varint length + bytes)
    uint8_t cmd_len = static_cast<uint8_t>(std::min(command.size(), size_t(12)));
    payload.push_back(cmd_len);
    payload.insert(payload.end(), command.begin(), command.begin() + cmd_len);

    // Reject code byte (BIP 61)
    payload.push_back(code);

    // Write reason string (varint length + bytes)
    uint8_t reason_len = static_cast<uint8_t>(std::min(reason.size(), size_t(200)));
    payload.push_back(reason_len);
    payload.insert(payload.end(), reason.begin(), reason.begin() + reason_len);

    CNetMessage reject_msg("reject", payload);
    g_node_context.connman->PushMessage(peer_id, reject_msg);
}

/**
 * NET-011/NET-013 FIX: Cleanup rate limit state for a disconnected peer
 * Prevents memory leaks from stale peer entries
 */
void CleanupPeerRateLimitState(int peer_id) {
    {
        std::lock_guard<std::mutex> lock(cs_getdata_rate);
        g_peer_getdata_timestamps.erase(peer_id);
    }
    {
        std::lock_guard<std::mutex> lock(cs_headers_rate);
        g_peer_headers_timestamps.erase(peer_id);
    }
    {
        std::lock_guard<std::mutex> lock(cs_served_blocks);
        g_peer_served_blocks.erase(peer_id);
        g_peer_dedup_strikes.erase(peer_id);
        // dilv-dedup-livelock-fix Part B (LOW-2): release the per-peer re-send state on
        // disconnect so it can't leak across connection churn.
        g_peer_resend_times.erase(peer_id);
        g_peer_resend_bucket.erase(peer_id);
        g_peer_dedup_last_strike.erase(peer_id);
        g_peer_resend_total_bytes.erase(peer_id);
    }
}

/**
 * NET-013 FIX: Helper to clean stale entries from a timestamp map
 * CWE-662 FIX: Extracted to separate function to make synchronization explicit for static analysis
 */
static void CleanupTimestampMap(std::map<int, std::vector<int64_t>>& map,
                                 std::mutex& mutex,
                                 int64_t now,
                                 int64_t max_age_seconds) {
    std::lock_guard<std::mutex> lock(mutex);
    for (auto it = map.begin(); it != map.end(); ) {
        auto& timestamps = it->second;
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(),
                [now, max_age_seconds](int64_t ts) { return now - ts > max_age_seconds; }),
            timestamps.end());

        if (timestamps.empty()) {
            it = map.erase(it);
        } else {
            ++it;
        }
    }

    // If map is still too large, remove oldest entries (LRU eviction)
    while (map.size() > MAX_RATE_LIMIT_MAP_SIZE) {
        map.erase(map.begin());
    }
}

/**
 * NET-013 FIX: Periodic cleanup of stale rate limit entries
 * Call this periodically (e.g., every 60 seconds) to prevent memory growth
 */
void PeriodicRateLimitCleanup() {
    const int64_t now = GetTime();

    // Clean up GETDATA rate limit entries (stale after 60 seconds)
    CleanupTimestampMap(g_peer_getdata_timestamps, cs_getdata_rate, now, 60);

    // Clean up HEADERS rate limit entries (stale after 60 seconds)
    CleanupTimestampMap(g_peer_headers_timestamps, cs_headers_rate, now, 60);

    // Clean up connection cooldown entries (stale after 5 minutes)
    {
        std::lock_guard<std::mutex> lock(cs_connection_cooldown);
        for (auto it = g_last_connection_attempt.begin(); it != g_last_connection_attempt.end(); ) {
            if (now - it->second > 300) {  // 5 minutes
                it = g_last_connection_attempt.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean up the per-peer dedup / re-send state.
    {
        std::lock_guard<std::mutex> lock(cs_served_blocks);

        // dilv-dedup-livelock-fix Part B (LOW-2): age out per-(peer,hash) re-send cooldown
        // entries once the cooldown has elapsed (they carry no further meaning) and drop
        // emptied peers. This is pure staleness reclamation, not capping.
        for (auto pit = g_peer_resend_times.begin(); pit != g_peer_resend_times.end(); ) {
            auto& hashes = pit->second;
            for (auto hit = hashes.begin(); hit != hashes.end(); ) {
                if (now - hit->second > RESEND_COOLDOWN_SECONDS) {
                    hit = hashes.erase(hit);
                } else {
                    ++hit;
                }
            }
            if (hashes.empty()) {
                pit = g_peer_resend_times.erase(pit);
            } else {
                ++pit;
            }
        }

        // MED-2 / C-2: ATOMIC-UNIT capping. The six per-peer maps
        // (g_peer_served_blocks, g_peer_dedup_strikes, g_peer_resend_times,
        // g_peer_resend_bucket, g_peer_dedup_last_strike, g_peer_resend_total_bytes)
        // describe ONE logical per-peer record. Capping them independently
        // (the old `while(map.size()>cap) erase(begin())` per map) could half-evict a
        // peer — e.g. drop its strikes/served set while keeping its
        // resend_total_bytes — which would reset the non-decaying backstop or the
        // dedup view for a still-live abuser. Instead, pick ONE victim set of
        // peer_ids and erase those SAME peers from ALL six maps so no peer is ever
        // half-present.
        //
        // The cap is keyed off g_peer_served_blocks (the largest / canonical
        // per-peer record); after NEW-1 wires per-disconnect cleanup, this only
        // fires under pathological churn beyond MAX_RATE_LIMIT_MAP_SIZE live peers.
        //
        // Eviction order: lowest peer_id first (std::map key order). Node IDs are
        // monotonic and never reused (connman m_next_node_id), so lowest peer_id ==
        // oldest connection. This is NOT attacker-gameable toward evicting a victim:
        // an attacker cannot lower their own peer_id (IDs are server-assigned on
        // connect), and evicting the oldest connections first is the desired LRU-ish
        // behavior. Tradeoff (documented): we evict by connection age, not last
        // activity — a cheap, monotonic, non-gameable proxy. A true last-activity
        // timestamp isn't maintained for all peers (g_peer_dedup_last_strike only
        // tracks strike events), so introducing one for ordering would add state for
        // a path that is already a rare backstop behind NEW-1.
        if (g_peer_served_blocks.size() > MAX_RATE_LIMIT_MAP_SIZE) {
            size_t to_evict = g_peer_served_blocks.size() - MAX_RATE_LIMIT_MAP_SIZE;
            std::vector<int> victims;
            victims.reserve(to_evict);
            for (auto it = g_peer_served_blocks.begin();
                 it != g_peer_served_blocks.end() && victims.size() < to_evict; ++it) {
                victims.push_back(it->first);
            }
            for (int victim : victims) {
                g_peer_served_blocks.erase(victim);
                g_peer_dedup_strikes.erase(victim);
                g_peer_resend_times.erase(victim);
                g_peer_resend_bucket.erase(victim);
                g_peer_dedup_last_strike.erase(victim);
                g_peer_resend_total_bytes.erase(victim);
            }
        }
    }
}

// NET-016 FIX: Error message sanitization notes
// Production deployment should implement proper logging framework with:
// - Log levels (DEBUG, INFO, WARN, ERROR)
// - Sanitized production messages (no peer IDs, internal state in ERROR level)
// - Detailed messages only in DEBUG level
// Current implementation uses std::cout for development convenience
// Replace with spdlog or similar for production

// Global network statistics
CNetworkStats g_network_stats;

// P0-5 FIX: Use std::atomic for global pointers to prevent initialization race conditions
// These pointers may be accessed from multiple threads during startup/shutdown

// Global transaction relay manager (Phase 5.3)
std::atomic<CTxRelayManager*> g_tx_relay_manager{nullptr};

// Global pointers for transaction relay (Phase 5.3)
std::atomic<CTxMemPool*> g_mempool{nullptr};
std::atomic<CTransactionValidator*> g_tx_validator{nullptr};
std::atomic<CUTXOSet*> g_utxo_set{nullptr};
// Issue #83: g_chain_height removed — was only written at startup, causing
// stale-height peer penalties post-IBD. Consumers now read g_chainstate.GetHeight().

// Global pointers for P2P networking (NW-005)
// Phase 5: Removed g_connection_manager - use CConnman via NodeContext instead
std::atomic<CNetMessageProcessor*> g_message_processor{nullptr};

// Phase 1.2: Block fetcher now accessed via NodeContext
// REMOVED: g_block_fetcher extern - use NodeContext::block_fetcher instead

std::string CNetworkStats::ToString() const {
    // CID 1675175/1675189/1675204/1675227/1675242/1675243/1675259 FIX: Use std::ostringstream for explicit type-safe conversion
    // This completely eliminates any printf format specifier issues and ensures portability
    // across all platforms where size_t may vary in size (32-bit vs 64-bit)
    // 
    // IMPORTANT: This function does NOT use printf format specifiers. It uses std::ostringstream
    // with stream insertion operators (<<), which are type-safe and do not require format specifiers.
    // There are NO printf, sprintf, snprintf, strprintf, or any other printf-style function calls
    // in this function. All string formatting is done via std::ostringstream stream operators.
    // 
    // Note: std::ostringstream::operator<< has overloads for unsigned long long, which safely
    // handles all size_t values regardless of platform. The explicit cast ensures type safety
    // and eliminates any potential format specifier mismatches that static analysis tools
    // might detect with printf-style formatting.
    std::ostringstream oss;
    oss << "CNetworkStats(peers=" << static_cast<unsigned long long>(connected_peers) 
        << "/" << static_cast<unsigned long long>(total_peers)
        << ", handshake=" << static_cast<unsigned long long>(handshake_complete)
        << ", bytes=" << static_cast<unsigned long long>(bytes_recv) 
        << "/" << static_cast<unsigned long long>(bytes_sent)
        << ", msgs=" << static_cast<unsigned long long>(messages_recv) 
        << "/" << static_cast<unsigned long long>(messages_sent) << ")";
    return oss.str();
}

// CNetMessageProcessor implementation

CNetMessageProcessor::CNetMessageProcessor(CPeerManager& peer_mgr)
    : peer_manager(peer_mgr)
{
    // Default handlers do nothing
    on_version = [](int, const NetProtocol::CVersionMessage&) {};
    on_verack = [](int) {};  // BUG #132 FIX: Initialize on_verack to prevent race condition
    on_ping = [](int, uint64_t) {};
    on_pong = [](int, uint64_t) {};
    on_addr = [](int, const std::vector<NetProtocol::CAddress>&) {};
    on_inv = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_getdata = [](int, const std::vector<NetProtocol::CInv>&) {};
    on_block = [](int, const CBlock&) {};
    on_tx = [](int, const CTransaction&) {};
    on_getheaders = [](int, const NetProtocol::CGetHeadersMessage&) {};
    on_headers = [](int, const std::vector<CBlockHeader>&) {};
    on_sendheaders = [](int) {};  // BIP 130
    // BIP 152: Compact block handlers
    on_sendcmpct = [](int, bool, uint64_t) {};
    on_cmpctblock = [](int, const CBlockHeaderAndShortTxIDs&) {};
    on_getblocktxn = [](int, const BlockTransactionsRequest&) {};
    on_blocktxn = [](int, const BlockTransactions&) {};
    // Digital DNA handlers (no-op until wired by node)
    on_dna_latency_ping = [](int, uint64_t) {};
    on_dna_latency_pong = [](int, uint64_t, uint64_t) {};
    on_dna_time_sync = [](int, uint64_t, uint64_t, uint64_t, bool, uint64_t) {};
    on_dna_bw_test = [](int, uint32_t, uint64_t, uint64_t) {};
    on_dna_bw_result = [](int, uint64_t, double, double) {};
}

bool CNetMessageProcessor::ProcessMessage(int peer_id, const CNetMessage& message) {
    if (!message.IsValid()) {
        return false;
    }

    std::string command = message.header.GetCommand();
    uint32_t payload_size = message.header.payload_size;

    // NET-003 FIX: Validate payload size before deserialization
    // Prevents memory waste and cache pollution from oversized payloads
    struct MessageSizeLimit {
        uint32_t min_size;
        uint32_t max_size;
    };

    static const std::map<std::string, MessageSizeLimit> size_limits = {
        {"ping",       {8, 8}},                      // Exactly 8 bytes (uint64_t nonce)
        {"pong",       {8, 8}},                      // Exactly 8 bytes (uint64_t nonce)
        {"verack",     {0, 0}},                      // Empty message
        {"version",    {85, 400}},                   // Min 85 bytes, max ~400 bytes with user agent
        {"getaddr",    {0, 0}},                      // Empty message
        {"addr",       {1, 30000 * 30}},             // Max 30k addresses * 30 bytes each
        {"inv",        {1, 50000 * 36}},             // Max 50k inventory items * 36 bytes each
        {"getdata",    {1, 50000 * 36}},             // Max 50k items * 36 bytes each
        {"block",      {80, 8 * 1024 * 1024}},       // Min 80 bytes header, max 8MB blocks
        {"tx",         {60, 1 * 1024 * 1024}},       // Min 60 bytes, max 1MB transactions
        {"getheaders", {33, 8236}},                  // Min 33 bytes (empty locator + stop hash), max ~8KB
        {"headers",    {1, 2000 * 145 + 9}},          // Max 2000 headers * 145 bytes (144 VDF + 1 tx count) + 9 varint
        {"getblocks",  {36, 8236}},                  // Similar to getheaders
        {"mempool",    {0, 0}},                      // Empty message
        {"reject",     {1, 1024}},                   // Variable, max 1KB for reject messages
        {"sendheaders", {0, 0}},                     // BIP 130: Empty message (signal only)
        {"sendcmpct", {9, 9}},                       // BIP 152: bool (1) + uint64_t (8) = 9 bytes
        {"cmpctblock", {80, 8 * 1024 * 1024}},       // BIP 152: Header + short IDs (min ~header size)
        {"getblocktxn", {33, 50000 * 4 + 33}},       // BIP 152: block hash + varint + indices
        {"blocktxn",   {33, 8 * 1024 * 1024}},       // BIP 152: block hash + transactions
        // Digital DNA protocol
        {"dnalping",   {8, 8}},                        // uint64_t nonce only
        {"dnalpong",   {8, 8}},                        // uint64_t nonce only
        {"dnatsync",   {25, 25}},                      // ts_us(8) + wall_ms(8) + nonce(8) + is_response(1)
        {"dnabwtest",  {20, 1048596}},                 // nonce(8) + size(4) + send_wall_ms(8) + payload(0..1MB)
        {"dnabwres",   {24, 24}},                      // nonce(8) + upload(8) + download(8)
        {"dnaireq",    {20, 20}},                      // mik_identity(20)
        {"dnaires",    {21, 8192}},                    // mik(20) + found(1) [+ data_len(2) + data(max 4096)] [+ SMP1 trailer: magic(4)+ts(8)+nonce(8)+sig_len(2)+sig(3309)=3331]
        // Phase 2: DNA Verification & Attestation
        {"dnavchall",  {92, 8192}},                    // Minimum challenge size 92 bytes
        {"dnavresp",   {70, 8192}},                    // Minimum response size 70 bytes
        {"dnavatts",   {112, 8192}},                   // Attestation bounds
    };

    auto it = size_limits.find(command);
    if (it != size_limits.end()) {
        if (payload_size < it->second.min_size || payload_size > it->second.max_size) {
            ErrorMessage error = CErrorFormatter::NetworkError("process message", 
                "Invalid payload size for '" + std::string(command) + "'");
            std::cerr << CErrorFormatter::FormatForUser(error) << std::endl;
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: Invalid payload size for '" << command
                          << "' from peer " << peer_id << " (got " << payload_size
                          << " bytes, expected " << it->second.min_size << "-" << it->second.max_size << ")"
                          << std::endl;
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }
    }

    CDataStream stream(message.payload);

    g_network_stats.messages_recv++;
    g_network_stats.bytes_recv += message.GetTotalSize();

    // BUG #132 DEBUG: Log all incoming messages to trace handshake
    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[MSG-RECV] peer=" << peer_id << " cmd=" << command << std::endl;

    // Dispatch based on command
    if (command == "version") {
        return ProcessVersionMessage(peer_id, stream);
    } else if (command == "verack") {
        return ProcessVerackMessage(peer_id);
    } else if (command == "ping") {
        return ProcessPingMessage(peer_id, stream);
    } else if (command == "pong") {
        return ProcessPongMessage(peer_id, stream);
    } else if (command == "getaddr") {
        return ProcessGetAddrMessage(peer_id);
    } else if (command == "addr") {
        return ProcessAddrMessage(peer_id, stream);
    } else if (command == "inv") {
        return ProcessInvMessage(peer_id, stream);
    } else if (command == "getdata") {
        return ProcessGetDataMessage(peer_id, stream);
    } else if (command == "block") {
        return ProcessBlockMessage(peer_id, stream);
    } else if (command == "tx") {
        return ProcessTxMessage(peer_id, stream);
    } else if (command == "getheaders") {
        return ProcessGetHeadersMessage(peer_id, stream);
    } else if (command == "headers") {
        return ProcessHeadersMessage(peer_id, stream);
    } else if (command == "sendheaders") {
        return ProcessSendHeadersMessage(peer_id);  // BIP 130
    } else if (command == "sendcmpct") {
        return ProcessSendCmpctMessage(peer_id, stream);  // BIP 152
    } else if (command == "cmpctblock") {
        return ProcessCmpctBlockMessage(peer_id, stream);  // BIP 152
    } else if (command == "getblocktxn") {
        return ProcessGetBlockTxnMessage(peer_id, stream);  // BIP 152
    } else if (command == "blocktxn") {
        return ProcessBlockTxnMessage(peer_id, stream);  // BIP 152
    } else if (command == "mempool") {
        return ProcessMempoolMessage(peer_id);
    // Digital DNA protocol messages
    } else if (command == "dnalping") {
        return ProcessDNALatencyPingMessage(peer_id, stream);
    } else if (command == "dnalpong") {
        return ProcessDNALatencyPongMessage(peer_id, stream);
    } else if (command == "dnatsync") {
        return ProcessDNATimeSyncMessage(peer_id, stream);
    } else if (command == "dnabwtest") {
        return ProcessDNABWTestMessage(peer_id, stream);
    } else if (command == "dnabwres") {
        return ProcessDNABWResultMessage(peer_id, stream);
    } else if (command == "dnaireq") {
        return ProcessDNAIdentReqMessage(peer_id, stream);
    } else if (command == "dnaires") {
        return ProcessDNAIdentResMessage(peer_id, stream);
    }
    // Phase 2: DNA Verification messages
    else if (command == "dnavchall") {
        return ProcessDNAVerifyChallengeMessage(peer_id, stream);
    }
    else if (command == "dnavresp") {
        return ProcessDNAVerifyResponseMessage(peer_id, stream);
    }
    else if (command == "dnavatts") {
        return ProcessDNAVerifyAttestMessage(peer_id, stream);
    }

    // Unknown message type
    return true;  // Don't penalize for unknown messages
}

bool CNetMessageProcessor::ProcessVersionMessage(int peer_id, CDataStream& stream) {
    try {
        NetProtocol::CVersionMessage msg;

        // Basic fields
        msg.version = stream.ReadInt32();
        msg.services = stream.ReadUint64();
        msg.timestamp = stream.ReadInt64();

        // addr_recv - receiver's network address (26 bytes)
        msg.addr_recv.services = stream.ReadUint64();
        stream.read(msg.addr_recv.ip, 16);
        msg.addr_recv.port = stream.ReadUint16();

        // addr_from - sender's network address (26 bytes)
        msg.addr_from.services = stream.ReadUint64();
        stream.read(msg.addr_from.ip, 16);
        msg.addr_from.port = stream.ReadUint16();

        // Remaining fields
        msg.nonce = stream.ReadUint64();
        msg.user_agent = stream.ReadString();
        msg.start_height = stream.ReadInt32();
        msg.relay = stream.ReadUint8() != 0;

        // v1.4.2+: Genesis hash validation to prevent cross-chain connections
        // Peers on different genesis chains (e.g., old testnet binary) cause chain sync issues
        uint256 our_genesis = Genesis::GetGenesisHash();
        bool has_genesis_hash = stream.size() >= 32;  // Check if there's more data

        if (has_genesis_hash) {
            stream.read(msg.genesis_hash.data, 32);

            if (msg.genesis_hash != our_genesis) {
                // Peer is on a different blockchain - likely hasn't updated their binary
                // Use IP-based rate limiting to detect and ban probing attacks
                // Get actual connection IP from CNode (not self-reported addr_from which may be 0.0.0.0)
                std::string peer_ip = "0.0.0.0";  // Fallback
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer_ip = node->addr.ToStringIP();
                }
                std::string their_genesis_hex = msg.genesis_hash.GetHex().substr(0, 16);

                // Record failure and check if IP should be banned
                bool should_ban = peer_manager.GetBanManager().RecordGenesisFailure(peer_ip, their_genesis_hex);

                if (should_ban && !peer_manager.IsSeedNode(peer_ip)) {
                    // Ban this IP for 24 hours (repeated genesis probing)
                    // Seed nodes are exempt - genesis mismatch from a seed indicates
                    // a temporary chain fork, not an attack
                    peer_manager.GetBanManager().Ban(peer_ip, CBanManager::DEFAULT_BAN_TIME,
                                                      BanReason::NodeMisbehaving,
                                                      MisbehaviorType::INVALID_GENESIS, 100);

                    std::cout << "[SECURITY] Banned IP " << peer_ip
                              << " for repeated genesis mismatch (probing detected)" << std::endl;
                } else {
                    // First/second failure from this IP - show helpful message
                    LogPrintf(NET, WARN, "Peer %d is on a DIFFERENT BLOCKCHAIN (genesis mismatch)", peer_id);
                    if (g_verbose.load(std::memory_order_relaxed)) {
                        std::cout << "\n[P2P] ================================================" << std::endl;
                        std::cout << "[P2P] CONNECTION REJECTED - DIFFERENT BLOCKCHAIN" << std::endl;
                        std::cout << "[P2P] ================================================" << std::endl;
                        std::cout << "[P2P] Peer " << peer_id << " (" << msg.user_agent << ") from " << peer_ip << std::endl;
                        std::cout << "[P2P] Their genesis: " << their_genesis_hex << "..." << std::endl;
                        std::cout << "[P2P] Our genesis:   " << our_genesis.GetHex().substr(0, 16) << "..." << std::endl;
                        std::cout << "[P2P] " << std::endl;
                        std::cout << "[P2P] HOW TO FIX (for the connecting peer):" << std::endl;
                        std::cout << "[P2P] 1. Download the latest binary: https://github.com/dilithion/dilithion/releases" << std::endl;
                        std::cout << "[P2P] 2. Stop your node" << std::endl;
                        std::cout << "[P2P] 3. Reset chain state: run with --reset-chain (preserves wallet.dat)" << std::endl;
                        std::cout << "[P2P] 4. Restart with the new binary" << std::endl;
                        std::cout << "[P2P] ================================================\n" << std::endl;
                    }
                }

                // A5: Send reject message so the peer knows why they were disconnected
                SendRejectMessage(peer_id, "version",
                    "Genesis hash mismatch - wrong network or outdated binary. "
                    "Download latest from https://github.com/dilithion/dilithion/releases");
                return false;
            }
        } else {
            // Old client (pre-v1.4.2) - no genesis hash in VERSION message
            // Allow connection but log warning - they might be on wrong chain
            LogPrintf(NET, WARN, "Peer %d (%s) is running old protocol (no genesis hash)",
                      peer_id, msg.user_agent.c_str());
            if (g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "[P2P] WARNING: Peer " << peer_id << " (" << msg.user_agent
                          << ") is running old protocol without genesis validation." << std::endl;
                std::cout << "[P2P] Please update to latest version: https://github.com/dilithion/dilithion/releases" << std::endl;
            }
        }

        // NET-001 FIX: Explicit user agent length validation (defense-in-depth)
        // Note: NET-002 already limits ReadString() to 256 bytes, but we validate explicitly
        if (msg.user_agent.length() > 256) {
            ErrorMessage error = CErrorFormatter::NetworkError("process version message", 
                "User agent too long from peer");
            error.severity = ErrorSeverity::WARNING;
            LogPrintf(ALL, WARN, "%s", CErrorFormatter::FormatForLog(error).c_str());
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: User agent too long from peer " << peer_id
                          << " (" << msg.user_agent.length() << " bytes, max 256)" << std::endl;
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_HANDSHAKE);
            return false;
        }

        // Protocol version negotiation (Bitcoin Core pattern)
        // Reject peers with incompatible protocol versions
        // DilV requires v3.8.3+ (70007) due to fork defense consensus changes
        int minProtoVersion = (NetProtocol::g_network_magic == NetProtocol::DILV_MAGIC)
            ? NetProtocol::DILV_MIN_PEER_PROTO_VERSION
            : NetProtocol::MIN_PEER_PROTO_VERSION;
        if (msg.version < minProtoVersion) {
            LogPrintf(NET, WARN, "Peer %d has incompatible protocol version %d (minimum: %d)",
                      peer_id, msg.version, minProtoVersion);
            ErrorMessage error = CErrorFormatter::NetworkError("process version message", 
                "Peer has incompatible protocol version");
            error.severity = ErrorSeverity::WARNING;
            LogPrintf(ALL, WARN, "%s", CErrorFormatter::FormatForLog(error).c_str());
            if (g_verbose.load(std::memory_order_relaxed)) {
                std::cout << "\n[P2P] ================================================" << std::endl;
                std::cout << "[P2P] CONNECTION REJECTED - OUTDATED SOFTWARE" << std::endl;
                std::cout << "[P2P] ================================================" << std::endl;
                std::cout << "[P2P] Peer " << peer_id << " (" << msg.user_agent << ") protocol v"
                          << msg.version << " (minimum required: " << minProtoVersion << ")" << std::endl;
                std::cout << "[P2P] " << std::endl;
                std::cout << "[P2P] This peer is running outdated software with incompatible" << std::endl;
                std::cout << "[P2P] consensus rules, which causes fork creation on the network." << std::endl;
                std::cout << "[P2P] " << std::endl;
                std::cout << "[P2P] Your IP will be temporarily banned for 10 minutes." << std::endl;
                std::cout << "[P2P] " << std::endl;
                std::cout << "[P2P] HOW TO FIX:" << std::endl;
                std::cout << "[P2P] 1. Download the latest version from https://github.com/dilithion/dilithion" << std::endl;
                std::cout << "[P2P] 2. Stop your node" << std::endl;
                std::cout << "[P2P] 3. Delete blocks/ and chainstate/ (keep wallet.dat!)" << std::endl;
                std::cout << "[P2P] 4. Download the bootstrap from the releases page" << std::endl;
                std::cout << "[P2P] 5. Extract bootstrap and restart with the new binary" << std::endl;
                std::cout << "[P2P] ================================================\n" << std::endl;
            }
            // Send reject message so the peer knows WHY they were banned
            SendRejectMessage(peer_id, "version",
                "Outdated protocol version " + std::to_string(msg.version) +
                " (minimum: " + std::to_string(minProtoVersion) +
                "). Banned for 10 minutes. Upgrade at https://github.com/dilithion/dilithion",
                REJECT_OBSOLETE);
            // Ban for 10 minutes (not 1 hour) - these are miners who need to update, not attackers
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_PROTOCOL_VERSION);
            return false;
        }

        // Feature flags validation (Bitcoin Core pattern)
        // Ensure peer supports basic network functionality
        if ((msg.services & NetProtocol::NODE_NETWORK) == 0) {
            LogPrintf(NET, WARN, "Peer %d does not support NODE_NETWORK service flag", peer_id);
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] WARNING: Peer " << peer_id << " does not support NODE_NETWORK" << std::endl;
            // Don't reject, but log for monitoring
        }

        // Update peer info - create peer if not exists (BUG #124 FIX)
        // Inbound connections don't go through AddPeer(), so we must create the peer here
        auto peer = peer_manager.GetPeer(peer_id);
        if (!peer) {
            // BUG #124: Inbound connections weren't registered in CPeerManager
            // This caused "no suitable peers" error because GetValidPeersForDownload() returned empty
            // Use AddPeerWithId to ensure the peer ID matches the connection manager's ID
            peer = peer_manager.AddPeerWithId(peer_id);
            if (peer) {
                // BUG #125 FIX: Copy actual connection IP from CNode to CPeer
                // AddPeerWithId creates peer without address, causing "no suitable peers"
                // because IBD code can't identify which peer has blocks
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer->addr = node->addr;  // Copy actual TCP connection IP
                }
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[PeerManager] Created peer " << peer_id << " for inbound connection" << std::endl;
            }
        }

        if (peer) {
            LogPrintf(NET, INFO, "Received VERSION from peer %d (version=%d, agent=%s, height=%d, services=0x%016llx)",
                      peer_id, msg.version, msg.user_agent.c_str(), msg.start_height, msg.services);

            // BUG #125 FIX: Ensure peer has valid address (may be null for existing peers)
            if (peer->addr.IsNull()) {
                CNode* node = peer_manager.GetNode(peer_id);
                if (node) {
                    peer->addr = node->addr;
                }
            }

            // Store peer data (but DON'T update state yet - handler needs to check state)
            peer->version = msg.version;
            peer->user_agent = msg.user_agent;
            peer->start_height = msg.start_height;
            peer->relay = msg.relay;
        } else {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] WARNING: Could not create peer " << peer_id << " (connection limit reached?)" << std::endl;
        }

        // Call handler BEFORE updating state - handler checks state to decide if
        // we need to send VERSION back to inbound peers
        on_version(peer_id, msg);

        // BUG #148 FIX: Update state AFTER handler has had chance to respond
        // This fixes the bug where inbound peers never got our VERSION because
        // we bumped state before the handler could check it
        if (peer) {
            // SSOT FIX #1: Update CNode::state (single source of truth) first
            CNode* node = peer_manager.GetNode(peer_id);
            if (node && node->state.load() < CNode::STATE_VERSION_SENT) {
                node->state.store(CNode::STATE_VERSION_SENT);
                node->fVersionSent.store(true);
            }
            // Update deprecated CPeer::state for backward compatibility
            if (peer->state < CPeer::STATE_VERSION_SENT) {
                peer->state = CPeer::STATE_VERSION_SENT;
            }
        }

        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: VERSION message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: VERSION message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessVerackMessage(int peer_id) {
    auto peer = peer_manager.GetPeer(peer_id);
    if (!peer) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ProcessVerackMessage: peer " << peer_id << " not found" << std::endl;
        return true;
    }

    // BUG #148 FIX: More robust VERACK handling - complete handshake if:
    // 1. We're in VERSION_SENT state (normal case), OR
    // 2. We're in CONNECTED state and have received VERSION (race condition case)
    // This prevents stuck handshakes due to race conditions
    bool should_complete = (peer->state == CPeer::STATE_VERSION_SENT) ||
                           (peer->state == CPeer::STATE_CONNECTED && peer->version > 0);

    if (should_complete && peer->state != CPeer::STATE_HANDSHAKE_COMPLETE) {
        peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
        g_network_stats.handshake_complete++;

        // FIX Issue 2: Also update CNode::state to keep in sync with CPeer::state
        // CNode is owned by CConnman but tracked in CPeerManager::nodes map
        CNode* node = peer_manager.GetNode(peer_id);
        if (node) {
            node->state.store(CNode::STATE_HANDSHAKE_COMPLETE);
            node->fSuccessfullyConnected.store(true);
            node->nVersion = peer->version;
            node->strSubVer = peer->user_agent;
            node->nStartingHeight = peer->start_height;
            node->fRelay = peer->relay;
        } else {
            // BUG #148 DEBUG: Log when GetNode fails - this causes "no suitable peers"
            // because GetValidPeersForDownload checks CNode::state, not CPeer::state
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] WARNING: ProcessVerackMessage - GetNode(" << peer_id
                          << ") returned nullptr! CNode state NOT updated to HANDSHAKE_COMPLETE. "
                          << "This peer will be excluded from block downloads." << std::endl;
        }

        // Phase 3.2: Notify CPeerManager for unified peer tracking
        // This initializes block sync state in the CPeer object
        // NOTE: CNodeStateManager removed - CPeerManager is now single source of truth
        peer_manager.OnPeerHandshakeComplete(peer_id, peer->start_height, true);

        // Trigger VERACK handler (for IBD initialization)
        if (on_verack) {
            on_verack(peer_id);
        }

        // Mark address as good in AddrMan NOW that handshake is verified.
        // This is the correct place (not at ConnectNode time) because we've
        // confirmed the peer is a real Dilithion node via VERSION+VERACK exchange.
        if (node) {
            peer_manager.MarkAddressGood(node->addr);
        }

        LogPrintf(NET, INFO, "Handshake complete with peer %d (version=%d, height=%d)",
                  peer_id, peer->version, peer->start_height);
    }
    return true;
}

bool CNetMessageProcessor::ProcessPingMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();
        on_ping(peer_id, nonce);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: PING message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: PING message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessPongMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();
        on_pong(peer_id, nonce);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: PONG message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: PONG message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetAddrMessage(int peer_id) {
    // Peer is requesting addresses - respond with known addresses
    // Bitcoin Core pattern: return up to 1000 addresses (23% of AddrMan, capped)

    std::vector<NetProtocol::CAddress> addrs;

    // Get addresses from connected peers (up to 10)
    auto connected_addrs = peer_manager.GetPeerAddresses(10);
    addrs.insert(addrs.end(), connected_addrs.begin(), connected_addrs.end());

    // Get addresses from AddrMan (up to 990 more to reach 1000 total)
    auto addrman_addrs = peer_manager.SelectAddressesToConnect(990);
    for (const auto& addr : addrman_addrs) {
        if (addr.IsRoutable()) {
            addrs.push_back(addr);
        }
    }

    if (addrs.empty()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] GETADDR from peer " << peer_id << " - no addresses to share" << std::endl;
        return true;
    }

    // Create and send ADDR message
    CNetMessage addr_msg = CreateAddrMessage(addrs);

    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    extern NodeContext g_node_context;
    if (g_node_context.connman) {
        g_node_context.connman->PushMessage(peer_id, addr_msg);
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] Sent " << addrs.size() << " addresses to peer "
                      << peer_id << " in response to GETADDR" << std::endl;
    }

    return true;
}

bool CNetMessageProcessor::ProcessAddrMessage(int peer_id, CDataStream& stream) {
    try {
        // NET-007 FIX: Rate limiting for ADDR messages
        // Allow max 1 ADDR message per 10 seconds per peer (addresses change slowly)
        const int64_t MAX_ADDR_PER_WINDOW = 1;
        const int64_t RATE_LIMIT_WINDOW = 10;  // 10 seconds

        int64_t now = GetTime();
        {
            std::lock_guard<std::mutex> lock(cs_addr_rate_limit);
            auto& timestamps = peer_addr_timestamps[peer_id];

            // Remove timestamps older than window
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now, RATE_LIMIT_WINDOW](int64_t ts) { return now - ts > RATE_LIMIT_WINDOW; }),
                timestamps.end());

            // Check if peer exceeds rate limit
            if (timestamps.size() >= static_cast<size_t>(MAX_ADDR_PER_WINDOW)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] ERROR: Peer " << peer_id << " exceeded ADDR rate limit ("
                              << timestamps.size() << " messages in last " << RATE_LIMIT_WINDOW << " seconds)" << std::endl;
                // NET-011 FIX: Penalize peer for rate limit violation
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::ADDR_RATE_EXCEEDED);
                return false;
            }

            // Record this ADDR message
            timestamps.push_back(now);
        }

        uint64_t count = stream.ReadCompactSize();
        if (count > Consensus::MAX_INV_SIZE) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: ADDR message too large from peer " << peer_id
                          << " (count=" << count << ")" << std::endl;
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        std::vector<NetProtocol::CAddress> addrs;
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CAddress addr;
            addr.time = stream.ReadUint32();
            addr.services = stream.ReadUint64();
            stream.read(addr.ip, 16);
            addr.port = stream.ReadUint16();

            // NET-015 FIX: Validate IP address before accepting
            if (addr.IsRoutable()) {
                addrs.push_back(addr);
            }
            // Silently drop non-routable addresses (loopback, private, multicast)
        }

        on_addr(peer_id, addrs);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: ADDR message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: ADDR message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessInvMessage(int peer_id, CDataStream& stream) {
    try {
        // NET-006 FIX: Rate limiting for INV messages
        // Raised to 200 to tolerate old-code nodes with large mempools rebroadcasting.
        // New code (v3.6.9+) batches INVs so this limit is rarely hit.
        const int64_t MAX_INV_PER_SECOND = 200;
        const int64_t RATE_LIMIT_WINDOW = 1;  // 1 second

        int64_t now = GetTime();
        {
            std::lock_guard<std::mutex> lock(cs_inv_rate_limit);
            auto& timestamps = peer_inv_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now, RATE_LIMIT_WINDOW](int64_t ts) { return now - ts > RATE_LIMIT_WINDOW; }),
                timestamps.end());

            // Check if peer exceeds rate limit
            if (timestamps.size() >= static_cast<size_t>(MAX_INV_PER_SECOND)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] ERROR: Peer " << peer_id << " exceeded INV rate limit ("
                              << timestamps.size() << " messages in last second)" << std::endl;
                // NET-011 FIX: Penalize peer for rate limit violation
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INV_RATE_EXCEEDED);
                return false;
            }

            // Record this INV message
            timestamps.push_back(now);
        }

        uint64_t count = stream.ReadCompactSize();
        if (count > Consensus::MAX_INV_SIZE) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: INV message too large from peer " << peer_id
                          << " (count=" << count << ")" << std::endl;
            // NET-011 FIX: Penalize peer for sending oversized message
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        std::vector<NetProtocol::CInv> inv;
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv item;
            item.type = stream.ReadUint32();
            item.hash = stream.ReadUint256();
            inv.push_back(item);
        }

        // Phase 5.3: Handle transaction inventory announcements
        std::vector<NetProtocol::CInv> vToFetch;

        // P0-5 FIX: Load atomic pointers once for this block
        auto* tx_relay = g_tx_relay_manager.load();
        auto* mempool = g_mempool.load();

        for (const NetProtocol::CInv& inv_item : inv) {
            // NET-014/NET-018 FIX: Validate inventory type before processing
            // Only MSG_TX_INV(1), MSG_BLOCK_INV(2), MSG_FILTERED_BLOCK(3), MSG_CMPCT_BLOCK(4) are valid
            if (inv_item.type < 1 || inv_item.type > 4) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] WARNING: Invalid INV type " << inv_item.type
                              << " from peer " << peer_id << " - penalizing" << std::endl;
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
                continue;  // Skip invalid items but continue processing valid ones
            }

            if (inv_item.type == NetProtocol::MSG_TX_INV) {
                // Check if we need this transaction
                if (tx_relay && mempool) {
                    if (!tx_relay->AlreadyHave(inv_item.hash, *mempool)) {
                        vToFetch.push_back(inv_item);
                        tx_relay->MarkRequested(inv_item.hash, peer_id);

                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[P2P] Requesting transaction "
                                      << inv_item.hash.GetHex().substr(0, 16)
                                      << "... from peer " << peer_id << std::endl;
                    }
                }
            }
            else if (inv_item.type == NetProtocol::MSG_BLOCK_INV) {
                // DISABLED: Block requests must go through headers-first IBD system
                // The high-level SetInvHandler callback will trigger RequestHeaders(),
                // which feeds blocks through the IBD coordinator with proper tracking.
                // Direct GETDATA for blocks bypasses CBlockFetcher, breaking the
                // chunk-based sliding window download system.
                // vToFetch.push_back(inv_item);  // LEGACY - DO NOT USE
            }
            // MSG_FILTERED_BLOCK(3) and MSG_CMPCT_BLOCK(4) are valid but not processed here
        }

        // Request transactions/blocks we don't have
        if (!vToFetch.empty()) {
            // Create GETDATA message
            CNetMessage getdata_msg = CreateGetDataMessage(vToFetch);

            // BUG #106 FIX: Actually send the GETDATA request to the peer!
            // Phase 5: Use CConnman instead of deprecated CConnectionManager
            extern NodeContext g_node_context;
            if (g_node_context.connman) {
                g_node_context.connman->PushMessage(peer_id, getdata_msg);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Sent GETDATA for " << vToFetch.size()
                              << " item(s) to peer " << peer_id << std::endl;
            } else {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Cannot send GETDATA - connman not initialized" << std::endl;
            }
        }

        // Call handler for any additional processing
        on_inv(peer_id, inv);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: INV message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: INV message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetDataMessage(int peer_id, CDataStream& stream) {
    try {
        // P2-1 FIX: Rate limiting for GETDATA messages
        // Prevents CPU exhaustion DoS via unlimited GETDATA requests
        {
            std::lock_guard<std::mutex> lock(cs_getdata_rate);
            int64_t now = GetTime();
            auto& timestamps = g_peer_getdata_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 1; }),
                timestamps.end());

            if (timestamps.size() >= MAX_GETDATA_PER_SECOND) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] RATE LIMIT: Too many GETDATA from peer " << peer_id
                              << " (" << timestamps.size() << "/" << MAX_GETDATA_PER_SECOND << " per second)" << std::endl;
                peer_manager.Misbehaving(peer_id, 2, MisbehaviorType::GETDATA_RATE_EXCEEDED);  // Reduced from 10 - IBD sync is legitimate
                return false;
            }
            timestamps.push_back(now);
        }

        // BUG #87 DEBUG: Log GETDATA processing
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] Processing GETDATA from peer " << peer_id << std::endl;
        // Read number of inv items
        uint64_t count = stream.ReadCompactSize();

        if (count > NetProtocol::MAX_INV_SIZE) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: GETDATA message too large from peer " << peer_id
                          << " (count=" << count << ")" << std::endl;
            return false;
        }

        std::vector<NetProtocol::CInv> getdata;
        getdata.reserve(count);

        // Read each inv item
        for (uint64_t i = 0; i < count; i++) {
            NetProtocol::CInv inv;
            inv.type = stream.ReadUint32();
            inv.hash = stream.ReadUint256();

            // NET-020 FIX: Validate inventory type before adding
            if (inv.type < 1 || inv.type > 4) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] WARNING: Invalid GETDATA type " << inv.type
                              << " from peer " << peer_id << " - penalizing" << std::endl;
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
                continue;  // Skip invalid items
            }
            getdata.push_back(inv);
        }

        // Phase 5.3: Handle transaction data requests
        // P0-5 FIX: Load atomic pointer for mempool
        auto* mempool_ptr = g_mempool.load();
        for (const NetProtocol::CInv& inv : getdata) {
            if (inv.type == NetProtocol::MSG_TX_INV) {
                // Try to get transaction from mempool
                if (mempool_ptr) {
                    // Create dummy transaction for mempool lookup
                    CTransactionRef tx_ref = MakeTransactionRef();
                    CTxMemPoolEntry entry(tx_ref, 0, 0, 0);

                    if (mempool_ptr->GetTx(inv.hash, entry)) {
                        CTransactionRef tx = entry.GetSharedTx();

                        // Create TX message
                        CNetMessage tx_msg = CreateTxMessage(*tx);

                        // BUG #106 FIX: Actually send the transaction to the requesting peer!
                        // Phase 5: Use CConnman instead of deprecated CConnectionManager
                        extern NodeContext g_node_context;
                        if (g_node_context.connman) {
                            g_node_context.connman->PushMessage(peer_id, tx_msg);
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[P2P] Sent transaction "
                                          << inv.hash.GetHex().substr(0, 16)
                                          << "... to peer " << peer_id << std::endl;
                        } else {
                            if (g_verbose.load(std::memory_order_relaxed))
                                std::cout << "[P2P] Cannot send transaction - connman not initialized" << std::endl;
                        }
                    } else {
                        if (g_verbose.load(std::memory_order_relaxed))
                            std::cout << "[P2P] Transaction "
                                      << inv.hash.GetHex().substr(0, 16)
                                      << "... not found in mempool for peer " << peer_id << std::endl;
                        // Could send "notfound" message here
                    }
                }
            }
            else if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                // Existing block handling (keep as-is)
                // Block serving logic would go here
            }
        }

        // Per-connection GETDATA deduplication: check for re-requested blocks
        // A legitimate node never re-requests blocks already received on the same connection.
        // Penalize with soft misbehavior scoring (not an instant ban).
        int duplicate_count = 0;
        {
            std::lock_guard<std::mutex> lock(cs_served_blocks);
            auto& served = g_peer_served_blocks[peer_id];
            for (const auto& inv : getdata) {
                if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                    if (served.count(inv.hash)) {
                        ++duplicate_count;
                    }
                }
            }
        }

        if (duplicate_count > 0) {
            // dilv-dedup-livelock-fix Part B: rate-limited re-send instead of permanent starvation.
            // Decide everything under ONE cs_served_blocks lock, then do all I/O (Misbehaving,
            // DisconnectNode, on_getdata, logging) AFTER releasing it.
            // L-c (TOCTOU): the decide→release→serve split is safe because GETDATA for a given
            // peer is processed by the SINGLE threadMessageHandler thread (connman.cpp:186), so no
            // concurrent GETDATA from the same peer can interleave between the decision lock release
            // and the serve. The lock guards only against unrelated threads touching the shared maps
            // (e.g. the periodic sweep / disconnect cleanup), not against same-peer re-entrancy.
            const int64_t now = GetTime();
            std::set<uint256> resend_set;   // duplicate hashes approved for re-send this batch
            int resend_count = 0;
            int cooldown_skipped = 0;
            bool budget_breached = false;
            int strikes = 0;
            int64_t total_resent_bytes = 0;
            {
                std::lock_guard<std::mutex> lock(cs_served_blocks);

                // --- MED-4: decay the strike counter (-1 per STRIKE_DECAY_SECONDS since last
                //     strike-affecting activity) so honest long-lived connections don't strike out.
                auto strike_it = g_peer_dedup_strikes.find(peer_id);
                if (strike_it != g_peer_dedup_strikes.end() && strike_it->second > 0) {
                    auto last_it = g_peer_dedup_last_strike.find(peer_id);
                    if (last_it != g_peer_dedup_last_strike.end()) {
                        int64_t elapsed = now - last_it->second;
                        if (elapsed > 0) {
                            int decay = static_cast<int>(elapsed / STRIKE_DECAY_SECONDS);
                            if (decay > 0) {
                                strike_it->second = std::max(0, strike_it->second - decay);
                            }
                        }
                    }
                }

                // --- refill this peer's byte token bucket up to the per-window cap.
                ResendBucket& bucket = g_peer_resend_bucket[peer_id];
                if (!bucket.init) {
                    bucket.tokens = RESEND_BYTE_BUDGET_PER_WINDOW;  // start full
                    bucket.last_refill = now;
                    bucket.init = true;
                } else {
                    int64_t elapsed = now - bucket.last_refill;
                    if (elapsed > 0) {
                        int64_t refill = elapsed * RESEND_BYTE_BUDGET_PER_WINDOW / RESEND_BUDGET_WINDOW_SECONDS;
                        bucket.tokens = std::min(RESEND_BYTE_BUDGET_PER_WINDOW, bucket.tokens + refill);
                        bucket.last_refill = now;
                    }
                }

                // --- per duplicate hash: approve a re-send iff the per-(peer,hash) cooldown has
                //     elapsed AND the byte budget has room. Cooldown-blocked dups are skipped
                //     silently (could be honest impatience). Budget exhaustion is a breach.
                auto& served = g_peer_served_blocks[peer_id];
                auto& resend_times = g_peer_resend_times[peer_id];
                for (const auto& inv : getdata) {
                    if (inv.type != NetProtocol::MSG_BLOCK_INV) continue;
                    if (!served.count(inv.hash)) continue;  // not a duplicate
                    if (resend_set.count(inv.hash)) continue;  // already decided this hash in-batch
                    auto rt = resend_times.find(inv.hash);
                    if (rt != resend_times.end() && now - rt->second < RESEND_COOLDOWN_SECONDS) {
                        ++cooldown_skipped;  // within cooldown — do not re-send, do not penalize
                        continue;
                    }
                    if (bucket.tokens >= RESEND_COST_BYTES) {
                        bucket.tokens -= RESEND_COST_BYTES;             // MED-2: debit worst-case bytes
                        resend_times[inv.hash] = now;
                        resend_set.insert(inv.hash);
                        ++resend_count;
                        total_resent_bytes = (g_peer_resend_total_bytes[peer_id] += RESEND_COST_BYTES);
                    } else {
                        budget_breached = true;  // out of budget — refuse re-send, penalize below
                    }
                }
                // bound the per-(peer,hash) cooldown map (belt-and-suspenders; also swept periodically)
                if (resend_times.size() > MAX_SERVED_BLOCKS_TRACK) {
                    auto it = resend_times.begin();
                    size_t to_remove = resend_times.size() - MAX_SERVED_BLOCKS_TRACK;
                    for (size_t i = 0; i < to_remove; ++i) it = resend_times.erase(it);
                }

                // --- a budget BREACH (not a mere re-request) counts as one strike (post-decay).
                //     Within-budget / cooldown-skipped re-requests are served (or quietly ignored)
                //     FREE — no strike, no penalty — so honest low-rate parent-recovery re-requests
                //     (ibd_coordinator.cpp:2057/1657; F-001 §3) are never disconnected. This keeps the
                //     disconnect lever (strikes) gated identically to the penalty lever (Misbehaving),
                //     which also fires only on breach below. re-send NEVER clears strikes.
                if (budget_breached) {
                    strikes = ++g_peer_dedup_strikes[peer_id];
                    g_peer_dedup_last_strike[peer_id] = now;
                } else {
                    auto sit = g_peer_dedup_strikes.find(peer_id);
                    strikes = (sit != g_peer_dedup_strikes.end()) ? sit->second : 0;  // report decayed value
                }
                if (total_resent_bytes == 0) {
                    total_resent_bytes = g_peer_resend_total_bytes[peer_id];  // no re-send this batch
                }
            }

            // --- MED-2/contract: Misbehaving penalty ONLY on budget breach (honest within-budget
            //     re-requests are served free). Penalty scales with the batch, capped as before.
            if (budget_breached) {
                int penalty = std::min(duplicate_count * DUPLICATE_GETDATA_PENALTY, MAX_DEDUP_BATCH_PENALTY);
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] DEDUP: Peer " << peer_id << " exceeded re-send byte budget (+"
                              << penalty << " misbehavior, strike " << strikes << "/" << MAX_DEDUP_STRIKES
                              << ")" << std::endl;
                peer_manager.Misbehaving(peer_id, penalty, MisbehaviorType::GETDATA_RATE_EXCEEDED);
            }
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] DEDUP: Peer " << peer_id << " re-requested " << duplicate_count
                          << " already-served blocks (re-send " << resend_count << ", cooldown-skip "
                          << cooldown_skipped << ", strike " << strikes << "/" << MAX_DEDUP_STRIKES
                          << ", total re-sent " << total_resent_bytes << "B)" << std::endl;

            // --- disconnect levers: (1) decaying strike counter for fast abuse; (2) MED-4
            //     non-decaying total-re-sent-bytes backstop for slow-drip abuse under the strike
            //     threshold. Honest clients trip neither (Part A removes the storm; residual
            //     parent-recovery re-requests are orders of magnitude below both).
            const bool backstop_tripped = (total_resent_bytes >= RESEND_BACKSTOP_TOTAL_BYTES);
            bool disconnect = (strikes >= MAX_DEDUP_STRIKES) || backstop_tripped;
            if (disconnect) {
                // MED-1/C-1: a backstop trip means this connection has cost us
                // RESEND_BACKSTOP_TOTAL_BYTES (2 GiB) of re-sent block bandwidth — far
                // above anything an honest IBD client (or rare parent-recovery re-request)
                // could ever incur. That is PROVEN sustained abuse, so it is ban-worthy,
                // not merely disconnect-worthy: a bare DisconnectNode lets the attacker
                // reconnect with a fresh peer_id (node IDs are monotonic) and a reset
                // budget, resuming the ~32 MiB/window drip indefinitely (this also closes
                // C-3 slow-drip). Cross the misbehavior ban threshold (BAN_THRESHOLD = 100,
                // peers.cpp:280 / peer_scorer m_ban_threshold) in ONE shot so banman.Ban
                // records the IP persistently (checked at connect — survives reconnect).
                // The strike-path disconnect (fast abuse) already routes through Misbehaving
                // on each breach above, so it accumulates toward the same threshold; here we
                // guarantee the slow-drip backstop also bans rather than just dropping.
                if (backstop_tripped) {
                    if (g_verbose.load(std::memory_order_relaxed))
                        std::cout << "[P2P] DEDUP: Peer " << peer_id << " tripped re-send byte"
                                  << " backstop (" << total_resent_bytes << "B/"
                                  << RESEND_BACKSTOP_TOTAL_BYTES << "B) — banning (proven"
                                  << " sustained abuse)" << std::endl;
                    peer_manager.Misbehaving(peer_id, CPeerManager::BAN_THRESHOLD,
                                             MisbehaviorType::GETDATA_RATE_EXCEEDED);
                }
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] DEDUP: Disconnecting peer " << peer_id
                              << " (strikes " << strikes << "/" << MAX_DEDUP_STRIKES
                              << ", total re-sent " << total_resent_bytes << "B/"
                              << RESEND_BACKSTOP_TOTAL_BYTES << "B)" << std::endl;
                g_node_context.connman->DisconnectNode(peer_id);
                CleanupPeerRateLimitState(peer_id);
                return true;
            }

            // --- serve: all non-duplicate items PLUS the duplicate items approved for re-send.
            std::vector<NetProtocol::CInv> items_to_serve;
            {
                std::lock_guard<std::mutex> lock(cs_served_blocks);
                auto& served = g_peer_served_blocks[peer_id];
                for (const auto& inv : getdata) {
                    bool is_dup = (inv.type == NetProtocol::MSG_BLOCK_INV) && served.count(inv.hash);
                    if (!is_dup || resend_set.count(inv.hash)) {
                        items_to_serve.push_back(inv);  // new item, or an approved re-send
                    }
                }
            }
            if (!items_to_serve.empty()) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Invoking GETDATA handler for " << items_to_serve.size()
                              << " items from peer " << peer_id << " (" << resend_count
                              << " rate-limited re-sends, " << cooldown_skipped << " cooldown-skipped)" << std::endl;
                on_getdata(peer_id, items_to_serve);
            } else {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Skipping GETDATA for peer " << peer_id
                              << " - all " << getdata.size() << " items already served, none re-sendable yet"
                              << std::endl;
            }
        } else {
            // No duplicates - serve normally
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Invoking GETDATA handler for " << getdata.size() << " items from peer " << peer_id << std::endl;
            on_getdata(peer_id, getdata);
        }

        // Record served blocks for future dedup detection
        {
            std::lock_guard<std::mutex> lock(cs_served_blocks);
            auto& served = g_peer_served_blocks[peer_id];
            for (const auto& inv : getdata) {
                if (inv.type == NetProtocol::MSG_BLOCK_INV) {
                    served.insert(inv.hash);
                }
            }
            // Cap tracking set size per peer to prevent memory growth
            if (served.size() > MAX_SERVED_BLOCKS_TRACK) {
                // Evict entries from beginning of set to stay within limit
                auto it = served.begin();
                size_t to_remove = served.size() - MAX_SERVED_BLOCKS_TRACK;
                for (size_t i = 0; i < to_remove; ++i) {
                    it = served.erase(it);
                }
            }
        }

        return true;

    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETDATA message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETDATA message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessBlockMessage(int peer_id, CDataStream& stream) {
    try {
        CBlock block;
        // Deserialize block header
        block.nVersion = stream.ReadInt32();
        block.hashPrevBlock = stream.ReadUint256();
        block.hashMerkleRoot = stream.ReadUint256();
        block.nTime = stream.ReadUint32();
        block.nBits = stream.ReadUint32();
        block.nNonce = stream.ReadUint32();

        // VDF extension fields (version >= 4)
        if (block.IsVDFBlock()) {
            block.vdfOutput = stream.ReadUint256();
            block.vdfProofHash = stream.ReadUint256();
        }

        // Deserialize transaction data
        uint64_t vtx_size = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vtx_size > MAX_BLOCK_VTX_BYTES) {
            // NET-011 FIX: Penalize peer for sending invalid block
            SendRejectMessage(peer_id, "block", "Block vtx data exceeds maximum size (" + std::to_string(vtx_size) + " bytes)");
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::BLOCK_TOO_LARGE);  // Severe penalty - likely attack
            throw std::runtime_error("Block vtx data exceeds maximum size");
        }

        block.vtx.resize(vtx_size);
        if (vtx_size > 0) {
            stream.read(block.vtx.data(), vtx_size);
        }

        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[BLOCK-PROCESS] Deserialized block, calling on_block handler..." << std::endl;
            std::cout.flush();
        }
        on_block(peer_id, block);
        if (g_verbose.load(std::memory_order_relaxed)) {
            std::cout << "[BLOCK-PROCESS] on_block handler returned" << std::endl;
            std::cout.flush();
        }
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: BLOCK message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: BLOCK message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessTxMessage(int peer_id, CDataStream& stream) {
    try {
        // Deserialize transaction
        CTransaction tx;
        tx.nVersion = stream.ReadInt32();

        // Read inputs
        const uint64_t vin_size_raw = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vin_size_raw > MAX_TX_INPUTS) {
            // NET-011 FIX: Penalize peer for sending invalid transaction
            SendRejectMessage(peer_id, "tx", "Transaction input count exceeds limit");
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_TRANSACTION);  // Severe penalty - likely attack
            throw std::runtime_error("Transaction input count exceeds limit");
        }

        // Create validated const bound for loop (CWE-606 fix: explicit trusted bound)
        const size_t vin_size = static_cast<size_t>(vin_size_raw);
        tx.vin.resize(vin_size);
        for (size_t i = 0; i < vin_size; i++) {
            tx.vin[i].prevout.hash = stream.ReadUint256();
            tx.vin[i].prevout.n = stream.ReadUint32();

            uint64_t script_size = stream.ReadCompactSize();

            // NET-003 FIX: Validate script size before resize
            if (script_size > MAX_SCRIPT_SIZE) {
                throw std::runtime_error("Script size exceeds limit");
            }

            tx.vin[i].scriptSig.resize(script_size);
            if (script_size > 0) {
                stream.read(tx.vin[i].scriptSig.data(), script_size);
            }

            tx.vin[i].nSequence = stream.ReadUint32();
        }

        // Read outputs
        const uint64_t vout_size_raw = stream.ReadCompactSize();

        // NET-003 FIX: Validate size before resize to prevent integer overflow
        if (vout_size_raw > MAX_TX_OUTPUTS) {
            throw std::runtime_error("Transaction output count exceeds limit");
        }

        // Create validated const bound for loop (CWE-606 fix: explicit trusted bound)
        const size_t vout_size = static_cast<size_t>(vout_size_raw);
        tx.vout.resize(vout_size);
        for (size_t i = 0; i < vout_size; i++) {
            tx.vout[i].nValue = stream.ReadUint64();

            uint64_t script_size = stream.ReadCompactSize();

            // NET-003 FIX: Validate script size before resize
            if (script_size > MAX_SCRIPT_SIZE) {
                throw std::runtime_error("Script size exceeds limit");
            }

            tx.vout[i].scriptPubKey.resize(script_size);
            if (script_size > 0) {
                stream.read(tx.vout[i].scriptPubKey.data(), script_size);
            }
        }

        // Read locktime
        tx.nLockTime = stream.ReadUint32();

        // Get transaction hash
        const uint256 txid = tx.GetHash();

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] Received transaction " << txid.GetHex().substr(0, 16)
                      << "... from peer " << peer_id << std::endl;

        // P0-5 FIX: Load atomic pointers for transaction processing
        auto* tx_relay = g_tx_relay_manager.load();
        auto* mempool = g_mempool.load();
        auto* tx_validator = g_tx_validator.load();
        auto* utxo_set = g_utxo_set.load();
        // Issue #83: read live chain tip, not a stale startup-only global.
        extern CChainState g_chainstate;
        int chain_height_signed = g_chainstate.GetHeight();
        if (chain_height_signed < 0) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Dropping tx " << txid.GetHex().substr(0, 16)
                          << "... from peer " << peer_id << ": no chain tip" << std::endl;
            return true;  // No tip yet — not the peer's fault, don't penalise.
        }
        unsigned int chain_height = static_cast<unsigned int>(chain_height_signed);

        // Phase 5.3: Transaction relay processing
        if (tx_relay) {
            // Remove from in-flight
            tx_relay->RemoveInFlight(txid);
        }

        // Check if we already have it
        if (mempool && mempool->Exists(txid)) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Transaction " << txid.GetHex().substr(0, 16)
                          << "... already in mempool" << std::endl;
            on_tx(peer_id, tx);
            return true;
        }

        // Validate transaction
        if (tx_validator && utxo_set && mempool) {
            std::string error;
            CAmount fee = 0;

            if (!tx_validator->CheckTransaction(tx, *utxo_set, chain_height, fee, error)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Invalid transaction " << txid.GetHex().substr(0, 16)
                              << "... from peer " << peer_id << ": " << error << std::endl;
                // Mark as rejected to prevent relay loops (re-requesting same invalid tx)
                if (tx_relay) {
                    tx_relay->MarkRejected(txid);
                }
                // DoS hardening: Penalize peer for sending invalid transactions
                // Distinguish between different failure types for appropriate penalties
                bool is_severe = (error.find("double-spend") != std::string::npos ||
                                  error.find("invalid signature") != std::string::npos ||
                                  error.find("malformed") != std::string::npos);
                int penalty = is_severe ? 50 : 10;  // Severe violations get higher penalty
                peer_manager.Misbehaving(peer_id, penalty, MisbehaviorType::INVALID_TRANSACTION);
                return false;
            }

            // Add to mempool
            std::string mempool_error;
            int64_t current_time = GetTime();
            CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));

            if (!mempool->AddTx(tx_ref, fee, current_time, chain_height, &mempool_error)) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] Failed to add tx " << txid.GetHex().substr(0, 16)
                              << "... to mempool: " << mempool_error << std::endl;
                return true;  // Not necessarily peer's fault
            }

            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Accepted transaction " << txid.GetHex().substr(0, 16)
                          << "... from peer " << peer_id << " (fee: " << fee << " ions)" << std::endl;

            // Relay to other peers
            AnnounceTransactionToPeers(txid, peer_id);

            // Call handler
            on_tx(peer_id, *tx_ref);
            return true;
        }

        // If global pointers not set, log warning and drop
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] WARNING: Cannot validate tx " << txid.GetHex().substr(0, 16)
                      << "... - missing subsystems (validator=" << (tx_validator ? "yes" : "NO")
                      << " utxo=" << (utxo_set ? "yes" : "NO")
                      << " mempool=" << (mempool ? "yes" : "NO") << ")" << std::endl;
        on_tx(peer_id, tx);
        return true;
    } catch (const std::out_of_range& e) {
        // NET-004 FIX: Specific error handling for truncated messages
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: TX message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        // NET-004 FIX: Detailed error logging with misbehavior penalty
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: TX message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessGetHeadersMessage(int peer_id, CDataStream& stream) {
    try {
        NetProtocol::CGetHeadersMessage msg;

        // Read locator size
        uint64_t locator_size = stream.ReadCompactSize();

        // Validate locator size (max 32 hashes in locator)
        if (locator_size > 32) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: GETHEADERS locator size too large: " << locator_size << std::endl;
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        // Read locator hashes
        msg.locator.resize(locator_size);
        for (uint64_t i = 0; i < locator_size; i++) {
            msg.locator[i] = stream.ReadUint256();
        }

        // BUG #149 FIX: Removed overly strict locator validation
        // Bitcoin Core doesn't reject GETHEADERS for unknown locator hashes - it simply
        // iterates through them to find the first common block. The handler will skip
        // unknown hashes and find the first one we know about. This allows peers that
        // are ahead of us (with more headers) to still request more headers from us.
        // The on_getheaders handler in dilithion-node.cpp correctly handles unknown hashes.

        // Read stop hash
        msg.hashStop = stream.ReadUint256();

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] Received GETHEADERS from peer " << peer_id
                      << " (locator size: " << locator_size << ")" << std::endl;

        // Call handler
        if (on_getheaders) {
            on_getheaders(peer_id, msg);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETHEADERS message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETHEADERS message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessHeadersMessage(int peer_id, CDataStream& stream) {
    try {
        // P3-N2 FIX: Rate limiting for HEADERS messages (disabled during IBD)
        // During IBD, we actively request headers and need them rapidly
        // Rate limiting only applies post-IBD to prevent unsolicited flooding
        extern NodeContext g_node_context;
        bool is_ibd = false;
        if (g_node_context.headers_manager) {
            int header_height = g_node_context.headers_manager->GetBestHeight();
            extern CChainState g_chainstate;
            int chain_height = g_chainstate.GetHeight();
            is_ibd = (header_height > chain_height + 10);  // IBD if >10 blocks behind
        }

        if (!is_ibd) {
            std::lock_guard<std::mutex> lock(cs_headers_rate);
            int64_t now = GetTime();
            auto& timestamps = g_peer_headers_timestamps[peer_id];

            // Remove timestamps older than 1 second
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t ts) { return now - ts > 1; }),
                timestamps.end());

            if (timestamps.size() >= MAX_HEADERS_PER_SECOND) {
                // Note: We no longer penalize peers for sending many HEADERS.
                // HEADERS are responses to our GETHEADERS requests, so high volume
                // during fork sync is expected and not malicious behavior.
                // We still skip processing to avoid memory pressure, but don't ban.
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] RATE LIMIT: Skipping HEADERS from peer " << peer_id
                              << " (" << timestamps.size() << "/" << MAX_HEADERS_PER_SECOND << " per second)" << std::endl;
                return false;
            }
            timestamps.push_back(now);
        }

        // Read header count
        uint64_t header_count = stream.ReadCompactSize();

        // Validate count (Bitcoin Core max is 2000, wired via Consensus::MAX_HEADERS_RESULTS)
        if (header_count > Consensus::MAX_HEADERS_RESULTS) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: HEADERS count too large: " << header_count << std::endl;
            // Phase 3: route through MaybePunishNodeForHeaders via the
            // CPeerManager::MisbehaveHeaders forwarder. Same end weight (20)
            // and same banlist.dat diagnostic code as pre-cutover; the
            // wrapper is now on a production path.
            peer_manager.MisbehaveHeaders(peer_id,
                ::dilithion::net::port::HeaderRejectReason::MemoryBoundExceeded);
            return false;
        }

        std::vector<CBlockHeader> headers;
        headers.reserve(header_count);

        // Read each header
        for (uint64_t i = 0; i < header_count; i++) {
            CBlockHeader header;
            header.nVersion = stream.ReadInt32();
            header.hashPrevBlock = stream.ReadUint256();
            header.hashMerkleRoot = stream.ReadUint256();
            header.nTime = stream.ReadUint32();
            header.nBits = stream.ReadUint32();
            header.nNonce = stream.ReadUint32();

            // VDF extension fields (version >= 4)
            if (header.IsVDFBlock()) {
                header.vdfOutput = stream.ReadUint256();
                header.vdfProofHash = stream.ReadUint256();
            }

            // Skip transaction count (headers message has 0 txs per header)
            uint64_t tx_count = stream.ReadCompactSize();
            if (tx_count != 0) {
                if (g_verbose.load(std::memory_order_relaxed))
                    std::cout << "[P2P] ERROR: HEADERS message with tx_count != 0" << std::endl;
                peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_BLOCK_HEADER);
                return false;
            }

            headers.push_back(header);
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] Received " << header_count << " headers from peer " << peer_id << std::endl;

        // Call handler
        if (on_headers) {
            on_headers(peer_id, headers);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: HEADERS message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: HEADERS message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// BIP 130: sendheaders message
bool CNetMessageProcessor::ProcessSendHeadersMessage(int peer_id) {
    // sendheaders is a signal message with no payload
    // When received, the peer is requesting that we send HEADERS instead of INV
    // for new block announcements

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[P2P] Peer " << peer_id << " sent sendheaders (prefers HEADERS over INV)" << std::endl;

    // Call handler to update peer preference
    if (on_sendheaders) {
        on_sendheaders(peer_id);
    }

    return true;
}

// BIP 152: sendcmpct message
bool CNetMessageProcessor::ProcessSendCmpctMessage(int peer_id, CDataStream& stream) {
    try {
        // sendcmpct payload: bool high_bandwidth + uint64_t version
        uint8_t high_bandwidth_byte = stream.ReadUint8();
        bool high_bandwidth = (high_bandwidth_byte != 0);
        uint64_t version = stream.ReadUint64();

        // BIP 152 only supports version 1 (version 2 is for segwit, not applicable to Dilithion)
        if (version != 1) {
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] Peer " << peer_id << " sent sendcmpct with unsupported version "
                          << version << " (expected 1)" << std::endl;
            return true;  // Ignore but don't disconnect
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Peer " << peer_id << " sent sendcmpct (high_bandwidth="
                      << (high_bandwidth ? "true" : "false") << ", version=" << version << ")" << std::endl;

        // Call handler to update peer preference
        if (on_sendcmpct) {
            on_sendcmpct(peer_id, high_bandwidth, version);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: SENDCMPCT message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: SENDCMPCT message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// BIP 152: cmpctblock message
bool CNetMessageProcessor::ProcessCmpctBlockMessage(int peer_id, CDataStream& stream) {
    try {
        CBlockHeaderAndShortTxIDs cmpctblock;

        // Deserialize header
        cmpctblock.header.nVersion = stream.ReadInt32();
        cmpctblock.header.hashPrevBlock = stream.ReadUint256();
        cmpctblock.header.hashMerkleRoot = stream.ReadUint256();
        cmpctblock.header.nTime = stream.ReadUint32();
        cmpctblock.header.nBits = stream.ReadUint32();
        cmpctblock.header.nNonce = stream.ReadUint32();

        // VDF extension fields (version >= 4)
        if (cmpctblock.header.IsVDFBlock()) {
            cmpctblock.header.vdfOutput = stream.ReadUint256();
            cmpctblock.header.vdfProofHash = stream.ReadUint256();
        }

        // Nonce for short ID calculation
        cmpctblock.nonce = stream.ReadUint64();
        // Note: Short ID keys are lazily initialized by GetShortID() when needed

        // Read prefilled transactions
        uint64_t prefilled_count = stream.ReadCompactSize();
        if (prefilled_count > 10000) {  // Sanity limit
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: CMPCTBLOCK with too many prefilled txs from peer "
                          << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        cmpctblock.prefilledtxn.reserve(prefilled_count);
        for (uint64_t i = 0; i < prefilled_count; i++) {
            PrefilledTransaction ptx;
            ptx.index = static_cast<uint16_t>(stream.ReadCompactSize());

            // Deserialize transaction
            ptx.tx.nVersion = stream.ReadInt32();

            // Read inputs
            uint64_t vin_size = stream.ReadCompactSize();
            if (vin_size > 10000) {
                throw std::runtime_error("Too many tx inputs");
            }
            ptx.tx.vin.resize(vin_size);
            for (uint64_t j = 0; j < vin_size; j++) {
                ptx.tx.vin[j].prevout.hash = stream.ReadUint256();
                ptx.tx.vin[j].prevout.n = stream.ReadUint32();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > MAX_SCRIPT_SIZE) throw std::runtime_error("Script too large");
                ptx.tx.vin[j].scriptSig.resize(script_size);
                if (script_size > 0) {
                    stream.read(ptx.tx.vin[j].scriptSig.data(), script_size);
                }
                ptx.tx.vin[j].nSequence = stream.ReadUint32();
            }

            // Read outputs
            uint64_t vout_size = stream.ReadCompactSize();
            if (vout_size > 10000) {
                throw std::runtime_error("Too many tx outputs");
            }
            ptx.tx.vout.resize(vout_size);
            for (uint64_t j = 0; j < vout_size; j++) {
                ptx.tx.vout[j].nValue = stream.ReadUint64();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > MAX_SCRIPT_SIZE) throw std::runtime_error("Script too large");
                ptx.tx.vout[j].scriptPubKey.resize(script_size);
                if (script_size > 0) {
                    stream.read(ptx.tx.vout[j].scriptPubKey.data(), script_size);
                }
            }

            ptx.tx.nLockTime = stream.ReadUint32();
            cmpctblock.prefilledtxn.push_back(std::move(ptx));
        }

        // Read short IDs (6 bytes each)
        uint64_t shortid_count = stream.ReadCompactSize();
        if (shortid_count > 100000) {  // Sanity limit
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: CMPCTBLOCK with too many short IDs from peer "
                          << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        cmpctblock.shorttxids.reserve(shortid_count);
        for (uint64_t i = 0; i < shortid_count; i++) {
            // Short IDs are 6 bytes, stored as uint64_t with upper 2 bytes zeroed
            uint8_t shortid_bytes[6];
            stream.read(shortid_bytes, 6);
            uint64_t shortid = 0;
            for (int j = 0; j < 6; j++) {
                shortid |= (static_cast<uint64_t>(shortid_bytes[j]) << (j * 8));
            }
            cmpctblock.shorttxids.push_back(shortid);
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received CMPCTBLOCK from peer " << peer_id
                      << " (hash=" << cmpctblock.header.GetHash().GetHex().substr(0, 16)
                      << "..., prefilled=" << cmpctblock.prefilledtxn.size()
                      << ", shorttxids=" << cmpctblock.shorttxids.size() << ")" << std::endl;

        // Call handler for block reconstruction
        if (on_cmpctblock) {
            on_cmpctblock(peer_id, cmpctblock);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: CMPCTBLOCK message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: CMPCTBLOCK message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// BIP 152: getblocktxn message
bool CNetMessageProcessor::ProcessGetBlockTxnMessage(int peer_id, CDataStream& stream) {
    try {
        BlockTransactionsRequest req;

        // Read block hash
        req.blockhash = stream.ReadUint256();

        // Read requested indices
        uint64_t index_count = stream.ReadCompactSize();
        if (index_count > 50000) {  // Sanity limit
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: GETBLOCKTXN with too many indices from peer "
                          << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        req.indexes.reserve(index_count);
        for (uint64_t i = 0; i < index_count; i++) {
            req.indexes.push_back(static_cast<uint16_t>(stream.ReadCompactSize()));
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received GETBLOCKTXN from peer " << peer_id
                      << " (block=" << req.blockhash.GetHex().substr(0, 16)
                      << "..., " << req.indexes.size() << " txns requested)" << std::endl;

        // Call handler to serve requested transactions
        if (on_getblocktxn) {
            on_getblocktxn(peer_id, req);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETBLOCKTXN message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: GETBLOCKTXN message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// BIP 152: blocktxn message
bool CNetMessageProcessor::ProcessBlockTxnMessage(int peer_id, CDataStream& stream) {
    try {
        BlockTransactions resp;

        // Read block hash
        resp.blockhash = stream.ReadUint256();

        // Read transactions
        uint64_t tx_count = stream.ReadCompactSize();
        if (tx_count > 100000) {  // Sanity limit
            if (g_verbose.load(std::memory_order_relaxed))
                std::cout << "[P2P] ERROR: BLOCKTXN with too many transactions from peer "
                          << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 100, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        resp.txn.reserve(tx_count);
        for (uint64_t i = 0; i < tx_count; i++) {
            CTransaction tx;
            tx.nVersion = stream.ReadInt32();

            // Read inputs
            uint64_t vin_size = stream.ReadCompactSize();
            if (vin_size > 10000) {
                throw std::runtime_error("Too many tx inputs");
            }
            tx.vin.resize(vin_size);
            for (uint64_t j = 0; j < vin_size; j++) {
                tx.vin[j].prevout.hash = stream.ReadUint256();
                tx.vin[j].prevout.n = stream.ReadUint32();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > MAX_SCRIPT_SIZE) throw std::runtime_error("Script too large");
                tx.vin[j].scriptSig.resize(script_size);
                if (script_size > 0) {
                    stream.read(tx.vin[j].scriptSig.data(), script_size);
                }
                tx.vin[j].nSequence = stream.ReadUint32();
            }

            // Read outputs
            uint64_t vout_size = stream.ReadCompactSize();
            if (vout_size > 10000) {
                throw std::runtime_error("Too many tx outputs");
            }
            tx.vout.resize(vout_size);
            for (uint64_t j = 0; j < vout_size; j++) {
                tx.vout[j].nValue = stream.ReadUint64();
                uint64_t script_size = stream.ReadCompactSize();
                if (script_size > MAX_SCRIPT_SIZE) throw std::runtime_error("Script too large");
                tx.vout[j].scriptPubKey.resize(script_size);
                if (script_size > 0) {
                    stream.read(tx.vout[j].scriptPubKey.data(), script_size);
                }
            }

            tx.nLockTime = stream.ReadUint32();
            resp.txn.push_back(std::move(tx));
        }

        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[BIP152] Received BLOCKTXN from peer " << peer_id
                      << " (block=" << resp.blockhash.GetHex().substr(0, 16)
                      << "..., " << resp.txn.size() << " txns)" << std::endl;

        // Call handler to complete block reconstruction
        if (on_blocktxn) {
            on_blocktxn(peer_id, resp);
        }

        return true;
    } catch (const std::out_of_range& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: BLOCKTXN message truncated from peer " << peer_id << std::endl;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[P2P] ERROR: BLOCKTXN message parsing failed from peer " << peer_id
                      << ": " << e.what() << std::endl;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// Create messages

CNetMessage CNetMessageProcessor::CreateVersionMessage(const NetProtocol::CAddress& addr_recv, const NetProtocol::CAddress& addr_from) {
    // BUG #50 FIX: Get actual blockchain height for VERSION message
    // This allows remote peers to determine if they need to sync from us
    extern CChainState g_chainstate;
    int32_t blockchain_height = g_chainstate.GetHeight();

    // Initialize message with actual blockchain height (Bitcoin Core pattern)
    NetProtocol::CVersionMessage msg(blockchain_height);

    // Populate address fields (Bitcoin Core standard)
    msg.addr_recv = addr_recv;  // Peer's address (where we're sending to)
    msg.addr_from = addr_from;  // Our address (what we believe our external IP to be)

    // Advertise our service flags (Bitcoin Core pattern)
    msg.services = NetFeatures::GetOurServices();

    // Generate random nonce to prevent self-connections (Bitcoin Core standard)
    // Use time + random for uniqueness
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    msg.nonce = gen();

    // v1.4.2+: Include our genesis hash to prevent cross-chain connections
    msg.genesis_hash = Genesis::GetGenesisHash();

    std::vector<uint8_t> payload = SerializeVersionMessage(msg);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("version", payload);
}

CNetMessage CNetMessageProcessor::CreateVerackMessage() {
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;

    return CNetMessage("verack", {});
}

CNetMessage CNetMessageProcessor::CreatePingMessage(uint64_t nonce) {
    std::vector<uint8_t> payload = SerializePingPong(nonce);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("ping", payload);
}

CNetMessage CNetMessageProcessor::CreatePongMessage(uint64_t nonce) {
    std::vector<uint8_t> payload = SerializePingPong(nonce);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("pong", payload);
}

CNetMessage CNetMessageProcessor::CreateGetAddrMessage() {
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;

    return CNetMessage("getaddr", {});
}

CNetMessage CNetMessageProcessor::CreateAddrMessage(
    const std::vector<NetProtocol::CAddress>& addrs)
{
    std::vector<uint8_t> payload = SerializeAddrMessage(addrs);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("addr", payload);
}

CNetMessage CNetMessageProcessor::CreateInvMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    std::vector<uint8_t> payload = SerializeInvMessage(inv);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("inv", payload);
}

CNetMessage CNetMessageProcessor::CreateGetDataMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    std::vector<uint8_t> payload = SerializeInvMessage(inv);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + payload.size();

    return CNetMessage("getdata", payload);
}

CNetMessage CNetMessageProcessor::CreateBlockMessage(const CBlock& block) {
    CDataStream stream;

    stream.WriteInt32(block.nVersion);
    stream.WriteUint256(block.hashPrevBlock);
    stream.WriteUint256(block.hashMerkleRoot);
    stream.WriteUint32(block.nTime);
    stream.WriteUint32(block.nBits);
    stream.WriteUint32(block.nNonce);

    // VDF extension fields (version >= 4)
    if (block.IsVDFBlock()) {
        stream.WriteUint256(block.vdfOutput);
        stream.WriteUint256(block.vdfProofHash);
    }

    // Serialize transaction data
    stream.WriteCompactSize(block.vtx.size());
    if (!block.vtx.empty()) {
        stream.write(block.vtx.data(), block.vtx.size());
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("block", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateTxMessage(const CTransaction& tx) {
    CDataStream stream;

    // Serialize version
    stream.WriteInt32(tx.nVersion);

    // Serialize inputs
    stream.WriteCompactSize(tx.vin.size());
    for (const CTxIn& txin : tx.vin) {
        stream.WriteUint256(txin.prevout.hash);
        stream.WriteUint32(txin.prevout.n);

        stream.WriteCompactSize(txin.scriptSig.size());
        if (!txin.scriptSig.empty()) {
            stream.write(txin.scriptSig.data(), txin.scriptSig.size());
        }

        stream.WriteUint32(txin.nSequence);
    }

    // Serialize outputs
    stream.WriteCompactSize(tx.vout.size());
    for (const CTxOut& txout : tx.vout) {
        stream.WriteUint64(txout.nValue);

        stream.WriteCompactSize(txout.scriptPubKey.size());
        if (!txout.scriptPubKey.empty()) {
            stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
        }
    }

    // Serialize locktime
    stream.WriteUint32(tx.nLockTime);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("tx", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateGetHeadersMessage(const NetProtocol::CGetHeadersMessage& msg) {
    CDataStream stream;

    // Serialize locator size and hashes
    stream.WriteCompactSize(msg.locator.size());
    for (const uint256& hash : msg.locator) {
        stream.WriteUint256(hash);
    }

    // Serialize stop hash
    stream.WriteUint256(msg.hashStop);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("getheaders", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateHeadersMessage(const std::vector<CBlockHeader>& headers) {
    CDataStream stream;

    // Serialize header count
    stream.WriteCompactSize(headers.size());

    // Serialize each header
    for (const CBlockHeader& header : headers) {
        stream.WriteInt32(header.nVersion);
        stream.WriteUint256(header.hashPrevBlock);
        stream.WriteUint256(header.hashMerkleRoot);
        stream.WriteUint32(header.nTime);
        stream.WriteUint32(header.nBits);
        stream.WriteUint32(header.nNonce);

        // VDF extension fields (version >= 4)
        if (header.IsVDFBlock()) {
            stream.WriteUint256(header.vdfOutput);
            stream.WriteUint256(header.vdfProofHash);
        }

        // Transaction count (always 0 for headers message)
        stream.WriteCompactSize(0);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("headers", stream.GetData());
}

// BIP 130: sendheaders message (empty payload - just a signal)
CNetMessage CNetMessageProcessor::CreateSendHeadersMessage() {
    // sendheaders has no payload - it's just a signal that we prefer HEADERS over INV

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24;  // Just the header, no payload

    return CNetMessage("sendheaders", std::vector<uint8_t>());
}

// BIP 152: sendcmpct message
CNetMessage CNetMessageProcessor::CreateSendCmpctMessage(bool high_bandwidth, uint64_t version) {
    CDataStream stream;

    // Payload: bool (1 byte) + uint64_t version (8 bytes)
    stream.WriteUint8(high_bandwidth ? 1 : 0);
    stream.WriteUint64(version);

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("sendcmpct", stream.GetData());
}

// BIP 152: cmpctblock message
CNetMessage CNetMessageProcessor::CreateCmpctBlockMessage(const CBlockHeaderAndShortTxIDs& cmpctblock) {
    CDataStream stream;

    // Serialize header
    stream.WriteInt32(cmpctblock.header.nVersion);
    stream.WriteUint256(cmpctblock.header.hashPrevBlock);
    stream.WriteUint256(cmpctblock.header.hashMerkleRoot);
    stream.WriteUint32(cmpctblock.header.nTime);
    stream.WriteUint32(cmpctblock.header.nBits);
    stream.WriteUint32(cmpctblock.header.nNonce);

    // VDF extension fields (version >= 4)
    if (cmpctblock.header.IsVDFBlock()) {
        stream.WriteUint256(cmpctblock.header.vdfOutput);
        stream.WriteUint256(cmpctblock.header.vdfProofHash);
    }

    // Nonce for short ID calculation
    stream.WriteUint64(cmpctblock.nonce);

    // Prefilled transactions
    stream.WriteCompactSize(cmpctblock.prefilledtxn.size());
    for (const auto& ptx : cmpctblock.prefilledtxn) {
        stream.WriteCompactSize(ptx.index);

        // Serialize transaction
        stream.WriteInt32(ptx.tx.nVersion);

        // Inputs
        stream.WriteCompactSize(ptx.tx.vin.size());
        for (const auto& txin : ptx.tx.vin) {
            stream.WriteUint256(txin.prevout.hash);
            stream.WriteUint32(txin.prevout.n);
            stream.WriteCompactSize(txin.scriptSig.size());
            if (!txin.scriptSig.empty()) {
                stream.write(txin.scriptSig.data(), txin.scriptSig.size());
            }
            stream.WriteUint32(txin.nSequence);
        }

        // Outputs
        stream.WriteCompactSize(ptx.tx.vout.size());
        for (const auto& txout : ptx.tx.vout) {
            stream.WriteUint64(txout.nValue);
            stream.WriteCompactSize(txout.scriptPubKey.size());
            if (!txout.scriptPubKey.empty()) {
                stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
            }
        }

        stream.WriteUint32(ptx.tx.nLockTime);
    }

    // Short IDs (6 bytes each)
    stream.WriteCompactSize(cmpctblock.shorttxids.size());
    for (uint64_t shortid : cmpctblock.shorttxids) {
        // Write lower 6 bytes of the short ID
        for (int i = 0; i < 6; i++) {
            stream.WriteUint8((shortid >> (i * 8)) & 0xFF);
        }
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("cmpctblock", stream.GetData());
}

// BIP 152: getblocktxn message
CNetMessage CNetMessageProcessor::CreateGetBlockTxnMessage(const BlockTransactionsRequest& req) {
    CDataStream stream;

    // Block hash
    stream.WriteUint256(req.blockhash);

    // Indices (field name is 'indexes' per BIP 152)
    stream.WriteCompactSize(req.indexes.size());
    for (uint16_t idx : req.indexes) {
        stream.WriteCompactSize(idx);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("getblocktxn", stream.GetData());
}

// BIP 152: blocktxn message
CNetMessage CNetMessageProcessor::CreateBlockTxnMessage(const BlockTransactions& resp) {
    CDataStream stream;

    // Block hash
    stream.WriteUint256(resp.blockhash);

    // Transactions
    stream.WriteCompactSize(resp.txn.size());
    for (const auto& tx : resp.txn) {
        stream.WriteInt32(tx.nVersion);

        // Inputs
        stream.WriteCompactSize(tx.vin.size());
        for (const auto& txin : tx.vin) {
            stream.WriteUint256(txin.prevout.hash);
            stream.WriteUint32(txin.prevout.n);
            stream.WriteCompactSize(txin.scriptSig.size());
            if (!txin.scriptSig.empty()) {
                stream.write(txin.scriptSig.data(), txin.scriptSig.size());
            }
            stream.WriteUint32(txin.nSequence);
        }

        // Outputs
        stream.WriteCompactSize(tx.vout.size());
        for (const auto& txout : tx.vout) {
            stream.WriteUint64(txout.nValue);
            stream.WriteCompactSize(txout.scriptPubKey.size());
            if (!txout.scriptPubKey.empty()) {
                stream.write(txout.scriptPubKey.data(), txout.scriptPubKey.size());
            }
        }

        stream.WriteUint32(tx.nLockTime);
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();

    return CNetMessage("blocktxn", stream.GetData());
}

// ============================================================
// Digital DNA P2P Protocol Implementation
// ============================================================

// DNA rate limit constants
static const int64_t DNA_PING_COOLDOWN_SEC = 10;    // 1 dnalping per peer per 10s
static const int64_t DNA_TSYNC_COOLDOWN_SEC = 30;   // 1 dnatsync per peer per 30s
static const int64_t DNA_BWTEST_COOLDOWN_SEC = 600;  // 1 dnabwtest per peer per 10min
static const int DNA_BWTEST_GLOBAL_MAX = 3;           // Max 3 concurrent BW tests globally
static const int64_t DNA_IDENT_COOLDOWN_SEC = 10;    // 1 dnaireq per peer per 10s
static const int64_t DNA_NONCE_TIMEOUT_SEC = 60;      // Nonces expire after 60s

void CNetMessageProcessor::RegisterDNANonce(uint64_t nonce, int peer_id, uint64_t send_timestamp_us) {
    std::lock_guard<std::mutex> lock(cs_dna_nonces);
    int64_t now = GetTime();
    dna_pending_nonces_[nonce] = {peer_id, now, send_timestamp_us};
}

bool CNetMessageProcessor::ValidateDNANonce(uint64_t nonce, int peer_id) {
    std::lock_guard<std::mutex> lock(cs_dna_nonces);
    auto it = dna_pending_nonces_.find(nonce);
    if (it == dna_pending_nonces_.end()) return false;
    if (it->second.peer_id != peer_id) return false;
    int64_t now = GetTime();
    if (now - it->second.send_time_sec > DNA_NONCE_TIMEOUT_SEC) {
        dna_pending_nonces_.erase(it);
        return false;
    }
    dna_pending_nonces_.erase(it);
    return true;
}

uint64_t CNetMessageProcessor::GetDNANonceSendTimestamp(uint64_t nonce) const {
    std::lock_guard<std::mutex> lock(cs_dna_nonces);
    auto it = dna_pending_nonces_.find(nonce);
    if (it == dna_pending_nonces_.end()) return 0;
    return it->second.send_timestamp_us;
}

void CNetMessageProcessor::CleanupDNANonces() {
    std::lock_guard<std::mutex> lock(cs_dna_nonces);
    int64_t now = GetTime();
    for (auto it = dna_pending_nonces_.begin(); it != dna_pending_nonces_.end();) {
        if (now - it->second.send_time_sec > DNA_NONCE_TIMEOUT_SEC) {
            it = dna_pending_nonces_.erase(it);
        } else {
            ++it;
        }
    }
}

bool CNetMessageProcessor::ProcessDNALatencyPingMessage(int peer_id, CDataStream& stream) {
    try {
        // Rate limit: 1 per peer per 10s
        {
            std::lock_guard<std::mutex> lock(cs_dna_rate_limit);
            int64_t now = GetTime();
            auto& last = peer_dna_ping_timestamps[peer_id];
            if (now - last < DNA_PING_COOLDOWN_SEC) {
                peer_manager.Misbehaving(peer_id, 5, MisbehaviorType::PING_RATE_EXCEEDED);
                return false;
            }
            last = now;
        }

        uint64_t nonce = stream.ReadUint64();
        on_dna_latency_ping(peer_id, nonce);
        return true;
    } catch (const std::out_of_range&) {
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessDNALatencyPongMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();

        // Pong must match a pending nonce we sent
        if (!ValidateDNANonce(nonce, peer_id)) {
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_HANDSHAKE);
            return false;
        }

        // Get receive timestamp for RTT calculation
        auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        on_dna_latency_pong(peer_id, nonce, static_cast<uint64_t>(now_us));
        return true;
    } catch (const std::out_of_range&) {
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessDNATimeSyncMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t sender_ts_us = stream.ReadUint64();
        uint64_t sender_wall_ms = stream.ReadUint64();
        uint64_t nonce = stream.ReadUint64();
        uint8_t is_response_byte = 0;
        stream.read(&is_response_byte, 1);
        bool is_response = (is_response_byte != 0);

        uint64_t local_send_ts_us = 0;
        if (is_response) {
            // Retrieve stored send timestamp BEFORE validation erases the nonce
            local_send_ts_us = GetDNANonceSendTimestamp(nonce);
            // Response: must match a pending nonce
            if (!ValidateDNANonce(nonce, peer_id)) {
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_HANDSHAKE);
                return false;
            }
        } else {
            // Request: rate limit
            std::lock_guard<std::mutex> lock(cs_dna_rate_limit);
            int64_t now = GetTime();
            auto& last = peer_dna_tsync_timestamps[peer_id];
            if (now - last < DNA_TSYNC_COOLDOWN_SEC) {
                peer_manager.Misbehaving(peer_id, 5, MisbehaviorType::PING_RATE_EXCEEDED);
                return false;
            }
            last = now;
        }

        on_dna_time_sync(peer_id, sender_ts_us, sender_wall_ms, nonce, is_response, local_send_ts_us);
        return true;
    } catch (const std::out_of_range&) {
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessDNABWTestMessage(int peer_id, CDataStream& stream) {
    bool counter_incremented = false;
    try {
        uint64_t nonce = stream.ReadUint64();
        uint32_t payload_size = stream.ReadUint32();
        uint64_t send_wall_ms = stream.ReadUint64();  // Sender's wall clock at send time

        // Validate: claimed payload_size must match actual remaining bytes
        size_t actual_remaining = stream.remaining();
        if (actual_remaining != payload_size) {
            peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }

        // Rate limit: 1 per peer per 10min, max 3 global
        {
            std::lock_guard<std::mutex> lock(cs_dna_rate_limit);
            int64_t now = GetTime();
            auto& last = peer_dna_bwtest_timestamps[peer_id];
            if (now - last < DNA_BWTEST_COOLDOWN_SEC) {
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PING_RATE_EXCEEDED);
                return false;
            }
            if (dna_bwtest_global_count_.load() >= DNA_BWTEST_GLOBAL_MAX) {
                // Too many concurrent tests, silently drop
                return true;
            }
            last = now;
            dna_bwtest_global_count_++;
            counter_incremented = true;
        }

        on_dna_bw_test(peer_id, payload_size, nonce, send_wall_ms);
        dna_bwtest_global_count_--;
        return true;
    } catch (const std::out_of_range&) {
        if (counter_incremented) dna_bwtest_global_count_--;
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        if (counter_incremented) dna_bwtest_global_count_--;
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessDNABWResultMessage(int peer_id, CDataStream& stream) {
    try {
        uint64_t nonce = stream.ReadUint64();

        // Must match a pending nonce
        if (!ValidateDNANonce(nonce, peer_id)) {
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_HANDSHAKE);
            return false;
        }

        uint64_t upload_bits = stream.ReadUint64();
        uint64_t download_bits = stream.ReadUint64();
        double upload_mbps, download_mbps;
        std::memcpy(&upload_mbps, &upload_bits, 8);
        std::memcpy(&download_mbps, &download_bits, 8);

        // Sanity check values
        if (upload_mbps < 0.0 || upload_mbps > 100000.0 ||
            download_mbps < 0.0 || download_mbps > 100000.0) {
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
            return false;
        }

        on_dna_bw_result(peer_id, nonce, upload_mbps, download_mbps);
        return true;
    } catch (const std::out_of_range&) {
        peer_manager.Misbehaving(peer_id, 20, MisbehaviorType::TRUNCATED_MESSAGE);
        return false;
    } catch (const std::exception& e) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

// DNA message creation

CNetMessage CNetMessageProcessor::CreateDNALatencyPingMessage(uint64_t nonce) {
    CDataStream stream;
    stream.WriteUint64(nonce);
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnalping", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNALatencyPongMessage(uint64_t nonce) {
    CDataStream stream;
    stream.WriteUint64(nonce);
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnalpong", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNATimeSyncMessage(uint64_t sender_ts_us,
    uint64_t sender_wall_ms, uint64_t nonce, bool is_response)
{
    CDataStream stream;
    stream.WriteUint64(sender_ts_us);
    stream.WriteUint64(sender_wall_ms);
    stream.WriteUint64(nonce);
    uint8_t resp_byte = is_response ? 1 : 0;
    stream.write(&resp_byte, 1);
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnatsync", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNABWTestMessage(uint64_t nonce, uint32_t payload_size) {
    CDataStream stream;
    stream.WriteUint64(nonce);
    stream.WriteUint32(payload_size);
    // Send wall clock timestamp for bandwidth elapsed calculation
    auto send_wall_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    stream.WriteUint64(send_wall_ms);
    // Append random payload
    std::vector<uint8_t> payload(payload_size);
    std::mt19937 rng(static_cast<uint32_t>(nonce & 0xFFFFFFFF));
    for (auto& b : payload) b = static_cast<uint8_t>(rng() & 0xFF);
    stream.write(payload.data(), payload.size());
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnabwtest", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNABWResultMessage(uint64_t nonce,
    double upload_mbps, double download_mbps)
{
    CDataStream stream;
    stream.WriteUint64(nonce);
    uint64_t upload_bits, download_bits;
    std::memcpy(&upload_bits, &upload_mbps, 8);
    std::memcpy(&download_bits, &download_mbps, 8);
    stream.WriteUint64(upload_bits);
    stream.WriteUint64(download_bits);
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnabwres", stream.GetData());
}

// ---------------------------------------------------------------------------
// DNA Identity Request/Response (Phase 3b)
// ---------------------------------------------------------------------------

bool CNetMessageProcessor::ProcessDNAIdentReqMessage(int peer_id, CDataStream& stream) {
    try {
        if (stream.size() < 20) {
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::TRUNCATED_MESSAGE);
            return false;
        }

        // Rate limit: 1 per peer per 10s (silently drop excess — no misbehavior penalty)
        {
            std::lock_guard<std::mutex> lock(cs_dna_rate_limit);
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            auto& last = peer_dna_ident_timestamps[peer_id];
            if (now - last < DNA_IDENT_COOLDOWN_SEC) {
                return true;  // Silently accept — rate-limited DNA requests are not misbehavior
            }
            last = now;
        }

        std::array<uint8_t, 20> mik{};
        stream.read(mik.data(), 20);

        if (on_dna_ident_req) {
            on_dna_ident_req(peer_id, mik);
        }
        return true;
    } catch (...) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

bool CNetMessageProcessor::ProcessDNAIdentResMessage(int peer_id, CDataStream& stream) {
    try {
        if (stream.remaining() < 21) {
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::TRUNCATED_MESSAGE);
            return false;
        }

        std::array<uint8_t, 20> mik{};
        stream.read(mik.data(), 20);

        uint8_t found = stream.ReadUint8();

        std::vector<uint8_t> dna_data;
        if (found == 0x01 && stream.remaining() >= 2) {
            uint16_t data_len = stream.ReadUint16();
            if (data_len > 4096 || stream.remaining() < data_len) {
                peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_MESSAGE_SIZE);
                return false;
            }
            dna_data.resize(data_len);
            stream.read(dna_data.data(), data_len);
        }

        // Phase 1.5: parse optional SMP1 trailer. The trailer starts at the
        // byte immediately after dna_data (or after the `found` byte if
        // found==0). Trailer parse MUST NOT inspect bytes inside dna_data —
        // the offset rule prevents dual-interpretation of DNA bytes. Use
        // `remaining()` not `size()`: `size()` is the buffer total, which
        // includes already-read bytes; `remaining()` is the unread tail.
        std::vector<uint8_t> trailer_bytes;
        size_t tail = stream.remaining();
        if (tail > 0) {
            trailer_bytes.resize(tail);
            stream.read(trailer_bytes.data(), tail);
        }

        digital_dna::SampleEnvelope envelope;
        auto parse_result = digital_dna::SampleEnvelope::TryParse(trailer_bytes, envelope);

        // found=0 + SMP1 trailer is spec-violating (a sig without data is
        // meaningless) — reject with misbehaviour.
        if (parse_result == digital_dna::SampleEnvelope::ParseResult::SIGNED &&
            found != 0x01) {
            std::cout << "[DNA] Malformed SMP1 trailer from peer " << peer_id
                      << " (signed trailer with found=0)" << std::endl;
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }
        // MALFORMED SMP1 trailer — attacker or buggy sender. Penalise.
        // The "[DNA] Malformed SMP1 trailer" log line is the rollout-gate
        // observable referenced in .claude/contracts/dna_phase_1_5.md
        // (NYC 24h gate: zero of these expected).
        if (parse_result == digital_dna::SampleEnvelope::ParseResult::MALFORMED) {
            std::cout << "[DNA] Malformed SMP1 trailer from peer " << peer_id << std::endl;
            peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::INVALID_MESSAGE_SIZE);
            return false;
        }
        // UNKNOWN_MAGIC or NONE — envelope stays empty/unsigned, no penalty.
        // The handler routes unsigned messages through the merge-fill path.

        if (on_dna_ident_res) {
            on_dna_ident_res(peer_id, mik, found == 0x01, dna_data, envelope);
        }
        return true;
    } catch (...) {
        peer_manager.Misbehaving(peer_id, 10, MisbehaviorType::PARSE_FAILURE);
        return false;
    }
}

CNetMessage CNetMessageProcessor::CreateDNAIdentReqMessage(const std::array<uint8_t, 20>& mik) {
    CDataStream stream;
    stream.write(mik.data(), 20);
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnaireq", stream.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNAIdentResMessage(
    const std::array<uint8_t, 20>& mik, bool found,
    const std::vector<uint8_t>& dna_data,
    const digital_dna::SampleEnvelope* envelope,
    int peer_version)
{
    CDataStream stream;
    stream.write(mik.data(), 20);
    stream.WriteUint8(found ? 0x01 : 0x00);
    if (found && !dna_data.empty()) {
        uint16_t data_len = static_cast<uint16_t>(std::min(dna_data.size(), size_t(4096)));
        stream.WriteUint16(data_len);
        stream.write(dna_data.data(), data_len);
    }

    // Phase 1.5: append SMP1 trailer iff (a) caller supplied a signed
    // envelope AND (b) peer version meets the minimum. Sending a trailer to
    // an older peer would trip the old {21, 4117} payload cap and trigger
    // misbehaviour scoring on that peer. Silent fallback to unsigned keeps
    // a single sender call-site safe across a mixed-version network.
    if (envelope != nullptr &&
        !envelope->signature.empty() &&
        peer_version >= NetProtocol::DNA_SMP1_MIN_PROTOCOL_VERSION) {
        auto trailer = envelope->ToWireBytes();
        if (!trailer.empty()) {
            stream.write(trailer.data(), trailer.size());
        }
    }

    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + stream.size();
    return CNetMessage("dnaires", stream.GetData());
}

// Phase 2: DNA Verification message processing

static constexpr int64_t DNA_VERIFY_COOLDOWN_SEC = 30;
static constexpr int DNA_VERIFY_GLOBAL_MAX = 3;
static constexpr int DNA_ATTEST_PER_HOUR_MAX = 10;

bool CNetMessageProcessor::ProcessDNAVerifyChallengeMessage(int peer_id, CDataStream& stream) {
    std::vector<uint8_t> payload = stream.GetData();
    if (payload.size() < 92) return false;  // Minimum challenge size

    // Rate limit: 1 per peer per 30 seconds
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    auto it = peer_dna_verify_timestamps.find(peer_id);
    if (it != peer_dna_verify_timestamps.end() && (now - it->second) < DNA_VERIFY_COOLDOWN_SEC) {
        return true;  // Silently drop
    }
    peer_dna_verify_timestamps[peer_id] = now;

    if (on_dna_verify_challenge) {
        on_dna_verify_challenge(peer_id, payload);
    }
    return true;
}

bool CNetMessageProcessor::ProcessDNAVerifyResponseMessage(int peer_id, CDataStream& stream) {
    std::vector<uint8_t> payload = stream.GetData();
    if (payload.size() < 70) return false;  // Minimum response size

    if (on_dna_verify_response) {
        on_dna_verify_response(peer_id, payload);
    }
    return true;
}

bool CNetMessageProcessor::ProcessDNAVerifyAttestMessage(int peer_id, CDataStream& stream) {
    std::vector<uint8_t> payload = stream.GetData();
    if (payload.size() < 112 || payload.size() > 8192) return false;  // Size bounds

    // Rate limit: max 10 per peer per hour
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    auto it = peer_dna_attest_timestamps.find(peer_id);
    if (it != peer_dna_attest_timestamps.end() && (now - it->second) < 360) {
        return true;  // Silently drop (allow ~10/hour)
    }
    peer_dna_attest_timestamps[peer_id] = now;

    if (on_dna_verify_attest) {
        on_dna_verify_attest(peer_id, payload);
    }
    return true;
}

CNetMessage CNetMessageProcessor::CreateDNAVerifyChallengeMessage(const std::vector<uint8_t>& data) {
    CDataStream ss;
    ss.write(data.data(), data.size());
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + ss.size();
    return CNetMessage("dnavchall", ss.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNAVerifyResponseMessage(const std::vector<uint8_t>& data) {
    CDataStream ss;
    ss.write(data.data(), data.size());
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + ss.size();
    return CNetMessage("dnavresp", ss.GetData());
}

CNetMessage CNetMessageProcessor::CreateDNAVerifyAttestMessage(const std::vector<uint8_t>& data) {
    CDataStream ss;
    ss.write(data.data(), data.size());
    g_network_stats.messages_sent++;
    g_network_stats.bytes_sent += 24 + ss.size();
    return CNetMessage("dnavatts", ss.GetData());
}

// Serialization helpers

std::vector<uint8_t> CNetMessageProcessor::SerializeVersionMessage(
    const NetProtocol::CVersionMessage& msg)
{
    CDataStream stream;

    // Basic fields
    stream.WriteInt32(msg.version);
    stream.WriteUint64(msg.services);
    stream.WriteInt64(msg.timestamp);

    // addr_recv - receiver's network address (26 bytes)
    // Note: CAddress has time field, but version message format doesn't include it
    stream.WriteUint64(msg.addr_recv.services);
    stream.write(msg.addr_recv.ip, 16);
    stream.WriteUint16(msg.addr_recv.port);

    // addr_from - sender's network address (26 bytes)
    stream.WriteUint64(msg.addr_from.services);
    stream.write(msg.addr_from.ip, 16);
    stream.WriteUint16(msg.addr_from.port);

    // Remaining fields
    stream.WriteUint64(msg.nonce);
    stream.WriteString(msg.user_agent);
    stream.WriteInt32(msg.start_height);
    stream.WriteUint8(msg.relay ? 1 : 0);

    // v1.4.2+: Genesis hash to prevent cross-chain connections
    // Old clients will ignore extra bytes, new clients validate genesis match
    stream.write(msg.genesis_hash.data, 32);

    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializePingPong(uint64_t nonce) {
    CDataStream stream;
    stream.WriteUint64(nonce);
    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializeAddrMessage(
    const std::vector<NetProtocol::CAddress>& addrs)
{
    CDataStream stream;
    stream.WriteCompactSize(addrs.size());
    for (const auto& addr : addrs) {
        stream.WriteUint32(addr.time);
        stream.WriteUint64(addr.services);
        stream.write(addr.ip, 16);
        stream.WriteUint16(addr.port);
    }
    return stream.GetData();
}

std::vector<uint8_t> CNetMessageProcessor::SerializeInvMessage(
    const std::vector<NetProtocol::CInv>& inv)
{
    CDataStream stream;
    stream.WriteCompactSize(inv.size());
    for (const auto& item : inv) {
        stream.WriteUint32(item.type);
        stream.WriteUint256(item.hash);
    }
    return stream.GetData();
}

// REMOVED: CConnectionManager implementation - replaced by CConnman
// All methods removed - see CConnman class for equivalent functionality


// ============================================================================
// Phase 5.3: Transaction Relay Functions
// ============================================================================

/**
 * ProcessMempoolMessage
 *
 * Handle "mempool" P2P message from a peer requesting our mempool contents.
 * Responds with INV messages for all transactions in our mempool.
 * Rate-limited to prevent DoS.
 */
bool CNetMessageProcessor::ProcessMempoolMessage(int peer_id) {
    // Rate limit: track last mempool response per peer
    static std::map<int, std::chrono::steady_clock::time_point> last_mempool_response;
    static std::mutex mempool_rate_mutex;

    {
        std::lock_guard<std::mutex> lock(mempool_rate_mutex);
        auto now = std::chrono::steady_clock::now();
        auto it = last_mempool_response.find(peer_id);
        if (it != last_mempool_response.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed < 60) {
                return true;  // Rate limited - ignore
            }
        }
        last_mempool_response[peer_id] = now;
    }

    auto* mempool = g_mempool.load();
    if (!mempool) return true;

    extern NodeContext g_node_context;
    if (!g_node_context.connman || !g_node_context.message_processor) return true;

    auto txs = mempool->GetOrderedTxs();
    if (txs.empty()) return true;

    // Send INV for all mempool transactions (batched, max 1000 per message)
    std::vector<NetProtocol::CInv> inv_vec;
    inv_vec.reserve(std::min(txs.size(), (size_t)1000));

    for (const auto& tx : txs) {
        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, tx->GetHash()));
        if (inv_vec.size() >= 1000) {
            CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
            g_node_context.connman->PushMessage(peer_id, inv_msg);
            inv_vec.clear();
        }
    }

    // Send remaining
    if (!inv_vec.empty()) {
        CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
        g_node_context.connman->PushMessage(peer_id, inv_msg);
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[P2P] Sent " << txs.size() << " mempool tx INV(s) to peer "
                  << peer_id << " (mempool request)" << std::endl;

    return true;
}

/**
 * AnnounceTransactionToPeers
 *
 * Announce a transaction to all connected peers via INV message.
 * This is called when:
 * 1. Wallet sends a new transaction
 * 2. Node receives and validates a transaction from a peer (relay)
 *
 * @param txid Transaction hash to announce
 * @param exclude_peer Peer ID to exclude (e.g., originating peer), -1 for none
 */
void AnnounceTransactionToPeers(const uint256& txid, int64_t exclude_peer, bool force_reannounce) {
    // Check if networking infrastructure is initialized
    // Phase 1.2: Use NodeContext for peer manager
    // P0-5 FIX: Load atomic pointer
    auto* tx_relay = g_tx_relay_manager.load();
    extern NodeContext g_node_context;
    // Phase 5: Use CConnman instead of deprecated CConnectionManager
    if (!g_node_context.peer_manager || !g_node_context.connman || !g_node_context.message_processor || !tx_relay) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[TX-RELAY] Cannot announce transaction " << txid.GetHex().substr(0, 16)
                      << "... (networking not initialized)" << std::endl;
        return;
    }

    // Get list of connected peers
    std::vector<std::shared_ptr<CPeer>> peers = g_node_context.peer_manager->GetConnectedPeers();

    if (peers.empty()) {
        if (g_verbose.load(std::memory_order_relaxed))
            std::cout << "[TX-RELAY] No connected peers to announce transaction "
                      << txid.GetHex().substr(0, 16) << "..." << std::endl;
        return;
    }

    int announced_count = 0;
    int skipped_count = 0;

    // Announce to each peer
    for (const auto& peer : peers) {
        // Skip excluded peer
        if (peer->id == exclude_peer) {
            continue;
        }

        // Skip if not handshake complete
        if (!peer->IsHandshakeComplete()) {
            continue;
        }

        // Skip if peer doesn't relay transactions
        if (!peer->relay) {
            continue;
        }

        // Check if we should announce to this peer (skip for rebroadcast)
        if (!force_reannounce && !tx_relay->ShouldAnnounce(peer->id, txid)) {
            skipped_count++;
            continue;
        }

        // Create INV message
        std::vector<NetProtocol::CInv> inv_vec;
        inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, txid));

        CNetMessage inv_message = g_node_context.message_processor->CreateInvMessage(inv_vec);

        // Send INV message to peer
        // Phase 5: Use CConnman instead of deprecated CConnectionManager
        // PushMessage always succeeds (queues message), so we can mark as announced
        g_node_context.connman->PushMessage(peer->id, inv_message);
        // Mark as announced to prevent duplicates
        tx_relay->MarkAnnounced(peer->id, txid);
        announced_count++;
    }

    if (g_verbose.load(std::memory_order_relaxed))
        std::cout << "[TX-RELAY] Announced transaction " << txid.GetHex().substr(0, 16)
                  << "... to " << announced_count << " peer(s) "
                  << "(skipped " << skipped_count << " already announced, "
                  << "excluded peer " << exclude_peer << ")" << std::endl;
}
