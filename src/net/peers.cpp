// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <net/peers.h>
#include <net/dns.h>
#include <net/block_tracker.h>
#include <core/node_context.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <node/mempool.h>
#include <net/port/sync_coordinator.h>  // Phase 6 PR6.5a: routes via ISyncCoordinator
#include <net/headers_manager.h>        // F19: CHeadersManager::OnPeerDisconnected
#include <net/net.h>
#include <net/connman.h>
#include <net/protocol.h>
#include <consensus/chain.h>  // Issue #83: g_chainstate.GetHeight() (replaces g_chain_height)
#include <net/port/addrman_v2.h>             // Phase 1 port: CAddrMan_v2 (default)
#include <net/port/legacy_addrman_adapter.h> // Phase 1 port: legacy fallback
#include <net/port/peer_scorer.h>             // Phase 2 port: CPeerScorer
#include <digital_dna/digital_dna.h>  // Digital DNA: Sybil-resistant identity
#include <util/strencodings.h>
#include <util/logging.h>
#include <algorithm>
#include <cstdlib>  // std::getenv (Phase 1 port: addrman impl selection)
#include <cstring>  // std::strcmp
#include <set>

// SSOT: Access to global node context for CBlockTracker
extern NodeContext g_node_context;

// Global peer manager instance (raw pointer - ownership in g_node_context)
// REMOVED: g_peer_manager global - use NodeContext::peer_manager instead

// CPeer implementation

// Phase 2 port: CPeer::Misbehaving DELETED (Q3=B). Scoring lives in
// CPeerScorer; the cumulative-score-and-cross-threshold logic moved to
// CPeerScorer::Misbehaving. Callers that previously did
// `peer->Misbehaving(score)` now go through `CPeerManager::Misbehaving(
// peer_id, score, type)` which forwards to the scorer.

void CPeer::Ban(int64_t ban_until) {
    state = STATE_BANNED;
    ban_time = ban_until;
}

void CPeer::Disconnect() {
    if (state != STATE_BANNED) {
        state = STATE_DISCONNECTED;
    }
}

std::string CPeer::ToString() const {
    // Phase 2 port: misbehavior_score field deleted; this string is used
    // only for debug logging where the score is a nice-to-have, not load-
    // bearing. Callers wanting the score should query
    // CPeerManager::GetMisbehaviorScore(peer_id) directly.
    return strprintf("CPeer(id=%d, addr=%s, state=%d, version=%d, height=%d)",
                    id, addr.ToString().c_str(), state, version,
                    start_height);
}

// CPeerManager implementation

CPeerManager::CPeerManager(const std::string& datadir)
    : banman(datadir), next_peer_id(1), data_dir(datadir) {
    InitializeSeedNodes();

    // Phase 1 port: select address-manager implementation.
    //
    // Default: CAddrMan_v2 (new port). Operator escape hatch:
    //   DILITHION_USE_ADDRMAN_V2=0  -> wrap legacy CAddrMan via the adapter.
    //
    // The adapter exposes the same IAddressManager surface, so the rest of
    // CPeerManager can call addrman-> uniformly regardless of impl. CLI-flag
    // wiring is deliberately deferred to Phase 6 (PeerManager rewrite); env
    // var keeps the rollback path operator-accessible without that plumbing.
    {
        const char* env = std::getenv("DILITHION_USE_ADDRMAN_V2");
        const bool use_legacy = (env != nullptr) && (std::strcmp(env, "0") == 0);
        if (use_legacy) {
            addrman = std::make_unique<dilithion::net::port::LegacyAddrManAdapter>();
        } else {
            addrman = std::make_unique<dilithion::net::port::CAddrMan_v2>();
        }
    }

    // Configure persistence path before any Load/Save call. Either impl
    // silently ignores Save/Load when the path is empty (headless tests).
    if (!data_dir.empty()) {
        addrman->SetDataPath(data_dir + "/peers.dat");
        LoadPeers();
    }

    // Phase 2 port: select misbehavior scorer.
    //
    // Default: CPeerScorer (the new port). Operator escape hatch:
    //   DILITHION_USE_NEW_PEER_SCORER=0  -> m_scorer stays null; Misbehaving
    //                                       and DecayMisbehaviorScores become
    //                                       tracking-disabled no-ops. Manual
    //                                       ban via RPC still works; protocol-
    //                                       level disconnects still fire.
    //
    // Same env-var pattern as Phase 1's DILITHION_USE_ADDRMAN_V2. CLI-flag
    // wiring deferred to Phase 6 per plan §10 Q4 / consistency rule.
    {
        const char* env = std::getenv("DILITHION_USE_NEW_PEER_SCORER");
        const bool disabled = (env != nullptr) && (std::strcmp(env, "0") == 0);
        if (!disabled) {
            m_scorer = std::make_unique<dilithion::net::port::CPeerScorer>();
        }
    }

    // Network: Initialize enhanced peer discovery against the interface.
    peer_discovery = std::make_unique<CPeerDiscovery>(*this, *addrman);

    // Network: Connection quality tracker is initialized automatically (default constructor)
}

// Phase 2 port: cumulative misbehavior score for a peer. Replaces direct
// reads of the deleted CPeer::misbehavior_score field. Returns 0 if the
// scorer is null (env-var=OFF tracking-disabled mode) or if the peer has
// no recorded score.
int CPeerManager::GetMisbehaviorScore(int peer_id) const {
    if (!m_scorer) return 0;
    return m_scorer->GetScore(peer_id);
}

// Phase 3: typed-reason Misbehaving for HeadersSync-layer call sites.
// Routes through the maybe_punish_node.h wrapper to compute the weight
// (DefaultWeight + Q6=B override), maps to the legacy diagnostic enum
// for banlist.dat audit, then calls the existing Misbehaving forwarder
// so seed-node guard + banman.Ban + AddrMan signal all fire.
void CPeerManager::MisbehaveHeaders(
    int peer_id,
    ::dilithion::net::port::HeaderRejectReason reason)
{
    const int weight = ::dilithion::net::port::HeaderRejectWeight(reason);
    const auto policy_type =
        ::dilithion::net::port::MapHeaderRejectToMisbehaviorType(reason);
    const ::MisbehaviorType diag =
        ::dilithion::net::port::MapPolicyToDiagnostic(policy_type);
    Misbehaving(peer_id, weight, diag);
}

bool CPeerManager::SavePeers() {
    if (data_dir.empty()) {
        return false;
    }

    std::string path = data_dir + "/peers.dat";
    // SetDataPath was already configured in the constructor; this just
    // re-affirms in case the data_dir changed mid-life (unusual). Safe to
    // call repeatedly.
    addrman->SetDataPath(path);
    bool result = addrman->Save();

    if (result) {
        LogPrintf(NET, INFO, "Saved %zu peer addresses to %s", addrman->Size(), path.c_str());
    } else {
        LogPrintf(NET, ERROR, "Failed to save peers to %s", path.c_str());
    }

    return result;
}

bool CPeerManager::LoadPeers() {
    if (data_dir.empty()) {
        return false;
    }

    std::string path = data_dir + "/peers.dat";
    addrman->SetDataPath(path);
    bool result = addrman->Load();

    if (result) {
        LogPrintf(NET, INFO, "Loaded %zu peer addresses from %s", addrman->Size(), path.c_str());
    }
    // Silent if no existing peers.dat - normal for new node

    return result;
}

std::shared_ptr<CPeer> CPeerManager::AddPeer(const NetProtocol::CAddress& addr) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Check if IP is banned using CBanManager
    std::string ip = addr.ToStringIP();

    if (banman.IsBanned(ip)) {
        return nullptr;
    }

    // BUG #105 FIX: Check connection limit using CONNECTED peer count, not map size
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    if (connected >= MAX_TOTAL_CONNECTIONS) {
        return nullptr;
    }

    // Create new peer
    auto peer = std::make_shared<CPeer>(next_peer_id++, addr);
    peers[peer->id] = peer;


    return peer;
}

std::shared_ptr<CPeer> CPeerManager::AddPeerWithId(int peer_id) {
    // BUG #124 FIX: Add peer with specific ID for inbound connections
    // Inbound connections don't go through AddPeer(), so we need to create the peer
    // with the exact ID that CConnectionManager uses

    // First, try to get address from CNode (need to lock cs_nodes first to avoid deadlock)
    NetProtocol::CAddress addr;
    {
        std::lock_guard<std::recursive_mutex> lock(cs_nodes);
        auto node_it = node_refs.find(peer_id);
        if (node_it != node_refs.end() && node_it->second) {
            addr = node_it->second->addr;
        }
    }

    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Check if peer already exists
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        // BUG FIX: Update address if it was zeroed
        if (it->second->addr.IsNull() && !addr.IsNull()) {
            it->second->addr = addr;
        }
        if (it->second->connect_time == 0) {
            it->second->connect_time = GetTime();
        }
        return it->second;
    }

    // BUG #105 FIX: Check connection limit using CONNECTED peer count
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    if (connected >= MAX_TOTAL_CONNECTIONS) {
        return nullptr;
    }

    // Create new peer with the specified ID and address from CNode
    auto peer = std::make_shared<CPeer>(peer_id, addr);
    peer->state = CPeer::STATE_CONNECTED;
    peers[peer_id] = peer;

    // Update next_peer_id if needed to avoid ID collisions (atomic CAS loop)
    int expected = next_peer_id.load();
    while (peer_id >= expected) {
        if (next_peer_id.compare_exchange_weak(expected, peer_id + 1)) {
            break;
        }
    }

    return peer;
}

void CPeerManager::RemovePeer(int peer_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        it->second->Disconnect();
        peers.erase(it);
    }
    // Phase 2 port: reclaim the scorer's map slot for this NodeId. The
    // map would otherwise grow unbounded over node uptime (slow-leak DoS).
    if (m_scorer) m_scorer->ResetScore(peer_id);
}

std::shared_ptr<CPeer> CPeerManager::GetPeer(int peer_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    return (it != peers.end()) ? it->second : nullptr;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetAllPeers() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        result.push_back(pair.second);
    }
    // P5-LOW FIX: Return without std::move to allow RVO (copy elision)
    return result;
}

std::vector<std::shared_ptr<CPeer>> CPeerManager::GetConnectedPeers() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::shared_ptr<CPeer>> result;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            result.push_back(pair.second);
        }
    }
    // P5-LOW FIX: Return without std::move to allow RVO (copy elision)
    return result;
}

std::vector<CPeerManager::BlockDownloadEntry> CPeerManager::GetBlockDownloadSnapshot() const {
    // Phase 10 PR10.2 — joint atomic snapshot under cs_peers.
    //
    // Lock-ordering: cs_peers → block_tracker.m_mutex (established order
    // at the two genuinely-nested precedents MarkBlockAsInFlight + Get-
    // BlocksInFlightForPeer; see header docblock for audit details). No
    // deadlock potential — block_tracker's encapsulation invariant
    // (block_tracker.h:419) prevents the inverse order from existing.
    //
    // Performance profile (PR10.2-RT-MEDIUM-1 honest characterization):
    // holds cs_peers for O(N) where N is connected-peer count (capped at
    // 125 by MAX_OUTBOUND_CONNECTIONS + max_inbound). Each iteration
    // nested-locks block_tracker.m_mutex for an O(1) map lookup. Worst-
    // case hold time at N=125 is ~20-50µs (per-iteration map lookup is
    // a few hundred ns + recursive_mutex acquisition overhead). This is
    // operationally fine for a telemetry-tier RPC consumed every ~10min
    // during burn-in (PR9.2 runbook §3 cadence) — but would NOT be
    // appropriate inside a hot peer-event path that holds cs_peers
    // under load (e.g. peer-event dispatch, MarkBlockAsInFlight per
    // block request).
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    std::vector<BlockDownloadEntry> result;
    if (!g_node_context.block_tracker) {
        return result;  // empty — block_tracker not initialized
    }

    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            BlockDownloadEntry entry;
            entry.peer_id = pair.first;
            entry.blocks_in_flight = g_node_context.block_tracker->GetPeerInFlightCount(pair.first);
            result.push_back(entry);
        }
    }
    return result;
}

bool CPeerManager::CanAcceptConnection() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    // BUG #105 FIX: Count only CONNECTED peers, not total map entries
    // Previously used peers.size() which included disconnected/zombie peers
    size_t connected = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            connected++;
        }
    }
    return connected < MAX_TOTAL_CONNECTIONS;
}

size_t CPeerManager::GetConnectionCount() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    size_t count = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            count++;
        }
    }
    return count;
}

size_t CPeerManager::GetOutboundCount() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    // For now, simplified - assume first 8 connected peers are outbound
    size_t count = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected() && count < MAX_OUTBOUND_CONNECTIONS) {
            count++;
        }
    }
    return std::min(count, (size_t)MAX_OUTBOUND_CONNECTIONS);
}

size_t CPeerManager::GetInboundCount() const {
    return GetConnectionCount() - GetOutboundCount();
}

std::vector<NetProtocol::CAddress> CPeerManager::GetPeerAddresses(int max_count) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<NetProtocol::CAddress> result;

    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            result.push_back(pair.second->addr);
            if (result.size() >= (size_t)max_count) {
                break;
            }
        }
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

void CPeerManager::AddPeerAddress(const NetProtocol::CAddress& addr) {
    // Skip localhost and invalid addresses
    std::string ip = addr.ToStringIP();
    if (ip == "127.0.0.1" || ip == "::1" || ip.empty()) {
        return;
    }

    // Phase 1 port: IAddressManager takes (CAddress, CAddress source).
    //
    // BLOCKER fix per Cursor review (2026-04-26): pass addr as its own
    // source. The legacy code passed an empty CNetAddr here, which made
    // every unknown-origin address share source group [0,0]. Upstream's
    // new-bucket math caps "addresses from one source group" at 64 buckets
    // (ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP) — sharing a source group
    // collapses self-discovered addresses into 64/1024 = 6.25% of the
    // bucket grid, weakening the eclipse-defense diversity property.
    //
    // Self-source restores diversity: each addr's group becomes its own
    // source group, so addresses spread across the full 1024 new buckets.
    // The "addr == source -> time_penalty = 0" early-return in AddInternal
    // is the intended behavior for self-announced addresses, which is what
    // an unknown-origin address effectively is.
    addrman->Add(addr, addr);
}

std::vector<NetProtocol::CAddress> CPeerManager::QueryDNSSeeds() {
    std::vector<NetProtocol::CAddress> result;

    for (const auto& seed_hostname : dns_seeds) {
        try {
            std::vector<NetProtocol::CAddress> addresses =
                CDNSResolver::QuerySeed(seed_hostname, NetProtocol::DEFAULT_PORT);

            if (addresses.empty()) {
                continue;
            }

            for (const auto& addr : addresses) {
                result.push_back(addr);
                AddPeerAddress(addr);
            }

        } catch (const std::exception& e) {
            LogPrintf(NET, WARN, "Failed to query DNS seed %s: %s", seed_hostname.c_str(), e.what());
            continue;
        } catch (...) {
            continue;
        }
    }

    if (!result.empty()) {
        LogPrintf(NET, INFO, "DNS seeds: found %zu peer addresses", result.size());
    }

    return result;
}

void CPeerManager::BanPeer(int peer_id, int64_t ban_time_seconds) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = peers.find(peer_id);
    if (it != peers.end()) {
        int64_t ban_until = GetTime() + ban_time_seconds;
        it->second->Ban(ban_until);

        // Add IP to banned list using CBanManager
        std::string ip = it->second->addr.ToStringIP();
        banman.Ban(ip, ban_time_seconds, BanReason::NodeMisbehaving,
                   MisbehaviorType::NONE, GetMisbehaviorScore(peer_id));
    }
}

void CPeerManager::BanIP(const std::string& ip, int64_t ban_time_seconds) {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Use CBanManager (handles LRU eviction internally)
    banman.Ban(ip, ban_time_seconds, BanReason::ManuallyBanned);

    // Disconnect all peers from this IP
    int64_t ban_until = GetTime() + ban_time_seconds;
    for (auto& pair : peers) {
        if (pair.second->addr.ToStringIP() == ip) {
            pair.second->Ban(ban_until);
        }
    }
}

void CPeerManager::UnbanIP(const std::string& ip) {
    banman.Unban(ip);
}

bool CPeerManager::IsBanned(const std::string& ip) const {
    return banman.IsBanned(ip);
}

void CPeerManager::ClearBans() {
    banman.ClearBanned();
}

// Phase 2 port: forwarder. Routes scoring through CPeerScorer (when enabled
// via DILITHION_USE_NEW_PEER_SCORER, default ON), then performs the
// post-threshold ban plumbing (Q2=A — caller, not scorer, calls banman.Ban).
//
// Signature unchanged from pre-cutover: all ~107 call sites compile as-is.
// Behavior preserved:
//   * Seed-node protection (never ban seeds for misbehavior)
//   * Outdated-protocol-version uses short ban time (10min); other categories
//     use default (1h)
//   * CBanEntry populated with correct fields (banReason, misbehaviorType,
//     score-at-ban-time)
//   * Immediate CNode disconnect on ban (BUG #246)
void CPeerManager::Misbehaving(int peer_id, int howmuch, MisbehaviorType type) {
    auto peer = GetPeer(peer_id);
    if (!peer) return;

    // Seed-node protection: same logic as pre-cutover. Seed IPs are trusted
    // infrastructure; banning them isolates the node.
    std::string peer_ip = peer->addr.ToStringIP();
    if (peer->addr.IsNull()) {
        std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
        auto it = node_refs.find(peer_id);
        if (it != node_refs.end() && it->second && !it->second->addr.IsNull()) {
            peer_ip = it->second->addr.ToStringIP();
        }
    }
    if (IsSeedNode(peer_ip)) {
        LogPrintf(NET, WARN, "[CPeerManager] Ignoring misbehavior score for seed node %s (peer %d, type=%s, score=%d)\n",
                  peer_ip.c_str(), peer_id, MisbehaviorTypeToString(type), howmuch);
        return;
    }

    // Tracking-disabled mode (DILITHION_USE_NEW_PEER_SCORER=0): no scoring,
    // no ban via misbehavior. Manual ban via RPC still works; protocol-level
    // disconnects still fire.
    if (!m_scorer) {
        return;
    }

    // Resolve the actual weight: explicit (howmuch>0) overrides type default.
    // ::GetMisbehaviorScore is the legacy helper from banman.h that maps the
    // DIAGNOSTIC enum to weights — we keep it for legacy `type` parity. The
    // scorer also has its own DefaultWeight() table for the FROZEN policy
    // enum, but that's a different enum (see misbehavior_policy.h DELIBERATE
    // DIVERGENCE block). Using the legacy helper here preserves call-site
    // semantics for the ~107 existing callers.
    const int score = howmuch > 0 ? howmuch : ::GetMisbehaviorScore(type);

    // Score it. Threshold cross is the scorer's call.
    const bool threshold_crossed = m_scorer->Misbehaving(peer_id, score, "");
    if (!threshold_crossed) return;

    // Threshold crossed — ban the peer. (Q2=A: forwarder, not scorer, owns
    // banman + immediate disconnect plumbing.)
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Outdated protocol version gets a short ban (operator-friendly: legitimate
    // miners just need to update). All other categories use the default 1h.
    const int64_t ban_time = (type == MisbehaviorType::INVALID_PROTOCOL_VERSION)
                              ? PROTOCOL_VERSION_BAN_TIME
                              : DEFAULT_BAN_TIME;

    const int64_t ban_until = GetTime() + ban_time;
    peer->Ban(ban_until);

    // BUG FIX: Get IP from peer first, fall back to CNode if peer's addr is null
    // (race condition can cause peer->addr to be zeroed if AddPeerWithId runs
    // before RegisterNode).
    std::string ip = peer->addr.ToStringIP();

    // BUG #246 FIX: Immediately disconnect banned peer.
    {
        std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
        auto it = node_refs.find(peer_id);
        if (it != node_refs.end() && it->second) {
            if (peer->addr.IsNull() && !it->second->addr.IsNull()) {
                ip = it->second->addr.ToStringIP();
            }
            it->second->MarkDisconnect();
        }
    }

    // Cumulative score at ban time — query scorer.
    const int cumulative = m_scorer->GetScore(peer_id);

    banman.Ban(ip, ban_time, BanReason::NodeMisbehaving, type, cumulative);

    // Phase 2 plan §10 Q1=C: cross-session badness signal flows through
    // AddrMan's RecordAttempt(PeerMisbehaved) — biases future outbound
    // selection AWAY from this peer's group across restarts. Without this
    // wire-up the Q1=C decision wouldn't materialize: the scorer is
    // transient by design, banlist.dat covers active bans, and the AddrMan
    // bias is what carries the "this peer was bad" signal forward when the
    // ban eventually expires.
    //
    // Cursor Phase 2 review Q16 (2026-04-26) flagged this as a missing
    // piece of Q1=C; wire-up landed here. Test:
    // peer_scorer_banman_integration_tests::test_misbehavior_signals_addrman.
    if (addrman && !peer->addr.IsNull()) {
        addrman->RecordAttempt(peer->addr,
                               ::dilithion::net::ConnectionOutcome::PeerMisbehaved);
    }

    // Operator-facing log line — one per ban. Matches pre-cutover format.
    if (ban_time >= 3600) {
        std::cout << "[BAN] Peer " << peer_id << " (" << ip
                  << ") banned for " << (ban_time / 3600) << "h - "
                  << MisbehaviorTypeToString(type)
                  << " (score: " << cumulative << ")" << std::endl;
    } else {
        std::cout << "[BAN] Peer " << peer_id << " (" << ip
                  << ") banned for " << (ban_time / 60) << "min - "
                  << MisbehaviorTypeToString(type)
                  << " (score: " << cumulative << ")" << std::endl;
    }
}

// Phase 2 port: forwarder. Per-peer score decay lives in CPeerScorer; the
// banman housekeeping (SweepExpiredBans + CleanupGenesisFailures) stays
// here. Called every 30 seconds from the existing tick.
void CPeerManager::DecayMisbehaviorScores() {
    if (m_scorer) {
        m_scorer->DecayAll();
    }
    banman.SweepExpiredBans();
    banman.CleanupGenesisFailures();
}

CPeerManager::Stats CPeerManager::GetStats() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    Stats stats;
    stats.total_peers = peers.size();
    stats.connected_peers = 0;

    for (const auto& pair : peers) {
        if (pair.second->IsConnected()) {
            stats.connected_peers++;
        }
    }

    // Calculate outbound/inbound inline to avoid deadlock
    size_t outbound = 0;
    for (const auto& pair : peers) {
        if (pair.second->IsConnected() && outbound < MAX_OUTBOUND_CONNECTIONS) {
            outbound++;
        }
    }
    stats.outbound_connections = std::min(outbound, (size_t)MAX_OUTBOUND_CONNECTIONS);
    stats.inbound_connections = stats.connected_peers - stats.outbound_connections;
    stats.banned_ips = banman.GetBannedCount();

    return stats;
}

int CPeerManager::GetBestPeerHeight() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Returns the highest chain height reported by any connected peer.
    // Used for IBD detection and progress display.
    //
    // BUG FIX: Don't require full handshake (VERACK) to use start_height.
    // After ProcessVersionMessage, start_height is already set from the peer's
    // VERSION message. Requiring IsHandshakeComplete() creates an unnecessary gap
    // where we know the peer's height but report 0 (confusing during IBD).
    // Also check best_known_height which gets updated during headers sync and
    // may be higher than start_height for long-lived connections.
    int best = 0;
    for (const auto& pair : peers) {
        const auto& peer = pair.second;
        // Accept height from any peer that has completed handshake OR has received
        // a VERSION message (start_height > 0 means we got their VERSION)
        if (peer->IsHandshakeComplete() || peer->start_height > 0) {
            int peer_height = std::max(peer->start_height, peer->best_known_height);
            if (peer_height > best) {
                best = peer_height;
            }
        }
    }
    return best;
}

bool CPeerManager::HasCompletedHandshakes() const {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // BUG #69 FIX: Check if ANY peer has completed VERSION/VERACK handshake
    // This distinguishes between:
    // 1. "Connections initiated but no VERSION received yet" (return false)
    // 2. "Peers have completed handshake but are at height 0" (return true)
    //
    // Used by IsInitialBlockDownload() to avoid incorrectly staying in IBD mode
    // when all connected peers legitimately have height 0 (bootstrap scenario).
    for (const auto& pair : peers) {
        if (pair.second->IsHandshakeComplete()) {
            return true;  // At least one peer completed handshake
        }
    }
    return false;  // No handshakes completed yet
}

void CPeerManager::InitializeSeedNodes() {
    // Hardcoded seed nodes for Dilithion network
    // These are reliable nodes run by the community

    seed_nodes.clear();

    // Check which network we're on
    bool isTestnet = Dilithion::g_chainParams && Dilithion::g_chainParams->IsTestnet();
    bool isDilV = Dilithion::g_chainParams && Dilithion::g_chainParams->IsDilV();
    bool isRegtest = Dilithion::g_chainParams && Dilithion::g_chainParams->IsRegtest();

    // Regtest must NEVER reach out to public seed nodes. The 4-node harness
    // wires peers via --addnode and the regtest network is air-gapped from
    // mainnet/testnet/DilV public infra. Without this short-circuit, regtest
    // falls through the isTestnet/isDilV checks into the mainnet branch and
    // attempts to dial 138.197.68.128:8444 etc., which causes peer churn,
    // CPU contention, and stalled mining templates.
    if (isRegtest) {
        dns_seeds.clear();
        return;
    }

    if (isDilV) {
        // ============================================
        // DILV SEED NODES (same servers, port 9444)
        // ============================================
        dns_seeds = {
            "seed-dilv.dilithion.org",
            "seed-dilv1.dilithion.org",
            "seed-dilv2.dilithion.org",
        };

        // DILV SEED NODE #1: NYC (DigitalOcean NYC3)
        // IP: 138.197.68.128, Port: 9444
        NetProtocol::CAddress seed_nyc;
        seed_nyc.services = NetProtocol::NODE_NETWORK;
        seed_nyc.SetIPv4(0x8AC54480);  // 138.197.68.128
        seed_nyc.port = NetProtocol::DILV_PORT;
        seed_nyc.time = GetTime();
        seed_nodes.push_back(seed_nyc);

        // DILV SEED NODE #2: London (DigitalOcean LON1)
        // IP: 167.172.56.119, Port: 9444
        NetProtocol::CAddress seed_london;
        seed_london.services = NetProtocol::NODE_NETWORK;
        seed_london.SetIPv4(0xA7AC3877);  // 167.172.56.119
        seed_london.port = NetProtocol::DILV_PORT;
        seed_london.time = GetTime();
        seed_nodes.push_back(seed_london);

        // DILV SEED NODE #3: Singapore (DigitalOcean SGP1)
        // IP: 165.22.103.114, Port: 9444
        NetProtocol::CAddress seed_singapore;
        seed_singapore.services = NetProtocol::NODE_NETWORK;
        seed_singapore.SetIPv4(0xA5166772);  // 165.22.103.114
        seed_singapore.port = NetProtocol::DILV_PORT;
        seed_singapore.time = GetTime();
        seed_nodes.push_back(seed_singapore);

        // DILV SEED NODE #4: Sydney (DigitalOcean SYD1)
        // IP: 134.199.159.83, Port: 9444
        NetProtocol::CAddress seed_sydney;
        seed_sydney.services = NetProtocol::NODE_NETWORK;
        seed_sydney.SetIPv4(0x86C79F53);  // 134.199.159.83
        seed_sydney.port = NetProtocol::DILV_PORT;
        seed_sydney.time = GetTime();
        seed_nodes.push_back(seed_sydney);
    } else if (isTestnet) {
        // ============================================
        // TESTNET SEED NODES
        // ============================================
        dns_seeds = {
            "seed-testnet.dilithion.org",
            "seed-testnet1.dilithion.org",
            "seed-testnet2.dilithion.org",
        };

        // TESTNET SEED NODE #1: NYC (DigitalOcean NYC3)
        // IP: 134.122.4.164, Port: 18444 (testnet)
        NetProtocol::CAddress seed_nyc;
        seed_nyc.services = NetProtocol::NODE_NETWORK;
        seed_nyc.SetIPv4(0x867A04A4);  // 134.122.4.164
        seed_nyc.port = NetProtocol::TESTNET_PORT;
        seed_nyc.time = GetTime();
        seed_nodes.push_back(seed_nyc);

        // TESTNET SEED NODE #2: London (DigitalOcean LON1)
        // IP: 209.97.177.197, Port: 18444 (testnet)
        NetProtocol::CAddress seed_london;
        seed_london.services = NetProtocol::NODE_NETWORK;
        seed_london.SetIPv4(0xD161B1C5);  // 209.97.177.197
        seed_london.port = NetProtocol::TESTNET_PORT;
        seed_london.time = GetTime();
        seed_nodes.push_back(seed_london);

        // TESTNET SEED NODE #3: Singapore (DigitalOcean SGP1)
        // IP: 188.166.255.63, Port: 18444 (testnet)
        NetProtocol::CAddress seed_singapore;
        seed_singapore.services = NetProtocol::NODE_NETWORK;
        seed_singapore.SetIPv4(0xBCA6FF3F);  // 188.166.255.63
        seed_singapore.port = NetProtocol::TESTNET_PORT;
        seed_singapore.time = GetTime();
        seed_nodes.push_back(seed_singapore);
    } else {
        // ============================================
        // MAINNET SEED NODES
        // ============================================
        dns_seeds = {
            "seed.dilithion.org",
            "seed1.dilithion.org",
            "seed2.dilithion.org",
        };

        // MAINNET SEED NODE #1: NYC (DigitalOcean NYC3)
        // IP: 138.197.68.128, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_nyc;
        seed_nyc.services = NetProtocol::NODE_NETWORK;
        seed_nyc.SetIPv4(0x8AC54480);  // 138.197.68.128
        seed_nyc.port = NetProtocol::DEFAULT_PORT;
        seed_nyc.time = GetTime();
        seed_nodes.push_back(seed_nyc);

        // MAINNET SEED NODE #2: London (DigitalOcean LON1)
        // IP: 167.172.56.119, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_london;
        seed_london.services = NetProtocol::NODE_NETWORK;
        seed_london.SetIPv4(0xA7AC3877);  // 167.172.56.119
        seed_london.port = NetProtocol::DEFAULT_PORT;
        seed_london.time = GetTime();
        seed_nodes.push_back(seed_london);

        // MAINNET SEED NODE #3: Singapore (DigitalOcean SGP1)
        // IP: 165.22.103.114, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_singapore;
        seed_singapore.services = NetProtocol::NODE_NETWORK;
        seed_singapore.SetIPv4(0xA5166772);  // 165.22.103.114
        seed_singapore.port = NetProtocol::DEFAULT_PORT;
        seed_singapore.time = GetTime();
        seed_nodes.push_back(seed_singapore);

        // MAINNET SEED NODE #4: Sydney (DigitalOcean SYD1)
        // IP: 134.199.159.83, Port: 8444 (mainnet)
        NetProtocol::CAddress seed_sydney;
        seed_sydney.services = NetProtocol::NODE_NETWORK;
        seed_sydney.SetIPv4(0x86C79F53);  // 134.199.159.83
        seed_sydney.port = NetProtocol::DEFAULT_PORT;
        seed_sydney.time = GetTime();
        seed_nodes.push_back(seed_sydney);
    }

    // FUTURE: Add more seed nodes as they become available
    // Community operators can run seed nodes and submit them via GitHub
    //
    // To add a new seed node:
    //   NetProtocol::CAddress new_seed;
    //   new_seed.services = NetProtocol::NODE_NETWORK;
    //   new_seed.SetIPv4(0xXXXXXXXX);  // Convert IP to hex (e.g., 192.168.0.1 = 0xC0A80001)
    //   new_seed.port = NetProtocol::TESTNET_PORT;  // Use DEFAULT_PORT for mainnet
    //   new_seed.time = GetTime();
    //   seed_nodes.push_back(new_seed);
    //
    // Seed node requirements:
    // - Static IP address with port 18444 (testnet) or 8444 (mainnet) open
    // - 95%+ uptime (24/7 operation)
    // - Minimum 1 Mbps bandwidth
    // - Not mining (relay only)
    // - Latest Dilithion node software
    //
    // Users can also manually configure peers using --addnode command line parameter.
}

bool CPeerManager::IsSeedNode(const std::string& ip) const {
    for (const auto& seed : seed_nodes) {
        if (seed.ToStringIP() == ip) {
            return true;
        }
    }
    return false;
}

// Address database management (NW-003 - now uses Bitcoin Core CAddrMan)

void CPeerManager::MarkAddressGood(const NetProtocol::CAddress& addr) {
    // Phase 1 port: IAddressManager dispatches via ConnectionOutcome. Success
    // performs the equivalent of legacy Good() — promote to tried with
    // test-before-evict on collision.
    //
    // NOTE: this is only called for OUTBOUND connections — addr.port is the
    // correct P2P port (caller responsibility, not changed by the port).
    addrman->RecordAttempt(addr, ::dilithion::net::ConnectionOutcome::Success);
}

void CPeerManager::MarkAddressTried(const NetProtocol::CAddress& addr) {
    // Phase 1 port: legacy Attempt(addr, fCountFailure=true) maps to a
    // count-failure outcome. Per the IAddressManager dispatch table:
    // HandshakeFailed/Timeout/PeerMisbehaved all bump n_attempts; pick
    // Timeout as the closest semantic match for the "we tried, no answer"
    // flow this method represented in the legacy code.
    addrman->RecordAttempt(addr, ::dilithion::net::ConnectionOutcome::Timeout);
}

std::vector<NetProtocol::CAddress> CPeerManager::SelectAddressesToConnect(int count) {
    std::vector<NetProtocol::CAddress> result;
    std::set<std::string> seen_ips;  // Track already-selected addresses to prevent duplicates

    // Use AddrMan's deterministic selection algorithm
    // This provides eclipse attack protection via the bucket system
    int attempts = 0;
    int max_attempts = count * 3;  // Allow some failed attempts due to duplicates

    while ((int)result.size() < count && attempts < max_attempts) {
        attempts++;

        // Phase 1 port: IAddressManager::Select returns optional<CAddress>
        // directly (no wrapper pair, no CService intermediate). nullopt
        // means the bucket walk found no candidates this iteration.
        auto sel = addrman->Select(::dilithion::net::OutboundClass::FullRelay);
        if (!sel.has_value()) {
            break;  // No more addresses available
        }
        const NetProtocol::CAddress& selected_addr = *sel;

        // Deduplicate by IP string (port-independent — multiple ports per IP
        // is unusual on this network; single-port-per-host stays in result).
        std::string ip_str = selected_addr.ToStringIP();
        if (seen_ips.count(ip_str)) {
            continue;  // Skip duplicate
        }
        seen_ips.insert(std::move(ip_str));

        // Refresh time stamp to "now" for outbound-relay propagation —
        // matches legacy behavior at this call site.
        NetProtocol::CAddress addr = selected_addr;
        addr.time = static_cast<uint32_t>(GetTime());
        if (addr.services == 0) addr.services = NetProtocol::NODE_NETWORK;

        result.push_back(addr);
    }

    // P5-LOW FIX: Return without std::move to allow RVO
    return result;
}

size_t CPeerManager::GetAddressCount() const {
    return addrman->Size();
}

bool CPeerManager::EvictPeersIfNeeded() {
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // Only evict if we're at or over the limit
    if (peers.size() < MAX_TOTAL_CONNECTIONS) {
        return false;  // No eviction needed
    }

    // Find candidate peers to evict
    // Priority: Keep outbound connections (we initiated), evict inbound with highest misbehavior
    std::vector<std::pair<int, int>> eviction_candidates;  // (peer_id, score)

    int64_t now = GetTime();
    for (const auto& [peer_id, peer] : peers) {
        // Only consider connected peers for eviction
        if (!peer->IsConnected()) {
            continue;
        }

        // Never evict manual peers (Bitcoin Core pattern)
        // --connect, --addnode, and RPC addnode peers are protected from eviction
        CNode* node = GetNode(peer_id);
        if (node && node->fManual) {
            continue;
        }

        // Calculate eviction score (higher = more likely to evict)
        // Phase 2 port: misbehavior score lives in CPeerScorer now.
        int score = GetMisbehaviorScore(peer_id);

        // Prefer to evict peers with no recent activity (no messages in last 5 minutes)
        if (peer->last_recv > 0 && (now - peer->last_recv) > 5 * 60) {
            score += 50;  // Inactive peer
        } else if (peer->last_recv == 0) {
            score += 100;  // Never received anything
        }

        // Prefer to evict peers that haven't completed handshake
        if (!peer->IsHandshakeComplete()) {
            score += 200;  // Incomplete handshake
        }

        eviction_candidates.push_back({peer_id, score});
    }

    if (eviction_candidates.empty()) {
        return false;  // No candidates to evict
    }

    // Phase 4: Trust-based eviction bonus (only when active and not during IBD)
    {
        // Issue #83: read live chain tip via canonical accessor (GetHeight() returns
        // -1 if no tip — comparison below naturally yields trust_active=false).
        extern CChainState g_chainstate;
        int current_height = g_chainstate.GetHeight();
        bool trust_active = Dilithion::g_chainParams &&
                            current_height >= Dilithion::g_chainParams->trustWeightedNetworkHeight;
        bool in_ibd = g_node_context.sync_coordinator &&
                      g_node_context.sync_coordinator->IsInitialBlockDownload();

        if (trust_active && !in_ibd && g_node_context.GetPeerTrustScore) {
            for (auto& [pid, score] : eviction_candidates) {
                double trust = g_node_context.GetPeerTrustScore(pid);
                if (trust >= 0) {
                    // Lower trust = higher eviction score
                    // Trust 0 → +50, Trust 50 → +25, Trust 100 → +0
                    score += static_cast<int>(50.0 * (1.0 - trust / 100.0));
                }
                // trust == -1.0 means unknown peer — grace period, no bonus applied
            }
        }
    }

    // Sort by score (highest first = most likely to evict)
    std::sort(eviction_candidates.begin(), eviction_candidates.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // Evict the worst peer
    int peer_to_evict = eviction_candidates[0].first;
    auto peer = GetPeer(peer_to_evict);
    if (peer) {
        LogPrintf(NET, INFO, "Evicting peer %d (score: %d, addr: %s)",
                  peer_to_evict, eviction_candidates[0].second, peer->addr.ToString().c_str());
        // F22 (v4.3.3 Track B): eviction used RemovePeer only, bypassing
        // CConnman::DispatchPeerDisconnected — port OnPeerDisconnected (F18+)
        // never ran. Mirror DisconnectNodes ordering: dispatch first while
        // CPeer/CNode state is still observable, then legacy map removal.
        if (g_node_context.connman) {
            g_node_context.connman->DispatchPeerDisconnected(peer_to_evict);
        }
        RemovePeer(peer_to_evict);
        return true;
    }

    return false;
}

void CPeerManager::PeriodicMaintenance() {
    // Decay misbehavior scores
    DecayMisbehaviorScores();

    // Evict peers if needed
    EvictPeersIfNeeded();

    // P3-N8 FIX: Disconnect peers with stale handshakes
    // If a peer hasn't completed handshake within 60 seconds, disconnect them
    // This prevents attackers from occupying connection slots indefinitely
    // BUG #148 FIX: Reduced from 300s to 60s - handshake should complete within seconds,
    // not minutes. 300s was causing zombie peers to occupy slots too long.
    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        static const int64_t HANDSHAKE_TIMEOUT = 60;  // BUG #148: Reduced from 300s
        int64_t now = GetTime();

        static const int64_t MANUAL_HANDSHAKE_TIMEOUT = 120;  // Manual peers get 2x timeout
        std::vector<int> peers_to_disconnect;
        for (const auto& pair : peers) {
            CPeer* peer = pair.second.get();
            if (peer->state == CPeer::STATE_CONNECTING ||
                peer->state == CPeer::STATE_CONNECTED ||
                peer->state == CPeer::STATE_VERSION_SENT) {
                // Peer is in handshake state
                CNode* node = GetNode(peer->id);
                int64_t timeout = (node && node->fManual) ? MANUAL_HANDSHAKE_TIMEOUT : HANDSHAKE_TIMEOUT;
                int64_t age = now - peer->connect_time;
                if (age > timeout) {
                    peers_to_disconnect.push_back(peer->id);
                }
            }
        }

        // Disconnect stale peers (outside the loop to avoid iterator invalidation)
        // BUG #144 FIX: Also mark CNode for disconnect so CConnman removes it from m_nodes
        for (int peer_id : peers_to_disconnect) {
            auto it = peers.find(peer_id);
            if (it != peers.end()) {
                it->second->Disconnect();
                // Also mark the CNode for disconnect
                CNode* node = GetNode(peer_id);
                if (node) {
                    node->MarkDisconnect();
                }
            }
        }
    }

    // Save peers periodically (every 15 minutes)
    static int64_t last_save_time = 0;
    int64_t now = GetTime();
    if (now - last_save_time > 15 * 60) {
        SavePeers();
        last_save_time = now;
    }
}

// =============================================================================
// Phase 3.2: Block tracking methods (ported from CNodeStateManager)
// =============================================================================

bool CPeerManager::MarkBlockAsInFlight(int peer_id, const uint256& hash, const CBlockIndex* pindex)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker handles tracking via CBlockFetcher::RequestBlockFromPeer
    // This method is now only for legacy orphan block tracking

    if (mapBlocksInFlight.count(hash)) {
        return false;
    }

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return false;
    }

    CPeer* peer = it->second.get();

    // Use CBlockTracker for capacity check
    int peer_blocks_in_flight = 0;
    if (g_node_context.block_tracker) {
        peer_blocks_in_flight = g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }
    if (peer_blocks_in_flight >= MAX_BLOCKS_IN_FLIGHT_PER_PEER) {
        return false;
    }

    // Legacy tracking for orphan blocks (no known height)
    QueuedBlock qb(hash, pindex);
    peer->vBlocksInFlight.push_back(qb);
    peer->nBlocksInFlight++;

    auto list_it = std::prev(peer->vBlocksInFlight.end());
    mapBlocksInFlight[hash] = std::make_pair(peer_id, list_it);

    return true;
}

int CPeerManager::MarkBlockAsReceived(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;
    }

    int peer_id = it->second.first;
    auto list_it = it->second.second;

    // Get peer and remove from their list
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        CPeer* peer = peer_it->second.get();
        peer->vBlocksInFlight.erase(list_it);
        peer->nBlocksInFlight--;

        // Reset stall count on successful receive
        peer->nStallingCount = 0;
        peer->nBlocksDownloaded++;
        peer->lastSuccessTime = std::chrono::steady_clock::now();
    }

    // Remove from global map
    mapBlocksInFlight.erase(it);

    return peer_id;
}

void CPeerManager::MarkBlockAsReceived(int peer_id, const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker handles tracking via OnBlockReceived
    // This method just updates peer stats

    // Update peer stats
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        peer_it->second->nBlocksDownloaded++;
        peer_it->second->lastSuccessTime = std::chrono::steady_clock::now();
        peer_it->second->nStallingCount = 0;
    }

    // Legacy: clean up mapBlocksInFlight if present (for orphan blocks)
    auto it = mapBlocksInFlight.find(hash);
    if (it != mapBlocksInFlight.end()) {
        int tracked_peer = it->second.first;
        auto list_it = it->second.second;

        auto tracked_peer_it = peers.find(tracked_peer);
        if (tracked_peer_it != peers.end()) {
            CPeer* peer = tracked_peer_it->second.get();
            peer->vBlocksInFlight.erase(list_it);
            if (peer->nBlocksInFlight > 0) {
                peer->nBlocksInFlight--;
            }
        }
        mapBlocksInFlight.erase(it);
    }
}

int CPeerManager::RemoveBlockFromFlight(const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = mapBlocksInFlight.find(hash);
    if (it == mapBlocksInFlight.end()) {
        return -1;
    }

    int peer_id = it->second.first;
    auto list_it = it->second.second;

    // Get peer and remove from their list (don't reset stall count - this is timeout)
    auto peer_it = peers.find(peer_id);
    if (peer_it != peers.end()) {
        CPeer* peer = peer_it->second.get();
        peer->vBlocksInFlight.erase(list_it);
        // IBD HANG FIX #21: Guard against going negative
        if (peer->nBlocksInFlight > 0) {
            peer->nBlocksInFlight--;
        }
    }

    // Remove from global map
    mapBlocksInFlight.erase(it);

    return peer_id;
}

bool CPeerManager::IsBlockInFlight(const uint256& hash) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    return mapBlocksInFlight.count(hash) > 0;
}

int CPeerManager::GetBlockPeer(const uint256& hash) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    auto it = mapBlocksInFlight.find(hash);
    if (it != mapBlocksInFlight.end()) {
        return it->second.first;
    }
    return -1;
}

std::vector<std::pair<uint256, int>> CPeerManager::GetBlocksInFlight() const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::pair<uint256, int>> result;
    for (const auto& entry : mapBlocksInFlight) {
        result.push_back(std::make_pair(entry.first, entry.second.first));
    }
    return result;
}

int CPeerManager::GetBlocksInFlightForPeer(int peer_id) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    // SSOT: CBlockTracker is the single source of truth for in-flight counts
    if (g_node_context.block_tracker) {
        return g_node_context.block_tracker->GetPeerInFlightCount(peer_id);
    }

    // Legacy fallback: Count from mapBlocksInFlight
    int count = 0;
    for (const auto& entry : mapBlocksInFlight) {
        if (entry.second.first == peer_id) {
            count++;
        }
    }
    return count;
}

std::vector<std::pair<uint256, int>> CPeerManager::GetTimedOutBlocks(int timeout_seconds) const
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<std::pair<uint256, int>> result;

    auto now = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::seconds(timeout_seconds);

    for (const auto& pair : peers) {
        CPeer* peer = pair.second.get();
        for (const auto& qb : peer->vBlocksInFlight) {
            auto elapsed = now - qb.time;
            if (elapsed > timeout_duration) {
                result.push_back(std::make_pair(qb.hash, pair.first));
            }
        }
    }

    return result;
}

std::vector<uint256> CPeerManager::GetAndClearPeerBlocks(int peer_id)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<uint256> result;

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return result;
    }

    CPeer* peer = it->second.get();

    // Collect all block hashes
    for (const auto& qb : peer->vBlocksInFlight) {
        result.push_back(qb.hash);
        mapBlocksInFlight.erase(qb.hash);
    }

    // Clear peer's list
    peer->vBlocksInFlight.clear();
    peer->nBlocksInFlight = 0;

    return result;
}

std::vector<int> CPeerManager::CheckForStallingPeers()
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);
    std::vector<int> stallingPeers;
    auto now = std::chrono::steady_clock::now();

    for (auto& pair : peers) {
        CPeer* peer = pair.second.get();
        if (peer->vBlocksInFlight.empty()) {
            continue;
        }

        // Check oldest block in flight
        const QueuedBlock& oldest = peer->vBlocksInFlight.front();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - oldest.time);
        CNode* node = GetNode(pair.first);
        bool isManual = (node && node->fManual);
        auto timeout = peer->GetBlockTimeout(isManual);

        if (elapsed > timeout) {
            peer->nStallingCount++;
            peer->lastStallTime = now;

            // Reset the timer for next check
            peer->vBlocksInFlight.front().time = now;

            // If stalling too many times, mark for disconnection
            if (peer->nStallingCount >= 5) {
                stallingPeers.push_back(pair.first);
            }
        }
    }

    return stallingPeers;
}

void CPeerManager::UpdatePeerStats(int peer_id, bool success, std::chrono::milliseconds responseTime)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;
    }

    CPeer* peer = it->second.get();

    if (success) {
        peer->nBlocksDownloaded++;
        peer->lastSuccessTime = std::chrono::steady_clock::now();

        // Update average response time (exponential moving average)
        if (responseTime.count() > 0) {
            peer->avgResponseTime = std::chrono::milliseconds(
                (peer->avgResponseTime.count() * 7 + responseTime.count()) / 8
            );
        }
    } else {
        peer->nStallingCount++;
        peer->lastStallTime = std::chrono::steady_clock::now();
    }
}

void CPeerManager::ClearPeerInFlightState(int peer_id)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;
    }

    CPeer* peer = it->second.get();

    // BUG #166 FIX: Clear vBlocksInFlight and corresponding map entries
    for (const auto& qb : peer->vBlocksInFlight) {
        auto map_it = mapBlocksInFlight.find(qb.hash);
        if (map_it != mapBlocksInFlight.end() && map_it->second.first == peer_id) {
            mapBlocksInFlight.erase(map_it);
        }
    }

    peer->vBlocksInFlight.clear();
    peer->nBlocksInFlight = 0;

    // BUG #166 FIX: Reset stall count so peer can become suitable again
    peer->nStallingCount = 0;
    peer->lastStallTime = std::chrono::steady_clock::now();
}

std::vector<int> CPeerManager::GetValidPeersForDownload() const
{
    std::lock_guard<std::recursive_mutex> lock_peers(cs_peers);
    std::lock_guard<std::recursive_mutex> lock_nodes(cs_nodes);
    std::vector<int> result;

    for (const auto& pair : peers) {
        int peer_id = pair.first;
        CPeer* peer = pair.second.get();

        // Check if CNode still exists
        auto node_it = node_refs.find(peer_id);
        if (node_it == node_refs.end() || node_it->second == nullptr) {
            continue;
        }

        CNode* node = node_it->second;

        // SSOT: Check CNode state (socket, disconnect flag, handshake)
        if (!node->HasValidSocket() || node->fDisconnect.load() || !node->IsHandshakeComplete()) {
            continue;
        }

        // Must be suitable for download (not stalling too much)
        if (!peer->IsSuitableForDownload()) {
            continue;
        }

        result.push_back(peer_id);
    }

    return result;
}

bool CPeerManager::IsPeerSuitableForDownload(int peer_id) const
{
    // BUG #148 FIX: Lock both mutexes to check node validity
    std::lock_guard<std::recursive_mutex> lock_peers(cs_peers);
    std::lock_guard<std::recursive_mutex> lock_nodes(cs_nodes);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return false;
    }

    CPeer* peer = it->second.get();

    // BUG #148 FIX: Check if CNode still exists
    auto node_it = node_refs.find(peer_id);
    if (node_it == node_refs.end() || node_it->second == nullptr) {
        return false;
    }

    CNode* node = node_it->second;

    // BUG #148 FIX: Check if CNode has valid socket
    if (!node->HasValidSocket() || node->fDisconnect.load()) {
        return false;
    }

    // SSOT FIX #1: Check CNode::state (single source of truth) instead of CPeer::state
    // CNode::state is authoritative - CPeer::state is deprecated
    // Note: 'node' is already obtained from node_refs above
    return node->IsHandshakeComplete() &&  // Query CNode::state (SSOT)
           peer->IsSuitableForDownload();
}

void CPeerManager::UpdatePeerBestKnownHeight(int peer_id, int height)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;  // Peer not found
    }

    CPeer* peer = it->second.get();

    // Only update if new height is higher (peer can't "un-mine" blocks)
    if (height > peer->best_known_height) {
        peer->best_known_height = height;
    }
}

void CPeerManager::UpdatePeerBestKnownTip(int peer_id, int height, const uint256& hash)
{
    std::lock_guard<std::recursive_mutex> lock(cs_peers);

    auto it = peers.find(peer_id);
    if (it == peers.end()) {
        return;  // Peer not found
    }

    CPeer* peer = it->second.get();

    // Only update if new height is higher (consistent with UpdatePeerBestKnownHeight)
    if (height > peer->best_known_height) {
        peer->best_known_height = height;
        peer->best_known_hash = hash;
        peer->last_tip_update = std::chrono::steady_clock::now();
    }
}

bool CPeerManager::OnPeerHandshakeComplete(int peer_id, int starting_height, bool preferred)
{
    // DEADLOCK FIX: Split into phases to avoid holding cs_peers while calling
    // PushMessage (which acquires cs_vNodes via CConnman::GetNode).
    // Without this fix, Thread A (SocketHandler) holding cs_vNodes → cs_peers
    // and Thread B (here) holding cs_peers → cs_vNodes creates ABBA deadlock.
    std::string peer_addr_str;  // Captured under lock for DNA notification

    // Phase 1: Update peer state (under cs_peers lock)
    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);

        auto it = peers.find(peer_id);
        if (it == peers.end()) {
            // Create peer entry if not exists
            // BUG FIX: Get address from CNode to avoid null addr
            NetProtocol::CAddress addr;
            {
                std::lock_guard<std::recursive_mutex> node_lock(cs_nodes);
                auto node_it = node_refs.find(peer_id);
                if (node_it != node_refs.end() && node_it->second) {
                    addr = node_it->second->addr;
                }
            }
            auto new_peer = std::make_shared<CPeer>(peer_id, addr);
            new_peer->state = CPeer::STATE_CONNECTED;
            peers[peer_id] = std::move(new_peer);
            it = peers.find(peer_id);
        }

        CPeer* peer = it->second.get();

        peer->state = CPeer::STATE_HANDSHAKE_COMPLETE;
        peer->start_height = starting_height;
        peer->best_known_height = starting_height;  // Initialize to starting height
        peer->fPreferredDownload = preferred;
        peer->fSyncStarted = false;

        // Initialize timing
        auto now = std::chrono::steady_clock::now();
        peer->m_stalling_since = now;
        peer->m_downloading_since = now;
        peer->m_last_block_announcement = now;
        peer->last_tip_update = now;  // Initialize so peer isn't excluded as stale before first HEADERS
        peer->lastSuccessTime = now;
        peer->lastStallTime = now;

        // Capture address for DNA notification (before releasing lock)
        peer_addr_str = peer->addr.ToString();
    }
    // cs_peers released — safe to call into CConnman now

    // Phase 2: Send mempool INV (no peer locks held)
    // PushMessage calls CConnman::GetNode which acquires cs_vNodes.
    // This MUST be outside cs_peers to maintain lock ordering: cs_vNodes → cs_peers.
    // If peer disconnected between phase 1 and here, PushMessage returns false (safe).
    {
        extern std::atomic<CTxMemPool*> g_mempool;
        auto* mempool = g_mempool.load();
        if (mempool && g_node_context.connman && g_node_context.message_processor) {
            auto txs = mempool->GetOrderedTxs();
            if (!txs.empty()) {
                const size_t MAX_INV_ON_CONNECT = 8;
                size_t to_send = std::min(txs.size(), MAX_INV_ON_CONNECT);
                std::vector<NetProtocol::CInv> inv_vec;
                inv_vec.reserve(to_send);
                for (size_t i = 0; i < to_send; i++) {
                    inv_vec.push_back(NetProtocol::CInv(NetProtocol::MSG_TX_INV, txs[i]->GetHash()));
                }
                CNetMessage inv_msg = g_node_context.message_processor->CreateInvMessage(inv_vec);
                g_node_context.connman->PushMessage(peer_id, inv_msg);
                std::cout << "[TX-RELAY] Sent " << to_send
                          << " of " << txs.size() << " mempool tx INV(s) to new peer " << peer_id << std::endl;
            }
        }
    }

    // Phase 3: Digital DNA notification (no locks needed, uses captured addr)
    if (auto collector = g_node_context.GetDNACollector()) {
        // Convert peer address to 20-byte ID (hash of IP:port)
        std::array<uint8_t, 20> peer_dna_id = {};
        auto hash = std::hash<std::string>{}(peer_addr_str);
        memcpy(peer_dna_id.data(), &hash, std::min(sizeof(hash), peer_dna_id.size()));
        collector->on_peer_connected(peer_dna_id);
    }

    return true;
}

void CPeerManager::OnPeerDisconnected(int peer_id)
{
    // Track failed connections in AddrMan so stale addresses get evicted.
    // If handshake never completed, this was a failed connection attempt.
    // For inbound peers whose address isn't in AddrMan, Attempt() is a no-op.
    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        auto it = peers.find(peer_id);
        if (it != peers.end() && it->second->state != CPeer::STATE_HANDSHAKE_COMPLETE) {
            MarkAddressTried(it->second->addr);
        }
    }

    // Re-queue any in-flight blocks from this peer (legacy tracking)
    GetAndClearPeerBlocks(peer_id);

    // SSOT: Also notify CBlockTracker to clear this peer's blocks
    // This prevents "no suitable peers" stalls from stale in-flight blocks
    if (g_node_context.block_tracker) {
        auto heights = g_node_context.block_tracker->OnPeerDisconnected(peer_id);
        if (!heights.empty()) {
            std::cout << "[BLOCK-TRACKER] Cleared " << heights.size()
                      << " in-flight blocks from disconnected peer " << peer_id << std::endl;
        }
    }

    // Digital DNA: Notify collector about peer disconnection
    if (auto collector = g_node_context.GetDNACollector()) {
        // Get peer address for ID computation
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        auto it = peers.find(peer_id);
        if (it != peers.end()) {
            std::array<uint8_t, 20> peer_dna_id = {};
            std::string addr_str = it->second->addr.ToString();
            auto hash = std::hash<std::string>{}(addr_str);
            memcpy(peer_dna_id.data(), &hash, std::min(sizeof(hash), peer_dna_id.size()));
            collector->on_peer_disconnected(peer_dna_id);
        }
    }

    // F19/F20/F21 (v4.3.3 Track B): leak-class cleanups — methods existed but
    // had no production caller on the disconnect path.
    if (g_node_context.headers_manager) {
        g_node_context.headers_manager->OnPeerDisconnected(peer_id);
    }
    connection_quality.RemovePeer(peer_id);
    m_peer_bandwidth_throttle.RemovePeer(peer_id);

    // dilv-dedup-livelock-fix (NEW-1): next instance of the F19/F20/F21 leak class.
    // CleanupPeerRateLimitState was previously called ONLY from the dedup self-
    // disconnect branch (net.cpp); the normal disconnect path (timeout / eviction /
    // graceful) left all six dedup/re-send maps behind. Node IDs are monotonic
    // (never reused, connman m_next_node_id), so on a long-running seed serving
    // IBD to churning peers the maps grew unbounded = slow memory-exhaustion DoS.
    // Wiring it here releases that state on EVERY disconnect.
    // Lock-order safety: this runs under CConnman::cs_vNodes (DisconnectNodes →
    // DispatchPeerDisconnected); CleanupPeerRateLimitState takes the rate-limit
    // mutexes only, and no path takes a rate-limit mutex then cs_vNodes — no
    // inversion (see decl comment in net.h).
    CleanupPeerRateLimitState(peer_id);

    // The actual peer removal is handled by RemovePeer()
}

// Phase 1: CNode management methods (event-driven networking)
// These methods replace CPeer methods for new event-driven architecture

CNode* CPeerManager::AddNode(const NetProtocol::CAddress& addr, bool inbound) {
    // DEPRECATED: Use CConnman::ConnectNode() or CConnman::AcceptConnection() instead.
    std::string ip = addr.ToStringIP();
    if (banman.IsBanned(ip)) {
        return nullptr;
    }

    if (!CanAcceptConnection()) {
        return nullptr;
    }

    int node_id = next_peer_id++;
    CNode* node_ptr = new CNode(node_id, addr, inbound);

    {
        std::lock_guard<std::recursive_mutex> lock(cs_nodes);
        node_refs[node_id] = node_ptr;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(cs_peers);
        if (peers.find(node_id) == peers.end()) {
            auto peer = std::make_shared<CPeer>(node_id, addr);
            peer->state = inbound ? CPeer::STATE_CONNECTED : CPeer::STATE_CONNECTING;
            peers[node_id] = std::move(peer);
        }
    }

    return node_ptr;
}

bool CPeerManager::RegisterNode(int node_id, CNode* node, const NetProtocol::CAddress& addr, bool inbound) {
    // Store reference to CConnman's CNode (non-owning)
    std::string ip = addr.ToStringIP();

    // BUG #148 ROOT CAUSE FIX: Return false if IP is banned
    // Caller MUST check return value and NOT add to m_nodes if false
    // Otherwise, CNode exists in m_nodes but not in node_refs, causing
    // GetNode() to return nullptr during handshake
    // Seed node exemption: never reject seed nodes even if banned
    if (banman.IsBanned(ip)) {
        if (IsSeedNode(ip)) {
            LogPrintf(NET, WARN, "[CPeerManager] RegisterNode: Seed node %s is banned but allowing connection (seed exemption)\n", ip.c_str());
            banman.Unban(ip);
        } else {
            LogPrintf(NET, WARN, "[CPeerManager] RegisterNode: IP %s is banned, rejecting connection\n", ip.c_str());
            return false;
        }
    }

    // DEADLOCK FIX: Use scoped_lock for consistent lock ordering.
    // Other code paths (EvictPeersIfNeeded, Misbehaving) acquire cs_peers then cs_nodes.
    // scoped_lock uses deadlock-avoidance algorithm, matching RemoveNode's approach.
    {
        std::scoped_lock lock(cs_peers, cs_nodes);

        node_refs[node_id] = node;

        auto it = peers.find(node_id);
        if (it == peers.end()) {
            // Create new peer
            auto peer = std::make_shared<CPeer>(node_id, addr);
            peer->state = inbound ? CPeer::STATE_CONNECTED : CPeer::STATE_CONNECTING;
            peers[node_id] = std::move(peer);
        } else {
            // BUG FIX: Update existing peer's address (may have been created by AddPeerWithId
            // with zeroed address due to race condition)
            it->second->addr = addr;
            if (it->second->connect_time == 0) {
                it->second->connect_time = GetTime();
            }
        }
    }

    // Update next_peer_id if needed to avoid ID collisions (atomic CAS loop)
    int expected = next_peer_id.load();
    while (node_id >= expected) {
        if (next_peer_id.compare_exchange_weak(expected, node_id + 1)) {
            break;
        }
    }

    return true;  // Registration successful
}

void CPeerManager::RemoveNode(int node_id) {
    // RACE FIX v2: Hold BOTH locks atomically using std::scoped_lock
    // This prevents ProcessVerackMessage from seeing partial state during removal.
    //
    // Previous fix (remove peer first, then node) still had a race window:
    //   T1: ThreadMessageHandler calls GetPeer() - succeeds
    //   T2: ThreadSocketHandler acquires cs_peers, erases peer
    //   T2: ThreadSocketHandler releases cs_peers  <-- RACE WINDOW
    //   T1: ThreadMessageHandler calls GetNode() - FAILS (node_refs not yet erased)
    //   T2: ThreadSocketHandler acquires cs_nodes, erases node_refs
    //
    // With std::scoped_lock, both maps are protected for the entire operation.
    // std::scoped_lock uses deadlock-avoidance algorithm (std::lock) internally.
    std::scoped_lock lock(cs_peers, cs_nodes);

    peers.erase(node_id);
    node_refs.erase(node_id);

    // Phase 2 port: reclaim the scorer's map slot. Same reasoning as
    // RemovePeer above — bounded by MAX_TOTAL_CONNECTIONS in practice but
    // unbounded if ResetScore is forgotten on any disconnect path.
    if (m_scorer) m_scorer->ResetScore(node_id);
}

CNode* CPeerManager::GetNode(int node_id) {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    auto it = node_refs.find(node_id);
    if (it != node_refs.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<CNode*> CPeerManager::GetAllNodes() {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    std::vector<CNode*> result;
    result.reserve(node_refs.size());

    for (auto& pair : node_refs) {
        if (pair.second) {
            result.push_back(pair.second);
        }
    }

    return result;
}

std::vector<CNode*> CPeerManager::GetConnectedNodes() {
    std::lock_guard<std::recursive_mutex> lock(cs_nodes);

    std::vector<CNode*> result;

    for (auto& pair : node_refs) {
        CNode* node = pair.second;
        if (node && node->IsConnected()) {
            result.push_back(node);
        }
    }

    return result;
}