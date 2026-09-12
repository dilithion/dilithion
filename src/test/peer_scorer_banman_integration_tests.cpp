// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// Phase 2 Day 2 PM: peer-scorer + banman integration tests.
//
// Covers (per port_phase_2_implementation_plan.md §4.2) the behaviours that
// emerge from CPeerScorer + CPeerManager forwarder + CBanManager working
// together — distinct from the in-isolation unit tests in
// peer_scorer_tests.cpp.
//
// SCOPE NOTE: the plan also listed seed-node-protection coverage. That test
// requires ChainParams initialization (seed_nodes is populated from
// chainparams in CPeerManager::InitializeSeedNodes) which is non-trivial
// outside the boost test harness. Seed protection IS exercised by the
// existing CPeerManager::Misbehaving guard at peers.cpp:472 in production;
// regression coverage from that path is via the in-tree
// misbehavior_scoring_tests.cpp (unchanged behavioural contract — still
// green after PR2.2 cutover).

#include <net/peers.h>
#include <net/banman.h>
#include <net/protocol.h>
#include <net/port/addrman_v2.h>  // PHASE-2.5-ADDRMAN-BIAS: dynamic_cast target
#include <net/port/maybe_punish_node.h>

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

// Build a NetProtocol::CAddress from IPv4 octets — host byte order in.
NetProtocol::CAddress MakeAddrV4(uint32_t ipv4, uint16_t port = 8444)
{
    NetProtocol::CAddress a;
    a.SetIPv4(ipv4);
    a.port = port;
    a.services = NetProtocol::NODE_NETWORK;
    a.time = 1700000000;
    return a;
}

// Friend-of-friend helper: read CBanManager state for a given peer's IP.
// We don't have direct access to peers's banman, but we can use the
// IsBanned API on a constructed manager; the integration test wires both.
// In-process: just use peer_manager's interface — we test what the SUT
// exposes, not its internals.

}  // anonymous namespace

// ============================================================================
// Tests
// ============================================================================

// 1. Threshold cross actually flows through to a CBanManager ban.
//    Pre-cutover, this was implicit; post-cutover, the forwarder's "scorer
//    returned true → call banman.Ban" path is the integration we want to
//    verify end-to-end.
void test_threshold_cross_bans_via_banman()
{
    std::cout << "  test_threshold_cross_bans_via_banman..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x01020304));  // 1.2.3.4 (routable)
    assert(peer != nullptr);

    // Single weight-100 strike crosses default 100 threshold.
    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);

    // The forwarder calls peer->Ban (sets STATE_BANNED) — verify via the
    // peer's own state, since IsBanned on CBanManager requires hitting the
    // private banman member directly which the integration test doesn't
    // expose. The `peer->IsBanned()` check is the contract the cutover
    // preserves.
    auto post = pm.GetPeer(peer->id);
    assert(post != nullptr);
    assert(post->IsBanned());

    std::cout << " OK\n";
}

// 2. Cumulative score visible via the new accessor matches scorer state.
void test_get_misbehavior_score_round_trip()
{
    std::cout << "  test_get_misbehavior_score_round_trip..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x01020305));
    assert(peer != nullptr);

    assert(pm.GetMisbehaviorScore(peer->id) == 0);

    pm.Misbehaving(peer->id, 30, MisbehaviorType::PARSE_FAILURE);
    assert(pm.GetMisbehaviorScore(peer->id) == 30);

    pm.Misbehaving(peer->id, 25, MisbehaviorType::PARSE_FAILURE);
    assert(pm.GetMisbehaviorScore(peer->id) == 55);

    std::cout << " OK\n";
}

// 3. Outdated-protocol-version uses short ban time. CPeerScorer reports
//    threshold cross; the forwarder picks PROTOCOL_VERSION_BAN_TIME (10min)
//    instead of DEFAULT_BAN_TIME (1h) when the type matches.
void test_protocol_version_uses_short_ban_time()
{
    std::cout << "  test_protocol_version_uses_short_ban_time..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x01020306));
    assert(peer != nullptr);

    const int64_t before = GetTime();
    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_PROTOCOL_VERSION);
    const int64_t after  = GetTime();

    auto post = pm.GetPeer(peer->id);
    assert(post != nullptr);
    assert(post->IsBanned());

    // peer->ban_time is the absolute Unix-time when the ban expires.
    // For INVALID_PROTOCOL_VERSION the duration is PROTOCOL_VERSION_BAN_TIME (600s);
    // verify the ban-until landed in [before+600, after+600+SLACK].
    constexpr int64_t kProtocolBanSecs = 10 * 60;
    constexpr int64_t kSlack = 5;  // generous: tests + clock granularity
    const int64_t expected_min = before + kProtocolBanSecs;
    const int64_t expected_max = after  + kProtocolBanSecs + kSlack;
    assert(post->ban_time >= expected_min && post->ban_time <= expected_max);

    std::cout << " OK (ban_until=" << post->ban_time
              << ", window=[" << expected_min << "," << expected_max << "])\n";
}

// 4. Default category (anything other than INVALID_PROTOCOL_VERSION) uses
//    DEFAULT_BAN_TIME (1h).
void test_default_misbehaviortype_uses_long_ban_time()
{
    std::cout << "  test_default_misbehaviortype_uses_long_ban_time..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x01020307));
    assert(peer != nullptr);

    const int64_t before = GetTime();
    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);
    const int64_t after  = GetTime();

    auto post = pm.GetPeer(peer->id);
    assert(post != nullptr);
    assert(post->IsBanned());

    constexpr int64_t kDefaultBanSecs = 60 * 60;  // 1 hour
    constexpr int64_t kSlack = 5;
    const int64_t expected_min = before + kDefaultBanSecs;
    const int64_t expected_max = after  + kDefaultBanSecs + kSlack;
    assert(post->ban_time >= expected_min && post->ban_time <= expected_max);

    std::cout << " OK\n";
}

// 5. Decay reduces the scorer's score but does NOT unban an already-banned
//    peer. CBanManager owns the ban lifecycle independent of the scorer.
void test_decay_does_not_unban_already_banned_peer()
{
    std::cout << "  test_decay_does_not_unban_already_banned_peer..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x01020308));
    assert(peer != nullptr);

    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);
    auto post = pm.GetPeer(peer->id);
    assert(post != nullptr);
    assert(post->IsBanned());

    const int64_t ban_time_before = post->ban_time;

    // Run several decay ticks. Each decrements every tracked score by 1;
    // the ban itself is in CBanManager and on the peer's ban_time field —
    // neither is touched by DecayMisbehaviorScores.
    for (int i = 0; i < 50; ++i) {
        pm.DecayMisbehaviorScores();
    }

    auto still = pm.GetPeer(peer->id);
    assert(still != nullptr);
    assert(still->IsBanned());                     // still banned
    assert(still->ban_time == ban_time_before);    // ban_until unchanged

    std::cout << " OK\n";
}

// PHASE-2.5-ADDRMAN-BIAS ticket: deterministic verification that the Phase 2
// wire-up's effect on AddrMan state actually materializes. Q16 deferred
// portion. Pairs with the smoke test below.
//
// Uses CAddrMan_v2::GetEntryAttemptCountForTest (added 2026-04-26 alongside
// this test) to observe n_attempts directly — bounded to the direct effect
// of RecordAttempt(PeerMisbehaved), not the full bias-on-Select chain
// (which would need a probabilistic harness).
void test_misbehavior_increments_addrman_attempts()
{
    std::cout << "  test_misbehavior_increments_addrman_attempts..." << std::flush;

    CPeerManager pm("");

    // Add the peer's IP to AddrMan first via the public Add path. Without
    // an entry, RecordAttempt is a silent no-op.
    auto addr = MakeAddrV4(0x09080706);
    NetProtocol::CAddress empty_source;
    auto* addrman_iface = pm.GetAddrManagerForTest();  // see below
    assert(addrman_iface != nullptr);
    addrman_iface->Add(addr, empty_source);

    // Cast to concrete CAddrMan_v2 for the *ForTest accessor.
    auto* v2 = dynamic_cast<dilithion::net::port::CAddrMan_v2*>(addrman_iface);
    if (!v2) {
        // Operator escape hatch is on (legacy adapter); skip — coverage is
        // for the v2 production path.
        std::cout << " SKIP (v2 adapter not active)\n";
        return;
    }

    const int before = v2->GetEntryAttemptCountForTest(addr);
    assert(before >= 0);  // entry exists

    // Add the peer to peer-manager and cross misbehavior threshold.
    auto peer = pm.AddPeer(addr);
    assert(peer != nullptr);
    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);

    // The forwarder calls addrman->RecordAttempt(addr, PeerMisbehaved) on
    // threshold cross, which routes via AttemptInternal(count_failure=true)
    // and bumps n_attempts. So after the call, the entry's attempt count
    // should be strictly greater than `before`.
    const int after = v2->GetEntryAttemptCountForTest(addr);
    assert(after > before);

    std::cout << " OK (n_attempts: " << before << " -> " << after << ")\n";
}

// 6a. Phase 2 Q16 wire-up: on threshold cross, the forwarder signals
//     CAddrMan_v2 via RecordAttempt(PeerMisbehaved). This is the cross-
//     session badness signal Q1=C relied on (without it, Q1=C wouldn't
//     materialize — scorer is transient by design).
//
//     Coverage scope: SMOKE only. Verifies the wire-up doesn't crash and
//     addrman state remains consistent through the Misbehaving flow. The
//     deeper "Select biases away after restart" test is deferred to a
//     future Phase 2.5 hardening pass — that test is genuinely complex
//     (probabilistic; needs two-instance harness reading the same
//     peers.dat) and beyond Phase 2's scope.
void test_misbehavior_signals_addrman()
{
    std::cout << "  test_misbehavior_signals_addrman..." << std::flush;

    CPeerManager pm("");
    auto peer = pm.AddPeer(MakeAddrV4(0x05060708));
    assert(peer != nullptr);

    // Cross threshold — forwarder calls addrman->RecordAttempt(PeerMisbehaved).
    pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);

    // Wire-up sanity: no crash; peer is banned (proves the threshold-cross
    // path actually executed); peer manager is still queryable.
    auto post = pm.GetPeer(peer->id);
    assert(post != nullptr);
    assert(post->IsBanned());
    assert(pm.GetMisbehaviorScore(peer->id) == 100);

    std::cout << " OK\n";
}

// 6. Operator escape hatch: DILITHION_USE_NEW_PEER_SCORER=0 disables
//    scoring entirely. Misbehaving becomes a tracking-disabled no-op;
//    GetMisbehaviorScore returns 0; peer never bans via misbehavior.
//
// We can't toggle the env var mid-test (CPeerManager reads it at
// construction), so this test sets it BEFORE constructing pm, then
// unsets it afterwards.
void test_env_var_off_disables_scoring()
{
    std::cout << "  test_env_var_off_disables_scoring..." << std::flush;

#ifdef _WIN32
    _putenv("DILITHION_USE_NEW_PEER_SCORER=0");
#else
    setenv("DILITHION_USE_NEW_PEER_SCORER", "0", /*overwrite=*/1);
#endif

    {
        CPeerManager pm("");
        auto peer = pm.AddPeer(MakeAddrV4(0x01020309));
        assert(peer != nullptr);

        // Even at threshold weight, no ban — scorer is null.
        pm.Misbehaving(peer->id, 100, MisbehaviorType::INVALID_BLOCK_HEADER);

        auto post = pm.GetPeer(peer->id);
        assert(post != nullptr);
        assert(!post->IsBanned());                        // tracking disabled
        assert(pm.GetMisbehaviorScore(peer->id) == 0);    // accessor null-safe
    }

#ifdef _WIN32
    _putenv("DILITHION_USE_NEW_PEER_SCORER=");
#else
    unsetenv("DILITHION_USE_NEW_PEER_SCORER");
#endif

    std::cout << " OK\n";
}


// 9. THE PRODUCTION HEADER-REJECT PATH, WHICH HAD NO TEST AT ALL.
//
//    Measured 2026-09-10 (F4 census): CPeerManager::MisbehaveHeaders is called
//    from exactly one place in the tree, net.cpp:1856, and was referenced by no
//    test. It is ALSO the only production consumer of the HeaderRejectReason
//    weight table — maybe_punish_node.h's MaybePunishNodeForHeaders wrapper is
//    not on any production path, despite that file's header having claimed for
//    months that it was "WIRED ... via the CPeerManager::MisbehaveHeaders
//    forwarder". So every arm that pinned the weights pinned them on a path
//    production does not take.
//
//    This test takes the production path. It asserts the SCORE that a peer
//    actually accumulates, not the number the table returns.
void test_misbehave_headers_scores_only_the_scored_reasons()
{
    std::cout << "  test_misbehave_headers_scores_only_the_scored_reasons..." << std::flush;

    using ::dilithion::net::port::HeaderRejectReason;
    using ::dilithion::net::port::HeaderRejectWeight;
    using ::dilithion::net::port::kAllHeaderRejectReasons;

    int scored = 0, unscored = 0;

    for (HeaderRejectReason reason : kAllHeaderRejectReasons) {
        // A fresh manager per reason: scores accumulate, and a shared one would
        // make the honest-signal assertion depend on iteration order.
        CPeerManager pm("");
        auto peer = pm.AddPeer(MakeAddrV4(0x01020304));  // 1.2.3.4 (routable)
        assert(peer != nullptr);
        assert(pm.GetMisbehaviorScore(peer->id) == 0);

        pm.MisbehaveHeaders(peer->id, reason);

        const int expected = HeaderRejectWeight(reason);
        assert(pm.GetMisbehaviorScore(peer->id) == expected);

        if (expected == 0) {
            ++unscored;
            // An honest-emittable signal, or one that is our own fault, must
            // leave the peer entirely untouched -- not merely below threshold.
            auto post = pm.GetPeer(peer->id);
            assert(post != nullptr);
            assert(!post->IsBanned());
        } else {
            ++scored;
        }
    }

    // NON-VACUITY, both directions. Without these, a forwarder that scored
    // NOTHING would satisfy every assertion above, and so would one that had
    // quietly lost half its reasons.
    assert(scored == 4);
    assert(unscored == 5);

    std::cout << " OK\n";
}

// ============================================================================
// main
// ============================================================================

int main()
{
    std::cout << "\n=== Phase 2: CPeerScorer + CBanManager Integration Tests ===\n"
              << std::endl;

    try {
        test_threshold_cross_bans_via_banman();
        test_get_misbehavior_score_round_trip();
        test_protocol_version_uses_short_ban_time();
        test_default_misbehaviortype_uses_long_ban_time();
        test_decay_does_not_unban_already_banned_peer();
        test_misbehavior_increments_addrman_attempts();
        test_misbehavior_signals_addrman();
        test_env_var_off_disables_scoring();
        test_misbehave_headers_scores_only_the_scored_reasons();

        std::cout << "\n=== All Phase 2 Integration Tests Passed (9 tests) ==="
                  << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed with unknown exception" << std::endl;
        return 1;
    }
}
