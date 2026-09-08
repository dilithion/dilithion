// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DNA Propagation Phase 1 — Unit Tests
 *
 * Covers:
 *   1. IDNARegistry::append_sample() — accept, archive, dim-loss reject
 *   2. History 100-sample cap enforced on DNARegistryDB
 *   3. DNASampleRateLimiter — per-peer bucket, per-MIK global, per-MIK-per-peer
 *
 * Wire-level receiver handler rewrite (which uses both of the above plus
 * `g_mik_peer_map` plausibility) is exercised in-process when the node binary
 * runs; end-to-end two-node scenarios are deferred to manual deploy testing.
 *
 * Mapping semantics (post-`fix/mik-peer-map-semantics`, 2026-04-23):
 *   `g_mik_peer_map[mik] = peer_id` is set ONLY when `register_identity`
 *   succeeds on a previously-unseen MIK (SUCCESS or SYBIL_FLAGGED result).
 *   Merge-fill paths and silent-drop paths MUST NOT update the mapping.
 *   This prevents relays from promoting themselves to mapped-peer status
 *   simply by forwarding a benign `dnaires`. The signed-envelope path
 *   (Phase 1.5) is the authenticated route for unmapped peers to push
 *   full replacements.
 */

#include <digital_dna/digital_dna.h>
#include <digital_dna/dna_registry_db.h>
#include <digital_dna/sample_envelope.h>
#include <digital_dna/sample_rate_limiter.h>
#include <dfmp/mik.h>  // MIK_PRIVKEY_SIZE, MIK_PUBKEY_SIZE, MIK_SIGNATURE_SIZE
#include <net/net.h>     // CNetMessageProcessor + CNetMessage
#include <net/peers.h>   // CPeerManager
#include <net/protocol.h> // PROTOCOL_VERSION constants
#include <net/serialize.h> // CDataStream

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// Dilithium3 keypair — declared here because the test needs to fabricate
// a real keypair for sign/verify round-trips (not available via the public
// wallet path in a pure unit test).
extern "C" {
    int pqcrystals_dilithium3_ref_keypair(uint8_t *pk, uint8_t *sk);
}

#define RESET_  "\033[0m"
#define GREEN_  "\033[32m"
#define RED_    "\033[31m"
#define YELLOW_ "\033[33m"
#define BLUE_   "\033[34m"

int g_tests_passed = 0;
int g_tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE_ << "[TEST] " << #name << RESET_ << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN_ << "  PASSED" << RESET_ << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED_ << "  FAILED: " << e.what() << RESET_ << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED_ << "  FAILED: Unknown exception" << RESET_ << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(cond, msg) \
    if (!(cond)) throw std::runtime_error(msg);

#define ASSERT_EQ(a, b, msg) \
    if ((a) != (b)) throw std::runtime_error(std::string(msg) + " (mismatch)");

namespace fs = std::filesystem;
using digital_dna::DigitalDNA;
using digital_dna::DNARegistryDB;
using digital_dna::DNASampleRateLimiter;
using digital_dna::IDNARegistry;

// ---------------------------------------------------------------------------
// Helpers: fabricate a minimally-valid DigitalDNA with selectable dimensions.
// ---------------------------------------------------------------------------

static DigitalDNA make_dna(uint8_t addr_seed,
                           bool with_memory = false,
                           bool with_thermal = false,
                           bool with_drift = false,
                           bool with_bandwidth = false,
                           bool with_behavioral = false,
                           uint32_t reg_height = 1)
{
    DigitalDNA d;
    for (size_t i = 0; i < d.address.size(); ++i) d.address[i] = static_cast<uint8_t>(addr_seed + i);
    d.mik_identity = d.address;  // use same bytes so MIK key path runs
    d.is_valid = true;
    d.registration_height = reg_height;
    d.registration_time = 1700000000;

    // Core dims: ensure latency + timing populate (defaults are already-present
    // objects; we just set identifying values).
    d.timing.iterations_per_second = 100000.0;

    if (with_memory) {
        digital_dna::MemoryFingerprint m;
        d.memory = m;
    }
    if (with_thermal) {
        digital_dna::ThermalProfile t;
        d.thermal = t;
    }
    if (with_drift) {
        digital_dna::ClockDriftFingerprint c;
        d.clock_drift = c;
    }
    if (with_bandwidth) {
        digital_dna::BandwidthFingerprint b;
        d.bandwidth = b;
    }
    if (with_behavioral) {
        digital_dna::BehavioralProfile bp;
        bp.observation_blocks = 10;  // non-empty so the registry treats it as populated
        d.behavioral = bp;
    }
    return d;
}

struct ScratchDir {
    fs::path path;
    explicit ScratchDir(const std::string& tag) {
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch()).count();
        path = fs::temp_directory_path() /
               ("dilithion_prop_" + tag + "_" + std::to_string(ns));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path, ec);
        if (ec) throw std::runtime_error("scratch: " + ec.message());
    }
    ~ScratchDir() { std::error_code ec; fs::remove_all(path, ec); }
};

// ---------------------------------------------------------------------------
// append_sample tests
// ---------------------------------------------------------------------------

TEST(append_sample_unregistered_registers) {
    ScratchDir dir("asu");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");
    auto d = make_dna(0x11);
    auto result = reg.append_sample(d);
    ASSERT(result == IDNARegistry::RegisterResult::SUCCESS, "Expected SUCCESS on first sample");
    ASSERT(reg.is_registered(d.address), "Address should be registered");
}

TEST(append_sample_enriches_and_archives) {
    ScratchDir dir("ase");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto slim = make_dna(0x22);                                     // 2 core dims
    auto enriched = make_dna(0x22, true, true, false, false, false); // +memory +thermal

    ASSERT(reg.append_sample(slim) == IDNARegistry::RegisterResult::SUCCESS, "first sample");
    auto r = reg.append_sample(enriched);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED || r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "second sample should update");

    // Canonical is now enriched.
    auto canonical = reg.get_identity(enriched.address);
    ASSERT(canonical.has_value(), "canonical present");
    ASSERT(canonical->memory.has_value(), "memory set on canonical");
    ASSERT(canonical->thermal.has_value(), "thermal set on canonical");

    // History has 1 entry (the old slim DNA).
    auto hist = reg.get_dna_history(enriched.mik_identity, 10);
    ASSERT_EQ(hist.size(), (size_t)1, "one history entry");
}

TEST(append_sample_rejects_dimension_loss) {
    ScratchDir dir("asl");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto rich = make_dna(0x33, true, true, true, true, true);  // all optional dims
    auto thin = make_dna(0x33, false, false, false, false, false);  // just core

    ASSERT(reg.append_sample(rich) == IDNARegistry::RegisterResult::SUCCESS, "first");
    auto r = reg.append_sample(thin);
    ASSERT(r == IDNARegistry::RegisterResult::INVALID_DNA, "dim-loss must be rejected");

    // Canonical still has all dims.
    auto canonical = reg.get_identity(thin.address);
    ASSERT(canonical.has_value(), "canonical still present");
    ASSERT(canonical->memory.has_value(), "memory still set");
    ASSERT(canonical->thermal.has_value(), "thermal still set");
}

TEST(append_sample_same_dim_value_change_accepted) {
    ScratchDir dir("asv");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto a = make_dna(0x44, true, true, false, false, false);
    ASSERT(reg.append_sample(a) == IDNARegistry::RegisterResult::SUCCESS, "first");

    // Same dimension set, value tweaked.
    auto b = a;
    b.timing.iterations_per_second = 110000.0;
    auto r = reg.append_sample(b);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED || r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "same-dim value change accepted");

    auto canonical = reg.get_identity(a.address);
    ASSERT(canonical.has_value(), "canonical present");
    if (std::abs(canonical->timing.iterations_per_second - 110000.0) > 1.0)
        throw std::runtime_error("timing IPS not updated");
}

TEST(history_capped_at_max_per_mik) {
    ScratchDir dir("hc");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto d = make_dna(0x55);
    ASSERT(reg.append_sample(d) == IDNARegistry::RegisterResult::SUCCESS, "first");

    // Push MAX_HISTORY_PER_MIK + 20 enriched samples, each distinguishable by
    // incrementing timing IPS to force core_dimensions_changed semantics but
    // not trigger the dim-loss guard.
    const size_t extra = IDNARegistry::MAX_HISTORY_PER_MIK + 20;
    for (size_t i = 1; i <= extra; ++i) {
        auto next = d;
        next.timing.iterations_per_second = 100000.0 + static_cast<double>(i);
        // Force timestamp diversity so history keys are unique.
        reg.append_sample(next);
    }

    auto hist = reg.get_dna_history(d.mik_identity, IDNARegistry::MAX_HISTORY_PER_MIK + 50);
    // Post-write count must not exceed MAX_HISTORY_PER_MIK.
    ASSERT(hist.size() <= IDNARegistry::MAX_HISTORY_PER_MIK,
           "history must be capped at MAX_HISTORY_PER_MIK, got " + std::to_string(hist.size()));
}

// ---------------------------------------------------------------------------
// DNASampleRateLimiter tests
// ---------------------------------------------------------------------------

static std::array<uint8_t, 20> make_mik(uint8_t seed) {
    std::array<uint8_t, 20> m{};
    for (size_t i = 0; i < m.size(); ++i) m[i] = static_cast<uint8_t>(seed + i);
    return m;
}

TEST(rate_limiter_peer_bucket_burst_then_refill) {
    DNASampleRateLimiter lim;
    uint64_t t = 1000;

    // Use distinct MIKs per call so the per-MIK / per-MIK-per-peer layers
    // never block us. This isolates layer 1 (peer bucket).
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        auto r = lim.allow_detail(42, make_mik(static_cast<uint8_t>(i + 1)), t);
        ASSERT(r == DNASampleRateLimiter::Reject::OK,
               "burst sample " + std::to_string(i) + " should pass");
    }

    // Now bucket is empty — 6th sample in the same second rejected.
    auto r = lim.allow_detail(42, make_mik(0xAA), t);
    ASSERT(r == DNASampleRateLimiter::Reject::PEER_BUCKET,
           "post-burst sample should be PEER_BUCKET-rejected");

    // After refill interval, one token available.
    t += DNASampleRateLimiter::PEER_BUCKET_REFILL_SEC;
    r = lim.allow_detail(42, make_mik(0xBB), t);
    ASSERT(r == DNASampleRateLimiter::Reject::OK, "refilled token accepts");
}

TEST(rate_limiter_per_mik_global) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xCC);
    uint64_t t = 2000;

    // Accept one from peer 1.
    ASSERT(lim.allow(1, mik, t), "first sample passes");

    // Different peer 2, same MIK, within 10-min window → rejected by MIK_GLOBAL.
    auto r = lim.allow_detail(2, mik, t + 60);
    ASSERT(r == DNASampleRateLimiter::Reject::MIK_GLOBAL,
           "second-peer same-MIK sample rejected by MIK_GLOBAL");

    // After 10 min + 1s, accepted.
    r = lim.allow_detail(2, mik, t + DNASampleRateLimiter::MIK_GLOBAL_MIN_SEC + 1);
    ASSERT(r == DNASampleRateLimiter::Reject::OK,
           "after MIK_GLOBAL_MIN_SEC same-MIK sample accepted");
}

TEST(rate_limiter_per_mik_per_peer) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xDD);
    uint64_t t = 3000;

    ASSERT(lim.allow(7, mik, t), "first");

    // Same peer, same MIK, after MIK_GLOBAL window but BEFORE MIK_PEER window
    // → should be rejected by MIK_PEER.
    uint64_t t_mid = t + DNASampleRateLimiter::MIK_GLOBAL_MIN_SEC + 1;
    auto r = lim.allow_detail(7, mik, t_mid);
    ASSERT(r == DNASampleRateLimiter::Reject::MIK_PEER,
           "same peer same MIK within 30 min rejected by MIK_PEER");

    // After the 30-min per-peer window, accepted.
    uint64_t t_late = t + DNASampleRateLimiter::MIK_PEER_MIN_SEC + 1;
    r = lim.allow_detail(7, mik, t_late);
    ASSERT(r == DNASampleRateLimiter::Reject::OK,
           "after MIK_PEER_MIN_SEC same peer same MIK accepted");
}

TEST(rate_limiter_reject_leaves_state_unchanged) {
    DNASampleRateLimiter lim;
    auto mik = make_mik(0xEE);
    uint64_t t = 4000;

    // Exhaust peer bucket on MIK A.
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        lim.allow(10, make_mik(static_cast<uint8_t>(i + 100)), t);
    }

    // Try to push MIK sample — rejected by peer bucket.
    ASSERT(!lim.allow(10, mik, t), "rejected by peer bucket");

    // Since it was rejected, MIK should not be in the global-last-accept map.
    // We can infer this by: a different peer submitting for the same MIK in
    // the same second should pass (no MIK_GLOBAL block).
    ASSERT(lim.allow(99, mik, t),
           "after rejected attempt, MIK state must be unchanged so another peer can accept");
}

// ---------------------------------------------------------------------------
// Phase 1.1 merge-fill tests
// ---------------------------------------------------------------------------

TEST(merge_fill_fills_missing_dimension) {
    // existing has no bandwidth; incoming has bandwidth → merged has bandwidth.
    auto existing = make_dna(0xA0, true, true, false, false, false);  // mem+thermal
    auto incoming = make_dna(0xA0, true, true, false, true,  false);  // mem+thermal+bw

    int filled = -1;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 1, "should fill exactly one dim (bandwidth)");
    ASSERT(merged.bandwidth.has_value(), "merged has bandwidth");
    ASSERT(merged.memory.has_value(), "merged keeps memory");
    ASSERT(merged.thermal.has_value(), "merged keeps thermal");
    ASSERT(!merged.clock_drift.has_value(), "merged doesn't invent clock_drift");
    ASSERT(!merged.behavioral.has_value(), "merged doesn't invent behavioral");
}

TEST(merge_fill_no_gap_returns_existing_with_zero_filled) {
    // Both have the same populated set → filled=0.
    auto existing = make_dna(0xA1, true, true, false, false, false);
    auto incoming = make_dna(0xA1, true, true, false, false, false);

    int filled = -1;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 0, "no dims to fill when both have same set");
    // merged should be equivalent to existing.
    ASSERT(merged.memory.has_value() == existing.memory.has_value(), "memory preserved");
    ASSERT(merged.thermal.has_value() == existing.thermal.has_value(), "thermal preserved");
    ASSERT(!merged.bandwidth.has_value(), "bandwidth still absent");
}

TEST(merge_fill_preserves_existing_values_on_conflict) {
    // existing has memory populated; incoming has memory populated with a
    // different marker. Merge must keep existing's value.
    auto existing = make_dna(0xA2, true, true, false, false, false);
    existing.timing.iterations_per_second = 100000.0;  // distinguishing marker

    auto incoming = make_dna(0xA2, true, true, false, true, false);
    incoming.timing.iterations_per_second = 777777.0;  // different value — must NOT win

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    ASSERT_EQ(filled, 1, "only bandwidth filled");
    ASSERT(merged.bandwidth.has_value(), "bandwidth now present");
    // Core field (timing.iterations_per_second) must come from existing.
    if (std::abs(merged.timing.iterations_per_second - 100000.0) > 1.0)
        throw std::runtime_error("timing IPS must be preserved from existing, not overwritten");
}

TEST(merge_fill_multiple_missing_dims) {
    auto existing = make_dna(0xA3, false, false, false, false, false);  // only core
    auto incoming = make_dna(0xA3, true,  true,  true,  true,  true);   // all enriched

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);

    // Counts: memory, thermal, clock_drift, bandwidth, behavioral = 5.
    ASSERT_EQ(filled, 5, "should fill 5 dims");
    ASSERT(merged.memory.has_value(), "memory filled");
    ASSERT(merged.thermal.has_value(), "thermal filled");
    ASSERT(merged.clock_drift.has_value(), "clock_drift filled");
    ASSERT(merged.bandwidth.has_value(), "bandwidth filled");
    ASSERT(merged.behavioral.has_value(), "behavioral filled");
}

TEST(merge_fill_then_append_sample_succeeds_with_dim_loss_guard) {
    // End-to-end: seed the registry with a thin DNA (mapped-peer-equivalent,
    // via append_sample on fresh MIK), then simulate an unmapped peer
    // providing an enriched sample. Call merge + append and verify the
    // canonical record has the new dim.
    ScratchDir dir("mf_e2e");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    auto slim = make_dna(0xA4, true, true, false, false, false);   // 4 dims
    ASSERT(reg.append_sample(slim) == IDNARegistry::RegisterResult::SUCCESS, "seed");

    auto enriched_from_relay = make_dna(0xA4, true, true, false, true, false);  // +bw
    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(slim, enriched_from_relay, &filled);
    ASSERT_EQ(filled, 1, "relay fills bandwidth");

    auto r = reg.append_sample(merged);
    ASSERT(r == IDNARegistry::RegisterResult::UPDATED ||
           r == IDNARegistry::RegisterResult::DNA_CHANGED,
           "merged sample should be accepted by append_sample");

    auto canonical = reg.get_identity(slim.address);
    ASSERT(canonical.has_value(), "canonical present");
    ASSERT(canonical->bandwidth.has_value(), "canonical now has bandwidth after merge-append");
}

TEST(merge_fill_perspective_dim_is_fillable) {
    // perspective isn't optional<T> — it has its own populated predicate.
    // Verify merge treats it correctly.
    auto existing = make_dna(0xA5, false, false, false, false, false);
    // existing has zero peers in perspective by default.
    ASSERT_EQ(existing.perspective.total_unique_peers(), (size_t)0, "existing has no peer data");

    auto incoming = existing;  // same address
    // Simulate incoming perspective with a snapshot.
    digital_dna::PerspectiveSnapshot snap;
    snap.timestamp = 1700000000;
    snap.block_height = 100;
    for (size_t i = 0; i < 20; ++i) {
        std::array<uint8_t, 20> peer{};
        for (size_t j = 0; j < 20; ++j) peer[j] = static_cast<uint8_t>(i + j);
        snap.active_peers.push_back(peer);
    }
    incoming.perspective.snapshots.push_back(snap);

    int filled = 0;
    auto merged = digital_dna::merge_fill_missing_dims(existing, incoming, &filled);
    ASSERT(filled >= 1, "perspective should count as a filled dim");
    ASSERT(!merged.perspective.snapshots.empty(), "merged got the perspective snapshot");
}

// ---------------------------------------------------------------------------
// Phase 1.2 — discovery MIK source (dna_registry ∪ cooldown_tracker)
// ---------------------------------------------------------------------------

// Mirrors the linear-dedup union used in the discovery block of both node
// binaries. Tested here instead of extracted because the production site is
// six lines and co-locating the test with the inline code would pull the
// whole `g_node_context` graph into unit tests.
static std::vector<std::array<uint8_t, 20>>
union_dedupe_miks(std::vector<std::array<uint8_t, 20>> a,
                  const std::vector<std::array<uint8_t, 20>>& b) {
    for (const auto& m : b) {
        bool dup = false;
        for (const auto& e : a) { if (e == m) { dup = true; break; } }
        if (!dup) a.push_back(m);
    }
    return a;
}

TEST(discovery_source_dil_empty_cooldown_tracker_returns_registry_miks) {
    // DIL reality: cooldown_tracker is populated only via VDF block-connect
    // callbacks, so on RandomX chains GetKnownAddresses() is always empty.
    // The Phase 1.2 fix sources from dna_registry first so discovery can
    // still fire. This test asserts the in-memory path used by unit tests
    // and by relay-only nodes that haven't opened a LevelDB registry.
    // SUCCESS *or* SYBIL_FLAGGED — both mean STORED, which is all this test is
    // about (it asserts discovery sourcing, not Sybil scoring). It is the same
    // predicate the node itself uses: `stored = SUCCESS || SYBIL_FLAGGED`
    // (dilithion-node.cpp, first-seen registration).
    //
    // These fixtures now come back SYBIL_FLAGGED, and that is the HIGH-C fix
    // working. make_dna() gives every identity an EMPTY latency fingerprint and
    // an identical timing signature, so before the has_latency gate each pair
    // scored (latency ~0 + timing 1.0) / 2 = 0.50 — sitting just under
    // SUSPICIOUS_THRESHOLD (0.55) purely because a dimension nobody measured
    // was averaged in as evidence of DIFFERENCE. That is the attacker opt-out,
    // reproduced by our own fixtures. With latency excluded when no seed pair is
    // comparable, two identities identical in every measured dimension score 1.0
    // and are flagged, which is the correct verdict. See
    // latency_gate_flags_identical_identities in dna_serialization_test.cpp.
    auto stored = [](IDNARegistry::RegisterResult r) {
        return r == IDNARegistry::RegisterResult::SUCCESS ||
               r == IDNARegistry::RegisterResult::SYBIL_FLAGGED;
    };
    digital_dna::DigitalDNARegistry reg;
    ASSERT(stored(reg.register_identity(make_dna(0x10))), "r1");
    ASSERT(stored(reg.register_identity(make_dna(0x20))), "r2");
    ASSERT(stored(reg.register_identity(make_dna(0x30))), "r3");

    std::vector<std::array<uint8_t, 20>> empty_cooldown;
    auto sourced = union_dedupe_miks(reg.get_all_miks(), empty_cooldown);

    ASSERT_EQ(sourced.size(), (size_t)3, "all three registry MIKs surface when cooldown is empty");
}

TEST(discovery_source_union_dedupes_overlap) {
    // MIKs appearing in both dna_registry and cooldown_tracker must be
    // emitted exactly once. With 120 live miners on mainnet today a
    // non-deduped source would blow up the round-robin window and fire
    // duplicate dnaireq messages at the same peer.
    digital_dna::DigitalDNARegistry reg;
    auto dna_a = make_dna(0xA0);
    auto dna_b = make_dna(0xB0);
    // SUCCESS or SYBIL_FLAGGED — both mean stored; see the note in
    // discovery_source_dil_empty_cooldown_tracker_returns_registry_miks for why
    // these fixtures are now flagged (HIGH-C has_latency gate).
    auto stored = [](IDNARegistry::RegisterResult r) {
        return r == IDNARegistry::RegisterResult::SUCCESS ||
               r == IDNARegistry::RegisterResult::SYBIL_FLAGGED;
    };
    ASSERT(stored(reg.register_identity(dna_a)), "ra");
    ASSERT(stored(reg.register_identity(dna_b)), "rb");

    std::vector<std::array<uint8_t, 20>> cooldown{
        dna_a.mik_identity,              // overlap with registry
        make_mik(0xC0),                  // unique to cooldown
    };

    auto sourced = union_dedupe_miks(reg.get_all_miks(), cooldown);

    ASSERT_EQ(sourced.size(), (size_t)3, "A, B, C — A deduped to single copy");
    size_t count_a = 0;
    for (const auto& m : sourced) {
        if (m == dna_a.mik_identity) ++count_a;
    }
    ASSERT_EQ(count_a, (size_t)1, "A appears exactly once");
}

TEST(dna_registry_db_get_all_miks_returns_stored_miks) {
    // Parallel check: the LevelDB-backed registry (production path) exposes
    // get_all_miks via the IDNARegistry interface after Phase 1.2.
    ScratchDir dir("gam");
    DNARegistryDB reg;
    ASSERT(reg.Open(dir.path.string()), "open db");

    ASSERT(reg.append_sample(make_dna(0x70)) == IDNARegistry::RegisterResult::SUCCESS, "s1");
    ASSERT(reg.append_sample(make_dna(0x80)) == IDNARegistry::RegisterResult::SUCCESS, "s2");

    IDNARegistry* iface = &reg;  // go through the interface, not the concrete class
    auto miks = iface->get_all_miks();
    ASSERT_EQ(miks.size(), (size_t)2, "two MIKs surfaced via interface");
}

// ---------------------------------------------------------------------------
// Phase 1.5 — SampleEnvelope sign/verify, TryParse negatives,
//             replay cache, staged rate-limiter APIs.
// ---------------------------------------------------------------------------

namespace p15 {

struct Keypair {
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
};

static Keypair make_keypair() {
    Keypair k;
    k.pubkey.resize(DFMP::MIK_PUBKEY_SIZE);
    k.privkey.resize(DFMP::MIK_PRIVKEY_SIZE);
    int rc = pqcrystals_dilithium3_ref_keypair(k.pubkey.data(), k.privkey.data());
    if (rc != 0) throw std::runtime_error("keypair generation failed");
    return k;
}

static std::array<uint8_t, 20> make_mik(uint8_t seed) {
    std::array<uint8_t, 20> m{};
    for (size_t i = 0; i < m.size(); ++i) m[i] = seed + static_cast<uint8_t>(i);
    return m;
}

static std::vector<uint8_t> make_dna_bytes(uint8_t seed, size_t len = 256) {
    std::vector<uint8_t> out(len);
    for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(seed ^ (i * 31));
    return out;
}

} // namespace p15

using digital_dna::SampleEnvelope;

TEST(envelope_sign_verify_roundtrip) {
    auto kp = p15::make_keypair();
    auto mik = p15::make_mik(0x01);
    auto dna = p15::make_dna_bytes(0x42);
    std::vector<uint8_t> sig;
    bool ok = SampleEnvelope::Sign(
        kp.privkey.data(), kp.privkey.size(), mik,
        1700000000ULL, 0xdeadbeefULL, dna, sig);
    ASSERT(ok, "Sign should succeed");
    ASSERT_EQ(sig.size(), DFMP::MIK_SIGNATURE_SIZE, "signature length");
    ASSERT(SampleEnvelope::Verify(
               kp.pubkey, mik, 1700000000ULL, 0xdeadbeefULL, dna, sig),
           "Verify of round-trip should pass");
}

TEST(envelope_verify_rejects_tampered_signature) {
    auto kp = p15::make_keypair();
    auto mik = p15::make_mik(0x02);
    auto dna = p15::make_dna_bytes(0x77);
    std::vector<uint8_t> sig;
    ASSERT(SampleEnvelope::Sign(kp.privkey.data(), kp.privkey.size(),
                                 mik, 1700000000ULL, 1ULL, dna, sig), "sign");
    sig[42] ^= 0x01;  // flip one bit
    ASSERT(!SampleEnvelope::Verify(kp.pubkey, mik, 1700000000ULL, 1ULL, dna, sig),
           "tampered signature must fail verify");
}

TEST(envelope_verify_rejects_tampered_dna_data) {
    auto kp = p15::make_keypair();
    auto mik = p15::make_mik(0x03);
    auto dna = p15::make_dna_bytes(0x11);
    std::vector<uint8_t> sig;
    ASSERT(SampleEnvelope::Sign(kp.privkey.data(), kp.privkey.size(),
                                 mik, 1700000000ULL, 2ULL, dna, sig), "sign");
    dna[7] ^= 0x01;
    ASSERT(!SampleEnvelope::Verify(kp.pubkey, mik, 1700000000ULL, 2ULL, dna, sig),
           "tampered dna_data must fail verify");
}

TEST(envelope_verify_rejects_wrong_mik) {
    auto kp = p15::make_keypair();
    auto mik1 = p15::make_mik(0x04);
    auto mik2 = p15::make_mik(0x05);  // different
    auto dna = p15::make_dna_bytes(0x22);
    std::vector<uint8_t> sig;
    ASSERT(SampleEnvelope::Sign(kp.privkey.data(), kp.privkey.size(),
                                 mik1, 1700000000ULL, 3ULL, dna, sig), "sign");
    ASSERT(!SampleEnvelope::Verify(kp.pubkey, mik2, 1700000000ULL, 3ULL, dna, sig),
           "verify under different mik must fail");
}

TEST(envelope_tryparse_empty_returns_none) {
    SampleEnvelope env;
    auto r = SampleEnvelope::TryParse({}, env);
    ASSERT(r == SampleEnvelope::ParseResult::NONE, "empty trailer = NONE");
    ASSERT(env.signature.empty(), "signature empty on NONE");
}

TEST(envelope_tryparse_unknown_magic_is_silent_ignore) {
    SampleEnvelope env;
    // 4 bytes not matching "SMP1"
    std::vector<uint8_t> t = {'X','X','X','X', 0,0,0,0, 0,0,0,0};
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::UNKNOWN_MAGIC,
           "unknown magic must be UNKNOWN_MAGIC (forward-compat), not malformed");
}

TEST(envelope_tryparse_truncated_magic_is_malformed) {
    SampleEnvelope env;
    // Fewer than 4 bytes = can't determine magic => malformed
    std::vector<uint8_t> t = {'S','M'};
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED, "truncated magic = MALFORMED");
}

TEST(envelope_tryparse_truncated_timestamp) {
    SampleEnvelope env;
    // SMP1 magic + 5 bytes of "timestamp" (truncated; need 8)
    std::vector<uint8_t> t = {'S','M','P','1', 1,2,3,4,5};
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED, "truncated ts = MALFORMED");
}

TEST(envelope_tryparse_truncated_nonce) {
    SampleEnvelope env;
    // SMP1 + 8-byte ts + 3 bytes of nonce (truncated; need 8)
    std::vector<uint8_t> t(4 + 8 + 3, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED, "truncated nonce = MALFORMED");
}

TEST(envelope_tryparse_truncated_sig_len) {
    SampleEnvelope env;
    // SMP1 + ts(8) + nonce(8) + 1 byte of sig_len (need 2)
    std::vector<uint8_t> t(4 + 8 + 8 + 1, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED, "truncated sig_len = MALFORMED");
}

TEST(envelope_tryparse_siglen_zero_is_malformed) {
    SampleEnvelope env;
    std::vector<uint8_t> t(4 + 8 + 8 + 2, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    // sig_len = 0 (already zeroed), remaining = 0 — still malformed per spec
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED,
           "sig_len=0 is meaningless with SMP1 — must be MALFORMED");
}

TEST(envelope_tryparse_wrong_sig_len) {
    SampleEnvelope env;
    // sig_len = 100 (not Dilithium3's 3309) but remaining matches to make sure
    // the length check fires before the remaining-bytes check.
    std::vector<uint8_t> t(4 + 8 + 8 + 2 + 100, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    t[4 + 8 + 8] = 100;  // sig_len LE low byte
    t[4 + 8 + 8 + 1] = 0;
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED,
           "sig_len != MIK_SIGNATURE_SIZE must be MALFORMED");
}

TEST(envelope_tryparse_sig_len_gt_remaining) {
    SampleEnvelope env;
    // sig_len = MIK_SIGNATURE_SIZE (3309) but only 10 bytes remain
    std::vector<uint8_t> t(4 + 8 + 8 + 2 + 10, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    uint16_t sig_len = static_cast<uint16_t>(DFMP::MIK_SIGNATURE_SIZE);
    t[4 + 8 + 8] = static_cast<uint8_t>(sig_len & 0xFF);
    t[4 + 8 + 8 + 1] = static_cast<uint8_t>(sig_len >> 8);
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED,
           "sig_len larger than remaining bytes = MALFORMED");
}

TEST(envelope_tryparse_trailing_bytes_after_sig) {
    SampleEnvelope env;
    // sig_len = MIK_SIGNATURE_SIZE, but trailer carries one extra byte after.
    std::vector<uint8_t> t(4 + 8 + 8 + 2 + DFMP::MIK_SIGNATURE_SIZE + 1, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    uint16_t sig_len = static_cast<uint16_t>(DFMP::MIK_SIGNATURE_SIZE);
    t[4 + 8 + 8] = static_cast<uint8_t>(sig_len & 0xFF);
    t[4 + 8 + 8 + 1] = static_cast<uint8_t>(sig_len >> 8);
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED,
           "extra bytes after declared signature must be MALFORMED (strict mode)");
}

TEST(envelope_tryparse_duplicate_magic) {
    SampleEnvelope env;
    // SMP1 header + a second SMP1 inside the signature region (place at an
    // offset that collides with what would otherwise be a valid trailer).
    std::vector<uint8_t> t(4 + 8 + 8 + 2 + DFMP::MIK_SIGNATURE_SIZE, 0);
    t[0]='S'; t[1]='M'; t[2]='P'; t[3]='1';
    uint16_t sig_len = static_cast<uint16_t>(DFMP::MIK_SIGNATURE_SIZE);
    t[4 + 8 + 8] = static_cast<uint8_t>(sig_len & 0xFF);
    t[4 + 8 + 8 + 1] = static_cast<uint8_t>(sig_len >> 8);
    // Place a second SMP1 at offset 100 (well inside the signature region)
    t[100]='S'; t[101]='M'; t[102]='P'; t[103]='1';
    auto r = SampleEnvelope::TryParse(t, env);
    ASSERT(r == SampleEnvelope::ParseResult::MALFORMED,
           "duplicate SMP1 markers in trailer region must be MALFORMED");
}

TEST(envelope_tryparse_valid_roundtrip_via_towire) {
    auto kp = p15::make_keypair();
    auto mik = p15::make_mik(0x06);
    auto dna = p15::make_dna_bytes(0x55);
    SampleEnvelope in;
    in.timestamp_sec = 1700000123ULL;
    in.nonce = 0xcafebabe12345678ULL;
    ASSERT(SampleEnvelope::Sign(kp.privkey.data(), kp.privkey.size(),
                                 mik, in.timestamp_sec, in.nonce, dna, in.signature),
           "sign roundtrip");

    auto wire = in.ToWireBytes();
    ASSERT(!wire.empty(), "wire bytes non-empty");

    SampleEnvelope out;
    auto r = SampleEnvelope::TryParse(wire, out);
    ASSERT(r == SampleEnvelope::ParseResult::SIGNED,
           "roundtrip via ToWireBytes -> TryParse must be SIGNED");
    ASSERT_EQ(out.timestamp_sec, in.timestamp_sec, "ts roundtrip");
    ASSERT_EQ(out.nonce, in.nonce, "nonce roundtrip");
    ASSERT_EQ(out.signature.size(), in.signature.size(), "sig size roundtrip");
    ASSERT(std::memcmp(out.signature.data(), in.signature.data(), in.signature.size()) == 0,
           "sig bytes roundtrip");

    // And the parsed envelope verifies against the original pubkey.
    ASSERT(SampleEnvelope::Verify(kp.pubkey, mik, out.timestamp_sec, out.nonce,
                                   dna, out.signature),
           "parsed sig verifies");
}

// ---- Replay cache -------------------------------------------------------

TEST(replay_cache_not_seen_before_record) {
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x10);
    ASSERT(!lim.replay_seen(mik, 100, 1), "unseen (mik,ts,nonce) is not in cache");
}

TEST(replay_cache_seen_after_record) {
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x11);
    lim.replay_record(mik, 100, 1, 1700000000ULL);
    ASSERT(lim.replay_seen(mik, 100, 1), "recorded (mik,ts,nonce) must be seen");
    ASSERT(!lim.replay_seen(mik, 100, 2), "different nonce not seen");
    ASSERT(!lim.replay_seen(mik, 101, 1), "different ts not seen");
}

TEST(replay_cache_expires_after_ttl) {
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x12);
    lim.replay_record(mik, 100, 42, 1700000000ULL);
    ASSERT(lim.replay_seen(mik, 100, 42), "seen at record time");
    // After record: entry expires at now_sec + REPLAY_TTL_SEC (1700000000 + 600)
    // A later record at a time past that will prune the expired entry.
    lim.replay_record(mik, 200, 99, 1700000000ULL + DNASampleRateLimiter::REPLAY_TTL_SEC + 1);
    ASSERT(!lim.replay_seen(mik, 100, 42), "original entry pruned after TTL");
    ASSERT(lim.replay_seen(mik, 200, 99), "new entry still present");
}

// ---- Staged rate-limiter APIs ------------------------------------------

TEST(staged_consume_peer_bucket_caps_at_burst) {
    DNASampleRateLimiter lim;
    // Peer 1 starts at full burst = 5 tokens. Staged API caps at burst.
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        ASSERT(lim.consume_peer_bucket(1, 1000), "burst consume");
    }
    ASSERT(!lim.consume_peer_bucket(1, 1000), "6th consume in same second must fail");
}

TEST(staged_peer_bucket_refills_over_time) {
    DNASampleRateLimiter lim;
    // Drain all 5 tokens.
    for (int i = 0; i < static_cast<int>(DNASampleRateLimiter::PEER_BUCKET_BURST); ++i) {
        lim.consume_peer_bucket(1, 1000);
    }
    // One refill tick is PEER_BUCKET_REFILL_SEC.
    ASSERT(lim.consume_peer_bucket(1, 1000 + DNASampleRateLimiter::PEER_BUCKET_REFILL_SEC),
           "one refill after refill-sec should allow one consume");
}

TEST(staged_check_mik_limits_is_non_mutating) {
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x20);
    // Fresh MIK — both layers pass. Call twice: idempotent / non-mutating.
    ASSERT(lim.check_mik_limits(1, mik, 1000), "first check passes");
    ASSERT(lim.check_mik_limits(1, mik, 1000), "second check still passes (non-mutating)");
}

TEST(staged_commit_mik_limits_persists) {
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x21);
    ASSERT(lim.check_mik_limits(1, mik, 1000), "initial check passes");
    lim.commit_mik_limits(1, mik, 1000);
    // Immediately after commit, per-MIK global should deny for MIK_GLOBAL_MIN_SEC.
    ASSERT(!lim.check_mik_limits(2, mik, 1001),
           "different peer within MIK global window must fail");
    ASSERT(!lim.check_mik_limits(1, mik, 1001),
           "same peer within MIK-per-peer window must fail");
    // After MIK_GLOBAL_MIN_SEC + 1, a different peer passes the global layer
    // but still fails MIK-per-peer on peer 1; peer 2 sees fresh state.
    uint64_t later = 1000 + DNASampleRateLimiter::MIK_GLOBAL_MIN_SEC + 1;
    ASSERT(lim.check_mik_limits(2, mik, later),
           "different peer after global min passes");
}

TEST(staged_allow_still_works_for_phase_1_callers) {
    // Regression: the atomic allow() / allow_detail() path must still be intact
    // after the split-API refactor so Phase 1.1 merge-fill callers don't break.
    DNASampleRateLimiter lim;
    auto mik = p15::make_mik(0x22);
    ASSERT(lim.allow(1, mik, 1000), "first allow accepts");
    ASSERT(!lim.allow(1, mik, 1001), "same peer within window rejects");
}

// ---------------------------------------------------------------------------
// Phase 1.5 — wire-format tests (CreateDNAIdentResMessage version gate +
//             ProcessDNAIdentResMessage trailer parser)
// ---------------------------------------------------------------------------

namespace p15wire {

// Helper: scan a payload for the SMP1 magic anywhere after the first
// (header + data_len) bytes. Used to assert that the version gate either
// did or did not append the trailer.
static bool ContainsSMP1MagicAfter(const std::vector<uint8_t>& payload, size_t offset) {
    if (payload.size() < offset + 4) return false;
    for (size_t i = offset; i + 4 <= payload.size(); ++i) {
        if (payload[i] == 'S' && payload[i+1] == 'M' &&
            payload[i+2] == 'P' && payload[i+3] == '1') {
            return true;
        }
    }
    return false;
}

// Build a fake but well-formed envelope (signature is zeros — content
// doesn't matter for the version-gate test, only its size + presence).
static digital_dna::SampleEnvelope MakeFakeEnvelope() {
    digital_dna::SampleEnvelope env;
    env.timestamp_sec = 1700000000ULL;
    env.nonce = 0x1234567890abcdefULL;
    env.signature.assign(DFMP::MIK_SIGNATURE_SIZE, 0xAB);
    return env;
}

// Build a minimal dnaires payload (mik + found + len + dna_data) without trailer.
// dna_data_len bytes of fill 0xCD. Used as a baseline body for the parser tests.
static std::vector<uint8_t> BuildDnairesBody(const std::array<uint8_t, 20>& mik,
                                              size_t dna_data_len)
{
    std::vector<uint8_t> body;
    body.insert(body.end(), mik.begin(), mik.end());      // mik(20)
    body.push_back(0x01);                                  // found = 1
    body.push_back(static_cast<uint8_t>(dna_data_len & 0xFF));        // len LE lo
    body.push_back(static_cast<uint8_t>((dna_data_len >> 8) & 0xFF)); // len LE hi
    for (size_t i = 0; i < dna_data_len; ++i) body.push_back(0xCD);   // dna_data fill
    return body;
}

} // namespace p15wire

TEST(create_dnaires_version_gate_emits_no_trailer_for_old_peer) {
    CPeerManager pm;  // empty datadir is fine for in-memory test
    CNetMessageProcessor processor(pm);

    auto mik = p15::make_mik(0xA1);
    auto env = p15wire::MakeFakeEnvelope();
    std::vector<uint8_t> dna_data(256, 0xCD);

    // Old peer (one less than the SMP1 minimum) — must NOT receive a trailer.
    int old_version = NetProtocol::DNA_SMP1_MIN_PROTOCOL_VERSION - 1;
    auto msg_old = processor.CreateDNAIdentResMessage(mik, true, dna_data, &env, old_version);

    // Expected legacy size: 20 (mik) + 1 (found) + 2 (len) + 256 (dna_data) = 279
    const size_t legacy_size = 20 + 1 + 2 + dna_data.size();
    ASSERT_EQ(msg_old.payload.size(), legacy_size,
              "legacy payload size for old peer");
    ASSERT(!p15wire::ContainsSMP1MagicAfter(msg_old.payload, 0),
           "old-peer payload must not contain SMP1 magic anywhere");
}

TEST(create_dnaires_version_gate_emits_trailer_for_new_peer) {
    CPeerManager pm;
    CNetMessageProcessor processor(pm);

    auto mik = p15::make_mik(0xA2);
    auto env = p15wire::MakeFakeEnvelope();
    std::vector<uint8_t> dna_data(256, 0xCD);

    // New peer at exactly the SMP1 minimum — MUST receive the trailer.
    int new_version = NetProtocol::DNA_SMP1_MIN_PROTOCOL_VERSION;
    auto msg_new = processor.CreateDNAIdentResMessage(mik, true, dna_data, &env, new_version);

    const size_t body_size = 20 + 1 + 2 + dna_data.size();
    ASSERT(msg_new.payload.size() > body_size,
           "new-peer payload must be larger than legacy (trailer present)");
    ASSERT(p15wire::ContainsSMP1MagicAfter(msg_new.payload, body_size),
           "SMP1 magic must appear at trailer offset = header + data_len");
}

TEST(create_dnaires_no_envelope_never_emits_trailer) {
    // Sanity: even at a new peer version, omitting the envelope (nullptr)
    // must produce the legacy unsigned shape — guards the seed-without-MIK case.
    CPeerManager pm;
    CNetMessageProcessor processor(pm);

    auto mik = p15::make_mik(0xA3);
    std::vector<uint8_t> dna_data(128, 0x77);

    auto msg = processor.CreateDNAIdentResMessage(
        mik, true, dna_data, nullptr,
        NetProtocol::DNA_SMP1_MIN_PROTOCOL_VERSION);

    const size_t expected = 20 + 1 + 2 + dna_data.size();
    ASSERT_EQ(msg.payload.size(), expected,
              "no-envelope path produces legacy payload regardless of peer version");
}

// ---- ProcessDNAIdentResMessage parser harness ---------------------------

// Captured-state shim — the handler writes here for assertion.
namespace p15wire {
struct CapturedRes {
    bool invoked = false;
    std::array<uint8_t, 20> mik{};
    bool found = false;
    std::vector<uint8_t> dna_data;
    digital_dna::SampleEnvelope envelope;
    void clear() { invoked = false; mik = {}; found = false; dna_data.clear(); envelope = {}; }
};
static CapturedRes g_captured;

static void Capture(int /*peer_id*/, const std::array<uint8_t, 20>& m, bool f,
                    const std::vector<uint8_t>& d,
                    const digital_dna::SampleEnvelope& env) {
    g_captured.invoked = true;
    g_captured.mik = m;
    g_captured.found = f;
    g_captured.dna_data = d;
    g_captured.envelope = env;
}
} // namespace p15wire

TEST(process_dnaires_unsigned_no_trailer_invokes_handler_no_penalty) {
    CPeerManager pm;
    CNetMessageProcessor processor(pm);
    processor.SetDNAIdentResHandler(p15wire::Capture);
    p15wire::g_captured.clear();

    auto mik = p15::make_mik(0xB1);
    auto body = p15wire::BuildDnairesBody(mik, 64);
    CNetMessage msg("dnaires", body);

    bool ok = processor.ProcessMessage(/*peer_id=*/42, msg);
    ASSERT(ok, "process must succeed");
    ASSERT(p15wire::g_captured.invoked, "handler invoked");
    ASSERT(p15wire::g_captured.envelope.signature.empty(),
           "no trailer => empty signature on envelope");
    ASSERT_EQ(p15wire::g_captured.dna_data.size(), (size_t)64, "dna_data round-trips");
}

TEST(process_dnaires_unknown_magic_silent_ignore_no_penalty) {
    CPeerManager pm;
    CNetMessageProcessor processor(pm);
    processor.SetDNAIdentResHandler(p15wire::Capture);
    p15wire::g_captured.clear();

    auto mik = p15::make_mik(0xB2);
    auto body = p15wire::BuildDnairesBody(mik, 32);
    // Append an unknown 4-byte magic + zero filler at the trailer offset.
    body.insert(body.end(), {'X', 'X', 'X', 'X', 0, 0, 0, 0, 0, 0, 0, 0});
    CNetMessage msg("dnaires", body);

    // Forward-compat rule: unknown magic at trailer offset must NOT misbehave.
    bool ok = processor.ProcessMessage(/*peer_id=*/43, msg);
    ASSERT(ok, "unknown magic must succeed without penalty");
    ASSERT(p15wire::g_captured.invoked, "handler invoked even with unknown trailer");
    ASSERT(p15wire::g_captured.envelope.signature.empty(),
           "unknown trailer => envelope stays unsigned");
}

TEST(process_dnaires_signed_roundtrip_populates_envelope) {
    CPeerManager pm;
    CNetMessageProcessor processor(pm);
    processor.SetDNAIdentResHandler(p15wire::Capture);
    p15wire::g_captured.clear();

    auto mik = p15::make_mik(0xB3);
    auto kp = p15::make_keypair();
    std::vector<uint8_t> dna(96, 0xCD);

    digital_dna::SampleEnvelope env;
    env.timestamp_sec = 1700000123ULL;
    env.nonce = 0xDEADBEEFCAFE0001ULL;
    ASSERT(digital_dna::SampleEnvelope::Sign(
               kp.privkey.data(), kp.privkey.size(), mik,
               env.timestamp_sec, env.nonce, dna, env.signature),
           "sign sample for parser test");

    // Build body: mik + found + len + dna + SMP1 trailer.
    auto body = p15wire::BuildDnairesBody(mik, dna.size());
    // Replace dna_data fill with the actual dna bytes used for signing.
    std::copy(dna.begin(), dna.end(), body.begin() + 20 + 1 + 2);
    auto trailer = env.ToWireBytes();
    body.insert(body.end(), trailer.begin(), trailer.end());

    CNetMessage msg("dnaires", body);
    bool ok = processor.ProcessMessage(/*peer_id=*/44, msg);
    ASSERT(ok, "signed dnaires must parse");
    ASSERT(p15wire::g_captured.invoked, "handler invoked");
    ASSERT_EQ(p15wire::g_captured.envelope.timestamp_sec, env.timestamp_sec, "ts roundtrip");
    ASSERT_EQ(p15wire::g_captured.envelope.nonce, env.nonce, "nonce roundtrip");
    ASSERT_EQ(p15wire::g_captured.envelope.signature.size(),
              (size_t)DFMP::MIK_SIGNATURE_SIZE, "sig length roundtrip");
}

TEST(process_dnaires_malformed_smp1_misbehaviour_no_handler_invocation) {
    CPeerManager pm;
    CNetMessageProcessor processor(pm);
    processor.SetDNAIdentResHandler(p15wire::Capture);
    p15wire::g_captured.clear();

    auto mik = p15::make_mik(0xB4);
    auto body = p15wire::BuildDnairesBody(mik, 16);
    // Append SMP1 magic but truncate before the timestamp ends — MALFORMED.
    body.insert(body.end(), {'S', 'M', 'P', '1', 0x01, 0x02, 0x03});  // only 3 of 8 ts bytes
    CNetMessage msg("dnaires", body);

    bool ok = processor.ProcessMessage(/*peer_id=*/45, msg);
    ASSERT(!ok, "malformed SMP1 must reject");
    ASSERT(!p15wire::g_captured.invoked,
           "handler must NOT be invoked when parser rejects");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "\n" << YELLOW_ << "=== DNA Propagation Phase 1 + 1.1 + 1.5 Tests ===" << RESET_ << "\n" << std::endl;

    test_append_sample_unregistered_registers_wrapper();
    test_append_sample_enriches_and_archives_wrapper();
    test_append_sample_rejects_dimension_loss_wrapper();
    test_append_sample_same_dim_value_change_accepted_wrapper();
    test_history_capped_at_max_per_mik_wrapper();

    test_rate_limiter_peer_bucket_burst_then_refill_wrapper();
    test_rate_limiter_per_mik_global_wrapper();
    test_rate_limiter_per_mik_per_peer_wrapper();
    test_rate_limiter_reject_leaves_state_unchanged_wrapper();

    // Phase 1.1 merge-fill tests
    test_merge_fill_fills_missing_dimension_wrapper();
    test_merge_fill_no_gap_returns_existing_with_zero_filled_wrapper();
    test_merge_fill_preserves_existing_values_on_conflict_wrapper();
    test_merge_fill_multiple_missing_dims_wrapper();
    test_merge_fill_then_append_sample_succeeds_with_dim_loss_guard_wrapper();
    test_merge_fill_perspective_dim_is_fillable_wrapper();

    // Phase 1.2 discovery source tests
    test_discovery_source_dil_empty_cooldown_tracker_returns_registry_miks_wrapper();
    test_discovery_source_union_dedupes_overlap_wrapper();
    test_dna_registry_db_get_all_miks_returns_stored_miks_wrapper();

    // Phase 1.5 envelope tests
    test_envelope_sign_verify_roundtrip_wrapper();
    test_envelope_verify_rejects_tampered_signature_wrapper();
    test_envelope_verify_rejects_tampered_dna_data_wrapper();
    test_envelope_verify_rejects_wrong_mik_wrapper();

    test_envelope_tryparse_empty_returns_none_wrapper();
    test_envelope_tryparse_unknown_magic_is_silent_ignore_wrapper();
    test_envelope_tryparse_truncated_magic_is_malformed_wrapper();
    test_envelope_tryparse_truncated_timestamp_wrapper();
    test_envelope_tryparse_truncated_nonce_wrapper();
    test_envelope_tryparse_truncated_sig_len_wrapper();
    test_envelope_tryparse_siglen_zero_is_malformed_wrapper();
    test_envelope_tryparse_wrong_sig_len_wrapper();
    test_envelope_tryparse_sig_len_gt_remaining_wrapper();
    test_envelope_tryparse_trailing_bytes_after_sig_wrapper();
    test_envelope_tryparse_duplicate_magic_wrapper();
    test_envelope_tryparse_valid_roundtrip_via_towire_wrapper();

    // Phase 1.5 replay cache tests
    test_replay_cache_not_seen_before_record_wrapper();
    test_replay_cache_seen_after_record_wrapper();
    test_replay_cache_expires_after_ttl_wrapper();

    // Phase 1.5 staged rate-limiter API tests
    test_staged_consume_peer_bucket_caps_at_burst_wrapper();
    test_staged_peer_bucket_refills_over_time_wrapper();
    test_staged_check_mik_limits_is_non_mutating_wrapper();
    test_staged_commit_mik_limits_persists_wrapper();
    test_staged_allow_still_works_for_phase_1_callers_wrapper();

    // Phase 1.5 follow-up: wire-format and parser harness tests
    test_create_dnaires_version_gate_emits_no_trailer_for_old_peer_wrapper();
    test_create_dnaires_version_gate_emits_trailer_for_new_peer_wrapper();
    test_create_dnaires_no_envelope_never_emits_trailer_wrapper();
    test_process_dnaires_unsigned_no_trailer_invokes_handler_no_penalty_wrapper();
    test_process_dnaires_unknown_magic_silent_ignore_no_penalty_wrapper();
    test_process_dnaires_signed_roundtrip_populates_envelope_wrapper();
    test_process_dnaires_malformed_smp1_misbehaviour_no_handler_invocation_wrapper();

    std::cout << "\n" << YELLOW_ << "=== Results ===" << RESET_ << std::endl;
    std::cout << GREEN_ << "Passed: " << g_tests_passed << RESET_ << std::endl;
    if (g_tests_failed > 0) {
        std::cout << RED_ << "Failed: " << g_tests_failed << RESET_ << std::endl;
        return 1;
    }
    return 0;
}
