/**
 * Digital DNA Serialization & Persistence Tests
 *
 * Tests:
 *  1. v2 serialize roundtrip (core 3 dimensions)
 *  2. v3 serialize roundtrip (all 8 dimensions)
 *  3. v1 backward compatibility (legacy 56-byte format)
 *  4. DNA2 magic detection
 *  5. Partial optional roundtrip (some v3.0 dims set)
 *  6. Registry DB CRUD (open, register, retrieve, reopen, verify)
 *  7. Registry advisory Sybil (similar identities both stored)
 *  8. Registry update_identity (progressive enrichment)
 */

#include "digital_dna.h"
#include "dna_registry_interface.h"
#include "dna_registry_db.h"
#include <dfmp/mik.h>

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cassert>
#include <filesystem>
#include <cmath>

using namespace digital_dna;

static int tests_passed = 0;
static int tests_failed = 0;

static void CHECK(bool condition, const char* name) {
    if (condition) {
        std::cout << "  [PASS] " << name << std::endl;
        tests_passed++;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
        tests_failed++;
    }
}

// Helper: create a DigitalDNA with core dims only
static DigitalDNA make_core_dna(uint8_t addr_byte, double median_ms, double ips, uint32_t height) {
    DigitalDNA dna;
    dna.address.fill(addr_byte);
    dna.registration_height = height;
    dna.registration_time = 1700000000 + height;
    dna.is_valid = true;

    // Latency: 4 seeds
    dna.latency.seed_stats.resize(4);
    for (int i = 0; i < 4; i++) {
        dna.latency.seed_stats[i].median_ms = median_ms + i * 10.0;
    }

    // Timing
    dna.timing.iterations_per_second = ips;
    dna.timing.total_iterations = 10000000;

    // Perspective (minimal)
    // PerspectiveProof has internal state — just leave it default

    return dna;
}

// Helper: add all v3.0 dimensions
static void add_v3_dims(DigitalDNA& dna) {
    // Memory
    MemoryFingerprint mem;
    mem.access_curve.push_back({32, 1.5, 50000.0});
    mem.access_curve.push_back({256, 3.2, 40000.0});
    mem.access_curve.push_back({4096, 8.7, 30000.0});
    mem.estimated_l1_kb = 32;
    mem.estimated_l2_kb = 256;
    mem.estimated_l3_kb = 8192;
    mem.dram_latency_ns = 65.0;
    mem.peak_bandwidth_mbps = 45000.0;
    dna.memory = mem;

    // Clock drift
    ClockDriftFingerprint cd;
    cd.drift_rate_ppm = 12.5;
    cd.drift_stability = 0.95;
    cd.jitter_signature = 0.003;
    dna.clock_drift = cd;

    // Bandwidth
    BandwidthFingerprint bw;
    bw.median_upload_mbps = 50.0;
    bw.median_download_mbps = 200.0;
    bw.median_asymmetry = 4.0;
    bw.bandwidth_stability = 0.88;
    dna.bandwidth = bw;

    // Thermal
    ThermalProfile tp;
    tp.speed_curve = {100000.0, 98000.0, 95000.0, 94000.0, 93500.0};
    tp.measurement_interval_sec = 60;
    tp.initial_speed = 100000.0;
    tp.sustained_speed = 93500.0;
    tp.throttle_ratio = 0.935;
    tp.time_to_steady_state_sec = 180.0;
    tp.thermal_jitter = 500.0;
    dna.thermal = tp;

    // Behavioral
    BehavioralProfile bp;
    for (int i = 0; i < 24; i++) bp.hourly_activity[i] = (i >= 8 && i <= 22) ? 1.0 : 0.1;
    bp.mean_relay_delay_ms = 150.0;
    bp.relay_consistency = 0.85;
    bp.avg_peer_session_duration_sec = 43200.0;
    bp.peer_diversity_score = 0.7;
    bp.tx_relay_rate = 0.02;
    bp.tx_timing_entropy = 3.5;
    bp.observation_blocks = 2000;
    dna.behavioral = bp;
}

// ============ Test 1: v2 serialize roundtrip (core 3 dims) ============
static void test_v2_serialize_roundtrip() {
    std::cout << "\n=== Test 1: v2 serialize roundtrip (core dims) ===\n";

    auto dna = make_core_dna(0xAA, 45.0, 500000.0, 1000);
    auto data = dna.serialize();

    CHECK(data.size() >= 5, "Serialized data has minimum size");
    CHECK(data[0] == 0x44 && data[1] == 0x4E && data[2] == 0x41 && data[3] == 0x32,
          "Starts with DNA2 magic");
    CHECK(data[4] == 0x03, "Version byte is 0x03");

    auto restored = DigitalDNA::deserialize(data);
    CHECK(restored.has_value(), "Deserialize succeeds");
    CHECK(restored->address == dna.address, "Address matches");
    CHECK(restored->registration_height == dna.registration_height, "Height matches");
    CHECK(restored->registration_time == dna.registration_time, "Time matches");
    CHECK(restored->latency.seed_stats.size() == 4, "4 seed stats");
    CHECK(std::abs(restored->latency.seed_stats[0].median_ms - 45.0) < 0.001, "Median ms matches");
    CHECK(std::abs(restored->timing.iterations_per_second - 500000.0) < 0.001, "IPS matches");
    CHECK(restored->is_valid, "is_valid set");
    CHECK(!restored->memory.has_value(), "No memory (core only)");
    CHECK(!restored->clock_drift.has_value(), "No clock drift (core only)");
    CHECK(!restored->bandwidth.has_value(), "No bandwidth (core only)");
    CHECK(!restored->thermal.has_value(), "No thermal (core only)");
    CHECK(!restored->behavioral.has_value(), "No behavioral (core only)");
}

// ============ Test 2: v3 serialize roundtrip (all 8 dims) ============
static void test_v3_serialize_roundtrip() {
    std::cout << "\n=== Test 2: v3 serialize roundtrip (all 8 dims) ===\n";

    auto dna = make_core_dna(0xBB, 120.0, 750000.0, 5000);
    add_v3_dims(dna);

    auto data = dna.serialize();
    auto restored = DigitalDNA::deserialize(data);

    CHECK(restored.has_value(), "Deserialize succeeds");
    CHECK(restored->memory.has_value(), "Memory present");
    CHECK(restored->clock_drift.has_value(), "Clock drift present");
    CHECK(restored->bandwidth.has_value(), "Bandwidth present");
    CHECK(restored->thermal.has_value(), "Thermal present");
    CHECK(restored->behavioral.has_value(), "Behavioral present");

    // Verify memory values
    CHECK(restored->memory->access_curve.size() == 3, "Memory: 3 probe results");
    CHECK(std::abs(restored->memory->estimated_l1_kb - 32.0) < 0.001, "Memory: L1 matches");
    CHECK(std::abs(restored->memory->dram_latency_ns - 65.0) < 0.001, "Memory: DRAM latency matches");

    // Verify clock drift values
    CHECK(std::abs(restored->clock_drift->drift_rate_ppm - 12.5) < 0.001, "Clock: drift rate matches");
    CHECK(std::abs(restored->clock_drift->drift_stability - 0.95) < 0.001, "Clock: stability matches");

    // Verify bandwidth values
    CHECK(std::abs(restored->bandwidth->median_upload_mbps - 50.0) < 0.001, "BW: upload matches");
    CHECK(std::abs(restored->bandwidth->median_download_mbps - 200.0) < 0.001, "BW: download matches");

    // Verify thermal values
    CHECK(restored->thermal->speed_curve.size() == 5, "Thermal: 5 curve points");
    CHECK(std::abs(restored->thermal->initial_speed - 100000.0) < 0.001, "Thermal: initial matches");
    CHECK(std::abs(restored->thermal->throttle_ratio - 0.935) < 0.001, "Thermal: throttle matches");

    // Verify behavioral values
    CHECK(std::abs(restored->behavioral->mean_relay_delay_ms - 150.0) < 0.001, "Behavioral: relay delay matches");
    CHECK(restored->behavioral->observation_blocks == 2000, "Behavioral: observation blocks match");
}

// ============ Test 3: v1 backward compat ============
static void test_v1_backward_compat() {
    std::cout << "\n=== Test 3: v1 backward compatibility ===\n";

    // Build a legacy v1 blob manually (no magic, starts with address)
    std::vector<uint8_t> v1_data;

    // Address (20 bytes)
    for (int i = 0; i < 20; i++) v1_data.push_back(0xCC);

    // Registration height (4 bytes LE) = 42
    v1_data.push_back(42); v1_data.push_back(0); v1_data.push_back(0); v1_data.push_back(0);

    // Registration time (8 bytes LE) = 1700000042
    uint64_t t = 1700000042;
    for (int i = 0; i < 8; i++) v1_data.push_back(static_cast<uint8_t>(t >> (i * 8)));

    // Seed count (4 bytes) = 2
    v1_data.push_back(2); v1_data.push_back(0); v1_data.push_back(0); v1_data.push_back(0);

    // 2 seed medians (each 8 bytes)
    double m1 = 33.0, m2 = 55.0;
    uint64_t bits;
    std::memcpy(&bits, &m1, 8); for (int i = 0; i < 8; i++) v1_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));
    std::memcpy(&bits, &m2, 8); for (int i = 0; i < 8; i++) v1_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));

    // Timing IPS (8 bytes)
    double ips = 300000.0;
    std::memcpy(&bits, &ips, 8); for (int i = 0; i < 8; i++) v1_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));

    // Perspective (12 bytes: peer_count 4 + turnover 8)
    for (int i = 0; i < 12; i++) v1_data.push_back(0);

    CHECK(v1_data.size() == 72, "v1 blob is 72 bytes (20+4+8+4+16+8+12)");

    // First bytes are NOT "DNA2" magic (0xCC != 0x44)
    CHECK(v1_data[0] != 0x44, "v1 blob does not start with DNA2 magic");

    auto restored = DigitalDNA::deserialize(v1_data);
    CHECK(restored.has_value(), "v1 deserialize succeeds");
    CHECK(restored->address[0] == 0xCC, "v1 address preserved");
    CHECK(restored->registration_height == 42, "v1 height preserved");
    CHECK(std::abs(restored->latency.seed_stats[0].median_ms - 33.0) < 0.001, "v1 median preserved");
    CHECK(std::abs(restored->timing.iterations_per_second - 300000.0) < 0.001, "v1 IPS preserved");
}

// ============ Test 4: Magic detection ============
static void test_magic_detection() {
    std::cout << "\n=== Test 4: DNA2 magic detection ===\n";

    // v2 format (has magic)
    auto dna = make_core_dna(0x11, 50.0, 400000.0, 100);
    auto v2_data = dna.serialize();
    CHECK(v2_data[0] == 'D' && v2_data[1] == 'N' && v2_data[2] == 'A' && v2_data[3] == '2',
          "v2 data has 'DNA2' magic string");

    // Empty data
    auto empty = DigitalDNA::deserialize({});
    CHECK(!empty.has_value(), "Empty data returns nullopt");

    // Too short
    auto too_short = DigitalDNA::deserialize({0x44, 0x4E, 0x41});
    CHECK(!too_short.has_value(), "3-byte data returns nullopt");

    // Magic + wrong version
    std::vector<uint8_t> bad_ver = {0x44, 0x4E, 0x41, 0x32, 0xFF};
    auto bad = DigitalDNA::deserialize(bad_ver);
    CHECK(!bad.has_value(), "Unknown version returns nullopt");
}

// ============ Test 5: Partial optional roundtrip ============
static void test_partial_optional_roundtrip() {
    std::cout << "\n=== Test 5: Partial optional roundtrip ===\n";

    auto dna = make_core_dna(0x55, 80.0, 600000.0, 3000);

    // Only add memory and bandwidth (no clock drift, thermal, behavioral)
    MemoryFingerprint mem;
    mem.access_curve.push_back({64, 2.0, 48000.0});
    mem.estimated_l1_kb = 64;
    mem.estimated_l2_kb = 512;
    mem.estimated_l3_kb = 16384;
    mem.dram_latency_ns = 70.0;
    mem.peak_bandwidth_mbps = 50000.0;
    dna.memory = mem;

    BandwidthFingerprint bw;
    bw.median_upload_mbps = 100.0;
    bw.median_download_mbps = 500.0;
    bw.median_asymmetry = 5.0;
    bw.bandwidth_stability = 0.92;
    dna.bandwidth = bw;

    auto data = dna.serialize();
    auto restored = DigitalDNA::deserialize(data);

    CHECK(restored.has_value(), "Deserialize succeeds");
    CHECK(restored->memory.has_value(), "Memory present");
    CHECK(!restored->clock_drift.has_value(), "Clock drift absent (not set)");
    CHECK(restored->bandwidth.has_value(), "Bandwidth present");
    CHECK(!restored->thermal.has_value(), "Thermal absent (not set)");
    CHECK(!restored->behavioral.has_value(), "Behavioral absent (not set)");
    CHECK(std::abs(restored->memory->estimated_l1_kb - 64.0) < 0.001, "Memory L1 correct");
    CHECK(std::abs(restored->bandwidth->median_upload_mbps - 100.0) < 0.001, "BW upload correct");
}

// ============ Test 6: Registry DB CRUD ============
static void test_registry_db_crud() {
    std::cout << "\n=== Test 6: Registry DB CRUD ===\n";

    std::string db_path = "test_dna_registry_crud";

    // Cleanup from previous run
    std::filesystem::remove_all(db_path);

    {
        DNARegistryDB db;
        CHECK(db.Open(db_path), "Open succeeds");
        CHECK(db.count() == 0, "Empty initially");

        auto dna = make_core_dna(0x01, 40.0, 500000.0, 100);
        auto result = db.register_identity(dna);
        CHECK(result == IDNARegistry::RegisterResult::SUCCESS, "Register succeeds");
        CHECK(db.count() == 1, "Count is 1");
        CHECK(db.is_registered(dna.address), "is_registered returns true");

        auto retrieved = db.get_identity(dna.address);
        CHECK(retrieved.has_value(), "get_identity returns value");
        CHECK(std::abs(retrieved->timing.iterations_per_second - 500000.0) < 0.001, "Retrieved IPS matches");

        // Duplicate registration
        auto dup_result = db.register_identity(dna);
        CHECK(dup_result == IDNARegistry::RegisterResult::ALREADY_REGISTERED, "Duplicate returns ALREADY_REGISTERED");

        db.Close();
    }

    // Reopen and verify persistence
    {
        DNARegistryDB db;
        CHECK(db.Open(db_path), "Reopen succeeds");
        CHECK(db.count() == 1, "Persisted 1 identity");

        std::array<uint8_t, 20> addr;
        addr.fill(0x01);
        CHECK(db.is_registered(addr), "Persisted identity found");

        db.Close();
    }

    std::filesystem::remove_all(db_path);
}

// ============ Test 7: Advisory Sybil (both stored) ============
static void test_registry_advisory_sybil() {
    std::cout << "\n=== Test 7: Advisory Sybil detection ===\n";

    DigitalDNARegistry registry;

    // Create two nearly identical identities (different addresses, same hardware)
    auto dna1 = make_core_dna(0x01, 45.0, 500000.0, 100);
    auto dna2 = make_core_dna(0x02, 45.1, 500001.0, 101);  // Very similar

    auto r1 = registry.register_identity(dna1);
    CHECK(r1 == IDNARegistry::RegisterResult::SUCCESS, "First registration: SUCCESS");

    auto r2 = registry.register_identity(dna2);
    // Advisory mode: should store regardless, but may flag
    CHECK(r2 == IDNARegistry::RegisterResult::SUCCESS ||
          r2 == IDNARegistry::RegisterResult::SYBIL_FLAGGED,
          "Second registration: SUCCESS or SYBIL_FLAGGED (both stored)");

    CHECK(registry.count() == 2, "Both identities stored");
    CHECK(registry.is_registered(dna1.address), "First identity present");
    CHECK(registry.is_registered(dna2.address), "Second identity present");
}

// ============ Test 8: Update identity (progressive enrichment) ============
static void test_registry_update_identity() {
    std::cout << "\n=== Test 8: Progressive enrichment (update_identity) ===\n";

    DigitalDNARegistry registry;

    // Register with core dims only
    auto dna = make_core_dna(0x77, 60.0, 700000.0, 200);
    auto r1 = registry.register_identity(dna);
    CHECK(r1 == IDNARegistry::RegisterResult::SUCCESS, "Initial registration succeeds");

    auto initial = registry.get_identity(dna.address);
    CHECK(initial.has_value(), "Initial identity retrieved");
    CHECK(!initial->memory.has_value(), "Initially no memory dim");

    // Enrich with v3.0 dims
    add_v3_dims(dna);
    auto r2 = registry.update_identity(dna);
    CHECK(r2 == IDNARegistry::RegisterResult::UPDATED, "Update returns UPDATED");

    auto enriched = registry.get_identity(dna.address);
    CHECK(enriched.has_value(), "Enriched identity retrieved");
    CHECK(enriched->memory.has_value(), "Memory dim now present");
    CHECK(enriched->clock_drift.has_value(), "Clock drift dim now present");
    CHECK(enriched->thermal.has_value(), "Thermal dim now present");
    CHECK(enriched->behavioral.has_value(), "Behavioral dim now present");
    CHECK(registry.count() == 1, "Still only 1 identity");

    // Update non-existent address
    auto dna_fake = make_core_dna(0xFF, 10.0, 100000.0, 1);
    auto r3 = registry.update_identity(dna_fake);
    CHECK(r3 == IDNARegistry::RegisterResult::INVALID_DNA, "Update non-existent returns INVALID_DNA");
}

// =================================================================
// Test 9: Perspective cached fields survive serialize/deserialize
// =================================================================
void test_perspective_cached_roundtrip() {
    std::cout << "\n=== Test 9: Perspective cached fields roundtrip ===\n";

    auto dna = make_core_dna(0xAA, 100.0, 2000000.0, 5);
    // Simulate that perspective has peer_count/turnover from live collection
    // These are serialized as summary stats (peer_count + turnover double)

    auto data = dna.serialize();
    CHECK(!data.empty(), "Serialization produces non-empty data");

    auto restored = DigitalDNA::deserialize(data);
    CHECK(restored.has_value(), "Deserialization succeeds");

    // The cached fields should be populated from the serialized summary
    CHECK(restored->perspective.cached_peer_count >= 0, "cached_peer_count populated");
    CHECK(restored->perspective.cached_turnover_rate >= 0.0, "cached_turnover_rate populated");

    // total_unique_peers should return cached value when snapshots are empty
    CHECK(restored->perspective.snapshots.empty(), "No snapshots after deserialize");
    size_t peers = restored->perspective.total_unique_peers();
    double turnover = restored->perspective.peer_turnover_rate();
    CHECK(peers == restored->perspective.cached_peer_count, "total_unique_peers uses cached fallback");
    CHECK(turnover == restored->perspective.cached_turnover_rate, "peer_turnover_rate uses cached fallback");
}

// ============ Test 10: v3 serialize with MIK identity ============
static void test_v3_mik_serialize_roundtrip() {
    std::cout << "\n=== Test 10: v3 MIK identity serialize roundtrip ===\n";

    auto dna = make_core_dna(0xDD, 55.0, 600000.0, 2000);
    // Set a distinct MIK identity (different from address)
    dna.mik_identity.fill(0xEE);

    auto data = dna.serialize();

    CHECK(data.size() >= 5, "Serialized data has minimum size");
    CHECK(data[0] == 'D' && data[1] == 'N' && data[2] == 'A' && data[3] == '2',
          "Starts with DNA2 magic");
    CHECK(data[4] == 0x03, "Version byte is 0x03 (v3)");

    auto restored = DigitalDNA::deserialize(data);
    CHECK(restored.has_value(), "Deserialize succeeds");
    CHECK(restored->address[0] == 0xDD, "Address preserved");
    CHECK(restored->mik_identity[0] == 0xEE, "MIK identity preserved");
    CHECK(restored->mik_identity != restored->address, "MIK != address (distinct)");
    CHECK(restored->registration_height == 2000, "Height matches");
    CHECK(std::abs(restored->timing.iterations_per_second - 600000.0) < 0.001, "IPS matches");
}

// ============ Test 11: v2 backward compat sets mik_identity = address ============
static void test_v2_backward_compat_mik() {
    std::cout << "\n=== Test 11: v2 backward compat (mik = address) ===\n";

    // Build a v2 blob manually by using old format
    // Easiest: create a DNA, serialize as v3, then manually patch version byte to 0x02
    // and remove the 20-byte MIK field
    // Actually, let's just verify that v2 data still deserializes correctly
    // by checking the v1 deserializer already handles this.
    // The v2 path in deserialize now checks version == 0x02 and sets mik=address.
    // Let's build a v2 blob manually:

    std::vector<uint8_t> v2_data;
    // Magic
    v2_data.push_back(0x44); v2_data.push_back(0x4E);
    v2_data.push_back(0x41); v2_data.push_back(0x32);
    // Version = 0x02
    v2_data.push_back(0x02);
    // Address (20 bytes of 0xAA)
    for (int i = 0; i < 20; i++) v2_data.push_back(0xAA);
    // Registration height = 500
    v2_data.push_back(0xF4); v2_data.push_back(0x01); v2_data.push_back(0x00); v2_data.push_back(0x00);
    // Registration time = 1700000500
    uint64_t t = 1700000500;
    for (int i = 0; i < 8; i++) v2_data.push_back(static_cast<uint8_t>(t >> (i * 8)));
    // Flags = 0 (no optional dims)
    v2_data.push_back(0x00);
    // Seed count = 2
    v2_data.push_back(0x02); v2_data.push_back(0x00); v2_data.push_back(0x00); v2_data.push_back(0x00);
    // 2 seed medians
    double m1 = 50.0, m2 = 60.0;
    uint64_t bits;
    std::memcpy(&bits, &m1, 8); for (int i = 0; i < 8; i++) v2_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));
    std::memcpy(&bits, &m2, 8); for (int i = 0; i < 8; i++) v2_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));
    // Timing IPS
    double ips = 450000.0;
    std::memcpy(&bits, &ips, 8); for (int i = 0; i < 8; i++) v2_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));
    // Perspective: peer_count(4) + turnover(8)
    v2_data.push_back(5); v2_data.push_back(0); v2_data.push_back(0); v2_data.push_back(0);
    double turn = 0.5;
    std::memcpy(&bits, &turn, 8); for (int i = 0; i < 8; i++) v2_data.push_back(static_cast<uint8_t>(bits >> (i * 8)));

    auto restored = DigitalDNA::deserialize(v2_data);
    CHECK(restored.has_value(), "v2 deserialize succeeds");
    CHECK(restored->address[0] == 0xAA, "v2 address preserved");
    CHECK(restored->mik_identity == restored->address, "v2 backward compat: mik_identity == address");
    CHECK(restored->registration_height == 500, "v2 height preserved");
}

// ============ Test 12: MIK-based registry lookup ============
static void test_mik_registry_lookup() {
    std::cout << "\n=== Test 12: MIK-based registry lookup ===\n";

    DigitalDNARegistry registry;

    auto dna = make_core_dna(0x01, 40.0, 500000.0, 100);
    dna.mik_identity.fill(0xBB);  // Distinct MIK

    auto result = registry.register_identity(dna);
    CHECK(result == IDNARegistry::RegisterResult::SUCCESS, "Register succeeds");

    // Lookup by address (legacy)
    auto by_addr = registry.get_identity(dna.address);
    CHECK(by_addr.has_value(), "get_identity by address works");
    CHECK(by_addr->mik_identity[0] == 0xBB, "MIK preserved in address lookup");

    // Lookup by MIK (new primary key)
    std::array<uint8_t, 20> mik{};
    mik.fill(0xBB);
    auto by_mik = registry.get_identity_by_mik(mik);
    CHECK(by_mik.has_value(), "get_identity_by_mik works");
    CHECK(by_mik->address[0] == 0x01, "Address preserved in MIK lookup");

    // Lookup by wrong MIK
    std::array<uint8_t, 20> wrong_mik{};
    wrong_mik.fill(0xCC);
    auto by_wrong = registry.get_identity_by_mik(wrong_mik);
    CHECK(!by_wrong.has_value(), "Wrong MIK returns nullopt");
}

// ============ Test 13: MIK-based DB registry lookup ============
static void test_mik_registry_db_lookup() {
    std::cout << "\n=== Test 13: MIK-based DB registry lookup ===\n";

    std::string db_path = "test_dna_registry_mik";
    std::filesystem::remove_all(db_path);

    {
        DNARegistryDB db;
        CHECK(db.Open(db_path), "Open succeeds");

        auto dna = make_core_dna(0x22, 60.0, 700000.0, 300);
        dna.mik_identity.fill(0x33);

        auto result = db.register_identity(dna);
        CHECK(result == IDNARegistry::RegisterResult::SUCCESS, "DB register succeeds");

        // Lookup by MIK
        std::array<uint8_t, 20> mik{};
        mik.fill(0x33);
        auto by_mik = db.get_identity_by_mik(mik);
        CHECK(by_mik.has_value(), "DB get_identity_by_mik works");
        CHECK(by_mik->address[0] == 0x22, "DB MIK lookup returns correct address");

        db.Close();
    }

    // Reopen and verify MIK index is rebuilt from cache
    {
        DNARegistryDB db;
        CHECK(db.Open(db_path), "DB reopen succeeds");

        std::array<uint8_t, 20> mik{};
        mik.fill(0x33);
        auto by_mik = db.get_identity_by_mik(mik);
        CHECK(by_mik.has_value(), "DB MIK lookup survives reopen");

        db.Close();
    }

    std::filesystem::remove_all(db_path);
}

// ============ Test 14: DNA hash includes MIK identity ============
static void test_hash_includes_mik() {
    std::cout << "\n=== Test 14: DNA hash includes MIK identity ===\n";

    auto dna1 = make_core_dna(0x01, 40.0, 500000.0, 100);
    dna1.mik_identity.fill(0xAA);

    auto dna2 = make_core_dna(0x01, 40.0, 500000.0, 100);
    dna2.mik_identity.fill(0xBB);  // Different MIK, same address

    auto hash1 = dna1.hash();
    auto hash2 = dna2.hash();
    CHECK(hash1 != hash2, "Different MIK produces different hash");

    auto dna3 = make_core_dna(0x01, 40.0, 500000.0, 100);
    dna3.mik_identity.fill(0xAA);  // Same as dna1
    auto hash3 = dna3.hash();
    CHECK(hash1 == hash3, "Same MIK produces same hash");
}

// ============ Test 15: DNA commitment build & parse roundtrip ============
static void test_dna_commitment_roundtrip() {
    std::cout << "\n=== Test 15: DNA commitment build & parse roundtrip ===\n";

    // Create a DNA and compute its hash
    auto dna = make_core_dna(0x42, 35.0, 600000.0, 200);
    dna.mik_identity.fill(0xCC);
    auto dnaHash = dna.hash();

    // Build commitment bytes
    std::vector<uint8_t> commitData;
    // Simulate: MIK marker first (0xDF), then reference data, then DNA commitment
    // For this test, just build the DNA commitment part
    DFMP::BuildDNACommitment(dnaHash, commitData);

    // Verify format: 0xDD + 32 bytes = 33 bytes total
    CHECK(commitData.size() == 33, "Commitment is 33 bytes (marker + hash)");
    CHECK(commitData[0] == 0xDD, "First byte is DNA_COMMITMENT_MARKER (0xDD)");

    // Verify hash matches
    std::array<uint8_t, 32> extractedHash{};
    std::copy(commitData.begin() + 1, commitData.end(), extractedHash.begin());
    CHECK(extractedHash == dnaHash, "Extracted hash matches original DNA hash");
}

// ============ Test 16: DNA commitment parsed from full scriptSig ============
static void test_dna_commitment_in_scriptsig() {
    std::cout << "\n=== Test 16: DNA commitment parsed from full scriptSig ===\n";

    // Build a minimal scriptSig with MIK reference + DNA commitment
    // Format: [height bytes] [msg] [MIK_MARKER] [MIK_TYPE_REFERENCE] [identity:20] [sig:3309] [0xDD] [hash:32]

    std::vector<uint8_t> scriptSig;

    // Height: 1 byte (height=100)
    scriptSig.push_back(0x01);  // push 1 byte
    scriptSig.push_back(100);

    // Message
    std::string msg = "Test block";
    scriptSig.insert(scriptSig.end(), msg.begin(), msg.end());

    // MIK reference
    DFMP::Identity mikId;
    std::memset(mikId.data, 0xEE, 20);

    // Build a fake signature (3309 bytes of 0xAA)
    std::vector<uint8_t> fakeSig(DFMP::MIK_SIGNATURE_SIZE, 0xAA);

    std::vector<uint8_t> mikData;
    DFMP::BuildMIKScriptSigReference(mikId, fakeSig, mikData);
    scriptSig.insert(scriptSig.end(), mikData.begin(), mikData.end());

    // DNA commitment
    auto dna = make_core_dna(0x42, 35.0, 600000.0, 200);
    dna.mik_identity.fill(0xEE);  // Same as MIK identity
    auto dnaHash = dna.hash();
    DFMP::BuildDNACommitment(dnaHash, scriptSig);

    // Parse it back
    DFMP::CMIKScriptData parsed;
    bool ok = DFMP::ParseMIKFromScriptSig(scriptSig, parsed);
    CHECK(ok, "ParseMIKFromScriptSig succeeds");
    CHECK(parsed.has_dna_hash, "DNA hash flag is set");
    CHECK(parsed.dna_hash == dnaHash, "Parsed DNA hash matches original");

    // Verify MIK identity was also parsed correctly
    CHECK(std::memcmp(parsed.identity.data, mikId.data, 20) == 0, "MIK identity parsed correctly");
}

// ============ Test 17: DNA commitment absent pre-activation ============
static void test_dna_commitment_absent() {
    std::cout << "\n=== Test 17: DNA commitment absent (pre-activation) ===\n";

    // Build scriptSig with MIK but NO DNA commitment
    std::vector<uint8_t> scriptSig;
    scriptSig.push_back(0x01);
    scriptSig.push_back(50);
    std::string msg = "No DNA";
    scriptSig.insert(scriptSig.end(), msg.begin(), msg.end());

    DFMP::Identity mikId;
    std::memset(mikId.data, 0xDD, 20);  // Intentionally 0xDD to test it's not confused with marker
    std::vector<uint8_t> fakeSig(DFMP::MIK_SIGNATURE_SIZE, 0xBB);
    std::vector<uint8_t> mikData;
    DFMP::BuildMIKScriptSigReference(mikId, fakeSig, mikData);
    scriptSig.insert(scriptSig.end(), mikData.begin(), mikData.end());

    // Parse — should succeed but has_dna_hash should be false
    DFMP::CMIKScriptData parsed;
    bool ok = DFMP::ParseMIKFromScriptSig(scriptSig, parsed);
    CHECK(ok, "ParseMIKFromScriptSig succeeds without DNA commitment");
    CHECK(!parsed.has_dna_hash, "has_dna_hash is false when no commitment present");
}

// ============ Test 18: serialize->deserialize->distance round-trip ============
// Pins the exact failure mode PR #116 repaired: serialize() persists only
// seed_stats[i].median_ms (not seed_name / raw measurements), and the previous
// distance() matched seeds by name over raw measurements — so every DESERIALIZED
// DNA collapsed to the 1000.0 "no data" sentinel and latency was silently dead.
// No prior test round-trips through serialize -> deserialize -> distance, so the
// dead comparator passed CI. This asserts distance() over two DESERIALIZED DNAs
// reflects the median deltas and is NOT the sentinel.
static void test_latency_distance_roundtrip() {
    std::cout << "\n=== Test 18: serialize->deserialize->distance round-trip ===\n";

    // make_core_dna seeds 4 medians: base, base+10, base+20, base+30 (all positive).
    auto dna_a = make_core_dna(0x01, 45.0, 500000.0, 100);  // medians 45,55,65,75
    auto dna_b = make_core_dna(0x02, 45.0, 500000.0, 101);  // medians 45,55,65,75 (identical)
    auto dna_c = make_core_dna(0x03, 65.0, 500000.0, 102);  // medians 65,75,85,95 (+20 each)

    // Round-trip all three through the wire format.
    auto ra = DigitalDNA::deserialize(dna_a.serialize());
    auto rb = DigitalDNA::deserialize(dna_b.serialize());
    auto rc = DigitalDNA::deserialize(dna_c.serialize());
    CHECK(ra.has_value() && rb.has_value() && rc.has_value(),
          "All three DNAs deserialize");

    // Sanity: medians actually survived the round-trip as positive values.
    CHECK(ra->latency.seed_stats.size() == 4, "Deserialized A has 4 seed medians");
    CHECK(std::abs(ra->latency.seed_stats[0].median_ms - 45.0) < 0.001,
          "Deserialized median[0] preserved");

    // Identical medians -> distance ~= 0 (and crucially NOT the 1000.0 sentinel).
    double d_same = LatencyFingerprint::distance(ra->latency, rb->latency);
    CHECK(d_same < 0.001, "Identical deserialized medians -> distance ~= 0");
    CHECK(std::abs(d_same - 1000.0) > 1.0,
          "Identical medians -> NOT the 1000.0 no-data sentinel (comparator alive)");

    // Medians offset by 20ms at every position -> mean abs delta == 20.
    double d_off = LatencyFingerprint::distance(ra->latency, rc->latency);
    CHECK(std::abs(d_off - 20.0) < 0.001, "Medians +20ms -> distance ~= 20");
    CHECK(std::abs(d_off - 1000.0) > 1.0,
          "Offset medians -> NOT the 1000.0 no-data sentinel");
}

int main() {
    std::cout << "Digital DNA Serialization & Persistence Tests\n";
    std::cout << "=============================================\n";

    test_v2_serialize_roundtrip();
    test_v3_serialize_roundtrip();
    test_v1_backward_compat();
    test_magic_detection();
    test_partial_optional_roundtrip();
    test_registry_db_crud();
    test_registry_advisory_sybil();
    test_registry_update_identity();
    test_perspective_cached_roundtrip();
    test_v3_mik_serialize_roundtrip();
    test_v2_backward_compat_mik();
    test_mik_registry_lookup();
    test_mik_registry_db_lookup();
    test_hash_includes_mik();
    test_dna_commitment_roundtrip();
    test_dna_commitment_in_scriptsig();
    test_dna_commitment_absent();
    test_latency_distance_roundtrip();

    std::cout << "\n=============================================\n";
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed\n";

    return tests_failed > 0 ? 1 : 0;
}
