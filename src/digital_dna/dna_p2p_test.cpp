// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Digital DNA P2P Protocol Tests
 *
 * Tests for clock drift + bandwidth measurement protocol messages,
 * rate limiting, and nonce validation.
 */

#include "clock_drift.h"
#include "bandwidth_proof.h"

#include <iostream>
#include <cassert>
#include <cstring>
#include <array>
#include <chrono>
#include <thread>

using namespace digital_dna;

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { \
        std::cout << "  [PASS] " << msg << std::endl; \
        g_passed++; \
    } else { \
        std::cout << "  [FAIL] " << msg << std::endl; \
        g_failed++; \
    } \
} while(0)

// NOTE: former "Test 1: TimeSyncMessage serialize/deserialize roundtrip" removed —
// the TimeSyncMessage struct + its serialize()/deserialize() were dead code (the
// live MSG_DNA_TIME_SYNC wire is the net.cpp CDataStream path) and have been deleted.

// =================================================================
// Test 2: BandwidthFingerprint serialize/deserialize roundtrip
// =================================================================
void test_bandwidth_roundtrip() {
    std::cout << "\n=== Test 2: BandwidthFingerprint serialize/deserialize ===" << std::endl;

    BandwidthFingerprint fp;
    fp.median_upload_mbps = 50.5;
    fp.median_download_mbps = 100.25;
    fp.median_asymmetry = 0.503;
    fp.bandwidth_stability = 2.1;

    auto data = fp.serialize();
    CHECK(data.size() > 0, "BandwidthFingerprint serializes to non-empty");

    auto decoded = BandwidthFingerprint::deserialize(data);
    CHECK(std::abs(decoded.median_upload_mbps - 50.5) < 0.001, "upload_mbps roundtrip");
    CHECK(std::abs(decoded.median_download_mbps - 100.25) < 0.001, "download_mbps roundtrip");
    CHECK(std::abs(decoded.median_asymmetry - 0.503) < 0.001, "asymmetry roundtrip");
    CHECK(std::abs(decoded.bandwidth_stability - 2.1) < 0.001, "stability roundtrip");
}

// =================================================================
// Test 3: ClockDriftCollector with simulated exchanges
// =================================================================
void test_clock_drift_from_exchanges() {
    std::cout << "\n=== Test 3: Clock drift from simulated exchanges ===" << std::endl;

    ClockDriftCollector collector;

    CHECK(!collector.is_ready(), "Not ready initially");
    CHECK(collector.sample_count() == 0, "Zero samples initially");

    // Simulate 60 exchanges with slight drift (10 ppm)
    std::array<uint8_t, 20> peer{};
    peer[0] = 0x42;

    for (int i = 0; i < 60; i++) {
        uint64_t local_send = 1000000ULL + i * 300000000ULL;   // 300ms intervals
        uint64_t peer_ts = local_send + 10 * i;  // 10us drift per interval (~10ppm relative)
        uint64_t local_recv = local_send + 50000;  // 50ms RTT

        collector.record_exchange(peer, local_send, peer_ts, local_recv);
    }

    CHECK(collector.sample_count() == 60, "60 samples recorded");
    // Note: is_ready() also requires MIN_OBSERVATION_MS (4 hours)
    // In simulation we have only ~18s of elapsed time, so it won't be "ready"
    // but we can still get a fingerprint

    auto fp = collector.get_fingerprint();
    CHECK(fp.num_samples == 60, "Fingerprint has 60 samples");
    CHECK(fp.num_reference_peers >= 1, "At least 1 reference peer");
    // The drift rate should be computable (non-NaN)
    CHECK(fp.drift_rate_ppm == fp.drift_rate_ppm, "Drift rate is not NaN");
}

// =================================================================
// Test 4: BandwidthProofCollector measurements
// =================================================================
void test_bandwidth_from_measurements() {
    std::cout << "\n=== Test 4: Bandwidth from measurements ===" << std::endl;

    BandwidthProofCollector collector;

    CHECK(!collector.is_ready(), "Not ready initially");

    // Add 5 measurements
    for (int i = 0; i < 5; i++) {
        BandwidthMeasurement m;
        m.peer_id[0] = static_cast<uint8_t>(i);
        m.upload_mbps = 45.0 + i;
        m.download_mbps = 90.0 + i * 2;
        m.asymmetry_ratio = m.upload_mbps / m.download_mbps;
        m.timestamp = 1700000000000ULL + i * 900000;
        collector.record_measurement(m);
    }

    CHECK(collector.is_ready(), "Ready after 5 measurements (>= MIN_MEASUREMENTS=3)");

    auto fp = collector.get_fingerprint();
    CHECK(fp.measurements.size() == 5, "5 measurements stored");
    // Derived metrics should be computed
    CHECK(fp.median_upload_mbps > 0.0, "Upload > 0");
    CHECK(fp.median_download_mbps > 0.0, "Download > 0");
    CHECK(fp.median_asymmetry > 0.0, "Asymmetry > 0");
}

// =================================================================
// Test 5: Throughput computation
// =================================================================
void test_throughput_computation() {
    std::cout << "\n=== Test 5: Throughput computation ===" << std::endl;

    // 1 MB in 100ms = 10 MB/s = 80 Mbps
    double mbps = BandwidthProofCollector::compute_throughput_mbps(1024 * 1024, 100);
    CHECK(std::abs(mbps - 80.0) < 5.0, "1MB in 100ms ~ 80 Mbps");

    // 256 KB in 50ms = ~40 Mbps
    double mbps2 = BandwidthProofCollector::compute_throughput_mbps(256 * 1024, 50);
    CHECK(mbps2 > 30.0 && mbps2 < 50.0, "256KB in 50ms ~ 40 Mbps");

    // Edge case: 0 ms elapsed
    double mbps3 = BandwidthProofCollector::compute_throughput_mbps(1024, 0);
    CHECK(mbps3 == 0.0 || mbps3 > 0.0, "Zero elapsed doesn't crash");
}

// =================================================================
// Test 6: ClockDriftFingerprint serialize/deserialize
// =================================================================
void test_clock_drift_fingerprint_roundtrip() {
    std::cout << "\n=== Test 6: ClockDriftFingerprint serialize/deserialize ===" << std::endl;

    ClockDriftFingerprint fp;
    fp.drift_rate_ppm = 12.345;
    fp.drift_stability = 0.567;
    fp.jitter_signature = 89.012;
    fp.observation_start = 1000000;
    fp.observation_end = 2000000;
    fp.num_reference_peers = 5;
    fp.num_samples = 100;

    auto data = fp.serialize();
    CHECK(data.size() > 0, "Serialized to non-empty");

    auto decoded = ClockDriftFingerprint::deserialize(data);
    CHECK(std::abs(decoded.drift_rate_ppm - 12.345) < 0.001, "drift_rate_ppm roundtrip");
    CHECK(std::abs(decoded.drift_stability - 0.567) < 0.001, "drift_stability roundtrip");
    CHECK(std::abs(decoded.jitter_signature - 89.012) < 0.001, "jitter_signature roundtrip");
    CHECK(decoded.observation_start == 1000000, "observation_start roundtrip");
    CHECK(decoded.observation_end == 2000000, "observation_end roundtrip");
    CHECK(decoded.num_reference_peers == 5, "num_reference_peers roundtrip");
    CHECK(decoded.num_samples == 100, "num_samples roundtrip");
}

// =================================================================
// Test 7: Bandwidth throughput with realistic elapsed times
// Regression: previously used hardcoded elapsed_ms=1
// =================================================================
void test_bandwidth_realistic_elapsed() {
    std::cout << "\n=== Test 7: Bandwidth with realistic elapsed ===" << std::endl;

    // 256KB in 50ms (realistic for LAN) = ~40 Mbps
    double mbps_50 = BandwidthProofCollector::compute_throughput_mbps(256 * 1024, 50);
    CHECK(mbps_50 > 10.0 && mbps_50 < 200.0, "256KB/50ms gives sane bandwidth (10-200 Mbps)");

    // 1MB in 500ms (realistic for WAN) = ~16 Mbps
    double mbps_500 = BandwidthProofCollector::compute_throughput_mbps(1024 * 1024, 500);
    CHECK(mbps_500 > 5.0 && mbps_500 < 50.0, "1MB/500ms gives sane bandwidth (5-50 Mbps)");

    // Regression: elapsed_ms=1 gave absurdly high values
    double mbps_1 = BandwidthProofCollector::compute_throughput_mbps(1024 * 1024, 1);
    CHECK(mbps_1 > 1000.0, "1MB/1ms gives unrealistic bandwidth (>1 Gbps) — this is the bug case");

    // Sanity: elapsed=100 gives reasonable result
    double mbps_100 = BandwidthProofCollector::compute_throughput_mbps(1024 * 1024, 100);
    CHECK(mbps_100 > 50.0 && mbps_100 < 200.0, "1MB/100ms gives reasonable bandwidth");
}

int main() {
    std::cout << "Digital DNA P2P Protocol Tests" << std::endl;
    std::cout << "==============================" << std::endl;

    test_bandwidth_roundtrip();
    test_clock_drift_from_exchanges();
    test_bandwidth_from_measurements();
    test_throughput_computation();
    test_clock_drift_fingerprint_roundtrip();
    test_bandwidth_realistic_elapsed();

    std::cout << "\n==============================" << std::endl;
    std::cout << "Results: " << g_passed << " passed, " << g_failed << " failed" << std::endl;

    return g_failed > 0 ? 1 : 0;
}
