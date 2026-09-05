#ifndef DILITHION_LATENCY_FINGERPRINT_H
#define DILITHION_LATENCY_FINGERPRINT_H

#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <cstdint>

namespace digital_dna {

// Seed node configuration
struct SeedNode {
    std::string name;
    std::string ip;
    uint16_t port;
};

// Latency statistics for one seed node
struct LatencyStats {
    std::string seed_name;
    double median_ms = 0.0;
    double p10_ms = 0.0;
    double p90_ms = 0.0;
    double mean_ms = 0.0;
    double stddev_ms = 0.0;
    uint32_t samples = 0;
    uint32_t failures = 0;

    // Raw measurements for analysis
    std::vector<double> measurements;
};

// Complete latency fingerprint
struct LatencyFingerprint {
    std::vector<LatencyStats> seed_stats;   // Variable-size for decentralized latency (future)
    uint64_t measurement_timestamp;
    uint32_t measurement_height;  // Block height when measured

    // Serialization
    std::string to_json() const;
    static LatencyFingerprint from_json(const std::string& json);

    // Comparison
    static double distance(const LatencyFingerprint& a, const LatencyFingerprint& b);
    static double wasserstein_distance(const std::vector<double>& a, const std::vector<double>& b);
};

// Fingerprint collector
class LatencyFingerprintCollector {
public:
    LatencyFingerprintCollector();
    ~LatencyFingerprintCollector();

    // Configuration
    void set_samples_per_seed(uint32_t samples) { samples_per_seed_ = samples; }
    void set_timeout_ms(uint32_t timeout) { timeout_ms_ = timeout; }

    // Collection
    LatencyFingerprint collect();
    LatencyStats measure_seed(const SeedNode& seed);

    // Individual RTT measurement
    double measure_rtt(const std::string& ip, uint16_t port);

private:
    uint32_t samples_per_seed_ = 100;
    uint32_t timeout_ms_ = 5000;

    // Statistical helpers
    static double compute_median(std::vector<double>& values);
    static double compute_percentile(std::vector<double>& values, double p);
    static double compute_mean(const std::vector<double>& values);
    static double compute_stddev(const std::vector<double>& values, double mean);
};

// Default mainnet seed nodes.
// APPEND-ONLY CONSTRAINT: LatencyFingerprint::distance() compares per-seed medians
// POSITIONALLY (index i in one fingerprint vs index i in another). These ordered seed
// lists are what the collector probes, so the list must only ever grow — never remove
// or reorder an entry — or cross-version fingerprint comparisons would silently compare
// different cities (e.g. London-vs-Singapore) and produce meaningless distances.
const std::array<SeedNode, 4> MAINNET_SEEDS = {{
    {"NYC", "138.197.68.128", 8444},
    {"London", "167.172.56.119", 8444},
    {"Singapore", "165.22.103.114", 8444},
    {"Sydney", "134.199.159.83", 8444}
}};

// Testnet seed nodes
const std::array<SeedNode, 3> TESTNET_SEEDS = {{
    {"NYC", "134.122.4.164", 18444},
    {"Singapore", "188.166.255.63", 18444},
    {"London", "209.97.177.197", 18444}
}};

} // namespace digital_dna

#endif // DILITHION_LATENCY_FINGERPRINT_H
