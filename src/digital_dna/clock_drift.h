#ifndef DILITHION_CLOCK_DRIFT_H
#define DILITHION_CLOCK_DRIFT_H

/**
 * Clock Drift Fingerprinting (5th Dimension)
 *
 * Every computer's quartz crystal oscillator drifts uniquely due to
 * manufacturing imprecision. By measuring clock drift relative to peers
 * over the observation window, we add a dimension that is:
 * - Orthogonal to all existing dimensions
 * - Stable over weeks
 * - Trivially detects co-located VMs (shared physical oscillator)
 *
 * Measurement: Exchange timestamps with connected peers periodically,
 * compute linear regression of offset vs. time = drift rate (ppm).
 */

#include <array>
#include <vector>
#include <cstdint>
#include <string>
#include <mutex>

namespace digital_dna {

struct ClockDriftSample {
    std::array<uint8_t, 20> reference_peer;   // Who we compared against
    int64_t offset_us;                         // Our clock offset from peer (microseconds)
    uint64_t local_timestamp_us;               // Our local monotonic timestamp
    uint64_t wall_timestamp_ms;                // Wall clock when sampled
};

struct ClockDriftFingerprint {
    // Raw samples (kept for analysis, not transmitted in full)
    std::vector<ClockDriftSample> samples;

    // Derived metrics (the actual fingerprint)
    double drift_rate_ppm = 0.0;        // Parts per million drift relative to peers
    double drift_stability = 0.0;       // Std dev of drift rate over time (lower = more stable)
    double jitter_signature = 0.0;      // RMS of offset residuals after linear fit (characteristic jitter)

    // Measurement metadata
    uint64_t observation_start = 0;
    uint64_t observation_end = 0;
    uint32_t num_reference_peers = 0;
    uint32_t num_samples = 0;

    // Minimum samples before fingerprint is considered reliable
    static constexpr uint32_t MIN_SAMPLES = 50;
    static constexpr uint64_t MIN_OBSERVATION_MS = 4 * 3600 * 1000ULL;  // 4 hours

    bool is_reliable() const {
        return num_samples >= MIN_SAMPLES &&
               (observation_end - observation_start) >= MIN_OBSERVATION_MS;
    }

    // Comparison
    static double similarity(const ClockDriftFingerprint& a, const ClockDriftFingerprint& b);

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static ClockDriftFingerprint deserialize(const std::vector<uint8_t>& data);
};

// NOTE: The TimeSyncMessage struct + its serialize()/deserialize() were removed
// as dead code. The live MSG_DNA_TIME_SYNC wire is produced/consumed by
// CreateDNATimeSyncMessage / ProcessDNATimeSyncMessage in net.cpp via CDataStream
// (little-endian); the struct was a separate, never-wired format used only by tests.

class ClockDriftCollector {
public:
    ClockDriftCollector();

    // Record an incoming time sync exchange
    // Call with local send time, local receive time, and peer's timestamp
    void record_exchange(
        const std::array<uint8_t, 20>& peer_id,
        uint64_t local_send_us,
        uint64_t peer_timestamp_us,
        uint64_t local_recv_us);

    // Get current fingerprint (computes linear regression over samples)
    ClockDriftFingerprint get_fingerprint() const;

    // Check if we have enough samples
    bool is_ready() const;

    // Reset collection
    void reset();

    // Number of samples collected
    size_t sample_count() const;

private:
    mutable std::mutex mutex_;
    std::vector<ClockDriftSample> samples_;
    uint64_t start_time_ms_ = 0;
    static constexpr size_t MAX_SAMPLES = 10000;

    // Linear regression: offset_us = drift_rate * elapsed_us + intercept
    struct RegressionResult {
        double slope;       // drift rate (us per us, multiply by 1e6 for ppm)
        double intercept;
        double r_squared;
        double residual_rms;  // RMS of residuals (jitter signature)
    };

    RegressionResult compute_regression() const;
};

} // namespace digital_dna

#endif // DILITHION_CLOCK_DRIFT_H
