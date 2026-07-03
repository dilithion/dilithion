#include "clock_drift.h"
#include "dna_serialize.h"  // WF-1: explicit-LE consensus serialization helpers

#include <algorithm>
#include <cmath>
#include <cstring>
#include <chrono>
#include <numeric>
#include <set>
#include <sstream>
#include <iomanip>

namespace digital_dna {

// NOTE: TimeSyncMessage::serialize()/deserialize() (and the struct) were removed
// as dead code — the live MSG_DNA_TIME_SYNC wire is handled by
// CreateDNATimeSyncMessage / ProcessDNATimeSyncMessage in net.cpp (CDataStream, LE).

// --- ClockDriftCollector ---

ClockDriftCollector::ClockDriftCollector() {}

void ClockDriftCollector::record_exchange(
    const std::array<uint8_t, 20>& peer_id,
    uint64_t local_send_us,
    uint64_t peer_timestamp_us,
    uint64_t local_recv_us)
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (start_time_ms_ == 0) start_time_ms_ = now_ms;

    // Estimate one-way delay and clock offset
    // Using Cristian's algorithm: offset = peer_time - (send + recv) / 2
    uint64_t local_midpoint = (local_send_us + local_recv_us) / 2;
    int64_t offset = static_cast<int64_t>(peer_timestamp_us) - static_cast<int64_t>(local_midpoint);

    ClockDriftSample sample;
    sample.reference_peer = peer_id;
    sample.offset_us = offset;
    sample.local_timestamp_us = local_midpoint;
    sample.wall_timestamp_ms = static_cast<uint64_t>(now_ms);

    if (samples_.size() < MAX_SAMPLES) {
        samples_.push_back(sample);
    }
}

bool ClockDriftCollector::is_ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (samples_.size() < ClockDriftFingerprint::MIN_SAMPLES) return false;
    if (samples_.empty()) return false;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    return (static_cast<uint64_t>(now_ms) - start_time_ms_) >= ClockDriftFingerprint::MIN_OBSERVATION_MS;
}

size_t ClockDriftCollector::sample_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return samples_.size();
}

void ClockDriftCollector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
    start_time_ms_ = 0;
}

ClockDriftCollector::RegressionResult ClockDriftCollector::compute_regression() const {
    RegressionResult result{0.0, 0.0, 0.0, 0.0};

    if (samples_.size() < 2) return result;

    // Linear regression: offset_us = slope * local_timestamp_us + intercept
    // X = local_timestamp_us (relative to first sample)
    // Y = offset_us

    uint64_t t0 = samples_.front().local_timestamp_us;
    size_t n = samples_.size();

    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_xx = 0;
    for (const auto& s : samples_) {
        double x = static_cast<double>(s.local_timestamp_us - t0);
        double y = static_cast<double>(s.offset_us);
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_xx += x * x;
    }

    double denom = n * sum_xx - sum_x * sum_x;
    if (std::abs(denom) < 1e-20) return result;

    result.slope = (n * sum_xy - sum_x * sum_y) / denom;
    result.intercept = (sum_y - result.slope * sum_x) / n;

    // R-squared and residual RMS
    double mean_y = sum_y / n;
    double ss_tot = 0, ss_res = 0;
    for (const auto& s : samples_) {
        double x = static_cast<double>(s.local_timestamp_us - t0);
        double y = static_cast<double>(s.offset_us);
        double predicted = result.slope * x + result.intercept;
        double residual = y - predicted;
        ss_res += residual * residual;
        ss_tot += (y - mean_y) * (y - mean_y);
    }

    result.r_squared = (ss_tot > 1e-20) ? 1.0 - ss_res / ss_tot : 0.0;
    result.residual_rms = std::sqrt(ss_res / n);

    return result;
}

ClockDriftFingerprint ClockDriftCollector::get_fingerprint() const {
    std::lock_guard<std::mutex> lock(mutex_);

    ClockDriftFingerprint fp;
    fp.samples = samples_;
    fp.num_samples = static_cast<uint32_t>(samples_.size());
    fp.observation_start = start_time_ms_;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    fp.observation_end = static_cast<uint64_t>(now_ms);

    // Count unique peers
    std::set<std::array<uint8_t, 20>> peers;
    for (const auto& s : samples_) {
        peers.insert(s.reference_peer);
    }
    fp.num_reference_peers = static_cast<uint32_t>(peers.size());

    // Compute linear regression
    auto reg = compute_regression();

    // Drift rate: slope is in us/us, convert to ppm (parts per million)
    fp.drift_rate_ppm = reg.slope * 1e6;

    // Jitter signature: RMS of offset residuals after linear fit
    fp.jitter_signature = reg.residual_rms;

    // Drift stability: compute drift rate over first half vs second half
    if (samples_.size() >= 10) {
        size_t mid = samples_.size() / 2;

        // First half regression
        auto first_half = samples_;
        first_half.resize(mid);
        // Simplified: compute mean offset rate for each half
        double sum1 = 0, sum2 = 0;
        uint64_t t0 = samples_.front().local_timestamp_us;
        for (size_t i = 0; i < mid; i++) {
            double dt = static_cast<double>(samples_[i].local_timestamp_us - t0);
            if (dt > 0) sum1 += samples_[i].offset_us / dt;
        }
        for (size_t i = mid; i < samples_.size(); i++) {
            double dt = static_cast<double>(samples_[i].local_timestamp_us - t0);
            if (dt > 0) sum2 += samples_[i].offset_us / dt;
        }
        // offset_us / elapsed_us already gives drift in us/us (= ppm), no 1e6 needed
        double rate1 = (mid > 0) ? sum1 / mid : 0;
        double rate2 = (samples_.size() - mid > 0) ? sum2 / (samples_.size() - mid) : 0;
        fp.drift_stability = std::abs(rate1 - rate2);
    }

    return fp;
}

// --- ClockDriftFingerprint ---

double ClockDriftFingerprint::similarity(const ClockDriftFingerprint& a, const ClockDriftFingerprint& b) {
    if (!a.is_reliable() || !b.is_reliable()) return 0.0;

    // 1. Drift rate similarity (most distinctive)
    // Two machines with drift within 0.1 ppm = likely same oscillator
    double rate_diff = std::abs(a.drift_rate_ppm - b.drift_rate_ppm);
    double rate_sim = std::exp(-rate_diff / 0.5);  // 0.5 ppm half-life

    // 2. Jitter signature similarity
    double max_jitter = std::max(a.jitter_signature, b.jitter_signature);
    double jitter_sim = (max_jitter > 1e-6) ?
        1.0 - std::abs(a.jitter_signature - b.jitter_signature) / max_jitter :
        1.0;
    jitter_sim = std::max(0.0, jitter_sim);

    // 3. Stability similarity
    double max_stab = std::max(a.drift_stability, b.drift_stability);
    double stab_sim = (max_stab > 1e-6) ?
        1.0 - std::abs(a.drift_stability - b.drift_stability) / max_stab :
        1.0;
    stab_sim = std::max(0.0, stab_sim);

    // Weighted: drift rate is primary signal
    return 0.60 * rate_sim +
           0.25 * jitter_sim +
           0.15 * stab_sim;
}

std::string ClockDriftFingerprint::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(6);

    oss << "{\n";
    oss << "  \"drift_rate_ppm\": " << drift_rate_ppm << ",\n";
    oss << "  \"drift_stability\": " << drift_stability << ",\n";
    oss << "  \"jitter_signature\": " << jitter_signature << ",\n";
    oss << "  \"num_samples\": " << num_samples << ",\n";
    oss << "  \"num_reference_peers\": " << num_reference_peers << ",\n";
    oss << "  \"observation_start\": " << observation_start << ",\n";
    oss << "  \"observation_end\": " << observation_end << ",\n";
    oss << "  \"is_reliable\": " << (is_reliable() ? "true" : "false") << "\n";
    oss << "}\n";

    return oss.str();
}

std::vector<uint8_t> ClockDriftFingerprint::serialize() const {
    // Serialize derived metrics only (not raw samples)
    // 3 doubles (24) + 2 uint64 (16) + 2 uint32 (8) = 48 bytes
    // WF-1: explicit little-endian (byte-identical on LE hosts to the previous
    // memcpy copies; portable across architectures).
    std::vector<uint8_t> data(48);
    size_t offset = 0;

    dna_le::set_double(data.data() + offset, drift_rate_ppm); offset += 8;
    dna_le::set_double(data.data() + offset, drift_stability); offset += 8;
    dna_le::set_double(data.data() + offset, jitter_signature); offset += 8;
    dna_le::set_u64(data.data() + offset, observation_start); offset += 8;
    dna_le::set_u64(data.data() + offset, observation_end); offset += 8;
    dna_le::set_u32(data.data() + offset, num_reference_peers); offset += 4;
    dna_le::set_u32(data.data() + offset, num_samples); offset += 4;

    return data;
}

ClockDriftFingerprint ClockDriftFingerprint::deserialize(const std::vector<uint8_t>& data) {
    ClockDriftFingerprint fp;
    if (data.size() < 48) return fp;

    // WF-1: explicit little-endian reads, matched to serialize() above.
    size_t offset = 0;
    fp.drift_rate_ppm = dna_le::get_double(data.data() + offset); offset += 8;
    fp.drift_stability = dna_le::get_double(data.data() + offset); offset += 8;
    fp.jitter_signature = dna_le::get_double(data.data() + offset); offset += 8;
    fp.observation_start = dna_le::get_u64(data.data() + offset); offset += 8;
    fp.observation_end = dna_le::get_u64(data.data() + offset); offset += 8;
    fp.num_reference_peers = dna_le::get_u32(data.data() + offset); offset += 4;
    fp.num_samples = dna_le::get_u32(data.data() + offset); offset += 4;

    return fp;
}

} // namespace digital_dna
