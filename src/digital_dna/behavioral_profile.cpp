#include "behavioral_profile.h"
#include "dna_serialize.h"  // WF-1: explicit-LE consensus serialization helpers

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace digital_dna {

BehavioralProfileCollector::BehavioralProfileCollector() {
    hourly_block_relays_.fill(0);
}

void BehavioralProfileCollector::on_block_relayed(uint64_t timestamp_ms, double relay_delay_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (start_time_ == 0) start_time_ = timestamp_ms;

    // Extract hour from timestamp (UTC)
    uint64_t sec = timestamp_ms / 1000;
    uint32_t hour = static_cast<uint32_t>((sec / 3600) % 24);
    hourly_block_relays_[hour]++;
    total_block_relays_++;

    // Record relay delay
    if (relay_delays_.size() < MAX_RELAY_SAMPLES) {
        relay_delays_.push_back(relay_delay_ms);
    } else {
        // Reservoir sampling: replace random element
        size_t idx = total_block_relays_ % MAX_RELAY_SAMPLES;
        relay_delays_[idx] = relay_delay_ms;
    }
}

void BehavioralProfileCollector::on_tx_relayed(uint64_t timestamp_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (start_time_ == 0) start_time_ = timestamp_ms;

    if (tx_timestamps_.size() < MAX_TX_TIMESTAMPS) {
        tx_timestamps_.push_back(timestamp_ms);
    }
}

void BehavioralProfileCollector::on_peer_connected(uint64_t timestamp_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (start_time_ == 0) start_time_ = timestamp_ms;
}

void BehavioralProfileCollector::on_peer_disconnected(uint64_t timestamp_ms, uint64_t session_duration_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    (void)timestamp_ms;

    if (peer_sessions_.size() < MAX_SESSION_SAMPLES) {
        peer_sessions_.push_back(static_cast<double>(session_duration_sec));
    }
}

void BehavioralProfileCollector::on_block_received(uint32_t block_height) {
    std::lock_guard<std::mutex> lock(mutex_);
    (void)block_height;
    blocks_observed_++;
}

BehavioralProfile BehavioralProfileCollector::get_profile() const {
    std::lock_guard<std::mutex> lock(mutex_);

    BehavioralProfile profile;
    profile.observation_blocks = blocks_observed_;
    profile.start_time = start_time_;

    // Current time estimate from last event
    uint64_t now_ms = 0;
    if (!tx_timestamps_.empty()) now_ms = tx_timestamps_.back();
    if (!relay_delays_.empty() && start_time_ > 0) {
        // Approximate current time
        now_ms = std::max(now_ms, start_time_);
    }
    profile.end_time = now_ms;

    // Hourly activity distribution (normalized)
    normalize_hourly(profile.hourly_activity);

    // Relay delay stats
    if (!relay_delays_.empty()) {
        double sum = std::accumulate(relay_delays_.begin(), relay_delays_.end(), 0.0);
        profile.mean_relay_delay_ms = sum / relay_delays_.size();

        double sq_sum = 0.0;
        for (double d : relay_delays_) {
            double diff = d - profile.mean_relay_delay_ms;
            sq_sum += diff * diff;
        }
        profile.relay_consistency = std::sqrt(sq_sum / relay_delays_.size());
    }

    // Peer session duration
    if (!peer_sessions_.empty()) {
        double sum = std::accumulate(peer_sessions_.begin(), peer_sessions_.end(), 0.0);
        profile.avg_peer_session_duration_sec = sum / peer_sessions_.size();
    }

    // Transaction relay rate (txs per hour)
    if (!tx_timestamps_.empty() && start_time_ > 0) {
        uint64_t duration_ms = now_ms > start_time_ ? now_ms - start_time_ : 1;
        double hours = duration_ms / 3600000.0;
        if (hours > 0.001) {
            profile.tx_relay_rate = tx_timestamps_.size() / hours;
        }
    }

    // Transaction timing entropy
    profile.tx_timing_entropy = compute_tx_entropy();

    return profile;
}

void BehavioralProfileCollector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    hourly_block_relays_.fill(0);
    total_block_relays_ = 0;
    relay_delays_.clear();
    peer_sessions_.clear();
    tx_timestamps_.clear();
    start_time_ = 0;
    blocks_observed_ = 0;
}

void BehavioralProfileCollector::normalize_hourly(std::array<double, 24>& out) const {
    double total = 0;
    for (uint32_t count : hourly_block_relays_) total += count;

    if (total < 1.0) {
        out.fill(1.0 / 24.0);  // Uniform if no data
        return;
    }

    for (size_t i = 0; i < 24; i++) {
        out[i] = hourly_block_relays_[i] / total;
    }
}

double BehavioralProfileCollector::compute_tx_entropy() const {
    if (tx_timestamps_.size() < 10) return 0.0;

    // Bucket timestamps into 24 hourly bins
    std::array<uint32_t, 24> bins{};
    for (uint64_t ts : tx_timestamps_) {
        uint32_t hour = static_cast<uint32_t>((ts / 3600000) % 24);
        bins[hour]++;
    }

    // Shannon entropy
    double total = static_cast<double>(tx_timestamps_.size());
    double entropy = 0.0;
    for (uint32_t count : bins) {
        if (count > 0) {
            double p = count / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;  // Max entropy = log2(24) ≈ 4.585 for perfectly uniform distribution
}

double BehavioralProfileCollector::cosine_similarity(const std::array<double, 24>& a,
                                                      const std::array<double, 24>& b) {
    double dot = 0.0, norm_a = 0.0, norm_b = 0.0;
    for (size_t i = 0; i < 24; i++) {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }

    double denom = std::sqrt(norm_a) * std::sqrt(norm_b);
    if (denom < 1e-10) return 0.0;

    return dot / denom;
}

double BehavioralProfileCollector::metric_similarity(double a, double b) {
    if (a < 1e-10 && b < 1e-10) return 1.0;
    double max_val = std::max(std::abs(a), std::abs(b));
    if (max_val < 1e-10) return 1.0;
    return 1.0 - std::abs(a - b) / max_val;
}

double BehavioralProfile::similarity(const BehavioralProfile& a, const BehavioralProfile& b) {
    // Weighted combination of sub-similarities

    // 1. Hourly activity cosine similarity (strongest signal — timezone proxy)
    double hourly_sim = BehavioralProfileCollector::cosine_similarity(a.hourly_activity, b.hourly_activity);

    // 2. Relay performance similarity
    double relay_sim = BehavioralProfileCollector::metric_similarity(
        a.mean_relay_delay_ms, b.mean_relay_delay_ms);

    // 3. Peer session duration similarity
    double session_sim = BehavioralProfileCollector::metric_similarity(
        a.avg_peer_session_duration_sec, b.avg_peer_session_duration_sec);

    // 4. Transaction pattern similarity
    double tx_rate_sim = BehavioralProfileCollector::metric_similarity(
        a.tx_relay_rate, b.tx_relay_rate);
    double tx_entropy_sim = BehavioralProfileCollector::metric_similarity(
        a.tx_timing_entropy, b.tx_timing_entropy);

    // Weights: hourly activity is strongest signal
    return 0.40 * hourly_sim +
           0.20 * relay_sim +
           0.15 * session_sim +
           0.15 * tx_rate_sim +
           0.10 * tx_entropy_sim;
}

std::string BehavioralProfile::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);

    oss << "{\n";
    oss << "  \"observation_blocks\": " << observation_blocks << ",\n";
    oss << "  \"is_mature\": " << (is_mature() ? "true" : "false") << ",\n";
    oss << "  \"start_time\": " << start_time << ",\n";
    oss << "  \"end_time\": " << end_time << ",\n";
    oss << "  \"mean_relay_delay_ms\": " << mean_relay_delay_ms << ",\n";
    oss << "  \"relay_consistency\": " << relay_consistency << ",\n";
    oss << "  \"avg_peer_session_sec\": " << avg_peer_session_duration_sec << ",\n";
    oss << "  \"peer_diversity\": " << peer_diversity_score << ",\n";
    oss << "  \"tx_relay_rate\": " << tx_relay_rate << ",\n";
    oss << "  \"tx_timing_entropy\": " << tx_timing_entropy << ",\n";

    oss << "  \"hourly_activity\": [";
    for (size_t i = 0; i < 24; i++) {
        oss << hourly_activity[i];
        if (i < 23) oss << ", ";
    }
    oss << "]\n";

    oss << "}\n";

    return oss.str();
}

std::vector<uint8_t> BehavioralProfile::serialize() const {
    // WF-1: explicit little-endian (byte-identical on LE hosts to the previous
    // reinterpret_cast copies; portable across architectures).
    std::vector<uint8_t> data;

    // hourly_activity: 24 * 8 = 192 bytes
    for (size_t i = 0; i < 24; i++) {
        dna_le::put_double(data, hourly_activity[i]);
    }

    // 6 doubles: 48 bytes
    dna_le::put_double(data, mean_relay_delay_ms);
    dna_le::put_double(data, relay_consistency);
    dna_le::put_double(data, avg_peer_session_duration_sec);
    dna_le::put_double(data, peer_diversity_score);
    dna_le::put_double(data, tx_relay_rate);
    dna_le::put_double(data, tx_timing_entropy);

    // Metadata: 4 + 8 + 8 = 20 bytes
    dna_le::put_u32(data, observation_blocks);
    dna_le::put_u64(data, start_time);
    dna_le::put_u64(data, end_time);

    // Total: 192 + 48 + 20 = 260 bytes
    return data;
}

BehavioralProfile BehavioralProfile::deserialize(const std::vector<uint8_t>& data) {
    BehavioralProfile profile;
    if (data.size() < 260) return profile;

    size_t offset = 0;

    // WF-1: explicit little-endian reads, matched to serialize() above.
    // hourly_activity: 192 bytes
    for (size_t i = 0; i < 24; i++) {
        profile.hourly_activity[i] = dna_le::get_double(data.data() + offset);
        offset += 8;
    }

    // 6 doubles: 48 bytes
    auto read_double = [&]() -> double {
        double v = dna_le::get_double(data.data() + offset);
        offset += 8;
        return v;
    };
    profile.mean_relay_delay_ms = read_double();
    profile.relay_consistency = read_double();
    profile.avg_peer_session_duration_sec = read_double();
    profile.peer_diversity_score = read_double();
    profile.tx_relay_rate = read_double();
    profile.tx_timing_entropy = read_double();

    // Metadata
    profile.observation_blocks = dna_le::get_u32(data.data() + offset); offset += 4;
    profile.start_time = dna_le::get_u64(data.data() + offset); offset += 8;
    profile.end_time = dna_le::get_u64(data.data() + offset); offset += 8;

    return profile;
}

} // namespace digital_dna
