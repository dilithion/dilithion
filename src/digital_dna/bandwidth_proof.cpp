#include "bandwidth_proof.h"
#include "dna_serialize.h"  // WF-1: explicit-LE consensus serialization helpers

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace digital_dna {

BandwidthProofCollector::BandwidthProofCollector(const BandwidthTestConfig& config)
    : config_(config) {}

void BandwidthProofCollector::record_measurement(const BandwidthMeasurement& measurement) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (measurements_.size() < MAX_MEASUREMENTS) {
        measurements_.push_back(measurement);
    }
}

double BandwidthProofCollector::compute_throughput_mbps(uint32_t payload_bytes, uint64_t elapsed_ms) {
    if (elapsed_ms == 0) return 0.0;
    // bytes -> megabits: bytes * 8 / 1000000
    // per second: / (elapsed_ms / 1000)
    return (static_cast<double>(payload_bytes) * 8.0 / 1000000.0) / (elapsed_ms / 1000.0);
}

BandwidthFingerprint BandwidthProofCollector::get_fingerprint() const {
    std::lock_guard<std::mutex> lock(mutex_);

    BandwidthFingerprint fp;
    fp.measurements = measurements_;
    fp.compute_derived();
    return fp;
}

bool BandwidthProofCollector::is_ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return measurements_.size() >= config_.min_peers;
}

void BandwidthProofCollector::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    measurements_.clear();
}

// --- BandwidthFingerprint ---

static double compute_median_double(std::vector<double> values) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    size_t n = values.size();
    if (n % 2 == 0) return (values[n/2 - 1] + values[n/2]) / 2.0;
    return values[n/2];
}

void BandwidthFingerprint::compute_derived() {
    if (measurements.empty()) return;

    std::vector<double> uploads, downloads, asymmetries;
    for (const auto& m : measurements) {
        uploads.push_back(m.upload_mbps);
        downloads.push_back(m.download_mbps);
        if (m.download_mbps > 0.01) {
            asymmetries.push_back(m.upload_mbps / m.download_mbps);
        }
    }

    median_upload_mbps = compute_median_double(uploads);
    median_download_mbps = compute_median_double(downloads);
    median_asymmetry = asymmetries.empty() ? 0.0 : compute_median_double(asymmetries);

    // Bandwidth stability: coefficient of variation of download speeds
    if (downloads.size() >= 2) {
        double mean = std::accumulate(downloads.begin(), downloads.end(), 0.0) / downloads.size();
        double sq_sum = 0.0;
        for (double d : downloads) {
            double diff = d - mean;
            sq_sum += diff * diff;
        }
        double stddev = std::sqrt(sq_sum / downloads.size());
        bandwidth_stability = (mean > 0.01) ? stddev / mean : 0.0;  // CoV
    }
}

double BandwidthFingerprint::similarity(const BandwidthFingerprint& a, const BandwidthFingerprint& b) {
    if (!a.is_reliable() || !b.is_reliable()) return 0.0;

    // 1. Upload throughput similarity (log-scale for wide range)
    double up_sim = 0.0;
    if (a.median_upload_mbps > 0.01 && b.median_upload_mbps > 0.01) {
        double log_diff = std::abs(std::log(a.median_upload_mbps) - std::log(b.median_upload_mbps));
        up_sim = std::exp(-log_diff / 0.5);  // Half-life at ~65% difference
    }

    // 2. Download throughput similarity (log-scale)
    double down_sim = 0.0;
    if (a.median_download_mbps > 0.01 && b.median_download_mbps > 0.01) {
        double log_diff = std::abs(std::log(a.median_download_mbps) - std::log(b.median_download_mbps));
        down_sim = std::exp(-log_diff / 0.5);
    }

    // 3. Asymmetry ratio similarity (distinguishes home vs datacenter)
    double asym_sim = 1.0 - std::abs(a.median_asymmetry - b.median_asymmetry);
    asym_sim = std::max(0.0, asym_sim);

    // 4. Stability similarity (cloud = stable, home = variable)
    double max_stab = std::max(a.bandwidth_stability, b.bandwidth_stability);
    double stab_sim = (max_stab > 0.01) ?
        1.0 - std::abs(a.bandwidth_stability - b.bandwidth_stability) / max_stab :
        1.0;
    stab_sim = std::max(0.0, stab_sim);

    // Asymmetry is the strongest distinguisher
    return 0.25 * up_sim +
           0.25 * down_sim +
           0.30 * asym_sim +
           0.20 * stab_sim;
}

std::string BandwidthFingerprint::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";
    oss << "  \"median_upload_mbps\": " << median_upload_mbps << ",\n";
    oss << "  \"median_download_mbps\": " << median_download_mbps << ",\n";
    oss << "  \"median_asymmetry\": " << std::setprecision(4) << median_asymmetry << ",\n";
    oss << "  \"bandwidth_stability\": " << bandwidth_stability << ",\n";
    oss << "  \"num_measurements\": " << measurements.size() << ",\n";
    oss << "  \"is_reliable\": " << (is_reliable() ? "true" : "false") << "\n";
    oss << "}\n";

    return oss.str();
}

std::vector<uint8_t> BandwidthFingerprint::serialize() const {
    // Derived metrics only: 4 doubles (32 bytes) + measurement count (4 bytes)
    // WF-1: explicit little-endian (byte-identical on LE hosts to the previous
    // memcpy copies; portable across architectures).
    std::vector<uint8_t> data(36);
    size_t offset = 0;

    dna_le::set_double(data.data() + offset, median_upload_mbps); offset += 8;
    dna_le::set_double(data.data() + offset, median_download_mbps); offset += 8;
    dna_le::set_double(data.data() + offset, median_asymmetry); offset += 8;
    dna_le::set_double(data.data() + offset, bandwidth_stability); offset += 8;
    uint32_t count = static_cast<uint32_t>(measurements.size());
    dna_le::set_u32(data.data() + offset, count); offset += 4;

    return data;
}

BandwidthFingerprint BandwidthFingerprint::deserialize(const std::vector<uint8_t>& data) {
    BandwidthFingerprint fp;
    if (data.size() < 36) return fp;

    // WF-1: explicit little-endian reads, matched to serialize() above.
    size_t offset = 0;
    fp.median_upload_mbps = dna_le::get_double(data.data() + offset); offset += 8;
    fp.median_download_mbps = dna_le::get_double(data.data() + offset); offset += 8;
    fp.median_asymmetry = dna_le::get_double(data.data() + offset); offset += 8;
    fp.bandwidth_stability = dna_le::get_double(data.data() + offset); offset += 8;
    // measurement count is informational only (no raw measurements in serialized form)

    return fp;
}

} // namespace digital_dna
