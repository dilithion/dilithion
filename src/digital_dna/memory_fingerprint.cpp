#include "memory_fingerprint.h"
#include "dna_serialize.h"  // WF-1: explicit-LE consensus serialization helpers

#include <algorithm>
#include <cmath>
#include <cstring>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <numeric>

namespace digital_dna {

// Probe sizes: 4KB to 64MB in powers of 2
const std::vector<uint32_t> MemoryFingerprintCollector::PROBE_SIZES = {
    4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048,
    4096, 8192, 16384, 32768, 65536
};

MemoryProbeResult MemoryFingerprintCollector::probe_random_access(uint32_t working_set_kb, uint32_t iterations) {
    MemoryProbeResult result;
    result.working_set_kb = working_set_kb;
    result.access_time_ns = 0.0;
    result.bandwidth_mbps = 0.0;

    size_t size_bytes = static_cast<size_t>(working_set_kb) * 1024;
    size_t num_entries = size_bytes / sizeof(uint32_t);
    if (num_entries < 2) {
        return result;
    }

    // Allocate buffer
    std::vector<uint32_t> buffer(num_entries);

    // Initialize with pointer-chase pattern (random permutation)
    // Each entry points to the next random index, forming a single cycle
    // This defeats hardware prefetchers
    std::vector<uint32_t> indices(num_entries);
    std::iota(indices.begin(), indices.end(), 0);

    std::mt19937 rng(working_set_kb);  // Deterministic seed per size
    for (size_t i = num_entries - 1; i > 0; i--) {
        std::uniform_int_distribution<size_t> dist(0, i);
        size_t j = dist(rng);
        std::swap(indices[i], indices[j]);
    }

    // Build pointer-chase: buffer[indices[i]] = indices[i+1]
    for (size_t i = 0; i < num_entries - 1; i++) {
        buffer[indices[i]] = indices[i + 1];
    }
    buffer[indices[num_entries - 1]] = indices[0];  // Close the cycle

    // Warmup: traverse half the chain
    uint32_t idx = indices[0];
    for (uint32_t i = 0; i < iterations / 4; i++) {
        idx = buffer[idx];
    }

    // Timed pointer-chase traversal
    auto start = std::chrono::high_resolution_clock::now();

    for (uint32_t i = 0; i < iterations; i++) {
        idx = buffer[idx];
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    // Prevent compiler from optimizing away the loop
    volatile uint32_t sink = idx;
    (void)sink;

    result.access_time_ns = static_cast<double>(elapsed_ns) / iterations;
    result.bandwidth_mbps = probe_bandwidth(working_set_kb);

    return result;
}

double MemoryFingerprintCollector::probe_bandwidth(uint32_t working_set_kb) {
    size_t size_bytes = static_cast<size_t>(working_set_kb) * 1024;
    if (size_bytes < 64) return 0.0;

    // Allocate and fill buffer
    std::vector<uint8_t> buffer(size_bytes, 0xAB);

    // Sequential read pass (measures bandwidth)
    volatile uint64_t sum = 0;
    uint32_t passes = std::max(1u, 256 * 1024 / working_set_kb);  // Scale passes to ~256MB total

    auto start = std::chrono::high_resolution_clock::now();

    for (uint32_t p = 0; p < passes; p++) {
        const uint64_t* ptr = reinterpret_cast<const uint64_t*>(buffer.data());
        size_t count = size_bytes / sizeof(uint64_t);
        for (size_t i = 0; i < count; i++) {
            sum += ptr[i];
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    // Prevent optimization
    (void)sum;

    double total_bytes = static_cast<double>(size_bytes) * passes;
    double elapsed_sec = elapsed_ns / 1e9;
    if (elapsed_sec < 1e-9) return 0.0;

    return (total_bytes / (1024.0 * 1024.0)) / elapsed_sec;  // MB/s
}

void MemoryFingerprintCollector::detect_cache_boundaries(MemoryFingerprint& fp) {
    if (fp.access_curve.size() < 3) return;

    // Find inflection points where access time increases sharply
    // A "jump" is when the ratio of consecutive access times exceeds a threshold
    static constexpr double JUMP_THRESHOLD = 1.5;  // 50% increase

    double max_bw = 0.0;
    for (const auto& probe : fp.access_curve) {
        if (probe.bandwidth_mbps > max_bw) {
            max_bw = probe.bandwidth_mbps;
        }
    }
    fp.peak_bandwidth_mbps = max_bw;

    // Detect L1/L2/L3 boundaries by finding the 3 largest jumps
    struct Jump {
        size_t index;
        double ratio;
        uint32_t size_kb;
    };
    std::vector<Jump> jumps;

    for (size_t i = 1; i < fp.access_curve.size(); i++) {
        double prev = fp.access_curve[i - 1].access_time_ns;
        double curr = fp.access_curve[i].access_time_ns;
        if (prev > 0.1) {  // Avoid division by near-zero
            double ratio = curr / prev;
            if (ratio > JUMP_THRESHOLD) {
                jumps.push_back({i, ratio, fp.access_curve[i - 1].working_set_kb});
            }
        }
    }

    // Sort by ratio (largest jumps first)
    std::sort(jumps.begin(), jumps.end(),
              [](const Jump& a, const Jump& b) { return a.ratio > b.ratio; });

    // Assign boundaries to L1, L2, L3 in order of working set size
    std::vector<uint32_t> boundary_sizes;
    for (const auto& j : jumps) {
        boundary_sizes.push_back(j.size_kb);
    }
    std::sort(boundary_sizes.begin(), boundary_sizes.end());

    if (boundary_sizes.size() >= 1) fp.estimated_l1_kb = boundary_sizes[0];
    if (boundary_sizes.size() >= 2) fp.estimated_l2_kb = boundary_sizes[1];
    if (boundary_sizes.size() >= 3) fp.estimated_l3_kb = boundary_sizes[2];

    // DRAM latency = access time at largest working set
    fp.dram_latency_ns = fp.access_curve.back().access_time_ns;
}

MemoryFingerprint MemoryFingerprintCollector::collect() {
    MemoryFingerprint fp;
    fp.access_curve.reserve(PROBE_SIZES.size());

    for (uint32_t size_kb : PROBE_SIZES) {
        auto result = probe_random_access(size_kb, ACCESSES_PER_PROBE);
        fp.access_curve.push_back(result);
    }

    detect_cache_boundaries(fp);
    return fp;
}

// Dynamic Time Warping distance between two access curves
static double dtw_distance(const std::vector<MemoryProbeResult>& a,
                           const std::vector<MemoryProbeResult>& b) {
    size_t n = a.size();
    size_t m = b.size();
    if (n == 0 || m == 0) return 1e9;

    // DTW cost matrix
    std::vector<std::vector<double>> cost(n + 1, std::vector<double>(m + 1, 1e9));
    cost[0][0] = 0.0;

    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= m; j++) {
            // Distance metric: relative difference in access times
            double d = std::abs(std::log(a[i-1].access_time_ns + 1.0) -
                                std::log(b[j-1].access_time_ns + 1.0));

            cost[i][j] = d + std::min({cost[i-1][j], cost[i][j-1], cost[i-1][j-1]});
        }
    }

    return cost[n][m];
}

double MemoryFingerprint::similarity(const MemoryFingerprint& a, const MemoryFingerprint& b) {
    if (a.access_curve.empty() || b.access_curve.empty()) return 0.0;

    double dist = dtw_distance(a.access_curve, b.access_curve);

    // Normalize by path length
    size_t path_len = std::max(a.access_curve.size(), b.access_curve.size());
    double normalized = dist / path_len;

    // Convert distance to similarity in [0, 1]
    // Use exponential decay: similarity = exp(-k * distance)
    // k chosen so that a normalized distance of ~2.0 gives similarity ~0.1
    static constexpr double K = 1.15;
    return std::exp(-K * normalized);
}

std::string MemoryFingerprint::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";
    oss << "  \"estimated_l1_kb\": " << estimated_l1_kb << ",\n";
    oss << "  \"estimated_l2_kb\": " << estimated_l2_kb << ",\n";
    oss << "  \"estimated_l3_kb\": " << estimated_l3_kb << ",\n";
    oss << "  \"dram_latency_ns\": " << dram_latency_ns << ",\n";
    oss << "  \"peak_bandwidth_mbps\": " << peak_bandwidth_mbps << ",\n";
    oss << "  \"probe_count\": " << access_curve.size() << ",\n";
    oss << "  \"access_curve\": [\n";

    for (size_t i = 0; i < access_curve.size(); i++) {
        const auto& p = access_curve[i];
        oss << "    {\"size_kb\": " << p.working_set_kb
            << ", \"latency_ns\": " << p.access_time_ns
            << ", \"bw_mbps\": " << p.bandwidth_mbps << "}";
        if (i < access_curve.size() - 1) oss << ",";
        oss << "\n";
    }

    oss << "  ]\n";
    oss << "}\n";

    return oss.str();
}

std::vector<uint8_t> MemoryFingerprint::serialize() const {
    // WF-1: explicit little-endian (byte-identical on LE hosts to the previous
    // reinterpret_cast copies; portable across architectures).
    std::vector<uint8_t> data;

    // Header: probe count (4 bytes)
    uint32_t count = static_cast<uint32_t>(access_curve.size());
    dna_le::put_u32(data, count);

    // Each probe: working_set_kb(4) + access_time_ns(8,double) + bandwidth_mbps(8,double) = 20 bytes
    for (const auto& p : access_curve) {
        dna_le::put_u32(data, p.working_set_kb);
        dna_le::put_double(data, p.access_time_ns);
        dna_le::put_double(data, p.bandwidth_mbps);
    }

    // Derived features: 5 doubles = 40 bytes
    dna_le::put_double(data, estimated_l1_kb);
    dna_le::put_double(data, estimated_l2_kb);
    dna_le::put_double(data, estimated_l3_kb);
    dna_le::put_double(data, dram_latency_ns);
    dna_le::put_double(data, peak_bandwidth_mbps);

    return data;
}

MemoryFingerprint MemoryFingerprint::deserialize(const std::vector<uint8_t>& data) {
    MemoryFingerprint fp;
    if (data.size() < 4) return fp;

    size_t offset = 0;

    // Read probe count
    uint32_t count;
    std::memcpy(&count, data.data() + offset, 4);
    offset += 4;

    // Sanity check
    if (count > 100 || data.size() < offset + count * 20 + 40) return fp;

    // WF-1: explicit little-endian reads, matched to serialize() above.
    // Read probes
    fp.access_curve.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        MemoryProbeResult p;
        p.working_set_kb = dna_le::get_u32(data.data() + offset); offset += 4;
        p.access_time_ns = dna_le::get_double(data.data() + offset); offset += 8;
        p.bandwidth_mbps = dna_le::get_double(data.data() + offset); offset += 8;
        fp.access_curve.push_back(p);
    }

    // Read derived features
    fp.estimated_l1_kb = dna_le::get_double(data.data() + offset); offset += 8;
    fp.estimated_l2_kb = dna_le::get_double(data.data() + offset); offset += 8;
    fp.estimated_l3_kb = dna_le::get_double(data.data() + offset); offset += 8;
    fp.dram_latency_ns = dna_le::get_double(data.data() + offset); offset += 8;
    fp.peak_bandwidth_mbps = dna_le::get_double(data.data() + offset); offset += 8;

    return fp;
}

} // namespace digital_dna
