/**
 * Digital DNA Implementation
 */

#include "digital_dna.h"

#include <crypto/sha3.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <iostream>

namespace digital_dna {

// ============ DigitalDNA ============

std::string DigitalDNA::to_json() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    oss << "{\n";

    // Address
    oss << "  \"address\": \"";
    for (int i = 0; i < 8; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)address[i];
    }
    oss << std::dec << "...\",\n";

    // Registration
    oss << "  \"registration_height\": " << registration_height << ",\n";
    oss << "  \"registration_time\": " << registration_time << ",\n";
    oss << "  \"is_valid\": " << (is_valid ? "true" : "false") << ",\n";

    // Latency fingerprint
    oss << "  \"latency\": {\n";
    oss << "    \"seeds\": [";
    for (size_t i = 0; i < latency.seed_stats.size(); i++) {
        oss << "{\"name\": \"" << latency.seed_stats[i].seed_name << "\", ";
        oss << "\"median_ms\": " << latency.seed_stats[i].median_ms << "}";
        if (i < latency.seed_stats.size() - 1) oss << ", ";
    }
    oss << "]\n";
    oss << "  },\n";

    // Timing signature
    oss << "  \"timing\": {\n";
    oss << "    \"iterations\": " << timing.total_iterations << ",\n";
    oss << "    \"iterations_per_second\": " << timing.iterations_per_second << ",\n";
    oss << "    \"mean_interval_us\": " << timing.mean_interval_us << "\n";
    oss << "  },\n";

    // Perspective
    oss << "  \"perspective\": {\n";
    oss << "    \"total_unique_peers\": " << perspective.total_unique_peers() << ",\n";
    oss << "    \"peer_turnover_rate\": " << perspective.peer_turnover_rate() << ",\n";
    oss << "    \"witness_coverage\": " << perspective.witness_coverage() << "\n";
    oss << "  }\n";

    oss << "}";

    return oss.str();
}

// ---- Serialization helpers (little-endian) ----

static void write_u8(std::vector<uint8_t>& out, uint8_t v) {
    out.push_back(v);
}
static void write_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
static void write_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
}
static void write_double(std::vector<uint8_t>& out, double v) {
    uint64_t bits; std::memcpy(&bits, &v, sizeof(double)); write_u64(out, bits);
}
static void write_blob(std::vector<uint8_t>& out, const std::vector<uint8_t>& blob) {
    write_u32(out, static_cast<uint32_t>(blob.size()));
    out.insert(out.end(), blob.begin(), blob.end());
}

static bool read_u8(const std::vector<uint8_t>& data, size_t& off, uint8_t& v) {
    if (off + 1 > data.size()) return false;
    v = data[off++]; return true;
}
static bool read_u32(const std::vector<uint8_t>& data, size_t& off, uint32_t& v) {
    if (off + 4 > data.size()) return false;
    v = 0; for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(data[off + i]) << (i * 8);
    off += 4; return true;
}
static bool read_u64(const std::vector<uint8_t>& data, size_t& off, uint64_t& v) {
    if (off + 8 > data.size()) return false;
    v = 0; for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(data[off + i]) << (i * 8);
    off += 8; return true;
}
static bool read_double(const std::vector<uint8_t>& data, size_t& off, double& v) {
    uint64_t bits; if (!read_u64(data, off, bits)) return false;
    std::memcpy(&v, &bits, sizeof(double)); return true;
}
static bool read_blob(const std::vector<uint8_t>& data, size_t& off, std::vector<uint8_t>& blob) {
    uint32_t len; if (!read_u32(data, off, len)) return false;
    if (off + len > data.size()) return false;
    blob.assign(data.begin() + off, data.begin() + off + len);
    off += len; return true;
}

// DNA2 envelope constants
static constexpr uint8_t DNA_MAGIC[4] = {0x44, 0x4E, 0x41, 0x32};  // "DNA2"
static constexpr uint8_t DNA_VERSION = 0x03;
static constexpr uint8_t DNA_VERSION_V2 = 0x02;  // For backward compat

// Dimension flags
static constexpr uint8_t FLAG_MEMORY     = 0x01;
static constexpr uint8_t FLAG_CLOCKDRIFT = 0x02;
static constexpr uint8_t FLAG_BANDWIDTH  = 0x04;
static constexpr uint8_t FLAG_THERMAL    = 0x08;
static constexpr uint8_t FLAG_BEHAVIORAL = 0x10;

std::vector<uint8_t> DigitalDNA::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(256);  // Typical size estimate

    // ---- Envelope ----
    data.insert(data.end(), DNA_MAGIC, DNA_MAGIC + 4);
    write_u8(data, DNA_VERSION);

    // ---- Metadata ----
    data.insert(data.end(), address.begin(), address.end());  // 20 bytes
    data.insert(data.end(), mik_identity.begin(), mik_identity.end());  // 20 bytes (v3)
    write_u32(data, registration_height);
    write_u64(data, registration_time);

    // ---- Dimension flags ----
    uint8_t flags = 0;
    if (memory)     flags |= FLAG_MEMORY;
    if (clock_drift) flags |= FLAG_CLOCKDRIFT;
    if (bandwidth)  flags |= FLAG_BANDWIDTH;
    if (thermal)    flags |= FLAG_THERMAL;
    if (behavioral) flags |= FLAG_BEHAVIORAL;
    write_u8(data, flags);

    // ---- Core v2.0 dimensions (always present) ----

    // Latency: seed_count + N * median_ms
    write_u32(data, static_cast<uint32_t>(latency.seed_stats.size()));
    for (const auto& s : latency.seed_stats) {
        write_double(data, s.median_ms);
    }

    // Timing: iterations_per_second
    write_double(data, timing.iterations_per_second);

    // Perspective: peer_count + turnover_rate
    write_u32(data, static_cast<uint32_t>(perspective.total_unique_peers()));
    write_double(data, perspective.peer_turnover_rate());

    // ---- Optional v3.0 dimensions (length-prefixed blobs) ----

    if (memory) {
        write_blob(data, memory->serialize());
    }
    if (clock_drift) {
        write_blob(data, clock_drift->serialize());
    }
    if (bandwidth) {
        write_blob(data, bandwidth->serialize());
    }
    if (thermal) {
        // ThermalProfile has no serialize() — inline it
        std::vector<uint8_t> tbuf;
        write_u32(tbuf, static_cast<uint32_t>(thermal->speed_curve.size()));
        for (double v : thermal->speed_curve) write_double(tbuf, v);
        write_u32(tbuf, thermal->measurement_interval_sec);
        write_double(tbuf, thermal->initial_speed);
        write_double(tbuf, thermal->sustained_speed);
        write_double(tbuf, thermal->throttle_ratio);
        write_double(tbuf, thermal->time_to_steady_state_sec);
        write_double(tbuf, thermal->thermal_jitter);
        write_blob(data, tbuf);
    }
    if (behavioral) {
        write_blob(data, behavioral->serialize());
    }

    return data;
}

// ---- Legacy v1 deserializer (no magic, starts with 20-byte address) ----
static std::optional<DigitalDNA> deserialize_v1(const std::vector<uint8_t>& data) {
    // Minimum: 20 (addr) + 4 (height) + 8 (time) + 4 (seed_count) + 8 (timing) + 12 (persp) = 56
    if (data.size() < 56) return std::nullopt;

    DigitalDNA dna;
    size_t off = 0;

    std::copy(data.begin(), data.begin() + 20, dna.address.begin());
    off += 20;

    uint32_t tmp32;
    if (!read_u32(data, off, tmp32)) return std::nullopt;
    dna.registration_height = tmp32;

    uint64_t tmp64;
    if (!read_u64(data, off, tmp64)) return std::nullopt;
    dna.registration_time = tmp64;

    uint32_t seed_count;
    if (!read_u32(data, off, seed_count)) return std::nullopt;
    if (seed_count > 100) return std::nullopt;  // Sanity
    if (off + seed_count * 8 + 8 + 12 > data.size()) return std::nullopt;

    dna.latency.seed_stats.resize(seed_count);
    for (uint32_t s = 0; s < seed_count; s++) {
        if (!read_double(data, off, dna.latency.seed_stats[s].median_ms)) return std::nullopt;
    }

    if (!read_double(data, off, dna.timing.iterations_per_second)) return std::nullopt;

    // Perspective (simplified — v1 only stored count + turnover)
    off += 12;

    // v1 has no MIK — use address as fallback
    dna.mik_identity = dna.address;

    dna.is_valid = true;
    return dna;
}

std::optional<DigitalDNA> DigitalDNA::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 5) return std::nullopt;

    // Check for DNA2 magic envelope
    if (data[0] == DNA_MAGIC[0] && data[1] == DNA_MAGIC[1] &&
        data[2] == DNA_MAGIC[2] && data[3] == DNA_MAGIC[3]) {

        size_t off = 4;
        uint8_t version;
        if (!read_u8(data, off, version)) return std::nullopt;
        if (version != DNA_VERSION && version != DNA_VERSION_V2) return std::nullopt;

        DigitalDNA dna;

        // Address (20 bytes)
        if (off + 20 > data.size()) return std::nullopt;
        std::copy(data.begin() + off, data.begin() + off + 20, dna.address.begin());
        off += 20;

        // MIK identity (20 bytes, v3 only)
        if (version >= DNA_VERSION) {
            if (off + 20 > data.size()) return std::nullopt;
            std::copy(data.begin() + off, data.begin() + off + 20, dna.mik_identity.begin());
            off += 20;
        } else {
            // v2 backward compat: mik_identity = address
            dna.mik_identity = dna.address;
        }

        // Metadata
        if (!read_u32(data, off, dna.registration_height)) return std::nullopt;
        if (!read_u64(data, off, dna.registration_time)) return std::nullopt;

        // Dimension flags
        uint8_t flags;
        if (!read_u8(data, off, flags)) return std::nullopt;

        // Core v2.0: Latency
        uint32_t seed_count;
        if (!read_u32(data, off, seed_count)) return std::nullopt;
        if (seed_count > 100) return std::nullopt;
        dna.latency.seed_stats.resize(seed_count);
        for (uint32_t s = 0; s < seed_count; s++) {
            if (!read_double(data, off, dna.latency.seed_stats[s].median_ms)) return std::nullopt;
        }

        // Core v2.0: Timing
        if (!read_double(data, off, dna.timing.iterations_per_second)) return std::nullopt;

        // Core v2.0: Perspective (summary stats — full peer list not serialized)
        uint32_t peer_count;
        if (!read_u32(data, off, peer_count)) return std::nullopt;
        double turnover;
        if (!read_double(data, off, turnover)) return std::nullopt;
        dna.perspective.cached_peer_count = peer_count;
        dna.perspective.cached_turnover_rate = turnover;

        // Optional v3.0 dimensions (order matches flags)
        if (flags & FLAG_MEMORY) {
            std::vector<uint8_t> blob;
            if (!read_blob(data, off, blob)) return std::nullopt;
            dna.memory = MemoryFingerprint::deserialize(blob);
        }
        if (flags & FLAG_CLOCKDRIFT) {
            std::vector<uint8_t> blob;
            if (!read_blob(data, off, blob)) return std::nullopt;
            dna.clock_drift = ClockDriftFingerprint::deserialize(blob);
        }
        if (flags & FLAG_BANDWIDTH) {
            std::vector<uint8_t> blob;
            if (!read_blob(data, off, blob)) return std::nullopt;
            dna.bandwidth = BandwidthFingerprint::deserialize(blob);
        }
        if (flags & FLAG_THERMAL) {
            std::vector<uint8_t> blob;
            if (!read_blob(data, off, blob)) return std::nullopt;
            // Inline ThermalProfile deserialization
            ThermalProfile tp;
            size_t toff = 0;
            uint32_t curve_count;
            if (!read_u32(blob, toff, curve_count)) return std::nullopt;
            if (curve_count > 10000) return std::nullopt;  // Sanity
            tp.speed_curve.resize(curve_count);
            for (uint32_t i = 0; i < curve_count; i++) {
                if (!read_double(blob, toff, tp.speed_curve[i])) return std::nullopt;
            }
            if (!read_u32(blob, toff, tp.measurement_interval_sec)) return std::nullopt;
            if (!read_double(blob, toff, tp.initial_speed)) return std::nullopt;
            if (!read_double(blob, toff, tp.sustained_speed)) return std::nullopt;
            if (!read_double(blob, toff, tp.throttle_ratio)) return std::nullopt;
            if (!read_double(blob, toff, tp.time_to_steady_state_sec)) return std::nullopt;
            if (!read_double(blob, toff, tp.thermal_jitter)) return std::nullopt;
            dna.thermal = tp;
        }
        if (flags & FLAG_BEHAVIORAL) {
            std::vector<uint8_t> blob;
            if (!read_blob(data, off, blob)) return std::nullopt;
            dna.behavioral = BehavioralProfile::deserialize(blob);
        }

        dna.is_valid = true;
        return dna;
    }

    // No DNA2 magic — try legacy v1 format
    return deserialize_v1(data);
}

std::array<uint8_t, 32> DigitalDNA::hash() const {
    auto data = serialize();
    std::array<uint8_t, 32> result;
    SHA3_256(data.data(), data.size(), result.data());
    return result;
}

// ============ SimilarityScore ============

std::string SimilarityScore::verdict() const {
    if (is_same_identity()) {
        return "SAME_IDENTITY";
    } else if (is_suspicious()) {
        return "SUSPICIOUS";
    } else {
        return "DIFFERENT";
    }
}

// ============ DigitalDNACollector ============

DigitalDNACollector::DigitalDNACollector(const std::array<uint8_t, 20>& address, const Config& config)
    : address_(address)
    , config_(config)
    , latency_collector_()
    , timing_collector_(TimingConfig{config.timing_iterations, config.timing_checkpoint_interval, 10000})
    , perspective_collector_(address, PerspectiveConfig{60, config.perspective_duration_sec, 3, false})
{
    latency_collector_.set_samples_per_seed(config.latency_samples);
    latency_collector_.set_timeout_ms(config.latency_timeout_ms);
}

DigitalDNACollector::~DigitalDNACollector() {
    collecting_ = false;
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }
}

void DigitalDNACollector::start_collection() {
    collecting_ = true;

    // Run collection in background thread to avoid blocking node startup
    collection_thread_ = std::thread([this]() {
        // 1. Collect latency fingerprint (~30 seconds)
        LatencyFingerprint latency;
        latency.measurement_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        // Measure against seeds (testnet or mainnet)
        auto measure_seeds = [&](const auto& seeds) {
            latency.seed_stats.reserve(seeds.size());
            for (size_t i = 0; i < seeds.size(); i++) {
                if (!collecting_) return;
                latency.seed_stats.push_back(latency_collector_.measure_seed(seeds[i]));
            }
        };
        if (config_.testnet) {
            measure_seeds(TESTNET_SEEDS);
        } else {
            measure_seeds(MAINNET_SEEDS);
        }
        latency_result_ = latency;

        // 2. Collect timing signature (seconds to minutes)
        std::array<uint8_t, 32> challenge = {};
        for (int i = 0; i < 20; i++) {
            challenge[i] = address_[i];
        }
        timing_result_ = timing_collector_.collect(challenge);
        if (!collecting_) return;

        // 3. Derive thermal profile from timing checkpoints (zero extra cost)
        if (config_.collect_thermal && timing_result_) {
            thermal_result_ = derive_thermal_profile(*timing_result_, 60);
        }

        // 4. Collect memory fingerprint (~5 seconds)
        if (config_.collect_memory && collecting_) {
            memory_result_ = memory_collector_.collect();
        }

        // 5. Perspective snapshots: take periodic snapshots while waiting for
        // perspective collection to complete. Peers connect/disconnect via
        // on_peer_connected/disconnected hooks, but snapshots must be explicitly
        // recorded to capture the peer set state over time.
        uint32_t snapshot_height = 0;
        while (collecting_ && !perspective_collector_.is_complete()) {
            perspective_collector_.take_snapshot(snapshot_height++);
            // Sleep 60 seconds between snapshots (interruptible via collecting_ flag)
            for (int i = 0; i < 60 && collecting_; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        // Behavioral collection is ongoing via on_block_* hooks
    });
}

void DigitalDNACollector::stop_collection() {
    collecting_ = false;

    // Wait for background collection thread to finish
    if (collection_thread_.joinable()) {
        collection_thread_.join();
    }

    // Take a final perspective snapshot to capture current peer state
    perspective_collector_.take_snapshot(0);

    // Finalize perspective
    perspective_result_ = perspective_collector_.get_proof();
}

double DigitalDNACollector::get_progress() const {
    if (!collecting_) {
        return latency_result_ && timing_result_ && perspective_result_ ? 1.0 : 0.0;
    }

    double latency_progress = latency_result_ ? 1.0 : 0.0;
    double timing_progress = timing_collector_.get_progress();
    double perspective_progress = perspective_collector_.get_progress();

    // Weighted: latency 20%, timing 30%, perspective 50%
    return 0.2 * latency_progress + 0.3 * timing_progress + 0.5 * perspective_progress;
}

std::optional<DigitalDNA> DigitalDNACollector::get_dna() const {
    if (!latency_result_ || !timing_result_) {
        return std::nullopt;
    }

    DigitalDNA dna;
    dna.address = address_;
    dna.mik_identity = mik_identity_;
    dna.latency = *latency_result_;
    dna.timing = *timing_result_;
    dna.perspective = perspective_result_.value_or(perspective_collector_.get_proof());
    dna.registration_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    // v3.0 local dimensions (populated if collection completed)
    dna.memory = memory_result_;
    dna.thermal = thermal_result_;

    // Behavioral profile (populated over time via on_block/on_tx hooks)
    auto bp = behavioral_collector_.get_profile();
    if (bp.observation_blocks > 0) {
        dna.behavioral = bp;
    }

    // P2P dimensions (populated over time via P2P message exchanges)
    if (clock_drift_collector_.is_ready()) {
        dna.clock_drift = clock_drift_collector_.get_fingerprint();
    }
    if (bandwidth_collector_.is_ready()) {
        dna.bandwidth = bandwidth_collector_.get_fingerprint();
    }

    dna.is_valid = true;
    return dna;
}

std::optional<std::array<uint8_t, 20>> DigitalDNACollector::get_address_if_ready() const {
    // Mirror get_dna()'s readiness guard, but return ONLY the cheap 20-byte address
    // — no full-DNA build/deep-copy (see header: hot-path allocator-churn / OOM fix).
    if (!latency_result_ || !timing_result_) {
        return std::nullopt;
    }
    return address_;
}

void DigitalDNACollector::on_peer_connected(const std::array<uint8_t, 20>& peer_id) {
    perspective_collector_.on_peer_connected(peer_id);
}

void DigitalDNACollector::on_peer_disconnected(const std::array<uint8_t, 20>& peer_id) {
    perspective_collector_.on_peer_disconnected(peer_id);
}

void DigitalDNACollector::on_block_received(uint32_t height) {
    behavioral_collector_.on_block_received(height);
}

void DigitalDNACollector::on_tx_relayed(uint64_t timestamp_ms) {
    behavioral_collector_.on_tx_relayed(timestamp_ms);
}

void DigitalDNACollector::on_time_sync_response(const std::array<uint8_t, 20>& peer_id,
    uint64_t local_send_us, uint64_t peer_timestamp_us, uint64_t local_recv_us)
{
    clock_drift_collector_.record_exchange(peer_id, local_send_us, peer_timestamp_us, local_recv_us);
}

void DigitalDNACollector::on_bandwidth_result(const std::array<uint8_t, 20>& peer_id,
    double upload_mbps, double download_mbps)
{
    BandwidthMeasurement m;
    m.peer_id = peer_id;
    m.upload_mbps = upload_mbps;
    m.download_mbps = download_mbps;
    m.asymmetry_ratio = (download_mbps > 0.001) ? (upload_mbps / download_mbps) : 0.0;
    m.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    bandwidth_collector_.record_measurement(m);
}

// ============ DigitalDNARegistry ============

DigitalDNARegistry::DigitalDNARegistry() {}

IDNARegistry::RegisterResult DigitalDNARegistry::register_identity(const DigitalDNA& dna) {
    if (!dna.is_valid) {
        return RegisterResult::INVALID_DNA;
    }

    if (is_registered(dna.address)) {
        return RegisterResult::ALREADY_REGISTERED;
    }

    // Advisory Sybil check: always store, log warning if similar
    bool sybil_flagged = false;
    auto similar = find_similar(dna, SimilarityScore::SUSPICIOUS_THRESHOLD);
    for (const auto& [other, score] : similar) {
        std::ostringstream addr_a, addr_b;
        for (int i = 0; i < 4; i++) addr_a << std::hex << std::setw(2) << std::setfill('0') << (int)dna.address[i];
        for (int i = 0; i < 4; i++) addr_b << std::hex << std::setw(2) << std::setfill('0') << (int)other.address[i];
        std::cout << "[DNA-SYBIL] ADVISORY: " << addr_a.str() << "... matches " << addr_b.str()
                  << "... (" << score.verdict() << ", score=" << std::fixed << std::setprecision(3)
                  << score.combined_score << ", dims=" << score.dimensions_scored << ")" << std::endl;
        sybil_flagged = true;
    }

    identities_.push_back(dna);
    return sybil_flagged ? RegisterResult::SYBIL_FLAGGED : RegisterResult::SUCCESS;
}

IDNARegistry::RegisterResult DigitalDNARegistry::update_identity(const DigitalDNA& dna) {
    if (!dna.is_valid) {
        return RegisterResult::INVALID_DNA;
    }

    auto it = std::find_if(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == dna.address; });
    if (it == identities_.end()) {
        return RegisterResult::INVALID_DNA;  // Must be registered first
    }

    // Phase 5: Detect core dimension changes
    bool dimensionsChanged = core_dimensions_changed(*it, dna);

    *it = dna;  // Replace with enriched version
    return dimensionsChanged ? RegisterResult::DNA_CHANGED : RegisterResult::UPDATED;
}

IDNARegistry::RegisterResult DigitalDNARegistry::append_sample(const DigitalDNA& dna) {
    if (!dna.is_valid) {
        return RegisterResult::INVALID_DNA;
    }

    auto it = std::find_if(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == dna.address; });

    if (it == identities_.end()) {
        // Not registered — add it (no Sybil advisory log in the sample path).
        identities_.push_back(dna);
        return RegisterResult::SUCCESS;
    }

    // Dimension-loss guard: reject silently-shrinking samples.
    auto removes_dims = [](const DigitalDNA& old_dna, const DigitalDNA& new_dna) {
        if (old_dna.perspective.total_unique_peers() > 0 &&
            new_dna.perspective.total_unique_peers() == 0 &&
            new_dna.perspective.snapshots.empty()) return true;
        if (old_dna.memory && !new_dna.memory) return true;
        if (old_dna.clock_drift && !new_dna.clock_drift) return true;
        if (old_dna.bandwidth && !new_dna.bandwidth) return true;
        if (old_dna.thermal && !new_dna.thermal) return true;
        if (old_dna.behavioral && !new_dna.behavioral) return true;
        return false;
    };
    if (removes_dims(*it, dna)) {
        return RegisterResult::INVALID_DNA;
    }

    bool dimensionsChanged = core_dimensions_changed(*it, dna);
    *it = dna;  // In-memory impl does not archive history (LevelDB impl does).
    return dimensionsChanged ? RegisterResult::DNA_CHANGED : RegisterResult::UPDATED;
}

bool DigitalDNARegistry::is_registered(const std::array<uint8_t, 20>& address) const {
    return std::any_of(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == address; });
}

std::optional<DigitalDNA> DigitalDNARegistry::get_identity(const std::array<uint8_t, 20>& address) const {
    auto it = std::find_if(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.address == address; });
    if (it != identities_.end()) {
        return *it;
    }
    return std::nullopt;
}

std::optional<DigitalDNA> DigitalDNARegistry::get_identity_by_mik(const std::array<uint8_t, 20>& mik) const {
    auto it = std::find_if(identities_.begin(), identities_.end(),
        [&](const DigitalDNA& d) { return d.mik_identity == mik; });
    if (it != identities_.end()) {
        return *it;
    }
    return std::nullopt;
}

std::vector<std::pair<DigitalDNA, SimilarityScore>> DigitalDNARegistry::find_similar(
    const DigitalDNA& dna,
    double threshold
) const {
    std::vector<std::pair<DigitalDNA, SimilarityScore>> results;

    for (const auto& other : identities_) {
        if (other.address == dna.address) continue;

        auto score = compare(dna, other);
        if (score.combined_score >= threshold) {
            results.push_back({other, score});
        }
    }

    // Sort by similarity (highest first)
    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) {
            return a.second.combined_score > b.second.combined_score;
        });

    return results;
}

SimilarityScore DigitalDNARegistry::compare(const DigitalDNA& a, const DigitalDNA& b) const {
    SimilarityScore score;

    // Core v2.0 dimensions (always available)
    score.latency_similarity = calculate_latency_similarity(a.latency, b.latency);
    score.timing_similarity = calculate_timing_similarity(a.timing, b.timing);

    // Perspective may return -1.0 if both have no peer data (e.g. after deserialization)
    double p_sim = calculate_perspective_similarity(a.perspective, b.perspective);
    if (p_sim < 0.0) {
        score.perspective_similarity = 0.0;
        score.has_perspective = false;
    } else {
        score.perspective_similarity = p_sim;
        score.has_perspective = true;
    }

    // v3.0 extended dimensions (scored only when both identities have data)
    if (a.memory && b.memory) {
        score.memory_similarity = MemoryFingerprint::similarity(*a.memory, *b.memory);
        score.has_memory = true;
    }
    if (a.clock_drift && b.clock_drift) {
        score.clock_drift_similarity = ClockDriftFingerprint::similarity(*a.clock_drift, *b.clock_drift);
        score.has_clock_drift = true;
    }
    if (a.bandwidth && b.bandwidth) {
        score.bandwidth_similarity = BandwidthFingerprint::similarity(*a.bandwidth, *b.bandwidth);
        score.has_bandwidth = true;
    }
    if (a.thermal && b.thermal) {
        score.thermal_similarity = ThermalProfile::similarity(*a.thermal, *b.thermal);
        score.has_thermal = true;
    }
    if (a.behavioral && b.behavioral) {
        score.behavioral_similarity = BehavioralProfile::similarity(*a.behavioral, *b.behavioral);
        score.has_behavioral = true;
    }

    return compute_combined_score(score);
}

SimilarityScore DigitalDNARegistry::compute_combined_score(SimilarityScore score) {
    // Equal-weight average across all available dimensions.
    // During bootstrap (few v3.0 identities), this degrades gracefully
    // to the 3 core dimensions. As the network matures, all 8 contribute.
    //
    // Correlation-aware damping: V (Timing), M (Memory), T (Thermal) are
    // correlated by hardware SKU. When all three are high and close to each
    // other, they likely indicate "same model" not "same machine." We dampen
    // their combined contribution so they don't inflate the score.

    double sum = 0.0;
    double weight_sum = 0.0;

    // Helper: add a dimension with given weight
    auto add = [&](double similarity, double weight) {
        sum += similarity * weight;
        weight_sum += weight;
    };

    // Independent dimensions: full weight (1.0 each)
    add(score.latency_similarity, 1.0);         // L: geographic
    if (score.has_perspective)
        add(score.perspective_similarity, 1.0); // P: network topology (skipped if no peer data)

    // V/M/T correlation cluster: check if they move together
    double vmt_weight = 1.0;  // default: full weight each
    bool has_vmt_cluster = score.has_memory && score.has_thermal;
    if (has_vmt_cluster) {
        double v = score.timing_similarity;
        double m = score.memory_similarity;
        double t = score.thermal_similarity;
        double vmt_max = std::max({v, m, t});
        double vmt_min = std::min({v, m, t});
        double vmt_spread = vmt_max - vmt_min;

        // If all three are high (>0.80) and tightly clustered (spread <0.15),
        // they're likely correlated by hardware SKU. Dampen to 0.5 weight each
        // so the cluster contributes ~1.5 dimensions instead of 3.
        if (vmt_min > 0.80 && vmt_spread < 0.15) {
            vmt_weight = 0.5;
        }
    }

    add(score.timing_similarity, vmt_weight);     // V: VDF speed
    if (score.has_memory)
        add(score.memory_similarity, vmt_weight);  // M: cache hierarchy
    if (score.has_thermal)
        add(score.thermal_similarity, vmt_weight); // T: cooling curve

    // Independent extended dimensions: full weight
    if (score.has_clock_drift)
        add(score.clock_drift_similarity, 1.0);   // D: oscillator (unique per machine)
    if (score.has_bandwidth)
        add(score.bandwidth_similarity, 1.0);      // B: throughput
    if (score.has_behavioral)
        add(score.behavioral_similarity, 1.0);     // BP: activity patterns

    score.dimensions_scored = static_cast<uint32_t>(
        2 + (score.has_perspective ? 1 : 0) +
        (score.has_memory ? 1 : 0) + (score.has_clock_drift ? 1 : 0) +
        (score.has_bandwidth ? 1 : 0) + (score.has_thermal ? 1 : 0) +
        (score.has_behavioral ? 1 : 0));
    score.combined_score = (weight_sum > 0.0) ? sum / weight_sum : 0.0;

    return score;
}

std::vector<DigitalDNA> DigitalDNARegistry::get_all() const {
    return identities_;
}

std::vector<std::array<uint8_t, 20>> DigitalDNARegistry::get_all_miks() const {
    std::vector<std::array<uint8_t, 20>> result;
    result.reserve(identities_.size());
    for (const auto& dna : identities_) {
        if (dna.mik_identity == std::array<uint8_t, 20>{}) continue;
        result.push_back(dna.mik_identity);
    }
    return result;
}

std::vector<std::pair<uint64_t, DigitalDNA>> DigitalDNARegistry::get_dna_history(
    const std::array<uint8_t, 20>& /*mik*/, size_t /*max_entries*/) const {
    // In-memory registry doesn't track history
    return {};
}

bool DigitalDNARegistry::save(const std::string& path) const {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    uint32_t count = static_cast<uint32_t>(identities_.size());
    ofs.write(reinterpret_cast<const char*>(&count), 4);

    for (const auto& dna : identities_) {
        auto data = dna.serialize();
        uint32_t size = static_cast<uint32_t>(data.size());
        ofs.write(reinterpret_cast<const char*>(&size), 4);
        ofs.write(reinterpret_cast<const char*>(data.data()), size);
    }

    return true;
}

bool DigitalDNARegistry::load(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    uint32_t count;
    ifs.read(reinterpret_cast<char*>(&count), 4);

    identities_.clear();
    for (uint32_t i = 0; i < count; i++) {
        uint32_t size;
        ifs.read(reinterpret_cast<char*>(&size), 4);

        std::vector<uint8_t> data(size);
        ifs.read(reinterpret_cast<char*>(data.data()), size);

        auto dna = DigitalDNA::deserialize(data);
        if (dna) {
            identities_.push_back(*dna);
        }
    }

    return true;
}

double DigitalDNARegistry::calculate_latency_similarity(
    const LatencyFingerprint& a, const LatencyFingerprint& b
) const {
    return latency_similarity(a, b);
}

double DigitalDNARegistry::calculate_timing_similarity(
    const TimingSignature& a, const TimingSignature& b
) const {
    return timing_similarity(a, b);
}

double DigitalDNARegistry::calculate_perspective_similarity(
    const PerspectiveProof& a, const PerspectiveProof& b
) const {
    return perspective_similarity(a, b);
}

// ============ Utility Functions ============

double latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b) {
    // Use Euclidean distance, convert to similarity
    double distance = LatencyFingerprint::distance(a, b);

    // Convert distance to similarity (0-1)
    // At 0ms distance -> 1.0 similarity
    // At 100ms distance -> ~0.37 similarity
    // At 300ms distance -> ~0.05 similarity
    return std::exp(-distance / 100.0);
}

double timing_similarity(const TimingSignature& a, const TimingSignature& b) {
    // Use progress rate similarity (more stable than checkpoint correlation)
    return TimingSignature::progress_rate_similarity(a, b);
}

double perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b) {
    return PerspectiveProof::similarity(a, b);
}

const std::array<SeedNode, 4>& get_mainnet_seeds() {
    return MAINNET_SEEDS;
}

const std::array<SeedNode, 3>& get_testnet_seeds() {
    return TESTNET_SEEDS;
}

} // namespace digital_dna
