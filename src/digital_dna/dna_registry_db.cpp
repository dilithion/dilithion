#include "dna_registry_db.h"

#include <leveldb/write_batch.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace digital_dna {

const std::string DNARegistryDB::KEY_PREFIX = "dna:";
const std::string DNARegistryDB::MIK_KEY_PREFIX = "dna_mik:";
const std::string DNARegistryDB::HIST_KEY_PREFIX = "dna_hist:";
const std::string DNARegistryDB::ATT_KEY_PREFIX = "dna_att:";

DNARegistryDB::DNARegistryDB() {}

DNARegistryDB::~DNARegistryDB() {
    Close();
}

bool DNARegistryDB::Open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (db_) return true;  // Already open

    path_ = path;

    leveldb::Options options;
    options.create_if_missing = true;

    leveldb::DB* raw_db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, path, &raw_db);
    if (!status.ok()) {
        return false;
    }

    db_.reset(raw_db);

    // Load all identities into cache
    load_cache();

    return true;
}

void DNARegistryDB::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    db_.reset();
}

bool DNARegistryDB::IsOpen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return db_ != nullptr;
}

IDNARegistry::RegisterResult DNARegistryDB::register_identity(const DigitalDNA& dna) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return RegisterResult::DB_ERROR;
    if (!dna.is_valid) return RegisterResult::INVALID_DNA;

    // Check if already registered
    std::string key = make_key(dna.address);
    std::string existing;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &existing);
    if (status.ok()) {
        return RegisterResult::ALREADY_REGISTERED;
    }

    // Sybil check: compare DNA against all known identities
    bool sybil_flagged = false;
    for (const auto& [addr, other] : cache_) {
        if (addr == dna.address) continue;

        auto score = compare(dna, other);

        if (score.is_same_identity() || score.is_suspicious()) {
            std::string logPrefix = m_enforceDNADedup && score.is_same_identity()
                ? "[DNA-SYBIL] REJECTED: " : "[DNA-SYBIL] ADVISORY: ";
            std::cout << logPrefix << address_to_hex(dna.address)
                      << " matches " << address_to_hex(addr)
                      << " (" << score.verdict()
                      << ", score=" << std::fixed << std::setprecision(3) << score.combined_score
                      << ", dims=" << score.dimensions_scored << ")" << std::endl;
            std::cout << "[DNA-SYBIL]   L=" << std::setprecision(2) << score.latency_similarity
                      << " V=" << score.timing_similarity
                      << " P=" << score.perspective_similarity;
            if (score.has_memory) std::cout << " M=" << score.memory_similarity;
            if (score.has_clock_drift) std::cout << " D=" << score.clock_drift_similarity;
            if (score.has_bandwidth) std::cout << " B=" << score.bandwidth_similarity;
            if (score.has_thermal) std::cout << " T=" << score.thermal_similarity;
            if (score.has_behavioral) std::cout << " BP=" << score.behavioral_similarity;
            std::cout << std::endl;
            sybil_flagged = true;

            // Phase 2A: Reject (don't store) when enforcement enabled and
            // DNA matches at the SAME_IDENTITY level (>=0.92 or physics rule)
            if (m_enforceDNADedup && score.is_same_identity()) {
                return RegisterResult::SYBIL_REJECTED;
            }
        }

        // ML supplementary logging (advisory only)
        if (score.is_suspicious() && ml_detector_ &&
            ml_detector_->get_mode() != MLSybilDetector::Mode::DISABLED) {

            double lat_dist = LatencyFingerprint::distance(dna.latency, other.latency);
            double vdf_ratio = (other.timing.iterations_per_second > 0)
                ? dna.timing.iterations_per_second / other.timing.iterations_per_second : 1.0;
            double mem_dtw = (dna.memory && other.memory)
                ? (1.0 - score.memory_similarity) * 100.0 : 0.0;
            double drift_diff = (dna.clock_drift && other.clock_drift)
                ? std::abs(dna.clock_drift->drift_rate_ppm - other.clock_drift->drift_rate_ppm) : 0.0;
            double bw_asym_diff = (dna.bandwidth && other.bandwidth)
                ? std::abs(dna.bandwidth->median_asymmetry - other.bandwidth->median_asymmetry) : 0.0;
            double therm_diff = (dna.thermal && other.thermal)
                ? std::abs(dna.thermal->throttle_ratio - other.thermal->throttle_ratio) : 0.0;
            double reg_gap = std::abs(
                static_cast<double>(dna.registration_height) - static_cast<double>(other.registration_height));

            auto features = ml_detector_->extract_features(
                lat_dist, 0.0, vdf_ratio, score.timing_similarity,
                mem_dtw, drift_diff, score.perspective_similarity,
                score.behavioral_similarity, bw_asym_diff, therm_diff,
                0.0, reg_gap, false);

            bool full_dims = score.dimensions_scored >= 8;
            ml_detector_->record_scored(full_dims);
            ml_detector_->is_anomalous(features);  // Advisory logging inside
        }
    }

    // Store identity (reached here = passed enforcement check or enforcement disabled)
    auto data = dna.serialize();
    std::string value(data.begin(), data.end());

    // Dual-key write: address key + MIK key
    leveldb::WriteBatch batch;
    batch.Put(key, value);

    // Write MIK key if mik_identity is non-zero
    std::array<uint8_t, 20> zero_mik{};
    if (dna.mik_identity != zero_mik) {
        std::string mik_key = make_mik_key(dna.mik_identity);
        batch.Put(mik_key, value);
        mik_to_address_[dna.mik_identity] = dna.address;
    }

    status = db_->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        return RegisterResult::DB_ERROR;
    }

    // Evict oldest cache entry if at capacity (LevelDB still has full data)
    if (cache_.size() >= MAX_CACHE_SIZE) {
        cache_.erase(cache_.begin());
    }
    cache_[dna.address] = dna;
    return sybil_flagged ? RegisterResult::SYBIL_FLAGGED : RegisterResult::SUCCESS;
}

// Helper: count populated dimensions on a DigitalDNA record.
// Latency and timing are always considered present (core dims baked in at collection).
// Perspective counts as present if any peer data exists.
static int count_populated_dimensions(const DigitalDNA& d) {
    int n = 2;  // latency + timing always present on a valid DNA
    if (d.perspective.total_unique_peers() > 0 || !d.perspective.snapshots.empty()) n++;
    if (d.memory) n++;
    if (d.clock_drift) n++;
    if (d.bandwidth) n++;
    if (d.thermal) n++;
    if (d.behavioral) n++;
    return n;
}

// Helper: returns true iff `new_dna` removes any populated dimension that `old_dna` had.
// Same set or superset is OK. Value changes within the same set are OK.
static bool removes_populated_dimensions(const DigitalDNA& old_dna, const DigitalDNA& new_dna) {
    if (old_dna.perspective.total_unique_peers() > 0 &&
        new_dna.perspective.total_unique_peers() == 0 &&
        new_dna.perspective.snapshots.empty()) return true;
    if (old_dna.memory && !new_dna.memory) return true;
    if (old_dna.clock_drift && !new_dna.clock_drift) return true;
    if (old_dna.bandwidth && !new_dna.bandwidth) return true;
    if (old_dna.thermal && !new_dna.thermal) return true;
    if (old_dna.behavioral && !new_dna.behavioral) return true;
    return false;
}

// Helper: evict oldest history entries for a MIK until count is within cap.
// Mutates the provided WriteBatch with Delete operations for evicted keys.
// Caller must hold mutex_ and pass the open db_.
static void evict_old_history(leveldb::DB* db,
                              leveldb::WriteBatch& batch,
                              const std::string& hist_prefix,
                              size_t cap) {
    if (!db) return;
    // Collect all history keys for this MIK in lexicographic (chronological) order.
    std::vector<std::string> keys;
    std::unique_ptr<leveldb::Iterator> it(db->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(hist_prefix); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, hist_prefix.size()) != hist_prefix) break;
        keys.push_back(key);
    }
    // Evict oldest until size <= cap. Note: this runs BEFORE the new entry is
    // written, so the effective post-write count is (keys.size() - evicted + 1).
    // We want post-write count <= cap, so evict until keys.size() < cap.
    while (keys.size() >= cap) {
        batch.Delete(keys.front());
        keys.erase(keys.begin());
    }
}

IDNARegistry::RegisterResult DNARegistryDB::append_sample(const DigitalDNA& dna) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return RegisterResult::DB_ERROR;
    if (!dna.is_valid) return RegisterResult::INVALID_DNA;

    std::string key = make_key(dna.address);
    std::string existing;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &existing);

    if (!status.ok()) {
        // Not yet registered — mutex is NOT reentrant so we inline the register
        // path rather than calling register_identity (which re-locks). The new
        // entry writes go through the same helpers as register_identity, minus
        // the Sybil-flag log (this is a receiver-side acceptance path, not a
        // miner's first registration).
        // NOTE (fresh-pass MEDIUM, H-1 adjacency) — this branch creates a
        // permanent, sender-keyed registry entry, and the gate for it is NOT
        // here. Creating on first sample is this function's DOCUMENTED contract
        // (src/test/dna_propagation_tests.cpp, append_sample_unregistered_registers,
        // asserts SUCCESS for exactly this case), and the registry has no peer
        // context to rate-limit with. A gate added here was tried and reverted:
        // it reddened 9 tests in dna_propagation_tests, which is the contract
        // saying no.
        // The gate belongs at the call sites, which hold peer_id — see the
        // comment above the mapped fast path in dilithion-node.cpp / dilv-node.cpp.
        std::array<uint8_t, 20> zero_mik{};
        auto data = dna.serialize();
        std::string value(data.begin(), data.end());
        leveldb::WriteBatch batch;
        batch.Put(key, value);
        if (dna.mik_identity != zero_mik) {
            batch.Put(make_mik_key(dna.mik_identity), value);
            mik_to_address_[dna.mik_identity] = dna.address;
        }
        status = db_->Write(leveldb::WriteOptions(), &batch);
        if (!status.ok()) return RegisterResult::DB_ERROR;
        if (cache_.size() >= MAX_CACHE_SIZE) cache_.erase(cache_.begin());
        cache_[dna.address] = dna;
        return RegisterResult::SUCCESS;
    }

    // Already registered — archive old, write new, cap history.
    auto oldDna = DigitalDNA::deserialize(
        std::vector<uint8_t>(existing.begin(), existing.end()));

    // Dimension-loss guard: reject silently-shrinking samples.
    if (oldDna && removes_populated_dimensions(*oldDna, dna)) {
        return RegisterResult::INVALID_DNA;
    }

    bool dimensionsChanged = false;
    if (oldDna) {
        dimensionsChanged = core_dimensions_changed(*oldDna, dna);
    }

    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    auto data = dna.serialize();
    std::string value(data.begin(), data.end());

    leveldb::WriteBatch batch;
    batch.Put(key, value);

    std::array<uint8_t, 20> zero_mik{};
    if (dna.mik_identity != zero_mik) {
        batch.Put(make_mik_key(dna.mik_identity), value);
        mik_to_address_[dna.mik_identity] = dna.address;

        if (oldDna) {
            std::string histPrefix = HIST_KEY_PREFIX + address_to_hex(dna.mik_identity) + ":";
            // Evict oldest entries BEFORE adding new one so post-write count <= cap.
            evict_old_history(db_.get(), batch, histPrefix, IDNARegistry::MAX_HISTORY_PER_MIK);

            // Write history entry for the OLD DNA being superseded.
            // Timestamp key ensures lexicographic (chronological) order.
            std::string histKey = make_hist_key(dna.mik_identity, now);
            batch.Put(histKey, existing);
        }
    }

    status = db_->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) return RegisterResult::DB_ERROR;

    cache_[dna.address] = dna;
    return dimensionsChanged ? RegisterResult::DNA_CHANGED : RegisterResult::UPDATED;
}

IDNARegistry::RegisterResult DNARegistryDB::update_identity(const DigitalDNA& dna) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return RegisterResult::DB_ERROR;
    if (!dna.is_valid) return RegisterResult::INVALID_DNA;

    // Must already be registered
    std::string key = make_key(dna.address);
    std::string existing;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &existing);
    if (!status.ok()) {
        return RegisterResult::INVALID_DNA;  // Not registered yet
    }

    // Archive the previous DNA as history before overwriting
    auto oldDna = DigitalDNA::deserialize(
        std::vector<uint8_t>(existing.begin(), existing.end()));

    // Phase 5: Detect core dimension changes
    bool dimensionsChanged = false;
    if (oldDna) {
        dimensionsChanged = core_dimensions_changed(*oldDna, dna);
    }

    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    // Overwrite with enriched version — dual-key write + history
    auto data = dna.serialize();
    std::string value(data.begin(), data.end());

    leveldb::WriteBatch batch;
    batch.Put(key, value);

    std::array<uint8_t, 20> zero_mik{};
    if (dna.mik_identity != zero_mik) {
        batch.Put(make_mik_key(dna.mik_identity), value);
        mik_to_address_[dna.mik_identity] = dna.address;

        // Write history entry for the OLD DNA being superseded
        if (oldDna) {
            std::string histKey = make_hist_key(dna.mik_identity, now);
            batch.Put(histKey, existing);  // existing = serialized old DNA
        }
    }

    status = db_->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        return RegisterResult::DB_ERROR;
    }

    cache_[dna.address] = dna;
    return dimensionsChanged ? RegisterResult::DNA_CHANGED : RegisterResult::UPDATED;
}

bool DNARegistryDB::is_registered(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check cache first
    if (cache_.find(address) != cache_.end()) return true;

    // Check DB
    if (!db_) return false;
    std::string key = make_key(address);
    std::string value;
    return db_->Get(leveldb::ReadOptions(), key, &value).ok();
}

std::optional<DigitalDNA> DNARegistryDB::get_identity(const std::array<uint8_t, 20>& address) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check cache first
    auto it = cache_.find(address);
    if (it != cache_.end()) return it->second;

    // Check DB
    if (!db_) return std::nullopt;
    std::string key = make_key(address);
    std::string value;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) return std::nullopt;

    std::vector<uint8_t> data(value.begin(), value.end());
    return DigitalDNA::deserialize(data);
}

std::optional<DigitalDNA> DNARegistryDB::get_identity_by_mik(const std::array<uint8_t, 20>& mik) const {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check MIK-to-address index first
    auto idx = mik_to_address_.find(mik);
    if (idx != mik_to_address_.end()) {
        auto it = cache_.find(idx->second);
        if (it != cache_.end()) return it->second;
    }

    // Fallback: scan cache for matching mik_identity
    for (const auto& [addr, dna] : cache_) {
        if (dna.mik_identity == mik) return dna;
    }

    // Check DB via MIK key
    if (!db_) return std::nullopt;
    std::string key = make_mik_key(mik);
    std::string value;
    leveldb::Status status = db_->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) return std::nullopt;

    std::vector<uint8_t> data(value.begin(), value.end());
    return DigitalDNA::deserialize(data);
}

std::vector<std::pair<DigitalDNA, SimilarityScore>> DNARegistryDB::find_similar(
    const DigitalDNA& dna,
    double threshold
) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::pair<DigitalDNA, SimilarityScore>> results;

    for (const auto& [addr, other] : cache_) {
        if (addr == dna.address) continue;

        auto score = compare(dna, other);
        if (score.combined_score >= threshold) {
            results.push_back({other, score});
        }
    }

    std::sort(results.begin(), results.end(),
        [](const auto& a, const auto& b) {
            return a.second.combined_score > b.second.combined_score;
        });

    return results;
}

SimilarityScore DNARegistryDB::compare(const DigitalDNA& a, const DigitalDNA& b) const {
    SimilarityScore score;

    // Core v2.0 dimensions.
    // Latency is scored only when the two fingerprints share at least one
    // comparable seed — see SimilarityScore::has_latency. This path and
    // DigitalDNARegistry::compare must stay in step: they feed the SAME
    // compute_combined_score, so a gate applied in one and not the other means
    // the persistent registry and the in-memory one disagree about a Sybil.
    score.has_latency = LatencyFingerprint::comparable_seed_count(a.latency, b.latency) > 0;
    score.latency_similarity = score.has_latency
        ? calculate_latency_similarity(a.latency, b.latency)
        : 0.0;
    score.timing_similarity = calculate_timing_similarity(a.timing, b.timing);
    score.perspective_similarity = calculate_perspective_similarity(a.perspective, b.perspective);

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

    return DigitalDNARegistry::compute_combined_score(score);
}

std::vector<DigitalDNA> DNARegistryDB::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DigitalDNA> result;
    result.reserve(cache_.size());
    for (const auto& [addr, dna] : cache_) {
        result.push_back(dna);
    }
    return result;
}

size_t DNARegistryDB::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

bool DNARegistryDB::remove_identity(const std::array<uint8_t, 20>& address) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return false;

    // Remove MIK key if we have the identity cached
    auto it = cache_.find(address);
    if (it != cache_.end()) {
        std::array<uint8_t, 20> zero_mik{};
        if (it->second.mik_identity != zero_mik) {
            db_->Delete(leveldb::WriteOptions(), make_mik_key(it->second.mik_identity));
            mik_to_address_.erase(it->second.mik_identity);
        }
    }

    std::string key = make_key(address);
    leveldb::Status status = db_->Delete(leveldb::WriteOptions(), key);

    cache_.erase(address);

    return status.ok();
}

std::vector<std::pair<uint64_t, DigitalDNA>> DNARegistryDB::get_dna_history(
    const std::array<uint8_t, 20>& mik, size_t max_entries) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::pair<uint64_t, DigitalDNA>> result;
    if (!db_) return result;

    // Scan all history keys for this MIK: dna_hist:<mik_hex>:
    std::string prefix = HIST_KEY_PREFIX + address_to_hex(mik) + ":";
    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));

    for (it->Seek(prefix); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, prefix.size()) != prefix) break;

        // Extract timestamp from key suffix (16 hex chars)
        std::string ts_hex = key.substr(prefix.size());
        uint64_t timestamp = 0;
        sscanf(ts_hex.c_str(), "%" SCNx64, &timestamp);

        std::string value = it->value().ToString();
        std::vector<uint8_t> data(value.begin(), value.end());
        auto dna = DigitalDNA::deserialize(data);
        if (dna) {
            result.push_back({timestamp, *dna});
        }

        if (result.size() >= max_entries) break;
    }

    return result;  // Already sorted chronologically (lexicographic key order)
}

void DNARegistryDB::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!db_) return;

    // Delete all entries with dna: and dna_mik: prefixes
    leveldb::WriteBatch batch;
    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(KEY_PREFIX); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        // Both "dna:" and "dna_mik:" keys are in lexicographic range starting at "dna:"
        if (key.substr(0, 3) != "dna") break;
        batch.Delete(key);
    }
    db_->Write(leveldb::WriteOptions(), &batch);

    cache_.clear();
    mik_to_address_.clear();
}

// --- Private helpers ---

std::string DNARegistryDB::make_key(const std::array<uint8_t, 20>& address) const {
    return KEY_PREFIX + address_to_hex(address);
}

std::string DNARegistryDB::make_mik_key(const std::array<uint8_t, 20>& mik) const {
    return MIK_KEY_PREFIX + address_to_hex(mik);
}

std::string DNARegistryDB::make_hist_key(const std::array<uint8_t, 20>& mik, uint64_t timestamp) const {
    // Format: dna_hist:<mik_hex>:<timestamp_hex_16_chars>
    // Zero-padded timestamp ensures lexicographic = chronological ordering
    char ts[17];
    snprintf(ts, sizeof(ts), "%016" PRIx64, timestamp);
    return HIST_KEY_PREFIX + address_to_hex(mik) + ":" + ts;
}

std::string DNARegistryDB::address_to_hex(const std::array<uint8_t, 20>& addr) {
    std::ostringstream oss;
    for (auto b : addr) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

void DNARegistryDB::load_cache() const {
    if (!db_) return;

    cache_.clear();
    mik_to_address_.clear();

    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(KEY_PREFIX); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, KEY_PREFIX.size()) != KEY_PREFIX) break;
        // Skip MIK keys (they start with "dna_mik:" which is > "dna:" lexicographically)
        if (key.substr(0, MIK_KEY_PREFIX.size()) == MIK_KEY_PREFIX) continue;

        std::string value = it->value().ToString();
        std::vector<uint8_t> data(value.begin(), value.end());
        auto dna = DigitalDNA::deserialize(data);
        if (dna) {
            cache_[dna->address] = *dna;
            // Build MIK index
            std::array<uint8_t, 20> zero_mik{};
            if (dna->mik_identity != zero_mik) {
                mik_to_address_[dna->mik_identity] = dna->address;
            }
        }

        if (cache_.size() >= MAX_CACHE_SIZE) break;
    }
}

double DNARegistryDB::calculate_latency_similarity(
    const LatencyFingerprint& a, const LatencyFingerprint& b
) const {
    return latency_similarity(a, b);
}

double DNARegistryDB::calculate_timing_similarity(
    const TimingSignature& a, const TimingSignature& b
) const {
    return timing_similarity(a, b);
}

double DNARegistryDB::calculate_perspective_similarity(
    const PerspectiveProof& a, const PerspectiveProof& b
) const {
    return perspective_similarity(a, b);
}

// --- ML Detector Integration ---

void DNARegistryDB::set_ml_detector(std::shared_ptr<MLSybilDetector> detector) {
    std::lock_guard<std::mutex> lock(mutex_);
    ml_detector_ = std::move(detector);
}

std::string DNARegistryDB::ml_status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ml_detector_) return "{\"status\": \"not_configured\"}";
    return ml_detector_->status_json();
}

// --- Attestation Storage (Phase 2: Verification) ---

std::string DNARegistryDB::make_att_key(const std::array<uint8_t, 20>& target_mik,
                                         const std::array<uint8_t, 20>& verifier_mik,
                                         uint32_t height) const {
    char h[9];
    snprintf(h, sizeof(h), "%08x", height);
    return ATT_KEY_PREFIX + address_to_hex(target_mik) + ":" + address_to_hex(verifier_mik) + ":" + h;
}

bool DNARegistryDB::store_attestation(const verification::DNAAttestation& attestation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return false;

    std::string key = make_att_key(attestation.target_mik, attestation.verifier_mik,
                                    attestation.registration_height);
    auto data = attestation.serialize();
    std::string value(data.begin(), data.end());

    leveldb::Status status = db_->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

std::vector<verification::DNAAttestation> DNARegistryDB::get_attestations(
    const std::array<uint8_t, 20>& target_mik) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<verification::DNAAttestation> result;
    if (!db_) return result;

    std::string prefix = ATT_KEY_PREFIX + address_to_hex(target_mik) + ":";
    std::unique_ptr<leveldb::Iterator> it(db_->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(prefix); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.substr(0, prefix.size()) != prefix) break;

        std::string value = it->value().ToString();
        std::vector<uint8_t> data(value.begin(), value.end());
        auto att = verification::DNAAttestation::deserialize(data);
        if (att) {
            result.push_back(std::move(*att));
        }

        if (result.size() >= 100) break;  // Safety cap
    }
    return result;
}

size_t DNARegistryDB::count_pass_attestations(const std::array<uint8_t, 20>& target_mik) const {
    auto atts = get_attestations(target_mik);
    size_t pass_count = 0;
    for (const auto& att : atts) {
        if (att.overall_pass) pass_count++;
    }
    return pass_count;
}

verification::VerificationStatus DNARegistryDB::get_verification_status(
    const std::array<uint8_t, 20>& mik) const {
    auto atts = get_attestations(mik);
    if (atts.empty()) return verification::VerificationStatus::UNVERIFIED;

    size_t pass_count = 0;
    size_t fail_count = 0;
    for (const auto& att : atts) {
        if (att.overall_pass) pass_count++;
        else fail_count++;
    }

    if (pass_count >= verification::ATTESTATION_QUORUM)
        return verification::VerificationStatus::VERIFIED;
    if (fail_count > verification::VERIFIER_COUNT / 2)
        return verification::VerificationStatus::FAILED;
    return verification::VerificationStatus::PENDING;
}

std::vector<std::array<uint8_t, 20>> DNARegistryDB::get_all_miks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::array<uint8_t, 20>> result;
    result.reserve(mik_to_address_.size());
    for (const auto& [mik, addr] : mik_to_address_) {
        result.push_back(mik);
    }
    return result;
}

} // namespace digital_dna
