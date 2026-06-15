/**
 * Digital DNA v3.0 - Anonymous Sybil-Resistant Identity System
 *
 * Combines eight unforgeable identity dimensions:
 *   L  - Latency Fingerprint (geographic location via RTT)
 *   V  - VDF Timing Signature (hardware fingerprint via computation speed)
 *   P  - Perspective Proof (network vantage point via peer observations)
 *   M  - Memory Fingerprint (cache hierarchy probing)
 *   D  - Clock Drift (crystal oscillator uniqueness)
 *   B  - Bandwidth Proof (network throughput measurement)
 *   T  - Thermal Profile (cooling curve from VDF checkpoints)
 *   BP - Behavioral Profile (protocol participation patterns)
 *
 * Key properties:
 *   - Anonymous: No KYC, no trusted hardware, no personal data
 *   - Unforgeable: Based on physics (speed of light, computation time)
 *   - Verifiable: Third parties can validate claims
 *   - Sybil-resistant: Similar identities flagged for additional verification
 *   - Data-driven: Equal-weight bootstrap, ML calibration, then ML-primary
 */

#ifndef DILITHION_DIGITAL_DNA_H
#define DILITHION_DIGITAL_DNA_H

#include "latency_fingerprint.h"
#include "timing_signature.h"
#include "perspective_proof.h"
#include "memory_fingerprint.h"
#include "clock_drift.h"
#include "bandwidth_proof.h"
#include "behavioral_profile.h"

#include <array>
#include <cmath>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <functional>
#include <thread>

namespace digital_dna {

// Forward declarations
class CConnman;  // Peer manager (from net.h)

/**
 * Complete Digital DNA identity.
 *
 * This is the unforgeable identity that proves a miner is unique.
 */
struct DigitalDNA {
    // Core identity components (v2.0)
    LatencyFingerprint latency;         // L: Geographic fingerprint
    TimingSignature timing;             // V: Hardware fingerprint
    PerspectiveProof perspective;       // P: Network vantage point

    // Extended dimensions (v3.0 — optional for backward compat)
    std::optional<MemoryFingerprint> memory;           // M: Cache hierarchy
    std::optional<ClockDriftFingerprint> clock_drift;  // D: Oscillator uniqueness
    std::optional<BandwidthFingerprint> bandwidth;     // B: Throughput measurement
    std::optional<ThermalProfile> thermal;             // T: Cooling curve
    std::optional<BehavioralProfile> behavioral;       // BP: Protocol patterns

    // Metadata
    std::array<uint8_t, 20> address;    // Coinbase address (legacy key)
    std::array<uint8_t, 20> mik_identity{}; // MIK identity (primary key — persistent across address rotation)
    uint32_t registration_height;       // Block height when registered
    uint64_t registration_time;         // Unix timestamp

    // Verification status (Phase 2: peer attestation)
    uint8_t verification_status = 0;  // 0=UNVERIFIED, 1=PENDING, 2=VERIFIED, 3=FAILED

    // Validation state
    bool is_valid = false;
    std::string validation_error;

    // Serialization
    std::string to_json() const;
    std::vector<uint8_t> serialize() const;
    static std::optional<DigitalDNA> deserialize(const std::vector<uint8_t>& data);

    // Compute 32-byte identity hash
    std::array<uint8_t, 32> hash() const;
};

/**
 * Similarity score between two Digital DNA identities.
 */
struct SimilarityScore {
    // Per-dimension scores (0.0 = different, 1.0 = identical)
    double latency_similarity = 0.0;       // L: RTT fingerprint
    double timing_similarity = 0.0;        // V: VDF speed
    double perspective_similarity = 0.0;   // P: Peer set Jaccard
    double memory_similarity = 0.0;        // M: Cache hierarchy DTW
    double clock_drift_similarity = 0.0;   // D: Oscillator drift
    double bandwidth_similarity = 0.0;     // B: Throughput profile
    double thermal_similarity = 0.0;       // T: Cooling curve
    double behavioral_similarity = 0.0;    // BP: Activity patterns

    // Data availability flags (0.0 is a valid score — "completely different")
    bool has_perspective = true;   // Core dim, but false when peer data unavailable
    bool has_memory = false;
    bool has_clock_drift = false;
    bool has_bandwidth = false;
    bool has_thermal = false;
    bool has_behavioral = false;

    double combined_score = 0.0;           // Equal-weight average of available dimensions

    // How many dimensions were available for scoring
    uint32_t dimensions_scored = 0;

    // v3.0 thresholds (conservative bootstrap — will be refined by ML)
    static constexpr double SAME_IDENTITY_THRESHOLD = 0.92;   // Auto-reject
    static constexpr double SUSPICIOUS_THRESHOLD = 0.55;      // Trigger challenge

    // Physics-justified hard rule: if both Memory AND Clock Drift > 0.95,
    // probability of two distinct machines matching both is vanishingly small
    static constexpr double PHYSICS_HARD_THRESHOLD = 0.95;

    bool is_same_identity() const {
        // Hard physics rule: Memory + Clock Drift both extremely high → auto-reject
        if (memory_similarity >= PHYSICS_HARD_THRESHOLD &&
            clock_drift_similarity >= PHYSICS_HARD_THRESHOLD) {
            return true;
        }
        return combined_score >= SAME_IDENTITY_THRESHOLD;
    }

    bool is_suspicious() const { return combined_score >= SUSPICIOUS_THRESHOLD; }

    std::string verdict() const;
};

/**
 * IDNARegistry - Common interface for Digital DNA registries.
 *
 * Abstracts the registry backend so RPC and node code don't depend
 * on whether identities are stored in memory (unit tests) or LevelDB (production).
 */
class IDNARegistry {
public:
    virtual ~IDNARegistry() = default;

    enum class RegisterResult {
        SUCCESS,
        ALREADY_REGISTERED,
        SYBIL_FLAGGED,      // Advisory: stored but flagged
        SYBIL_REJECTED,     // Enforcement: rejected, NOT stored (Phase 2A)
        UPDATED,             // Progressive enrichment: existing record updated
        DNA_CHANGED,         // Identity updated with core dimension changes
        INVALID_DNA,
        DB_ERROR
    };

    virtual RegisterResult register_identity(const DigitalDNA& dna) = 0;
    virtual RegisterResult update_identity(const DigitalDNA& dna) = 0;

    /**
     * Accept a continuous-sampling DNA update (Phase 1 propagation fix).
     *
     *   - If MIK is not yet registered, delegates to register_identity().
     *   - Otherwise, archives the existing canonical DNA into the per-MIK
     *     history keyspace (capped at MAX_HISTORY_PER_MIK) and writes the
     *     new DNA as the canonical record.
     *   - REJECTS (returns INVALID_DNA) if the incoming sample would *remove*
     *     populated dimensions from the current record. Dimensions may change
     *     value, may add, but may not silently disappear.
     *
     * This is the entry point for receiver-side acceptance of peer-broadcast
     * samples after rate-limit / plausibility checks. `update_identity` is
     * kept for callers that want the legacy semantics (strict "must already
     * be registered" contract, no dimension-loss guard).
     */
    virtual RegisterResult append_sample(const DigitalDNA& dna) = 0;

    /** Maximum history entries retained per MIK before oldest is evicted. */
    static constexpr size_t MAX_HISTORY_PER_MIK = 100;

    virtual bool is_registered(const std::array<uint8_t, 20>& address) const = 0;
    virtual std::optional<DigitalDNA> get_identity(const std::array<uint8_t, 20>& address) const = 0;
    virtual std::optional<DigitalDNA> get_identity_by_mik(const std::array<uint8_t, 20>& mik) const = 0;
    virtual std::vector<std::pair<DigitalDNA, SimilarityScore>> find_similar(
        const DigitalDNA& dna,
        double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD) const = 0;
    virtual SimilarityScore compare(const DigitalDNA& a, const DigitalDNA& b) const = 0;
    virtual std::vector<DigitalDNA> get_all() const = 0;
    virtual size_t count() const = 0;

    /** Phase 1.2 — DNA propagation: return all MIKs known to this registry.
     *  Used as the primary source for the discovery-request loop so DIL
     *  (RandomX, no VDF-gated cooldown tracker) can find peers to ask. */
    virtual std::vector<std::array<uint8_t, 20>> get_all_miks() const = 0;

    /** Get DNA change history for a MIK identity (oldest first).
     *  Each entry is a previous DNA snapshot archived when update_identity() was called.
     *  Single change = likely new hardware/location. Multiple regular changes = suspicious. */
    virtual std::vector<std::pair<uint64_t, DigitalDNA>> get_dna_history(
        const std::array<uint8_t, 20>& mik, size_t max_entries = 100) const = 0;
};

/**
 * Digital DNA collector.
 *
 * Collects all identity components and creates a DigitalDNA proof.
 */
class DigitalDNACollector {
public:
    struct Config {
        // Latency config
        uint32_t latency_samples;
        uint32_t latency_timeout_ms;

        // Timing config
        uint64_t timing_iterations;
        uint64_t timing_checkpoint_interval;

        // Perspective config
        uint32_t perspective_duration_sec;
        uint32_t perspective_min_peers;

        // v3.0 local dimensions
        bool collect_memory = true;
        bool collect_thermal = true;
        bool testnet = false;

        Config()
            : latency_samples(20)
            , latency_timeout_ms(5000)
            , timing_iterations(1'000'000)
            , timing_checkpoint_interval(10'000)
            , perspective_duration_sec(3600)
            , perspective_min_peers(4)
        {}
    };

    explicit DigitalDNACollector(const std::array<uint8_t, 20>& address, const Config& config = Config());
    ~DigitalDNACollector();

    // Set MIK identity (call before start_collection or after MIK is generated)
    void set_mik_identity(const std::array<uint8_t, 20>& mik) { mik_identity_ = mik; }

    // Start/stop collection
    void start_collection();
    void stop_collection();
    bool is_collecting() const { return collecting_; }

    // Progress (0.0 to 1.0)
    double get_progress() const;

    // Get collected DNA (only valid after latency + timing complete)
    std::optional<DigitalDNA> get_dna() const;

    // Cheap accessor: the own 20-byte address + readiness, WITHOUT building/copying
    // the full DigitalDNA. get_dna() deep-copies ~440KB (clock-drift sample vector,
    // perspective snapshots, bandwidth, behavioral); callers that need only the
    // address — e.g. the per-block-connect block-relay-credit check — MUST use this.
    // Calling get_dna() on the hot connect path churned the allocator at DilV's
    // block rate and fragmented the glibc arenas → OOM after 1–2 days (fix 2026-06-15).
    std::optional<std::array<uint8_t, 20>> get_address_if_ready() const;

    // Peer hooks (call from peer manager)
    void on_peer_connected(const std::array<uint8_t, 20>& peer_id);
    void on_peer_disconnected(const std::array<uint8_t, 20>& peer_id);

    // Behavioral profile hooks (Phase 3)
    void on_block_received(uint32_t height);
    void on_tx_relayed(uint64_t timestamp_ms);

    // Clock drift hooks (Phase 4 P2P)
    void on_time_sync_response(const std::array<uint8_t, 20>& peer_id,
        uint64_t local_send_us, uint64_t peer_timestamp_us, uint64_t local_recv_us);
    ClockDriftCollector& get_clock_drift_collector() { return clock_drift_collector_; }

    // Bandwidth measurement hooks (Phase 4 P2P)
    void on_bandwidth_result(const std::array<uint8_t, 20>& peer_id,
        double upload_mbps, double download_mbps);
    BandwidthProofCollector& get_bandwidth_collector() { return bandwidth_collector_; }

private:
    std::array<uint8_t, 20> address_;
    std::array<uint8_t, 20> mik_identity_{};
    Config config_;
    bool collecting_ = false;

    // Core collectors
    LatencyFingerprintCollector latency_collector_;
    TimingSignatureCollector timing_collector_;
    PerspectiveCollector perspective_collector_;

    // v3.0 local dimension collectors
    MemoryFingerprintCollector memory_collector_;
    BehavioralProfileCollector behavioral_collector_;

    // v3.0 P2P dimension collectors (fed by P2P message handlers)
    ClockDriftCollector clock_drift_collector_;
    BandwidthProofCollector bandwidth_collector_;

    // Background collection thread
    std::thread collection_thread_;

    // Results
    std::optional<LatencyFingerprint> latency_result_;
    std::optional<TimingSignature> timing_result_;
    std::optional<PerspectiveProof> perspective_result_;
    std::optional<MemoryFingerprint> memory_result_;
    std::optional<ThermalProfile> thermal_result_;
};

/**
 * Digital DNA registry (in-memory, implements IDNARegistry).
 *
 * Used for unit tests and as a simple registry backend.
 * For production use DNARegistryDB (LevelDB-backed).
 */
class DigitalDNARegistry : public IDNARegistry {
public:
    DigitalDNARegistry();

    // IDNARegistry implementation
    RegisterResult register_identity(const DigitalDNA& dna) override;
    RegisterResult update_identity(const DigitalDNA& dna) override;
    RegisterResult append_sample(const DigitalDNA& dna) override;
    bool is_registered(const std::array<uint8_t, 20>& address) const override;
    std::optional<DigitalDNA> get_identity(const std::array<uint8_t, 20>& address) const override;
    std::optional<DigitalDNA> get_identity_by_mik(const std::array<uint8_t, 20>& mik) const override;
    std::vector<std::pair<DigitalDNA, SimilarityScore>> find_similar(
        const DigitalDNA& dna,
        double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD
    ) const override;
    SimilarityScore compare(const DigitalDNA& a, const DigitalDNA& b) const override;
    std::vector<DigitalDNA> get_all() const override;
    size_t count() const override { return identities_.size(); }
    std::vector<std::array<uint8_t, 20>> get_all_miks() const override;
    std::vector<std::pair<uint64_t, DigitalDNA>> get_dna_history(
        const std::array<uint8_t, 20>& mik, size_t max_entries = 100) const override;

    // Persistence (flat file — for tests / backward compat)
    bool save(const std::string& path) const;
    bool load(const std::string& path);

    // v3.0 equal-weight scoring across all available dimensions
    static SimilarityScore compute_combined_score(SimilarityScore score);

private:
    std::vector<DigitalDNA> identities_;

    // Similarity calculation (core v2.0 dimensions)
    double calculate_latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b) const;
    double calculate_timing_similarity(const TimingSignature& a, const TimingSignature& b) const;
    double calculate_perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b) const;
};

/**
 * Utility functions
 */

// Compute similarity between two latency fingerprints
// Returns 1.0 if identical, 0.0 if completely different
double latency_similarity(const LatencyFingerprint& a, const LatencyFingerprint& b);

// Compute similarity between two timing signatures
// Based on progress rate comparison
double timing_similarity(const TimingSignature& a, const TimingSignature& b);

// Compute similarity between two perspective proofs
// Uses Jaccard similarity of peer sets
double perspective_similarity(const PerspectiveProof& a, const PerspectiveProof& b);

// Get mainnet seed nodes
const std::array<SeedNode, 4>& get_mainnet_seeds();

// Get testnet seed nodes
const std::array<SeedNode, 3>& get_testnet_seeds();

// Returns true if core identity dimensions changed meaningfully
// (not just registration_height/timestamp enrichment)
inline bool core_dimensions_changed(const DigitalDNA& old_dna, const DigitalDNA& new_dna) {
    // Timing: >10% change in IPS → hardware change
    if (old_dna.timing.iterations_per_second > 0 && new_dna.timing.iterations_per_second > 0) {
        double ratio = new_dna.timing.iterations_per_second / old_dna.timing.iterations_per_second;
        if (ratio < 0.9 || ratio > 1.1) return true;
    }

    // Latency: median changed by >20ms on any seed → location change
    size_t min_seeds = std::min(old_dna.latency.seed_stats.size(), new_dna.latency.seed_stats.size());
    for (size_t i = 0; i < min_seeds; i++) {
        double diff = std::abs(old_dna.latency.seed_stats[i].median_ms - new_dna.latency.seed_stats[i].median_ms);
        if (diff > 20.0) return true;
    }

    return false;
}

/**
 * Phase 1.1 merge helper — "fill-only" merge for propagation from unmapped peers.
 *
 * Starts from `existing` (the canonical record we already trust) and fills in
 * ONLY dimensions that are currently unpopulated, taking each filled value
 * from `incoming`. Core fields (address, mik_identity, latency, timing,
 * registration_{height,time}) are always preserved from `existing`.
 *
 * This preserves data provenance: an unmapped peer can help us fill missing
 * dimensions (beneficial — improves coverage) but cannot overwrite existing
 * values (which would allow a relay peer to pollute readings claimed by the
 * miner). The mapped-peer path in the receiver continues to accept full
 * replacements for trust-equivalent updates.
 *
 * If `filled_count_out` is non-null, it is set to the number of dimensions
 * this call actually filled (0 means nothing to do — caller should drop).
 *
 * Populated predicates match the coverage counters used elsewhere:
 *   - optional<T>: populated iff engaged
 *   - perspective: populated iff total_unique_peers() > 0 OR snapshots non-empty
 *   - latency/timing: always "populated" (core), never merged from incoming
 */
inline DigitalDNA merge_fill_missing_dims(const DigitalDNA& existing,
                                          const DigitalDNA& incoming,
                                          int* filled_count_out = nullptr) {
    DigitalDNA merged = existing;
    int filled = 0;

    if (!existing.memory && incoming.memory) {
        merged.memory = incoming.memory;
        ++filled;
    }
    if (!existing.clock_drift && incoming.clock_drift) {
        merged.clock_drift = incoming.clock_drift;
        ++filled;
    }
    if (!existing.bandwidth && incoming.bandwidth) {
        merged.bandwidth = incoming.bandwidth;
        ++filled;
    }
    if (!existing.thermal && incoming.thermal) {
        merged.thermal = incoming.thermal;
        ++filled;
    }
    if (!existing.behavioral && incoming.behavioral) {
        merged.behavioral = incoming.behavioral;
        ++filled;
    }
    // Perspective is not optional<T> but has a populated predicate.
    bool existing_has_perspective = (existing.perspective.total_unique_peers() > 0
                                     || !existing.perspective.snapshots.empty());
    bool incoming_has_perspective = (incoming.perspective.total_unique_peers() > 0
                                     || !incoming.perspective.snapshots.empty());
    if (!existing_has_perspective && incoming_has_perspective) {
        merged.perspective = incoming.perspective;
        ++filled;
    }

    if (filled_count_out) *filled_count_out = filled;
    return merged;
}

/**
 * Phase 1.5: merge an authenticated (signed) sample with the existing
 * canonical record, treating the signed sample as the source of truth for
 * any dimension it asserts.
 *
 * Per dim:
 *   - If incoming has the dim populated → use incoming's value (signed
 *     assertion from the MIK holder is authoritative).
 *   - Else → keep existing's value (preserves dims the MIK doesn't assert
 *     this round, which may have been enriched from other peers).
 *
 * The merged result always has at least the dim count of `existing`, so the
 * dim-loss guard in `append_sample` never trips for signed traffic. This
 * lets a miner who currently collects only a subset of dims still publish
 * authoritative updates for the ones they DO collect, without losing the
 * network's accumulated knowledge of the dims they don't.
 *
 * Trust-model note: the MIK can update dims they assert, but cannot delete
 * dims they don't assert. They could already publish wrong values for dims
 * they assert (no defense against a dishonest MIK on its own data). The
 * per-dim provenance refinement (which would, for example, defer to the
 * receiver's own latency/bandwidth measurements over the MIK's claim) is
 * deferred to a Phase 2 spec with explicit Cursor design review.
 */
inline DigitalDNA merge_authoritative_dims(const DigitalDNA& existing,
                                           const DigitalDNA& incoming) {
    // Start from incoming. Core dims (latency, timing, identity, address) are
    // always present on a valid DigitalDNA, so they take incoming's values
    // unconditionally — that's the "authoritative for what's asserted" rule.
    DigitalDNA merged = incoming;

    // Optional dims: if incoming didn't assert, fall back to existing.
    if (!incoming.memory      && existing.memory)      merged.memory      = existing.memory;
    if (!incoming.clock_drift && existing.clock_drift) merged.clock_drift = existing.clock_drift;
    if (!incoming.bandwidth   && existing.bandwidth)   merged.bandwidth   = existing.bandwidth;
    if (!incoming.thermal     && existing.thermal)     merged.thermal     = existing.thermal;
    if (!incoming.behavioral  && existing.behavioral)  merged.behavioral  = existing.behavioral;

    // Perspective: same predicate as merge_fill_missing_dims uses.
    bool incoming_has_perspective = (incoming.perspective.total_unique_peers() > 0
                                     || !incoming.perspective.snapshots.empty());
    bool existing_has_perspective = (existing.perspective.total_unique_peers() > 0
                                     || !existing.perspective.snapshots.empty());
    if (!incoming_has_perspective && existing_has_perspective) {
        merged.perspective = existing.perspective;
    }

    return merged;
}

} // namespace digital_dna

#endif // DILITHION_DIGITAL_DNA_H
