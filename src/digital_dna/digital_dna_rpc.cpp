/**
 * Digital DNA RPC Implementation
 */

#include "digital_dna_rpc.h"
#include "dna_verification.h"
#include "dna_registry_db.h"
#include "verification_manager.h"
#include <core/node_context.h>
#include <vdf/cooldown_tracker.h>
#include <wallet/wallet.h>
#include <util/base58.h>
#include <net/peers.h>
#include <net/connman.h>
#include <net/node.h>

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <memory>

// Forward-declared in node_context.h
extern NodeContext g_node_context;

// Legacy global node state (wallet lives here, not in NodeContext)
// Layout must match globals.cpp / dilithion-node.cpp exactly
struct NodeState {
    std::atomic<bool> running;
    std::atomic<bool> new_block_found;
    std::atomic<bool> mining_enabled;
    std::atomic<uint64_t> template_version{0};
    std::string mining_address_override;
    bool rotate_mining_address;
    void* rpc_server;
    void* miner;
    CWallet* wallet;
    void* p2p_socket;
    void* http_server;
};
extern NodeState g_node_state;

namespace digital_dna {

static std::array<uint8_t, 20> g_my_address = {};

DigitalDNARpc::DigitalDNARpc(IDNARegistry& registry)
    : registry_(registry) {}

void DigitalDNARpc::register_commands() {
    handlers_["getmydigitaldna"] = [this](const JsonObject& p) { return cmd_getmydigitaldna(p); };
    handlers_["registerdigitaldna"] = [this](const JsonObject& p) { return cmd_registerdigitaldna(p); };
    handlers_["getdigitaldna"] = [this](const JsonObject& p) { return cmd_getdigitaldna(p); };
    handlers_["comparedigitaldna"] = [this](const JsonObject& p) { return cmd_comparedigitaldna(p); };
    handlers_["findsimilaridentities"] = [this](const JsonObject& p) { return cmd_findsimilaridentities(p); };
    handlers_["listdigitaldna"] = [this](const JsonObject& p) { return cmd_listdigitaldna(p); };
    handlers_["getdigitaldnastats"] = [this](const JsonObject& p) { return cmd_getdigitaldnastats(p); };
    handlers_["collectdigitaldna"] = [this](const JsonObject& p) { return cmd_collectdigitaldna(p); };
    handlers_["validatedigitaldna"] = [this](const JsonObject& p) { return cmd_validatedigitaldna(p); };
    handlers_["getlatencyfingerprint"] = [this](const JsonObject& p) { return cmd_getlatencyfingerprint(p); };
    handlers_["gettimingsignature"] = [this](const JsonObject& p) { return cmd_gettimingsignature(p); };
    handlers_["getperspectiveproof"] = [this](const JsonObject& p) { return cmd_getperspectiveproof(p); };
    handlers_["dumpdigitaldna"] = [this](const JsonObject& p) { return cmd_dumpdigitaldna(p); };
    handlers_["getdigitaldnahistory"] = [this](const JsonObject& p) { return cmd_getdigitaldnahistory(p); };
    handlers_["getdnamonitor"] = [this](const JsonObject& p) { return cmd_getdnamonitor(p); };
    // Phase 2: DNA Verification & Attestation
    handlers_["getverificationstatus"] = [this](const JsonObject& p) { return cmd_getverificationstatus(p); };
    handlers_["listattestations"] = [this](const JsonObject& p) { return cmd_listattestations(p); };
    handlers_["getverificationconfig"] = [this](const JsonObject& p) { return cmd_getverificationconfig(p); };
    // Phase 4: Peer trust scoring
    handlers_["getpeertrust"] = [this](const JsonObject& p) { return cmd_getpeertrust(p); };
}

RpcHandler DigitalDNARpc::get_handler(const std::string& method) const {
    auto it = handlers_.find(method);
    if (it != handlers_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> DigitalDNARpc::list_commands() const {
    std::vector<std::string> cmds;
    for (const auto& [name, _] : handlers_) {
        cmds.push_back(name);
    }
    std::sort(cmds.begin(), cmds.end());
    return cmds;
}

JsonObject DigitalDNARpc::execute(const std::string& method, const JsonObject& params) {
    auto handler = get_handler(method);
    if (!handler) {
        return error(-32601, "Method not found: " + method);
    }
    return handler(params);
}

void DigitalDNARpc::set_my_address(const std::array<uint8_t, 20>& address) {
    g_my_address = address;
}

std::shared_ptr<DigitalDNACollector> DigitalDNARpc::get_collector() {
    return g_node_context.GetDNACollector();
}

void DigitalDNARpc::set_collector(std::shared_ptr<DigitalDNACollector> collector) {
    g_node_context.SetDNACollector(std::move(collector));
}

// ============ Command Implementations ============

JsonObject DigitalDNARpc::cmd_getmydigitaldna(const JsonObject& params) {
    // Get this node's collected Digital DNA
    auto collector = g_node_context.GetDNACollector();
    if (!collector) {
        return error(-1, "Digital DNA not collected yet. Run 'collectdigitaldna start' first.");
    }

    auto dna = collector->get_dna();
    if (!dna) {
        JsonObject result;
        result["status"] = "collecting";
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << (collector->get_progress() * 100);
        result["progress"] = oss.str() + "%";
        return result;
    }

    return dna_to_json(*dna);
}

JsonObject DigitalDNARpc::cmd_registerdigitaldna(const JsonObject& params) {
    // Register this node's Digital DNA on-chain
    auto collector = g_node_context.GetDNACollector();
    if (!collector) {
        return error(-1, "Digital DNA not collected yet");
    }

    auto dna = collector->get_dna();
    if (!dna) {
        return error(-1, "DNA collection incomplete");
    }

    auto result = registry_.register_identity(*dna);

    JsonObject response;
    switch (result) {
        case IDNARegistry::RegisterResult::SUCCESS:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity registered successfully";
            break;
        case IDNARegistry::RegisterResult::ALREADY_REGISTERED:
            response["status"] = "error";
            response["error"] = "already_registered";
            response["message"] = "This address is already registered";
            break;
        case IDNARegistry::RegisterResult::SYBIL_FLAGGED:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity registered (advisory: similar identity exists)";
            response["sybil_flagged"] = "true";
            break;
        case IDNARegistry::RegisterResult::SYBIL_REJECTED:
            response["status"] = "error";
            response["error"] = "sybil_rejected";
            response["message"] = "Identity rejected: DNA too similar to existing registered identity (score >= 0.92)";
            break;
        case IDNARegistry::RegisterResult::INVALID_DNA:
            response["status"] = "error";
            response["error"] = "invalid_dna";
            response["message"] = "Digital DNA proof is invalid";
            break;
        case IDNARegistry::RegisterResult::UPDATED:
            response["status"] = "success";
            response["address"] = address_to_hex(dna->address);
            response["message"] = "Identity updated with enriched dimensions";
            break;
        case IDNARegistry::RegisterResult::DB_ERROR:
            response["status"] = "error";
            response["error"] = "db_error";
            response["message"] = "Database write failed";
            break;
    }

    return response;
}

JsonObject DigitalDNARpc::cmd_getdigitaldna(const JsonObject& params) {
    // Get Digital DNA for a specific address or MIK identity
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address (accepts MIK identity or address hex)");
    }

    auto dna = resolve_identity(it->second);
    if (!dna) {
        return error(-1, "Identity not registered: " + it->second);
    }

    return dna_to_json(*dna);
}

JsonObject DigitalDNARpc::cmd_comparedigitaldna(const JsonObject& params) {
    // Compare two identities for similarity
    auto it1 = params.find("address1");
    auto it2 = params.find("address2");

    if (it1 == params.end() || it2 == params.end()) {
        return error(-1, "Missing required parameters: address1, address2");
    }

    auto dna1 = resolve_identity(it1->second);
    auto dna2 = resolve_identity(it2->second);

    if (!dna1) return error(-1, "Identity not registered: " + it1->second);
    if (!dna2) return error(-1, "Identity not registered: " + it2->second);

    auto score = registry_.compare(*dna1, *dna2);

    JsonObject result;
    result["address1"] = it1->second;
    result["address2"] = it2->second;
    result["latency_similarity"] = std::to_string(score.latency_similarity);
    result["timing_similarity"] = std::to_string(score.timing_similarity);
    result["perspective_similarity"] = std::to_string(score.perspective_similarity);
    result["combined_score"] = std::to_string(score.combined_score);
    result["verdict"] = score.verdict();
    result["is_same_identity"] = score.is_same_identity() ? "true" : "false";
    result["is_suspicious"] = score.is_suspicious() ? "true" : "false";

    return result;
}

JsonObject DigitalDNARpc::cmd_findsimilaridentities(const JsonObject& params) {
    // Find identities similar to a given address
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address");
    }

    double threshold = SimilarityScore::SUSPICIOUS_THRESHOLD;
    auto th_it = params.find("threshold");
    if (th_it != params.end()) {
        threshold = std::stod(th_it->second);
    }

    auto dna = resolve_identity(it->second);
    if (!dna) return error(-1, "Identity not registered: " + it->second);

    auto similar = registry_.find_similar(*dna, threshold);

    JsonObject result;
    result["address"] = it->second;
    result["threshold"] = std::to_string(threshold);
    result["count"] = std::to_string(similar.size());

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < similar.size(); i++) {
        oss << "{";
        oss << "\"address\": \"" << address_to_hex(similar[i].first.address) << "\", ";
        oss << "\"similarity\": " << std::fixed << std::setprecision(4) << similar[i].second.combined_score << ", ";
        oss << "\"verdict\": \"" << similar[i].second.verdict() << "\"";
        oss << "}";
        if (i < similar.size() - 1) oss << ", ";
    }
    oss << "]";
    result["similar"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_listdigitaldna(const JsonObject& params) {
    // List all registered identities
    int limit = 100;
    auto it = params.find("limit");
    if (it != params.end()) {
        limit = std::stoi(it->second);
    }

    int offset = 0;
    auto off_it = params.find("offset");
    if (off_it != params.end()) {
        offset = std::stoi(off_it->second);
    }

    auto all = registry_.get_all();

    JsonObject result;
    result["total"] = std::to_string(all.size());
    result["limit"] = std::to_string(limit);
    result["offset"] = std::to_string(offset);

    std::ostringstream oss;
    oss << "[";
    int count = 0;
    for (size_t i = offset; i < all.size() && count < limit; i++, count++) {
        oss << "{";
        oss << "\"address\": \"" << address_to_hex(all[i].address) << "\", ";
        oss << "\"mik_identity\": \"" << address_to_hex(all[i].mik_identity) << "\", ";
        oss << "\"registration_height\": " << all[i].registration_height << ", ";
        oss << "\"iterations_per_sec\": " << std::fixed << std::setprecision(0)
            << all[i].timing.iterations_per_second;
        oss << "}";
        if (i < all.size() - 1 && count < limit - 1) oss << ", ";
    }
    oss << "]";
    result["identities"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_getdigitaldnastats(const JsonObject& params) {
    // Get network-wide identity statistics
    auto all = registry_.get_all();

    double total_ips = 0;
    double min_ips = std::numeric_limits<double>::max();
    double max_ips = 0;

    std::map<std::string, int> region_counts;

    for (const auto& dna : all) {
        total_ips += dna.timing.iterations_per_second;
        min_ips = std::min(min_ips, dna.timing.iterations_per_second);
        max_ips = std::max(max_ips, dna.timing.iterations_per_second);

        // Determine region from latency (lowest RTT = closest seed)
        double min_rtt = std::numeric_limits<double>::max();
        std::string region = "unknown";
        for (const auto& s : dna.latency.seed_stats) {
            if (s.median_ms < min_rtt && s.median_ms > 0) {
                min_rtt = s.median_ms;
                region = s.seed_name;
            }
        }
        region_counts[region]++;
    }

    JsonObject result;
    result["total_identities"] = std::to_string(all.size());

    if (!all.empty()) {
        result["avg_iterations_per_sec"] = std::to_string(total_ips / all.size());
        result["min_iterations_per_sec"] = std::to_string(min_ips);
        result["max_iterations_per_sec"] = std::to_string(max_ips);
    }

    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto& [region, count] : region_counts) {
        if (!first) oss << ", ";
        oss << "\"" << region << "\": " << count;
        first = false;
    }
    oss << "}";
    result["region_distribution"] = oss.str();

    // Sybil detection summary
    int suspicious_pairs = 0;
    int same_identity_pairs = 0;
    for (size_t i = 0; i < all.size(); i++) {
        for (size_t j = i + 1; j < all.size(); j++) {
            auto score = registry_.compare(all[i], all[j]);
            if (score.is_same_identity()) same_identity_pairs++;
            else if (score.is_suspicious()) suspicious_pairs++;
        }
    }
    result["suspicious_pairs"] = std::to_string(suspicious_pairs);
    result["same_identity_pairs"] = std::to_string(same_identity_pairs);

    return result;
}

JsonObject DigitalDNARpc::cmd_collectdigitaldna(const JsonObject& params) {
    // Start or check DNA collection process
    auto it = params.find("action");
    std::string action = it != params.end() ? it->second : "status";

    if (action == "start") {
        auto cur = g_node_context.GetDNACollector();
        if (cur && cur->is_collecting()) {
            return error(-1, "Collection already in progress");
        }

        // Get mining address from wallet (not g_my_address which may be stale)
        std::array<uint8_t, 20> address{};
        if (g_node_state.wallet) {
            auto pubKeyHash = g_node_state.wallet->GetPubKeyHash();
            if (pubKeyHash.size() == 20) {
                std::copy(pubKeyHash.begin(), pubKeyHash.end(), address.begin());
                g_my_address = address;  // Update global too
            }
        }
        if (address == std::array<uint8_t, 20>{}) {
            // Fall back to g_my_address if wallet not available
            address = g_my_address;
        }

        // Create new collector — shared_ptr for safe cross-thread replacement
        auto new_collector = std::make_shared<DigitalDNACollector>(address);

        // Set MIK identity from wallet
        if (g_node_state.wallet) {
            DFMP::Identity mikId = g_node_state.wallet->GetMIKIdentity();
            if (!mikId.IsNull()) {
                std::array<uint8_t, 20> mikArr{};
                std::copy(mikId.data, mikId.data + 20, mikArr.begin());
                new_collector->set_mik_identity(mikArr);
            }
        }

        new_collector->start_collection();
        set_collector(std::move(new_collector));

        JsonObject result;
        result["status"] = "started";
        result["message"] = "Digital DNA collection started";
        return result;

    } else if (action == "stop") {
        auto collector = g_node_context.GetDNACollector();
        if (!collector) {
            return error(-1, "No collection in progress");
        }

        collector->stop_collection();

        JsonObject result;
        result["status"] = "stopped";
        return result;

    } else {  // status
        auto collector = g_node_context.GetDNACollector();
        if (!collector) {
            JsonObject result;
            result["status"] = "not_started";
            result["message"] = "Run 'collectdigitaldna start' to begin";
            return result;
        }

        JsonObject result;
        if (collector->is_collecting()) {
            result["status"] = "collecting";
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(1) << (collector->get_progress() * 100);
            result["progress"] = oss.str() + "%";
        } else {
            auto dna = collector->get_dna();
            if (dna) {
                result["status"] = "complete";
                result["is_valid"] = dna->is_valid ? "true" : "false";
            } else {
                result["status"] = "incomplete";
            }
        }
        return result;
    }
}

JsonObject DigitalDNARpc::cmd_validatedigitaldna(const JsonObject& params) {
    // Validate a Digital DNA proof
    auto it = params.find("address");
    if (it == params.end()) {
        return error(-1, "Missing required parameter: address");
    }

    auto dna = resolve_identity(it->second);
    if (!dna) return error(-1, "Identity not registered");

    JsonObject result;
    result["address"] = address_to_hex(dna->address);
    result["mik_identity"] = address_to_hex(dna->mik_identity);
    result["is_valid"] = dna->is_valid ? "true" : "false";

    // Check for Sybils
    auto similar = registry_.find_similar(*dna, SimilarityScore::SUSPICIOUS_THRESHOLD);
    result["has_similar_identities"] = similar.empty() ? "false" : "true";
    result["similar_count"] = std::to_string(similar.size());

    // Validate components
    bool latency_valid = dna->latency.seed_stats[0].samples > 0;
    bool timing_valid = dna->timing.iterations_per_second > 0;
    bool perspective_valid = dna->perspective.total_unique_peers() > 0;

    result["latency_valid"] = latency_valid ? "true" : "false";
    result["timing_valid"] = timing_valid ? "true" : "false";
    result["perspective_valid"] = perspective_valid ? "true" : "false";

    return result;
}

JsonObject DigitalDNARpc::cmd_getlatencyfingerprint(const JsonObject& params) {
    // Get just the latency component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address or MIK
        auto dna = resolve_identity(it->second);
        if (!dna) return error(-1, "Identity not registered");

        JsonObject result;
        result["address"] = address_to_hex(dna->address);

        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < dna->latency.seed_stats.size(); i++) {
            const auto& s = dna->latency.seed_stats[i];
            oss << "{";
            oss << "\"seed\": \"" << s.seed_name << "\", ";
            oss << "\"median_ms\": " << std::fixed << std::setprecision(2) << s.median_ms << ", ";
            oss << "\"stddev_ms\": " << s.stddev_ms << ", ";
            oss << "\"samples\": " << s.samples;
            oss << "}";
            if (i < dna->latency.seed_stats.size() - 1) oss << ", ";
        }
        oss << "]";
        result["seeds"] = oss.str();

        return result;
    }

    // Get live measurement for this node
    LatencyFingerprintCollector collector;
    collector.set_samples_per_seed(10);
    collector.set_timeout_ms(5000);

    LatencyFingerprint fp;
    fp.seed_stats.resize(MAINNET_SEEDS.size());
    for (size_t i = 0; i < MAINNET_SEEDS.size(); i++) {
        fp.seed_stats[i] = collector.measure_seed(MAINNET_SEEDS[i]);
    }

    JsonObject result;
    result["type"] = "live_measurement";

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < fp.seed_stats.size(); i++) {
        const auto& s = fp.seed_stats[i];
        oss << "{";
        oss << "\"seed\": \"" << s.seed_name << "\", ";
        oss << "\"median_ms\": " << std::fixed << std::setprecision(2) << s.median_ms << ", ";
        oss << "\"samples\": " << s.samples;
        oss << "}";
        if (i < fp.seed_stats.size() - 1) oss << ", ";
    }
    oss << "]";
    result["seeds"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_gettimingsignature(const JsonObject& params) {
    // Get just the timing component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address
        auto dna = resolve_identity(it->second);
        if (!dna) return error(-1, "Identity not registered");

        JsonObject result;
        result["address"] = address_to_hex(dna->address);
        result["iterations"] = std::to_string(dna->timing.total_iterations);
        result["iterations_per_second"] = std::to_string(dna->timing.iterations_per_second);
        result["mean_interval_us"] = std::to_string(dna->timing.mean_interval_us);
        result["stddev_interval_us"] = std::to_string(dna->timing.stddev_interval_us);

        return result;
    }

    // Run live benchmark
    uint64_t iterations = 1'000'000;
    auto bench_it = params.find("iterations");
    if (bench_it != params.end()) {
        iterations = std::stoull(bench_it->second);
    }

    TimingConfig config;
    config.total_iterations = iterations;
    config.checkpoint_interval = 10000;
    config.warmup_iterations = 10000;

    TimingSignatureCollector collector(config);

    std::array<uint8_t, 32> challenge = {};
    auto timing = collector.collect(challenge);

    JsonObject result;
    result["type"] = "live_measurement";
    result["iterations"] = std::to_string(timing.total_iterations);
    result["total_time_ms"] = std::to_string(timing.total_time_us / 1000.0);
    result["iterations_per_second"] = std::to_string(timing.iterations_per_second);
    result["mean_interval_us"] = std::to_string(timing.mean_interval_us);
    result["stddev_interval_us"] = std::to_string(timing.stddev_interval_us);

    return result;
}

JsonObject DigitalDNARpc::cmd_getperspectiveproof(const JsonObject& params) {
    // Get just the perspective component
    auto it = params.find("address");

    if (it != params.end()) {
        // Get for specific address or MIK
        auto dna = resolve_identity(it->second);
        if (!dna) return error(-1, "Identity not registered");

        JsonObject result;
        result["address"] = address_to_hex(dna->address);
        result["total_unique_peers"] = std::to_string(dna->perspective.total_unique_peers());
        result["peer_turnover_rate"] = std::to_string(dna->perspective.peer_turnover_rate());
        result["witness_coverage"] = std::to_string(dna->perspective.witness_coverage());
        result["num_snapshots"] = std::to_string(dna->perspective.snapshots.size());

        return result;
    }

    // Get current node's perspective (would need peer manager integration)
    JsonObject result;
    result["type"] = "current_node";
    result["message"] = "Perspective requires peer manager integration";
    result["status"] = "not_available";

    return result;
}

// ============ Helpers ============

std::string DigitalDNARpc::address_to_hex(const std::array<uint8_t, 20>& addr) const {
    std::ostringstream oss;
    for (auto b : addr) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

// Convert raw 20-byte pubkey hash to base58check D... address
static std::string pubkeyhash_to_address(const std::array<uint8_t, 20>& hash) {
    // Version byte 0x1E produces addresses starting with 'D'
    std::vector<uint8_t> data;
    data.push_back(0x1E);
    data.insert(data.end(), hash.begin(), hash.end());
    return EncodeBase58Check(data);
}

std::array<uint8_t, 20> DigitalDNARpc::hex_to_address(const std::string& hex) const {
    std::array<uint8_t, 20> addr = {};
    for (size_t i = 0; i < 20 && i * 2 + 1 < hex.size(); i++) {
        addr[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
    }
    return addr;
}

std::optional<DigitalDNA> DigitalDNARpc::resolve_identity(const std::string& hex_key) const {
    auto key = hex_to_address(hex_key);
    // Try MIK lookup first (primary key)
    auto dna = registry_.get_identity_by_mik(key);
    if (dna) return dna;
    // Fallback to address lookup (backward compat)
    return registry_.get_identity(key);
}

JsonObject DigitalDNARpc::dna_to_json(const DigitalDNA& dna) const {
    JsonObject result;

    result["address"] = pubkeyhash_to_address(dna.address);
    result["address_hex"] = address_to_hex(dna.address);
    result["mik_identity"] = address_to_hex(dna.mik_identity);
    result["registration_height"] = std::to_string(dna.registration_height);
    result["registration_time"] = std::to_string(dna.registration_time);
    result["is_valid"] = dna.is_valid ? "true" : "false";

    // Latency
    std::ostringstream lat_oss;
    lat_oss << "[";
    for (size_t i = 0; i < dna.latency.seed_stats.size(); i++) {
        const auto& s = dna.latency.seed_stats[i];
        lat_oss << std::fixed << std::setprecision(1) << s.median_ms;
        if (i < dna.latency.seed_stats.size() - 1) lat_oss << ", ";
    }
    lat_oss << "]";
    result["latency_fingerprint_ms"] = lat_oss.str();

    // Timing
    result["iterations_per_second"] = std::to_string(dna.timing.iterations_per_second);

    // Perspective
    result["unique_peers"] = std::to_string(dna.perspective.total_unique_peers());
    result["peer_turnover"] = std::to_string(dna.perspective.peer_turnover_rate());

    // Hash
    auto hash = dna.hash();
    std::ostringstream hash_oss;
    for (int i = 0; i < 8; i++) {
        hash_oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    hash_oss << "...";
    result["identity_hash"] = hash_oss.str();

    return result;
}

JsonObject DigitalDNARpc::score_to_json(const SimilarityScore& score) const {
    JsonObject result;
    result["latency_similarity"] = std::to_string(score.latency_similarity);
    result["timing_similarity"] = std::to_string(score.timing_similarity);
    result["perspective_similarity"] = std::to_string(score.perspective_similarity);
    result["has_perspective"] = score.has_perspective ? "true" : "false";
    result["dimensions_scored"] = std::to_string(score.dimensions_scored);
    result["combined_score"] = std::to_string(score.combined_score);
    result["verdict"] = score.verdict();
    return result;
}

JsonObject DigitalDNARpc::error(int code, const std::string& message) const {
    JsonObject result;
    result["error"] = "true";
    result["code"] = std::to_string(code);
    result["message"] = message;
    return result;
}

JsonObject DigitalDNARpc::cmd_dumpdigitaldna(const JsonObject& params) {
    // Full dump of all registered DNA identities with every dimension.
    // Designed for offline calibration: pull snapshots at day 0/7/14,
    // compare dimension distributions, calibrate weights.

    auto all = registry_.get_all();

    JsonObject result;
    result["total"] = std::to_string(all.size());
    result["dump_time"] = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    std::ostringstream oss;
    oss << std::fixed;
    oss << "[";
    for (size_t idx = 0; idx < all.size(); idx++) {
        const auto& dna = all[idx];
        oss << "{";

        // Identity
        oss << "\"address\": \"" << address_to_hex(dna.address) << "\", ";
        oss << "\"mik_identity\": \"" << address_to_hex(dna.mik_identity) << "\", ";
        oss << "\"registration_height\": " << dna.registration_height << ", ";
        oss << "\"registration_time\": " << dna.registration_time << ", ";
        oss << "\"is_valid\": " << (dna.is_valid ? "true" : "false") << ", ";

        // Hash
        auto hash = dna.hash();
        oss << "\"identity_hash\": \"";
        for (auto b : hash) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        oss << std::dec << "\", ";

        // L: Latency fingerprint
        oss << "\"latency\": {";
        oss << "\"measurement_height\": " << dna.latency.measurement_height << ", ";
        oss << "\"measurement_timestamp\": " << dna.latency.measurement_timestamp << ", ";
        oss << "\"seeds\": [";
        for (size_t i = 0; i < dna.latency.seed_stats.size(); i++) {
            const auto& s = dna.latency.seed_stats[i];
            oss << "{\"name\": \"" << s.seed_name << "\", ";
            oss << std::setprecision(2);
            oss << "\"median_ms\": " << s.median_ms << ", ";
            oss << "\"mean_ms\": " << s.mean_ms << ", ";
            oss << "\"p10_ms\": " << s.p10_ms << ", ";
            oss << "\"p90_ms\": " << s.p90_ms << ", ";
            oss << "\"stddev_ms\": " << s.stddev_ms << ", ";
            oss << "\"samples\": " << s.samples << ", ";
            oss << "\"failures\": " << s.failures << "}";
            if (i < dna.latency.seed_stats.size() - 1) oss << ", ";
        }
        oss << "]}, ";

        // V: Timing signature
        oss << "\"timing\": {";
        oss << std::setprecision(1);
        oss << "\"iterations_per_second\": " << dna.timing.iterations_per_second << ", ";
        oss << "\"total_iterations\": " << dna.timing.total_iterations << ", ";
        oss << "\"total_time_us\": " << dna.timing.total_time_us << ", ";
        oss << std::setprecision(2);
        oss << "\"mean_interval_us\": " << dna.timing.mean_interval_us << ", ";
        oss << "\"stddev_interval_us\": " << dna.timing.stddev_interval_us << ", ";
        oss << "\"checkpoints\": " << dna.timing.checkpoints.size();
        oss << "}, ";

        // P: Perspective proof
        oss << "\"perspective\": {";
        oss << "\"unique_peers\": " << dna.perspective.total_unique_peers() << ", ";
        oss << std::setprecision(4);
        oss << "\"peer_turnover\": " << dna.perspective.peer_turnover_rate() << ", ";
        oss << "\"snapshots\": " << dna.perspective.snapshots.size();
        oss << "}, ";

        // M: Memory fingerprint (optional)
        oss << "\"memory\": ";
        if (dna.memory.has_value()) {
            const auto& m = *dna.memory;
            oss << "{";
            oss << std::setprecision(1);
            oss << "\"estimated_l1_kb\": " << m.estimated_l1_kb << ", ";
            oss << "\"estimated_l2_kb\": " << m.estimated_l2_kb << ", ";
            oss << "\"estimated_l3_kb\": " << m.estimated_l3_kb << ", ";
            oss << std::setprecision(2);
            oss << "\"dram_latency_ns\": " << m.dram_latency_ns << ", ";
            oss << "\"peak_bandwidth_mbps\": " << m.peak_bandwidth_mbps << ", ";
            oss << "\"access_curve\": [";
            for (size_t i = 0; i < m.access_curve.size(); i++) {
                oss << "{\"ws_kb\": " << m.access_curve[i].working_set_kb;
                oss << ", \"ns\": " << m.access_curve[i].access_time_ns;
                oss << ", \"mbps\": " << m.access_curve[i].bandwidth_mbps << "}";
                if (i < m.access_curve.size() - 1) oss << ", ";
            }
            oss << "]}";
        } else {
            oss << "null";
        }
        oss << ", ";

        // D: Clock drift (optional)
        oss << "\"clock_drift\": ";
        if (dna.clock_drift.has_value()) {
            const auto& d = *dna.clock_drift;
            oss << "{";
            oss << std::setprecision(6);
            oss << "\"drift_rate_ppm\": " << d.drift_rate_ppm << ", ";
            oss << "\"drift_stability\": " << d.drift_stability << ", ";
            oss << "\"jitter_signature\": " << d.jitter_signature << ", ";
            oss << "\"num_samples\": " << d.num_samples << ", ";
            oss << "\"num_reference_peers\": " << d.num_reference_peers << ", ";
            oss << "\"observation_start\": " << d.observation_start << ", ";
            oss << "\"observation_end\": " << d.observation_end << ", ";
            oss << "\"reliable\": " << (d.is_reliable() ? "true" : "false");
            oss << "}";
        } else {
            oss << "null";
        }
        oss << ", ";

        // B: Bandwidth (optional)
        oss << "\"bandwidth\": ";
        if (dna.bandwidth.has_value()) {
            const auto& b = *dna.bandwidth;
            oss << "{";
            oss << std::setprecision(2);
            oss << "\"median_upload_mbps\": " << b.median_upload_mbps << ", ";
            oss << "\"median_download_mbps\": " << b.median_download_mbps << ", ";
            oss << std::setprecision(4);
            oss << "\"median_asymmetry\": " << b.median_asymmetry << ", ";
            oss << std::setprecision(2);
            oss << "\"bandwidth_stability\": " << b.bandwidth_stability << ", ";
            oss << "\"measurements\": " << b.measurements.size() << ", ";
            oss << "\"reliable\": " << (b.is_reliable() ? "true" : "false");
            oss << "}";
        } else {
            oss << "null";
        }
        oss << ", ";

        // T: Thermal (optional)
        oss << "\"thermal\": ";
        if (dna.thermal.has_value()) {
            const auto& t = *dna.thermal;
            oss << "{";
            oss << std::setprecision(2);
            oss << "\"initial_speed\": " << t.initial_speed << ", ";
            oss << "\"sustained_speed\": " << t.sustained_speed << ", ";
            oss << std::setprecision(4);
            oss << "\"throttle_ratio\": " << t.throttle_ratio << ", ";
            oss << std::setprecision(2);
            oss << "\"time_to_steady_state_sec\": " << t.time_to_steady_state_sec << ", ";
            oss << "\"thermal_jitter\": " << t.thermal_jitter << ", ";
            oss << "\"speed_curve_points\": " << t.speed_curve.size();
            oss << "}";
        } else {
            oss << "null";
        }
        oss << ", ";

        // BP: Behavioral profile (optional)
        oss << "\"behavioral\": ";
        if (dna.behavioral.has_value()) {
            const auto& bp = *dna.behavioral;
            oss << "{";
            oss << std::setprecision(4);
            oss << "\"hourly_activity\": [";
            for (int h = 0; h < 24; h++) {
                oss << bp.hourly_activity[h];
                if (h < 23) oss << ", ";
            }
            oss << "], ";
            oss << std::setprecision(2);
            oss << "\"mean_relay_delay_ms\": " << bp.mean_relay_delay_ms << ", ";
            oss << "\"relay_consistency\": " << bp.relay_consistency << ", ";
            oss << "\"avg_peer_session_duration_sec\": " << bp.avg_peer_session_duration_sec << ", ";
            oss << std::setprecision(4);
            oss << "\"peer_diversity_score\": " << bp.peer_diversity_score << ", ";
            oss << std::setprecision(2);
            oss << "\"tx_relay_rate\": " << bp.tx_relay_rate << ", ";
            oss << std::setprecision(4);
            oss << "\"tx_timing_entropy\": " << bp.tx_timing_entropy << ", ";
            oss << "\"observation_blocks\": " << bp.observation_blocks << ", ";
            oss << "\"mature\": " << (bp.is_mature() ? "true" : "false");
            oss << "}";
        } else {
            oss << "null";
        }

        oss << "}";
        if (idx < all.size() - 1) oss << ", ";
    }
    oss << "]";
    result["identities"] = oss.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_getdigitaldnahistory(const JsonObject& params) {
    auto it = params.find("mik");
    if (it == params.end()) {
        return error(-32602, "Missing required parameter: mik (40-character hex MIK identity)");
    }

    auto mik = hex_to_address(it->second);

    size_t max_entries = 100;
    auto limit_it = params.find("limit");
    if (limit_it != params.end()) {
        int val = std::atoi(limit_it->second.c_str());
        if (val > 0 && val <= 1000) max_entries = static_cast<size_t>(val);
    }

    auto history = registry_.get_dna_history(mik, max_entries);

    // Also get current DNA for context
    auto current = registry_.get_identity_by_mik(mik);

    JsonObject result;
    result["mik"] = it->second;
    result["change_count"] = std::to_string(history.size());
    result["has_current"] = current.has_value() ? "true" : "false";

    if (current) {
        auto hash = current->hash();
        std::ostringstream hoss;
        for (auto b : hash) hoss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        result["current_hash"] = hoss.str();
        result["current_registration_height"] = std::to_string(current->registration_height);
    }

    std::ostringstream oss;
    oss << std::fixed;
    oss << "[";
    for (size_t i = 0; i < history.size(); i++) {
        const auto& [timestamp, dna] = history[i];
        auto hash = dna.hash();

        oss << "{";
        oss << "\"archived_at\": " << timestamp << ", ";
        oss << "\"hash\": \"";
        for (auto b : hash) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        oss << std::dec << "\", ";
        oss << "\"registration_height\": " << dna.registration_height << ", ";
        oss << std::setprecision(1);
        oss << "\"iterations_per_sec\": " << dna.timing.iterations_per_second << ", ";

        // Latency summary (medians only)
        oss << "\"latency_medians\": [";
        for (size_t j = 0; j < dna.latency.seed_stats.size(); j++) {
            oss << std::setprecision(1) << dna.latency.seed_stats[j].median_ms;
            if (j < dna.latency.seed_stats.size() - 1) oss << ", ";
        }
        oss << "], ";

        // Key dimension changes (for quick pattern detection)
        if (dna.clock_drift) {
            oss << std::setprecision(4);
            oss << "\"drift_rate_ppm\": " << dna.clock_drift->drift_rate_ppm << ", ";
        }
        if (dna.memory) {
            oss << std::setprecision(0);
            oss << "\"estimated_l3_kb\": " << dna.memory->estimated_l3_kb << ", ";
        }

        oss << "\"unique_peers\": " << dna.perspective.total_unique_peers();
        oss << "}";
        if (i < history.size() - 1) oss << ", ";
    }
    oss << "]";
    result["history"] = oss.str();

    return result;
}

// ============ DNA Monitoring Dashboard ============

JsonObject DigitalDNARpc::cmd_getdnamonitor(const JsonObject& /*params*/) {
    auto all = registry_.get_all();
    JsonObject result;
    result["total_identities"] = std::to_string(all.size());

    if (all.empty()) {
        result["dimension_coverage"] = "{}";
        result["trust_distribution"] = "{}";
        result["sybil_clusters"] = "[]";
        result["rotation_alerts"] = "[]";
        result["health_score"] = "0";
        result["health_grade"] = "N/A";
        return result;
    }

    // --- 1. Dimension coverage ---
    int has_perspective = 0, has_memory = 0, has_drift = 0, has_bw = 0, has_thermal = 0, has_behavioral = 0;
    for (const auto& dna : all) {
        // Perspective is "present" only if there's actual peer data (snapshots or cached count)
        if (dna.perspective.total_unique_peers() > 0 || !dna.perspective.snapshots.empty()) has_perspective++;
        if (dna.memory) has_memory++;
        if (dna.clock_drift) has_drift++;
        if (dna.bandwidth) has_bw++;
        if (dna.thermal) has_thermal++;
        if (dna.behavioral) has_behavioral++;
    }
    int n = static_cast<int>(all.size());
    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1);
        oss << "{";
        oss << "\"latency\": 100.0, ";  // Always present (core)
        oss << "\"timing\": 100.0, ";   // Always present (core)
        oss << "\"perspective\": " << (100.0 * has_perspective / n) << ", ";
        oss << "\"memory\": " << (100.0 * has_memory / n) << ", ";
        oss << "\"clock_drift\": " << (100.0 * has_drift / n) << ", ";
        oss << "\"bandwidth\": " << (100.0 * has_bw / n) << ", ";
        oss << "\"thermal\": " << (100.0 * has_thermal / n) << ", ";
        oss << "\"behavioral\": " << (100.0 * has_behavioral / n);
        oss << "}";
        result["dimension_coverage"] = oss.str();
    }

    // --- 2. Sybil cluster detection ---
    // Build adjacency: identities with similarity > SUSPICIOUS_THRESHOLD
    // Then find connected components of size >= 3
    struct Edge { size_t a; size_t b; double score; };
    std::vector<Edge> edges;
    for (size_t i = 0; i < all.size(); i++) {
        for (size_t j = i + 1; j < all.size(); j++) {
            auto s = registry_.compare(all[i], all[j]);
            if (s.is_suspicious() || s.is_same_identity()) {
                edges.push_back({i, j, s.combined_score});
            }
        }
    }

    // Union-Find for clustering
    std::vector<size_t> parent(all.size());
    for (size_t i = 0; i < all.size(); i++) parent[i] = i;
    std::function<size_t(size_t)> find = [&](size_t x) -> size_t {
        return parent[x] == x ? x : (parent[x] = find(parent[x]));
    };
    for (const auto& e : edges) {
        size_t ra = find(e.a), rb = find(e.b);
        if (ra != rb) parent[ra] = rb;
    }

    // Group by cluster root
    std::map<size_t, std::vector<size_t>> clusters;
    for (size_t i = 0; i < all.size(); i++) {
        size_t root = find(i);
        // Only track if this identity has at least one suspicious edge
        bool has_edge = false;
        for (const auto& e : edges) {
            if (e.a == i || e.b == i) { has_edge = true; break; }
        }
        if (has_edge) clusters[root].push_back(i);
    }

    {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3);
        oss << "[";
        bool first_cluster = true;
        for (const auto& [root, members] : clusters) {
            if (members.size() < 2) continue;  // Only report pairs or larger
            if (!first_cluster) oss << ", ";
            first_cluster = false;

            oss << "{\"size\": " << members.size();
            oss << ", \"severity\": " << (members.size() >= 3 ? "\"HIGH\"" : "\"MEDIUM\"");

            // Find max similarity within cluster
            double max_sim = 0;
            for (size_t i = 0; i < members.size(); i++) {
                for (size_t j = i + 1; j < members.size(); j++) {
                    auto s = registry_.compare(all[members[i]], all[members[j]]);
                    max_sim = std::max(max_sim, s.combined_score);
                }
            }
            oss << ", \"max_similarity\": " << max_sim;

            // List MIK identities in cluster
            oss << ", \"miks\": [";
            for (size_t i = 0; i < members.size(); i++) {
                oss << "\"" << address_to_hex(all[members[i]].mik_identity) << "\"";
                if (i < members.size() - 1) oss << ", ";
            }
            oss << "]}";
        }
        oss << "]";
        result["sybil_clusters"] = oss.str();
    }

    // Count clusters for health scoring
    int cluster_count = 0;
    int large_cluster_count = 0;
    for (const auto& [root, members] : clusters) {
        if (members.size() >= 2) cluster_count++;
        if (members.size() >= 3) large_cluster_count++;
    }
    result["cluster_count"] = std::to_string(cluster_count);
    result["large_cluster_count"] = std::to_string(large_cluster_count);

    // --- 3. Rotation alerts (MIKs with 3+ changes) ---
    {
        std::ostringstream oss;
        oss << "[";
        bool first_alert = true;
        for (const auto& dna : all) {
            std::array<uint8_t, 20> zero_mik{};
            if (dna.mik_identity == zero_mik) continue;

            auto history = registry_.get_dna_history(dna.mik_identity, 50);
            if (history.size() < 2) continue;  // 0-1 changes is normal

            if (!first_alert) oss << ", ";
            first_alert = false;

            oss << "{\"mik\": \"" << address_to_hex(dna.mik_identity) << "\"";
            oss << ", \"change_count\": " << history.size();

            // Classify: 2 changes could be legitimate, 3+ is suspicious
            const char* severity = "LOW";
            if (history.size() >= 5) severity = "HIGH";
            else if (history.size() >= 3) severity = "MEDIUM";
            oss << ", \"severity\": \"" << severity << "\"";

            // Time span of changes
            if (!history.empty()) {
                uint64_t first_ts = history.front().first;
                uint64_t last_ts = history.back().first;
                uint64_t span_hours = (last_ts > first_ts) ? (last_ts - first_ts) / 3600 : 0;
                oss << ", \"span_hours\": " << span_hours;
            }

            oss << "}";
        }
        oss << "]";
        result["rotation_alerts"] = oss.str();
    }

    // --- 4. Trust distribution (if trust manager available) ---
    // Note: trust scores are managed separately; count by tier from DNA registry
    // We can approximate by looking at registration heights (age proxy)
    {
        std::ostringstream oss;
        oss << "{";
        oss << "\"total_tracked\": " << all.size();
        // Group by registration age brackets
        int fresh = 0, young = 0, mature = 0, old = 0;
        uint32_t max_height = 0;
        for (const auto& dna : all) {
            max_height = std::max(max_height, dna.registration_height);
        }
        for (const auto& dna : all) {
            uint32_t age = max_height - dna.registration_height;
            if (age < 1000) fresh++;       // < ~12 hours (DilV)
            else if (age < 5000) young++;  // < ~2.5 days
            else if (age < 20000) mature++; // < ~10 days
            else old++;                     // 10+ days
        }
        oss << ", \"fresh_lt_1k_blocks\": " << fresh;
        oss << ", \"young_1k_5k_blocks\": " << young;
        oss << ", \"mature_5k_20k_blocks\": " << mature;
        oss << ", \"veteran_gt_20k_blocks\": " << old;
        oss << "}";
        result["trust_distribution"] = oss.str();
    }

    // --- 5. Network health score (0-100) ---
    // Factors: identity count, dimension coverage, cluster ratio, diversity
    double health = 0.0;

    // Identity count contribution (0-25 pts, linear up to 50 identities)
    health += std::min(25.0, static_cast<double>(n) * 0.5);

    // Dimension coverage contribution (0-25 pts)
    double dim_coverage = (has_memory + has_drift + has_bw + has_thermal + has_behavioral)
                         / (5.0 * n);
    health += dim_coverage * 25.0;

    // Low cluster ratio contribution (0-25 pts, penalty for suspicious clusters)
    if (n > 1) {
        double suspicious_ratio = static_cast<double>(cluster_count) / (n / 2.0);
        health += std::max(0.0, 25.0 * (1.0 - suspicious_ratio));
    } else {
        health += 25.0;
    }

    // Unique regions contribution (0-25 pts)
    std::map<std::string, int> regions;
    for (const auto& dna : all) {
        double min_rtt = 1e9;
        std::string region = "unknown";
        for (const auto& s : dna.latency.seed_stats) {
            if (s.median_ms > 0 && s.median_ms < min_rtt) {
                min_rtt = s.median_ms;
                region = s.seed_name;
            }
        }
        regions[region]++;
    }
    health += std::min(25.0, static_cast<double>(regions.size()) * 6.25);

    health = std::min(100.0, std::max(0.0, health));
    result["health_score"] = std::to_string(static_cast<int>(health));

    const char* grade;
    if (health >= 80) grade = "A";
    else if (health >= 60) grade = "B";
    else if (health >= 40) grade = "C";
    else if (health >= 20) grade = "D";
    else grade = "F";
    result["health_grade"] = grade;

    // Sybil Defense Phase 5: Mining concentration (Gini coefficient)
    // Gini = 0.0 (perfect equality) to 1.0 (one miner has everything)
    // Healthy network: 0.2-0.5. Sybil attack: very low (<0.15, too uniform)
    // or very high (>0.7, one entity dominates).
    if (g_node_context.cooldown_tracker) {
        // Get per-MIK block counts from the cooldown tracker's height→winner map
        auto knownAddrs = g_node_context.cooldown_tracker->GetKnownAddresses();
        int currentHeight = 0;
        // Estimate current height from last known winner
        for (const auto& addr : knownAddrs) {
            int h = g_node_context.cooldown_tracker->GetLastWinHeight(addr);
            if (h > currentHeight) currentHeight = h;
        }

        // Count blocks per MIK in last 200 blocks
        std::map<std::array<uint8_t, 20>, int> mikBlocks;
        int window = 200;
        for (const auto& addr : knownAddrs) {
            int count = g_node_context.cooldown_tracker->GetBlockCountInWindow(addr, currentHeight, window);
            if (count > 0) {
                mikBlocks[addr] = count;
            }
        }

        if (mikBlocks.size() >= 2) {
            // Compute Gini coefficient
            std::vector<double> shares;
            double total = 0;
            for (auto& [addr, count] : mikBlocks) {
                shares.push_back(static_cast<double>(count));
                total += count;
            }
            std::sort(shares.begin(), shares.end());

            int n = static_cast<int>(shares.size());
            double sumWeighted = 0;
            for (int i = 0; i < n; i++) {
                sumWeighted += (2.0 * (i + 1) - n - 1) * shares[i];
            }
            double gini = sumWeighted / (n * total);

            std::ostringstream giniStr;
            giniStr << std::fixed << std::setprecision(3) << gini;
            result["mining_gini"] = giniStr.str();
            result["mining_active_miners"] = std::to_string(n);
            result["mining_window_blocks"] = std::to_string(window);

            // Alert levels (monitoring only)
            std::string giniAlert = "normal";
            if (gini > 0.7) giniAlert = "CRITICAL_HIGH";    // one entity dominates
            else if (gini < 0.15 && n > 20) giniAlert = "SUSPICIOUS_LOW";  // too uniform (Sybil)
            else if (gini > 0.5) giniAlert = "elevated";
            result["mining_gini_alert"] = giniAlert;
        }
    }

    return result;
}

// ============ Phase 2: DNA Verification & Attestation RPCs ============

JsonObject DigitalDNARpc::cmd_getverificationstatus(const JsonObject& params) {
    auto it = params.find("mik");
    if (it == params.end() || it->second.empty()) {
        return error(-1, "Missing required parameter: mik (40-character hex)");
    }

    std::array<uint8_t, 20> mik = hex_to_address(it->second);

    // Get verification status from registry
    auto* reg = dynamic_cast<DNARegistryDB*>(&registry_);
    if (!reg) {
        return error(-2, "DNA registry not available");
    }

    auto status = reg->get_verification_status(mik);
    auto attestations = reg->get_attestations(mik);
    size_t pass_count = reg->count_pass_attestations(mik);

    JsonObject result;
    const char* status_names[] = {"UNVERIFIED", "PENDING", "VERIFIED", "FAILED"};
    int status_idx = static_cast<int>(status);
    result["status"] = (status_idx >= 0 && status_idx <= 3) ? status_names[status_idx] : "UNKNOWN";
    result["attestation_count"] = std::to_string(attestations.size());
    result["pass_count"] = std::to_string(pass_count);
    result["fail_count"] = std::to_string(attestations.size() - pass_count);
    result["quorum_required"] = std::to_string(verification::ATTESTATION_QUORUM);

    // List verifier MIKs
    std::ostringstream verifiers_json;
    verifiers_json << "[";
    for (size_t i = 0; i < attestations.size(); ++i) {
        if (i > 0) verifiers_json << ",";
        verifiers_json << "\"" << address_to_hex(attestations[i].verifier_mik) << "\"";
    }
    verifiers_json << "]";
    result["verifiers"] = verifiers_json.str();

    return result;
}

JsonObject DigitalDNARpc::cmd_listattestations(const JsonObject& params) {
    auto it = params.find("mik");
    if (it == params.end() || it->second.empty()) {
        return error(-1, "Missing required parameter: mik (40-character hex)");
    }

    std::array<uint8_t, 20> mik = hex_to_address(it->second);

    auto* reg = dynamic_cast<DNARegistryDB*>(&registry_);
    if (!reg) {
        return error(-2, "DNA registry not available");
    }

    auto attestations = reg->get_attestations(mik);

    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < attestations.size(); ++i) {
        const auto& att = attestations[i];
        if (i > 0) oss << ",";
        oss << "{";
        oss << "\"verifier\":\"" << address_to_hex(att.verifier_mik) << "\",";
        oss << "\"target\":\"" << address_to_hex(att.target_mik) << "\",";
        oss << "\"height\":" << att.registration_height << ",";
        oss << "\"timestamp\":" << att.timestamp << ",";
        oss << "\"overall_pass\":" << (att.overall_pass ? "true" : "false") << ",";
        oss << std::fixed << std::setprecision(2);
        oss << "\"vdf_measured\":" << att.vdf_timing.measured_value << ",";
        oss << "\"vdf_claimed\":" << att.vdf_timing.claimed_value << ",";
        oss << "\"vdf_pass\":" << (att.vdf_timing.pass ? "true" : "false") << ",";
        oss << "\"bw_up_measured\":" << att.bandwidth_up.measured_value << ",";
        oss << "\"bw_down_measured\":" << att.bandwidth_down.measured_value << ",";
        oss << "\"latency_rtt_ms\":" << att.latency_rtt_ms;
        oss << "}";
    }
    oss << "]";

    JsonObject result;
    result["mik"] = address_to_hex(mik);
    result["count"] = std::to_string(attestations.size());
    result["attestations"] = oss.str();
    return result;
}

JsonObject DigitalDNARpc::cmd_getverificationconfig(const JsonObject& params) {
    (void)params;
    JsonObject result;
    result["verifier_count"] = std::to_string(verification::VERIFIER_COUNT);
    result["attestation_quorum"] = std::to_string(verification::ATTESTATION_QUORUM);
    result["vdf_challenge_iterations"] = std::to_string(verification::VDF_CHALLENGE_ITERS);
    result["vdf_timing_tolerance"] = std::to_string(verification::VDF_TIMING_TOLERANCE);
    result["bandwidth_tolerance"] = std::to_string(verification::BW_TOLERANCE);
    result["vdf_timeout_sec"] = std::to_string(verification::VDF_CHALLENGE_TIMEOUT_SEC);
    result["bw_timeout_sec"] = std::to_string(verification::BW_CHALLENGE_TIMEOUT_SEC);
    result["latency_timeout_sec"] = std::to_string(verification::LATENCY_TIMEOUT_SEC);
    result["max_concurrent"] = std::to_string(verification::MAX_CONCURRENT_VERIFICATIONS);
    result["rate_limit_sec"] = std::to_string(verification::VERIFICATION_RATE_LIMIT_SEC);

    // Pending count from verification manager
    if (g_node_context.verification_manager) {
        result["pending_verifications"] = std::to_string(
            g_node_context.verification_manager->PendingCount());
    } else {
        result["pending_verifications"] = "0";
    }

    return result;
}

// ============ Peer Trust Scoring ============

JsonObject DigitalDNARpc::cmd_getpeertrust(const JsonObject& params) {
    // Optional: filter by peer_id
    int filter_peer_id = -1;
    auto it = params.find("peer_id");
    if (it != params.end() && !it->second.empty()) {
        try {
            filter_peer_id = std::stoi(it->second);
        } catch (...) {
            return error(-1, "Invalid peer_id parameter");
        }
    }

    if (!g_node_context.peer_manager) {
        return error(-2, "Peer manager not available");
    }

    auto peers = g_node_context.peer_manager->GetConnectedPeers();

    std::ostringstream oss;
    oss << "[";
    bool first = true;

    for (const auto& peer : peers) {
        if (!peer) continue;
        if (filter_peer_id >= 0 && peer->id != filter_peer_id) continue;

        // Get trust score via the callback wired in node startup
        double trust_score = -1.0;
        if (g_node_context.GetPeerTrustScore) {
            trust_score = g_node_context.GetPeerTrustScore(peer->id);
        }

        // Determine trust tier from score
        const char* trust_tier = "UNKNOWN";
        if (trust_score >= 0.0) {
            if (trust_score >= TrustScore::TIER_VETERAN) {
                trust_tier = "VETERAN";
            } else if (trust_score >= TrustScore::TIER_TRUSTED) {
                trust_tier = "TRUSTED";
            } else if (trust_score >= TrustScore::TIER_ESTABLISHED) {
                trust_tier = "ESTABLISHED";
            } else if (trust_score >= TrustScore::TIER_NEW) {
                trust_tier = "NEW";
            } else {
                trust_tier = "UNTRUSTED";
            }
        }

        // Pull inbound status from CNode (source of truth)
        bool is_inbound = false;
        if (g_node_context.connman) {
            CNode* pnode = g_node_context.connman->GetNode(peer->id);
            if (pnode) {
                is_inbound = pnode->fInbound;
            }
        }

        if (!first) oss << ",";
        first = false;

        oss << "{";
        oss << "\"peer_id\":" << peer->id << ",";
        oss << std::fixed << std::setprecision(2);
        oss << "\"trust_score\":" << trust_score << ",";
        oss << "\"trust_tier\":\"" << trust_tier << "\",";
        oss << "\"is_inbound\":" << (is_inbound ? "true" : "false");
        oss << "}";
    }

    oss << "]";

    JsonObject result;
    result["peers"] = oss.str();
    result["count"] = std::to_string(peers.size());
    return result;
}

// ============ Help Documentation ============

std::vector<RpcCommandInfo> get_rpc_help() {
    return {
        {
            "getmydigitaldna",
            "Get this node's Digital DNA identity",
            "None",
            "Object with address, latency fingerprint, timing signature, perspective proof",
            "getmydigitaldna"
        },
        {
            "registerdigitaldna",
            "Register this node's identity on-chain (requires collected DNA)",
            "None",
            "Object with status (success/error) and message",
            "registerdigitaldna"
        },
        {
            "getdigitaldna",
            "Get Digital DNA for any registered address",
            "address (string) - 40-character hex address",
            "Object with full Digital DNA details",
            "getdigitaldna {\"address\": \"0123456789abcdef0123456789abcdef01234567\"}"
        },
        {
            "comparedigitaldna",
            "Compare two identities for similarity (Sybil detection)",
            "address1 (string), address2 (string) - two addresses to compare",
            "Object with similarity scores and verdict (SAME_IDENTITY/SUSPICIOUS/DIFFERENT)",
            "comparedigitaldna {\"address1\": \"...\", \"address2\": \"...\"}"
        },
        {
            "findsimilaridentities",
            "Find identities similar to a given address",
            "address (string), threshold (optional, default 0.70)",
            "Array of similar identities with similarity scores",
            "findsimilaridentities {\"address\": \"...\", \"threshold\": 0.8}"
        },
        {
            "listdigitaldna",
            "List all registered identities",
            "limit (optional, default 100), offset (optional, default 0)",
            "Array of registered identities",
            "listdigitaldna {\"limit\": 50, \"offset\": 0}"
        },
        {
            "getdigitaldnastats",
            "Get network-wide identity statistics",
            "None",
            "Object with total identities, region distribution, Sybil detection summary",
            "getdigitaldnastats"
        },
        {
            "collectdigitaldna",
            "Start/check DNA collection process",
            "action (string) - 'start', 'stop', or 'status' (default)",
            "Collection status and progress",
            "collectdigitaldna {\"action\": \"start\"}"
        },
        {
            "validatedigitaldna",
            "Validate a Digital DNA proof",
            "address (string) - address to validate",
            "Validation results and Sybil check",
            "validatedigitaldna {\"address\": \"...\"}"
        },
        {
            "getlatencyfingerprint",
            "Get latency fingerprint (live measurement or for address)",
            "address (optional) - if provided, get stored fingerprint",
            "RTT measurements to all seed nodes",
            "getlatencyfingerprint  OR  getlatencyfingerprint {\"address\": \"...\"}"
        },
        {
            "gettimingsignature",
            "Get timing signature (live benchmark or for address)",
            "address (optional), iterations (optional, default 1M)",
            "VDF timing metrics",
            "gettimingsignature  OR  gettimingsignature {\"iterations\": 5000000}"
        },
        {
            "getperspectiveproof",
            "Get perspective proof for an address",
            "address (string) - address to query",
            "Peer observation statistics",
            "getperspectiveproof {\"address\": \"...\"}"
        },
        {
            "dumpdigitaldna",
            "Dump all DNA identities with full dimension data for offline calibration",
            "None",
            "Array of all registered identities with all 8 dimension details",
            "dumpdigitaldna"
        },
        {
            "getdigitaldnahistory",
            "Get DNA change history for a MIK identity (detect hardware/location changes)",
            "mik (string) - 40-character hex MIK identity",
            "Change count, current hash, and array of archived DNA snapshots",
            "getdigitaldnahistory {\"mik\": \"0123456789abcdef0123456789abcdef01234567\"}"
        },
        {
            "getdnamonitor",
            "Network-wide DNA monitoring dashboard with Sybil cluster detection, rotation alerts, dimension coverage, and health score",
            "None",
            "Object with sybil_clusters, rotation_alerts, dimension_coverage, trust_distribution, health_score, health_grade",
            "getdnamonitor"
        },
        {
            "getpeertrust",
            "Get trust scores for all connected peers (or a specific peer)",
            "peer_id (optional, int) - filter to a specific peer",
            "Object with count and peers array [{peer_id, trust_score, trust_tier, is_inbound}]",
            "getpeertrust  OR  getpeertrust {\"peer_id\": 3}"
        },
        {
            "getverificationstatus",
            "Get DNA verification status and attestation summary for a MIK identity",
            "mik (string) - 40-character hex MIK identity",
            "Object with status (UNVERIFIED/PENDING/VERIFIED/FAILED), attestation_count, pass_count, fail_count, verifiers",
            "getverificationstatus {\"mik\": \"0123456789abcdef0123456789abcdef01234567\"}"
        },
        {
            "listattestations",
            "List all attestations for a MIK identity with per-dimension measurement details",
            "mik (string) - 40-character hex MIK identity",
            "Array of attestation objects with verifier, height, timestamp, VDF/BW/latency results",
            "listattestations {\"mik\": \"0123456789abcdef0123456789abcdef01234567\"}"
        },
        {
            "getverificationconfig",
            "Get current DNA verification protocol configuration parameters",
            "None",
            "Object with verifier_count, quorum, tolerances, timeouts, pending count",
            "getverificationconfig"
        }
    };
}

} // namespace digital_dna
