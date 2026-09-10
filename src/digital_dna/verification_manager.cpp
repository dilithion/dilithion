// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <digital_dna/verification_manager.h>
#include <type_traits>   // static_assert on thread_local destructibility
#include <digital_dna/dna_registry_db.h>
#include <digital_dna/trust_score.h>
#include <dfmp/mik.h>
#include <crypto/sha3.h>
#include <vdf/vdf.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <random>

namespace digital_dna {
namespace verification {

// ============================================================================
// Construction
// ============================================================================

VerificationManager::VerificationManager(DNARegistryDB* registry, TrustScoreManager* trust)
    : registry_(registry), trust_(trust) {}

void VerificationManager::SetMyMIK(const std::array<uint8_t, 20>& mik,
                                    const std::vector<uint8_t>& pubkey,
                                    const void* privkey_ptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    my_mik_ = mik;
    my_pubkey_ = pubkey;
    my_mik_key_ = privkey_ptr;
    has_mik_ = true;
}

// ============================================================================
// Helpers
// ============================================================================

uint64_t VerificationManager::RandomNonce() {
    thread_local std::mt19937_64 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    static_assert(std::is_trivially_destructible<std::mt19937_64>::value,
                  "a thread_local's destructor would run on freed storage here");
    // ⚠️ On this toolchain a thread_local's destructor runs AFTER its storage has
    // been free()d: GCC on mingw-w64 implements thread_local with emutls, and
    // emutls' pthread key is destroyed before the key libstdc++ uses to run C++
    // destructors. So a thread_local that is not trivially destructible reads and
    // acts on freed memory at every thread exit. mt19937_64 has no destructor to
    // run -- asserted rather than assumed, and enforced tree-wide by
    // scripts/check_thread_local_guard.sh. The assert sits ON the declaration
    // deliberately: the guard requires it within six lines, so that moving the
    // declaration cannot leave the proof behind. See EpochThreadRecord in
    // src/consensus/chain.cpp for what to do when state DOES need an exit hook.
    return rng();
}

std::array<uint8_t, 32> VerificationManager::ComputeVDFSeed(
    const std::array<uint8_t, 32>& block_hash,
    const std::array<uint8_t, 20>& verifier_mik,
    const std::array<uint8_t, 20>& target_mik)
{
    // SHA3(block_hash || verifier_mik || target_mik || "vdf")
    std::vector<uint8_t> preimage;
    preimage.reserve(32 + 20 + 20 + 3);
    preimage.insert(preimage.end(), block_hash.begin(), block_hash.end());
    preimage.insert(preimage.end(), verifier_mik.begin(), verifier_mik.end());
    preimage.insert(preimage.end(), target_mik.begin(), target_mik.end());
    preimage.push_back('v'); preimage.push_back('d'); preimage.push_back('f');

    std::array<uint8_t, 32> seed;
    SHA3_256(preimage.data(), preimage.size(), seed.data());
    return seed;
}

bool VerificationManager::IsRateLimited(const std::array<uint8_t, 20>& target_mik) const {
    auto key = std::make_pair(my_mik_, target_mik);
    auto it = last_verification_time_.find(key);
    if (it == last_verification_time_.end()) return false;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (now - it->second) < VERIFICATION_RATE_LIMIT_SEC;
}

// ============================================================================
// New Registration Handler
// ============================================================================

void VerificationManager::OnNewRegistration(
    const std::array<uint8_t, 20>& target_mik,
    uint32_t reg_height,
    const std::array<uint8_t, 32>& block_hash)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (!has_mik_) return;  // Relay-only nodes don't verify
    if (target_mik == my_mik_) return;  // Can't verify ourselves
    if (!registry_) return;  // Defensive: registry must be available

    // Check if we're a selected verifier
    auto all_miks = registry_->get_all_miks();
    auto verifiers = SelectVerifiers(block_hash, target_mik, all_miks);

    bool is_verifier = false;
    for (const auto& v : verifiers) {
        if (v == my_mik_) { is_verifier = true; break; }
    }
    if (!is_verifier) return;

    // Rate limit check
    if (IsRateLimited(target_mik)) {
        std::cout << "[DNA-VERIFY] Rate-limited: already verified target recently" << std::endl;
        return;
    }

    // Concurrency check
    if (active_verifications_.load() >= MAX_CONCURRENT_VERIFICATIONS) {
        // Queue for later
        queued_.push_back({target_mik, reg_height, block_hash});
        std::cout << "[DNA-VERIFY] Queued verification (active=" << active_verifications_.load() << ")" << std::endl;
        return;
    }

    StartVerificationLocked(target_mik, reg_height, block_hash);
}

bool VerificationManager::StartVerificationLocked(
    const std::array<uint8_t, 20>& target_mik,
    uint32_t reg_height,
    const std::array<uint8_t, 32>& block_hash)
{
    // Find peer connection to target
    int peer_id = -1;
    if (find_peer_by_mik_) {
        peer_id = find_peer_by_mik_(target_mik);
    }
    if (peer_id < 0) {
        std::cout << "[DNA-VERIFY] Target not connected, skipping verification" << std::endl;
        return false;
    }

    // Create pending verification
    PendingVerification pv;
    pv.target_mik = target_mik;
    pv.registration_height = reg_height;
    pv.block_hash = block_hash;
    pv.vdf_seed = ComputeVDFSeed(block_hash, my_mik_, target_mik);
    pv.nonce = RandomNonce();
    pv.peer_id = peer_id;
    pv.state = PendingVerification::WAITING_VDF;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    pv.challenge_sent_time = now;

    // Get target's claimed VDF timing
    if (registry_) {
        auto identity = registry_->get_identity_by_mik(target_mik);
        if (identity) {
            pv.claimed_vdf_iters_per_sec = identity->timing.iterations_per_second;
        }
    }

    pending_[pv.nonce] = pv;
    active_verifications_++;

    // Update rate limit
    last_verification_time_[std::make_pair(my_mik_, target_mik)] = now;

    // Send challenge
    SendVDFChallenge(pv);

    std::cout << "[DNA-VERIFY] Initiated verification for target (peer " << peer_id << ")" << std::endl;
    return true;
}

void VerificationManager::SendVDFChallenge(const PendingVerification& pv) {
    if (!send_challenge_) return;

    VerificationChallenge challenge;
    challenge.target_mik = pv.target_mik;
    challenge.verifier_mik = my_mik_;
    challenge.registration_height = pv.registration_height;
    challenge.vdf_seed = pv.vdf_seed;
    challenge.vdf_iterations = VDF_CHALLENGE_ITERS;
    challenge.nonce = pv.nonce;

    auto data = challenge.serialize();
    send_challenge_(pv.peer_id, data);
}

// ============================================================================
// Challenge Received (we are the target)
// ============================================================================

void VerificationManager::OnChallengeReceived(int peer_id, const std::vector<uint8_t>& data) {
    auto challenge = VerificationChallenge::deserialize(data);
    if (!challenge) {
        std::cout << "[DNA-VERIFY] Invalid challenge from peer " << peer_id << std::endl;
        return;
    }

    // Verify the challenge is for us
    if (challenge->target_mik != my_mik_) {
        std::cout << "[DNA-VERIFY] Challenge not for us, ignoring" << std::endl;
        return;
    }

    // Cap iterations to prevent DoS (max 200K)
    if (challenge->vdf_iterations > 200000) {
        std::cout << "[DNA-VERIFY] Challenge iterations too high (" << challenge->vdf_iterations << "), ignoring" << std::endl;
        return;
    }

    std::cout << "[DNA-VERIFY] Received VDF challenge: " << challenge->vdf_iterations
              << " iterations from peer " << peer_id << std::endl;

    // Compute VDF proof
    vdf::VDFConfig config;
    config.target_iterations = challenge->vdf_iterations;

    auto start = std::chrono::steady_clock::now();
    vdf::VDFResult result = vdf::compute(challenge->vdf_seed, challenge->vdf_iterations, config);
    auto end = std::chrono::steady_clock::now();
    uint64_t elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if (result.proof.empty()) {
        std::cout << "[DNA-VERIFY] VDF computation failed!" << std::endl;
        return;
    }

    // Build response
    VerificationResponse response;
    response.nonce = challenge->nonce;
    response.target_mik = my_mik_;
    response.vdf_output = result.output;
    response.vdf_proof = result.proof;
    response.vdf_elapsed_us = elapsed_us;

    if (send_response_) {
        auto resp_data = response.serialize();
        send_response_(peer_id, resp_data);
        std::cout << "[DNA-VERIFY] Sent VDF response (" << elapsed_us / 1000 << "ms)" << std::endl;
    }
}

// ============================================================================
// Response Received (we are the verifier)
// ============================================================================

void VerificationManager::OnResponseReceived(int peer_id, const std::vector<uint8_t>& data) {
    auto response = VerificationResponse::deserialize(data);
    if (!response) {
        std::cout << "[DNA-VERIFY] Invalid response from peer " << peer_id << std::endl;
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Find the pending verification by nonce
    auto it = pending_.find(response->nonce);
    if (it == pending_.end()) {
        std::cout << "[DNA-VERIFY] No pending verification for nonce, ignoring" << std::endl;
        return;
    }

    PendingVerification& pv = it->second;
    if (pv.state != PendingVerification::WAITING_VDF) {
        return;  // Already processed
    }

    // Verify the VDF proof
    vdf::VDFConfig config;
    config.target_iterations = VDF_CHALLENGE_ITERS;

    vdf::VDFResult vdf_result;
    vdf_result.output = response->vdf_output;
    vdf_result.proof = response->vdf_proof;
    vdf_result.iterations = VDF_CHALLENGE_ITERS;

    bool proof_valid = vdf::verify(pv.vdf_seed, vdf_result, config);
    pv.vdf_proof_valid = proof_valid;

    if (!proof_valid) {
        std::cout << "[DNA-VERIFY] VDF proof INVALID from peer " << peer_id << std::endl;
    } else {
        // Calculate measured iterations per second
        double elapsed_sec = response->vdf_elapsed_us / 1e6;
        if (elapsed_sec > 0.001) {  // Guard against division by zero
            pv.measured_vdf_iters_per_sec = VDF_CHALLENGE_ITERS / elapsed_sec;
        }
        std::cout << "[DNA-VERIFY] VDF proof VALID. Measured: "
                  << static_cast<int>(pv.measured_vdf_iters_per_sec)
                  << " iter/s, Claimed: " << static_cast<int>(pv.claimed_vdf_iters_per_sec) << std::endl;
    }

    pv.state = PendingVerification::COMPLETE;

    // Create and broadcast attestation
    FinalizeAttestation(pv);

    // Cleanup
    active_verifications_--;
    pending_.erase(it);
}

// ============================================================================
// Attestation Creation
// ============================================================================

void VerificationManager::FinalizeAttestation(PendingVerification& pv) {
    if (!has_mik_ || !my_mik_key_) return;

    // Determine VDF pass/fail
    bool vdf_pass = false;
    if (pv.vdf_proof_valid && pv.claimed_vdf_iters_per_sec > 0) {
        double ratio = std::abs(pv.measured_vdf_iters_per_sec - pv.claimed_vdf_iters_per_sec)
                       / pv.claimed_vdf_iters_per_sec;
        vdf_pass = (ratio <= VDF_TIMING_TOLERANCE);
    }

    // Build attestation
    DNAAttestation att;
    att.target_mik = pv.target_mik;
    att.verifier_mik = my_mik_;
    att.registration_height = pv.registration_height;
    att.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    att.vdf_timing.measured_value = pv.measured_vdf_iters_per_sec;
    att.vdf_timing.claimed_value = pv.claimed_vdf_iters_per_sec;
    att.vdf_timing.pass = vdf_pass;

    // Bandwidth and latency not measured in this simplified Phase 2
    // (will be added when bandwidth/latency verification is wired)
    att.bandwidth_up = {0.0, 0.0, true};   // Not measured = pass by default
    att.bandwidth_down = {0.0, 0.0, true};
    att.latency_rtt_ms = 0.0;

    // Overall: VDF must pass. BW is informational for now.
    att.overall_pass = vdf_pass;

    // Sign the attestation body
    auto body = att.serialize_body();
    auto* mik_key = static_cast<const DFMP::CMiningIdentityKey*>(my_mik_key_);
    std::vector<uint8_t> signature;
    if (!mik_key->SignArbitrary(body, signature)) {
        std::cout << "[DNA-VERIFY] Failed to sign attestation!" << std::endl;
        return;
    }
    att.signature = std::move(signature);
    att.verifier_pubkey = my_pubkey_;

    // Store locally
    if (registry_) {
        registry_->store_attestation(att);
    }

    // Update verification status
    UpdateVerificationStatus(pv.target_mik);

    // Update trust score
    if (trust_) {
        if (att.overall_pass) {
            trust_->on_sybil_challenge_cleared(pv.target_mik, pv.registration_height);
        } else {
            trust_->on_sybil_challenge(pv.target_mik, pv.registration_height);
        }
    }

    // Broadcast to network
    if (broadcast_attestation_) {
        auto att_data = att.serialize();
        broadcast_attestation_(att_data);
        std::cout << "[DNA-VERIFY] Broadcast attestation (pass=" << att.overall_pass << ")" << std::endl;
    }
}

// ============================================================================
// Attestation Received (from other verifiers)
// ============================================================================

void VerificationManager::OnAttestationReceived(int peer_id, const std::vector<uint8_t>& data) {
    auto att = DNAAttestation::deserialize(data);
    if (!att) {
        std::cout << "[DNA-VERIFY] Invalid attestation from peer " << peer_id << std::endl;
        return;
    }

    // Verify the Dilithium3 signature
    if (!att->verify_signature()) {
        std::cout << "[DNA-VERIFY] Attestation signature INVALID from peer " << peer_id << std::endl;
        return;
    }

    // Verify the verifier_mik matches the pubkey
    auto derived = DFMP::DeriveIdentityFromMIK(att->verifier_pubkey);
    std::array<uint8_t, 20> derived_arr;
    std::memcpy(derived_arr.data(), derived.data, 20);
    if (derived_arr != att->verifier_mik) {
        std::cout << "[DNA-VERIFY] Attestation verifier MIK mismatch" << std::endl;
        return;
    }

    // Age validation: reject stale attestations by block height
    uint32_t height = current_height_.load();
    if (height > 0) {
        constexpr uint32_t MAX_ATTESTATION_AGE_BLOCKS = 1000;
        if (att->registration_height + MAX_ATTESTATION_AGE_BLOCKS < height) {
            std::cout << "[DNA-VERIFY] Rejecting stale attestation (reg_height="
                      << att->registration_height << " current=" << height << ")" << std::endl;
            return;
        }
    }

    // Timestamp validation: reject if > 24 hours old
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    constexpr int64_t MAX_ATTESTATION_AGE_SEC = 86400;  // 24 hours
    if (att->timestamp > 0 && (now_sec - static_cast<int64_t>(att->timestamp)) > MAX_ATTESTATION_AGE_SEC) {
        std::cout << "[DNA-VERIFY] Rejecting old attestation (age > 24h)" << std::endl;
        return;
    }

    // Store the attestation
    if (registry_) {
        registry_->store_attestation(*att);
    }

    // Update verification status
    UpdateVerificationStatus(att->target_mik);

    std::cout << "[DNA-VERIFY] Stored attestation from verifier for target (pass="
              << att->overall_pass << ")" << std::endl;
}

// ============================================================================
// Status Updates
// ============================================================================

void VerificationManager::UpdateVerificationStatus(const std::array<uint8_t, 20>& target_mik) {
    if (!registry_) return;

    auto status = registry_->get_verification_status(target_mik);

    // Update the DigitalDNA record's verification_status field
    auto identity = registry_->get_identity_by_mik(target_mik);
    if (identity) {
        identity->verification_status = static_cast<uint8_t>(status);
        registry_->update_identity(*identity);
    }

    if (status == VerificationStatus::VERIFIED) {
        std::cout << "[DNA-VERIFY] MIK is now VERIFIED!" << std::endl;
    } else if (status == VerificationStatus::FAILED) {
        std::cout << "[DNA-VERIFY] MIK verification FAILED" << std::endl;
    }
}

// ============================================================================
// Queries
// ============================================================================

VerificationStatus VerificationManager::GetStatus(const std::array<uint8_t, 20>& mik) const {
    if (!registry_) return VerificationStatus::UNVERIFIED;
    return registry_->get_verification_status(mik);
}

std::vector<DNAAttestation> VerificationManager::GetAttestations(const std::array<uint8_t, 20>& mik) const {
    if (!registry_) return {};
    return registry_->get_attestations(mik);
}

bool VerificationManager::IsVerifierFor(const std::array<uint8_t, 20>& target_mik,
                                         const std::array<uint8_t, 32>& block_hash) const {
    if (!has_mik_ || !registry_) return false;
    auto all_miks = registry_->get_all_miks();
    auto verifiers = SelectVerifiers(block_hash, target_mik, all_miks);
    for (const auto& v : verifiers) {
        if (v == my_mik_) return true;
    }
    return false;
}

size_t VerificationManager::PendingCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.size();
}

// ============================================================================
// Periodic Tick (timeout handling)
// ============================================================================

void VerificationManager::Tick(uint32_t current_height) {
    current_height_ = current_height;
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    // Check for timed-out verifications
    std::vector<uint64_t> timed_out;
    for (const auto& [nonce, pv] : pending_) {
        if (pv.state == PendingVerification::WAITING_VDF &&
            (now - pv.challenge_sent_time) > VDF_CHALLENGE_TIMEOUT_SEC) {
            timed_out.push_back(nonce);
        }
    }

    for (uint64_t nonce : timed_out) {
        auto& pv = pending_[nonce];
        std::cout << "[DNA-VERIFY] Verification timed out for peer " << pv.peer_id << std::endl;

        // Create FAIL attestation for timeout
        pv.vdf_proof_valid = false;
        pv.state = PendingVerification::COMPLETE;
        FinalizeAttestation(pv);

        active_verifications_--;
        pending_.erase(nonce);
    }

    // Process queued verifications if slots available
    while (!queued_.empty() && active_verifications_.load() < MAX_CONCURRENT_VERIFICATIONS) {
        auto q = queued_.back();
        queued_.pop_back();
        std::cout << "[DNA-VERIFY] Starting queued verification (remaining=" << queued_.size() << ")" << std::endl;
        StartVerificationLocked(q.target_mik, q.registration_height, q.block_hash);
    }
}

} // namespace verification
} // namespace digital_dna
