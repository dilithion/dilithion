// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <x402/facilitator.h>
#include <core/node_context.h>
#include <digital_dna/trust_score.h>
#include <digital_dna/dna_registry_db.h>
#include <vdf/vdf.h>
#include <crypto/sha3.h>
#include <util/base58.h>
#include <iostream>
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>
#include <iomanip>

// Dilithium3 verification (linked at build time)
extern "C" {
    int pqcrystals_dilithium3_ref_verify(const uint8_t *sig, size_t siglen,
                                         const uint8_t *m, size_t mlen,
                                         const uint8_t *ctx, size_t ctxlen,
                                         const uint8_t *pk);
}

namespace x402 {

// Dilithium3 constants
static constexpr size_t DILITHIUM3_PUBKEY_SIZE = 1952;
static constexpr size_t DILITHIUM3_SIG_SIZE = 3309;

// Challenge expiry
static constexpr uint64_t SIWX_CHALLENGE_TTL_SEC = 300;   // 5 minutes
static constexpr uint64_t VDF_DEFAULT_ITERATIONS = 100000; // 100K
static constexpr uint64_t VDF_DEFAULT_TIMEOUT_SEC = 30;
static constexpr size_t MAX_PENDING_CHALLENGES = 1000;

CFacilitator::CFacilitator() {}

void CFacilitator::RegisterUTXOSet(CUTXOSet* utxo_set) {
    m_vma.RegisterUTXOSet(utxo_set);
}

void CFacilitator::RegisterMempool(CTxMemPool* mempool) {
    m_vma.RegisterMempool(mempool);
}

void CFacilitator::RegisterChainState(CChainState* chainstate) {
    m_vma.RegisterChainState(chainstate);
}

void CFacilitator::RegisterNodeContext(NodeContext* ctx) {
    m_node_ctx = ctx;
}

bool CFacilitator::IsX402Request(const std::string& path) {
    return path.find("/x402/") == 0;
}

std::string CFacilitator::HandleRequest(const std::string& method,
                                         const std::string& path,
                                         const std::string& body,
                                         const std::string& clientIP) {
    // Remove /x402/ prefix
    std::string subpath = path.substr(6);  // Skip "/x402/"

    // Separate endpoint, sub-endpoint, and query string
    std::string endpoint;
    std::string param;
    std::string query;

    // Extract query string first
    size_t qmark = subpath.find('?');
    std::string pathPart = subpath;
    if (qmark != std::string::npos) {
        query = subpath.substr(qmark + 1);
        pathPart = subpath.substr(0, qmark);
    }

    size_t slash = pathPart.find('/');
    if (slash != std::string::npos) {
        endpoint = pathPart.substr(0, slash);
        param = pathPart.substr(slash + 1);
    } else {
        endpoint = pathPart;
    }

    // Route to handlers — core endpoints
    if (endpoint == "verify" && method == "POST") {
        return HandleVerify(body, clientIP);
    }
    else if (endpoint == "settle" && method == "POST") {
        return HandleSettle(body, clientIP);
    }
    else if (endpoint == "supported" && method == "GET") {
        return HandleSupported(clientIP);
    }
    else if (endpoint == "status" && method == "GET") {
        if (param.empty()) {
            return BuildErrorResponse(400, "Missing txid parameter");
        }
        return HandleStatus(param, clientIP);
    }
    // Extension endpoints
    else if (endpoint == "dna-attest" && method == "GET") {
        return HandleDnaAttest(query, clientIP);
    }
    else if (endpoint == "vdf-challenge" && method == "POST") {
        return HandleVdfChallenge(body, clientIP);
    }
    else if (endpoint == "vdf-verify" && method == "POST") {
        return HandleVdfVerify(body, clientIP);
    }
    else if (endpoint == "siwx") {
        // Sub-route: /x402/siwx/challenge or /x402/siwx/verify
        if (param == "challenge" && method == "POST") {
            return HandleSiwxChallenge(body, clientIP);
        }
        else if (param == "verify" && method == "POST") {
            return HandleSiwxVerify(body, clientIP);
        }
        return BuildErrorResponse(404, "Unknown SIWX endpoint");
    }
    else {
        return BuildHTTPResponse(404, "{\"error\":\"Not found\",\"path\":\"" + path + "\"}");
    }
}

// ============================================================================
// Core Endpoint Handlers (unchanged)
// ============================================================================

std::string CFacilitator::HandleVerify(const std::string& body, const std::string& clientIP) {
    std::string rawTx, recipient;
    int64_t amount = 0;

    if (!ExtractString(body, "rawTransaction", rawTx)) {
        return BuildErrorResponse(400, "Missing rawTransaction field");
    }
    if (!ExtractString(body, "recipient", recipient)) {
        return BuildErrorResponse(400, "Missing recipient field");
    }
    if (!ExtractInt(body, "amount", amount)) {
        return BuildErrorResponse(400, "Missing or invalid amount field");
    }
    if (amount <= 0) {
        return BuildErrorResponse(400, "Amount must be positive");
    }

    VerifyResult result;
    if (!m_vma.VerifyPayment(rawTx, recipient, amount, result)) {
        return BuildErrorResponse(500, "Verification engine error");
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"valid\":" << (result.valid ? "true" : "false") << ",";
    oss << "\"reason\":\"" << result.reason << "\",";
    oss << "\"payerAddress\":\"" << result.payerAddress << "\",";
    oss << "\"amount\":" << result.amount << ",";
    oss << "\"tier\":\"" << (m_vma.IsMicropayment(amount) ? "micropayment" : "standard") << "\",";
    oss << "\"confirmationsRequired\":" << (m_vma.IsMicropayment(amount) ? 0 : 1);
    oss << "}";

    return BuildHTTPResponse(result.valid ? 200 : 400, oss.str());
}

std::string CFacilitator::HandleSettle(const std::string& body, const std::string& clientIP) {
    std::string rawTx, recipient;
    int64_t amount = 0;

    if (!ExtractString(body, "rawTransaction", rawTx)) {
        return BuildErrorResponse(400, "Missing rawTransaction field");
    }
    if (!ExtractString(body, "recipient", recipient)) {
        return BuildErrorResponse(400, "Missing recipient field");
    }
    if (!ExtractInt(body, "amount", amount)) {
        return BuildErrorResponse(400, "Missing or invalid amount field");
    }
    if (amount <= 0) {
        return BuildErrorResponse(400, "Amount must be positive");
    }

    SettlementResult result;
    if (!m_vma.SettlePayment(rawTx, recipient, amount, result)) {
        return BuildErrorResponse(500, "Settlement engine error");
    }

    return BuildHTTPResponse(result.success ? 200 : 400, result.ToJSON());
}

std::string CFacilitator::HandleSupported(const std::string& clientIP) {
    FacilitatorInfo info;
    info.version = "2.0";
    info.schemes = {"exact"};
    info.networks = {NETWORK_ID};
    info.assets = {ASSET_ID};
    info.micropaymentThreshold = m_vma.GetMicropaymentThreshold();
    info.vmaEnabled = true;

    // Advertise extensions in JSON
    std::string base = info.ToJSON();

    // Inject extensions list before closing brace
    std::string extensions = ",\"extensions\":[\"dna-trust\",\"vdf-challenge\",\"siwx-dilithium\"]";
    if (base.size() > 1 && base.back() == '}') {
        base.insert(base.size() - 1, extensions);
    }

    return BuildHTTPResponse(200, base);
}

std::string CFacilitator::HandleStatus(const std::string& txid, const std::string& clientIP) {
    int confirmations = m_vma.GetConfirmations(txid);

    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << txid << "\",";
    oss << "\"confirmations\":" << confirmations << ",";
    if (confirmations >= 0) {
        oss << "\"status\":\"" << (confirmations == 0 ? "mempool" : "confirmed") << "\"";
    } else {
        oss << "\"status\":\"not_found\"";
    }
    oss << "}";

    return BuildHTTPResponse(confirmations >= 0 ? 200 : 404, oss.str());
}

// ============================================================================
// Extension: DNA Trust Attestation
// ============================================================================

std::string CFacilitator::HandleDnaAttest(const std::string& query, const std::string& clientIP) {
    if (!m_node_ctx) {
        return BuildErrorResponse(503, "Node context not available");
    }
    if (!m_node_ctx->trust_manager) {
        return BuildErrorResponse(503, "Trust manager not initialized");
    }

    // Parse ?address=ADDR from query string
    std::string address;
    size_t pos = query.find("address=");
    if (pos == std::string::npos) {
        return BuildErrorResponse(400, "Missing address parameter");
    }
    address = query.substr(pos + 8);
    // Trim at & if there are more params
    size_t amp = address.find('&');
    if (amp != std::string::npos) {
        address = address.substr(0, amp);
    }
    if (address.empty()) {
        return BuildErrorResponse(400, "Empty address parameter");
    }

    // Decode the DilV address to get the 20-byte pubkey hash
    // Address format: Base58Check(0x1E || hash20)
    std::vector<uint8_t> decoded;
    if (!DecodeBase58Check(address, decoded) || decoded.size() != 21 || decoded[0] != 0x1E) {
        return BuildErrorResponse(400, "Invalid DilV address");
    }
    std::array<uint8_t, 20> addr_key;
    std::memcpy(addr_key.data(), decoded.data() + 1, 20);

    // Build attestation response
    DnaTrustAttestation att;
    att.address = address;
    att.network = NETWORK_ID;
    att.timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    if (m_node_ctx->trust_manager->has_score(addr_key)) {
        digital_dna::TrustScore score = m_node_ctx->trust_manager->get_score(addr_key);
        att.trustScore = score.current_score;
        att.trustTier = score.tier_name();
        att.registrationHeight = score.registration_height;
        att.consecutiveHeartbeats = score.consecutive_heartbeats;
        att.isRegistered = true;
    } else {
        att.trustScore = 0.0;
        att.trustTier = "UNTRUSTED";
        att.registrationHeight = 0;
        att.consecutiveHeartbeats = 0;
        att.isRegistered = false;
    }

    return BuildHTTPResponse(200, att.ToJSON());
}

// ============================================================================
// Extension: VDF Challenge
// ============================================================================

std::string CFacilitator::HandleVdfChallenge(const std::string& body, const std::string& clientIP) {
    // Parse optional parameters
    std::string address;
    int64_t iterations = 0;
    ExtractString(body, "address", address);
    ExtractInt(body, "iterations", iterations);

    if (iterations <= 0) {
        iterations = static_cast<int64_t>(VDF_DEFAULT_ITERATIONS);
    }

    // Generate random challenge seed
    std::random_device rd;
    std::mt19937_64 gen(rd());
    uint8_t seed[32];
    for (int i = 0; i < 4; i++) {
        uint64_t val = gen();
        std::memcpy(seed + i * 8, &val, 8);
    }

    // Hash seed with address for uniqueness
    if (!address.empty()) {
        uint8_t combined[64];
        std::memcpy(combined, seed, 32);
        uint8_t addr_hash[32];
        SHA3_256(reinterpret_cast<const uint8_t*>(address.data()), address.size(), addr_hash);
        std::memcpy(combined + 32, addr_hash, 32);
        SHA3_256(combined, 64, seed);
    }

    std::string seedHex = BytesToHex(seed, 32);

    // Generate challenge ID from seed hash
    uint8_t idHash[32];
    uint64_t now = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    uint8_t idInput[40];
    std::memcpy(idInput, seed, 32);
    std::memcpy(idInput + 32, &now, 8);
    SHA3_256(idInput, 40, idHash);
    std::string challengeId = BytesToHex(idHash, 16); // 16 bytes = 32 hex chars

    // Store pending challenge
    {
        std::lock_guard<std::mutex> lock(m_vdf_mutex);
        CleanupExpiredChallenges();
        if (m_vdf_challenges.size() >= MAX_PENDING_CHALLENGES) {
            return BuildErrorResponse(429, "Too many pending challenges");
        }
        m_vdf_challenges[challengeId] = {
            seedHex,
            static_cast<uint64_t>(iterations),
            now,
            VDF_DEFAULT_TIMEOUT_SEC
        };
    }

    // Build response
    VdfChallengeResponse resp;
    resp.challengeId = challengeId;
    resp.seed = seedHex;
    resp.iterations = static_cast<uint64_t>(iterations);
    resp.timeoutSec = VDF_DEFAULT_TIMEOUT_SEC;
    resp.network = NETWORK_ID;

    return BuildHTTPResponse(200, resp.ToJSON());
}

std::string CFacilitator::HandleVdfVerify(const std::string& body, const std::string& clientIP) {
    std::string challengeId, outputHex, proofHex;
    int64_t iterations = 0;

    if (!ExtractString(body, "challengeId", challengeId)) {
        return BuildErrorResponse(400, "Missing challengeId");
    }
    if (!ExtractString(body, "output", outputHex)) {
        return BuildErrorResponse(400, "Missing output");
    }
    if (!ExtractString(body, "proof", proofHex)) {
        return BuildErrorResponse(400, "Missing proof");
    }
    if (!ExtractInt(body, "iterations", iterations) || iterations <= 0) {
        return BuildErrorResponse(400, "Missing or invalid iterations");
    }

    // Look up pending challenge
    std::string seedHex;
    uint64_t expectedIters;
    {
        std::lock_guard<std::mutex> lock(m_vdf_mutex);
        auto it = m_vdf_challenges.find(challengeId);
        if (it == m_vdf_challenges.end()) {
            VdfVerifyResult fail;
            fail.valid = false;
            fail.challengeId = challengeId;
            fail.iterations = 0;
            fail.reason = "Unknown or expired challenge";
            return BuildHTTPResponse(404, fail.ToJSON());
        }

        uint64_t now = static_cast<uint64_t>(
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        if (now > it->second.issuedAt + it->second.timeoutSec) {
            m_vdf_challenges.erase(it);
            VdfVerifyResult fail;
            fail.valid = false;
            fail.challengeId = challengeId;
            fail.iterations = 0;
            fail.reason = "Challenge expired";
            return BuildHTTPResponse(400, fail.ToJSON());
        }

        seedHex = it->second.seed;
        expectedIters = it->second.iterations;
        m_vdf_challenges.erase(it); // One-time use
    }

    // Verify iterations match
    if (static_cast<uint64_t>(iterations) != expectedIters) {
        VdfVerifyResult fail;
        fail.valid = false;
        fail.challengeId = challengeId;
        fail.iterations = static_cast<uint64_t>(iterations);
        fail.reason = "Iteration count mismatch";
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Decode hex values
    std::vector<uint8_t> seedBytes, outputBytes, proofBytes;
    if (!HexToBytes(seedHex, seedBytes) || seedBytes.size() != 32) {
        return BuildErrorResponse(500, "Internal error: invalid seed");
    }
    if (!HexToBytes(outputHex, outputBytes) || outputBytes.size() != 32) {
        VdfVerifyResult fail;
        fail.valid = false;
        fail.challengeId = challengeId;
        fail.iterations = static_cast<uint64_t>(iterations);
        fail.reason = "Invalid output format (expected 32 bytes hex)";
        return BuildHTTPResponse(400, fail.ToJSON());
    }
    if (!HexToBytes(proofHex, proofBytes) || proofBytes.empty()) {
        VdfVerifyResult fail;
        fail.valid = false;
        fail.challengeId = challengeId;
        fail.iterations = static_cast<uint64_t>(iterations);
        fail.reason = "Invalid proof format";
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Build VDFResult and verify
    std::array<uint8_t, 32> challenge;
    std::memcpy(challenge.data(), seedBytes.data(), 32);

    vdf::VDFResult vdfResult;
    std::memcpy(vdfResult.output.data(), outputBytes.data(), 32);
    vdfResult.proof = proofBytes;
    vdfResult.iterations = static_cast<uint64_t>(iterations);

    bool valid = vdf::verify(challenge, vdfResult);

    VdfVerifyResult result;
    result.valid = valid;
    result.challengeId = challengeId;
    result.iterations = static_cast<uint64_t>(iterations);
    result.reason = valid ? "Proof verified" : "Cryptographic verification failed";

    return BuildHTTPResponse(valid ? 200 : 400, result.ToJSON());
}

// ============================================================================
// Extension: SIWX (Sign-In-With-X) Dilithium3
// ============================================================================

std::string CFacilitator::HandleSiwxChallenge(const std::string& body, const std::string& clientIP) {
    std::string address, domain;

    if (!ExtractString(body, "address", address) || address.empty()) {
        return BuildErrorResponse(400, "Missing address");
    }
    if (!ExtractString(body, "domain", domain)) {
        domain = "dilithion.org"; // Default domain
    }

    // Generate random nonce
    std::random_device rd;
    std::mt19937_64 gen(rd());
    uint8_t nonce[32];
    for (int i = 0; i < 4; i++) {
        uint64_t val = gen();
        std::memcpy(nonce + i * 8, &val, 8);
    }

    uint64_t now = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    // Generate challenge ID
    uint8_t idInput[40];
    std::memcpy(idInput, nonce, 32);
    std::memcpy(idInput + 32, &now, 8);
    uint8_t idHash[32];
    SHA3_256(idInput, 40, idHash);
    std::string challengeId = BytesToHex(idHash, 16);

    SIWXChallenge challenge;
    challenge.challengeId = challengeId;
    challenge.nonce = BytesToHex(nonce, 32);
    challenge.domain = domain;
    challenge.address = address;
    challenge.network = NETWORK_ID;
    challenge.issuedAt = now;
    challenge.expiresAt = now + SIWX_CHALLENGE_TTL_SEC;

    // Store pending challenge
    {
        std::lock_guard<std::mutex> lock(m_siwx_mutex);
        // Cleanup old challenges opportunistically
        auto it = m_siwx_challenges.begin();
        while (it != m_siwx_challenges.end()) {
            if (now > it->second.expiresAt) {
                it = m_siwx_challenges.erase(it);
            } else {
                ++it;
            }
        }
        if (m_siwx_challenges.size() >= MAX_PENDING_CHALLENGES) {
            return BuildErrorResponse(429, "Too many pending challenges");
        }
        m_siwx_challenges[challengeId] = challenge;
    }

    return BuildHTTPResponse(200, challenge.ToJSON());
}

std::string CFacilitator::HandleSiwxVerify(const std::string& body, const std::string& clientIP) {
    std::string challengeId, signatureHex, publicKeyHex, address;

    if (!ExtractString(body, "challengeId", challengeId)) {
        return BuildErrorResponse(400, "Missing challengeId");
    }
    if (!ExtractString(body, "signature", signatureHex)) {
        return BuildErrorResponse(400, "Missing signature");
    }
    if (!ExtractString(body, "publicKey", publicKeyHex)) {
        return BuildErrorResponse(400, "Missing publicKey");
    }
    if (!ExtractString(body, "address", address)) {
        return BuildErrorResponse(400, "Missing address");
    }

    // Look up and consume the challenge
    SIWXChallenge challenge;
    {
        std::lock_guard<std::mutex> lock(m_siwx_mutex);
        auto it = m_siwx_challenges.find(challengeId);
        if (it == m_siwx_challenges.end()) {
            SIWXResult fail;
            fail.valid = false;
            fail.address = address;
            fail.reason = "Unknown or expired challenge";
            fail.network = NETWORK_ID;
            return BuildHTTPResponse(404, fail.ToJSON());
        }

        uint64_t now = static_cast<uint64_t>(
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
        if (now > it->second.expiresAt) {
            m_siwx_challenges.erase(it);
            SIWXResult fail;
            fail.valid = false;
            fail.address = address;
            fail.reason = "Challenge expired";
            fail.network = NETWORK_ID;
            return BuildHTTPResponse(400, fail.ToJSON());
        }

        challenge = it->second;
        m_siwx_challenges.erase(it); // One-time use
    }

    // Verify claimed address matches challenge
    if (challenge.address != address) {
        SIWXResult fail;
        fail.valid = false;
        fail.address = address;
        fail.reason = "Address does not match challenge";
        fail.network = NETWORK_ID;
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Decode public key and signature from hex
    std::vector<uint8_t> pubkeyBytes, sigBytes;
    if (!HexToBytes(publicKeyHex, pubkeyBytes) || pubkeyBytes.size() != DILITHIUM3_PUBKEY_SIZE) {
        SIWXResult fail;
        fail.valid = false;
        fail.address = address;
        fail.reason = "Invalid public key (expected 1952 bytes)";
        fail.network = NETWORK_ID;
        return BuildHTTPResponse(400, fail.ToJSON());
    }
    if (!HexToBytes(signatureHex, sigBytes) || sigBytes.empty()) {
        SIWXResult fail;
        fail.valid = false;
        fail.address = address;
        fail.reason = "Invalid signature";
        fail.network = NETWORK_ID;
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Step 1: Verify address binding — pubkey must hash to the claimed address
    // Compute SHA3-256(SHA3-256(pubkey))[0..20] and compare against address
    uint8_t hash1[32], hash2[32];
    SHA3_256(pubkeyBytes.data(), pubkeyBytes.size(), hash1);
    SHA3_256(hash1, 32, hash2);

    // Decode claimed address to get the expected 20-byte pubkey hash
    std::vector<uint8_t> addrDecoded;
    if (!DecodeBase58Check(address, addrDecoded) || addrDecoded.size() != 21 || addrDecoded[0] != 0x1E) {
        SIWXResult fail;
        fail.valid = false;
        fail.address = address;
        fail.reason = "Invalid DilV address format";
        fail.network = NETWORK_ID;
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Compare pubkey hash against address hash
    if (std::memcmp(hash2, addrDecoded.data() + 1, 20) != 0) {
        SIWXResult fail;
        fail.valid = false;
        fail.address = address;
        fail.reason = "Public key does not match claimed address";
        fail.network = NETWORK_ID;
        return BuildHTTPResponse(400, fail.ToJSON());
    }

    // Step 2: Verify Dilithium3 signature over the nonce
    std::vector<uint8_t> nonceBytes;
    if (!HexToBytes(challenge.nonce, nonceBytes) || nonceBytes.size() != 32) {
        return BuildErrorResponse(500, "Internal error: invalid stored nonce");
    }

    int result = pqcrystals_dilithium3_ref_verify(
        sigBytes.data(), sigBytes.size(),
        nonceBytes.data(), nonceBytes.size(),
        nullptr, 0,  // No context
        pubkeyBytes.data()
    );

    bool sigValid = (result == 0);

    SIWXResult siwxResult;
    siwxResult.valid = sigValid;
    siwxResult.address = address;
    siwxResult.network = NETWORK_ID;
    siwxResult.reason = sigValid ? "Signature verified" : "Dilithium3 signature verification failed";

    return BuildHTTPResponse(sigValid ? 200 : 400, siwxResult.ToJSON());
}

// ============================================================================
// Response & Utility Helpers
// ============================================================================

std::string CFacilitator::BuildHTTPResponse(int statusCode, const std::string& body) {
    std::ostringstream oss;
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 400: statusText = "Bad Request"; break;
        case 404: statusText = "Not Found"; break;
        case 429: statusText = "Too Many Requests"; break;
        case 500: statusText = "Internal Server Error"; break;
        case 503: statusText = "Service Unavailable"; break;
        default: statusText = "Unknown"; break;
    }

    oss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    oss << "Content-Type: application/json\r\n";
    // CVE-2026-RPC-CORS: NO CORS headers. Same-origin only.
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

std::string CFacilitator::BuildErrorResponse(int httpCode, const std::string& message) {
    std::ostringstream oss;
    oss << "{\"error\":\"" << message << "\"}";
    return BuildHTTPResponse(httpCode, oss.str());
}

bool CFacilitator::ExtractString(const std::string& json, const std::string& key, std::string& value) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return false;

    size_t q1 = json.find('"', colon);
    if (q1 == std::string::npos) return false;

    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return false;

    value = json.substr(q1 + 1, q2 - q1 - 1);
    return true;
}

bool CFacilitator::ExtractInt(const std::string& json, const std::string& key, int64_t& value) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return false;

    size_t colon = json.find(':', pos + search.size());
    if (colon == std::string::npos) return false;

    size_t numStart = json.find_first_not_of(" \t\n\r", colon + 1);
    if (numStart == std::string::npos) return false;

    try {
        value = std::stoll(json.substr(numStart));
        return true;
    } catch (...) {
        return false;
    }
}

std::string CFacilitator::BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool CFacilitator::HexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        char hi = hex[i], lo = hex[i + 1];
        uint8_t byte = 0;
        if (hi >= '0' && hi <= '9') byte = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') byte = (hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') byte = (hi - 'A' + 10) << 4;
        else return false;
        if (lo >= '0' && lo <= '9') byte |= (lo - '0');
        else if (lo >= 'a' && lo <= 'f') byte |= (lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') byte |= (lo - 'A' + 10);
        else return false;
        out.push_back(byte);
    }
    return true;
}

void CFacilitator::CleanupExpiredChallenges() {
    uint64_t now = static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    // Cleanup VDF challenges (caller must hold m_vdf_mutex)
    auto it = m_vdf_challenges.begin();
    while (it != m_vdf_challenges.end()) {
        if (now > it->second.issuedAt + it->second.timeoutSec) {
            it = m_vdf_challenges.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// Extension Type ToJSON() implementations
// ============================================================================

std::string DnaTrustAttestation::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"address\":\"" << address << "\",";
    oss << "\"network\":\"" << network << "\",";
    oss << "\"trustScore\":" << std::fixed << std::setprecision(2) << trustScore << ",";
    oss << "\"trustTier\":\"" << trustTier << "\",";
    oss << "\"registrationHeight\":" << registrationHeight << ",";
    oss << "\"consecutiveHeartbeats\":" << consecutiveHeartbeats << ",";
    oss << "\"timestamp\":" << timestamp << ",";
    oss << "\"isRegistered\":" << (isRegistered ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string VdfChallengeResponse::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"challengeId\":\"" << challengeId << "\",";
    oss << "\"seed\":\"" << seed << "\",";
    oss << "\"iterations\":" << iterations << ",";
    oss << "\"timeoutSec\":" << timeoutSec << ",";
    oss << "\"network\":\"" << network << "\"";
    oss << "}";
    return oss.str();
}

std::string VdfVerifyResult::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"valid\":" << (valid ? "true" : "false") << ",";
    oss << "\"challengeId\":\"" << challengeId << "\",";
    oss << "\"iterations\":" << iterations << ",";
    oss << "\"reason\":\"" << reason << "\"";
    oss << "}";
    return oss.str();
}

std::string SIWXChallenge::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"challengeId\":\"" << challengeId << "\",";
    oss << "\"nonce\":\"" << nonce << "\",";
    oss << "\"domain\":\"" << domain << "\",";
    oss << "\"address\":\"" << address << "\",";
    oss << "\"network\":\"" << network << "\",";
    oss << "\"issuedAt\":" << issuedAt << ",";
    oss << "\"expiresAt\":" << expiresAt;
    oss << "}";
    return oss.str();
}

std::string SIWXResult::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"valid\":" << (valid ? "true" : "false") << ",";
    oss << "\"address\":\"" << address << "\",";
    oss << "\"reason\":\"" << reason << "\",";
    oss << "\"network\":\"" << network << "\"";
    oss << "}";
    return oss.str();
}

} // namespace x402
