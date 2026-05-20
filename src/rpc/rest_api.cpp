// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <rpc/rest_api.h>
#include <rpc/ratelimiter.h>
#include <node/mempool.h>
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <consensus/chain.h>
#include <consensus/fees.h>
#include <consensus/tx_validation.h>
#include <wallet/wallet.h>
#include <util/strencodings.h>
#include <primitives/transaction.h>

#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

// Rate limit endpoint names (matched in ratelimiter.cpp)
static const std::string ENDPOINT_BALANCE = "api_balance";
static const std::string ENDPOINT_UTXOS = "api_utxos";
static const std::string ENDPOINT_TX = "api_tx";
static const std::string ENDPOINT_BROADCAST = "api_broadcast";
static const std::string ENDPOINT_INFO = "api_info";
static const std::string ENDPOINT_FEE = "api_fee";

// Maximum UTXOs to return per request (DoS protection)
static const size_t MAX_UTXOS_PER_RESPONSE = 1000;

CRestAPI::CRestAPI()
    : m_mempool(nullptr)
    , m_blockchain(nullptr)
    , m_utxo_set(nullptr)
    , m_chainstate(nullptr)
    , m_rateLimiter(nullptr)
{
}

bool CRestAPI::IsRESTRequest(const std::string& path) {
    return path.find("/api/v1/") == 0;
}

std::string CRestAPI::HandleRequest(const std::string& method,
                                    const std::string& path,
                                    const std::string& body,
                                    const std::string& clientIP) {
    // Parse the endpoint from path
    // Expected paths:
    // - /api/v1/balance/{address}
    // - /api/v1/utxos/{address}
    // - /api/v1/tx/{txid}
    // - /api/v1/broadcast
    // - /api/v1/info
    // - /api/v1/fee

    std::string endpoint;
    std::string param;

    // Remove /api/v1/ prefix
    std::string subpath = path.substr(8);  // Skip "/api/v1/"

    // Find first slash to separate endpoint from parameter
    size_t slash = subpath.find('/');
    if (slash != std::string::npos) {
        endpoint = subpath.substr(0, slash);
        param = subpath.substr(slash + 1);
    } else {
        endpoint = subpath;
    }

    // Route to appropriate handler
    if (endpoint == "balance" && method == "GET") {
        if (param.empty()) {
            return BuildErrorResponse(400, 1001, "Missing address parameter");
        }
        return HandleBalance(param, clientIP);
    }
    else if (endpoint == "utxos" && method == "GET") {
        if (param.empty()) {
            return BuildErrorResponse(400, 1001, "Missing address parameter");
        }
        return HandleUTXOs(param, clientIP);
    }
    else if (endpoint == "tx" && method == "GET") {
        if (param.empty()) {
            return BuildErrorResponse(400, 1002, "Missing txid parameter");
        }
        return HandleTransaction(param, clientIP);
    }
    else if (endpoint == "broadcast" && method == "POST") {
        return HandleBroadcast(body, clientIP);
    }
    else if (endpoint == "info" && method == "GET") {
        return HandleInfo(clientIP);
    }
    else if (endpoint == "fee" && method == "GET") {
        return HandleFee(clientIP);
    }
    else if (method != "GET" && method != "POST") {
        return BuildMethodNotAllowedResponse();
    }
    else {
        return BuildNotFoundResponse();
    }
}

bool CRestAPI::CheckRateLimit(const std::string& clientIP, const std::string& endpoint) {
    if (!m_rateLimiter) {
        return true;  // No rate limiter = allow all
    }
    return m_rateLimiter->AllowMethodRequest(clientIP, endpoint);
}

std::string CRestAPI::HandleBalance(const std::string& address, const std::string& clientIP) {
    // Rate limit check
    if (!CheckRateLimit(clientIP, ENDPOINT_BALANCE)) {
        return BuildRateLimitResponse();
    }

    // Validate address
    if (!ValidateAddress(address)) {
        return BuildErrorResponse(400, 1003, "Invalid address format");
    }

    if (!m_utxo_set || !m_chainstate) {
        return BuildErrorResponse(503, 2001, "UTXO set not available");
    }

    // Parse address to get pubkey hash
    CDilithiumAddress addr;
    if (!addr.SetString(address)) {
        return BuildErrorResponse(400, 1003, "Invalid address format");
    }

    // Sum UTXOs for this address, separating mature and immature coinbase
    int64_t confirmed = 0;
    int64_t immature = 0;
    int64_t unconfirmed = 0;
    unsigned int currentHeight = m_chainstate->GetHeight();
    static const unsigned int COINBASE_MATURITY = 100;

    // Get confirmed balance from UTXO set
    m_utxo_set->ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        // Check if this UTXO belongs to the address
        if (!entry.out.IsNull() && entry.out.scriptPubKey.size() >= 20) {
            // Extract pubkey hash from scriptPubKey (P2PKH format)
            // Script format: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
            // Or simplified: <20-byte hash> for P2SH-like
            const std::vector<uint8_t>& script = entry.out.scriptPubKey;
            const std::vector<uint8_t>& addrData = addr.GetData();

            // Compare address data (version byte + 20-byte hash)
            if (addrData.size() >= 21) {
                bool matches = false;
                if (script.size() == 25 &&
                    script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
                    script[23] == 0x88 && script[24] == 0xac) {
                    // P2PKH: OP_DUP OP_HASH160 PUSH20 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
                    matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin() + 3);
                } else if (script.size() == 20) {
                    // Direct 20-byte hash (legacy)
                    matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin());
                }

                if (matches) {
                    // Skip UTXOs already spent by an in-flight mempool tx —
                    // otherwise balance overstates what's actually spendable
                    // and the light wallet picks a "rich" address whose
                    // funds are all locked.
                    if (m_mempool && m_mempool->IsSpent(outpoint)) {
                        return true;
                    }
                    if (entry.fCoinBase && currentHeight < entry.nHeight + COINBASE_MATURITY) {
                        immature += entry.out.nValue;
                    } else {
                        confirmed += entry.out.nValue;
                    }
                }
            }
        }
        return true;  // Continue iteration
    });

    // Add unconfirmed balance from mempool transactions
    if (m_mempool) {
        auto mempool_txs = m_mempool->GetOrderedTxs();
        for (const auto& tx : mempool_txs) {
            for (const auto& vout : tx->vout) {
                if (!vout.IsNull() && vout.scriptPubKey.size() >= 20) {
                    const std::vector<uint8_t>& script = vout.scriptPubKey;
                    const std::vector<uint8_t>& addrData = addr.GetData();
                    if (addrData.size() >= 21) {
                        bool matches = false;
                        if (script.size() == 25 &&
                            script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
                            script[23] == 0x88 && script[24] == 0xac) {
                            matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin() + 3);
                        } else if (script.size() == 20) {
                            matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin());
                        }
                        if (matches) {
                            unconfirmed += vout.nValue;
                        }
                    }
                }
            }
        }
    }

    // Build response
    std::ostringstream oss;
    oss << "{";
    oss << "\"address\":\"" << EscapeJSON(address) << "\",";
    oss << "\"confirmed\":" << confirmed << ",";
    oss << "\"immature\":" << immature << ",";
    oss << "\"unconfirmed\":" << unconfirmed << ",";
    oss << "\"confirmed_formatted\":\"" << FormatAmount(confirmed) << "\",";
    oss << "\"immature_formatted\":\"" << FormatAmount(immature) << "\",";
    oss << "\"unconfirmed_formatted\":\"" << FormatAmount(unconfirmed) << "\"";
    oss << "}";

    return BuildHTTPResponse(200, oss.str());
}

std::string CRestAPI::HandleUTXOs(const std::string& address, const std::string& clientIP) {
    // Rate limit check
    if (!CheckRateLimit(clientIP, ENDPOINT_UTXOS)) {
        return BuildRateLimitResponse();
    }

    // Validate address
    if (!ValidateAddress(address)) {
        return BuildErrorResponse(400, 1003, "Invalid address format");
    }

    if (!m_utxo_set || !m_chainstate) {
        return BuildErrorResponse(503, 2001, "UTXO set not available");
    }

    // Parse address
    CDilithiumAddress addr;
    if (!addr.SetString(address)) {
        return BuildErrorResponse(400, 1003, "Invalid address format");
    }

    int currentHeight = m_chainstate->GetHeight();

    // Collect UTXOs for this address
    std::vector<std::string> utxoJsons;
    size_t count = 0;

    m_utxo_set->ForEach([&](const COutPoint& outpoint, const CUTXOEntry& entry) {
        if (count >= MAX_UTXOS_PER_RESPONSE) {
            return false;  // Stop iteration
        }

        // Check if this UTXO belongs to the address
        if (!entry.out.IsNull() && entry.out.scriptPubKey.size() >= 20) {
            const std::vector<uint8_t>& script = entry.out.scriptPubKey;
            const std::vector<uint8_t>& addrData = addr.GetData();

            bool matches = false;
            if (addrData.size() >= 21 && script.size() >= 20) {
                if (script.size() == 20) {
                    matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin());
                } else if (script.size() >= 23) {
                    if (script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14) {
                        matches = std::equal(addrData.begin() + 1, addrData.begin() + 21, script.begin() + 3);
                    }
                }
            }

            if (matches) {
                // Skip UTXOs already spent by an in-flight mempool tx. Light
                // wallets have no independent view of the mempool, so without
                // this filter they re-select these outputs and the next
                // broadcast is rejected as a double-spend.
                if (m_mempool && m_mempool->IsSpent(outpoint)) {
                    return true;  // continue iterating, skip this one
                }

                int confirmations = (entry.nHeight > 0 && currentHeight >= (int)entry.nHeight)
                    ? (currentHeight - entry.nHeight + 1) : 0;

                std::ostringstream utxo;
                utxo << "{";
                utxo << "\"txid\":\"" << outpoint.hash.GetHex() << "\",";
                utxo << "\"vout\":" << outpoint.n << ",";
                utxo << "\"amount\":" << entry.out.nValue << ",";
                utxo << "\"amount_formatted\":\"" << FormatAmount(entry.out.nValue) << "\",";
                utxo << "\"confirmations\":" << confirmations << ",";
                utxo << "\"coinbase\":" << (entry.fCoinBase ? "true" : "false");
                utxo << "}";

                utxoJsons.push_back(utxo.str());
                count++;
            }
        }
        return true;  // Continue iteration
    });

    // Build response
    std::ostringstream oss;
    oss << "{";
    oss << "\"address\":\"" << EscapeJSON(address) << "\",";
    oss << "\"utxos\":[";
    for (size_t i = 0; i < utxoJsons.size(); i++) {
        if (i > 0) oss << ",";
        oss << utxoJsons[i];
    }
    oss << "],";
    oss << "\"count\":" << utxoJsons.size() << ",";
    oss << "\"truncated\":" << (count >= MAX_UTXOS_PER_RESPONSE ? "true" : "false");
    oss << "}";

    return BuildHTTPResponse(200, oss.str());
}

std::string CRestAPI::HandleTransaction(const std::string& txid, const std::string& clientIP) {
    // Rate limit check
    if (!CheckRateLimit(clientIP, ENDPOINT_TX)) {
        return BuildRateLimitResponse();
    }

    // Validate txid
    if (!ValidateTxid(txid)) {
        return BuildErrorResponse(400, 1004, "Invalid transaction ID format");
    }

    if (!m_mempool || !m_blockchain || !m_chainstate) {
        return BuildErrorResponse(503, 2002, "Blockchain not available");
    }

    uint256 hash;
    hash.SetHex(txid);

    // Check mempool first
    if (m_mempool->Exists(hash)) {
        std::ostringstream oss;
        oss << "{";
        oss << "\"txid\":\"" << hash.GetHex() << "\",";
        oss << "\"confirmations\":0,";
        oss << "\"in_mempool\":true";
        oss << "}";
        return BuildHTTPResponse(200, oss.str());
    }

    // Search blockchain (last 1000 blocks for performance)
    CBlockIndex* pTip = m_chainstate->GetTip();
    if (!pTip) {
        return BuildErrorResponse(503, 2002, "Chain state not initialized");
    }

    const int MAX_BLOCKS_TO_SEARCH = 1000;
    int blocksSearched = 0;
    CBlockIndex* pCurrent = pTip;

    while (pCurrent && blocksSearched < MAX_BLOCKS_TO_SEARCH) {
        CBlock block;
        uint256 blockHash = pCurrent->GetBlockHash();

        if (!m_blockchain->ReadBlock(blockHash, block)) {
            pCurrent = pCurrent->pprev;
            blocksSearched++;
            continue;
        }

        // Search transactions in block
        const uint8_t* ptr = block.vtx.data();
        const uint8_t* end = block.vtx.data() + block.vtx.size();

        while (ptr < end) {
            CTransaction tx;
            size_t bytesConsumed = 0;
            std::string deserializeError;

            if (!tx.Deserialize(ptr, end - ptr, &deserializeError, &bytesConsumed)) {
                break;
            }

            if (tx.GetHash() == hash) {
                int confirmations = pTip->nHeight - pCurrent->nHeight + 1;

                std::ostringstream oss;
                oss << "{";
                oss << "\"txid\":\"" << hash.GetHex() << "\",";
                oss << "\"blockhash\":\"" << blockHash.GetHex() << "\",";
                oss << "\"blockheight\":" << pCurrent->nHeight << ",";
                oss << "\"confirmations\":" << confirmations << ",";
                oss << "\"in_mempool\":false";
                oss << "}";
                return BuildHTTPResponse(200, oss.str());
            }

            ptr += bytesConsumed;
        }

        pCurrent = pCurrent->pprev;
        blocksSearched++;
    }

    return BuildErrorResponse(404, 3001, "Transaction not found");
}

std::string CRestAPI::HandleBroadcast(const std::string& body, const std::string& clientIP) {
    // Rate limit check (critical endpoint)
    if (!CheckRateLimit(clientIP, ENDPOINT_BROADCAST)) {
        return BuildRateLimitResponse();
    }

    if (!m_mempool || !m_utxo_set || !m_chainstate) {
        return BuildErrorResponse(503, 2003, "Node not ready for broadcasts");
    }

    // Parse JSON body to get rawtx
    // Expected: {"rawtx":"hex-encoded-transaction"}
    size_t rawtx_pos = body.find("\"rawtx\"");
    if (rawtx_pos == std::string::npos) {
        return BuildErrorResponse(400, 1005, "Missing rawtx parameter");
    }

    size_t colon = body.find(":", rawtx_pos);
    size_t quote1 = body.find("\"", colon);
    size_t quote2 = body.find("\"", quote1 + 1);
    if (quote1 == std::string::npos || quote2 == std::string::npos) {
        return BuildErrorResponse(400, 1005, "Invalid rawtx parameter format");
    }

    std::string hex_str = body.substr(quote1 + 1, quote2 - quote1 - 1);

    // Deserialize transaction
    std::vector<uint8_t> tx_data = ParseHex(hex_str);
    if (tx_data.empty()) {
        return BuildErrorResponse(400, 1006, "Invalid hex string");
    }

    CTransaction tx;
    std::string deserialize_error;
    if (!tx.Deserialize(tx_data.data(), tx_data.size(), &deserialize_error)) {
        return BuildErrorResponse(400, 1007, "Failed to deserialize transaction: " + deserialize_error);
    }

    // Validate transaction
    CTransactionValidator txValidator;
    std::string validation_error;
    CAmount tx_fee = 0;
    unsigned int current_height = m_chainstate->GetHeight();

    if (!txValidator.CheckTransaction(tx, *m_utxo_set, current_height, tx_fee, validation_error)) {
        return BuildErrorResponse(400, 1008, "Transaction validation failed: " + validation_error);
    }

    // Create shared pointer and add to mempool
    CTransactionRef txRef = MakeTransactionRef(tx);
    uint256 txid = txRef->GetHash();

    std::string mempool_error;
    int64_t current_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    if (!m_mempool->AddTx(txRef, tx_fee, current_time, current_height, &mempool_error)) {
        return BuildErrorResponse(400, 1009, "Failed to add to mempool: " + mempool_error);
    }

    // Success - transaction will be relayed to network
    std::ostringstream oss;
    oss << "{";
    oss << "\"txid\":\"" << txid.GetHex() << "\",";
    oss << "\"accepted\":true";
    oss << "}";

    return BuildHTTPResponse(200, oss.str());
}

std::string CRestAPI::HandleInfo(const std::string& clientIP) {
    // Rate limit check
    if (!CheckRateLimit(clientIP, ENDPOINT_INFO)) {
        return BuildRateLimitResponse();
    }

    if (!m_blockchain || !m_chainstate) {
        return BuildErrorResponse(503, 2002, "Blockchain not available");
    }

    int height = m_chainstate->GetHeight();
    uint256 bestBlockHash;
    if (!m_blockchain->ReadBestBlock(bestBlockHash)) {
        return BuildErrorResponse(503, 2004, "Failed to read best block");
    }

    // Get chain name from configuration
    std::string chain = m_testnet ? "test" : "main";

    // Calculate difficulty
    double difficulty = 1.0;
    CBlock bestBlock;
    if (m_blockchain->ReadBlock(bestBlockHash, bestBlock)) {
        if (bestBlock.nBits != 0) {
            // Simplified difficulty calculation
            // difficulty = max_target / current_target
            uint32_t nBits = bestBlock.nBits;
            int nShift = (nBits >> 24) & 0xff;
            double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);
            while (nShift < 29) {
                dDiff *= 256.0;
                nShift++;
            }
            while (nShift > 29) {
                dDiff /= 256.0;
                nShift--;
            }
            difficulty = dDiff;
        }
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(8);
    oss << "{";
    oss << "\"height\":" << height << ",";
    oss << "\"bestblockhash\":\"" << bestBlockHash.GetHex() << "\",";
    oss << "\"chain\":\"" << chain << "\",";
    oss << "\"difficulty\":" << difficulty;
    oss << "}";

    return BuildHTTPResponse(200, oss.str());
}

std::string CRestAPI::HandleFee(const std::string& clientIP) {
    // Rate limit check
    if (!CheckRateLimit(clientIP, ENDPOINT_FEE)) {
        return BuildRateLimitResponse();
    }

    // Fee estimation (ions per KB) — dynamic based on mempool state.
    // Floor is consensus minimum: FEE_PER_BYTE (5 ions/byte) * 1000 = 5000 ions/KB.
    // Anything below this gets rejected by Consensus::CheckFee — clients that trusted
    // a sub-consensus value here produced txs that failed validation.
    const int64_t kConsensusMinRate = static_cast<int64_t>(Consensus::FEE_PER_BYTE) * 1000;
    int64_t recommended = kConsensusMinRate;
    int64_t minimum = kConsensusMinRate;

    if (m_mempool) {
        size_t pool_size = 0, pool_bytes = 0;
        double min_fee_rate = 0.0, max_fee_rate = 0.0;
        m_mempool->GetStats(pool_size, pool_bytes, min_fee_rate, max_fee_rate);

        if (pool_size > 0 && min_fee_rate > 0) {
            // Use mempool fee rates: minimum is the floor, recommended
            // is 2x the current minimum to ensure priority confirmation.
            minimum = std::max(static_cast<int64_t>(min_fee_rate * 1000), kConsensusMinRate);
            recommended = std::max(minimum * 2, kConsensusMinRate);
        }
    }

    std::ostringstream oss;
    oss << "{";
    oss << "\"recommended\":" << recommended << ",";
    oss << "\"minimum\":" << minimum << ",";
    oss << "\"unit\":\"ions_per_kb\"";
    oss << "}";

    return BuildHTTPResponse(200, oss.str());
}

// Helper methods

std::string CRestAPI::BuildHTTPResponse(int statusCode, const std::string& body) {
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 400: statusText = "Bad Request"; break;
        case 404: statusText = "Not Found"; break;
        case 405: statusText = "Method Not Allowed"; break;
        case 429: statusText = "Too Many Requests"; break;
        case 503: statusText = "Service Unavailable"; break;
        default: statusText = "Unknown"; break;
    }

    std::ostringstream response;
    response << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Content-Length: " << body.size() << "\r\n";
    // CVE-2026-RPC-CORS: NO CORS headers. Same-origin only. Browsers cannot
    // read REST responses cross-origin, preventing drive-by data exfil.
    response << "Cache-Control: no-cache\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    return response.str();
}

std::string CRestAPI::BuildRateLimitResponse() {
    return BuildHTTPResponse(429, "{\"error\":{\"code\":4001,\"message\":\"Rate limit exceeded\"}}");
}

std::string CRestAPI::BuildNotFoundResponse() {
    return BuildHTTPResponse(404, "{\"error\":{\"code\":4004,\"message\":\"Endpoint not found\"}}");
}

std::string CRestAPI::BuildMethodNotAllowedResponse() {
    return BuildHTTPResponse(405, "{\"error\":{\"code\":4005,\"message\":\"Method not allowed\"}}");
}

std::string CRestAPI::BuildErrorResponse(int httpCode, int errorCode, const std::string& message) {
    std::ostringstream oss;
    oss << "{\"error\":{\"code\":" << errorCode << ",\"message\":\"" << EscapeJSON(message) << "\"}}";
    return BuildHTTPResponse(httpCode, oss.str());
}

std::string CRestAPI::EscapeJSON(const std::string& str) const {
    std::ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '\"': escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    escaped << "\\u" << std::hex << std::setfill('0') << std::setw(4) << (int)c;
                } else {
                    escaped << c;
                }
        }
    }
    return escaped.str();
}

std::string CRestAPI::FormatAmount(int64_t amount) const {
    // Format amount as DIL with 8 decimal places
    bool negative = amount < 0;
    if (negative) amount = -amount;

    int64_t whole = amount / 100000000;
    int64_t frac = amount % 100000000;

    std::ostringstream oss;
    if (negative) oss << "-";
    oss << whole << "." << std::setfill('0') << std::setw(8) << frac << " DIL";
    return oss.str();
}

bool CRestAPI::ValidateAddress(const std::string& address) const {
    // Basic validation: Dilithion addresses start with 'D' and are ~34 chars
    if (address.empty() || address[0] != 'D') {
        return false;
    }
    if (address.size() < 25 || address.size() > 40) {
        return false;
    }
    // Check for valid Base58 characters
    for (char c : address) {
        if (!((c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
              (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
              (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z'))) {
            return false;
        }
    }
    return true;
}

bool CRestAPI::ValidateTxid(const std::string& txid) const {
    // Transaction IDs are 64 hex characters
    if (txid.size() != 64) {
        return false;
    }
    for (char c : txid) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}
