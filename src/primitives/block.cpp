// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/block.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ostream>
#include <iostream>

std::string uint256::GetHex() const {
    std::stringstream ss;
    for (int i = 31; i >= 0; i--) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

void uint256::SetHex(const std::string& str) {
    memset(data, 0, 32);

    if (str.empty()) {
        return;
    }

    // Hex string should be 64 characters (32 bytes * 2 hex chars)
    size_t len = str.length();
    if (len > 64) {
        len = 64;
    }

    // Convert hex string to bytes (big-endian format, stored in reverse for little-endian)
    // GetHex() outputs in reverse order (data[31] first), so SetHex() should match
    for (size_t i = 0; i < len / 2; i++) {
        size_t strPos = len - 2 - (i * 2);  // Start from end of string
        std::string byteStr = str.substr(strPos, 2);
        data[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    // Handle odd-length strings (shouldn't happen, but be safe)
    if (len % 2 == 1) {
        std::string byteStr = "0" + str.substr(0, 1);
        data[len / 2] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }
}

// Stream output operator for Boost.Test
std::ostream& operator<<(std::ostream& os, const uint256& h) {
    return os << h.GetHex();
}

std::vector<uint8_t> CBlockHeader::SerializeHeader() const {
    std::vector<uint8_t> buf;
    buf.reserve(GetHeaderSize());

    // Legacy 80-byte portion: version(4) + prevBlock(32) + merkleRoot(32) + time(4) + bits(4) + nonce(4)
    // WF-1: explicit little-endian for the four 32-bit scalars (byte-identical to
    // the previous host-endian copy on LE hosts; portable to any architecture).
    AppendLE32(buf, static_cast<uint32_t>(nVersion));
    buf.insert(buf.end(), hashPrevBlock.begin(), hashPrevBlock.end());
    buf.insert(buf.end(), hashMerkleRoot.begin(), hashMerkleRoot.end());
    AppendLE32(buf, nTime);
    AppendLE32(buf, nBits);
    AppendLE32(buf, nNonce);

    // VDF extension (64 bytes, version >= 4 only)
    if (IsVDFBlock()) {
        buf.insert(buf.end(), vdfOutput.begin(), vdfOutput.end());
        buf.insert(buf.end(), vdfProofHash.begin(), vdfProofHash.end());
    }

    return buf;
}

uint256 CBlockHeader::GetHash() const {
    // Return cached hash if available
    if (fHashCached) {
        return cachedHash;
    }

    std::vector<uint8_t> data = SerializeHeader();

    uint256 result;
    if (IsVDFBlock()) {
        // VDF blocks use SHA3-256 of the full 144-byte header (no RandomX).
        SHA3_256(data.data(), data.size(), result.data);
    } else {
        // Legacy blocks use RandomX hash of the 80-byte header.
        randomx_hash_fast(data.data(), data.size(), result.data);
    }

    cachedHash = result;
    fHashCached = true;
    return result;
}

uint256 CBlockHeader::GetFastHash() const {
    // SHA3-256 of the full header (version-aware) for fast identification.
    std::vector<uint8_t> data = SerializeHeader();
    uint256 result;
    SHA3_256(data.data(), data.size(), result.data);
    return result;
}
