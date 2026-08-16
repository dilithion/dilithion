// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <primitives/transaction.h>
#include <crypto/sha3.h>
#include <cstring>
#include <stdexcept>
#include <set>

// Define static const members (required for C++11/14 linkage)
const uint32_t CTxIn::SEQUENCE_FINAL;

/** Helper function to serialize a uint32_t in little-endian format */
static void SerializeUint32(std::vector<uint8_t>& data, uint32_t value) {
    data.push_back(static_cast<uint8_t>(value));
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value >> 16));
    data.push_back(static_cast<uint8_t>(value >> 24));
}

/** Helper function to serialize a uint64_t in little-endian format */
static void SerializeUint64(std::vector<uint8_t>& data, uint64_t value) {
    data.push_back(static_cast<uint8_t>(value));
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value >> 16));
    data.push_back(static_cast<uint8_t>(value >> 24));
    data.push_back(static_cast<uint8_t>(value >> 32));
    data.push_back(static_cast<uint8_t>(value >> 40));
    data.push_back(static_cast<uint8_t>(value >> 48));
    data.push_back(static_cast<uint8_t>(value >> 56));
}

/** Helper function to serialize a compact size (Bitcoin-style varint).
 *  Declared in primitives/transaction.h and exported (non-static) so the
 *  single-source sighash preimage builder reuses this one encoder — FIX-1 HIGH-1. */
void SerializeCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size));
        data.push_back(static_cast<uint8_t>(size >> 8));
    } else if (size <= 0xFFFFFFFF) {
        data.push_back(254);
        SerializeUint32(data, static_cast<uint32_t>(size));
    } else {
        data.push_back(255);
        SerializeUint64(data, size);
    }
}

std::vector<uint8_t> CTransaction::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());

    // Serialize version (4 bytes, little-endian)
    SerializeUint32(data, static_cast<uint32_t>(nVersion));

    // Serialize number of inputs
    SerializeCompactSize(data, vin.size());

    // Serialize each input
    for (const CTxIn& txin : vin) {
        // Serialize prevout hash (32 bytes)
        data.insert(data.end(), txin.prevout.hash.begin(), txin.prevout.hash.end());
        
        // Serialize prevout index (4 bytes, little-endian)
        SerializeUint32(data, txin.prevout.n);
        
        // Serialize scriptSig length and data
        SerializeCompactSize(data, txin.scriptSig.size());
        data.insert(data.end(), txin.scriptSig.begin(), txin.scriptSig.end());
        
        // Serialize sequence (4 bytes, little-endian)
        SerializeUint32(data, txin.nSequence);
    }

    // Serialize number of outputs
    SerializeCompactSize(data, vout.size());

    // Serialize each output
    for (const CTxOut& txout : vout) {
        // Serialize value (8 bytes, little-endian)
        SerializeUint64(data, txout.nValue);
        
        // Serialize scriptPubKey length and data
        SerializeCompactSize(data, txout.scriptPubKey.size());
        data.insert(data.end(), txout.scriptPubKey.begin(), txout.scriptPubKey.end());
    }

    // Serialize locktime (4 bytes, little-endian)
    SerializeUint32(data, nLockTime);

    return data;
}

uint256 CTransaction::GetHash() const {
    if (!hash_valid) {
        // Serialize transaction
        std::vector<uint8_t> data = Serialize();

        // Hash with SHA3-256 (quantum-resistant)
        SHA3_256(data.data(), data.size(), hash_cached.data);
        hash_valid = true;
    }
    return hash_cached;
}

uint256 CTransaction::GetSigningHash() const {
    // BUG #86 FIX: Serialize transaction WITHOUT scriptSig for signature verification
    // This ensures signing and verification use the same hash, regardless of scriptSig content.
    // Similar to Bitcoin's SIGHASH_ALL but simplified for Dilithion's single signature scheme.

    std::vector<uint8_t> data;
    data.reserve(256);  // Reasonable initial size

    // Serialize version (4 bytes, little-endian)
    SerializeUint32(data, static_cast<uint32_t>(nVersion));

    // Serialize number of inputs
    SerializeCompactSize(data, vin.size());

    // Serialize each input WITHOUT scriptSig
    for (const CTxIn& txin : vin) {
        // Serialize prevout hash (32 bytes)
        data.insert(data.end(), txin.prevout.hash.begin(), txin.prevout.hash.end());

        // Serialize prevout index (4 bytes, little-endian)
        SerializeUint32(data, txin.prevout.n);

        // BUG #86 FIX: Use empty scriptSig (just zero length)
        SerializeCompactSize(data, 0);  // Empty scriptSig

        // Serialize sequence (4 bytes, little-endian)
        SerializeUint32(data, txin.nSequence);
    }

    // Serialize number of outputs
    SerializeCompactSize(data, vout.size());

    // Serialize each output
    for (const CTxOut& txout : vout) {
        // Serialize value (8 bytes, little-endian)
        SerializeUint64(data, txout.nValue);

        // Serialize scriptPubKey length and data
        SerializeCompactSize(data, txout.scriptPubKey.size());
        data.insert(data.end(), txout.scriptPubKey.begin(), txout.scriptPubKey.end());
    }

    // Serialize locktime (4 bytes, little-endian)
    SerializeUint32(data, nLockTime);

    // Hash with SHA3-256
    uint256 result;
    SHA3_256(data.data(), data.size(), result.data);
    return result;
}

size_t CTransaction::GetSerializedSize() const {
    size_t size = 0;
    
    // Version (4 bytes)
    size += 4;
    
    // Input count varint (1-9 bytes)
    uint64_t vin_size = vin.size();
    if (vin_size < 253) size += 1;
    else if (vin_size <= 0xFFFF) size += 3;
    else if (vin_size <= 0xFFFFFFFF) size += 5;
    else size += 9;
    
    // Each input
    for (const CTxIn& txin : vin) {
        size += 32;  // prevout hash
        size += 4;   // prevout index
        
        // scriptSig size varint
        uint64_t script_size = txin.scriptSig.size();
        if (script_size < 253) size += 1;
        else if (script_size <= 0xFFFF) size += 3;
        else if (script_size <= 0xFFFFFFFF) size += 5;
        else size += 9;
        
        size += txin.scriptSig.size();  // scriptSig data
        size += 4;  // sequence
    }
    
    // Output count varint (1-9 bytes)
    uint64_t vout_size = vout.size();
    if (vout_size < 253) size += 1;
    else if (vout_size <= 0xFFFF) size += 3;
    else if (vout_size <= 0xFFFFFFFF) size += 5;
    else size += 9;
    
    // Each output
    for (const CTxOut& txout : vout) {
        size += 8;  // value
        
        // scriptPubKey size varint
        uint64_t script_size = txout.scriptPubKey.size();
        if (script_size < 253) size += 1;
        else if (script_size <= 0xFFFF) size += 3;
        else if (script_size <= 0xFFFFFFFF) size += 5;
        else size += 9;
        
        size += txout.scriptPubKey.size();  // scriptPubKey data
    }
    
    // Locktime (4 bytes)
    size += 4;
    
    return size;
}

bool CTransaction::CheckBasicStructure() const {
    // Transaction must have at least one input and one output
    // Exception: coinbase transactions can have special inputs
    if (vin.empty()) {
        return false;
    }
    
    if (vout.empty()) {
        return false;
    }
    
    // Check that outputs don't overflow
    uint64_t totalOut = 0;
    for (const CTxOut& txout : vout) {
        // TX-006 FIX: Removed impossible negative check on unsigned type
        // nValue is uint64_t (unsigned), so it can never be negative
        // Static assert ensures this remains true if type changes in future
        static_assert(std::is_unsigned<decltype(txout.nValue)>::value,
                      "CTxOut::nValue must be unsigned type");

        if (txout.nValue > 21000000ULL * 100000000ULL) {  // Max supply * ions
            return false;
        }

        // Check for overflow using explicit pattern
        if (txout.nValue > UINT64_MAX - totalOut) {
            return false;
        }
        totalOut += txout.nValue;
    }
    
    // Check for oversized transaction (max 1MB for now)
    if (GetSerializedSize() > 1000000) {
        return false;
    }
    
    // Coinbase transactions have special rules
    if (IsCoinBase()) {
        // Coinbase scriptSig must be between 2 and 6000 bytes
        // DFMP v2.0: Increased from 100 to 6000 to accommodate MIK data
        // MIK registration: marker(1) + type(1) + pubkey(1952) + signature(3309) = 5263 bytes
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 6000) {
            return false;
        }
    } else {
        // Non-coinbase transactions must not have null prevouts
        for (const CTxIn& txin : vin) {
            if (txin.prevout.IsNull()) {
                return false;
            }
        }

        // Check for duplicate inputs (non-coinbase only)
        std::set<COutPoint> unique_inputs;
        for (const CTxIn& txin : vin) {
            if (!unique_inputs.insert(txin.prevout).second) {
                return false;  // Duplicate input detected
            }
        }
    }

    return true;
}

uint64_t CTransaction::GetValueOut() const {
    uint64_t total = 0;
    for (const CTxOut& txout : vout) {
        // Check for overflow using explicit pattern
        if (txout.nValue > UINT64_MAX - total) {
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
        }
        total += txout.nValue;
    }
    return total;
}

// ============================================================================
// Deserialization Helper Functions (CS-002)
// ============================================================================

/** Helper function to deserialize a uint32_t from little-endian format */
static bool DeserializeUint32(const uint8_t*& data, const uint8_t* end, uint32_t& value, std::string* error = nullptr) {
    if (end - data < 4) {
        if (error) *error = "Insufficient data for uint32_t";
        return false;
    }

    value = static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24);

    data += 4;
    return true;
}

/** Helper function to deserialize a uint64_t from little-endian format */
static bool DeserializeUint64(const uint8_t*& data, const uint8_t* end, uint64_t& value, std::string* error = nullptr) {
    if (end - data < 8) {
        if (error) *error = "Insufficient data for uint64_t";
        return false;
    }

    value = static_cast<uint64_t>(data[0]) |
            (static_cast<uint64_t>(data[1]) << 8) |
            (static_cast<uint64_t>(data[2]) << 16) |
            (static_cast<uint64_t>(data[3]) << 24) |
            (static_cast<uint64_t>(data[4]) << 32) |
            (static_cast<uint64_t>(data[5]) << 40) |
            (static_cast<uint64_t>(data[6]) << 48) |
            (static_cast<uint64_t>(data[7]) << 56);

    data += 8;
    return true;
}

/** Deserialize a compact size (Bitcoin-style varint) with minimal-encoding
 *  enforcement (malleability finding #5). Declared in primitives/transaction.h
 *  and exported (non-static) so validation.cpp's block tx-count decoder reuses
 *  THIS one decoder rather than keeping a third hand-rolled copy that drifts. */
bool DeserializeCompactSize(const uint8_t*& data, const uint8_t* end, uint64_t& size, std::string* error) {
    if (data >= end) {
        if (error) *error = "Insufficient data for CompactSize";
        return false;
    }

    uint8_t first = *data;
    data++;

    if (first < 253) {
        size = first;
        // 1-byte form is always minimal; no range check needed.
        return true;
    } else if (first == 253) {
        // 2-byte size
        if (end - data < 2) {
            if (error) *error = "Insufficient data for CompactSize (2-byte)";
            return false;
        }
        size = static_cast<uint64_t>(data[0]) |
               (static_cast<uint64_t>(data[1]) << 8);
        data += 2;
    } else if (first == 254) {
        // 4-byte size
        uint32_t size32;
        if (!DeserializeUint32(data, end, size32, error)) {
            return false;
        }
        size = size32;
    } else {  // first == 255
        // 8-byte size
        if (!DeserializeUint64(data, end, size, error)) {
            return false;
        }
    }

    // Malleability finding #5: reject non-minimal (non-shortest) encodings so a
    // single value has exactly one wire byte-string. Shared range check keeps
    // all three decoders in lockstep.
    if (!CompactSizeIsCanonical(first, size)) {
        if (error) *error = "Non-canonical CompactSize (non-minimal encoding)";
        return false;
    }
    return true;
}

// ============================================================================
// CTransaction Deserialization (CS-002)
// ============================================================================

bool CTransaction::Deserialize(const uint8_t* data, size_t len, std::string* error, size_t* bytesConsumed) {
    // Clear current transaction state
    SetNull();

    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    // Deserialize version (4 bytes)
    uint32_t version;
    if (!DeserializeUint32(ptr, end, version, error)) {
        return false;
    }
    nVersion = static_cast<int32_t>(version);

    // Deserialize input count
    uint64_t vin_count;
    if (!DeserializeCompactSize(ptr, end, vin_count, error)) {
        return false;
    }

    // Sanity check: max 100k inputs
    if (vin_count > 100000) {
        if (error) *error = "Too many inputs";
        return false;
    }

    // TX-003 FIX: Estimate minimum transaction size before allocating
    // This prevents DoS from malformed transactions that claim huge counts
    // but don't have the data to back it up
    //
    // Minimum size per input: 32 (hash) + 4 (index) + 1 (scriptSig len=0) + 4 (sequence) = 41 bytes
    // Minimum size per output: 8 (value) + 1 (scriptPubKey len=0) = 9 bytes
    const size_t MIN_TX_INPUT_SIZE = 41;
    const size_t MIN_TX_OUTPUT_SIZE = 9;

    // Check if we have enough data remaining for claimed input count
    size_t min_inputs_size = vin_count * MIN_TX_INPUT_SIZE;
    if (min_inputs_size > static_cast<size_t>(end - ptr)) {
        if (error) *error = "Transaction claims more inputs than data available";
        return false;
    }

    // Deserialize each input
    vin.resize(vin_count);
    for (size_t i = 0; i < vin_count; i++) {
        CTxIn& txin = vin[i];

        // Deserialize prevout hash (32 bytes)
        if (end - ptr < 32) {
            if (error) *error = "Insufficient data for prevout hash";
            return false;
        }
        std::memcpy(txin.prevout.hash.data, ptr, 32);
        ptr += 32;

        // Deserialize prevout index (4 bytes)
        if (!DeserializeUint32(ptr, end, txin.prevout.n, error)) {
            return false;
        }

        // Deserialize scriptSig length
        uint64_t scriptSig_len;
        if (!DeserializeCompactSize(ptr, end, scriptSig_len, error)) {
            return false;
        }

        // Sanity check: max 20KB scriptSig
        // Raised from 10KB for Dilithium post-quantum signatures (3,309 bytes each).
        // Registration blocks need: MIK pubkey (1,952) + MIK sig (3,309) + up to 4
        // attestation sigs (4 × 3,314) + DNA commitment (33) ≈ 18,566 bytes.
        if (scriptSig_len > 20000) {
            if (error) *error = "scriptSig too large";
            return false;
        }

        // Deserialize scriptSig data
        if (end - ptr < static_cast<ptrdiff_t>(scriptSig_len)) {
            if (error) *error = "Insufficient data for scriptSig";
            return false;
        }
        txin.scriptSig.assign(ptr, ptr + scriptSig_len);
        ptr += scriptSig_len;

        // Deserialize sequence (4 bytes)
        if (!DeserializeUint32(ptr, end, txin.nSequence, error)) {
            return false;
        }
    }

    // Deserialize output count
    uint64_t vout_count;
    if (!DeserializeCompactSize(ptr, end, vout_count, error)) {
        return false;
    }

    // Sanity check: max 100k outputs
    if (vout_count > 100000) {
        if (error) *error = "Too many outputs";
        return false;
    }

    // TX-003 FIX: Check if we have enough data remaining for claimed output count
    size_t min_outputs_size = vout_count * MIN_TX_OUTPUT_SIZE;
    if (min_outputs_size > static_cast<size_t>(end - ptr)) {
        if (error) *error = "Transaction claims more outputs than data available";
        return false;
    }

    // Deserialize each output
    vout.resize(vout_count);
    for (size_t i = 0; i < vout_count; i++) {
        CTxOut& txout = vout[i];

        // Deserialize value (8 bytes)
        if (!DeserializeUint64(ptr, end, txout.nValue, error)) {
            return false;
        }

        // Deserialize scriptPubKey length
        uint64_t scriptPubKey_len;
        if (!DeserializeCompactSize(ptr, end, scriptPubKey_len, error)) {
            return false;
        }

        // Sanity check: max 10KB scriptPubKey
        if (scriptPubKey_len > 10000) {
            if (error) *error = "scriptPubKey too large";
            return false;
        }

        // Deserialize scriptPubKey data
        if (end - ptr < static_cast<ptrdiff_t>(scriptPubKey_len)) {
            if (error) *error = "Insufficient data for scriptPubKey";
            return false;
        }
        txout.scriptPubKey.assign(ptr, ptr + scriptPubKey_len);
        ptr += scriptPubKey_len;
    }

    // Deserialize locktime (4 bytes)
    if (!DeserializeUint32(ptr, end, nLockTime, error)) {
        return false;
    }

    // If caller provided bytesConsumed, return how many bytes we read
    if (bytesConsumed) {
        *bytesConsumed = ptr - data;
    } else {
        // Otherwise, verify we consumed exactly the right amount of data
        if (ptr != end) {
            if (error) *error = "Extra data after transaction";
            return false;
        }
    }

    // Invalidate cached hash (will be recalculated on next GetHash())
    hash_valid = false;

    return true;
}
