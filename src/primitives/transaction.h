// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_PRIMITIVES_TRANSACTION_H
#define DILITHION_PRIMITIVES_TRANSACTION_H

#include <primitives/block.h>
#include <cstdint>
#include <vector>
#include <memory>

/** Serialize a compact size (Bitcoin-style varint) into a byte buffer.
 *  Exported so downstream consensus code (e.g. the single-source sighash
 *  preimage builder) reuses THIS one canonical encoder instead of hand-rolling
 *  a duplicate — see FIX-1 HIGH-1. There must be exactly one CompactSize encoder. */
void SerializeCompactSize(std::vector<uint8_t>& data, uint64_t size);

/** Malleability closure (finding #5): the single-source minimality rule for
 *  CompactSize decoders. A CompactSize MUST be encoded in its shortest form,
 *  or the two byte-strings for one value become a wire-hygiene / relay-dedup
 *  ambiguity. All three decoders (CDataStream::ReadCompactSize,
 *  DeserializeCompactSize, and the block tx-count decoder in validation.cpp,
 *  which now delegates here) share THIS one range check so they cannot drift.
 *
 *  @param prefix  the leading discriminator byte that was read
 *  @param value   the value decoded from the bytes that followed it
 *  @return true iff `prefix` is the shortest encoding that can represent `value`.
 *
 *  Soft-fork tightening: rejects a strict subset of previously-accepted
 *  encodings; nothing previously-invalid becomes valid. Safe on a fresh
 *  canonical genesis by construction (no honest producer emits non-minimal). */
inline bool CompactSizeIsCanonical(uint8_t prefix, uint64_t value) {
    if (prefix < 253)      return true;                    // 1-byte form: value == prefix, always minimal
    if (prefix == 253)     return value >= 253;            // 3-byte form must carry >= 253
    if (prefix == 254)     return value > 0xFFFFULL;       // 5-byte form must carry > 0xFFFF
    /* prefix == 255 */    return value > 0xFFFFFFFFULL;   // 9-byte form must carry > 0xFFFFFFFF
}

/** Deserialize a compact size (Bitcoin-style varint) from a byte range, with
 *  minimal-encoding enforcement (finding #5). Exported (non-static) so the
 *  block tx-count decoder in validation.cpp reuses THIS one decoder instead of
 *  hand-rolling a third copy that drifts. Advances `data` past the bytes read.
 *  Returns false (setting *error, if provided) on truncation or non-minimal
 *  encoding. */
bool DeserializeCompactSize(const uint8_t*& data, const uint8_t* end,
                            uint64_t& size, std::string* error);

/**
 * An outpoint - a combination of a transaction hash and an index n into its vout
 */
class COutPoint {
public:
    uint256 hash;
    uint32_t n;

    COutPoint() : n(0xffffffff) {}
    COutPoint(const uint256& hashIn, uint32_t nIn) : hash(hashIn), n(nIn) {}

    bool IsNull() const { return hash.IsNull() && n == 0xffffffff; }

    void SetNull() {
        hash = uint256();
        n = 0xffffffff;
    }

    bool operator==(const COutPoint& other) const {
        return (hash == other.hash && n == other.n);
    }

    bool operator<(const COutPoint& other) const {
        if (hash == other.hash) {
            return n < other.n;
        }
        return hash < other.hash;
    }
};

/**
 * An input of a transaction. It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn {
public:
    COutPoint prevout;
    std::vector<uint8_t> scriptSig;  // Signature script (placeholder for Dilithium signature)
    uint32_t nSequence;

    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    CTxIn() : nSequence(SEQUENCE_FINAL) {}

    CTxIn(COutPoint prevoutIn, std::vector<uint8_t> scriptSigIn = std::vector<uint8_t>(), uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(prevoutIn), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    CTxIn(uint256 hashPrevTx, uint32_t nOut, std::vector<uint8_t> scriptSigIn = std::vector<uint8_t>(), uint32_t nSequenceIn = SEQUENCE_FINAL)
        : prevout(hashPrevTx, nOut), scriptSig(scriptSigIn), nSequence(nSequenceIn) {}

    bool operator==(const CTxIn& other) const {
        return (prevout == other.prevout &&
                scriptSig == other.scriptSig &&
                nSequence == other.nSequence);
    }
};

/**
 * An output of a transaction. It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut {
public:
    uint64_t nValue;
    std::vector<uint8_t> scriptPubKey;  // Locking script (P2PKH for now)

    CTxOut() : nValue(0) {}

    CTxOut(uint64_t nValueIn, std::vector<uint8_t> scriptPubKeyIn)
        : nValue(nValueIn), scriptPubKey(scriptPubKeyIn) {}

    bool IsNull() const { return nValue == 0 && scriptPubKey.empty(); }

    void SetNull() {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool operator==(const CTxOut& other) const {
        return (nValue == other.nValue &&
                scriptPubKey == other.scriptPubKey);
    }
};

/**
 * The basic transaction that is broadcast on the network and contained in
 * blocks. A transaction can contain multiple inputs and outputs.
 */
class CTransaction {
public:
    // Transaction version
    int32_t nVersion;

    // Transaction inputs
    std::vector<CTxIn> vin;

    // Transaction outputs
    std::vector<CTxOut> vout;

    // Lock time (0 = not locked)
    uint32_t nLockTime;

    // Cached hash
    mutable uint256 hash_cached;
    mutable bool hash_valid;

    /** Construct a CTransaction with default values. */
    CTransaction() : nVersion(1), nLockTime(0), hash_valid(false) {}

    /** Construct a CTransaction with specified values. */
    CTransaction(int32_t nVersionIn, std::vector<CTxIn> vinIn, std::vector<CTxOut> voutIn, uint32_t nLockTimeIn)
        : nVersion(nVersionIn), vin(vinIn), vout(voutIn), nLockTime(nLockTimeIn), hash_valid(false) {}

    /** Copy constructor */
    CTransaction(const CTransaction& tx)
        : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash_valid(false) {}

    /** Assignment operator */
    CTransaction& operator=(const CTransaction& tx) {
        nVersion = tx.nVersion;
        vin = tx.vin;
        vout = tx.vout;
        nLockTime = tx.nLockTime;
        hash_valid = false;
        return *this;
    }

    /** Compute the hash of this transaction. */
    uint256 GetHash() const;

    /** Compute the signing hash of this transaction (excludes scriptSig for signature verification).
     *  This is used in both signing and verification to ensure consistent hash computation.
     *  Similar to Bitcoin's SIGHASH_ALL but simplified for Dilithion's single signature scheme.
     */
    uint256 GetSigningHash() const;

    /** Get the serialized size of this transaction. */
    size_t GetSerializedSize() const;

    /** Check if transaction is null (no inputs or outputs). */
    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    /** Set transaction to null state. */
    void SetNull() {
        nVersion = 1;
        vin.clear();
        vout.clear();
        nLockTime = 0;
        hash_valid = false;
    }

    /** Basic validation - check structure is valid. */
    bool CheckBasicStructure() const;

    /** Get total output value. */
    uint64_t GetValueOut() const;

    /** Check if this is a coinbase transaction (first tx in block, creates new coins). */
    bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    /** Serialize transaction data for hashing or transmission. */
    std::vector<uint8_t> Serialize() const;

    /** Deserialize transaction data from byte stream (CS-002).
     * @param data Pointer to serialized data
     * @param len Length of data buffer
     * @param error Optional pointer to store error message
     * @param bytesConsumed Optional pointer to store number of bytes consumed
     * @return true if successful
     * Note: If bytesConsumed is provided, extra data after transaction is allowed.
     */
    bool Deserialize(const uint8_t* data, size_t len, std::string* error = nullptr, size_t* bytesConsumed = nullptr);
};

/** A reference to a transaction (shared pointer for efficiency). */
typedef std::shared_ptr<const CTransaction> CTransactionRef;

/** Create a transaction reference. */
inline CTransactionRef MakeTransactionRef() {
    return std::make_shared<const CTransaction>();
}

/** Create a transaction reference from existing transaction. */
template <typename Tx>
inline CTransactionRef MakeTransactionRef(Tx&& txIn) {
    return std::make_shared<const CTransaction>(std::forward<Tx>(txIn));
}

#endif // DILITHION_PRIMITIVES_TRANSACTION_H
