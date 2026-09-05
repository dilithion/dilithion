// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_PRIMITIVES_TRANSACTION_H
#define DILITHION_PRIMITIVES_TRANSACTION_H

#include <primitives/block.h>
#include <atomic>
#include <cstdint>
#include <vector>
#include <memory>

/** Serialize a compact size (Bitcoin-style varint) into a byte buffer.
 *  Exported so downstream consensus code (e.g. the single-source sighash
 *  preimage builder) reuses THIS one canonical encoder instead of hand-rolling
 *  a duplicate — see FIX-1 HIGH-1. There must be exactly one CompactSize encoder. */
void SerializeCompactSize(std::vector<uint8_t>& data, uint64_t size);

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

    /** Construct a CTransaction with default values. */
    CTransaction() : nVersion(1), nLockTime(0), hash_state(HASH_EMPTY) {}

    /** Construct a CTransaction with specified values. */
    CTransaction(int32_t nVersionIn, std::vector<CTxIn> vinIn, std::vector<CTxOut> voutIn, uint32_t nLockTimeIn)
        : nVersion(nVersionIn), vin(vinIn), vout(voutIn), nLockTime(nLockTimeIn), hash_state(HASH_EMPTY) {}

    /** Copy constructor.
     *  Deliberately does NOT carry the source's cached hash across: the copy
     *  is the publication boundary (MakeTransactionRef copy-constructs into a
     *  shared_ptr<const CTransaction>), and recomputing from the copied fields
     *  guarantees a published ref can never inherit a cache that went stale
     *  on a mutable builder-side local. */
    CTransaction(const CTransaction& tx)
        : nVersion(tx.nVersion), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), hash_state(HASH_EMPTY) {}

    /** Assignment operator */
    CTransaction& operator=(const CTransaction& tx) {
        nVersion = tx.nVersion;
        vin = tx.vin;
        vout = tx.vout;
        nLockTime = tx.nLockTime;
        InvalidateHashCache();
        return *this;
    }

    /** Return the txid (SHA3-256 of Serialize()), memoised.
     *
     *  BKL-01 / issue #167: the memo is filled with a compute-once protocol so
     *  that any number of threads may call GetHash() concurrently on one shared
     *  `const CTransaction` (the CTransactionRef case) without a data race:
     *  exactly one caller wins the HASH_EMPTY -> HASH_COMPUTING transition and
     *  is the sole writer of `hash_cached`; it publishes with a release-store of
     *  HASH_VALID, which every fast-path acquire-load pairs with. Losers return
     *  their own locally computed (identical) value and never touch the cache.
     *
     *  The memo is invalidated by every member function that mutates the
     *  transaction (SetNull, Deserialize, operator=; constructors start empty).
     *  It is NOT invalidated by direct writes to the public fields — a caller
     *  that calls GetHash() and then mutates vin/vout/nVersion/nLockTime in
     *  place on the same object must treat the earlier txid as stale. Every
     *  production builder (miner coinbase, wallet, RPC, genesis, net decoders)
     *  mutates first and hashes last, and publication copies (see the copy
     *  constructor), so no shared ref can carry a stale txid. */
    uint256 GetHash() const;

    /** Compute the txid from the current fields without touching the memo.
     *  Pure: safe to call from any thread on a const object. GetHash() returns
     *  exactly this value. */
    uint256 ComputeHash() const;

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
        InvalidateHashCache();
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

private:
    /** Memo states for the txid cache. Transitions: EMPTY -> COMPUTING (by the
     *  single CAS winner) -> VALID (release-store by that same winner); any
     *  mutating member resets to EMPTY. */
    enum : uint8_t { HASH_EMPTY = 0, HASH_COMPUTING = 1, HASH_VALID = 2 };

    /** Cached txid. Written only by the thread that won the EMPTY->COMPUTING
     *  CAS in GetHash(); read only after an acquire-load observed HASH_VALID. */
    mutable uint256 hash_cached;
    mutable std::atomic<uint8_t> hash_state;

    void InvalidateHashCache() { hash_state.store(HASH_EMPTY, std::memory_order_release); }
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
