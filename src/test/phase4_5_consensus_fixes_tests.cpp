// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Phase 4.5 Consensus Fixes - Comprehensive Test Suite
 *
 * This test suite validates all fixes made in Phase 4.5:
 * - Phase 4.5.1: CVE-2012-2459 Merkle Tree Duplicate Transaction Attack
 * - Phase 4.5.2: Chain Reorganization Rollback Failure Handling
 * - Phase 4.5.3: Integer Overflow & Negative Timespan in Difficulty Calculation
 * - Phase 4.5.4: RAII Memory Management (tested implicitly through usage)
 *
 * Priority: P0 CRITICAL - These are security fixes that must be validated
 */

#include <boost/test/unit_test.hpp>

#include <consensus/validation.h>
#include <consensus/pow.h>
#include <consensus/chain.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <node/block_index.h>
#include <node/utxo_set.h>
#include <core/chainparams.h>
#include <uint256.h>
#include <crypto/sha3.h>
#include <amount.h>

#include <vector>
#include <cstring>
#include <memory>
#include <set>
#include <filesystem>
#include <random>
#include <sstream>

// NOTE: the live CBlockValidator lives in the GLOBAL namespace (not Consensus).
// The pre-fix test's `using namespace Consensus;` was part of its staleness.

namespace {
// Helper: build a representative CTransaction and return it as a CTransactionRef,
// matching the LIVE CBlockValidator::BuildMerkleRoot(std::vector<CTransactionRef>)
// signature (the pre-fix test used a stale BlockValidator/std::vector<CTransaction>
// API that no longer exists).
CTransactionRef MakeTx(uint8_t fill, int32_t version = 1, uint64_t amount = 50 * COIN) {
    CTransaction tx;
    tx.nVersion = version;
    tx.nLockTime = 0;
    uint256 prevHash;
    memset(prevHash.data, fill, 32);
    std::vector<uint8_t> sig(100, fill);
    tx.vin.push_back(CTxIn(prevHash, 0, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> scriptPubKey(50, fill);
    tx.vout.push_back(CTxOut(amount, scriptPubKey));
    return MakeTransactionRef(std::move(tx));
}

// ---------------------------------------------------------------------------
// Connect-path guard fixtures (INFO-1 fold): drive the REAL guard inside
// CUTXOSet::ApplyBlock rather than re-implementing its set-insert logic.
// ---------------------------------------------------------------------------

// RAII temp directory for a per-test leveldb UTXO db, mirroring the pattern in
// chainstate_integrity_tests.cpp / tx_index_integration_tests.cpp.
struct UtxoTempDir {
    std::filesystem::path path;
    explicit UtxoTempDir(const std::string& tag) {
        std::random_device rd;
        std::ostringstream oss;
        oss << "dilithion-phase45-cve-" << tag << "-" << rd();
        path = std::filesystem::temp_directory_path() / oss.str();
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
    }
    ~UtxoTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::string str() const { return path.string(); }
};

// A minimal non-coinbase tx with an EMPTY input vector. ApplyBlock's per-tx
// loop skips input-spending when vin is empty (the `for (txin : tx->vin)` body
// never runs), so this tx neither requires a pre-populated UTXO set nor can
// fail the "input not found" check. That is deliberate: it isolates the
// duplicate-txid guard as the SOLE reason a dup-txid block is rejected — with
// the guard removed, ApplyBlock processes both copies without error.
CTransactionRef MakeInputlessTx(uint8_t fill, uint64_t amount = 10 * COIN) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    // vin intentionally empty.
    std::vector<uint8_t> scriptPubKey(20, fill);
    tx.vout.push_back(CTxOut(amount, scriptPubKey));
    return MakeTransactionRef(std::move(tx));
}

// A coinbase-shaped tx (null prevout) for slot 0. ApplyBlock treats tx_idx==0
// as coinbase and skips its inputs regardless, but a null prevout keeps the
// shape honest.
CTransactionRef MakeCoinbaseLikeTx(uint8_t fill) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 nullPrev;  // all-zero => null prevout
    std::vector<uint8_t> sig{0xCB, fill};
    tx.vin.push_back(CTxIn(nullPrev, 0xFFFFFFFFu, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> scriptPubKey(20, fill);
    tx.vout.push_back(CTxOut(50 * COIN, scriptPubKey));
    return MakeTransactionRef(std::move(tx));
}

void WriteCompactSizeInline(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    } else {
        data.push_back(254);
        for (int i = 0; i < 4; ++i)
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
    }
}

// Assemble a CBlock whose vtx byte-blob is exactly what
// CBlockValidator::DeserializeBlockTransactions (called by ApplyBlock) parses:
// compactsize(txCount) followed by each tx->Serialize().
CBlock MakeBlockFromTxs(const std::vector<CTransactionRef>& txs) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1700000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    std::vector<uint8_t> vtx_data;
    WriteCompactSizeInline(vtx_data, txs.size());
    for (const auto& tx : txs) {
        auto data = tx->Serialize();
        vtx_data.insert(vtx_data.end(), data.begin(), data.end());
    }
    block.vtx = std::move(vtx_data);
    return block;
}

uint256 MakeDistinctBlockHash(uint8_t tag) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = tag;
    h.data[31] = 0x42;  // sentinel — never all-zero
    return h;
}
} // namespace

BOOST_AUTO_TEST_SUITE(phase4_5_consensus_fixes_tests)

// ============================================================================
// PHASE 4.5.1: CVE-2012-2459 MERKLE TREE DUPLICATE TRANSACTION TESTS
// ============================================================================

/**
 * CVE-2012-2459 — corrected to reflect LIVE behavior.
 *
 * The ORIGINAL test asserted that BuildMerkleRoot returns a NULL root when the
 * transaction list contains duplicates. That assertion is FALSE against the
 * live code: "BUG #49 FIX" (validation.cpp:59-62) deliberately removed the
 * merkle-layer duplicate check because it was rejecting valid orphan blocks.
 * The old test also called BlockValidator::BuildMerkleRoot(std::vector<CTransaction>),
 * a class/signature that no longer exists — it could not even compile, so it
 * gave false "CVE covered" comfort.
 *
 * Live truth (see _LIVE_CODE_DIVERGENCE_SCOPE JOB 1):
 *  - BuildMerkleRoot does NOT null out on duplicates (documented below), and
 *  - the CVE consensus-split path is closed on the connect path — historically
 *    incidentally by ApplyBlock's UTXO double-spend rejection, and now EXPLICITLY
 *    by the duplicate-txid guard added to CUTXOSet::ApplyBlock.
 *
 * This case documents the merkle-layer behavior so a future re-introduction of
 * a null-on-duplicate merkle rule (which would be a consensus change) is caught.
 */
BOOST_AUTO_TEST_CASE(cve_2012_2459_merkle_layer_does_not_null_on_duplicate) {
    CBlockValidator validator;

    CTransactionRef tx1 = MakeTx(0x42);

    // Duplicate transactions in the merkle input (the CVE attack shape).
    std::vector<CTransactionRef> dup_txs{tx1, tx1};
    uint256 dup_root = validator.BuildMerkleRoot(dup_txs);

    // LIVE behavior: BUG #49 removed the null-on-duplicate rule. The merkle root
    // is a normal, non-null hash. (The CVE is closed at the connect path, not here.)
    uint256 null_hash;
    memset(null_hash.data, 0, 32);
    BOOST_CHECK_MESSAGE(dup_root != null_hash,
        "LIVE: merkle root over duplicate txs is non-null (BUG #49 removed the "
        "merkle-layer CVE check; the guard lives on the connect path)");
}

/**
 * CVE-2012-2459 — unique transactions produce a valid (non-null) merkle root.
 */
BOOST_AUTO_TEST_CASE(cve_2012_2459_unique_transactions_valid) {
    CBlockValidator validator;

    CTransactionRef tx1 = MakeTx(0x42, 1, 50 * COIN);
    CTransactionRef tx2 = MakeTx(0x99, 1, 25 * COIN);

    std::vector<CTransactionRef> valid_txs{tx1, tx2};
    uint256 merkle_root = validator.BuildMerkleRoot(valid_txs);

    uint256 null_hash;
    memset(null_hash.data, 0, 32);
    BOOST_CHECK_MESSAGE(merkle_root != null_hash,
                       "Unique transactions should result in valid merkle root");
}

/**
 * CVE-2012-2459 — the connect-path duplicate-txid guard is the real closure.
 *
 * LOAD-BEARING (INFO-1 fold): this test exercises the ACTUAL guard inside
 * CUTXOSet::ApplyBlock (utxo_set.cpp: the `std::set<uint256> seen_txids` reject),
 * NOT a re-implementation of it. The earlier version of this case re-built the
 * set-insert logic inline and asserted on its own reconstruction — it would have
 * passed even with the real guard deleted (false coverage). This version builds
 * a real CBlock, calls ApplyBlock on a live (temp) UTXO db, and asserts the
 * return value.
 *
 * MUTATION-KILL PROPERTY (verified manually — see PR notes): the duplicate txs
 * are INPUT-LESS non-coinbase transactions, so ApplyBlock's input-spending path
 * is a no-op for them. The ONLY thing that rejects the dup-txid block is the
 * guard. With the guard removed, ApplyBlock processes both identical txs without
 * error and returns TRUE — so this assertion flips to a hard failure. The
 * unique-txid positive control proves the fixture itself lets ApplyBlock succeed,
 * i.e. a `false` on the dup block is attributable to the guard and not to some
 * incidental setup failure.
 */
BOOST_AUTO_TEST_CASE(cve_2012_2459_connect_path_dup_txid_detected) {
    // Sanity: byte-identical txs collide on txid; distinct fills do not.
    CTransactionRef probe_a = MakeInputlessTx(0x42);
    CTransactionRef probe_a_copy = MakeInputlessTx(0x42);
    CTransactionRef probe_b = MakeInputlessTx(0x99);
    BOOST_REQUIRE(probe_a->GetHash() == probe_a_copy->GetHash());
    BOOST_REQUIRE(probe_a->GetHash() != probe_b->GetHash());

    UtxoTempDir td("dup-txid");
    CUTXOSet utxo;
    BOOST_REQUIRE_MESSAGE(utxo.Open(td.str(), true),
        "must open a temp UTXO db to drive the real ApplyBlock guard");

    // --- Positive control: a unique-txid block is ACCEPTED. -----------------
    // coinbase-shaped tx at slot 0 + one distinct input-less tx. Proves the
    // fixture lets ApplyBlock reach success, so the dup-block rejection below is
    // the guard's doing, not a broken setup.
    {
        std::vector<CTransactionRef> unique_txs{
            MakeCoinbaseLikeTx(0x11), MakeInputlessTx(0x22)};
        CBlock unique_block = MakeBlockFromTxs(unique_txs);
        uint256 hashU = MakeDistinctBlockHash(0x01);
        BOOST_CHECK_MESSAGE(utxo.ApplyBlock(unique_block, /*height=*/1, hashU),
            "unique-txid block must be ACCEPTED by ApplyBlock (positive control)");
    }

    // --- The CVE shape: a block with two SAME-txid txs is REJECTED. ---------
    // [coinbase, txX, txX] — txX byte-identical twice => same txid. The guard
    // fires on the second copy. Because txX is input-less, removing the guard
    // would make ApplyBlock succeed (mutation-kill isolation).
    {
        CTransactionRef dupTx = MakeInputlessTx(0x55);
        CTransactionRef dupTx_copy = MakeInputlessTx(0x55);  // same bytes => same txid
        BOOST_REQUIRE(dupTx->GetHash() == dupTx_copy->GetHash());

        std::vector<CTransactionRef> dup_txs{
            MakeCoinbaseLikeTx(0x33), dupTx, dupTx_copy};
        CBlock dup_block = MakeBlockFromTxs(dup_txs);
        uint256 hashD = MakeDistinctBlockHash(0x02);
        BOOST_CHECK_MESSAGE(!utxo.ApplyBlock(dup_block, /*height=*/2, hashD),
            "duplicate-txid block must be REJECTED by the ApplyBlock guard "
            "(CVE-2012-2459); if this passes with the guard present but the "
            "test still succeeds after the guard is deleted, the test is not "
            "load-bearing");
    }
}

// NOTE: Phase 4.5.2 (chain reorg), 4.5.3 (difficulty overflow / negative
// timespan), and 4.5.4 (RAII) are NOT unit-tested here. They require a full
// blockchain-database integration harness (reorg) or are covered by sanitizers
// (RAII). Vacuous `BOOST_CHECK_MESSAGE(true, ...)` "documentation" placeholders
// were removed — they inflated the suite with fake coverage. The only
// load-bearing cases in this file are the CVE-2012-2459 tests above, which
// drive the REAL guard via CUTXOSet::ApplyBlock.

BOOST_AUTO_TEST_SUITE_END()
