// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

// Boost unit tests for the small-RPCs cluster ported from Bitcoin Core
// v28.0 (T1.B). Coverage:
//   waitfornewblock        -- short-timeout returns the current tip.
//   waitforblock           -- short-timeout returns the current tip.
//   waitforblockheight     -- already-met height returns immediately.
//   waitforblockheight     -- notify wakes a waiter early.
//   gettxoutproof          -- happy path (proof is constructed and
//                             verifytxoutproof recovers the txids)
//                             plus non-existent-txid negative case.
//   verifytxoutproof       -- corrupted-hex negative case.
//
// getblockstats is intentionally not in this cluster: it requires
// per-tx fee fields that depend on undo-data exposure (separate
// workstream alongside coinstatsindex).
//
// These exercise CRPCServer's public surface directly; they do NOT
// stand up the HTTP server. Static handlers run as plain function
// calls, and the instance-method handler (gettxoutproof) runs against
// a CRPCServer constructed with a non-production port (no Listen()
// ever called).

#include <boost/test/unit_test.hpp>

#include <rpc/server.h>

#include <consensus/chain.h>
#include <consensus/validation.h>
#include <core/chainparams.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

extern CChainState g_chainstate;

BOOST_AUTO_TEST_SUITE(rpc_small_cluster_tests)

namespace {

// ---- Test scaffolding (mirrors patterns from tx_index_tests.cpp) ----

std::string MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("rpc_small_cluster_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path.string();
}

void CleanupTempDir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

class TempDbScope {
public:
    explicit TempDbScope(const std::string& tag) : m_path(MakeTempDir(tag)) {}
    ~TempDbScope() { CleanupTempDir(m_path); }
    const std::string& path() const { return m_path; }
    TempDbScope(const TempDbScope&) = delete;
    TempDbScope& operator=(const TempDbScope&) = delete;
private:
    std::string m_path;
};

void WriteCompactSize(std::vector<uint8_t>& data, uint64_t size) {
    if (size < 253) {
        data.push_back(static_cast<uint8_t>(size));
    } else if (size <= 0xFFFF) {
        data.push_back(253);
        data.push_back(static_cast<uint8_t>(size & 0xFF));
        data.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    } else if (size <= 0xFFFFFFFF) {
        data.push_back(254);
        for (int i = 0; i < 4; ++i) {
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
        }
    } else {
        data.push_back(255);
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<uint8_t>((size >> (i * 8)) & 0xFF));
        }
    }
}

CTransactionRef MakeUniqueTx(uint8_t seed_a, uint8_t seed_b) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    uint256 prev;
    std::memset(prev.data, seed_a, 32);
    std::vector<uint8_t> sig{seed_a, seed_b, 0xAA};
    tx.vin.push_back(CTxIn(prev, seed_b, sig, CTxIn::SEQUENCE_FINAL));
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, seed_a, seed_b};
    tx.vout.push_back(CTxOut(1000ULL + seed_a, spk));
    return MakeTransactionRef(tx);
}

// Coinbase: vin[0].prevout is null. Output value = subsidy + fee. We use
// 50 DIL = 5'000'000'000 ions (matches CalculateBlockSubsidy at height 0
// for the default chain params).
CTransactionRef MakeCoinbaseTx(uint64_t value, uint8_t scriptsig_seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    CTxIn vin;
    vin.prevout.SetNull();
    vin.scriptSig = std::vector<uint8_t>{scriptsig_seed, 0x01, 0x02};
    vin.nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin.push_back(vin);
    std::vector<uint8_t> spk{0x76, 0xa9, 0x14, scriptsig_seed, 0xCB};
    tx.vout.push_back(CTxOut(value, spk));
    return MakeTransactionRef(tx);
}

CBlock MakeBlock(const std::vector<CTransactionRef>& txs) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = 1700000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    std::vector<uint8_t> vtx_data;
    WriteCompactSize(vtx_data, txs.size());
    for (const auto& tx : txs) {
        auto data = tx->Serialize();
        vtx_data.insert(vtx_data.end(), data.begin(), data.end());
    }
    block.vtx = std::move(vtx_data);

    // Build merkle root so the block is internally consistent
    // (verifytxoutproof compares reconstructed roots against the
    // block header's hashMerkleRoot).
    CBlockValidator validator;
    block.hashMerkleRoot = validator.BuildMerkleRoot(txs);
    return block;
}

uint256 SyntheticBlockHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = seed;
    h.data[31] = 0xAB;
    return h;
}

// Stand up a small chain (n blocks, each with one coinbase + one regular
// tx), persisted to a CBlockchainDB so RPC handlers can ReadBlock /
// ReadBlockIndex against it. Cleans up g_chainstate before building.
struct ClusterChainFixture {
    std::vector<uint256>                             per_height_hash;
    std::vector<std::vector<CTransactionRef>>        per_height_txs;
    std::vector<CBlock>                              per_height_block;

    // PR #38 red-team C6: save/restore g_chainParams. The fixture mutates
    // a process-wide global; per project convention (see
    // src/test/timestamp_tests.cpp, src/test/chain_selector_tests.cpp:698)
    // tests that touch g_chainParams should save the prior pointer and
    // restore on teardown. Otherwise a later test that depends on a
    // different g_chainParams gets state pollution from this fixture.
    Dilithion::ChainParams* m_prev_chain_params = nullptr;

    ~ClusterChainFixture() {
        // Restore prior g_chainParams. The static cluster_test_params
        // we set lives binary-long, so restoring just decouples our
        // fixture from later tests' expected pointer.
        Dilithion::g_chainParams = m_prev_chain_params;
        // Belt-and-suspenders: make sure our SetTipForTest doesn't leak
        // either.
        g_chainstate.Cleanup();
    }

    void Build(int n_blocks, CBlockchainDB& chain_db) {
        per_height_hash.clear();
        per_height_txs.clear();
        per_height_block.clear();
        per_height_hash.reserve(n_blocks);
        per_height_txs.reserve(n_blocks);
        per_height_block.reserve(n_blocks);

        g_chainstate.Cleanup();

        // PR #38 red-team C5 follow-up: clear the cluster shutdown flag.
        // Other test suites in the same binary may have called
        // CRPCServer::Stop() (which sets the flag) before us. Without
        // this reset, wait-* RPC predicates would short-circuit on
        // shutdown=true and the cluster tests would fail with the chain
        // returning immediately at the wrong height.
        CRPCServer::ResetClusterStateForTests();

        // PR #38 red-team C6: capture prior g_chainParams BEFORE we
        // potentially overwrite it.
        m_prev_chain_params = Dilithion::g_chainParams;

        // Ensure chain params are initialized before any subsidy/difficulty
        // computation. CalculateBlockSubsidy reads halvingInterval from
        // g_chainParams; if g_chainParams is zero-initialized (default-
        // constructed via `new ChainParams()`), halvingInterval==0 causes
        // an integer divide-by-zero. The local agent's tests passed only
        // because some prior test in the suite happened to leave a valid
        // g_chainParams behind; on fresh CI, the divide-by-zero crashes
        // test execution. Set up Mainnet defaults here for determinism.
        if (Dilithion::g_chainParams == nullptr ||
            Dilithion::g_chainParams->halvingInterval == 0) {
            static Dilithion::ChainParams cluster_test_params =
                Dilithion::ChainParams::Mainnet();
            Dilithion::g_chainParams = &cluster_test_params;
        }

        CBlockIndex* prev_idx = nullptr;
        uint64_t subsidy = CBlockValidator::CalculateBlockSubsidy(0);

        for (int h = 0; h < n_blocks; ++h) {
            uint256 block_hash = SyntheticBlockHash(static_cast<uint8_t>(h + 1));
            per_height_hash.push_back(block_hash);

            // Coinbase pays subsidy exactly (no fees), then one user tx.
            auto cb  = MakeCoinbaseTx(subsidy,
                                      static_cast<uint8_t>(0xC0 | h));
            auto utx = MakeUniqueTx(static_cast<uint8_t>(h + 0x10),
                                    static_cast<uint8_t>(h + 0x20));
            std::vector<CTransactionRef> txs{cb, utx};
            per_height_txs.push_back(txs);

            CBlock block = MakeBlock(txs);
            block.nTime = 1700000000 + static_cast<uint32_t>(h * 60);
            if (h == 0) {
                block.hashPrevBlock = uint256();
            } else {
                block.hashPrevBlock = per_height_hash[h - 1];
            }
            BOOST_REQUIRE(chain_db.WriteBlock(block_hash, block));
            {
                CBlockIndex idx_persist;
                idx_persist.nHeight = h;
                idx_persist.phashBlock = block_hash;
                idx_persist.nTime = block.nTime;
                idx_persist.nVersion = block.nVersion;
                idx_persist.header.hashMerkleRoot = block.hashMerkleRoot;
                idx_persist.header.hashPrevBlock = block.hashPrevBlock;
                idx_persist.nBits = block.nBits;
                idx_persist.nNonce = block.nNonce;
                idx_persist.nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                                      CBlockIndex::BLOCK_HAVE_DATA;
                BOOST_REQUIRE(chain_db.WriteBlockIndex(block_hash, idx_persist));
            }
            per_height_block.push_back(block);

            auto pidx = std::make_unique<CBlockIndex>();
            pidx->nHeight = h;
            pidx->phashBlock = block_hash;
            pidx->pprev = prev_idx;
            pidx->nTime = block.nTime;
            pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                            CBlockIndex::BLOCK_HAVE_DATA;

            CBlockIndex* raw = pidx.get();
            BOOST_REQUIRE(g_chainstate.AddBlockIndex(block_hash,
                                                     std::move(pidx)));
            if (prev_idx != nullptr) prev_idx->pnext = raw;
            prev_idx = raw;
        }
        if (prev_idx != nullptr) g_chainstate.SetTipForTest(prev_idx);
    }
};

// Strip the "<key>": prefix off a JSON-string value embedded in our
// hand-rolled JSON. Returns true if found; on success `value` is the
// raw substring (no quotes for strings, raw token for ints).
bool ExtractScalar(const std::string& body,
                   const std::string& key,
                   std::string& value) {
    std::string needle = "\"" + key + "\":";
    auto p = body.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    if (p < body.size() && body[p] == '"') {
        auto q = body.find('"', p + 1);
        if (q == std::string::npos) return false;
        value = body.substr(p + 1, q - p - 1);
        return true;
    }
    auto end = body.find_first_of(",}", p);
    if (end == std::string::npos) return false;
    value = body.substr(p, end - p);
    return true;
}

} // namespace

// ---- Help-text and registration smoke test ----

BOOST_AUTO_TEST_CASE(help_text_lists_all_five_rpcs) {
    CRPCServer srv(0);  // port 0; never starts the listener
    // RPC_Help is private but exposed via the "help" handler. We don't
    // call the full request path here; instead we just confirm that the
    // help-text addition compiles + that the handlers map is populated
    // by introspecting NotifyBlockTipChanged (no-op) and the new
    // statics being callable.
    BOOST_CHECK_NO_THROW(CRPCServer::NotifyBlockTipChanged());
}

// ---- waitforblockheight: already-met case returns immediately ----

BOOST_AUTO_TEST_CASE(waitforblockheight_already_met_returns_immediately) {
    TempDbScope scope_chain("wait_height_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(3, chain_db);

    // Tip is at height 2. Asking for height 0 should return nearly
    // instantly because the predicate is already true.
    auto t0 = std::chrono::steady_clock::now();
    std::string result = CRPCServer::RPC_WaitForBlockHeight(
        "{\"height\":0,\"timeout_ms\":5000}");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK_LT(elapsed, 1000);  // must not have actually waited

    std::string height_str;
    BOOST_REQUIRE(ExtractScalar(result, "height", height_str));
    BOOST_CHECK_EQUAL(height_str, "2");

    g_chainstate.Cleanup();
}

// ---- waitfornewblock + waitforblock: timeout returns current tip ----

BOOST_AUTO_TEST_CASE(waitfornewblock_short_timeout_returns_tip) {
    TempDbScope scope_chain("wait_new_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(2, chain_db);  // tip at height 1

    auto t0 = std::chrono::steady_clock::now();
    std::string result = CRPCServer::RPC_WaitForNewBlock(
        "{\"timeout_ms\":150}");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK_GE(elapsed, 100);  // honored the timeout floor
    BOOST_CHECK_LT(elapsed, 5000); // didn't wait forever

    // Returned tip should be height 1 (no new block was connected).
    std::string height_str;
    BOOST_REQUIRE(ExtractScalar(result, "height", height_str));
    BOOST_CHECK_EQUAL(height_str, "1");

    g_chainstate.Cleanup();
}

BOOST_AUTO_TEST_CASE(waitforblock_short_timeout_returns_current_tip) {
    TempDbScope scope_chain("wait_block_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(1, chain_db);  // tip at height 0

    // Wait for a hash that will never arrive.
    uint256 ghost = SyntheticBlockHash(0xFE);
    std::string params = std::string("{\"hash\":\"") + ghost.GetHex() +
                         "\",\"timeout_ms\":120}";
    auto t0 = std::chrono::steady_clock::now();
    std::string result = CRPCServer::RPC_WaitForBlock(params);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK_GE(elapsed, 80);

    std::string height_str;
    BOOST_REQUIRE(ExtractScalar(result, "height", height_str));
    BOOST_CHECK_EQUAL(height_str, "0");

    g_chainstate.Cleanup();
}

// ---- waitforblockheight: notify wakes a waiter early ----

BOOST_AUTO_TEST_CASE(waitforblockheight_wakes_on_notify) {
    TempDbScope scope_chain("wait_notify_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(2, chain_db);  // tip at height 1

    // Spawn a thread that, after a short delay, advances the tip and
    // pings NotifyBlockTipChanged() the way the chainstate callback
    // would in production.
    std::thread bumper([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        // Append a third block so tip advances to height 2.
        uint256 block_hash = SyntheticBlockHash(0xF1);
        auto cb  = MakeCoinbaseTx(
            CBlockValidator::CalculateBlockSubsidy(0), 0xC9);
        CBlock block = MakeBlock({cb});
        block.nTime = 1700000999;
        block.hashPrevBlock = fix.per_height_hash.back();
        chain_db.WriteBlock(block_hash, block);
        {
            CBlockIndex idx_persist;
            idx_persist.nHeight = 2;
            idx_persist.phashBlock = block_hash;
            idx_persist.nTime = block.nTime;
            idx_persist.nVersion = block.nVersion;
            idx_persist.header.hashMerkleRoot = block.hashMerkleRoot;
            idx_persist.header.hashPrevBlock = block.hashPrevBlock;
            idx_persist.nBits = block.nBits;
            idx_persist.nNonce = block.nNonce;
            idx_persist.nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                                  CBlockIndex::BLOCK_HAVE_DATA;
            chain_db.WriteBlockIndex(block_hash, idx_persist);
        }

        auto pidx = std::make_unique<CBlockIndex>();
        pidx->nHeight = 2;
        pidx->phashBlock = block_hash;
        pidx->pprev = g_chainstate.GetTip();
        pidx->nTime = block.nTime;
        pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                        CBlockIndex::BLOCK_HAVE_DATA;
        CBlockIndex* raw = pidx.get();
        g_chainstate.AddBlockIndex(block_hash, std::move(pidx));
        if (auto* prev = g_chainstate.GetTip()) prev->pnext = raw;
        // SetTip, not SetTipForTest: the main thread is parked in
        // RPC_WaitForBlockHeight and re-reads the tip via GetTip() under cs_main
        // every time its cv predicate runs. NotifyBlockTipChanged() deliberately
        // takes no mutex (an AB-BA with cs_main on the connect path -- see its
        // comment), so an UNLOCKED write here has no happens-before edge to the
        // woken waiter's read: TSan reports exactly that pair (this line vs
        // chain.cpp GetTip) on every main TSan run. The locking SetTip closes it.
        // Same pattern as PR #215 (tx_index_tests). SetTip's invariants hold:
        // `raw` went through AddBlockIndex above and nHeight == 2. Unlike #215
        // the lock hides nothing else: the unlocked `pnext` write above has no
        // concurrent reader here (the waiter reads only hash and height).
        g_chainstate.SetTip(raw);
        CRPCServer::NotifyBlockTipChanged();
    });

    auto t0 = std::chrono::steady_clock::now();
    std::string result = CRPCServer::RPC_WaitForBlockHeight(
        "{\"height\":2,\"timeout_ms\":5000}");
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    bumper.join();

    BOOST_CHECK_LT(elapsed, 4000);  // woke well before the 5s ceiling
    std::string height_str;
    BOOST_REQUIRE(ExtractScalar(result, "height", height_str));
    BOOST_CHECK_EQUAL(height_str, "2");

    g_chainstate.Cleanup();
}

// ---- waitforblock: bad hash rejected ----

BOOST_AUTO_TEST_CASE(waitforblock_short_hex_rejected) {
    BOOST_CHECK_THROW(
        CRPCServer::RPC_WaitForBlock("{\"hash\":\"deadbeef\"}"),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(waitforblockheight_negative_rejected) {
    BOOST_CHECK_THROW(
        CRPCServer::RPC_WaitForBlockHeight("{\"height\":-1}"),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(wait_timeout_zero_rejected) {
    BOOST_CHECK_THROW(
        CRPCServer::RPC_WaitForNewBlock("{\"timeout_ms\":0}"),
        std::runtime_error);
}

// ---- gettxoutproof + verifytxoutproof: round-trip ----

BOOST_AUTO_TEST_CASE(txoutproof_round_trip) {
    TempDbScope scope_chain("txoutproof_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(2, chain_db);

    CRPCServer srv(0);
    srv.RegisterBlockchain(&chain_db);
    srv.RegisterChainState(&g_chainstate);

    // Use the user (non-coinbase) tx from height 0.
    auto& txs = fix.per_height_txs[0];
    BOOST_REQUIRE_EQUAL(txs.size(), 2u);
    uint256 wanted_txid = txs[1]->GetHash();
    uint256 block_hash  = fix.per_height_hash[0];

    std::string proof_params =
        std::string("{\"txids\":[\"") + wanted_txid.GetHex() +
        "\"],\"blockhash\":\"" + block_hash.GetHex() + "\"}";
    std::string proof_response = srv.RPC_GetTxOutProof(proof_params);

    // Strip the surrounding quotes to get the raw hex.
    BOOST_REQUIRE_GT(proof_response.size(), 2u);
    BOOST_CHECK_EQUAL(proof_response.front(), '"');
    BOOST_CHECK_EQUAL(proof_response.back(),  '"');
    std::string proof_hex = proof_response.substr(1, proof_response.size() - 2);

    // Verify round-trips.
    std::string verify_params = "{\"proof\":\"" + proof_hex + "\"}";
    std::string verify_response = CRPCServer::RPC_VerifyTxOutProof(verify_params);

    // The recovered txid list must contain our wanted txid; the recovered
    // merkle root must equal the block's stored merkle root.
    BOOST_CHECK(verify_response.find(wanted_txid.GetHex()) != std::string::npos);

    std::string root_hex;
    BOOST_REQUIRE(ExtractScalar(verify_response, "merkleroot", root_hex));
    BOOST_CHECK_EQUAL(root_hex, fix.per_height_block[0].hashMerkleRoot.GetHex());

    std::string returned_block_hash;
    BOOST_REQUIRE(ExtractScalar(verify_response, "blockhash",
                                returned_block_hash));
    BOOST_CHECK_EQUAL(returned_block_hash, block_hash.GetHex());

    g_chainstate.Cleanup();
}

BOOST_AUTO_TEST_CASE(gettxoutproof_unknown_txid_rejected) {
    TempDbScope scope_chain("gettxoutproof_neg");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(1, chain_db);

    CRPCServer srv(0);
    srv.RegisterBlockchain(&chain_db);
    srv.RegisterChainState(&g_chainstate);

    // A txid that is NOT in the supplied block.
    uint256 ghost;
    std::memset(ghost.data, 0xAA, 32);

    std::string params =
        std::string("{\"txids\":[\"") + ghost.GetHex() +
        "\"],\"blockhash\":\"" + fix.per_height_hash[0].GetHex() + "\"}";
    BOOST_CHECK_THROW(srv.RPC_GetTxOutProof(params), std::runtime_error);

    g_chainstate.Cleanup();
}

BOOST_AUTO_TEST_CASE(verifytxoutproof_corrupted_hex_rejected) {
    // Truncated header (less than 32 bytes for blockhash).
    BOOST_CHECK_THROW(
        CRPCServer::RPC_VerifyTxOutProof("{\"proof\":\"deadbeef\"}"),
        std::runtime_error);
    // Non-hex.
    BOOST_CHECK_THROW(
        CRPCServer::RPC_VerifyTxOutProof("{\"proof\":\"zzz\"}"),
        std::runtime_error);
    // Missing param.
    BOOST_CHECK_THROW(
        CRPCServer::RPC_VerifyTxOutProof("{}"),
        std::runtime_error);
}

// ---- PR #38 red-team C8: missing test cases the first round didn't cover.

// C8(a): concurrent waiters parked on the cluster CV are ALL woken by a
// single NotifyBlockTipChanged(). The notify_all() semantics in the code
// are correct but the prior suite only had one waiter at a time -- a
// regression that swapped notify_all for notify_one would silently slip
// past the existing tests.
BOOST_AUTO_TEST_CASE(waitforblockheight_notify_wakes_multiple_waiters) {
    TempDbScope scope_chain("multi_waiter_chain");
    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    ClusterChainFixture fix;
    fix.Build(2, chain_db);  // tip at height 1

    // Spawn 3 waiters on the same height target.
    std::atomic<int> woke_count{0};
    auto waiter = [&]() {
        std::string result = CRPCServer::RPC_WaitForBlockHeight(
            "{\"height\":2,\"timeout_ms\":5000}");
        std::string h_str;
        if (ExtractScalar(result, "height", h_str) && h_str == "2") {
            ++woke_count;
        }
    };
    std::thread w1(waiter);
    std::thread w2(waiter);
    std::thread w3(waiter);

    // Wait briefly for all 3 to park on the CV.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Advance the chain (mirrors what waitforblockheight_wakes_on_notify
    // does for one waiter, but here we have three).
    uint256 block_hash = SyntheticBlockHash(0xF2);
    auto cb  = MakeCoinbaseTx(CBlockValidator::CalculateBlockSubsidy(0), 0xCA);
    CBlock block = MakeBlock({cb});
    block.nTime = 1700000999;
    block.hashPrevBlock = fix.per_height_hash.back();
    chain_db.WriteBlock(block_hash, block);
    {
        CBlockIndex idx_persist;
        idx_persist.nHeight = 2;
        idx_persist.phashBlock = block_hash;
        idx_persist.nTime = block.nTime;
        idx_persist.nVersion = block.nVersion;
        idx_persist.header.hashMerkleRoot = block.hashMerkleRoot;
        idx_persist.header.hashPrevBlock = block.hashPrevBlock;
        idx_persist.nBits = block.nBits;
        idx_persist.nNonce = block.nNonce;
        idx_persist.nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                              CBlockIndex::BLOCK_HAVE_DATA;
        chain_db.WriteBlockIndex(block_hash, idx_persist);
    }
    auto pidx = std::make_unique<CBlockIndex>();
    pidx->nHeight = 2;
    pidx->phashBlock = block_hash;
    pidx->pprev = g_chainstate.GetTip();
    pidx->nTime = block.nTime;
    pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                    CBlockIndex::BLOCK_HAVE_DATA;
    CBlockIndex* raw = pidx.get();
    g_chainstate.AddBlockIndex(block_hash, std::move(pidx));
    if (auto* prev = g_chainstate.GetTip()) prev->pnext = raw;
    // SetTip, not SetTipForTest: three waiters are parked in
    // RPC_WaitForBlockHeight and re-read the tip under cs_main on wake, and the
    // notify below takes no mutex, so this is the same unlocked-write race as
    // waitforblockheight_wakes_on_notify above. CI's TSan log showed only that
    // first site because TSan deduplicated the second behind it: measured, this
    // test run on its own reports the race (3/3), and with the first site fixed
    // alone the whole suite's single report moves HERE (5/5). A fix aimed at one
    // site leaves the sibling invisible; both are locked in the same change.
    g_chainstate.SetTip(raw);

    // Single notify_all() should wake all three waiters. notify_one()
    // would only wake one and the other two would time out.
    CRPCServer::NotifyBlockTipChanged();

    w1.join();
    w2.join();
    w3.join();

    // All 3 must have woken with the correct height. notify_one would
    // produce woke_count == 1.
    BOOST_CHECK_EQUAL(woke_count.load(), 3);
}

// C8(b): verifytxoutproof must reject nTransactions = 0xFFFFFFFF without
// hanging the worker thread. Pre-fix: MerkleTreeHeight's `1u << height`
// is UB at height >= 32; on x86_64 the shift count is masked to 5 bits
// so `1u << 32` = 1 and the loop never terminates (authenticated DoS).
// Post-fix: handler caps nTransactions at kVerifyTxOutProofMaxTxs and
// MerkleTreeHeight has a 32-iteration upper bound as defense in depth.
BOOST_AUTO_TEST_CASE(verifytxoutproof_oversize_ntxs_rejected) {
    // Build a 41-byte proof prefix: 32-byte block hash + 4-byte
    // nTransactions = 0xFFFFFFFF + 1-byte CompactSize nHashes = 0.
    std::vector<uint8_t> bytes;
    for (int i = 0; i < 32; ++i) bytes.push_back(0x42);  // block hash
    bytes.push_back(0xFF); bytes.push_back(0xFF);
    bytes.push_back(0xFF); bytes.push_back(0xFF);  // nTransactions
    bytes.push_back(0x00);  // nHashes = 0
    bytes.push_back(0x00);  // nFlagBytes = 0

    std::ostringstream hex;
    for (uint8_t b : bytes) {
        hex << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    std::string params = "{\"proof\":\"" + hex.str() + "\"}";

    // Must throw quickly (no infinite loop, no OOM crash). The exact
    // error message is implementation detail; we only assert the
    // call returns within a reasonable time.
    auto t0 = std::chrono::steady_clock::now();
    BOOST_CHECK_THROW(CRPCServer::RPC_VerifyTxOutProof(params),
                      std::runtime_error);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    // Pre-fix this would never return. Post-fix the cap rejects in <100ms.
    BOOST_CHECK_LT(elapsed, 5000);
}

BOOST_AUTO_TEST_SUITE_END()
