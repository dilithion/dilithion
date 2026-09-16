// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Coinstatsindex integration tests -- PR-BA-2.
 *
 *   - getindexinfo registers coinstatsindex alongside txindex (schema-lock).
 *   - Reindex outer-loop catches a tip advance during the inner walk
 *     (R1 / E.2 mirror -- exercises the BaseIndex pattern that closes
 *     FA-HI-1).
 *   - Reorg-during-rebuild: mid-walk reorg via a contested-height fixture
 *     (E.6 mirror) -- walk bails, m_synced stays false, m_last_height is
 *     not advanced past the contested height.
 */

#include <boost/test/unit_test.hpp>

#include <index/coinstatsindex.h>
#include <index/tx_index.h>
#include <kernel/coinstats.h>
#include <rpc/server.h>

#include <consensus/chain.h>
#include <consensus/validation.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <node/utxo_set.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

extern CChainState g_chainstate;

namespace coin_stats_index_test_hooks {
extern std::atomic<uint64_t> g_walk_iteration_count;
}

BOOST_AUTO_TEST_SUITE(coinstatsindex_integration_tests)

namespace {

std::string MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("cs_int_" + tag + "_" +
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

uint256 HashForHeight(int height) {
    uint256 h;
    std::memset(h.data, 0, 32);
    uint32_t height_u = static_cast<uint32_t>(height);
    std::memcpy(h.data, &height_u, 4);
    h.data[31] = 0xCC;
    return h;
}

uint256 MakeHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, seed, 32);
    return h;
}

CTransactionRef MakeCoinbase(uint32_t height_marker, uint64_t reward, uint8_t spk_seed) {
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    std::vector<uint8_t> sig;
    sig.push_back(0x04);
    sig.push_back(static_cast<uint8_t>(height_marker & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 8) & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 16) & 0xFF));
    sig.push_back(static_cast<uint8_t>((height_marker >> 24) & 0xFF));
    tx.vin.push_back(CTxIn(COutPoint(), sig));
    std::vector<uint8_t> spk(25, spk_seed);
    spk[0] = 0x76; spk[1] = 0xa9; spk[2] = 0x14;
    spk[23] = 0x88; spk[24] = 0xac;
    tx.vout.push_back(CTxOut(reward, spk));
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

    CBlockValidator validator;
    block.hashMerkleRoot = validator.BuildMerkleRoot(txs);
    return block;
}

struct ChainFixture {
    std::vector<CTransactionRef> per_height_coinbase;
    std::vector<uint256>         per_height_hash;
    std::vector<CBlock>          per_height_block;

    void Build(int n_blocks, CBlockchainDB& chain_db, CUTXOSet& utxo_set) {
        per_height_coinbase.clear();
        per_height_hash.clear();
        per_height_block.clear();
        per_height_coinbase.reserve(n_blocks);
        per_height_hash.reserve(n_blocks);
        per_height_block.reserve(n_blocks);

        g_chainstate.Cleanup();

        CBlockIndex* prev_idx = nullptr;
        for (int h = 0; h < n_blocks; ++h) {
            uint256 block_hash = HashForHeight(h);
            per_height_hash.push_back(block_hash);

            auto cb = MakeCoinbase(static_cast<uint32_t>(h),
                                   5000ULL + h,
                                   static_cast<uint8_t>(0xC0 + (h & 0x3F)));
            per_height_coinbase.push_back(cb);

            CBlock block = MakeBlock({cb});
            block.hashPrevBlock = (h == 0) ? uint256() : per_height_hash[h - 1];

            BOOST_REQUIRE(chain_db.WriteBlock(block_hash, block));
            BOOST_REQUIRE(utxo_set.ApplyBlock(block, h, block_hash));
            per_height_block.push_back(block);

            auto pidx = std::make_unique<CBlockIndex>();
            pidx->nHeight = h;
            pidx->phashBlock = block_hash;
            pidx->pprev = prev_idx;
            pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                            CBlockIndex::BLOCK_HAVE_DATA;
            CBlockIndex* raw = pidx.get();
            BOOST_REQUIRE(g_chainstate.AddBlockIndex(block_hash, std::move(pidx)));
            if (prev_idx != nullptr) {
                prev_idx->pnext = raw;
            }
            prev_idx = raw;
        }

        if (prev_idx != nullptr) {
            g_chainstate.SetTipForTest(prev_idx);
        }
        BOOST_REQUIRE(utxo_set.Flush());
    }
};

bool WaitForSync(CCoinStatsIndex& idx, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (idx.IsSynced()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return idx.IsSynced();
}

} // namespace

// ===========================================================================
// getindexinfo schema-lock with coinstatsindex registered.
//
// Three response shapes covered:
//   (a) no indexes registered                              -> "{}"
//   (b) coinstatsindex enabled, mid-sync                   -> {"coinstatsindex":{...}}
//   (c) coinstatsindex enabled + synced                    -> with best_block_height=N
//   (d) BOTH txindex and coinstatsindex synced             -> both keys
// ===========================================================================
BOOST_AUTO_TEST_CASE(getindexinfo_schema_lock_in_coinstats) {
    // Pre-state: ensure no globals leak from prior tests in this process.
    g_tx_index.reset();
    g_coin_stats_index.reset();

    // (a) No index registered.
    BOOST_CHECK_EQUAL(CRPCServer::RPC_GetIndexInfo(""), std::string("{}"));

    TempDbScope scope_cs("gisidx");
    TempDbScope scope_chain("gischain");
    TempDbScope scope_utxo("gisutxo");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    CUTXOSet utxo_set;
    BOOST_REQUIRE(utxo_set.Open(scope_utxo.path(), true));

    constexpr int kN = 3;
    ChainFixture fix;
    fix.Build(kN, chain_db, utxo_set);

    g_coin_stats_index = std::make_unique<CCoinStatsIndex>();
    BOOST_REQUIRE(g_coin_stats_index->Init(scope_cs.path(), &chain_db, &utxo_set));

    // (b) Cold-start. Schema includes the M2 `corrupted` field.
    BOOST_CHECK(!g_coin_stats_index->IsSynced());
    BOOST_CHECK_EQUAL(g_coin_stats_index->LastIndexedHeight(), -1);
    BOOST_CHECK(!g_coin_stats_index->IsCorrupted());
    BOOST_CHECK_EQUAL(
        CRPCServer::RPC_GetIndexInfo(""),
        std::string("{\"coinstatsindex\":{\"synced\":false,\"best_block_height\":-1,\"corrupted\":false}}"));

    // (c) Synced.
    g_coin_stats_index->StartBackgroundSync();
    BOOST_REQUIRE(WaitForSync(*g_coin_stats_index, std::chrono::seconds(5)));
    BOOST_CHECK_EQUAL(
        CRPCServer::RPC_GetIndexInfo(""),
        std::string("{\"coinstatsindex\":{\"synced\":true,\"best_block_height\":2,\"corrupted\":false}}"));

    // (d) Add txindex too. Must be listed BEFORE coinstatsindex per the
    // handler's ordering (txindex first, coinstatsindex second).
    TempDbScope scope_tx("txfortest");
    g_tx_index = std::make_unique<CTxIndex>();
    BOOST_REQUIRE(g_tx_index->Init(scope_tx.path(), &chain_db));
    g_tx_index->StartBackgroundSync();
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            if (g_tx_index->IsSynced()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    BOOST_REQUIRE(g_tx_index->IsSynced());

    BOOST_CHECK_EQUAL(
        CRPCServer::RPC_GetIndexInfo(""),
        std::string("{\"txindex\":{\"synced\":true,\"best_block_height\":2},"
                    "\"coinstatsindex\":{\"synced\":true,\"best_block_height\":2,\"corrupted\":false}}"));

    // Teardown.
    g_tx_index->Stop();
    g_tx_index.reset();
    g_coin_stats_index->Stop();
    g_coin_stats_index.reset();

    BOOST_CHECK_EQUAL(CRPCServer::RPC_GetIndexInfo(""), std::string("{}"));

    g_chainstate.Cleanup();
}

// ===========================================================================
// Reindex outer-loop catches a tip advance during the inner walk.
// Mirrors tx_index_tests E.2; the load-bearing assertion is that the
// per-height records for ALL N+M heights are written.
// ===========================================================================
BOOST_AUTO_TEST_CASE(reindex_outer_loop_catches_tip_advance) {
    TempDbScope scope_idx("e2idx");
    TempDbScope scope_chain("e2chain");
    TempDbScope scope_utxo("e2utxo");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    CUTXOSet utxo_set;
    BOOST_REQUIRE(utxo_set.Open(scope_utxo.path(), true));

    constexpr int kN_initial = 1500;
    constexpr int kM_extra   = 25;
    ChainFixture fix;
    fix.Build(kN_initial, chain_db, utxo_set);

    CCoinStatsIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db, &utxo_set));

    const uint64_t pre_walk_count =
        coin_stats_index_test_hooks::g_walk_iteration_count.load();
    idx.StartBackgroundSync();

    // Wait for the inner walk to start, then extend the chain.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (coin_stats_index_test_hooks::g_walk_iteration_count.load()
            > pre_walk_count + 5) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    BOOST_REQUIRE(coin_stats_index_test_hooks::g_walk_iteration_count.load()
                  > pre_walk_count + 5);

    // Extend chainstate by kM_extra blocks. Manually append (not Build,
    // which wipes prior state).
    {
        CBlockIndex* prev_idx =
            g_chainstate.GetBlockIndex(fix.per_height_hash[kN_initial - 1]);
        BOOST_REQUIRE(prev_idx != nullptr);

        for (int h = kN_initial; h < kN_initial + kM_extra; ++h) {
            uint256 block_hash = HashForHeight(h);
            fix.per_height_hash.push_back(block_hash);
            auto cb = MakeCoinbase(static_cast<uint32_t>(h),
                                   5000ULL + h,
                                   static_cast<uint8_t>(0xC0 + (h & 0x3F)));
            fix.per_height_coinbase.push_back(cb);
            CBlock block = MakeBlock({cb});
            block.hashPrevBlock = fix.per_height_hash[h - 1];
            BOOST_REQUIRE(chain_db.WriteBlock(block_hash, block));
            BOOST_REQUIRE(utxo_set.ApplyBlock(block, h, block_hash));
            fix.per_height_block.push_back(block);

            auto pidx = std::make_unique<CBlockIndex>();
            pidx->nHeight = h;
            pidx->phashBlock = block_hash;
            pidx->pprev = prev_idx;
            pidx->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                            CBlockIndex::BLOCK_HAVE_DATA;
            CBlockIndex* raw = pidx.get();
            BOOST_REQUIRE(g_chainstate.AddBlockIndex(block_hash, std::move(pidx)));
            prev_idx->pnext = raw;
            prev_idx = raw;
        }
        // SetTip, not SetTipForTest: the CCoinStatsIndex sync thread started by
        // StartBackgroundSync() above is mid-walk and re-reads the tip via
        // GetTip() under cs_main after each pass (SyncLoop, coinstatsindex.cpp),
        // so this write must take cs_main too; SetTipForTest assigns pindexTip
        // unlocked. Same pattern as PR #215 (tx_index_tests, this test's
        // structural twin) and PR #219 (rpc_small_cluster_tests).
        //
        // MEASURED (CI-faithful TSan build, TSAN_OPTIONS=suppress_equal_addresses=0
        // so dedup cannot hide a sibling): the unlocked write in the order this
        // test had before -- write, then utxo_set.Flush() -- gave 0 reports in
        // 3/3 runs. That is NOT the absence of a race: Flush() releases cs_utxo
        // after the write, and the walk thread acquires cs_utxo in
        // ReadUndoBlock (ComputeBlockStats) before its next GetTip(), so TSan
        // sees a happens-before edge that is an accident of the test's next
        // statement. Probe (not committed): the same unlocked write with
        // Flush() ordered BEFORE it -> 1 report in 3/3 runs, this line
        // (SetTipForTest, chain.h) vs GetTip() in SyncLoop (coinstatsindex.cpp).
        // SetTip turns that incidental ordering into a lock; with SetTip the
        // probe ordering reports 0/3.
        //
        // As in #215, this lock also HIDES a race it does not fix: the
        // `prev_idx->pnext = raw` writes above stay unlocked (cs_main is
        // private) and the walk thread reads pnext WITHOUT cs_main at TWO
        // sites in coinstatsindex.cpp: WalkBlockRange's main-chain pick
        // (IsOnMainChain, ~:681) and WriteBlock's H3 parent check (~:488).
        // Those reads were already ordered here before this change -- each
        // pnext write for heights kN_initial..kN_initial+kM_extra-2 by the
        // NEXT iteration's AddBlockIndex (which takes and releases cs_main),
        // and only the last one by the Flush() edge -- so they never reported
        // in either arm, and a clean TSan run of this test says NOTHING about
        // those readers. Both sites are recorded in register row
        // TX-INDEX-REORG-DURING-REINDEX-MAPS-TXID-TO-ORPHAN.
        //
        // SetTip's invariants hold: every index above went through
        // AddBlockIndex, nHeight >= kN_initial, and nothing in this file reads
        // GetHeight() (which SetTip now keeps current) before Cleanup().
        g_chainstate.SetTip(prev_idx);
        BOOST_REQUIRE(utxo_set.Flush());
    }

    BOOST_REQUIRE(WaitForSync(idx, std::chrono::seconds(20)));
    BOOST_CHECK_EQUAL(idx.LastIndexedHeight(), kN_initial + kM_extra - 1);

    // Per-height records for all N+M heights are present.
    for (int h = 0; h < kN_initial + kM_extra; ++h) {
        CoinStats s;
        BOOST_REQUIRE_MESSAGE(idx.LookupStats(h, s),
                              "missing per-height record at h=" << h);
    }

    idx.Stop();
    g_chainstate.Cleanup();
}

// ===========================================================================
// Reorg-during-rebuild: TWO competing blocks at one height, neither on
// main chain. Walk MUST bail; m_last_height is NOT advanced past the
// contested height; m_synced stays false (operators detect via IsSynced).
// Mirrors tx_index_tests E.6 / FA-MD-5 simulation.
// ===========================================================================
BOOST_AUTO_TEST_CASE(reindex_skips_height_with_no_main_chain) {
    TempDbScope scope_idx("e6idx");
    TempDbScope scope_chain("e6chain");
    TempDbScope scope_utxo("e6utxo");

    CBlockchainDB chain_db;
    BOOST_REQUIRE(chain_db.Open(scope_chain.path(), true));
    CUTXOSet utxo_set;
    BOOST_REQUIRE(utxo_set.Open(scope_utxo.path(), true));

    constexpr int kN = 3;       // heights 0, 1, 2
    ChainFixture fix;
    fix.Build(kN, chain_db, utxo_set);

    constexpr int kContested = 1;
    CBlockIndex* prev_idx = g_chainstate.GetBlockIndex(fix.per_height_hash[0]);
    CBlockIndex* main_at_contested =
        g_chainstate.GetBlockIndex(fix.per_height_hash[kContested]);
    BOOST_REQUIRE(prev_idx != nullptr);
    BOOST_REQUIRE(main_at_contested != nullptr);

    // Inject a competing block at the contested height (not on main chain).
    auto cb_competitor = MakeCoinbase(static_cast<uint32_t>(kContested),
                                      99999ULL, 0xEE);
    CBlock blk_competitor = MakeBlock({cb_competitor});
    blk_competitor.hashPrevBlock = fix.per_height_hash[0];

    uint256 hash_competitor = MakeHash(0x71);
    BOOST_REQUIRE(chain_db.WriteBlock(hash_competitor, blk_competitor));

    auto pidx_competitor = std::make_unique<CBlockIndex>();
    pidx_competitor->nHeight = kContested;
    pidx_competitor->phashBlock = hash_competitor;
    pidx_competitor->pprev = prev_idx;
    pidx_competitor->pnext = nullptr;
    pidx_competitor->nStatus = CBlockIndex::BLOCK_VALID_HEADER |
                               CBlockIndex::BLOCK_HAVE_DATA;
    BOOST_REQUIRE(g_chainstate.AddBlockIndex(hash_competitor,
                                             std::move(pidx_competitor)));

    // Clear pnext on the original height-1 block so neither candidate
    // reports IsOnMainChain.
    main_at_contested->pnext = nullptr;

    g_chainstate.SetTipForTest(
        g_chainstate.GetBlockIndex(fix.per_height_hash[kN - 1]));

    CCoinStatsIndex idx;
    BOOST_REQUIRE(idx.Init(scope_idx.path(), &chain_db, &utxo_set));
    idx.StartBackgroundSync();

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    idx.Stop();

    // m_last_height was NOT advanced past the contested height.
    BOOST_CHECK_LT(idx.LastIndexedHeight(), kContested);

    // The walk bailed; m_synced stays false.
    BOOST_CHECK(!idx.IsSynced());

    g_chainstate.Cleanup();
}

BOOST_AUTO_TEST_SUITE_END()
