// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// REORG-DEPTH FINALITY CAP KATs (REORG_DEPTH_FINALITY_DESIGN, ecosystem #6).
//
// Consensus::MAX_REORG_DEPTH (=60) is meant to be a HARD finality bound, but it
// was historically enforced ONLY on the in-band ActivateBestChain path. The
// automatic IBD/fork-recovery callers reach CChainState::DisconnectToHeight()
// directly, and that chokepoint enforced only a checkpoint floor — no depth cap.
// A peer feeding forged low-difficulty headers (on VDF the header work is
// forgeable at ~zero cost) could thereby roll a synced node back to its last
// checkpoint, or all the way to genesis on a young/relaunch chain with only a
// genesis checkpoint. The fix adds a depth-cap guard inside DisconnectToHeight,
// gated by a new `bool allowDeep` (default false = enforce cap); operator RPC
// callers pass allowDeep=true.
//
// These KATs exercise the REAL CChainState::DisconnectToHeight() end-to-end.
//
// Anti-vacuity (the green-by-absence trap this design explicitly warns about):
// the fixture is built on CHECKPOINT-FREE params (regtest with checkpoints
// cleared), so the pre-existing checkpoint floor can NEVER be the cause of a
// rejection — the ONLY thing that can reject is the new depth cap. The chain is
// built to height 200 with real (minimal) block data in a temp DB so the
// disconnect loop actually runs via pointer manipulation (no UTXO/mempool/
// identity set => those undos are skipped), which makes the H-60 POSITIVE
// control disconnect for real — not a no-op — so it is a genuine discriminator.
//
// Mutation control (verify-the-verifier), covered collectively by cases below:
//   * flip the guard `depth > MAX_REORG_DEPTH` to `>=`  => the H-60 at-cap
//     positive control (disconnect_allows_at_cap_automatic) starts REJECTING
//     (returns -1) and REDDENS.
//   * delete the guard entirely                         => the H-61 rejection
//     (disconnect_refuses_above_cap_automatic) starts DISCONNECTING (returns 61,
//     tip moves to 139) and REDDENS.
//   * make allowDeep enforce the cap anyway (ignore the flag) => the operator
//     carve-out (disconnect_operator_carveout_allows_above_cap) REDDENS.

#include <boost/test/unit_test.hpp>

#include <consensus/chain.h>
#include <consensus/params.h>        // Consensus::MAX_REORG_DEPTH
#include <core/chainparams.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <primitives/block.h>
#include <uint256.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>

namespace {

// Per-test temp directory for the CBlockchainDB (RAII cleanup).
struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string& tag) {
        const auto base = std::filesystem::temp_directory_path() / "reorg_depth_cap";
        std::filesystem::create_directories(base);
        const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        path = base / (tag + "_" + std::to_string(stamp));
        std::filesystem::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);  // best-effort
    }
    std::string str() const { return path.string(); }
};

// Distinct, non-null block hash per height (height 0 is not the all-zero
// genesis-null sentinel).
uint256 HashForHeight(int h) {
    uint256 x;
    std::memset(x.data, 0, 32);
    x.data[0] = static_cast<uint8_t>(h & 0xFF);
    x.data[1] = static_cast<uint8_t>((h >> 8) & 0xFF);
    x.data[2] = 0xC0;  // keep every hash non-null and distinct from genesis-null
    return x;
}

// Build a validated active-chain index of heights 0..N on `cs`, writing a
// minimal block under each hash in `db`. With cs.pUTXOSet / pMemPool null and
// DFMP::g_identityDb irrelevant (empty vtx => the identity-undo body is skipped),
// DisconnectTip succeeds by pure pointer manipulation + db.ReadBlock — so the
// disconnect loop genuinely runs without a full UTXO/block harness.
bool BuildChain(CChainState& cs, CBlockchainDB& db, int N) {
    CBlockIndex* parent = nullptr;
    for (int h = 0; h <= N; ++h) {
        const uint256 hh = HashForHeight(h);

        // Minimal block written under this hash so DisconnectTip's ReadBlock
        // yields block_loaded=true. Empty vtx => no tx-dependent undo runs.
        CBlock blk;
        blk.nVersion = CBlockHeader::VDF_VERSION;
        blk.hashPrevBlock = parent ? parent->GetBlockHash() : uint256();
        blk.nTime = 1700000000u + static_cast<uint32_t>(h);
        blk.nBits = 0x1d00ffff;
        if (!db.WriteBlock(hh, blk)) return false;

        auto idx = std::make_unique<CBlockIndex>();
        idx->pprev = parent;
        idx->nHeight = h;
        idx->nStatus = CBlockIndex::BLOCK_VALID_CHAIN | CBlockIndex::BLOCK_HAVE_DATA;
        idx->phashBlock = hh;
        std::memset(idx->nChainWork.data, 0, 32);
        idx->nChainWork.data[0] = static_cast<uint8_t>(h & 0xFF);
        idx->nChainWork.data[1] = static_cast<uint8_t>((h >> 8) & 0xFF);

        if (!cs.AddBlockIndex(hh, std::move(idx))) return false;
        parent = cs.GetBlockIndex(hh);
        if (parent == nullptr) return false;
    }
    cs.SetTip(parent);
    return true;
}

// Fixture: checkpoint-free params installed as g_chainParams (so ONLY the depth
// cap — never the checkpoint floor — can cause a rejection), auto-restored.
struct CapParamsFixture {
    Dilithion::ChainParams params;
    Dilithion::ChainParams* saved{nullptr};
    CapParamsFixture() : params(Dilithion::ChainParams::Regtest()) {
        params.checkpoints.clear();  // checkpoint-free: excludes the floor as a cause
        saved = Dilithion::g_chainParams;
        Dilithion::g_chainParams = &params;
    }
    ~CapParamsFixture() {
        Dilithion::g_chainParams = saved;
    }
};

constexpr int kTip = 200;

}  // namespace

BOOST_AUTO_TEST_SUITE(reorg_depth_cap_tests)

// H-61 automatic (allowDeep=false) => REFUSED at the cap; tip untouched. On
// checkpoint-free params this rejection can ONLY be the new depth cap.
// Mutation: deleting the guard makes this disconnect 61 blocks => reddens.
BOOST_FIXTURE_TEST_CASE(disconnect_refuses_above_cap_automatic, CapParamsFixture) {
    TempDir td("refuse");
    CBlockchainDB db;
    BOOST_REQUIRE(db.Open(td.str()));

    CChainState cs;
    cs.SetDatabase(&db);
    BOOST_REQUIRE(BuildChain(cs, db, kTip));
    BOOST_REQUIRE_EQUAL(cs.GetHeight(), kTip);

    const int target = kTip - (Consensus::MAX_REORG_DEPTH + 1);  // depth 61
    const int rc = cs.DisconnectToHeight(target, db, /*batchSize=*/0, /*allowDeep=*/false);

    BOOST_CHECK_MESSAGE(rc == -1,
        "an automatic disconnect of " << (Consensus::MAX_REORG_DEPTH + 1)
        << " blocks (> MAX_REORG_DEPTH) must be REFUSED; got rc=" << rc);
    BOOST_CHECK_MESSAGE(cs.GetHeight() == kTip,
        "a refused deep disconnect must leave the tip untouched; height="
        << cs.GetHeight());
}

// H-60 automatic (allowDeep=false) => ALLOWED (depth == cap); disconnects for
// real. Pins `>` not `>=` and proves the guard is not "reject everything".
// Mutation: flipping `>` to `>=` makes this REFUSE => reddens.
BOOST_FIXTURE_TEST_CASE(disconnect_allows_at_cap_automatic, CapParamsFixture) {
    TempDir td("atcap");
    CBlockchainDB db;
    BOOST_REQUIRE(db.Open(td.str()));

    CChainState cs;
    cs.SetDatabase(&db);
    BOOST_REQUIRE(BuildChain(cs, db, kTip));
    BOOST_REQUIRE_EQUAL(cs.GetHeight(), kTip);

    const int target = kTip - Consensus::MAX_REORG_DEPTH;  // depth 60 == cap
    const int rc = cs.DisconnectToHeight(target, db, /*batchSize=*/0, /*allowDeep=*/false);

    BOOST_CHECK_MESSAGE(rc == Consensus::MAX_REORG_DEPTH,
        "a disconnect of exactly MAX_REORG_DEPTH blocks must SUCCEED; got rc=" << rc);
    BOOST_CHECK_MESSAGE(cs.GetHeight() == target,
        "at-cap disconnect must move the tip to the target; height="
        << cs.GetHeight() << " target=" << target);
}

// H-61 with allowDeep=true (operator carve-out) => ALLOWED past the cap;
// disconnects 61 blocks. Still checkpoint-floor bounded (none here).
// Mutation: making allowDeep ignore-and-enforce reddens this.
BOOST_FIXTURE_TEST_CASE(disconnect_operator_carveout_allows_above_cap, CapParamsFixture) {
    TempDir td("carveout");
    CBlockchainDB db;
    BOOST_REQUIRE(db.Open(td.str()));

    CChainState cs;
    cs.SetDatabase(&db);
    BOOST_REQUIRE(BuildChain(cs, db, kTip));
    BOOST_REQUIRE_EQUAL(cs.GetHeight(), kTip);

    const int depth61 = Consensus::MAX_REORG_DEPTH + 1;
    const int target = kTip - depth61;  // depth 61
    const int rc = cs.DisconnectToHeight(target, db, /*batchSize=*/0, /*allowDeep=*/true);

    BOOST_CHECK_MESSAGE(rc == depth61,
        "the operator carve-out (allowDeep=true) must disconnect past the cap; got rc="
        << rc);
    BOOST_CHECK_MESSAGE(cs.GetHeight() == target,
        "operator deep disconnect must move the tip to the target; height="
        << cs.GetHeight() << " target=" << target);
}

BOOST_AUTO_TEST_SUITE_END()
