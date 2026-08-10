// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// MINER NONCE WRITE — HOT-LOOP COVERAGE
// =====================================
//
// The miner assembles the 80-byte legacy PoW preimage ONCE per template change
// (WriteMiningHeaderLE) and then rewrites ONLY the nonce field on EVERY nonce
// iteration. The WF-1 differential suite covered the first write and nothing
// covered the second: a mutation run changed the hot loop's nonce offset from
// 76 to 72 and the entire wf1 suite stayed green (11/11 cases, 77/77 checks),
// because wf1_host_endian_differential_test drives the helper and never enters
// miner/controller.cpp.
//
// That is a total-outage-class blind spot. A wrong hot-loop offset means the
// miner hashes a buffer that disagrees with the header it submits, so every
// block it finds is rejected by every peer — a mining outage that ships green.
//
// This suite closes it from both ends:
//
//   A. hot_loop_composition_matches_serialize_header
//      Replays the EXACT two-call composition the hot loop performs
//      (WriteMiningHeaderLE with the template placeholder, then
//      WriteMiningNonceLE with the live nonce) against the validator's
//      CBlockHeader::SerializeHeader(), byte for byte, over many nonces.
//      Both calls are the real production functions — not a mirror.
//
//   B. real_miner_submits_blocks_that_validate
//      Drives the REAL CMiningController: starts mining, lets the real
//      MiningWorker hot loop run, and re-validates each block the miner
//      actually submits by hashing the validator's SerializeHeader() bytes and
//      checking the PoW target. If the hot loop writes the nonce anywhere
//      other than where the validator reads it, the submitted block's
//      validator-side hash is uncorrelated with what the miner tested, so it
//      clears the target only with probability ~1/32 per block — requiring
//      SUBMITS_REQUIRED consecutive blocks makes that survival probability
//      ~2^-30.
//
// Cost note: case B pays for a LIGHT-mode RandomX cache (~256MB, ~1-2s) and a
// few hundred hashes. CMiningController::StartMining() additionally kicks off a
// background FULL-mode (2GB) dataset build on hosts with >=3GB RAM; that is
// production behaviour, not something this test asks for.

#include <boost/test/unit_test.hpp>

#include <miner/controller.h>
#include <primitives/block.h>
#include <consensus/pow.h>
#include <crypto/randomx_hash.h>

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// A template header with every field distinct and non-zero, so a
// mis-positioned write cannot hide behind a zero byte.
CBlockHeader MakeTemplateHeader()
{
    CBlockHeader h;
    h.nVersion = 1;                 // legacy (80-byte) header
    for (int i = 0; i < 32; ++i) {
        h.hashPrevBlock.data[i]   = static_cast<uint8_t>(0x10 + i);
        h.hashMerkleRoot.data[i]  = static_cast<uint8_t>(0xC0 - i);
    }
    h.nTime  = 0x5F3A1C27;
    h.nBits  = 0x1D00FFFF;
    // Deliberately adversarial placeholder: this is the value the hot loop is
    // supposed to OVERWRITE every iteration. If the hot-loop write lands at the
    // wrong offset, 0xA5A5A5A5 survives in the nonce field and the corrupted
    // byte range is easy to attribute.
    h.nNonce = 0xA5A5A5A5;
    return h;
}

std::string HexDump(const uint8_t* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    return s;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(miner_nonce_write_tests)

// ---------------------------------------------------------------------------
// A. The hot loop's two-call composition, byte-compared to the validator.
//
//    controller.cpp does, per template change:   WriteMiningHeaderLE(header, blk, blk.nNonce)
//    and then, per nonce iteration:              WriteMiningNonceLE(header, nonce32)
//
//    The resulting 80 bytes MUST equal SerializeHeader() of the same header
//    carrying that nonce. Any offset error in EITHER write shows up here.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(hot_loop_composition_matches_serialize_header)
{
    const CBlockHeader tmpl = MakeTemplateHeader();

    // Step 1: the template-change write, exactly as controller.cpp:436 does it
    // (passing the template's own placeholder nonce).
    uint8_t header[80];
    std::memset(header, 0xEE, sizeof(header));   // poison: nothing may be left unwritten
    WriteMiningHeaderLE(header, tmpl, tmpl.nNonce);

    // Sanity: the offset constant is where the validator's layout puts the nonce.
    // Non-fatal on purpose: if this drifts we still want the byte-for-byte
    // comparisons below to run and report exactly which bytes moved.
    BOOST_CHECK_EQUAL(MINING_HEADER_NONCE_OFFSET, 76u);

    const uint32_t kNonces[] = {
        0x00000000u, 0x00000001u, 0x0000007Fu, 0x000000FFu,
        0x00001D00u,                 // collides with the nBits value's low half
        0x1D00FFFFu,                 // equals nBits — a swap here must still fail
        0xA5A5A5A5u,                 // equals the placeholder
        0x5F3A1C27u,                 // equals nTime
        0x7FFFFFFFu, 0x80000000u, 0xDEADBEEFu, 0xFFFFFFFFu,
    };

    uint8_t previous[80];
    std::memcpy(previous, header, 80);

    for (uint32_t nonce : kNonces) {
        // Step 2: the per-iteration hot-loop write, exactly as controller.cpp:449.
        WriteMiningNonceLE(header, nonce);

        // The validator's view of the same header at the same nonce.
        CBlockHeader expected = tmpl;
        expected.nNonce = nonce;
        const std::vector<uint8_t> want = expected.SerializeHeader();
        BOOST_REQUIRE_EQUAL(want.size(), 80u);

        BOOST_CHECK_MESSAGE(std::memcmp(header, want.data(), 80) == 0,
            "miner hot-loop buffer != CBlockHeader::SerializeHeader() at nonce 0x"
            + HexDump(reinterpret_cast<const uint8_t*>(&nonce), 4) + "\n"
            "  miner:     " + HexDump(header, 80) + "\n"
            "  validator: " + HexDump(want.data(), 80));

        // The hot-loop write must touch the nonce field and NOTHING else:
        // bytes 0..75 are identical to the previous iteration's buffer.
        BOOST_CHECK_MESSAGE(std::memcmp(header, previous, MINING_HEADER_NONCE_OFFSET) == 0,
            "the per-iteration nonce write modified bytes outside the nonce field");
        std::memcpy(previous, header, 80);
    }
}

// ---------------------------------------------------------------------------
// B. The REAL miner. Start CMiningController, let MiningWorker's hot loop run,
//    and re-validate every block it submits through the validator's path.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(real_miner_submits_blocks_that_validate)
{
    // LIGHT-mode RandomX. The miner's per-thread VM and randomx_hash_for_validation
    // below both draw on THIS cache, so miner and validator are hashing with the
    // same key by construction.
    const char* kKey = "Dilithion-RandomX-v1";
    randomx_init_validation_mode(kKey, std::strlen(kKey));

    // Target: top byte < 0x08 (HashLessThan compares data[31] first), i.e. about
    // 1 in 32 hashes wins. Not all-0x00 and not all-0xFF, both of which
    // StartMining() rejects.
    uint256 target;
    std::memset(target.data, 0xFF, 32);
    target.data[31] = 0x07;

    CBlock tmplBlock;
    static_cast<CBlockHeader&>(tmplBlock) = MakeTemplateHeader();
    // nTime must not be the frozen constant used in case A only; any value works,
    // but use a live one so this is not accidentally a fixed-preimage test.
    tmplBlock.nTime = static_cast<uint32_t>(std::time(nullptr));
    CBlockTemplate blockTemplate(tmplBlock, target, /*height=*/1);

    // Number of independently-found blocks that must all validate. Each one a
    // wrong-offset miner clears only with probability ~1/32.
    const size_t SUBMITS_REQUIRED = 6;

    std::mutex mu;
    std::vector<CBlock> found;

    CMiningController miner(2);
    miner.SetBlockFoundCallback([&](const CBlock& blk) {
        std::lock_guard<std::mutex> lock(mu);
        found.push_back(blk);
    });

    BOOST_REQUIRE(miner.StartMining(blockTemplate));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(180);
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(mu);
            if (found.size() >= SUBMITS_REQUIRED) break;
        }
        if (std::chrono::steady_clock::now() > deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    miner.StopMining();

    std::vector<CBlock> blocks;
    {
        std::lock_guard<std::mutex> lock(mu);
        blocks = found;
    }

    // A miner that produced nothing at a 1-in-32 target within 3 minutes means a
    // broken environment (no RandomX cache, no worker threads) — the test cannot
    // conclude anything and must say so rather than pass vacuously.
    BOOST_REQUIRE_MESSAGE(blocks.size() >= SUBMITS_REQUIRED,
        "real miner submitted only " + std::to_string(blocks.size()) + " block(s) of "
        + std::to_string(SUBMITS_REQUIRED) + " before the deadline — cannot conclude. "
        "Hashes computed: " + std::to_string(miner.GetStats().nHashesComputed));

    // The hot loop must actually have iterated (many hashes for a few blocks),
    // otherwise "the loop was entered" is not established.
    BOOST_CHECK_GT(miner.GetStats().nHashesComputed, SUBMITS_REQUIRED);

    for (size_t i = 0; i < SUBMITS_REQUIRED; ++i) {
        const CBlock& blk = blocks[i];

        // The submitted nonce must be a value the hot loop wrote, not the
        // template placeholder left over from WriteMiningHeaderLE.
        BOOST_CHECK_MESSAGE(blk.nNonce != 0xA5A5A5A5u,
            "submitted block still carries the template's placeholder nonce");

        // Validator path: serialize the submitted header and hash it.
        const std::vector<uint8_t> hdr = blk.SerializeHeader();
        BOOST_REQUIRE_EQUAL(hdr.size(), 80u);

        uint256 hash;
        randomx_hash_for_validation(hdr.data(), hdr.size(), hash.begin());

        BOOST_CHECK_MESSAGE(HashLessThan(hash, target),
            "block #" + std::to_string(i) + " submitted by the REAL miner FAILS PoW when "
            "re-hashed from CBlockHeader::SerializeHeader() — the miner hashed a buffer "
            "that disagrees with the header it submitted (wrong nonce offset in the hot "
            "loop). nonce=0x" + HexDump(reinterpret_cast<const uint8_t*>(&blk.nNonce), 4)
            + " header=" + HexDump(hdr.data(), hdr.size())
            + " hash=" + hash.GetHex());
    }

    // MANDATORY, not politeness. CMiningController::StartMining() fires
    // randomx_init_mining_mode_async() on any host with >=3GB RAM, and NOTHING
    // in the codebase ever joins the global std::thread it parks in
    // randomx_hash.cpp. A joinable std::thread destroyed at static-destruction
    // time calls std::terminate(), so without this join the whole test binary
    // aborts after reporting success. (Same latent defect applies to
    // dilithion-node --mine at shutdown; out of scope here, reported instead.)
    randomx_wait_for_mining_mode();
}

BOOST_AUTO_TEST_SUITE_END()
