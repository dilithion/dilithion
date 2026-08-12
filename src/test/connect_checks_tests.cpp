// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Connect-path block validator KATs (C-R3 remediation).
 *
 * Directly exercises ConnectBlockChecks() — the unified read-only gate that
 * CChainState::ConnectTip runs immediately before CUTXOSet::ApplyBlock. These
 * are Tier-A "seam" KATs: they hit the validator as a pure function of
 * (block, utxoSet, height, fVerifyScripts), which is the cleanest way to prove
 * each check is enforced and load-bearing without constructing a full
 * PoW/MIK/VDF/attestation block to reach ConnectTip.
 *
 * Every rejection KAT is paired with a positive control (a well-formed block
 * that is ACCEPTED) so a rejection is attributable to the specific check under
 * test, not to an incidental structural failure (anti-vacuity).
 *
 * The garbage-signature helper CreateTestTransaction attaches a constant 0xAA
 * blob that is not a valid ML-DSA signature; the valid-signature helpers
 * (MakeKey / SignInputLegacy) produce a real Dilithium3 signature over the exact
 * 44-byte preimage the interpreter verifies, so the accepted controls are real.
 */

#include <boost/test/unit_test.hpp>

#include <node/utxo_set.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <consensus/validation.h>
#include <consensus/connect_checks.h>
#include <consensus/sighash_preimage.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>
#include <amount.h>
#include <uint256.h>

extern "C" {
    #include <api.h>   // pqcrystals_dilithium3_ref_{keypair,signature} + size constants
}

#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <filesystem>

BOOST_AUTO_TEST_SUITE(connect_checks_tests)

// ============================================================================
// Fixture: install a deterministic ChainParams so subsidy / coinbaseMaturity /
// chainID are stable, and restore the previous pointer on teardown.
// ============================================================================
namespace {

struct ChainParamsFixture {
    Dilithion::ChainParams* saved{nullptr};
    Dilithion::ChainParams* owned{nullptr};
    ChainParamsFixture() {
        saved = Dilithion::g_chainParams;
        owned = new Dilithion::ChainParams(Dilithion::ChainParams::Mainnet());
        Dilithion::g_chainParams = owned;
    }
    ~ChainParamsFixture() {
        Dilithion::g_chainParams = saved;
        delete owned;
    }
};

// ---- UTXO test-set lifecycle -------------------------------------------------
std::string OpenTempUTXO(CUTXOSet& utxo) {
    static unsigned long long counter = 0;
    std::string p = std::filesystem::temp_directory_path().string() +
                    "/cc_test_" + std::to_string((unsigned long long)time(nullptr)) +
                    "_" + std::to_string(counter++);
    std::filesystem::create_directories(p);
    BOOST_REQUIRE(utxo.Open(p, true));
    BOOST_REQUIRE(utxo.IsOpen());
    return p;
}
void CleanupUTXO(const std::string& p) {
    try { std::filesystem::remove_all(p); } catch (...) {}
}

uint256 MakeHash(uint8_t seed) {
    uint256 h; memset(h.data, seed, 32); return h;
}

// ---- compact-size + block builder (mirror of utxo_tests helpers) -------------
void WriteCompactSize(std::vector<uint8_t>& d, uint64_t s) {
    if (s < 253) { d.push_back((uint8_t)s); }
    else if (s <= 0xFFFF) { d.push_back(253); d.push_back(s & 0xFF); d.push_back((s >> 8) & 0xFF); }
    else if (s <= 0xFFFFFFFF) {
        d.push_back(254);
        for (int i = 0; i < 4; i++) d.push_back((s >> (i * 8)) & 0xFF);
    } else {
        d.push_back(255);
        for (int i = 0; i < 8; i++) d.push_back((s >> (i * 8)) & 0xFF);
    }
}

CBlock MakeBlock(const std::vector<CTransactionRef>& txs) {
    CBlock block;
    block.nVersion = 1;
    block.nTime = (uint32_t)time(nullptr);
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;

    std::vector<uint8_t> vtx;
    WriteCompactSize(vtx, txs.size());
    for (const auto& tx : txs) {
        std::vector<uint8_t> td = tx->Serialize();
        vtx.insert(vtx.end(), td.begin(), td.end());
    }
    block.vtx = vtx;

    CBlockValidator v;
    block.hashMerkleRoot = v.BuildMerkleRoot(txs);
    return block;
}

// ---- P2PKH scriptPubKey with a chosen 20-byte hash ---------------------------
std::vector<uint8_t> P2PKH(const uint8_t hash20[20]) {
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), hash20, hash20 + 20);
    spk.push_back(0x88);
    spk.push_back(0xac);
    return spk;
}

// A Dilithium3 keypair plus the P2PKH scriptPubKey that commits to it.
struct Key {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    std::vector<uint8_t> spk;   // committed P2PKH scriptPubKey
};

Key MakeKey() {
    Key k;
    k.pk.resize(pqcrystals_dilithium3_ref_PUBLICKEYBYTES);
    k.sk.resize(pqcrystals_dilithium3_ref_SECRETKEYBYTES);
    BOOST_REQUIRE_EQUAL(pqcrystals_dilithium3_ref_keypair(k.pk.data(), k.sk.data()), 0);
    uint8_t h1[32], h2[32];
    SHA3_256(k.pk.data(), k.pk.size(), h1);
    SHA3_256(h1, 32, h2);          // double SHA3-256; first 20 bytes are the pubkey hash
    k.spk = P2PKH(h2);
    return k;
}

// Build a real legacy-format scriptSig (LE16(3309)|sig|LE16(1952)|pk) signing the
// exact preimage the interpreter checks for input `idx` of `tx`.
std::vector<uint8_t> SignInputLegacy(const CTransaction& tx, size_t idx, const Key& k) {
    uint32_t chain_id = Dilithion::g_chainParams ? Dilithion::g_chainParams->chainID : 1;
    uint256 txhash = tx.GetSigningHash();
    uint8_t msg[32];
    Consensus::ComputeSighash(txhash, (uint32_t)idx, (uint32_t)tx.nVersion, chain_id, msg);

    std::vector<uint8_t> sig(pqcrystals_dilithium3_ref_BYTES);
    size_t siglen = 0;
    BOOST_REQUIRE_EQUAL(
        pqcrystals_dilithium3_ref_signature(sig.data(), &siglen, msg, 32, nullptr, 0, k.sk.data()), 0);
    BOOST_REQUIRE_EQUAL(siglen, (size_t)pqcrystals_dilithium3_ref_BYTES);

    std::vector<uint8_t> ss;
    ss.push_back((uint8_t)(siglen & 0xFF));
    ss.push_back((uint8_t)((siglen >> 8) & 0xFF));
    ss.insert(ss.end(), sig.begin(), sig.end());
    uint16_t pklen = (uint16_t)k.pk.size();
    ss.push_back((uint8_t)(pklen & 0xFF));
    ss.push_back((uint8_t)((pklen >> 8) & 0xFF));
    ss.insert(ss.end(), k.pk.begin(), k.pk.end());
    return ss;
}

// Coinbase paying `value` (single output). scriptSig carries `data` for uniqueness.
CTransactionRef Coinbase(uint64_t value, uint32_t data) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    std::vector<uint8_t> ss = {0x04,
        (uint8_t)(data & 0xFF), (uint8_t)((data >> 8) & 0xFF),
        (uint8_t)((data >> 16) & 0xFF), (uint8_t)((data >> 24) & 0xFF)};
    tx.vin.push_back(CTxIn(COutPoint(), ss));
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), 20, 0x01);
    spk.push_back(0x88); spk.push_back(0xac);
    tx.vout.push_back(CTxOut(value, spk));
    return MakeTransactionRef(tx);
}

// Non-coinbase spend of `prevout` -> single output `outVal`, signed by `signer`
// if provided (else a garbage 0xAA scriptSig).
CTransactionRef Spend(const COutPoint& prevout, uint64_t outVal,
                      const std::vector<uint8_t>& outSpk,
                      const Key* signer) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(prevout, std::vector<uint8_t>(100, 0xAA), CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(outVal, outSpk));
    if (signer) {
        tx.vin[0].scriptSig = SignInputLegacy(tx, 0, *signer);
    }
    return MakeTransactionRef(tx);
}

std::vector<uint8_t> DummyP2PKH(uint8_t fill) {
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), 20, fill);
    spk.push_back(0x88); spk.push_back(0xac);
    return spk;
}

uint64_t Subsidy(uint32_t h) { return CBlockValidator::CalculateBlockSubsidy(h); }

} // namespace

// ============================================================================
// CHECK 2 — spend signatures
// ============================================================================

// A1: value-valid garbage-signature spend is REJECTED when fVerifyScripts=true
// (the exact case utxo_tests/utxo_reorg_handling asserts ApplyBlock ACCEPTS).
BOOST_FIXTURE_TEST_CASE(cc_A1_garbage_signature_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0x80), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, DummyP2PKH(0xAA)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr)  // garbage sig, value-valid
    };
    CBlock block = MakeBlock(txs);

    std::string err;
    BOOST_CHECK(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err));
    BOOST_CHECK_MESSAGE(err.find("signature") != std::string::npos ||
                        err.find("script") != std::string::npos,
                        "expected signature rejection, got: " << err);

    // With signature verification gated off (below script-assumevalid), the same
    // value-valid block is ACCEPTED — proves ONLY the signature gate rejected A1.
    std::string err2;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/false, err2),
                        "value-valid block should pass with scripts off: " << err2);

    utxo.Close(); CleanupUTXO(path);
}

// A4: positive control — a real ML-DSA signature over a committed coin is ACCEPTED.
BOOST_FIXTURE_TEST_CASE(cc_A4_valid_signature_accepted, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k = MakeKey();
    COutPoint prev(MakeHash(0x81), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k.spk), 1, false));  // committed to k
    BOOST_REQUIRE(utxo.Flush());

    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), &k)   // valid signature by k
    };
    CBlock block = MakeBlock(txs);

    std::string err;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err),
                        "valid-signature block should be accepted: " << err);

    utxo.Close(); CleanupUTXO(path);
}

// Signature must be bound to the COIN's committed key: a valid signature by the
// WRONG key (correct format, wrong pubkey<->hash binding) is REJECTED.
BOOST_FIXTURE_TEST_CASE(cc_signature_wrong_key_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key owner = MakeKey();
    Key attacker = MakeKey();
    COutPoint prev(MakeHash(0x82), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, owner.spk), 1, false)); // committed to owner
    BOOST_REQUIRE(utxo.Flush());

    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), &attacker)  // signed by the wrong key
    };
    CBlock block = MakeBlock(txs);

    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, true, err),
                        "spend signed by non-owner must be rejected");

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// CHECK 3 — value conservation (coinbase + non-coinbase)
// ============================================================================

// A2: over-subsidy coinbase is REJECTED (scripts off, so only the value check can fire).
BOOST_FIXTURE_TEST_CASE(cc_A2_over_subsidy_coinbase_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 5;

    std::vector<CTransactionRef> over = { Coinbase(Subsidy(H) + 1, H) };   // +1 over subsidy, no fees
    CBlock overBlock = MakeBlock(over);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(overBlock, utxo, H, false, err),
                        "over-subsidy coinbase must be rejected");
    BOOST_CHECK(err.find("subsidy") != std::string::npos);

    // Positive control: coinbase == subsidy is ACCEPTED.
    std::vector<CTransactionRef> ok = { Coinbase(Subsidy(H), H) };
    CBlock okBlock = MakeBlock(ok);
    std::string err2;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(okBlock, utxo, H, false, err2),
                        "coinbase == subsidy should be accepted: " << err2);

    utxo.Close(); CleanupUTXO(path);
}

// A3: non-coinbase mint (Sigma(out) > Sigma(in)) is REJECTED (scripts off).
BOOST_FIXTURE_TEST_CASE(cc_A3_noncoinbase_mint_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0x83), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(50 * COIN, DummyP2PKH(0xAA)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // out (60) > in (50): value creation.
    std::vector<CTransactionRef> mint = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 60 * COIN, DummyP2PKH(0x02), nullptr)
    };
    CBlock mintBlock = MakeBlock(mint);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(mintBlock, utxo, H, false, err),
                        "non-coinbase mint must be rejected");
    BOOST_CHECK(err.find("less than outputs") != std::string::npos ||
                err.find("mint") != std::string::npos);

    // Positive control: out (40) < in (50) is ACCEPTED (fee = 10).
    std::vector<CTransactionRef> ok = {
        Coinbase(Subsidy(H) + 10 * COIN, H),   // may also claim the fee
        Spend(prev, 40 * COIN, DummyP2PKH(0x02), nullptr)
    };
    CBlock okBlock = MakeBlock(ok);
    std::string err2;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(okBlock, utxo, H, false, err2),
                        "value-valid spend should be accepted: " << err2);

    utxo.Close(); CleanupUTXO(path);
}

// Coinbase may legitimately claim the fees of in-block spends.
BOOST_FIXTURE_TEST_CASE(cc_coinbase_claims_fees_accepted, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0x84), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(50 * COIN, DummyP2PKH(0xAA)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // fee = 50 - 41 = 9; coinbase = subsidy + 9 is exactly the ceiling -> ACCEPT.
    std::vector<CTransactionRef> ok = {
        Coinbase(Subsidy(H) + 9 * COIN, H),
        Spend(prev, 41 * COIN, DummyP2PKH(0x02), nullptr)
    };
    CBlock okBlock = MakeBlock(ok);
    std::string err;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(okBlock, utxo, H, false, err),
                        "coinbase claiming exact fees should be accepted: " << err);

    // One ion over the fee ceiling -> REJECT.
    std::vector<CTransactionRef> over = {
        Coinbase(Subsidy(H) + 9 * COIN + 1, H),
        Spend(prev, 41 * COIN, DummyP2PKH(0x02), nullptr)
    };
    CBlock overBlock = MakeBlock(over);
    std::string err2;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(overBlock, utxo, H, false, err2),
                        "coinbase claiming more than subsidy+fees must be rejected");

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// CHECK 1 — merkle root commitment
// ============================================================================
BOOST_FIXTURE_TEST_CASE(cc_merkle_mismatch_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H), H) };
    CBlock good = MakeBlock(txs);

    // Sanity: correct merkle passes.
    std::string err0;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(good, utxo, H, false, err0),
                        "correct-merkle coinbase-only block should pass: " << err0);

    // Tamper the header commitment -> vtx no longer matches header -> REJECT.
    CBlock bad = good;
    bad.hashMerkleRoot = MakeHash(0xEE);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(bad, utxo, H, false, err),
                        "merkle mismatch must be rejected");
    BOOST_CHECK(err.find("merkle") != std::string::npos);

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// CHECK 4 — in-block double-spend
// ============================================================================
BOOST_FIXTURE_TEST_CASE(cc_in_block_double_spend_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0x85), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, DummyP2PKH(0xAA)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // Two non-coinbase txs spend the SAME confirmed outpoint within one block.
    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr),
        Spend(prev, 80 * COIN, DummyP2PKH(0x03), nullptr)
    };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, false, err),
                        "in-block double-spend must be rejected");
    BOOST_CHECK(err.find("double-spend") != std::string::npos);

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// CHECK 5 — coinbase maturity
// ============================================================================
BOOST_FIXTURE_TEST_CASE(cc_immature_coinbase_spend_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);

    // Confirmed COINBASE output created at height 1.
    COutPoint cb(MakeHash(0x86), 0);
    BOOST_REQUIRE(utxo.AddUTXO(cb, CTxOut(50 * COIN, DummyP2PKH(0xAA)), 1, /*coinbase=*/true));
    BOOST_REQUIRE(utxo.Flush());

    const unsigned int maturity = (unsigned int)Dilithion::g_chainParams->coinbaseMaturity;

    // Spend at height 5 (< maturity) -> REJECT.
    {
        const uint32_t H = 5;
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(cb, 40 * COIN, DummyP2PKH(0x02), nullptr)
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, false, err),
                            "immature coinbase spend must be rejected");
        BOOST_CHECK(err.find("immature") != std::string::npos);
    }

    // Spend well past maturity -> ACCEPT.
    {
        const uint32_t H = 1 + maturity + 10;
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(cb, 40 * COIN, DummyP2PKH(0x02), nullptr)
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, false, err),
                            "mature coinbase spend should be accepted: " << err);
    }

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// A5 — in-block chaining overlay (the top consensus-split risk)
// ============================================================================
// A child tx that spends a parent EARLIER IN THE SAME BLOCK must resolve against
// the per-block overlay and be ACCEPTED (valid sigs). If the overlay were absent
// the child would falsely reject with "input not found" — a chain split.
BOOST_FIXTURE_TEST_CASE(cc_A5_in_block_chain_accepted, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k1 = MakeKey();  // owns the confirmed coin
    Key k2 = MakeKey();  // owns the in-block parent's output

    COutPoint prev(MakeHash(0x87), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k1.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // Parent txA: spends confirmed coin (signed by k1) -> output committed to k2.
    CTransactionRef txA = Spend(prev, 99 * COIN, k2.spk, &k1);
    COutPoint aOut(txA->GetHash(), 0);
    // Child txB: spends txA:0 (signed by k2) -> output.
    CTransactionRef txB = Spend(aOut, 98 * COIN, DummyP2PKH(0x05), &k2);

    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H) + 2 * COIN, H), txA, txB };
    CBlock block = MakeBlock(txs);

    std::string err;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err),
                        "valid in-block-chained spend must be accepted (overlay): " << err);

    // Flip the child's signature to garbage -> the overlay-resolved input still
    // runs through the signature gate and REJECTS.
    CTransactionRef txBbad = Spend(aOut, 98 * COIN, DummyP2PKH(0x05), nullptr);
    std::vector<CTransactionRef> txs2 = { Coinbase(Subsidy(H) + 2 * COIN, H), txA, txBbad };
    CBlock block2 = MakeBlock(txs2);
    std::string err2;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block2, utxo, H, true, err2),
                        "garbage-sig child of in-block parent must be rejected");

    utxo.Close(); CleanupUTXO(path);
}

// Spending a non-existent outpoint is a HARD reject (input existence).
BOOST_FIXTURE_TEST_CASE(cc_missing_input_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint ghost(MakeHash(0x88), 0);  // never added
    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(ghost, 10 * COIN, DummyP2PKH(0x02), nullptr)
    };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, false, err),
                        "spend of non-existent output must be rejected");
    BOOST_CHECK(err.find("not found") != std::string::npos);

    utxo.Close(); CleanupUTXO(path);
}

BOOST_AUTO_TEST_SUITE_END()
