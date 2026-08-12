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
#include <consensus/tx_validation.h>   // TxValidation::MAX_MONEY (MoneyRange edge KATs)
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

// Non-coinbase spend of `prevout` with MULTIPLE outputs, signed by `signer`
// (input 0). Mirrors Spend() but lets a parent create several outputs so the
// per-output overlay can be exercised by distinct children.
CTransactionRef SpendTo(const COutPoint& prevout,
                        const std::vector<CTxOut>& outs,
                        const Key* signer) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(prevout, std::vector<uint8_t>(100, 0xAA), CTxIn::SEQUENCE_FINAL));
    for (const auto& o : outs) tx.vout.push_back(o);
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

// ============================================================================
// HIGH-1 — assume-valid signature-skip gate (ConnectPathMaySkipScriptVerify)
// ============================================================================
// The connect path may skip the ML-DSA signature step ONLY for a historical
// block (at/below a POSITIVE assume-valid height) while the node is in initial
// block download. A block at the tip, a height above the assume-valid height,
// or a chain with scriptAssumeValidHeight<=0 must ALWAYS verify. This unit test
// pins each of the three AND-clauses (dropping any one reddens a specific case).
BOOST_AUTO_TEST_CASE(cc_high1_script_assumevalid_predicate) {
    // Relaunch/reset chain: scriptAssumeValidHeight<=0 => NEVER skip, ANY height,
    // in or out of IBD. (Verifies every block from height 1 — no dormant window.)
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(1,     0, /*IBD=*/true));
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(1,     0, /*IBD=*/false));
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(50000, 0, /*IBD=*/true));
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(1,    -1, /*IBD=*/true));
    // Pins the `scriptAssumeValidHeight > 0` clause: genesis height 0 with a
    // 0 assume-valid height must NOT skip (drop the clause => 0<=0 && IBD => true).
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(0,     0, /*IBD=*/true));

    // Configured assume-valid height (mainnet dfmpAssumeValidHeight=44233), block
    // at/below it: skip ONLY during IBD.
    BOOST_CHECK( ConnectPathMaySkipScriptVerify(100,   44233, /*IBD=*/true));
    BOOST_CHECK( ConnectPathMaySkipScriptVerify(44233, 44233, /*IBD=*/true));   // boundary
    // Pins the IBD clause (the HIGH-1 core): the SAME historical height AT THE TIP
    // (not IBD) must verify — closes the self-mined low-height tip-block vector.
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(100,   44233, /*IBD=*/false));
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(44233, 44233, /*IBD=*/false));
    // Pins the `nHeight <= assumeValidHeight` clause: above the height => verify.
    BOOST_CHECK(!ConnectPathMaySkipScriptVerify(44234, 44233, /*IBD=*/true));
}

// HIGH-1 end-to-end: derive fVerifyScripts exactly as ConnectTip does and confirm
// a value-valid GARBAGE-signature spend (the theft primitive) is REJECTED at the
// tip and on a relaunch chain, and legitimately skipped only for a historical IBD
// block (proving the skip is real, not vacuous).
BOOST_FIXTURE_TEST_CASE(cc_high1_tip_and_relaunch_verify_signatures, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);

    Key owner = MakeKey();
    COutPoint prev(MakeHash(0x90), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, owner.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    auto garbageSigBlockAt = [&](uint32_t H) {
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr)   // garbage 0xAA sig
        };
        return MakeBlock(txs);
    };

    const int relaunchAVH = 0;       // reset chain: assume-valid disabled
    const int mainnetAVH  = 44233;   // shipped mainnet dfmpAssumeValidHeight

    // (a) Relaunch chain, block 1, DURING IBD: assume-valid disabled => VERIFY =>
    //     the garbage-sig spend is REJECTED (confirms a reset chain with
    //     assumeValidHeight=0 verifies signatures from block 1).
    {
        const uint32_t H = 1;
        const bool fVerify = !ConnectPathMaySkipScriptVerify((int)H, relaunchAVH, /*IBD=*/true);
        BOOST_CHECK(fVerify);
        CBlock b = garbageSigBlockAt(H);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, (int)H, fVerify, err),
            "relaunch(assumeValidHeight=0) block 1 must verify signatures");
    }

    // (b) Mainnet params, low-height block AT THE TIP (not IBD): VERIFY => REJECT.
    //     This is exactly the freshly-mined low-height tip-block theft HIGH-1 closes.
    {
        const uint32_t H = 100;   // far below 44233
        const bool fVerify = !ConnectPathMaySkipScriptVerify((int)H, mainnetAVH, /*IBD=*/false);
        BOOST_CHECK(fVerify);
        CBlock b = garbageSigBlockAt(H);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, (int)H, fVerify, err),
            "low-height TIP block must verify signatures (assume-valid must not skip at tip)");
    }

    // (c) Control: mainnet params, low-height block DURING IBD below assume-valid =>
    //     skip is legitimate (Bitcoin Core assumevalid). fVerify=false and the
    //     value-valid block is ACCEPTED — proving the skip actually happens (so the
    //     rejects in (a)/(b) are attributable to the signature gate, not vacuous).
    {
        const uint32_t H = 100;
        const bool fVerify = !ConnectPathMaySkipScriptVerify((int)H, mainnetAVH, /*IBD=*/true);
        BOOST_CHECK(!fVerify);
        CBlock b = garbageSigBlockAt(H);
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(b, utxo, (int)H, fVerify, err),
            "historical IBD block below assume-valid may skip signatures: " << err);
    }

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// HIGH-1 round-2 — scriptAssumeValidHeight decoupled from dfmpAssumeValidHeight
// ============================================================================
// The connect-path signature gate now draws from a DEDICATED
// scriptAssumeValidHeight (default 0), NOT dfmpAssumeValidHeight. Both tests go
// end-to-end through ConnectPathVerifyScripts — the single decision point
// ConnectTip calls — so a regression that re-couples the two knobs, or that
// defaults scriptAssumeValidHeight to a nonzero DFMP-style value, reddens them.

// (1) INVERSION of round-1 case (c). With the decoupled default
// scriptAssumeValidHeight==0, a value-valid GARBAGE-signature spend at a low
// height DURING IBD is REJECTED — where the round-1 coupled gate (reading
// dfmpAssumeValidHeight=44000/44233) ACCEPTED the identical block.
BOOST_FIXTURE_TEST_CASE(cc_high1_scriptavh_default0_rejects_garbage_sig_in_ibd, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);

    // Decoupled by construction: the signature knob is 0 while the DFMP knob keeps
    // its live (raise-only) value. If a regression copied the DFMP value into the
    // script knob, this REQUIRE — and the reject below — would fire.
    BOOST_REQUIRE_EQUAL(Dilithion::g_chainParams->scriptAssumeValidHeight, 0);
    BOOST_REQUIRE(Dilithion::g_chainParams->dfmpAssumeValidHeight > 0);

    Key owner = MakeKey();
    COutPoint prev(MakeHash(0x98), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, owner.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    const uint32_t H = 100;   // far below dfmpAssumeValidHeight — the round-1 skip window

    // Derive fVerifyScripts EXACTLY as ConnectTip does (via the shared helper).
    // Default scriptAVH=0 => ConnectPathMaySkipScriptVerify is false => verify.
    const bool fVerify = ConnectPathVerifyScripts(Dilithion::g_chainParams, (int)H, /*IBD=*/true);
    BOOST_CHECK_MESSAGE(fVerify,
        "scriptAssumeValidHeight default 0 must verify signatures even at a low height during IBD");

    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr)   // garbage 0xAA sig, value-valid
    };
    CBlock b = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, (int)H, fVerify, err),
        "garbage-sig spend at height 100 during IBD must be REJECTED under the decoupled default "
        "(round-1's coupled knob accepted it)");
    BOOST_CHECK_MESSAGE(err.find("signature") != std::string::npos ||
                        err.find("script") != std::string::npos,
        "rejection must be attributable to the signature gate, got: " << err);

    utxo.Close(); CleanupUTXO(path);
}

// (2) DECOUPLING proof. Raising dfmpAssumeValidHeight to a large value must NOT
// change fVerifyScripts. If the signature gate still read the DFMP knob, a raise
// to 999999 would (height 100, IBD) skip signatures and ACCEPT the theft spend.
BOOST_FIXTURE_TEST_CASE(cc_high1_dfmp_raise_does_not_disable_signatures, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);

    Key owner = MakeKey();
    COutPoint prev(MakeHash(0x99), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, owner.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    const uint32_t H = 100;

    // Baseline: with the DFMP knob at its shipped value, signatures verify.
    BOOST_REQUIRE(ConnectPathVerifyScripts(Dilithion::g_chainParams, (int)H, /*IBD=*/true));

    // Raise the DFMP knob far above H; leave scriptAssumeValidHeight at 0 (the
    // fixture owns its ChainParams copy, restored on teardown). The signature gate
    // reads the script knob, so it is UNAFFECTED — still verifies.
    Dilithion::g_chainParams->dfmpAssumeValidHeight = 999999;
    BOOST_REQUIRE_EQUAL(Dilithion::g_chainParams->scriptAssumeValidHeight, 0);
    const bool fVerify = ConnectPathVerifyScripts(Dilithion::g_chainParams, (int)H, /*IBD=*/true);
    BOOST_CHECK_MESSAGE(fVerify,
        "raising dfmpAssumeValidHeight must NOT disable ML-DSA signature verification (decoupling)");

    // End-to-end: the theft spend is still REJECTED after the DFMP-knob raise.
    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr)   // garbage sig
    };
    CBlock b = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, (int)H, fVerify, err),
        "after raising dfmpAssumeValidHeight, a garbage-sig spend must still be REJECTED");
    BOOST_CHECK_MESSAGE(err.find("signature") != std::string::npos ||
                        err.find("script") != std::string::npos,
        "rejection must be attributable to the signature gate, got: " << err);

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// MEDIUM-1 — overlay: multiple children of one same-block parent
// ============================================================================
// Two children spend DISTINCT outputs of a same-block parent (both real sigs):
// both resolve from the per-block overlay -> ACCEPT. Load-bearing: without the
// overlay both children fail "input not found".
BOOST_FIXTURE_TEST_CASE(cc_overlay_multi_child_accepted, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k1 = MakeKey();  // owns the confirmed coin
    Key k2 = MakeKey();  // owns txA output 0
    Key k3 = MakeKey();  // owns txA output 1

    COutPoint prev(MakeHash(0x91), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k1.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // txA: spends prev (k1) -> out0 = 60 (k2), out1 = 39 (k3). fee = 1.
    std::vector<CTxOut> aOuts = { CTxOut(60 * COIN, k2.spk), CTxOut(39 * COIN, k3.spk) };
    CTransactionRef txA = SpendTo(prev, aOuts, &k1);
    COutPoint a0(txA->GetHash(), 0);
    COutPoint a1(txA->GetHash(), 1);

    // txB spends a0 (k2) -> 59 (fee 1); txC spends a1 (k3) -> 38 (fee 1).
    CTransactionRef txB = Spend(a0, 59 * COIN, DummyP2PKH(0x05), &k2);
    CTransactionRef txC = Spend(a1, 38 * COIN, DummyP2PKH(0x06), &k3);

    // total in-block fees = 3.
    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H) + 3 * COIN, H), txA, txB, txC };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err),
        "two children spending distinct outputs of a same-block parent must be accepted: " << err);

    utxo.Close(); CleanupUTXO(path);
}

// Two children spend the SAME output of a same-block parent (overlay outpoint):
// the second is a double-spend -> REJECT. Load-bearing on the spentInBlock guard
// applied to an OVERLAY-resolved outpoint (both sigs are valid, so only the
// double-spend check can reject).
BOOST_FIXTURE_TEST_CASE(cc_overlay_double_spend_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k1 = MakeKey();
    Key k2 = MakeKey();
    COutPoint prev(MakeHash(0x92), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k1.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // txA: spends prev (k1) -> out0 = 99 (k2).
    std::vector<CTxOut> aOuts = { CTxOut(99 * COIN, k2.spk) };
    CTransactionRef txA = SpendTo(prev, aOuts, &k1);
    COutPoint a0(txA->GetHash(), 0);

    // txB and txC BOTH spend a0, both signed by the real owner k2 (distinct
    // output values => distinct txids, so seenTxids does NOT fire first).
    CTransactionRef txB = Spend(a0, 98 * COIN, DummyP2PKH(0x05), &k2);
    CTransactionRef txC = Spend(a0, 97 * COIN, DummyP2PKH(0x06), &k2);

    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H) + 4 * COIN, H), txA, txB, txC };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err),
        "second spend of a same-block (overlay) output must be rejected");
    BOOST_CHECK(err.find("double-spend") != std::string::npos);

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// MEDIUM-2 — MoneyRange guards (out-of-range input / output)
// ============================================================================
// Attribution: each assertion pins the SPECIFIC guard that must fire first. If
// that guard is neutered the reject falls through to a different-message guard
// (or the block is accepted), reddening the token check.
BOOST_FIXTURE_TEST_CASE(cc_value_out_of_range_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 5;

    // (a) SPENT-OUTPUT (input side) value out of range. The spent coin's value is
    //     MAX_MONEY+1; the per-input MoneyRange guard must fire ("spent output
    //     value out of range") BEFORE the totalIn/fee accumulators.
    {
        COutPoint big(MakeHash(0x93), 0);
        BOOST_REQUIRE(utxo.AddUTXO(big, CTxOut((uint64_t)TxValidation::MAX_MONEY + 1, DummyP2PKH(0xAA)), 1, false));
        BOOST_REQUIRE(utxo.Flush());
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(big, 10 * COIN, DummyP2PKH(0x02), nullptr)   // small in-range output
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/false, err),
            "spend of an out-of-range coin must be rejected");
        BOOST_CHECK_MESSAGE(err.find("spent output value out of range") != std::string::npos,
            "expected the per-input MoneyRange guard to fire, got: " << err);
    }

    // (b) OUTPUT value out of range. In-range input (100), output = MAX_MONEY+1.
    //     The per-output MoneyRange guard must fire ("output value out of range")
    //     before the totalOut accumulator ("total output ...") or the mint check.
    {
        COutPoint ok(MakeHash(0x94), 0);
        BOOST_REQUIRE(utxo.AddUTXO(ok, CTxOut(100 * COIN, DummyP2PKH(0xAA)), 1, false));
        BOOST_REQUIRE(utxo.Flush());
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(ok, (uint64_t)TxValidation::MAX_MONEY + 1, DummyP2PKH(0x02), nullptr)
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/false, err),
            "an out-of-range output value must be rejected");
        // "output value out of range" must be present, but NOT the accumulator
        // ("total output ...") nor the mint ("less than outputs") message — those
        // are the fall-through guards a neutered per-output check would hit.
        BOOST_CHECK_MESSAGE(err.find("output value out of range") != std::string::npos &&
                            err.find("total") == std::string::npos &&
                            err.find("less than outputs") == std::string::npos,
            "expected the per-output MoneyRange guard to fire first, got: " << err);
    }

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// MEDIUM-3 — coinbase maturity at the EXACT threshold (off-by-one pinning)
// ============================================================================
// Coinbase created at height 1, maturity M. Spending at height M (confs = M-1)
// is immature -> REJECT; spending at height M+1 (confs = M) is mature -> ACCEPT.
// Together these pin `<` (dropping to `<=` reddens the accept; loosening reddens
// the reject).
BOOST_FIXTURE_TEST_CASE(cc_coinbase_maturity_exact_threshold, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);

    const unsigned int M = (unsigned int)Dilithion::g_chainParams->coinbaseMaturity;
    BOOST_REQUIRE(M >= 1);

    COutPoint cb(MakeHash(0x95), 0);
    BOOST_REQUIRE(utxo.AddUTXO(cb, CTxOut(50 * COIN, DummyP2PKH(0xAA)), 1, /*coinbase=*/true));
    BOOST_REQUIRE(utxo.Flush());

    // confs = M-1 at H = M -> immature -> REJECT.
    {
        const uint32_t H = M;                 // confs = M - 1
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(cb, 40 * COIN, DummyP2PKH(0x02), nullptr)
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, (int)H, /*fVerifyScripts=*/false, err),
            "coinbase spend at exactly maturity-1 confirmations must be rejected");
        BOOST_CHECK(err.find("immature") != std::string::npos);
    }

    // confs = M at H = M+1 -> mature -> ACCEPT.
    {
        const uint32_t H = M + 1;             // confs = M
        std::vector<CTransactionRef> txs = {
            Coinbase(Subsidy(H), H),
            Spend(cb, 40 * COIN, DummyP2PKH(0x02), nullptr)
        };
        CBlock block = MakeBlock(txs);
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, (int)H, /*fVerifyScripts=*/false, err),
            "coinbase spend at exactly maturity confirmations must be accepted: " << err);
    }

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// LOW — duplicate txid and non-topological (child-before-parent) rejects
// ============================================================================
// Two identical non-coinbase txs (same txid) -> the seenTxids guard fires
// ("duplicate transaction") BEFORE the double-spend guard. Load-bearing: with
// seenTxids removed the second copy would instead reject as a double-spend
// (different message), reddening the token check.
BOOST_FIXTURE_TEST_CASE(cc_duplicate_txid_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0x96), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, DummyP2PKH(0xAA)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    // Two byte-identical spends => identical txid.
    CTransactionRef dup1 = Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr);
    CTransactionRef dup2 = Spend(prev, 90 * COIN, DummyP2PKH(0x02), nullptr);
    BOOST_REQUIRE(dup1->GetHash() == dup2->GetHash());

    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H), H), dup1, dup2 };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/false, err),
        "a block containing a duplicate transaction must be rejected");
    BOOST_CHECK_MESSAGE(err.find("duplicate") != std::string::npos,
        "expected the duplicate-txid guard to fire first, got: " << err);
}

// Child-before-parent (non-topological) ordering: the child's input is not yet
// in the overlay or the confirmed set -> "input not found" REJECT. Pins that the
// connect path requires topological order (matches ApplyBlock).
BOOST_FIXTURE_TEST_CASE(cc_child_before_parent_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k1 = MakeKey();
    Key k2 = MakeKey();
    COutPoint prev(MakeHash(0x97), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k1.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    CTransactionRef txA = SpendTo(prev, { CTxOut(99 * COIN, k2.spk) }, &k1);
    COutPoint a0(txA->GetHash(), 0);
    CTransactionRef txB = Spend(a0, 98 * COIN, DummyP2PKH(0x05), &k2);

    // Child (txB) placed BEFORE parent (txA).
    std::vector<CTransactionRef> txs = { Coinbase(Subsidy(H) + 2 * COIN, H), txB, txA };
    CBlock block = MakeBlock(txs);
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, err),
        "child-before-parent (non-topological) block must be rejected");
    BOOST_CHECK(err.find("not found") != std::string::npos);

    utxo.Close(); CleanupUTXO(path);
}

BOOST_AUTO_TEST_SUITE_END()
