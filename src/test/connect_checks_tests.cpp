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
#include <consensus/params.h>          // Consensus::DEV_FUND_PUBKEY_HASH / MINING_TAX_PERCENT / COINBASE_SCRIPTSIG_MAX_SIZE
#include <consensus/chain.h>           // CChainState (null-UTXO fail-closed KAT)
#include <consensus/pow.h>             // CheckProofOfWork / IsValidPoWTarget / MAX_DIFFICULTY_BITS
#include <consensus/vdf_validation.h>  // CheckMIKExpiration (fail-closed KATs)
#include <node/block_index.h>          // CBlockIndex (null-UTXO fail-closed KAT)
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

// A canonical-LAYOUT garbage scriptSig: the exact 5265-byte P2PKH shape
// (LE16(3309) | 3309*fill | LE16(1952) | 1952*fill) with junk sig/pk content.
// It PASSES the connect-path canonical-scriptSig gate (CHECK 6) on LAYOUT — so a
// spend that isolates a NON-signature check with fVerifyScripts=false reaches
// that check instead of being culled by the malleability gate — while its junk
// content still FAILS the ML-DSA signature step when fVerifyScripts=true. (The
// placeholder was a 100-byte 0xAA blob before the malleability gate landed; this
// mirrors dd983607's canonicalisation of tx_validation_tests. Malleated-LAYOUT
// scriptSigs — the thing the gate rejects — are constructed explicitly per test.)
std::vector<uint8_t> CanonicalLayoutSig(uint8_t fill = 0xAA) {
    const size_t SIG = 3309, PK = 1952;
    std::vector<uint8_t> s;
    s.reserve(2 + SIG + 2 + PK);
    s.push_back((uint8_t)(SIG & 0xFF)); s.push_back((uint8_t)((SIG >> 8) & 0xFF));
    s.insert(s.end(), SIG, fill);
    s.push_back((uint8_t)(PK & 0xFF));  s.push_back((uint8_t)((PK >> 8) & 0xFF));
    s.insert(s.end(), PK, fill);
    return s;
}

// The mainnet Dev-Fund / Dev-Reward P2PKH outputs CheckCoinbase requires at
// height H (2% of subsidy, split 50/50). Exposed so tests can build a coinbase
// that omits / underpays one of them (round-2 HIGH: tax enforced at connect).
uint64_t RequiredDevFund(uint32_t H) {
    uint64_t tax = (CBlockValidator::CalculateBlockSubsidy(H) * Consensus::MINING_TAX_PERCENT) / 100;
    return (tax * Consensus::DEV_FUND_SHARE) / 100;
}
uint64_t RequiredDevReward(uint32_t H) {
    uint64_t tax = (CBlockValidator::CalculateBlockSubsidy(H) * Consensus::MINING_TAX_PERCENT) / 100;
    return tax - RequiredDevFund(H);
}
std::vector<uint8_t> DevFundSpk()   { return P2PKH(Consensus::DEV_FUND_PUBKEY_HASH); }
std::vector<uint8_t> DevRewardSpk() { return P2PKH(Consensus::DEV_REWARD_PUBKEY_HASH); }

// Coinbase paying `value` in TOTAL across the mainnet-required layout
// (miner + Dev Fund + Dev Reward, tax computed for height `H`); the miner
// output absorbs value - tax. scriptSig carries `data` for uniqueness. Since
// the round-2 fold, ConnectBlockChecks runs the full CheckCoinbase (structure
// + tax + value cap) at connect, so a positive-control coinbase must carry the
// tax outputs. All existing callers pass H as `data`, so tax is sized for H.
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
    const uint64_t df = RequiredDevFund(data), dr = RequiredDevReward(data);
    const uint64_t miner = (value >= df + dr) ? (value - df - dr) : 0;
    tx.vout.push_back(CTxOut(miner, spk));
    tx.vout.push_back(CTxOut(df, DevFundSpk()));
    tx.vout.push_back(CTxOut(dr, DevRewardSpk()));
    return MakeTransactionRef(tx);
}

// A coinbase with an EXPLICIT output list and scriptSig (no tax layout applied):
// the raw builder the round-2 structural KATs use to construct malformed
// coinbases (missing tax output, oversize scriptSig, wrong form, ...).
CTransactionRef CoinbaseRaw(const std::vector<CTxOut>& outs,
                            const std::vector<uint8_t>& scriptSig) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(COutPoint(), scriptSig));
    for (const auto& o : outs) tx.vout.push_back(o);
    return MakeTransactionRef(tx);
}

// Non-coinbase spend of `prevout` -> single output `outVal`, signed by `signer`
// if provided (else a garbage 0xAA scriptSig).
CTransactionRef Spend(const COutPoint& prevout, uint64_t outVal,
                      const std::vector<uint8_t>& outSpk,
                      const Key* signer) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(prevout, CanonicalLayoutSig(0xAA), CTxIn::SEQUENCE_FINAL));
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
    tx.vin.push_back(CTxIn(prevout, CanonicalLayoutSig(0xAA), CTxIn::SEQUENCE_FINAL));
    for (const auto& o : outs) tx.vout.push_back(o);
    if (signer) {
        tx.vin[0].scriptSig = SignInputLegacy(tx, 0, *signer);
    }
    return MakeTransactionRef(tx);
}

// Non-coinbase spend of `prevout` carrying an EXPLICIT raw scriptSig (no signing),
// so a test can inject a malleated-LAYOUT scriptSig the canonical gate must reject.
CTransactionRef SpendRaw(const COutPoint& prevout, uint64_t outVal,
                         const std::vector<uint8_t>& outSpk,
                         const std::vector<uint8_t>& rawScriptSig) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(prevout, rawScriptSig, CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(outVal, outSpk));
    return MakeTransactionRef(tx);
}

std::vector<uint8_t> DummyP2PKH(uint8_t fill) {
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), 20, fill);
    spk.push_back(0x88); spk.push_back(0xac);
    return spk;
}

uint64_t Subsidy(uint32_t h) { return CBlockValidator::CalculateBlockSubsidy(h); }

// A block whose non-coinbase tx is fully valid EXCEPT for the scriptSig LAYOUT it
// carries: coinbase(subsidy) + a value-valid (in 100 -> out 90, fee 10), mature,
// existent, single-spend of the confirmed P2PKH coin `prev`, with scriptSig `ss`.
// Merkle is recomputed over the actual (possibly malleated) tx. With
// fVerifyScripts=false the ONLY connect-path check that can reject is the
// canonical-scriptSig gate (CHECK 6), so acceptance/rejection is attributable to
// the scriptSig layout alone.
CBlock MallBlock(const COutPoint& prev, const std::vector<uint8_t>& ss, uint32_t H) {
    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        SpendRaw(prev, 90 * COIN, DummyP2PKH(0x02), ss)
    };
    return MakeBlock(txs);
}

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

// ============================================================================
// MALLEABILITY (finding #4) — canonical P2PKH scriptSig ON THE CONNECT PATH
// ============================================================================
// MALLEABILITY_REREVIEW HIGH: the canonical-scriptSig gate lived only on the
// mempool/relay path (CheckTransactionInputs) and a DEAD block validator, so a
// malleated scriptSig MINED INTO A BLOCK was accepted by every node on connect.
// CHECK 6 closes that: ConnectBlockChecks now enforces the SAME single-source
// predicate (IsCanonicalP2PKHScriptSig) that the mempool path uses.
//
// Every rejection below runs with fVerifyScripts=FALSE so ONLY the UNCONDITIONAL
// canonical gate can reject — the ML-DSA step is off, and each spend is otherwise
// value-valid, mature, existent, single-spend, correct-merkle. So a reject is
// attributable to CHECK 6 alone, and neutering CHECK 6 flips every reject to
// ACCEPT (the mutation proof; see MALLEABILITY_INTEGRATION.md for the run).

// Positive control: the honest canonical layout is ACCEPTED on the connect path,
// both with signatures OFF (proves the gate passes the canonical LAYOUT) and with
// signatures ON over a real ML-DSA signature (proves the gate does not reject the
// honest producer's byte-string). The coinbase in each block carries a NON-
// canonical scriptSig ({0x04,...}) yet the block is accepted — proving CHECK 6 is
// correctly exempt for the coinbase input.
BOOST_FIXTURE_TEST_CASE(cc_mall_canonical_scriptsig_accepted, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    Key k = MakeKey();
    COutPoint prev(MakeHash(0xC0), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k.spk), 1, false));  // committed to k
    BOOST_REQUIRE(utxo.Flush());

    // Real ML-DSA signature => the exact 5265-byte canonical layout.
    std::vector<CTransactionRef> txs = {
        Coinbase(Subsidy(H), H),
        Spend(prev, 90 * COIN, DummyP2PKH(0x02), &k)
    };
    CBlock block = MakeBlock(txs);

    std::string errOn;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/true, errOn),
        "honest canonical spend must be accepted with signatures ON: " << errOn);
    std::string errOff;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(block, utxo, H, /*fVerifyScripts=*/false, errOff),
        "honest canonical layout must pass CHECK 6 with signatures OFF: " << errOff);

    utxo.Close(); CleanupUTXO(path);
}

// Rejection matrix: each malleated LAYOUT (the txid-malleability vectors B1..B4)
// mined into a block is REJECTED on the connect path. Anti-vacuity: the SAME
// harness first accepts the base canonical layout, so every reject is caused by
// the layout mutation, not incidental structural failure.
BOOST_FIXTURE_TEST_CASE(cc_mall_malleated_scriptsig_rejected_on_connect, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    // Confirmed P2PKH coin. Signatures are OFF for this whole case, so the pubkey<->
    // hash binding is not checked and a Dummy P2PKH scriptPubKey suffices; the coin
    // only needs to BE P2PKH so CHECK 6 keys on it.
    COutPoint prev(MakeHash(0xC0), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, DummyP2PKH(0xC1)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    const std::vector<uint8_t> canonical = CanonicalLayoutSig(0xAA);  // 5265 bytes, valid layout
    BOOST_REQUIRE_EQUAL(canonical.size(), (size_t)5265);

    // --- Anti-vacuity: the base canonical layout is ACCEPTED (scripts off) --------
    {
        CBlock ok = MallBlock(prev, canonical, H);
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(ok, utxo, H, /*fVerifyScripts=*/false, err),
            "base canonical layout must be accepted so rejects are attributable: " << err);
    }

    auto expectReject = [&](const std::vector<uint8_t>& ss, const char* label) {
        CBlock b = MallBlock(prev, ss, H);
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, H, /*fVerifyScripts=*/false, err),
            label << ": malleated scriptSig must be REJECTED on the connect path");
        BOOST_CHECK_MESSAGE(err.find("malleability") != std::string::npos ||
                            err.find("canonical") != std::string::npos,
            label << ": reject must be attributable to CHECK 6, got: " << err);
    };

    // B3 — prepend junk: size 5266 != 5265 (size branch).
    {
        std::vector<uint8_t> s = canonical;
        s.insert(s.begin(), 0x00);
        expectReject(s, "junk-prepended");
    }
    // B3 — stack residue: an extra pushed element appended (size 5267, size branch).
    {
        std::vector<uint8_t> s = canonical;
        s.push_back(0x01); s.push_back(0xFF);   // trailing residue
        expectReject(s, "stack-residue-appended");
    }
    // B4 — wrong pk_len FIELD: total size stays 5265, but the pk_len field is 1951
    // (not 1952). This is the sub-vector IsLegacyScriptSig misses (pk_len branch).
    {
        std::vector<uint8_t> s = canonical;
        const size_t off = 2 + 3309;            // pk_len field offset
        s[off] = (uint8_t)(1951 & 0xFF); s[off + 1] = (uint8_t)((1951 >> 8) & 0xFF);
        expectReject(s, "wrong-pk_len");
    }
    // wrong sig_len FIELD: size stays 5265, sig_len field is 3308 (sig_len branch).
    {
        std::vector<uint8_t> s = canonical;
        s[0] = (uint8_t)(3308 & 0xFF); s[1] = (uint8_t)((3308 >> 8) & 0xFF);
        expectReject(s, "wrong-sig_len");
    }
    // B1/B2 — push-opcode / non-minimal-push framing: encode sig & pk via a
    // 4-byte-length PUSHDATA4-style prefix instead of the canonical 2-byte length.
    // Size = 5 + 3309 + 5 + 1952 = 5271 != 5265 (size branch); no push opcodes are
    // part of the canonical layout at all.
    {
        std::vector<uint8_t> s;
        auto pushData4 = [&](size_t n) {
            s.push_back(0x4e);                                   // OP_PUSHDATA4
            for (int i = 0; i < 4; ++i) s.push_back((uint8_t)((n >> (i * 8)) & 0xFF));
            s.insert(s.end(), n, 0xAA);
        };
        pushData4(3309);   // sig
        pushData4(1952);   // pk
        BOOST_REQUIRE_EQUAL(s.size(), (size_t)5271);
        expectReject(s, "push-opcode-nonminimal");
    }

    utxo.Close(); CleanupUTXO(path);
}

// The gate is UNCONDITIONAL: a malleated scriptSig is rejected on the connect path
// EVEN when signatures are assume-valid-skipped (fVerifyScripts=false). This is the
// property that makes the closure a real consensus rule rather than a signature-
// path artifact, and that keeps the connect surface identical to the mempool
// surface (which enforces it unconditionally). Contrast: the SAME junk-prepended
// layout with signatures ON is ALSO rejected (via CHECK 6 before the sig step).
BOOST_FIXTURE_TEST_CASE(cc_mall_gate_unconditional_wrt_assumevalid, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 2;

    COutPoint prev(MakeHash(0xC2), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, DummyP2PKH(0xC3)), 1, false));
    BOOST_REQUIRE(utxo.Flush());

    std::vector<uint8_t> malleated = CanonicalLayoutSig(0xAA);
    malleated.insert(malleated.begin(), 0x00);   // junk-prepended -> non-canonical

    CBlock b = MallBlock(prev, malleated, H);

    std::string errOff;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, H, /*fVerifyScripts=*/false, errOff),
        "malleated scriptSig must be rejected even with signatures assume-valid-skipped");
    BOOST_CHECK_MESSAGE(errOff.find("malleability") != std::string::npos ||
                        errOff.find("canonical") != std::string::npos,
        "scripts-off reject must be the canonical gate, got: " << errOff);

    std::string errOn;
    BOOST_CHECK_MESSAGE(!ConnectBlockChecks(b, utxo, H, /*fVerifyScripts=*/true, errOn),
        "malleated scriptSig must also be rejected with signatures ON");

    utxo.Close(); CleanupUTXO(path);
}

// ============================================================================
// EXTERNAL ROUND-2 FOLD — BLOCKER/HIGH KATs
// (branch fold/external-round2-blockers). Each rejection is paired with a
// positive control so it is attributable to the specific rule under test, and
// each rule was mutation-verified: reverting the corresponding fix in the
// validator turns the named assertion RED (see the fold commit message).
// ============================================================================

// ---- helpers local to the round-2 KATs -------------------------------------

// A "fake coinbase": a NORMAL-form transaction (single NON-null input) placed at
// index 0, paying `value` to a miner-style P2PKH. Pre-fold, ConnectBlockChecks
// and ApplyBlock trusted POSITION (txIdx == 0 => coinbase) so this tx's input
// was never resolved and its value never conserved.
CTransactionRef FakeCoinbaseAtIdx0(uint64_t value, uint8_t seed) {
    CTransaction tx;
    tx.nVersion = 1; tx.nLockTime = 0;
    tx.vin.push_back(CTxIn(COutPoint(MakeHash(seed), 0), CanonicalLayoutSig(0xAA), CTxIn::SEQUENCE_FINAL));
    tx.vout.push_back(CTxOut(value, DummyP2PKH(0x33)));
    return MakeTransactionRef(tx);
}

// A block whose only tx is a coinbase built by CoinbaseRaw with an explicit
// output list — used by the tax / scriptSig-cap KATs.
CBlock TaxBlock(uint32_t H, const std::vector<CTxOut>& outs, uint32_t data = 0x51) {
    std::vector<uint8_t> ss = {0x04, (uint8_t)data, (uint8_t)H, 0, 0};
    return MakeBlock({ CoinbaseRaw(outs, ss) });
}

// ---- #1 BLOCKER: coinbase by FORM, not POSITION -----------------------------

// A normal-form spend at index 0 (the "fake coinbase") is REJECTED by the
// connect-path validator on FORM — even when its value is within the coinbase
// cap (subsidy) so the value cap alone could NOT have caught it — and ApplyBlock
// independently refuses to mutate on it. Positive control: a real coinbase at
// index 0 is accepted. Mutation: revert CHECK 0 (position-only) => the
// value==subsidy variant is ACCEPTED by ConnectBlockChecks => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_fake_coinbase_at_idx0_rejected_by_form, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 7;

    // (a) 1e6 DIL "mint" at index 0 — the supply-inflation shape.
    {
        CBlock blk = MakeBlock({ FakeCoinbaseAtIdx0(1000000ULL * COIN, 0x71) });
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(blk, utxo, H, false, err),
                            "fake coinbase (1e6 DIL) at index 0 must be rejected");
        BOOST_CHECK_MESSAGE(err.find("not coinbase-form") != std::string::npos,
                            "rejection must be attributable to the FORM check, got: " << err);
        // ApplyBlock (the mutator) refuses independently.
        BOOST_CHECK_MESSAGE(!utxo.ApplyBlock(blk, H, blk.GetHash()),
                            "ApplyBlock must refuse a non-coinbase-form first tx");
    }
    // (b) value == subsidy at index 0 — passes the value cap; ONLY the form
    //     check can reject it. This is the load-bearing mutation target.
    {
        CBlock blk = MakeBlock({ FakeCoinbaseAtIdx0(Subsidy(H), 0x72) });
        std::string err;
        BOOST_CHECK_MESSAGE(!ConnectBlockChecks(blk, utxo, H, false, err),
                            "fake coinbase (== subsidy) at index 0 must be rejected on FORM");
        BOOST_CHECK(err.find("not coinbase-form") != std::string::npos);
        BOOST_CHECK(!utxo.ApplyBlock(blk, H, blk.GetHash()));
        // Refused before any batch write: none of its outputs were created.
        BOOST_CHECK(!utxo.HaveUTXO(COutPoint(blk.GetHash(), 0)));
    }
    // (c) positive control: real coinbase at index 0 accepted + applied.
    {
        CBlock ok = MakeBlock({ Coinbase(Subsidy(H), H) });
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(ok, utxo, H, false, err),
                            "real coinbase must be accepted: " << err);
        BOOST_CHECK(utxo.ApplyBlock(ok, H, ok.GetHash()));
    }
    utxo.Close(); CleanupUTXO(path);
}

// A coinbase-FORM tx at index > 0 is REJECTED structurally (not merely by the
// incidental input-not-found on its null prevout), and ApplyBlock refuses.
// Positive control: the same block with a real spend at index 1 is accepted.
// Mutation: delete the idx>0 IsCoinBase() reject in ConnectBlockChecks => the
// error string is no longer the structural one => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_coinbase_form_at_idx1_rejected, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 3;

    CBlock bad = MakeBlock({ Coinbase(Subsidy(H), H), Coinbase(Subsidy(H), H + 100) });
    std::string err;
    BOOST_CHECK(!ConnectBlockChecks(bad, utxo, H, false, err));
    BOOST_CHECK_MESSAGE(err.find("coinbase-form transaction at index 1") != std::string::npos,
                        "must be the structural reject, got: " << err);
    BOOST_CHECK(!utxo.ApplyBlock(bad, H, bad.GetHash()));

    // Positive control: real spend at index 1.
    Key k = MakeKey();
    COutPoint prev(MakeHash(0x90), 0);
    BOOST_REQUIRE(utxo.AddUTXO(prev, CTxOut(100 * COIN, k.spk), 1, false));
    BOOST_REQUIRE(utxo.Flush());
    CBlock ok = MakeBlock({ Coinbase(Subsidy(H) + 10 * COIN, H),
                            Spend(prev, 90 * COIN, DummyP2PKH(0x02), &k) });
    std::string err2;
    BOOST_CHECK_MESSAGE(ConnectBlockChecks(ok, utxo, H, true, err2), "control: " << err2);
    utxo.Close(); CleanupUTXO(path);
}

// ---- #2 HIGH: coinbase structure + Dev-Fund/Dev-Reward tax enforced at CONNECT

// A coinbase that OMITS the Dev Fund output (value otherwise <= subsidy) is
// REJECTED by ConnectBlockChecks — with fVerifyScripts=false, i.e. exactly the
// connect that arrival could have skipped (forkPreValidated / skipPoWCheck /
// feeCalcReliable=false). Underpaid Dev Reward likewise. Positive control: the
// full tax layout at the same height is accepted. Mutation: revert CHECK 3 to
// the value-cap-only form => both bad blocks ACCEPTED => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_dev_tax_enforced_at_connect, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 11;
    const uint64_t S = Subsidy(H);
    const uint64_t df = RequiredDevFund(H), dr = RequiredDevReward(H);
    BOOST_REQUIRE(df > 0 && dr > 0);

    // (a) Dev Fund output missing (miner takes it).
    {
        CBlock blk = TaxBlock(H, { CTxOut(S - dr, DummyP2PKH(0x01)), CTxOut(dr, DevRewardSpk()),
                                   CTxOut(0, DummyP2PKH(0x05)) /* pad to 3 outputs */ });
        std::string err;
        BOOST_CHECK(!ConnectBlockChecks(blk, utxo, H, false, err));
        BOOST_CHECK_MESSAGE(err.find("Dev Fund") != std::string::npos, "got: " << err);
    }
    // (b) Dev Reward underpaid by 1.
    {
        CBlock blk = TaxBlock(H, { CTxOut(S - df - dr + 1, DummyP2PKH(0x01)),
                                   CTxOut(df, DevFundSpk()), CTxOut(dr - 1, DevRewardSpk()) });
        std::string err;
        BOOST_CHECK(!ConnectBlockChecks(blk, utxo, H, false, err));
        BOOST_CHECK_MESSAGE(err.find("Dev Reward") != std::string::npos, "got: " << err);
    }
    // (c) positive control: exact layout accepted.
    {
        CBlock blk = TaxBlock(H, { CTxOut(S - df - dr, DummyP2PKH(0x01)),
                                   CTxOut(df, DevFundSpk()), CTxOut(dr, DevRewardSpk()) });
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(blk, utxo, H, false, err), "control: " << err);
    }
    // (d) genesis keeps CheckCoinbase's structure-only treatment: at height 0
    //     no tax and any value is accepted (pre-funded genesis).
    {
        CBlock blk = TaxBlock(0, { CTxOut(123456789ULL * COIN, DummyP2PKH(0x01)) });
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(blk, utxo, 0, false, err), "genesis: " << err);
    }
    utxo.Close(); CleanupUTXO(path);
}

// ---- #8: coinbase scriptSig size cap at the connect seam ---------------------

// An oversize (MAX+1) or undersize (MIN-1) coinbase scriptSig is REJECTED by
// ConnectBlockChecks BEFORE any parser touches it; exactly MAX bytes is
// accepted (positive control at the boundary). The MIN-1 assertion pins the
// CHECK 0 error string so the cap's PRE-PARSE position is what is tested
// (CheckCoinbase at the end of the validator would also reject, with a
// different message). Mutation: delete the CHECK 0 size bounds => the MIN-1
// message changes to CheckCoinbase's => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_coinbase_scriptsig_cap_at_connect, ChainParamsFixture) {
    CUTXOSet utxo; std::string path = OpenTempUTXO(utxo);
    const uint32_t H = 4;
    const uint64_t S = Subsidy(H);
    const uint64_t df = RequiredDevFund(H), dr = RequiredDevReward(H);
    std::vector<CTxOut> outs = { CTxOut(S - df - dr, DummyP2PKH(0x01)),
                                 CTxOut(df, DevFundSpk()), CTxOut(dr, DevRewardSpk()) };

    auto blockWithSs = [&](size_t n) {
        std::vector<uint8_t> ss(n, 0x42);
        if (n >= 4) { ss[0] = 0x04; ss[1] = (uint8_t)H; }
        return MakeBlock({ CoinbaseRaw(outs, ss) });
    };
    {
        // MAX+1: the wire deserializer (CTransaction::Deserialize, 20000-byte
        // scriptSig bound) already culls this before CHECK 0 can — so the
        // oversize case is DOUBLY bounded on the connect seam; either message
        // is a rejection BEFORE any coinbase parser runs.
        CBlock blk = blockWithSs(Consensus::COINBASE_SCRIPTSIG_MAX_SIZE + 1);
        std::string err;
        BOOST_CHECK(!ConnectBlockChecks(blk, utxo, H, false, err));
        BOOST_CHECK_MESSAGE(err.find("coinbase scriptSig size out of bounds") != std::string::npos ||
                            err.find("scriptSig too large") != std::string::npos,
                            "must be a size-bound rejection, got: " << err);
    }
    {
        // MIN-1: only CHECK 0 rejects this before the parsers — pins the cap's
        // pre-parse position (mutation target).
        CBlock blk = blockWithSs(Consensus::COINBASE_SCRIPTSIG_MIN_SIZE - 1);
        std::string err;
        BOOST_CHECK(!ConnectBlockChecks(blk, utxo, H, false, err));
        BOOST_CHECK_MESSAGE(err.find("coinbase scriptSig size out of bounds") != std::string::npos,
                            "must be the pre-parse CHECK 0 cap, got: " << err);
    }
    {
        CBlock blk = blockWithSs(Consensus::COINBASE_SCRIPTSIG_MAX_SIZE);
        std::string err;
        BOOST_CHECK_MESSAGE(ConnectBlockChecks(blk, utxo, H, false, err), "boundary control: " << err);
    }
    utxo.Close(); CleanupUTXO(path);
}

// ---- #3 HIGH: null pUTXOSet FAILS CLOSED in ConnectTip -----------------------

// With NO UTXO set attached and the test opt-in OFF, ConnectTip must return
// false and must NOT mark the block BLOCK_VALID_CHAIN. Positive control: with
// the (test-only) opt-in ON the very same call proceeds and marks the block —
// which is precisely the pre-fold fail-open behaviour, now reachable only via
// the explicit switch. Mutation: delete the null-UTXO guard => opt-in-OFF arm
// returns true / marks valid => RED. Uses a height-0 legacy block so no
// other gate (DFMP/attestation/VDF) can be the cause of the result.
BOOST_FIXTURE_TEST_CASE(cc_r2_null_utxoset_fails_closed, ChainParamsFixture) {
    const bool savedAllow = CChainState::TestAllowConnectWithoutUTXOSet();
    struct Restore { bool v; ~Restore() { CChainState::SetTestAllowConnectWithoutUTXOSet(v); } } restore{savedAllow};

    CBlock blk;                       // legacy, empty body — height-0 shape
    blk.nVersion = 1; blk.nTime = 1700000000u; blk.nBits = 0x1d00ffff;

    auto makeIdx = [&]() {
        auto idx = std::make_unique<CBlockIndex>();
        idx->nHeight = 0;
        idx->nStatus = 0;
        idx->phashBlock = blk.GetHash();
        return idx;
    };

    // (a) opt-in OFF => fail closed.
    {
        CChainState cs;               // pUTXOSet == nullptr
        CChainState::SetTestAllowConnectWithoutUTXOSet(false);
        auto idx = makeIdx();
        CBlockIndex* p = idx.get();
        BOOST_REQUIRE(cs.AddBlockIndex(p->GetBlockHash(), std::move(idx)));
        BOOST_CHECK_MESSAGE(!cs.ConnectTip(p, blk, false),
                            "ConnectTip must FAIL CLOSED with no UTXO set");
        BOOST_CHECK_MESSAGE((p->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) == 0,
                            "block must NOT be marked BLOCK_VALID_CHAIN");
        BOOST_CHECK_MESSAGE((p->nStatus & CBlockIndex::BLOCK_FAILED_VALID) == 0,
                            "misconfiguration must not brand the block invalid");
    }
    // (b) opt-in ON (test exemption) => proceeds and marks valid.
    {
        CChainState cs;
        CChainState::SetTestAllowConnectWithoutUTXOSet(true);
        auto idx = makeIdx();
        CBlockIndex* p = idx.get();
        BOOST_REQUIRE(cs.AddBlockIndex(p->GetBlockHash(), std::move(idx)));
        BOOST_CHECK(cs.ConnectTip(p, blk, false));
        BOOST_CHECK((p->nStatus & CBlockIndex::BLOCK_VALID_CHAIN) != 0);
    }
}

// ---- #4: PoW target validity — zero / overflow / over-easy nBits -------------

// CheckProofOfWork and CheckProofOfWorkDFMP reject a compact nBits whose target
// is ZERO (mantissa 0 / size 0), OVERFLOWS (size > 32) or is EASIER than
// powLimit (target > CompactToBig(MAX_DIFFICULTY_BITS)) — even for the
// all-zero hash that trivially satisfies hash < target. Canonical-range nBits
// (genesis 0x1e01fffe, hardest 0x1d00ffff, powLimit 0x1f0fffff itself, and a
// bit-23 "negative" mantissa as carried by 1,667 canonical DIL blocks around
// h=18,4xx) are ACCEPTED as targets. Mutation: delete the powLimit compare in
// IsValidPoWTarget => 0x2000ffff / 0x20ffffff accepted => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_pow_rejects_over_easy_nbits, ChainParamsFixture) {
    uint256 zeroHash; std::memset(zeroHash.data, 0, 32);   // < any non-zero target

    // Over-easy encodings.
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x2000ffff));  // size 32, target > powLimit
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x20ffffff));  // size 32, ~all-ones target
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x1f10ffff));  // just above powLimit
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x21000001));  // size 33 => overflow => zero
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x1d000000));  // zero mantissa
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0x00ffffff));  // size 0
    BOOST_CHECK(!CheckProofOfWork(zeroHash, 0));

    // Canonical-range encodings accepted (zero hash satisfies hash < target).
    BOOST_CHECK(CheckProofOfWork(zeroHash, 0x1f0fffff));   // == powLimit (MAX_DIFFICULTY_BITS)
    BOOST_CHECK(CheckProofOfWork(zeroHash, 0x1e01fffe));   // DIL genesis
    BOOST_CHECK(CheckProofOfWork(zeroHash, 0x1d00ffff));   // MIN_DIFFICULTY_BITS / DilV
    BOOST_CHECK(CheckProofOfWork(zeroHash, 0x1dac1449));   // bit-23 set: canonical DIL h=18,496 — NOT rejected

    // IsValidPoWTarget agrees.
    uint256 t;
    BOOST_CHECK(IsValidPoWTarget(0x1dac1449, t));
    BOOST_CHECK(!IsValidPoWTarget(0x2000ffff, t));
    BOOST_CHECK(!IsValidPoWTarget(0x21000001, t));

    // DFMP path agrees: over-easy nBits rejected before any MIK work; canonical
    // nBits proceeds (legacy block, assume-valid range => HashLessThan(hash, target)).
    CBlock blk = MakeBlock({ Coinbase(Subsidy(5), 5) });
    blk.nVersion = 1;
    BOOST_CHECK(!CheckProofOfWorkDFMP(blk, zeroHash, 0x2000ffff, 5, /*activationHeight=*/0));
    BOOST_CHECK(!CheckProofOfWorkDFMP(blk, zeroHash, 0x21000001, 5, 0));
    BOOST_CHECK(CheckProofOfWorkDFMP(blk, zeroHash, 0x1f0fffff, 5, 0));
}

// ---- #5: CheckProofOfWorkDFMP must not index vin[0] of an input-less first tx

// A legacy block whose first tx has NO inputs reaches the MIK-parse step
// (deserialises fine); pre-fold `coinbaseTx.vin[0]` was undefined behaviour
// (crash) there. Now it is REJECTED (not coinbase-form). Positive control: a
// real coinbase with the same hash/nBits proceeds. Mutation: delete the
// IsCoinBase() guard => UB / crash on the input-less block => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_dfmp_pow_rejects_inputless_first_tx, ChainParamsFixture) {
    uint256 zeroHash; std::memset(zeroHash.data, 0, 32);
    CTransaction noIn; noIn.nVersion = 1; noIn.nLockTime = 0;
    noIn.vout.push_back(CTxOut(1 * COIN, DummyP2PKH(0x01)));
    CBlock bad = MakeBlock({ MakeTransactionRef(noIn) });
    bad.nVersion = 1;
    BOOST_CHECK(!CheckProofOfWorkDFMP(bad, zeroHash, 0x1f0fffff, 5, 0));

    // Two-input first tx (also not coinbase-form) rejected as well.
    CTransaction twoIn; twoIn.nVersion = 1; twoIn.nLockTime = 0;
    twoIn.vin.push_back(CTxIn(COutPoint(), {0x04,1,2,3,4}));
    twoIn.vin.push_back(CTxIn(COutPoint(MakeHash(0x11), 0), {0x04,1,2,3,4}, CTxIn::SEQUENCE_FINAL));
    twoIn.vout.push_back(CTxOut(1 * COIN, DummyP2PKH(0x01)));
    CBlock bad2 = MakeBlock({ MakeTransactionRef(twoIn) });
    bad2.nVersion = 1;
    BOOST_CHECK(!CheckProofOfWorkDFMP(bad2, zeroHash, 0x1f0fffff, 5, 0));

    CBlock ok = MakeBlock({ Coinbase(Subsidy(5), 5) });
    ok.nVersion = 1;
    BOOST_CHECK(CheckProofOfWorkDFMP(ok, zeroHash, 0x1f0fffff, 5, 0));
}

// ---- #6: CheckMIKExpiration FAILS CLOSED on parse failure --------------------

// Post-activation, a block with an empty vtx / unparseable coinbase / no MIK
// data is REJECTED (was: returned true, "let other checks handle"). Pre-
// activation the same blocks pass (rule not in force). Mutation: restore the
// `return true` on the empty-vtx / no-MIK arms => RED.
BOOST_FIXTURE_TEST_CASE(cc_r2_mik_expiration_fails_closed, ChainParamsFixture) {
    // ACTIVATE the rule on the fixture's private params copy (live chains: disabled).
    owned->mikExpirationActivationHeight = 1;
    owned->mikExpirationThreshold = 100;

    std::string err;
    // (a) empty vtx.
    {
        CBlock blk; blk.nVersion = CBlockHeader::VDF_VERSION;
        BOOST_CHECK_MESSAGE(!CheckMIKExpiration(blk, 10, err), "empty vtx must fail closed");
        BOOST_CHECK(err.find("no transactions") != std::string::npos);
    }
    // (b) coinbase with no MIK data (plain height-push scriptSig).
    {
        CBlock blk = MakeBlock({ Coinbase(Subsidy(10), 10) });
        blk.nVersion = CBlockHeader::VDF_VERSION;
        err.clear();
        BOOST_CHECK_MESSAGE(!CheckMIKExpiration(blk, 10, err), "no MIK data must fail closed");
        BOOST_CHECK(err.find("no parseable MIK") != std::string::npos);
    }
    // (c) first tx not coinbase-form.
    {
        CBlock blk = MakeBlock({ FakeCoinbaseAtIdx0(1 * COIN, 0x77) });
        blk.nVersion = CBlockHeader::VDF_VERSION;
        err.clear();
        BOOST_CHECK(!CheckMIKExpiration(blk, 10, err));
        BOOST_CHECK(err.find("not coinbase-form") != std::string::npos);
    }
    // (d) garbage vtx (unparseable varint / coinbase).
    {
        CBlock blk; blk.nVersion = CBlockHeader::VDF_VERSION;
        blk.vtx = {0xfe, 0x00};                    // 0xfe varint prefix, truncated
        err.clear();
        BOOST_CHECK(!CheckMIKExpiration(blk, 10, err));
        blk.vtx = {0x01, 0xff, 0xff};              // 1 tx, junk body
        err.clear();
        BOOST_CHECK(!CheckMIKExpiration(blk, 10, err));
    }
    // (e) pre-activation positive control: the same empty block passes.
    {
        owned->mikExpirationActivationHeight = 999999999;
        CBlock blk; blk.nVersion = CBlockHeader::VDF_VERSION;
        err.clear();
        BOOST_CHECK(CheckMIKExpiration(blk, 10, err));
    }
}

// ---- #7: DFMP assume-valid gate — IBD guard + checkpoint anchor -------------

// The DFMP-family skip needs a POSITIVE configured height, nHeight <= it, and
// (IBD OR checkpoint-anchored). Mirrors cc_high1_script_assumevalid_predicate.
// Mutation: drop the (fIBD || anchored) term => the synced-unanchored row
// returns true => RED.
BOOST_AUTO_TEST_CASE(cc_r2_dfmp_assumevalid_predicate) {
    const int AVH = 44000;
    // In IBD, at/below AVH => skip (regardless of anchor).
    BOOST_CHECK( ConnectPathMaySkipDFMPChecks(1,     AVH, true,  false));
    BOOST_CHECK( ConnectPathMaySkipDFMPChecks(AVH,   AVH, true,  false));
    // Synced, at/below AVH, NOT anchored => must check (the round-2 gap).
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(1,     AVH, false, false));
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(AVH,   AVH, false, false));
    // Synced but proven checkpoint-anchored => skip (canonical history is safe).
    BOOST_CHECK( ConnectPathMaySkipDFMPChecks(1,     AVH, false, true));
    BOOST_CHECK( ConnectPathMaySkipDFMPChecks(AVH,   AVH, false, true));
    // Above AVH => never skip, whatever the flags.
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(AVH+1, AVH, true,  true));
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(AVH+1, AVH, false, false));
    // Non-positive configured height => never skip.
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(1, 0,  true, true));
    BOOST_CHECK(!ConnectPathMaySkipDFMPChecks(1, -1, true, true));
}

BOOST_AUTO_TEST_SUITE_END()
