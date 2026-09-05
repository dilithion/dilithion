/**
 * VDF Consensus Validation unit tests.
 *
 * Tests: ComputeVDFChallenge determinism, CheckVDFProof with real chiavdf,
 *        rejection of missing/invalid proofs, proof hash commitment.
 */
#include <consensus/vdf_validation.h>
#include <vdf/vdf.h>
#include <vdf/coinbase_vdf.h>
#include <crypto/sha3.h>
#include <core/chainparams.h>
#include <dfmp/mik.h>
#include <dfmp/dfmp.h>
#include <consensus/chain.h>
#include <node/block_index.h>
#include <node/utxo_set.h>
#include <filesystem>
#include <random>
#include <sstream>
#include <iostream>
#include <cassert>
#include <cstring>

static int passed = 0;
static int failed = 0;

#define TEST(name) do { std::cout << "  " << #name << "... " << std::flush; } while(0)
#define PASS()     do { std::cout << "PASS\n"; ++passed; } while(0)
#define CHECK(c)   do { if (!(c)) { std::cout << "FAIL (" << #c << ")\n"; ++failed; return; } } while(0)

// Helper: create a minimal VDF block with valid proof.
// Uses a small iteration count for fast testing.
static CBlock MakeVDFBlock(
    const uint256& prevHash,
    int height,
    const std::array<uint8_t, 20>& minerAddr,
    uint64_t iterations)
{
    CBlock block;
    block.nVersion = CBlockHeader::VDF_VERSION;  // version 4
    block.hashPrevBlock = prevHash;
    block.nBits = 0x1d00ffff;
    block.nTime = 1700000000;
    block.nNonce = 0;

    // 1. Compute VDF challenge and result.
    auto challenge = ComputeVDFChallenge(prevHash, height, minerAddr);

    vdf::VDFConfig cfg;
    cfg.target_iterations = iterations;
    vdf::VDFResult result = vdf::compute(challenge, iterations, cfg);

    // 2. Set header fields.
    std::memcpy(block.vdfOutput.data, result.output.data(), 32);
    block.vdfProofHash = CoinbaseVDF::ComputeProofHash(result.proof);

    // 3. Build coinbase transaction with VDF proof and miner address.
    //    Format: [version(4)][vin_count(1)][prevout(36)][scriptSig_len(varint)][scriptSig][seq(4)]
    //            [vout_count(1)][value(8)][scriptPubKey_len(varint)][scriptPubKey][locktime(4)]
    std::vector<uint8_t> vtxData;

    // Transaction count = 1 (compact size)
    vtxData.push_back(1);

    // --- Coinbase transaction ---
    // nVersion = 1
    int32_t txVersion = 1;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&txVersion),
                   reinterpret_cast<uint8_t*>(&txVersion) + 4);

    // vin count = 1
    vtxData.push_back(1);

    // prevout: null hash (32 zeros) + index 0xFFFFFFFF (coinbase)
    for (int i = 0; i < 32; i++) vtxData.push_back(0);
    uint32_t coinbaseIndex = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&coinbaseIndex),
                   reinterpret_cast<uint8_t*>(&coinbaseIndex) + 4);

    // scriptSig: height bytes + VDF proof
    std::vector<uint8_t> scriptSig;
    // BIP34 height encoding: [push_size] [height_le_bytes]
    scriptSig.push_back(0x03);  // push 3 bytes
    uint32_t h = static_cast<uint32_t>(height);
    scriptSig.push_back(static_cast<uint8_t>(h & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));

    // Embed VDF proof using CoinbaseVDF helper
    CTxIn tempIn;
    tempIn.scriptSig = scriptSig;
    CoinbaseVDF::EmbedProof(tempIn, result.proof);
    scriptSig = tempIn.scriptSig;

    // Write scriptSig length (varint) + data
    if (scriptSig.size() < 253) {
        vtxData.push_back(static_cast<uint8_t>(scriptSig.size()));
    } else {
        vtxData.push_back(253);
        uint16_t len16 = static_cast<uint16_t>(scriptSig.size());
        vtxData.push_back(static_cast<uint8_t>(len16 & 0xFF));
        vtxData.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
    }
    vtxData.insert(vtxData.end(), scriptSig.begin(), scriptSig.end());

    // nSequence
    uint32_t seq = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&seq),
                   reinterpret_cast<uint8_t*>(&seq) + 4);

    // vout count = 1
    vtxData.push_back(1);

    // value = 50 DIL (5000000000 ions)
    uint64_t value = 50ULL * 100000000ULL;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&value),
                   reinterpret_cast<uint8_t*>(&value) + 8);

    // scriptPubKey: P2PKH = OP_DUP(76) OP_HASH160(a9) OP_PUSH20(14) [20 bytes addr] OP_EQUALVERIFY(88) OP_CHECKSIG(ac)
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), minerAddr.begin(), minerAddr.end());
    spk.push_back(0x88);
    spk.push_back(0xac);
    vtxData.push_back(static_cast<uint8_t>(spk.size()));  // scriptPubKey length
    vtxData.insert(vtxData.end(), spk.begin(), spk.end());

    // locktime = 0
    uint32_t locktime = 0;
    vtxData.insert(vtxData.end(),
                   reinterpret_cast<uint8_t*>(&locktime),
                   reinterpret_cast<uint8_t*>(&locktime) + 4);

    block.vtx = vtxData;

    // 4. Build merkle root (SHA3-256 of the single coinbase tx).
    //    The coinbase tx starts at vtxData[1] (after the tx count byte).
    SHA3_256(vtxData.data() + 1, vtxData.size() - 1, block.hashMerkleRoot.data);

    return block;
}

// ---------------------------------------------------------------------------
// LP-10 helper: build a VDF block whose coinbase carries a REAL Dilithium
// registration-MIK signature, plus a real Wesolowski proof. Used to test the
// connect-path MIK-signature wiring (CheckVDFBlockMIKSignature).
// ---------------------------------------------------------------------------
static CBlock MakeVDFBlockWithSignedMIK(
    const uint256& prevHash,
    int height,
    DFMP::CMiningIdentityKey& mik,   // already Generate()'d by caller
    uint64_t iterations)
{
    CBlock block;
    block.nVersion = CBlockHeader::VDF_VERSION;
    block.hashPrevBlock = prevHash;
    block.nBits = 0x1d00ffff;
    block.nTime = 1700000000;
    block.nNonce = 0;

    // Miner payout address = MIK identity bytes (any 20 bytes work for the proof).
    std::array<uint8_t, 20> minerAddr{};
    std::memcpy(minerAddr.data(), mik.identity.data, 20);

    // Real VDF proof.
    auto challenge = ComputeVDFChallenge(prevHash, height, minerAddr);
    vdf::VDFConfig cfg;
    cfg.target_iterations = iterations;
    vdf::VDFResult result = vdf::compute(challenge, iterations, cfg);

    std::memcpy(block.vdfOutput.data, result.output.data(), 32);
    block.vdfProofHash = CoinbaseVDF::ComputeProofHash(result.proof);

    // Real MIK signature over (prevHash, height, nTime).
    std::vector<uint8_t> mikSig;
    bool signedOk = mik.Sign(prevHash, height, block.nTime, mikSig);
    if (!signedOk) {
        // Surface as an obviously-invalid block; the test will fail loudly.
        block.vtx.clear();
        return block;
    }

    // Registration MIK scriptSig data: [0xDF][0x01][pubkey][signature]
    std::vector<uint8_t> mikScriptData;
    DFMP::BuildMIKScriptSigRegistration(mik.pubkey, mikSig, mikScriptData);

    // --- Build coinbase manually (same layout as MakeVDFBlock). ---
    std::vector<uint8_t> vtxData;
    vtxData.push_back(1);  // tx count

    int32_t txVersion = 1;
    vtxData.insert(vtxData.end(), reinterpret_cast<uint8_t*>(&txVersion),
                   reinterpret_cast<uint8_t*>(&txVersion) + 4);
    vtxData.push_back(1);  // vin count
    for (int i = 0; i < 32; i++) vtxData.push_back(0);
    uint32_t coinbaseIndex = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(), reinterpret_cast<uint8_t*>(&coinbaseIndex),
                   reinterpret_cast<uint8_t*>(&coinbaseIndex) + 4);

    // scriptSig: BIP34 height(3) + MIK registration data + VDF proof.
    std::vector<uint8_t> scriptSig;
    scriptSig.push_back(0x03);
    uint32_t h = static_cast<uint32_t>(height);
    scriptSig.push_back(static_cast<uint8_t>(h & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 8) & 0xFF));
    scriptSig.push_back(static_cast<uint8_t>((h >> 16) & 0xFF));
    scriptSig.insert(scriptSig.end(), mikScriptData.begin(), mikScriptData.end());

    CTxIn tempIn;
    tempIn.scriptSig = scriptSig;
    CoinbaseVDF::EmbedProof(tempIn, result.proof);
    scriptSig = tempIn.scriptSig;

    // scriptSig length (varint — this is > 253, so 0xFD + 2 LE bytes).
    if (scriptSig.size() < 253) {
        vtxData.push_back(static_cast<uint8_t>(scriptSig.size()));
    } else {
        vtxData.push_back(253);
        uint16_t len16 = static_cast<uint16_t>(scriptSig.size());
        vtxData.push_back(static_cast<uint8_t>(len16 & 0xFF));
        vtxData.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
    }
    vtxData.insert(vtxData.end(), scriptSig.begin(), scriptSig.end());

    uint32_t seq = 0xFFFFFFFF;
    vtxData.insert(vtxData.end(), reinterpret_cast<uint8_t*>(&seq),
                   reinterpret_cast<uint8_t*>(&seq) + 4);

    vtxData.push_back(1);  // vout count
    uint64_t value = 50ULL * 100000000ULL;
    vtxData.insert(vtxData.end(), reinterpret_cast<uint8_t*>(&value),
                   reinterpret_cast<uint8_t*>(&value) + 8);

    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), minerAddr.begin(), minerAddr.end());
    spk.push_back(0x88);
    spk.push_back(0xac);
    vtxData.push_back(static_cast<uint8_t>(spk.size()));
    vtxData.insert(vtxData.end(), spk.begin(), spk.end());

    uint32_t locktime = 0;
    vtxData.insert(vtxData.end(), reinterpret_cast<uint8_t*>(&locktime),
                   reinterpret_cast<uint8_t*>(&locktime) + 4);

    block.vtx = vtxData;
    SHA3_256(vtxData.data() + 1, vtxData.size() - 1, block.hashMerkleRoot.data);
    return block;
}

// LP-10: install a DilV-like chainparams with a known VDF iteration count and
// a controllable proof-enforcement activation height.
static void InstallLP10ChainParams(uint64_t vdfIters, int enforcementHeight)
{
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::DilV());
    }
    Dilithion::g_chainParams->vdfIterations = vdfIters;
    Dilithion::g_chainParams->vdfProofEnforcementHeight = enforcementHeight;
}

// ---------------------------------------------------------------------------

static void test_challenge_deterministic()
{
    TEST(challenge_deterministic);
    uint256 prevHash;
    prevHash.data[0] = 0xAB;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto c1 = ComputeVDFChallenge(prevHash, 100, addr);
    auto c2 = ComputeVDFChallenge(prevHash, 100, addr);
    CHECK(c1 == c2);
    PASS();
}

static void test_challenge_varies_with_height()
{
    TEST(challenge_varies_with_height);
    uint256 prevHash;
    prevHash.data[0] = 0xAB;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    auto c1 = ComputeVDFChallenge(prevHash, 100, addr);
    auto c2 = ComputeVDFChallenge(prevHash, 101, addr);
    CHECK(c1 != c2);
    PASS();
}

static void test_challenge_varies_with_address()
{
    TEST(challenge_varies_with_address);
    uint256 prevHash;
    prevHash.data[0] = 0xAB;
    std::array<uint8_t, 20> a1{}, a2{};
    a1[0] = 0x01;
    a2[0] = 0x02;

    auto c1 = ComputeVDFChallenge(prevHash, 100, a1);
    auto c2 = ComputeVDFChallenge(prevHash, 100, a2);
    CHECK(c1 != c2);
    PASS();
}

static void test_valid_vdf_block_accepted()
{
    TEST(valid_vdf_block_accepted);
    uint256 prevHash;
    prevHash.data[0] = 0xDE;
    prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    // Use small iteration count for fast test.
    uint64_t iters = 1000;
    CBlock block = MakeVDFBlock(prevHash, 500, addr, iters);

    std::string error;
    bool ok = CheckVDFProof(block, 500, prevHash, iters, error);
    if (!ok) {
        std::cout << "FAIL: " << error << "\n";
        ++failed;
        return;
    }
    CHECK(ok);
    PASS();
}

static void test_wrong_iterations_rejected()
{
    TEST(wrong_iterations_rejected);
    uint256 prevHash;
    prevHash.data[0] = 0xDE;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    uint64_t iters = 1000;
    CBlock block = MakeVDFBlock(prevHash, 500, addr, iters);

    // Verify with wrong iteration count.
    std::string error;
    bool ok = CheckVDFProof(block, 500, prevHash, iters + 1000, error);
    CHECK(!ok);
    PASS();
}

static void test_missing_proof_rejected()
{
    TEST(missing_proof_rejected);
    CBlock block;
    block.nVersion = CBlockHeader::VDF_VERSION;
    block.nBits = 0x1d00ffff;
    block.vdfOutput.data[0] = 0xFF;
    block.vdfProofHash.data[0] = 0xFF;
    // Empty vtx — no coinbase
    block.vtx.clear();

    std::string error;
    bool ok = CheckVDFProof(block, 100, uint256(), 1000, error);
    CHECK(!ok);
    PASS();
}

static void test_null_vdf_output_rejected()
{
    TEST(null_vdf_output_rejected);
    CBlock block;
    block.nVersion = CBlockHeader::VDF_VERSION;
    block.nBits = 0x1d00ffff;
    // vdfOutput is null

    std::string error;
    bool ok = CheckVDFProof(block, 100, uint256(), 1000, error);
    CHECK(!ok);
    PASS();
}

static void test_tampered_proof_hash_rejected()
{
    TEST(tampered_proof_hash_rejected);
    uint256 prevHash;
    prevHash.data[0] = 0xDE;
    std::array<uint8_t, 20> addr{};
    addr[0] = 0x42;

    CBlock block = MakeVDFBlock(prevHash, 500, addr, 1000);

    // Tamper with proof hash
    block.vdfProofHash.data[0] ^= 0xFF;

    std::string error;
    bool ok = CheckVDFProof(block, 500, prevHash, 1000, error);
    CHECK(!ok);
    PASS();
}

// ===========================================================================
// LP-10 connect-path wiring tests
// ===========================================================================

// POSITIVE (load-bearing): an honestly-mined VDF block PASSES the gated
// connect-path proof check at a height AT/ABOVE the activation height.
// This proves the new wiring does NOT reject honest blocks.
static void test_lp10_honest_block_accepted_above_activation()
{
    TEST(lp10_honest_block_accepted_above_activation);
    const uint64_t iters = 1000;
    const int activation = 100;
    const int height = 200;   // >= activation
    InstallLP10ChainParams(iters, activation);

    uint256 prevHash; prevHash.data[0] = 0xDE; prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{}; addr[0] = 0x42;
    CBlock block = MakeVDFBlock(prevHash, height, addr, iters);

    std::string error;
    bool ok = CheckVDFProofConnect(block, height, prevHash, error);
    if (!ok) { std::cout << "FAIL: honest block rejected: " << error << "\n"; ++failed; return; }
    CHECK(ok);
    PASS();
}

// NEGATIVE: a forged (corrupted output) VDF block is REJECTED at/above activation.
static void test_lp10_forged_proof_rejected_above_activation()
{
    TEST(lp10_forged_proof_rejected_above_activation);
    const uint64_t iters = 1000;
    const int activation = 100;
    const int height = 200;
    InstallLP10ChainParams(iters, activation);

    uint256 prevHash; prevHash.data[0] = 0xDE; prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{}; addr[0] = 0x42;
    CBlock block = MakeVDFBlock(prevHash, height, addr, iters);

    // Corrupt one byte of the VDF output (attacker-set lowest-output grind).
    block.vdfOutput.data[0] ^= 0x01;

    std::string error;
    bool ok = CheckVDFProofConnect(block, height, prevHash, error);
    CHECK(!ok);   // must be rejected
    PASS();
}

// GRANDFATHER: the SAME forged block is ACCEPTED BELOW the activation height.
static void test_lp10_forged_proof_accepted_below_activation()
{
    TEST(lp10_forged_proof_accepted_below_activation);
    const uint64_t iters = 1000;
    const int activation = 1000;
    const int height = 200;   // < activation -> grandfathered
    InstallLP10ChainParams(iters, activation);

    uint256 prevHash; prevHash.data[0] = 0xDE; prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{}; addr[0] = 0x42;
    CBlock block = MakeVDFBlock(prevHash, height, addr, iters);
    block.vdfOutput.data[0] ^= 0x01;   // forged

    std::string error;
    bool ok = CheckVDFProofConnect(block, height, prevHash, error);
    CHECK(ok);   // below activation: grandfathered, accepted
    PASS();
}

// SENTINEL: with enforcement OFF (sentinel 999999999), even a forged block at a
// realistic height is accepted (build ships safe).
static void test_lp10_disabled_sentinel_accepts_forged()
{
    TEST(lp10_disabled_sentinel_accepts_forged);
    const uint64_t iters = 1000;
    InstallLP10ChainParams(iters, 999999999);  // OFF

    uint256 prevHash; prevHash.data[0] = 0xDE; prevHash.data[1] = 0xAD;
    std::array<uint8_t, 20> addr{}; addr[0] = 0x42;
    CBlock block = MakeVDFBlock(prevHash, 50000, addr, iters);
    block.vdfOutput.data[0] ^= 0x01;

    std::string error;
    bool ok = CheckVDFProofConnect(block, 50000, prevHash, error);
    CHECK(ok);
    PASS();
}

// POSITIVE (MIK): an honestly-signed registration-MIK VDF block PASSES the
// gated connect-path MIK-signature check at/above activation.
static void test_lp10_honest_mik_signature_accepted_above_activation()
{
    TEST(lp10_honest_mik_signature_accepted_above_activation);
    const uint64_t iters = 1000;
    const int activation = 100;
    const int height = 200;
    InstallLP10ChainParams(iters, activation);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }

    uint256 prevHash; prevHash.data[0] = 0xBE; prevHash.data[1] = 0xEF;
    CBlock block = MakeVDFBlockWithSignedMIK(prevHash, height, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    std::string error;
    bool ok = CheckVDFBlockMIKSignature(block, height, error);
    if (!ok) { std::cout << "FAIL: honest MIK sig rejected: " << error << "\n"; ++failed; return; }
    CHECK(ok);
    PASS();
}

// NEGATIVE (MIK): a corrupted MIK signature is REJECTED at/above activation,
// and the same block is ACCEPTED below activation (grandfathered).
static void test_lp10_forged_mik_signature_rejected_above_accepted_below()
{
    TEST(lp10_forged_mik_signature_rejected_above_accepted_below);
    const uint64_t iters = 1000;

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }

    uint256 prevHash; prevHash.data[0] = 0xBE; prevHash.data[1] = 0xEF;
    const int height = 200;
    CBlock block = MakeVDFBlockWithSignedMIK(prevHash, height, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    // Corrupt one byte of the MIK signature inside the coinbase scriptSig.
    // The signature is the last 3309 bytes before the VDF-proof marker; flip a
    // byte well inside the MIK data region. Robust approach: re-parse, flip in
    // the raw vtx by locating the MIK marker.
    bool flipped = false;
    for (size_t i = 0; i + 1 < block.vtx.size(); ++i) {
        if (block.vtx[i] == DFMP::MIK_MARKER &&
            block.vtx[i + 1] == DFMP::MIK_TYPE_REGISTRATION) {
            // pubkey(1952) starts at i+2; signature(3309) starts at i+2+1952.
            size_t sigStart = i + 2 + DFMP::MIK_PUBKEY_SIZE;
            if (sigStart + 100 < block.vtx.size()) {
                block.vtx[sigStart + 50] ^= 0xFF;  // corrupt the signature
                flipped = true;
            }
            break;
        }
    }
    if (!flipped) { std::cout << "FAIL: could not locate MIK sig to corrupt\n"; ++failed; return; }
    // Merkle root no longer matters for this isolated check.

    // Above activation: rejected.
    InstallLP10ChainParams(iters, 100);
    std::string error;
    bool okAbove = CheckVDFBlockMIKSignature(block, height, error);
    if (okAbove) { std::cout << "FAIL: forged MIK sig accepted above activation\n"; ++failed; return; }

    // Below activation: grandfathered, accepted.
    InstallLP10ChainParams(iters, 1000);
    std::string error2;
    bool okBelow = CheckVDFBlockMIKSignature(block, height, error2);
    if (!okBelow) { std::cout << "FAIL: forged MIK sig rejected below activation: " << error2 << "\n"; ++failed; return; }

    PASS();
}

// ===========================================================================
// LP-10 ConnectTip INTEGRATION tests
//
// WHY THESE EXIST, stated precisely. The six LP-10 tests above call
// CheckVDFProofConnect / CheckVDFBlockMIKSignature DIRECTLY. They prove the
// CHECKERS work. They do not prove that anything CALLS them -- and that gap is
// the exact shape of the defect LP-10 was written to fix. Before LP-10 the VDF
// verifier existed and was correct; several comments on the production connect
// path deferred to it; and its only caller was CBlockValidator::CheckBlock,
// which the source itself labels dead code with zero callers. A correct
// checker that nothing invokes is, from the chain's point of view,
// indistinguishable from no checker at all.
//
// So these tests call the REAL production CChainState::ConnectTip and assert
// on its return value -- on BOTH the normal path and the skipValidation=true
// reorg-reconnect path that ConnectTip's LP-10 comment claims to cover. That
// comment is treated here as an unverified claim, not as documentation.
//
// ATTRIBUTION -- how these avoid passing for the wrong reason. ConnectTip runs
// roughly ten other rejection sites before it reaches the LP-10 block, so a
// test that merely asserted "forged block rejected" would be over-determined:
// any of them could be the one rejecting, and the test would stay green if the
// LP-10 wiring were deleted tomorrow. Three devices close that:
//
//   (a) A DISCRIMINATING control (connecttip_forged_proof_accepted_below_
//       enforcement). The SAME forged block runs through the SAME fixture, at
//       the SAME height, on the SAME path, with ONLY vdfProofEnforcementHeight
//       moved above the block -- and must be ACCEPTED. No other check in
//       ConnectTip reads that field. If any of them were doing the rejecting,
//       this control would fail.
//   (b) A POSITIVE control (connecttip_honest_vdf_block_accepted_both_paths):
//       an honest block must be ACCEPTED through the whole of ConnectTip,
//       proving the forged cases reach the LP-10 block rather than dying early.
//   (c) BLOCK_FAILED_VALID, asserted set on rejection and clear on acceptance.
//
// EVERY case uses MakeVDFBlockWithSignedMIK, never MakeVDFBlock. ConnectTip
// runs BOTH LP-10 checks, and a MakeVDFBlock coinbase carries no MIK data at
// all, so it fails CheckVDFBlockMIKSignature's parse whenever enforcement is
// active. Building the proof cases on the bare helper would have made the
// honest positive control fail and every negative case pass for the wrong
// reason.
// ===========================================================================

// Height used by every ConnectTip case. 200 sits below DilV's
// seedAttestationActivationHeight (2000), so CheckMIKAttestations is inert.
static const int kCTHeight = 200;

// Install DilV-shaped chainparams for the ConnectTip cases.
//
// Deliberately NOT a neutralised fixture: dfmpActivationHeight defaults to
// DilV's shipped 0, so CheckProofOfWorkDFMP really does run on the
// !skipValidation path (it early-returns true for VDF blocks at/above
// vdfActivationHeight, which DilV also ships as 0). The only cases that move
// it are the ones that must present a NON-VDF block, where that early return
// no longer applies. Every field this fixture depends on is set explicitly on
// every call, so no case can inherit another case's overrides.
static void InstallConnectTipChainParams(uint64_t vdfIters, int enforcementHeight,
                                         int assumeValidHeight, int dfmpActivationHeight = 0)
{
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(Dilithion::ChainParams::DilV());
    }
    Dilithion::g_chainParams->vdfIterations             = vdfIters;
    Dilithion::g_chainParams->vdfProofEnforcementHeight = enforcementHeight;
    Dilithion::g_chainParams->dfmpAssumeValidHeight     = assumeValidHeight;
    Dilithion::g_chainParams->dfmpActivationHeight      = dfmpActivationHeight;
}

// Run the REAL production CChainState::ConnectTip. A default-constructed
// CChainState leaves pdb / pUTXOSet / pMemPool all nullptr, and every DB,
// UTXO and mempool step inside ConnectTip is guarded on those being non-null,
// so this exercises the validation spine and nothing else.
static bool RunConnectTip(const CBlock& block, int height, bool skipValidation,
                          bool* outMarkedFailedValid, CUTXOSet* utxo = nullptr)
{
    CChainState chain;
    if (utxo != nullptr) {
        chain.SetUTXOSet(utxo);
    }
    CBlockIndex idx;
    idx.nHeight  = height;
    idx.nTime    = block.nTime;
    idx.nBits    = block.nBits;
    // nVersion is set for realism only. ConnectTip branches on
    // block.IsVDFBlock(), never on pindex->nVersion -- do not read this field
    // as the mechanism under test in the non-VDF case below.
    idx.nVersion = block.nVersion;
    // GetBlockHash() does not compute -- it logs an error and returns a null
    // hash unless phashBlock was set explicitly. ConnectTip calls it on entry.
    idx.phashBlock.data[0]  = 0xC0;
    idx.phashBlock.data[1]  = static_cast<uint8_t>(height & 0xFF);
    idx.phashBlock.data[31] = 0x01;

    bool ok = chain.ConnectTip(&idx, block, skipValidation);
    if (outMarkedFailedValid != nullptr) {
        *outMarkedFailedValid = (idx.nStatus & CBlockIndex::BLOCK_FAILED_VALID) != 0;
    }
    return ok;
}

static uint256 CTPrevHash()
{
    uint256 h;
    h.data[0] = 0xBE;
    h.data[1] = 0xEF;
    return h;
}

// NOTE, load-bearing: every ConnectTip case here uses a REGISTRATION MIK.
// CheckVDFBlockMIKSignature fails OPEN for a REFERENCE MIK whose pubkey cannot
// be resolved (vdf_validation.cpp:309-315 -- g_identityDb is always null in
// this binary), so a reference-MIK block would be ACCEPTED however corrupt its
// signature. If you add a ConnectTip case built on a reference MIK, the
// forged-signature assertions below go vacuous rather than failing loudly.
// That fail-open branch is the one that runs during multi-block reorg undo and
// it has NO coverage here -- see the scope note at the bottom of this file.
//
// Corrupt the Dilithium signature inside the coinbase registration-MIK blob,
// then RE-COMMIT the merkle root. ConnectTip runs LP-4's merkle recompute
// before it reaches LP-10, so a forgery that left the header root stale would
// be rejected by the merkle check and the test would pass for the wrong
// reason. A real attacker forging a signature would re-commit too -- the
// header root is theirs to set.
static bool ForgeMIKSignatureInPlace(CBlock& block)
{
    // Locate the MIK blob by LAYOUT, not by scanning for a byte pair.
    //
    // A scan was tried and measured FLAKY at ~10% (4 failures in 40 runs): the
    // 1952-byte Dilithium pubkey and 3309-byte signature are effectively random,
    // so a second [0xDF][0x01] pair occurs inside them with probability
    // ~5261/65536 per block. Requiring exactly one occurrence therefore failed
    // at random across keypairs; taking the first occurrence is correct but
    // rests on an unstated assumption. Deriving the offset from the coinbase
    // layout is both deterministic and a stronger assertion -- it pins the
    // layout itself, so a change to the coinbase shape fails here loudly rather
    // than silently moving the byte this function corrupts.
    //
    // vtx layout, from MakeVDFBlockWithSignedMIK above:
    //   [0]      transaction count      (1)
    //   [1..4]   nVersion               (4)
    //   [5]      vin count              (1)
    //   [6..37]  prevout hash           (32)
    //   [38..41] prevout index          (4)
    //   [42..44] scriptSig length       (3: 0xFD + u16, the proof makes it >253)
    //   [45..48] BIP34 height push      (4: 0x03 + 3 height bytes)
    //   [49]     MIK marker             <- here
    const size_t at = 1 + 4 + 1 + 32 + 4 + 3 + 4;
    if (at + 1 >= block.vtx.size() ||
        block.vtx[at] != DFMP::MIK_MARKER ||
        block.vtx[at + 1] != DFMP::MIK_TYPE_REGISTRATION) {
        std::cout << "(no MIK registration marker at the layout offset " << at
                  << " -- the coinbase layout changed) ";
        return false;
    }
    // Layout: [0xDF][0x01][pubkey MIK_PUBKEY_SIZE][signature MIK_SIGNATURE_SIZE].
    const size_t sigStart = at + 2 + DFMP::MIK_PUBKEY_SIZE;
    const size_t flipAt   = sigStart + 50;
    if (sigStart + DFMP::MIK_SIGNATURE_SIZE > block.vtx.size() ||
        flipAt >= sigStart + DFMP::MIK_SIGNATURE_SIZE) {
        std::cout << "(MIK signature does not fit where the layout says) ";
        return false;
    }
    block.vtx[flipAt] ^= 0xFF;
    // Re-commit: LP-4's merkle recompute runs BEFORE LP-10 in ConnectTip, so a
    // forgery that left the header root stale would be rejected by the merkle
    // check and the test would pass for entirely the wrong reason. A real
    // attacker re-commits too -- the header root is theirs to set.
    SHA3_256(block.vtx.data() + 1, block.vtx.size() - 1, block.hashMerkleRoot.data);
    return true;
}

// POSITIVE CONTROL. An honest VDF block must be ACCEPTED through the entire of
// ConnectTip, on both paths, at a height at/above the enforcement height.
// Without this, every negative case below could be green merely because
// ConnectTip rejects everything handed to it.
static void test_connecttip_honest_vdf_block_accepted_both_paths()
{
    TEST(connecttip_honest_vdf_block_accepted_both_paths);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, /*skipValidation=*/false, &flagged)) {
        std::cout << "FAIL: honest block REJECTED by ConnectTip (skipValidation=false)\n";
        ++failed; return;
    }
    CHECK(!flagged);

    flagged = true;
    if (!RunConnectTip(block, kCTHeight, /*skipValidation=*/true, &flagged)) {
        std::cout << "FAIL: honest block REJECTED by ConnectTip (skipValidation=true)\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// THE REGRESSION TEST. A forged VDF proof must be rejected BY ConnectTip
// itself on the normal connect path, and the block marked BLOCK_FAILED_VALID.
static void test_connecttip_forged_proof_rejected_normal_path()
{
    TEST(connecttip_forged_proof_rejected_normal_path);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    // Attacker-ground output: the header no longer matches the proof. A header
    // field, so the merkle commitment is untouched and LP-4 cannot be the one
    // rejecting this block.
    block.vdfOutput.data[0] ^= 0x01;

    bool flagged = false;
    bool ok = RunConnectTip(block, kCTHeight, /*skipValidation=*/false, &flagged);
    CHECK(!ok);
    CHECK(flagged);   // the LP-10 branch marks the index BLOCK_FAILED_VALID
    PASS();
}

// THE CLAIM THE COMMENT MAKES AND NOTHING TESTED. ConnectTip's LP-10 comment
// states the checks "run for ALL connect paths INCLUDING skipValidation=true
// reorg reconnects", on the reasoning that VDF block selection is effectively
// a reorg every block. Three of ConnectTip's production call sites pass
// skipValidation=true. If the LP-10 block were ever moved inside the
// !skipValidation gate -- where the attestation and DNA checks used to live,
// and from which BUG #281 had to rescue them -- a forged block would reach the
// UTXO set through the reorg path. This is the test for that.
static void test_connecttip_forged_proof_rejected_on_reorg_path()
{
    TEST(connecttip_forged_proof_rejected_on_reorg_path);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    block.vdfOutput.data[0] ^= 0x01;

    bool flagged = false;
    bool ok = RunConnectTip(block, kCTHeight, /*skipValidation=*/true, &flagged);
    CHECK(!ok);
    CHECK(flagged);
    PASS();
}

// THE DISCRIMINATING CONTROL. Byte-for-byte the same forged block, the same
// height, both the same paths -- with ONLY vdfProofEnforcementHeight moved
// above the block. It must be ACCEPTED. No other check in ConnectTip reads
// that field, so this is what makes the two rejections above attributable to
// the LP-10 wiring rather than to any of the ~10 earlier rejection sites.
static void test_connecttip_forged_proof_accepted_below_enforcement()
{
    TEST(connecttip_forged_proof_accepted_below_enforcement);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/1000, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    block.vdfOutput.data[0] ^= 0x01;   // identical forgery to the two cases above

    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, /*skipValidation=*/false, &flagged)) {
        std::cout << "FAIL: forged block rejected BELOW enforcement -- the rejections "
                     "above are NOT attributable to the LP-10 gate\n";
        ++failed; return;
    }
    CHECK(!flagged);

    flagged = true;
    if (!RunConnectTip(block, kCTHeight, /*skipValidation=*/true, &flagged)) {
        std::cout << "FAIL: forged block rejected BELOW enforcement on reorg path\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// TODAY'S PRODUCTION STATE. With the shipped sentinel (999999999) nothing is
// enforced on either path. This pins the deployed behaviour, so that the day
// someone sets a real height, the diff to this test is the visible record of
// what changed.
static void test_connecttip_sentinel_accepts_forged_both_paths()
{
    TEST(connecttip_sentinel_accepts_forged_both_paths);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/999999999, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    block.vdfOutput.data[0] ^= 0x01;

    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: sentinel build rejected a forged block (normal path)\n";
        ++failed; return;
    }
    CHECK(!flagged);

    flagged = true;
    if (!RunConnectTip(block, kCTHeight, true, &flagged)) {
        std::cout << "FAIL: sentinel build rejected a forged block (reorg path)\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// NO ASSUME-VALID EXEMPTION. The LP-10 block sits below ConnectTip's
// assumeValid computation and deliberately does not consult it -- unlike
// attestation, DNA and the cooldown checks, which all skip when assumeValid is
// true. DilV ships dfmpAssumeValidHeight = 44233, so a block at height 200 is
// assume-valid in production shape. A forged proof must STILL be rejected.
static void test_connecttip_forged_proof_rejected_despite_assume_valid()
{
    TEST(connecttip_forged_proof_rejected_despite_assume_valid);
    const uint64_t iters = 1000;
    // 44233 is DilV's shipped dfmpAssumeValidHeight; kCTHeight (200) is at or
    // below it, so assumeValid is TRUE for this block.
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/44233);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock honest = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (honest.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    // Positive control under the SAME assume-valid fixture.
    bool flagged = true;
    if (!RunConnectTip(honest, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: honest block rejected under the assume-valid fixture\n";
        ++failed; return;
    }

    CBlock forged = honest;
    forged.vdfOutput.data[0] ^= 0x01;

    flagged = false;
    bool ok = RunConnectTip(forged, kCTHeight, false, &flagged);
    CHECK(!ok);
    CHECK(flagged);

    flagged = false;
    ok = RunConnectTip(forged, kCTHeight, true, &flagged);
    CHECK(!ok);
    CHECK(flagged);
    PASS();
}

// The MIK-signature half of the LP-10 wiring, through ConnectTip, on both
// paths, with its own discriminating control.
static void test_connecttip_forged_mik_signature_rejected_both_paths()
{
    TEST(connecttip_forged_mik_signature_rejected_both_paths);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    // Positive control: the honestly-signed block must connect.
    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: honestly-signed MIK block rejected by ConnectTip\n";
        ++failed; return;
    }

    if (!ForgeMIKSignatureInPlace(block)) {
        std::cout << "FAIL: could not locate the MIK signature to corrupt\n";
        ++failed; return;
    }

    flagged = false;
    bool ok = RunConnectTip(block, kCTHeight, false, &flagged);
    CHECK(!ok);
    CHECK(flagged);

    flagged = false;
    ok = RunConnectTip(block, kCTHeight, true, &flagged);
    CHECK(!ok);
    CHECK(flagged);

    // Discriminating control: same corrupted block, enforcement moved above it.
    // If the merkle re-commit above were wrong, or any earlier check were the
    // one rejecting, this would fail rather than silently validating nothing.
    InstallConnectTipChainParams(iters, /*enforcement=*/1000, /*assumeValid=*/0);
    flagged = true;
    if (!RunConnectTip(block, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: corrupted-MIK block rejected BELOW enforcement -- the "
                     "rejection is not attributable to the LP-10 gate\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// A non-VDF block (nVersion < VDF_VERSION) must not be subjected to the VDF
// checks at all, however broken its VDF header fields are -- otherwise a chain
// of legacy blocks would be rejected wholesale.
//
// ⚠️ WHAT THIS CASE DOES **NOT** DO, corrected after review: it does not pin
// IsVDFBlock() as the entry condition, and cannot. The gate is duplicated at
// THREE sites -- the caller (chain.cpp:1834) and both callees
// (vdf_validation.cpp:224 and :258, each `if (!block.IsVDFBlock()) return
// true;`). Widening the caller gate to `if (true)` leaves this case GREEN,
// because the callees still exempt the block. The exemption is defended in
// depth and this case asserts the OUTCOME of all three together, not any one
// of them. Do not cite it as mutation coverage of the caller's gate.
//
// dfmpActivationHeight is moved out of range for this case ONLY: DilV ships it
// at 0, and CheckProofOfWorkDFMP's early return for VDF blocks no longer
// applies once nVersion drops below VDF_VERSION, so it would otherwise reject
// this block for a reason that has nothing to do with the gate under test.
static void test_connecttip_non_vdf_block_not_subject_to_vdf_checks()
{
    TEST(connecttip_non_vdf_block_not_subject_to_vdf_checks);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0,
                                 /*dfmpActivationHeight=*/1000000);

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }

    block.vdfOutput.data[0] ^= 0x01;                    // would fail if checked
    block.nVersion = CBlockHeader::VDF_VERSION - 1;     // ...but it is not a VDF block

    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: non-VDF block rejected by the VDF wiring\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// ⛔ MEDIUM-3 (red-team, folded): THE ACTIVATION BOUNDARY ITSELF.
//
// The gate is `if (height < enforcementHeight) return true;` -- vdf_validation.cpp:218
// for the proof and :252 for the MIK signature. Every other case in this file
// sits STRICTLY above or STRICTLY below the enforcement height, so the exact
// fork edge was untested on both checkers: flipping `<` to `<=` is a ONE-BLOCK
// consensus split between upgraded and non-upgraded nodes, and it left this
// entire suite green.
//
// vdfProofEnforcementHeight is a scheduled hard fork whose number is still
// unpinned. An off-by-one at the activation edge is exactly the class of defect
// that cannot be found once it is live. ONE block is used for both halves, with
// only the enforcement height moved across it, so the two verdicts differ in
// nothing but the comparison under test.
static void test_connecttip_enforcement_boundary_is_exact()
{
    TEST(connecttip_enforcement_boundary_is_exact);
    const uint64_t iters = 1000;

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    CBlock forged = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (forged.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    forged.vdfOutput.data[0] ^= 0x01;

    // height == enforcement - 1  ->  strictly below  ->  GRANDFATHERED.
    InstallConnectTipChainParams(iters, /*enforcement=*/kCTHeight + 1, /*assumeValid=*/0);
    bool flagged = true;
    if (!RunConnectTip(forged, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: rejected at height == enforcement-1; the gate is too eager "
                     "by one block (`<` may have become `<=`)\n";
        ++failed; return;
    }
    CHECK(!flagged);

    // height == enforcement  ->  the FIRST enforced block  ->  REJECTED.
    InstallConnectTipChainParams(iters, /*enforcement=*/kCTHeight, /*assumeValid=*/0);
    flagged = false;
    bool ok = RunConnectTip(forged, kCTHeight, false, &flagged);
    if (ok) {
        std::cout << "FAIL: accepted at height == enforcement; the fork's FIRST block is "
                     "unenforced (`<` may have become `<=`)\n";
        ++failed; return;
    }
    CHECK(!ok);
    CHECK(flagged);

    // Same boundary, same block, on the reorg path.
    flagged = false;
    ok = RunConnectTip(forged, kCTHeight, true, &flagged);
    CHECK(!ok);
    CHECK(flagged);

    // And the MIK-signature checker has its own copy of the same comparison
    // (vdf_validation.cpp:252), so it needs its own boundary case.
    CBlock mikForged = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
    if (mikForged.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    if (!ForgeMIKSignatureInPlace(mikForged)) {
        std::cout << "FAIL: could not locate the MIK signature to corrupt\n";
        ++failed; return;
    }

    InstallConnectTipChainParams(iters, /*enforcement=*/kCTHeight + 1, /*assumeValid=*/0);
    flagged = true;
    if (!RunConnectTip(mikForged, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: MIK gate rejected at height == enforcement-1\n";
        ++failed; return;
    }
    CHECK(!flagged);

    InstallConnectTipChainParams(iters, /*enforcement=*/kCTHeight, /*assumeValid=*/0);
    flagged = false;
    ok = RunConnectTip(mikForged, kCTHeight, false, &flagged);
    if (ok) {
        std::cout << "FAIL: MIK gate accepted at height == enforcement\n";
        ++failed; return;
    }
    CHECK(!ok);
    CHECK(flagged);
    PASS();
}

// ⛔ MEDIUM-2 (red-team, folded): "Runs BEFORE ApplyBlock so a forged block
// never mutates the UTXO set" -- chain.cpp:1832-1833.
//
// That ordering IS the security content of where LP-10 sits. Rejecting late
// still returns false, but a forged block would already have hit the UTXO set.
// Every other case here runs with pUTXOSet == nullptr, so ApplyBlock is a
// no-op and the ordering is invisible: moving the whole LP-10 block BELOW
// ApplyBlock leaves them all green, because order is not observable through a
// return value.
//
// This case gives the harness a REAL CUTXOSet on a temp directory so the
// ordering becomes observable. The honest half is not decoration -- it is what
// stops the forged assertion being vacuous: if ApplyBlock never worked in this
// harness at all, "the UTXO set did not grow" would be trivially true and
// would prove nothing.
static void test_connecttip_forged_block_never_reaches_the_utxo_set()
{
    TEST(connecttip_forged_block_never_reaches_the_utxo_set);
    const uint64_t iters = 1000;
    InstallConnectTipChainParams(iters, /*enforcement=*/100, /*assumeValid=*/0);

    std::random_device rd;
    std::ostringstream oss;
    oss << "dilithion-lp10-connecttip-utxo-" << rd();
    std::filesystem::path dir = std::filesystem::temp_directory_path() / oss.str();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);

    {
        CUTXOSet utxo;
        if (!utxo.Open(dir.string(), true)) {
            std::cout << "FAIL: could not open a temp UTXO set\n";
            ++failed;
            std::filesystem::remove_all(dir, ec);
            return;
        }

        DFMP::CMiningIdentityKey mik;
        if (!mik.Generate()) {
            std::cout << "FAIL: MIK generate\n"; ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }

        // POSITIVE CONTROL -- proves the observable actually moves.
        CBlock honest = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
        if (honest.vtx.empty()) {
            std::cout << "FAIL: block build/sign\n"; ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }
        const uint64_t before = utxo.GetUTXOCount();
        if (!RunConnectTip(honest, kCTHeight, false, nullptr, &utxo)) {
            std::cout << "FAIL: honest block rejected with a real UTXO set attached\n";
            ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }
        const uint64_t afterHonest = utxo.GetUTXOCount();
        if (afterHonest <= before) {
            std::cout << "FAIL: the honest block did not grow the UTXO set -- this "
                         "observable is inert, so the forged assertion below would be "
                         "vacuous\n";
            ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }

        // THE ASSERTION: a forged block is rejected AND leaves the set untouched.
        CBlock forged = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, iters);
        if (forged.vtx.empty()) {
            std::cout << "FAIL: block build/sign\n"; ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }
        forged.vdfOutput.data[0] ^= 0x01;

        bool flagged = false;
        bool ok = RunConnectTip(forged, kCTHeight, false, &flagged, &utxo);
        if (ok) {
            std::cout << "FAIL: forged block accepted with a real UTXO set attached\n";
            ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }
        if (utxo.GetUTXOCount() != afterHonest) {
            std::cout << "FAIL: a REJECTED forged block still mutated the UTXO set -- "
                         "the LP-10 checks are running AFTER ApplyBlock\n";
            ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }

        // Same, on the reorg path.
        ok = RunConnectTip(forged, kCTHeight, true, &flagged, &utxo);
        if (ok || utxo.GetUTXOCount() != afterHonest) {
            std::cout << "FAIL: forged block mutated the UTXO set on the reorg path\n";
            ++failed;
            utxo.Close(); std::filesystem::remove_all(dir, ec); return;
        }

        utxo.Close();
    }
    std::filesystem::remove_all(dir, ec);
    PASS();
}

// MERGE GUARD — the fail-open hazard, made loud.
//
// Two lineages currently carry two DIFFERENT implementations of this same
// consensus check, with OPPOSITE defaults:
//
//   * this one (LP-10, on main): the checks are wired into ConnectTip but
//     gated by vdfProofEnforcementHeight, shipped OFF at the 999999999
//     sentinel on all four networks — so nothing is enforced today;
//   * an earlier one (cb38afa7, shipped in v4.5.1/v4.5.2, and NOT an ancestor
//     of main): verifies unconditionally by default — so it IS enforcing on
//     the branches that carry it.
//
// Reconciling those two branches means choosing which gate survives. If the
// sentinel wins, a live CRITICAL fix is silently disabled: the merge is
// textually clean, the semantics invert, and it fails OPEN. Neither lineage's
// own suite can catch that, because each is written to its own gate's
// contract — main's tests assert that a forged block IS accepted below the
// activation height, which is precisely the assertion that would keep passing
// while enforcement disappeared.
//
// This case pins the SHIPPED default on every network, and the runtime
// behaviour that follows from it, so that the enforcement state of the chain
// is something a test asserts rather than a constant nobody reads.
//
// ⚠️ IT IS ONE-DIRECTIONAL, corrected after review. It goes RED when
// enforcement APPEARS. It does NOT catch the fail-open direction named above:
// if the sentinel wins the merge and cb38afa7's always-on verification is
// dropped, the resulting state is identical to today and this case stays
// GREEN -- as does the whole suite, which is written to main's gate. Do not
// treat this as a safety net for the merge itself. **The fail-open direction
// is covered by human review at merge time and by nothing else in this file.**
// Catching it mechanically needs the assertion run against the MERGED tree,
// where "a forged DilV v4 block must not connect at shipped defaults" is the
// property, and that is the inverse of what is asserted below.
//
// ⚠️ IF THIS TEST GOES RED: you have changed DilV consensus enforcement. That
// may be exactly right — activating it is a planned hard fork — but it must be
// a STATED decision in your PR, not a side-effect of a merge. Do not "fix" it
// by restoring the sentinel without first checking whether you have just
// disabled the always-on path inherited from cb38afa7.
static void InstallShippedDilVChainParams()
{
    Dilithion::ChainParams shipped = Dilithion::ChainParams::DilV();
    if (!Dilithion::g_chainParams) {
        Dilithion::g_chainParams = new Dilithion::ChainParams(shipped);
    }
    // Wholesale restore, deliberately NOT a list of named fields: an
    // enumerated restore silently goes stale the day a case overrides a fifth
    // field, and this case's whole point is that it runs against SHIPPED
    // parameters rather than a previous case's leftovers.
    *Dilithion::g_chainParams = shipped;
}

static void test_connecttip_shipped_defaults_are_not_enforcing()
{
    TEST(connecttip_shipped_defaults_are_not_enforcing);
    const int kSentinel = 999999999;

    // (1) The constant itself, on all four networks.
    if (Dilithion::ChainParams::Mainnet().vdfProofEnforcementHeight != kSentinel) {
        std::cout << "FAIL: Mainnet vdfProofEnforcementHeight is no longer the sentinel\n";
        ++failed; return;
    }
    if (Dilithion::ChainParams::Testnet().vdfProofEnforcementHeight != kSentinel) {
        std::cout << "FAIL: Testnet vdfProofEnforcementHeight is no longer the sentinel\n";
        ++failed; return;
    }
    if (Dilithion::ChainParams::DilV().vdfProofEnforcementHeight != kSentinel) {
        std::cout << "FAIL: DilV vdfProofEnforcementHeight is no longer the sentinel -- "
                     "DilV VDF enforcement state has CHANGED, see the merge-guard note\n";
        ++failed; return;
    }
    if (Dilithion::ChainParams::Regtest().vdfProofEnforcementHeight != kSentinel) {
        std::cout << "FAIL: Regtest vdfProofEnforcementHeight is no longer the sentinel\n";
        ++failed; return;
    }

    // (2) The behaviour that follows from it, through the real ConnectTip, at
    //     SHIPPED DilV parameters with nothing overridden. A forged proof is
    //     accepted on both paths today. This half is what catches an
    //     always-on implementation arriving via merge while the sentinel stays
    //     in place — the constant would still read 999999999, but the block
    //     would no longer connect.
    InstallShippedDilVChainParams();

    DFMP::CMiningIdentityKey mik;
    if (!mik.Generate()) { std::cout << "FAIL: MIK generate\n"; ++failed; return; }
    // iterations here only govern how this test builds its own proof; the
    // checker never reads them, because at the sentinel it returns before
    // verifying anything.
    CBlock block = MakeVDFBlockWithSignedMIK(CTPrevHash(), kCTHeight, mik, 1000);
    if (block.vtx.empty()) { std::cout << "FAIL: block build/sign\n"; ++failed; return; }
    block.vdfOutput.data[0] ^= 0x01;

    bool flagged = true;
    if (!RunConnectTip(block, kCTHeight, false, &flagged)) {
        std::cout << "FAIL: a forged VDF block was REJECTED at shipped DilV defaults -- "
                     "DilV IS now enforcing. See the merge-guard note above this test.\n";
        ++failed; return;
    }
    CHECK(!flagged);

    flagged = true;
    if (!RunConnectTip(block, kCTHeight, true, &flagged)) {
        std::cout << "FAIL: a forged VDF block was REJECTED at shipped DilV defaults "
                     "on the reorg path -- DilV IS now enforcing.\n";
        ++failed; return;
    }
    CHECK(!flagged);
    PASS();
}

// ===========================================================================
// SCOPE OF THE ConnectTip CASES — what they do NOT cover
//
// Written down rather than left implied, because prose that claims more than
// the assertions deliver is the defect this whole file exists to catch.
//
// 1. THE CALLERS. These drive ConnectTip DIRECTLY. They say nothing about
//    ActivateBestChain's eight call sites (chain.cpp:672, 700, 761, 1096,
//    1182, 1206, 1255) or the port path's ActivateBestChainStep (:3352). A
//    change that stopped calling ConnectTip, or called it with the wrong
//    block, is invisible here.
// 2. THE REFERENCE-MIK FAIL-OPEN BRANCH. CheckVDFBlockMIKSignature returns
//    TRUE for a REFERENCE MIK whose pubkey cannot be resolved
//    (vdf_validation.cpp:309-315). DFMP::g_identityDb is always null in this
//    binary and every fixture is a REGISTRATION MIK, so that branch is never
//    entered -- and it is precisely the branch that runs during multi-block
//    reorg undo, which is the stated justification for running LP-10 on the
//    skipValidation=true path. The pass-on-missing posture is UNVERIFIED.
// 3. LOCK DISCIPLINE. ConnectTip takes no lock of its own and relies on
//    callers holding cs_main. Single-threaded here by construction, so a
//    lock-ordering regression on that path cannot be seen.
// 4. THE FAIL-OPEN MERGE DIRECTION. See the merge-guard note above: this
//    suite trips when enforcement APPEARS, not when it silently disappears.
// 5. REAL BLOCKS. Every block here is synthetic and coinbase-only, built at
//    1000 VDF iterations. Nothing here says whether blocks being mined on
//    DilV today would pass enforcement -- that needs a history replay over
//    stored mainnet blocks, which is a separate, still-unbuilt tool.
// ===========================================================================

int main()
{
    std::cout << "\nVDF Consensus Validation Tests\n";
    std::cout << "==============================\n\n";

    // Initialize VDF library.
    if (!vdf::init()) {
        std::cerr << "ERROR: Failed to initialize VDF library\n";
        return 1;
    }

    test_challenge_deterministic();
    test_challenge_varies_with_height();
    test_challenge_varies_with_address();
    test_valid_vdf_block_accepted();
    test_wrong_iterations_rejected();
    test_missing_proof_rejected();
    test_null_vdf_output_rejected();
    test_tampered_proof_hash_rejected();

    // LP-10 connect-path wiring tests (proof + MIK signature, activation-gated)
    test_lp10_honest_block_accepted_above_activation();
    test_lp10_forged_proof_rejected_above_activation();
    test_lp10_forged_proof_accepted_below_activation();
    test_lp10_disabled_sentinel_accepts_forged();
    test_lp10_honest_mik_signature_accepted_above_activation();
    test_lp10_forged_mik_signature_rejected_above_accepted_below();

    // LP-10 ConnectTip INTEGRATION tests (the checks above go through the REAL
    // CChainState::ConnectTip, on both the normal and the reorg-reconnect path)
    test_connecttip_honest_vdf_block_accepted_both_paths();
    test_connecttip_forged_proof_rejected_normal_path();
    test_connecttip_forged_proof_rejected_on_reorg_path();
    test_connecttip_forged_proof_accepted_below_enforcement();
    test_connecttip_sentinel_accepts_forged_both_paths();
    test_connecttip_forged_proof_rejected_despite_assume_valid();
    test_connecttip_forged_mik_signature_rejected_both_paths();
    test_connecttip_non_vdf_block_not_subject_to_vdf_checks();
    test_connecttip_enforcement_boundary_is_exact();
    test_connecttip_forged_block_never_reaches_the_utxo_set();
    test_connecttip_shipped_defaults_are_not_enforcing();

    vdf::shutdown();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }
    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
