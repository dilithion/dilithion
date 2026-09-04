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

    vdf::shutdown();

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    if (failed > 0) {
        std::cout << "\n=== TESTS FAILED ===\n";
        return 1;
    }
    std::cout << "\n=== ALL TESTS PASSED ===\n";
    return 0;
}
