// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * VDF connect-path wiring KATs (ECOSYSTEM_HUNT_FINDINGS #3 remediation).
 *
 * The defect: CheckVDFProof() verifies a DilV v4 block's Wesolowski VDF proof
 * AND its coinbase commitment, but had only a dead-code caller — every live
 * accept path skipped it, so any MIK holder could forge v4 blocks at zero
 * sequential cost. The fix wires CheckVDFProof onto the connect path via the
 * ConnectPathCheckVDF() seam, gated for IBD by a dedicated vdfAssumeValidHeight.
 *
 * These KATs hit that seam as a (near-)pure function of
 * (block, height, prevHash, fInitialBlockDownload) + g_chainParams — the same
 * approach connect_checks_tests.cpp uses to prove the C-R3 connect validator is
 * enforced and load-bearing without constructing a full PoW/MIK/attestation
 * block to reach the real ConnectTip. The connect site calls ConnectPathCheckVDF
 * UNCONDITIONALLY in ConnectTip's reorg-safe region (outside every
 * `if (!skipValidation)`), so the seam's verdict is the connect-path verdict for
 * both normal AND reorg/fork-activation connects.
 *
 * Anti-vacuity (mutation corroboration): the honest v4 block is the positive
 * control for the FORGE-A rejection. FORGE-A satisfies BOTH cheap checks
 * (vdfProofHash == SHA3(proof) AND vdfOutput == SHA3(proof[0:formSize])) so it
 * reaches the expensive class-group Wesolowski step — and is rejected there
 * while the honest block is accepted. If the Wesolowski verify were a no-op both
 * would pass; only a live, discriminating verify yields ACCEPT(honest) +
 * REJECT(forged). And the gate KATs redden under a skip-when-should-verify
 * mutation.
 */

#include <boost/test/unit_test.hpp>

#include <consensus/connect_checks.h>
#include <consensus/vdf_validation.h>
#include <consensus/validation.h>   // CBlockValidator (BuildMerkleRoot)
#include <vdf/vdf.h>
#include <vdf/coinbase_vdf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <core/chainparams.h>
#include <crypto/sha3.h>
#include <uint256.h>

#include <array>
#include <vector>
#include <string>
#include <cstring>

BOOST_AUTO_TEST_SUITE(vdf_connect_tests)

namespace {

// Small iteration count keeps each VDF compute in the low-ms range while still
// producing a genuine Wesolowski proof that verify() accepts. The fixture pins
// g_chainParams->vdfIterations to the SAME value so CheckVDFProof verifies with
// the exact iteration count the honest proof was computed at.
constexpr uint64_t TEST_VDF_ITERS = 1000;

struct DilVParamsFixture {
    Dilithion::ChainParams* saved{nullptr};
    Dilithion::ChainParams* owned{nullptr};
    DilVParamsFixture() {
        saved = Dilithion::g_chainParams;
        owned = new Dilithion::ChainParams(Dilithion::ChainParams::DilV());
        owned->vdfIterations = TEST_VDF_ITERS;  // fast VDF for the unit test
        Dilithion::g_chainParams = owned;
        vdf::init();
    }
    ~DilVParamsFixture() {
        Dilithion::g_chainParams = saved;
        delete owned;
    }
};

void WriteCompactSize(std::vector<uint8_t>& d, uint64_t s) {
    if (s < 253) { d.push_back((uint8_t)s); }
    else if (s <= 0xFFFF) { d.push_back(253); d.push_back(s & 0xFF); d.push_back((s >> 8) & 0xFF); }
    else { d.push_back(254); for (int i = 0; i < 4; i++) d.push_back((s >> (i * 8)) & 0xFF); }
}

std::vector<uint8_t> P2PKH(const std::array<uint8_t, 20>& a) {
    std::vector<uint8_t> spk = {0x76, 0xa9, 0x14};
    spk.insert(spk.end(), a.begin(), a.end());
    spk.push_back(0x88); spk.push_back(0xac);
    return spk;
}

// Build a v4 VDF block whose coinbase pays to `minerAddr` (so
// ExtractCoinbaseAddress recovers it and the challenge derivation is symmetric)
// and whose coinbase scriptSig embeds `proof`. The header VDF fields are caller-
// supplied so honest and forged variants can be modelled precisely.
CBlock MakeVDFBlock(const uint256& prevHash,
                    const std::array<uint8_t, 20>& minerAddr,
                    const std::vector<uint8_t>& proof,
                    const uint256& vdfOutput,
                    const uint256& vdfProofHash,
                    int32_t nVersion = CBlockHeader::VDF_VERSION) {
    CTransaction cb;
    cb.nVersion = 1; cb.nLockTime = 0;
    // Leading coinbase scriptSig filler (height push / extranonce); ExtractProof
    // scans for the VDF_TAG so the exact prefix is irrelevant.
    std::vector<uint8_t> ss = {0x04, 0x01, 0x02, 0x03, 0x04};
    CTxIn cbIn(COutPoint(), ss);
    CoinbaseVDF::EmbedProof(cbIn, proof);
    cb.vin.push_back(cbIn);
    cb.vout.push_back(CTxOut(5000000000ULL, P2PKH(minerAddr)));
    CTransactionRef cbRef = MakeTransactionRef(cb);

    CBlock block;
    block.nVersion = nVersion;
    block.nTime = 1700000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 0;
    block.hashPrevBlock = prevHash;
    block.vdfOutput = vdfOutput;
    block.vdfProofHash = vdfProofHash;

    std::vector<uint8_t> vtx;
    WriteCompactSize(vtx, 1);
    std::vector<uint8_t> td = cbRef->Serialize();
    vtx.insert(vtx.end(), td.begin(), td.end());
    block.vtx = vtx;

    CBlockValidator v;
    block.hashMerkleRoot = v.BuildMerkleRoot(std::vector<CTransactionRef>{cbRef});
    return block;
}

uint256 MakePrev(uint8_t fill) { uint256 h; std::memset(h.data, fill, 32); return h; }

// Compute a genuine VDF proof for (prevHash, height, minerAddr) at TEST_VDF_ITERS.
vdf::VDFResult ComputeHonest(const uint256& prevHash, int height,
                             const std::array<uint8_t, 20>& minerAddr) {
    std::array<uint8_t, 32> challenge = ComputeVDFChallenge(prevHash, height, minerAddr);
    return vdf::compute(challenge, TEST_VDF_ITERS);
}

}  // namespace

// ============================================================================
// GATE HELPER — pure-function KATs (ConnectPathMaySkipVDFVerify / VerifyVDF)
// Mutation target: a skip-when-should-verify flip reddens these directly.
// ============================================================================

BOOST_AUTO_TEST_CASE(vdf_gate_default_zero_always_verifies) {
    // vdfAssumeValidHeight == 0 (the default on every network/relaunch, and the
    // null-params fail-safe) => NEVER skip, at ANY height, in or out of IBD.
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(1,     0, /*IBD=*/true));
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(1,     0, /*IBD=*/false));
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(100000, 0, /*IBD=*/true));
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(1,    -1, /*IBD=*/true));
    // ConnectPathVerifyVDF returns TRUE (must verify) for all of the above.
    BOOST_CHECK( ConnectPathVerifyVDF(nullptr, 100, /*IBD=*/true));   // fail-safe
    BOOST_CHECK( ConnectPathVerifyVDF(nullptr, 100, /*IBD=*/false));
}

BOOST_AUTO_TEST_CASE(vdf_gate_configured_height_semantics) {
    const int AVH = 1000;
    // Skip ONLY when configured (>0) AND at/below the height AND still in IBD.
    BOOST_CHECK( ConnectPathMaySkipVDFVerify(100,  AVH, /*IBD=*/true));   // below, IBD
    BOOST_CHECK( ConnectPathMaySkipVDFVerify(1000, AVH, /*IBD=*/true));   // boundary
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(1001, AVH, /*IBD=*/true));   // above
    BOOST_CHECK(!ConnectPathMaySkipVDFVerify(100,  AVH, /*IBD=*/false));  // tip: never skip
}

BOOST_FIXTURE_TEST_CASE(vdf_gate_dilv_params_default_verify_all_heights, DilVParamsFixture) {
    // DilV ships vdfAssumeValidHeight == 0 => every DilV block verifies its VDF
    // proof, at every height, in IBD or not.
    BOOST_REQUIRE_EQUAL(Dilithion::g_chainParams->vdfAssumeValidHeight, 0);
    for (int h : {1, 100, 44233, 200000, 500000}) {
        BOOST_CHECK_MESSAGE(ConnectPathVerifyVDF(Dilithion::g_chainParams, h, /*IBD=*/true),
                            "DilV default vdfAssumeValidHeight=0 must verify VDF at height " << h);
        BOOST_CHECK(ConnectPathVerifyVDF(Dilithion::g_chainParams, h, /*IBD=*/false));
    }
}

// ============================================================================
// CONNECT-PATH SEAM — honest ACCEPT / forged REJECT (the security property)
// ============================================================================

BOOST_FIXTURE_TEST_CASE(vdf_connect_honest_block_accepted, DilVParamsFixture) {
    const uint256 prev = MakePrev(0xAB);
    const int height = 100;
    std::array<uint8_t, 20> minerAddr; minerAddr.fill(0x11);

    vdf::VDFResult r = ComputeHonest(prev, height, minerAddr);
    BOOST_REQUIRE(!r.proof.empty());  // compute produced a real proof

    uint256 out; std::memcpy(out.data, r.output.data(), 32);
    uint256 ph = CoinbaseVDF::ComputeProofHash(r.proof);
    CBlock honest = MakeVDFBlock(prev, minerAddr, r.proof, out, ph);

    // Positive control through the connect-path seam (post-IBD tip connect).
    std::string err;
    BOOST_CHECK_MESSAGE(ConnectPathCheckVDF(honest, height, prev, /*IBD=*/false, err),
                        "honest v4 block must be ACCEPTED on the connect path; err=" << err);
    // And directly through CheckVDFProof at the same iteration count.
    std::string err2;
    BOOST_CHECK(CheckVDFProof(honest, height, prev, TEST_VDF_ITERS, err2));
}

BOOST_FIXTURE_TEST_CASE(vdf_connect_forged_proof_rejected, DilVParamsFixture) {
    const uint256 prev = MakePrev(0xAB);
    const int height = 100;
    std::array<uint8_t, 20> minerAddr; minerAddr.fill(0x11);

    // Establish the honest proof size (200 = 2*formSize) from a real compute so
    // FORGE-A matches the length verify() requires.
    vdf::VDFResult r = ComputeHonest(prev, height, minerAddr);
    BOOST_REQUIRE(!r.proof.empty());
    const size_t proofLen = r.proof.size();
    const size_t formSize = proofLen / 2;

    // FORGE-A: fabricated proof bytes, with BOTH commitments recomputed so every
    // cheap check passes and the block reaches the class-group Wesolowski step.
    std::vector<uint8_t> fproof(proofLen);
    for (size_t i = 0; i < proofLen; ++i) fproof[i] = (uint8_t)((i * 7u + 1u) & 0xFF);
    uint256 fph = CoinbaseVDF::ComputeProofHash(fproof);            // step-5 commitment OK
    uint256 fout; SHA3_256(fproof.data(), formSize, fout.data);     // verify() output-consistency OK
    CBlock forged = MakeVDFBlock(prev, minerAddr, fproof, fout, fph);

    // Rejected on the connect path (default vdfAssumeValidHeight=0 => verify).
    std::string err;
    BOOST_CHECK_MESSAGE(!ConnectPathCheckVDF(forged, height, prev, /*IBD=*/false, err),
                        "FORGE-A must be REJECTED on the connect path");
    BOOST_CHECK_MESSAGE(err.find("Wesolowski") != std::string::npos,
                        "rejection must come from the class-group verify, got: " << err);

    // Also rejected when IBD=true, because vdfAssumeValidHeight defaults to 0
    // (no dormant skip window) — this is the "verification runs at all heights"
    // guarantee: an in-IBD low-height block is still verified.
    std::string errIbd;
    BOOST_CHECK(!ConnectPathCheckVDF(forged, height, prev, /*IBD=*/true, errIbd));
}

BOOST_FIXTURE_TEST_CASE(vdf_connect_commitment_tamper_rejected, DilVParamsFixture) {
    // N2: honest proof but a flipped header vdfProofHash => rejected at the cheap
    // commitment step (proves step-5 commitment is on the connect path too).
    const uint256 prev = MakePrev(0xCD);
    const int height = 250;
    std::array<uint8_t, 20> minerAddr; minerAddr.fill(0x22);

    vdf::VDFResult r = ComputeHonest(prev, height, minerAddr);
    BOOST_REQUIRE(!r.proof.empty());
    uint256 out; std::memcpy(out.data, r.output.data(), 32);
    uint256 ph = CoinbaseVDF::ComputeProofHash(r.proof);
    ph.data[0] ^= 0xFF;  // tamper the commitment

    CBlock tampered = MakeVDFBlock(prev, minerAddr, r.proof, out, ph);
    std::string err;
    BOOST_CHECK(!ConnectPathCheckVDF(tampered, height, prev, /*IBD=*/false, err));
    BOOST_CHECK_MESSAGE(err.find("commitment") != std::string::npos ||
                        err.find("mismatch") != std::string::npos,
                        "expected commitment-mismatch rejection, got: " << err);
}

// ============================================================================
// GATE WIRING through the seam — the SAME forged block is skipped ONLY under a
// configured vdfAssumeValidHeight + IBD + at/below boundary, and verified
// otherwise. Proves the assume-valid gate is actually wired into the seam.
// ============================================================================

BOOST_FIXTURE_TEST_CASE(vdf_connect_assumevalid_gate_wired, DilVParamsFixture) {
    const uint256 prev = MakePrev(0xAB);
    const int height = 100;
    std::array<uint8_t, 20> minerAddr; minerAddr.fill(0x11);

    vdf::VDFResult r = ComputeHonest(prev, height, minerAddr);
    BOOST_REQUIRE(!r.proof.empty());
    std::vector<uint8_t> fproof(r.proof.size());
    for (size_t i = 0; i < fproof.size(); ++i) fproof[i] = (uint8_t)((i * 7u + 1u) & 0xFF);
    uint256 fph = CoinbaseVDF::ComputeProofHash(fproof);
    uint256 fout; SHA3_256(fproof.data(), fproof.size() / 2, fout.data);
    CBlock forged = MakeVDFBlock(prev, minerAddr, fproof, fout, fph);

    // Configure a positive assume-valid height above the block height.
    Dilithion::g_chainParams->vdfAssumeValidHeight = 1000;

    std::string err;
    // IBD + at/below boundary => SKIP => forged block is (wrongly, but by design)
    // ACCEPTED — this is the assume-valid IBD optimisation firing.
    BOOST_CHECK_MESSAGE(ConnectPathCheckVDF(forged, height, prev, /*IBD=*/true, err),
                        "assume-valid+IBD+below-boundary must SKIP the verify; err=" << err);
    // Same block at the tip (post-IBD) => never skipped => REJECTED.
    BOOST_CHECK(!ConnectPathCheckVDF(forged, height, prev, /*IBD=*/false, err));
    // Same block above the boundary in IBD => not skipped => REJECTED.
    BOOST_CHECK(!ConnectPathCheckVDF(forged, /*height=*/2000, prev, /*IBD=*/true, err));
}

// ============================================================================
// EXEMPTIONS — non-VDF (pre-v4) blocks and genesis are unaffected.
// ============================================================================

BOOST_FIXTURE_TEST_CASE(vdf_connect_non_vdf_and_genesis_exempt, DilVParamsFixture) {
    const uint256 prev = MakePrev(0xEF);
    std::array<uint8_t, 20> minerAddr; minerAddr.fill(0x33);

    // A pre-v4 block (nVersion=1) is not a VDF block: seam returns true regardless
    // of the (here empty/garbage) VDF header fields.
    std::vector<uint8_t> junk(200, 0x00);
    CBlock legacy = MakeVDFBlock(prev, minerAddr, junk, MakePrev(0x01), MakePrev(0x02),
                                 /*nVersion=*/1);
    std::string err;
    BOOST_CHECK(ConnectPathCheckVDF(legacy, 100, prev, /*IBD=*/false, err));

    // Genesis (height 0) is exempt even for a v4 block.
    CBlock v4 = MakeVDFBlock(prev, minerAddr, junk, MakePrev(0x01), MakePrev(0x02));
    BOOST_CHECK(ConnectPathCheckVDF(v4, /*height=*/0, prev, /*IBD=*/false, err));
}

BOOST_AUTO_TEST_SUITE_END()
