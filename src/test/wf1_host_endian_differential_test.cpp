// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// WF-1 HOST-ENDIAN DIFFERENTIAL / BYTE-EQUALITY TEST (Boost.Test suite)
// =====================================================================
//
// This suite is the machine-checked safety proof for the WF-1 fix, which
// converted host-endian consensus-observable serialization sites to explicit
// little-endian. On a little-endian host the new bytes MUST be byte-identical
// to the old host-endian bytes — otherwise the block-header hash (and the
// frozen genesis hash) would change and split the chain.
//
// It is wired into `test_dilithion` (BOOST_TEST_OBJECTS) so CI, which runs
// ./test_dilithion, exercises the WF-1 byte-equality AND the both-genesis-hash-
// unchanged assertions on every build.
//
// De-tautology (review fold): the byte-equality checks DRIVE the real production
// serializers rather than comparing two hand-copied mirrors —
//   - A1  : CBlockHeader::SerializeHeader()               (production)
//   - A2  : new==old mirror, compensated by == A1 canonical (production anchor)
//   - A3s : GetShortID() -> FillShortTxIDSelector()       (production) vs the
//           SipHash key derived from the OLD host-endian preimage
//   - A3w : CBlockHeaderAndShortTxIDs::Serialize/Deserialize round-trip (production)
//   - A4  : WriteMiningHeaderLE() — the SAME helper the miner hot loop calls —
//           and additionally asserted byte-equal to A1 SerializeHeader()
//   - C1  : vdf preimage mirror new==old
//   - B1-4: digital-DNA *::serialize() (production) vs old host-endian mirror
//
// GENESIS: both frozen genesis hashes are asserted byte-unchanged — DIL mainnet
// (RandomX, 80-byte header) and DilV (VDF/SHA3, 144-byte header) — via BOTH the
// header preimage bytes AND the full end-to-end hash vs the chainparams constant.

#include <boost/test/unit_test.hpp>

#include <primitives/block.h>
#include <node/genesis.h>
#include <core/chainparams.h>
#include <crypto/randomx_hash.h>
#include <crypto/sha3.h>
#include <crypto/siphash.h>
#include <net/blockencodings.h>
#include <consensus/vdf_validation.h>
#include <digital_dna/behavioral_profile.h>
#include <digital_dna/clock_drift.h>
#include <digital_dna/memory_fingerprint.h>
#include <digital_dna/bandwidth_proof.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>

using namespace Dilithion;

BOOST_AUTO_TEST_SUITE(wf1_host_endian_tests)

// ---------------------------------------------------------------------------
// OLD host-endian emitters (verbatim reproductions of the pre-WF-1 code).
// ---------------------------------------------------------------------------

static std::vector<uint8_t> old_block_serialize_header(const CBlockHeader& h) {
    // Reproduces primitives/block.cpp SerializeHeader() BEFORE the fix.
    std::vector<uint8_t> buf;
    const uint8_t* p;
    p = reinterpret_cast<const uint8_t*>(&h.nVersion); buf.insert(buf.end(), p, p + 4);
    buf.insert(buf.end(), h.hashPrevBlock.begin(), h.hashPrevBlock.end());
    buf.insert(buf.end(), h.hashMerkleRoot.begin(), h.hashMerkleRoot.end());
    p = reinterpret_cast<const uint8_t*>(&h.nTime);  buf.insert(buf.end(), p, p + 4);
    p = reinterpret_cast<const uint8_t*>(&h.nBits);  buf.insert(buf.end(), p, p + 4);
    p = reinterpret_cast<const uint8_t*>(&h.nNonce); buf.insert(buf.end(), p, p + 4);
    if (h.nVersion >= CBlockHeader::VDF_VERSION) {
        buf.insert(buf.end(), h.vdfOutput.begin(), h.vdfOutput.end());
        buf.insert(buf.end(), h.vdfProofHash.begin(), h.vdfProofHash.end());
    }
    return buf;
}

// A2: genesis.cpp SerializeBlockHeader (legacy 80-byte mining helper), old form.
static std::vector<uint8_t> old_genesis_serialize_header(const CBlock& block, uint32_t nonce) {
    std::vector<uint8_t> data;
    const uint8_t* vb = reinterpret_cast<const uint8_t*>(&block.nVersion);
    data.insert(data.end(), vb, vb + 4);
    data.insert(data.end(), block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    data.insert(data.end(), block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
    const uint8_t* tb = reinterpret_cast<const uint8_t*>(&block.nTime); data.insert(data.end(), tb, tb + 4);
    const uint8_t* bb = reinterpret_cast<const uint8_t*>(&block.nBits); data.insert(data.end(), bb, bb + 4);
    const uint8_t* nb = reinterpret_cast<const uint8_t*>(&nonce);       data.insert(data.end(), nb, nb + 4);
    return data;
}

// A2 genesis.cpp SerializeBlockHeader (legacy 80-byte mining helper), NEW form.
// The production helper is file-static in genesis.cpp; this mirrors its exact
// emission (AppendLE32 for the four scalars). It is NOT relied on alone — it is
// asserted byte-equal to the canonical A1 SerializeHeader() below, which IS
// production, so the mirror is anchored to production.
static std::vector<uint8_t> new_genesis_serialize_header(const CBlock& block, uint32_t nonce) {
    std::vector<uint8_t> data;
    AppendLE32(data, static_cast<uint32_t>(block.nVersion));
    data.insert(data.end(), block.hashPrevBlock.begin(), block.hashPrevBlock.end());
    data.insert(data.end(), block.hashMerkleRoot.begin(), block.hashMerkleRoot.end());
    AppendLE32(data, block.nTime);
    AppendLE32(data, block.nBits);
    AppendLE32(data, nonce);
    return data;
}

// A3-FillShortTxIDSelector: the 88-byte SHA3 preimage, OLD host-endian form.
static std::vector<uint8_t> old_a3_selector_preimage(const CBlockHeader& header, uint64_t nonce) {
    std::vector<uint8_t> data(88);
    memcpy(data.data(),      &header.nVersion, 4);
    memcpy(data.data() + 4,  header.hashPrevBlock.data, 32);
    memcpy(data.data() + 36, header.hashMerkleRoot.data, 32);
    memcpy(data.data() + 68, &header.nTime, 4);
    memcpy(data.data() + 72, &header.nBits, 4);
    memcpy(data.data() + 76, &header.nNonce, 4);
    memcpy(data.data() + 80, &nonce, 8);
    return data;
}

// C1: vdf challenge 56-byte preimage, old form.
static std::vector<uint8_t> old_c1_vdf_preimage(const uint256& prevHash, int height,
                                                const std::array<uint8_t, 20>& addr) {
    std::vector<uint8_t> pre(56);
    memcpy(pre.data(), prevHash.data, 32);
    uint32_t hLE = static_cast<uint32_t>(height);
    memcpy(pre.data() + 32, &hLE, 4);
    memcpy(pre.data() + 36, addr.data(), 20);
    return pre;
}

// C1 NEW preimage (mirrors production emission in vdf_validation.cpp).
static std::vector<uint8_t> new_c1_vdf_preimage(const uint256& prevHash, int height,
                                                const std::array<uint8_t, 20>& addr) {
    std::vector<uint8_t> pre(56);
    memcpy(pre.data(), prevHash.data, 32);
    uint32_t h = static_cast<uint32_t>(height);
    pre[32] = static_cast<uint8_t>(h);
    pre[33] = static_cast<uint8_t>(h >> 8);
    pre[34] = static_cast<uint8_t>(h >> 16);
    pre[35] = static_cast<uint8_t>(h >> 24);
    memcpy(pre.data() + 36, addr.data(), 20);
    return pre;
}

// Derive the SipHash short-txid keys from a raw 88-byte preimage the SAME way
// FillShortTxIDSelector() does internally (SHA3-256, then two LE 64-bit keys).
// Used to compute the EXPECTED keys from the OLD host-endian preimage, which we
// then compare against the REAL production keys observed through GetShortID().
static void keys_from_preimage(const std::vector<uint8_t>& pre, uint64_t& k0, uint64_t& k1) {
    uint8_t hash[32];
    SHA3_256(pre.data(), pre.size(), hash);
    k0 = 0; k1 = 0;
    for (int i = 0; i < 8; i++) {
        k0 |= static_cast<uint64_t>(hash[i]) << (i * 8);
        k1 |= static_cast<uint64_t>(hash[i + 8]) << (i * 8);
    }
}

// ---------------------------------------------------------------------------
// Representative header inputs.
// ---------------------------------------------------------------------------
static CBlockHeader make_header(int32_t v, uint32_t t, uint32_t bits, uint32_t nonce, bool vdf) {
    CBlockHeader h;
    h.nVersion = v; h.nTime = t; h.nBits = bits; h.nNonce = nonce;
    for (int i = 0; i < 32; i++) { h.hashPrevBlock.data[i] = static_cast<uint8_t>(0x11 * (i + 1));
                                   h.hashMerkleRoot.data[i] = static_cast<uint8_t>(0x07 * (i + 3)); }
    if (vdf) {
        for (int i = 0; i < 32; i++) { h.vdfOutput.data[i] = static_cast<uint8_t>(i);
                                       h.vdfProofHash.data[i] = static_cast<uint8_t>(0xF0 - i); }
    }
    return h;
}

struct HV { int32_t v; uint32_t t; uint32_t bits; uint32_t nonce; };
static const std::vector<HV> kHvs = {
    {1, 1737158400u, 0x1e01fffeu, 429612875u},   // DIL genesis-like
    {0, 0u, 0u, 0u},
    {4, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu},   // VDF, all-ones
    {4, 0x01020304u, 0xdeadbeefu, 0x12345678u},   // VDF, mixed
    {1, 0x80000000u, 0x00ff00ffu, 0x0000abcdu},
};

// ===========================================================================
// FAMILY A — block-header hash preimage.
// ===========================================================================

// A1: canonical CBlockHeader::SerializeHeader() is byte-identical to old form.
BOOST_AUTO_TEST_CASE(a1_block_serialize_header) {
    for (const auto& x : kHvs) {
        bool vdf = (x.v >= CBlockHeader::VDF_VERSION);
        CBlockHeader h = make_header(x.v, x.t, x.bits, x.nonce, vdf);
        BOOST_CHECK(h.SerializeHeader() == old_block_serialize_header(h));
    }
}

// A2: genesis mining helper (legacy 80-byte). new==old AND new==A1 canonical
// (miner and validator agree byte-for-byte). A2 is anchored to production via A1.
BOOST_AUTO_TEST_CASE(a2_genesis_serialize_header) {
    for (const auto& x : kHvs) {
        CBlockHeader legacy = make_header(x.v, x.t, x.bits, x.nonce, false);
        legacy.nVersion = 1; legacy.nNonce = x.nonce;
        CBlock gb; static_cast<CBlockHeader&>(gb) = legacy;

        std::vector<uint8_t> newA2 = new_genesis_serialize_header(gb, x.nonce);
        BOOST_CHECK(newA2 == old_genesis_serialize_header(gb, x.nonce));
        // Anchor to production: A2 helper == canonical A1 legacy serialization.
        BOOST_CHECK(newA2 == legacy.SerializeHeader());
    }
}

// A3-selector: PRODUCTION-DRIVING. GetShortID() lazily invokes the real
// FillShortTxIDSelector() to derive the SipHash keys, then SipHashes the txid.
// We assert that the short-id produced by the real production path equals the
// short-id computed from keys derived from the OLD host-endian 88-byte preimage.
// If FillShortTxIDSelector's endian emission ever drifts, the derived keys — and
// thus GetShortID's output — diverge and this fails. No hand-copied mirror of
// the production preimage is trusted here.
BOOST_AUTO_TEST_CASE(a3_selector_production_driving) {
    uint256 txid;
    for (int i = 0; i < 32; i++) txid.data[i] = static_cast<uint8_t>(0x5A ^ (i * 3));

    for (const auto& x : kHvs) {
        bool vdf = (x.v >= CBlockHeader::VDF_VERSION);
        CBlockHeader h = make_header(x.v, x.t, x.bits, x.nonce, vdf);
        uint64_t sel_nonce = 0x1122334455667788ULL ^ x.nonce;

        // REAL production path: build the compact-block object and ask it for a
        // short id. This runs the production FillShortTxIDSelector().
        CBlockHeaderAndShortTxIDs comp;
        comp.header = h;
        comp.nonce = sel_nonce;
        uint64_t prod_shortid = comp.GetShortID(txid);

        // Expected: derive keys from the OLD host-endian preimage and SipHash.
        uint64_t k0, k1;
        keys_from_preimage(old_a3_selector_preimage(h, sel_nonce), k0, k1);
        uint64_t expected = SipHashUint256(k0, k1, txid) & 0xffffffffffffULL;

        BOOST_CHECK_EQUAL(prod_shortid, expected);
    }
}

// A3-wire: PRODUCTION Serialize()/Deserialize() round-trips header scalars,
// selector nonce and short-txids identically. (The wire framing itself is P2P-
// only and lives on a separate branch; this just proves the round-trip holds.)
BOOST_AUTO_TEST_CASE(a3_wire_roundtrip_production) {
    for (const auto& x : kHvs) {
        bool vdf = (x.v >= CBlockHeader::VDF_VERSION);
        CBlockHeader h = make_header(x.v, x.t, x.bits, x.nonce, vdf);
        uint64_t sel_nonce = 0x1122334455667788ULL ^ x.nonce;

        CBlockHeaderAndShortTxIDs comp;
        comp.header = h;
        comp.nonce = sel_nonce;
        comp.shorttxids = { 0x010203040506ULL, 0x0A0B0C0D0E0FULL };
        std::vector<uint8_t> wire = comp.Serialize();

        CBlockHeaderAndShortTxIDs back;
        BOOST_REQUIRE(back.Deserialize(wire.data(), wire.size()));
        BOOST_CHECK_EQUAL(back.header.nVersion, h.nVersion);
        BOOST_CHECK_EQUAL(back.header.nTime, h.nTime);
        BOOST_CHECK_EQUAL(back.header.nBits, h.nBits);
        BOOST_CHECK_EQUAL(back.header.nNonce, h.nNonce);
        BOOST_CHECK_EQUAL(back.nonce, comp.nonce);
        BOOST_CHECK(back.shorttxids == comp.shorttxids);
    }
}

// A4: PRODUCTION-DRIVING. WriteMiningHeaderLE() is the exact helper the miner
// hot loop (controller.cpp MiningWorker) calls to assemble its 80-byte PoW
// buffer. We drive THAT function and assert (i) byte-equal to the old host-
// endian miner emission, and (ii) — the property that actually matters —
// byte-equal to the canonical validator serialization SerializeHeader() for the
// same legacy header. A future drift in the miner buffer assembly now fails CI.
BOOST_AUTO_TEST_CASE(a4_controller_header_production_driving) {
    for (const auto& x : kHvs) {
        // The miner only mines legacy (80-byte) blocks; force v1.
        CBlockHeader h = make_header(x.v, x.t, x.bits, x.nonce, false);
        h.nVersion = 1;

        // (i) real production assembly vs old host-endian miner emission.
        std::vector<uint8_t> prod(80);
        WriteMiningHeaderLE(prod.data(), h, x.nonce);

        std::vector<uint8_t> old(80);
        {
            size_t off = 0;
            memcpy(old.data() + off, &h.nVersion, 4); off += 4;
            memcpy(old.data() + off, h.hashPrevBlock.begin(), 32); off += 32;
            memcpy(old.data() + off, h.hashMerkleRoot.begin(), 32); off += 32;
            memcpy(old.data() + off, &h.nTime, 4); off += 4;
            memcpy(old.data() + off, &h.nBits, 4); off += 4;
            memcpy(old.data() + 76, &x.nonce, 4);
        }
        BOOST_CHECK(prod == old);

        // (ii) THE property: miner buffer == validator SerializeHeader() with the
        // same nonce in the header. This is what keeps mined PoW acceptable.
        CBlockHeader hv = h; hv.nNonce = x.nonce;
        BOOST_CHECK(prod == hv.SerializeHeader());
    }
}

// ===========================================================================
// FAMILY C — VDF challenge preimage.
// ===========================================================================
BOOST_AUTO_TEST_CASE(c1_vdf_preimage) {
    uint256 prev;
    for (int i = 0; i < 32; i++) prev.data[i] = static_cast<uint8_t>(0x33 + i);
    std::array<uint8_t, 20> addr{};
    for (int i = 0; i < 20; i++) addr[i] = static_cast<uint8_t>(0xA0 + i);
    std::vector<int> heights = {0, 1, 40000, 0x00FF00FF, 0x7FFFFFFF, (int)0xFFFFFFFF};
    for (int hgt : heights) {
        BOOST_CHECK(new_c1_vdf_preimage(prev, hgt, addr) == old_c1_vdf_preimage(prev, hgt, addr));
    }
}

// ===========================================================================
// FAMILY B — Digital-DNA dna_hash preimage (production *::serialize()).
// ===========================================================================
BOOST_AUTO_TEST_CASE(b1_behavioral_profile) {
    using namespace digital_dna;
    BehavioralProfile p;
    for (int i = 0; i < 24; i++) p.hourly_activity[i] = 1.5 * i - 3.25;
    p.mean_relay_delay_ms = 42.125; p.relay_consistency = 0.75;
    p.avg_peer_session_duration_sec = 123456.789; p.peer_diversity_score = 0.333;
    p.tx_relay_rate = 9.5; p.tx_timing_entropy = 3.14159265358979;
    p.observation_blocks = 0xDEADBEEF; p.start_time = 0x0102030405060708ULL;
    p.end_time = 0xFFFFFFFFFFFFFFFFULL;
    std::vector<uint8_t> got = p.serialize();

    std::vector<uint8_t> old;
    auto pd = [&](double d){ const uint8_t* q = reinterpret_cast<const uint8_t*>(&d); old.insert(old.end(), q, q + 8); };
    for (int i = 0; i < 24; i++) pd(p.hourly_activity[i]);
    pd(p.mean_relay_delay_ms); pd(p.relay_consistency); pd(p.avg_peer_session_duration_sec);
    pd(p.peer_diversity_score); pd(p.tx_relay_rate); pd(p.tx_timing_entropy);
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.observation_blocks); old.insert(old.end(), q, q + 4); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.start_time); old.insert(old.end(), q, q + 8); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.end_time); old.insert(old.end(), q, q + 8); }
    BOOST_CHECK(got == old);

    BehavioralProfile r = BehavioralProfile::deserialize(got);
    BOOST_CHECK_EQUAL(r.observation_blocks, p.observation_blocks);
    BOOST_CHECK_EQUAL(r.start_time, p.start_time);
    BOOST_CHECK_EQUAL(r.end_time, p.end_time);
    BOOST_CHECK_EQUAL(r.tx_timing_entropy, p.tx_timing_entropy);
}

BOOST_AUTO_TEST_CASE(b2_clock_drift) {
    using namespace digital_dna;
    ClockDriftFingerprint f;
    f.drift_rate_ppm = -1.25; f.drift_stability = 0.001; f.jitter_signature = 987.654;
    f.observation_start = 0x1111222233334444ULL; f.observation_end = 0x5555666677778888ULL;
    f.num_reference_peers = 0xABCD1234; f.num_samples = 0x0000FFFF;
    std::vector<uint8_t> got = f.serialize();

    std::vector<uint8_t> old(48); size_t o = 0;
    memcpy(old.data()+o,&f.drift_rate_ppm,8); o+=8;
    memcpy(old.data()+o,&f.drift_stability,8); o+=8;
    memcpy(old.data()+o,&f.jitter_signature,8); o+=8;
    memcpy(old.data()+o,&f.observation_start,8); o+=8;
    memcpy(old.data()+o,&f.observation_end,8); o+=8;
    memcpy(old.data()+o,&f.num_reference_peers,4); o+=4;
    memcpy(old.data()+o,&f.num_samples,4); o+=4;
    BOOST_CHECK(got == old);

    ClockDriftFingerprint r = ClockDriftFingerprint::deserialize(got);
    BOOST_CHECK_EQUAL(r.num_reference_peers, f.num_reference_peers);
    BOOST_CHECK_EQUAL(r.observation_end, f.observation_end);
    BOOST_CHECK_EQUAL(r.jitter_signature, f.jitter_signature);
}

BOOST_AUTO_TEST_CASE(b3_memory_fingerprint) {
    using namespace digital_dna;
    MemoryFingerprint f;
    for (int i = 0; i < 3; i++) {
        MemoryProbeResult p;
        p.working_set_kb = static_cast<uint32_t>(64u << i);
        p.access_time_ns = 10.5 * (i + 1);
        p.bandwidth_mbps = 1000.0 / (i + 1);
        f.access_curve.push_back(p);
    }
    f.estimated_l1_kb = 32.0; f.estimated_l2_kb = 256.0; f.estimated_l3_kb = 8192.0;
    f.dram_latency_ns = 85.25; f.peak_bandwidth_mbps = 42000.5;
    std::vector<uint8_t> got = f.serialize();

    std::vector<uint8_t> old;
    uint32_t count = static_cast<uint32_t>(f.access_curve.size());
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&count); old.insert(old.end(), q, q + 4); }
    for (const auto& p : f.access_curve) {
        { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.working_set_kb); old.insert(old.end(), q, q + 4); }
        { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.access_time_ns); old.insert(old.end(), q, q + 8); }
        { const uint8_t* q = reinterpret_cast<const uint8_t*>(&p.bandwidth_mbps); old.insert(old.end(), q, q + 8); }
    }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&f.estimated_l1_kb); old.insert(old.end(), q, q + 8); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&f.estimated_l2_kb); old.insert(old.end(), q, q + 8); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&f.estimated_l3_kb); old.insert(old.end(), q, q + 8); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&f.dram_latency_ns); old.insert(old.end(), q, q + 8); }
    { const uint8_t* q = reinterpret_cast<const uint8_t*>(&f.peak_bandwidth_mbps); old.insert(old.end(), q, q + 8); }
    BOOST_CHECK(got == old);

    MemoryFingerprint r = MemoryFingerprint::deserialize(got);
    BOOST_CHECK_EQUAL(r.access_curve.size(), f.access_curve.size());
    BOOST_CHECK_EQUAL(r.access_curve[2].bandwidth_mbps, f.access_curve[2].bandwidth_mbps);
    BOOST_CHECK_EQUAL(r.peak_bandwidth_mbps, f.peak_bandwidth_mbps);
}

BOOST_AUTO_TEST_CASE(b4_bandwidth_proof) {
    using namespace digital_dna;
    BandwidthFingerprint f;
    f.median_upload_mbps = 55.5; f.median_download_mbps = 940.25;
    f.median_asymmetry = 0.059; f.bandwidth_stability = 0.98;
    f.measurements.resize(7);  // count only is serialized
    std::vector<uint8_t> got = f.serialize();

    std::vector<uint8_t> old(36); size_t o = 0;
    memcpy(old.data()+o,&f.median_upload_mbps,8); o+=8;
    memcpy(old.data()+o,&f.median_download_mbps,8); o+=8;
    memcpy(old.data()+o,&f.median_asymmetry,8); o+=8;
    memcpy(old.data()+o,&f.bandwidth_stability,8); o+=8;
    uint32_t count = static_cast<uint32_t>(f.measurements.size());
    memcpy(old.data()+o,&count,4); o+=4;
    BOOST_CHECK(got == old);

    BandwidthFingerprint r = BandwidthFingerprint::deserialize(got);
    BOOST_CHECK_EQUAL(r.median_download_mbps, f.median_download_mbps);
    BOOST_CHECK_EQUAL(r.bandwidth_stability, f.bandwidth_stability);
}

// ===========================================================================
// GENESIS HASH UNCHANGED — DIL mainnet (legacy/RandomX, 80-byte header).
// ===========================================================================
BOOST_AUTO_TEST_CASE(genesis_dil_mainnet_unchanged) {
    ChainParams* saved = g_chainParams;
    g_chainParams = new ChainParams(ChainParams::Mainnet());
    const std::string frozen = g_chainParams->genesisHash;  // chainparams.cpp constant

    CBlock genesis = Genesis::CreateGenesisBlock();

    // (a) Airtight: the 80-byte header preimage the hash consumes must be
    //     byte-identical to the old host-endian construction. RandomX is a pure
    //     function of these bytes, so identical bytes => identical hash.
    std::vector<uint8_t> newPre = genesis.SerializeHeader();
    BOOST_CHECK(newPre == old_block_serialize_header(genesis));
    BOOST_CHECK_EQUAL(newPre.size(), 80u);

    // (b) End-to-end: compute the actual RandomX genesis hash vs frozen constant.
    const char* rx_key = "Dilithion-RandomX-v1";
    randomx_init_for_hashing(rx_key, strlen(rx_key), 0);  // light init
    genesis.InvalidateCache();
    std::string computed = genesis.GetHash().GetHex();
    BOOST_CHECK_MESSAGE(computed == frozen,
        "DIL genesis hash CHANGED (chain split): computed=" << computed << " frozen=" << frozen);

    delete g_chainParams;
    g_chainParams = saved;
}

// ===========================================================================
// GENESIS HASH UNCHANGED — DilV (VDF/SHA3, 144-byte header).
// ===========================================================================
BOOST_AUTO_TEST_CASE(genesis_dilv_unchanged) {
    ChainParams* saved = g_chainParams;
    g_chainParams = new ChainParams(ChainParams::DilV());
    const std::string frozen = g_chainParams->genesisHash;

    CBlock genesis = Genesis::CreateDilVGenesisBlock();

    // Sanity: must actually be a VDF (v4) block, else the VDF-extension bytes
    // below would be silently skipped and the check would be vacuous.
    BOOST_REQUIRE_MESSAGE(genesis.nVersion == CBlockHeader::VDF_VERSION && genesis.IsVDFBlock(),
        "DilV genesis is not a VDF block (nVersion=" << genesis.nVersion << ") — check vacuous");

    // (a) Airtight: full 144-byte header preimage (80-byte legacy incl. the WF-1
    //     endian sites + 64-byte VDF extension) byte-identical to old host-endian.
    std::vector<uint8_t> newPre = genesis.SerializeHeader();
    BOOST_CHECK(newPre == old_block_serialize_header(genesis));
    BOOST_CHECK_EQUAL(newPre.size(), 144u);

    // (b) End-to-end: actual SHA3-256 genesis hash vs frozen constant. No RandomX
    //     key/VM init needed for VDF blocks.
    genesis.InvalidateCache();
    std::string computed = genesis.GetHash().GetHex();
    BOOST_CHECK_MESSAGE(computed == frozen,
        "DilV genesis hash CHANGED (chain split): computed=" << computed << " frozen=" << frozen);

    delete g_chainParams;
    g_chainParams = saved;
}

BOOST_AUTO_TEST_SUITE_END()
