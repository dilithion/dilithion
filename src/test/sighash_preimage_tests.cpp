// Copyright (c) 2025-2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DIFFERENTIAL byte-equality proof for the single-source sighash preimage,
 * wired into the Boost test suite so CI (which builds+runs test_dilithion)
 * exercises it on every run.
 *
 * This is the SAFETY PROOF for the sighash refactor. Before the refactor, FIVE
 * sign/verify sites each hand-built the ML-DSA preimage
 *   tx_signing_hash(32) || input_idx(4LE) || tx_version(4LE) || chain_id(4LE)
 * and SHA3-256'd it. This refactor collapses them into one BuildSighashPreimage.
 *
 * A single divergent byte between a SIGN site and a VERIFY site would make every
 * spend fail to verify — a total, unrecoverable spend freeze (a chain-splitting
 * / liveness bug). So we do NOT trust "looks the same": we reproduce the EXACT
 * pre-refactor open-coded byte sequence here (the "legacy" reference), run it and
 * the new helper over many representative inputs, and assert byte-for-byte
 * equality of both the 44-byte preimage AND the final 32-byte SHA3 digest.
 *
 * Byte-inequality on ANY vector => the refactor is NOT byte-equal => FAIL.
 *
 * Mutation-kill property: the forward-compat suite_id argument MUST NOT change
 * any v0 byte. A mutation that made suite_id leak into the layout would flip a
 * signed byte and desync sign/verify — this suite asserts suite_id is inert.
 *
 * NOTE: the standalone `sighash_differential_tests` binary (src/test/
 * sighash_differential_tests.cpp) retains the same proof for a no-Boost local
 * run; THIS file is the CI-run copy. Keep the two in lockstep.
 */

#include <boost/test/unit_test.hpp>

#include <consensus/sighash_preimage.h>
#include <crypto/sha3.h>
#include <uint256.h>

#include <cstdint>
#include <cstring>
#include <vector>

// Part of main Boost test suite (no BOOST_TEST_MODULE here - defined in test_dilithion.cpp)

namespace {

// ---------------------------------------------------------------------------
// LEGACY reference: the EXACT open-coded preimage assembly that lived at all
// five sites before the refactor (interpreter.cpp / tx_validation.cpp /
// wallet.cpp / server.cpp x2). Copied verbatim in structure so any drift in the
// new helper is caught. Do NOT "simplify" this — it is the ground truth.
// ---------------------------------------------------------------------------
std::vector<uint8_t> LegacyBuildPreimage(const uint256& tx_hash,
                                         uint32_t input_idx,
                                         uint32_t version,
                                         uint32_t chain_id) {
    std::vector<uint8_t> sig_message;
    sig_message.reserve(44);

    // Transaction hash (32 bytes)
    sig_message.insert(sig_message.end(), tx_hash.begin(), tx_hash.end());

    // Input index (4 bytes LE)
    sig_message.push_back(static_cast<uint8_t>(input_idx & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((input_idx >> 24) & 0xFF));

    // Transaction version (4 bytes LE)
    sig_message.push_back(static_cast<uint8_t>(version & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));

    // Chain ID (4 bytes LE)
    sig_message.push_back(static_cast<uint8_t>(chain_id & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 8) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 16) & 0xFF));
    sig_message.push_back(static_cast<uint8_t>((chain_id >> 24) & 0xFF));

    return sig_message;
}

void LegacyComputeSighash(const uint256& tx_hash,
                          uint32_t input_idx,
                          uint32_t version,
                          uint32_t chain_id,
                          uint8_t out[32]) {
    std::vector<uint8_t> m = LegacyBuildPreimage(tx_hash, input_idx, version, chain_id);
    SHA3_256(m.data(), m.size(), out);
}

// Build a uint256 with a repeating fill byte so vectors are reproducible.
uint256 FillHash(uint8_t b) {
    uint256 h;
    memset(h.data, b, 32);
    return h;
}

// Build a uint256 with a per-byte pattern (i*step + base) to exercise ordering.
uint256 PatternHash(uint8_t base, uint8_t step) {
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data[i] = static_cast<uint8_t>(base + i * step);
    return h;
}

struct Vec { uint256 hash; uint32_t idx; uint32_t version; uint32_t chain_id; const char* name; };

// Representative inputs: varied txid (fill + pattern), varied idx (incl. 0,
// max, high-bit-set), varied version, varied chainId (DIL/DilV-ish + edge).
std::vector<Vec> Vectors() {
    return {
        { FillHash(0x00), 0,          1,          1,          "all-zero hash, idx0, v1, chain1" },
        { FillHash(0xFF), 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, "all-ones hash, max idx/v/chain" },
        { FillHash(0x42), 1,          1,          1,          "0x42 hash, idx1" },
        { PatternHash(0x01, 0x07), 7, 2,          0x00000539, "pattern hash, idx7, v2, chain 1337" },
        { PatternHash(0x80, 0x03), 0x00010000, 3, 0x00A5C0DE, "pattern hash, idx 65536, v3" },
        { FillHash(0x99), 0x7FFFFFFF, 4,          0x80000000, "high-bit idx/chain edge" },
        { PatternHash(0xAB, 0xFD), 42, 0x0000000A, 0x0000002A, "another pattern, mid values" },
        { FillHash(0x01), 0x000000FF, 5,          0xDEADBEEF, "byte-boundary idx 255" },
        { FillHash(0x10), 0x0000FF00, 6,          0x0000ABCD, "idx 0xFF00 (2nd byte)" },
        { FillHash(0x20), 0x00FF0000, 7,          0x00FEDCBA, "idx 0xFF0000 (3rd byte)" },
    };
}

}  // namespace

BOOST_AUTO_TEST_SUITE(sighash_preimage_tests)

// ---------------------------------------------------------------------------
// The 44-byte preimage produced by the single-source helper must be BYTE-EQUAL
// to the legacy open-coded assembly across every representative vector.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(preimage_44_bytes_equal_to_legacy) {
    for (const auto& v : Vectors()) {
        std::vector<uint8_t> legacy = LegacyBuildPreimage(v.hash, v.idx, v.version, v.chain_id);
        std::vector<uint8_t> helper =
            Consensus::BuildSighashPreimage(v.hash, v.idx, v.version, v.chain_id,
                                            /*suite_id (v0: ignored)=*/0);

        BOOST_REQUIRE_MESSAGE(legacy.size() == 44,
            std::string("legacy preimage size != 44 for vector: ") + v.name);
        BOOST_REQUIRE_MESSAGE(helper.size() == 44,
            std::string("helper preimage size != 44 for vector: ") + v.name);

        // Byte-for-byte equality; on failure, report the first divergent byte.
        bool equal = (legacy == helper);
        if (!equal) {
            for (size_t i = 0; i < 44; ++i) {
                BOOST_CHECK_MESSAGE(legacy[i] == helper[i],
                    std::string("byte divergence for vector '") + v.name + "'");
            }
        }
        BOOST_CHECK_MESSAGE(equal,
            std::string("44-byte PREIMAGE differs for vector: ") + v.name);
    }
}

// ---------------------------------------------------------------------------
// MUTATION-KILL: the forward-compat suite_id argument must NOT affect the v0
// 44-byte layout. Any code path that let suite_id leak into the bytes would be
// caught here (and would desync sign vs verify on the live chain).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(suite_id_is_inert_for_v0_layout) {
    for (const auto& v : Vectors()) {
        std::vector<uint8_t> helper0 =
            Consensus::BuildSighashPreimage(v.hash, v.idx, v.version, v.chain_id, /*suite_id=*/0);
        std::vector<uint8_t> helper7 =
            Consensus::BuildSighashPreimage(v.hash, v.idx, v.version, v.chain_id, /*suite_id=*/7);

        BOOST_CHECK_MESSAGE(helper7 == helper0,
            std::string("suite_id changed the v0 44-byte layout (must be inert) for vector: ")
                + v.name);
    }
}

// ---------------------------------------------------------------------------
// The 32-byte SHA3 digest (the ACTUAL signed message) produced by the helper's
// ComputeSighash must be byte-equal to the legacy compute across every vector.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(digest_32_bytes_equal_to_legacy) {
    for (const auto& v : Vectors()) {
        uint8_t legacy_hash[32];
        uint8_t helper_hash[32];
        LegacyComputeSighash(v.hash, v.idx, v.version, v.chain_id, legacy_hash);
        Consensus::ComputeSighash(v.hash, v.idx, v.version, v.chain_id, helper_hash);

        BOOST_CHECK_MESSAGE(memcmp(legacy_hash, helper_hash, 32) == 0,
            std::string("32-byte SHA3 DIGEST differs for vector: ") + v.name);
    }
}

BOOST_AUTO_TEST_SUITE_END()
