// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DIFFERENTIAL byte-equality proof for the single-source sighash preimage.
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
 * Standalone (no Boost, no full-node link): depends only on the helper, sha3,
 * and uint256 (primitives/block). Exit code 0 = all vectors byte-equal.
 */

#include <consensus/sighash_preimage.h>
#include <crypto/sha3.h>
#include <uint256.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// LEGACY reference: the EXACT open-coded preimage assembly that lived at all
// five sites before the refactor (interpreter.cpp / tx_validation.cpp /
// wallet.cpp / server.cpp x2). Copied verbatim in structure so any drift in the
// new helper is caught. Do NOT "simplify" this — it is the ground truth.
// ---------------------------------------------------------------------------
static std::vector<uint8_t> LegacyBuildPreimage(const uint256& tx_hash,
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

static void LegacyComputeSighash(const uint256& tx_hash,
                                 uint32_t input_idx,
                                 uint32_t version,
                                 uint32_t chain_id,
                                 uint8_t out[32]) {
    std::vector<uint8_t> m = LegacyBuildPreimage(tx_hash, input_idx, version, chain_id);
    SHA3_256(m.data(), m.size(), out);
}

// Build a uint256 with a repeating fill byte so vectors are reproducible.
static uint256 FillHash(uint8_t b) {
    uint256 h;
    memset(h.data, b, 32);
    return h;
}

// Build a uint256 with a per-byte pattern (i*step + base) to exercise ordering.
static uint256 PatternHash(uint8_t base, uint8_t step) {
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data[i] = static_cast<uint8_t>(base + i * step);
    return h;
}

struct Vec { uint256 hash; uint32_t idx; uint32_t version; uint32_t chain_id; const char* name; };

int main() {
    // Representative inputs: varied txid (fill + pattern), varied idx (incl. 0,
    // max, high-bit-set), varied version, varied chainId (DIL/DilV-ish + edge).
    std::vector<Vec> vectors = {
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

    int failures = 0;
    int checked = 0;

    for (const auto& v : vectors) {
        // --- 44-byte preimage byte-equality ---
        std::vector<uint8_t> legacy = LegacyBuildPreimage(v.hash, v.idx, v.version, v.chain_id);
        std::vector<uint8_t> helper =
            Consensus::BuildSighashPreimage(v.hash, v.idx, v.version, v.chain_id,
                                            /*suite_id (v0: ignored)=*/0);

        ++checked;
        if (legacy.size() != 44 || helper.size() != 44) {
            printf("[FAIL] %s: size mismatch legacy=%zu helper=%zu (expected 44)\n",
                   v.name, legacy.size(), helper.size());
            ++failures;
            continue;
        }
        if (legacy != helper) {
            printf("[FAIL] %s: 44-byte PREIMAGE differs\n", v.name);
            for (size_t i = 0; i < 44; ++i) {
                if (legacy[i] != helper[i])
                    printf("        byte %zu: legacy=0x%02X helper=0x%02X\n",
                           i, legacy[i], helper[i]);
            }
            ++failures;
            continue;
        }

        // --- suite_id must NOT affect v0 bytes (forward-compat arg is inert) ---
        std::vector<uint8_t> helper_suite7 =
            Consensus::BuildSighashPreimage(v.hash, v.idx, v.version, v.chain_id, /*suite_id=*/7);
        ++checked;
        if (helper_suite7 != helper) {
            printf("[FAIL] %s: suite_id changed the v0 44-byte layout (must be inert)\n", v.name);
            ++failures;
            continue;
        }

        // --- 32-byte SHA3 digest byte-equality (the actual signed message) ---
        uint8_t legacy_hash[32];
        uint8_t helper_hash[32];
        LegacyComputeSighash(v.hash, v.idx, v.version, v.chain_id, legacy_hash);
        Consensus::ComputeSighash(v.hash, v.idx, v.version, v.chain_id, helper_hash);
        ++checked;
        if (memcmp(legacy_hash, helper_hash, 32) != 0) {
            printf("[FAIL] %s: 32-byte SHA3 DIGEST differs\n", v.name);
            ++failures;
            continue;
        }

        printf("[ OK ] %s\n", v.name);
    }

    printf("\n%d checks across %zu vectors; %d failure(s)\n",
           checked, vectors.size(), failures);
    if (failures == 0) {
        printf("PASS: single-source sighash preimage is BYTE-EQUAL to the legacy open-coded form.\n");
        return 0;
    }
    printf("FAIL: sighash refactor is NOT byte-equal — chain-splitting risk. DO NOT MERGE.\n");
    return 1;
}
