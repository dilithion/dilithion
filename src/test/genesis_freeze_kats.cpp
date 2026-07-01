// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Genesis-freeze Known-Answer Tests (KATs).
 *
 * PURPOSE — freeze-drift protection, NOT logic change.
 * These tests ASSERT the current, settled-by-code byte-level behavior of two
 * genesis-irreversible surfaces so a future refactor cannot silently drift them
 * before the ION genesis is minted. They add NO consensus logic; every value
 * pinned here is what the live code already produces. If one of these KATs ever
 * FAILS, that means a consensus-relevant byte layout changed — investigate, do
 * not "fix the test".
 *
 * Surfaces pinned (from the genesis-freeze completeness sweep, 2026-07-01):
 *
 *   GAP-4 — VDF challenge preimage.
 *     challenge = SHA3-256( prevHash(32) || height_le32(4) || minerAddr(20) )
 *     = a fixed 56-byte preimage -> a fixed 32-byte challenge.
 *     Source of truth: src/consensus/vdf_validation.cpp:26-41
 *                      (decl src/consensus/vdf_validation.h:48-52)
 *     NOTE on endianness: the height field is written by memcpy'ing a host
 *     uint32_t (vdf_validation.cpp:34-35), i.e. little-endian on the x86-64
 *     build targets. This KAT freezes the CURRENT observed bytes. The sweep
 *     row WF-1 separately tracks the host-endian-vs-explicit-LE question; this
 *     KAT is the drift tripwire for that surface, not its resolution.
 *
 *   GAP-6 — ION script opcode value->semantic map + HTLC template.
 *     OP_SHA3_256 = 0xa8  -> single SHA3-256 (NOT Bitcoin's OP_SHA256).
 *     OP_HASH160  = 0xa9  -> double-SHA3-256 truncated to 20 bytes
 *                            (NOT Bitcoin's RIPEMD160(SHA256)).
 *     Source of truth: opcode values  src/script/script.h:88-95
 *                      handlers       src/script/interpreter.cpp:430-459
 *                      HTLC template  src/script/htlc.cpp:21-62
 *     These KATs pin the exact opcode OUTPUT bytes on a fixed input, so the
 *     "port the Bitcoin Core interpreter" directive (register C-14) can never
 *     be misread as "adopt Bitcoin's opcode SEMANTICS".
 *
 * Run: ./genesis_freeze_kats
 */

#include <consensus/vdf_validation.h>
#include <primitives/block.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <script/htlc.h>
#include <crypto/sha3.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// ============================================================================
// Minimal test framework (same pattern as src/test/script_tests.cpp)
// ============================================================================

static int passed = 0;
static int failed = 0;

#define TEST(name) \
    do { std::cout << "  " << #name << "... "; std::cout.flush(); } while (0)

#define PASS() \
    do { std::cout << "PASS\n"; ++passed; } while (0)

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cout << "FAIL (" << #cond << ")\n"; \
            ++failed; \
            return; \
        } \
    } while (0)

// ============================================================================
// Hex helpers
// ============================================================================

static std::string ToHex(const uint8_t* p, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(k[p[i] >> 4]);
        s.push_back(k[p[i] & 0x0f]);
    }
    return s;
}

template <size_t N>
static std::string ToHex(const std::array<uint8_t, N>& a) {
    return ToHex(a.data(), N);
}

static std::string ToHex(const std::vector<uint8_t>& v) {
    return ToHex(v.data(), v.size());
}

// Double-SHA3-256 truncated to 20 bytes — the reference definition of
// OP_HASH160 / WalletCrypto::HashPubKey. Kept local so the KAT is an
// INDEPENDENT witness of the interpreter's handler, not a call into it.
static std::vector<uint8_t> RefHash160(const std::vector<uint8_t>& data) {
    uint8_t h1[32], h2[32];
    SHA3_256(data.data(), data.size(), h1);
    SHA3_256(h1, 32, h2);
    return std::vector<uint8_t>(h2, h2 + 20);
}

// ============================================================================
// Fixed KAT inputs (arbitrary but PINNED — never change these)
// ============================================================================

// prevHash = 0x00,0x01,...,0x1f  (bytes 0..31 in order)
static uint256 KatPrevHash() {
    uint256 h;
    for (int i = 0; i < 32; ++i) h.data[i] = static_cast<uint8_t>(i);
    return h;
}

// height = 123456 (0x0001e240)
static const int KAT_HEIGHT = 123456;

// minerAddr = 0x20,0x21,...,0x33  (bytes 32..51 in order)
static std::array<uint8_t, 20> KatMinerAddr() {
    std::array<uint8_t, 20> a{};
    for (int i = 0; i < 20; ++i) a[i] = static_cast<uint8_t>(32 + i);
    return a;
}

// ---------------------------------------------------------------------------
// GOLDEN VALUES — the frozen bytes. A change here is a consensus change.
// ---------------------------------------------------------------------------

// GAP-4: the exact 56-byte VDF challenge preimage for (KatPrevHash, 123456,
// KatMinerAddr). prevHash(32) || 40e20100 (123456 LE) || minerAddr(20).
static const char* KAT_VDF_PREIMAGE_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"  // prevHash
    "40e20100"                                                          // height 123456 LE
    "202122232425262728292a2b2c2d2e2f30313233";                        // minerAddr

// GAP-4: SHA3-256 of that 56-byte preimage.
static const char* KAT_VDF_CHALLENGE_HEX =
    "c675d0588dd8d3c91591de53f878f12b0c20e86014995caea9f41e370bd40718";

// GAP-6: OP_SHA3_256 output on the ASCII input "abc" (0x616263).
// This is the standard NIST SHA3-256("abc") test vector — a built-in
// corroboration that the chain hash is SHA3-256, not Keccak-256.
static const char* KAT_SHA3_ABC_HEX =
    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";

// GAP-6: OP_HASH160 (double-SHA3-256[:20]) output on the ASCII input "abc".
static const char* KAT_HASH160_ABC_HEX =
    "f6362cbb9fb8a60f03c2f0d8124d2c6a1a828e2d";

// ============================================================================
// GAP-4 — VDF challenge preimage KAT
// ============================================================================

// The preimage is a private detail of ComputeVDFChallenge, so we reconstruct
// it here byte-for-byte per the documented layout and assert (a) it matches the
// pinned golden and (b) SHA3-256(preimage) == ComputeVDFChallenge(...). If the
// production layout drifts, the challenge KAT below breaks even if this doesn't.
static void test_gap4_vdf_challenge_preimage_layout() {
    TEST(gap4_vdf_challenge_preimage_layout);

    uint256 prev = KatPrevHash();
    std::array<uint8_t, 20> addr = KatMinerAddr();

    // Reconstruct the 56-byte preimage exactly as vdf_validation.cpp:31-37 does.
    uint8_t preimage[56];
    std::memcpy(preimage, prev.data, 32);
    uint32_t hLE = static_cast<uint32_t>(KAT_HEIGHT);
    std::memcpy(preimage + 32, &hLE, 4);
    std::memcpy(preimage + 36, addr.data(), 20);

    // (a) preimage bytes are frozen.
    CHECK(ToHex(preimage, 56) == std::string(KAT_VDF_PREIMAGE_HEX));

    // Independent SHA3 of the reconstructed preimage.
    uint8_t expect[32];
    SHA3_256(preimage, 56, expect);
    std::cout << "\n    [pin] VDF preimage    = " << ToHex(preimage, 56)
              << "\n    [pin] VDF challenge   = " << ToHex(expect, 32) << "\n  ...";

    CHECK(ToHex(expect, 32) == std::string(KAT_VDF_CHALLENGE_HEX));
    PASS();
}

static void test_gap4_vdf_challenge_matches_production() {
    TEST(gap4_vdf_challenge_matches_production);

    uint256 prev = KatPrevHash();
    std::array<uint8_t, 20> addr = KatMinerAddr();

    // The actual production function under freeze.
    std::array<uint8_t, 32> got = ComputeVDFChallenge(prev, KAT_HEIGHT, addr);

    // (b) production output == pinned golden challenge.
    CHECK(ToHex(got) == std::string(KAT_VDF_CHALLENGE_HEX));
    PASS();
}

// ============================================================================
// GAP-6 — opcode value -> semantic map
// ============================================================================

// The opcode NUMBERS themselves are consensus. Pin them so a renumber is caught.
static void test_gap6_opcode_numbers_frozen() {
    TEST(gap6_opcode_numbers_frozen);
    CHECK(static_cast<uint8_t>(OP_SHA3_256) == 0xa8);
    CHECK(static_cast<uint8_t>(OP_HASH160) == 0xa9);
    CHECK(static_cast<uint8_t>(OP_CHECKLOCKTIMEVERIFY) == 0xb1);
    CHECK(static_cast<uint8_t>(OP_CHECKSEQUENCEVERIFY) == 0xb2);
    PASS();
}

// OP_SHA3_256 must be a single SHA3-256 (NOT Bitcoin's OP_SHA256).
// Execute the opcode through the real interpreter and pin the output bytes.
static void test_gap6_op_sha3_256_output_frozen() {
    TEST(gap6_op_sha3_256_output_frozen);

    std::vector<uint8_t> in = {'a', 'b', 'c'};

    CScript s;
    s << in << OP_SHA3_256;

    std::vector<std::vector<uint8_t>> stack;
    class NullChecker : public SignatureChecker {
    public:
        bool CheckSig(const std::vector<uint8_t>&, const std::vector<uint8_t>&) const override { return false; }
        bool CheckLockTime(int64_t) const override { return false; }
        bool CheckSequence(int64_t) const override { return false; }
    } checker;
    std::string err;

    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, checker, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0].size() == 32);

    // Frozen golden output.
    CHECK(ToHex(stack[0]) == std::string(KAT_SHA3_ABC_HEX));

    // Cross-check: interpreter output == a direct one-shot SHA3-256("abc").
    uint8_t direct[32];
    SHA3_256(in.data(), in.size(), direct);
    CHECK(ToHex(stack[0]) == ToHex(direct, 32));

    PASS();
}

// OP_HASH160 must be double-SHA3-256[:20] (NOT RIPEMD160(SHA256)).
static void test_gap6_op_hash160_is_double_sha3_trunc20() {
    TEST(gap6_op_hash160_is_double_sha3_trunc20);

    std::vector<uint8_t> in = {'a', 'b', 'c'};

    CScript s;
    s << in << OP_HASH160;

    std::vector<std::vector<uint8_t>> stack;
    class NullChecker : public SignatureChecker {
    public:
        bool CheckSig(const std::vector<uint8_t>&, const std::vector<uint8_t>&) const override { return false; }
        bool CheckLockTime(int64_t) const override { return false; }
        bool CheckSequence(int64_t) const override { return false; }
    } checker;
    std::string err;

    CHECK(EvalScript(stack, s, SCRIPT_VERIFY_NONE, checker, err));
    CHECK(stack.size() == 1);
    CHECK(stack[0].size() == 20);  // truncated to 20 bytes

    // Frozen golden output.
    CHECK(ToHex(stack[0]) == std::string(KAT_HASH160_ABC_HEX));

    // Cross-check 1: interpreter output == double-SHA3-256[:20].
    CHECK(stack[0] == RefHash160(in));

    // Cross-check 2 (NEGATIVE): the output must NOT be a single SHA3-256
    // truncated to 20 bytes — proves it is a DOUBLE hash, not a single.
    uint8_t single[32];
    SHA3_256(in.data(), in.size(), single);
    CHECK(std::memcmp(stack[0].data(), single, 20) != 0);

    PASS();
}

// The HTLC template's opcode GRAMMAR is frozen: the hashlock branch uses
// OP_SHA3_256 and the key branches use OP_HASH160. Pin the opcode sequence so
// the template can't silently re-home to different hash opcodes.
static void test_gap6_htlc_template_opcode_grammar() {
    TEST(gap6_htlc_template_opcode_grammar);

    HTLCParameters p;
    p.hash_lock = std::vector<uint8_t>(32, 0x11);          // 32-byte SHA3 image
    p.claim_pubkey_hash = std::vector<uint8_t>(20, 0x22);  // 20-byte hash160
    p.refund_pubkey_hash = std::vector<uint8_t>(20, 0x33);
    p.timeout_height = 500;

    CScript script = CreateHTLCScript(p);

    // Walk the script and collect the opcode skeleton (opcodes only, data
    // pushes recorded as a single sentinel 0x00 marker position).
    std::vector<uint8_t> opcodes;
    {
        size_t i = 0;
        const std::vector<uint8_t>& raw = script;
        while (i < raw.size()) {
            uint8_t op = raw[i++];
            if (op >= 1 && op <= 75) {
                // direct data push of `op` bytes
                i += op;
                opcodes.push_back(0x00);  // sentinel: "a data push happened"
            } else {
                opcodes.push_back(op);
            }
        }
    }

    // Expected skeleton (0x00 = data push):
    //  IF SHA3_256 <hash_lock> EQUALVERIFY DUP HASH160 <claim> EQUALVERIFY CHECKSIG
    //  ELSE <timeout> CHECKLOCKTIMEVERIFY DROP DUP HASH160 <refund> EQUALVERIFY CHECKSIG
    //  ENDIF
    const std::vector<uint8_t> expect = {
        OP_IF,
        OP_SHA3_256, 0x00, OP_EQUALVERIFY,
        OP_DUP, OP_HASH160, 0x00, OP_EQUALVERIFY, OP_CHECKSIG,
        OP_ELSE,
        0x00, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
        OP_DUP, OP_HASH160, 0x00, OP_EQUALVERIFY, OP_CHECKSIG,
        OP_ENDIF,
    };

    std::cout << "\n    [pin] HTLC opcode skel = " << ToHex(opcodes) << "\n  ...";
    CHECK(opcodes == expect);

    // The hashlock opcode is specifically OP_SHA3_256 (index 1 in the skeleton).
    CHECK(opcodes[1] == static_cast<uint8_t>(OP_SHA3_256));

    PASS();
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::cout << "Genesis-freeze KATs (VDF challenge + opcode semantics)\n";
    std::cout << "=====================================================\n";

    std::cout << "GAP-4 VDF challenge preimage:\n";
    test_gap4_vdf_challenge_preimage_layout();
    test_gap4_vdf_challenge_matches_production();

    std::cout << "GAP-6 opcode value->semantic map + HTLC template:\n";
    test_gap6_opcode_numbers_frozen();
    test_gap6_op_sha3_256_output_frozen();
    test_gap6_op_hash160_is_double_sha3_trunc20();
    test_gap6_htlc_template_opcode_grammar();

    std::cout << "=====================================================\n";
    std::cout << "passed=" << passed << " failed=" << failed << "\n";
    return failed == 0 ? 0 : 1;
}
