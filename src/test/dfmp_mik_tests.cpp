// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * DFMP v2.0 Mining Identity Key (MIK) Unit Tests
 *
 * Tests:
 * 1. MIK generation (Dilithium3 keypair)
 * 2. MIK signing and verification
 * 3. Identity derivation from pubkey
 * 4. ScriptSig building and parsing
 * 5. Maturity penalty calculation
 * 6. Heat penalty calculation
 * 7. Total multiplier calculation
 */

#include <dfmp/mik.h>
#include <dfmp/dfmp.h>
#include <uint256.h>

#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <algorithm>

// ANSI color codes
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

// Test result tracking
int g_tests_passed = 0;
int g_tests_failed = 0;

// Helper macros
#define TEST(name) \
    void test_##name(); \
    void test_##name##_wrapper() { \
        std::cout << BLUE << "[TEST] " << #name << RESET << std::endl; \
        try { \
            test_##name(); \
            std::cout << GREEN << "  PASSED" << RESET << std::endl; \
            g_tests_passed++; \
        } catch (const std::exception& e) { \
            std::cout << RED << "  FAILED: " << e.what() << RESET << std::endl; \
            g_tests_failed++; \
        } catch (...) { \
            std::cout << RED << "  FAILED: Unknown exception" << RESET << std::endl; \
            g_tests_failed++; \
        } \
    } \
    void test_##name()

#define ASSERT(condition, message) \
    if (!(condition)) { \
        throw std::runtime_error(message); \
    }

#define ASSERT_EQ(a, b, message) \
    if ((a) != (b)) { \
        throw std::runtime_error(std::string(message) + " (expected " + std::to_string(b) + ", got " + std::to_string(a) + ")"); \
    }

#define ASSERT_NEAR(a, b, epsilon, message) \
    if (std::abs((a) - (b)) > (epsilon)) { \
        throw std::runtime_error(std::string(message) + " (expected ~" + std::to_string(b) + ", got " + std::to_string(a) + ")"); \
    }

// =======================================================================
// Test 1: MIK Generation
// =======================================================================
TEST(mik_generation) {
    DFMP::CMiningIdentityKey mik;

    // Initially should be invalid
    ASSERT(!mik.IsValid(), "New MIK should be invalid");
    ASSERT(!mik.HasPrivateKey(), "New MIK should not have private key");

    // Generate keypair
    bool generated = mik.Generate();
    ASSERT(generated, "MIK generation should succeed");

    // Should now be valid
    ASSERT(mik.IsValid(), "Generated MIK should be valid");
    ASSERT(mik.HasPrivateKey(), "Generated MIK should have private key");

    // Check key sizes
    ASSERT_EQ(mik.pubkey.size(), DFMP::MIK_PUBKEY_SIZE, "Pubkey size incorrect");
    ASSERT_EQ(mik.privkey.size(), DFMP::MIK_PRIVKEY_SIZE, "Privkey size incorrect");

    // Identity should be derived
    ASSERT(!mik.identity.IsNull(), "Identity should not be null");

    std::cout << "    Generated MIK identity: " << mik.GetIdentityHex() << std::endl;
    std::cout << "    Pubkey size: " << mik.pubkey.size() << " bytes" << std::endl;
    std::cout << "    Privkey size: " << mik.privkey.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 2: MIK Signing and Verification
// =======================================================================
TEST(mik_sign_verify) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create test message parameters
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    int height = 12345;
    uint32_t timestamp = 1700000000;

    // Sign
    std::vector<uint8_t> signature;
    bool signed_ok = mik.Sign(prevHash, height, timestamp, signature);
    ASSERT(signed_ok, "Signing should succeed");
    ASSERT_EQ(signature.size(), DFMP::MIK_SIGNATURE_SIZE, "Signature size incorrect");

    // Verify with correct parameters
    bool verified = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, prevHash, height, timestamp, mik.identity);
    ASSERT(verified, "Verification should succeed with correct parameters");

    // Verify with wrong height should fail
    bool wrong_height = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, prevHash, height + 1, timestamp, mik.identity);
    ASSERT(!wrong_height, "Verification should fail with wrong height");

    // --- Timestamp tolerance contract (v4.0.20, commit 77dcb748) ---------
    // The signature is made at wall-clock T1 (RPC) but the block's final nTime
    // is set at T3 (after VDF + grace). VerifyMIKSignature therefore accepts a
    // signature whose signed timestamp lies in
    //     [nTime - kMIKVerifyBackwardWindowSeconds, nTime]
    // i.e. tolerance is BACKWARD ONLY and BOUNDED. Both halves are consensus-
    // relevant: unbounded tolerance would let a signature be replayed onto an
    // arbitrarily later block, forward tolerance would do the same backwards.

    // Inside the window (signed T, block nTime = T+1) -> accepted.
    ASSERT(DFMP::VerifyMIKSignature(
               mik.pubkey, signature, prevHash, height, timestamp + 1, mik.identity),
           "Verification should ACCEPT nTime 1s after the signed timestamp (backward window)");

    // Exactly at the far edge of the window -> accepted.
    ASSERT(DFMP::VerifyMIKSignature(
               mik.pubkey, signature, prevHash, height,
               timestamp + DFMP::kMIKVerifyBackwardWindowSeconds, mik.identity),
           "Verification should ACCEPT nTime at exactly the window edge");

    // One second past the window -> rejected. (Window is bounded.)
    ASSERT(!DFMP::VerifyMIKSignature(
               mik.pubkey, signature, prevHash, height,
               timestamp + DFMP::kMIKVerifyBackwardWindowSeconds + 1, mik.identity),
           "Verification should REJECT nTime one second beyond the backward window");

    // Earlier nTime than the signed timestamp -> rejected. (No forward tolerance.)
    ASSERT(!DFMP::VerifyMIKSignature(
               mik.pubkey, signature, prevHash, height, timestamp - 1, mik.identity),
           "Verification should REJECT nTime earlier than the signed timestamp");

    // The strict entry point must reject any timestamp but the exact one.
    ASSERT(DFMP::VerifyMIKSignatureExact(
               mik.pubkey, signature, prevHash, height, timestamp, mik.identity),
           "Exact verification should succeed on the exact timestamp");
    ASSERT(!DFMP::VerifyMIKSignatureExact(
               mik.pubkey, signature, prevHash, height, timestamp + 1, mik.identity),
           "Exact verification should fail on any other timestamp");

    // Verify with wrong prevHash should fail
    uint256 wrongHash;
    wrongHash.SetHex("0000000000000000000000000000000000000000000000000000000000000002");
    bool wrong_hash = DFMP::VerifyMIKSignature(
        mik.pubkey, signature, wrongHash, height, timestamp, mik.identity);
    ASSERT(!wrong_hash, "Verification should fail with wrong prevHash");

    std::cout << "    Signature size: " << signature.size() << " bytes" << std::endl;
    std::cout << "    Verification tests passed" << std::endl;
}

// =======================================================================
// Test 3: Identity Derivation
// =======================================================================
TEST(identity_derivation) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Derive identity from pubkey
    DFMP::Identity derived = DFMP::DeriveIdentityFromMIK(mik.pubkey);

    // Should match the stored identity
    ASSERT(derived == mik.identity, "Derived identity should match stored identity");
    ASSERT(!derived.IsNull(), "Derived identity should not be null");

    // Identity should be 20 bytes (displayed as 40 hex chars)
    std::string hex = derived.GetHex();
    ASSERT_EQ(hex.length(), 40, "Identity hex should be 40 characters");

    // Deriving from empty pubkey should return null identity
    std::vector<uint8_t> emptyPubkey;
    DFMP::Identity nullIdentity = DFMP::DeriveIdentityFromMIK(emptyPubkey);
    ASSERT(nullIdentity.IsNull(), "Empty pubkey should give null identity");

    std::cout << "    Identity: " << hex << std::endl;
}

// =======================================================================
// Test 4: ScriptSig Registration Building and Parsing
// =======================================================================
TEST(scriptsig_registration) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create signature
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    std::vector<uint8_t> signature;
    ASSERT(mik.Sign(prevHash, 1, 1700000000, signature), "Signing failed");

    // --- Legacy (pre-v3.0) registration: no PoW nonce -------------------
    // marker(1) + type(1) + pubkey(1952) + sig(3309) = 5263 = MIK_REGISTRATION_SIZE_V2
    std::vector<uint8_t> scriptSigData;
    bool built = DFMP::BuildMIKScriptSigRegistration(mik.pubkey, signature, scriptSigData);
    ASSERT(built, "Building registration scriptSig should succeed");

    ASSERT_EQ(scriptSigData.size(), DFMP::MIK_REGISTRATION_SIZE_V2, "Legacy registration size incorrect");

    // Check marker and type
    ASSERT_EQ(scriptSigData[0], DFMP::MIK_MARKER, "Marker byte incorrect");
    ASSERT_EQ(scriptSigData[1], DFMP::MIK_TYPE_REGISTRATION, "Type byte incorrect");

    // Parse it back
    DFMP::CMIKScriptData parsed;
    bool parseOk = DFMP::ParseMIKFromScriptSig(scriptSigData, parsed);
    ASSERT(parseOk, "Parsing registration should succeed");
    ASSERT(parsed.isRegistration, "Should be recognized as registration");
    ASSERT(parsed.identity == mik.identity, "Parsed identity should match");
    ASSERT(parsed.pubkey == mik.pubkey, "Parsed pubkey should match");
    ASSERT(parsed.signature == signature, "Parsed signature should match");
    ASSERT_EQ(parsed.registrationNonce, 0, "Legacy registration should parse nonce as 0");

    // --- v3.0 registration WITH PoW nonce (the path production actually uses)
    // marker(1) + type(1) + pubkey(1952) + sig(3309) + nonce(8) = 5271
    // This is the only form emitted by miner/controller.cpp and both node
    // binaries; the 3-arg builder above has no production callers.
    const uint64_t kNonce = 0x0123456789ABCDEFULL;
    std::vector<uint8_t> nonceData;
    ASSERT(DFMP::BuildMIKScriptSigRegistration(mik.pubkey, signature, kNonce, nonceData),
           "Building v3.0 registration scriptSig should succeed");
    ASSERT_EQ(nonceData.size(), DFMP::MIK_REGISTRATION_SIZE, "v3.0 registration size incorrect");
    ASSERT_EQ(nonceData.size(), DFMP::MIK_REGISTRATION_SIZE_V2 + 8, "v3.0 registration should be legacy + 8");

    DFMP::CMIKScriptData parsedNonce;
    ASSERT(DFMP::ParseMIKFromScriptSig(nonceData, parsedNonce), "Parsing v3.0 registration should succeed");
    ASSERT(parsedNonce.isRegistration, "v3.0 form should be recognized as registration");
    ASSERT(parsedNonce.identity == mik.identity, "v3.0 parsed identity should match");
    ASSERT(parsedNonce.pubkey == mik.pubkey, "v3.0 parsed pubkey should match");
    ASSERT(parsedNonce.signature == signature, "v3.0 parsed signature should match");
    ASSERT(parsedNonce.registrationNonce == kNonce, "v3.0 registration nonce should round-trip");

    std::cout << "    Legacy registration scriptSig size: " << scriptSigData.size() << " bytes" << std::endl;
    std::cout << "    v3.0 registration scriptSig size:   " << nonceData.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 5: ScriptSig Reference Building and Parsing
// =======================================================================
TEST(scriptsig_reference) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");

    // Create signature
    uint256 prevHash;
    prevHash.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    std::vector<uint8_t> signature;
    ASSERT(mik.Sign(prevHash, 100, 1700000000, signature), "Signing failed");

    // Build reference scriptSig data
    std::vector<uint8_t> scriptSigData;
    bool built = DFMP::BuildMIKScriptSigReference(mik.identity, signature, scriptSigData);
    ASSERT(built, "Building reference scriptSig should succeed");

    // Check size: marker(1) + type(1) + identity(20) + sig(3309) = 3331
    ASSERT_EQ(scriptSigData.size(), DFMP::MIK_REFERENCE_MIN_SIZE, "Reference size incorrect");

    // Check marker and type
    ASSERT_EQ(scriptSigData[0], DFMP::MIK_MARKER, "Marker byte incorrect");
    ASSERT_EQ(scriptSigData[1], DFMP::MIK_TYPE_REFERENCE, "Type byte incorrect");

    // Parse it back
    DFMP::CMIKScriptData parsed;
    bool parseOk = DFMP::ParseMIKFromScriptSig(scriptSigData, parsed);
    ASSERT(parseOk, "Parsing reference should succeed");
    ASSERT(!parsed.isRegistration, "Should be recognized as reference");
    ASSERT(parsed.identity == mik.identity, "Parsed identity should match");
    ASSERT(parsed.pubkey.empty(), "Reference should not have pubkey");
    ASSERT(parsed.signature == signature, "Parsed signature should match");

    std::cout << "    Reference scriptSig size: " << scriptSigData.size() << " bytes" << std::endl;
}

// =======================================================================
// Test 6: Maturity Penalty Calculation (v2.0 legacy + v3.0 + live v3.3)
// =======================================================================
// NOTE (2026-08-08): the unversioned DFMP::GetPendingPenalty() was REPURPOSED
// from the v2.0 curve to the v3.0 curve in b0097a96 ("feat: DFMP v3.0"),
// atomically with the introduction of dfmpV3ActivationHeight. The v2.0 curve
// was preserved verbatim under the *_V2 names and is still what pow.cpp runs
// for heights below activation. This test now pins BOTH curves, because both
// are consensus-live for their own height ranges during re-validation.
TEST(maturity_penalty_v2) {
    // ---- v2.0 curve: 3.0 -> 2.5 -> 2.0 -> 1.5 -> 1.0 in 100-block steps ----
    // (pow.cpp path for height < dfmpV3ActivationHeight)
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(100, -1), 3.0, 0.01, "v2.0 new identity should be 3.0x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(100, 100), 3.0, 0.01, "v2.0 age 0 should be 3.0x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(199, 100), 3.0, 0.01, "v2.0 age 99 should be 3.0x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(200, 100), 2.5, 0.01, "v2.0 age 100 should be 2.5x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(300, 100), 2.0, 0.01, "v2.0 age 200 should be 2.0x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(400, 100), 1.5, 0.01, "v2.0 age 300 should be 1.5x");
    ASSERT_NEAR(DFMP::GetMaturityPenalty_V2(500, 100), 1.0, 0.01, "v2.0 age 400+ should be 1.0x");

    // ---- v3.0 curve: 5.0 -> 4.0 -> 3.0 -> 2.0 -> 1.5 -> 1.0, 160-block steps
    // (pow.cpp path for dfmpV3ActivationHeight <= height < dfmpV31ActivationHeight)
    double newPenalty = DFMP::GetPendingPenalty(100, -1);
    ASSERT_NEAR(newPenalty, 5.0, 0.01, "v3.0 new identity should be 5.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(100, 100), 5.0, 0.01, "v3.0 age 0 should be 5.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(259, 100), 5.0, 0.01, "v3.0 age 159 should be 5.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(260, 100), 4.0, 0.01, "v3.0 age 160 should be 4.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(420, 100), 3.0, 0.01, "v3.0 age 320 should be 3.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(580, 100), 2.0, 0.01, "v3.0 age 480 should be 2.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(740, 100), 1.5, 0.01, "v3.0 age 640 should be 1.5x");
    ASSERT_NEAR(DFMP::GetPendingPenalty(900, 100), 1.0, 0.01, "v3.0 age 800 should be 1.0x (mature)");

    // ---- v3.3 curve (LIVE on DIL and DilV today): 2.5 -> 2.0 -> 1.5 -> 1.25
    //      -> 1.1 -> 1.0 in 100-block steps over 500 blocks
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(100, -1), 2.5, 0.01, "v3.3 new identity should be 2.5x");
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(200, 100), 2.0, 0.01, "v3.3 age 100 should be 2.0x");
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(300, 100), 1.5, 0.01, "v3.3 age 200 should be 1.5x");
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(400, 100), 1.25, 0.01, "v3.3 age 300 should be 1.25x");
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(500, 100), 1.1, 0.01, "v3.3 age 400 should be 1.1x");
    ASSERT_NEAR(DFMP::GetPendingPenalty_V33(600, 100), 1.0, 0.01, "v3.3 age 500 should be 1.0x (mature)");

    // The three curves must remain DISTINCT — collapsing them would be a
    // silent consensus change for one of the height ranges.
    ASSERT(DFMP::GetMaturityPenalty_V2(100, -1) != DFMP::GetPendingPenalty(100, -1),
           "v2.0 and v3.0 maturity starts must differ");
    ASSERT(DFMP::GetPendingPenalty(100, -1) != DFMP::GetPendingPenalty_V33(100, -1),
           "v3.0 and v3.3 maturity starts must differ");

    std::cout << "    v2.0 new: " << DFMP::GetMaturityPenalty_V2(100, -1) << "x" << std::endl;
    std::cout << "    v3.0 new: " << newPenalty << "x" << std::endl;
    std::cout << "    v3.3 new: " << DFMP::GetPendingPenalty_V33(100, -1) << "x (live)" << std::endl;
}

// =======================================================================
// Test 7: Heat Penalty Calculation (v2.0)
// =======================================================================
// NOTE (2026-08-08): as with maturity, DFMP::GetHeatMultiplier() was
// repurposed from the v2.0 curve to the v3.0 curve (b0097a96, then the curve
// itself retuned in e28d2fa1). The v2.0 curve survives as GetHeatPenalty_V2().
TEST(heat_penalty_v2) {
    // ---- v2.0 curve: free <=20, linear +0.1/block to 25, then x1.08 ----
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(0),  1.0,  0.01, "v2.0 heat 0 should be 1.0x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(10), 1.0,  0.01, "v2.0 heat 10 should be 1.0x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(20), 1.0,  0.01, "v2.0 heat 20 should be 1.0x (free tier boundary)");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(21), 1.1,  0.01, "v2.0 heat 21 should be 1.1x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(23), 1.3,  0.01, "v2.0 heat 23 should be 1.3x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(25), 1.5,  0.01, "v2.0 heat 25 should be 1.5x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(26), 1.62, 0.02, "v2.0 heat 26 should be ~1.62x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(30), 2.20, 0.05, "v2.0 heat 30 should be ~2.20x");
    ASSERT_NEAR(DFMP::GetHeatPenalty_V2(40), 4.76, 0.10, "v2.0 heat 40 should be ~4.76x");

    // ---- v3.0 curve: free <=12, 2.0x cliff at 13, then x1.58 per block ----
    double heat0 = DFMP::GetHeatMultiplier(0);
    ASSERT_NEAR(heat0, 1.0, 0.01, "v3.0 heat 0 should be 1.0x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier(12), 1.0, 0.01, "v3.0 heat 12 should be 1.0x (free tier boundary)");
    double heat13 = DFMP::GetHeatMultiplier(13);
    ASSERT_NEAR(heat13, 2.0, 0.01, "v3.0 heat 13 should be the 2.0x cliff");
    ASSERT_NEAR(DFMP::GetHeatMultiplier(14), 3.16, 0.01, "v3.0 heat 14 should be 3.16x (2.0 x 1.58)");
    double heat20 = DFMP::GetHeatMultiplier(20);
    ASSERT_NEAR(heat20, 49.162, 0.01, "v3.0 heat 20 should be ~49.16x (2.0 x 1.58^7)");

    // v3.0 dynamic free-tier scaling: with few unique miners the free tier
    // widens to OBSERVATION_WINDOW / uniqueMiners. 360/10 = 36 > 12, so heat
    // 20 becomes free. This is the anti-false-positive guard for small networks.
    ASSERT_NEAR(DFMP::GetHeatMultiplier(20, 10), 1.0, 0.01,
                "v3.0 heat 20 with 10 unique miners should be free (dynamic tier 36)");
    ASSERT_NEAR(DFMP::GetHeatMultiplier(37, 10), 2.0, 0.01,
                "v3.0 heat 37 with 10 unique miners should hit the 2.0x cliff");
    // With many miners the dynamic tier collapses back to the 12-block floor.
    ASSERT_NEAR(DFMP::GetHeatMultiplier(13, 100), 2.0, 0.01,
                "v3.0 dynamic tier must not fall below FREE_TIER_THRESHOLD");

    // ---- v3.3 curve (LIVE): free <=12, linear +0.25/block to 24 (4.0x),
    //      then x1.58 per block. No dynamic scaling.
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(12), 1.00, 0.01, "v3.3 heat 12 should be 1.0x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(13), 1.25, 0.01, "v3.3 heat 13 should be 1.25x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(18), 2.50, 0.01, "v3.3 heat 18 should be 2.5x");
    // Interior of the linear zone. Without these, shortening the linear zone is
    // invisible: the exponential branch's exponent is measured from
    // LINEAR_ZONE_END_V33 too, so an early exit still lands on 4.0x at heat 24.
    // (Mutant M4 survived until these were added.)
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(21), 3.25, 0.01, "v3.3 heat 21 should be 3.25x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(22), 3.50, 0.01, "v3.3 heat 22 should be 3.5x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(23), 3.75, 0.01, "v3.3 heat 23 should be 3.75x");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(24), 4.00, 0.01, "v3.3 heat 24 should be 4.0x (linear zone end)");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(25), 6.32, 0.01, "v3.3 heat 25 should be 6.32x (4.0 x 1.58)");
    ASSERT_NEAR(DFMP::GetHeatMultiplier_V33(30), 62.23, 0.01, "v3.3 heat 30 should be ~62.23x");

    // Monotonicity: heat must never reduce a miner's penalty.
    for (int h = 1; h <= 40; ++h) {
        ASSERT(DFMP::GetHeatMultiplier_V33(h) >= DFMP::GetHeatMultiplier_V33(h - 1),
               "v3.3 heat curve must be monotonically non-decreasing");
        ASSERT(DFMP::GetHeatMultiplier(h) >= DFMP::GetHeatMultiplier(h - 1),
               "v3.0 heat curve must be monotonically non-decreasing");
    }

    std::cout << "    v2.0 heat 25: " << DFMP::GetHeatPenalty_V2(25) << "x" << std::endl;
    std::cout << "    v3.0 cliff (13): " << heat13 << "x, heat 20: " << heat20 << "x" << std::endl;
    std::cout << "    v3.3 heat 24: " << DFMP::GetHeatMultiplier_V33(24) << "x (live)" << std::endl;
}

// =======================================================================
// Test 8: Total Multiplier Calculation
// =======================================================================
TEST(total_multiplier) {
    // ---- v2.0: total = maturity_V2 x heat_V2 ----
    ASSERT_NEAR(DFMP::GetTotalMultiplier_V2(100, -1, 0),  3.00, 0.01, "v2.0 new + no heat should be 3.0x");
    ASSERT_NEAR(DFMP::GetTotalMultiplier_V2(100, -1, 25), 4.50, 0.02, "v2.0 new + heat 25 should be 4.5x");
    ASSERT_NEAR(DFMP::GetTotalMultiplier_V2(600, 100, 30), 2.20, 0.05, "v2.0 mature + heat 30 should be ~2.2x");
    ASSERT_NEAR(DFMP::GetTotalMultiplier_V2(200, 100, 21), 2.75, 0.02, "v2.0 age 100 + heat 21 should be 2.75x");

    // ---- v3.0: total = maturity_v3.0 x heat_v3.0 ----
    // New identity, no heat: 5.0 * 1.0
    double total1 = DFMP::GetTotalMultiplier(100, -1, 0);
    ASSERT_NEAR(total1, 5.0, 0.01, "v3.0 new + no heat should be 5.0x");

    // New identity at the heat cliff: 5.0 * 2.0
    double total2 = DFMP::GetTotalMultiplier(100, -1, 13);
    ASSERT_NEAR(total2, 10.0, 0.02, "v3.0 new + heat 13 should be 10.0x");

    // Mature identity (age 800), heat 14: 1.0 * 3.16
    double total3 = DFMP::GetTotalMultiplier(900, 100, 14);
    ASSERT_NEAR(total3, 3.16, 0.02, "v3.0 mature + heat 14 should be ~3.16x");

    // Age 160 (4.0x), free-tier heat: 4.0 * 1.0
    double total4 = DFMP::GetTotalMultiplier(260, 100, 12);
    ASSERT_NEAR(total4, 4.0, 0.02, "v3.0 age 160 + free-tier heat should be 4.0x");

    // Total must be the product of its two factors, for every combination
    // sampled — the factorisation is the DFMP invariant, not an accident.
    for (int age : {0, 160, 320, 800}) {
        for (int heat : {0, 12, 13, 16}) {
            double expected = DFMP::GetPendingPenalty(100 + age, 100) * DFMP::GetHeatMultiplier(heat);
            double actual = DFMP::GetTotalMultiplier(100 + age, 100, heat);
            ASSERT_NEAR(actual, expected, std::max(0.001, expected * 1e-5),
                        "v3.0 total must equal maturity x heat");
        }
    }

    std::cout << "    v3.0 new + no heat: " << total1 << "x" << std::endl;
    std::cout << "    v3.0 new + cliff heat: " << total2 << "x" << std::endl;
    std::cout << "    v3.0 mature + heat 14: " << total3 << "x" << std::endl;
    std::cout << "    v3.0 age 160 + free heat: " << total4 << "x" << std::endl;
}

// =======================================================================
// Test 9: Constants Verification
// =======================================================================
TEST(constants_verification) {
    // Verify key sizes match Dilithium3 spec
    ASSERT_EQ(DFMP::MIK_PUBKEY_SIZE, 1952, "Pubkey size should be 1952");
    ASSERT_EQ(DFMP::MIK_PRIVKEY_SIZE, 4032, "Privkey size should be 4032");
    ASSERT_EQ(DFMP::MIK_SIGNATURE_SIZE, 3309, "Signature size should be 3309");
    ASSERT_EQ(DFMP::MIK_IDENTITY_SIZE, 20, "Identity size should be 20");

    // Verify marker bytes
    ASSERT_EQ(DFMP::MIK_MARKER, 0xDF, "MIK marker should be 0xDF");
    ASSERT_EQ(DFMP::MIK_TYPE_REGISTRATION, 0x01, "Registration type should be 0x01");
    ASSERT_EQ(DFMP::MIK_TYPE_REFERENCE, 0x02, "Reference type should be 0x02");

    // ScriptSig payload sizes: the two registration wire formats must stay
    // exactly 8 bytes apart (the v3.0 PoW nonce) and must not drift.
    ASSERT_EQ(DFMP::MIK_REGISTRATION_SIZE_V2, 5263, "Legacy registration size should be 5263");
    ASSERT_EQ(DFMP::MIK_REGISTRATION_SIZE, 5271, "v3.0 registration size should be 5271");
    ASSERT_EQ(DFMP::MIK_REFERENCE_MIN_SIZE, 3331, "Reference size should be 3331");

    // MIK signature timestamp tolerance window (v4.0.20).
    ASSERT_EQ(DFMP::kMIKVerifyBackwardWindowSeconds, 180, "Backward window should be 180s");

    // Verify v3.0 constants (the unversioned names carry the v3.0 values)
    ASSERT_EQ(DFMP::OBSERVATION_WINDOW, 360, "Observation window should be 360");
    ASSERT_EQ(DFMP::FREE_TIER_THRESHOLD, 12, "Free tier should be 12");
    ASSERT_EQ(DFMP::MATURITY_BLOCKS, 800, "Maturity blocks should be 800");
    ASSERT_NEAR(DFMP::PENDING_PENALTY_START, 5.0, 1e-9, "v3.0 maturity start should be 5.0x");
    ASSERT_NEAR(DFMP::HEAT_CLIFF_PENALTY, 2.0, 1e-9, "v3.0 heat cliff should be 2.0x");
    ASSERT_NEAR(DFMP::HEAT_GROWTH_RATE, 1.58, 1e-9, "v3.0 heat growth should be 1.58x");

    // Verify v2.0 constants still exist unchanged (pre-activation consensus)
    ASSERT_EQ(DFMP::FREE_TIER_THRESHOLD_V2, 20, "v2.0 free tier should be 20");
    ASSERT_EQ(DFMP::MATURITY_BLOCKS_V2, 400, "v2.0 maturity blocks should be 400");
    ASSERT_NEAR(DFMP::MATURITY_PENALTY_START_V2, 3.0, 1e-9, "v2.0 maturity start should be 3.0x");

    // Verify v3.3 constants (LIVE on both chains)
    ASSERT_EQ(DFMP::FREE_TIER_THRESHOLD_V33, 12, "v3.3 free tier should be 12");
    ASSERT_EQ(DFMP::LINEAR_ZONE_END_V33, 24, "v3.3 linear zone should end at 24");
    ASSERT_EQ(DFMP::MATURITY_BLOCKS_V32, 500, "v3.2/v3.3 maturity blocks should be 500");

    std::cout << "    All constants verified" << std::endl;
}

// =======================================================================
// Test 10: MIK Clear (Secure Wipe)
// =======================================================================
TEST(mik_clear) {
    DFMP::CMiningIdentityKey mik;
    ASSERT(mik.Generate(), "MIK generation failed");
    ASSERT(mik.IsValid(), "MIK should be valid after generation");

    // Store identity for comparison
    std::string identityBefore = mik.GetIdentityHex();

    // Clear the MIK
    mik.Clear();

    // Should now be invalid
    ASSERT(!mik.IsValid(), "MIK should be invalid after clear");
    ASSERT(!mik.HasPrivateKey(), "MIK should not have private key after clear");
    ASSERT(mik.pubkey.empty(), "Pubkey should be empty after clear");
    ASSERT(mik.privkey.empty(), "Privkey should be empty after clear");
    ASSERT(mik.identity.IsNull(), "Identity should be null after clear");

    std::cout << "    Identity before clear: " << identityBefore << std::endl;
    std::cout << "    MIK securely wiped" << std::endl;
}

// =======================================================================
// Main Test Runner
// =======================================================================
int main() {
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "DFMP v2.0 MIK Unit Tests" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << std::endl;

    // Run all tests
    test_mik_generation_wrapper();
    test_mik_sign_verify_wrapper();
    test_identity_derivation_wrapper();
    test_scriptsig_registration_wrapper();
    test_scriptsig_reference_wrapper();
    test_maturity_penalty_v2_wrapper();
    test_heat_penalty_v2_wrapper();
    test_total_multiplier_wrapper();
    test_constants_verification_wrapper();
    test_mik_clear_wrapper();

    // Print summary
    std::cout << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "Test Summary" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << GREEN << "Passed: " << g_tests_passed << RESET << std::endl;
    std::cout << RED << "Failed: " << g_tests_failed << RESET << std::endl;
    std::cout << YELLOW << "Total:  " << (g_tests_passed + g_tests_failed) << RESET << std::endl;
    std::cout << std::endl;

    if (g_tests_failed == 0) {
        std::cout << GREEN << "ALL TESTS PASSED!" << RESET << std::endl;
        return 0;
    } else {
        std::cout << RED << "SOME TESTS FAILED" << RESET << std::endl;
        return 1;
    }
}
