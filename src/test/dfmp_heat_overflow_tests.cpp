// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * C-3: DFMP heat-penalty integer-overflow hardening — behavioral validator (§3.2)
 *
 * The bug: each versioned heat fn ran `penalty = (penalty * GROWTH) / 100` in a loop.
 * At high heat the `penalty * GROWTH` intermediate overflows int64, wraps to a small/
 * negative value, and CalculateEffectiveTarget then clamps it UP to 1.0x — handing the
 * HEAVIEST miner the EASIEST target (concentration defense nullified, monotonicity broken).
 *
 * The fix: activation-gated saturating fixed-point. With saturate=true the penalty is
 * capped at FP_HEAT_MULTIPLIER_MAX before it can overflow. With saturate=false the math
 * is byte-identical to the legacy binary (below-gate consensus-frozen).
 *
 * Assertions:
 *  - S1/S2  saturate=TRUE: every version, heat 0..360, result in [FP_SCALE, MAX] AND
 *           monotonic non-decreasing. No crash/UB.
 *  - S3     saturate=TRUE at a known overflow input returns MAX (hardest); the legacy
 *           (saturate=FALSE) path differs — proving the fix is load-bearing.
 *  - S4     saturate=FALSE, sub-overflow heat: byte-identical to a hand-replicated legacy
 *           formula (consensus-frozen below gate).
 *  - combinator: CalculateTotalMultiplierFP_V33 with near-cap heat + saturate=TRUE stays
 *           bounded (no product overflow).
 */

#include <dfmp/dfmp.h>

#include <iostream>
#include <string>
#include <cstdint>
#include <climits>

// ANSI color codes
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define RED     "\033[31m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"

int g_tests_passed = 0;
int g_tests_failed = 0;

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

using namespace DFMP;

// ---------------------------------------------------------------------------
// Hand-replicated LEGACY formulas (the exact unmodified pre-fix math).
// Used to prove saturate=false is byte-identical (S4) and that the saturated
// path is load-bearing vs the legacy wrap (S3). NOTE: these intentionally
// reproduce the int64 overflow for high heat (well-defined here only as the
// reference for "what the old binary did" — we compare divergence, not the
// wrapped value itself, to stay clear of relying on signed-overflow UB).
// ---------------------------------------------------------------------------

// Legacy v3.3 heat (no dynamic scaling). Mirrors CalculateHeatMultiplierFP_V33
// with saturate omitted. Uses unsigned accumulation to model the bit pattern
// without invoking signed-overflow UB in the test harness itself.
static int64_t legacyHeatV33(int heat) {
    if (heat <= FREE_TIER_THRESHOLD_V33) return FP_SCALE;
    if (heat <= LINEAR_ZONE_END_V33) {
        int excess = heat - FREE_TIER_THRESHOLD_V33;
        return FP_SCALE + (static_cast<int64_t>(excess) * FP_SCALE) / 4;
    }
    int64_t penalty = FP_LINEAR_END_PENALTY_V33;
    int exponent = heat - LINEAR_ZONE_END_V33;
    for (int i = 0; i < exponent; i++) {
        // Replicate (penalty * 158)/100 in the int64 bit-pattern via uint64.
        uint64_t prod = static_cast<uint64_t>(penalty) * static_cast<uint64_t>(FP_HEAT_GROWTH_V33);
        penalty = static_cast<int64_t>(prod) / 100;
    }
    return penalty;
}

// ---------------------------------------------------------------------------
// Generic per-version heat invocation (saturate threaded through).
// ---------------------------------------------------------------------------
static int64_t heatBase(int heat, bool sat) { return CalculateHeatMultiplierFP(heat, 0, sat); }
static int64_t heatV31(int heat, bool sat)  { return CalculateHeatMultiplierFP_V31(heat, 0, sat); }
static int64_t heatV32(int heat, bool sat)  { return CalculateHeatMultiplierFP_V32(heat, 0, sat); }
static int64_t heatV33(int heat, bool sat)  { return CalculateHeatMultiplierFP_V33(heat, sat); }
static int64_t heatV34v(int heat, bool sat) { return CalculateHeatMultiplierFP_V34(heat, true, sat); }
static int64_t heatV34u(int heat, bool sat) { return CalculateHeatMultiplierFP_V34(heat, false, sat); }

struct VersionFn {
    const char* name;
    int64_t (*fn)(int, bool);
};

static const VersionFn kVersions[] = {
    {"base(v3.0)", heatBase},
    {"v3.1",       heatV31},
    {"v3.2",       heatV32},
    {"v3.3",       heatV33},
    {"v3.4-verified",   heatV34v},
    {"v3.4-unverified", heatV34u},
};

// =======================================================================
// S1 + S2: bounded + monotonic for every version, saturate=TRUE, heat 0..360
// =======================================================================
TEST(s1_s2_bounded_monotonic_all_versions) {
    for (const auto& v : kVersions) {
        int64_t prev = -1;
        for (int heat = 0; heat <= OBSERVATION_WINDOW; heat++) {
            int64_t r = v.fn(heat, /*saturate=*/true);

            // S1: bounded in [FP_SCALE, FP_HEAT_MULTIPLIER_MAX]
            ASSERT(r >= FP_SCALE,
                std::string(v.name) + " heat=" + std::to_string(heat) +
                " below FP_SCALE: " + std::to_string(r));
            ASSERT(r <= FP_HEAT_MULTIPLIER_MAX,
                std::string(v.name) + " heat=" + std::to_string(heat) +
                " above MAX: " + std::to_string(r));

            // S2: monotonic non-decreasing — more history NEVER yields an easier target
            ASSERT(r >= prev,
                std::string(v.name) + " NON-MONOTONIC at heat=" + std::to_string(heat) +
                " (" + std::to_string(r) + " < prev " + std::to_string(prev) + ")");
            prev = r;
        }
        std::cout << "    " << v.name << ": bounded + monotonic over heat 0..360 (max="
                  << v.fn(OBSERVATION_WINDOW, true) << ")" << std::endl;
    }
}

// =======================================================================
// S3: known overflow input → saturate=TRUE returns MAX (hardest);
//     legacy saturate=FALSE differs (proves the fix is load-bearing).
// =======================================================================
TEST(s3_overflow_input_hardest_and_load_bearing) {
    const int kOverflowHeat = 90;  // well past where (penalty*158) overflows int64

    // V33 (a live version)
    int64_t satV33 = heatV33(kOverflowHeat, /*saturate=*/true);
    ASSERT(satV33 == FP_HEAT_MULTIPLIER_MAX,
        "V33 heat=90 saturate=true must return FP_HEAT_MULTIPLIER_MAX, got " +
        std::to_string(satV33));

    int64_t legacyV33 = heatV33(kOverflowHeat, /*saturate=*/false);
    // Load-bearing: the legacy path must DIFFER from the saturated path at this input.
    // (The legacy int64 multiply overflows and wraps; the exact wrapped value is not a
    // stable contract — what matters is that it is NOT the saturated hardest value, so the
    // gate genuinely changes behavior. If the gate were a no-op this assertion would fail.)
    ASSERT(legacyV33 != satV33,
        "V33 heat=90: legacy path must differ from saturated path (load-bearing check)");
    // NOTE: we deliberately do NOT assert legacyV33 equals a hand-replicated OVERFLOWED
    // value — the legacy int64 multiply is UB on overflow, so the exact wrapped bits are not
    // a portable contract (asserting it would rest the test on UB matching across compilers).
    // Below-gate byte-identity is proven instead by S4 over the WELL-DEFINED sub-overflow
    // range (heat 0..70) — which is what consensus actually relies on — plus the collapse
    // proof below (legacy drops below FP_SCALE; saturated returns MAX).

    // The exact C-3 defect (easiest-target collapse): somewhere in the heat sweep the legacy
    // int64 wrap drops the heaviest miner BELOW FP_SCALE (1.0x) — which CalculateEffectiveTarget
    // then floors UP to 1.0x, handing the heaviest miner the EASIEST target. Prove such a heat
    // exists in legacy, and that at the SAME heat the saturated path returns the HARDEST (MAX),
    // i.e. monotonic. This is the precise concentration-defense nullification C-3 closes.
    int collapseHeat = -1;
    for (int h = LINEAR_ZONE_END_V33 + 1; h <= OBSERVATION_WINDOW; h++) {
        int64_t legacy = heatV33(h, /*saturate=*/false);
        if (legacy < FP_SCALE) {  // wrapped to "no penalty" or negative — the collapse
            collapseHeat = h;
            break;
        }
    }
    ASSERT(collapseHeat != -1,
        "expected at least one heat where the legacy wrap collapses below FP_SCALE "
        "(the easiest-target defect); none found");
    int64_t legacyCollapse = heatV33(collapseHeat, /*saturate=*/false);
    int64_t satCollapse    = heatV33(collapseHeat, /*saturate=*/true);
    ASSERT(satCollapse == FP_HEAT_MULTIPLIER_MAX,
        "at collapse heat the saturated path must return MAX (hardest), got " +
        std::to_string(satCollapse));
    std::cout << "    collapse heat=" << collapseHeat << ": legacy=" << legacyCollapse
              << " (< FP_SCALE → floored to easiest 1.0x) vs saturated=" << satCollapse
              << " (MAX, hardest)" << std::endl;

    // V34 verified (also live-adjacent)
    int64_t satV34 = heatV34v(kOverflowHeat, /*saturate=*/true);
    ASSERT(satV34 == FP_HEAT_MULTIPLIER_MAX,
        "V34 heat=90 saturate=true must return FP_HEAT_MULTIPLIER_MAX, got " +
        std::to_string(satV34));

    std::cout << "    V33 heat=90: saturated=" << satV33
              << " (MAX) vs legacy=" << legacyV33 << " (wrapped, easier)" << std::endl;
}

// =======================================================================
// S4: below-gate identity — saturate=FALSE byte-identical to legacy formula
//     across sub-overflow heat 0..70 (V33).
// =======================================================================
TEST(s4_below_gate_byte_identical_v33) {
    for (int heat = 0; heat <= 70; heat++) {
        int64_t live   = heatV33(heat, /*saturate=*/false);
        int64_t golden = legacyHeatV33(heat);
        ASSERT(live == golden,
            "V33 saturate=false diverged from legacy at heat=" + std::to_string(heat) +
            " (live=" + std::to_string(live) + ", golden=" + std::to_string(golden) + ")");
    }
    std::cout << "    V33 saturate=false == legacy formula for heat 0..70 (consensus-frozen)"
              << std::endl;

    // Cursor MED-2: broaden below-gate identity to ALL versions. saturate is a NO-OP below
    // each version's overflow point — i.e. saturate=true == saturate=false for every
    // sub-overflow heat. This proves per-version byte-identity without a per-version replica.
    // At the FIRST true/false divergence (the cap point) the saturated path must be exactly MAX
    // (it caps + breaks); below it the two are bit-identical.
    for (const auto& v : kVersions) {
        int boundary = -1;
        for (int heat = 0; heat <= OBSERVATION_WINDOW; heat++) {
            int64_t sat = v.fn(heat, /*saturate=*/true);
            int64_t leg = v.fn(heat, /*saturate=*/false);
            if (sat == leg) continue;  // identical below the cap
            boundary = heat;
            ASSERT(sat == FP_HEAT_MULTIPLIER_MAX,
                std::string(v.name) + ": first saturate true/false divergence at heat=" +
                std::to_string(heat) + " but saturated != MAX (got " + std::to_string(sat) + ")");
            break;
        }
        std::cout << "    " << v.name << ": saturate is a no-op below heat="
                  << (boundary < 0 ? OBSERVATION_WINDOW : boundary) << " (byte-identical)" << std::endl;
    }

    // Combinator below-gate identity (Cursor MED-2): the saturate flag must not change any
    // sub-overflow combinator value either.
    for (int heat = 0; heat <= 50; heat++) {
        int64_t s = CalculateTotalMultiplierFP_V33(0, -1, heat, /*saturate=*/true);
        int64_t l = CalculateTotalMultiplierFP_V33(0, -1, heat, /*saturate=*/false);
        ASSERT(s == l,
            "V33 combinator saturate flag changed a sub-overflow value at heat=" +
            std::to_string(heat) + " (s=" + std::to_string(s) + ", l=" + std::to_string(l) + ")");
    }
    std::cout << "    V33 combinator saturate=true == false for sub-overflow heat 0..50" << std::endl;
}

// =======================================================================
// Combinator: CalculateTotalMultiplierFP_V33 near-cap heat + saturate=TRUE
//     stays bounded (the (pendingFP * heatFP)/FP_SCALE product cannot overflow).
// =======================================================================
TEST(combinator_v33_near_cap_bounded) {
    // firstSeenHeight=-1 → maturity 2.5x (FP_PENDING_START_V32). heat=90 → heatFP saturates.
    int64_t total = CalculateTotalMultiplierFP_V33(/*currentHeight=*/0, /*firstSeenHeight=*/-1,
                                                   /*heat=*/90, /*saturate=*/true);
    // maturity stacks ON TOP of the capped heat: product = maturityFP * heatCap / FP_SCALE.
    // The 128-bit math computes it exactly; it must clamp at the TRUE int64 boundary, NOT at
    // FP_HEAT_MULTIPLIER_MAX (Cursor MED-1) — else the maturity multiplier is discarded and the
    // target is ~2.5x easier than it should be. The real product (~1.46e17) fits int64.
    int64_t maturityFP = CalculatePendingPenaltyFP_V33(0, -1);  // the maturity at this height
    int64_t heatCap    = heatV33(90, /*saturate=*/true);        // = FP_HEAT_MULTIPLIER_MAX
    int64_t expected   = static_cast<int64_t>(
        (static_cast<__uint128_t>(maturityFP) * static_cast<__uint128_t>(heatCap)) / FP_SCALE);
    ASSERT(total > 0, "V33 combinator total must be positive (no overflow), got " +
        std::to_string(total));
    ASSERT(total == expected,
        "V33 combinator must return the exact maturity x heat product " + std::to_string(expected) +
        ", got " + std::to_string(total));
    // LOAD-BEARING for MED-1: the stacked product MUST exceed the heat cap alone — if the code
    // still ceilinged at FP_HEAT_MULTIPLIER_MAX this fails (maturity stacking lost).
    ASSERT(total > FP_HEAT_MULTIPLIER_MAX,
        "V33 combinator must stack maturity above the heat cap (MED-1), got " + std::to_string(total));
    ASSERT(total > FP_SCALE,
        "V33 combinator at heat=90 collapsed to <= 1.0x: " + std::to_string(total));
    std::cout << "    V33 combinator (heat=90, maturity 2.5x, saturate): total=" << total
              << " (bounded, no overflow)" << std::endl;
}

// =======================================================================
// Constant sanity: FP_HEAT_MULTIPLIER_MAX margin proof holds.
// =======================================================================
TEST(constant_overflow_margin) {
    // The next multiply must not overflow: MAX * FP_HEAT_GROWTH <= INT64_MAX.
    ASSERT(FP_HEAT_MULTIPLIER_MAX == INT64_MAX / FP_HEAT_GROWTH,
        "FP_HEAT_MULTIPLIER_MAX must equal INT64_MAX / FP_HEAT_GROWTH");
    // Margin: MAX * 158 fits (proven via the quotient property; check via uint128-free bound).
    ASSERT(FP_HEAT_MULTIPLIER_MAX <= INT64_MAX / FP_HEAT_GROWTH,
        "FP_HEAT_MULTIPLIER_MAX * FP_HEAT_GROWTH would overflow int64");
    ASSERT(FP_HEAT_MULTIPLIER_MAX > FP_SCALE,
        "FP_HEAT_MULTIPLIER_MAX must be well above FP_SCALE");
    std::cout << "    FP_HEAT_MULTIPLIER_MAX = " << FP_HEAT_MULTIPLIER_MAX
              << " (INT64_MAX / " << FP_HEAT_GROWTH << ")" << std::endl;
}

int main() {
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << YELLOW << "C-3 DFMP Heat Overflow Tests" << RESET << std::endl;
    std::cout << YELLOW << "========================================" << RESET << std::endl;
    std::cout << std::endl;

    test_constant_overflow_margin_wrapper();
    test_s1_s2_bounded_monotonic_all_versions_wrapper();
    test_s3_overflow_input_hardest_and_load_bearing_wrapper();
    test_s4_below_gate_byte_identical_v33_wrapper();
    test_combinator_v33_near_cap_bounded_wrapper();

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
