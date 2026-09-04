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
 *
 * ACTIVATION-GATE assertions (added after mutation testing showed S1-S4 pass `saturate`
 * as a literal bool and therefore gave the gate ZERO coverage — inverting `>=` to `<`
 * left this suite 5/5 GREEN):
 *  - G1     DFMP::DfmpSaturatingMathActive boundary: false at H-1, true at H, height 0
 *           legacy, null g_chainParams legacy at every height.
 *  - G2     shipped chain params keep the gate OFF (999999999) on all four networks —
 *           consensus-freeze guard against an accidental activation.
 *  - G3     the four consensus-critical sites (consensus/pow.cpp, miner/controller.cpp,
 *           node/dilithion-node.cpp, node/dilv-node.cpp) all route through that ONE
 *           predicate and no file outside chainparams re-derives the comparison.
 *  - G4     -fwrapv (which makes this file's whole subject — signed wrap — DEFINED
 *           behavior) is machine-enforced: the Makefile's CONSENSUS_CXXFLAGS override
 *           exists and every first-party compile recipe includes it.
 */

#include <dfmp/dfmp.h>
#include <core/chainparams.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
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
        // Guard against vacuity (red-team LOW-1): if NO true/false divergence was seen in range,
        // saturate genuinely never fired — which is only legitimate if the version is properly
        // bounded at max heat (its whole curve fits below the cap). If it instead reached the cap
        // (or wrapped) without the loop catching a split, the saturate branch is broken or the
        // test range is too short. Assert genuine boundedness in that case.
        if (boundary == -1) {
            int64_t mx = v.fn(OBSERVATION_WINDOW, /*saturate=*/true);
            ASSERT(mx >= FP_SCALE && mx < FP_HEAT_MULTIPLIER_MAX,
                std::string(v.name) + ": no saturate divergence in heat 0.." +
                std::to_string(OBSERVATION_WINDOW) + " but max-heat value " + std::to_string(mx) +
                " is not bounded below the cap (range too short, or saturate cap not firing)");
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

// =======================================================================
// C-3 ACTIVATION GATE COVERAGE
//
// Why this exists: mutation testing showed the activation predicate had ZERO
// coverage. Inverting `height >= activationHeight` to `height <` left this
// suite 5/5 GREEN, because every assertion passed `saturate` as a literal
// bool and nothing ever constructed a height or read chainparams. Worse, the
// predicate was hand-written at four independent sites (consensus/pow.cpp,
// miner/controller.cpp, node/dilithion-node.cpp, node/dilv-node.cpp) with
// nothing asserting they agreed — one slipped `>` vs `>=` splits MINER from
// VALIDATOR at exactly the activation boundary.
//
// G1 pins the predicate's semantics (null params / height 0 / H-1 / H / H+1).
// G2 pins the shipped chain params: the gate is OFF on all four networks.
// G3 pins the wiring: the four sites route through the ONE predicate.
// =======================================================================

// RAII: point g_chainParams at a test-local params object, restore on scope exit.
// Never mutates the shipped chainparams factories.
class ScopedChainParams {
public:
    explicit ScopedChainParams(Dilithion::ChainParams* p) : m_saved(Dilithion::g_chainParams) {
        Dilithion::g_chainParams = p;
    }
    ~ScopedChainParams() { Dilithion::g_chainParams = m_saved; }
private:
    Dilithion::ChainParams* m_saved;
};

// =======================================================================
// G1: the single-sourced predicate itself — boundary, zero, null params.
// KILLS: `>=` -> `>`, `>=` -> `<`, `>=` -> `<=`, dropped null guard,
//        off-by-one on the activation height.
// =======================================================================
TEST(g1_activation_predicate_boundary) {
    // --- null g_chainParams => legacy math at EVERY height (no crash) ---
    {
        ScopedChainParams guard(nullptr);
        ASSERT(DfmpSaturatingMathActive(0) == false,
            "null chainparams @ height 0 must be legacy (false)");
        ASSERT(DfmpSaturatingMathActive(1) == false,
            "null chainparams @ height 1 must be legacy (false)");
        ASSERT(DfmpSaturatingMathActive(999999999) == false,
            "null chainparams @ 999999999 must be legacy (false)");
        ASSERT(DfmpSaturatingMathActive(INT_MAX) == false,
            "null chainparams @ INT_MAX must be legacy (false)");
    }

    // --- a REAL (test-local) activation height: exact boundary semantics ---
    // NOTE: this is a test-local ChainParams object. The shipped activation
    // height is NOT changed — see G2.
    {
        Dilithion::ChainParams tp = Dilithion::ChainParams::Mainnet();
        const int H = 1234567;
        tp.dfmpOverflowFixActivationHeight = H;
        ScopedChainParams guard(&tp);

        ASSERT(DfmpSaturatingMathActive(0) == false,
            "height 0 must be legacy when activation height is 1234567");
        ASSERT(DfmpSaturatingMathActive(1) == false,
            "height 1 must be legacy");
        ASSERT(DfmpSaturatingMathActive(H - 2) == false,
            "H-2 must be legacy");
        // The two assertions that discriminate `>=` from every neighbour:
        ASSERT(DfmpSaturatingMathActive(H - 1) == false,
            "H-1 must be LEGACY (activation is >=, not >)");
        ASSERT(DfmpSaturatingMathActive(H) == true,
            "H must be ACTIVE (activation is >=, not >)");
        ASSERT(DfmpSaturatingMathActive(H + 1) == true,
            "H+1 must be ACTIVE");
        ASSERT(DfmpSaturatingMathActive(INT_MAX) == true,
            "INT_MAX must be ACTIVE");
        std::cout << "    boundary @ H=" << H << ": H-1=false, H=true (>=)" << std::endl;
    }

    // --- activation height 0 => active from genesis (documents the >= edge) ---
    {
        Dilithion::ChainParams tp = Dilithion::ChainParams::Mainnet();
        tp.dfmpOverflowFixActivationHeight = 0;
        ScopedChainParams guard(&tp);
        ASSERT(DfmpSaturatingMathActive(0) == true,
            "activation height 0 must be ACTIVE at height 0 (>=)");
    }
}

// =======================================================================
// G2: the shipped chain params keep the gate OFF. This is the
// consensus-freeze guard: if anyone lands a real activation height without
// a deliberate consensus decision, this goes RED.
// KILLS: an accidental/silent change of dfmpOverflowFixActivationHeight.
// =======================================================================
TEST(g2_shipped_params_gate_is_off) {
    // v4.6.0 ACTIVATION (Will, 2026-08-15): the gate is no longer frozen OFF —
    // it activates at a per-chain height (~3wk adoption window from the live
    // tips at decision time; RE-PIN at release cut). This test's job flips
    // with it: pin the DECIDED heights so an accidental/silent change — in
    // EITHER direction — still goes RED, and prove the predicate is exact at
    // each chain's boundary.
    struct { const char* name; Dilithion::ChainParams params; int activation; } chains[] = {
        { "Mainnet", Dilithion::ChainParams::Mainnet(), 93000  },
        { "Testnet", Dilithion::ChainParams::Testnet(), 0      },
        { "DilV",    Dilithion::ChainParams::DilV(),    255000 },
        { "Regtest", Dilithion::ChainParams::Regtest(), 0      },  // derives from Testnet
    };
    for (auto& c : chains) {
        ASSERT(c.params.dfmpOverflowFixActivationHeight == c.activation,
            std::string("dfmpOverflowFixActivationHeight changed on ")
                .append(c.name)
                .append(" — that is a CONSENSUS decision, not a refactor").c_str());

        Dilithion::ChainParams local = c.params;
        ScopedChainParams guard(&local);
        // Exact boundary: legacy math strictly below, saturating at and above.
        if (c.activation > 0) {
            ASSERT(DfmpSaturatingMathActive(0) == false,
                std::string("gate must be OFF at genesis on ").append(c.name).c_str());
            ASSERT(DfmpSaturatingMathActive(c.activation - 1) == false,
                std::string("gate must be OFF just below activation on ").append(c.name).c_str());
        }
        ASSERT(DfmpSaturatingMathActive(c.activation) == true,
            std::string("gate must flip exactly at activation on ").append(c.name).c_str());
        ASSERT(DfmpSaturatingMathActive(c.activation + 1) == true,
            std::string("gate must stay ON above activation on ").append(c.name).c_str());
    }
    std::cout << "    activation pinned: Mainnet 93000, Testnet 0, DilV 255000, Regtest 0"
              << std::endl;
}

// -----------------------------------------------------------------------
// Source-scan helpers for G3.
// -----------------------------------------------------------------------
static std::string readWholeFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open source file: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Locate the repo's src/ directory. Explicit override wins; otherwise walk up
// from the CWD. Throws (test FAILS, never silently skips) if not found.
static std::string findSrcDir() {
    if (const char* env = std::getenv("DILITHION_SRC_ROOT")) {
        std::filesystem::path p = std::filesystem::path(env) / "src";
        if (std::filesystem::is_directory(p)) return p.string();
        throw std::runtime_error("DILITHION_SRC_ROOT set but has no src/: " + std::string(env));
    }
    std::filesystem::path dir = std::filesystem::current_path();
    for (int i = 0; i < 8; i++) {
        std::filesystem::path cand = dir / "src" / "dfmp" / "dfmp.cpp";
        if (std::filesystem::is_regular_file(cand)) return (dir / "src").string();
        if (!dir.has_parent_path() || dir.parent_path() == dir) break;
        dir = dir.parent_path();
    }
    throw std::runtime_error(
        "could not locate the repo src/ directory from CWD — run this binary from the "
        "repo root, or set DILITHION_SRC_ROOT");
}

// Strip // and /* */ comments so the G3 scan counts CODE, not prose.
//
// ⛔ WHY THIS EXISTS. G3 asserts a site names the gate parameter ZERO times.
// The scan was a raw string::find over the whole file, so it could not tell a
// call from a comment -- and on 2026-08-10 a commit added a COMMENT to
// consensus/pow.cpp explaining the parameter. The comment is good: it documents
// the live activation height. The test failed anyway, and main's gcc/Release
// leg stayed red for three weeks while every PR inherited the failure.
//
// A test that punishes documentation for the thing it guards is not guarding
// it -- it is training people to delete explanations. The property G3 actually
// cares about is "no site RE-DERIVES the gate in code"; comments cannot
// re-derive anything.
//
// Deliberately simple: no string-literal tracking, because the identifiers
// this file scans for never appear inside string literals in the sites it
// reads. If that ever changes, this must grow a literal-aware pass rather than
// have the assertion relaxed.
static std::string stripComments(const std::string& src) {
    std::string out;
    out.reserve(src.size());
    for (size_t i = 0; i < src.size(); ) {
        if (src[i] == '/' && i + 1 < src.size() && src[i + 1] == '/') {
            while (i < src.size() && src[i] != '\n') ++i;   // keep the newline
        } else if (src[i] == '/' && i + 1 < src.size() && src[i + 1] == '*') {
            i += 2;
            while (i + 1 < src.size() && !(src[i] == '*' && src[i + 1] == '/')) ++i;
            i = (i + 1 < src.size()) ? i + 2 : src.size();
            out += ' ';                                            // keep tokens apart
        } else {
            out += src[i++];
        }
    }
    return out;
}

static size_t countOccurrences(const std::string& hay, const std::string& needle) {
    const std::string code = stripComments(hay);
    size_t n = 0, pos = 0;
    while ((pos = code.find(needle, pos)) != std::string::npos) { n++; pos += needle.size(); }
    return n;
}

// G3/G4 assert about CODE, not prose: a rationale comment naming the parameter
// (e.g. the k1 -fwrapv comment at pow.cpp:418) must not trip the single-source
// sweep. Strips //-to-EOL only — the dominant style here; a block comment naming
// the param would still count, which fails safe (a human looks, then rewords).
static std::string stripLineComments(const std::string& body) {
    std::string out;
    out.reserve(body.size());
    size_t pos = 0;
    while (pos < body.size()) {
        size_t eol = body.find('\n', pos);
        if (eol == std::string::npos) eol = body.size();
        size_t slashes = body.find("//", pos);
        size_t end = (slashes != std::string::npos && slashes < eol) ? slashes : eol;
        out.append(body, pos, end - pos);
        out.push_back('\n');
        pos = eol + 1;
    }
    return out;
}

// =======================================================================
// G3: the four consensus-critical call sites route through the ONE
// predicate, and NOTHING outside chainparams/dfmp.cpp re-derives it.
//
// This is the by-construction agreement proof: if all four sites call the
// same function, they cannot disagree; G1 then pins that function's
// semantics. This test is the regression guard against someone re-inlining
// a hand-written comparison at a fifth site.
//
// KILLS: any re-introduced local `height >= ...dfmpOverflowFixActivationHeight`
//        expression, and any call site dropped from the single source.
// =======================================================================
TEST(g3_four_call_sites_single_sourced) {
    const std::filesystem::path src = findSrcDir();
    std::cout << "    scanning: " << src.string() << std::endl;

    const std::string kParam = "dfmpOverflowFixActivationHeight";
    const std::string kCall  = "DFMP::DfmpSaturatingMathActive(";

    // 1) Each of the four sites calls the predicate and inlines nothing.
    const char* sites[] = {
        "consensus/pow.cpp",
        "miner/controller.cpp",
        "node/dilithion-node.cpp",
        "node/dilv-node.cpp",
    };
    for (const char* rel : sites) {
        const std::string body = stripLineComments(readWholeFile((src / rel).string()));
        ASSERT(countOccurrences(body, kCall) >= 1,
            std::string(rel) + " must call DFMP::DfmpSaturatingMathActive()");
        ASSERT(countOccurrences(body, kParam) == 0,
            std::string(rel) + " must NOT read dfmpOverflowFixActivationHeight directly "
                               "— call DFMP::DfmpSaturatingMathActive()");
        std::cout << "    " << rel << ": routed" << std::endl;
    }

    // 2) Repo-wide: the ONLY places that may name the param are the
    //    chainparams declaration/assignments and the single predicate.
    std::vector<std::string> offenders;
    size_t predicateFileHits = 0;
    for (const auto& e : std::filesystem::recursive_directory_iterator(src)) {
        if (!e.is_regular_file()) continue;
        const std::string ext = e.path().extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp") continue;
        const std::string rel = std::filesystem::relative(e.path(), src).generic_string();
        const std::string body = stripLineComments(readWholeFile(e.path().string()));
        if (countOccurrences(body, kParam) == 0) continue;
        if (rel == "core/chainparams.h" || rel == "core/chainparams.cpp") continue;
        if (rel == "dfmp/dfmp.cpp") { predicateFileHits++; continue; }
        if (rel == "test/dfmp_heat_overflow_tests.cpp") continue;  // this file (G2 freeze check)
        offenders.push_back(rel);
    }
    if (!offenders.empty()) {
        std::string msg = "dfmpOverflowFixActivationHeight re-derived outside the single "
                          "source (MINER/VALIDATOR SPLIT RISK) in:";
        for (const auto& o : offenders) msg += " " + o;
        throw std::runtime_error(msg);
    }
    ASSERT(predicateFileHits == 1,
        "dfmp/dfmp.cpp must exist and define the single predicate");

    // 3) The predicate definition itself uses >= (not >, <, <=).
    const std::string dfmpBody = readWholeFile((src / "dfmp" / "dfmp.cpp").string());
    ASSERT(countOccurrences(dfmpBody,
            "height >= Dilithion::g_chainParams->dfmpOverflowFixActivationHeight") == 1,
        "the single predicate must be exactly `height >= "
        "Dilithion::g_chainParams->dfmpOverflowFixActivationHeight`");
    ASSERT(countOccurrences(dfmpBody, "Dilithion::g_chainParams &&") >= 1,
        "the single predicate must keep the null-chainparams guard");
    std::cout << "    single source verified (>= + null guard)" << std::endl;
}

// =======================================================================
// G4: -fwrapv is machine-enforced, not comment-enforced.
//
// The heat arithmetic this suite hardens is DEFINED behavior only under
// -fwrapv (signed overflow wraps); without it the compiler may legally
// assume no overflow and emit a consensus-divergent binary. The Makefile
// carries the full rationale for the delivery mechanism (`override
// CONSENSUS_CXXFLAGS := -fwrapv`, injected per-recipe because `override
// CXXFLAGS +=` silently breaks every later plain `+=`). Until now that
// mechanism was enforced only by a comment saying recipes MUST include
// it. This test pins both halves, so dropping the variable or writing a
// compile recipe without it fails a suite instead of shipping UB.
// =======================================================================
TEST(g4_consensus_fwrapv_machine_enforced) {
    const std::filesystem::path srcPath = findSrcDir();
    const std::filesystem::path root = srcPath.parent_path();
    const std::string mk = readWholeFile((root / "Makefile").string());

    // 1) The override variable exists, exactly once, with the flag.
    ASSERT(countOccurrences(mk, "override CONSENSUS_CXXFLAGS := -fwrapv") == 1,
        "Makefile must define `override CONSENSUS_CXXFLAGS := -fwrapv` exactly once");

    // 2) Every first-party compile recipe includes $(CONSENSUS_CXXFLAGS).
    //    A compile recipe = a tab-indented recipe line invoking $(CXX) with -c.
    //    Scoped to recipes that use $(CXXFLAGS): the consensus-flag contract
    //    rides with first-party flag sets. Hardcoded-flag third-party recipes
    //    (chiavdf c_wrapper) are a separately-documented exemption — see the
    //    "Do NOT extend this hardcoded-flags pattern" comment above that rule.
    // Join backslash-continuations FIRST — a recipe split across lines would
    // otherwise evade every substring check (fold: red-team M-3; the two
    // Dilithium-primitive recipes were invisible to the first version).
    std::string mkJoined;
    mkJoined.reserve(mk.size());
    for (size_t i = 0; i < mk.size(); ++i) {
        if (mk[i] == '\\' && i + 1 < mk.size() && mk[i + 1] == '\n') { mkJoined += ' '; ++i; continue; }
        if (mk[i] == '\\' && i + 2 < mk.size() && mk[i + 1] == '\r' && mk[i + 2] == '\n') { mkJoined += ' '; i += 2; continue; }
        mkJoined += mk[i];
    }

    std::vector<std::string> naked;
    std::istringstream lines(mkJoined);
    std::string line;
    size_t lineno = 0, recipes = 0;
    while (std::getline(lines, line)) {
        lineno++;
        if (line.empty() || line[0] != '\t') continue;          // recipe lines only
        if (line.find("$(CXX)") == std::string::npos) continue;
        if (line.find(" -c ") == std::string::npos) continue;   // compile, not link
        if (line.find("$(CXXFLAGS)") == std::string::npos) continue;  // third-party exemption
        recipes++;
        if (line.find("$(CONSENSUS_CXXFLAGS)") == std::string::npos) {
            naked.push_back("Makefile(joined-line):" + std::to_string(lineno));
        }
    }
    // 7 first-party compile recipes exist today (incl. the two Dilithium
    // primitive recipes only visible after continuation-joining). A DROP below
    // that is a recipe escaping the sweep, not legitimate shrinkage.
    ASSERT(recipes >= 7,
        "first-party compile recipe count dropped below 7 — a recipe is evading the sweep "
        "(continuation trick or variable rename); fix the matcher, don't relax this");
    if (!naked.empty()) {
        std::string msg = "compile recipes missing $(CONSENSUS_CXXFLAGS) (CONSENSUS-UB RISK):";
        for (const auto& n : naked) msg += " " + n;
        throw std::runtime_error(msg);
    }
    std::cout << "    " << recipes << " compile recipes checked, all carry $(CONSENSUS_CXXFLAGS)"
              << std::endl;
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
    test_g1_activation_predicate_boundary_wrapper();
    test_g2_shipped_params_gate_is_off_wrapper();
    test_g3_four_call_sites_single_sourced_wrapper();
    test_g4_consensus_fwrapv_machine_enforced_wrapper();

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
