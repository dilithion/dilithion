// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Shutdown final-Disarm ownership — structural pins.
 *
 * The invariant (red-team @ eac44a4e, MED-3 fold): the shutdown watchdog's
 * deadline must cover EVERY teardown step, and the last teardown actor on every
 * exit path is RandomXShutdownGuard's destructor (first local of main =>
 * destructs last; it joins the RandomX threads). Therefore that destructor —
 * and ONLY it — calls ShutdownProgress::Disarm(). Any Disarm() reachable
 * earlier re-opens an unbounded-hang window at exactly the step the
 * J1/K2 shutdown work exists to bound (the pre-fold defect: both mains
 * disarmed at their tail, then the guard joined with no deadline).
 *
 * Destruction order is a comment-enforced property of main()'s declaration
 * order, and comment-enforced orderings rot (see G4 in
 * dfmp_heat_overflow_tests for the same argument about -fwrapv). These
 * checks make both halves fail a suite instead of rotting:
 *
 *   1. src/crypto/randomx_hash.h calls Disarm() exactly once (the guard dtor)
 *      and stages the join so the deadline clock names it.
 *   2. Neither main() calls ShutdownProgress::Disarm() at all.
 *   3. No file outside the guard header + the watchdog's own header calls
 *      Disarm() (repo-wide sweep, tests exempt).
 *   4. In both mains, RandomXShutdownGuard is declared BEFORE
 *      NodeContextShutdownGuard (destructs after it), so the final joins and
 *      the final Disarm really are last.
 */

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static int g_passed = 0;
static int g_failed = 0;

#define ASSERT(cond, msg) \
    do { if (!(cond)) throw std::runtime_error(msg); } while (0)

#define TEST(name) void test_##name()
#define RUN(name) \
    do { \
        std::cout << "[TEST] " << #name << std::endl; \
        try { test_##name(); std::cout << "  PASSED" << std::endl; g_passed++; } \
        catch (const std::exception& e) { std::cout << "  FAILED: " << e.what() << std::endl; g_failed++; } \
    } while (0)

static std::string readWholeFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + p);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static size_t countOccurrences(const std::string& hay, const std::string& needle) {
    size_t n = 0, pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) { n++; pos += needle.size(); }
    return n;
}

static std::filesystem::path findSrcDir() {
    if (const char* env = std::getenv("DILITHION_SRC_ROOT")) {
        return std::filesystem::path(env);
    }
    std::filesystem::path dir = std::filesystem::current_path();
    for (int i = 0; i < 6; i++) {
        if (std::filesystem::exists(dir / "src" / "consensus" / "pow.cpp")) return dir / "src";
        if (!dir.has_parent_path() || dir.parent_path() == dir) break;
        dir = dir.parent_path();
    }
    throw std::runtime_error("could not locate repo src/ — run from repo root or set DILITHION_SRC_ROOT");
}

static const std::string kDisarm = "ShutdownProgress::Disarm()";

TEST(guard_owns_exactly_one_disarm) {
    const auto src = findSrcDir();
    const std::string guard = readWholeFile((src / "crypto" / "randomx_hash.h").string());
    ASSERT(countOccurrences(guard, kDisarm) == 1,
        "crypto/randomx_hash.h must call ShutdownProgress::Disarm() exactly once (the guard dtor)");
    ASSERT(countOccurrences(guard, "Stage(\"randomx thread join") == 1,
        "the guard dtor must Stage the join so the deadline clock names the final step");
    std::cout << "    guard: 1 Disarm + staged join" << std::endl;
}

TEST(mains_never_disarm) {
    const auto src = findSrcDir();
    for (const char* rel : {"node/dilithion-node.cpp", "node/dilv-node.cpp"}) {
        const std::string body = readWholeFile((src / rel).string());
        ASSERT(countOccurrences(body, kDisarm) == 0,
            std::string(rel) + " must not call ShutdownProgress::Disarm() — the final Disarm "
            "is owned by RandomXShutdownGuard, which destructs after everything here");
        std::cout << "    " << rel << ": no Disarm" << std::endl;
    }
}

TEST(repo_wide_no_other_disarm) {
    const auto src = findSrcDir();
    std::vector<std::string> offenders;
    for (const auto& e : std::filesystem::recursive_directory_iterator(src)) {
        if (!e.is_regular_file()) continue;
        const std::string ext = e.path().extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp") continue;
        const std::string rel = std::filesystem::relative(e.path(), src).generic_string();
        if (rel == "crypto/randomx_hash.h") continue;          // the owner
        if (rel == "util/shutdown_progress.h") continue;       // the definition
        if (rel.rfind("test/", 0) == 0) continue;              // tests may reference it
        const std::string body = readWholeFile(e.path().string());
        if (countOccurrences(body, kDisarm) != 0) offenders.push_back(rel);
    }
    if (!offenders.empty()) {
        std::string msg = "early Disarm() reintroduced (UNBOUNDED-HANG WINDOW) in:";
        for (const auto& o : offenders) msg += " " + o;
        throw std::runtime_error(msg);
    }
    std::cout << "    repo-wide: no stray Disarm callers" << std::endl;
}

TEST(guard_declared_first_in_both_mains) {
    const auto src = findSrcDir();
    for (const char* rel : {"node/dilithion-node.cpp", "node/dilv-node.cpp"}) {
        const std::string body = readWholeFile((src / rel).string());
        const size_t rx = body.find("RandomXShutdownGuard randomx_shutdown_guard;");
        const size_t nc = body.find("} node_context_shutdown_guard{");
        ASSERT(rx != std::string::npos,
            std::string(rel) + " must declare RandomXShutdownGuard randomx_shutdown_guard;");
        ASSERT(nc != std::string::npos,
            std::string(rel) + " must declare node_context_shutdown_guard (unwind bound)");
        ASSERT(rx < nc,
            std::string(rel) + ": RandomXShutdownGuard must be declared BEFORE "
            "NodeContextShutdownGuard so it destructs AFTER it and the final "
            "Disarm really is final");
        std::cout << "    " << rel << ": declaration order pins destruction order" << std::endl;
    }
}

int main() {
    std::cout << "=== shutdown final-Disarm ownership (structural) ===" << std::endl;
    RUN(guard_owns_exactly_one_disarm);
    RUN(mains_never_disarm);
    RUN(repo_wide_no_other_disarm);
    RUN(guard_declared_first_in_both_mains);
    std::cout << "Passed: " << g_passed << "  Failed: " << g_failed << std::endl;
    return g_failed == 0 ? 0 : 1;
}
