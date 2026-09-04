// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

/**
 * Large-page opt-in reachability test.
 *
 * The defect this pins: randomx_set_large_pages_allowed(1) used to be called only
 * from the `else` branch of `if (randomx_is_mining_mode_ready())` in
 * CMiningController::StartMining. dilithion-node starts FULL-mode init at boot on any
 * host with >= 8192 MB RAM whether or not it mines, so on exactly the machines large
 * pages are worth having, the mode was already ready when mining started, the `else`
 * never ran, and the opt-in was never recorded. Worse, nothing said so: the status was
 * reported from inside the dataset allocator, which returns early when the opt-in is
 * off, so the log contained no large-page line at all.
 *
 * Every scenario below is an ORDERING, because ordering is the whole mechanism: the
 * request counts if and only if it lands before the dataset allocation reads it.
 *
 * Each scenario needs a fresh process -- the RandomX module's mode state is global and
 * a built dataset cannot be rebuilt -- so this binary re-execs itself once per scenario
 * when run with no arguments.
 *
 * These assertions are written to FAIL if the fix is reverted:
 *   relay-then-mine  fails if the too-late request is silently swallowed (the shipped
 *                    defect: no line of any kind).
 *   late-request     fails if the too-late warning is gated on the dataset having
 *                    FINISHED building rather than on it having COMMITTED to a page size.
 *                    This is the 30-120s window the old g_mining_ready check stayed
 *                    silent in. Verified by mutation: re-adding that gate fails this
 *                    scenario and only this one.
 *   mine-from-start  fails if the opt-in stops reaching the allocator at all.
 *   no-full-mode     fails if a mining node on a small host is left with no status line.
 */

#include <crypto/randomx_hash.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

const char* kKey = "Dilithion-RandomX-v1";

int g_failures = 0;

void Check(bool ok, const std::string& what) {
    std::cerr << (ok ? "  [PASS] " : "  [FAIL] ") << what << std::endl;
    if (!ok) g_failures++;
}

// Captures everything the module prints. The status lines ARE the deliverable here --
// an operator diagnosing half hashrate has nothing else to go on -- so they are what
// gets asserted, not an internal flag.
class CoutCapture {
public:
    CoutCapture() : m_old(std::cout.rdbuf(m_buf.rdbuf())) {}
    ~CoutCapture() { std::cout.rdbuf(m_old); }
    std::string str() const { return m_buf.str(); }
private:
    std::stringstream m_buf;
    std::streambuf* m_old;
};

bool Contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

size_t CountOccurrences(const std::string& haystack, const std::string& needle) {
    size_t n = 0, pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        n++;
        pos += needle.size();
    }
    return n;
}

void WaitForMiningMode() {
    randomx_wait_for_mining_mode();
    for (int i = 0; i < 6000 && !randomx_is_mining_mode_ready(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Block until the FULL-mode init thread has passed the point where it reads the opt-in
// and allocates. "Initializing dataset with N threads..." is printed after both, and
// BEFORE the 30-120s dataset fill -- so seeing it puts us squarely inside the window
// where the dataset is already committed to a page size but g_mining_ready is still
// false. That is precisely the window the pre-fix warning was silent in. Waiting for a
// printed marker rather than sleeping keeps the scenario deterministic; a racy test of a
// race is no test.
bool WaitForDatasetCommitted(const CoutCapture& cap) {
    for (int i = 0; i < 6000; ++i) {
        if (Contains(cap.str(), "[MINING] Initializing dataset with")) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

// ---------------------------------------------------------------------------------
// Scenario: node started WITHOUT --mine on an 8GB+ host, told to mine afterwards.
// This is the shipped defect's exact shape.
// ---------------------------------------------------------------------------------
int ScenarioRelayThenMine() {
    CoutCapture cap;

    // Node startup, no --mine: dilithion-node.cpp passes 0 here and builds the dataset
    // anyway, to speed up IBD verification.
    randomx_set_large_pages_allowed(0);
    randomx_init_mining_mode_async(kKey, strlen(kKey));
    WaitForMiningMode();

    const std::string during_startup = cap.str();

    // Now mining starts. This is the call that used to be unreachable.
    randomx_set_large_pages_allowed(1);
    randomx_log_large_page_status_for_mining(1);

    const std::string after_mining_start = cap.str();
    const std::string mining_lines = after_mining_start.substr(during_startup.size());

    Check(randomx_is_mining_mode_ready() != 0, "FULL mode built during startup (relay path)");

    // Relay silence: a node that never asked for large pages must not be lectured
    // about them. This half was already correct and must stay correct.
    Check(!Contains(during_startup, "Large pages:"),
          "no large-page line while merely relaying (never requested)");

    // The regression the fix exists for: mining started, so there MUST be a line, and it
    // must say the request was too late rather than implying it worked.
    Check(Contains(mining_lines, "Large pages: IGNORED"),
          "mining start reports IGNORED once the dataset is already built");
    Check(Contains(mining_lines, "--mine"),
          "IGNORED line tells the operator how to fix it (restart with --mine)");
    Check(!Contains(mining_lines, "Large pages: ENABLED"),
          "does not claim ENABLED for a request that arrived too late");

    // StartMining runs once per block template; the line must not flood the log.
    randomx_log_large_page_status_for_mining(1);
    randomx_log_large_page_status_for_mining(1);
    Check(CountOccurrences(cap.str(), "Large pages: IGNORED") == 1,
          "repeated mining starts do not repeat the line");

    return g_failures;
}

// ---------------------------------------------------------------------------------
// Scenario: the request lands WHILE the dataset build is in flight. The old warning was
// gated on g_mining_ready, so it stayed silent for the whole 30-120s build and the
// request vanished without a word.
// ---------------------------------------------------------------------------------
int ScenarioLateRequest() {
    CoutCapture cap;

    randomx_set_large_pages_allowed(0);
    randomx_init_mining_mode_async(kKey, strlen(kKey));

    Check(WaitForDatasetCommitted(cap),
          "dataset committed to a page size while the build is still in flight");

    const bool ready_yet = randomx_is_mining_mode_ready() != 0;

    const size_t before = cap.str().size();
    randomx_set_large_pages_allowed(1);
    randomx_log_large_page_status_for_mining(1);
    const std::string mining_lines = cap.str().substr(before);

    Check(Contains(mining_lines, "Large pages: IGNORED"),
          std::string("in-flight request reported as too late (mining_mode_ready=") +
              (ready_yet ? "true" : "false") + " at the time of the request)");
    Check(!mining_lines.empty(), "in-flight request is not silently swallowed");

    WaitForMiningMode();
    return g_failures;
}

// ---------------------------------------------------------------------------------
// Scenario: --mine from the outset. The opt-in must reach the allocator.
// ---------------------------------------------------------------------------------
int ScenarioMineFromStart() {
    CoutCapture cap;

    randomx_set_large_pages_allowed(1);
    randomx_init_mining_mode_async(kKey, strlen(kKey));
    WaitForMiningMode();

    const std::string startup = cap.str();
    const size_t before = cap.str().size();
    randomx_log_large_page_status_for_mining(1);
    const std::string mining_lines = cap.str().substr(before);

    const bool granted = randomx_large_pages_active() != 0;

    // Allocator-time report. One of the two, decided by whether the OS granted the pages.
    Check(Contains(startup, "Large pages: ENABLED") ||
              Contains(startup, "Large pages: UNAVAILABLE"),
          std::string("allocator reported the outcome at build time (host granted large"
                      " pages: ") + (granted ? "yes" : "no") + ")");

    // Never IGNORED: the request was in place before the allocation read it.
    Check(!Contains(startup, "Large pages: IGNORED") &&
              !Contains(mining_lines, "Large pages: IGNORED"),
          "a request made before the allocation is never reported as too late");

    // The mining-start line agrees with what actually happened.
    Check(Contains(mining_lines, granted ? "Large pages: ENABLED"
                                         : "Large pages: UNAVAILABLE"),
          "mining-start status matches randomx_large_pages_active()");

    return g_failures;
}

// ---------------------------------------------------------------------------------
// Scenario: mining host too small for the FULL dataset. There is no dataset for large
// pages to back, and the operator still gets told that rather than nothing.
// ---------------------------------------------------------------------------------
int ScenarioNoFullMode() {
    CoutCapture cap;
    randomx_set_large_pages_allowed(1);
    randomx_log_large_page_status_for_mining(0);
    const std::string out = cap.str();

    Check(Contains(out, "Large pages: N/A"),
          "LIGHT-only mining host still gets a large-page line");
    return g_failures;
}

struct Scenario {
    const char* name;
    int (*fn)();
};

const Scenario kScenarios[] = {
    {"relay-then-mine", ScenarioRelayThenMine},
    {"late-request",    ScenarioLateRequest},
    {"mine-from-start", ScenarioMineFromStart},
    {"no-full-mode",    ScenarioNoFullMode},
};

}  // namespace

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        for (const auto& s : kScenarios) {
            if (std::strcmp(argv[1], s.name) == 0) {
                std::cerr << "=== scenario: " << s.name << " ===" << std::endl;
                const int failures = s.fn();
                std::cerr << (failures == 0 ? "=== OK ===" : "=== FAILED ===") << std::endl;
                return failures == 0 ? 0 : 1;
            }
        }
        std::cerr << "unknown scenario: " << argv[1] << std::endl;
        return 2;
    }

    // Driver: one fresh process per scenario. The module's mode state is global and a
    // built dataset cannot be un-built, so running two orderings in one process would
    // test neither.
    int failures = 0;
    for (const auto& s : kScenarios) {
        std::string cmd = std::string("\"") + argv[0] + "\" " + s.name;
        const int rc = std::system(cmd.c_str());
        if (rc != 0) {
            std::cerr << "SCENARIO FAILED: " << s.name << " (rc=" << rc << ")" << std::endl;
            failures++;
        }
    }
    std::cerr << (failures == 0 ? "ALL SCENARIOS PASSED" : "SCENARIOS FAILED") << std::endl;
    return failures == 0 ? 0 : 1;
}
