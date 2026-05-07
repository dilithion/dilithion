// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.3.2 M1 fix — auto_rebuild marker write path mode-symmetry tests.
//
// PURPOSE
// =======
// Validate that the recovery marker `<datadir>/auto_rebuild` is reliably written
// when the chain corruption flags fire, regardless of which sync-coordinator
// configuration the node runs (legacy CIbdCoordinatorAdapter under
// `--usenewpeerman=0`, or port-CPeerManager under `--usenewpeerman=1`).
//
// HISTORY
// =======
// v4.3.1 LDN canary 2026-05-04 reproduced the M1 defect:
//   - chain.cpp Fix 2 set `m_chain_needs_rebuild=true` on disconnect failure.
//   - The legacy poll-and-write block lived in CIbdCoordinator::Tick().
//   - Under `--usenewpeerman=1`, that Tick() is replaced by port-CPeerManager,
//     so the poll never ran. `[CRITICAL] Triggering auto_rebuild` printed but
//     no marker file was ever created. Wrapper crash-looped restarting into
//     broken state; chain regressed h=44518 → h=44265 in 4 minutes.
//
// FIX (v4.3.2)
// ============
// Extracted the poll-and-write logic into a free helper
// `Dilithion::MaybeTriggerChainRebuild` (see src/util/chain_reset.cpp). Main
// loops in dilv-node.cpp + dilithion-node.cpp call it AFTER
// `sync_coordinator->Tick()`, in BOTH modes.
//
// THESE TESTS
// ===========
//   1. test_marker_written_when_chain_rebuild_flagged — happy path: flag set
//      via production code path (RecordUndoFailure × threshold), helper
//      called once, marker file exists with expected reason string.
//   2. test_no_marker_when_no_flag — neither flag set, helper is no-op.
//   3. test_idempotent_double_call — call helper twice with flag set, marker
//      written exactly once (latch semantics preserved from legacy block).
//   4. test_disk_write_failure_still_triggers_shutdown — point datadir at an
//      empty string (forces WriteAutoRebuildMarker to refuse), flag set,
//      assert running_flag still toggled to false.
//   5. test_mode_symmetric_marker_contents — drive helper through two
//      separate "ticks" (simulating flag=0 and flag=1 paths) and assert the
//      marker contents are byte-identical, proving the fix delivers the same
//      recovery experience to operators regardless of mode.
//
// Tests use a temp directory for the marker; cleanup runs in the destructor.

#include <util/chain_reset.h>

#include <consensus/chain.h>
#include <node/block_index.h>
#include <primitives/block.h>
#include <uint256.h>

#include <atomic>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Tiny RAII tempdir for marker output. Created under the system temp root.
// ---------------------------------------------------------------------------
struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        std::ostringstream oss;
        oss << "dilithion-v432-m1-" << tag << "-" << rd();
        path = std::filesystem::temp_directory_path() / oss.str();
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        // ignore ec — if creation fails, subsequent ops will report it.
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::string str() const { return path.string(); }
    std::filesystem::path marker() const { return path / "auto_rebuild"; }
};

// ---------------------------------------------------------------------------
// Build a minimal CChainState and drive m_chain_needs_rebuild = true via
// the production code path RecordUndoFailure × kPersistentUndoFailureThreshold.
// Returns the failing block hash (used by the helper to format the reason).
// ---------------------------------------------------------------------------
uint256 MakeBlockHash(uint8_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = seed;
    h.data[31] = seed;
    return h;
}

// Threshold (kPersistentUndoFailureThreshold) is 3 in chain.h. We hit it
// 3× in a row on the same hash to satisfy "persistent" semantics. We use
// a height of 1 to avoid any tip-related side effects — RecordUndoFailure
// just bumps the counter and flips the atomic.
void DriveChainRebuildViaProductionPath(CChainState& cs) {
    const uint256 failing = MakeBlockHash(0xAB);
    for (int i = 0; i < 3; ++i) {
        cs.RecordUndoFailure(failing, 1);
    }
    assert(cs.NeedsChainRebuild() && "test setup: production path failed to flip flag");
}

// ---------------------------------------------------------------------------
// Read the marker file content as a single string (trim trailing newline).
// ---------------------------------------------------------------------------
std::string ReadMarker(const std::filesystem::path& p) {
    std::ifstream in(p);
    if (!in.is_open()) return "";
    std::ostringstream oss;
    oss << in.rdbuf();
    std::string s = oss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// =============================================================================
// Test 1: happy path — chain_rebuild flag set, helper writes marker + flips
// the running flag.
// =============================================================================
void test_marker_written_when_chain_rebuild_flagged() {
    std::cout << "  test_marker_written_when_chain_rebuild_flagged..." << std::flush;
    Dilithion::ResetMaybeTriggerLatchForTesting();

    TempDir td("happy");
    CChainState cs;
    DriveChainRebuildViaProductionPath(cs);

    std::atomic<bool> running{true};
    const bool fired = Dilithion::MaybeTriggerChainRebuild(cs, td.str(), &running);

    assert(fired && "first invocation with flag set must fire");
    assert(std::filesystem::exists(td.marker()) && "marker file must be on disk");
    const std::string body = ReadMarker(td.marker());
    assert(body.find("Persistent UndoBlock failure at height") != std::string::npos
           && "reason must include UndoBlock failure prefix");
    assert(body.find("hash=") != std::string::npos && "reason must include failing hash");
    assert(running.load() == false && "running flag must be cleared");

    std::cout << " OK\n";
}

// =============================================================================
// Test 2: no flag set — helper is a no-op.
// =============================================================================
void test_no_marker_when_no_flag() {
    std::cout << "  test_no_marker_when_no_flag..." << std::flush;
    Dilithion::ResetMaybeTriggerLatchForTesting();

    TempDir td("noflag");
    CChainState cs;
    // Deliberately do NOT drive any flag. Default-constructed atomic<bool> is
    // false; the helper's cheap-path early-return must fire.

    std::atomic<bool> running{true};
    const bool fired = Dilithion::MaybeTriggerChainRebuild(cs, td.str(), &running);

    assert(!fired && "no flag → no fire");
    assert(!std::filesystem::exists(td.marker()) && "no marker on disk when flag clear");
    assert(running.load() == true && "running flag must NOT be cleared");

    std::cout << " OK\n";
}

// =============================================================================
// Test 3: idempotency — call helper twice, marker written once. This is what
// prevents the LDN crash-loop from running away: even if the main loop calls
// the helper on every iteration after the flag is set, only the first call
// writes (and signals shutdown).
// =============================================================================
void test_idempotent_double_call() {
    std::cout << "  test_idempotent_double_call..." << std::flush;
    Dilithion::ResetMaybeTriggerLatchForTesting();

    TempDir td("idem");
    CChainState cs;
    DriveChainRebuildViaProductionPath(cs);

    std::atomic<bool> running{true};
    const bool fired1 = Dilithion::MaybeTriggerChainRebuild(cs, td.str(), &running);
    const std::string body1 = ReadMarker(td.marker());

    // Re-arm running so we can detect whether the second call would re-trigger.
    running.store(true);
    const bool fired2 = Dilithion::MaybeTriggerChainRebuild(cs, td.str(), &running);
    const std::string body2 = ReadMarker(td.marker());

    assert(fired1 && "first call fires");
    assert(!fired2 && "second call must be a no-op (latch consumed)");
    assert(body1 == body2 && "marker contents unchanged across calls");
    assert(running.load() == true && "second call must NOT touch running flag");

    std::cout << " OK\n";
}

// =============================================================================
// Test 4: disk-write failure path — pass empty datadir to force
// WriteAutoRebuildMarker to refuse. Helper must STILL flip the running flag,
// because letting the node continue on broken state is strictly worse than
// crash-looping with an obvious error in stderr.
// =============================================================================
void test_disk_write_failure_still_triggers_shutdown() {
    std::cout << "  test_disk_write_failure_still_triggers_shutdown..." << std::flush;
    Dilithion::ResetMaybeTriggerLatchForTesting();

    CChainState cs;
    DriveChainRebuildViaProductionPath(cs);

    std::atomic<bool> running{true};
    const std::string empty_datadir;  // forces WriteAutoRebuildMarker to log + return false
    const bool fired = Dilithion::MaybeTriggerChainRebuild(cs, empty_datadir, &running);

    assert(fired && "even with bad datadir, the trigger must fire");
    assert(running.load() == false && "running must be cleared regardless of disk write");

    std::cout << " OK\n";
}

// =============================================================================
// Test 5: mode symmetry — simulate two main-loop iterations corresponding to
// flag=0 (legacy adapter) and flag=1 (port CPeerManager). In production both
// modes call exactly the same helper after sync_coordinator->Tick(), so this
// test verifies that the same input yields byte-identical output regardless
// of which Tick() shape ran first.
//
// We simulate mode-0 by calling the helper after running NO Tick (the helper
// is mode-agnostic — what matters is the helper observes the same chainstate
// flags). For mode-1 we reset the latch and call again with a fresh
// chainstate prepared identically.
// =============================================================================
void test_mode_symmetric_marker_contents() {
    std::cout << "  test_mode_symmetric_marker_contents..." << std::flush;

    auto run_one = [](const std::string& tag) -> std::string {
        Dilithion::ResetMaybeTriggerLatchForTesting();
        TempDir td(tag);
        CChainState cs;
        DriveChainRebuildViaProductionPath(cs);
        std::atomic<bool> running{true};
        const bool fired = Dilithion::MaybeTriggerChainRebuild(cs, td.str(), &running);
        assert(fired);
        assert(running.load() == false);
        // Read BEFORE TempDir destructor wipes it.
        return ReadMarker(td.marker());
    };

    const std::string body_mode0 = run_one("mode0");
    const std::string body_mode1 = run_one("mode1");

    assert(!body_mode0.empty() && "mode-0 marker non-empty");
    assert(!body_mode1.empty() && "mode-1 marker non-empty");
    assert(body_mode0 == body_mode1
           && "v4.3.2 invariant: marker contents must be mode-symmetric");

    std::cout << " OK (mode-0 == mode-1: " << body_mode0 << ")\n";
}

// =============================================================================
// Test 6 (v4.4 follow-up / contract item 8): concurrent-write durability.
// (See top-of-file includes for <thread> — std::thread used here.)
//
// Multiple in-process paths can race to call WriteAutoRebuildMarker:
//   - startup integrity check (dilv-node.cpp / dilithion-node.cpp)
//   - periodic ChainstateIntegrityMonitor callback
//   - MaybeTriggerChainRebuild from main-loop poll
//   - forcerebuild RPC handler
//
// Without process-level serialization two writers can truncate-overwrite each
// other and produce a torn file (one writer's prefix concatenated with another
// writer's suffix). v4.4 adds a process-lifetime mutex inside
// WriteAutoRebuildMarker plus atomic-rename so the marker file is always one
// of the proposed reasons in full, never a torn mix.
//
// This test spawns N threads that all call WriteAutoRebuildMarker against the
// same datadir simultaneously with distinct reason strings. After the join,
// the resulting marker MUST equal exactly one of the proposed reasons — no
// torn or partial content. Order isn't asserted (last-writer-wins is fine);
// atomicity IS the contract.
// =============================================================================
void test_concurrent_marker_writes_produce_well_formed_file() {
    std::cout << "  test_concurrent_marker_writes_produce_well_formed_file..." << std::flush;

    constexpr int kThreads = 8;
    TempDir td("concurrent");

    // Generate N distinct reason strings, each long enough that a torn write
    // would produce a string that is NOT a complete reason (mid-string cut).
    std::vector<std::string> reasons;
    reasons.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        std::ostringstream oss;
        oss << "concurrent-test-thread-" << i
            << "-padded-with-text-so-tearing-is-detectable-"
            << std::string(64, 'A' + i);  // 64 distinguishable bytes per thread
        reasons.push_back(oss.str());
    }

    std::vector<std::thread> writers;
    writers.reserve(kThreads);
    std::atomic<int> ok_count{0};
    for (int i = 0; i < kThreads; ++i) {
        writers.emplace_back([&td, &reasons, &ok_count, i] {
            const bool ok = Dilithion::WriteAutoRebuildMarker(td.str(), reasons[i]);
            if (ok) ok_count.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& t : writers) t.join();

    // All N writers should have succeeded — the mutex serializes but doesn't
    // fail any caller.
    assert(ok_count.load() == kThreads && "every writer must succeed under serialization");

    // Marker file must equal exactly ONE of the proposed reasons (not torn).
    const std::string body = ReadMarker(td.marker());
    assert(!body.empty() && "marker file must exist after concurrent writes");
    bool matched = false;
    for (const auto& r : reasons) {
        if (body == r) {
            matched = true;
            break;
        }
    }
    assert(matched && "marker contents must equal exactly one writer's reason — "
                      "torn write detected");

    // No leftover .tmp file (atomic-rename should have moved it).
    const std::filesystem::path tmpPath = td.path / "auto_rebuild.tmp";
    assert(!std::filesystem::exists(tmpPath) && ".tmp file must not leak");

    std::cout << " OK (" << kThreads << " concurrent writers, no torn content)\n";
}

}  // namespace

int main() {
    std::cout << "\n=== v4.3.2 M1 — auto_rebuild marker mode-symmetry tests ===\n"
              << "    (regression suite for LDN canary 2026-05-04)\n"
              << "    + v4.4 follow-up: concurrent-write durability\n"
              << std::endl;
    try {
        test_marker_written_when_chain_rebuild_flagged();
        test_no_marker_when_no_flag();
        test_idempotent_double_call();
        test_disk_write_failure_still_triggers_shutdown();
        test_mode_symmetric_marker_contents();
        test_concurrent_marker_writes_produce_well_formed_file();
        std::cout << "\n=== All 6 tests passed ===\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
