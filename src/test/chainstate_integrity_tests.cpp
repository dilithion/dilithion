// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// v4.4 chainstate-integrity hardening — startup-walk regression tests.
//
// PURPOSE
// =======
// Validate CUTXOSet::VerifyUndoDataInRange returns:
//   - true  when every block in [fromHeight, toHeight] has a present, framed undo entry
//   - false (cause="missing")            when an in-window block has no undo entry
//   - false (cause="checksum_mismatch")  when an in-window block's entry has corrupted bytes
//   - true  when the corrupted/missing block is OUTSIDE [fromHeight, toHeight]
//
// HISTORY
// =======
// The 2026-04-25 incident on NYC + LDN exhibited the missing-undo-data corruption
// mode: chainstate had advanced past blocks whose undo entries were never durably
// written. UndoBlock could not disconnect them; reorg attempts failed; nodes
// crash-looped trying to reorg a chain they could not undo. v4.0.19 added
// CChainState::VerifyRecentUndoIntegrity (a fixed 100-block startup probe). v4.4
// generalises it to a rolling window from highest-checkpoint to tip via
// CUTXOSet::VerifyUndoDataInRange and adds SHA3-256 checksum verification that
// the v4.0.19 path lacked.

#include <node/utxo_set.h>
#include <node/block_index.h>
#include <node/chainstate_integrity_monitor.h>
#include <consensus/chain.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
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

struct TempDir {
    std::filesystem::path path;
    explicit TempDir(const std::string& tag) {
        std::random_device rd;
        std::ostringstream oss;
        oss << "dilithion-v44-integrity-" << tag << "-" << rd();
        path = std::filesystem::temp_directory_path() / oss.str();
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::string str() const { return path.string(); }
};

uint256 MakeBlockHash(int seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = static_cast<uint8_t>(seed & 0xFF);
    h.data[1] = static_cast<uint8_t>((seed >> 8) & 0xFF);
    h.data[31] = 0x42;  // sentinel — never produces an all-zero hash
    return h;
}

// Build a synthetic CBlockIndex chain of `count` blocks at heights 1..count.
// Returns the tip; chainOut owns the indices.
CBlockIndex* BuildSyntheticChain(int count,
                                 std::vector<std::unique_ptr<CBlockIndex>>& chainOut) {
    chainOut.clear();
    chainOut.reserve(count);
    for (int h = 1; h <= count; ++h) {
        auto pi = std::make_unique<CBlockIndex>();
        pi->nHeight = h;
        pi->phashBlock = MakeBlockHash(h);
        pi->pprev = (h > 1) ? chainOut.back().get() : nullptr;
        chainOut.push_back(std::move(pi));
    }
    return chainOut.back().get();
}

void WriteValidUndoForChain(CUTXOSet& utxo,
                            const std::vector<std::unique_ptr<CBlockIndex>>& chain) {
    for (const auto& pi : chain) {
        // Minimum-viable payload: 4-byte spentCount = 0. WriteFramedUndoForTesting
        // appends the SHA3-256 checksum so VerifyUndoChecksum returns Valid on read.
        std::vector<uint8_t> payload(4, 0);
        bool ok = utxo.WriteFramedUndoForTesting(pi->phashBlock, payload);
        assert(ok && "WriteFramedUndoForTesting must succeed");
    }
}

// =============================================================================
// Test 1: clean chainstate — every in-window block has a valid undo record,
// walk passes, no failure populated.
// =============================================================================
void test_integrity_passes_on_clean_chainstate() {
    std::cout << "  test_integrity_passes_on_clean_chainstate..." << std::flush;
    TempDir td("clean");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true) && "open clean utxo db");

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    UndoIntegrityFailure failure;
    bool ok = utxo.VerifyUndoDataInRange(tip, 1, 100, failure);
    assert(ok && "clean chain must verify");
    assert(failure.height == -1 && "no failure on clean chain");
    assert(failure.cause.empty() && "no cause on clean chain");

    std::cout << " OK\n";
}

// =============================================================================
// Test 2: missing undo — delete one in-window block's entry; walk fails with
// cause="missing", failure_out populated with the deleted height + hash.
// =============================================================================
void test_integrity_fails_on_missing_undo() {
    std::cout << "  test_integrity_fails_on_missing_undo..." << std::flush;
    TempDir td("missing");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true) && "open utxo db");

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    const uint256 victim = chain[49]->phashBlock;  // height 50 (chain[0] is height 1)
    assert(utxo.DeleteUndoForTesting(victim) && "delete undo entry");

    UndoIntegrityFailure failure;
    bool ok = utxo.VerifyUndoDataInRange(tip, 1, 100, failure);
    assert(!ok && "missing undo entry must surface as failure");
    assert(failure.height == 50 && "failure must be reported at the deleted height");
    assert(failure.blockHash == victim && "failure hash must match");
    assert(failure.cause == "missing" && "cause must be 'missing'");

    std::cout << " OK\n";
}

// =============================================================================
// Test 3: checksum corruption — flip one payload byte; walk fails with
// cause="checksum_mismatch".
// =============================================================================
void test_integrity_fails_on_checksum_corruption() {
    std::cout << "  test_integrity_fails_on_checksum_corruption..." << std::flush;
    TempDir td("corruption");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true) && "open utxo db");

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    const uint256 victim = chain[49]->phashBlock;  // height 50
    assert(utxo.CorruptUndoForTesting(victim) && "corrupt undo entry");

    UndoIntegrityFailure failure;
    bool ok = utxo.VerifyUndoDataInRange(tip, 1, 100, failure);
    assert(!ok && "corrupted undo entry must surface as failure");
    assert(failure.height == 50 && "failure must be reported at the corrupted height");
    assert(failure.blockHash == victim && "failure hash must match");
    assert(failure.cause == "checksum_mismatch" && "cause must be 'checksum_mismatch'");

    std::cout << " OK\n";
}

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
// Test 4: window discipline — corrupt a block BELOW [fromHeight, toHeight]; walk
// must skip it and report success. Validates the "rolling window from
// highest_checkpoint+1 to tip" semantic.
// =============================================================================
void test_integrity_short_window_skips_below_checkpoint() {
    std::cout << "  test_integrity_short_window_skips_below_checkpoint..." << std::flush;
    TempDir td("window");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true) && "open utxo db");

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    // Delete the entry at height 30 (BELOW the [51, 100] verification window).
    const uint256 below_window = chain[29]->phashBlock;
    assert(utxo.DeleteUndoForTesting(below_window) && "delete below-window undo entry");

    UndoIntegrityFailure failure;
    bool ok = utxo.VerifyUndoDataInRange(tip, 51, 100, failure);
    assert(ok && "h=30 below window must not surface as failure");
    assert(failure.height == -1 && "no failure on in-window walk");
    assert(failure.cause.empty() && "no cause when window-bounded walk passes");

    std::cout << " OK\n";
}

// =============================================================================
// Periodic-monitor tests (Block 7)
// =============================================================================
// Exercise ChainstateIntegrityMonitor's RunOneCycleForTesting path plus the
// full snapshot → walk → revalidate sequence in the orphan-skip configuration
// that requires manual driving (mid-cycle tip swap is not exposed via a test
// hook on the monitor itself).

// =============================================================================
// Test 5: periodic monitor on a clean chain — single cycle returns true,
// running flag preserved, no marker file produced.
// =============================================================================
void test_periodic_monitor_passes_on_clean_chain() {
    std::cout << "  test_periodic_monitor_passes_on_clean_chain..." << std::flush;
    TempDir td("monitor-clean");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true));

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    CChainState cs;
    cs.SetUTXOSet(&utxo);
    cs.SetTipForTest(tip);

    std::atomic<bool> running{true};
    Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);

    bool result = monitor.RunOneCycleForTesting();
    assert(result && "clean chain cycle must return true");
    assert(running.load() && "running flag must NOT be flipped on clean chain");

    auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
    assert(!std::filesystem::exists(markerPath) && "no marker on clean chain");

    std::cout << " OK\n";
}

// =============================================================================
// Test 6: periodic monitor against runtime corruption — corrupt one undo
// entry in the active-chain window, run one cycle, assert (a) cycle returns
// false (corruption confirmed), (b) marker file written with structured
// reason, (c) running flag flipped to false.
// =============================================================================
void test_periodic_monitor_fails_on_runtime_corruption() {
    std::cout << "  test_periodic_monitor_fails_on_runtime_corruption..." << std::flush;
    TempDir td("monitor-corrupt");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true));

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    // Corrupt block at h=80. Monitor's 500-block window covers all 100 blocks.
    const uint256 victim = chain[79]->phashBlock;
    assert(utxo.CorruptUndoForTesting(victim) && "corrupt undo entry");

    CChainState cs;
    cs.SetUTXOSet(&utxo);
    cs.SetTipForTest(tip);

    std::atomic<bool> running{true};
    Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);
    // Zero the retry backoff so the 3-attempt self-heal loop doesn't add 60s.
    // A checksum mismatch is reproducible, so it still fails all 3 attempts and
    // confirms corruption exactly as before the self-heal change.
    monitor.SetRevalidateBackoffForTesting(std::chrono::milliseconds::zero());

    bool result = monitor.RunOneCycleForTesting();
    assert(!result && "corrupted chain cycle must return false");
    assert(!running.load() && "running flag must be flipped on confirmed corruption");

    auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
    assert(std::filesystem::exists(markerPath) && "marker must be written");

    const std::string reason = ReadMarker(markerPath);
    assert(reason.find("Periodic integrity check failed") != std::string::npos
           && "reason must include the periodic prefix");
    assert(reason.find("height 80") != std::string::npos
           && "reason must include failure height");
    assert(reason.find("checksum_mismatch") != std::string::npos
           && "reason must include cause");

    std::cout << " OK (reason: " << reason << ")\n";
}

// =============================================================================
// Test 7: periodic monitor clean shutdown — Start() spawns worker, Stop()
// interrupts the cv-wait promptly, worker thread joined within 5s.
// Validates trap-8 / RT F-11: condition_variable::wait_for(predicate)
// rather than sleep_for(6h).
// =============================================================================
void test_periodic_monitor_clean_shutdown() {
    std::cout << "  test_periodic_monitor_clean_shutdown..." << std::flush;
    TempDir td("monitor-shutdown");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true));

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(100, chain);
    WriteValidUndoForChain(utxo, chain);

    CChainState cs;
    cs.SetUTXOSet(&utxo);
    cs.SetTipForTest(tip);

    std::atomic<bool> running{true};
    Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);

    monitor.Start();
    assert(monitor.IsRunningForTesting() && "worker thread should be alive after Start()");

    // Brief sleep so the worker definitely entered cv.wait_for.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto t0 = std::chrono::steady_clock::now();
    monitor.Stop();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0).count();

    assert(!monitor.IsRunningForTesting() && "worker thread must be joined after Stop()");
    // cv.notify_all should interrupt the 6h wait_for in milliseconds, not 6h.
    assert(elapsed_ms < 5000 && "Stop() must be fast — cv interrupt should be ~ms");

    std::cout << " OK (Stop took " << elapsed_ms << "ms)\n";
}

// =============================================================================
// Test 8: orphan-skip on reorg — the snapshot is taken against chain A but a
// reorg supersedes A with chain B before the walk. The walk hits a "missing"
// entry (one we deleted to simulate UndoBlock having removed it during the
// reorg), and the revalidation gate verifies that the snapshotted hash is
// no longer on the active chain → orphan-skip, no marker, no shutdown.
//
// Validates Cursor F-1 + Inverse Adversarial trap 2A. We drive the three
// monitor primitives manually because the monitor's RunOneCycleForTesting
// does not expose a hook for swapping the tip mid-cycle.
// =============================================================================
void test_periodic_monitor_skips_orphan_on_reorg() {
    std::cout << "  test_periodic_monitor_skips_orphan_on_reorg..." << std::flush;
    TempDir td("monitor-orphan");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true));

    // Chain A: heights 1..100, hashes from MakeBlockHash.
    std::vector<std::unique_ptr<CBlockIndex>> chainA;
    CBlockIndex* tipA = BuildSyntheticChain(100, chainA);
    WriteValidUndoForChain(utxo, chainA);

    // Chain B: forks at h=50 (shared parent chainA[49]). Different hashes for
    // h=51..100 via a chain-B marker byte. We do NOT write undo entries for
    // chain B — irrelevant to this test (we never walk against B's hashes).
    std::vector<std::unique_ptr<CBlockIndex>> chainB_extension;
    chainB_extension.reserve(50);
    CBlockIndex* prevB = chainA[49].get();  // parent at h=50 shared with A
    for (int h = 51; h <= 100; ++h) {
        auto pi = std::make_unique<CBlockIndex>();
        pi->nHeight = h;
        uint256 hash;
        std::memset(hash.data, 0, 32);
        hash.data[0] = static_cast<uint8_t>(h & 0xFF);
        hash.data[1] = static_cast<uint8_t>((h >> 8) & 0xFF);
        hash.data[2] = 0xFE;  // chain-B marker byte distinguishes from A
        hash.data[31] = 0x42;
        pi->phashBlock = hash;
        pi->pprev = prevB;
        chainB_extension.push_back(std::move(pi));
        prevB = chainB_extension.back().get();
    }
    CBlockIndex* tipB = chainB_extension.back().get();

    CChainState cs;
    cs.SetUTXOSet(&utxo);
    cs.SetTipForTest(tipA);

    // Step 1 — snapshot the integrity window against chain A.
    auto snapshot = cs.SnapshotIntegrityWindow(500);
    assert(!snapshot.empty() && "snapshot non-empty");

    // Step 2 — simulate UndoBlock deleting chain A's h=80 undo entry as part
    // of the reorg that's about to land.
    const uint256 victimHash = chainA[79]->phashBlock;
    assert(utxo.DeleteUndoForTesting(victimHash) && "delete h=80 undo entry");

    // Step 3 — reorg happens: tip switches to chain B.
    cs.SetTipForTest(tipB);

    // Step 4 — walk the snapshot. Walk fails at h=80 (missing entry) since
    // the snapshot still contains chain A's h=80 hash.
    UndoIntegrityFailure failure;
    bool walkOk = utxo.VerifyUndoDataFromSnapshot(snapshot, failure);
    assert(!walkOk && "walk must report missing undo entry");
    assert(failure.cause == "missing" && "cause must be 'missing'");
    assert(failure.height == 80 && "failure at the deleted height");
    assert(failure.blockHash == victimHash && "failure hash matches deleted entry");

    // Step 5 — revalidation gate. Fresh tip is chain B; walking pprev to h=80
    // arrives at chain B's h=80 (different hash from chain A's). The gate
    // returns false (orphan-skip), the callback is NOT invoked, no marker.
    bool callbackFired = false;
    bool genuine = cs.RevalidateUnderCsMain(failure.height, failure.blockHash,
                                            [&callbackFired] { callbackFired = true; });
    assert(!genuine && "block was reorged out — revalidation must report orphan-skip");
    assert(!callbackFired && "marker-write callback must NOT fire on orphan-skip");

    // Step 6 — no marker file should exist in datadir.
    auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
    assert(!std::filesystem::exists(markerPath) && "no marker on orphan-skip");

    std::cout << " OK\n";
}

// =============================================================================
// Test 9: transient-classification — genuine corruption modes (missing key,
// checksum mismatch) must be classified transient=false so the self-heal loop
// NEVER tolerates real corruption. (The inverse direction — a true IsIOError
// being classified transient=true — cannot be exercised without LevelDB fault
// injection; this test locks in the safety-critical direction: real corruption
// is never mislabelled transient.)
// =============================================================================
void test_transient_classification_never_masks_real_corruption() {
    std::cout << "  test_transient_classification_never_masks_real_corruption..."
              << std::flush;
    TempDir td("transient-class");
    CUTXOSet utxo;
    assert(utxo.Open(td.str(), true));

    std::vector<std::unique_ptr<CBlockIndex>> chain;
    CBlockIndex* tip = BuildSyntheticChain(20, chain);
    WriteValidUndoForChain(utxo, chain);

    // Case A: clean missing key (IsNotFound) — transient must be false.
    {
        const uint256 victim = chain[9]->phashBlock;
        assert(utxo.DeleteUndoForTesting(victim));
        std::vector<std::pair<int, uint256>> snapshot;
        snapshot.emplace_back(chain[9]->nHeight, victim);
        UndoIntegrityFailure failure;
        bool ok = utxo.VerifyUndoDataFromSnapshot(snapshot, failure);
        assert(!ok && "missing key must fail the walk");
        assert(failure.cause == "missing" && "clean absent key => 'missing'");
        assert(failure.transient == false &&
               "a genuinely-missing key must NEVER be classified transient");
        // restore for next case
        WriteValidUndoForChain(utxo, chain);
    }

    // Case B: checksum mismatch — transient must be false.
    {
        const uint256 victim = chain[9]->phashBlock;
        assert(utxo.CorruptUndoForTesting(victim));
        std::vector<std::pair<int, uint256>> snapshot;
        snapshot.emplace_back(chain[9]->nHeight, victim);
        UndoIntegrityFailure failure;
        bool ok = utxo.VerifyUndoDataFromSnapshot(snapshot, failure);
        assert(!ok && "checksum mismatch must fail the walk");
        assert(failure.cause == "checksum_mismatch");
        assert(failure.transient == false &&
               "a checksum mismatch must NEVER be classified transient");
    }

    (void)tip;
    std::cout << " OK\n";
}

// =============================================================================
// Test 9b: classifier unit — the (cause, transient) mapping at the LevelDB-
// status seam. This is the EXACT line that shipped the BLOCKER: IsCorruption()
// was bucketed transient=true, so real on-disk corruption would be tolerated
// forever. A no-op classifier (or one that buckets IsCorruption with IsIOError)
// MUST fail these asserts. Drives synthetic leveldb::Status values directly —
// the dangerous direction (IsCorruption) that Test 9 admitted it couldn't reach.
// =============================================================================
void test_classify_undo_fetch_status_mapping() {
    std::cout << "  test_classify_undo_fetch_status_mapping..." << std::flush;

    // IsCorruption() => HARD FAIL. Real on-disk damage reproduces on every read;
    // it must route to the corruption gate (marker + shutdown), NOT tolerate.
    {
        UndoIntegrityFailure f;
        ClassifyUndoFetchStatus(leveldb::Status::Corruption("bad SST CRC32C"), f);
        assert(f.transient == false &&
               "IsCorruption MUST be non-transient (real on-disk corruption, not a blip)");
        assert(f.cause == "io_corruption" && "IsCorruption => cause 'io_corruption'");
    }

    // IsIOError() => transient. A recoverable storage blip may clear on retry.
    {
        UndoIntegrityFailure f;
        ClassifyUndoFetchStatus(leveldb::Status::IOError("EIO blip"), f);
        assert(f.transient == true &&
               "IsIOError MUST be transient (recoverable storage-layer blip)");
        assert(f.cause == "io_error" && "IsIOError => cause 'io_error'");
    }

    // NotFound / any other non-ok status => fail-safe non-transient "missing".
    {
        UndoIntegrityFailure f;
        ClassifyUndoFetchStatus(leveldb::Status::NotFound("absent key"), f);
        assert(f.transient == false &&
               "a genuinely-absent key must be non-transient ('missing')");
        assert(f.cause == "missing" && "IsNotFound => cause 'missing'");
    }

    std::cout << " OK\n";
}

// =============================================================================
// Test 9c: end-to-end monitor routing through the undo-fetch fault injector.
// Proves the DANGEROUS direction the BLOCKER was about — a persistent
// IsCorruption is NEVER tolerated; it confirms across retries -> marker +
// shutdown. And the SAFE-but-tolerant direction — a transient IsIOError that
// clears on retry IS tolerated (node keeps running, no marker). A no-op
// classifier (IsCorruption mislabelled transient) fails the persistent-
// corruption case: it would take the tolerate branch, leave running=true, and
// write no marker.
// =============================================================================
void test_monitor_routes_injected_faults() {
    std::cout << "  test_monitor_routes_injected_faults..." << std::flush;

    // --- Case A: persistent IsCorruption -> shut down WITH marker (NOT tolerated).
    {
        TempDir td("inject-corruption");
        CUTXOSet utxo;
        assert(utxo.Open(td.str(), true));
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        CBlockIndex* tip = BuildSyntheticChain(50, chain);
        WriteValidUndoForChain(utxo, chain);  // chain is otherwise CLEAN on disk
        CChainState cs;
        cs.SetUTXOSet(&utxo);
        cs.SetTipForTest(tip);

        // Inject a persistent (every-call) IsCorruption at the fetch seam.
        int corruptionCalls = 0;
        g_undo_fetch_fault_injector = [&corruptionCalls]() {
            ++corruptionCalls;
            return leveldb::Status::Corruption("persistent SST CRC failure");
        };

        std::atomic<bool> running{true};
        Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);
        monitor.SetRevalidateBackoffForTesting(std::chrono::milliseconds::zero());
        bool cyclePass = monitor.RunOneCycleForTesting();
        g_undo_fetch_fault_injector = nullptr;  // clear before asserts/destructors

        assert(!cyclePass &&
               "persistent IsCorruption must NOT pass the cycle (real corruption)");
        assert(!running.load() &&
               "persistent IsCorruption MUST flip running=false (shutdown), NOT tolerate");
        auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
        assert(std::filesystem::exists(markerPath) &&
               "persistent IsCorruption MUST write the auto_rebuild marker");
        assert(corruptionCalls >= 1 && "injector must have been consulted");
    }

    // --- Case B: transient IsIOError that CLEARS on retry -> tolerated (running).
    {
        TempDir td("inject-ioerror-clears");
        CUTXOSet utxo;
        assert(utxo.Open(td.str(), true));
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        CBlockIndex* tip = BuildSyntheticChain(50, chain);
        WriteValidUndoForChain(utxo, chain);  // clean on disk
        CChainState cs;
        cs.SetUTXOSet(&utxo);
        cs.SetTipForTest(tip);

        // Deterministic one-shot: fail the very FIRST fetch with IsIOError, then
        // clear. The walk short-circuits on first failure, so attempt 1 fails
        // (transient IOError); the post-backoff (zero) retry walk reads the
        // healthy on-disk data and passes -> the fault is tolerated, no marker.
        std::atomic<int> calls{0};
        g_undo_fetch_fault_injector = [&calls]() {
            if (calls.fetch_add(1) == 0) {
                return leveldb::Status::IOError("transient EIO (one-shot)");
            }
            return leveldb::Status::OK();
        };

        std::atomic<bool> running{true};
        Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);
        monitor.SetRevalidateBackoffForTesting(std::chrono::milliseconds::zero());
        bool cyclePass = monitor.RunOneCycleForTesting();
        g_undo_fetch_fault_injector = nullptr;

        assert(calls.load() >= 2 &&
               "injector must have been consulted on attempt 1 (fail) and a retry");
        assert(cyclePass &&
               "transient IsIOError that clears on retry MUST pass (tolerated)");
        assert(running.load() &&
               "transient IsIOError that clears MUST keep running (no shutdown)");
        auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
        assert(!std::filesystem::exists(markerPath) &&
               "no marker for a transient fault that cleared on retry");
        (void)tip;
    }

    std::cout << " OK\n";
}

// =============================================================================
// Test 10: retry loop confirms reproducible corruption only after exhausting
// all attempts (with zeroed backoff) — and a clean chain still passes through
// the multi-attempt loop with no false positive.
// =============================================================================
void test_retry_loop_confirms_reproducible_corruption() {
    std::cout << "  test_retry_loop_confirms_reproducible_corruption..."
              << std::flush;

    // Clean chain: must pass even though the loop now runs up to 3 attempts.
    {
        TempDir td("retry-clean");
        CUTXOSet utxo;
        assert(utxo.Open(td.str(), true));
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        CBlockIndex* tip = BuildSyntheticChain(50, chain);
        WriteValidUndoForChain(utxo, chain);
        CChainState cs;
        cs.SetUTXOSet(&utxo);
        cs.SetTipForTest(tip);
        std::atomic<bool> running{true};
        Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);
        monitor.SetRevalidateBackoffForTesting(std::chrono::milliseconds::zero());
        assert(monitor.RunOneCycleForTesting() && "clean chain must pass loop");
        assert(running.load() && "running flag preserved on clean chain");
    }

    // Reproducible corruption: fails all attempts, confirms, writes marker.
    {
        TempDir td("retry-corrupt");
        CUTXOSet utxo;
        assert(utxo.Open(td.str(), true));
        std::vector<std::unique_ptr<CBlockIndex>> chain;
        CBlockIndex* tip = BuildSyntheticChain(50, chain);
        WriteValidUndoForChain(utxo, chain);
        assert(utxo.CorruptUndoForTesting(chain[24]->phashBlock));
        CChainState cs;
        cs.SetUTXOSet(&utxo);
        cs.SetTipForTest(tip);
        std::atomic<bool> running{true};
        Dilithion::ChainstateIntegrityMonitor monitor(cs, utxo, td.str(), &running);
        monitor.SetRevalidateBackoffForTesting(std::chrono::milliseconds::zero());
        assert(!monitor.RunOneCycleForTesting() &&
               "reproducible corruption must confirm after retries");
        assert(!running.load() && "running flag flipped on confirmed corruption");
        auto markerPath = std::filesystem::path(td.str()) / "auto_rebuild";
        assert(std::filesystem::exists(markerPath) && "marker written");
    }

    std::cout << " OK\n";
}

}  // namespace

int main() {
    std::cout << "\n=== v4.4 chainstate-integrity tests ===\n"
              << "    Block 4 (startup walk): CUTXOSet::VerifyUndoDataInRange\n"
              << "    Block 7 (periodic monitor): ChainstateIntegrityMonitor\n"
              << std::endl;
    try {
        std::cout << "[startup walk]" << std::endl;
        test_integrity_passes_on_clean_chainstate();
        test_integrity_fails_on_missing_undo();
        test_integrity_fails_on_checksum_corruption();
        test_integrity_short_window_skips_below_checkpoint();

        std::cout << "[periodic monitor]" << std::endl;
        test_periodic_monitor_passes_on_clean_chain();
        test_periodic_monitor_fails_on_runtime_corruption();
        test_periodic_monitor_clean_shutdown();
        test_periodic_monitor_skips_orphan_on_reorg();

        std::cout << "[self-heal / transient tolerance]" << std::endl;
        test_transient_classification_never_masks_real_corruption();
        test_classify_undo_fetch_status_mapping();
        test_monitor_routes_injected_faults();
        test_retry_loop_confirms_reproducible_corruption();

        std::cout << "\n=== All 12 tests passed ===\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
