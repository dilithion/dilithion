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

#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
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

}  // namespace

int main() {
    std::cout << "\n=== v4.4 chainstate-integrity startup-walk tests ===\n"
              << "    (CUTXOSet::VerifyUndoDataInRange — pprev walk)\n"
              << std::endl;
    try {
        test_integrity_passes_on_clean_chainstate();
        test_integrity_fails_on_missing_undo();
        test_integrity_fails_on_checksum_corruption();
        test_integrity_short_window_skips_below_checkpoint();
        std::cout << "\n=== All 4 tests passed ===\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test failed (unknown)" << std::endl;
        return 1;
    }
}
