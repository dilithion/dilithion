// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

// BKL-01 / issue #167: CTransaction::GetHash() memoised its txid through a
// plain `mutable bool` + `mutable uint256`, so N threads sharing one
// CTransactionRef raced on the flag and on the 32 hash bytes (TSan-confirmed
// on tx_index_tests/concurrent_findtx_and_writeblock). This suite pins the
// fix's contract:
//
//   1. concurrent GetHash() on one shared const object returns one value from
//      every thread, and that value is the fresh recompute (ComputeHash) and
//      an independently computed SHA3-256(Serialize());
//   2. every mutating MEMBER (operator=, copy-construct, Deserialize, SetNull)
//      invalidates the memo, so the next GetHash() reflects the new fields;
//   3. the publication boundary (MakeTransactionRef copy) recomputes from the
//      copied fields, so a shared ref can never inherit a stale memo from a
//      builder-side local that was mutated in place after hashing.
//
// Honesty note (see fix_txhash_race_report.md): without ThreadSanitizer the
// first case cannot RELIABLY detect the original race on x86 — the racing
// writers store identical bytes, so a torn read is invisible. The load-bearing
// proof is the TSan run; this case exists so that the TSan run has something
// that hammers a cold memo from many threads at once, and so that a future
// regression which produces a *different* value (e.g. a partially-written
// cache being returned) is caught even without TSan.

#include <boost/test/unit_test.hpp>

#include <crypto/sha3.h>
#include <primitives/transaction.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

namespace {

// Build a transaction whose serialization is a few KB (Dilithium-sized
// scriptSigs) so the compute window is wide enough for threads to overlap.
CTransaction MakeTx(uint32_t seed, size_t n_in, size_t n_out) {
    CTransaction tx;
    tx.nVersion = 1 + static_cast<int32_t>(seed % 2);
    tx.nLockTime = seed * 7919u;
    for (size_t i = 0; i < n_in; ++i) {
        uint256 prev;
        for (int b = 0; b < 32; ++b) {
            prev.data[b] = static_cast<uint8_t>(seed * 31u + i * 17u + b);
        }
        std::vector<uint8_t> sig(3309, static_cast<uint8_t>(seed + i));
        sig[0] = static_cast<uint8_t>(i);
        tx.vin.emplace_back(COutPoint(prev, static_cast<uint32_t>(i)), sig, 0xFFFFFFFFu);
    }
    for (size_t o = 0; o < n_out; ++o) {
        std::vector<uint8_t> spk(25, static_cast<uint8_t>(0x76 + o));
        tx.vout.emplace_back(1000000ull * (o + 1) + seed, spk);
    }
    return tx;
}

// Independent oracle: the same bytes the memo is supposed to cache, computed
// without going anywhere near GetHash()/ComputeHash().
uint256 IndependentTxid(const CTransaction& tx) {
    const std::vector<uint8_t> bytes = tx.Serialize();
    uint256 h;
    SHA3_256(bytes.data(), bytes.size(), h.data);
    return h;
}

} // namespace

BOOST_AUTO_TEST_SUITE(tx_hash_cache_race_tests)

// (1) N threads, one shared const ref, cold memo, released together through a
// spin barrier so they all enter the slow path at once. Repeated over many
// fresh objects to widen the sample.
BOOST_AUTO_TEST_CASE(concurrent_gethash_on_shared_ref_is_identical_and_fresh) {
    constexpr int kThreads = 8;
    constexpr int kRounds = 200;
    constexpr int kCallsPerThread = 32;

    uint64_t total_observations = 0;
    uint64_t mismatches = 0;

    for (int round = 0; round < kRounds; ++round) {
        const CTransactionRef ref = MakeTransactionRef(MakeTx(static_cast<uint32_t>(round), 3, 2));
        const uint256 expected = IndependentTxid(*ref);

        std::vector<uint256> seen(static_cast<size_t>(kThreads) * kCallsPerThread);
        std::atomic<int> ready{0};
        std::atomic<bool> go{false};

        std::vector<std::thread> threads;
        threads.reserve(kThreads);
        for (int t = 0; t < kThreads; ++t) {
            threads.emplace_back([&, t]() {
                ready.fetch_add(1, std::memory_order_acq_rel);
                while (!go.load(std::memory_order_acquire)) { /* spin */ }
                for (int c = 0; c < kCallsPerThread; ++c) {
                    seen[static_cast<size_t>(t) * kCallsPerThread + c] = ref->GetHash();
                }
            });
        }
        while (ready.load(std::memory_order_acquire) < kThreads) { std::this_thread::yield(); }
        go.store(true, std::memory_order_release);
        for (auto& th : threads) th.join();

        for (const uint256& h : seen) {
            ++total_observations;
            if (!(h == expected)) ++mismatches;
        }

        // The memo, once filled, must equal the fresh recompute AND the oracle.
        BOOST_CHECK(ref->GetHash() == ref->ComputeHash());
        BOOST_CHECK(ref->ComputeHash() == expected);
    }

    BOOST_CHECK_EQUAL(total_observations,
                      static_cast<uint64_t>(kThreads) * kCallsPerThread * kRounds);
    BOOST_CHECK_EQUAL(mismatches, 0u);
}

// (2) Ordering: every mutating member invalidates the memo. Each step first
// warms the memo on the OLD contents, then mutates through the member, then
// requires the next GetHash() to equal the fresh recompute of the NEW
// contents — and to differ from the warmed value, so a memo that was never
// reset cannot pass by coincidence.
BOOST_AUTO_TEST_CASE(mutating_members_invalidate_memo) {
    CTransaction tx = MakeTx(1, 1, 1);
    const uint256 h_initial = tx.GetHash();
    BOOST_REQUIRE(h_initial == tx.ComputeHash());
    BOOST_REQUIRE(h_initial == IndependentTxid(tx));

    // operator=
    {
        const CTransaction other = MakeTx(2, 2, 1);
        tx = other;
        BOOST_CHECK(tx.GetHash() == tx.ComputeHash());
        BOOST_CHECK(tx.GetHash() == other.ComputeHash());
        BOOST_CHECK(!(tx.GetHash() == h_initial));
    }

    // copy-construct from a warmed source: copy starts empty and recomputes
    {
        const uint256 h_src = tx.GetHash();
        const CTransaction copy(tx);
        BOOST_CHECK(copy.GetHash() == copy.ComputeHash());
        BOOST_CHECK(copy.GetHash() == h_src);
    }

    // Deserialize
    {
        const uint256 h_before = tx.GetHash();
        const CTransaction third = MakeTx(3, 1, 3);
        const std::vector<uint8_t> bytes = third.Serialize();
        std::string err;
        BOOST_REQUIRE_MESSAGE(tx.Deserialize(bytes.data(), bytes.size(), &err), err);
        BOOST_CHECK(tx.GetHash() == tx.ComputeHash());
        BOOST_CHECK(tx.GetHash() == third.ComputeHash());
        BOOST_CHECK(!(tx.GetHash() == h_before));
    }

    // SetNull
    {
        const uint256 h_before = tx.GetHash();
        tx.SetNull();
        BOOST_CHECK(tx.GetHash() == tx.ComputeHash());
        BOOST_CHECK(tx.GetHash() == CTransaction().ComputeHash());
        BOOST_CHECK(!(tx.GetHash() == h_before));
    }
}

// (3) Publication boundary: a builder-side local that was hashed and THEN
// mutated through a public field (not an invalidating member — the residual of
// the compute-once design, documented in the header) cannot leak its stale
// memo into a shared ref, because MakeTransactionRef copy-constructs and the
// copy starts with an empty memo.
BOOST_AUTO_TEST_CASE(publication_copy_recomputes_from_fields) {
    CTransaction local = MakeTx(4, 1, 1);
    const uint256 h_before = local.GetHash();

    local.vout.push_back(CTxOut(42, std::vector<uint8_t>{0xAA, 0xBB}));

    const CTransactionRef published = MakeTransactionRef(local);
    BOOST_CHECK(published->GetHash() == published->ComputeHash());
    BOOST_CHECK(published->GetHash() == IndependentTxid(*published));
    BOOST_CHECK(!(published->GetHash() == h_before));

    // And a copy-assigned destination likewise recomputes.
    CTransaction assigned;
    assigned = local;
    BOOST_CHECK(assigned.GetHash() == IndependentTxid(local));
}

BOOST_AUTO_TEST_SUITE_END()
