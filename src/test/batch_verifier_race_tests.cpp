// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// LP-5 / CRITICAL-1 + MED-2 concurrency stress + differential harness.
//
// Purpose (contract §3.2): prove the per-batch session refactor removes the
// cross-batch race in CSignatureBatchVerifier.
//
//   - N concurrent caller threads each run BeginBatch -> Add(>=2 P2PKH-shaped
//     Dilithium3 signature tasks) -> Wait, in a tight loop.
//   - Batches are a mix of all-valid and "exactly-one-bad-signature" batches,
//     interleaved at random so valid and invalid batches are in flight
//     simultaneously under worker-pool contention.
//   - DIFFERENTIAL INVARIANT (A-004): for every batch, the verifier's Wait()
//     verdict MUST equal the sequential oracle (per-signature
//     pqcrystals_dilithium3_ref_verify run directly, single-threaded). Any
//     divergence is a fail.
//   - A-002: a one-bad-sig batch must NEVER return true (no invalid-sig accept).
//   - A-001 / A-003: a valid batch must NEVER return false (no cross-contam
//     from a concurrent bad batch; no counter underflow / hang).
//   - A-005: each iteration enters Wait() right after Add(), exercising the
//     narrow window before the final worker decrement (lost-wakeup / MED-2).
//
// CONTROL vs FIX (A-010): on the pre-fix code (shared global batch state) this
// harness reliably reports a differential mismatch and/or hangs on a size_t
// underflow. On the fixed code (per-batch session) every iteration matches the
// oracle and the run completes. Build under ThreadSanitizer on Linux
// (make TSAN=1 batch_verifier_race_tests) to additionally flag the data race
// on the control and confirm clean on the fix.
//
// The harness drives CSignatureBatchVerifier directly (not the full RPC stack)
// because the race lives entirely in the verifier's per-batch state; this keeps
// the proof minimal and deterministic while reproducing the exact concurrent
// BeginBatch/Add/Wait load shape the RPC worker pool produces.

#include <consensus/signature_batch_verifier.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <thread>
#include <vector>

extern "C" {
int pqcrystals_dilithium3_ref_keypair(uint8_t* pk, uint8_t* sk);
int pqcrystals_dilithium3_ref_signature(uint8_t* sig, size_t* siglen,
                                        const uint8_t* m, size_t mlen,
                                        const uint8_t* ctx, size_t ctxlen,
                                        const uint8_t* sk);
int pqcrystals_dilithium3_ref_verify(const uint8_t* sig, size_t siglen,
                                     const uint8_t* m, size_t mlen,
                                     const uint8_t* ctx, size_t ctxlen,
                                     const uint8_t* pk);
}

static constexpr size_t PK_SIZE = 1952;   // Dilithium3 public key
static constexpr size_t SIG_SIZE = 3309;  // Dilithium3 signature
static constexpr size_t MSG_SIZE = 32;    // SHA3-256 preimage hash the node feeds

// A single signature triple, in the exact (signature, message, pubkey) shape
// that BatchVerifyScripts hands to verifier.Add().
struct Triple {
    std::vector<uint8_t> sig;
    std::vector<uint8_t> msg;
    std::vector<uint8_t> pub;
};

// Sequential oracle: verify one triple exactly as VerifySingle does (same sizes,
// same ctx=nullptr,0), but on the calling thread with no shared state.
static bool OracleVerify(const Triple& t) {
    if (t.sig.size() != SIG_SIZE) return false;
    if (t.pub.size() != PK_SIZE) return false;
    if (t.msg.size() != MSG_SIZE) return false;
    return pqcrystals_dilithium3_ref_verify(t.sig.data(), t.sig.size(),
                                            t.msg.data(), t.msg.size(),
                                            nullptr, 0, t.pub.data()) == 0;
}

// Build one valid triple from a fresh keypair over a random message.
static Triple MakeValid(std::mt19937_64& rng) {
    std::vector<uint8_t> pk(PK_SIZE), sk(4032 /*Dilithium3 SECRETKEYBYTES*/);
    // keypair uses its own RNG internally; deterministic per call isn't required.
    pqcrystals_dilithium3_ref_keypair(pk.data(), sk.data());

    Triple t;
    t.pub = pk;
    t.msg.resize(MSG_SIZE);
    for (auto& b : t.msg) b = static_cast<uint8_t>(rng());

    t.sig.resize(SIG_SIZE);
    size_t siglen = 0;
    pqcrystals_dilithium3_ref_signature(t.sig.data(), &siglen, t.msg.data(),
                                        t.msg.size(), nullptr, 0, sk.data());
    t.sig.resize(siglen);
    // Dilithium3 signature is fixed-length SIG_SIZE; pad/trim defensively.
    t.sig.resize(SIG_SIZE);
    return t;
}

// Corrupt a valid triple into an invalid one by flipping a message byte. The
// signature no longer matches the message => verify must fail. This models the
// "one bad signature in the batch" case without changing sizes.
static Triple MakeBadFrom(const Triple& good) {
    Triple t = good;
    t.msg[0] ^= 0xFF;
    return t;
}

int main() {
    std::printf("[LP-5 harness] building key/signature pool...\n");

    // Pre-generate a pool of valid triples (keypair+sign is ~ms; do it once).
    std::mt19937_64 seed_rng(0xC0FFEEull);
    constexpr size_t POOL = 24;
    std::vector<Triple> pool;
    pool.reserve(POOL);
    for (size_t i = 0; i < POOL; ++i) pool.push_back(MakeValid(seed_rng));

    // Sanity: every pooled triple verifies, and a corrupted one does not.
    for (const auto& t : pool) {
        if (!OracleVerify(t)) {
            std::printf("[LP-5 harness] FAIL: pool triple did not self-verify\n");
            return 1;
        }
    }
    if (OracleVerify(MakeBadFrom(pool[0]))) {
        std::printf("[LP-5 harness] FAIL: corrupted triple unexpectedly verified\n");
        return 1;
    }
    std::printf("[LP-5 harness] pool ok (%zu triples)\n", POOL);

    // Start the shared verifier (same shape as node startup: 4 workers).
    InitSignatureVerifier(4);

    constexpr int kThreads = 8;       // more concurrent callers than 4 workers
    constexpr int kItersPerThread = 400;
    constexpr size_t kMinInputs = 2;  // batch path requires >=2 inputs
    constexpr size_t kMaxInputs = 6;

    std::atomic<long> mismatches{0};
    std::atomic<long> bad_accepted{0};
    std::atomic<long> good_rejected{0};
    std::atomic<long> total_batches{0};

    auto worker = [&](int tid) {
        std::mt19937_64 rng(0x9E3779B97F4A7C15ull ^ (uint64_t)(tid + 1));
        for (int it = 0; it < kItersPerThread; ++it) {
            // Compose a batch of [kMinInputs..kMaxInputs] triples drawn from pool.
            size_t n = kMinInputs + (rng() % (kMaxInputs - kMinInputs + 1));
            std::vector<Triple> batch;
            batch.reserve(n);
            for (size_t i = 0; i < n; ++i) {
                batch.push_back(pool[rng() % pool.size()]);
            }
            // ~40% of batches carry exactly one bad signature.
            bool inject_bad = (rng() % 5) < 2;
            if (inject_bad) {
                size_t k = rng() % n;
                batch[k] = MakeBadFrom(batch[k]);
            }

            // Sequential oracle verdict for this exact batch.
            bool oracle_ok = true;
            for (const auto& t : batch) {
                if (!OracleVerify(t)) { oracle_ok = false; break; }
            }

            // Batch verifier verdict — the path under test.
            auto session = g_signature_verifier->BeginBatch();
            for (size_t i = 0; i < batch.size(); ++i) {
                g_signature_verifier->Add(session, batch[i].sig, batch[i].msg,
                                          batch[i].pub, i);
            }
            std::string err;
            bool batch_ok = g_signature_verifier->Wait(session, err);

            total_batches.fetch_add(1);
            if (batch_ok != oracle_ok) {
                mismatches.fetch_add(1);
                if (batch_ok && !oracle_ok) bad_accepted.fetch_add(1);
                if (!batch_ok && oracle_ok) good_rejected.fetch_add(1);
            }
        }
    };

    std::printf("[LP-5 harness] running %d threads x %d iters (workers=4)...\n",
                kThreads, kItersPerThread);
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker, t);
    for (auto& th : threads) th.join();

    ShutdownSignatureVerifier();

    long mm = mismatches.load();
    long ba = bad_accepted.load();
    long gr = good_rejected.load();
    long tot = total_batches.load();

    std::printf("[LP-5 harness] batches=%ld  mismatches=%ld  bad-accepted=%ld  good-rejected=%ld\n",
                tot, mm, ba, gr);

    if (mm != 0) {
        std::printf("[LP-5 harness] RESULT: FAIL — batch verdict diverged from sequential oracle.\n");
        std::printf("                (bad-accepted=%ld is an invalid-signature acceptance; good-rejected=%ld is cross-batch contamination.)\n",
                    ba, gr);
        return 1;
    }
    std::printf("[LP-5 harness] RESULT: PASS — every batch matched the sequential oracle under concurrent load.\n");
    return 0;
}
