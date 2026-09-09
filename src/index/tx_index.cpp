// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <index/tx_index.h>

#include <consensus/chain.h>
#include <consensus/validation.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <primitives/transaction.h>

#include <leveldb/db.h>
#include <leveldb/iterator.h>
#include <leveldb/options.h>
#include <leveldb/slice.h>
#include <leveldb/status.h>
#include <leveldb/write_batch.h>

#include <cstring>
#include <iostream>
#include <thread>

extern CChainState g_chainstate;

std::unique_ptr<CTxIndex> g_tx_index;

const std::string CTxIndex::META_KEY = std::string("\x00meta", 5);

// Test-observability hooks. Live in a dedicated namespace so production
// code never reads them. Cost in production: a few bytes of static
// storage and one relaxed atomic touch per gated event. All hooks are
// inert (no behavior change) unless tests explicitly set the gating
// atomic.
//
// - g_wipe_write_count (U3): counts the number of m_db->Write() calls
//   issued by WipeIndex AFTER the leveldb status is OK (PR-7G A4). The
//   counter proves the wipe is implemented as a SINGLE WriteBatch and
//   measures committed writes, not attempts.
//
// - g_walk_iteration_count (PR-7G E.2): incremented each time
//   WalkBlockRange enters a new height inside its inner loop. Tests can
//   poll this counter to inject blocks mid-walk deterministically.
//
// - g_force_eraseblock_failure (PR-7G E.4): when set true by a test,
//   makes EraseBlock skip the leveldb write and return false (as if the
//   underlying leveldb write had failed). Drives the m_corrupted-on-
//   failure path without filesystem fragility on Windows MSYS2.
namespace tx_index_test_hooks {
std::atomic<uint64_t> g_wipe_write_count{0};
std::atomic<uint64_t> g_walk_iteration_count{0};
std::atomic<bool>     g_force_eraseblock_failure{false};
}

CTxIndex::CTxIndex() = default;

CTxIndex::~CTxIndex() {
    Stop();
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        std::cout << "[txindex] shutting down" << std::endl;
    }
    m_db.reset();
}

std::string CTxIndex::MakeTxKey(const uint256& txid) {
    std::string key;
    key.reserve(TX_KEY_SIZE);
    key.push_back('t');
    key.append(reinterpret_cast<const char*>(txid.data), 32);
    return key;
}

bool CTxIndex::WriteMeta(leveldb::WriteBatch& batch, int height, const uint256& hash) {
    char value[META_VALUE_SIZE];
    value[0] = static_cast<char>(SCHEMA_VERSION);
    int32_t h_le = static_cast<int32_t>(height);
    std::memcpy(&value[1], &h_le, 4);
    std::memcpy(&value[5], hash.data, 8);
    batch.Put(leveldb::Slice(META_KEY.data(), META_KEY.size()),
              leveldb::Slice(value, META_VALUE_SIZE));
    return true;
}

// U2 (Cursor 2nd-pass): calling Init twice on the same instance returns true
// AND is a no-op. No leveldb re-open, no meta re-read, no state mutation, no
// thread spawn. The early-return on m_db != nullptr below pins this contract;
// any future change to Init must preserve it (PR-3 callback wiring depends on
// idempotent Init across paths).
//
// R1 (Cursor 2nd-pass): the C7 startup integrity check calls into
// g_chainstate (which acquires cs_main internally). m_mutex is NEVER held
// across those calls. Init is single-threaded by contract — it runs once
// during node startup before any worker or callback can enter CTxIndex —
// so we use a unique_lock and explicitly drop it before the chainstate
// query and the wipe, then re-take it only to set state. This honors the
// lock-order invariant explicitly rather than relying on the startup
// single-thread property.
bool CTxIndex::Init(const std::string& datadir, CBlockchainDB* chain_db) {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_db) {
        // Already initialized — U2 no-op path.
        return true;
    }

    m_chain_db = chain_db;

    leveldb::Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 4 * 1024 * 1024;
    options.max_open_files = 100;

    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, datadir, &db);
    if (!status.ok()) {
        // U4 (Cursor 2nd-pass): stale-LOCK path — when leveldb fails to open
        // because another process holds the LOCK file, surface the exact path
        // and remediation step. No retry, no crash, no infinite loop.
        //
        // PR-7G A2: prefer the typed predicate IsIOError() — leveldb returns
        // an IOError status whenever it cannot acquire the LOCK file (see
        // depends/leveldb/util/env_*.cc PosixEnv::LockFile / WindowsEnv).
        // Substring fallback is retained for portability across leveldb
        // versions whose error text we cannot inspect at compile time, but
        // the typed predicate is the primary signal.
        const std::string status_str = status.ToString();
        const bool likely_lock =
            status.IsIOError() ||
            status_str.find("lock") != std::string::npos ||
            status_str.find("LOCK") != std::string::npos ||
            status_str.find("Resource temporarily unavailable") != std::string::npos;
        if (likely_lock) {
            std::cerr << "[txindex] failed to open index database "
                      << "(likely stale LOCK file from previous unclean shutdown -- "
                      << "remove " << datadir << "/LOCK and retry): "
                      << status_str << std::endl;
        } else {
            std::cerr << "[txindex] Failed to open index database at " << datadir
                      << ": " << status_str << std::endl;
        }
        return false;
    }
    m_db.reset(db);

    std::string meta_value;
    leveldb::Status meta_status = m_db->Get(
        leveldb::ReadOptions(),
        leveldb::Slice(META_KEY.data(), META_KEY.size()),
        &meta_value);

    if (meta_status.IsNotFound()) {
        m_last_height.store(-1);
        m_synced.store(false);
        return true;
    }

    if (!meta_status.ok()) {
        std::cerr << "[txindex] Failed to read meta record: " << meta_status.ToString() << std::endl;
        m_db.reset();
        return false;
    }

    if (meta_value.size() != META_VALUE_SIZE) {
        std::cerr << "[txindex] Meta record has wrong size: " << meta_value.size()
                  << " (expected " << META_VALUE_SIZE << ")" << std::endl;
        m_db.reset();
        return false;
    }

    if (static_cast<uint8_t>(meta_value[0]) != SCHEMA_VERSION) {
        std::cerr << "[txindex] Meta record has unknown schema version: "
                  << static_cast<int>(static_cast<uint8_t>(meta_value[0])) << std::endl;
        m_db.reset();
        return false;
    }

    int32_t height = 0;
    std::memcpy(&height, &meta_value[1], 4);

    // PR-7G R5: bound-check the meta height. The on-disk value is a signed
    // 32-bit int; the only legitimate values are -1 (cold) or [0, tip].
    // Anything outside [-1, kMaxReasonableHeight] is provable corruption
    // (e.g. a forged INT_MAX would overflow `current = height + 1` in
    // SyncLoop, wrapping to INT_MIN and producing a near-2^31-iteration
    // hang). Wipe and treat as cold-start. The 100M cap is well above any
    // plausible chain depth in this lifetime.
    constexpr int32_t kMaxReasonableHeight = 100'000'000;
    if (height < -1 || height > kMaxReasonableHeight) {
        std::cerr << "[txindex] meta height " << height
                  << " is out of bounds [-1, " << kMaxReasonableHeight
                  << "] -- treating as corrupt and wiping" << std::endl;
        lock.unlock();
        const bool wiped = WipeIndex();
        lock.lock();
        if (!wiped) {
            std::cerr << "[txindex] integrity wipe failed; closing index" << std::endl;
            m_db.reset();
            return false;
        }
        m_last_height.store(-1);
        m_synced.store(false);
        return true;
    }

    m_last_height.store(height);
    m_synced.store(false);

    // C7 (plan §5): startup integrity check. If meta says we have indexed
    // up to `height` AND the live chainstate has a block at that height,
    // the truncated 8-byte hash recorded in meta must match the truncated
    // hash of that block. On contradiction, atomically wipe via a single
    // WriteBatch and reset to -1.
    //
    // If chainstate has NO block at the recorded height (e.g., chainstate
    // not yet populated, or running in a unit test that doesn't seed
    // mapBlockIndex), leave the index alone — we cannot prove a mismatch
    // without ground truth, and an unwarranted wipe would lose work.
    if (height >= 0) {
        char meta_trunc[8];
        std::memcpy(meta_trunc, &meta_value[5], 8);

        // Release m_mutex before chainstate query (R1 invariant).
        lock.unlock();

        uint256 expected_hash;
        bool have_block_at_height = false;
        std::vector<uint256> hashes_at_h = g_chainstate.GetBlocksAtHeight(height);
        for (const uint256& h : hashes_at_h) {
            CBlockIndex* pi = g_chainstate.GetBlockIndex(h);
            if (pi != nullptr && pi->IsOnMainChain()) {
                expected_hash = pi->GetBlockHash();
                have_block_at_height = true;
                break;
            }
        }
        // No main-chain block but at least one block index entry at the
        // height: use the first one. Avoids spurious wipe when pnext wiring
        // hasn't completed at very early startup.
        if (!have_block_at_height && !hashes_at_h.empty()) {
            CBlockIndex* pi = g_chainstate.GetBlockIndex(hashes_at_h.front());
            if (pi != nullptr) {
                expected_hash = pi->GetBlockHash();
                have_block_at_height = true;
            }
        }

        bool need_wipe = false;
        if (have_block_at_height) {
            char chain_trunc[8];
            std::memcpy(chain_trunc, expected_hash.data, 8);
            if (std::memcmp(meta_trunc, chain_trunc, 8) != 0) {
                need_wipe = true;
            }
        }
        // If !have_block_at_height: chainstate not yet populated for this
        // height; leave the index untouched. The reindex thread will not
        // walk past m_last_height for blocks the index already covers.

        if (need_wipe) {
            // SEC-MD-3: re-verify state before destructive wipe. The lock
            // was released for the chainstate query (R1); during that
            // window a concurrent WriteBlock (e.g. from a prematurely-
            // registered callback) could have advanced m_last_height. If
            // it did, the staleness assumption underlying need_wipe no
            // longer holds — abort the wipe rather than discard new work.
            // Today's PR-3 wiring registers callbacks AFTER Init returns,
            // so this race is not exploitable, but the class header does
            // not enforce that ordering — defense in depth.
            lock.lock();
            if (m_last_height.load() != height) {
                std::cerr << "[txindex] integrity wipe skipped: state advanced "
                          << "during init (recorded=" << height
                          << ", now=" << m_last_height.load()
                          << ") -- leaving index intact" << std::endl;
            } else {
                lock.unlock();   // wipe doesn't need m_mutex (leveldb own mutex)
                std::cerr << "[txindex] startup integrity check failed at height "
                          << height << " -- wiping index and resetting to -1" << std::endl;
                const bool wiped = WipeIndex();
                lock.lock();
                if (!wiped) {
                    std::cerr << "[txindex] integrity wipe failed; closing index" << std::endl;
                    m_db.reset();
                    return false;
                }
                if (m_last_height.load() == height) {
                    m_last_height.store(-1);
                    m_synced.store(false);
                }
                // else: race lost during wipe; leave m_last_height as the
                // concurrent-writer's value. The reindex thread will re-walk
                // anything that the wipe erased — self-healing.
            }
        } else {
            lock.lock();
        }
    }

    return true;
}

bool CTxIndex::WipeIndex() {
    // No lock acquired here — Init calls WipeIndex without holding m_mutex
    // (see C7 path). Init runs single-threaded during startup; no callback
    // or reindex thread can enter CTxIndex before Init returns.
    if (!m_db) {
        return false;
    }

    leveldb::WriteBatch batch;

    {
        std::unique_ptr<leveldb::Iterator> it(
            m_db->NewIterator(leveldb::ReadOptions()));
        for (it->Seek("t"); it->Valid(); it->Next()) {
            leveldb::Slice k = it->key();
            if (k.size() == 0 || k.data()[0] != 't') break;
            batch.Delete(k);
        }
    }

    batch.Delete(leveldb::Slice(META_KEY.data(), META_KEY.size()));

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[txindex] WipeIndex write failed: "
                  << status.ToString() << std::endl;
        return false;
    }
    // PR-7G A4: counter measures committed writes only (post-status.ok()),
    // not attempts. Failed writes shouldn't bump the counter; otherwise
    // U3's "exactly 1 db->Write call" assertion is inflated by failures.
    tx_index_test_hooks::g_wipe_write_count.fetch_add(1, std::memory_order_relaxed);
    // PR-7G R2 (CONCERN-B2): the only legitimate runtime reset for the
    // sticky m_corrupted flag is a successful wipe (C7 / --reindex). The
    // index has just been reduced to a clean cold-start state on disk;
    // any prior staleness has been erased.
    m_corrupted.store(false);
    return true;
}

bool CTxIndex::WriteBlock(const CBlock& block, int height, const uint256& block_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    if (height <= m_last_height.load()) {
        // Already indexed (or earlier height); monotonicity no-op (C1).
        return true;
    }

    std::vector<CTransactionRef> txs;
    std::string err;
    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, txs, err)) {
        std::cerr << "[txindex] Failed to deserialize block transactions at height "
                  << height << ": " << err << std::endl;
        return false;
    }

    leveldb::WriteBatch batch;

    char value[TX_VALUE_SIZE];
    std::memset(value, 0, TX_VALUE_SIZE);
    value[0] = static_cast<char>(SCHEMA_VERSION);
    std::memcpy(&value[1], block_hash.data, 32);

    for (size_t i = 0; i < txs.size(); ++i) {
        uint32_t pos_le = static_cast<uint32_t>(i);
        std::memcpy(&value[33], &pos_le, 4);
        std::string key = MakeTxKey(txs[i]->GetHash());
        batch.Put(leveldb::Slice(key.data(), key.size()),
                  leveldb::Slice(value, TX_VALUE_SIZE));
    }

    if (!WriteMeta(batch, height, block_hash)) {
        return false;
    }

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[txindex] WriteBlock failed at height " << height
                  << ": " << status.ToString() << std::endl;
        return false;
    }

    m_last_height.store(height);
    return true;
}

bool CTxIndex::EraseBlock(const CBlock& block, int height, const uint256& block_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    // C1 (PR-3 fold-in): a stray double-disconnect or out-of-order erase
    // becomes a no-op rather than walking m_last_height backwards. Returns
    // true to keep callers idempotent — no leveldb write is issued.
    if (height != m_last_height.load()) {
        return true;
    }

    std::vector<CTransactionRef> txs;
    std::string err;
    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, txs, err)) {
        std::cerr << "[txindex] Failed to deserialize block transactions during EraseBlock at height "
                  << height << ": " << err << std::endl;
        return false;
    }

    leveldb::WriteBatch batch;
    for (const auto& tx : txs) {
        std::string key = MakeTxKey(tx->GetHash());
        batch.Delete(leveldb::Slice(key.data(), key.size()));
    }

    int new_height = (height > 0) ? (height - 1) : -1;
    uint256 prev_hash;
    if (height > 0) {
        prev_hash = block.hashPrevBlock;
    }
    if (!WriteMeta(batch, new_height, prev_hash)) {
        return false;
    }

    // PR-7G R2: optimistic m_last_height decrement BEFORE issuing the
    // leveldb write. Without this, a write failure leaves m_last_height==H
    // while the (intended) on-disk state is height H-1; a subsequent
    // connect-replacement at height H would hit the C1 monotonicity guard
    // (`height <= m_last_height` is `H <= H` = true) and silently no-op,
    // so the replacement block's tx records would never be written.
    // Decrementing first allows the replacement WriteBlock to succeed
    // (its height becomes > new_height); we then set the sticky m_corrupted
    // flag to give RPC operators a signal that the on-disk index may
    // contain stale records for the failed-erase block.
    m_last_height.store(new_height);

    // PR-7G E.4 test-hook seam: when set, simulate a leveldb write failure
    // without touching the filesystem. Production cost is one relaxed
    // atomic load on the EraseBlock path, fired only on real disconnects.
    const bool force_fail =
        tx_index_test_hooks::g_force_eraseblock_failure.load(std::memory_order_relaxed);

    leveldb::Status status =
        force_fail ? leveldb::Status::IOError("forced EraseBlock failure (test)")
                   : m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[txindex] EraseBlock failed at height " << height
                  << ": " << status.ToString() << std::endl;
        // PR-7G R2: sticky flag — the on-disk records for `height` may be
        // stale (the optimistic m_last_height already decremented but the
        // delete-batch never landed). Operators see corruption via RPC
        // mismatch counters and the IsCorrupted() getter; recovery is
        // --reindex (which calls WipeIndex and clears the flag).
        m_corrupted.store(true);
        return false;
    }
    (void)block_hash;
    return true;
}

bool CTxIndex::FindTx(const uint256& txid, uint256& block_hash, uint32_t& tx_pos) const {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) {
        return false;
    }

    std::string key = MakeTxKey(txid);
    std::string value;
    leveldb::Status status = m_db->Get(leveldb::ReadOptions(),
                                       leveldb::Slice(key.data(), key.size()),
                                       &value);
    if (!status.ok()) {
        return false;
    }

    if (value.size() != TX_VALUE_SIZE) {
        return false;
    }

    if (static_cast<uint8_t>(value[0]) != SCHEMA_VERSION) {
        return false;
    }

    std::memcpy(block_hash.data, &value[1], 32);
    uint32_t pos_le = 0;
    std::memcpy(&pos_le, &value[33], 4);
    tx_pos = pos_le;

    return true;
}

int CTxIndex::LastIndexedHeight() const {
    return m_last_height.load();
}

bool CTxIndex::IsBuiltUpToHeight(int h) const {
    return m_last_height.load() >= h;
}

bool CTxIndex::IsSynced() const {
    return m_synced.load();
}

bool CTxIndex::IsCorrupted() const {
    return m_corrupted.load();
}

void CTxIndex::StartBackgroundSync() {
    // R2 (Cursor 2nd-pass): preconditions checked BEFORE thread spawn.
    // m_chain_db / m_db / g_chainstate.GetTip() must all be non-null.
    // If any are missing, log to stderr and return without spawning.
    //
    // GetTip() acquires cs_main internally (R1). We do NOT hold m_mutex
    // here — read it through the public API only.
    //
    // SEC-MD-1: m_starting gates the spawn-vs-stop race. SEC-MD-2: clear
    // m_interrupt under the same lock so a Start-after-Stop sequence
    // produces a thread that actually runs (idempotency claim on Stop()
    // does not imply permanent termination of the class).
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_db || !m_chain_db) {
            std::cerr << "[txindex] StartBackgroundSync called before chainstate "
                      << "initialized; reindex skipped" << std::endl;
            return;
        }
        if (m_starting.load() || m_sync_thread.joinable()) {
            // Either another caller is mid-spawn, or a thread is already running.
            return;
        }
        m_starting.store(true);
        m_interrupt.store(false);   // SEC-MD-2: re-spawn must clear stale latch
        m_synced.store(false);      // SEC-MD-2 follow-on: leftover-true from a prior
                                    // sync cycle would make WaitForSync return
                                    // immediately on re-spawn (test vacuity) AND
                                    // mislead RPC fast-path readers that check
                                    // IsSynced. Mirror Bitcoin Core BaseIndex.

    }

    CBlockIndex* tip = g_chainstate.GetTip();
    if (tip == nullptr) {
        m_starting.store(false);    // release the gate before bailing
        std::cerr << "[txindex] StartBackgroundSync called before chainstate "
                  << "initialized; reindex skipped" << std::endl;
        return;
    }
    const int snapshotted_tip = tip->nHeight;

    // R2 pin: snapshot tip ONCE at thread entry; thread walks
    // [m_last_height+1, snapshotted_tip].
    m_sync_thread = std::thread(&CTxIndex::SyncLoop, this, snapshotted_tip);
    m_starting.store(false);        // thread is now joinable; gate released
}

// R3 (Cursor 2nd-pass) — load-bearing comment, NOT decoration:
// Chain reads (`g_chainstate.GetTip()`, `g_chainstate.GetBlockIndex(hash)`)
// acquire `cs_main` internally. `m_mutex` MUST NOT be held across these
// calls. The callback path only enters CTxIndex through `WriteBlock` /
// `EraseBlock`, which acquire `m_mutex` themselves; the reindex thread
// acquires `m_mutex` only via the same `WriteBlock` call site.
//
// PR-7G R1 (Bitcoin Core BaseIndex pattern):
//   SyncLoop wraps an outer loop around WalkBlockRange. After each inner
//   walk completes, it re-reads `g_chainstate.GetTip()->nHeight` and, if
//   the tip advanced during the walk, walks the newly-visible range.
//   m_synced is set to true ONLY when the tip is stable across a full
//   walk pass. Live callbacks short-circuit at the lambda site while
//   `!IsSynced()` (see dilithion-node.cpp / dilv-node.cpp), so the
//   reindex thread is the SOLE writer to the index until catchup
//   completes — closing the FA-HI-1 leapfrog vector by separating
//   reindex and live writers temporally rather than relying on the C1
//   monotonicity guard alone.
bool CTxIndex::WalkBlockRange(int start, int end) {
    int current = start;
    while (current <= end) {
        if (m_interrupt.load()) {
            return false;
        }

        // PR-7G E.2 test-hook seam: tests can poll this counter to inject
        // blocks mid-walk deterministically. Production cost: one relaxed
        // atomic increment per height, on the rare reindex path only.
        tx_index_test_hooks::g_walk_iteration_count.fetch_add(
            1, std::memory_order_relaxed);

        // Resolve current height -> block hash via g_chainstate. We do NOT
        // hold m_mutex across this call (R1).
        std::vector<uint256> hashes = g_chainstate.GetBlocksAtHeight(current);
        if (hashes.empty()) {
            std::cerr << "[txindex] reindex: no block index entry at height "
                      << current << "; aborting reindex" << std::endl;
            return false;
        }

        // Prefer the on-main-chain block at this height. PR-7G R6: when
        // MULTIPLE blocks exist at this height and NONE is on main chain
        // (e.g. mid-reorg where DisconnectTip cleared pnext on the old
        // block but the new ConnectTip hasn't fired yet), do NOT fall
        // back to hashes.front(). hashes.front() is non-deterministic
        // (mapBlockIndex ordering) and can land on a stale side-chain
        // block whose tx records would then persist forever (FA-MD-5).
        // Skip the height with a log line and rely on the outer-loop
        // tip-rebase to revisit it once the reorg settles.
        //
        // The hashes.size()==1 single-block case still falls through to
        // hashes.front() — this is the normal "current tip" case where
        // pnext is null for the genuine tip block. There is no ambiguity
        // when there's only one candidate.
        uint256 block_hash;
        bool found_main = false;
        for (const uint256& h : hashes) {
            CBlockIndex* pi = g_chainstate.GetBlockIndex(h);
            if (pi != nullptr && pi->IsOnMainChain()) {
                block_hash = h;
                found_main = true;
                break;
            }
        }
        if (!found_main) {
            if (hashes.size() > 1) {
                // PR-7G R6: stop the walk here. m_last_height is NOT
                // advanced past the contested height; the reindex is
                // not yet complete. SyncLoop's outer loop will return
                // without setting m_synced=true, so operators detect
                // via IsSynced()==false. After the reorg settles, a
                // subsequent StartBackgroundSync will re-walk from
                // m_last_height+1 and find a single main-chain block.
                std::cerr << "[txindex] reindex: no main-chain block at height "
                          << current << " (mid-reorg, " << hashes.size()
                          << " candidates) -- bailing walk; outer loop will "
                          << "revisit when the reorg settles" << std::endl;
                return false;
            }
            block_hash = hashes.front();
        }

        // m_chain_db is set by Init; reads are independent of m_mutex.
        CBlock block;
        if (!m_chain_db->ReadBlock(block_hash, block)) {
            std::cerr << "[txindex] reindex: failed to read block at height "
                      << current << "; skipping" << std::endl;
            ++current;
            continue;
        }

        // WriteBlock acquires m_mutex internally. The reindex thread does
        // NOT hold m_mutex across this call.
        //
        // PR-7G R4: a WriteBlock failure during reindex is unrecoverable
        // for THIS walk pass — the local meta is now inconsistent with
        // the writer's intent. Break and signal failure to the outer
        // loop; the outer loop will return without setting m_synced=true
        // so operators detect via `IsSynced()` polling that the index is
        // not fully built. (Under the new gating, C1 same-height no-op
        // is impossible during reindex because live callbacks are gated
        // off — so a `false` return here is always a real disk error.)
        if (!WriteBlock(block, current, block_hash)) {
            std::cerr << "[txindex] reindex: WriteBlock failed at height "
                      << current << "; aborting walk (m_synced stays false)"
                      << std::endl;
            return false;
        }

        if ((current % 1000) == 0) {
            std::cout << "[txindex] indexed " << current
                      << "/" << end << " blocks" << std::endl;
        }
        ++current;
    }

    return true;
}

void CTxIndex::SyncLoop(int initial_snapshotted_tip) {
    int current_target = initial_snapshotted_tip;

    while (!m_interrupt.load()) {
        // DEFERRED-RECLAMATION CHECKPOINT — loop top, before the walk. This
        // thread holds no CBlockIndex* between iterations: each resolve/deref in
        // WalkBlockRange spans two or three lines and nothing is retained across
        // an iteration (tx_index.cpp documents the same discipline for m_mutex).
        // Pin duration is therefore ONE WALK PASS, not the life of the sync.
        g_chainstate.EpochCheckpoint();

        // PR-7G R1: each iteration walks `[m_last_height+1, current_target]`,
        // then re-reads the live tip. If the tip advanced during the walk,
        // bump current_target and walk again. Only when the tip is stable
        // across a full walk pass do we set m_synced=true.
        const int walk_start = m_last_height.load() + 1;
        if (walk_start > current_target) {
            // Either we resumed already at-or-past the target (warm-stale
            // resume case), or the previous iteration completed up to
            // current_target. Fall through to the tip re-read below.
        } else {
            const bool walk_completed = WalkBlockRange(walk_start, current_target);
            if (m_interrupt.load() || !walk_completed) {
                // Bail without setting m_synced=true. Operators detect the
                // incomplete state via IsSynced()==false. R4 path.
                return;
            }
        }

        // Re-read the chain tip. If it advanced during the walk, continue;
        // otherwise we're synced.
        CBlockIndex* tip = g_chainstate.GetTip();
        if (tip == nullptr) {
            // Chainstate vanished mid-walk (shutdown in progress?) — bail
            // without setting m_synced.
            return;
        }
        const int tip_now = tip->nHeight;
        if (tip_now <= current_target) {
            std::cout << "[txindex] indexed " << current_target
                      << "/" << current_target << " blocks (sync complete)"
                      << std::endl;
            m_synced.store(true);
            return;
        }
        current_target = tip_now;
    }
}

void CTxIndex::Interrupt() {
    m_interrupt.store(true);
}

void CTxIndex::Stop() {
    m_interrupt.store(true);
    // SEC-MD-1: wait for any in-progress StartBackgroundSync to finish
    // assigning m_sync_thread before checking joinable(). Without this,
    // a Stop racing a Start could observe joinable()==false during the
    // brief window between m_mutex release and m_sync_thread assignment,
    // skip the join, and leak an unjoined thread.
    while (m_starting.load()) {
        std::this_thread::yield();
    }
    if (m_sync_thread.joinable()) {
        m_sync_thread.join();
    }
}

void CTxIndex::IncrementMismatches() {
    m_mismatches_observed.fetch_add(1, std::memory_order_relaxed);
}

uint64_t CTxIndex::MismatchCount() const {
    return m_mismatches_observed.load(std::memory_order_relaxed);
}
