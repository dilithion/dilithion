// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <index/coinstatsindex.h>

#include <consensus/chain.h>
#include <consensus/validation.h>
#include <node/block_index.h>
#include <node/blockchain_storage.h>
#include <node/undo_data.h>
#include <node/utxo_set.h>
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

std::unique_ptr<CCoinStatsIndex> g_coin_stats_index;

const std::string CCoinStatsIndex::META_KEY = std::string("\x00meta", 5);

// Test-observability hooks. Mirrors `tx_index_test_hooks`. Off by default;
// production code never reads them. See tx_index.cpp for hook conventions.
namespace coin_stats_index_test_hooks {
std::atomic<uint64_t> g_wipe_write_count{0};
std::atomic<uint64_t> g_walk_iteration_count{0};
std::atomic<bool>     g_force_eraseblock_failure{false};
}

CCoinStatsIndex::CCoinStatsIndex() = default;

CCoinStatsIndex::~CCoinStatsIndex() {
    Stop();
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        std::cout << "[coinstatsindex] shutting down" << std::endl;
    }
    m_db.reset();
}

std::string CCoinStatsIndex::MakeHeightKey(int height) {
    // Big-endian height so leveldb's lex order matches numeric order.
    std::string key;
    key.reserve(H_KEY_SIZE);
    key.push_back('h');
    const uint32_t h_be = static_cast<uint32_t>(height);
    key.push_back(static_cast<char>((h_be >> 24) & 0xFF));
    key.push_back(static_cast<char>((h_be >> 16) & 0xFF));
    key.push_back(static_cast<char>((h_be >>  8) & 0xFF));
    key.push_back(static_cast<char>( h_be        & 0xFF));
    return key;
}

void CCoinStatsIndex::EncodeHeightValue(const CoinStats& s, char out[H_VALUE_SIZE]) {
    std::memset(out, 0, H_VALUE_SIZE);
    out[0] = static_cast<char>(SCHEMA_VERSION);
    std::memcpy(&out[1], s.hashChainCommitment.data, 32);

    auto put_u64 = [out](size_t offset, uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out[offset + i] = static_cast<char>((v >> (i * 8)) & 0xFF);
        }
    };

    put_u64(33, s.coinsCount);
    put_u64(41, s.totalAmount);
    put_u64(49, s.blockAdditions);
    put_u64(57, s.blockRemovals);
    put_u64(65, s.blockTotalOut);
    put_u64(73, s.blockTotalIn);
    put_u64(81, s.blockSubsidyFees);
}

bool CCoinStatsIndex::DecodeHeightValue(const std::string& v, CoinStats& s) {
    if (v.size() != H_VALUE_SIZE) return false;
    if (static_cast<uint8_t>(v[0]) != SCHEMA_VERSION) return false;

    std::memcpy(s.hashChainCommitment.data, v.data() + 1, 32);

    auto get_u64 = [&v](size_t offset) -> uint64_t {
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i) {
            r |= (static_cast<uint64_t>(static_cast<uint8_t>(v[offset + i])) << (i * 8));
        }
        return r;
    };

    s.coinsCount       = get_u64(33);
    s.totalAmount      = get_u64(41);
    s.blockAdditions   = get_u64(49);
    s.blockRemovals    = get_u64(57);
    s.blockTotalOut    = get_u64(65);
    s.blockTotalIn     = get_u64(73);
    s.blockSubsidyFees = get_u64(81);
    return true;
}

bool CCoinStatsIndex::WriteMeta(leveldb::WriteBatch& batch, int height, const uint256& hash) {
    char value[META_VALUE_SIZE];
    std::memset(value, 0, META_VALUE_SIZE);
    value[0] = static_cast<char>(SCHEMA_VERSION);
    int32_t h_le = static_cast<int32_t>(height);
    std::memcpy(&value[1], &h_le, 4);
    std::memcpy(&value[5], hash.data, 8);
    batch.Put(leveldb::Slice(META_KEY.data(), META_KEY.size()),
              leveldb::Slice(value, META_VALUE_SIZE));
    return true;
}

bool CCoinStatsIndex::WriteHeightRecord(leveldb::WriteBatch& batch,
                                        int height,
                                        const CoinStats& s) {
    std::string key = MakeHeightKey(height);
    char value[H_VALUE_SIZE];
    EncodeHeightValue(s, value);
    batch.Put(leveldb::Slice(key.data(), key.size()),
              leveldb::Slice(value, H_VALUE_SIZE));
    return true;
}

bool CCoinStatsIndex::Init(const std::string& datadir,
                           CBlockchainDB* chain_db,
                           const CUTXOSet* utxo_set) {
    std::unique_lock<std::mutex> lock(m_mutex);

    if (m_db) {
        // Idempotent: already initialised. Mirrors txindex U2 contract.
        return true;
    }

    m_chain_db = chain_db;
    m_utxo_set = utxo_set;

    leveldb::Options options;
    options.create_if_missing = true;
    options.write_buffer_size = 4 * 1024 * 1024;
    options.max_open_files    = 100;

    leveldb::DB* db = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, datadir, &db);
    if (!status.ok()) {
        const std::string status_str = status.ToString();
        const bool likely_lock =
            status.IsIOError() ||
            status_str.find("lock") != std::string::npos ||
            status_str.find("LOCK") != std::string::npos ||
            status_str.find("Resource temporarily unavailable") != std::string::npos;
        if (likely_lock) {
            std::cerr << "[coinstatsindex] failed to open index database "
                      << "(likely stale LOCK file from previous unclean shutdown -- "
                      << "remove " << datadir << "/LOCK and retry): "
                      << status_str << std::endl;
        } else {
            std::cerr << "[coinstatsindex] Failed to open index database at "
                      << datadir << ": " << status_str << std::endl;
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
        m_running = CoinStats{};
        return true;
    }

    if (!meta_status.ok()) {
        std::cerr << "[coinstatsindex] Failed to read meta record: "
                  << meta_status.ToString() << std::endl;
        m_db.reset();
        return false;
    }

    if (meta_value.size() != META_VALUE_SIZE) {
        std::cerr << "[coinstatsindex] Meta record has wrong size: "
                  << meta_value.size() << " (expected " << META_VALUE_SIZE
                  << ")" << std::endl;
        m_db.reset();
        return false;
    }

    if (static_cast<uint8_t>(meta_value[0]) != SCHEMA_VERSION) {
        std::cerr << "[coinstatsindex] Meta record has unknown schema version: "
                  << static_cast<int>(static_cast<uint8_t>(meta_value[0]))
                  << std::endl;
        m_db.reset();
        return false;
    }

    int32_t height = 0;
    std::memcpy(&height, &meta_value[1], 4);

    // R5 bound check. Mirrors txindex.
    constexpr int32_t kMaxReasonableHeight = 100'000'000;
    if (height < -1 || height > kMaxReasonableHeight) {
        std::cerr << "[coinstatsindex] meta height " << height
                  << " is out of bounds [-1, " << kMaxReasonableHeight
                  << "] -- treating as corrupt and wiping" << std::endl;
        lock.unlock();
        const bool wiped = WipeIndex();
        lock.lock();
        if (!wiped) {
            std::cerr << "[coinstatsindex] integrity wipe failed; closing index"
                      << std::endl;
            m_db.reset();
            return false;
        }
        m_last_height.store(-1);
        m_synced.store(false);
        m_running = CoinStats{};
        return true;
    }

    m_last_height.store(height);
    m_synced.store(false);

    // Repopulate m_running from the on-disk last-indexed record so live
    // WriteBlock can fold incrementally without re-reading every time.
    //
    // M3 FIX: when the meta claims height=N but the record at N is missing
    // or undecodable, do a full WipeIndex (mirroring the C7 / R5 path)
    // rather than a soft in-memory reset. The soft reset left every record
    // at heights 0..N-1 on disk; a subsequent reindex would write 0..N-1
    // afresh but ANY records past the new tip would survive forever
    // (since WriteBlock's monotonicity guard short-circuits at last+1).
    // A full wipe guarantees no stale records past the new tip.
    if (height >= 0) {
        std::string key = MakeHeightKey(height);
        std::string value;
        leveldb::Status s2 = m_db->Get(leveldb::ReadOptions(),
                                       leveldb::Slice(key.data(), key.size()),
                                       &value);
        if (s2.ok()) {
            CoinStats restored;
            if (DecodeHeightValue(value, restored)) {
                m_running = restored;
            } else {
                std::cerr << "[coinstatsindex] last-indexed record at height "
                          << height << " did not decode; wiping index to "
                          << "guarantee no stale records past the new tip."
                          << std::endl;
                lock.unlock();
                const bool wiped = WipeIndex();
                lock.lock();
                if (!wiped) {
                    std::cerr << "[coinstatsindex] integrity wipe failed; "
                              << "closing index" << std::endl;
                    m_db.reset();
                    return false;
                }
                m_last_height.store(-1);
                m_synced.store(false);
                m_running = CoinStats{};
                return true;
            }
        } else if (s2.IsNotFound()) {
            std::cerr << "[coinstatsindex] meta says height " << height
                      << " but no record present; wiping index to "
                      << "guarantee no stale records past the new tip."
                      << std::endl;
            lock.unlock();
            const bool wiped = WipeIndex();
            lock.lock();
            if (!wiped) {
                std::cerr << "[coinstatsindex] integrity wipe failed; "
                          << "closing index" << std::endl;
                m_db.reset();
                return false;
            }
            m_last_height.store(-1);
            m_synced.store(false);
            m_running = CoinStats{};
            return true;
        } else {
            std::cerr << "[coinstatsindex] error reading last-indexed record: "
                      << s2.ToString() << std::endl;
            m_db.reset();
            return false;
        }
    } else {
        m_running = CoinStats{};
    }

    // C7 startup integrity check. Mirrors txindex.
    if (height >= 0) {
        char meta_trunc[8];
        std::memcpy(meta_trunc, &meta_value[5], 8);

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

        if (need_wipe) {
            lock.lock();
            if (m_last_height.load() != height) {
                std::cerr << "[coinstatsindex] integrity wipe skipped: state "
                          << "advanced during init (recorded=" << height
                          << ", now=" << m_last_height.load()
                          << ") -- leaving index intact" << std::endl;
            } else {
                lock.unlock();
                std::cerr << "[coinstatsindex] startup integrity check failed at "
                          << "height " << height
                          << " -- wiping index and resetting to -1" << std::endl;
                const bool wiped = WipeIndex();
                lock.lock();
                if (!wiped) {
                    std::cerr << "[coinstatsindex] integrity wipe failed; closing index"
                              << std::endl;
                    m_db.reset();
                    return false;
                }
                if (m_last_height.load() == height) {
                    m_last_height.store(-1);
                    m_synced.store(false);
                    m_running = CoinStats{};
                }
            }
        } else {
            lock.lock();
        }
    }

    return true;
}

bool CCoinStatsIndex::WipeIndex() {
    if (!m_db) return false;

    leveldb::WriteBatch batch;
    {
        std::unique_ptr<leveldb::Iterator> it(
            m_db->NewIterator(leveldb::ReadOptions()));
        for (it->Seek("h"); it->Valid(); it->Next()) {
            leveldb::Slice k = it->key();
            if (k.size() == 0 || k.data()[0] != 'h') break;
            batch.Delete(k);
        }
    }
    batch.Delete(leveldb::Slice(META_KEY.data(), META_KEY.size()));

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[coinstatsindex] WipeIndex write failed: "
                  << status.ToString() << std::endl;
        return false;
    }
    coin_stats_index_test_hooks::g_wipe_write_count.fetch_add(
        1, std::memory_order_relaxed);
    m_corrupted.store(false);
    return true;
}

bool CCoinStatsIndex::ComputeBlockStats(const CBlock& block,
                                        int height,
                                        const uint256& block_hash,
                                        CoinStats& parent_stats,
                                        CoinStats& after_stats) const {
    if (m_utxo_set == nullptr) {
        std::cerr << "[coinstatsindex] ComputeBlockStats: utxo_set not wired"
                  << std::endl;
        return false;
    }

    // Read the on-disk undo data for this block.
    CBlockUndo undo;
    // Genesis block (height 0) has no spent inputs and need not have an
    // undo record on disk; treat missing-undo at height 0 as "empty" and
    // proceed. Any other height with missing undo is a hard error.
    const bool got_undo = m_utxo_set->ReadUndoBlock(block_hash, undo);
    if (!got_undo && height != 0) {
        std::cerr << "[coinstatsindex] ComputeBlockStats: undo data missing "
                  << "for block at height " << height << " (hash "
                  << block_hash.GetHex().substr(0, 16) << "...)" << std::endl;
        return false;
    }

    // Deserialise the block transactions.
    std::vector<CTransactionRef> txs;
    std::string err;
    CBlockValidator validator;
    if (!validator.DeserializeBlockTransactions(block, txs, err)) {
        std::cerr << "[coinstatsindex] ComputeBlockStats: deserialize failed at "
                  << "height " << height << ": " << err << std::endl;
        return false;
    }

    // Apply.
    after_stats = parent_stats;
    if (!CoinStatsApplyBlock(after_stats, block, undo, txs,
                             static_cast<uint32_t>(height))) {
        std::cerr << "[coinstatsindex] ComputeBlockStats: ApplyBlock failed at "
                  << "height " << height << std::endl;
        return false;
    }
    return true;
}

bool CCoinStatsIndex::WriteBlock(const CBlock& block, int height, const uint256& block_hash) {
    // P2P-17: unique_lock, not lock_guard, because the main-chain pre-check below
    // calls into the chainstate (which takes cs_main) and m_mutex MUST NOT be held
    // across that call. See the comment at the unlock site.
    std::unique_lock<std::mutex> lock(m_mutex);

    if (!m_db) return false;

    // H1 fail-fast: a corrupted index refuses further writes. Without this
    // guard, an EraseBlock leveldb-write failure that left m_corrupted=true
    // would still admit subsequent WriteBlocks that fold onto a stale parent
    // and persist further-corrupt records. Operator must --reindex to
    // recover.
    if (m_corrupted.load()) {
        std::cerr << "[coinstatsindex] WriteBlock refused at height " << height
                  << ": index is in corrupted state -- restart with --reindex"
                  << std::endl;
        return false;
    }

    if (height <= m_last_height.load()) {
        // Already indexed; monotonicity no-op.
        return true;
    }

    // Block must immediately follow the last-indexed height. If it doesn't,
    // refuse the write -- the reindex thread is responsible for filling in
    // gaps. This is the cold-rebuild contract.
    if (height != m_last_height.load() + 1) {
        std::cerr << "[coinstatsindex] WriteBlock: non-contiguous height "
                  << height << " (last=" << m_last_height.load() << ")"
                  << std::endl;
        return false;
    }

    // H3 parent-mismatch detection: verify the block's claimed parent
    // matches the chainstate's main-chain block at height-1. The reindex
    // thread reads chainstate per-height without holding cs_main between
    // iterations; if a reorg fires mid-walk and the inner walk has already
    // advanced m_last_height past the divergence point, a subsequent
    // WriteBlock based on the now-orphaned parent would persist a corrupt
    // record. Detect by comparing the just-supplied block's hashPrevBlock
    // against the canonical main-chain hash at height-1.
    if (height > 0) {
        // P2P-17 FIX — a LATENT AB-BA. Severity corrected on review, and the
        // correction matters: this is not a live deadlock.
        //
        // This block calls into the chainstate, and both GetBlocksAtHeight
        // (chain.cpp) and GetBlockIndex take cs_main. Holding m_mutex across
        // them created the second half of a cycle:
        //
        //   edge 1  cs_main -> m_mutex :  ActivateBestChain holds cs_main at
        //           function scope, DisconnectTip fires the block-disconnect
        //           callbacks with it STILL held (cs_main is recursive, so an
        //           inner scope ending does not release it), and the registered
        //           callback calls EraseBlock, which takes m_mutex.
        //   edge 2  m_mutex -> cs_main :  m_sync_thread -> SyncLoop ->
        //           WalkBlockRange -> WriteBlock, holding m_mutex here, and
        //           WalkBlockRange holds no cs_main at all.
        //
        // Two threads, opposite orders — but NOT concurrently reachable today.
        // Edge 1 exists only through the node-registered callbacks
        // (dilithion-node.cpp:3480/:3489, dilv-node.cpp:3302/:3311) and EVERY one
        // is gated on IsSynced(); edge 2 runs only from SyncLoop, which finishes
        // before IsSynced() opens. The two edges are TEMPORALLY EXCLUSIVE, by the
        // same gate relied on below. I originally filed this as live: I used the
        // gate to argue the unlock window was safe and then failed to apply it to
        // reachability, which is the asymmetry to avoid — a gate that protects
        // you also constrains your finding.
        //
        // It is still worth fixing, and for a reason that outlasts the gate: the
        // exclusion is an EMERGENT property of two IsSynced() checks in a
        // different file. Add a third caller, widen the gate, or make the live
        // path fire during catch-up, and the cycle is real with nothing to catch
        // it. Releasing m_mutex across the query makes the inversion
        // STRUCTURALLY IMPOSSIBLE rather than gate-dependent.
        //
        // THE DISCIPLINE ALREADY EXISTED ONE FUNCTION AWAY: Init() in this file
        // uses unique_lock and unlock()s before every chainstate call, and
        // tx_index.cpp:520 spells out the same rule ("GetTip() acquires cs_main
        // internally (R1). We do NOT hold m_mutex"). WriteBlock is the sibling
        // that missed it — which is why the fix is to match them, not invent.
        //
        // WHY THE UNLOCK WINDOW IS SAFE, and this is the part worth checking if
        // you change either caller: WriteBlock has exactly two callers and they
        // are MUTUALLY EXCLUSIVE. The live connect-callback path is gated on
        // IsSynced(), and m_synced is stored true exactly once, at SyncLoop's
        // final `return`. So the sync thread has exited before the callback can
        // ever call in. No second WriteBlock can observe the window and fold
        // onto a stale m_running. If a third caller is ever added, or the
        // IsSynced() gate is removed, re-examine this: m_running is read AFTER
        // the window.
        //
        // [!] THE TEARDOWN PREMISE - F10, external panel round 2. This window
        // also depends on something the whole-body lock_guard used to supply BY
        // CONSTRUCTION, and which was written down nowhere until now.
        //
        // ~CCoinStatsIndex calls Stop(), then takes m_mutex, then m_db.reset().
        // Stop() joins m_sync_thread ONLY and does not take m_mutex. So the
        // destructor can acquire this mutex WHILE a callback-thread WriteBlock is
        // sitting in one of these unlock windows, free m_db and destroy the
        // object - and the callback thread then calls lock.lock() on a mutex
        // inside a freed object. Under the old whole-body guard the destructor
        // simply blocked until WriteBlock returned. That protection is gone, and
        // this comment is where it has to be replaced.
        //
        // THE PREMISE: nothing may destroy this index while a block-connect
        // callback can still fire. The callbacks are never unregistered (the only
        // clear is in chain.cpp, outside the shutdown sequence), so quiescing the
        // callback SOURCE is the only thing that holds it.
        //
        // [measured, dilithion-node.cpp] the index is reset at four sites:
        //   :3552  before the callback is registered           - safe by order
        //   :9258  normal shutdown, AFTER g_node_context.Shutdown() (:9220),
        //          which stops the validation queue and connman - quiesced
        //   :9324  catch (std::exception)                       - NOT QUIESCED
        //   :9380  catch (...)                                  - NOT QUIESCED
        // Both catch blocks were read line by line: neither calls Shutdown(),
        // Stop(), connman or anything validation-related before the reset. So on
        // an exception path the premise DOES NOT HOLD today. That is a
        // shutdown-ordering gap which this change makes reachable; it is FILED,
        // not silently patched here, and that is why this note names the exact
        // sites instead of asserting "shutdown handles it".
        //
        // AND a post-retake `if (!m_db) return false;` must NOT stand in for this
        // argument: re-checking m_db after the retake closes only the null-deref
        // half. The freed-object half - locking a mutex that no longer exists -
        // happens BEFORE any such check could run.
        lock.unlock();
        const std::vector<uint256> prev_hashes =
            g_chainstate.GetBlocksAtHeight(height - 1);
        uint256 expected_prev;
        bool have_prev = false;
        for (const uint256& h : prev_hashes) {
            CBlockIndex* pi = g_chainstate.GetBlockIndex(h);
            if (pi != nullptr && pi->IsOnMainChain()) {
                expected_prev = pi->GetBlockHash();
                have_prev = true;
                break;
            }
        }
        if (have_prev && expected_prev != block.hashPrevBlock) {
            std::cerr << "[coinstatsindex] WriteBlock parent-mismatch at "
                      << "height " << height << ": expected prev="
                      << expected_prev.GetHex().substr(0, 16) << "..., "
                      << "got prev=" << block.hashPrevBlock.GetHex().substr(0, 16)
                      << "... (likely reorg during reindex) -- setting "
                      << "corrupt flag and refusing write" << std::endl;
            m_corrupted.store(true);
            return false;  // returning with m_mutex released is fine: m_corrupted
                           // is atomic and unique_lock's destructor is a no-op.
        }
        lock.lock();  // retake for the m_running / m_db work below
        // Re-validating after the re-take is unnecessary today and the reason is
        // the same gate: no EraseBlock and no callback-driven WriteBlock can run
        // while the sync thread is inside this window, because IsSynced() is
        // still false — so neither m_corrupted nor height contiguity can have
        // moved under us. If the gate ever changes, re-check BOTH here.
    }

    CoinStats parent = m_running;
    CoinStats after;
    if (!ComputeBlockStats(block, height, block_hash, parent, after)) {
        return false;
    }

    leveldb::WriteBatch batch;
    if (!WriteHeightRecord(batch, height, after)) return false;
    if (!WriteMeta(batch, height, block_hash))    return false;

    leveldb::Status status = m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[coinstatsindex] WriteBlock failed at height " << height
                  << ": " << status.ToString() << std::endl;
        return false;
    }

    m_running = after;
    m_last_height.store(height);
    return true;
}

bool CCoinStatsIndex::EraseBlock(const CBlock& block, int height, const uint256& block_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_db) return false;

    // H1 fail-fast: a corrupted index refuses further erases too. (The
    // sticky m_corrupted flag is set by an earlier failure; only WipeIndex
    // / restart can clear it.) We deliberately fail rather than no-op so
    // operators see the corruption signal.
    if (m_corrupted.load()) {
        std::cerr << "[coinstatsindex] EraseBlock refused at height " << height
                  << ": index is in corrupted state -- restart with --reindex"
                  << std::endl;
        return false;
    }

    // Stray double-disconnect or out-of-order: idempotent no-op (mirrors
    // txindex C1).
    if (height != m_last_height.load()) return true;

    leveldb::WriteBatch batch;

    // Delete the per-height record at H.
    {
        std::string key = MakeHeightKey(height);
        batch.Delete(leveldb::Slice(key.data(), key.size()));
    }

    // Restore the parent-height record's hashChainCommitment into m_running on
    // commit. Read it now so we have a consistent snapshot to roll back to.
    CoinStats restored;
    int new_height = (height > 0) ? (height - 1) : -1;
    uint256 prev_hash;
    if (height > 0) {
        prev_hash = block.hashPrevBlock;
        std::string prev_key = MakeHeightKey(new_height);
        std::string prev_val;
        leveldb::Status s = m_db->Get(leveldb::ReadOptions(),
                                      leveldb::Slice(prev_key.data(), prev_key.size()),
                                      &prev_val);
        if (!s.ok() || !DecodeHeightValue(prev_val, restored)) {
            std::cerr << "[coinstatsindex] EraseBlock: cannot read parent "
                      << "record at height " << new_height << "; setting corrupt"
                      << std::endl;
            m_corrupted.store(true);
            return false;
        }
    } else {
        // Erasing genesis: rolling back to the empty pre-chain state.
        restored = CoinStats{};
    }

    if (!WriteMeta(batch, new_height, prev_hash)) return false;

    // H1 FIX: write FIRST, then commit the in-memory rollback. The previous
    // implementation decremented m_last_height optimistically BEFORE writing,
    // and on write failure left m_running pointing at the after-failed-block
    // state -- so a subsequent WriteBlock at H folded onto a stale parent and
    // persisted a corrupt record. Now: snapshot pre-rollback state, attempt
    // write, commit rollback only on success; on failure leave both
    // m_last_height and m_running unchanged and set m_corrupted=true. The
    // IsCorrupted() guard at the top of WriteBlock / EraseBlock then
    // refuses further writes until WipeIndex / --reindex.
    const bool force_fail =
        coin_stats_index_test_hooks::g_force_eraseblock_failure.load(
            std::memory_order_relaxed);

    leveldb::Status status =
        force_fail ? leveldb::Status::IOError("forced EraseBlock failure (test)")
                   : m_db->Write(leveldb::WriteOptions(), &batch);
    if (!status.ok()) {
        std::cerr << "[coinstatsindex] EraseBlock failed at height " << height
                  << ": " << status.ToString() << " -- index now in corrupted "
                  << "state; restart with --reindex" << std::endl;
        m_corrupted.store(true);
        // Leave m_last_height and m_running unchanged.
        return false;
    }

    // Commit rollback only after the write succeeded.
    m_last_height.store(new_height);
    m_running = restored;
    (void)block_hash;
    return true;
}

bool CCoinStatsIndex::LookupStats(int height, CoinStats& out) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;
    if (height < 0) return false;

    std::string key = MakeHeightKey(height);
    std::string value;
    leveldb::Status status = m_db->Get(leveldb::ReadOptions(),
                                       leveldb::Slice(key.data(), key.size()),
                                       &value);
    if (!status.ok()) return false;
    return DecodeHeightValue(value, out);
}

int  CCoinStatsIndex::LastIndexedHeight() const { return m_last_height.load(); }
bool CCoinStatsIndex::IsBuiltUpToHeight(int h) const { return m_last_height.load() >= h; }
bool CCoinStatsIndex::IsSynced() const { return m_synced.load(); }
bool CCoinStatsIndex::IsCorrupted() const { return m_corrupted.load(); }

void CCoinStatsIndex::StartBackgroundSync() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_db || !m_chain_db || !m_utxo_set) {
            std::cerr << "[coinstatsindex] StartBackgroundSync called before "
                      << "chainstate / utxo_set initialised; reindex skipped"
                      << std::endl;
            return;
        }
        if (m_starting.load() || m_sync_thread.joinable()) return;
        m_starting.store(true);
        m_interrupt.store(false);
        m_synced.store(false);
    }

    CBlockIndex* tip = g_chainstate.GetTip();
    if (tip == nullptr) {
        m_starting.store(false);
        std::cerr << "[coinstatsindex] StartBackgroundSync called before "
                  << "chainstate initialised; reindex skipped" << std::endl;
        return;
    }
    const int snapshotted_tip = tip->nHeight;

    g_chainstate.DeclareEpochParticipant("coinstatsindex-sync");
    m_sync_thread = std::thread(&CCoinStatsIndex::SyncLoop, this, snapshotted_tip);
    m_starting.store(false);
}

bool CCoinStatsIndex::WalkBlockRange(int start, int end) {
    int current = start;
    while (current <= end) {
        if (m_interrupt.load()) return false;

        coin_stats_index_test_hooks::g_walk_iteration_count.fetch_add(
            1, std::memory_order_relaxed);

        std::vector<uint256> hashes = g_chainstate.GetBlocksAtHeight(current);
        if (hashes.empty()) {
            std::cerr << "[coinstatsindex] reindex: no block index entry at "
                      << "height " << current << "; aborting reindex" << std::endl;
            return false;
        }

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
                std::cerr << "[coinstatsindex] reindex: no main-chain block at "
                          << "height " << current << " (mid-reorg, "
                          << hashes.size() << " candidates) -- bailing walk; "
                          << "outer loop will revisit when the reorg settles"
                          << std::endl;
                return false;
            }
            block_hash = hashes.front();
        }

        CBlock block;
        if (!m_chain_db->ReadBlock(block_hash, block)) {
            std::cerr << "[coinstatsindex] reindex: failed to read block at "
                      << "height " << current << "; skipping" << std::endl;
            ++current;
            continue;
        }

        if (!WriteBlock(block, current, block_hash)) {
            std::cerr << "[coinstatsindex] reindex: WriteBlock failed at height "
                      << current << "; aborting walk (m_synced stays false)"
                      << std::endl;
            return false;
        }

        if ((current % 1000) == 0) {
            std::cout << "[coinstatsindex] indexed " << current
                      << "/" << end << " blocks" << std::endl;
        }
        ++current;
    }
    return true;
}

void CCoinStatsIndex::SyncLoop(int initial_snapshotted_tip) {
    int current_target = initial_snapshotted_tip;

    while (!m_interrupt.load()) {
        // DEFERRED-RECLAMATION CHECKPOINT — loop top, before the walk. This
        // thread holds no CBlockIndex* between iterations: each resolve/deref in
        // WalkBlockRange spans two or three lines and nothing is retained across
        // an iteration (tx_index.cpp documents the same discipline for m_mutex).
        // Pin duration is therefore ONE WALK PASS, not the life of the sync.
        g_chainstate.EpochCheckpoint("coinstatsindex-sync");

        const int walk_start = m_last_height.load() + 1;
        if (walk_start > current_target) {
            // Already at-or-past the target; fall through to tip re-read.
        } else {
            const bool walk_completed = WalkBlockRange(walk_start, current_target);
            if (m_interrupt.load() || !walk_completed) return;
        }

        CBlockIndex* tip = g_chainstate.GetTip();
        if (tip == nullptr) return;
        const int tip_now = tip->nHeight;
        if (tip_now <= current_target) {
            std::cout << "[coinstatsindex] indexed " << current_target
                      << "/" << current_target << " blocks (sync complete)"
                      << std::endl;
            m_synced.store(true);
            return;
        }
        current_target = tip_now;
    }
}

void CCoinStatsIndex::Interrupt() { m_interrupt.store(true); }

void CCoinStatsIndex::Stop() {
    m_interrupt.store(true);
    while (m_starting.load()) std::this_thread::yield();
    if (m_sync_thread.joinable()) m_sync_thread.join();
}

void CCoinStatsIndex::IncrementMismatches() {
    m_mismatches_observed.fetch_add(1, std::memory_order_relaxed);
}

uint64_t CCoinStatsIndex::MismatchCount() const {
    return m_mismatches_observed.load(std::memory_order_relaxed);
}
