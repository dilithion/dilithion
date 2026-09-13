// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_INDEX_COINSTATSINDEX_H
#define DILITHION_INDEX_COINSTATSINDEX_H

// PR-BA-2: UTXO-set statistics index.
//
// Bitcoin Core port: `src/index/coinstatsindex.{h,cpp}` (v28.0).
//
// Records per-block UTXO-set statistics in a leveldb instance separate from
// txindex's database. For each indexed height H, we persist:
//
//   - `hashChainCommitment`  SHA3-256 chain-path commitment after the block
//                            (NOT a UTXO-set state hash; see kernel/coinstats.h)
//   - `coinsCount`           number of UTXOs after the block
//   - `totalAmount`          sum of UTXO output values after the block
//   - `blockAdditions`     per-block count of new UTXOs
//   - `blockRemovals`      per-block count of spent UTXOs
//   - `blockTotalOut`      block output sum (new outputs)
//   - `blockTotalIn`       block input sum (spent prevouts)
//   - `blockSubsidyFees`   coinbase output total (subsidy + fees claimed)
//
// The index reuses the txindex BaseIndex pattern verbatim (PR-7G R1):
//
//   - Live `RegisterBlockConnect` callbacks GATED on `IsSynced()` until the
//     reindex thread catches up. While `IsSynced()==false`, callbacks
//     short-circuit at the lambda site. The reindex thread is the SOLE
//     writer to the index until catchup completes.
//
//   - `SyncLoop` wraps an outer loop around `WalkBlockRange`. After the
//     inner walk completes, it re-reads `g_chainstate.GetTip()->nHeight`;
//     if the tip advanced during the walk, walks the newly-visible range.
//     `m_synced` flips to `true` ONLY when the tip is stable across a
//     full pass.
//
//   - Sticky `m_corrupted` flag set on `EraseBlock` leveldb-write failure.
//     Never auto-cleared at runtime; reset only by `WipeIndex` (the C7 /
//     `--reindex` path) or process restart with a fresh `g_coin_stats_index`.
//
//   - C7 startup integrity check: if the on-disk meta records height H and
//     chainstate has a different block at H, wipe and reset to -1.
//
//   - R5 meta-height bound check: reject pathological INT_MAX values.
//
// --- Concurrency --------------------------------------------------------
//
// Same threading model as `CTxIndex`. Three call sites:
//
//   1. Connect callback (chain validator). Holds `cs_main`. Calls
//      `WriteBlock` only when `IsSynced()` is true.
//   2. Disconnect callback (chain validator). ALSO holds `cs_main` — see below.
//      Calls `EraseBlock` only when `IsSynced()` is true.
//
// ⛔ THIS HEADER PREVIOUSLY SAID THE DISCONNECT CALLBACK DOES **NOT** HOLD
// `cs_main`. That is false, and the codebase had already retracted it at the
// disconnect site in `chain.cpp` without correcting the pointers to it:
//
//     `cs_main` is a RECURSIVE mutex. `DisconnectTip` is called from
//     `ActivateBestChain`, which holds it at FUNCTION scope, and an inner scope
//     ending only decrements the recursion count. So BOTH callback families fire
//     with `cs_main` HELD. There is no contrast to draw.
//
// It is corrected here because it is not cosmetic: anyone modelling this path
// from the header concludes the disconnect side is lock-free and designs the
// wrong fix — on the very file whose lock order is being fixed. A correction that
// lands at the site and not at the places that point to the site has only moved
// the wrong answer somewhere quieter.
//   3. Reindex thread (`m_sync_thread`). Spawned by `StartBackgroundSync`.
//      Reads `g_chainstate` without holding `m_mutex`; acquires `m_mutex`
//      only inside `WriteBlock`.
//
// --- hashChainCommitment vs BC's hash_serialized ------------------------
//
// `hashChainCommitment` is a CHAIN-PATH commitment (SHA3-256 fold of
// parent || delta), NOT BC v28.0's `hash_serialized` (which is a canonical-
// traversal STATE hash). The two have different invariants: two chains
// reaching the same UTXO set via different orderings produce different
// chain-path commitments. Useful for reorg detection, NOT for cross-
// validation against from-scratch UTXO walks. See kernel/coinstats.h for
// the full caveat list and PR-BA-3-design TODO.

#include <kernel/coinstats.h>
#include <primitives/block.h>
#include <uint256.h>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

class CBlockchainDB;
class CUTXOSet;

class CCoinStatsIndex {
public:
    CCoinStatsIndex();
    ~CCoinStatsIndex();

    CCoinStatsIndex(const CCoinStatsIndex&) = delete;
    CCoinStatsIndex& operator=(const CCoinStatsIndex&) = delete;

    /**
     * Open / re-open the leveldb at `datadir`, validate the schema/meta,
     * and run the C7 startup integrity check against the live chainstate.
     *
     * `chain_db` provides `ReadBlock(hash)` for the reindex thread.
     * `utxo_set` provides `ReadUndoBlock(hash)` for delta computation.
     *
     * @return true on success; false on unrecoverable open / parse error.
     *         A failed Init leaves the instance with `m_db == nullptr`.
     */
    bool Init(const std::string& datadir,
              CBlockchainDB* chain_db,
              const CUTXOSet* utxo_set);

    /**
     * Apply a block to the index. Called from the connect-callback (gated
     * on IsSynced) and from the reindex thread.
     *
     * @return true on success; false on a leveldb write failure or undo-
     *         data unavailability. Failure during reindex aborts the walk.
     */
    bool WriteBlock(const CBlock& block, int height, const uint256& block_hash);

    /**
     * Roll back a block from the index. Called from the disconnect
     * callback (gated on IsSynced).
     *
     * @return true on success (or no-op for monotonicity guard); false on
     *         leveldb write failure (sets sticky `m_corrupted`).
     */
    bool EraseBlock(const CBlock& block, int height, const uint256& block_hash);

    /**
     * Look up the per-block stats for a given height. Returns false if the
     * height is not yet indexed.
     */
    bool LookupStats(int height, CoinStats& out) const;

    int  LastIndexedHeight() const;
    bool IsBuiltUpToHeight(int h) const;
    bool IsSynced() const;

    /**
     * Sticky corruption flag. Set on EraseBlock leveldb-write failure;
     * cleared only by `WipeIndex` (C7 / --reindex path) or fresh process.
     */
    bool IsCorrupted() const;

    void StartBackgroundSync();
    void Interrupt();
    void Stop();

    void IncrementMismatches();
    uint64_t MismatchCount() const;

private:
    static constexpr uint8_t SCHEMA_VERSION = 0x01;

    // Per-height key: 1 byte 'h' prefix + 4-byte big-endian height. The
    // big-endian height ensures lexicographic order matches numeric order
    // across the whole 32-bit range, so an iterator scan returns blocks
    // in height-ascending order without sorting.
    static constexpr size_t H_KEY_SIZE = 5;

    // Per-height value layout (versioned):
    //   byte 0:        schema version (0x01)
    //   bytes 1..32:   hashChainCommitment  (32 bytes, raw SHA-3 output)
    //   bytes 33..40:  coinsCount           (uint64_t LE)
    //   bytes 41..48:  totalAmount          (uint64_t LE)
    //   bytes 49..56:  blockAdditions       (uint64_t LE)
    //   bytes 57..64:  blockRemovals        (uint64_t LE)
    //   bytes 65..72:  blockTotalOut        (uint64_t LE)
    //   bytes 73..80:  blockTotalIn         (uint64_t LE)
    //   bytes 81..88:  blockSubsidyFees     (uint64_t LE)
    static constexpr size_t H_VALUE_SIZE = 1 + 32 + 8 * 7;

    // Meta record (matches txindex layout):
    //   byte 0:        schema version (0x01)
    //   bytes 1..4:    last_indexed_height  (int32_t LE; -1 = cold)
    //   bytes 5..12:   truncated last-indexed block hash (8 bytes)
    static constexpr size_t META_VALUE_SIZE = 13;

    static const std::string META_KEY;   // "\x00meta" -- 5-byte literal

    std::unique_ptr<leveldb::DB> m_db;
    CBlockchainDB*               m_chain_db = nullptr;
    const CUTXOSet*              m_utxo_set = nullptr;

    mutable std::mutex m_mutex;

    std::atomic<bool>     m_synced{false};
    std::atomic<int>      m_last_height{-1};
    std::atomic<bool>     m_interrupt{false};
    std::atomic<uint64_t> m_mismatches_observed{0};

    // Sticky corruption flag. See class docblock above.
    std::atomic<bool>     m_corrupted{false};

    // Spawn-vs-stop race gate (mirrors txindex SEC-MD-1).
    std::atomic<bool>     m_starting{false};

    // In-memory running stats. Updated on WriteBlock (additive) and on
    // EraseBlock (rollback). Protected by m_mutex. The on-disk per-height
    // record is the authoritative source; this is a hot-path cache.
    CoinStats m_running;

    std::thread m_sync_thread;

    static std::string MakeHeightKey(int height);

    // Encode/decode the per-height record body.
    static void   EncodeHeightValue(const CoinStats& s, char out[H_VALUE_SIZE]);
    static bool   DecodeHeightValue(const std::string& v, CoinStats& s);

    bool WriteMeta(leveldb::WriteBatch& batch, int height, const uint256& hash);
    bool WriteHeightRecord(leveldb::WriteBatch& batch,
                           int height,
                           const CoinStats& s);

    // Single-WriteBatch wipe: collects Deletes for every 'h'-prefix key
    // plus the meta key; issues one m_db->Write. Caller must NOT hold
    // m_mutex.
    bool WipeIndex();

    // Reindex thread body. Mirrors CTxIndex::SyncLoop.
    void SyncLoop(int initial_snapshotted_tip);

    // Inner-walk helper. Mirrors CTxIndex::WalkBlockRange.
    bool WalkBlockRange(int start, int end);

    // Compute the after-block CoinStats for the supplied (block, height).
    // Reads the undo data via m_utxo_set->ReadUndoBlock(block_hash) and
    // deserialises the block transactions. Returns false on undo-data
    // unavailability or deserialisation failure.
    bool ComputeBlockStats(const CBlock& block,
                           int height,
                           const uint256& block_hash,
                           CoinStats& parent_stats,
                           CoinStats& after_stats) const;
};

extern std::unique_ptr<CCoinStatsIndex> g_coin_stats_index;

#endif // DILITHION_INDEX_COINSTATSINDEX_H
