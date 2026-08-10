// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_NODE_MEMPOOL_PERSIST_H
#define DILITHION_NODE_MEMPOOL_PERSIST_H

// Mempool persistence — port of Bitcoin Core's `src/kernel/mempool_persist.{h,cpp}`
// (v28.0). Saves the unconfirmed mempool to disk on shutdown, restores it on
// startup. Eliminates the "every restart drops the mempool" UX hit that
// distorts wallet state and fee estimator data accumulation.
//
// Schema (mempool.dat layout):
//
//   +0     u8       version_byte = 0x01      [in the clear]
//   +1     u8[32]   xor_key                  [in the clear]
//   +33    u64      tx_count (LE)            [XOR-scrambled with xor_key]
//   +41    ...      tx_records               [XOR-scrambled with xor_key]
//   +N     u8[8]    sha3_256_truncated       [XOR-scrambled with xor_key]
//
// Each tx_record (logical fields, XOR-scrambled on disk):
//   +0     u32    serialized_size (LE)
//   +4     u8[]   serialized_tx (length = serialized_size)
//   +X     i64    entry_time (LE, unix seconds; matches CTxMemPoolEntry::GetTime())
//   +X+8   i64    fee_paid (LE, CAmount; matches CTxMemPoolEntry::GetFee())
//
// XOR scrambling protects against antivirus interference: serialized
// transaction script bytes can match malware signatures, causing AVs to
// silently delete mempool.dat. A 32-byte random key (regenerated on every
// dump) is written in the clear, then all subsequent bytes (including the
// integrity footer) are XOR'd with the cycled key. This mirrors Bitcoin
// Core v27+ (`PR #28207`).
//
// The integrity footer is computed over the UNSCRAMBLED bytes -- it
// protects logical-content integrity. LoadMempool unscrambles first,
// then verifies the footer, then parses.
//
// SHA3-256 truncated to 8 bytes is used for the integrity footer (rather than
// SHA-256 truncated as Bitcoin Core does) to match Dilithion's project-wide
// post-quantum hash convention. The 8-byte truncation gives 64-bit corruption-
// detection strength -- ample for catching accidental disk corruption. The
// strength against an adversary is also 64-bit, but the threat model assumes
// any adversary with filesystem write access can simply overwrite the file
// with a valid one, so the truncation is acceptable. Load cost is sub-ms over
// any plausible mempool size.
//
// Atomicity: DumpMempool writes to <datadir>/mempool.dat.new, fsyncs it, and
// then publishes it over mempool.dat via util::AtomicReplaceFile() --
// rename(2) on POSIX, MoveFileExW(MOVEFILE_REPLACE_EXISTING |
// MOVEFILE_WRITE_THROUGH) on Windows. Both are single filesystem operations,
// so mempool.dat is at every instant either the complete previous file or the
// complete new one: never torn, never absent. If the publish fails, the .new
// file is removed and the prior mempool.dat is left intact.
//
// CORRECTION (M4): this comment previously claimed the publish used
// std::filesystem::rename and that this "is also atomic on NTFS for same-volume
// moves". That was wrong in a way that mattered. libstdc++ implements
// std::filesystem::rename with _wrename(), which FAILS outright when the
// destination already exists -- so on Windows the guarantee documented here was
// not merely weaker than stated, the publish did not happen at all on any dump
// after the first. Do not reintroduce std::filesystem::rename on this path; see
// the rationale block in src/util/atomic_file.h.

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <string>

class CTxMemPool;

namespace mempool_persist {

// Test-hook seams for failure injection. Production code path checks these
// with relaxed atomic loads; cost is one atomic load per dump call. Mirror of
// the `tx_index_test_hooks` pattern from the txindex port.
//
// g_force_dump_failure       -- fires BEFORE fopen (no .new file is created)
// g_force_late_dump_failure  -- fires AFTER .new is fully written; exercises
//                                cleanup path (.new removal, prior file intact)
namespace test_hooks {
extern std::atomic<bool> g_force_dump_failure;
extern std::atomic<bool> g_force_late_dump_failure;
}

constexpr uint8_t  SCHEMA_VERSION  = 0x01;
constexpr size_t   FOOTER_SIZE     = 8;            // truncated SHA3-256
constexpr size_t   XOR_KEY_SIZE    = 32;           // XOR-scramble key (BC v27+ antivirus mitigation)
constexpr size_t   MIN_FILE_SIZE   = 1 + XOR_KEY_SIZE + 8 + FOOTER_SIZE;
                                                   // version + key + tx_count + footer
constexpr uint64_t MAX_TX_COUNT    = 200'000;      // 2x DEFAULT_MAX_MEMPOOL_COUNT (100k)
constexpr uint32_t MAX_TX_SIZE     = 4 * 1024 * 1024;  // 4 MB sanity bound on serialized tx
constexpr size_t   MAX_FILE_SIZE   = 512ULL * 1024 * 1024;
                                                   // 512 MB hard cap; well above any plausible
                                                   // 300 MB live mempool. LoadMempool refuses to
                                                   // allocate above this and treats as cold-start.

const std::string FILENAME       = "mempool.dat";
const std::string FILENAME_TMP   = "mempool.dat.new";

struct DumpResult {
    bool        success;
    std::string error_message;     // populated when !success
    size_t      txs_written = 0;
    std::string final_path;        // <datadir>/mempool.dat on success, empty otherwise
};

struct LoadResult {
    bool        success;            // true even on cold-start (file missing / corrupt)
    std::string error_message;      // populated only on hard error (datadir unreadable, etc.)
    size_t      txs_read = 0;
    size_t      txs_admitted = 0;
    size_t      txs_dropped_invalid = 0;  // tracked-tx no longer admissible (reorged-out, etc.)
    bool        cold_start = false;       // true if file missing or corrupted
    std::string cold_start_reason;        // populated when cold_start == true
};

/**
 * Atomic save: write to <datadir>/mempool.dat.new, fsync, rename to mempool.dat.
 * Caller must hold no mempool lock; this function takes the mempool lock
 * internally via GetAllEntries().
 *
 * On disk-full or transient failure, returns success=false with an error
 * message; the prior mempool.dat (if any) is left intact.
 */
DumpResult DumpMempool(const CTxMemPool& mempool,
                       const std::filesystem::path& datadir);

/**
 * Read from <datadir>/mempool.dat, validate, admit each tx via mempool.AddTx.
 *
 * On any non-catastrophic problem (file missing, version mismatch, integrity
 * footer mismatch, malformed tx, tx no longer admissible against current
 * chain state), this function returns LoadResult{success=true, cold_start=true}
 * and leaves the mempool in whatever state it was on entry (typically empty).
 *
 * Hard errors (datadir unreadable, exception during AddTx) return success=false.
 *
 * @param mempool         The destination mempool (will be mutated via AddTx).
 * @param datadir         The Dilithion data directory.
 * @param current_height  The current chain tip height; passed to AddTx.
 */
LoadResult LoadMempool(CTxMemPool& mempool,
                       const std::filesystem::path& datadir,
                       unsigned int current_height);

}  // namespace mempool_persist

#endif  // DILITHION_NODE_MEMPOOL_PERSIST_H
