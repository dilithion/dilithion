// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#ifndef DILITHION_POLICY_FEE_PERSIST_H
#define DILITHION_POLICY_FEE_PERSIST_H

// Fee-estimator persistence -- mirror of node/mempool_persist.{h,cpp}.
// Saves CBlockPolicyEstimator state to <datadir>/fee_estimates.dat on
// shutdown; restores on startup.
//
// Schema (fee_estimates.dat layout) -- byte-for-byte parallel to
// mempool.dat for project-wide schema consistency:
//
//   +0     u8       version_byte = FEE_ESTIMATES_FILE_VERSION
//   +1     u8[32]   xor_key                                    [in the clear]
//   +33    ...      scrambled body
//   +N     u8[8]    sha3_256_truncated                         [scrambled]
//
// Body (logical fields, XOR-scrambled on disk):
//   u32   best_seen_height
//   u32   historical_first
//   u32   historical_best
//   u32   bucket_count
//   for each bucket:
//       i64   bucket_upper_bound_milli_ions  (long double * 1e6, rounded;
//                                             tolerates platform LD precision)
//   for each horizon (3 collections, in order: short, med, long):
//       u32   confirm_periods
//       u32   bucket_count
//       u32   unconf_depth
//       for each [period][bucket]: i64 conf_avg (Q32.32 fixed-point)
//       for each [period][bucket]: i64 fail_avg (Q32.32 fixed-point)
//       for each bucket:           i64 tx_ct_avg (Q32.32 fixed-point)
//       for each [age][bucket]:    i32 unconf_count
//       for each bucket:           i32 old_unconf
//   u64   tracked_tx_count
//   for each tracked tx:
//       u8[32] txhash
//       u32    height
//       u32    bucket_index
//       u8     horizon_mask
//
// XOR-scramble + SHA3-256 truncated footer rationale: identical to
// mempool.dat. AV-signature mitigation + integrity-detection at sub-ms
// load cost. See node/mempool_persist.h for full rationale.
//
// Atomicity: write to <datadir>/fee_estimates.dat.new, fsync it, then publish
// over fee_estimates.dat with util::AtomicReplaceFile() -- rename(2) on POSIX,
// MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) on Windows,
// which also covers the parent-directory fsync. The destination is at every
// instant either the complete previous file or the complete new one: never
// torn, never absent. On any failure the .new file is removed and the prior
// fee_estimates.dat is left intact.
//
// CORRECTION (M4): the publish previously used std::filesystem::rename and
// this paragraph asserted the resulting atomicity as a property of the
// platform. On the toolchain we ship, fs::rename does perform an atomic
// replace -- but that is a libstdc++ implementation detail, not a guarantee,
// and it has not always been true on MinGW. The requirement is now stated in
// the source. Measured results are in src/util/atomic_file.h.
//
// Cold-start semantics: any of (file missing, version mismatch, footer
// mismatch, malformed body, bucket-ladder mismatch) yields LoadResult{
// success=true, cold_start=true} -- the estimator stays as a fresh
// instance and accumulates from the next block. NEVER throws.

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <string>

namespace policy {
namespace fee_estimator {
class CBlockPolicyEstimator;
}  // namespace fee_estimator
}  // namespace policy

namespace policy {
namespace fee_persist {

// Test-hook seams for failure injection. Mirrors mempool_persist's
// pattern verbatim. Production reads are relaxed-atomic loads (sub-ns).
//
// g_force_dump_failure       -- fires BEFORE fopen (no .new file created)
// g_force_late_dump_failure  -- fires AFTER .new is fully written; exercises
//                                the cleanup path (.new removal, prior
//                                file intact)
namespace test_hooks {
extern std::atomic<bool> g_force_dump_failure;
extern std::atomic<bool> g_force_late_dump_failure;
}

constexpr uint8_t  SCHEMA_VERSION = 0x01;
constexpr size_t   FOOTER_SIZE    = 8;            // truncated SHA3-256
constexpr size_t   XOR_KEY_SIZE   = 32;           // matches mempool_persist
constexpr size_t   MIN_FILE_SIZE  = 1 + XOR_KEY_SIZE + 16 + FOOTER_SIZE;
                                                  // version + key + minimum body + footer
constexpr size_t   MAX_FILE_SIZE  = 64ULL * 1024 * 1024;
                                                  // 64 MB hard cap. Even a fully populated
                                                  // estimator with 100k tracked txs and the
                                                  // full 200-bucket ladder x 42 periods x 3
                                                  // horizons fits in well under 16 MB; 64
                                                  // MB is 4x safety margin.
constexpr uint64_t MAX_TRACKED_TX = 200'000;      // 2x DEFAULT_MAX_MEMPOOL_COUNT
constexpr uint32_t MAX_BUCKET_COUNT = 1024;       // sanity bound; real ladder is ~200
constexpr uint32_t MAX_PERIODS      = 1024;       // sanity bound; max real periods = 42
constexpr uint32_t MAX_UNCONF_DEPTH = 4096;       // sanity bound; max real depth = 42*24

const std::string FILENAME     = "fee_estimates.dat";
const std::string FILENAME_TMP = "fee_estimates.dat.new";

struct DumpResult {
    bool        success = false;
    std::string error_message;        // populated when !success
    size_t      bytes_written = 0;
    size_t      tracked_tx_count = 0;
    std::string final_path;           // <datadir>/fee_estimates.dat on success, empty otherwise
};

struct LoadResult {
    bool        success = false;       // true even on cold-start
    std::string error_message;         // populated only on hard error
    size_t      tracked_tx_count = 0;
    bool        cold_start = false;    // true if file missing / corrupted / mismatched
    std::string cold_start_reason;     // populated when cold_start == true
};

/**
 * Atomic save: write to <datadir>/fee_estimates.dat.new, fsync, then atomically
 * replace fee_estimates.dat via util::AtomicReplaceFile() (NOT
 * std::filesystem::rename -- see the header comment above and
 * src/util/atomic_file.h). Caller must hold no estimator lock; this function
 * takes the estimator's internal mutex via snapshot().
 *
 * On disk-full or transient failure, returns success=false with an error
 * message; the prior fee_estimates.dat (if any) is left intact.
 */
DumpResult DumpFeeEstimates(const policy::fee_estimator::CBlockPolicyEstimator& estimator,
                            const std::filesystem::path& datadir);

/**
 * Read from <datadir>/fee_estimates.dat, validate, restore via
 * estimator.restore().
 *
 * On any non-catastrophic problem (file missing, version mismatch, integrity
 * footer mismatch, malformed body, bucket-ladder mismatch), this function
 * returns LoadResult{success=true, cold_start=true} and leaves the estimator
 * in whatever state it was on entry (typically fresh).
 *
 * Hard errors (datadir unreadable) return success=false.
 *
 * @param estimator       The destination estimator (will be mutated via restore()).
 * @param datadir         The Dilithion data directory.
 */
LoadResult LoadFeeEstimates(policy::fee_estimator::CBlockPolicyEstimator& estimator,
                            const std::filesystem::path& datadir);

}  // namespace fee_persist
}  // namespace policy

#endif  // DILITHION_POLICY_FEE_PERSIST_H
