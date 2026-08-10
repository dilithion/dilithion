// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <policy/fee_persist.h>

#include <policy/fees.h>
#include <net/serialize.h>
#include <crypto/sha3.h>
#include <uint256.h>
#include <util/atomic_file.h>

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define POSIX_FSYNC(fd) _commit(fd)
#else
#include <fcntl.h>
#include <unistd.h>
#define POSIX_FSYNC(fd) fsync(fd)
#endif

namespace policy {
namespace fee_persist {

namespace test_hooks {
std::atomic<bool> g_force_dump_failure{false};
std::atomic<bool> g_force_late_dump_failure{false};
}

namespace {

using policy::fee_estimator::CBlockPolicyEstimator;
using policy::fee_estimator::TxConfirmStats;

// ---------------------------------------------------------------------------
// Numeric encoding
// ---------------------------------------------------------------------------

// Bucket boundary encoding: store as int64 = round(ld * 1e6). At our bucket
// range (1000 .. 1e7) this gives us 6 decimal digits of precision -- vastly
// more than the 1.05x bucket spacing requires (about 2% of the smallest
// bucket). The INF_FEERATE sentinel (MAX_MONEY) is stored as INT64_MAX to
// avoid overflow; DecodeBucket recognizes it and returns INF_FEERATE.
// Long-double comparison in restore() uses 1e-3 RELATIVE tolerance to absorb
// the loss-y round-trip (precision ~1e-6 of value at BUCKET_SCALE=1e6).
constexpr long double BUCKET_SCALE = 1e6L;

int64_t EncodeBucket(long double ld) {
    // INF sentinel: any value at or above the in-memory INF_FEERATE
    // encodes to INT64_MAX. (Not technically Inf -- it's MAX_MONEY -- but
    // we treat the top-of-ladder bucket as "out of range high" semantically.)
    if (ld >= policy::fee_estimator::INF_FEERATE) return INT64_MAX;
    // Avoid std::llround on Windows (LLP64) -- round explicitly.
    const long double scaled = ld * BUCKET_SCALE;
    if (scaled >= static_cast<long double>(INT64_MAX) - 1) return INT64_MAX;
    if (scaled <= static_cast<long double>(INT64_MIN) + 1) return INT64_MIN;
    const long double rounded = (scaled >= 0.0L)
        ? std::floor(scaled + 0.5L)
        : std::ceil(scaled - 0.5L);
    return static_cast<int64_t>(rounded);
}

long double DecodeBucket(int64_t v) {
    if (v == INT64_MAX) return policy::fee_estimator::INF_FEERATE;
    return static_cast<long double>(v) / BUCKET_SCALE;
}

// Counter encoding: Q32.32 fixed-point. The decayed counters accumulate
// values up to a few thousand (in real workloads); 32 fractional bits give
// us ~2.3e-10 precision, far more than the long-double-decay-step error.
// 32 integer bits give us up to ~2 billion observations, more than enough.
constexpr long double Q32_SCALE = 4294967296.0L;  // 2^32

int64_t EncodeCounter(long double ld) {
    if (ld <= 0.0L) return 0;
    const long double scaled = ld * Q32_SCALE;
    if (scaled >= static_cast<long double>(INT64_MAX)) return INT64_MAX;
    return static_cast<int64_t>(static_cast<double>(scaled));
}

long double DecodeCounter(int64_t v) {
    if (v <= 0) return 0.0L;
    return static_cast<long double>(v) / Q32_SCALE;
}

// ---------------------------------------------------------------------------
// SHA3-256 footer + XOR-scramble (verbatim from mempool_persist)
// ---------------------------------------------------------------------------

std::vector<uint8_t> ComputeFooter(const std::vector<uint8_t>& payload) {
    uint8_t full[32];
    SHA3_256(payload.data(), payload.size(), full);
    return std::vector<uint8_t>(full, full + FOOTER_SIZE);
}

bool VerifyFooter(const std::vector<uint8_t>& whole_file) {
    if (whole_file.size() < FOOTER_SIZE) return false;
    const size_t payload_size = whole_file.size() - FOOTER_SIZE;
    uint8_t computed[32];
    SHA3_256(whole_file.data(), payload_size, computed);
    return std::memcmp(computed, whole_file.data() + payload_size,
                       FOOTER_SIZE) == 0;
}

std::vector<uint8_t> GenerateXorKey() {
    std::vector<uint8_t> key(XOR_KEY_SIZE);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < XOR_KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(dist(rd));
    }
    return key;
}

void XorScramble(uint8_t* data, size_t length,
                 const std::vector<uint8_t>& key, size_t offset = 0) {
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key[(i + offset) % XOR_KEY_SIZE];
    }
}

// (FsyncParentDir removed: the parent-directory fsync now lives in
//  util::AtomicReplaceFile(durable=true), so there is one implementation.)

std::string AtomicWrite(const std::filesystem::path& target,
                        const std::vector<uint8_t>& bytes) {
    if (test_hooks::g_force_dump_failure.load(std::memory_order_relaxed)) {
        return "forced dump failure (test, early)";
    }

    const std::filesystem::path tmp = target.parent_path() / FILENAME_TMP;
    auto cleanup_tmp = [&]() {
        std::error_code ec_unused;
        std::filesystem::remove(tmp, ec_unused);
    };

    FILE* f = std::fopen(tmp.string().c_str(), "wb");
    if (f == nullptr) {
        return "fopen(" + tmp.string() + ") failed: " + std::strerror(errno);
    }
    const size_t written = std::fwrite(bytes.data(), 1, bytes.size(), f);
    if (written != bytes.size()) {
        const std::string err = std::strerror(errno);
        std::fclose(f);
        cleanup_tmp();
        return "fwrite short: " + err;
    }
    if (std::fflush(f) != 0) {
        const std::string err = std::strerror(errno);
        std::fclose(f);
        cleanup_tmp();
        return "fflush failed: " + err;
    }

    if (test_hooks::g_force_late_dump_failure.load(
            std::memory_order_relaxed)) {
        std::fclose(f);
        cleanup_tmp();
        return "forced dump failure (test, late)";
    }

#ifdef _WIN32
    const int fd = _fileno(f);
#else
    const int fd = fileno(f);
#endif
    if (fd < 0 || POSIX_FSYNC(fd) != 0) {
        const std::string err = std::strerror(errno);
        std::fclose(f);
        cleanup_tmp();
        return "fsync failed: " + err;
    }
    std::fclose(f);

    // Publish atomically. Same change as src/node/mempool_persist.cpp (these
    // two writers are line-for-line clones): the publish no longer depends on
    // std::filesystem::rename's Windows behaviour, which is a libstdc++
    // implementation detail rather than a guarantee. util::AtomicReplaceFile
    // uses MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) on
    // Windows and rename(2) + parent-dir fsync on POSIX; durable=true subsumes
    // the FsyncParentDir call that used to follow. See src/util/atomic_file.h.
    std::string move_err;
    if (!util::AtomicReplaceFile(tmp, target, &move_err, /*durable=*/true)) {
        // No-op if the replace succeeded and only the durability step failed;
        // `target` is never removed.
        cleanup_tmp();
        return move_err;
    }
    return std::string();
}

// ---------------------------------------------------------------------------
// Stats serialization
// ---------------------------------------------------------------------------

void WriteStats(CDataStream& s, const TxConfirmStats& stats) {
    const size_t bucket_count = stats.tx_ct_avg.size();
    const uint32_t periods = static_cast<uint32_t>(stats.conf_avg.size());
    const uint32_t depth   = static_cast<uint32_t>(stats.unconf_txs.size());
    s.WriteUint32(periods);
    s.WriteUint32(static_cast<uint32_t>(bucket_count));
    s.WriteUint32(depth);

    for (uint32_t p = 0; p < periods; ++p) {
        for (size_t b = 0; b < bucket_count; ++b) {
            s.WriteInt64(EncodeCounter(stats.conf_avg[p][b]));
        }
    }
    for (uint32_t p = 0; p < periods; ++p) {
        for (size_t b = 0; b < bucket_count; ++b) {
            s.WriteInt64(EncodeCounter(stats.fail_avg[p][b]));
        }
    }
    for (size_t b = 0; b < bucket_count; ++b) {
        s.WriteInt64(EncodeCounter(stats.tx_ct_avg[b]));
    }
    for (uint32_t a = 0; a < depth; ++a) {
        for (size_t b = 0; b < bucket_count; ++b) {
            s.WriteInt32(static_cast<int32_t>(stats.unconf_txs[a][b]));
        }
    }
    for (size_t b = 0; b < bucket_count; ++b) {
        s.WriteInt32(static_cast<int32_t>(stats.old_unconf_txs[b]));
    }
}

bool ReadStats(CDataStream& s, TxConfirmStats& out, std::string& err) {
    const uint32_t periods = s.ReadUint32();
    const uint32_t bucket_count_raw = s.ReadUint32();
    const uint32_t depth   = s.ReadUint32();

    if (periods == 0 || periods > MAX_PERIODS) {
        err = "stats periods=" + std::to_string(periods) + " out of range";
        return false;
    }
    if (bucket_count_raw == 0 || bucket_count_raw > MAX_BUCKET_COUNT) {
        err = "stats bucket_count=" + std::to_string(bucket_count_raw) +
              " out of range";
        return false;
    }
    if (depth > MAX_UNCONF_DEPTH) {
        err = "stats unconf_depth=" + std::to_string(depth) +
              " out of range";
        return false;
    }
    const size_t bucket_count = static_cast<size_t>(bucket_count_raw);

    out.conf_avg.assign(periods,
                        std::vector<long double>(bucket_count, 0.0L));
    out.fail_avg.assign(periods,
                        std::vector<long double>(bucket_count, 0.0L));
    out.tx_ct_avg.assign(bucket_count, 0.0L);
    out.unconf_txs.assign(depth, std::vector<int>(bucket_count, 0));
    out.old_unconf_txs.assign(bucket_count, 0);

    for (uint32_t p = 0; p < periods; ++p) {
        for (size_t b = 0; b < bucket_count; ++b) {
            out.conf_avg[p][b] = DecodeCounter(s.ReadInt64());
        }
    }
    for (uint32_t p = 0; p < periods; ++p) {
        for (size_t b = 0; b < bucket_count; ++b) {
            out.fail_avg[p][b] = DecodeCounter(s.ReadInt64());
        }
    }
    for (size_t b = 0; b < bucket_count; ++b) {
        out.tx_ct_avg[b] = DecodeCounter(s.ReadInt64());
    }
    for (uint32_t a = 0; a < depth; ++a) {
        for (size_t b = 0; b < bucket_count; ++b) {
            out.unconf_txs[a][b] = static_cast<int>(s.ReadInt32());
        }
    }
    for (size_t b = 0; b < bucket_count; ++b) {
        out.old_unconf_txs[b] = static_cast<int>(s.ReadInt32());
    }
    return true;
}

}  // anonymous namespace

DumpResult DumpFeeEstimates(const CBlockPolicyEstimator& estimator,
                            const std::filesystem::path& datadir) {
    DumpResult result;

    auto snap = estimator.snapshot();

    if (snap.tracked_txs.size() > MAX_TRACKED_TX) {
        result.error_message = "tracked tx count " +
            std::to_string(snap.tracked_txs.size()) +
            " exceeds dump cap " + std::to_string(MAX_TRACKED_TX);
        return result;
    }
    if (snap.buckets.size() > MAX_BUCKET_COUNT) {
        result.error_message = "bucket count " +
            std::to_string(snap.buckets.size()) +
            " exceeds dump cap " + std::to_string(MAX_BUCKET_COUNT);
        return result;
    }

    CDataStream stream;
    stream.reserve(8192);

    stream.WriteUint8(SCHEMA_VERSION);
    const std::vector<uint8_t> xor_key = GenerateXorKey();
    stream.write(xor_key.data(), xor_key.size());

    const size_t body_start = stream.size();

    // Header
    stream.WriteUint32(snap.best_seen_height);
    stream.WriteUint32(snap.historical_first);
    stream.WriteUint32(snap.historical_best);

    // Buckets
    stream.WriteUint32(static_cast<uint32_t>(snap.buckets.size()));
    for (long double b : snap.buckets) {
        stream.WriteInt64(EncodeBucket(b));
    }

    // Three stat collections
    WriteStats(stream, snap.short_stats);
    WriteStats(stream, snap.med_stats);
    WriteStats(stream, snap.long_stats);

    // Tracked txs
    stream.WriteUint64(static_cast<uint64_t>(snap.tracked_txs.size()));
    for (const auto& [h, t] : snap.tracked_txs) {
        stream.WriteUint256(h);
        stream.WriteUint32(t.height);
        stream.WriteUint32(t.bucket_index);
        stream.WriteUint8(t.horizon_mask);
    }

    std::vector<uint8_t> bytes = stream.GetData();
    const std::vector<uint8_t> footer = ComputeFooter(bytes);

    // Scramble body (everything after version + key).
    if (bytes.size() > body_start) {
        XorScramble(bytes.data() + body_start, bytes.size() - body_start,
                    xor_key);
    }
    // Append scrambled footer.
    const size_t footer_offset_in_body = bytes.size() - body_start;
    bytes.insert(bytes.end(), footer.begin(), footer.end());
    XorScramble(bytes.data() + body_start + footer_offset_in_body, FOOTER_SIZE,
                xor_key, footer_offset_in_body);

    if (bytes.size() > MAX_FILE_SIZE) {
        result.error_message = "computed file size " +
            std::to_string(bytes.size()) + " exceeds MAX_FILE_SIZE " +
            std::to_string(MAX_FILE_SIZE);
        return result;
    }

    const std::filesystem::path target = datadir / FILENAME;
    const std::string write_error = AtomicWrite(target, bytes);
    if (!write_error.empty()) {
        result.error_message = write_error;
        return result;
    }

    result.success = true;
    result.bytes_written = bytes.size();
    result.tracked_tx_count = snap.tracked_txs.size();
    result.final_path = target.string();
    std::cout << "[fee_estimator] DumpFeeEstimates: wrote "
              << bytes.size() << " bytes ("
              << snap.tracked_txs.size() << " tracked txs) to "
              << target.string() << std::endl;
    return result;
}

LoadResult LoadFeeEstimates(CBlockPolicyEstimator& estimator,
                            const std::filesystem::path& datadir) {
    LoadResult result;

    const std::filesystem::path target = datadir / FILENAME;
    std::error_code ec;

    if (!std::filesystem::exists(target, ec)) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file not found";
        std::cout << "[fee_estimator] LoadFeeEstimates: " << target.string()
                  << " not found, starting fresh" << std::endl;
        return result;
    }

    const std::uintmax_t reported_size = std::filesystem::file_size(target, ec);
    if (ec) {
        result.error_message = "file_size(" + target.string() +
            ") failed: " + ec.message();
        return result;
    }
    if (reported_size > MAX_FILE_SIZE) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file size " +
            std::to_string(reported_size) + " exceeds MAX_FILE_SIZE " +
            std::to_string(MAX_FILE_SIZE);
        std::cerr << "[fee_estimator] LoadFeeEstimates: "
                  << result.cold_start_reason << " -- starting fresh"
                  << std::endl;
        return result;
    }
    if (reported_size < MIN_FILE_SIZE) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file too small (" +
            std::to_string(reported_size) + " bytes, minimum " +
            std::to_string(MIN_FILE_SIZE) + ")";
        std::cerr << "[fee_estimator] LoadFeeEstimates: "
                  << result.cold_start_reason << " -- starting fresh"
                  << std::endl;
        return result;
    }

    std::ifstream in(target.string(), std::ios::binary);
    if (!in.is_open()) {
        result.error_message = "failed to open " + target.string();
        return result;
    }
    std::vector<uint8_t> whole_file(static_cast<size_t>(reported_size));
    if (!in.read(reinterpret_cast<char*>(whole_file.data()), reported_size)) {
        result.error_message = "read failed on " + target.string();
        return result;
    }
    in.close();

    const uint8_t version = whole_file[0];
    if (version != SCHEMA_VERSION) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "unknown schema version " +
            std::to_string(version);
        std::cerr << "[fee_estimator] LoadFeeEstimates: "
                  << result.cold_start_reason << " -- starting fresh"
                  << std::endl;
        return result;
    }

    std::vector<uint8_t> xor_key(whole_file.begin() + 1,
                                  whole_file.begin() + 1 + XOR_KEY_SIZE);
    const size_t body_start = 1 + XOR_KEY_SIZE;
    XorScramble(whole_file.data() + body_start,
                whole_file.size() - body_start, xor_key);

    if (!VerifyFooter(whole_file)) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "integrity footer mismatch";
        std::cerr << "[fee_estimator] LoadFeeEstimates: "
                  << result.cold_start_reason << " -- starting fresh"
                  << std::endl;
        return result;
    }

    std::vector<uint8_t> payload(whole_file.begin() + body_start,
                                  whole_file.end() - FOOTER_SIZE);
    CDataStream stream(payload);

    try {
        CBlockPolicyEstimator::Snapshot snap;
        snap.best_seen_height = stream.ReadUint32();
        snap.historical_first = stream.ReadUint32();
        snap.historical_best  = stream.ReadUint32();

        // PR-EF-1-FIX Finding F7: validate historical ordering. A footer-
        // valid file (the file is on operator-controlled disk; an attacker
        // with FS write access could compute a fresh SHA3 footer over
        // forged bytes) could declare historical_first > historical_best.
        // Without this check, the unsigned subtraction
        // `historical_best - historical_first` wraps to a huge number,
        // which the accumulation gate at fees.cpp ~370 then "passes",
        // bypassing the insufficient-data window. Treat inconsistent
        // ordering as cold-start.
        // Both-zero is the legitimate "never observed a block" state.
        if (snap.historical_first != 0 &&
            snap.historical_first > snap.historical_best) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "historical_first (" +
                std::to_string(snap.historical_first) +
                ") > historical_best (" +
                std::to_string(snap.historical_best) + ")";
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }

        const uint32_t bucket_count = stream.ReadUint32();
        if (bucket_count == 0 || bucket_count > MAX_BUCKET_COUNT) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "bucket_count " +
                std::to_string(bucket_count) + " out of range";
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }
        snap.buckets.reserve(bucket_count);
        for (uint32_t i = 0; i < bucket_count; ++i) {
            snap.buckets.push_back(DecodeBucket(stream.ReadInt64()));
        }

        std::string err;
        if (!ReadStats(stream, snap.short_stats, err)) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "short stats: " + err;
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }
        if (!ReadStats(stream, snap.med_stats, err)) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "med stats: " + err;
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }
        if (!ReadStats(stream, snap.long_stats, err)) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "long stats: " + err;
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }

        const uint64_t tracked_count = stream.ReadUint64();
        if (tracked_count > MAX_TRACKED_TX) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "tracked_tx_count " +
                std::to_string(tracked_count) + " exceeds bound " +
                std::to_string(MAX_TRACKED_TX);
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }
        snap.tracked_txs.reserve(tracked_count);
        for (uint64_t i = 0; i < tracked_count; ++i) {
            uint256 h = stream.ReadUint256();
            CBlockPolicyEstimator::Snapshot::Tracked t;
            t.height       = stream.ReadUint32();
            t.bucket_index = stream.ReadUint32();
            t.horizon_mask = stream.ReadUint8();
            snap.tracked_txs.emplace_back(h, t);
        }

        // Hand off to the estimator. restore() does its own bucket-ladder
        // and stats-shape sanity check; mismatch -> cold-start.
        if (!estimator.restore(std::move(snap))) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason =
                "bucket ladder or stats shape mismatch (likely upgrade)";
            std::cerr << "[fee_estimator] LoadFeeEstimates: "
                      << result.cold_start_reason
                      << " -- starting fresh" << std::endl;
            return result;
        }

        result.tracked_tx_count = static_cast<size_t>(tracked_count);
    } catch (const std::exception& e) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = std::string("stream error: ") + e.what();
        std::cerr << "[fee_estimator] LoadFeeEstimates: "
                  << result.cold_start_reason << " -- starting fresh"
                  << std::endl;
        return result;
    }

    result.success = true;
    std::cout << "[fee_estimator] LoadFeeEstimates: restored "
              << result.tracked_tx_count
              << " tracked txs from " << target.string() << std::endl;
    return result;
}

}  // namespace fee_persist
}  // namespace policy
