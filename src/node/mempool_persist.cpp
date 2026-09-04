// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <node/mempool_persist.h>

#include <node/mempool.h>
#include <net/serialize.h>
#include <crypto/sha3.h>
#include <primitives/transaction.h>
#include <util/atomic_file.h>

#include <cerrno>
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

namespace mempool_persist {

namespace test_hooks {
std::atomic<bool> g_force_dump_failure{false};
std::atomic<bool> g_force_late_dump_failure{false};
}

namespace {

// Compute SHA3-256 of `payload` and return its truncated 8 leading bytes as a
// vector ready for appending to the on-disk file.
std::vector<uint8_t> ComputeFooter(const std::vector<uint8_t>& payload) {
    uint8_t full[32];
    SHA3_256(payload.data(), payload.size(), full);
    return std::vector<uint8_t>(full, full + FOOTER_SIZE);
}

// Verify the trailing FOOTER_SIZE bytes of `whole_file` against
// SHA3-256(whole_file[0, size-FOOTER_SIZE)). Returns true on match.
bool VerifyFooter(const std::vector<uint8_t>& whole_file) {
    if (whole_file.size() < FOOTER_SIZE) return false;
    const size_t payload_size = whole_file.size() - FOOTER_SIZE;
    uint8_t computed[32];
    SHA3_256(whole_file.data(), payload_size, computed);
    return std::memcmp(computed, whole_file.data() + payload_size, FOOTER_SIZE) == 0;
}

// Generate a 32-byte XOR-scramble key. Uses std::random_device which is
// /dev/urandom-equivalent on POSIX and BCryptGenRandom on Windows. Per-dump
// key avoids the situation where a static key is itself a malware signature.
std::vector<uint8_t> GenerateXorKey() {
    std::vector<uint8_t> key(XOR_KEY_SIZE);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < XOR_KEY_SIZE; ++i) {
        key[i] = static_cast<uint8_t>(dist(rd));
    }
    return key;
}

// XOR-scramble `data` in place with the cycled key. The key is the first
// XOR_KEY_SIZE bytes after the version byte; xor_key applies starting at
// `offset` from the beginning of the section to be scrambled (so we can
// scramble the body without re-scrambling the version byte and key itself).
void XorScramble(uint8_t* data, size_t length,
                 const std::vector<uint8_t>& key, size_t offset = 0) {
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= key[(i + offset) % XOR_KEY_SIZE];
    }
}

// (FsyncParentDir removed: the parent-directory fsync now lives in
//  util::AtomicReplaceFile(durable=true), so there is one implementation.)

// Write `bytes` to `target` atomically: write to .new, fsync the file, then
// atomically replace `target` via util::AtomicReplaceFile (durable=true, which
// also covers the parent-directory fsync on POSIX).
//
// Test seams:
//   g_force_dump_failure       -- fires BEFORE fopen (no .new file created)
//   g_force_late_dump_failure  -- fires AFTER .new is fully written but before
//                                  fsync; exercises the cleanup path
//
// Returns empty string on success; error text otherwise. On any failure, the
// .new file is removed if it exists, leaving any prior `target` intact.
std::string AtomicWrite(const std::filesystem::path& target,
                        const std::vector<uint8_t>& bytes) {
    if (test_hooks::g_force_dump_failure.load(std::memory_order_relaxed)) {
        return "forced dump failure (test, early)";
    }

    const std::filesystem::path tmp = target.parent_path() / FILENAME_TMP;

    // Lambda for cleanup of the .new file on any failure.
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

    // Late-failure test seam: at this point the .new file exists and contains
    // the full payload. Failing here exercises the cleanup-on-failure path.
    if (test_hooks::g_force_late_dump_failure.load(std::memory_order_relaxed)) {
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

    // Publish atomically, and NOT with std::filesystem::rename.
    //
    // This used to be a bare fs::rename(tmp, target). On POSIX that is correct,
    // and on the libstdc++ we currently ship it is correct on Windows too
    // (measured: it performs a real replace). But that is library behaviour we
    // do not control and MinGW has not always provided it.
    // util::AtomicReplaceFile states the requirement instead:
    // MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) on
    // Windows, rename(2) + parent-dir fsync on POSIX -- so `target` is at every
    // instant either the complete old file or the complete new one, and the
    // replace is durable. See src/util/atomic_file.h.
    //
    // durable=true subsumes the parent-directory fsync this function used to do
    // via its own local FsyncParentDir (now removed -- one implementation, in
    // util::AtomicReplaceFile). As before, a durability-only failure does NOT
    // remove the freshly renamed file: it is on disk and correct, only its
    // directory entry may not have been committed.
    std::string move_err;
    if (!util::AtomicReplaceFile(tmp, target, &move_err, /*durable=*/true)) {
        // Removes the tmp if the replace never happened; a no-op if it did and
        // only the durability step failed. `target` is never removed either way.
        cleanup_tmp();
        return move_err;
    }

    return std::string();   // success
}

}  // anonymous namespace

DumpResult DumpMempool(const CTxMemPool& mempool,
                       const std::filesystem::path& datadir) {
    DumpResult result;

    // Snapshot under the mempool lock. GetAllEntries copies out CTxMemPoolEntry
    // values; the embedded CTransactionRef is a shared_ptr so the copy is
    // cheap and the txs remain valid for the duration of this call.
    const std::vector<CTxMemPoolEntry> entries = mempool.GetAllEntries();

    if (entries.size() > MAX_TX_COUNT) {
        // Defensive: the mempool's own size cap should prevent this, but if it
        // doesn't, refuse to dump rather than write a file that LoadMempool
        // would then refuse to read.
        result.success = false;
        result.error_message = "mempool has " + std::to_string(entries.size()) +
                               " entries, exceeds dump cap " + std::to_string(MAX_TX_COUNT);
        return result;
    }

    // Build the payload (everything before the integrity footer).
    CDataStream stream;
    stream.reserve(entries.size() * 256);

    // Version byte.
    stream.WriteUint8(SCHEMA_VERSION);

    // 32-byte XOR scramble key. Random per-dump so a static key cannot itself
    // be a malware signature. Mirrors Bitcoin Core v27+ behaviour.
    const std::vector<uint8_t> xor_key = GenerateXorKey();
    stream.write(xor_key.data(), xor_key.size());

    // Mark where the scrambled body begins. Everything from here on gets
    // XOR-scrambled before write to disk.
    const size_t body_start = stream.size();

    stream.WriteUint64(static_cast<uint64_t>(entries.size()));

    for (const auto& entry : entries) {
        const std::vector<uint8_t> tx_bytes = entry.GetTx().Serialize();
        if (tx_bytes.size() > MAX_TX_SIZE) {
            result.success = false;
            result.error_message = "tx serialized size " + std::to_string(tx_bytes.size()) +
                                   " exceeds bound " + std::to_string(MAX_TX_SIZE);
            return result;
        }
        stream.WriteUint32(static_cast<uint32_t>(tx_bytes.size()));
        stream.write(tx_bytes);
        stream.WriteInt64(entry.GetTime());
        stream.WriteInt64(static_cast<int64_t>(entry.GetFee()));
    }

    std::vector<uint8_t> bytes = stream.GetData();

    // Compute the integrity footer over the UNSCRAMBLED bytes. The footer
    // protects logical-content integrity, not on-disk byte integrity. Loading
    // unscrambles first, then verifies the footer, then parses.
    const std::vector<uint8_t> footer = ComputeFooter(bytes);

    // XOR-scramble the body (everything after version + key). Version byte
    // and key bytes are written in the clear so LoadMempool can read them
    // before unscrambling.
    if (bytes.size() > body_start) {
        XorScramble(bytes.data() + body_start, bytes.size() - body_start, xor_key);
    }

    // Append the footer (also scrambled, for uniform body treatment).
    const size_t footer_offset_in_body = bytes.size() - body_start;
    bytes.insert(bytes.end(), footer.begin(), footer.end());
    XorScramble(bytes.data() + body_start + footer_offset_in_body, FOOTER_SIZE,
                xor_key, footer_offset_in_body);

    // Final size check before writing.
    if (bytes.size() > MAX_FILE_SIZE) {
        result.success = false;
        result.error_message = "computed file size " + std::to_string(bytes.size()) +
                               " exceeds MAX_FILE_SIZE " + std::to_string(MAX_FILE_SIZE);
        return result;
    }

    const std::filesystem::path target = datadir / FILENAME;
    const std::string write_error = AtomicWrite(target, bytes);
    if (!write_error.empty()) {
        result.success = false;
        result.error_message = write_error;
        return result;
    }

    result.success = true;
    result.txs_written = entries.size();
    result.final_path = target.string();
    std::cout << "[mempool] DumpMempool: wrote " << entries.size()
              << " transactions to " << target.string() << std::endl;
    return result;
}

LoadResult LoadMempool(CTxMemPool& mempool,
                       const std::filesystem::path& datadir,
                       unsigned int current_height) {
    LoadResult result;

    const std::filesystem::path target = datadir / FILENAME;

    std::error_code ec;
    if (!std::filesystem::exists(target, ec)) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file not found";
        std::cout << "[mempool] LoadMempool: " << target.string()
                  << " not found, starting with empty mempool" << std::endl;
        return result;
    }

    // B1: bound the file-size read. A pathological / malicious file claiming
    // to be multi-GB would otherwise allocate the full size before any
    // schema-level bounds kick in, crashing on bad_alloc.
    const std::uintmax_t reported_size = std::filesystem::file_size(target, ec);
    if (ec) {
        result.success = false;
        result.error_message = "file_size(" + target.string() + ") failed: " + ec.message();
        return result;
    }
    if (reported_size > MAX_FILE_SIZE) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file size " + std::to_string(reported_size) +
                                   " exceeds MAX_FILE_SIZE " + std::to_string(MAX_FILE_SIZE);
        std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                  << " -- starting with empty mempool" << std::endl;
        return result;
    }
    if (reported_size < MIN_FILE_SIZE) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "file too small (" + std::to_string(reported_size) +
                                   " bytes, minimum " + std::to_string(MIN_FILE_SIZE) + ")";
        std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                  << " -- starting with empty mempool" << std::endl;
        return result;
    }

    std::ifstream in(target.string(), std::ios::binary);
    if (!in.is_open()) {
        result.success = false;
        result.error_message = "failed to open " + target.string();
        return result;
    }

    std::vector<uint8_t> whole_file(static_cast<size_t>(reported_size));
    if (!in.read(reinterpret_cast<char*>(whole_file.data()), reported_size)) {
        result.success = false;
        result.error_message = "read failed on " + target.string();
        return result;
    }
    in.close();

    // Read the version byte (in the clear).
    const uint8_t version = whole_file[0];
    if (version != SCHEMA_VERSION) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "unknown schema version " + std::to_string(version);
        std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                  << " -- starting with empty mempool" << std::endl;
        return result;
    }

    // Extract the XOR key (in the clear, immediately after version).
    std::vector<uint8_t> xor_key(whole_file.begin() + 1,
                                  whole_file.begin() + 1 + XOR_KEY_SIZE);

    // Unscramble the body (everything after version + key, including footer).
    const size_t body_start = 1 + XOR_KEY_SIZE;
    XorScramble(whole_file.data() + body_start, whole_file.size() - body_start,
                xor_key);

    // Verify SHA3-256 truncated footer over the UNSCRAMBLED whole file.
    if (!VerifyFooter(whole_file)) {
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = "integrity footer mismatch";
        std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                  << " -- starting with empty mempool" << std::endl;
        return result;
    }

    // Parse payload (skip version+key prefix; trim footer suffix).
    std::vector<uint8_t> payload(whole_file.begin() + body_start,
                                  whole_file.end() - FOOTER_SIZE);
    CDataStream stream(payload);

    try {
        const uint64_t tx_count = stream.ReadUint64();
        if (tx_count > MAX_TX_COUNT) {
            result.success = true;
            result.cold_start = true;
            result.cold_start_reason = "tx_count " + std::to_string(tx_count) +
                                       " exceeds bound " + std::to_string(MAX_TX_COUNT);
            std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                      << " -- starting with empty mempool" << std::endl;
            return result;
        }

        for (uint64_t i = 0; i < tx_count; ++i) {
            const uint32_t tx_size = stream.ReadUint32();
            if (tx_size == 0 || tx_size > MAX_TX_SIZE) {
                // Malformed tx_size in the middle of the stream; bail and
                // treat as cold-start. The footer already passed, so this
                // is a schema-violation rather than corruption.
                result.success = true;
                result.cold_start = true;
                result.cold_start_reason = "malformed tx_size " + std::to_string(tx_size) +
                                           " at index " + std::to_string(i);
                std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                          << " -- starting with empty mempool" << std::endl;
                return result;
            }
            std::vector<uint8_t> tx_bytes = stream.read(tx_size);
            const int64_t entry_time = stream.ReadInt64();
            const int64_t fee_paid   = stream.ReadInt64();

            // Deserialize the tx. On parse failure, drop and continue: the
            // file's integrity footer matched, so this isn't disk corruption;
            // it's likely a tx schema we don't support (e.g. cross-major
            // upgrade) and we should keep loading the rest.
            auto tx = std::make_shared<CTransaction>();
            std::string parse_err;
            size_t bytes_consumed = 0;
            if (!tx->Deserialize(tx_bytes.data(), tx_bytes.size(), &parse_err,
                                 &bytes_consumed)) {
                ++result.txs_dropped_invalid;
                continue;
            }

            ++result.txs_read;

            // Admit via the public API. AddTx validates against the current
            // chainstate; rejected txs are tracked under txs_dropped_invalid.
            //
            // bypass_fee_check=true: restored txs passed Consensus::CheckFee
            // when first admitted to the mempool. Reorg-during-shutdown does
            // not change the fee. Skipping the re-check matches Bitcoin
            // Core's LoadMempool behavior. AddTx still validates everything
            // else (coinbase, double-spend, time skew, height, size).
            std::string admit_err;
            const bool admitted = mempool.AddTx(tx,
                                                static_cast<CAmount>(fee_paid),
                                                entry_time,
                                                current_height,
                                                &admit_err,
                                                /*bypass_fee_check=*/true);
            if (admitted) {
                ++result.txs_admitted;
            } else {
                ++result.txs_dropped_invalid;
            }
        }
    } catch (const std::exception& e) {
        // CDataStream throws on read past end; treat as cold-start.
        result.success = true;
        result.cold_start = true;
        result.cold_start_reason = std::string("stream error: ") + e.what();
        std::cerr << "[mempool] LoadMempool: " << result.cold_start_reason
                  << " -- starting with empty mempool" << std::endl;
        return result;
    }

    result.success = true;
    std::cout << "[mempool] LoadMempool: loaded " << result.txs_admitted
              << " transactions from " << target.string();
    if (result.txs_dropped_invalid > 0) {
        std::cout << " (dropped " << result.txs_dropped_invalid
                  << " with invalid inputs or schema)";
    }
    std::cout << std::endl;
    return result;
}

}  // namespace mempool_persist
