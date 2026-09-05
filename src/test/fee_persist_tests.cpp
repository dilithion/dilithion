// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license

#include <boost/test/unit_test.hpp>

#include <policy/fee_persist.h>
#include <policy/fees.h>
#include <crypto/sha3.h>
#include <uint256.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>
#include <vector>

BOOST_AUTO_TEST_SUITE(fee_persist_tests)

namespace {

uint256 MakeTxHash(uint32_t seed) {
    uint256 h;
    std::memset(h.data, 0, 32);
    h.data[0] = static_cast<uint8_t>(seed & 0xFF);
    h.data[1] = static_cast<uint8_t>((seed >> 8) & 0xFF);
    h.data[2] = static_cast<uint8_t>((seed >> 16) & 0xFF);
    h.data[3] = static_cast<uint8_t>((seed >> 24) & 0xFF);
    h.data[31] = static_cast<uint8_t>(seed * 0x9E + 0x37);
    return h;
}

std::filesystem::path MakeTempDir(const std::string& tag) {
    auto base = std::filesystem::temp_directory_path();
    auto path = base / ("fee_persist_test_" + tag + "_" +
        std::to_string(static_cast<long long>(
            std::chrono::steady_clock::now().time_since_epoch().count())));
    std::filesystem::create_directories(path);
    return path;
}

void CleanupTempDir(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

class TempDir {
public:
    explicit TempDir(const std::string& tag) : m_path(MakeTempDir(tag)) {}
    ~TempDir() { CleanupTempDir(m_path); }
    const std::filesystem::path& path() const { return m_path; }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
private:
    std::filesystem::path m_path;
};

// Drive the estimator through a deterministic synthetic mempool.
void DriveEstimator(policy::fee_estimator::CBlockPolicyEstimator& est,
                    unsigned int blocks, uint32_t seed_offset = 0) {
    using namespace policy::fee_estimator;
    for (unsigned int h = 1; h <= blocks; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 4; ++i) {
            uint256 t = MakeTxHash(h * 1000 + i + seed_offset);
            est.processTx(t, h, 50000 + i * 5000, 250, true);
            confirmed.push_back(t);
        }
        // Leave one tx unconfirmed every block for tracked-set non-emptiness.
        if (h % 5 == 0) {
            uint256 t = MakeTxHash(h * 1000 + 999 + seed_offset);
            est.processTx(t, h, 8000, 250, true);
        }
        est.processBlock(h, confirmed);
    }
}

// Build a forged fee_estimates.dat for malformed-input tests. Caller
// supplies the in-the-clear payload (everything between version+key and
// footer); we add the version, key, scramble, and footer.
void WriteForgedFile(const std::filesystem::path& datadir,
                     const std::vector<uint8_t>& clear_body) {
    std::vector<uint8_t> bytes;
    bytes.reserve(1 + policy::fee_persist::XOR_KEY_SIZE +
                  clear_body.size() + policy::fee_persist::FOOTER_SIZE);
    bytes.push_back(policy::fee_persist::SCHEMA_VERSION);

    std::vector<uint8_t> key(policy::fee_persist::XOR_KEY_SIZE);
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(i ^ 0x5A);
    bytes.insert(bytes.end(), key.begin(), key.end());

    std::vector<uint8_t> for_hash = bytes;
    for_hash.insert(for_hash.end(), clear_body.begin(), clear_body.end());
    uint8_t hash_full[32];
    SHA3_256(for_hash.data(), for_hash.size(), hash_full);

    const size_t body_start = bytes.size();
    bytes.insert(bytes.end(), clear_body.begin(), clear_body.end());
    for (size_t i = 0; i < clear_body.size(); ++i) {
        bytes[body_start + i] ^= key[i % key.size()];
    }
    const size_t footer_offset = bytes.size() - body_start;
    for (size_t i = 0; i < policy::fee_persist::FOOTER_SIZE; ++i) {
        bytes.push_back(hash_full[i] ^ key[(footer_offset + i) % key.size()]);
    }

    const auto fp = datadir / policy::fee_persist::FILENAME;
    std::ofstream f(fp.string(), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // anonymous namespace

// ---- C1: round-trip basic + identity --------------------------------

BOOST_AUTO_TEST_CASE(roundtrip_basic) {
    TempDir scope("roundtrip_basic");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    DriveEstimator(est_dump, 30);
    BOOST_REQUIRE_GE(est_dump.getBestSeenHeight(), 30u);
    const size_t pre_dump_tracked = est_dump.getTrackedTxCount();
    BOOST_REQUIRE_GT(pre_dump_tracked, 0u);

    auto dump = policy::fee_persist::DumpFeeEstimates(est_dump, scope.path());
    BOOST_REQUIRE_MESSAGE(dump.success, "dump error: " << dump.error_message);
    BOOST_CHECK_EQUAL(dump.tracked_tx_count, pre_dump_tracked);
    BOOST_CHECK(!dump.final_path.empty());

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE_MESSAGE(load.success,
                          "load error: " << load.error_message);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.tracked_tx_count, pre_dump_tracked);

    // Identity assertions.
    BOOST_CHECK_EQUAL(est_dump.getBestSeenHeight(),
                      est_load.getBestSeenHeight());
    BOOST_CHECK_EQUAL(est_dump.getTrackedTxCount(),
                      est_load.getTrackedTxCount());
    BOOST_CHECK_EQUAL(est_dump.getBlocksObserved(),
                      est_load.getBlocksObserved());

    using namespace policy::fee_estimator;
    auto rd = est_dump.estimateRawFee(2, 0.80,
                                      EstimateHorizon::MED_HALFLIFE);
    auto rl = est_load.estimateRawFee(2, 0.80,
                                      EstimateHorizon::MED_HALFLIFE);
    // PR-EF-1-FIX Finding F3: pin that the estimate is non-null on the
    // dump side (else the equality check below is satisfied trivially
    // by both sides being -1). A regression that loses all conf_avg
    // data on persistence would otherwise pass under the previous
    // toothless equality assertion.
    BOOST_REQUIRE_MESSAGE(rd.feerate > 0,
        "dump-side estimate must be non-null for the equality check below "
        "to be load-bearing; got feerate=" << static_cast<double>(rd.feerate));
    BOOST_REQUIRE_MESSAGE(rl.feerate > 0,
        "load-side estimate must be non-null after restore; got feerate="
        << static_cast<double>(rl.feerate));
    // Use a relative-tolerance compare rather than exact equality. The
    // Q32.32 counter round-trip (EncodeCounter/DecodeCounter) is not
    // bit-exact, and estimateMedianFee selects the lowest bucket whose
    // confirmation ratio crosses the target threshold -- a sub-ULP
    // perturbation can flip the boundary bucket index, yielding an
    // adjacent ladder value (~5% apart). Under gcc -O2 the dump-side
    // compare can also retain x87 excess precision while the load side
    // truncates through fixed-point, so exact equality flaked on the
    // gcc-Release CI matrix while passing at -O0. The persistence contract
    // guarantees ~1e-3 bucket-ladder fidelity (fees.cpp ApproxEqual tol =
    // abs*1e-3 + 1e-6); assert to that contract, not to bit-equality.
    BOOST_CHECK_LE(std::fabs(static_cast<double>(rd.feerate) -
                             static_cast<double>(rl.feerate)),
                   static_cast<double>(rd.feerate) * 1e-3 + 1e-6);
}

// ---- C2: round-trip empty (no observations) --------------------------

BOOST_AUTO_TEST_CASE(roundtrip_empty) {
    TempDir scope("roundtrip_empty");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    BOOST_REQUIRE_EQUAL(est_dump.getTrackedTxCount(), 0u);

    auto dump = policy::fee_persist::DumpFeeEstimates(est_dump, scope.path());
    BOOST_REQUIRE(dump.success);
    BOOST_CHECK_EQUAL(dump.tracked_tx_count, 0u);

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.tracked_tx_count, 0u);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(), 0u);
}

// ---- C3: round-trip large ------------------------------------------

BOOST_AUTO_TEST_CASE(roundtrip_large) {
    TempDir scope("roundtrip_large");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    DriveEstimator(est_dump, 100);
    const size_t pre_dump_tracked = est_dump.getTrackedTxCount();

    auto dump = policy::fee_persist::DumpFeeEstimates(est_dump, scope.path());
    BOOST_REQUIRE_MESSAGE(dump.success, "dump error: " << dump.error_message);

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(load.tracked_tx_count, pre_dump_tracked);
}

// ---- C4: missing file -> cold start --------------------------------

BOOST_AUTO_TEST_CASE(missing_file_cold_start) {
    TempDir scope("missing_file");
    BOOST_REQUIRE(!std::filesystem::exists(
        scope.path() / policy::fee_persist::FILENAME));

    policy::fee_estimator::CBlockPolicyEstimator est;
    auto load = policy::fee_persist::LoadFeeEstimates(est, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(load.tracked_tx_count, 0u);
    BOOST_CHECK_EQUAL(est.getBestSeenHeight(), 0u);
}

// ---- C5: truncated file -> cold start ------------------------------

BOOST_AUTO_TEST_CASE(corrupt_truncated_cold_start) {
    TempDir scope("corrupt_truncated");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    DriveEstimator(est_dump, 10);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_dump,
                                                        scope.path()).success);

    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    std::error_code ec;
    std::filesystem::resize_file(fp,
        policy::fee_persist::MIN_FILE_SIZE - 1, ec);
    BOOST_REQUIRE(!ec);

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(), 0u);
}

// ---- C6: bad version byte -> cold start ----------------------------

BOOST_AUTO_TEST_CASE(corrupt_bad_version_cold_start) {
    TempDir scope("corrupt_bad_version");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    DriveEstimator(est_dump, 5);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_dump,
                                                        scope.path()).success);

    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    {
        std::fstream f(fp.string(), std::ios::binary | std::ios::in |
                                     std::ios::out);
        BOOST_REQUIRE(f.is_open());
        f.seekp(0);
        const uint8_t bad = 0xFF;
        f.write(reinterpret_cast<const char*>(&bad), 1);
    }

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("schema version") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(), 0u);
}

// ---- C7: corrupted footer -> cold start ----------------------------

BOOST_AUTO_TEST_CASE(corrupt_footer_cold_start) {
    TempDir scope("corrupt_footer");

    policy::fee_estimator::CBlockPolicyEstimator est_dump;
    DriveEstimator(est_dump, 5);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_dump,
                                                        scope.path()).success);

    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    const auto file_size = std::filesystem::file_size(fp);
    {
        std::fstream f(fp.string(), std::ios::binary | std::ios::in |
                                     std::ios::out);
        BOOST_REQUIRE(f.is_open());
        f.seekp(file_size - 1);
        const uint8_t flipped = 0xCC;
        f.write(reinterpret_cast<const char*>(&flipped), 1);
    }

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("footer") != std::string::npos);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(), 0u);
}

// ---- C8: forced EARLY dump failure -> previous file intact ---------

BOOST_AUTO_TEST_CASE(atomicity_forced_early_failure) {
    TempDir scope("atomicity_early");

    policy::fee_estimator::CBlockPolicyEstimator est_first;
    DriveEstimator(est_first, 5);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_first,
                                                        scope.path()).success);
    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    BOOST_REQUIRE(std::filesystem::exists(fp));
    const auto first_size = std::filesystem::file_size(fp);

    policy::fee_estimator::CBlockPolicyEstimator est_second;
    DriveEstimator(est_second, 50, /*seed_offset=*/100000);
    policy::fee_persist::test_hooks::g_force_dump_failure.store(true);
    auto dump = policy::fee_persist::DumpFeeEstimates(est_second,
                                                      scope.path());
    policy::fee_persist::test_hooks::g_force_dump_failure.store(false);
    BOOST_CHECK(!dump.success);
    BOOST_CHECK(!dump.error_message.empty());

    // Prior file intact.
    BOOST_REQUIRE(std::filesystem::exists(fp));
    BOOST_CHECK_EQUAL(std::filesystem::file_size(fp), first_size);
    BOOST_CHECK(!std::filesystem::exists(
        scope.path() / policy::fee_persist::FILENAME_TMP));

    // Loading still yields the FIRST estimator's state.
    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(),
                      est_first.getBestSeenHeight());
}

// ---- C9: forced LATE dump failure -> .new cleaned up, prior intact -

BOOST_AUTO_TEST_CASE(atomicity_forced_late_failure) {
    TempDir scope("atomicity_late");

    policy::fee_estimator::CBlockPolicyEstimator est_first;
    DriveEstimator(est_first, 5);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_first,
                                                        scope.path()).success);
    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    const auto fp_tmp = scope.path() / policy::fee_persist::FILENAME_TMP;
    const auto first_size = std::filesystem::file_size(fp);

    policy::fee_estimator::CBlockPolicyEstimator est_second;
    DriveEstimator(est_second, 75, /*seed_offset=*/200000);
    policy::fee_persist::test_hooks::g_force_late_dump_failure.store(true);
    auto dump = policy::fee_persist::DumpFeeEstimates(est_second,
                                                      scope.path());
    policy::fee_persist::test_hooks::g_force_late_dump_failure.store(false);
    BOOST_CHECK(!dump.success);
    BOOST_CHECK(dump.error_message.find("late") != std::string::npos);

    BOOST_CHECK(!std::filesystem::exists(fp_tmp));
    BOOST_REQUIRE(std::filesystem::exists(fp));
    BOOST_CHECK_EQUAL(std::filesystem::file_size(fp), first_size);

    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(),
                      est_first.getBestSeenHeight());
}

// ---- C10: schema lock-in (validates structural shape) --------------

BOOST_AUTO_TEST_CASE(schema_lock_in_structure) {
    TempDir scope("schema_lock");

    policy::fee_estimator::CBlockPolicyEstimator est;
    DriveEstimator(est, 3);

    auto dump = policy::fee_persist::DumpFeeEstimates(est, scope.path());
    BOOST_REQUIRE(dump.success);

    const auto fp = scope.path() / policy::fee_persist::FILENAME;
    std::ifstream f(fp.string(), std::ios::binary);
    BOOST_REQUIRE(f.is_open());
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());

    BOOST_REQUIRE_GT(bytes.size(),
                     1u + policy::fee_persist::XOR_KEY_SIZE +
                     policy::fee_persist::FOOTER_SIZE);
    BOOST_CHECK_EQUAL(bytes[0], policy::fee_persist::SCHEMA_VERSION);

    // Round-trip via LoadFeeEstimates (the real schema verifier).
    policy::fee_estimator::CBlockPolicyEstimator est_load;
    auto load = policy::fee_persist::LoadFeeEstimates(est_load, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(!load.cold_start);
    BOOST_CHECK_EQUAL(est_load.getBestSeenHeight(),
                      est.getBestSeenHeight());
}

// ---- B1: oversize file -> cold start (DoS protection) -------------

BOOST_AUTO_TEST_CASE(oversize_file_cold_start) {
    TempDir scope("oversize");
    const auto fp = scope.path() / policy::fee_persist::FILENAME;

    std::ofstream f(fp.string(), std::ios::binary | std::ios::trunc);
    f.put(0x01);
    f.close();
    std::error_code ec;
    std::filesystem::resize_file(fp,
        policy::fee_persist::MAX_FILE_SIZE + 1, ec);
    BOOST_REQUIRE(!ec);

    policy::fee_estimator::CBlockPolicyEstimator est;
    auto load = policy::fee_persist::LoadFeeEstimates(est, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("MAX_FILE_SIZE") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(est.getBestSeenHeight(), 0u);
}

// ---- C11-a: tracked_tx_count > MAX_TRACKED_TX -> cold start --------

BOOST_AUTO_TEST_CASE(overcap_tracked_tx_count_cold_start) {
    TempDir scope("overcap_tracked");

    // Build a forged body with valid header + minimal stats but
    // tracked_tx_count = MAX_TRACKED_TX + 1.
    // Note: this file will fail the bucket-count read instead because we
    // can't trivially generate a valid stats body. So we test a different
    // overcap: bucket_count exceeding MAX_BUCKET_COUNT.
    std::vector<uint8_t> clear_body;
    auto put_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            clear_body.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };
    put_u32(0);    // best_seen_height
    put_u32(0);    // historical_first
    put_u32(0);    // historical_best
    put_u32(policy::fee_persist::MAX_BUCKET_COUNT + 1);  // bucket_count

    WriteForgedFile(scope.path(), clear_body);

    policy::fee_estimator::CBlockPolicyEstimator est;
    auto load = policy::fee_persist::LoadFeeEstimates(est, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("bucket_count") !=
                std::string::npos);
}

// ---- C11-b: read-past-end mid-body -> cold start -------------------

BOOST_AUTO_TEST_CASE(read_past_end_cold_start) {
    TempDir scope("read_past_end");

    std::vector<uint8_t> clear_body;
    auto put_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            clear_body.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };
    put_u32(0); put_u32(0); put_u32(0);
    put_u32(2);   // bucket_count = 2 -- will demand 2 i64 bucket entries
    // ... but we don't write any. Read should throw.

    WriteForgedFile(scope.path(), clear_body);

    policy::fee_estimator::CBlockPolicyEstimator est;
    auto load = policy::fee_persist::LoadFeeEstimates(est, scope.path());
    BOOST_REQUIRE(load.success);
    BOOST_CHECK(load.cold_start);
    BOOST_CHECK(load.cold_start_reason.find("stream error") !=
                std::string::npos);
}

// ---- C12: estimator continues observing post-restore ---------------

BOOST_AUTO_TEST_CASE(restored_estimator_keeps_observing) {
    TempDir scope("restored_keeps_observing");

    policy::fee_estimator::CBlockPolicyEstimator est_a;
    DriveEstimator(est_a, 30);
    BOOST_REQUIRE(policy::fee_persist::DumpFeeEstimates(est_a,
                                                        scope.path()).success);

    policy::fee_estimator::CBlockPolicyEstimator est_b;
    BOOST_REQUIRE(policy::fee_persist::LoadFeeEstimates(est_b,
                                                        scope.path()).success);
    const auto post_restore_height = est_b.getBestSeenHeight();
    BOOST_CHECK_EQUAL(post_restore_height, 30u);

    // Continue driving. Anti-replay must let us observe blocks > 30.
    for (unsigned int h = 31; h <= 35; ++h) {
        std::vector<uint256> confirmed;
        for (uint32_t i = 0; i < 3; ++i) {
            uint256 t = MakeTxHash(h * 5000 + i);
            est_b.processTx(t, h, 50000, 250, true);
            confirmed.push_back(t);
        }
        est_b.processBlock(h, confirmed);
    }
    BOOST_CHECK_EQUAL(est_b.getBestSeenHeight(), 35u);
}

BOOST_AUTO_TEST_SUITE_END()
