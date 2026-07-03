// Copyright (c) 2026 The Dilithion Core developers
// Distributed under the MIT software license
//
// bech32m (BIP350) codec + ION-gated address encoding — Boost.Test suite.
//
// Coverage:
//   (1) BIP350 reference vectors — valid decode + invalid-checksum/format
//       negatives, and a bech32-constant-1 string that MUST fail (proves the
//       0x2bc830a3 bech32m constant is actually in use, not bech32's 1).
//   (2) ConvertBits 8<->5 round-trip.
//   (3) ION address round-trip: pubkey -> bech32m(hrp "ion") -> decode ->
//       identical 20-byte hash; plus a fixed pin cross-checked against an
//       independent (Python) reference encoder.
//   (4) DIL/DilV BYTE-UNCHANGED regression pin: a fixed payload encodes to the
//       exact same Base58Check string as the pre-bech32m code (literal anchor).
//
// Uses an RAII ChainParamsGuard when switching g_chainParams so a failing
// assertion cannot leak ION params into the 29+ unrelated suites in
// test_dilithion (mirrors ion_vdf_dispatch_tests / wf1_host_endian).

#include <boost/test/unit_test.hpp>

#include <util/bech32m.h>
#include <wallet/wallet.h>
#include <core/chainparams.h>
#include <rpc/rest_api.h>

#include <cstdint>
#include <string>
#include <vector>

using namespace Dilithion;

namespace {

// RAII scope-guard: installs a fresh g_chainParams for the duration of a test
// case and restores + frees the previous one in its destructor.
struct ChainParamsGuard {
    ChainParams* saved;
    explicit ChainParamsGuard(ChainParams* fresh) : saved(g_chainParams) {
        g_chainParams = fresh;  // takes ownership of `fresh`
    }
    ~ChainParamsGuard() {
        delete g_chainParams;
        g_chainParams = saved;
    }
    ChainParamsGuard(const ChainParamsGuard&) = delete;
    ChainParamsGuard& operator=(const ChainParamsGuard&) = delete;
};

// A fixed 21-byte address payload: version 0x1E + hash bytes 0..19.
std::vector<uint8_t> FixedPayload() {
    std::vector<uint8_t> p;
    p.push_back(0x1E);
    for (uint8_t i = 0; i < 20; ++i) p.push_back(i);
    return p;
}

// Pins computed by an INDEPENDENT Python reference implementation (see PR body).
const char* ION_PIN    = "ion1rcqqzqsrqszsvpcgpy9qkrqdpc83qygjzvxvz3pd";
const char* BASE58_PIN = "D597kHXGdkwkryF9oGhz9Bp1ypTpFAn2iA";

} // namespace

BOOST_AUTO_TEST_SUITE(bech32m_tests)

// ---------------------------------------------------------------------------
// (1) BIP350 reference vectors — valid.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bip350_valid_vectors) {
    const char* valid[] = {
        "a1lqfn3a",
        "A1LQFN3A",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "?1v759aa",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    };
    for (const char* v : valid) {
        bech32m::DecodeResult r = bech32m::Decode(v);
        BOOST_CHECK_MESSAGE(r.ok, std::string("expected valid: ") + v);
        if (r.ok) {
            // Re-encoding the decoded (lowercased) form reproduces the input.
            std::string lower(v);
            for (char& c : lower) if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            BOOST_CHECK_EQUAL(bech32m::Encode(r.hrp, r.data), lower);
        }
    }
}

// ---------------------------------------------------------------------------
// (1) BIP350 reference vectors — invalid (bad checksum / format / mixed case),
//     and a bech32-const-1 string that MUST fail under the bech32m constant.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(bip350_invalid_vectors) {
    const char* invalid[] = {
        "A12UEL5L",        // valid BECH32 (const=1) -> MUST fail as bech32m
        "a12uel5l",        // same, lowercase
        "a1Lqfn3a",        // mixed case
        "1qyrz8wqd2c9m",   // empty HRP
        "qyrz8wqd2c9m",    // no separator
        "in1muywd",        // too-short data (< 6 checksum symbols)
        "a1lqfn3b",        // last data char mutated -> bad checksum
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryy", // mutated checksum
        "",                // empty
    };
    for (const char* v : invalid) {
        bech32m::DecodeResult r = bech32m::Decode(v);
        BOOST_CHECK_MESSAGE(!r.ok, std::string("expected invalid: ") + v);
    }
}

// Over-length input (BIP173 90-char cap) is rejected.
BOOST_AUTO_TEST_CASE(overlength_rejected) {
    std::string s = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4";
    BOOST_CHECK_GT(s.size(), 90u);
    BOOST_CHECK(!bech32m::Decode(s).ok);
}

// ---------------------------------------------------------------------------
// (2) ConvertBits 8<->5 round-trip.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(convertbits_roundtrip) {
    for (size_t len = 1; len <= 40; ++len) {
        std::vector<uint8_t> in;
        for (size_t i = 0; i < len; ++i) in.push_back(static_cast<uint8_t>((i * 37 + 11) & 0xff));

        std::vector<uint8_t> five;
        BOOST_REQUIRE(bech32m::ConvertBits(five, in, 8, 5, /*pad=*/true));
        for (uint8_t d : five) BOOST_CHECK_LT(d, 32);  // all valid 5-bit groups

        std::vector<uint8_t> back;
        BOOST_REQUIRE(bech32m::ConvertBits(back, five, 5, 8, /*pad=*/false));
        BOOST_CHECK(back == in);
    }
}

// A 5-bit value >= 32 fed to a 5->8 conversion must be rejected.
BOOST_AUTO_TEST_CASE(convertbits_rejects_overflow) {
    std::vector<uint8_t> bad = {31, 32};  // 32 overflows 5 bits
    std::vector<uint8_t> out;
    BOOST_CHECK(!bech32m::ConvertBits(out, bad, 5, 8, false));
}

// ---------------------------------------------------------------------------
// (3) ION address round-trip + fixed pin.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(ion_address_roundtrip) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));
    BOOST_REQUIRE(!g_chainParams->bech32Prefix.empty());
    BOOST_CHECK_EQUAL(g_chainParams->bech32Prefix, std::string("ion"));

    // Fixed dummy "pubkey" -> HashPubKey -> address.
    std::vector<uint8_t> pubkey;
    for (int i = 0; i < 64; ++i) pubkey.push_back(static_cast<uint8_t>(i * 7 + 3));
    std::vector<uint8_t> expectedHash = WalletCrypto::HashPubKey(pubkey);
    BOOST_REQUIRE_EQUAL(expectedHash.size(), 20u);

    CDilithiumAddress addr(pubkey);
    std::string s = addr.ToString();
    // ION addresses are bech32m: they begin with the hrp + '1'.
    BOOST_CHECK_MESSAGE(s.rfind("ion1", 0) == 0, "ION address must start with ion1: " + s);

    // Decode back and confirm the 20-byte hash survives round-trip.
    CDilithiumAddress parsed;
    BOOST_REQUIRE(parsed.SetString(s));
    BOOST_CHECK(parsed == addr);
    const std::vector<uint8_t>& data = parsed.GetData();
    BOOST_REQUIRE_EQUAL(data.size(), 21u);
    BOOST_CHECK_EQUAL(data[0], 0x1E);
    std::vector<uint8_t> gotHash(data.begin() + 1, data.end());
    BOOST_CHECK(gotHash == expectedHash);
}

// Fixed-payload pin: exact bech32m string cross-checked vs the Python reference.
BOOST_AUTO_TEST_CASE(ion_fixed_pin) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));
    CDilithiumAddress addr = CDilithiumAddress::FromData(FixedPayload());
    BOOST_CHECK_EQUAL(addr.ToString(), std::string(ION_PIN));

    // And it round-trips back to the exact payload.
    CDilithiumAddress parsed;
    BOOST_REQUIRE(parsed.SetString(ION_PIN));
    BOOST_CHECK(parsed.GetData() == FixedPayload());
}

// A Base58Check string must NOT parse on ION (auto-detect routes only "ion1..."
// to bech32m; a base58 string that doesn't start with the hrp falls through to
// Base58Check, which still works — so a valid base58 D-address is also accepted).
BOOST_AUTO_TEST_CASE(ion_autodetect) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));
    // The bech32m pin parses.
    CDilithiumAddress a;
    BOOST_CHECK(a.SetString(ION_PIN));
    // A corrupted bech32m string fails.
    std::string bad = ION_PIN;
    bad[bad.size() - 1] = (bad[bad.size() - 1] == 'p') ? 'q' : 'p';
    CDilithiumAddress b;
    BOOST_CHECK(!b.SetString(bad));
}

// ---------------------------------------------------------------------------
// (4) DIL/DilV BYTE-UNCHANGED regression pin.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(dil_base58_unchanged_pin) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Mainnet()));
    BOOST_REQUIRE(g_chainParams->bech32Prefix.empty());  // DIL uses Base58Check

    CDilithiumAddress addr = CDilithiumAddress::FromData(FixedPayload());
    std::string s = addr.ToString();
    // Exact literal anchor — breaks if the DIL encoding ever changes a byte.
    BOOST_CHECK_EQUAL(s, std::string(BASE58_PIN));
    // Round-trips.
    CDilithiumAddress parsed;
    BOOST_REQUIRE(parsed.SetString(s));
    BOOST_CHECK(parsed.GetData() == FixedPayload());
}

BOOST_AUTO_TEST_CASE(dilv_base58_unchanged) {
    ChainParamsGuard guard(new ChainParams(ChainParams::DilV()));
    BOOST_REQUIRE(g_chainParams->bech32Prefix.empty());  // DilV uses Base58Check
    CDilithiumAddress addr = CDilithiumAddress::FromData(FixedPayload());
    // Same base58 payload encoding as DIL (both empty-hrp / Base58Check).
    BOOST_CHECK_EQUAL(addr.ToString(), std::string(BASE58_PIN));
}

// ---------------------------------------------------------------------------
// (5) Wiring-completeness regression (red-team WIRING-COMPLETENESS fold).
//     These pin the ION-reachable address sites that previously bypassed the
//     gated CDilithiumAddress and hardcoded Base58/'D'-prefix logic.
// ---------------------------------------------------------------------------

// HIGH-1: the REST address-validation gate (ValidateAddress) must accept an ION
// bech32m address (previously hard-rejected by the 'D'-prefix + size>40 +
// Base58-charset pre-filter) and still reject garbage. Exercised through the
// PUBLIC HandleRequest entry point (ValidateAddress is a private helper): with
// no UTXO set registered, an address that PASSES validation falls through to a
// 503 "UTXO set not available", while an address that FAILS validation returns
// a 400 "Invalid address format" — so the two are cleanly distinguishable.
BOOST_AUTO_TEST_CASE(rest_validateaddress_ion) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));
    CRestAPI api;  // no components registered

    // Native ION address now passes validation (reaches the 503, not the 400).
    std::string ok = api.HandleRequest("GET", std::string("/api/v1/balance/") + ION_PIN, "", "127.0.0.1");
    BOOST_CHECK_MESSAGE(ok.find("Invalid address format") == std::string::npos,
                        "ION address wrongly rejected by REST ValidateAddress: " + ok);
    BOOST_CHECK(ok.find("UTXO set not available") != std::string::npos);

    // Uppercase ION address (case-insensitive, LOW-1) also passes the REST gate.
    std::string upper(ION_PIN);
    for (char& c : upper) if (c >= 'a' && c <= 'z') c -= ('a' - 'A');
    std::string okUp = api.HandleRequest("GET", std::string("/api/v1/utxos/") + upper, "", "127.0.0.1");
    BOOST_CHECK(okUp.find("Invalid address format") == std::string::npos);

    // Garbage is still rejected at the validation gate (400).
    std::string bad = api.HandleRequest("GET", "/api/v1/balance/not-a-real-address", "", "127.0.0.1");
    BOOST_CHECK(bad.find("Invalid address format") != std::string::npos);

    // A corrupted bech32m checksum is rejected too.
    std::string corrupt(ION_PIN);
    corrupt[corrupt.size() - 1] = (corrupt[corrupt.size() - 1] == 'p') ? 'q' : 'p';
    std::string badcs = api.HandleRequest("GET", std::string("/api/v1/balance/") + corrupt, "", "127.0.0.1");
    BOOST_CHECK(badcs.find("Invalid address format") != std::string::npos);
}

// HIGH-1 (DIL side): the REST gate on a Base58Check chain still accepts a valid
// DIL address and rejects a bech32m string — DIL behaviour unchanged.
BOOST_AUTO_TEST_CASE(rest_validateaddress_dil_unchanged) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Mainnet()));
    CRestAPI api;

    std::string dil = api.HandleRequest("GET", std::string("/api/v1/balance/") + BASE58_PIN, "", "127.0.0.1");
    BOOST_CHECK(dil.find("Invalid address format") == std::string::npos);   // DIL accepted
    BOOST_CHECK(dil.find("UTXO set not available") != std::string::npos);

    std::string ionOnDil = api.HandleRequest("GET", std::string("/api/v1/balance/") + ION_PIN, "", "127.0.0.1");
    BOOST_CHECK(ionOnDil.find("Invalid address format") != std::string::npos);  // ion1… invalid on DIL

    std::string junk = api.HandleRequest("GET", "/api/v1/balance/garbage", "", "127.0.0.1");
    BOOST_CHECK(junk.find("Invalid address format") != std::string::npos);
}

// LOW-1: an all-uppercase ION1… address parses (case-insensitive HRP gate) to
// the SAME payload as its lowercase form; a MIXED-case address is rejected.
BOOST_AUTO_TEST_CASE(ion_uppercase_accepted_mixed_rejected) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));

    std::string upper(ION_PIN);
    for (char& c : upper) if (c >= 'a' && c <= 'z') c -= ('a' - 'A');
    CDilithiumAddress up;
    BOOST_REQUIRE(up.SetString(upper));
    BOOST_CHECK(up.GetData() == FixedPayload());

    // Mixed case: uppercase the HRP only (bech32m rejects mixed case in Decode).
    std::string mixed(ION_PIN);
    mixed[0] = 'I'; mixed[1] = 'O'; mixed[2] = 'N';  // "ION1…" body stays lowercase
    CDilithiumAddress mx;
    BOOST_CHECK(!mx.SetString(mixed));
}

// MED-1 (DNA emit) / MED-2 (x402 parse): both now delegate to the gated
// ToString()/SetString(). Prove the parse path an ION user hits yields the same
// 21-byte payload the facilitator extracts (decoded.data()+1 == 20-byte hash),
// and that the emit side renders ion1… — the same round-trip the DNA RPC does.
BOOST_AUTO_TEST_CASE(ion_parse_emit_shared_gate) {
    ChainParamsGuard guard(new ChainParams(ChainParams::Ion()));
    // Emit side (DNA pubkeyhash_to_address delegates here): ion1… form.
    CDilithiumAddress emitted = CDilithiumAddress::FromData(FixedPayload());
    std::string s = emitted.ToString();
    BOOST_CHECK(s.rfind("ion1", 0) == 0);
    // Parse side (facilitator SetString delegates here): recovers payload,
    // version 0x1E, and a 20-byte hash tail exactly as decoded.data()+1 expects.
    CDilithiumAddress parsed;
    BOOST_REQUIRE(parsed.SetString(s));
    const std::vector<uint8_t>& d = parsed.GetData();
    BOOST_REQUIRE_EQUAL(d.size(), 21u);
    BOOST_CHECK_EQUAL(d[0], 0x1E);
    const std::vector<uint8_t> fp = FixedPayload();
    BOOST_CHECK(std::vector<uint8_t>(d.begin() + 1, d.end()) ==
                std::vector<uint8_t>(fp.begin() + 1, fp.end()));
}

BOOST_AUTO_TEST_SUITE_END()
