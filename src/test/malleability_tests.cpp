// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license
//
// Transaction-malleability closure tests (SECURITY-ecosystem-2026-08, findings
// #4 scriptSig malleability + #5 non-canonical CompactSize).
//
// Two soft-fork tightenings are exercised here:
//   Fix A — every CompactSize decoder rejects non-minimal (non-shortest) forms.
//   Fix B — a P2PKH scriptSig must be the ONE canonical 5265-byte layout, and
//           the interpreter enforces MINIMALDATA + CLEANSTACK on the general
//           (scriptV2) path.
//
// Each load-bearing check has a paired POSITIVE control (the honest form is
// accepted) so a green result cannot come from "reject everything", and each is
// separately mutation-proven (neuter -> the matching case reddens) — see
// MALLEABILITY_IMPL.md for the recorded mutation runs.

#include <boost/test/unit_test.hpp>

#include <consensus/tx_validation.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <node/utxo_set.h>
#include <net/serialize.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <amount.h>
#include <uint256.h>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(MalleabilityTests)

namespace {

// ---- Fix A helpers --------------------------------------------------------

// Decoder #2: the exported pointer-range decoder used by tx + block parsing.
bool Dec2(const std::vector<uint8_t>& bytes, uint64_t& out, std::string& err) {
    const uint8_t* p = bytes.data();
    const uint8_t* e = bytes.data() + bytes.size();
    return DeserializeCompactSize(p, e, out, &err);
}

// Decoder #1: the CDataStream stream decoder (throws on non-canonical).
bool Dec1(const std::vector<uint8_t>& bytes, uint64_t& out) {
    try {
        CDataStream ds(bytes);
        out = ds.ReadCompactSize();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// Build the non-minimal encoding of `value` under a chosen wider `prefix`.
std::vector<uint8_t> NonMinimal(uint8_t prefix, uint64_t value) {
    std::vector<uint8_t> b{prefix};
    int n = (prefix == 253) ? 2 : (prefix == 254) ? 4 : 8;
    for (int i = 0; i < n; ++i) b.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    return b;
}

// Build the minimal (canonical) encoding via the single-source encoder.
std::vector<uint8_t> Minimal(uint64_t value) {
    std::vector<uint8_t> b;
    SerializeCompactSize(b, value);
    return b;
}

// ---- Fix B helpers --------------------------------------------------------

const size_t SIG = 3309;   // DILITHIUM3_SIG_SIZE
const size_t PK  = 1952;   // DILITHIUM3_PK_SIZE

std::vector<uint8_t> P2PKHScript() {
    std::vector<uint8_t> s{0x76, 0xa9, 0x14};   // OP_DUP OP_HASH160 push20
    s.insert(s.end(), 20, 0x00);                // 20-byte hash (arbitrary)
    s.push_back(0x88);                          // OP_EQUALVERIFY
    s.push_back(0xac);                          // OP_CHECKSIG
    return s;
}

void PushLE16(std::vector<uint8_t>& s, uint16_t v) {
    s.push_back(static_cast<uint8_t>(v & 0xff));
    s.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}

// The ONE canonical P2PKH scriptSig: [3309 LE][sig][1952 LE][pk] = 5265 bytes.
std::vector<uint8_t> CanonicalScriptSig() {
    std::vector<uint8_t> s;
    PushLE16(s, static_cast<uint16_t>(SIG));
    s.insert(s.end(), SIG, 0xAB);
    PushLE16(s, static_cast<uint16_t>(PK));
    s.insert(s.end(), PK, 0xCD);
    return s;   // 5265
}

// B1: native push-opcode form (OP_PUSHDATA2) — same (sig,pk), different bytes.
std::vector<uint8_t> PushOpcodeScriptSig() {
    std::vector<uint8_t> s;
    s.push_back(OP_PUSHDATA2); PushLE16(s, static_cast<uint16_t>(SIG));
    s.insert(s.end(), SIG, 0xAB);
    s.push_back(OP_PUSHDATA2); PushLE16(s, static_cast<uint16_t>(PK));
    s.insert(s.end(), PK, 0xCD);
    return s;   // 5267
}

// B2: OP_PUSHDATA4 (non-minimal) form.
std::vector<uint8_t> PushData4ScriptSig() {
    auto le32 = [](std::vector<uint8_t>& s, uint32_t v) {
        s.push_back(v & 0xff); s.push_back((v >> 8) & 0xff);
        s.push_back((v >> 16) & 0xff); s.push_back((v >> 24) & 0xff);
    };
    std::vector<uint8_t> s;
    s.push_back(OP_PUSHDATA4); le32(s, static_cast<uint32_t>(SIG));
    s.insert(s.end(), SIG, 0xAB);
    s.push_back(OP_PUSHDATA4); le32(s, static_cast<uint32_t>(PK));
    s.insert(s.end(), PK, 0xCD);
    return s;
}

bool OpenUTXO(CUTXOSet& u, const std::string& path) {
    if (!u.Open(path, true)) return false;
    u.Clear();
    return true;
}

// One-input P2PKH-spending tx with the given scriptSig; returns validator verdict.
bool RunGate(const std::string& dbpath, const std::vector<uint8_t>& scriptSig,
             std::string& err, uint32_t nInputs = 1) {
    CUTXOSet utxo;
    BOOST_REQUIRE(OpenUTXO(utxo, dbpath));

    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = 0;
    const CAmount kInPerInput = 100 * COIN;
    const CAmount kFee = 1000000;   // 0.01 COIN: above size-min/relay-min, below MAX_REASONABLE_FEE (1e7)
    for (uint32_t i = 0; i < nInputs; ++i) {
        uint256 h; h.data[0] = 0x10; h.data[1] = static_cast<uint8_t>(i);
        COutPoint op(h, 0);
        utxo.AddUTXO(op, CTxOut(kInPerInput, P2PKHScript()), 10, false);
        tx.vin.push_back(CTxIn(op, scriptSig));
    }
    tx.vout.push_back(CTxOut(static_cast<CAmount>(nInputs) * kInPerInput - kFee, P2PKHScript()));

    CTransactionValidator validator;
    CAmount fee = 0;
    return validator.CheckTransactionInputs(tx, utxo, 100, fee, err);
}

class MockChecker : public SignatureChecker {
public:
    bool CheckSig(const std::vector<uint8_t>&, const std::vector<uint8_t>&) const override { return true; }
    bool CheckLockTime(int64_t) const override { return true; }
    bool CheckSequence(int64_t) const override { return true; }
};

CScript MakeScript(const std::vector<uint8_t>& v) { return CScript(v.begin(), v.end()); }

}  // namespace

// ===========================================================================
// Fix A — non-minimal CompactSize rejected at every decoder
// ===========================================================================

// T-A1: each wider prefix carrying a value that fits in a shorter form is
// rejected by decoders #1 and #2; the minimal form of the same value is
// accepted (positive control against a "reject-everything" pass).
BOOST_AUTO_TEST_CASE(A1_nonminimal_rejected_each_prefix) {
    std::string err;
    uint64_t v = 0;

    for (uint8_t prefix : {uint8_t(253), uint8_t(254), uint8_t(255)}) {
        auto bytes = NonMinimal(prefix, 1);   // value 1 always fits in 1 byte
        BOOST_CHECK_MESSAGE(!Dec2(bytes, v, err),
            "decoder#2 must reject non-minimal prefix " << int(prefix));
        BOOST_CHECK(err.find("Non-canonical") != std::string::npos);
        BOOST_CHECK_MESSAGE(!Dec1(bytes, v),
            "decoder#1 must reject non-minimal prefix " << int(prefix));
    }

    // Positive control: the minimal form of value 1 is accepted, value correct.
    auto ok = Minimal(1);
    BOOST_CHECK(Dec2(ok, v, err) && v == 1);
    BOOST_CHECK(Dec1(ok, v) && v == 1);
}

// T-A2: the smallest legal value of each width is accepted (off-by-one guard).
BOOST_AUTO_TEST_CASE(A2_boundary_minimal_accepted) {
    std::string err;
    uint64_t v = 0;
    const uint64_t cases[] = {252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000ULL};
    for (uint64_t val : cases) {
        auto b = Minimal(val);
        BOOST_CHECK_MESSAGE(Dec2(b, v, err) && v == val,
            "decoder#2 must accept minimal " << val << " err=" << err);
        BOOST_CHECK_MESSAGE(Dec1(b, v) && v == val,
            "decoder#1 must accept minimal " << val);
    }
}

// T-A3: a legal >= 2^32 value under the 9-byte (255) prefix is accepted
// identically by decoders #1 and #2 (previously decoder #3 special-rejected 255).
BOOST_AUTO_TEST_CASE(A3_255_prefix_consistency) {
    std::string err;
    uint64_t v1 = 0, v2 = 0;
    auto b = Minimal(0x123456789ULL);   // > 2^32 -> genuine 9-byte form
    BOOST_CHECK(b[0] == 0xFF);
    BOOST_CHECK(Dec2(b, v2, err) && v2 == 0x123456789ULL);
    BOOST_CHECK(Dec1(b, v1) && v1 == 0x123456789ULL);
    BOOST_CHECK(v1 == v2);
}

// T-A4: cross-decoder differential — decoders #1 and #2 agree (accept/reject +
// value) across a corpus in both minimal and every non-minimal padding.
BOOST_AUTO_TEST_CASE(A4_cross_decoder_differential) {
    std::string err;
    const uint64_t corpus[] = {0, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000ULL};
    for (uint64_t val : corpus) {
        // minimal must agree (both accept, same value)
        {
            auto b = Minimal(val);
            uint64_t a = 0, c = 0;
            bool r2 = Dec2(b, a, err);
            bool r1 = Dec1(b, c);
            BOOST_CHECK(r1 == r2);
            BOOST_CHECK(r2 && a == val && c == val);
        }
        // each wider-than-minimal padding must be rejected by BOTH
        for (uint8_t prefix : {uint8_t(253), uint8_t(254), uint8_t(255)}) {
            int width = (prefix == 253) ? 2 : (prefix == 254) ? 4 : 8;
            uint64_t cap = (width == 2) ? 0xFFFFULL : (width == 4) ? 0xFFFFFFFFULL : ~0ULL;
            uint64_t minForPrefix = (prefix == 253) ? 253 : (prefix == 254) ? 0x10000ULL : 0x100000000ULL;
            if (val > cap || val >= minForPrefix) continue;   // this padding would be legal/overflow
            auto b = NonMinimal(prefix, val);
            uint64_t a = 0, c = 0;
            bool r2 = Dec2(b, a, err);
            bool r1 = Dec1(b, c);
            BOOST_CHECK_MESSAGE(r1 == r2, "decoders disagree on non-minimal val=" << val << " prefix=" << int(prefix));
            BOOST_CHECK(!r2);
        }
    }
}

// T-A (decoder #3): the block tx-count decoder now enforces minimality too, and
// a minimal count fails for a DIFFERENT reason (not the canonical check) — proving
// the minimality rule fires specifically at that third site.
BOOST_AUTO_TEST_CASE(A_decoder3_block_txcount_minimality) {
    CBlockValidator bv;
    std::vector<CTransactionRef> txs;
    std::string err;

    CBlock blk;
    blk.vtx = NonMinimal(253, 1);        // non-minimal count prefix (value 1 in 3 bytes)
    blk.vtx.insert(blk.vtx.end(), 64, 0x00);  // trailing bytes so it's not a truncation
    BOOST_CHECK(!bv.DeserializeBlockTransactions(blk, txs, err));
    BOOST_CHECK_MESSAGE(err.find("Non-canonical") != std::string::npos,
        "decoder#3 must reject non-minimal tx-count; got: " << err);

    // Positive control: a MINIMAL count of 1 does not trip the canonical rule
    // (it fails later on incomplete tx data instead).
    txs.clear();
    CBlock blk2;
    blk2.vtx = Minimal(1);
    blk2.vtx.push_back(0x00);   // start of a tx but truncated
    BOOST_CHECK(!bv.DeserializeBlockTransactions(blk2, txs, err));
    BOOST_CHECK_MESSAGE(err.find("Non-canonical") == std::string::npos,
        "minimal count must not be rejected as non-canonical; got: " << err);
}

// ===========================================================================
// Fix B — canonical P2PKH scriptSig gate (path-independent, before batch/seq)
// ===========================================================================

// T-B1: the honest wallet-emitted canonical layout is ACCEPTED unchanged, and
// its txid is stable across serialize -> deserialize -> serialize.
BOOST_AUTO_TEST_CASE(B1_canonical_accepted) {
    std::string err;
    BOOST_CHECK_MESSAGE(RunGate(".test_mall_b1", CanonicalScriptSig(), err),
        "canonical P2PKH scriptSig must be accepted; err=" << err);

    // txid stability (the canonical form round-trips to the same bytes/hash).
    CTransaction tx;
    tx.nVersion = 1;
    tx.vin.push_back(CTxIn(COutPoint(uint256(), 0), CanonicalScriptSig()));
    tx.vout.push_back(CTxOut(10 * COIN, P2PKHScript()));
    auto ser = tx.Serialize();
    CTransaction tx2;
    BOOST_REQUIRE(tx2.Deserialize(ser.data(), ser.size()));
    BOOST_CHECK(tx.GetHash() == tx2.GetHash());
    BOOST_CHECK(tx2.Serialize() == ser);
}

// T-B2 (B1 vector): push-opcode re-encoding is REJECTED, and it really is a
// distinct txid (proving the malleability vector was real).
BOOST_AUTO_TEST_CASE(B2_pushopcode_rejected) {
    std::string err;
    BOOST_CHECK(!RunGate(".test_mall_b2", PushOpcodeScriptSig(), err));
    BOOST_CHECK_MESSAGE(err.find("Non-canonical scriptSig") != std::string::npos,
        "expected non-canonical scriptSig rejection; got: " << err);

    // The two forms carry the same (sig,pk) but hash to different txids.
    CTransaction a, b;
    a.nVersion = b.nVersion = 1;
    a.vin.push_back(CTxIn(COutPoint(uint256(), 0), CanonicalScriptSig()));
    b.vin.push_back(CTxIn(COutPoint(uint256(), 0), PushOpcodeScriptSig()));
    a.vout.push_back(CTxOut(10 * COIN, P2PKHScript()));
    b.vout.push_back(CTxOut(10 * COIN, P2PKHScript()));
    BOOST_CHECK(!(a.GetHash() == b.GetHash()));
}

// T-B3 (B2 vector): OP_PUSHDATA4 non-minimal form is REJECTED.
BOOST_AUTO_TEST_CASE(B3_pushdata4_rejected) {
    std::string err;
    BOOST_CHECK(!RunGate(".test_mall_b3", PushData4ScriptSig(), err));
    BOOST_CHECK(err.find("Non-canonical scriptSig") != std::string::npos);
}

// T-B4 (B3 vector, highest value): prepend a single-byte junk push — the
// cheapest, re-encoding-free malleation — is REJECTED by the exact-length gate.
BOOST_AUTO_TEST_CASE(B4_prepend_junk_rejected) {
    std::string err;
    auto junk = CanonicalScriptSig();
    junk.insert(junk.begin(), 0x00);   // OP_0 prepended -> 5266 bytes
    BOOST_CHECK(!RunGate(".test_mall_b4", junk, err));
    BOOST_CHECK(err.find("Non-canonical scriptSig") != std::string::npos);
}

// The gate is STRICTER than IsLegacyScriptSig: a 5265-byte layout with a correct
// sig_len but a WRONG inner pk_len (which the sequential path ignores but the
// batch path enforces) is rejected — closing a residual pk_len malleation AND a
// batch/sequential accept split.
BOOST_AUTO_TEST_CASE(B_wrong_pklen_rejected) {
    std::string err;
    auto s = CanonicalScriptSig();
    // Corrupt the pk_len field (bytes at offset 2+SIG) to 1951, keep total size.
    s[2 + SIG] = static_cast<uint8_t>(1951 & 0xff);
    s[2 + SIG + 1] = static_cast<uint8_t>((1951 >> 8) & 0xff);
    BOOST_CHECK(s.size() == 2 + SIG + 2 + PK);   // still 5265
    BOOST_CHECK(!RunGate(".test_mall_pklen", s, err));
    BOOST_CHECK(err.find("Non-canonical scriptSig") != std::string::npos);
}

// T-B5: path-independence. The gate lives in CheckTransactionInputs, which runs
// BEFORE CheckTransaction's batch-vs-sequential branch, so a >=2-input tx (which
// would take the batch path) is rejected on the SAME rule as a 1-input tx.
BOOST_AUTO_TEST_CASE(B5_path_independent) {
    std::string err1, err2;
    BOOST_CHECK(!RunGate(".test_mall_b5_1", PushOpcodeScriptSig(), err1, /*nInputs=*/1));
    BOOST_CHECK(!RunGate(".test_mall_b5_2", PushOpcodeScriptSig(), err2, /*nInputs=*/2));
    BOOST_CHECK(err1.find("Non-canonical scriptSig") != std::string::npos);
    BOOST_CHECK(err2.find("Non-canonical scriptSig") != std::string::npos);

    // And the canonical form is accepted on both arities (positive control).
    std::string ok1, ok2;
    BOOST_CHECK(RunGate(".test_mall_b5_ok1", CanonicalScriptSig(), ok1, 1));
    BOOST_CHECK(RunGate(".test_mall_b5_ok2", CanonicalScriptSig(), ok2, 2));
}

// T-B6 (negative control): coinbase inputs carry arbitrary scriptSig data and
// MUST NOT be subjected to the P2PKH canonical rule.
BOOST_AUTO_TEST_CASE(B6_coinbase_unaffected) {
    CUTXOSet utxo;
    BOOST_REQUIRE(OpenUTXO(utxo, ".test_mall_b6"));

    CTransaction cb;
    cb.nVersion = 1;
    // Coinbase: single input with a null prevout and arbitrary scriptSig.
    COutPoint nullOp(uint256(), 0xffffffff);
    cb.vin.push_back(CTxIn(nullOp, std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF, 0x01}));
    cb.vout.push_back(CTxOut(50 * COIN, P2PKHScript()));
    BOOST_REQUIRE(cb.IsCoinBase());

    CTransactionValidator validator;
    CAmount fee = 0;
    std::string err;
    BOOST_CHECK_MESSAGE(validator.CheckTransactionInputs(cb, utxo, 100, fee, err),
        "coinbase must be accepted regardless of scriptSig; err=" << err);
}

// ===========================================================================
// Interpreter — MINIMALDATA + CLEANSTACK (general / scriptV2 path)
// ===========================================================================

// CLEANSTACK: stack residue (extra element below the truthy top) is rejected
// only when the flag is set; without it the legacy behavior (top-only) passes.
BOOST_AUTO_TEST_CASE(cleanstack_rejects_residue) {
    MockChecker c;
    std::string err;
    // scriptSig pushes two 2-byte (minimal) elements; scriptPubKey is empty.
    std::vector<uint8_t> v{0x02, 0xAA, 0xBB, 0x02, 0xAA, 0xBB};
    CScript ss = MakeScript(v);
    CScript spk = MakeScript({});

    // Positive control: without CLEANSTACK the residue passes (top is truthy).
    BOOST_CHECK(VerifyScript(ss, spk, SCRIPT_VERIFY_NONE, c, err));
    // With CLEANSTACK the leftover element is rejected.
    BOOST_CHECK(!VerifyScript(ss, spk, SCRIPT_VERIFY_CLEANSTACK, c, err));
    BOOST_CHECK_MESSAGE(err.find("CLEANSTACK") != std::string::npos,
        "expected CLEANSTACK rejection; got: " << err);
}

// MINIMALDATA: a 100-byte element pushed via OP_PUSHDATA4 (non-minimal) is
// rejected under the flag; the minimal OP_PUSHDATA1 form and the flagless case
// are accepted.
BOOST_AUTO_TEST_CASE(minimaldata_rejects_nonminimal_push) {
    MockChecker c;
    std::string err;
    std::vector<uint8_t> data(100, 0x77);

    std::vector<uint8_t> pd4{OP_PUSHDATA4, 100, 0, 0, 0};
    pd4.insert(pd4.end(), data.begin(), data.end());
    std::vector<uint8_t> pd1{OP_PUSHDATA1, 100};
    pd1.insert(pd1.end(), data.begin(), data.end());

    std::vector<std::vector<uint8_t>> stack;
    // Non-minimal PUSHDATA4 rejected under MINIMALDATA.
    BOOST_CHECK(!EvalScript(stack, MakeScript(pd4), SCRIPT_VERIFY_MINIMALDATA, c, err));
    BOOST_CHECK_MESSAGE(err.find("MINIMALDATA") != std::string::npos,
        "expected MINIMALDATA rejection; got: " << err);

    // Positive control 1: minimal PUSHDATA1 form accepted under the flag.
    stack.clear();
    BOOST_CHECK(EvalScript(stack, MakeScript(pd1), SCRIPT_VERIFY_MINIMALDATA, c, err));
    // Positive control 2: without the flag, the PUSHDATA4 form is accepted.
    stack.clear();
    BOOST_CHECK(EvalScript(stack, MakeScript(pd4), SCRIPT_VERIFY_NONE, c, err));
}

BOOST_AUTO_TEST_SUITE_END()
